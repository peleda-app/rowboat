use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use bytes::Bytes;
use skein_core::{AccountId, Seq, TenantId, Timestamp};
use skein_engine::{AccountObserver, ObserverError};
use skein_storage::{StorageError, Version};
use tracing::{debug, warn};

use crate::model::{Batch, Compacted, Cursor, Endpoint};
use crate::signature::{ID_HEADER, SIGNATURE_HEADER, TIMESTAMP_HEADER, sign};
use crate::store::cursor_path;
use crate::{SendError, Transport, WebhookError, WebhookStore};

/// Most events in one batch.
pub const BATCH_SIZE: usize = 100;
/// Most batches sent to one endpoint for one account per run; the rest goes on the next run.
pub const MAX_BATCHES_PER_RUN: usize = 20;
/// Wait after the first failure, in seconds; doubles with every failure after it.
pub const FIRST_BACKOFF_SECS: u64 = 10;
/// Longest wait between attempts, in seconds.
pub const MAX_BACKOFF_SECS: u64 = 3_600;
/// How long an account's deliveries may keep failing before the endpoint is paused.
pub const PAUSE_AFTER_MS: i64 = 3 * 24 * 3_600 * 1_000;

/// The time delivery goes by.
pub trait Clock: Send + Sync {
    /// Now.
    fn now(&self) -> Timestamp;
}

/// The system clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::now()
    }
}

/// The wait after `failures` failed attempts in a row: 10 s, 20 s, 40 s, ... up to 1 h.
pub fn backoff_secs(failures: u32) -> u64 {
    let shift = failures.saturating_sub(1).min(20);
    FIRST_BACKOFF_SECS
        .saturating_mul(1u64 << shift)
        .min(MAX_BACKOFF_SECS)
}

/// What one delivery run did, summed over endpoints.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeliveryReport {
    /// Requests answered with `2xx`.
    pub batches: usize,
    /// Events in those requests.
    pub events: usize,
    /// Requests that failed.
    pub failures: usize,
    /// Endpoints skipped because their backoff has not passed.
    pub waiting: usize,
}

impl DeliveryReport {
    fn add(&mut self, other: DeliveryReport) {
        self.batches += other.batches;
        self.events += other.events;
        self.failures += other.failures;
        self.waiting += other.waiting;
    }
}

/// Signs and sends `body` as one batch.
pub(crate) async fn send_signed(
    transport: &dyn Transport,
    url: &str,
    secret: &str,
    batch_id: &str,
    now: Timestamp,
    body: Bytes,
) -> Result<u16, SendError> {
    let timestamp = now.0.div_euclid(1000);
    let headers = [
        (ID_HEADER, batch_id.to_owned()),
        (TIMESTAMP_HEADER, timestamp.to_string()),
        (SIGNATURE_HEADER, sign(secret, timestamp, &body)),
    ];
    transport.post(url, &headers, body).await
}

fn batch_id(endpoint: &str, account: &AccountId, what: &str) -> String {
    let hash = blake3::hash(format!("{endpoint}/{account}/{what}").as_bytes());
    hash.to_hex()[..32].to_owned()
}

/// Delivers an account's new events to the tenant's webhook endpoints, at least once and in
/// log order per endpoint and account.
///
/// Meant to run on the account's owner right after its worker ran (as an
/// [`AccountObserver`]), so only one node delivers an account at a time. Endpoints are served
/// concurrently; a failing endpoint backs off on its own without holding up others.
pub struct WebhookDelivery {
    store: WebhookStore,
    transport: Arc<dyn Transport>,
    clock: Arc<dyn Clock>,
}

impl WebhookDelivery {
    /// Delivery through `transport` on the system clock.
    pub fn new(store: WebhookStore, transport: Arc<dyn Transport>) -> Self {
        Self {
            store,
            transport,
            clock: Arc::new(SystemClock),
        }
    }

    /// Uses `clock` instead of the system clock.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Delivers whatever `account` has that its endpoints have not received yet: up to
    /// [`MAX_BATCHES_PER_RUN`] batches of up to [`BATCH_SIZE`] events per endpoint. A batch
    /// counts as delivered only on a `2xx`; then the cursor moves past it. Any other answer or
    /// error leaves the cursor, backs that endpoint off for this account ([`backoff_secs`]), and
    /// pauses the endpoint once failures have lasted [`PAUSE_AFTER_MS`]. Errors of one endpoint
    /// are logged and do not stop the others; only failing to list endpoints is returned.
    pub async fn deliver(
        &self,
        tenant: &TenantId,
        account: &AccountId,
    ) -> Result<DeliveryReport, WebhookError> {
        let endpoints: Vec<Endpoint> = self
            .store
            .list(tenant)
            .await?
            .into_iter()
            .filter(|e| !e.paused && e.wants_account(account))
            .collect();
        let results = futures::future::join_all(
            endpoints
                .iter()
                .map(|e| self.deliver_endpoint(tenant, account, e)),
        )
        .await;
        let mut report = DeliveryReport::default();
        for (endpoint, result) in endpoints.iter().zip(results) {
            match result {
                Ok(r) => report.add(r),
                Err(WebhookError::Storage(StorageError::Conflict)) => {
                    debug!(endpoint = %endpoint.id, %account, "webhook cursor changed meanwhile");
                }
                Err(e) => {
                    warn!(endpoint = %endpoint.id, %account, error = %e, "webhook delivery failed");
                }
            }
        }
        Ok(report)
    }

    async fn deliver_endpoint(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        endpoint: &Endpoint,
    ) -> Result<DeliveryReport, WebhookError> {
        let mut report = DeliveryReport::default();
        let path = cursor_path(&endpoint.id, account);
        let (mut cursor, mut version): (Cursor, Option<Version>) =
            match self.store.cursor(tenant, &path).await? {
                Some((c, v)) => (c, Some(v)),
                None => (Cursor::default(), None),
            };
        if cursor
            .next_attempt_at
            .is_some_and(|at| at > self.clock.now())
        {
            report.waiting += 1;
            return Ok(report);
        }
        let mut secret: Option<String> = None;
        for _ in 0..MAX_BATCHES_PER_RUN {
            let head = self.store.log.head(tenant, account).await?.0;
            if cursor.seq >= head {
                break;
            }
            let (batch, last, what) = match self
                .store
                .log
                .read(tenant, account, Seq(cursor.seq + 1), BATCH_SIZE)
                .await
            {
                Ok(events) => {
                    let Some(last) = events.last().map(|e| e.seq.0) else {
                        break;
                    };
                    let first = events[0].seq.0;
                    let events: Vec<_> = events
                        .into_iter()
                        .filter(|e| endpoint.wants_event(e))
                        .collect();
                    if events.is_empty() {
                        cursor.seq = last;
                        version = Some(
                            self.store
                                .save_cursor(tenant, &path, &cursor, version)
                                .await?,
                        );
                        continue;
                    }
                    let batch = Batch {
                        endpoint: endpoint.id.clone(),
                        tenant: tenant.clone(),
                        account: Some(account.clone()),
                        events,
                        compacted: None,
                        ping: false,
                    };
                    (batch, last, format!("{first}-{last}"))
                }
                Err(StorageError::Compacted { first }) => {
                    let batch = Batch {
                        endpoint: endpoint.id.clone(),
                        tenant: tenant.clone(),
                        account: Some(account.clone()),
                        events: Vec::new(),
                        compacted: Some(Compacted { first }),
                        ping: false,
                    };
                    (batch, first.saturating_sub(1), format!("compacted-{first}"))
                }
                Err(e) => return Err(e.into()),
            };
            let secret = match &secret {
                Some(s) => s.clone(),
                None => {
                    let s = self.store.secret(tenant, endpoint).await?;
                    secret = Some(s.clone());
                    s
                }
            };
            let count = batch.events.len();
            let body = Bytes::from(serde_json::to_vec(&batch).expect("batches serialize"));
            let now = self.clock.now();
            let started = Instant::now();
            let result = send_signed(
                &*self.transport,
                &endpoint.url,
                &secret,
                &batch_id(&endpoint.id, account, &what),
                now,
                body,
            )
            .await;
            let ms = started.elapsed().as_millis() as u64;
            match result {
                Ok(status) if (200..300).contains(&status) => {
                    debug!(endpoint = %endpoint.id, %account, status, events = count, ms, "webhook batch delivered");
                    cursor = Cursor {
                        seq: last,
                        last_status: Some(status),
                        delivered_at: Some(now),
                        ..Cursor::default()
                    };
                    version = Some(
                        self.store
                            .save_cursor(tenant, &path, &cursor, version)
                            .await?,
                    );
                    report.batches += 1;
                    report.events += count;
                }
                other => {
                    let (kind, status) = match other {
                        Ok(status) => ("http_status", Some(status)),
                        Err(e) => (e.kind(), None),
                    };
                    warn!(endpoint = %endpoint.id, %account, error = kind, status, ms, failures = cursor.failures + 1, "webhook batch failed");
                    cursor.failures += 1;
                    let since = *cursor.failing_since.get_or_insert(now);
                    cursor.next_attempt_at =
                        Some(now.plus_ms(backoff_secs(cursor.failures) as i64 * 1000));
                    cursor.last_error = Some(kind.to_owned());
                    cursor.last_status = status;
                    self.store
                        .save_cursor(tenant, &path, &cursor, version)
                        .await?;
                    report.failures += 1;
                    if now.0 - since.0 >= PAUSE_AFTER_MS {
                        warn!(endpoint = %endpoint.id, %account, "webhook endpoint paused after failing for 3 days");
                        self.store
                            .pause(
                                tenant,
                                &endpoint.id,
                                format!(
                                    "deliveries for account {account} failed for 3 days; last error: {kind}"
                                ),
                            )
                            .await?;
                    }
                    break;
                }
            }
        }
        Ok(report)
    }
}

#[async_trait]
impl AccountObserver for WebhookDelivery {
    async fn after_run(&self, tenant: &TenantId, account: &AccountId) -> Result<(), ObserverError> {
        self.deliver(tenant, account)
            .await
            .map(|_| ())
            .map_err(|e| ObserverError(e.to_string()))
    }
}
