//! [`DropService`]: the one implementation of the drop rules, over any [`DropStore`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use baton_core::Timestamp;
use baton_mailbox::{BoxId, BoxPolicy, MAX_TTL_MS, Message, MessageId};
use bytes::Bytes;
use tokio::sync::{Notify, Semaphore};

use crate::admission::AdmissionConfig;
use crate::replay::ReplayCache;
use crate::store::{Admitted, BoxInfo, DropStore, StoreError};
use crate::wire::{self, Body, Head, Opened, Reply, ServiceInfo, WireAdmission, WireMessage};
use crate::{Clock, ConfigError, DropError};

/// The largest message any service may accept.
pub const MAX_MESSAGE_CAP: u32 = 1024 * 1024;

/// Wire bytes a reply may spend per message besides the message itself.
const PER_MESSAGE_OVERHEAD: usize = 64;

/// The largest quotas a box may ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoxLimits {
    /// The largest byte quota.
    pub max_box_bytes: u64,
    /// The largest message quota.
    pub max_box_messages: u32,
    /// The longest time-to-live.
    pub max_ttl_ms: u64,
}

/// Operator settings of a drop service.
#[derive(Debug, Clone)]
pub struct DropConfig {
    /// The name requests are signed for (normally the public host name), so a request made for
    /// one service never verifies at another.
    pub realm: String,
    /// How far a request's timestamp may be from the service's clock, either way (default 5 min).
    pub freshness_ms: u32,
    /// Nonces remembered within the freshness window; when full of fresh ones, requests are
    /// refused with `Busy` (default 262,144, about 20 MiB).
    pub replay_capacity: usize,
    /// Nonces one box may hold in the replay cache; beyond this its requests are refused with
    /// `Busy` while other boxes are served (default 4,096, about 7 requests per second for ten
    /// minutes).
    pub replay_per_box: usize,
    /// The largest message (default 64 KiB, at most [`MAX_MESSAGE_CAP`]).
    pub max_message: u32,
    /// The largest byte quota a box admitted by a token may ask for (default 64 MiB).
    pub max_box_bytes: u64,
    /// The largest message quota a box admitted by a token may ask for (default 10,000).
    pub max_box_messages: u32,
    /// The longest time-to-live a box admitted by a token may ask for (default and at most 30
    /// days).
    pub max_ttl_ms: u64,
    /// The limits for boxes anybody can create (proof of work or an open service), each cut to
    /// the token limits (default 1 MiB, 1,000 messages, 7 days), so a few cheap boxes cannot
    /// claim the store.
    pub untrusted: BoxLimits,
    /// The longest a take waits (default 30 s).
    pub max_wait: Duration,
    /// The most messages one take returns (default 256).
    pub max_take: u32,
    /// The most message bytes one take returns (default 4 MiB, at least `max_message`).
    pub max_take_bytes: u32,
    /// Takes waiting at once; beyond this a take returns at once (default 10,000).
    pub max_waiters: usize,
    /// Takes waiting at once on one box; beyond this a take on that box returns at once
    /// (default 4).
    pub max_waiters_per_box: usize,
    /// Proof-of-work verifications running at once; beyond this creations get `Busy` (default 4).
    pub max_work_checks: usize,
    /// Who may create boxes.
    pub admission: AdmissionConfig,
}

impl DropConfig {
    /// The defaults for `realm` with `admission`.
    pub fn new(realm: impl Into<String>, admission: AdmissionConfig) -> Self {
        Self {
            realm: realm.into(),
            freshness_ms: 5 * 60 * 1000,
            replay_capacity: 1 << 18,
            replay_per_box: 4096,
            max_message: baton_mailbox::DEFAULT_MAX_MESSAGE as u32,
            max_box_bytes: 64 * 1024 * 1024,
            max_box_messages: 10_000,
            max_ttl_ms: MAX_TTL_MS,
            untrusted: BoxLimits {
                max_box_bytes: 1024 * 1024,
                max_box_messages: 1_000,
                max_ttl_ms: 7 * 24 * 3600 * 1000,
            },
            max_wait: Duration::from_secs(30),
            max_take: 256,
            max_take_bytes: 4 * 1024 * 1024,
            max_waiters: 10_000,
            max_waiters_per_box: 4,
            max_work_checks: 4,
            admission,
        }
    }

    /// Whether the settings are usable.
    pub fn check(&self) -> Result<(), ConfigError> {
        let realm_ok = !self.realm.is_empty()
            && self.realm.len() <= wire::MAX_REALM
            && self.realm.bytes().all(|b| b.is_ascii_graphic());
        if !realm_ok {
            return Err(ConfigError("realm must be 1 to 128 printable ASCII bytes"));
        }
        if self.max_message == 0 || self.max_message > MAX_MESSAGE_CAP {
            return Err(ConfigError("max_message must be 1 byte to 1 MiB"));
        }
        if self.max_take == 0 || self.max_take_bytes < self.max_message {
            return Err(ConfigError("takes must fit at least one largest message"));
        }
        if self.untrusted.max_ttl_ms < baton_mailbox::MIN_TTL_MS {
            return Err(ConfigError("untrusted box time-to-live below the minimum"));
        }
        if self.freshness_ms == 0
            || self.replay_capacity == 0
            || self.replay_per_box == 0
            || self.max_waiters_per_box == 0
            || self.max_work_checks == 0
            || self.max_ttl_ms > MAX_TTL_MS
            || self.max_ttl_ms < baton_mailbox::MIN_TTL_MS
            || self.max_wait > Duration::from_secs(300)
        {
            return Err(ConfigError("limit out of range"));
        }
        Ok(())
    }
}

/// The drop service: checks and executes requests against a [`DropStore`].
///
/// For every request, in this order: size, version, encoding, body hash, freshness, signature
/// (all in [`wire::open`]); then the box and the key's role; then admission for creations; then
/// the nonce is recorded (check, then commit); then the store executes it atomically. Logs
/// nothing.
pub struct DropService {
    store: Arc<dyn DropStore>,
    config: DropConfig,
    clock: Clock,
    replay: Mutex<ReplayCache>,
    pub(crate) waiters: Mutex<HashMap<BoxId, (Arc<Notify>, usize)>>,
    poll_slots: Arc<Semaphore>,
    work_slots: Arc<Semaphore>,
}

impl DropService {
    /// A service over `store` judging time by `clock`.
    pub fn new(
        store: Arc<dyn DropStore>,
        config: DropConfig,
        clock: Clock,
    ) -> Result<Self, ConfigError> {
        config.check()?;
        Ok(Self {
            store,
            replay: Mutex::new(ReplayCache::new(
                config.replay_capacity,
                config.replay_per_box,
            )),
            waiters: Mutex::new(HashMap::new()),
            poll_slots: Arc::new(Semaphore::new(config.max_waiters)),
            work_slots: Arc::new(Semaphore::new(config.max_work_checks)),
            config,
            clock,
        })
    }

    /// The settings.
    pub fn config(&self) -> &DropConfig {
        &self.config
    }

    /// What clients need to know.
    pub fn info(&self) -> ServiceInfo {
        let a = &self.config.admission;
        ServiceInfo {
            realm: self.config.realm.clone(),
            max_message: self.config.max_message,
            max_wait_ms: self.config.max_wait.as_millis() as u32,
            max_take: self.config.max_take,
            max_take_bytes: self.config.max_take_bytes,
            freshness_ms: self.config.freshness_ms,
            open: a.is_open(),
            tokens: a.has_tokens(),
            work: a.work().cloned(),
        }
    }

    /// The largest request accepted.
    pub fn max_request(&self) -> usize {
        self.config.max_message as usize + wire::OVERHEAD
    }

    /// The largest reply produced.
    pub fn max_reply(&self) -> usize {
        max_reply(&self.info())
    }

    /// Handles one raw request and returns the encoded reply.
    pub async fn handle(&self, raw: &[u8]) -> Vec<u8> {
        self.handle_with(raw, true).await
    }

    /// Like [`DropService::handle`]; with `may_wait` false a take returns at once instead of
    /// waiting (the HTTP server's long-poll budget is spent).
    pub async fn handle_with(&self, raw: &[u8], may_wait: bool) -> Vec<u8> {
        wire::encode_reply(&self.execute_with(raw, may_wait).await)
    }

    /// Handles one raw request.
    pub async fn execute(&self, raw: &[u8]) -> Result<Reply, DropError> {
        self.execute_with(raw, true).await
    }

    /// Like [`DropService::execute`]; with `may_wait` false a take never waits.
    pub async fn execute_with(&self, raw: &[u8], may_wait: bool) -> Result<Reply, DropError> {
        let now = (self.clock)();
        let Opened { head, body } = wire::open(
            raw,
            &self.config.realm,
            now,
            i64::from(self.config.freshness_ms),
            self.max_request(),
        )?;
        match &body {
            Body::Create { policy, admission } => self.create(&head, policy, admission, now).await,
            Body::Put { bytes } => self.put(&head, bytes.clone(), now).await,
            Body::Take {
                after,
                limit,
                wait_ms,
            } => {
                self.reader_box(&head, now).await?;
                self.commit(&head, now)?;
                let limit = (*limit).clamp(1, self.config.max_take);
                let wait = if may_wait {
                    Duration::from_millis(u64::from(*wait_ms)).min(self.config.max_wait)
                } else {
                    Duration::ZERO
                };
                self.take(&head.box_id, after.map(MessageId), limit, wait)
                    .await
            }
            Body::Ack { up_to } => {
                self.reader_box(&head, now).await?;
                self.commit(&head, now)?;
                self.store
                    .ack(&head.box_id, MessageId(*up_to), now)
                    .await
                    .map_err(store_err)?;
                Ok(Reply::Done)
            }
            Body::SetWriters { writers, version } => {
                baton_mailbox::check_writers(writers).map_err(|_| DropError::InvalidPolicy)?;
                self.reader_box(&head, now).await?;
                self.commit(&head, now)?;
                self.store
                    .set_writers(&head.box_id, writers, *version, now)
                    .await
                    .map_err(store_err)?;
                Ok(Reply::Done)
            }
            Body::Delete => {
                self.reader_box(&head, now).await?;
                self.commit(&head, now)?;
                self.store
                    .delete(&head.box_id, now)
                    .await
                    .map_err(store_err)?;
                self.notify(&head.box_id);
                Ok(Reply::Done)
            }
        }
    }

    /// Removes idle boxes and expired messages now; returns how many it removed.
    pub async fn sweep(&self) -> Result<u64, DropError> {
        self.store.sweep((self.clock)()).await.map_err(store_err)
    }

    async fn create(
        &self,
        head: &Head,
        policy: &BoxPolicy,
        admission: &WireAdmission,
        now: Timestamp,
    ) -> Result<Reply, DropError> {
        policy.check().map_err(|_| DropError::InvalidPolicy)?;
        if !self.within(policy, &self.token_limits()) {
            return Err(DropError::InvalidPolicy);
        }
        if head.key != policy.reader || head.box_id != BoxId::of_reader(&policy.reader) {
            return Err(DropError::Denied);
        }
        if self.get(&head.box_id, now).await?.is_some() {
            return Err(DropError::Exists);
        }
        let admitted = self.admit(&head.box_id, admission).await?;
        if admitted.untrusted() && !self.within(policy, &self.config.untrusted) {
            return Err(DropError::InvalidPolicy);
        }
        self.commit(head, now)?;
        self.store
            .create(&head.box_id, policy, admitted, now)
            .await
            .map_err(store_err)?;
        Ok(Reply::Done)
    }

    fn token_limits(&self) -> BoxLimits {
        BoxLimits {
            max_box_bytes: self.config.max_box_bytes,
            max_box_messages: self.config.max_box_messages,
            max_ttl_ms: self.config.max_ttl_ms,
        }
    }

    fn within(&self, policy: &BoxPolicy, limits: &BoxLimits) -> bool {
        policy.max_bytes <= limits.max_box_bytes
            && policy.max_messages <= limits.max_box_messages
            && policy.ttl_ms <= limits.max_ttl_ms
    }

    async fn admit(&self, id: &BoxId, admission: &WireAdmission) -> Result<Admitted, DropError> {
        let a = &self.config.admission;
        if let WireAdmission::Token(t) = admission
            && a.accepts_token(t)
        {
            return Ok(Admitted::Token);
        }
        if a.is_open() {
            return Ok(Admitted::Open);
        }
        match admission {
            WireAdmission::Work(nonce) => {
                let Some(work) = a.work().cloned() else {
                    return Err(DropError::Admission);
                };
                let _permit = self
                    .work_slots
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| DropError::Busy)?;
                let (id, nonce) = (*id, *nonce);
                let ok = tokio::task::spawn_blocking(move || work.verify(&id, nonce))
                    .await
                    .map_err(|_| DropError::Unavailable)?;
                if ok {
                    Ok(Admitted::Work)
                } else {
                    Err(DropError::Admission)
                }
            }
            _ => Err(DropError::Admission),
        }
    }

    async fn put(&self, head: &Head, bytes: Bytes, now: Timestamp) -> Result<Reply, DropError> {
        if bytes.len() > self.config.max_message as usize {
            return Err(DropError::TooLarge);
        }
        let info = self
            .get(&head.box_id, now)
            .await?
            .ok_or(DropError::UnknownBox)?;
        if !info.policy.writers.contains(&head.key) {
            return Err(DropError::Denied);
        }
        self.commit(head, now)?;
        let id = self
            .store
            .append(&head.box_id, &head.key, bytes, now)
            .await
            .map_err(store_err)?;
        self.notify(&head.box_id);
        Ok(Reply::Stored(id.0))
    }

    async fn take(
        &self,
        id: &BoxId,
        after: Option<MessageId>,
        limit: u32,
        wait: Duration,
    ) -> Result<Reply, DropError> {
        let mut found = self.read(id, after, limit).await?;
        if found.is_empty()
            && !wait.is_zero()
            && let Ok(_slot) = self.poll_slots.clone().try_acquire_owned()
            && let Some(waiter) = Waiter::try_new(self, id)
        {
            let notified = waiter.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            found = self.read(id, after, limit).await?;
            if found.is_empty() {
                let _ = tokio::time::timeout(wait, notified).await;
                found = self.read(id, after, limit).await?;
            }
        }
        Ok(Reply::Messages(self.trim(found)))
    }

    async fn read(
        &self,
        id: &BoxId,
        after: Option<MessageId>,
        limit: u32,
    ) -> Result<Vec<Message>, DropError> {
        self.store
            .read(id, after, limit, (self.clock)())
            .await
            .map_err(store_err)
    }

    fn trim(&self, found: Vec<Message>) -> Vec<WireMessage> {
        let mut total = 0usize;
        let mut out = Vec::with_capacity(found.len());
        for m in found {
            total += m.bytes.len();
            if !out.is_empty() && total > self.config.max_take_bytes as usize {
                break;
            }
            out.push(WireMessage {
                id: m.id.0,
                at: m.stored_at,
                bytes: m.bytes,
            });
        }
        out
    }

    async fn get(&self, id: &BoxId, now: Timestamp) -> Result<Option<BoxInfo>, DropError> {
        self.store.get(id, now).await.map_err(store_err)
    }

    async fn reader_box(&self, head: &Head, now: Timestamp) -> Result<BoxInfo, DropError> {
        let info = self
            .get(&head.box_id, now)
            .await?
            .ok_or(DropError::UnknownBox)?;
        if info.policy.reader != head.key {
            return Err(DropError::Denied);
        }
        Ok(info)
    }

    fn commit(&self, head: &Head, now: Timestamp) -> Result<(), DropError> {
        let mut k = blake3::Hasher::new();
        k.update(&head.key.to_bytes());
        k.update(&head.nonce);
        let expires = head
            .at
            .0
            .saturating_add(i64::from(self.config.freshness_ms));
        self.replay.lock().expect("replay lock").insert(
            *k.finalize().as_bytes(),
            head.box_id,
            expires,
            now.0,
        )
    }

    fn notify(&self, id: &BoxId) {
        if let Some((n, _)) = self.waiters.lock().expect("waiters lock").get(id) {
            n.notify_waiters();
        }
    }
}

struct Waiter<'a> {
    service: &'a DropService,
    id: BoxId,
    notify: Arc<Notify>,
}

impl<'a> Waiter<'a> {
    /// A waiter on box `id`, unless the box already has its share of waiters.
    fn try_new(service: &'a DropService, id: &BoxId) -> Option<Self> {
        let mut w = service.waiters.lock().expect("waiters lock");
        let entry = w.entry(*id).or_insert_with(|| (Arc::new(Notify::new()), 0));
        if entry.1 >= service.config.max_waiters_per_box {
            return None;
        }
        entry.1 += 1;
        Some(Self {
            service,
            id: *id,
            notify: entry.0.clone(),
        })
    }
}

impl Drop for Waiter<'_> {
    fn drop(&mut self) {
        let mut w = self.service.waiters.lock().expect("waiters lock");
        if let Some(entry) = w.get_mut(&self.id) {
            entry.1 = entry.1.saturating_sub(1);
            if entry.1 == 0 {
                w.remove(&self.id);
            }
        }
    }
}

/// The largest reply a service with `info` produces.
pub fn max_reply(info: &ServiceInfo) -> usize {
    info.max_take_bytes as usize + info.max_take as usize * PER_MESSAGE_OVERHEAD + 1024
}

fn store_err(e: StoreError) -> DropError {
    match e {
        StoreError::Exists => DropError::Exists,
        StoreError::Missing => DropError::UnknownBox,
        StoreError::Denied => DropError::Denied,
        StoreError::Quota => DropError::Quota,
        StoreError::Conflict => DropError::Conflict,
        StoreError::Backend(_) => DropError::Unavailable,
    }
}
