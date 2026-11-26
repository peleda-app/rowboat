use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use skein_core::{AccountId, TenantId, Timestamp};
use skein_keyring::{KeyScope, Keyring};
use skein_storage::{
    ControlStore, Expect, Log, StorageError, Version, decode_record, encode_record,
};

use crate::model::{Batch, Cursor, EVENT_TYPES, Endpoint};
use crate::signature::new_secret;
use crate::{SendError, Transport, WebhookError, WebhookPolicy, send_signed};

/// Most entries in an endpoint's `events` or `accounts` filter.
pub const MAX_FILTER: usize = 100;

const PAGE: usize = 1000;

/// What a new endpoint needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEndpoint {
    /// Where batches go; checked against the policy, host name resolution included.
    pub url: String,
    /// Only these event types, when set.
    pub events: Option<Vec<String>>,
    /// Only these accounts, when set.
    pub accounts: Option<Vec<AccountId>>,
}

/// Changes to an endpoint; `None` leaves a field as it is, `Some(None)` clears a filter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EndpointPatch {
    /// A new address, checked like at creation.
    pub url: Option<String>,
    /// A new event filter.
    pub events: Option<Option<Vec<String>>>,
    /// A new account filter.
    pub accounts: Option<Option<Vec<AccountId>>>,
    /// Pause or resume. Resuming clears the pause reason and the failure state of every
    /// cursor, so the next run tries at once.
    pub paused: Option<bool>,
}

/// Delivery of one account to an endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryState {
    /// The account.
    pub account: AccountId,
    /// Its cursor.
    pub cursor: Cursor,
}

/// Webhook endpoints and their cursors in a tenant's control records, with secrets sealed by
/// the keyring. Every write is a compare-and-swap, so concurrent changes from the API and from
/// the delivering node never overwrite each other silently.
#[derive(Clone)]
pub struct WebhookStore {
    pub(crate) control: Arc<dyn ControlStore>,
    pub(crate) log: Arc<dyn Log>,
    pub(crate) keyring: Arc<dyn Keyring>,
}

/// Control path of an endpoint.
pub fn endpoint_path(id: &str) -> String {
    format!("webhooks/{id}")
}

/// Control path of an endpoint's cursor for an account.
pub fn cursor_path(id: &str, account: &AccountId) -> String {
    format!("webhook-cursors/{id}/{account}")
}

fn context(id: &str) -> String {
    format!("webhooks/{id}")
}

/// Whether `id` is a lowercase ULID, the only form endpoint ids take.
pub fn valid_id(id: &str) -> bool {
    id.len() == 26
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
        && ulid::Ulid::from_string(&id.to_ascii_uppercase()).is_ok()
}

fn check_filters(
    events: &Option<Vec<String>>,
    accounts: &Option<Vec<AccountId>>,
) -> Result<(), WebhookError> {
    if let Some(events) = events {
        if events.is_empty() || events.len() > MAX_FILTER {
            return Err(WebhookError::Invalid("events holds 1 to 100 event types"));
        }
        if !events.iter().all(|e| EVENT_TYPES.contains(&e.as_str())) {
            return Err(WebhookError::Invalid("events holds an unknown event type"));
        }
    }
    if let Some(accounts) = accounts
        && (accounts.is_empty() || accounts.len() > MAX_FILTER)
    {
        return Err(WebhookError::Invalid("accounts holds 1 to 100 account ids"));
    }
    Ok(())
}

impl WebhookStore {
    /// A store over a tenant's control records, its log (for the heads new endpoints start at)
    /// and the keyring.
    pub fn new(
        control: Arc<dyn ControlStore>,
        log: Arc<dyn Log>,
        keyring: Arc<dyn Keyring>,
    ) -> Self {
        Self {
            control,
            log,
            keyring,
        }
    }

    async fn seal(
        &self,
        tenant: &TenantId,
        id: &str,
        secret: &str,
    ) -> Result<String, WebhookError> {
        let sealed = self
            .keyring
            .seal(
                &KeyScope::tenant_of(tenant),
                &context(id),
                secret.as_bytes(),
            )
            .await?;
        Ok(URL_SAFE_NO_PAD.encode(sealed))
    }

    /// Creates an endpoint and returns it with its secret, the only time the secret is shown
    /// besides [`WebhookStore::rotate`].
    ///
    /// The address is checked with [`WebhookPolicy::check`]; a host that does not resolve is
    /// refused. Every account that already has a log starts at its current head, so the
    /// endpoint gets changes from now on; accounts without a log yet start at the beginning.
    pub async fn create(
        &self,
        tenant: &TenantId,
        new: NewEndpoint,
        policy: &WebhookPolicy,
    ) -> Result<(Endpoint, String), WebhookError> {
        check_filters(&new.events, &new.accounts)?;
        let url = policy.check(&new.url).await?;
        let id = ulid::Ulid::generate().to_string().to_ascii_lowercase();
        let secret = new_secret()?;
        let endpoint = Endpoint {
            sealed_secret: self.seal(tenant, &id, &secret).await?,
            id,
            url: url.to_string(),
            events: new.events,
            accounts: new.accounts,
            created_at: Timestamp::now(),
            paused: false,
            paused_reason: None,
        };
        for (account, head) in self.log.heads(tenant).await? {
            let cursor = Cursor {
                seq: head.0,
                ..Cursor::default()
            };
            self.control
                .put(
                    tenant,
                    &cursor_path(&endpoint.id, &account),
                    encode_record(&cursor)?,
                    Expect::Any,
                )
                .await?;
        }
        self.control
            .put(
                tenant,
                &endpoint_path(&endpoint.id),
                encode_record(&endpoint)?,
                Expect::Absent,
            )
            .await?;
        Ok((endpoint, secret))
    }

    /// The endpoint and its version; `None` when missing or when `id` is not an endpoint id.
    pub async fn get(
        &self,
        tenant: &TenantId,
        id: &str,
    ) -> Result<Option<(Endpoint, Version)>, WebhookError> {
        if !valid_id(id) {
            return Ok(None);
        }
        match self.control.get(tenant, &endpoint_path(id)).await? {
            Some((bytes, version)) => Ok(Some((decode_record(&bytes)?, version))),
            None => Ok(None),
        }
    }

    async fn paths(&self, tenant: &TenantId, prefix: &str) -> Result<Vec<String>, WebhookError> {
        let mut out = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let page = self
                .control
                .list(tenant, prefix, after.as_deref(), PAGE)
                .await?;
            let full = page.len() == PAGE;
            after = page.last().cloned();
            out.extend(page);
            if !full {
                return Ok(out);
            }
        }
    }

    /// Every endpoint of the tenant, by id. Records that no longer exist when read are skipped.
    pub async fn list(&self, tenant: &TenantId) -> Result<Vec<Endpoint>, WebhookError> {
        let mut out = Vec::new();
        for path in self.paths(tenant, "webhooks").await? {
            if let Some((bytes, _)) = self.control.get(tenant, &path).await? {
                out.push(decode_record(&bytes)?);
            }
        }
        Ok(out)
    }

    /// Applies `patch`, retrying when the record changed meanwhile.
    pub async fn update(
        &self,
        tenant: &TenantId,
        id: &str,
        patch: EndpointPatch,
        policy: &WebhookPolicy,
    ) -> Result<Endpoint, WebhookError> {
        let url = match &patch.url {
            Some(url) => Some(policy.check(url).await?.to_string()),
            None => None,
        };
        let resumed = loop {
            let (mut endpoint, version) =
                self.get(tenant, id).await?.ok_or(WebhookError::NotFound)?;
            if let Some(url) = &url {
                endpoint.url = url.clone();
            }
            if let Some(events) = &patch.events {
                endpoint.events = events.clone();
            }
            if let Some(accounts) = &patch.accounts {
                endpoint.accounts = accounts.clone();
            }
            check_filters(&endpoint.events, &endpoint.accounts)?;
            let mut resumed = false;
            if let Some(paused) = patch.paused {
                resumed = endpoint.paused && !paused;
                endpoint.paused = paused;
                if !paused {
                    endpoint.paused_reason = None;
                }
            }
            match self
                .control
                .put(
                    tenant,
                    &endpoint_path(id),
                    encode_record(&endpoint)?,
                    Expect::Version(version),
                )
                .await
            {
                Ok(_) => break resumed.then_some(endpoint),
                Err(StorageError::Conflict) => continue,
                Err(e) => return Err(e.into()),
            }
        };
        match resumed {
            Some(endpoint) => {
                self.reset_failures(tenant, id).await?;
                Ok(endpoint)
            }
            None => Ok(self.get(tenant, id).await?.ok_or(WebhookError::NotFound)?.0),
        }
    }

    async fn reset_failures(&self, tenant: &TenantId, id: &str) -> Result<(), WebhookError> {
        for path in self.paths(tenant, &format!("webhook-cursors/{id}")).await? {
            for _ in 0..5 {
                let Some((bytes, version)) = self.control.get(tenant, &path).await? else {
                    break;
                };
                let mut cursor: Cursor = decode_record(&bytes)?;
                cursor.failures = 0;
                cursor.failing_since = None;
                cursor.next_attempt_at = None;
                match self
                    .control
                    .put(
                        tenant,
                        &path,
                        encode_record(&cursor)?,
                        Expect::Version(version),
                    )
                    .await
                {
                    Ok(_) => break,
                    Err(StorageError::Conflict) => continue,
                    Err(e) => return Err(e.into()),
                }
            }
        }
        Ok(())
    }

    /// Replaces the secret and returns the new one; the old one stops working for requests
    /// signed from now on.
    pub async fn rotate(&self, tenant: &TenantId, id: &str) -> Result<String, WebhookError> {
        let secret = new_secret()?;
        let sealed = self.seal(tenant, id, &secret).await?;
        loop {
            let (mut endpoint, version) =
                self.get(tenant, id).await?.ok_or(WebhookError::NotFound)?;
            endpoint.sealed_secret = sealed.clone();
            match self
                .control
                .put(
                    tenant,
                    &endpoint_path(id),
                    encode_record(&endpoint)?,
                    Expect::Version(version),
                )
                .await
            {
                Ok(_) => return Ok(secret),
                Err(StorageError::Conflict) => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Deletes the endpoint, then its cursors. `false` when there was no such endpoint.
    pub async fn delete(&self, tenant: &TenantId, id: &str) -> Result<bool, WebhookError> {
        if self.get(tenant, id).await?.is_none() {
            return Ok(false);
        }
        self.control
            .delete(tenant, &endpoint_path(id), Expect::Any)
            .await?;
        for path in self.paths(tenant, &format!("webhook-cursors/{id}")).await? {
            self.control.delete(tenant, &path, Expect::Any).await?;
        }
        Ok(true)
    }

    /// The cursor of every account the endpoint has delivered to or started at, by account.
    pub async fn deliveries(
        &self,
        tenant: &TenantId,
        id: &str,
    ) -> Result<Vec<DeliveryState>, WebhookError> {
        let prefix = format!("webhook-cursors/{id}");
        let mut out = Vec::new();
        for path in self.paths(tenant, &prefix).await? {
            let Some(account) = path.rsplit('/').next().and_then(|a| AccountId::new(a).ok()) else {
                continue;
            };
            if let Some((bytes, _)) = self.control.get(tenant, &path).await? {
                out.push(DeliveryState {
                    account,
                    cursor: decode_record(&bytes)?,
                });
            }
        }
        Ok(out)
    }

    /// Opens the endpoint's secret.
    pub async fn secret(
        &self,
        tenant: &TenantId,
        endpoint: &Endpoint,
    ) -> Result<String, WebhookError> {
        let sealed = URL_SAFE_NO_PAD
            .decode(&endpoint.sealed_secret)
            .map_err(|_| StorageError::Corrupt("sealed webhook secret".into()))?;
        let plain = self
            .keyring
            .open(
                &KeyScope::tenant_of(tenant),
                &context(&endpoint.id),
                &sealed,
            )
            .await?;
        String::from_utf8(plain).map_err(|_| StorageError::Corrupt("webhook secret".into()).into())
    }

    /// Sends one signed ping (`"ping": true`, no events) through `transport`, paused or not,
    /// and returns what came of it. Cursors are not touched.
    pub async fn ping(
        &self,
        tenant: &TenantId,
        id: &str,
        transport: &dyn Transport,
    ) -> Result<Result<u16, SendError>, WebhookError> {
        let (endpoint, _) = self.get(tenant, id).await?.ok_or(WebhookError::NotFound)?;
        let secret = self.secret(tenant, &endpoint).await?;
        let batch = Batch {
            endpoint: endpoint.id.clone(),
            tenant: tenant.clone(),
            account: None,
            events: Vec::new(),
            compacted: None,
            ping: true,
        };
        let body = Bytes::from(serde_json::to_vec(&batch).expect("batches serialize"));
        let batch_id = format!(
            "ping-{}",
            ulid::Ulid::generate().to_string().to_ascii_lowercase()
        );
        Ok(send_signed(
            transport,
            &endpoint.url,
            &secret,
            &batch_id,
            Timestamp::now(),
            body,
        )
        .await)
    }

    pub(crate) async fn cursor(
        &self,
        tenant: &TenantId,
        path: &str,
    ) -> Result<Option<(Cursor, Version)>, WebhookError> {
        match self.control.get(tenant, path).await? {
            Some((bytes, version)) => Ok(Some((decode_record(&bytes)?, version))),
            None => Ok(None),
        }
    }

    pub(crate) async fn save_cursor(
        &self,
        tenant: &TenantId,
        path: &str,
        cursor: &Cursor,
        version: Option<Version>,
    ) -> Result<Version, WebhookError> {
        let expect = version.map_or(Expect::Absent, Expect::Version);
        Ok(self
            .control
            .put(tenant, path, encode_record(cursor)?, expect)
            .await?)
    }

    /// Pauses the endpoint with `reason` unless it is paused already or gone.
    pub(crate) async fn pause(
        &self,
        tenant: &TenantId,
        id: &str,
        reason: String,
    ) -> Result<(), WebhookError> {
        loop {
            let Some((mut endpoint, version)) = self.get(tenant, id).await? else {
                return Ok(());
            };
            if endpoint.paused {
                return Ok(());
            }
            endpoint.paused = true;
            endpoint.paused_reason = Some(reason.clone());
            match self
                .control
                .put(
                    tenant,
                    &endpoint_path(id),
                    encode_record(&endpoint)?,
                    Expect::Version(version),
                )
                .await
            {
                Ok(_) => return Ok(()),
                Err(StorageError::Conflict) => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }
}
