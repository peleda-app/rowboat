//! Push from outside: providers (Gmail through Cloud Pub/Sub, Microsoft Graph through change
//! notifications) call our public endpoint instead of us holding a connection.
//!
//! [`PushRegistry`] maps an incoming notification, which names no tenant, to the account it is
//! for, and turns it into a hint on the signal topic [`hint_topic`] in that tenant's group.
//! [`Renewer`] keeps each account's subscription alive through the provider. Nothing here calls a
//! provider while handling a notification, so a flood of posts can never become a flood of
//! provider requests; only [`Renewer`] talks to providers, from the account's worker.
//!
//! Notifications are hints. A lost one only delays a sync until the next notification or poll.
//!
//! Layout in the object store:
//!
//! - `system/push/graph/{subscription_id}` → tenant, account, BLAKE3 of the `clientState`, expiry
//! - `system/push/gmail/{blake3(lowercased address)}` → tenant, account, expiry
//! - `tenants/{t}/control/push/{account}` → the account's [`PushState`]

mod notify;

#[cfg(test)]
mod tests;

use std::collections::BTreeSet;
use std::sync::Arc;

use base64::Engine;
use baton_signal::{Signal, SignalError};
use bytes::Bytes;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use skein_core::{AccountId, TenantId, Timestamp, coordination};
use skein_mail::{MailError, MailProvider};
use skein_storage::{
    ControlStore, Expect, Migrate, ObjectKey, Objects, StorageError, decode_record, encode_record,
};
use subtle::ConstantTimeEq;
use tracing::{debug, warn};

pub use skein_mail::{PUSH_GMAIL, PUSH_GRAPH, PushTarget, Subscription};

pub use notify::{
    GmailNotification, GraphNotification, MAX_GRAPH_ITEMS, MAX_VALIDATION_TOKEN, parse_gmail,
    parse_graph, validation_token,
};

/// Errors of push handling.
#[derive(Debug, thiserror::Error)]
pub enum PushError {
    /// Storage failed.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// The provider failed.
    #[error(transparent)]
    Mail(#[from] MailError),
    /// The signal backend failed.
    #[error(transparent)]
    Signal(#[from] SignalError),
    /// A subscription of a kind the registry cannot route (neither Gmail nor Graph).
    #[error("subscriptions of this kind cannot be routed")]
    Unsupported,
    /// A notification body that does not parse.
    #[error("the notification does not parse")]
    Invalid,
    /// No randomness was available.
    #[error("no randomness available")]
    Random,
}

/// The signal topic, in the tenant's group, that gets a message whenever a notification for `account`
/// is accepted. The account's worker listens there, next to `commands/{account}`.
pub fn hint_topic(account: &AccountId) -> String {
    format!("push/{account}")
}

/// A fresh random `clientState`: 32 random bytes as unpadded base64url (43 characters).
pub fn random_client_state() -> Result<String, PushError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| PushError::Random)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// `{public_url}/v1/push/graph`, the address Graph subscriptions point at.
pub fn graph_url(public_url: &str) -> String {
    format!("{}/v1/push/graph", public_url.trim_end_matches('/'))
}

/// The record of an account's subscription, at its tenant's control path `push/{account}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushState {
    /// The subscription as the provider last confirmed it.
    pub subscription: Subscription,
    /// When it was made or last renewed.
    pub renewed_at: Timestamp,
    /// BLAKE3 of the target's address and topic, to notice when they change.
    pub target_hash: String,
    /// Set by a lifecycle notification; the next [`Renewer::ensure`] renews at once.
    #[serde(default)]
    pub renew_now: bool,
}

impl Migrate for PushState {
    const VERSION: u16 = 1;
}

impl PushState {
    /// When to renew: once less than a third of the lifetime (from `renewed_at` to
    /// `expires_at`) is left, or at once when `renew_now` is set.
    pub fn renew_at(&self) -> Timestamp {
        if self.renew_now {
            return Timestamp(0);
        }
        let start = self.renewed_at.0;
        let end = self.subscription.expires_at.0;
        if end <= start {
            return Timestamp(start);
        }
        Timestamp(start + (end - start) / 3 * 2)
    }
}

#[derive(Serialize, Deserialize)]
struct GraphEntry {
    tenant: TenantId,
    account: AccountId,
    client_state_hash: String,
    expires_at: Timestamp,
}

impl Migrate for GraphEntry {
    const VERSION: u16 = 1;
}

#[derive(Serialize, Deserialize)]
struct GmailEntry {
    tenant: TenantId,
    account: AccountId,
    expires_at: Timestamp,
}

impl Migrate for GmailEntry {
    const VERSION: u16 = 1;
}

fn hash(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

fn email_hash(email: &str) -> String {
    hash(&email.trim().to_lowercase())
}

fn same_hash(stored: &str, presented: &str) -> bool {
    let presented = hash(presented);
    stored.len() == presented.len() && bool::from(stored.as_bytes().ct_eq(presented.as_bytes()))
}

fn target_hash(target: &PushTarget) -> String {
    hash(&format!(
        "{}\n{}",
        target.url,
        target.gmail_topic.as_deref().unwrap_or("")
    ))
}

fn state_path(account: &AccountId) -> String {
    format!("push/{account}")
}

/// How many accepted notifications became hints, after removing duplicates per account.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Accepted {
    /// Items read from the post.
    pub received: usize,
    /// Accounts that got a hint.
    pub hinted: usize,
}

/// Routes notifications to accounts and keeps each account's subscription record.
///
/// Registry entries live at the object store root because notifications name no tenant. An
/// entry is written by the account's owner only (through [`Renewer`]); lookups only read. A
/// Gmail address registered by two accounts routes to the one registered last.
#[derive(Clone)]
pub struct PushRegistry {
    objects: Arc<dyn Objects>,
    control: Arc<dyn ControlStore>,
}

impl PushRegistry {
    /// A registry in `objects` (the root object store, as for `TenantRegistry`) with account
    /// records in `control`.
    pub fn new(objects: Arc<dyn Objects>, control: Arc<dyn ControlStore>) -> Self {
        Self { objects, control }
    }

    fn prefix(kind: &str) -> ObjectKey {
        ObjectKey::root("system")
            .and_then(|k| k.join("push"))
            .and_then(|k| k.join(kind))
            .expect("constant")
    }

    fn graph_key(id: &str) -> Option<ObjectKey> {
        Self::prefix(PUSH_GRAPH).join(id).ok()
    }

    fn gmail_key(email: &str) -> ObjectKey {
        Self::prefix(PUSH_GMAIL)
            .join(&email_hash(email))
            .expect("hex is a valid segment")
    }

    fn key(sub: &Subscription) -> Result<ObjectKey, PushError> {
        match sub.provider_kind.as_str() {
            PUSH_GRAPH => Self::graph_key(&sub.id).ok_or(PushError::Unsupported),
            PUSH_GMAIL => Ok(Self::gmail_key(&sub.resource)),
            _ => Err(PushError::Unsupported),
        }
    }

    /// Routes notifications for `sub` to `tenant`/`account`. For Graph only the BLAKE3 hash of
    /// `client_state` is kept. Registering again overwrites. `Unsupported` for other kinds or a
    /// Graph id that cannot be a key segment.
    pub async fn register(
        &self,
        sub: &Subscription,
        tenant: &TenantId,
        account: &AccountId,
        client_state: &str,
    ) -> Result<(), PushError> {
        let key = Self::key(sub)?;
        let value = match sub.provider_kind.as_str() {
            PUSH_GRAPH => encode_record(&GraphEntry {
                tenant: tenant.clone(),
                account: account.clone(),
                client_state_hash: hash(client_state),
                expires_at: sub.expires_at,
            })?,
            _ => encode_record(&GmailEntry {
                tenant: tenant.clone(),
                account: account.clone(),
                expires_at: sub.expires_at,
            })?,
        };
        self.objects.put(&key, value, Expect::Any).await?;
        Ok(())
    }

    /// Updates the expiry of an existing entry for `sub` owned by `tenant`/`account`, keeping its
    /// client state hash. `false` when there is no such entry.
    async fn touch(
        &self,
        sub: &Subscription,
        tenant: &TenantId,
        account: &AccountId,
    ) -> Result<bool, PushError> {
        let key = Self::key(sub)?;
        let Some((bytes, version)) = self.objects.get(&key).await? else {
            return Ok(false);
        };
        let value = match sub.provider_kind.as_str() {
            PUSH_GRAPH => {
                let mut entry: GraphEntry = decode_record(&bytes)?;
                if (&entry.tenant, &entry.account) != (tenant, account) {
                    return Ok(false);
                }
                entry.expires_at = sub.expires_at;
                encode_record(&entry)?
            }
            _ => {
                let mut entry: GmailEntry = decode_record(&bytes)?;
                if (&entry.tenant, &entry.account) != (tenant, account) {
                    return Ok(false);
                }
                entry.expires_at = sub.expires_at;
                encode_record(&entry)?
            }
        };
        match self
            .objects
            .put(&key, value, Expect::Version(version))
            .await
        {
            Ok(_) => Ok(true),
            Err(StorageError::Conflict) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// The account a Graph notification is for, when `subscription_id` is registered and
    /// `client_state` hashes to the stored hash (compared in constant time). `None` otherwise,
    /// including for ids that cannot be keys; callers must not tell these cases apart in answers.
    pub async fn lookup_graph(
        &self,
        subscription_id: &str,
        client_state: &str,
    ) -> Result<Option<(TenantId, AccountId)>, PushError> {
        let Some(key) = Self::graph_key(subscription_id) else {
            return Ok(None);
        };
        let Some((bytes, _)) = self.objects.get(&key).await? else {
            let _ = same_hash(&hash(""), client_state);
            return Ok(None);
        };
        let entry: GraphEntry = decode_record(&bytes)?;
        Ok(same_hash(&entry.client_state_hash, client_state)
            .then_some((entry.tenant, entry.account)))
    }

    /// The account a Gmail notification for `email` is for (case-insensitive), if any.
    pub async fn lookup_gmail(
        &self,
        email: &str,
    ) -> Result<Option<(TenantId, AccountId)>, PushError> {
        let Some((bytes, _)) = self.objects.get(&Self::gmail_key(email)).await? else {
            return Ok(None);
        };
        let entry: GmailEntry = decode_record(&bytes)?;
        Ok(Some((entry.tenant, entry.account)))
    }

    /// Stops routing `sub`, but only if its entry still points at `tenant`/`account` (another
    /// account may have registered the same Gmail address since). Removing a missing entry
    /// succeeds.
    pub async fn remove(
        &self,
        sub: &Subscription,
        tenant: &TenantId,
        account: &AccountId,
    ) -> Result<(), PushError> {
        let Ok(key) = Self::key(sub) else {
            return Ok(());
        };
        let Some((bytes, version)) = self.objects.get(&key).await? else {
            return Ok(());
        };
        let owner = match sub.provider_kind.as_str() {
            PUSH_GRAPH => decode_record::<GraphEntry>(&bytes).map(|e| (e.tenant, e.account)),
            _ => decode_record::<GmailEntry>(&bytes).map(|e| (e.tenant, e.account)),
        };
        if owner.is_ok_and(|(t, a)| (&t, &a) != (tenant, account)) {
            return Ok(());
        }
        match self.objects.delete(&key, Expect::Version(version)).await {
            Ok(()) | Err(StorageError::Conflict) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// The account's subscription record, if it has one.
    pub async fn state(
        &self,
        tenant: &TenantId,
        account: &AccountId,
    ) -> Result<Option<PushState>, PushError> {
        match self.control.get(tenant, &state_path(account)).await? {
            Some((bytes, _)) => Ok(Some(decode_record(&bytes)?)),
            None => Ok(None),
        }
    }

    async fn save(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        state: &PushState,
    ) -> Result<(), PushError> {
        self.control
            .put(
                tenant,
                &state_path(account),
                encode_record(state)?,
                Expect::Any,
            )
            .await?;
        Ok(())
    }

    /// Whether the account needs [`Renewer::ensure`] now: it has no subscription record, or its
    /// renewal time ([`PushState::renew_at`]) has come.
    pub async fn due_for_renewal(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        now: Timestamp,
    ) -> Result<bool, PushError> {
        Ok(match self.state(tenant, account).await? {
            Some(state) => now >= state.renew_at(),
            None => true,
        })
    }

    /// Removes the account's registry entry and record without asking the provider, for an
    /// account that is deleted or whose credentials are gone; the provider's subscription runs
    /// out on its own.
    pub async fn forget(&self, tenant: &TenantId, account: &AccountId) -> Result<(), PushError> {
        if let Some(state) = self.state(tenant, account).await? {
            self.remove(&state.subscription, tenant, account).await?;
        }
        self.control
            .delete(tenant, &state_path(account), Expect::Any)
            .await?;
        Ok(())
    }

    async fn mark_renew_now(
        &self,
        tenant: &TenantId,
        account: &AccountId,
    ) -> Result<(), PushError> {
        let Some((bytes, version)) = self.control.get(tenant, &state_path(account)).await? else {
            return Ok(());
        };
        let mut state: PushState = decode_record(&bytes)?;
        if state.renew_now {
            return Ok(());
        }
        state.renew_now = true;
        match self
            .control
            .put(
                tenant,
                &state_path(account),
                encode_record(&state)?,
                Expect::Version(version),
            )
            .await
        {
            Ok(_) | Err(StorageError::Conflict) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn hint(
        &self,
        signal: &dyn Signal,
        tenant: &TenantId,
        account: &AccountId,
        provider: &str,
    ) -> Result<(), PushError> {
        let payload = Bytes::from(format!("{{\"provider\":\"{provider}\"}}"));
        signal
            .publish(&coordination::group(tenant), &hint_topic(account), payload)
            .await?;
        Ok(())
    }

    /// Handles a Graph notification post: every item whose subscription id and `clientState`
    /// match a registered subscription gives its account one hint on [`hint_topic`]. Lifecycle
    /// events (`reauthorizationRequired`, `subscriptionRemoved`, `missed`) also hint and, except
    /// `missed`, mark the subscription for renewal at the next [`Renewer::ensure`]. Items that do
    /// not match are dropped silently. Storage errors on single items are logged and skipped.
    /// `Invalid` only when the body does not parse.
    pub async fn accept_graph(
        &self,
        body: &[u8],
        signal: &dyn Signal,
    ) -> Result<Accepted, PushError> {
        let items = parse_graph(body)?;
        let received = items.len();
        let matched: Vec<(TenantId, AccountId, bool)> = futures::stream::iter(items)
            .map(|item| async move {
                let state = item.client_state.as_deref()?;
                match self.lookup_graph(&item.subscription_id, state).await {
                    Ok(Some((t, a))) => {
                        let renew = matches!(
                            item.lifecycle_event.as_deref(),
                            Some("reauthorizationRequired" | "subscriptionRemoved")
                        );
                        Some((t, a, renew))
                    }
                    Ok(None) => None,
                    Err(e) => {
                        warn!(error = %e, "push registry lookup failed");
                        None
                    }
                }
            })
            .buffer_unordered(16)
            .filter_map(|x| async move { x })
            .collect()
            .await;
        let mut accounts = BTreeSet::new();
        let mut renew = BTreeSet::new();
        for (t, a, r) in matched {
            if r {
                renew.insert((t.clone(), a.clone()));
            }
            accounts.insert((t, a));
        }
        for (t, a) in &renew {
            if let Err(e) = self.mark_renew_now(t, a).await {
                warn!(account = %a, error = %e, "cannot mark a subscription for renewal");
            }
        }
        let mut hinted = 0;
        for (t, a) in &accounts {
            match self.hint(signal, t, a, PUSH_GRAPH).await {
                Ok(()) => hinted += 1,
                Err(e) => warn!(account = %a, error = %e, "cannot publish a push hint"),
            }
        }
        debug!(received, hinted, "graph notifications");
        Ok(Accepted { received, hinted })
    }

    /// Handles a Gmail Pub/Sub push: the account registered for the address gets a hint on
    /// [`hint_topic`]. Unknown addresses are dropped silently. `Invalid` when the envelope does
    /// not parse.
    pub async fn accept_gmail(
        &self,
        body: &[u8],
        signal: &dyn Signal,
    ) -> Result<Accepted, PushError> {
        let note = parse_gmail(body)?;
        let mut hinted = 0;
        if let Some((t, a)) = self.lookup_gmail(&note.email).await? {
            self.hint(signal, &t, &a, PUSH_GMAIL).await?;
            hinted = 1;
        }
        debug!(hinted, "gmail notification");
        Ok(Accepted {
            received: 1,
            hinted,
        })
    }
}

/// What [`Renewer::ensure`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ensured {
    /// The provider cannot push from outside (or lacks what it needs, such as a Gmail topic);
    /// poll instead. Nothing is stored.
    Unsupported,
    /// A new subscription was made and registered.
    Subscribed(Subscription),
    /// The subscription was renewed (possibly replaced by one with a new id).
    Renewed(Subscription),
    /// The subscription has more than a third of its lifetime left; nothing was sent.
    Current(Subscription),
}

/// Keeps one account's push subscription alive through its provider.
///
/// Meant to be called by the account's owner (its worker) after each run, or whenever
/// [`Renewer::next_check`] comes. Calls for one account must not overlap; calls for different
/// accounts may.
#[derive(Clone)]
pub struct Renewer {
    registry: PushRegistry,
}

impl Renewer {
    /// A renewer storing into `registry`.
    pub fn new(registry: PushRegistry) -> Self {
        Self { registry }
    }

    /// The registry it stores into.
    pub fn registry(&self) -> &PushRegistry {
        &self.registry
    }

    /// When the account's subscription should next be renewed, `None` without one.
    pub async fn next_check(
        &self,
        tenant: &TenantId,
        account: &AccountId,
    ) -> Result<Option<Timestamp>, PushError> {
        Ok(self
            .registry
            .state(tenant, account)
            .await?
            .map(|s| s.renew_at()))
    }

    /// Subscribes when the account has no subscription, renews it when less than a third of its
    /// lifetime is left (or a lifecycle notification asked for it), and replaces it when
    /// `target`'s address or topic changed. `target.client_state` is used only for new
    /// subscriptions, so it may be fresh on every call ([`random_client_state`]). A failure
    /// leaves the previous subscription and record as they were; it keeps working until it
    /// expires, and the next call tries again.
    pub async fn ensure(
        &self,
        provider: &dyn MailProvider,
        tenant: &TenantId,
        account: &AccountId,
        target: &PushTarget,
        now: Timestamp,
    ) -> Result<Ensured, PushError> {
        let wanted = target_hash(target);
        let state = match self.registry.state(tenant, account).await? {
            Some(s) if s.target_hash != wanted => {
                debug!(%account, "push target changed; subscribing again");
                if let Err(e) = provider.unsubscribe(&s.subscription).await {
                    debug!(%account, error = %e, "unsubscribe failed; it will expire");
                }
                self.registry
                    .remove(&s.subscription, tenant, account)
                    .await?;
                None
            }
            other => other,
        };
        let Some(state) = state else {
            let Some(sub) = provider.subscribe(target).await? else {
                return Ok(Ensured::Unsupported);
            };
            self.store_new(&sub, tenant, account, target, now, &wanted)
                .await?;
            return Ok(Ensured::Subscribed(sub));
        };
        if now < state.renew_at() {
            return Ok(Ensured::Current(state.subscription));
        }
        let old = &state.subscription;
        let Some(sub) = provider.renew(old, target).await? else {
            self.registry.forget(tenant, account).await?;
            return Ok(Ensured::Unsupported);
        };
        let same_key = PushRegistry::key(old).ok() == PushRegistry::key(&sub).ok();
        if same_key && self.registry.touch(&sub, tenant, account).await? {
            self.registry
                .save(
                    tenant,
                    account,
                    &PushState {
                        subscription: sub.clone(),
                        renewed_at: now,
                        target_hash: wanted,
                        renew_now: false,
                    },
                )
                .await?;
            return Ok(Ensured::Renewed(sub));
        }
        if same_key && sub.provider_kind == PUSH_GRAPH {
            if let Err(e) = provider.unsubscribe(&sub).await {
                debug!(%account, error = %e, "unsubscribe failed; it will expire");
            }
            let Some(fresh) = provider.subscribe(target).await? else {
                self.registry.forget(tenant, account).await?;
                return Ok(Ensured::Unsupported);
            };
            self.store_new(&fresh, tenant, account, target, now, &wanted)
                .await?;
            return Ok(Ensured::Renewed(fresh));
        }
        if !same_key {
            self.registry.remove(old, tenant, account).await?;
        }
        self.store_new(&sub, tenant, account, target, now, &wanted)
            .await?;
        Ok(Ensured::Renewed(sub))
    }

    async fn store_new(
        &self,
        sub: &Subscription,
        tenant: &TenantId,
        account: &AccountId,
        target: &PushTarget,
        now: Timestamp,
        wanted: &str,
    ) -> Result<(), PushError> {
        match self
            .registry
            .register(sub, tenant, account, &target.client_state)
            .await
        {
            Ok(()) => {}
            Err(PushError::Unsupported) => {
                debug!(%account, "a subscription kind the registry cannot route");
            }
            Err(e) => return Err(e),
        }
        self.registry
            .save(
                tenant,
                account,
                &PushState {
                    subscription: sub.clone(),
                    renewed_at: now,
                    target_hash: wanted.to_owned(),
                    renew_now: false,
                },
            )
            .await
    }

    /// Ends the account's subscription at the provider (best effort) and removes its entry and
    /// record, for an account that is paused, deleted or loses its owner for good.
    pub async fn stop(
        &self,
        provider: &dyn MailProvider,
        tenant: &TenantId,
        account: &AccountId,
    ) -> Result<(), PushError> {
        if let Some(state) = self.registry.state(tenant, account).await?
            && let Err(e) = provider.unsubscribe(&state.subscription).await
        {
            debug!(%account, error = %e, "unsubscribe failed; it will expire");
        }
        self.registry.forget(tenant, account).await
    }
}
