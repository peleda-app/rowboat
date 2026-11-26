use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use baton_signal::Signal;
use futures::StreamExt;
use skein_core::{AccountId, BlobHash, Event, EventBody, TenantId, Timestamp};
use skein_storage::{
    Chain, HeadAttestor, IntegrityError, JournalHead, NoAttestor, SegmentRef, Storage,
    StorageError, verify_head, verify_segment,
};
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::parse::{Parsed, parse};
use crate::pim::parse_object;
use crate::store::{Store, StoreError};

/// Events applied per database transaction by default.
pub const DEFAULT_PAGE: usize = 200;
/// Largest original read by default; larger ones are kept as unavailable.
pub const DEFAULT_MAX_BLOB: u64 = 64 * 1024 * 1024;

/// Why following an account failed. The account is left at its last checkpoint.
#[derive(Debug, thiserror::Error)]
pub enum FollowError {
    /// Storage failed, or journal data failed verification.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// The database failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A database task did not finish.
    #[error("a database task failed")]
    Task,
    /// The events after the checkpoint are gone and there is no snapshot to start from.
    #[error("the journal no longer reaches the checkpoint and has no snapshot")]
    NoSnapshot,
}

impl From<IntegrityError> for FollowError {
    fn from(e: IntegrityError) -> Self {
        Self::Storage(e.into())
    }
}

/// How often [`Follower::run`] reads the journal.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// Between rounds over the accounts that get no hints (all of them without a signal).
    pub poll: Duration,
    /// Between rounds over every account, hinted or not.
    pub safety: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            poll: Duration::from_secs(5),
            safety: Duration::from_secs(300),
        }
    }
}

/// Follows the journals of one tenant into a [`Store`], reading Skein's storage contracts
/// directly.
///
/// Every account's head is checked with the [`HeadAttestor`] (none by default), and every
/// segment is read through [`Chain`] from that head and verified against the hash the chain
/// names, as `skein-storage-tiered` does for untrusted tiers; the last segment applied in full
/// is kept, and a newer head must link to it, so storage cannot roll back, reorder or swap
/// events under a follower. Events the journal no longer has (compacted) are replaced by the
/// latest snapshot, which storage vouches for alone.
pub struct Follower {
    storage: Storage,
    tenant: TenantId,
    store: Arc<Store>,
    allow: Option<BTreeSet<AccountId>>,
    page: usize,
    max_blob: u64,
    attestor: Arc<dyn HeadAttestor>,
    signal: Option<Arc<dyn Signal>>,
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, StoreError> + Send + 'static,
) -> Result<T, FollowError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| FollowError::Task)?
        .map_err(FollowError::Store)
}

#[derive(Default)]
struct Hints {
    pending: Mutex<BTreeSet<AccountId>>,
    notify: Notify,
}

impl Hints {
    fn wake(&self, account: &AccountId) {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(account.clone());
        self.notify.notify_one();
    }

    fn take(&self) -> BTreeSet<AccountId> {
        std::mem::take(&mut *self.pending.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

impl Follower {
    /// Follows every account of `tenant` in `storage` into `store`.
    pub fn new(storage: Storage, tenant: TenantId, store: Arc<Store>) -> Self {
        Self {
            storage,
            tenant,
            store,
            allow: None,
            page: DEFAULT_PAGE,
            max_blob: DEFAULT_MAX_BLOB,
            attestor: Arc::new(NoAttestor),
            signal: None,
        }
    }

    /// Follows only these accounts.
    pub fn with_accounts(mut self, accounts: BTreeSet<AccountId>) -> Self {
        self.allow = Some(accounts);
        self
    }

    /// Applies at most `page` events per transaction (at least 1).
    pub fn with_page_size(mut self, page: usize) -> Self {
        self.page = page.max(1);
        self
    }

    /// Reads originals up to `bytes`; larger ones are kept as unavailable.
    pub fn with_max_blob_bytes(mut self, bytes: u64) -> Self {
        self.max_blob = bytes;
        self
    }

    /// Checks every head with `attestor`, the one the journal's writers attest with.
    pub fn with_attestor(mut self, attestor: Arc<dyn HeadAttestor>) -> Self {
        self.attestor = attestor;
        self
    }

    /// Wakes [`Follower::run`] on the `heads/{account}` hints the engine publishes in the
    /// tenant's group, so hinted accounts are read at once and polled only every
    /// [`Timing::safety`].
    pub fn with_signal(mut self, signal: Arc<dyn Signal>) -> Self {
        self.signal = Some(signal);
        self
    }

    /// Brings every followed account up to its head now. An account that fails is logged and
    /// left for the next round; the others still sync. Fails only when the accounts cannot be
    /// listed.
    pub async fn sync_once(&self) -> Result<(), FollowError> {
        for account in self.accounts().await? {
            if let Err(e) = self.sync_account(&account).await {
                warn!(account = %account, error = %e, "account sync failed");
            }
        }
        Ok(())
    }

    async fn accounts(&self) -> Result<Vec<AccountId>, FollowError> {
        Ok(self
            .storage
            .log
            .heads(&self.tenant)
            .await?
            .into_iter()
            .map(|(account, _)| account)
            .filter(|a| self.allow.as_ref().is_none_or(|allow| allow.contains(a)))
            .collect())
    }

    /// Brings one account up to its head now.
    pub async fn sync_account(&self, account: &AccountId) -> Result<(), FollowError> {
        let mut rebuilt = false;
        loop {
            let signed = self.storage.log.signed_head(&self.tenant, account).await?;
            verify_head(&*self.attestor, &signed).await?;
            let head = signed.head;
            let id = account.to_string();
            let seq = head.seq.0;
            let store = self.store.clone();
            let (checkpoint, tip) = blocking(move || {
                store.note_head(&id, seq)?;
                Ok((store.checkpoint(&id)?, store.tip(&id)?))
            })
            .await?;
            if checkpoint >= seq {
                return check_settled(&head, checkpoint, tip.as_ref());
            }
            match self.segments_after(&head, checkpoint, tip.as_ref()).await {
                Ok(refs) => return self.apply(account, refs, checkpoint).await,
                Err(FollowError::Storage(StorageError::Integrity(IntegrityError::Missing {
                    ..
                }))) if !rebuilt => {
                    self.rebuild(account, checkpoint, seq).await?;
                    rebuilt = true;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// The segments holding the events after `checkpoint`, oldest first, found by walking back
    /// from `head`. The segment holding `checkpoint + 1` must link to `tip`.
    async fn segments_after(
        &self,
        head: &JournalHead,
        checkpoint: u64,
        tip: Option<&SegmentRef>,
    ) -> Result<Vec<SegmentRef>, FollowError> {
        let want = checkpoint + 1;
        let mut chain = Chain::new(&*self.storage.log, head);
        let mut refs = Vec::new();
        while let Some(segment) = chain.next().await? {
            let start = segment.segment.start.0;
            refs.push(segment.segment);
            if start <= want {
                if let Some(tip) = tip
                    && segment.prev.as_ref() != Some(tip)
                {
                    return Err(IntegrityError::Fork { seq: tip.end.0 }.into());
                }
                refs.reverse();
                return Ok(refs);
            }
        }
        Err(IntegrityError::Unchained { seq: want }.into())
    }

    async fn apply(
        &self,
        account: &AccountId,
        refs: Vec<SegmentRef>,
        mut checkpoint: u64,
    ) -> Result<(), FollowError> {
        let log = &self.storage.log;
        for segment in refs {
            let bytes = log
                .segment(&self.tenant, account, &segment)
                .await?
                .ok_or_else(|| IntegrityError::Missing {
                    segment: segment.name(),
                })?;
            let verified = verify_segment(&self.tenant, account, &segment, &bytes)?;
            drop(bytes);
            let events: Vec<Event> = verified
                .events
                .into_iter()
                .filter(|e| e.seq.0 > checkpoint)
                .collect();
            let pages: Vec<&[Event]> = if events.is_empty() {
                vec![&[]]
            } else {
                events.chunks(self.page).collect()
            };
            let last = pages.len() - 1;
            for (n, page) in pages.into_iter().enumerate() {
                for e in page {
                    self.ensure(account, e).await?;
                }
                let store = self.store.clone();
                let id = account.to_string();
                let page = page.to_vec();
                let tip = (n == last).then(|| segment.clone());
                let count = page.len();
                checkpoint =
                    blocking(move || store.apply_page_to(&id, &page, tip.as_ref())).await?;
                debug!(account = %account, events = count, checkpoint, "applied a page");
            }
        }
        Ok(())
    }

    async fn ensure(&self, account: &AccountId, e: &Event) -> Result<(), FollowError> {
        match &e.body {
            EventBody::MessageAdded {
                blob,
                size,
                received_at,
                ..
            } => {
                self.ensure_content(account, blob, *size, *received_at, e.at)
                    .await
            }
            EventBody::ObjectUpserted {
                blob,
                size,
                content_type,
                ..
            } => self.ensure_object(account, blob, *size, content_type).await,
            _ => Ok(()),
        }
    }

    async fn rebuild(
        &self,
        account: &AccountId,
        checkpoint: u64,
        head: u64,
    ) -> Result<(), FollowError> {
        let snapshot = self
            .storage
            .log
            .latest_snapshot(&self.tenant, account)
            .await?
            .ok_or(FollowError::NoSnapshot)?;
        if &snapshot.account != account {
            return Err(IntegrityError::Scope.into());
        }
        if snapshot.seq.0 <= checkpoint {
            return Err(IntegrityError::Rollback {
                trusted: checkpoint,
                seen: snapshot.seq.0,
            }
            .into());
        }
        if snapshot.seq.0 > head {
            return Err(IntegrityError::Mismatch {
                segment: format!("snapshot {}", snapshot.seq.0),
                reason: format!("past the attested head at {head}"),
            }
            .into());
        }
        let mut messages = 0usize;
        for mailbox in snapshot.mailboxes.values() {
            for state in mailbox.items.values() {
                self.ensure_content(
                    account,
                    &state.blob,
                    state.size,
                    state.received_at,
                    snapshot.at,
                )
                .await?;
                messages += 1;
            }
        }
        let mut objects = 0usize;
        for collection in snapshot.collections.values() {
            for state in collection.items.values() {
                self.ensure_object(account, &state.blob, state.size, &state.content_type)
                    .await?;
                objects += 1;
            }
        }
        let store = self.store.clone();
        let id = account.to_string();
        let seq = snapshot.seq.0;
        blocking(move || store.rebuild(&id, &snapshot)).await?;
        info!(account = %account, seq, messages, objects, "rebuilt from snapshot");
        Ok(())
    }

    async fn read_blob(
        &self,
        account: &AccountId,
        blob: &BlobHash,
        size: u64,
    ) -> Result<Option<bytes::Bytes>, FollowError> {
        if size > self.max_blob {
            warn!(account = %account, blob = %blob, size, "original larger than the limit");
            return Ok(None);
        }
        match self.storage.blobs.get(&self.tenant, blob).await {
            Ok(Some(bytes)) if bytes.len() as u64 <= self.max_blob => Ok(Some(bytes)),
            Ok(_) => {
                warn!(account = %account, blob = %blob, "original bytes unavailable");
                Ok(None)
            }
            Err(StorageError::Corrupt(_)) => {
                warn!(account = %account, blob = %blob, "original bytes do not match their hash");
                Ok(None)
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn ensure_content(
        &self,
        account: &AccountId,
        blob: &BlobHash,
        size: u64,
        received_at: Option<Timestamp>,
        seen_at: Timestamp,
    ) -> Result<(), FollowError> {
        let store = self.store.clone();
        let id = account.to_string();
        let b = *blob;
        if blocking(move || store.has_content(&id, &b)).await? {
            return Ok(());
        }
        let bytes = self.read_blob(account, blob, size).await?;
        let store = self.store.clone();
        let id = account.to_string();
        let b = *blob;
        blocking(move || {
            let parsed = match bytes {
                Some(bytes) => parse(&bytes),
                None => Parsed::unavailable(),
            };
            store.insert_content(&id, &b, size, received_at.map(|t| t.0), seen_at.0, &parsed)
        })
        .await
    }

    async fn ensure_object(
        &self,
        account: &AccountId,
        blob: &BlobHash,
        size: u64,
        content_type: &str,
    ) -> Result<(), FollowError> {
        let store = self.store.clone();
        let id = account.to_string();
        let b = *blob;
        if blocking(move || store.has_object(&id, &b)).await? {
            return Ok(());
        }
        let bytes = self.read_blob(account, blob, size).await?;
        let store = self.store.clone();
        let id = account.to_string();
        let b = *blob;
        let content_type = content_type.to_owned();
        blocking(move || {
            let parsed = parse_object(&content_type, bytes.as_deref());
            store.insert_object(&id, &b, size, &content_type, &parsed)
        })
        .await
    }

    /// Follows until `stop` turns true. Without a signal every account is synced every
    /// `timing.poll`. With one, each account is subscribed to its `heads/{account}` hints and
    /// read as soon as one arrives; hints carry no delivery guarantee, so every account is
    /// still synced every `timing.safety`, and new accounts are looked for every `timing.poll`.
    pub async fn run(self, timing: Timing, mut stop: watch::Receiver<bool>) {
        let hints = Arc::new(Hints::default());
        let mut subscribed: BTreeMap<AccountId, JoinHandle<()>> = BTreeMap::new();
        let mut poll = tokio::time::interval(timing.poll);
        let mut safety = tokio::time::interval(timing.safety);
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        safety.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        poll.tick().await;
        let mut first = true;
        loop {
            let round = tokio::select! {
                _ = safety.tick() => Some(true),
                _ = poll.tick() => Some(false),
                _ = hints.notify.notified() => {
                    for account in hints.take() {
                        if let Err(e) = self.sync_account(&account).await {
                            warn!(account = %account, error = %e, "hinted sync failed");
                        }
                    }
                    None
                }
                changed = stop.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    None
                }
            };
            if *stop.borrow() {
                break;
            }
            let Some(all) = round else {
                continue;
            };
            let accounts = match self.accounts().await {
                Ok(accounts) => accounts,
                Err(e) => {
                    warn!(error = %e, "listing accounts failed");
                    continue;
                }
            };
            if let Some(signal) = &self.signal {
                self.subscribe(signal, &mut subscribed, &accounts, &hints, first)
                    .await;
            }
            first = false;
            for account in &accounts {
                if !all && subscribed.contains_key(account) {
                    continue;
                }
                if let Err(e) = self.sync_account(account).await {
                    warn!(account = %account, error = %e, "account sync failed");
                }
            }
        }
        for (_, task) in subscribed {
            task.abort();
        }
    }

    async fn subscribe(
        &self,
        signal: &Arc<dyn Signal>,
        subscribed: &mut BTreeMap<AccountId, JoinHandle<()>>,
        accounts: &[AccountId],
        hints: &Arc<Hints>,
        first: bool,
    ) {
        subscribed.retain(|account, task| {
            let keep = accounts.contains(account) && !task.is_finished();
            if !keep {
                task.abort();
            }
            keep
        });
        let group = skein_core::coordination::group(&self.tenant);
        for account in accounts {
            if subscribed.contains_key(account) {
                continue;
            }
            let mut stream = match signal.subscribe(&group, &format!("heads/{account}")).await {
                Ok(stream) => stream,
                Err(e) => {
                    debug!(account = %account, error = %e, "subscribing to hints failed");
                    continue;
                }
            };
            if !first {
                hints.wake(account);
            }
            let hints = hints.clone();
            let id = account.clone();
            subscribed.insert(
                account.clone(),
                tokio::spawn(async move {
                    while stream.next().await.is_some() {
                        hints.wake(&id);
                    }
                }),
            );
        }
    }
}

fn check_settled(
    head: &JournalHead,
    checkpoint: u64,
    tip: Option<&SegmentRef>,
) -> Result<(), FollowError> {
    if checkpoint > head.seq.0 {
        return Err(IntegrityError::Rollback {
            trusted: checkpoint,
            seen: head.seq.0,
        }
        .into());
    }
    if let Some(tip) = tip
        && tip.end.0 == checkpoint
        && head.tip.as_ref() != Some(tip)
    {
        return Err(IntegrityError::Fork { seq: checkpoint }.into());
    }
    Ok(())
}
