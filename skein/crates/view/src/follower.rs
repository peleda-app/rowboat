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

use crate::observe::{Added, CommandOutcome, OutcomeKind, PageReport, Touched, ViewObserver};
use crate::parse::{MailParser, MessageParser, ParseContext, ParseError, Parsed};
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
    /// The parser hook could not run; the page is retried next round.
    #[error("the parser is unavailable")]
    Parser,
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

/// Messages parsed again per round of [`Follower::run`] when the parser's version changed.
pub const REPARSE_PER_ROUND: usize = 50;

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
    parser: Arc<dyn MessageParser>,
    observer: Option<Arc<dyn ViewObserver>>,
}

type Roles = BTreeMap<String, Option<skein_core::MailboxRole>>;

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
            parser: Arc::new(MailParser),
            observer: None,
        }
    }

    /// Parses originals with `parser` instead of the built-in [`MailParser`]. Content already
    /// stored is kept; the parser's version is stored with every message it parses.
    pub fn with_parser(mut self, parser: Arc<dyn MessageParser>) -> Self {
        self.parser = parser;
        self
    }

    /// Calls `observer` after every page of events (and every rebuild from a snapshot) is
    /// committed, in commit order, from the follower's task.
    pub fn with_observer(mut self, observer: Arc<dyn ViewObserver>) -> Self {
        self.observer = Some(observer);
        self
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
                Ok(refs) => return self.apply(account, refs, checkpoint, seq).await,
                Err(FollowError::Storage(StorageError::Integrity(IntegrityError::Missing {
                    ..
                }))) if !rebuilt => {
                    self.rebuild(account, checkpoint, seq).await?;
                    if let Some(observer) = &self.observer {
                        let store = self.store.clone();
                        let id = account.to_string();
                        let checkpoint = blocking(move || store.checkpoint(&id)).await?;
                        observer.page_applied(&PageReport {
                            account: account.to_string(),
                            checkpoint,
                            head: seq,
                            rebuilt: true,
                            mailboxes: Touched::Many,
                            mailboxes_changed: true,
                            ..PageReport::default()
                        });
                    }
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
        head: u64,
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
                let roles = page_roles(page);
                for e in page {
                    self.ensure(account, e, &roles).await?;
                }
                let report = self
                    .observer
                    .as_ref()
                    .map(|_| report_of(account, page, head));
                let store = self.store.clone();
                let id = account.to_string();
                let page = page.to_vec();
                let tip = (n == last).then(|| segment.clone());
                let count = page.len();
                checkpoint =
                    blocking(move || store.apply_page_to(&id, &page, tip.as_ref())).await?;
                debug!(account = %account, events = count, checkpoint, "applied a page");
                if let (Some(observer), Some(mut report)) = (&self.observer, report) {
                    report.checkpoint = checkpoint;
                    observer.page_applied(&report);
                }
            }
        }
        Ok(())
    }

    async fn ensure(
        &self,
        account: &AccountId,
        e: &Event,
        roles: &Roles,
    ) -> Result<(), FollowError> {
        match &e.body {
            EventBody::MessageAdded {
                blob,
                size,
                received_at,
                mailbox,
                ..
            } => {
                let role = match roles.get(mailbox) {
                    Some(role) => *role,
                    None => {
                        let store = self.store.clone();
                        let id = account.to_string();
                        let mb = mailbox.clone();
                        blocking(move || store.mailbox_role(&id, &mb))
                            .await?
                            .and_then(|r| serde_json::from_value(serde_json::Value::String(r)).ok())
                    }
                };
                let context = ParseContext {
                    account: account.to_string(),
                    mailbox: Some(mailbox.clone()),
                    role,
                };
                self.ensure_content(account, blob, *size, *received_at, e.at, &context)
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
        for (mailbox_id, mailbox) in &snapshot.mailboxes {
            for state in mailbox.items.values() {
                let context = ParseContext {
                    account: account.to_string(),
                    mailbox: Some(mailbox_id.clone()),
                    role: mailbox.info.role,
                };
                self.ensure_content(
                    account,
                    &state.blob,
                    state.size,
                    state.received_at,
                    snapshot.at,
                    &context,
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
        context: &ParseContext,
    ) -> Result<(), FollowError> {
        let store = self.store.clone();
        let id = account.to_string();
        let b = *blob;
        if blocking(move || store.has_content(&id, &b)).await? {
            return Ok(());
        }
        let bytes = self.read_blob(account, blob, size).await?;
        let (parsed, version) = match bytes {
            Some(bytes) => match self.parser.parse(&bytes, context).await {
                Ok(mut parsed) => {
                    parsed.available = true;
                    (parsed, Some(self.parser.version()))
                }
                Err(ParseError::Refused) => {
                    warn!(account = %account, blob = %blob, "the parser refused a message");
                    (Parsed::unavailable(), Some(self.parser.version()))
                }
                Err(ParseError::Unavailable) => return Err(FollowError::Parser),
            },
            None => (Parsed::unavailable(), None),
        };
        let store = self.store.clone();
        let id = account.to_string();
        let b = *blob;
        blocking(move || {
            store.insert_parsed(
                &id,
                &b,
                size,
                received_at.map(|t| t.0),
                seen_at.0,
                &parsed,
                version.as_deref(),
            )
        })
        .await
    }

    /// Parses again, with the current parser, at most `limit` stored messages that another
    /// parser version produced ([`Store::stale_messages`]), replacing their parsed fields and
    /// tags; threads, memberships and the address book stay. A refused message becomes
    /// unavailable; one whose original is gone keeps its content and is marked with the current
    /// version so it is not tried again. Returns how many were handled; stops early with
    /// [`FollowError::Parser`] when the parser cannot run.
    pub async fn reparse_stale(&self, limit: usize) -> Result<usize, FollowError> {
        let version = self.parser.version();
        let store = self.store.clone();
        let v = version.clone();
        let stale = blocking(move || store.stale_messages(&v, limit)).await?;
        let mut done = 0;
        for m in stale {
            let Ok(account) = AccountId::new(&m.account) else {
                continue;
            };
            if self.allow.as_ref().is_some_and(|a| !a.contains(&account)) {
                continue;
            }
            let context = ParseContext {
                account: m.account.clone(),
                mailbox: m.mailbox.clone(),
                role: m
                    .role
                    .clone()
                    .and_then(|r| serde_json::from_value(serde_json::Value::String(r)).ok()),
            };
            let store = self.store.clone();
            let v = version.clone();
            match self.read_blob(&account, &m.blob, m.size).await? {
                Some(bytes) => {
                    let parsed = match self.parser.parse(&bytes, &context).await {
                        Ok(mut parsed) => {
                            parsed.available = true;
                            parsed
                        }
                        Err(ParseError::Refused) => Parsed::unavailable(),
                        Err(ParseError::Unavailable) => return Err(FollowError::Parser),
                    };
                    blocking(move || store.replace_parsed(&m.account, &m.blob, &parsed, &v))
                        .await?;
                }
                None => blocking(move || store.mark_parsed(&m.account, &m.blob, &v)).await?,
            }
            done += 1;
        }
        if done > 0 {
            info!(messages = done, "parsed again with a new parser version");
        }
        Ok(done)
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
            if let Err(e) = self.reparse_stale(REPARSE_PER_ROUND).await {
                warn!(error = %e, "parsing again failed");
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

fn page_roles(page: &[Event]) -> Roles {
    page.iter()
        .filter_map(|e| match &e.body {
            EventBody::MailboxUpserted { mailbox } => Some((mailbox.id.clone(), mailbox.role)),
            _ => None,
        })
        .collect()
}

fn report_of(account: &AccountId, page: &[Event], head: u64) -> PageReport {
    let mut touched = BTreeSet::new();
    let mut many = false;
    let mut report = PageReport {
        account: account.to_string(),
        head,
        ..PageReport::default()
    };
    let mut touch = |mailbox: &str| {
        if !many {
            touched.insert(mailbox.to_owned());
            if touched.len() > crate::observe::MAX_TOUCHED {
                many = true;
            }
        }
    };
    for e in page {
        match &e.body {
            EventBody::MessageAdded {
                mailbox,
                blob,
                flags,
                ..
            } => {
                report.messages_added += 1;
                if report.added.len() < crate::observe::MAX_ADDED {
                    report.added.push(Added {
                        mailbox: mailbox.clone(),
                        message: blob.to_hex(),
                        seen: flags.contains("\\Seen"),
                    });
                }
                touch(mailbox);
            }
            EventBody::MessageRemoved { mailbox, .. }
            | EventBody::FlagsChanged { mailbox, .. }
            | EventBody::LabelsChanged { mailbox, .. } => touch(mailbox),
            EventBody::ResyncRequired { collection, .. } => touch(collection),
            EventBody::MailboxUpserted { .. } => report.mailboxes_changed = true,
            EventBody::MailboxDeleted { mailbox } => {
                report.mailboxes_changed = true;
                touch(mailbox);
            }
            EventBody::FirstSyncCompleted => report.first_sync_completed = true,
            EventBody::WriteApplied { command } => {
                report.outcome(command, OutcomeKind::Applied, None)
            }
            EventBody::WriteFailed { command, reason } => {
                report.outcome(command, OutcomeKind::Failed, Some(reason))
            }
            EventBody::Conflict { command, .. } => {
                report.outcome(command, OutcomeKind::Conflict, None)
            }
            EventBody::WriteUncertain { command } => {
                report.outcome(command, OutcomeKind::Uncertain, None)
            }
            EventBody::SendResult {
                command, refused, ..
            } => report.outcome(
                command,
                OutcomeKind::Sent {
                    refused: refused.len().min(u32::MAX as usize) as u32,
                },
                None,
            ),
            _ => {}
        }
    }
    report.mailboxes = if many {
        Touched::Many
    } else {
        Touched::Some(touched.into_iter().collect())
    };
    report
}

impl PageReport {
    fn outcome(
        &mut self,
        command: &skein_core::CommandId,
        kind: OutcomeKind,
        reason: Option<&String>,
    ) {
        if self.outcomes.len() < crate::observe::MAX_OUTCOMES {
            self.outcomes.push(CommandOutcome {
                command: command.to_string(),
                kind,
                reason: reason.map(|r| crate::observe::reason_word(r)),
            });
        }
    }
}
