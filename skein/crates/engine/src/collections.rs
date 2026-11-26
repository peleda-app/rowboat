//! Calendars and contacts: collection sync into the journal and `put_object` / `delete_object`
//! commands, with the same guarantees as mail.
//!
//! Sync writes in the order blobs → previews → events (fenced) → cursor (compare-and-swap,
//! fenced), drops events whose keys are already in the log after the saved position, and keeps
//! its cursors under `pim-cursors/{account}/…` and its state under `pim-state/{account}`, apart
//! from mail's. Commands use the same `started/{account}/{command}` markers as mail commands, so
//! cancelling through the API and crash protection work alike.

use std::collections::{HashMap, HashSet};

use baton_lease::{Lease, LeaseError};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use skein_core::{
    AccountId, BlobHash, CollectionInfo, Command, CommandBody, CommandId, Event, EventBody,
    FencingToken, ItemRef, ScheduleVia, Seq, SyncOutcome, TenantId,
};
use skein_pim::{
    PimChange, PimError, PimProvider, PimSession, PimWrite, RawObject, Scheduling, WriteOutcome,
};
use skein_storage::{ControlStore, Expect, StorageError};
use tracing::{debug, info, warn};

use crate::state::{CursorRecord, command_marker, encode_cursor};
use crate::status::{Area, pim_outcome};
use crate::{AccountConfig, CommandReport, Engine, EngineError};

const PAGE: usize = 100;
const MAX_PER_RUN: usize = 2_000;

/// Errors of calendar and contacts sync and commands.
#[derive(Debug, thiserror::Error)]
pub enum CollectionsError {
    /// The lease or storage failed, or this node does not own the account
    /// ([`EngineError::NotOwner`]).
    #[error(transparent)]
    Engine(#[from] EngineError),
    /// The calendar and contacts provider failed.
    #[error(transparent)]
    Pim(#[from] PimError),
}

impl CollectionsError {
    /// Whether another node owns the account (or took it over during the run).
    pub fn is_not_owner(&self) -> bool {
        matches!(self, Self::Engine(EngineError::NotOwner))
    }
}

impl From<StorageError> for CollectionsError {
    fn from(e: StorageError) -> Self {
        Self::Engine(e.into())
    }
}

impl From<LeaseError> for CollectionsError {
    fn from(e: LeaseError) -> Self {
        Self::Engine(e.into())
    }
}

/// What one sync run did in one collection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CollectionReport {
    /// Collection id.
    pub collection: String,
    /// Objects journaled as new or changed.
    pub upserted: u64,
    /// Removals journaled.
    pub removed: u64,
    /// Events dropped because they were already in the log (a crash replay).
    pub replayed: u64,
    /// Whether the provider reset the cursor.
    pub reset: bool,
}

/// What one calendar and contacts sync run did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CollectionsReport {
    /// Per collection synced.
    pub collections: Vec<CollectionReport>,
    /// Events appended in total.
    pub events: u64,
    /// The log head after the run.
    pub head: Seq,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PimState {
    collections: Vec<CollectionInfo>,
    fence: FencingToken,
}

#[derive(Serialize)]
struct Preview<'a> {
    collection: &'a str,
    item: &'a str,
    blob: String,
}

fn notifies(body: &CommandBody) -> bool {
    matches!(
        body,
        CommandBody::PutObject { notify: true, .. }
            | CommandBody::DeleteObject { notify: true, .. }
            | CommandBody::RespondObject { notify: true, .. }
    )
}

fn collection_of(body: &CommandBody) -> &str {
    match body {
        CommandBody::PutObject { collection, .. }
        | CommandBody::DeleteObject { collection, .. }
        | CommandBody::RespondObject { collection, .. } => collection,
        _ => "",
    }
}

fn event_key(parts: &[&[u8]]) -> String {
    let mut h = blake3::Hasher::new();
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    h.finalize().to_hex()[..32].to_owned()
}

fn cursor_path(account: &AccountId, collection: &str) -> String {
    let h = blake3::hash(collection.as_bytes()).to_hex();
    format!("pim-cursors/{account}/{}", &h[..32])
}

fn state_path(account: &AccountId) -> String {
    format!("pim-state/{account}")
}

fn corrupt(e: impl std::fmt::Display) -> EngineError {
    EngineError::Storage(StorageError::Corrupt(e.to_string()))
}

async fn load<T: for<'de> Deserialize<'de>>(
    control: &dyn ControlStore,
    tenant: &TenantId,
    path: &str,
) -> Result<(Option<T>, Expect), EngineError> {
    match control.get(tenant, path).await? {
        None => Ok((None, Expect::Absent)),
        Some((bytes, v)) => Ok((
            Some(serde_json::from_slice(&bytes).map_err(corrupt)?),
            Expect::Version(v),
        )),
    }
}

/// Saves a fenced record unless a newer owner already saved one.
async fn save_fenced<T: Serialize>(
    control: &dyn ControlStore,
    tenant: &TenantId,
    path: &str,
    record: &T,
    fence: FencingToken,
    fence_of: impl Fn(&[u8]) -> Option<FencingToken>,
    expect: Expect,
) -> Result<(), EngineError> {
    let bytes = Bytes::from(serde_json::to_vec(record).map_err(corrupt)?);
    match control.put(tenant, path, bytes, expect).await {
        Ok(_) => Ok(()),
        Err(StorageError::Conflict) => match control.get(tenant, path).await? {
            Some((b, _)) if fence_of(&b).is_some_and(|f| f > fence) => Err(EngineError::NotOwner),
            _ => Err(EngineError::Storage(StorageError::Conflict)),
        },
        Err(e) => Err(e.into()),
    }
}

fn selected<'a>(
    config: &AccountConfig,
    collections: &'a [CollectionInfo],
) -> Vec<(&'a str, skein_core::CollectionKind)> {
    collections
        .iter()
        .filter(|c| {
            !config.exclude.contains(&c.id)
                && config
                    .include
                    .as_ref()
                    .is_none_or(|inc| inc.contains(&c.id))
        })
        .map(|c| (c.id.as_str(), c.kind))
        .collect()
}

fn outcome_body(
    command: &CommandId,
    outcome: &WriteOutcome,
    server_blob: Option<BlobHash>,
) -> EventBody {
    match outcome {
        WriteOutcome::Applied { .. } => EventBody::WriteApplied {
            command: command.clone(),
        },
        WriteOutcome::Conflict { .. } => EventBody::Conflict {
            command: command.clone(),
            server_blob,
        },
        WriteOutcome::Failed { reason } => EventBody::WriteFailed {
            command: command.clone(),
            reason: reason.clone(),
        },
        WriteOutcome::Uncertain => EventBody::WriteUncertain {
            command: command.clone(),
        },
    }
}

impl Engine {
    /// Syncs every calendar and address book of the account once, if this node owns it.
    ///
    /// Guarantees, the same as [`Engine::sync_account`] gives for mail: the account is claimed
    /// with the owner's fencing token, so a node that lost it cannot append; for every batch the
    /// original bytes go to the blob store before the events that point at them, and the cursor is
    /// saved (compare-and-swap, fenced) only after the events are in the log; a batch seen again
    /// after a crash is dropped by its event keys, so no event is journaled twice.
    ///
    /// Collections new or changed since the last run become `collection_upserted`, vanished ones
    /// `collection_deleted` (and their cursors are dropped); objects become `object_upserted`
    /// (bytes as a blob, with the provider's version and media type) and `object_removed`; a
    /// cursor the provider no longer accepts becomes `resync_required` with the collection id,
    /// followed by the full listing. `include` and `exclude` of `config` select collection ids;
    /// `page` and `fetch_batch` bound each provider call. A collection that disappears during the
    /// run is skipped.
    pub async fn sync_collections(
        &self,
        config: &AccountConfig,
        provider: &dyn PimProvider,
    ) -> Result<CollectionsReport, CollectionsError> {
        let lease = self.collections_lease(config).await?;
        let started = std::time::Instant::now();
        let mut reset_seen = false;
        let result = self
            .sync_collections_owned(config, provider, &lease, &mut reset_seen)
            .await;
        match &result {
            Ok(report) => {
                self.record_status(config, lease.fence, Area::Pim, SyncOutcome::Ok, false)
                    .await;
                skein_metrics::global().events_appended.add(report.events);
                info!(
                    account = %config.account,
                    collections = report.collections.len(),
                    events = report.events,
                    head = report.head.0,
                    ms = started.elapsed().as_millis() as u64,
                    "collection sync finished"
                );
            }
            Err(e) if e.is_not_owner() => {}
            Err(e) => {
                warn!(account = %config.account, error = %e, "collection sync failed");
                if let Some(outcome) = pim_outcome(e) {
                    self.record_status(config, lease.fence, Area::Pim, outcome, reset_seen)
                        .await;
                }
            }
        }
        result
    }

    async fn collections_lease(&self, config: &AccountConfig) -> Result<Lease, CollectionsError> {
        Ok(self.lease(config).await?)
    }

    async fn sync_collections_owned(
        &self,
        config: &AccountConfig,
        provider: &dyn PimProvider,
        lease: &Lease,
        reset_seen: &mut bool,
    ) -> Result<CollectionsReport, CollectionsError> {
        let mut session = provider.connect().await?;
        let path = state_path(&config.account);
        let (state, state_expect) =
            load::<PimState>(&*self.storage.control, &config.tenant, &path).await?;
        let state = state.unwrap_or_default();
        if state.fence > lease.fence {
            return Err(EngineError::NotOwner.into());
        }
        let mut report = CollectionsReport::default();
        let collections = session.collections().await?;

        let mut events = Vec::new();
        for c in &collections {
            if !state.collections.iter().any(|old| old == c) {
                let json = serde_json::to_vec(c).map_err(corrupt)?;
                events.push(self.event(
                    config,
                    event_key(&[b"collection", c.id.as_bytes(), &json]),
                    EventBody::CollectionUpserted {
                        collection: c.clone(),
                    },
                ));
            }
        }
        let gone: Vec<&CollectionInfo> = state
            .collections
            .iter()
            .filter(|old| !collections.iter().any(|c| c.id == old.id))
            .collect();
        for old in &gone {
            events.push(self.event(
                config,
                event_key(&[b"collection-deleted", old.id.as_bytes()]),
                EventBody::CollectionDeleted {
                    collection: old.id.clone(),
                },
            ));
        }
        report.events += self.append(config, lease.fence, events).await?;
        for old in gone {
            match self
                .storage
                .control
                .delete(
                    &config.tenant,
                    &cursor_path(&config.account, &old.id),
                    Expect::Any,
                )
                .await
            {
                Ok(()) | Err(StorageError::Conflict) => {}
                Err(e) => return Err(e.into()),
            }
        }

        for (id, kind) in selected(config, &collections) {
            match self
                .sync_collection(config, &mut *session, lease.fence, id, kind, reset_seen)
                .await
            {
                Ok(cr) => {
                    report.events += cr.upserted + cr.removed + u64::from(cr.reset);
                    report.collections.push(cr);
                }
                Err(CollectionsError::Pim(PimError::NotFound)) => {
                    debug!(account = %config.account, "collection vanished during sync");
                }
                Err(e) => return Err(e),
            }
        }

        let new_state = PimState {
            collections,
            fence: lease.fence,
        };
        save_fenced(
            &*self.storage.control,
            &config.tenant,
            &path,
            &new_state,
            lease.fence,
            |b| serde_json::from_slice::<PimState>(b).ok().map(|s| s.fence),
            state_expect,
        )
        .await?;
        let _ = session.logout().await;
        report.head = self
            .storage
            .log
            .head(&config.tenant, &config.account)
            .await?;
        self.hint(config, report.head).await;
        Ok(report)
    }

    async fn sync_collection(
        &self,
        config: &AccountConfig,
        session: &mut dyn PimSession,
        fence: FencingToken,
        collection: &str,
        kind: skein_core::CollectionKind,
        reset_seen: &mut bool,
    ) -> Result<CollectionReport, CollectionsError> {
        let mut report = CollectionReport {
            collection: collection.to_owned(),
            ..Default::default()
        };
        let path = cursor_path(&config.account, collection);
        loop {
            let (record, expect) =
                load::<CursorRecord>(&*self.storage.control, &config.tenant, &path).await?;
            if let Some(r) = &record
                && r.fence > fence
            {
                return Err(EngineError::NotOwner.into());
            }
            let cursor = record
                .as_ref()
                .map(|r| r.cursor_bytes().map(skein_pim::Cursor))
                .transpose()?;
            let previous = record
                .as_ref()
                .map(|r| r.cursor.as_bytes().to_vec())
                .unwrap_or_default();
            let batch = session
                .changes(collection, cursor.as_ref(), config.page)
                .await?;

            let mut events = Vec::new();
            let mut upserted = Vec::new();
            for change in &batch.changes {
                match change {
                    PimChange::Reset { reason } => {
                        report.reset = true;
                        *reset_seen = true;
                        events.push(self.event(
                            config,
                            event_key(&[b"pim-reset", collection.as_bytes(), &previous]),
                            EventBody::ResyncRequired {
                                collection: collection.to_owned(),
                                reason: reason.clone(),
                                domain: Some(match kind {
                                    skein_core::CollectionKind::Calendar => {
                                        skein_core::Domain::Calendar
                                    }
                                    skein_core::CollectionKind::AddressBook => {
                                        skein_core::Domain::Contacts
                                    }
                                }),
                            },
                        ));
                    }
                    PimChange::Upserted { item, version } => {
                        upserted.push((item.clone(), version.clone()));
                    }
                    PimChange::Removed { item } => {
                        report.removed += 1;
                        events.push(self.event(
                            config,
                            event_key(&[
                                b"pim-removed",
                                collection.as_bytes(),
                                item.id.as_bytes(),
                                &previous,
                            ]),
                            EventBody::ObjectRemoved {
                                collection: collection.to_owned(),
                                item: item.clone(),
                            },
                        ));
                    }
                }
            }

            let items: Vec<ItemRef> = upserted.iter().map(|(i, _)| i.clone()).collect();
            let mut fetched = HashMap::new();
            for chunk in items.chunks(config.fetch_batch.max(1)) {
                for raw in session.fetch(collection, chunk).await? {
                    let size = raw.bytes.len() as u64;
                    let hash = self.storage.blobs.put(&config.tenant, raw.bytes).await?;
                    fetched.insert(
                        raw.item.id.clone(),
                        (hash, size, raw.version, raw.content_type),
                    );
                }
            }
            for (item, listed_version) in &upserted {
                let Some((blob, size, version, content_type)) = fetched.get(&item.id) else {
                    debug!(account = %config.account, "object vanished before it was fetched");
                    continue;
                };
                report.upserted += 1;
                self.preview_object(config, collection, &item.id, blob)
                    .await;
                events.push(self.event(
                    config,
                    event_key(&[
                        b"pim-upserted",
                        collection.as_bytes(),
                        item.id.as_bytes(),
                        blob.as_bytes(),
                        &previous,
                    ]),
                    EventBody::ObjectUpserted {
                        collection: collection.to_owned(),
                        item: item.clone(),
                        blob: *blob,
                        size: *size,
                        version: version.clone().or_else(|| listed_version.clone()),
                        content_type: content_type.clone(),
                    },
                ));
            }

            let since = record.as_ref().map(|r| r.log_seq).unwrap_or(Seq(0));
            let before = events.len();
            let events = self.drop_replayed_keys(config, since, events).await?;
            report.replayed += (before - events.len()) as u64;
            self.append(config, fence, events).await?;
            let head = self
                .storage
                .log
                .head(&config.tenant, &config.account)
                .await?;
            let saved = CursorRecord {
                cursor: encode_cursor(&batch.cursor.0),
                log_seq: head,
                fence,
            };
            save_fenced(
                &*self.storage.control,
                &config.tenant,
                &path,
                &saved,
                fence,
                |b| {
                    serde_json::from_slice::<CursorRecord>(b)
                        .ok()
                        .map(|r| r.fence)
                },
                expect,
            )
            .await?;
            if !batch.more {
                return Ok(report);
            }
        }
    }

    async fn drop_replayed_keys(
        &self,
        config: &AccountConfig,
        since: Seq,
        events: Vec<Event>,
    ) -> Result<Vec<Event>, EngineError> {
        if events.is_empty() {
            return Ok(events);
        }
        let head = self
            .storage
            .log
            .head(&config.tenant, &config.account)
            .await?;
        if head <= since {
            return Ok(events);
        }
        let mut seen = HashSet::new();
        let mut from = since.next();
        while from <= head {
            let page = match self
                .storage
                .log
                .read(&config.tenant, &config.account, from, 5_000)
                .await
            {
                Ok(page) => page,
                Err(StorageError::Compacted { first }) => {
                    from = Seq(first);
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            let Some(last) = page.last() else { break };
            from = last.seq.next();
            seen.extend(page.into_iter().map(|e| e.key));
        }
        Ok(events
            .into_iter()
            .filter(|e| !seen.contains(&e.key))
            .collect())
    }

    async fn preview_object(
        &self,
        config: &AccountConfig,
        collection: &str,
        item: &str,
        blob: &BlobHash,
    ) {
        let payload = Preview {
            collection,
            item,
            blob: blob.to_hex(),
        };
        let bytes = Bytes::from(serde_json::to_vec(&payload).expect("plain struct"));
        if let Err(e) = self
            .signal
            .publish(
                &skein_core::coordination::group(&config.tenant),
                &format!("preview/{}", config.account),
                bytes,
            )
            .await
        {
            debug!(error = %e, "preview not published");
        }
    }

    /// Runs the account's queued `put_object` and `delete_object` commands in submission order,
    /// if this node owns the account. Other commands are left in the queue untouched: the node
    /// loop routes mail commands to [`Engine::run_commands`] and these to this method.
    ///
    /// Before a command reaches the provider a marker is stored; if the node crashes before the
    /// outcome is in the log, the next run reports the command as `write_uncertain` instead of
    /// running it again. A command cancelled through the API before it started is dropped. When
    /// the provider cannot be reached before a command starts, or refuses the request without
    /// acting on it (sign-in refused, throttled, bad configuration), the error is returned and
    /// the command runs on a later try. The outcome is `write_applied`, `conflict` (with the server's current
    /// bytes as `server_blob` when they could be read), `write_failed` (`blob_missing`,
    /// `collection_not_found`, or the provider's reason) or `write_uncertain` (no answer came
    /// back). An applied `put_object` or `respond_object` whose object the provider read back
    /// also journals `object_upserted` with the command as `origin` and the bytes as the server
    /// holds them (which may differ from the ones sent), which tells the consumer the id of a
    /// created object; the next sync may report the same object again. A command with `notify`
    /// (`respond_object` by default) is followed by `schedule_result`: the server told the other
    /// side, or Skein mailed iTIP messages through the account's sender where the server does
    /// not schedule; those are sent once, never retried.
    pub async fn run_pim_commands(
        &self,
        config: &AccountConfig,
        provider: &dyn PimProvider,
    ) -> Result<CommandReport, CollectionsError> {
        let lease = self.collections_lease(config).await?;
        let mut report = CommandReport::default();
        let mut session: Option<Box<dyn PimSession>> = None;
        let mut after: Option<CommandId> = None;
        let mut seen = 0usize;
        let mut any = false;
        loop {
            let pending = self
                .storage
                .commands
                .pending_after(&config.tenant, &config.account, after.as_ref(), PAGE)
                .await?;
            if pending.is_empty() || seen >= MAX_PER_RUN {
                break;
            }
            after = pending.last().map(|c| c.id.clone());
            seen += pending.len();
            for command in pending {
                if !command.body.is_collection_command() {
                    continue;
                }
                any = true;
                let marker = command_marker(&config.account, command.id.as_str());
                let mark = self
                    .storage
                    .control
                    .get(&config.tenant, &marker)
                    .await?
                    .map(|(b, _)| b);
                if matches!(mark.as_deref(), Some(b"done") | Some(b"cancelled")) {
                    self.finish_pim(config, &command).await?;
                    continue;
                }
                let wants = notifies(&command.body);
                let mut scheduled: Option<EventBody> = None;
                let (outcome, write) = if mark.as_deref() == Some(b"scheduling") {
                    scheduled = Some(crate::schedule::told(
                        &command,
                        ScheduleVia::Mail,
                        Some("interrupted"),
                    ));
                    (
                        WriteOutcome::Applied {
                            item: None,
                            current: None,
                        },
                        None,
                    )
                } else if mark.is_some() {
                    (WriteOutcome::Uncertain, None)
                } else {
                    if session.is_none() {
                        session = Some(provider.connect().await?);
                    }
                    let s = session.as_mut().expect("connected");
                    let collection = collection_of(&command.body);
                    let way = if wants {
                        match s.scheduling(collection).await {
                            Ok(way) => Some(way),
                            Err(PimError::NotFound) => Some(Scheduling::Client),
                            Err(e) => return Err(e.into()),
                        }
                    } else {
                        None
                    };
                    let previous = match (&command.body, way) {
                        (
                            CommandBody::PutObject {
                                item: Some(item), ..
                            }
                            | CommandBody::DeleteObject { item, .. },
                            Some(Scheduling::Client),
                        ) => s
                            .fetch(collection, std::slice::from_ref(item))
                            .await
                            .ok()
                            .and_then(|v| v.into_iter().next()),
                        _ => None,
                    };
                    match self
                        .pim_write(config, &command, way == Some(Scheduling::Server))
                        .await?
                    {
                        None => (
                            WriteOutcome::Failed {
                                reason: "blob_missing".into(),
                            },
                            None,
                        ),
                        Some(write) => {
                            if !self.mark_pim_started(config, lease.fence, &marker).await? {
                                self.finish_pim(config, &command).await?;
                                continue;
                            }
                            let outcome = match s.apply(&write).await {
                                Ok(o) => o,
                                Err(PimError::Network(_)) => WriteOutcome::Uncertain,
                                Err(PimError::NotFound) => WriteOutcome::Failed {
                                    reason: "collection_not_found".into(),
                                },
                                Err(e) => {
                                    if matches!(
                                        e,
                                        PimError::Auth
                                            | PimError::Throttled { .. }
                                            | PimError::Config(_)
                                    ) {
                                        self.storage
                                            .control
                                            .delete(&config.tenant, &marker, Expect::Any)
                                            .await?;
                                    }
                                    return Err(e.into());
                                }
                            };
                            if let (WriteOutcome::Applied { current, .. }, Some(way)) =
                                (&outcome, way)
                            {
                                scheduled = Some(
                                    self.schedule(
                                        config,
                                        lease.fence,
                                        &command,
                                        way,
                                        &marker,
                                        s,
                                        previous.as_ref(),
                                        current.as_ref(),
                                        &write,
                                    )
                                    .await?,
                                );
                            }
                            (outcome, Some(write))
                        }
                    }
                };
                let server_blob = match (&outcome, &write) {
                    (WriteOutcome::Conflict { .. }, Some(w)) => {
                        self.current_bytes(config, session.as_mut(), w).await
                    }
                    _ => None,
                };
                match &outcome {
                    WriteOutcome::Applied { .. } => report.applied += 1,
                    WriteOutcome::Conflict { .. } | WriteOutcome::Failed { .. } => {
                        report.failed += 1
                    }
                    WriteOutcome::Uncertain => report.uncertain += 1,
                }
                let mut events = vec![self.event(
                    config,
                    format!("command-{}", command.id),
                    outcome_body(&command.id, &outcome, server_blob),
                )];
                if let (
                    WriteOutcome::Applied {
                        current: Some(current),
                        ..
                    },
                    CommandBody::PutObject { collection, .. }
                    | CommandBody::RespondObject { collection, .. },
                ) = (&outcome, &command.body)
                {
                    let size = current.bytes.len() as u64;
                    let blob = self
                        .storage
                        .blobs
                        .put(&config.tenant, current.bytes.clone())
                        .await?;
                    events.push(self.event(
                        config,
                        format!("command-{}-object", command.id),
                        EventBody::ObjectUpserted {
                            collection: collection.clone(),
                            item: current.item.clone(),
                            blob,
                            size,
                            version: current.version.clone(),
                            content_type: current.content_type.clone(),
                        },
                    ));
                }
                if let Some(result) = scheduled {
                    events.push(self.event(
                        config,
                        format!("command-{}-schedule", command.id),
                        result,
                    ));
                }
                for event in &mut events {
                    event.origin = Some(command.id.clone());
                    event.trace = command.trace.clone();
                }
                self.append(config, lease.fence, events).await?;
                self.storage
                    .control
                    .put(
                        &config.tenant,
                        &marker,
                        Bytes::from_static(b"done"),
                        Expect::Any,
                    )
                    .await?;
                self.finish_pim(config, &command).await?;
            }
        }
        if let Some(mut session) = session {
            let _ = session.logout().await;
        }
        if !any {
            return Ok(report);
        }
        let metrics = skein_metrics::global();
        metrics.commands_applied.add(report.applied);
        metrics.commands_failed.add(report.failed);
        metrics.commands_uncertain.add(report.uncertain);
        info!(
            account = %config.account,
            applied = report.applied,
            failed = report.failed,
            uncertain = report.uncertain,
            "collection commands finished"
        );
        let head = self
            .storage
            .log
            .head(&config.tenant, &config.account)
            .await?;
        self.hint(config, head).await;
        Ok(report)
    }

    /// The write a command asks for; `None` when its blob is not in the store.
    async fn pim_write(
        &self,
        config: &AccountConfig,
        command: &Command,
        notify: bool,
    ) -> Result<Option<PimWrite>, CollectionsError> {
        Ok(match &command.body {
            CommandBody::PutObject {
                collection,
                item,
                blob,
                if_version,
                ..
            } => self
                .storage
                .blobs
                .get(&config.tenant, blob)
                .await?
                .map(|bytes| PimWrite::Put {
                    collection: collection.clone(),
                    item: item.clone(),
                    bytes,
                    if_version: if_version.clone(),
                    key: command.id.to_string(),
                    notify,
                }),
            CommandBody::DeleteObject {
                collection,
                item,
                if_version,
                ..
            } => Some(PimWrite::Delete {
                collection: collection.clone(),
                item: item.clone(),
                if_version: if_version.clone(),
                notify,
            }),
            CommandBody::RespondObject {
                collection,
                item,
                answer,
                attendee,
                comment,
                if_version,
                ..
            } => Some(PimWrite::Respond {
                collection: collection.clone(),
                item: item.clone(),
                answer: *answer,
                attendee: attendee.clone(),
                comment: comment.clone(),
                if_version: if_version.clone(),
                notify,
            }),
            _ => unreachable!("only collection commands get here"),
        })
    }

    /// Tells the other side about an applied scheduling command: nothing to do where the
    /// server schedules, iMIP through the account's sender otherwise. The marker says
    /// `scheduling` while messages are being sent, so a crash then is reported, never repeated.
    #[allow(clippy::too_many_arguments)]
    async fn schedule(
        &self,
        config: &AccountConfig,
        fence: FencingToken,
        command: &Command,
        way: Scheduling,
        marker: &str,
        session: &mut Box<dyn PimSession>,
        previous: Option<&RawObject>,
        current: Option<&RawObject>,
        write: &PimWrite,
    ) -> Result<EventBody, CollectionsError> {
        if way == Scheduling::Server {
            return Ok(crate::schedule::told(command, ScheduleVia::Server, None));
        }
        let own = session.addresses().await.unwrap_or_default();
        let sent_object;
        let next = match (current, write) {
            (Some(c), _) => Some(c),
            (None, PimWrite::Put { item, bytes, .. }) => {
                sent_object = RawObject {
                    item: item.clone().unwrap_or(ItemRef {
                        id: String::new(),
                        uid: None,
                    }),
                    version: None,
                    bytes: bytes.clone(),
                    content_type: "text/calendar".into(),
                };
                Some(&sent_object)
            }
            _ => None,
        };
        let refetched;
        let planned = match &command.body {
            CommandBody::RespondObject {
                collection, item, ..
            } => {
                let object = match next {
                    Some(o) => Some(o),
                    None => {
                        refetched = session
                            .fetch(collection, std::slice::from_ref(item))
                            .await
                            .ok()
                            .and_then(|v| v.into_iter().next());
                        refetched.as_ref()
                    }
                };
                crate::schedule::reply_message(command, object, &own)
            }
            CommandBody::DeleteObject { .. } => {
                crate::schedule::organizer_messages(command, previous, None, &own)
            }
            _ => crate::schedule::organizer_messages(command, previous, next, &own),
        };
        let planned = match planned {
            Ok(p) => p,
            Err(reason) => {
                return Ok(crate::schedule::told(
                    command,
                    ScheduleVia::None,
                    Some(reason),
                ));
            }
        };
        self.check_lease(config, fence)?;
        self.storage
            .control
            .put(
                &config.tenant,
                marker,
                Bytes::from_static(b"scheduling"),
                Expect::Any,
            )
            .await?;
        Ok(self.mail_itip(config, command, planned).await)
    }

    /// The server's current bytes of the object a conflicting write named, stored as a blob.
    async fn current_bytes(
        &self,
        config: &AccountConfig,
        session: Option<&mut Box<dyn PimSession>>,
        write: &PimWrite,
    ) -> Option<BlobHash> {
        let (collection, item) = match write {
            PimWrite::Put {
                collection,
                item: Some(item),
                ..
            }
            | PimWrite::Delete {
                collection, item, ..
            }
            | PimWrite::Respond {
                collection, item, ..
            } => (collection, item),
            PimWrite::Put { item: None, .. } => return None,
        };
        let raw = session?
            .fetch(collection, std::slice::from_ref(item))
            .await
            .ok()?
            .into_iter()
            .next()?;
        self.storage.blobs.put(&config.tenant, raw.bytes).await.ok()
    }

    async fn mark_pim_started(
        &self,
        config: &AccountConfig,
        fence: FencingToken,
        marker: &str,
    ) -> Result<bool, EngineError> {
        self.check_lease(config, fence)?;
        match self
            .storage
            .control
            .put(
                &config.tenant,
                marker,
                Bytes::from_static(b"started"),
                Expect::Absent,
            )
            .await
        {
            Ok(_) => Ok(true),
            Err(StorageError::Conflict) => {
                let current = self.storage.control.get(&config.tenant, marker).await?;
                Ok(!matches!(current, Some((b, _)) if &b[..] == b"cancelled"))
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn finish_pim(
        &self,
        config: &AccountConfig,
        command: &Command,
    ) -> Result<(), EngineError> {
        self.storage
            .commands
            .complete(&config.tenant, &config.account, &command.id)
            .await?;
        match self
            .storage
            .control
            .delete(
                &config.tenant,
                &command_marker(&config.account, command.id.as_str()),
                Expect::Any,
            )
            .await
        {
            Ok(()) | Err(StorageError::Conflict) => {}
            Err(e) => warn!(error = %e, "command record not removed"),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use baton_lease::Leases;
    use skein_core::{CollectionKind, Timestamp, coordination};
    use skein_pim::testing::{ADDRESS_BOOK, CALENDAR, FakePim, PimServerControl, sample};
    use skein_storage::{ObjectControl, Objects, Storage, Version};
    use skein_storage_memory::MemoryObjects;

    use super::*;
    use crate::test_support::{ManualClock, control_leases, engine_with, profile, single_leases};

    fn tenant() -> TenantId {
        TenantId::new("t").unwrap()
    }

    fn account() -> AccountId {
        AccountId::new("a").unwrap()
    }

    fn config() -> AccountConfig {
        AccountConfig::new(tenant(), account())
    }

    fn engine_over(storage: Storage, leases: Arc<dyn Leases>, node: &str) -> Engine {
        engine_with(storage, leases, node)
    }

    fn single() -> (Engine, Storage) {
        let storage = Storage::over(Arc::new(MemoryObjects::new()));
        (engine_over(storage.clone(), single_leases(), "n1"), storage)
    }

    async fn events(storage: &Storage) -> Vec<Event> {
        storage
            .log
            .read(&tenant(), &account(), Seq(1), 100_000)
            .await
            .unwrap()
    }

    fn count(events: &[Event], pred: impl Fn(&EventBody) -> bool) -> usize {
        events.iter().filter(|e| pred(&e.body)).count()
    }

    fn upserted(b: &EventBody) -> bool {
        matches!(b, EventBody::ObjectUpserted { .. })
    }

    async fn snapshot(storage: &Storage) -> skein_storage::Snapshot {
        let mut s = skein_storage::Snapshot::empty(account());
        for e in events(storage).await {
            s.apply(&e);
        }
        s
    }

    #[tokio::test]
    async fn first_sync_journals_collections_and_every_object_with_its_bytes() {
        let (engine, storage) = single();
        let fake = FakePim::standard();
        fake.fill(CALENDAR, 25);
        fake.fill(ADDRESS_BOOK, 4);
        let mut config = config();
        config.page = 10;
        config.fetch_batch = 3;
        let report = engine.sync_collections(&config, &fake).await.unwrap();
        assert_eq!(report.collections.len(), 2);
        assert_eq!(
            report.collections.iter().map(|c| c.upserted).sum::<u64>(),
            29
        );
        let all = events(&storage).await;
        assert_eq!(
            count(&all, |b| matches!(b, EventBody::CollectionUpserted { .. })),
            2
        );
        assert_eq!(count(&all, upserted), 29);
        for e in &all {
            if let EventBody::ObjectUpserted {
                collection,
                item,
                blob,
                size,
                version,
                content_type,
            } = &e.body
            {
                let bytes = storage.blobs.get(&tenant(), blob).await.unwrap().unwrap();
                let (held_version, held) = fake.read(collection, item).await.unwrap();
                assert_eq!(bytes, held, "exact bytes");
                assert_eq!(*size, held.len() as u64);
                assert_eq!(version, &held_version);
                let kind = if collection == CALENDAR {
                    "text/calendar"
                } else {
                    "text/vcard"
                };
                assert_eq!(content_type, kind);
            }
        }
        let snap = snapshot(&storage).await;
        assert_eq!(snap.object_count(), 29);
        assert_eq!(
            snap.collections[ADDRESS_BOOK].info.kind,
            CollectionKind::AddressBook
        );

        let again = engine.sync_collections(&config, &fake).await.unwrap();
        assert_eq!(again.events, 0, "nothing changed, nothing journaled");
    }

    #[tokio::test]
    async fn incremental_changes_resets_and_collection_changes() {
        let (engine, storage) = single();
        let fake = FakePim::standard();
        fake.fill(CALENDAR, 3);
        let config = config();
        engine.sync_collections(&config, &fake).await.unwrap();

        fake.put(
            CALENDAR,
            "gen-0.ics",
            b"BEGIN:VCALENDAR\r\nX-CHANGED:1\r\nEND:VCALENDAR\r\n",
        )
        .await;
        fake.remove(CALENDAR, "gen-1.ics").await;
        fake.put(
            ADDRESS_BOOK,
            "new.vcf",
            &sample(CollectionKind::AddressBook, "new"),
        )
        .await;
        let r = engine.sync_collections(&config, &fake).await.unwrap();
        let cal = r
            .collections
            .iter()
            .find(|c| c.collection == CALENDAR)
            .unwrap();
        assert_eq!((cal.upserted, cal.removed, cal.reset), (1, 1, false));
        let snap = snapshot(&storage).await;
        assert_eq!(snap.object_count(), 3);
        assert!(
            !snap.collections[CALENDAR]
                .items
                .contains_key(&format!("{CALENDAR}gen-1.ics"))
        );

        fake.invalidate(CALENDAR).await;
        let r = engine.sync_collections(&config, &fake).await.unwrap();
        let cal = r
            .collections
            .iter()
            .find(|c| c.collection == CALENDAR)
            .unwrap();
        assert!(cal.reset);
        assert_eq!(cal.upserted, 2);
        let all = events(&storage).await;
        assert_eq!(
            count(
                &all,
                |b| matches!(b, EventBody::ResyncRequired { collection, .. } if collection == CALENDAR)
            ),
            1
        );
        assert_eq!(
            snapshot(&storage).await.object_count(),
            3,
            "a reset lists everything again"
        );

        fake.add_collection(CALENDAR, CollectionKind::Calendar, "Renamed");
        fake.remove_collection(ADDRESS_BOOK);
        engine.sync_collections(&config, &fake).await.unwrap();
        let snap = snapshot(&storage).await;
        assert_eq!(snap.collections[CALENDAR].info.name, "Renamed");
        assert!(!snap.collections.contains_key(ADDRESS_BOOK));
        let all = events(&storage).await;
        assert_eq!(
            count(&all, |b| matches!(b, EventBody::CollectionDeleted { .. })),
            1
        );

        fake.add_collection(ADDRESS_BOOK, CollectionKind::AddressBook, "Back");
        fake.put(
            ADDRESS_BOOK,
            "b.vcf",
            &sample(CollectionKind::AddressBook, "b"),
        )
        .await;
        engine.sync_collections(&config, &fake).await.unwrap();
        assert_eq!(
            snapshot(&storage).await.collections[ADDRESS_BOOK]
                .items
                .len(),
            1,
            "a collection that came back starts from a fresh cursor"
        );
    }

    struct FailCursorPut {
        inner: Arc<dyn ControlStore>,
        remaining_ok: AtomicUsize,
    }

    #[async_trait]
    impl ControlStore for FailCursorPut {
        async fn get(
            &self,
            t: &TenantId,
            p: &str,
        ) -> Result<Option<(Bytes, Version)>, StorageError> {
            self.inner.get(t, p).await
        }
        async fn put(
            &self,
            t: &TenantId,
            p: &str,
            v: Bytes,
            e: Expect,
        ) -> Result<Version, StorageError> {
            if p.starts_with("pim-cursors/") {
                let left = self.remaining_ok.load(Ordering::SeqCst);
                if left == 0 {
                    self.remaining_ok.store(usize::MAX, Ordering::SeqCst);
                    return Err(StorageError::backend(
                        "simulated crash before the cursor was saved",
                    ));
                }
                if left != usize::MAX {
                    self.remaining_ok.store(left - 1, Ordering::SeqCst);
                }
            }
            self.inner.put(t, p, v, e).await
        }
        async fn delete(&self, t: &TenantId, p: &str, e: Expect) -> Result<(), StorageError> {
            self.inner.delete(t, p, e).await
        }
        async fn list(
            &self,
            t: &TenantId,
            p: &str,
            a: Option<&str>,
            l: usize,
        ) -> Result<Vec<String>, StorageError> {
            self.inner.list(t, p, a, l).await
        }
        async fn purge(&self, t: &TenantId) -> Result<u64, StorageError> {
            self.inner.purge(t).await
        }
    }

    #[tokio::test]
    async fn a_crash_between_journal_and_cursor_never_duplicates_events() {
        let objects: Arc<dyn Objects> = Arc::new(MemoryObjects::new());
        let mut storage = Storage::over(objects.clone());
        storage.control = Arc::new(FailCursorPut {
            inner: Arc::new(ObjectControl::new(objects)),
            remaining_ok: AtomicUsize::new(1),
        });
        let engine = engine_over(storage.clone(), single_leases(), "n1");
        let fake = FakePim::new();
        fake.add_collection(CALENDAR, CollectionKind::Calendar, "Work");
        fake.fill(CALENDAR, 40);
        let mut config = config();
        config.page = 15;
        assert!(
            engine.sync_collections(&config, &fake).await.is_err(),
            "the second batch crashes"
        );
        let report = engine.sync_collections(&config, &fake).await.unwrap();
        assert_eq!(
            report.collections[0].replayed, 15,
            "the batch journaled before the crash is dropped"
        );
        let all = events(&storage).await;
        assert_eq!(count(&all, upserted), 40, "every object exactly once");
    }

    #[tokio::test]
    async fn a_node_that_lost_the_account_cannot_write() {
        let objects: Arc<dyn Objects> = Arc::new(MemoryObjects::new());
        let storage = Storage::over(objects.clone());
        let clock = ManualClock::new();
        let (leases, liveness) = control_leases(&storage, 30_000, Some(clock.clock()));
        let nodes = coordination::group(&tenant());
        liveness
            .heartbeat(&nodes, &profile("n1"), clock.now())
            .await
            .unwrap();
        liveness
            .heartbeat(&nodes, &profile("n2"), clock.now())
            .await
            .unwrap();
        let e1 = engine_over(storage.clone(), leases.clone(), "n1");
        let e2 = engine_over(storage.clone(), leases.clone(), "n2");
        let fake = FakePim::standard();
        fake.fill(CALENDAR, 5);
        let config = config();
        e1.sync_collections(&config, &fake).await.unwrap();
        assert!(
            e2.sync_collections(&config, &fake)
                .await
                .unwrap_err()
                .is_not_owner()
        );
        clock.advance(30_001);
        liveness
            .heartbeat(&nodes, &profile("n2"), clock.now())
            .await
            .unwrap();
        fake.put(CALENDAR, "x.ics", &sample(CollectionKind::Calendar, "x"))
            .await;
        e2.sync_collections(&config, &fake).await.unwrap();
        liveness
            .heartbeat(&nodes, &profile("n1"), clock.now())
            .await
            .unwrap();
        fake.put(CALENDAR, "y.ics", &sample(CollectionKind::Calendar, "y"))
            .await;
        assert!(
            e1.sync_collections(&config, &fake)
                .await
                .unwrap_err()
                .is_not_owner()
        );
        assert!(
            e1.run_pim_commands(&config, &fake)
                .await
                .unwrap_err()
                .is_not_owner()
        );
        let all = events(&storage).await;
        assert_eq!(
            count(&all, upserted),
            6,
            "the old owner wrote nothing after losing the account"
        );
    }

    fn command(body: CommandBody) -> Command {
        Command {
            id: CommandId::generate(),
            account: account(),
            created_at: Timestamp::now(),
            trace: None,
            body,
        }
    }

    fn outcome_of<'a>(all: &'a [Event], id: &CommandId) -> &'a EventBody {
        &all.iter()
            .find(|e| e.key == format!("command-{id}"))
            .expect("an outcome")
            .body
    }

    #[tokio::test]
    async fn put_with_a_stale_version_conflicts_and_delete_removes() {
        let (engine, storage) = single();
        let fake = FakePim::standard();
        let config = config();
        engine.sync_collections(&config, &fake).await.unwrap();

        let bytes = Bytes::from(sample(CollectionKind::Calendar, "meeting"));
        let blob = storage.blobs.put(&tenant(), bytes.clone()).await.unwrap();
        let create = command(CommandBody::PutObject {
            collection: CALENDAR.into(),
            item: None,
            blob,
            if_version: None,
            notify: false,
        });
        let mail = command(CommandBody::Delete {
            mailbox: "INBOX".into(),
            items: vec![],
            to_trash: false,
        });
        storage.commands.submit(&tenant(), &create).await.unwrap();
        storage.commands.submit(&tenant(), &mail).await.unwrap();
        let r = engine.run_pim_commands(&config, &fake).await.unwrap();
        assert_eq!(r.applied, 1);
        let pending = storage
            .commands
            .pending(&tenant(), &account(), 10)
            .await
            .unwrap();
        assert_eq!(
            pending.len(),
            1,
            "mail commands are left for the mail runner"
        );
        assert_eq!(pending[0].id, mail.id);
        let all = events(&storage).await;
        let object = all
            .iter()
            .find(|e| e.key == format!("command-{}-object", create.id))
            .expect("the created object is journaled with its id");
        assert_eq!(object.origin.as_ref(), Some(&create.id));
        let EventBody::ObjectUpserted { item, version, .. } = &object.body else {
            panic!("an object");
        };
        let (held_version, held) = fake.read(CALENDAR, item).await.unwrap();
        assert_eq!(held, bytes);
        assert_eq!(version, &held_version);

        engine.sync_collections(&config, &fake).await.unwrap();
        let changed = Bytes::from(sample(CollectionKind::Calendar, "meeting-moved"));
        let changed_blob = storage.blobs.put(&tenant(), changed.clone()).await.unwrap();
        let stale = command(CommandBody::PutObject {
            collection: CALENDAR.into(),
            item: Some(item.clone()),
            blob: changed_blob,
            if_version: Some("\"0\"".into()),
            notify: false,
        });
        storage.commands.submit(&tenant(), &stale).await.unwrap();
        let r = engine.run_pim_commands(&config, &fake).await.unwrap();
        assert_eq!(r.failed, 1);
        let all = events(&storage).await;
        let EventBody::Conflict { server_blob, .. } = outcome_of(&all, &stale.id) else {
            panic!("a conflict");
        };
        assert_eq!(
            storage
                .blobs
                .get(&tenant(), &server_blob.unwrap())
                .await
                .unwrap()
                .unwrap(),
            bytes,
            "the conflict carries the server's bytes"
        );
        assert_eq!(fake.read(CALENDAR, item).await.unwrap().1, bytes);

        let fresh = command(CommandBody::PutObject {
            collection: CALENDAR.into(),
            item: Some(item.clone()),
            blob: changed_blob,
            if_version: held_version.clone(),
            notify: false,
        });
        storage.commands.submit(&tenant(), &fresh).await.unwrap();
        assert_eq!(
            engine
                .run_pim_commands(&config, &fake)
                .await
                .unwrap()
                .applied,
            1
        );
        assert_eq!(fake.read(CALENDAR, item).await.unwrap().1, changed);

        let (now, _) = fake.read(CALENDAR, item).await.unwrap();
        let delete = command(CommandBody::DeleteObject {
            collection: CALENDAR.into(),
            item: item.clone(),
            if_version: now,
            notify: false,
        });
        storage.commands.submit(&tenant(), &delete).await.unwrap();
        assert_eq!(
            engine
                .run_pim_commands(&config, &fake)
                .await
                .unwrap()
                .applied,
            1
        );
        assert!(fake.read(CALENDAR, item).await.is_none());
        engine.sync_collections(&config, &fake).await.unwrap();
        assert_eq!(snapshot(&storage).await.object_count(), 0);
        let all = events(&storage).await;
        assert!(matches!(
            outcome_of(&all, &delete.id),
            EventBody::WriteApplied { .. }
        ));
    }

    #[tokio::test]
    async fn started_commands_are_uncertain_and_failures_are_reported() {
        let (engine, storage) = single();
        let fake = FakePim::standard();
        let config = config();
        let blob = storage
            .blobs
            .put(
                &tenant(),
                Bytes::from(sample(CollectionKind::AddressBook, "c")),
            )
            .await
            .unwrap();
        let put = |collection: &str| {
            command(CommandBody::PutObject {
                collection: collection.into(),
                item: None,
                blob,
                if_version: None,
                notify: false,
            })
        };
        let crashed = put(ADDRESS_BOOK);
        storage.commands.submit(&tenant(), &crashed).await.unwrap();
        storage
            .control
            .put(
                &tenant(),
                &format!("started/{}/{}", account(), crashed.id),
                Bytes::from_static(b"started"),
                Expect::Any,
            )
            .await
            .unwrap();
        let missing_blob = command(CommandBody::PutObject {
            collection: ADDRESS_BOOK.into(),
            item: None,
            blob: BlobHash::of(b"never uploaded"),
            if_version: None,
            notify: false,
        });
        storage
            .commands
            .submit(&tenant(), &missing_blob)
            .await
            .unwrap();
        let nowhere = put("/nowhere/");
        storage.commands.submit(&tenant(), &nowhere).await.unwrap();
        let lost = put(ADDRESS_BOOK);
        storage.commands.submit(&tenant(), &lost).await.unwrap();
        fake.lose_next_answer();
        let r = engine.run_pim_commands(&config, &fake).await.unwrap();
        assert_eq!((r.applied, r.failed, r.uncertain), (0, 2, 2));
        assert_eq!(
            fake.writes(),
            1,
            "the command that may have run was not sent"
        );
        let all = events(&storage).await;
        assert!(matches!(
            outcome_of(&all, &crashed.id),
            EventBody::WriteUncertain { .. }
        ));
        assert!(matches!(
            outcome_of(&all, &lost.id),
            EventBody::WriteUncertain { .. }
        ));
        assert!(matches!(
            outcome_of(&all, &missing_blob.id),
            EventBody::WriteFailed { reason, .. } if reason == "blob_missing"
        ));
        assert!(matches!(
            outcome_of(&all, &nowhere.id),
            EventBody::WriteFailed { reason, .. } if reason == "collection_not_found"
        ));
        assert!(
            storage
                .commands
                .pending(&tenant(), &account(), 10)
                .await
                .unwrap()
                .is_empty()
        );

        let throttled = put(ADDRESS_BOOK);
        storage
            .commands
            .submit(&tenant(), &throttled)
            .await
            .unwrap();
        fake.fail_next(PimError::Throttled { retry_after: None });
        assert!(engine.run_pim_commands(&config, &fake).await.is_err());
        let r = engine.run_pim_commands(&config, &fake).await.unwrap();
        assert_eq!(
            r.applied, 1,
            "a command that never reached the provider runs on the next try"
        );
    }

    #[tokio::test]
    async fn collection_sync_outcomes_land_in_the_status_record() {
        let (engine, storage) = single();
        let fake = FakePim::standard();
        let config = config();
        fake.fail_next(PimError::Network("down".into()));
        assert!(engine.sync_collections(&config, &fake).await.is_err());
        let status = crate::load_status(&*storage.control, &tenant(), &account())
            .await
            .unwrap()
            .unwrap();
        let pim = status.pim.unwrap();
        assert_eq!(pim.outcome, skein_core::SyncOutcome::Network);
        assert!(status.mail.is_none());
        engine.sync_collections(&config, &fake).await.unwrap();
        let pim = crate::load_status(&*storage.control, &tenant(), &account())
            .await
            .unwrap()
            .unwrap()
            .pim
            .unwrap();
        assert_eq!(pim.outcome, skein_core::SyncOutcome::Ok);
        assert_eq!(pim.error, Some(skein_core::SyncOutcome::Network));
    }
}
