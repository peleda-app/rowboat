use std::collections::HashSet;

use baton_lease::Lease;
use bytes::Bytes;
use serde::Serialize;
use skein_core::{
    AccountHealth, Event, EventBody, FencingToken, MailboxInfo, MailboxRole, SCHEMA_VERSION, Seq,
    SyncOutcome, Timestamp,
};
use skein_mail::{MailChange, MailError, MailProvider, MailSession};
use skein_storage::MAX_SEGMENT_EVENTS;
use tracing::{debug, info, warn};

use crate::state::{CursorRecord, encode_cursor, load_cursor, load_state, save_cursor, save_state};
use crate::status::{Area, mail_outcome};
use crate::{AccountConfig, Engine, EngineError};

/// What one sync run did in one mailbox.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MailboxReport {
    /// Mailbox id.
    pub mailbox: String,
    /// Messages added to the journal.
    pub added: u64,
    /// Removals recorded.
    pub removed: u64,
    /// Flag and label changes recorded.
    pub changed: u64,
    /// Events dropped because they were already in the log (a crash replay).
    pub replayed: u64,
    /// Whether the provider reset the cursor.
    pub reset: bool,
}

/// What one sync run did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Per mailbox.
    pub mailboxes: Vec<MailboxReport>,
    /// Events appended in total.
    pub events: u64,
    /// The log head after the run.
    pub head: Seq,
}

#[derive(Serialize)]
struct Preview<'a> {
    mailbox: &'a str,
    item: &'a str,
    blob: String,
}

fn event_key(parts: &[&[u8]]) -> String {
    let mut h = blake3::Hasher::new();
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    h.finalize().to_hex()[..32].to_owned()
}

impl Engine {
    /// Syncs every mailbox of the account once, if this node owns it.
    pub async fn sync_account(
        &self,
        config: &AccountConfig,
        provider: &dyn MailProvider,
    ) -> Result<SyncReport, EngineError> {
        let lease = self.lease(config).await?;
        let started = std::time::Instant::now();
        let mut reset_seen = false;
        let result = self
            .sync_owned(config, provider, &lease, &mut reset_seen)
            .await;
        let metrics = skein_metrics::global();
        match &result {
            Ok(report) => {
                self.record_status(config, lease.fence, Area::Mail, SyncOutcome::Ok, false)
                    .await;
                metrics.sync_ok.inc();
                metrics
                    .sync_millis
                    .add(started.elapsed().as_millis() as u64);
                metrics.events_appended.add(report.events);
                metrics
                    .messages_added
                    .add(report.mailboxes.iter().map(|m| m.added).sum());
                metrics
                    .events_replayed
                    .add(report.mailboxes.iter().map(|m| m.replayed).sum());
            }
            Err(e) => {
                metrics.sync_failed(match e {
                    EngineError::Mail(MailError::Auth) => skein_metrics::SyncFailure::Auth,
                    EngineError::Mail(MailError::Throttled { .. }) => {
                        skein_metrics::SyncFailure::Throttled
                    }
                    EngineError::Mail(m) if m.connection_lost() => {
                        skein_metrics::SyncFailure::Network
                    }
                    EngineError::NotOwner => skein_metrics::SyncFailure::NotOwner,
                    _ => skein_metrics::SyncFailure::Other,
                });
                self.record_health(config, &lease, e).await;
                if let Some(outcome) = mail_outcome(e) {
                    self.record_status(config, lease.fence, Area::Mail, outcome, reset_seen)
                        .await;
                }
            }
        }
        result
    }

    async fn sync_owned(
        &self,
        config: &AccountConfig,
        provider: &dyn MailProvider,
        lease: &Lease,
        reset_seen: &mut bool,
    ) -> Result<SyncReport, EngineError> {
        let started = std::time::Instant::now();
        let mut session = provider.connect().await?;
        let (mut state, state_expect) =
            load_state(&*self.storage.control, &config.tenant, &config.account).await?;
        if state.fence > lease.fence {
            return Err(EngineError::NotOwner);
        }
        let mut report = SyncReport::default();

        let mailboxes = session.mailboxes().await?;
        let mut events = Vec::new();
        for mb in &mailboxes {
            if !state.mailboxes.iter().any(|old| old == mb) {
                events.push(self.event(
                    config,
                    event_key(&[b"mailbox", mb.id.as_bytes(), mb.path.as_bytes()]),
                    EventBody::MailboxUpserted {
                        mailbox: mb.clone(),
                    },
                ));
            }
        }
        for old in &state.mailboxes {
            if !mailboxes.iter().any(|mb| mb.id == old.id) {
                events.push(self.event(
                    config,
                    event_key(&[b"mailbox-deleted", old.id.as_bytes()]),
                    EventBody::MailboxDeleted {
                        mailbox: old.id.clone(),
                    },
                ));
            }
        }
        let capabilities = session.capabilities().await?;
        if state.capabilities.as_ref() != Some(&capabilities) {
            let encoded = serde_json::to_vec(&capabilities).expect("plain struct");
            events.push(self.event(
                config,
                event_key(&[b"capabilities", &encoded]),
                EventBody::AccountCapabilities {
                    mail: capabilities.clone(),
                },
            ));
            state.capabilities = Some(capabilities);
        }
        if state.health != Some(AccountHealth::Healthy) {
            events.push(self.event(
                config,
                event_key(&[b"health", b"healthy", &lease.fence.0.to_le_bytes()]),
                EventBody::AccountHealthChanged {
                    health: AccountHealth::Healthy,
                },
            ));
            state.health = Some(AccountHealth::Healthy);
        }
        let head = self
            .storage
            .log
            .head(&config.tenant, &config.account)
            .await?;
        let since = if state.log_seq == Seq(0) && state.first_sync_done {
            head
        } else {
            state.log_seq
        };
        let earlier = self.keys_between(config, since, head).await?;
        let events: Vec<Event> = events
            .into_iter()
            .filter(|e| !earlier.contains(&e.key))
            .collect();
        report.events += self.append(config, lease.fence, events).await?;

        for mb in selected(config, &mailboxes) {
            let mr = self
                .sync_mailbox(config, &mut *session, lease.fence, &mb.id, reset_seen)
                .await?;
            report.events += mr.added + mr.removed + mr.changed + u64::from(mr.reset);
            report.mailboxes.push(mr);
        }

        if !state.first_sync_done {
            let done = vec![self.event(
                config,
                event_key(&[b"first-sync"]),
                EventBody::FirstSyncCompleted,
            )];
            let done: Vec<Event> = done
                .into_iter()
                .filter(|e| !earlier.contains(&e.key))
                .collect();
            report.events += self.append(config, lease.fence, done).await?;
            state.first_sync_done = true;
        }
        state.mailboxes = mailboxes;
        state.fence = lease.fence;
        state.log_seq = self
            .storage
            .log
            .head(&config.tenant, &config.account)
            .await?;
        save_state(
            &*self.storage.control,
            &config.tenant,
            &config.account,
            &state,
            state_expect,
        )
        .await?;
        let _ = session.logout().await;
        report.head = self
            .storage
            .log
            .head(&config.tenant, &config.account)
            .await?;
        info!(
            account = %config.account,
            events = report.events,
            head = report.head.0,
            ms = started.elapsed().as_millis() as u64,
            "sync finished"
        );
        self.hint(config, report.head).await;
        Ok(report)
    }

    async fn sync_mailbox(
        &self,
        config: &AccountConfig,
        session: &mut dyn MailSession,
        fence: FencingToken,
        mailbox: &str,
        reset_seen: &mut bool,
    ) -> Result<MailboxReport, EngineError> {
        let mut report = MailboxReport {
            mailbox: mailbox.to_owned(),
            ..Default::default()
        };
        loop {
            let (record, expect) = load_cursor(
                &*self.storage.control,
                &config.tenant,
                &config.account,
                mailbox,
            )
            .await?;
            if let Some(r) = &record
                && r.fence > fence
            {
                return Err(EngineError::NotOwner);
            }
            let cursor = record
                .as_ref()
                .map(|r| r.cursor_bytes().map(skein_mail::Cursor))
                .transpose()?;
            let previous = record
                .as_ref()
                .map(|r| r.cursor.as_bytes().to_vec())
                .unwrap_or_default();
            let batch = session
                .changes(mailbox, cursor.as_ref(), config.page)
                .await?;

            let mut events = Vec::new();
            let mut added = Vec::new();
            for change in &batch.changes {
                match change {
                    MailChange::Reset { reason } => {
                        report.reset = true;
                        *reset_seen = true;
                        events.push(self.event(
                            config,
                            event_key(&[b"reset", mailbox.as_bytes(), &previous]),
                            EventBody::ResyncRequired {
                                collection: mailbox.to_owned(),
                                reason: reason.clone(),
                                domain: Some(skein_core::Domain::Mail),
                            },
                        ));
                    }
                    MailChange::Added { item, .. } => added.push(item.clone()),
                    MailChange::Removed { item } => {
                        report.removed += 1;
                        events.push(self.event(
                            config,
                            event_key(&[b"removed", mailbox.as_bytes(), item.id.as_bytes()]),
                            EventBody::MessageRemoved {
                                mailbox: mailbox.to_owned(),
                                item: item.clone(),
                            },
                        ));
                    }
                    MailChange::Flags { item, flags } => {
                        report.changed += 1;
                        let joined = flags.iter().collect::<Vec<_>>().join(" ");
                        events.push(self.event(
                            config,
                            event_key(&[
                                b"flags",
                                mailbox.as_bytes(),
                                item.id.as_bytes(),
                                joined.as_bytes(),
                                &previous,
                            ]),
                            EventBody::FlagsChanged {
                                mailbox: mailbox.to_owned(),
                                item: item.clone(),
                                flags: flags.clone(),
                            },
                        ));
                    }
                    MailChange::Labels { item, labels } => {
                        report.changed += 1;
                        events.push(self.event(
                            config,
                            event_key(&[
                                b"labels",
                                mailbox.as_bytes(),
                                item.id.as_bytes(),
                                labels.join("\n").as_bytes(),
                                &previous,
                            ]),
                            EventBody::LabelsChanged {
                                mailbox: mailbox.to_owned(),
                                item: item.clone(),
                                labels: labels.clone(),
                            },
                        ));
                    }
                }
            }

            let mut fetched = std::collections::HashMap::new();
            let mut itips = std::collections::HashMap::new();
            for chunk in added.chunks(config.fetch_batch.max(1)) {
                for raw in session.fetch(mailbox, chunk).await? {
                    let hash = self
                        .storage
                        .blobs
                        .put(&config.tenant, raw.bytes.clone())
                        .await?;
                    if self.inspect_messages
                        && let Some(found) = skein_itip::imip::find(&raw.bytes)
                        && let Ok(summary) = skein_itip::summary(&found.calendar)
                    {
                        let size = found.calendar.len() as u64;
                        let part = self
                            .storage
                            .blobs
                            .put(&config.tenant, found.calendar)
                            .await?;
                        itips.insert(raw.item.id.clone(), (part, size, summary));
                    }
                    fetched.insert(raw.item.id.clone(), (hash, raw.bytes.len() as u64));
                }
            }
            for change in &batch.changes {
                if let MailChange::Added {
                    item,
                    flags,
                    labels,
                    received_at,
                } = change
                {
                    let Some((blob, size)) = fetched.get(&item.id) else {
                        debug!(account = %config.account, "message vanished before it was fetched");
                        continue;
                    };
                    report.added += 1;
                    self.preview(config, mailbox, &item.id, blob).await;
                    events.push(self.event(
                        config,
                        event_key(&[
                            b"added",
                            mailbox.as_bytes(),
                            item.id.as_bytes(),
                            blob.as_bytes(),
                            &previous,
                        ]),
                        EventBody::MessageAdded {
                            mailbox: mailbox.to_owned(),
                            item: item.clone(),
                            blob: *blob,
                            size: *size,
                            flags: flags.clone(),
                            labels: labels.clone(),
                            received_at: *received_at,
                        },
                    ));
                    if let Some((part, size, summary)) = itips.remove(&item.id) {
                        events.push(self.event(
                            config,
                            event_key(&[
                                b"itip",
                                mailbox.as_bytes(),
                                item.id.as_bytes(),
                                blob.as_bytes(),
                                &previous,
                            ]),
                            EventBody::ItipReceived {
                                mailbox: mailbox.to_owned(),
                                item: item.clone(),
                                blob: part,
                                size,
                                itip: Box::new(summary),
                            },
                        ));
                    }
                }
            }

            let since = record.as_ref().map(|r| r.log_seq).unwrap_or(Seq(0));
            let before = events.len();
            let events = self.drop_replayed(config, since, events).await?;
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
            save_cursor(
                &*self.storage.control,
                &config.tenant,
                &config.account,
                mailbox,
                &saved,
                expect,
            )
            .await?;
            if !batch.more {
                return Ok(report);
            }
        }
    }

    /// The keys of events after `since` up to `until`: what an earlier owner journaled after the
    /// account state was last saved, before this run wrote anything. Empty, without a read, when
    /// nothing was journaled in between.
    async fn keys_between(
        &self,
        config: &AccountConfig,
        since: Seq,
        until: Seq,
    ) -> Result<HashSet<String>, EngineError> {
        let mut seen = HashSet::new();
        let mut from = since.next();
        while from <= until {
            let page = match self
                .storage
                .log
                .read(&config.tenant, &config.account, from, 5_000)
                .await
            {
                Ok(page) => page,
                Err(skein_storage::StorageError::Compacted { first }) => {
                    from = Seq(first);
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            let Some(last) = page.last() else { break };
            from = last.seq.next();
            seen.extend(page.into_iter().filter(|e| e.seq <= until).map(|e| e.key));
        }
        Ok(seen)
    }

    async fn drop_replayed(
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
                Err(skein_storage::StorageError::Compacted { first }) => {
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

    pub(crate) async fn append(
        &self,
        config: &AccountConfig,
        fence: FencingToken,
        events: Vec<Event>,
    ) -> Result<u64, EngineError> {
        let n = events.len() as u64;
        let mut events = events;
        while !events.is_empty() {
            let rest = events.split_off(events.len().min(MAX_SEGMENT_EVENTS as usize));
            self.storage
                .log
                .append(&config.tenant, &config.account, fence, events)
                .await?;
            events = rest;
        }
        Ok(n)
    }

    pub(crate) fn event(&self, config: &AccountConfig, key: String, body: EventBody) -> Event {
        Event {
            v: SCHEMA_VERSION,
            seq: Seq(0),
            at: Timestamp::now(),
            account: config.account.clone(),
            key,
            origin: None,
            trace: None,
            body,
        }
    }

    async fn preview(
        &self,
        config: &AccountConfig,
        mailbox: &str,
        item: &str,
        blob: &skein_core::BlobHash,
    ) {
        let payload = Preview {
            mailbox,
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

    pub(crate) async fn hint(&self, config: &AccountConfig, head: Seq) {
        let bytes = Bytes::from(head.0.to_string());
        if let Err(e) = self
            .signal
            .publish(
                &skein_core::coordination::group(&config.tenant),
                &format!("heads/{}", config.account),
                bytes,
            )
            .await
        {
            debug!(error = %e, "hint not published");
        }
    }

    async fn record_health(&self, config: &AccountConfig, lease: &Lease, error: &EngineError) {
        let health = match error {
            EngineError::Mail(MailError::Auth) => AccountHealth::ReauthRequired,
            EngineError::Mail(MailError::Throttled { .. }) => AccountHealth::Throttled,
            EngineError::NotOwner => return,
            _ => AccountHealth::Degraded,
        };
        warn!(account = %config.account, ?health, "sync failed");
        let Ok((mut state, expect)) =
            load_state(&*self.storage.control, &config.tenant, &config.account).await
        else {
            return;
        };
        if state.health == Some(health) || state.fence > lease.fence {
            return;
        }
        let tag = format!("{health:?}");
        let event = self.event(
            config,
            event_key(&[b"health", tag.as_bytes(), &Timestamp::now().0.to_le_bytes()]),
            EventBody::AccountHealthChanged { health },
        );
        if self.append(config, lease.fence, vec![event]).await.is_ok() {
            state.health = Some(health);
            state.fence = lease.fence;
            let _ = save_state(
                &*self.storage.control,
                &config.tenant,
                &config.account,
                &state,
                expect,
            )
            .await;
        }
    }
}

/// Mailboxes to sync: selectable, allowed by include and exclude, and without Gmail label
/// mailboxes when an `All` mailbox is synced (their messages arrive from `All` with labels).
fn selected<'a>(config: &AccountConfig, mailboxes: &'a [MailboxInfo]) -> Vec<&'a MailboxInfo> {
    let allowed = |mb: &MailboxInfo| {
        mb.selectable
            && !config.exclude.contains(&mb.id)
            && config
                .include
                .as_ref()
                .is_none_or(|inc| inc.contains(&mb.id))
    };
    let has_all = mailboxes
        .iter()
        .any(|mb| mb.role == Some(MailboxRole::All) && allowed(mb));
    mailboxes
        .iter()
        .filter(|mb| allowed(mb))
        .filter(|mb| {
            !(has_all && mb.label && config.include.as_ref().is_none_or(|i| !i.contains(&mb.id)))
        })
        .collect()
}
