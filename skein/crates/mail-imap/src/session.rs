//! A signed-in session: mailboxes, change feeds and raw messages.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use async_imap::types::{Fetch, Flag};
use async_trait::async_trait;
use bytes::Bytes;
use futures::TryStreamExt;
use skein_core::{
    CommandBody, Flags, ItemRef, MailCapabilities, MailboxInfo, MailboxRole, Timestamp,
};
use skein_mail::{
    Cursor, MailChange, MailError, MailSession, MailboxChanges, RawMessage, WriteOutcome,
};

use crate::cursor::{CursorState, Snapshot};
use crate::{Caps, Session, SignedIn, convert, labels, list_mailboxes, timed, uid_set};

/// Messages per `UID FETCH` of metadata or flags.
const FETCH_BATCH: usize = 500;
/// UIDs per flag scan over known messages on servers without `CONDSTORE`.
const FLAG_SCAN_BATCH: usize = 5_000;
/// Bytes of message bodies asked for in one `UID FETCH`; a single larger message goes alone.
const BODY_BATCH_BYTES: u64 = 32 * 1024 * 1024;

pub(crate) struct Selected {
    pub id: String,
    pub writable: bool,
    pub validity: u32,
    /// `PERMANENTFLAGS` of a writable selection, or its `FLAGS` when the server sent none.
    pub permanent: Vec<String>,
    /// Whether `PERMANENTFLAGS` held `\*`.
    pub keywords: bool,
}

/// What the session knows about one listed mailbox.
pub(crate) struct Named {
    pub raw: String,
    pub selectable: bool,
    pub role: Option<MailboxRole>,
}

struct Status {
    validity: u32,
    uid_next: Option<u32>,
    modseq: Option<u64>,
    exists: u32,
}

pub(crate) struct ImapSession {
    pub(crate) session: Session,
    pub(crate) caps: Caps,
    pub(crate) timeout: Duration,
    pub(crate) names: HashMap<String, Named>,
    pub(crate) trash: Option<String>,
    pub(crate) delimiter: Option<Option<String>>,
    pub(crate) selected: Option<Selected>,
    pub(crate) broken: bool,
}

impl ImapSession {
    pub(crate) fn new(signed_in: SignedIn, timeout: Duration) -> Self {
        Self {
            session: signed_in.session,
            caps: signed_in.caps,
            timeout,
            names: HashMap::new(),
            trash: None,
            delimiter: None,
            selected: None,
            broken: false,
        }
    }

    fn check(&mut self) -> Result<(), MailError> {
        if self.broken {
            return Err(MailError::Network(
                "the connection broke earlier; connect again".into(),
            ));
        }
        while self.session.unsolicited_responses.try_recv().is_ok() {}
        Ok(())
    }

    fn settle<T>(&mut self, result: Result<T, MailError>) -> Result<T, MailError> {
        if matches!(result, Err(MailError::Network(_))) {
            self.broken = true;
        }
        result
    }

    pub(crate) fn clear_names(&mut self) {
        self.names.clear();
        self.trash = None;
    }

    pub(crate) async fn refresh_names(&mut self) -> Result<Vec<MailboxInfo>, MailError> {
        let listed = list_mailboxes(&mut self.session, self.caps.gmail, self.timeout).await?;
        self.clear_names();
        let mut out = Vec::with_capacity(listed.len());
        for (info, raw) in listed {
            if self.trash.is_none() && info.selectable && info.role == Some(MailboxRole::Trash) {
                self.trash = Some(info.id.clone());
            }
            self.names.insert(
                info.id.clone(),
                Named {
                    raw,
                    selectable: info.selectable,
                    role: info.role,
                },
            );
            out.push(info);
        }
        Ok(out)
    }

    /// What is known about a listed mailbox, selectable or not; `None` when it is not listed.
    pub(crate) async fn named(&mut self, id: &str) -> Result<Option<&Named>, MailError> {
        if !self.names.contains_key(id) {
            self.refresh_names().await?;
        }
        Ok(self.names.get(id))
    }

    /// The server's name of a selectable mailbox; `MailboxNotFound` otherwise.
    pub(crate) async fn raw_name(&mut self, id: &str) -> Result<String, MailError> {
        match self.named(id).await? {
            Some(named) if named.selectable => Ok(named.raw.clone()),
            _ => Err(MailError::MailboxNotFound),
        }
    }

    /// Opens `id` with `EXAMINE`, or with `SELECT` when `writable`.
    async fn open(&mut self, id: &str, writable: bool) -> Result<Status, MailError> {
        let raw = self.raw_name(id).await?;
        self.selected = None;
        let opened = if writable {
            timed(self.timeout, self.session.select(&raw)).await?
        } else {
            timed(self.timeout, self.session.examine(&raw)).await?
        };
        let mailbox = match opened {
            Ok(mailbox) => mailbox,
            Err(async_imap::error::Error::No(text)) if !crate::throttle_hint(&text) => {
                self.names.clear();
                return Err(MailError::MailboxNotFound);
            }
            Err(other) => return Err(convert(other)),
        };
        let validity = mailbox
            .uid_validity
            .ok_or_else(|| MailError::Protocol("the mailbox has no UIDVALIDITY".into()))?;
        let permanent = if mailbox.permanent_flags.is_empty() {
            &mailbox.flags
        } else {
            &mailbox.permanent_flags
        };
        let keywords = permanent.iter().any(|f| matches!(f, Flag::MayCreate));
        let permanent = permanent.iter().cloned().filter_map(flag_name).collect();
        self.selected = Some(Selected {
            id: id.to_owned(),
            writable,
            validity,
            permanent,
            keywords,
        });
        Ok(Status {
            validity,
            uid_next: mailbox.uid_next,
            modseq: mailbox.highest_modseq,
            exists: mailbox.exists,
        })
    }

    pub(crate) async fn select_writable(&mut self, id: &str) -> Result<u32, MailError> {
        Ok(self.open(id, true).await?.validity)
    }

    pub(crate) async fn examined(&mut self, id: &str) -> Result<u32, MailError> {
        if let Some(selected) = &self.selected
            && selected.id == id
            && !selected.writable
        {
            return Ok(selected.validity);
        }
        Ok(self.open(id, false).await?.validity)
    }

    async fn search(&mut self, query: &str) -> Result<HashSet<u32>, MailError> {
        timed(self.timeout, self.session.uid_search(query))
            .await?
            .map_err(convert)
    }

    pub(crate) async fn uid_fetch(
        &mut self,
        set: &str,
        items: &str,
    ) -> Result<Vec<Fetch>, MailError> {
        timed(self.timeout, async {
            self.session
                .uid_fetch(set, items)
                .await?
                .try_collect::<Vec<_>>()
                .await
        })
        .await?
        .map_err(convert)
    }

    fn snapshot(&self, fetch: &Fetch) -> Snapshot {
        let flags = Flags::new(fetch.flags().filter_map(flag_name));
        let labels = if self.caps.gmail {
            fetch
                .gmail_labels()
                .map(|raw| labels::label_names(raw.iter().map(|l| l.as_ref())))
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        Snapshot {
            flags: flags.iter().map(str::to_owned).collect(),
            labels,
        }
    }

    pub(crate) fn item(&self, validity: u32, uid: u32, msgid: u64) -> ItemRef {
        let id = if self.caps.gmail && msgid != 0 {
            msgid.to_string()
        } else {
            format!("{validity}:{uid}")
        };
        ItemRef { id, uid: Some(uid) }
    }

    /// Whether `item` can name a message in a mailbox whose `UIDVALIDITY` is `validity`. Gmail
    /// ids are `X-GM-MSGID`s, checked against the server separately.
    pub(crate) fn plausible(&self, item: &ItemRef, validity: u32) -> Option<u32> {
        let uid = item.uid?;
        if item.id == format!("{validity}:{uid}") {
            return Some(uid);
        }
        (self.caps.gmail && item.id.parse::<u64>().is_ok()).then_some(uid)
    }

    async fn changes_inner(
        &mut self,
        mailbox: &str,
        cursor: Option<&Cursor>,
        limit: usize,
    ) -> Result<MailboxChanges, MailError> {
        let started = Instant::now();
        let limit = limit.max(1);
        let status = self.open(mailbox, false).await?;
        let gmail = self.caps.gmail;
        let mut changes = Vec::new();
        let previous = match cursor.map(|c| CursorState::decode(&c.0)) {
            None => None,
            Some(Err(_)) => {
                changes.push(MailChange::Reset {
                    reason: "unreadable_cursor".into(),
                });
                None
            }
            Some(Ok(c)) if c.validity != status.validity => {
                changes.push(MailChange::Reset {
                    reason: "uidvalidity".into(),
                });
                None
            }
            Some(Ok(c)) if c.gmail != gmail => {
                changes.push(MailChange::Reset {
                    reason: "server_changed".into(),
                });
                None
            }
            Some(Ok(c)) => Some(c),
        };
        let continuing = previous.is_some();
        let mut state = previous.unwrap_or_else(|| CursorState::new(status.validity, gmail));
        let uid_next = status.uid_next.unwrap_or(0);
        let exists = status.exists as usize;

        let mut fresh: Vec<u32>;
        let mut gone: Vec<u32> = Vec::new();
        let complete = continuing && !state.partial && state.uidnext != 0;
        if complete && uid_next == state.uidnext && exists == state.len() {
            fresh = Vec::new();
        } else {
            let above = if complete {
                let since = state.uidnext;
                let found = self.search(&format!("UID {since}:*")).await?;
                let new: Vec<u32> = found
                    .into_iter()
                    .filter(|&u| u >= since && !state.contains(u))
                    .collect();
                (exists == state.len() + new.len()).then_some(new)
            } else {
                None
            };
            match above {
                Some(new) => fresh = new,
                None => {
                    let all = self.search("ALL").await?;
                    gone = state.uids().filter(|u| !all.contains(u)).collect();
                    fresh = all.into_iter().filter(|&u| !state.contains(u)).collect();
                }
            }
        }
        fresh.sort_unstable();

        for &uid in &gone {
            let msgid = state.remove(uid).unwrap_or(0);
            changes.push(MailChange::Removed {
                item: self.item(status.validity, uid, msgid),
            });
        }

        let flag_items = if gmail {
            "(UID FLAGS X-GM-LABELS)"
        } else {
            "(UID FLAGS)"
        };
        let mut seen: Vec<(u32, Snapshot)> = Vec::new();
        if continuing && state.len() > 0 {
            match (status.modseq, state.modseq) {
                (Some(now), Some(before)) if now == before => {}
                (Some(_), Some(before)) => {
                    let items = format!("{flag_items} (CHANGEDSINCE {before})");
                    for fetch in self.uid_fetch("1:*", &items).await? {
                        if let Some(uid) = fetch.uid {
                            seen.push((uid, self.snapshot(&fetch)));
                        }
                    }
                }
                _ => {
                    let known: Vec<u32> = state.uids().collect();
                    for chunk in known.chunks(FLAG_SCAN_BATCH) {
                        let set = format!("{}:{}", chunk[0], chunk[chunk.len() - 1]);
                        for fetch in self.uid_fetch(&set, flag_items).await? {
                            if let Some(uid) = fetch.uid {
                                seen.push((uid, self.snapshot(&fetch)));
                            }
                        }
                    }
                }
            }
        }
        seen.sort_by_key(|(uid, _)| *uid);
        seen.dedup_by_key(|(uid, _)| *uid);
        let mut flag_changes = 0usize;
        for (uid, now) in seen {
            let Some((msgid, before)) = state.get(uid) else {
                continue;
            };
            if *before == now {
                continue;
            }
            let item = self.item(status.validity, uid, msgid);
            if before.flags != now.flags {
                changes.push(MailChange::Flags {
                    item: item.clone(),
                    flags: Flags::new(now.flags.iter().cloned()),
                });
            }
            if gmail && before.labels != now.labels {
                changes.push(MailChange::Labels {
                    item,
                    labels: now.labels.clone(),
                });
            }
            flag_changes += 1;
            state.set(uid, now);
        }

        let more = fresh.len() > limit;
        fresh.truncate(limit);
        let mut skipped = false;
        let meta = if gmail {
            "(UID FLAGS INTERNALDATE X-GM-MSGID X-GM-LABELS)"
        } else {
            "(UID FLAGS INTERNALDATE)"
        };
        let mut added = 0usize;
        for chunk in fresh.chunks(FETCH_BATCH) {
            let fetches = self.uid_fetch(&uid_set(chunk), meta).await?;
            let mut by_uid: HashMap<u32, &Fetch> = HashMap::new();
            for fetch in &fetches {
                if let Some(uid) = fetch.uid {
                    by_uid.insert(uid, fetch);
                }
            }
            for &uid in chunk {
                let Some(fetch) = by_uid.get(&uid) else {
                    skipped = true;
                    continue;
                };
                let snapshot = self.snapshot(fetch);
                let msgid = fetch.gmail_msg_id().copied().unwrap_or(0);
                changes.push(MailChange::Added {
                    item: self.item(status.validity, uid, msgid),
                    flags: Flags::new(snapshot.flags.iter().cloned()),
                    labels: gmail.then(|| snapshot.labels.clone()),
                    received_at: fetch
                        .internal_date()
                        .map(|d| Timestamp(d.timestamp_millis())),
                });
                state.insert(uid, msgid, snapshot);
                added += 1;
            }
        }

        state.uidnext = uid_next;
        state.modseq = status.modseq;
        state.partial = more || skipped;
        tracing::debug!(
            added,
            removed = gone.len(),
            flag_changes,
            known = state.len(),
            more,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "imap changes"
        );
        Ok(MailboxChanges {
            changes,
            cursor: Cursor(Bytes::from(state.encode())),
            more,
        })
    }

    async fn fetch_inner(
        &mut self,
        mailbox: &str,
        items: &[ItemRef],
    ) -> Result<Vec<RawMessage>, MailError> {
        let validity = self.examined(mailbox).await?;
        let mut uids: Vec<u32> = items
            .iter()
            .filter_map(|i| self.plausible(i, validity))
            .collect();
        uids.sort_unstable();
        uids.dedup();
        let gmail = self.caps.gmail;
        let meta = if gmail {
            "(UID RFC822.SIZE X-GM-MSGID)"
        } else {
            "(UID RFC822.SIZE)"
        };
        let mut msgids: HashMap<u32, u64> = HashMap::new();
        let mut bodies: HashMap<u32, Bytes> = HashMap::new();
        for chunk in uids.chunks(FETCH_BATCH) {
            let mut present: Vec<(u32, u64)> = Vec::new();
            for fetch in self.uid_fetch(&uid_set(chunk), meta).await? {
                let Some(uid) = fetch.uid else { continue };
                if chunk.binary_search(&uid).is_err() {
                    continue;
                }
                present.push((uid, u64::from(fetch.size.unwrap_or(0))));
                msgids.insert(uid, fetch.gmail_msg_id().copied().unwrap_or(0));
            }
            present.sort_unstable();
            present.dedup_by_key(|(uid, _)| *uid);
            let mut batch: Vec<u32> = Vec::new();
            let mut bytes = 0u64;
            let mut batches = Vec::new();
            for (uid, size) in present {
                if !batch.is_empty() && bytes + size > BODY_BATCH_BYTES {
                    batches.push(std::mem::take(&mut batch));
                    bytes = 0;
                }
                batch.push(uid);
                bytes += size;
            }
            if !batch.is_empty() {
                batches.push(batch);
            }
            for batch in batches {
                for fetch in self
                    .uid_fetch(&uid_set(&batch), "(UID BODY.PEEK[])")
                    .await?
                {
                    if let (Some(uid), Some(body)) = (fetch.uid, fetch.body())
                        && batch.binary_search(&uid).is_ok()
                    {
                        bodies.insert(uid, Bytes::copy_from_slice(body));
                    }
                }
            }
        }
        let mut out = Vec::with_capacity(bodies.len());
        for item in items {
            let Some(uid) = self.plausible(item, validity) else {
                continue;
            };
            let Some(body) = bodies.get(&uid) else {
                continue;
            };
            if gmail
                && let Ok(id) = item.id.parse::<u64>()
                && msgids.get(&uid) != Some(&id)
            {
                continue;
            }
            out.push(RawMessage {
                item: item.clone(),
                bytes: body.clone(),
            });
        }
        tracing::debug!(asked = items.len(), returned = out.len(), "imap fetch");
        Ok(out)
    }
}

#[async_trait]
impl MailSession for ImapSession {
    async fn mailboxes(&mut self) -> Result<Vec<MailboxInfo>, MailError> {
        self.check()?;
        let result = self.refresh_names().await;
        self.settle(result)
    }

    /// Changes since `cursor`. See the crate docs for how removals and flag changes are found.
    async fn changes(
        &mut self,
        mailbox: &str,
        cursor: Option<&Cursor>,
        limit: usize,
    ) -> Result<MailboxChanges, MailError> {
        self.check()?;
        let result = self.changes_inner(mailbox, cursor, limit).await;
        self.settle(result)
    }

    async fn fetch(
        &mut self,
        mailbox: &str,
        items: &[ItemRef],
    ) -> Result<Vec<RawMessage>, MailError> {
        self.check()?;
        let result = self.fetch_inner(mailbox, items).await;
        self.settle(result)
    }

    async fn apply(
        &mut self,
        command: &CommandBody,
        content: Option<Bytes>,
    ) -> Result<WriteOutcome, MailError> {
        self.check()?;
        let result = self.apply_inner(command, content).await;
        if matches!(result, Ok(WriteOutcome::Uncertain)) {
            self.broken = true;
        }
        self.settle(result)
    }

    /// System flags and keywords from `PERMANENTFLAGS` of the inbox (opened with `SELECT`, since
    /// `EXAMINE` reports none) or of the mailbox a write already selected; see the crate docs.
    async fn capabilities(&mut self) -> Result<MailCapabilities, MailError> {
        self.check()?;
        let result = self.capabilities_inner().await;
        self.settle(result)
    }

    async fn logout(&mut self) -> Result<(), MailError> {
        if self.broken {
            return Ok(());
        }
        self.broken = true;
        timed(self.timeout, self.session.logout())
            .await?
            .map_err(convert)
    }
}

pub(crate) fn flag_name(flag: Flag<'_>) -> Option<String> {
    Some(match flag {
        Flag::Seen => "\\Seen".into(),
        Flag::Answered => "\\Answered".into(),
        Flag::Flagged => "\\Flagged".into(),
        Flag::Deleted => "\\Deleted".into(),
        Flag::Draft => "\\Draft".into(),
        Flag::Recent | Flag::MayCreate => return None,
        Flag::Custom(name) => name.into_owned(),
    })
}
