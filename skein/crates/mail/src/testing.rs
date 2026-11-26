//! A fake mail server for tests, and the conformance suite every provider runs.
//!
//! The suite drives a real server through [`ServerControl`] (adding, removing and flagging
//! messages behind the provider's back) and checks that the provider reports exactly those
//! changes. Providers run it against an in-process fake of their protocol; [`FakeMail`] runs it
//! against itself and serves engine and load tests.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use skein_core::{
    CommandBody, Flags, ItemRef, MailCapabilities, MailboxInfo, MailboxRole, Timestamp,
};
use tokio::sync::Notify;

use crate::{
    Changed, Cursor, MailChange, MailError, MailProvider, MailSession, MailWatch, MailboxChanges,
    RawMessage, WriteOutcome,
};

/// Changes a server behind the provider's back.
#[async_trait]
pub trait ServerControl: Send + Sync {
    /// Creates a mailbox.
    async fn create_mailbox(&self, mailbox: &str);
    /// Adds a message.
    async fn add(&self, mailbox: &str, bytes: &[u8], flags: Flags);
    /// Removes the message whose bytes are `bytes`.
    async fn remove(&self, mailbox: &str, bytes: &[u8]);
    /// Replaces the flags of the message whose bytes are `bytes`.
    async fn set_flags(&self, mailbox: &str, bytes: &[u8], flags: Flags);
    /// Makes the server stop accepting existing cursors for the mailbox (new `UIDVALIDITY`).
    async fn invalidate(&self, mailbox: &str);
    /// The flags of the message whose bytes are `bytes`, to check that reading changed nothing.
    async fn flags_of(&self, mailbox: &str, bytes: &[u8]) -> Option<Flags>;
}

#[derive(Default)]
struct Mbox {
    validity: u32,
    next_uid: u32,
    msgs: BTreeMap<u32, (Bytes, Flags)>,
    received: BTreeMap<u32, Timestamp>,
}

#[derive(Default)]
struct State {
    boxes: BTreeMap<String, Mbox>,
    fail_next: Option<MailError>,
    connects: u64,
    fetched: u64,
    next_validity: u32,
}

/// An in-memory mail server and its provider.
///
/// Message ids are `{validity}:{uid}`. Cursors hold the validity and every known UID with its
/// flags, like an IMAP client without `QRESYNC` would.
#[derive(Clone, Default)]
pub struct FakeMail {
    state: Arc<Mutex<State>>,
    notify: Arc<Notify>,
}

#[derive(Serialize, Deserialize)]
struct FakeCursor {
    validity: u32,
    known: BTreeMap<u32, Vec<String>>,
}

impl FakeMail {
    /// A server with an `INBOX`.
    pub fn new() -> Self {
        let fake = Self::default();
        fake.state.lock().unwrap().boxes.insert(
            "INBOX".into(),
            Mbox {
                validity: 1,
                next_uid: 1,
                ..Default::default()
            },
        );
        fake
    }

    /// Makes the next session call fail with `error`.
    pub fn fail_next(&self, error: MailError) {
        self.state.lock().unwrap().fail_next = Some(error);
    }

    /// How many sessions were opened.
    pub fn connects(&self) -> u64 {
        self.state.lock().unwrap().connects
    }

    /// How many messages were fetched.
    pub fn fetched(&self) -> u64 {
        self.state.lock().unwrap().fetched
    }

    /// Adds `count` generated messages of about `size` bytes to `mailbox`.
    pub fn fill(&self, mailbox: &str, count: usize, size: usize) {
        let mut st = self.state.lock().unwrap();
        let mbox = st.boxes.entry(mailbox.to_owned()).or_insert_with(|| Mbox {
            validity: 1,
            next_uid: 1,
            ..Default::default()
        });
        for _ in 0..count {
            let uid = mbox.next_uid;
            mbox.next_uid += 1;
            let header = format!(
                "From: sender{uid}@example.com\r\nTo: ada@example.org\r\nSubject: Message {uid}\r\nMessage-ID: <{uid}.{}@example.com>\r\n\r\n",
                mbox.validity
            );
            let mut body = header.into_bytes();
            while body.len() < size {
                body.extend_from_slice(b"Lorem ipsum dolor sit amet, consectetur adipiscing.\r\n");
            }
            mbox.msgs.insert(uid, (Bytes::from(body), Flags::default()));
        }
        drop(st);
        self.notify.notify_waiters();
    }

    fn take_failure(&self) -> Result<(), MailError> {
        match self.state.lock().unwrap().fail_next.take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn find(mbox: &Mbox, bytes: &[u8]) -> Option<u32> {
        mbox.msgs
            .iter()
            .find(|(_, (b, _))| &b[..] == bytes)
            .map(|(u, _)| *u)
    }

    fn item(validity: u32, uid: u32) -> ItemRef {
        ItemRef {
            id: format!("{validity}:{uid}"),
            uid: Some(uid),
        }
    }
}

#[async_trait]
impl ServerControl for FakeMail {
    async fn create_mailbox(&self, mailbox: &str) {
        self.state
            .lock()
            .unwrap()
            .boxes
            .entry(mailbox.to_owned())
            .or_insert_with(|| Mbox {
                validity: 1,
                next_uid: 1,
                ..Default::default()
            });
    }

    async fn add(&self, mailbox: &str, bytes: &[u8], flags: Flags) {
        {
            let mut st = self.state.lock().unwrap();
            let mbox = st.boxes.get_mut(mailbox).expect("mailbox exists");
            let uid = mbox.next_uid;
            mbox.next_uid += 1;
            mbox.msgs
                .insert(uid, (Bytes::copy_from_slice(bytes), flags));
        }
        self.notify.notify_waiters();
    }

    async fn remove(&self, mailbox: &str, bytes: &[u8]) {
        {
            let mut st = self.state.lock().unwrap();
            let mbox = st.boxes.get_mut(mailbox).expect("mailbox exists");
            if let Some(uid) = Self::find(mbox, bytes) {
                mbox.msgs.remove(&uid);
            }
        }
        self.notify.notify_waiters();
    }

    async fn set_flags(&self, mailbox: &str, bytes: &[u8], flags: Flags) {
        {
            let mut st = self.state.lock().unwrap();
            let mbox = st.boxes.get_mut(mailbox).expect("mailbox exists");
            if let Some(uid) = Self::find(mbox, bytes) {
                mbox.msgs.get_mut(&uid).unwrap().1 = flags;
            }
        }
        self.notify.notify_waiters();
    }

    async fn invalidate(&self, mailbox: &str) {
        let mut st = self.state.lock().unwrap();
        let mbox = st.boxes.get_mut(mailbox).expect("mailbox exists");
        mbox.validity += 1;
        let msgs = std::mem::take(&mut mbox.msgs);
        mbox.next_uid = 1;
        for (_, m) in msgs {
            let uid = mbox.next_uid;
            mbox.next_uid += 1;
            mbox.msgs.insert(uid, m);
        }
    }

    async fn flags_of(&self, mailbox: &str, bytes: &[u8]) -> Option<Flags> {
        let st = self.state.lock().unwrap();
        let mbox = st.boxes.get(mailbox)?;
        Self::find(mbox, bytes).map(|u| mbox.msgs[&u].1.clone())
    }
}

#[async_trait]
impl MailProvider for FakeMail {
    async fn connect(&self) -> Result<Box<dyn MailSession>, MailError> {
        self.take_failure()?;
        self.state.lock().unwrap().connects += 1;
        Ok(Box::new(FakeSession { fake: self.clone() }))
    }

    async fn watch(&self, _mailboxes: &[String]) -> Result<Option<Box<dyn MailWatch>>, MailError> {
        Ok(Some(Box::new(FakeWatch {
            notify: self.notify.clone(),
        })))
    }
}

struct FakeWatch {
    notify: Arc<Notify>,
}

#[async_trait]
impl MailWatch for FakeWatch {
    async fn next(&mut self) -> Result<Changed, MailError> {
        self.notify.notified().await;
        Ok(Changed { mailboxes: None })
    }
}

struct FakeSession {
    fake: FakeMail,
}

fn role(name: &str) -> Option<MailboxRole> {
    match name {
        "INBOX" => Some(MailboxRole::Inbox),
        "Sent" => Some(MailboxRole::Sent),
        "Trash" => Some(MailboxRole::Trash),
        "Archive" => Some(MailboxRole::Archive),
        "Junk" => Some(MailboxRole::Junk),
        _ => None,
    }
}

#[async_trait]
impl MailSession for FakeSession {
    async fn mailboxes(&mut self) -> Result<Vec<MailboxInfo>, MailError> {
        self.fake.take_failure()?;
        let st = self.fake.state.lock().unwrap();
        Ok(st
            .boxes
            .keys()
            .map(|name| MailboxInfo {
                id: name.clone(),
                path: name.clone(),
                role: role(name),
                selectable: true,
                label: false,
            })
            .collect())
    }

    async fn changes(
        &mut self,
        mailbox: &str,
        cursor: Option<&Cursor>,
        limit: usize,
    ) -> Result<MailboxChanges, MailError> {
        self.fake.take_failure()?;
        let st = self.fake.state.lock().unwrap();
        let mbox = st.boxes.get(mailbox).ok_or(MailError::MailboxNotFound)?;
        let mut changes = Vec::new();
        let mut known = match cursor {
            Some(c) => {
                let parsed: Option<FakeCursor> = serde_json::from_slice(&c.0).ok();
                if let Some(c) = parsed.filter(|c| c.validity == mbox.validity) {
                    c.known
                } else {
                    changes.push(MailChange::Reset {
                        reason: "uidvalidity".into(),
                    });
                    BTreeMap::new()
                }
            }
            None => BTreeMap::new(),
        };
        let gone: Vec<u32> = known
            .keys()
            .filter(|u| !mbox.msgs.contains_key(u))
            .copied()
            .collect();
        for uid in gone {
            known.remove(&uid);
            changes.push(MailChange::Removed {
                item: FakeMail::item(mbox.validity, uid),
            });
        }
        for (uid, flags) in known.iter_mut() {
            let now: Vec<String> = mbox.msgs[uid].1.iter().map(str::to_owned).collect();
            if *flags != now {
                *flags = now;
                changes.push(MailChange::Flags {
                    item: FakeMail::item(mbox.validity, *uid),
                    flags: mbox.msgs[uid].1.clone(),
                });
            }
        }
        let mut added = 0;
        let mut more = false;
        for (uid, (_, flags)) in &mbox.msgs {
            if known.contains_key(uid) {
                continue;
            }
            if added == limit.max(1) {
                more = true;
                break;
            }
            known.insert(*uid, flags.iter().map(str::to_owned).collect());
            changes.push(MailChange::Added {
                item: FakeMail::item(mbox.validity, *uid),
                flags: flags.clone(),
                labels: None,
                received_at: Some(
                    mbox.received
                        .get(uid)
                        .copied()
                        .unwrap_or(Timestamp(*uid as i64 * 1000)),
                ),
            });
            added += 1;
        }
        let cursor = FakeCursor {
            validity: mbox.validity,
            known,
        };
        Ok(MailboxChanges {
            changes,
            cursor: Cursor(Bytes::from(serde_json::to_vec(&cursor).unwrap())),
            more,
        })
    }

    async fn fetch(
        &mut self,
        mailbox: &str,
        items: &[ItemRef],
    ) -> Result<Vec<RawMessage>, MailError> {
        self.fake.take_failure()?;
        let mut st = self.fake.state.lock().unwrap();
        let mbox = st.boxes.get(mailbox).ok_or(MailError::MailboxNotFound)?;
        let mut out = Vec::new();
        for item in items {
            let Some(uid) = item.uid else { continue };
            if item.id != format!("{}:{uid}", mbox.validity) {
                continue;
            }
            if let Some((bytes, _)) = mbox.msgs.get(&uid) {
                out.push(RawMessage {
                    item: item.clone(),
                    bytes: bytes.clone(),
                });
            }
        }
        st.fetched += out.len() as u64;
        Ok(out)
    }

    async fn apply(
        &mut self,
        command: &CommandBody,
        content: Option<Bytes>,
    ) -> Result<WriteOutcome, MailError> {
        self.fake.take_failure()?;
        let outcome = {
            let mut st = self.fake.state.lock().unwrap();
            let uids = |mbox: &Mbox, items: &[ItemRef]| -> Vec<u32> {
                items
                    .iter()
                    .filter(|i| i.id.starts_with(&format!("{}:", mbox.validity)))
                    .filter_map(|i| i.uid)
                    .collect()
            };
            match command {
                CommandBody::SetFlags {
                    mailbox,
                    items,
                    add,
                    remove,
                } => {
                    let mbox = st
                        .boxes
                        .get_mut(mailbox)
                        .ok_or(MailError::MailboxNotFound)?;
                    for uid in uids(mbox, items) {
                        if let Some((_, flags)) = mbox.msgs.get_mut(&uid) {
                            let mut set: Vec<String> = flags
                                .iter()
                                .filter(|f| !remove.contains(f))
                                .map(str::to_owned)
                                .collect();
                            set.extend(add.iter().map(str::to_owned));
                            *flags = Flags::new(set);
                        }
                    }
                    WriteOutcome::Applied
                }
                CommandBody::Move { from, to, items } => {
                    if !st.boxes.contains_key(to) {
                        return Ok(WriteOutcome::Failed {
                            reason: "no_such_mailbox".into(),
                        });
                    }
                    let src = st.boxes.get_mut(from).ok_or(MailError::MailboxNotFound)?;
                    let moved: Vec<_> = uids(src, items)
                        .into_iter()
                        .filter_map(|u| src.msgs.remove(&u))
                        .collect();
                    let dst = st.boxes.get_mut(to).unwrap();
                    for m in moved {
                        let uid = dst.next_uid;
                        dst.next_uid += 1;
                        dst.msgs.insert(uid, m);
                    }
                    WriteOutcome::Applied
                }
                CommandBody::Delete {
                    mailbox,
                    items,
                    to_trash,
                } => {
                    if !st.boxes.contains_key(mailbox) {
                        return Err(MailError::MailboxNotFound);
                    }
                    let trash = st
                        .boxes
                        .keys()
                        .find(|n| role(n) == Some(MailboxRole::Trash))
                        .cloned();
                    match (to_trash, trash) {
                        (true, None) => WriteOutcome::Failed {
                            reason: "no_trash".into(),
                        },
                        (true, Some(trash)) if &trash == mailbox => WriteOutcome::Applied,
                        (true, Some(trash)) => {
                            let src = st.boxes.get_mut(mailbox).expect("checked");
                            let moved: Vec<_> = uids(src, items)
                                .into_iter()
                                .filter_map(|u| src.msgs.remove(&u))
                                .collect();
                            let dst = st.boxes.get_mut(&trash).expect("found");
                            for m in moved {
                                let uid = dst.next_uid;
                                dst.next_uid += 1;
                                dst.msgs.insert(uid, m);
                            }
                            WriteOutcome::Applied
                        }
                        (false, _) => {
                            let mbox = st.boxes.get_mut(mailbox).expect("checked");
                            for uid in uids(mbox, items) {
                                mbox.msgs.remove(&uid);
                            }
                            WriteOutcome::Applied
                        }
                    }
                }
                CommandBody::Copy { from, to, items } => {
                    if !st.boxes.contains_key(to) {
                        return Ok(WriteOutcome::Failed {
                            reason: "no_such_mailbox".into(),
                        });
                    }
                    let src = st.boxes.get(from).ok_or(MailError::MailboxNotFound)?;
                    let copied: Vec<_> = uids(src, items)
                        .into_iter()
                        .filter_map(|u| src.msgs.get(&u).cloned())
                        .collect();
                    let dst = st.boxes.get_mut(to).expect("checked");
                    for m in copied {
                        let uid = dst.next_uid;
                        dst.next_uid += 1;
                        dst.msgs.insert(uid, m);
                    }
                    WriteOutcome::Applied
                }
                CommandBody::CreateMailbox { path } => {
                    if st.boxes.contains_key(path) {
                        WriteOutcome::Failed {
                            reason: "exists".into(),
                        }
                    } else {
                        st.next_validity += 1;
                        let validity = 100 + st.next_validity;
                        st.boxes.insert(
                            path.clone(),
                            Mbox {
                                validity,
                                next_uid: 1,
                                ..Default::default()
                            },
                        );
                        WriteOutcome::Applied
                    }
                }
                CommandBody::RenameMailbox { mailbox, path } => {
                    if mailbox == "INBOX" {
                        WriteOutcome::Failed {
                            reason: "protected".into(),
                        }
                    } else if st.boxes.contains_key(path) {
                        WriteOutcome::Failed {
                            reason: "exists".into(),
                        }
                    } else {
                        let mbox = st.boxes.remove(mailbox).ok_or(MailError::MailboxNotFound)?;
                        st.boxes.insert(path.clone(), mbox);
                        WriteOutcome::Applied
                    }
                }
                CommandBody::DeleteMailbox { mailbox } => {
                    if mailbox == "INBOX" {
                        WriteOutcome::Failed {
                            reason: "protected".into(),
                        }
                    } else {
                        st.boxes.remove(mailbox).ok_or(MailError::MailboxNotFound)?;
                        WriteOutcome::Applied
                    }
                }
                CommandBody::Append {
                    mailbox,
                    flags,
                    received_at,
                    ..
                } => {
                    let Some(bytes) = content else {
                        return Ok(WriteOutcome::Failed {
                            reason: "missing_content".into(),
                        });
                    };
                    let mbox = st
                        .boxes
                        .get_mut(mailbox)
                        .ok_or(MailError::MailboxNotFound)?;
                    let uid = mbox.next_uid;
                    mbox.next_uid += 1;
                    mbox.msgs.insert(uid, (bytes, flags.clone()));
                    if let Some(at) = received_at {
                        mbox.received.insert(uid, *at);
                    }
                    WriteOutcome::Applied
                }
                CommandBody::Refetch { .. }
                | CommandBody::SetLabels { .. }
                | CommandBody::Send { .. }
                | CommandBody::PutObject { .. }
                | CommandBody::DeleteObject { .. }
                | CommandBody::RespondObject { .. }
                | CommandBody::RespondInvitation { .. }
                | CommandBody::Unknown => WriteOutcome::Failed {
                    reason: "unsupported".into(),
                },
            }
        };
        self.fake.notify.notify_waiters();
        Ok(outcome)
    }

    async fn capabilities(&mut self) -> Result<MailCapabilities, MailError> {
        let mut caps = crate::basic_capabilities();
        caps.system_flags.push("\\Deleted".into());
        caps.system_flags.sort();
        caps.keywords = true;
        caps.trash = true;
        caps.copy = true;
        caps.append_received_at = true;
        caps.mailboxes = true;
        Ok(caps)
    }

    async fn logout(&mut self) -> Result<(), MailError> {
        Ok(())
    }
}

#[derive(Default)]
struct Mirror {
    by_id: HashMap<String, (Bytes, Flags)>,
}

async fn drain(
    session: &mut Box<dyn MailSession>,
    mailbox: &str,
    cursor: Option<Cursor>,
    mirror: &mut Mirror,
    limit: usize,
) -> (Cursor, Vec<MailChange>) {
    let mut cursor = cursor;
    let mut all = Vec::new();
    loop {
        let batch = session
            .changes(mailbox, cursor.as_ref(), limit)
            .await
            .unwrap();
        let mut added = Vec::new();
        for change in &batch.changes {
            match change {
                MailChange::Reset { .. } => mirror.by_id.clear(),
                MailChange::Added { item, flags, .. } => added.push((item.clone(), flags.clone())),
                MailChange::Removed { item } => {
                    assert!(
                        mirror.by_id.remove(&item.id).is_some(),
                        "removed an unknown item"
                    );
                }
                MailChange::Flags { item, flags } => {
                    mirror
                        .by_id
                        .get_mut(&item.id)
                        .expect("flags of a known item")
                        .1 = flags.clone();
                }
                MailChange::Labels { .. } => {}
            }
        }
        let items: Vec<_> = added.iter().map(|(i, _)| i.clone()).collect();
        let raw = session.fetch(mailbox, &items).await.unwrap();
        assert_eq!(raw.len(), items.len(), "every added message can be fetched");
        for ((item, flags), msg) in added.into_iter().zip(raw) {
            assert_eq!(msg.item, item);
            assert!(
                mirror.by_id.insert(item.id, (msg.bytes, flags)).is_none(),
                "added twice"
            );
        }
        all.extend(batch.changes);
        cursor = Some(batch.cursor);
        if !batch.more {
            return (cursor.unwrap(), all);
        }
    }
}

fn contents(mirror: &Mirror) -> Vec<(Vec<u8>, Vec<String>)> {
    let mut v: Vec<_> = mirror
        .by_id
        .values()
        .map(|(b, f)| (b.to_vec(), f.iter().map(str::to_owned).collect()))
        .collect();
    v.sort();
    v
}

fn msg(n: u32) -> Vec<u8> {
    format!("From: ada@example.com\r\nTo: bob@example.org\r\nSubject: Test {n}\r\nMessage-ID: <{n}@example.com>\r\n\r\nBody {n}\r\n")
        .into_bytes()
}

/// The [`MailSession`] contract against a server that `control` can change. The server must have
/// an empty mailbox named `mailbox`.
pub async fn conformance(
    provider: Arc<dyn MailProvider>,
    control: Arc<dyn ServerControl>,
    mailbox: &str,
) {
    let mut session = provider.connect().await.unwrap();
    let boxes = session.mailboxes().await.unwrap();
    assert!(
        boxes.iter().any(|b| b.id == mailbox),
        "the mailbox is listed"
    );

    for n in 1..=7 {
        let flags = if n == 3 {
            Flags::new(["\\Flagged"])
        } else {
            Flags::default()
        };
        control.add(mailbox, &msg(n), flags).await;
    }
    let mut mirror = Mirror::default();
    let (cursor, _) = drain(&mut session, mailbox, None, &mut mirror, 3).await;
    assert_eq!(
        mirror.by_id.len(),
        7,
        "a listing without a cursor sees everything, paged"
    );
    assert_eq!(
        control.flags_of(mailbox, &msg(1)).await.unwrap(),
        Flags::default(),
        "reading does not mark messages seen"
    );

    let (cursor, changes) = drain(&mut session, mailbox, Some(cursor), &mut mirror, 3).await;
    assert!(
        changes.is_empty(),
        "nothing changed, nothing reported: {changes:?}"
    );

    control.add(mailbox, &msg(8), Flags::default()).await;
    control.remove(mailbox, &msg(2)).await;
    control
        .set_flags(mailbox, &msg(4), Flags::new(["\\Seen"]))
        .await;
    control.set_flags(mailbox, &msg(3), Flags::default()).await;
    let (cursor, changes) = drain(&mut session, mailbox, Some(cursor), &mut mirror, 3).await;
    assert_eq!(
        changes.len(),
        4,
        "exactly the four changes are reported: {changes:?}"
    );
    let mut expected: Vec<_> = [1, 3, 4, 5, 6, 7, 8]
        .into_iter()
        .map(|n| {
            let flags: Vec<String> = if n == 4 {
                vec!["\\Seen".into()]
            } else {
                vec![]
            };
            (msg(n), flags)
        })
        .collect();
    expected.sort();
    assert_eq!(contents(&mirror), expected);

    control.invalidate(mailbox).await;
    let (_, changes) = drain(&mut session, mailbox, Some(cursor), &mut mirror, 100).await;
    assert!(
        matches!(changes.first(), Some(MailChange::Reset { .. })),
        "an invalid cursor resets: {changes:?}"
    );
    assert_eq!(
        contents(&mirror),
        expected,
        "the reset lists everything again"
    );

    let none = session
        .fetch(
            mailbox,
            &[ItemRef {
                id: "999999:999999".into(),
                uid: Some(999_999),
            }],
        )
        .await
        .unwrap();
    assert!(none.is_empty(), "vanished messages are left out");
    session.logout().await.unwrap();
}

struct Listed {
    item: ItemRef,
    flags: Flags,
    labels: Option<Vec<String>>,
    received_at: Option<Timestamp>,
    bytes: Bytes,
}

async fn listing(session: &mut Box<dyn MailSession>, mailbox: &str) -> Vec<Listed> {
    let mut out: Vec<Listed> = Vec::new();
    let mut cursor = None;
    loop {
        let batch = session
            .changes(mailbox, cursor.as_ref(), 500)
            .await
            .unwrap();
        let added: Vec<_> = batch
            .changes
            .into_iter()
            .filter_map(|c| match c {
                MailChange::Added {
                    item,
                    flags,
                    labels,
                    received_at,
                } => Some((item, flags, labels, received_at)),
                _ => None,
            })
            .collect();
        let items: Vec<ItemRef> = added.iter().map(|a| a.0.clone()).collect();
        let raw = session.fetch(mailbox, &items).await.unwrap();
        for (item, flags, labels, received_at) in added {
            if let Some(m) = raw.iter().find(|m| m.item == item) {
                out.push(Listed {
                    item,
                    flags,
                    labels,
                    received_at,
                    bytes: m.bytes.clone(),
                });
            }
        }
        cursor = Some(batch.cursor);
        if !batch.more {
            return out;
        }
    }
}

async fn find(session: &mut Box<dyn MailSession>, mailbox: &str, bytes: &[u8]) -> Option<Listed> {
    listing(session, mailbox)
        .await
        .into_iter()
        .find(|l| l.bytes.as_ref() == bytes)
}

fn unique(run: &str, n: u32) -> Vec<u8> {
    format!(
        "From: ada@example.com\r\nTo: bob@example.org\r\nSubject: Write {run} {n}\r\nMessage-ID: <w{n}.{run}@example.com>\r\nDate: Thu, 19 Nov 2026 10:00:00 +0000\r\n\r\nWrite test {n}\r\n"
    )
    .into_bytes()
}

async fn applied(session: &mut Box<dyn MailSession>, command: CommandBody, what: &str) {
    let outcome = session.apply(&command, None).await.unwrap();
    assert_eq!(outcome, WriteOutcome::Applied, "{what}");
}

/// The write half of the [`MailSession`] contract, as far as the provider's
/// [`MailSession::capabilities`] claim, against a server that `control` can change. `mailbox` and
/// `other` must exist (they need not be empty); `label` names an existing label to add and remove
/// where the provider has labels. Messages it adds carry a unique subject and are removed again,
/// so it can run against a shared test account.
pub async fn write_conformance(
    provider: Arc<dyn MailProvider>,
    control: Arc<dyn ServerControl>,
    mailbox: &str,
    other: &str,
    label: Option<&str>,
) {
    let run = format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let mut session = provider.connect().await.unwrap();
    let caps = session.capabilities().await.unwrap();
    for flag in ["\\Seen", "\\Flagged"] {
        assert!(
            caps.system_flags.iter().any(|f| f == flag),
            "every provider sets {flag}"
        );
    }
    for n in 1..=4 {
        control
            .add(mailbox, &unique(&run, n), Flags::default())
            .await;
    }

    let one = find(&mut session, mailbox, &unique(&run, 1))
        .await
        .expect("the added message is listed");
    let flag = |add: &[&str], remove: &[&str]| CommandBody::SetFlags {
        mailbox: mailbox.to_owned(),
        items: vec![one.item.clone()],
        add: Flags::new(add.iter().copied()),
        remove: Flags::new(remove.iter().copied()),
    };
    applied(
        &mut session,
        flag(&["\\Seen", "\\Flagged"], &[]),
        "flags are added",
    )
    .await;
    applied(&mut session, flag(&[], &["\\Flagged"]), "a flag is removed").await;
    applied(
        &mut session,
        flag(&[], &["\\Flagged"]),
        "removing again is harmless",
    )
    .await;
    let now = find(&mut session, mailbox, &unique(&run, 1)).await.unwrap();
    assert!(now.flags.contains("\\Seen"), "{:?}", now.flags);
    assert!(!now.flags.contains("\\Flagged"), "{:?}", now.flags);
    if caps.keywords {
        applied(
            &mut session,
            flag(&["$Forwarded"], &[]),
            "a keyword is added",
        )
        .await;
        let now = find(&mut session, mailbox, &unique(&run, 1)).await.unwrap();
        assert!(now.flags.contains("$Forwarded"), "{:?}", now.flags);
    }

    let two = find(&mut session, mailbox, &unique(&run, 2)).await.unwrap();
    applied(
        &mut session,
        CommandBody::Move {
            from: mailbox.to_owned(),
            to: other.to_owned(),
            items: vec![two.item],
        },
        "a message is moved",
    )
    .await;
    assert!(
        find(&mut session, mailbox, &unique(&run, 2))
            .await
            .is_none()
    );
    let moved = find(&mut session, other, &unique(&run, 2))
        .await
        .expect("the moved message is in the target with its bytes");

    let three = find(&mut session, mailbox, &unique(&run, 3)).await.unwrap();
    let copy = CommandBody::Copy {
        from: mailbox.to_owned(),
        to: other.to_owned(),
        items: vec![three.item.clone()],
    };
    if caps.copy {
        applied(&mut session, copy, "a message is copied").await;
        assert!(
            find(&mut session, mailbox, &unique(&run, 3))
                .await
                .is_some()
        );
        assert!(find(&mut session, other, &unique(&run, 3)).await.is_some());
    } else {
        assert_eq!(
            session.apply(&copy, None).await.unwrap(),
            WriteOutcome::Failed {
                reason: "unsupported".into()
            }
        );
    }

    if caps.labels {
        let label = label.expect("a provider with labels needs a label to test with");
        let set = |add: bool| CommandBody::SetLabels {
            mailbox: mailbox.to_owned(),
            items: vec![three.item.clone()],
            add: if add { vec![label.to_owned()] } else { vec![] },
            remove: if add { vec![] } else { vec![label.to_owned()] },
        };
        applied(&mut session, set(true), "a label is added").await;
        let now = find(&mut session, mailbox, &unique(&run, 3)).await.unwrap();
        assert!(
            now.labels
                .as_ref()
                .is_some_and(|l| l.iter().any(|x| x == label)),
            "{:?}",
            now.labels
        );
        applied(&mut session, set(false), "a label is removed").await;
        let now = find(&mut session, mailbox, &unique(&run, 3)).await.unwrap();
        assert!(
            !now.labels.unwrap_or_default().iter().any(|x| x == label),
            "the label is gone"
        );
    }

    let four = find(&mut session, mailbox, &unique(&run, 4)).await.unwrap();
    applied(
        &mut session,
        CommandBody::Delete {
            mailbox: mailbox.to_owned(),
            items: vec![four.item],
            to_trash: false,
        },
        "a message is deleted",
    )
    .await;
    assert!(
        find(&mut session, mailbox, &unique(&run, 4))
            .await
            .is_none()
    );

    let trash = session
        .mailboxes()
        .await
        .unwrap()
        .into_iter()
        .find(|m| m.role == Some(skein_core::MailboxRole::Trash))
        .map(|m| m.id);
    if caps.trash {
        let trash = trash.expect("a provider with trash lists a trash mailbox");
        let one = find(&mut session, mailbox, &unique(&run, 1)).await.unwrap();
        applied(
            &mut session,
            CommandBody::Delete {
                mailbox: mailbox.to_owned(),
                items: vec![one.item],
                to_trash: true,
            },
            "a message goes to the trash",
        )
        .await;
        assert!(
            find(&mut session, mailbox, &unique(&run, 1))
                .await
                .is_none()
        );
        let trashed = find(&mut session, &trash, &unique(&run, 1))
            .await
            .expect("the message is in the trash");
        applied(
            &mut session,
            CommandBody::Delete {
                mailbox: trash.clone(),
                items: vec![trashed.item],
                to_trash: false,
            },
            "the trash is emptied",
        )
        .await;
    }

    let appended = unique(&run, 5);
    let at = Timestamp(1_795_000_000_000);
    let outcome = session
        .apply(
            &CommandBody::Append {
                mailbox: mailbox.to_owned(),
                blob: skein_core::BlobHash::of(&appended),
                flags: Flags::new(["\\Seen"]),
                received_at: Some(at),
            },
            Some(Bytes::from(appended.clone())),
        )
        .await
        .unwrap();
    assert_eq!(outcome, WriteOutcome::Applied, "a message is appended");
    let listed = find(&mut session, mailbox, &appended)
        .await
        .expect("the appended message is listed with its bytes");
    assert!(listed.flags.contains("\\Seen"), "{:?}", listed.flags);
    if caps.append_received_at {
        let got = listed.received_at.expect("a received time").0;
        assert!(
            (got - at.0).abs() < 1_000,
            "received at {got}, asked {}",
            at.0
        );
    }

    if caps.mailboxes {
        let path = format!("skein-conf-{run}");
        let renamed = format!("skein-conf-{run}-renamed");
        applied(
            &mut session,
            CommandBody::CreateMailbox { path: path.clone() },
            "a mailbox is created",
        )
        .await;
        let id_of = |boxes: &[MailboxInfo], path: &str| {
            boxes.iter().find(|b| b.path == path).map(|b| b.id.clone())
        };
        let boxes = session.mailboxes().await.unwrap();
        let id = id_of(&boxes, &path).expect("the new mailbox is listed");
        assert!(matches!(
            session
                .apply(&CommandBody::CreateMailbox { path: path.clone() }, None)
                .await
                .unwrap(),
            WriteOutcome::Failed { .. }
        ));
        applied(
            &mut session,
            CommandBody::RenameMailbox {
                mailbox: id,
                path: renamed.clone(),
            },
            "a mailbox is renamed",
        )
        .await;
        let boxes = session.mailboxes().await.unwrap();
        assert!(id_of(&boxes, &path).is_none());
        let id = id_of(&boxes, &renamed).expect("the renamed mailbox is listed");
        applied(
            &mut session,
            CommandBody::DeleteMailbox { mailbox: id },
            "a mailbox is deleted",
        )
        .await;
        let boxes = session.mailboxes().await.unwrap();
        assert!(id_of(&boxes, &renamed).is_none());
        if let Some(inbox) = boxes
            .iter()
            .find(|b| b.role == Some(skein_core::MailboxRole::Inbox))
        {
            assert!(
                matches!(
                    session
                        .apply(
                            &CommandBody::DeleteMailbox {
                                mailbox: inbox.id.clone()
                            },
                            None
                        )
                        .await,
                    Ok(WriteOutcome::Failed { .. }) | Err(_)
                ),
                "the inbox cannot be deleted"
            );
        }
    }

    let missing = session
        .apply(
            &CommandBody::SetFlags {
                mailbox: format!("skein-missing-{run}"),
                items: vec![moved.item.clone()],
                add: Flags::new(["\\Seen"]),
                remove: Flags::default(),
            },
            None,
        )
        .await;
    assert!(
        matches!(
            missing,
            Err(MailError::MailboxNotFound) | Ok(WriteOutcome::Failed { .. })
        ),
        "a missing mailbox is reported: {missing:?}"
    );

    for (target, n) in [(mailbox, 3), (mailbox, 5), (other, 2), (other, 3)] {
        if let Some(l) = find(&mut session, target, &unique(&run, n)).await {
            let _ = session
                .apply(
                    &CommandBody::Delete {
                        mailbox: target.to_owned(),
                        items: vec![l.item],
                        to_trash: false,
                    },
                    None,
                )
                .await;
        }
    }
    session.logout().await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_fake_keeps_the_contract() {
        let fake = FakeMail::new();
        conformance(Arc::new(fake.clone()), Arc::new(fake), "INBOX").await;
    }

    #[tokio::test]
    async fn the_fake_keeps_the_write_contract() {
        let fake = FakeMail::new();
        fake.create_mailbox("Archive").await;
        fake.create_mailbox("Trash").await;
        write_conformance(
            Arc::new(fake.clone()),
            Arc::new(fake),
            "INBOX",
            "Archive",
            None,
        )
        .await;
    }
}
