//! A fake calendar and contacts server for tests, and the conformance suite every provider runs.
//!
//! The suite drives a real server through [`PimServerControl`] (adding, changing and removing
//! objects behind the provider's back) and checks that the provider reports exactly those
//! changes, returns the exact bytes, and keeps the write preconditions. Providers run it against
//! an in-process fake of their protocol; [`FakePim`] runs it against itself and serves engine
//! tests.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use skein_core::{CollectionInfo, CollectionKind, ItemRef};

use crate::{
    Cursor, PimChange, PimChanges, PimError, PimProvider, PimSession, PimWrite, RawObject,
    Scheduling, WriteOutcome,
};

/// Changes a server behind the provider's back.
#[async_trait]
pub trait PimServerControl: Send + Sync {
    /// Creates or replaces the object named `name` (the last path segment) in `collection`.
    async fn put(&self, collection: &str, name: &str, bytes: &[u8]);
    /// Removes the object named `name`; nothing happens when there is none.
    async fn remove(&self, collection: &str, name: &str);
    /// Makes the server stop accepting existing cursors of the collection. Returns `false` when
    /// the server has nothing to invalidate (a DAV server without sync tokens, whose cursors hold
    /// every known version); the suite then only checks that the next listing is still right.
    async fn invalidate(&self, collection: &str) -> bool;
    /// The current version and bytes of `item`, `None` when it is not there.
    async fn read(&self, collection: &str, item: &ItemRef) -> Option<(Option<String>, Bytes)>;
    /// The bytes of every object in `collection`, sorted.
    async fn contents(&self, collection: &str) -> Vec<Bytes>;
}

struct Coll {
    info: CollectionInfo,
    generation: u64,
    objects: BTreeMap<String, (u64, Bytes)>,
    log: Vec<(u64, String)>,
}

#[derive(Default)]
struct State {
    colls: BTreeMap<String, Coll>,
    seq: u64,
    fail_next: Option<PimError>,
    lose_next_answer: bool,
    connects: u64,
    fetched: u64,
    writes: u64,
    server_schedules: bool,
    addresses: Vec<String>,
    notifies: Vec<bool>,
}

/// An in-memory calendar and contacts server and its provider.
///
/// Item ids are the collection id followed by the object's name, versions are `"{n}"` with a
/// server-wide counter, and cursors are `{generation}:{n}`, like a DAV server's sync token.
#[derive(Clone, Default)]
pub struct FakePim {
    state: Arc<Mutex<State>>,
}

/// The calendar of [`FakePim::standard`].
pub const CALENDAR: &str = "/calendars/ada/work/";
/// The address book of [`FakePim::standard`].
pub const ADDRESS_BOOK: &str = "/addressbooks/ada/contacts/";

fn version(seq: u64) -> String {
    format!("\"{seq}\"")
}

/// The name a create with `key` gets: letters, digits, `-` and `.` kept, every other byte as `_`
/// and two hex digits, so different keys never share a name.
pub fn name_for_key(key: &str, kind: CollectionKind) -> String {
    let mut out = String::with_capacity(key.len() + 4);
    for b in key.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'.' {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("_{b:02x}"));
        }
    }
    out.push_str(match kind {
        CollectionKind::Calendar => ".ics",
        CollectionKind::AddressBook => ".vcf",
    });
    out
}

impl FakePim {
    /// A server without collections.
    pub fn new() -> Self {
        Self::default()
    }

    /// A server with an empty calendar [`CALENDAR`] and an empty address book [`ADDRESS_BOOK`].
    pub fn standard() -> Self {
        let fake = Self::new();
        fake.add_collection(CALENDAR, CollectionKind::Calendar, "Work");
        fake.add_collection(ADDRESS_BOOK, CollectionKind::AddressBook, "Contacts");
        fake
    }

    /// Makes the server schedule ([`Scheduling::Server`]) or not (the default,
    /// [`Scheduling::Client`]).
    pub fn set_server_schedules(&self, on: bool) {
        self.state.lock().unwrap().server_schedules = on;
    }

    /// Sets the account's own calendar addresses.
    pub fn set_addresses(&self, addresses: &[&str]) {
        self.state.lock().unwrap().addresses = addresses.iter().map(|a| (*a).to_owned()).collect();
    }

    /// The `notify` flag of every write the server received, in order.
    pub fn notifies(&self) -> Vec<bool> {
        self.state.lock().unwrap().notifies.clone()
    }

    /// Adds an empty collection, or renames an existing one.
    pub fn add_collection(&self, id: &str, kind: CollectionKind, name: &str) {
        let mut st = self.state.lock().unwrap();
        let info = CollectionInfo {
            id: id.to_owned(),
            kind,
            name: name.to_owned(),
            color: None,
            read_only: false,
            components: if kind == CollectionKind::Calendar {
                vec!["VEVENT".into(), "VTODO".into()]
            } else {
                Vec::new()
            },
            role: None,
        };
        match st.colls.get_mut(id) {
            Some(c) => c.info = info,
            None => {
                st.colls.insert(
                    id.to_owned(),
                    Coll {
                        info,
                        generation: 1,
                        objects: BTreeMap::new(),
                        log: Vec::new(),
                    },
                );
            }
        }
    }

    /// Removes a collection with everything in it.
    pub fn remove_collection(&self, id: &str) {
        self.state.lock().unwrap().colls.remove(id);
    }

    /// Makes writes to the collection fail with `read_only`, and lists it as read-only.
    pub fn set_read_only(&self, id: &str, read_only: bool) {
        if let Some(c) = self.state.lock().unwrap().colls.get_mut(id) {
            c.info.read_only = read_only;
        }
    }

    /// Makes the next session call fail with `error`.
    pub fn fail_next(&self, error: PimError) {
        self.state.lock().unwrap().fail_next = Some(error);
    }

    /// Applies the next write but answers it with a network error, as if the answer was lost.
    pub fn lose_next_answer(&self) {
        self.state.lock().unwrap().lose_next_answer = true;
    }

    /// How many sessions were opened.
    pub fn connects(&self) -> u64 {
        self.state.lock().unwrap().connects
    }

    /// How many objects were fetched.
    pub fn fetched(&self) -> u64 {
        self.state.lock().unwrap().fetched
    }

    /// How many writes reached the server.
    pub fn writes(&self) -> u64 {
        self.state.lock().unwrap().writes
    }

    /// Adds `count` generated objects to `collection`, named `gen-{n}`.
    pub fn fill(&self, collection: &str, count: usize) {
        let mut st = self.state.lock().unwrap();
        let kind = st.colls[collection].info.kind;
        for n in 0..count {
            let name = format!("gen-{n}.{}", ext(kind));
            let bytes = sample(kind, &format!("gen-{n}"));
            write(&mut st, collection, &name, Some(Bytes::from(bytes)));
        }
    }

    fn take_failure(&self) -> Result<(), PimError> {
        match self.state.lock().unwrap().fail_next.take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

fn ext(kind: CollectionKind) -> &'static str {
    match kind {
        CollectionKind::Calendar => "ics",
        CollectionKind::AddressBook => "vcf",
    }
}

fn write(st: &mut State, collection: &str, name: &str, bytes: Option<Bytes>) -> u64 {
    st.seq += 1;
    let seq = st.seq;
    let c = st.colls.get_mut(collection).expect("collection exists");
    match bytes {
        Some(b) => {
            c.objects.insert(name.to_owned(), (seq, b));
        }
        None => {
            c.objects.remove(name);
        }
    }
    c.log.push((seq, name.to_owned()));
    seq
}

fn raw(collection: &str, name: &str, seq: u64, bytes: &Bytes, kind: CollectionKind) -> RawObject {
    RawObject {
        item: item(collection, name),
        version: Some(version(seq)),
        bytes: bytes.clone(),
        content_type: kind.media_type().into(),
    }
}

fn item(collection: &str, name: &str) -> ItemRef {
    ItemRef {
        id: format!("{collection}{name}"),
        uid: None,
    }
}

/// An invented calendar object or contact whose `UID` is built from `tag`.
pub fn sample(kind: CollectionKind, tag: &str) -> Vec<u8> {
    match kind {
        CollectionKind::Calendar => format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Skein//Tests//EN\r\nBEGIN:VEVENT\r\n\
             UID:{tag}@example.com\r\nDTSTAMP:20261201T090000Z\r\nDTSTART:20261201T100000Z\r\n\
             DTEND:20261201T110000Z\r\nSUMMARY:Planning {tag}\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
        ),
        CollectionKind::AddressBook => format!(
            "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:{tag}@example.com\r\nFN:Test Person {tag}\r\n\
             N:Person;Test;;;\r\nEMAIL:person-{tag}@example.org\r\nEND:VCARD\r\n"
        ),
    }
    .into_bytes()
}

#[async_trait]
impl PimServerControl for FakePim {
    async fn put(&self, collection: &str, name: &str, bytes: &[u8]) {
        let mut st = self.state.lock().unwrap();
        write(
            &mut st,
            collection,
            name,
            Some(Bytes::copy_from_slice(bytes)),
        );
    }

    async fn remove(&self, collection: &str, name: &str) {
        let mut st = self.state.lock().unwrap();
        if st.colls[collection].objects.contains_key(name) {
            write(&mut st, collection, name, None);
        }
    }

    async fn invalidate(&self, collection: &str) -> bool {
        let mut st = self.state.lock().unwrap();
        if let Some(c) = st.colls.get_mut(collection) {
            c.generation += 1;
        }
        true
    }

    async fn read(&self, collection: &str, item: &ItemRef) -> Option<(Option<String>, Bytes)> {
        let st = self.state.lock().unwrap();
        let name = item.id.strip_prefix(collection)?;
        st.colls
            .get(collection)?
            .objects
            .get(name)
            .map(|(seq, b)| (Some(version(*seq)), b.clone()))
    }

    async fn contents(&self, collection: &str) -> Vec<Bytes> {
        let st = self.state.lock().unwrap();
        let mut v: Vec<Bytes> = st
            .colls
            .get(collection)
            .map(|c| c.objects.values().map(|(_, b)| b.clone()).collect())
            .unwrap_or_default();
        v.sort();
        v
    }
}

#[async_trait]
impl PimProvider for FakePim {
    async fn connect(&self) -> Result<Box<dyn PimSession>, PimError> {
        self.take_failure()?;
        self.state.lock().unwrap().connects += 1;
        Ok(Box::new(FakeSession { fake: self.clone() }))
    }
}

struct FakeSession {
    fake: FakePim,
}

fn parse_cursor(cursor: &Cursor) -> Option<(u64, u64)> {
    let text = std::str::from_utf8(&cursor.0).ok()?;
    let (g, s) = text.split_once(':')?;
    Some((g.parse().ok()?, s.parse().ok()?))
}

#[async_trait]
impl PimSession for FakeSession {
    async fn collections(&mut self) -> Result<Vec<CollectionInfo>, PimError> {
        self.fake.take_failure()?;
        let st = self.fake.state.lock().unwrap();
        Ok(st.colls.values().map(|c| c.info.clone()).collect())
    }

    async fn changes(
        &mut self,
        collection: &str,
        cursor: Option<&Cursor>,
        limit: usize,
    ) -> Result<PimChanges, PimError> {
        self.fake.take_failure()?;
        let st = self.fake.state.lock().unwrap();
        let c = st.colls.get(collection).ok_or(PimError::NotFound)?;
        let mut changes = Vec::new();
        let since = match cursor {
            None => None,
            Some(cursor) => match parse_cursor(cursor) {
                Some((g, s)) if g == c.generation => Some(s),
                _ => {
                    changes.push(PimChange::Reset {
                        reason: "sync_token".into(),
                    });
                    None
                }
            },
        };
        let mut latest: HashMap<&str, u64> = HashMap::new();
        for (seq, name) in &c.log {
            if since.is_none_or(|s| *seq > s) {
                latest.insert(name, *seq);
            }
        }
        let mut touched: Vec<(u64, &str)> = latest
            .into_iter()
            .map(|(n, s)| (s, n))
            .filter(|(_, n)| since.is_some() || c.objects.contains_key(*n))
            .collect();
        touched.sort();
        let limit = limit.max(1);
        let more = touched.len() > limit;
        touched.truncate(limit);
        let upto = if more {
            touched.last().map(|(s, _)| *s).unwrap_or(0)
        } else {
            c.log
                .last()
                .map(|(s, _)| *s)
                .unwrap_or(0)
                .max(since.unwrap_or(0))
        };
        for (_, name) in touched {
            let item = item(collection, name);
            changes.push(match c.objects.get(name) {
                Some((seq, _)) => PimChange::Upserted {
                    item,
                    version: Some(version(*seq)),
                },
                None => PimChange::Removed { item },
            });
        }
        Ok(PimChanges {
            changes,
            cursor: Cursor(Bytes::from(format!("{}:{upto}", c.generation))),
            more,
        })
    }

    async fn fetch(
        &mut self,
        collection: &str,
        items: &[ItemRef],
    ) -> Result<Vec<RawObject>, PimError> {
        self.fake.take_failure()?;
        let mut st = self.fake.state.lock().unwrap();
        let c = st.colls.get(collection).ok_or(PimError::NotFound)?;
        let ct = c.info.kind.media_type();
        let mut out: Vec<RawObject> = Vec::new();
        for it in items {
            let Some(name) = it.id.strip_prefix(collection) else {
                continue;
            };
            if out.iter().any(|o| o.item.id == it.id) {
                continue;
            }
            if let Some((seq, bytes)) = c.objects.get(name) {
                out.push(RawObject {
                    item: it.clone(),
                    version: Some(version(*seq)),
                    bytes: bytes.clone(),
                    content_type: ct.into(),
                });
            }
        }
        st.fetched += out.len() as u64;
        Ok(out)
    }

    async fn apply(&mut self, w: &PimWrite) -> Result<WriteOutcome, PimError> {
        self.fake.take_failure()?;
        let mut st = self.fake.state.lock().unwrap();
        let collection = w.collection().to_owned();
        let collection = &collection;
        let notify = match w {
            PimWrite::Put { notify, .. }
            | PimWrite::Delete { notify, .. }
            | PimWrite::Respond { notify, .. } => *notify,
        };
        st.notifies.push(notify);
        let own = st.addresses.clone();
        let c = st.colls.get(collection).ok_or(PimError::NotFound)?;
        if c.info.read_only {
            return Ok(WriteOutcome::Failed {
                reason: "read_only".into(),
            });
        }
        let kind = c.info.kind;
        let outcome = match w {
            PimWrite::Respond {
                item: target,
                answer,
                attendee,
                comment,
                if_version,
                ..
            } => {
                let name = target.id.strip_prefix(collection.as_str()).unwrap_or("");
                let Some((seq, bytes)) = c.objects.get(name).cloned() else {
                    return Ok(WriteOutcome::Conflict { current: None });
                };
                if if_version.as_ref().is_some_and(|v| *v != version(seq)) {
                    return Ok(WriteOutcome::Conflict {
                        current: Some(version(seq)),
                    });
                }
                let who = match attendee {
                    Some(a) => Some(a.clone()),
                    None => skein_itip::facts(&bytes)
                        .ok()
                        .and_then(|f| f.own_attendee(&own).map(|a| a.address.clone())),
                };
                let changed = who
                    .ok_or(skein_itip::ItipError::AttendeeNotFound)
                    .and_then(|a| {
                        skein_itip::set_partstat(&bytes, &a, *answer, comment.as_deref())
                    });
                match changed {
                    Err(e) => WriteOutcome::Failed {
                        reason: e.reason().into(),
                    },
                    Ok(next) => {
                        let name = name.to_owned();
                        let seq = write(&mut st, collection, &name, Some(next.clone()));
                        st.writes += 1;
                        WriteOutcome::Applied {
                            item: Some(target.clone()),
                            current: Some(raw(collection, &name, seq, &next, kind)),
                        }
                    }
                }
            }
            PimWrite::Put {
                item: None,
                bytes,
                key,
                ..
            } => {
                let name = name_for_key(key, kind);
                match c.objects.get(&name) {
                    Some((seq, existing)) if existing == bytes => WriteOutcome::Applied {
                        item: Some(item(collection, &name)),
                        current: Some(raw(collection, &name, *seq, existing, kind)),
                    },
                    Some((seq, _)) => WriteOutcome::Conflict {
                        current: Some(version(*seq)),
                    },
                    None => {
                        let seq = write(&mut st, collection, &name, Some(bytes.clone()));
                        st.writes += 1;
                        WriteOutcome::Applied {
                            item: Some(item(collection, &name)),
                            current: Some(raw(collection, &name, seq, bytes, kind)),
                        }
                    }
                }
            }
            PimWrite::Put {
                item: Some(target),
                bytes,
                if_version,
                ..
            } => {
                let Some(name) = target.id.strip_prefix(collection.as_str()) else {
                    return Ok(WriteOutcome::Failed {
                        reason: "not_in_collection".into(),
                    });
                };
                let current = c.objects.get(name).map(|(s, _)| version(*s));
                match (if_version, &current) {
                    (Some(_), None) => WriteOutcome::Conflict { current: None },
                    (Some(want), Some(have)) if want != have => WriteOutcome::Conflict {
                        current: current.clone(),
                    },
                    _ => {
                        let name = name.to_owned();
                        let seq = write(&mut st, collection, &name, Some(bytes.clone()));
                        st.writes += 1;
                        WriteOutcome::Applied {
                            item: Some(target.clone()),
                            current: Some(raw(collection, &name, seq, bytes, kind)),
                        }
                    }
                }
            }
            PimWrite::Delete {
                item: target,
                if_version,
                ..
            } => {
                let name = target.id.strip_prefix(collection.as_str()).unwrap_or("");
                let current = c.objects.get(name).map(|(s, _)| version(*s));
                match (if_version, &current) {
                    (_, None) => WriteOutcome::Applied {
                        item: Some(target.clone()),
                        current: None,
                    },
                    (Some(want), Some(have)) if want != have => WriteOutcome::Conflict {
                        current: current.clone(),
                    },
                    _ => {
                        let name = name.to_owned();
                        write(&mut st, collection, &name, None);
                        st.writes += 1;
                        WriteOutcome::Applied {
                            item: Some(target.clone()),
                            current: None,
                        }
                    }
                }
            }
        };
        if std::mem::take(&mut st.lose_next_answer) {
            return Err(PimError::Network("the answer was lost".into()));
        }
        Ok(outcome)
    }

    async fn scheduling(&mut self, collection: &str) -> Result<Scheduling, PimError> {
        let st = self.fake.state.lock().unwrap();
        if !st.colls.contains_key(collection) {
            return Err(PimError::NotFound);
        }
        Ok(if st.server_schedules {
            Scheduling::Server
        } else {
            Scheduling::Client
        })
    }

    async fn addresses(&mut self) -> Result<Vec<String>, PimError> {
        Ok(self.fake.state.lock().unwrap().addresses.clone())
    }

    async fn logout(&mut self) -> Result<(), PimError> {
        Ok(())
    }
}

#[derive(Default)]
struct Mirror {
    by_id: HashMap<String, (Option<String>, Bytes)>,
}

impl Mirror {
    fn contents(&self) -> Vec<Bytes> {
        let mut v: Vec<Bytes> = self.by_id.values().map(|(_, b)| b.clone()).collect();
        v.sort();
        v
    }
}

async fn drain(
    session: &mut Box<dyn PimSession>,
    collection: &str,
    cursor: Option<Cursor>,
    mirror: &mut Mirror,
    limit: usize,
) -> (Cursor, Vec<PimChange>) {
    let mut cursor = cursor;
    let mut all = Vec::new();
    for _ in 0..10_000 {
        let batch = session
            .changes(collection, cursor.as_ref(), limit)
            .await
            .unwrap();
        let mut upserted = Vec::new();
        for change in &batch.changes {
            match change {
                PimChange::Reset { .. } => mirror.by_id.clear(),
                PimChange::Upserted { item, .. } => upserted.push(item.clone()),
                PimChange::Removed { item } => {
                    mirror.by_id.remove(&item.id);
                }
            }
        }
        let raw = session.fetch(collection, &upserted).await.unwrap();
        assert_eq!(
            raw.len(),
            upserted.len(),
            "every upserted object can be fetched"
        );
        for obj in raw {
            assert!(
                upserted.contains(&obj.item),
                "fetch answers only what was asked"
            );
            mirror.by_id.insert(obj.item.id, (obj.version, obj.bytes));
        }
        all.extend(batch.changes);
        cursor = Some(batch.cursor);
        if !batch.more {
            return (cursor.unwrap(), all);
        }
    }
    panic!("the change feed never ended");
}

fn name(kind: CollectionKind, n: u32) -> String {
    format!("conformance-{n}.{}", ext(kind))
}

fn obj(kind: CollectionKind, n: u32) -> Vec<u8> {
    sample(kind, &format!("conformance-{n}"))
}

fn upserts(changes: &[PimChange]) -> usize {
    changes
        .iter()
        .filter(|c| matches!(c, PimChange::Upserted { .. }))
        .count()
}

fn removals(changes: &[PimChange]) -> usize {
    changes
        .iter()
        .filter(|c| matches!(c, PimChange::Removed { .. }))
        .count()
}

/// The [`PimSession`] contract against a server that `control` can change. `collection` must
/// exist, be empty, writable and of `kind`.
pub async fn conformance(
    provider: Arc<dyn PimProvider>,
    control: Arc<dyn PimServerControl>,
    collection: &str,
    kind: CollectionKind,
) {
    let mut session = provider.connect().await.unwrap();
    let listed = session.collections().await.unwrap();
    let info = listed
        .iter()
        .find(|c| c.id == collection)
        .expect("the collection is listed");
    assert_eq!(info.kind, kind, "the collection has its kind");
    assert!(!info.read_only, "the collection is writable");
    assert_eq!(
        listed.iter().filter(|c| c.id == collection).count(),
        1,
        "each collection is listed once"
    );

    for n in 1..=5 {
        control.put(collection, &name(kind, n), &obj(kind, n)).await;
    }
    let mut mirror = Mirror::default();
    let (cursor, _) = drain(&mut session, collection, None, &mut mirror, 2).await;
    assert_eq!(
        mirror.contents(),
        control.contents(collection).await,
        "a listing without a cursor sees everything, paged, with the exact bytes"
    );
    for (id, (version, bytes)) in &mirror.by_id {
        let item = ItemRef {
            id: id.clone(),
            uid: None,
        };
        let (now, held) = control.read(collection, &item).await.expect("listed item");
        assert_eq!(&held, bytes);
        if version.is_some() {
            assert_eq!(version, &now, "the version belongs to the bytes");
        }
    }

    let (cursor, changes) = drain(&mut session, collection, Some(cursor), &mut mirror, 2).await;
    assert!(
        changes.is_empty(),
        "nothing changed, nothing reported: {changes:?}"
    );

    let changed = [obj(kind, 3), b"X-CHANGED:1\r\n".to_vec()].concat();
    control.put(collection, &name(kind, 3), &changed).await;
    control.remove(collection, &name(kind, 2)).await;
    control.put(collection, &name(kind, 6), &obj(kind, 6)).await;
    let (cursor, changes) = drain(&mut session, collection, Some(cursor), &mut mirror, 2).await;
    assert_eq!(
        (upserts(&changes), removals(&changes)),
        (2, 1),
        "exactly the three changes are reported: {changes:?}"
    );
    assert_eq!(mirror.contents(), control.contents(collection).await);

    let invalidated = control.invalidate(collection).await;
    let (_, changes) = drain(&mut session, collection, Some(cursor), &mut mirror, 100).await;
    assert!(
        !invalidated || matches!(changes.first(), Some(PimChange::Reset { .. })),
        "an invalid cursor resets: {changes:?}"
    );
    assert_eq!(
        mirror.contents(),
        control.contents(collection).await,
        "the reset lists everything again"
    );
    let garbage = Cursor(Bytes::from_static(b"\xff not a cursor"));
    let (_, changes) = drain(
        &mut session,
        collection,
        Some(garbage),
        &mut Mirror::default(),
        100,
    )
    .await;
    assert!(
        matches!(changes.first(), Some(PimChange::Reset { .. })),
        "an unreadable cursor resets"
    );

    let missing = ItemRef {
        id: format!("{collection}missing-object.{}", ext(kind)),
        uid: None,
    };
    let none = session
        .fetch(collection, std::slice::from_ref(&missing))
        .await
        .unwrap();
    assert!(none.is_empty(), "vanished objects are left out");

    let created_bytes = Bytes::from(obj(kind, 7));
    let create = PimWrite::Put {
        collection: collection.to_owned(),
        item: None,
        bytes: created_bytes.clone(),
        if_version: None,
        key: "01KCONFORMANCECREATE000000".into(),
        notify: false,
    };
    let WriteOutcome::Applied {
        item: Some(created),
        current,
    } = session.apply(&create).await.unwrap()
    else {
        panic!("a create is applied and names its object");
    };
    let (version, held) = control
        .read(collection, &created)
        .await
        .expect("the created object is there");
    assert_eq!(held, created_bytes, "a create stores the exact bytes");
    if let Some(current) = current {
        assert_eq!(current.item, created);
        assert_eq!(
            current.bytes, held,
            "the object read back is what the server holds"
        );
        assert_eq!(current.version, version);
    }
    let again = session.apply(&create).await.unwrap();
    assert!(
        matches!(&again, WriteOutcome::Applied { item: Some(i), .. } if *i == created),
        "repeating a create answers with the same object: {again:?}"
    );
    assert_eq!(
        control.contents(collection).await.len(),
        6,
        "one object per key"
    );

    let stale = PimWrite::Put {
        collection: collection.to_owned(),
        item: Some(created.clone()),
        bytes: Bytes::from(obj(kind, 8)),
        if_version: Some("\"stale-version\"".into()),
        key: "01KCONFORMANCESTALE0000000".into(),
        notify: false,
    };
    assert!(
        matches!(
            session.apply(&stale).await.unwrap(),
            WriteOutcome::Conflict { .. }
        ),
        "a stale version conflicts"
    );
    assert_eq!(
        control.read(collection, &created).await.unwrap().1,
        created_bytes
    );

    let updated_bytes = Bytes::from(obj(kind, 9));
    let update = PimWrite::Put {
        collection: collection.to_owned(),
        item: Some(created.clone()),
        bytes: updated_bytes.clone(),
        if_version: version.clone(),
        key: "01KCONFORMANCEUPDATE000000".into(),
        notify: false,
    };
    assert!(
        matches!(
            session.apply(&update).await.unwrap(),
            WriteOutcome::Applied { .. }
        ),
        "the current version is accepted"
    );
    let (now, held) = control.read(collection, &created).await.unwrap();
    assert_eq!(held, updated_bytes);
    if version.is_some() {
        assert_ne!(now, version, "a write changes the version");
    }

    let stale_delete = PimWrite::Delete {
        collection: collection.to_owned(),
        item: created.clone(),
        if_version: version.clone().or(Some("\"stale-version\"".into())),
        notify: false,
    };
    if now.is_some() {
        assert!(
            matches!(
                session.apply(&stale_delete).await.unwrap(),
                WriteOutcome::Conflict { .. }
            ),
            "a delete with a stale version conflicts"
        );
        assert!(control.read(collection, &created).await.is_some());
    }
    let delete = PimWrite::Delete {
        collection: collection.to_owned(),
        item: created.clone(),
        if_version: now,
        notify: false,
    };
    assert!(matches!(
        session.apply(&delete).await.unwrap(),
        WriteOutcome::Applied { .. }
    ));
    assert!(control.read(collection, &created).await.is_none());
    let gone = PimWrite::Delete {
        collection: collection.to_owned(),
        item: created.clone(),
        if_version: None,
        notify: false,
    };
    assert!(
        matches!(
            session.apply(&gone).await.unwrap(),
            WriteOutcome::Applied { .. }
        ),
        "deleting a gone object counts as applied"
    );

    for n in [1, 3, 4, 5, 6] {
        control.remove(collection, &name(kind, n)).await;
    }
    session.logout().await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_fake_keeps_the_contract() {
        let fake = FakePim::standard();
        conformance(
            Arc::new(fake.clone()),
            Arc::new(fake.clone()),
            CALENDAR,
            CollectionKind::Calendar,
        )
        .await;
        conformance(
            Arc::new(fake.clone()),
            Arc::new(fake.clone()),
            ADDRESS_BOOK,
            CollectionKind::AddressBook,
        )
        .await;
    }

    #[tokio::test]
    async fn read_only_collections_refuse_writes_and_lost_answers_are_network_errors() {
        let fake = FakePim::standard();
        let mut s = fake.connect().await.unwrap();
        let put = PimWrite::Put {
            collection: CALENDAR.into(),
            item: None,
            bytes: Bytes::from(sample(CollectionKind::Calendar, "x")),
            if_version: None,
            key: "k".into(),
            notify: false,
        };
        fake.set_read_only(CALENDAR, true);
        assert_eq!(
            s.apply(&put).await.unwrap(),
            WriteOutcome::Failed {
                reason: "read_only".into()
            }
        );
        fake.set_read_only(CALENDAR, false);
        fake.lose_next_answer();
        assert!(matches!(s.apply(&put).await, Err(PimError::Network(_))));
        assert_eq!(fake.writes(), 1, "the write still happened");
        assert!(matches!(
            s.changes("/nope/", None, 10).await,
            Err(PimError::NotFound)
        ));
        assert_eq!(
            name_for_key("a/b", CollectionKind::AddressBook),
            "a_2fb.vcf"
        );
    }
}
