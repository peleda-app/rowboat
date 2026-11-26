use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::Router;
use axum::body::Bytes as Body;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use serde_json::Map;
use skein_core::PartStat;
use skein_pim::Scheduling;
use skein_pim::testing::PimServerControl;

use super::*;

const USER: &str = "ada@example.com";
const PASSWORD: &str = "correct-horse-0451";
const ACCOUNT: &str = "acc-ada";
const BOOK: &str = "addressbook/ab1";
const OTHER_BOOK: &str = "addressbook/ab2";
const CAL: &str = "calendar/cal1";
const SHARED: &str = "calendar/cal2";

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum K {
    Cards,
    Events,
}

impl K {
    fn of(name: &str) -> Option<(Self, &str)> {
        let (prefix, method) = name.split_once('/')?;
        let k = match prefix {
            "ContactCard" | "AddressBook" => Self::Cards,
            "CalendarEvent" | "Calendar" => Self::Events,
            _ => return None,
        };
        Some((k, method))
    }

    fn member(self) -> &'static str {
        match self {
            Self::Cards => "addressBookIds",
            Self::Events => "calendarIds",
        }
    }

    fn filter(self) -> &'static str {
        match self {
            Self::Cards => "inAddressBook",
            Self::Events => "inCalendar",
        }
    }

    fn from_collection(collection: &str) -> (Self, &str) {
        match split(collection).unwrap() {
            (k, id) if k.kind == CollectionKind::AddressBook => (Self::Cards, id),
            (_, id) => (Self::Events, id),
        }
    }
}

struct Book {
    k: K,
    name: String,
    color: Option<String>,
    writable: bool,
}

#[derive(Default)]
struct Store {
    items: BTreeMap<String, Map<String, Value>>,
    state: u64,
    floor: u64,
    history: Vec<(u64, String, bool)>,
}

#[derive(Default)]
struct JState {
    port: u16,
    books: BTreeMap<String, Book>,
    stores: BTreeMap<K, Store>,
    created: u64,
    page: usize,
    no_calendars: bool,
    api_url: Option<String>,
    busy: u32,
    interfere: u32,
    huge_session: bool,
    requests: Vec<(String, String, bool)>,
    calls: Vec<String>,
    identities: Option<Vec<Value>>,
    scheduling: Vec<Option<bool>>,
}

#[derive(Clone)]
struct FakeJmap(Arc<Mutex<JState>>);

impl FakeJmap {
    fn standard() -> Self {
        let mut s = JState {
            page: 2,
            ..JState::default()
        };
        for (id, k, name, color, writable) in [
            ("ab1", K::Cards, "Contacts", None, true),
            ("ab2", K::Cards, "Work", None, true),
            ("cal1", K::Events, "Work & Life", Some("#336699"), true),
            ("cal2", K::Events, "Holidays", None, false),
        ] {
            s.books.insert(
                id.into(),
                Book {
                    k,
                    name: name.into(),
                    color: color.map(str::to_owned),
                    writable,
                },
            );
        }
        s.stores.insert(K::Cards, Store::default());
        s.stores.insert(K::Events, Store::default());
        s.identities = Some(Vec::new());
        Self(Arc::new(Mutex::new(s)))
    }

    fn set(&self, f: impl FnOnce(&mut JState)) {
        f(&mut self.0.lock().unwrap());
    }

    fn requests(&self) -> Vec<(String, String, bool)> {
        self.0.lock().unwrap().requests.clone()
    }

    fn calls(&self) -> Vec<String> {
        self.0.lock().unwrap().calls.clone()
    }

    fn scheduling(&self) -> Vec<Option<bool>> {
        self.0.lock().unwrap().scheduling.clone()
    }

    fn event(&self, id: &str) -> Value {
        Value::Object(self.0.lock().unwrap().stores[&K::Events].items[id].clone())
    }
}

/// Applies one JMAP patch entry: a property, or a path into nested objects.
fn patch_path(fields: &mut Map<String, Value>, path: &str, value: &Value) -> bool {
    let segments: Vec<String> = path
        .split('/')
        .map(|p| p.replace("~1", "/").replace("~0", "~"))
        .collect();
    let (last, parents) = segments.split_last().unwrap();
    let mut at = fields;
    for segment in parents {
        let Some(Value::Object(next)) = at.get_mut(segment) else {
            return false;
        };
        at = next;
    }
    if value.is_null() {
        at.remove(last);
    } else {
        at.insert(last.clone(), value.clone());
    }
    true
}

fn touch(store: &mut Store, id: &str, alive: bool) {
    store.state += 1;
    let state = store.state;
    store.history.push((state, id.to_owned(), alive));
}

fn render(id: &str, fields: &Map<String, Value>) -> Value {
    let mut map = fields.clone();
    map.insert("id".into(), json!(id));
    Value::Object(map)
}

fn canonical_bytes(id: &str, fields: &Map<String, Value>) -> Bytes {
    Bytes::from(serde_json::to_vec(&canonical(render(id, fields))).unwrap())
}

#[async_trait]
impl PimServerControl for FakeJmap {
    async fn put(&self, collection: &str, name: &str, bytes: &[u8]) {
        let (k, coll) = K::from_collection(collection);
        let Ok(Value::Object(mut fields)) = serde_json::from_slice(bytes) else {
            panic!("the fake holds JSON objects");
        };
        fields.insert(k.member().into(), json!({ coll: true }));
        let mut s = self.0.lock().unwrap();
        let store = s.stores.get_mut(&k).unwrap();
        store.items.insert(name.into(), fields);
        touch(store, name, true);
    }

    async fn remove(&self, collection: &str, name: &str) {
        let (k, _) = K::from_collection(collection);
        let mut s = self.0.lock().unwrap();
        let store = s.stores.get_mut(&k).unwrap();
        if store.items.remove(name).is_some() {
            touch(store, name, false);
        }
    }

    async fn invalidate(&self, collection: &str) -> bool {
        let (k, _) = K::from_collection(collection);
        let mut s = self.0.lock().unwrap();
        let store = s.stores.get_mut(&k).unwrap();
        store.state += 1;
        store.floor = store.state;
        true
    }

    async fn read(&self, collection: &str, item: &ItemRef) -> Option<(Option<String>, Bytes)> {
        let (k, coll) = K::from_collection(collection);
        let s = self.0.lock().unwrap();
        let fields = s.stores[&k].items.get(&item.id)?;
        if !member_of(&Value::Object(fields.clone()), k.member(), coll) {
            return None;
        }
        let bytes = canonical_bytes(&item.id, fields);
        Some((Some(version(&bytes)), bytes))
    }

    async fn contents(&self, collection: &str) -> Vec<Bytes> {
        let (k, coll) = K::from_collection(collection);
        let s = self.0.lock().unwrap();
        let mut v: Vec<Bytes> = s.stores[&k]
            .items
            .iter()
            .filter(|(_, f)| member_of(&Value::Object((*f).clone()), k.member(), coll))
            .map(|(id, f)| canonical_bytes(id, f))
            .collect();
        v.sort();
        v
    }
}

fn error(kind: &str) -> Value {
    json!({ "type": kind })
}

fn method(s: &mut JState, name: &str, args: &Value) -> (String, Value) {
    let fail = |kind: &str| ("error".to_owned(), error(kind));
    if args.get("accountId").and_then(Value::as_str) != Some(ACCOUNT) {
        return fail("accountNotFound");
    }
    if name == "ParticipantIdentity/get" {
        return match &s.identities {
            Some(list) => (
                name.to_owned(),
                json!({ "accountId": ACCOUNT, "state": "i1", "list": list, "notFound": [] }),
            ),
            None => fail("unknownMethod"),
        };
    }
    let Some((k, verb)) = K::of(name) else {
        return fail("unknownMethod");
    };
    if k == K::Events && s.no_calendars {
        return fail("unknownMethod");
    }
    let is_collection = name.starts_with("AddressBook/") || name.starts_with("Calendar/");
    if is_collection {
        let ids: Option<Vec<String>> = args.get("ids").and_then(Value::as_array).map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        });
        let list: Vec<Value> = s
            .books
            .iter()
            .filter(|(id, b)| b.k == k && ids.as_ref().is_none_or(|ids| ids.contains(id)))
            .map(|(id, b)| {
                let rights = match k {
                    K::Cards => json!({ "mayRead": true, "mayWrite": b.writable }),
                    K::Events => json!({ "mayReadItems": true, "mayWriteAll": b.writable, "mayWriteOwn": b.writable }),
                };
                json!({ "id": id, "name": b.name, "color": b.color, "myRights": rights })
            })
            .collect();
        return (
            name.to_owned(),
            json!({ "accountId": ACCOUNT, "state": "c1", "list": list, "notFound": [] }),
        );
    }
    let page = s.page;
    let interfere = s.interfere;
    let writable =
        |s: &JState, coll: &str| s.books.get(coll).is_some_and(|b| b.writable && b.k == k);
    let store_state = s.stores[&k].state.to_string();
    match verb {
        "get" => {
            let store = &s.stores[&k];
            let ids: Vec<String> = match args.get("ids") {
                Some(Value::Array(a)) => a
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect(),
                _ => store.items.keys().cloned().collect(),
            };
            let properties: Option<Vec<String>> =
                args.get("properties").and_then(Value::as_array).map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                });
            let mut list = Vec::new();
            let mut not_found = Vec::new();
            for id in ids {
                match store.items.get(&id) {
                    Some(fields) => {
                        let mut v = render(&id, fields);
                        if let Some(p) = &properties {
                            v.as_object_mut().unwrap().retain(|key, _| p.contains(key));
                        }
                        list.push(v);
                    }
                    None => not_found.push(id),
                }
            }
            (
                name.to_owned(),
                json!({ "accountId": ACCOUNT, "state": store_state, "list": list, "notFound": not_found }),
            )
        }
        "query" => {
            let store = &s.stores[&k];
            let filter = args.get("filter").cloned().unwrap_or(Value::Null);
            let coll = filter.get(k.filter()).and_then(Value::as_str);
            let uid = filter.get("uid").and_then(Value::as_str);
            let ids: Vec<String> = store
                .items
                .iter()
                .filter(|(_, f)| {
                    coll.is_none_or(|c| member_of(&Value::Object((*f).clone()), k.member(), c))
                })
                .filter(|(_, f)| {
                    uid.is_none_or(|u| f.get("uid").and_then(Value::as_str) == Some(u))
                })
                .map(|(id, _)| id.clone())
                .collect();
            let position = args.get("position").and_then(Value::as_u64).unwrap_or(0) as usize;
            let limit = args
                .get("limit")
                .and_then(Value::as_u64)
                .map_or(page, |l| (l as usize).min(page));
            let found: Vec<String> = ids.iter().skip(position).take(limit).cloned().collect();
            (
                name.to_owned(),
                json!({
                    "accountId": ACCOUNT, "queryState": store_state, "position": position,
                    "ids": found, "total": ids.len(), "canCalculateChanges": true,
                }),
            )
        }
        "changes" => {
            let store = &s.stores[&k];
            let Some(since) = args
                .get("sinceState")
                .and_then(Value::as_str)
                .and_then(|v| v.parse::<u64>().ok())
            else {
                return fail("invalidArguments");
            };
            if since < store.floor || since > store.state {
                return fail("cannotCalculateChanges");
            }
            let max = args
                .get("maxChanges")
                .and_then(Value::as_u64)
                .map_or(usize::MAX, |m| m as usize)
                .min(page.max(1));
            let entries: Vec<&(u64, String, bool)> = store
                .history
                .iter()
                .filter(|(st, _, _)| *st > since)
                .collect();
            let taken: Vec<&(u64, String, bool)> = entries.iter().take(max).copied().collect();
            let more = entries.len() > taken.len();
            let new_state = taken.last().map_or(since, |(st, _, _)| *st);
            let mut latest: BTreeMap<&str, bool> = BTreeMap::new();
            for (_, id, alive) in &taken {
                latest.insert(id, *alive);
            }
            let updated: Vec<&str> = latest
                .iter()
                .filter(|(_, a)| **a)
                .map(|(i, _)| *i)
                .collect();
            let destroyed: Vec<&str> = latest
                .iter()
                .filter(|(_, a)| !**a)
                .map(|(i, _)| *i)
                .collect();
            (
                name.to_owned(),
                json!({
                    "accountId": ACCOUNT, "oldState": since.to_string(), "newState": new_state.to_string(),
                    "hasMoreChanges": more, "created": [], "updated": updated, "destroyed": destroyed,
                }),
            )
        }
        "set" => {
            let notify = args.get("sendSchedulingMessages").and_then(Value::as_bool);
            assert!(
                k == K::Events || notify.is_none(),
                "address books take no scheduling argument"
            );
            s.scheduling.push(notify);
            if let Some(wanted) = args.get("ifInState").and_then(Value::as_str) {
                if interfere > 0 {
                    s.interfere -= 1;
                    let store = s.stores.get_mut(&k).unwrap();
                    touch(store, "someone-else", true);
                    store.items.remove("someone-else");
                }
                if wanted != s.stores[&k].state.to_string() {
                    return fail("stateMismatch");
                }
            }
            let old = s.stores[&k].state.to_string();
            let mut created = Map::new();
            let mut not_created = Map::new();
            let mut updated = Map::new();
            let mut not_updated = Map::new();
            let mut destroyed = Vec::new();
            let mut not_destroyed = Map::new();
            if let Some(create) = args.get("create").and_then(Value::as_object) {
                for (key, object) in create {
                    let Some(fields) = object.as_object().cloned() else {
                        not_created.insert(key.clone(), error("invalidProperties"));
                        continue;
                    };
                    let target = fields
                        .get(k.member())
                        .and_then(Value::as_object)
                        .and_then(|m| m.keys().next().cloned())
                        .unwrap_or_default();
                    if !writable(s, &target) {
                        not_created.insert(key.clone(), error("forbidden"));
                        continue;
                    }
                    if fields.contains_key("refuseMe") {
                        not_created.insert(key.clone(), json!({ "type": "invalidProperties", "description": "mentions ada@example.com" }));
                        continue;
                    }
                    s.created += 1;
                    let id = format!("obj-{}", s.created);
                    let store = s.stores.get_mut(&k).unwrap();
                    store.items.insert(id.clone(), fields);
                    touch(store, &id, true);
                    created.insert(key.clone(), json!({ "id": id }));
                }
            }
            if let Some(update) = args.get("update").and_then(Value::as_object) {
                for (id, patch) in update {
                    let current = s.stores[&k].items.get(id).cloned();
                    let Some(mut fields) = current else {
                        not_updated.insert(id.clone(), error("notFound"));
                        continue;
                    };
                    let inside = fields
                        .get(k.member())
                        .and_then(Value::as_object)
                        .and_then(|m| m.keys().next().cloned())
                        .unwrap_or_default();
                    if !writable(s, &inside) {
                        not_updated.insert(id.clone(), error("forbidden"));
                        continue;
                    }
                    let mut valid = true;
                    for (key, value) in patch.as_object().unwrap() {
                        valid &= patch_path(&mut fields, key, value);
                    }
                    if !valid {
                        not_updated.insert(id.clone(), error("invalidPatch"));
                        continue;
                    }
                    let store = s.stores.get_mut(&k).unwrap();
                    store.items.insert(id.clone(), fields);
                    touch(store, id, true);
                    updated.insert(id.clone(), Value::Null);
                }
            }
            if let Some(destroy) = args.get("destroy").and_then(Value::as_array) {
                for id in destroy.iter().filter_map(Value::as_str) {
                    let store = s.stores.get_mut(&k).unwrap();
                    if store.items.remove(id).is_some() {
                        touch(store, id, false);
                        destroyed.push(id.to_owned());
                    } else {
                        not_destroyed.insert(id.to_owned(), error("notFound"));
                    }
                }
            }
            (
                name.to_owned(),
                json!({
                    "accountId": ACCOUNT, "oldState": old, "newState": s.stores[&k].state.to_string(),
                    "created": created, "notCreated": not_created, "updated": updated,
                    "notUpdated": not_updated, "destroyed": destroyed, "notDestroyed": not_destroyed,
                }),
            )
        }
        _ => fail("unknownMethod"),
    }
}

async fn handle(
    State(fake): State<FakeJmap>,
    method_: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let mut s = fake.0.lock().unwrap();
    let expected = format!(
        "Basic {}",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{USER}:{PASSWORD}")
        )
    );
    let auth = headers.get("authorization").and_then(|v| v.to_str().ok());
    let signed = auth.is_some();
    s.requests
        .push((method_.to_string(), uri.path().to_owned(), signed));
    if uri.path() == "/.well-known/jmap" {
        return (
            StatusCode::TEMPORARY_REDIRECT,
            [("location", "/jmap/session")],
        )
            .into_response();
    }
    if auth != Some(expected.as_str()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if s.busy > 0 {
        s.busy -= 1;
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [("retry-after", "0")],
            "busy",
        )
            .into_response();
    }
    match (method_.as_str(), uri.path()) {
        ("GET", "/jmap/session") => {
            let mut capabilities = json!({
                CORE: { "maxObjectsInGet": 2, "maxCallsInRequest": 4, "maxObjectsInSet": 10 },
                CONTACTS: {},
            });
            let mut primary = json!({ CONTACTS: ACCOUNT });
            if !s.no_calendars {
                capabilities[CALENDARS] = json!({});
                primary[CALENDARS] = json!(ACCOUNT);
            }
            let mut session = json!({
                "capabilities": capabilities,
                "accounts": { ACCOUNT: { "name": USER } },
                "primaryAccounts": primary,
                "username": USER,
                "apiUrl": s.api_url.clone().unwrap_or_else(|| "/jmap/api".into()),
                "downloadUrl": "/jmap/download/{accountId}/{blobId}/{name}?type={type}",
                "uploadUrl": "/jmap/upload/{accountId}/",
                "state": "s1",
            });
            if s.huge_session {
                session["padding"] = json!("x".repeat(http::MAX_SESSION));
            }
            ([("content-type", "application/json")], session.to_string()).into_response()
        }
        ("POST", "/jmap/api") => {
            let request: Value = serde_json::from_slice(&body).unwrap();
            let mut responses = Vec::new();
            for call in request["methodCalls"].as_array().unwrap() {
                let name = call[0].as_str().unwrap();
                s.calls.push(name.to_owned());
                let (answer_name, args) = method(&mut s, name, &call[1]);
                responses.push(json!([answer_name, args, call[2]]));
            }
            (
                [("content-type", "application/json")],
                json!({ "methodResponses": responses, "sessionState": "s1" }).to_string(),
            )
                .into_response()
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn serve(fake: FakeJmap) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    fake.set(|s| s.port = address.port());
    let app = Router::new().fallback(handle).with_state(fake);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{address}")
}

fn password() -> Credentials {
    Credentials::Password {
        secret: PASSWORD.into(),
    }
}

fn provider(base: &str) -> JmapPimProvider {
    JmapPimProvider::new(JmapPimSettings::new(base, USER), password()).unwrap()
}

/// An invented JSCalendar event or JSContact card whose names are built from `tag`.
fn sample(kind: CollectionKind, tag: &str) -> Vec<u8> {
    match kind {
        CollectionKind::Calendar => json!({
            "@type": "Event",
            "uid": format!("{tag}@example.com"),
            "title": format!("Planning {tag}"),
            "start": "2026-12-01T10:00:00",
            "timeZone": "Etc/UTC",
            "duration": "PT1H",
        }),
        CollectionKind::AddressBook => json!({
            "@type": "Card",
            "version": "1.0",
            "uid": format!("{tag}@example.com"),
            "name": { "full": format!("Test Person {tag}") },
            "emails": { "e1": { "address": format!("person-{tag}@example.org") } },
        }),
    }
    .to_string()
    .into_bytes()
}

#[derive(Default)]
struct Mirror {
    by_id: BTreeMap<String, (Option<String>, Bytes)>,
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
        assert!(
            batch.changes.len() <= limit.max(1) + 1,
            "a page keeps the limit"
        );
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
            assert!(upserted.contains(&obj.item));
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

fn count(changes: &[PimChange]) -> (usize, usize) {
    (
        changes
            .iter()
            .filter(|c| matches!(c, PimChange::Upserted { .. }))
            .count(),
        changes
            .iter()
            .filter(|c| matches!(c, PimChange::Removed { .. }))
            .count(),
    )
}

fn holds_json(held: &[u8], sent: &[u8]) -> bool {
    let held: Value = serde_json::from_slice(held).unwrap();
    let sent: Value = serde_json::from_slice(sent).unwrap();
    sent.as_object()
        .unwrap()
        .iter()
        .all(|(k, v)| held.get(k) == Some(v))
}

/// The [`skein_pim::testing::conformance`] suite for providers whose objects are JSON the server
/// completes with its own properties (an id, the collection map), so a create stores the
/// properties sent rather than the exact bytes. Every other check is the same: paged listings
/// with the exact bytes, exact change reports, resets, versions tied to bytes, conditional
/// writes and idempotent creates.
async fn json_conformance(
    provider: Arc<dyn PimProvider>,
    control: Arc<dyn PimServerControl>,
    collection: &str,
    kind: CollectionKind,
) {
    let name = |n: u32| format!("conformance-{n}");
    let obj = |n: u32| sample(kind, &format!("conformance-{n}"));
    let mut session = provider.connect().await.unwrap();
    let listed = session.collections().await.unwrap();
    let info = listed
        .iter()
        .find(|c| c.id == collection)
        .expect("the collection is listed");
    assert_eq!(info.kind, kind);
    assert!(!info.read_only);
    assert_eq!(listed.iter().filter(|c| c.id == collection).count(), 1);

    for n in 1..=5 {
        control.put(collection, &name(n), &obj(n)).await;
    }
    let mut mirror = Mirror::default();
    let (cursor, _) = drain(&mut session, collection, None, &mut mirror, 2).await;
    assert_eq!(mirror.contents(), control.contents(collection).await);
    for (id, (version, bytes)) in &mirror.by_id {
        let item = ItemRef {
            id: id.clone(),
            uid: None,
        };
        let (now, held) = control.read(collection, &item).await.unwrap();
        assert_eq!(&held, bytes);
        assert_eq!(version, &now, "the version belongs to the bytes");
    }

    let (cursor, changes) = drain(&mut session, collection, Some(cursor), &mut mirror, 2).await;
    assert!(changes.is_empty(), "nothing changed: {changes:?}");

    control
        .put(collection, &name(3), &sample(kind, "conformance-3-changed"))
        .await;
    control.remove(collection, &name(2)).await;
    control.put(collection, &name(6), &obj(6)).await;
    let (cursor, changes) = drain(&mut session, collection, Some(cursor), &mut mirror, 2).await;
    assert_eq!(
        count(&changes),
        (2, 1),
        "exactly three changes: {changes:?}"
    );
    assert_eq!(mirror.contents(), control.contents(collection).await);

    let invalidated = control.invalidate(collection).await;
    let (_, changes) = drain(&mut session, collection, Some(cursor), &mut mirror, 100).await;
    assert!(
        !invalidated || matches!(changes.first(), Some(PimChange::Reset { .. })),
        "an invalid cursor resets: {changes:?}"
    );
    assert_eq!(mirror.contents(), control.contents(collection).await);
    let garbage = Cursor(Bytes::from_static(b"\xff not a cursor"));
    let (_, changes) = drain(
        &mut session,
        collection,
        Some(garbage),
        &mut Mirror::default(),
        100,
    )
    .await;
    assert!(matches!(changes.first(), Some(PimChange::Reset { .. })));

    let missing = ItemRef {
        id: "missing-object".into(),
        uid: None,
    };
    assert!(
        session
            .fetch(collection, std::slice::from_ref(&missing))
            .await
            .unwrap()
            .is_empty()
    );

    let sent = Bytes::from(obj(7));
    let create = PimWrite::Put {
        collection: collection.to_owned(),
        item: None,
        bytes: sent.clone(),
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
    let (version, held) = control.read(collection, &created).await.unwrap();
    assert!(
        holds_json(&held, &sent),
        "a create stores every property sent"
    );
    let current = current.expect("the object is read back");
    assert_eq!(current.item, created);
    assert_eq!(current.bytes, held);
    assert_eq!(current.version, version);
    let again = session.apply(&create).await.unwrap();
    assert!(
        matches!(&again, WriteOutcome::Applied { item: Some(i), .. } if *i == created),
        "repeating a create answers with the same object: {again:?}"
    );
    assert_eq!(control.contents(collection).await.len(), 6);

    let stale = PimWrite::Put {
        collection: collection.to_owned(),
        item: Some(created.clone()),
        bytes: Bytes::from(obj(8)),
        if_version: Some("\"stale-version\"".into()),
        key: "01KCONFORMANCESTALE0000000".into(),
        notify: false,
    };
    assert!(matches!(
        session.apply(&stale).await.unwrap(),
        WriteOutcome::Conflict { current: Some(_) }
    ));
    assert_eq!(control.read(collection, &created).await.unwrap().1, held);

    let updated = Bytes::from(obj(9));
    let update = PimWrite::Put {
        collection: collection.to_owned(),
        item: Some(created.clone()),
        bytes: updated.clone(),
        if_version: version.clone(),
        key: "01KCONFORMANCEUPDATE000000".into(),
        notify: false,
    };
    let WriteOutcome::Applied {
        current: Some(after),
        ..
    } = session.apply(&update).await.unwrap()
    else {
        panic!("the current version is accepted");
    };
    let (now, held) = control.read(collection, &created).await.unwrap();
    assert!(holds_json(&held, &updated));
    assert_eq!(after.bytes, held);
    assert_ne!(now, version, "a write changes the version");

    let stale_delete = PimWrite::Delete {
        collection: collection.to_owned(),
        item: created.clone(),
        if_version: version.clone(),
        notify: false,
    };
    assert!(matches!(
        session.apply(&stale_delete).await.unwrap(),
        WriteOutcome::Conflict { .. }
    ));
    assert!(control.read(collection, &created).await.is_some());
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
    assert!(matches!(
        session.apply(&gone).await.unwrap(),
        WriteOutcome::Applied { .. }
    ));

    for n in [1, 3, 4, 5, 6] {
        control.remove(collection, &name(n)).await;
    }
    session.logout().await.unwrap();
}

async fn suite(fake: &FakeJmap, base: &str) {
    let provider: Arc<dyn PimProvider> = Arc::new(provider(base));
    let control: Arc<dyn PimServerControl> = Arc::new(fake.clone());
    json_conformance(
        provider.clone(),
        control.clone(),
        CAL,
        CollectionKind::Calendar,
    )
    .await;
    json_conformance(provider, control, BOOK, CollectionKind::AddressBook).await;
}

#[tokio::test]
async fn keeps_the_contract_through_the_well_known_address() {
    let fake = FakeJmap::standard();
    let base = serve(fake.clone()).await;
    suite(&fake, &base).await;
    let requests = fake.requests();
    assert!(
        requests
            .iter()
            .filter(|(_, p, _)| p == "/.well-known/jmap")
            .all(|(_, _, signed)| !signed),
        "the well-known lookup goes without credentials"
    );
    assert!(
        requests
            .iter()
            .filter(|(m, _, _)| m == "POST")
            .all(|(_, _, s)| *s)
    );
    assert!(
        requests
            .iter()
            .any(|(m, p, s)| m == "GET" && p == "/jmap/session" && *s)
    );
    let calls = fake.calls();
    assert!(calls.iter().any(|c| c == "CalendarEvent/changes"));
    assert!(calls.iter().any(|c| c == "ContactCard/query"));
}

#[tokio::test]
async fn keeps_the_contract_with_one_object_per_page() {
    let fake = FakeJmap::standard();
    fake.set(|s| s.page = 1);
    let base = serve(fake.clone()).await;
    suite(&fake, &format!("{base}/jmap/session")).await;
}

#[tokio::test]
async fn lists_names_colors_access_and_only_offered_kinds() {
    let fake = FakeJmap::standard();
    let base = serve(fake.clone()).await;
    let mut s = provider(&base).connect().await.unwrap();
    let listed = s.collections().await.unwrap();
    let by_id: BTreeMap<&str, &CollectionInfo> =
        listed.iter().map(|c| (c.id.as_str(), c)).collect();
    assert_eq!(listed.len(), 4);
    assert_eq!(by_id[CAL].name, "Work & Life");
    assert_eq!(by_id[CAL].color.as_deref(), Some("#336699"));
    assert_eq!(by_id[CAL].components, ["VEVENT"]);
    assert!(by_id[SHARED].read_only);
    assert!(!by_id[BOOK].read_only);
    assert_eq!(by_id[OTHER_BOOK].kind, CollectionKind::AddressBook);
    assert!(matches!(
        s.changes("calendar/nope", None, 10).await,
        Err(PimError::NotFound)
    ));
    assert!(matches!(
        s.fetch("addressbook/nope", &[]).await,
        Err(PimError::NotFound)
    ));
    assert!(matches!(
        s.changes("elsewhere", None, 10).await,
        Err(PimError::NotFound)
    ));

    fake.set(|s| {
        s.no_calendars = true;
        s.calls.clear();
    });
    let mut s = provider(&base).connect().await.unwrap();
    let listed = s.collections().await.unwrap();
    assert!(listed.iter().all(|c| c.kind == CollectionKind::AddressBook));
    assert!(matches!(
        s.changes(CAL, None, 10).await,
        Err(PimError::NotFound)
    ));
    assert!(!fake.calls().iter().any(|c| c.starts_with("Calendar")));
}

#[tokio::test]
async fn bytes_are_canonical_whatever_the_key_order() {
    let a: Value = serde_json::from_str(
        r#"{"title":"x","@type":"Event","nested":{"b":1,"a":[{"z":1,"y":2}]}}"#,
    )
    .unwrap();
    let b: Value = serde_json::from_str(
        r#"{"nested":{"a":[{"y":2,"z":1}],"b":1},"@type":"Event","title":"x"}"#,
    )
    .unwrap();
    let a = serde_json::to_vec(&canonical(a)).unwrap();
    let b = serde_json::to_vec(&canonical(b)).unwrap();
    assert_eq!(a, b);
    assert_eq!(
        a,
        br#"{"@type":"Event","nested":{"a":[{"y":2,"z":1}],"b":1},"title":"x"}"#
    );
    assert_eq!(version(&a), version(&b));
    assert_eq!(version(&a).len(), 32);
}

#[tokio::test]
async fn a_card_moved_to_another_book_is_removed_from_the_first() {
    let fake = FakeJmap::standard();
    let base = serve(fake.clone()).await;
    fake.put(BOOK, "c1", &sample(CollectionKind::AddressBook, "1"))
        .await;
    let mut s = provider(&base).connect().await.unwrap();
    let first = s.changes(BOOK, None, 10).await.unwrap();
    assert_eq!(count(&first.changes), (1, 0));
    fake.put(OTHER_BOOK, "c1", &sample(CollectionKind::AddressBook, "1"))
        .await;
    let next = s.changes(BOOK, Some(&first.cursor), 10).await.unwrap();
    assert_eq!(
        next.changes,
        vec![PimChange::Removed {
            item: ItemRef {
                id: "c1".into(),
                uid: None
            }
        }]
    );
    let elsewhere = s.changes(OTHER_BOOK, None, 10).await.unwrap();
    assert_eq!(count(&elsewhere.changes), (1, 0));
    assert_eq!(
        s.fetch(
            BOOK,
            &[ItemRef {
                id: "c1".into(),
                uid: None
            }]
        )
        .await
        .unwrap(),
        vec![]
    );
}

#[tokio::test]
async fn a_state_the_server_does_not_know_resets() {
    let fake = FakeJmap::standard();
    let base = serve(fake.clone()).await;
    fake.put(CAL, "e1", &sample(CollectionKind::Calendar, "1"))
        .await;
    let mut s = provider(&base).connect().await.unwrap();
    let mut stranger = JmapCursor::fresh(CAL);
    stranger.state = "not-a-number".into();
    let changes = s.changes(CAL, Some(&stranger.encode()), 10).await.unwrap();
    assert_eq!(
        changes.changes[0],
        PimChange::Reset {
            reason: "state".into()
        }
    );
    assert_eq!(count(&changes.changes), (1, 0));
    let mut ahead = JmapCursor::fresh(CAL);
    ahead.state = "999".into();
    let changes = s.changes(CAL, Some(&ahead.encode()), 10).await.unwrap();
    assert_eq!(
        changes.changes[0],
        PimChange::Reset {
            reason: "state".into()
        }
    );
}

#[tokio::test]
async fn another_objects_change_is_retried_while_a_changed_object_conflicts() {
    let fake = FakeJmap::standard();
    let base = serve(fake.clone()).await;
    fake.put(CAL, "e1", &sample(CollectionKind::Calendar, "1"))
        .await;
    let mut s = provider(&base).connect().await.unwrap();
    let held = s
        .fetch(
            CAL,
            &[ItemRef {
                id: "e1".into(),
                uid: None,
            }],
        )
        .await
        .unwrap()
        .remove(0);
    let mut edited: Value = serde_json::from_slice(&held.bytes).unwrap();
    edited["title"] = json!("Planning moved");
    let put = PimWrite::Put {
        collection: CAL.into(),
        item: Some(held.item.clone()),
        bytes: Bytes::from(edited.to_string()),
        if_version: held.version.clone(),
        key: "01KEDIT".into(),
        notify: false,
    };
    fake.set(|s| s.interfere = 2);
    let WriteOutcome::Applied {
        current: Some(now), ..
    } = s.apply(&put).await.unwrap()
    else {
        panic!("a state moved by another object is retried");
    };
    let now: Value = serde_json::from_slice(&now.bytes).unwrap();
    assert_eq!(now["title"], "Planning moved");
    assert_eq!(
        fake.calls()
            .iter()
            .filter(|c| *c == "CalendarEvent/set")
            .count(),
        3
    );

    let again = s.apply(&put).await.unwrap();
    assert!(
        matches!(again, WriteOutcome::Conflict { current: Some(_) }),
        "the object itself changed: {again:?}"
    );
    fake.set(|s| s.interfere = 10);
    let fresh = s
        .fetch(CAL, std::slice::from_ref(&held.item))
        .await
        .unwrap()
        .remove(0);
    let delete = PimWrite::Delete {
        collection: CAL.into(),
        item: held.item.clone(),
        if_version: fresh.version,
        notify: false,
    };
    assert!(matches!(
        s.apply(&delete).await,
        Err(PimError::Throttled { .. })
    ));
    fake.set(|s| s.interfere = 0);
    assert!(matches!(
        s.apply(&delete).await.unwrap(),
        WriteOutcome::Applied { .. }
    ));
}

#[tokio::test]
async fn writes_the_server_refuses_fail_with_the_error_type() {
    let fake = FakeJmap::standard();
    let base = serve(fake.clone()).await;
    let mut s = provider(&base).connect().await.unwrap();
    let put = |collection: &str, bytes: Vec<u8>, key: &str| PimWrite::Put {
        collection: collection.into(),
        item: None,
        bytes: Bytes::from(bytes),
        if_version: None,
        key: key.into(),
        notify: false,
    };
    assert_eq!(
        s.apply(&put(SHARED, sample(CollectionKind::Calendar, "r"), "k1"))
            .await
            .unwrap(),
        WriteOutcome::Failed {
            reason: "forbidden".into()
        }
    );
    assert_eq!(
        s.apply(&put(
            CAL,
            br#"{"@type":"Event","refuseMe":true}"#.to_vec(),
            "k2"
        ))
        .await
        .unwrap(),
        WriteOutcome::Failed {
            reason: "invalidProperties".into()
        }
    );
    assert_eq!(
        s.apply(&put(CAL, b"BEGIN:VCALENDAR\r\n".to_vec(), "k3"))
            .await
            .unwrap(),
        WriteOutcome::Failed {
            reason: "not_json".into()
        }
    );
    let created = s
        .apply(&put(
            CAL,
            br#"{"@type":"Event","title":"No uid"}"#.to_vec(),
            "01KNOUID",
        ))
        .await
        .unwrap();
    let WriteOutcome::Applied {
        current: Some(current),
        ..
    } = created
    else {
        panic!("a create without a uid is applied");
    };
    let current: Value = serde_json::from_slice(&current.bytes).unwrap();
    assert_eq!(current["uid"], "01KNOUID", "the command id becomes the uid");
    let clash = s
        .apply(&put(
            CAL,
            br#"{"@type":"Event","title":"Other","uid":"01KNOUID"}"#.to_vec(),
            "k4",
        ))
        .await
        .unwrap();
    assert!(
        matches!(clash, WriteOutcome::Conflict { current: Some(_) }),
        "another object with the uid: {clash:?}"
    );
}

#[tokio::test]
async fn busy_servers_are_waited_out_then_throttled() {
    let fake = FakeJmap::standard();
    let base = serve(fake.clone()).await;
    let mut s = provider(&base).connect().await.unwrap();
    fake.set(|s| s.busy = 2);
    assert_eq!(s.collections().await.unwrap().len(), 4);
    fake.set(|s| s.busy = 10);
    assert!(matches!(
        s.collections().await,
        Err(PimError::Throttled {
            retry_after: Some(_)
        })
    ));
    fake.set(|s| s.busy = 1);
    let create = PimWrite::Put {
        collection: CAL.into(),
        item: None,
        bytes: Bytes::from(sample(CollectionKind::Calendar, "busy")),
        if_version: None,
        key: "01KBUSY".into(),
        notify: false,
    };
    let calls_before = fake.calls().len();
    let first = s.apply(&create).await;
    assert!(first.is_ok(), "the query is a read and waits: {first:?}");
    assert!(fake.calls().len() > calls_before);
}

#[tokio::test]
async fn an_api_address_on_another_origin_is_refused_with_nothing_sent_there() {
    let elsewhere = FakeJmap::standard();
    let other = serve(elsewhere.clone()).await;
    let fake = FakeJmap::standard();
    let base = serve(fake.clone()).await;
    fake.set(|s| s.api_url = Some(format!("{other}/jmap/api")));
    assert!(matches!(
        provider(&base).connect().await,
        Err(PimError::Protocol(_))
    ));
    assert!(elsewhere.requests().is_empty());
    fake.set(|s| {
        s.api_url = None;
        s.huge_session = true;
    });
    assert!(matches!(
        provider(&base).connect().await,
        Err(PimError::Protocol(_))
    ));
}

#[tokio::test]
async fn refused_credentials_and_bad_settings() {
    let fake = FakeJmap::standard();
    let base = serve(fake.clone()).await;
    let wrong = JmapPimProvider::new(
        JmapPimSettings::new(&base, USER),
        Credentials::Password {
            secret: "wrong".into(),
        },
    )
    .unwrap();
    assert!(matches!(wrong.connect().await, Err(PimError::Auth)));
    assert!(matches!(
        JmapPimProvider::new(
            JmapPimSettings::new("http://jmap.example.com", USER),
            password()
        ),
        Err(PimError::Config(_))
    ));
    assert!(matches!(
        JmapPimProvider::new(JmapPimSettings::new("jmap.example.com", ""), password()),
        Err(PimError::Config(_))
    ));
    assert_eq!(
        session_url("jmap.example.com").unwrap(),
        "https://jmap.example.com/.well-known/jmap"
    );
    let p = provider(&base);
    assert!(!format!("{p:?}").contains(PASSWORD));
    assert!(!format!("{:?}", JmapPimSettings::new(&base, USER)).contains(USER));
}

fn invitation() -> Vec<u8> {
    json!({
        "@type": "Event",
        "uid": "invite@example.com",
        "title": "Planning review",
        "start": "2026-12-03T15:00:00",
        "timeZone": "Etc/UTC",
        "duration": "PT30M",
        "participants": {
            "p0": {
                "@type": "Participant",
                "roles": { "owner": true, "attendee": true },
                "sendTo": { "imip": "mailto:organizer@example.org" },
                "participationStatus": "accepted",
            },
            "p1": {
                "@type": "Participant",
                "roles": { "attendee": true },
                "sendTo": { "imip": "mailto:Ada@Example.com" },
                "participationStatus": "needs-action",
            },
            "p2": {
                "@type": "Participant",
                "roles": { "attendee": true },
                "email": "grace@example.net",
                "participationStatus": "needs-action",
            },
        },
    })
    .to_string()
    .into_bytes()
}

fn event_ref(id: &str) -> ItemRef {
    ItemRef {
        id: id.into(),
        uid: None,
    }
}

fn respond(attendee: Option<&str>, answer: PartStat, if_version: Option<String>) -> PimWrite {
    PimWrite::Respond {
        collection: CAL.into(),
        item: event_ref("inv"),
        answer,
        attendee: attendee.map(str::to_owned),
        comment: None,
        if_version,
        notify: true,
    }
}

#[tokio::test]
async fn writes_pass_notify_to_calendars_only() {
    let fake = FakeJmap::standard();
    let base = serve(fake.clone()).await;
    let mut s = provider(&base).connect().await.unwrap();
    let create = |collection: &str, kind, key: &str, notify| PimWrite::Put {
        collection: collection.into(),
        item: None,
        bytes: Bytes::from(sample(kind, key)),
        if_version: None,
        key: key.into(),
        notify,
    };
    let WriteOutcome::Applied {
        item: Some(created),
        current: Some(held),
    } = s
        .apply(&create(CAL, CollectionKind::Calendar, "n1", true))
        .await
        .unwrap()
    else {
        panic!("the create is applied");
    };
    let mut edited: Value = serde_json::from_slice(&held.bytes).unwrap();
    edited["title"] = json!("Planning moved");
    let replace = PimWrite::Put {
        collection: CAL.into(),
        item: Some(created.clone()),
        bytes: Bytes::from(edited.to_string()),
        if_version: held.version.clone(),
        key: "n2".into(),
        notify: false,
    };
    assert!(matches!(
        s.apply(&replace).await.unwrap(),
        WriteOutcome::Applied { .. }
    ));
    let delete = PimWrite::Delete {
        collection: CAL.into(),
        item: created,
        if_version: None,
        notify: true,
    };
    assert!(matches!(
        s.apply(&delete).await.unwrap(),
        WriteOutcome::Applied { .. }
    ));
    assert!(matches!(
        s.apply(&create(BOOK, CollectionKind::AddressBook, "n3", true))
            .await
            .unwrap(),
        WriteOutcome::Applied { .. }
    ));
    assert_eq!(
        fake.scheduling(),
        [Some(true), Some(false), Some(true), None]
    );
    assert_eq!(s.scheduling(CAL).await.unwrap(), Scheduling::Server);
    assert_eq!(s.scheduling(BOOK).await.unwrap(), Scheduling::Client);
    assert!(matches!(
        s.scheduling("calendar/nope").await,
        Err(PimError::NotFound)
    ));
}

#[tokio::test]
async fn respond_sets_the_named_attendees_status() {
    let fake = FakeJmap::standard();
    let base = serve(fake.clone()).await;
    fake.put(CAL, "inv", &invitation()).await;
    let mut s = provider(&base).connect().await.unwrap();
    let mut write = respond(Some("mailto:ADA@example.com"), PartStat::Tentative, None);
    if let PimWrite::Respond { comment, .. } = &mut write {
        *comment = Some("Running late".into());
    }
    let WriteOutcome::Applied {
        item: Some(item),
        current: Some(current),
    } = s.apply(&write).await.unwrap()
    else {
        panic!("the answer is applied");
    };
    assert_eq!(item, event_ref("inv"));
    let after: Value = serde_json::from_slice(&current.bytes).unwrap();
    assert_eq!(
        after.pointer("/participants/p1/participationStatus"),
        Some(&json!("tentative"))
    );
    assert_eq!(
        after.pointer("/participants/p1/participationComment"),
        Some(&json!("Running late"))
    );
    assert_eq!(
        after.pointer("/participants/p2/participationStatus"),
        Some(&json!("needs-action"))
    );
    assert_eq!(after["title"], "Planning review");
    assert_eq!(fake.scheduling(), [Some(true)]);

    let by_email = respond(
        Some("Grace@example.net"),
        PartStat::Declined,
        current.version,
    );
    assert!(matches!(
        s.apply(&by_email).await.unwrap(),
        WriteOutcome::Applied { .. }
    ));
    assert_eq!(
        fake.event("inv")
            .pointer("/participants/p2/participationStatus"),
        Some(&json!("declined"))
    );
}

#[tokio::test]
async fn respond_finds_the_accounts_own_participant() {
    let fake = FakeJmap::standard();
    let base = serve(fake.clone()).await;
    fake.put(CAL, "inv", &invitation()).await;
    fake.set(|s| {
        s.identities = Some(vec![json!({
            "id": "i1",
            "name": "Ada",
            "sendTo": { "imip": "mailto:ada@example.com", "web": "https://example.com/ada" },
        })])
    });
    let mut s = provider(&base).connect().await.unwrap();
    assert_eq!(s.addresses().await.unwrap(), ["ada@example.com"]);
    assert!(matches!(
        s.apply(&respond(None, PartStat::Accepted, None))
            .await
            .unwrap(),
        WriteOutcome::Applied {
            current: Some(_),
            ..
        }
    ));
    assert_eq!(
        fake.event("inv")
            .pointer("/participants/p1/participationStatus"),
        Some(&json!("accepted"))
    );
}

#[tokio::test]
async fn respond_refuses_strangers_stale_versions_and_address_books() {
    let fake = FakeJmap::standard();
    let base = serve(fake.clone()).await;
    fake.put(CAL, "inv", &invitation()).await;
    let mut s = provider(&base).connect().await.unwrap();
    let before = fake.event("inv");
    assert_eq!(
        s.apply(&respond(
            Some("nobody@example.org"),
            PartStat::Accepted,
            None
        ))
        .await
        .unwrap(),
        WriteOutcome::Failed {
            reason: "attendee_not_found".into()
        }
    );
    assert!(matches!(
        s.apply(&respond(
            Some("ada@example.com"),
            PartStat::Accepted,
            Some("\"stale-version\"".into())
        ))
        .await
        .unwrap(),
        WriteOutcome::Conflict { current: Some(_) }
    ));
    let mut gone = respond(Some("ada@example.com"), PartStat::Accepted, None);
    if let PimWrite::Respond { item, .. } = &mut gone {
        *item = event_ref("missing");
    }
    assert_eq!(
        s.apply(&gone).await.unwrap(),
        WriteOutcome::Conflict { current: None }
    );
    let book = PimWrite::Respond {
        collection: BOOK.into(),
        item: event_ref("inv"),
        answer: PartStat::Declined,
        attendee: None,
        comment: None,
        if_version: None,
        notify: false,
    };
    assert_eq!(
        s.apply(&book).await.unwrap(),
        WriteOutcome::Failed {
            reason: "not_a_calendar".into()
        }
    );
    assert_eq!(fake.event("inv"), before);
    assert!(fake.scheduling().is_empty(), "nothing was written");
}

#[tokio::test]
async fn addresses_come_from_identities_and_the_session() {
    let fake = FakeJmap::standard();
    let base = serve(fake.clone()).await;
    fake.set(|s| {
        s.identities = Some(vec![
            json!({ "id": "i1", "sendTo": { "imip": "MAILTO:Ada.Work@Example.org" } }),
            json!({ "id": "i2", "sendTo": { "imip": "mailto:ada@example.com" } }),
            json!({ "id": "i3", "name": "No address" }),
            json!({ "id": "i4", "calendarAddress": "mailto:ada.bis@example.net" }),
        ])
    });
    let mut s = provider(&base).connect().await.unwrap();
    assert_eq!(
        s.addresses().await.unwrap(),
        [
            "ada.work@example.org",
            "ada@example.com",
            "ada.bis@example.net"
        ]
    );

    fake.set(|s| s.identities = None);
    assert_eq!(s.addresses().await.unwrap(), [USER]);

    fake.set(|s| s.no_calendars = true);
    let mut s = provider(&base).connect().await.unwrap();
    assert_eq!(s.addresses().await.unwrap(), [USER]);
}
