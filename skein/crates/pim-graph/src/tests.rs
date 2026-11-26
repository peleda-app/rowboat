use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::Router;
use axum::body::Bytes as Body;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, json};
use skein_core::PartStat;
use skein_pim::testing::PimServerControl;

use super::*;
use crate::write::CREATE_KEY_PROPERTY;

const TOKEN: &str = "graph-token-0451";
const CAL: &str = "calendars/cal-work";
const SHARED: &str = "calendars/cal-holidays";
const FOLDER: &str = "contacts/fld-work";
const CHILD: &str = "contacts/fld-clients";

#[derive(Clone)]
struct Obj {
    fields: Map<String, Value>,
    seq: u64,
    key: Option<String>,
}

struct Coll {
    kind: CollectionKind,
    name: String,
    color: Option<String>,
    can_edit: bool,
    parent: Option<String>,
    items: BTreeMap<String, Obj>,
    log: Vec<(u64, String)>,
    generation: u64,
}

#[derive(Default)]
struct GraphState {
    colls: BTreeMap<String, Coll>,
    seq: u64,
    created: u64,
    page: usize,
    busy: u32,
    busy_writes: bool,
    busy_after: Option<&'static str>,
    next_host: Option<String>,
    repeat_next: bool,
    huge: bool,
    user: Option<Value>,
    answers: Vec<(String, String, Value)>,
    requests: Vec<(String, String, bool)>,
}

#[derive(Clone)]
struct FakeGraph(Arc<Mutex<GraphState>>);

fn coll(kind: CollectionKind, name: &str) -> Coll {
    Coll {
        kind,
        name: name.into(),
        color: None,
        can_edit: true,
        parent: None,
        items: BTreeMap::new(),
        log: Vec::new(),
        generation: 1,
    }
}

impl FakeGraph {
    fn standard() -> Self {
        let mut s = GraphState {
            page: 2,
            user: Some(
                json!({ "mail": "ada@example.com", "userPrincipalName": "ada@example.com" }),
            ),
            ..GraphState::default()
        };
        s.colls.insert(
            DEFAULT_CONTACTS.into(),
            coll(CollectionKind::AddressBook, "Contacts"),
        );
        s.colls
            .insert(FOLDER.into(), coll(CollectionKind::AddressBook, "Work"));
        let mut child = coll(CollectionKind::AddressBook, "Clients");
        child.parent = Some("fld-work".into());
        s.colls.insert(CHILD.into(), child);
        let mut work = coll(CollectionKind::Calendar, "Work & Life");
        work.color = Some("#336699".into());
        s.colls.insert(CAL.into(), work);
        let mut shared = coll(CollectionKind::Calendar, "Holidays");
        shared.can_edit = false;
        s.colls.insert(SHARED.into(), shared);
        Self(Arc::new(Mutex::new(s)))
    }

    fn set(&self, f: impl FnOnce(&mut GraphState)) {
        f(&mut self.0.lock().unwrap());
    }

    fn requests(&self) -> Vec<(String, String, bool)> {
        self.0.lock().unwrap().requests.clone()
    }
}

fn change_key(seq: u64) -> String {
    format!("ck{seq}")
}

fn render(id: &str, obj: &Obj) -> Value {
    let mut map = obj.fields.clone();
    map.insert(
        "@odata.etag".into(),
        json!(format!("W/\"{}\"", change_key(obj.seq))),
    );
    map.insert("id".into(), json!(id));
    map.insert("changeKey".into(), json!(change_key(obj.seq)));
    Value::Object(map)
}

fn rendered(id: &str, obj: &Obj) -> Bytes {
    Bytes::from(serde_json::to_vec(&render(id, obj)).unwrap())
}

fn write_obj(s: &mut GraphState, collection: &str, id: &str, fields: Option<Obj>) -> u64 {
    s.seq += 1;
    let seq = s.seq;
    let c = s.colls.get_mut(collection).unwrap();
    match fields {
        Some(mut obj) => {
            obj.seq = seq;
            c.items.insert(id.into(), obj);
        }
        None => {
            c.items.remove(id);
        }
    }
    c.log.push((seq, id.into()));
    seq
}

#[async_trait]
impl PimServerControl for FakeGraph {
    async fn put(&self, collection: &str, name: &str, bytes: &[u8]) {
        let Ok(Value::Object(fields)) = serde_json::from_slice(bytes) else {
            panic!("the fake holds JSON objects");
        };
        let mut s = self.0.lock().unwrap();
        let key = s.colls[collection]
            .items
            .get(name)
            .and_then(|o| o.key.clone());
        write_obj(
            &mut s,
            collection,
            name,
            Some(Obj {
                fields,
                seq: 0,
                key,
            }),
        );
    }

    async fn remove(&self, collection: &str, name: &str) {
        let mut s = self.0.lock().unwrap();
        if s.colls[collection].items.contains_key(name) {
            write_obj(&mut s, collection, name, None);
        }
    }

    async fn invalidate(&self, collection: &str) -> bool {
        let mut s = self.0.lock().unwrap();
        let c = s.colls.get_mut(collection).unwrap();
        c.generation += 1;
        c.kind == CollectionKind::AddressBook
    }

    async fn read(&self, collection: &str, item: &ItemRef) -> Option<(Option<String>, Bytes)> {
        let s = self.0.lock().unwrap();
        let obj = s.colls.get(collection)?.items.get(&item.id)?;
        Some((Some(change_key(obj.seq)), rendered(&item.id, obj)))
    }

    async fn contents(&self, collection: &str) -> Vec<Bytes> {
        let s = self.0.lock().unwrap();
        let mut v: Vec<Bytes> = s.colls[collection]
            .items
            .iter()
            .map(|(id, o)| rendered(id, o))
            .collect();
        v.sort();
        v
    }
}

fn graph_json(status: StatusCode, value: Value) -> Response {
    (
        status,
        [("content-type", "application/json")],
        value.to_string(),
    )
        .into_response()
}

fn graph_error(status: StatusCode, code: &str) -> Response {
    graph_json(
        status,
        json!({ "error": { "code": code, "message": "Mentions ada@example.com" } }),
    )
}

fn query(uri: &Uri) -> BTreeMap<String, String> {
    url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes())
        .into_owned()
        .collect()
}

/// The collection id and the rest of the path below it.
fn locate(rest: &[&str]) -> Option<(String, Vec<String>)> {
    let tail = |n: usize| rest[n..].iter().map(|s| (*s).to_owned()).collect();
    match rest {
        ["contacts", ..] => Some((DEFAULT_CONTACTS.into(), tail(1))),
        ["contactFolders", f, "contacts", ..] => Some((format!("contacts/{f}"), tail(3))),
        ["calendars", c, "events", ..] => Some((format!("calendars/{c}"), tail(3))),
        _ => None,
    }
}

fn if_match_holds(headers: &HeaderMap, obj: Option<&Obj>) -> bool {
    match headers.get("if-match").and_then(|v| v.to_str().ok()) {
        None => true,
        Some(tag) => obj.is_some_and(|o| tag == format!("W/\"{}\"", change_key(o.seq))),
    }
}

fn delta(
    s: &GraphState,
    base: &str,
    prefix: &str,
    collection: &str,
    q: &BTreeMap<String, String>,
) -> Response {
    let c = &s.colls[collection];
    let link = format!("{base}{prefix}/delta");
    let (since, upto, offset) = if let Some(token) = q.get("$deltatoken") {
        let Some((g, since)) = token.split_once('.') else {
            return graph_error(StatusCode::GONE, "syncStateNotFound");
        };
        if g.parse::<u64>().ok() != Some(c.generation) {
            return graph_error(StatusCode::GONE, "syncStateNotFound");
        }
        (since.parse::<u64>().unwrap(), s.seq, 0)
    } else if let Some(token) = q.get("$skiptoken") {
        let parts: Vec<u64> = token.split('.').map(|p| p.parse().unwrap()).collect();
        if parts[0] != c.generation {
            return graph_error(StatusCode::GONE, "syncStateNotFound");
        }
        (parts[1], parts[2], parts[3] as usize)
    } else {
        (0, s.seq, 0)
    };
    let mut touched: BTreeMap<&str, u64> = BTreeMap::new();
    for (seq, id) in &c.log {
        if *seq > since && *seq <= upto {
            touched.insert(id, *seq);
        }
    }
    let entries: Vec<Value> = touched
        .keys()
        .filter_map(|id| match c.items.get(*id) {
            Some(obj) => Some(json!({
                "@odata.etag": format!("W/\"{}\"", change_key(obj.seq)),
                "id": id,
                "changeKey": change_key(obj.seq),
            })),
            None if since > 0 => Some(json!({ "id": id, "@removed": { "reason": "deleted" } })),
            None => None,
        })
        .collect();
    let page: Vec<Value> = entries.iter().skip(offset).take(s.page).cloned().collect();
    let mut answer = json!({ "value": page });
    if offset + s.page < entries.len() {
        let next_offset = if s.repeat_next {
            offset
        } else {
            offset + s.page
        };
        let host = s.next_host.clone().unwrap_or_else(|| base.to_owned());
        answer["@odata.nextLink"] = json!(format!(
            "{host}{prefix}/delta?$skiptoken={}.{since}.{upto}.{next_offset}",
            c.generation
        ));
    } else {
        answer["@odata.deltaLink"] = json!(format!("{link}?$deltatoken={}.{upto}", c.generation));
    }
    graph_json(StatusCode::OK, answer)
}

async fn handle(
    State(fake): State<FakeGraph>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let mut s = fake.0.lock().unwrap();
    let authorized = headers.get("authorization").and_then(|v| v.to_str().ok())
        == Some(&format!("Bearer {TOKEN}"));
    let path_query = uri
        .path_and_query()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_default();
    s.requests
        .push((method.to_string(), path_query, authorized));
    if !authorized {
        return graph_error(StatusCode::UNAUTHORIZED, "InvalidAuthenticationToken");
    }
    if s.busy > 0 && (method == Method::GET || s.busy_writes) {
        s.busy -= 1;
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", s.busy_after.unwrap_or("0"))],
            "slow down",
        )
            .into_response();
    }
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1")
        .to_owned();
    let base = format!("http://{host}");
    let path = uri.path().to_owned();
    let Some(after) = path.strip_prefix("/v1.0/") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let segments: Vec<&str> = after.split('/').collect();
    let (owner, rest): (String, &[&str]) = match segments.as_slice() {
        ["me", rest @ ..] => ("/v1.0/me".into(), rest),
        ["users", user, rest @ ..] => (format!("/v1.0/users/{user}"), rest),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let q = query(&uri);
    let top_folders = |s: &GraphState, parent: Option<&str>| -> Vec<Value> {
        s.colls
            .iter()
            .filter(|(id, c)| id.starts_with("contacts/") && c.parent.as_deref() == parent)
            .map(|(id, c)| {
                json!({
                    "id": id.trim_start_matches("contacts/"),
                    "displayName": c.name,
                    "parentFolderId": c.parent,
                })
            })
            .collect()
    };
    match (method.as_str(), rest) {
        ("GET", []) => {
            return match &s.user {
                Some(user) => graph_json(StatusCode::OK, user.clone()),
                None => graph_error(StatusCode::NOT_FOUND, "Request_ResourceNotFound"),
            };
        }
        ("GET", ["contactFolders"]) => {
            return graph_json(StatusCode::OK, json!({ "value": top_folders(&s, None) }));
        }
        ("GET", ["contactFolders", f, "childFolders"]) => {
            return graph_json(StatusCode::OK, json!({ "value": top_folders(&s, Some(f)) }));
        }
        ("GET", ["calendars"]) => {
            let value: Vec<Value> = s
                .colls
                .iter()
                .filter(|(id, _)| id.starts_with("calendars/"))
                .map(|(id, c)| {
                    json!({
                        "id": id.trim_start_matches("calendars/"),
                        "name": c.name,
                        "hexColor": c.color.clone().unwrap_or_default(),
                        "canEdit": c.can_edit,
                    })
                })
                .collect();
            return graph_json(StatusCode::OK, json!({ "value": value }));
        }
        _ => {}
    }
    let Some((collection, tail)) = locate(rest) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !s.colls.contains_key(&collection) {
        return graph_error(StatusCode::NOT_FOUND, "ErrorItemNotFound");
    }
    let prefix = format!("{owner}/{}", rest[..rest.len() - tail.len()].join("/"));
    let tail: Vec<&str> = tail.iter().map(String::as_str).collect();
    let kind = s.colls[&collection].kind;
    match (method.as_str(), tail.as_slice()) {
        ("GET", ["delta"]) if kind == CollectionKind::AddressBook => {
            delta(&s, &base, &prefix, &collection, &q)
        }
        ("GET", []) => {
            let c = &s.colls[&collection];
            if let Some(filter) = q.get("$filter") {
                assert!(filter.contains(CREATE_KEY_PROPERTY));
                let wanted = filter
                    .split("ep/value eq '")
                    .nth(1)
                    .and_then(|v| v.strip_suffix("')"))
                    .unwrap_or("")
                    .replace("''", "'");
                let value: Vec<Value> = c
                    .items
                    .iter()
                    .filter(|(_, o)| o.key.as_deref() == Some(wanted.as_str()))
                    .map(|(id, _)| json!({ "id": id }))
                    .collect();
                return graph_json(StatusCode::OK, json!({ "value": value }));
            }
            let skip: usize = q.get("$skip").and_then(|v| v.parse().ok()).unwrap_or(0);
            let all: Vec<Value> = c
                .items
                .iter()
                .map(|(id, o)| {
                    let mut v = json!({
                        "@odata.etag": format!("W/\"{}\"", change_key(o.seq)),
                        "id": id,
                        "changeKey": change_key(o.seq),
                    });
                    if let Some(t) = o.fields.get("type") {
                        v["type"] = t.clone();
                    }
                    v
                })
                .collect();
            let page: Vec<Value> = all.iter().skip(skip).take(s.page).cloned().collect();
            let mut answer = json!({ "value": page });
            if skip + s.page < all.len() {
                let host = s.next_host.clone().unwrap_or_else(|| base.clone());
                let next = if s.repeat_next { skip } else { skip + s.page };
                answer["@odata.nextLink"] = json!(format!("{host}{prefix}?$skip={next}"));
            }
            graph_json(StatusCode::OK, answer)
        }
        ("GET", [id]) => {
            if s.huge {
                return (StatusCode::OK, vec![b' '; MAX_ITEM + 1]).into_response();
            }
            match s.colls[&collection].items.get(*id) {
                Some(obj) => graph_json(StatusCode::OK, render(id, obj)),
                None => graph_error(StatusCode::NOT_FOUND, "ErrorItemNotFound"),
            }
        }
        ("POST", []) => {
            if !s.colls[&collection].can_edit {
                return graph_error(StatusCode::FORBIDDEN, "ErrorAccessDenied");
            }
            let Ok(Value::Object(mut fields)) = serde_json::from_slice::<Value>(&body) else {
                return graph_error(StatusCode::BAD_REQUEST, "BadRequest");
            };
            if fields.contains_key("refuseMe") {
                return graph_error(StatusCode::BAD_REQUEST, "ErrorInvalidProperty");
            }
            if let Some(tx) = fields.get("transactionId").and_then(Value::as_str)
                && let Some((id, obj)) = s.colls[&collection].items.iter().find(|(_, o)| {
                    o.fields.get("transactionId").and_then(Value::as_str) == Some(tx)
                })
            {
                return graph_json(StatusCode::CREATED, render(id, obj));
            }
            let key = fields
                .remove("singleValueExtendedProperties")
                .and_then(|p| {
                    p.as_array()?.iter().find_map(|e| {
                        (e.get("id")?.as_str()? == CREATE_KEY_PROPERTY)
                            .then(|| e.get("value")?.as_str().map(str::to_owned))?
                    })
                });
            s.created += 1;
            let id = format!("AAMk-{}", s.created);
            write_obj(
                &mut s,
                &collection,
                &id,
                Some(Obj {
                    fields,
                    seq: 0,
                    key,
                }),
            );
            let obj = s.colls[&collection].items[&id].clone();
            graph_json(StatusCode::CREATED, render(&id, &obj))
        }
        ("PATCH", [id]) => {
            if !s.colls[&collection].can_edit {
                return graph_error(StatusCode::FORBIDDEN, "ErrorAccessDenied");
            }
            let current = s.colls[&collection].items.get(*id).cloned();
            let Some(mut obj) = current else {
                return graph_error(StatusCode::NOT_FOUND, "ErrorItemNotFound");
            };
            if !if_match_holds(&headers, Some(&obj)) {
                return graph_error(StatusCode::PRECONDITION_FAILED, "ErrorIrresolvableConflict");
            }
            let Ok(Value::Object(fields)) = serde_json::from_slice::<Value>(&body) else {
                return graph_error(StatusCode::BAD_REQUEST, "BadRequest");
            };
            for (k, v) in fields {
                if v.is_null() {
                    obj.fields.remove(&k);
                } else {
                    obj.fields.insert(k, v);
                }
            }
            write_obj(&mut s, &collection, id, Some(obj));
            let obj = s.colls[&collection].items[*id].clone();
            graph_json(StatusCode::OK, render(id, &obj))
        }
        ("POST", [id, verb @ ("accept" | "decline" | "tentativelyAccept")]) => {
            let Some(mut obj) = s.colls[&collection].items.get(*id).cloned() else {
                return graph_error(StatusCode::NOT_FOUND, "ErrorItemNotFound");
            };
            let Ok(answer) = serde_json::from_slice::<Value>(&body) else {
                return graph_error(StatusCode::BAD_REQUEST, "BadRequest");
            };
            s.answers
                .push(((*id).to_owned(), (*verb).to_owned(), answer));
            if obj.fields.get("isOrganizer").and_then(Value::as_bool) == Some(true) {
                return graph_error(StatusCode::BAD_REQUEST, "ErrorInvalidRequest");
            }
            let response = match *verb {
                "accept" => "accepted",
                "decline" => "declined",
                _ => "tentativelyAccepted",
            };
            obj.fields.insert(
                "responseStatus".into(),
                json!({ "response": response, "time": "2026-11-21T10:00:00Z" }),
            );
            write_obj(&mut s, &collection, id, Some(obj));
            StatusCode::ACCEPTED.into_response()
        }
        ("DELETE", [id]) => {
            let current = s.colls[&collection].items.get(*id).cloned();
            if current.is_none() {
                return graph_error(StatusCode::NOT_FOUND, "ErrorItemNotFound");
            }
            if !if_match_holds(&headers, current.as_ref()) {
                return graph_error(StatusCode::PRECONDITION_FAILED, "ErrorIrresolvableConflict");
            }
            write_obj(&mut s, &collection, id, None);
            StatusCode::NO_CONTENT.into_response()
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

async fn serve(fake: FakeGraph) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new().fallback(handle).with_state(fake);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{address}")
}

fn token() -> Credentials {
    Credentials::AccessToken {
        token: TOKEN.into(),
    }
}

fn provider(base: &str) -> GraphPimProvider {
    GraphPimProvider::new(
        GraphPimSettings {
            api_url: Some(format!("{base}/v1.0")),
            ..GraphPimSettings::default()
        },
        token(),
    )
    .unwrap()
}

/// An invented Graph event or contact whose names are built from `tag`.
fn sample(kind: CollectionKind, tag: &str) -> Vec<u8> {
    match kind {
        CollectionKind::Calendar => json!({
            "subject": format!("Planning {tag}"),
            "body": { "contentType": "text", "content": "" },
            "start": { "dateTime": "2026-12-01T10:00:00.0000000", "timeZone": "UTC" },
            "end": { "dateTime": "2026-12-01T11:00:00.0000000", "timeZone": "UTC" },
        }),
        CollectionKind::AddressBook => json!({
            "displayName": format!("Test Person {tag}"),
            "givenName": "Test",
            "surname": "Person",
            "emailAddresses": [{ "address": format!("person-{tag}@example.org"), "name": "Test Person" }],
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

/// Whether `held` keeps every property of `sent` with the same value.
fn holds(held: &[u8], sent: &[u8]) -> bool {
    let held: Value = serde_json::from_slice(held).unwrap();
    let sent: Value = serde_json::from_slice(sent).unwrap();
    sent.as_object()
        .unwrap()
        .iter()
        .all(|(k, v)| held.get(k) == Some(v))
}

/// The [`skein_pim::testing::conformance`] suite for providers whose objects are JSON resources
/// the server completes with its own properties (an id, a version), so a create stores the
/// properties sent rather than the exact bytes. Every other check is the same: paged listings
/// with the exact bytes Graph serves, exact change reports, resets, versions tied to bytes,
/// conditional writes and idempotent creates.
pub(crate) async fn json_conformance(
    provider: Arc<dyn PimProvider>,
    control: Arc<dyn PimServerControl>,
    collection: &str,
    kind: CollectionKind,
    sample: fn(CollectionKind, &str) -> Vec<u8>,
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
    assert!(holds(&held, &sent), "a create stores every property sent");
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
    assert!(holds(&held, &updated));
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

async fn suite(
    fake: &FakeGraph,
    provider: GraphPimProvider,
    collections: &[(&str, CollectionKind)],
) {
    let provider: Arc<dyn PimProvider> = Arc::new(provider);
    let control: Arc<dyn PimServerControl> = Arc::new(fake.clone());
    for (collection, kind) in collections {
        json_conformance(provider.clone(), control.clone(), collection, *kind, sample).await;
    }
}

#[tokio::test]
async fn keeps_the_contract_for_calendars_folders_and_default_contacts() {
    let fake = FakeGraph::standard();
    let base = serve(fake.clone()).await;
    suite(
        &fake,
        provider(&base),
        &[
            (CAL, CollectionKind::Calendar),
            (FOLDER, CollectionKind::AddressBook),
            (DEFAULT_CONTACTS, CollectionKind::AddressBook),
        ],
    )
    .await;
    let requests = fake.requests();
    assert!(requests.iter().all(|(_, _, auth)| *auth));
    assert!(
        requests
            .iter()
            .any(|(_, p, _)| p.contains("/contacts/delta"))
    );
    assert!(
        requests
            .iter()
            .any(|(m, p, _)| m == "GET" && p.contains("singleValueExtendedProperties")),
        "a contact create looks for an earlier one first"
    );
    assert!(
        !requests.iter().any(|(_, p, _)| p.contains("calendarView")),
        "calendars are listed, never expanded"
    );
}

#[tokio::test]
async fn app_only_tokens_read_the_configured_user() {
    let fake = FakeGraph::standard();
    let base = serve(fake.clone()).await;
    let provider = GraphPimProvider::new(
        GraphPimSettings {
            api_url: Some(format!("{base}/v1.0")),
            user: Some("shared@example.com".into()),
            ..GraphPimSettings::default()
        },
        token(),
    )
    .unwrap();
    suite(&fake, provider, &[(CHILD, CollectionKind::AddressBook)]).await;
    let requests = fake.requests();
    assert!(
        requests
            .iter()
            .all(|(_, p, _)| p.starts_with("/v1.0/users/shared@example.com/"))
    );
    assert!(
        GraphPimProvider::new(
            GraphPimSettings {
                user: Some("two words".into()),
                ..GraphPimSettings::default()
            },
            token(),
        )
        .is_err()
    );
}

#[tokio::test]
async fn lists_folder_paths_colors_and_access() {
    let fake = FakeGraph::standard();
    let base = serve(fake.clone()).await;
    let mut s = provider(&base).connect().await.unwrap();
    let listed = s.collections().await.unwrap();
    let by_id: BTreeMap<&str, &CollectionInfo> =
        listed.iter().map(|c| (c.id.as_str(), c)).collect();
    assert_eq!(by_id[DEFAULT_CONTACTS].name, "Contacts");
    assert_eq!(by_id[FOLDER].name, "Work");
    assert_eq!(by_id[CHILD].name, "Work/Clients");
    assert_eq!(by_id[CAL].name, "Work & Life");
    assert_eq!(by_id[CAL].color.as_deref(), Some("#336699"));
    assert_eq!(by_id[CAL].components, ["VEVENT"]);
    assert!(!by_id[CAL].read_only);
    assert!(by_id[SHARED].read_only);
    assert_eq!(by_id[SHARED].color, None, "an empty hexColor is no color");
    assert_eq!(listed.len(), 5);
    assert!(matches!(
        s.changes("calendars/nope", None, 10).await,
        Err(PimError::NotFound)
    ));
    assert!(matches!(
        s.changes("contacts/nope", None, 10).await,
        Err(PimError::NotFound)
    ));
    assert!(matches!(
        s.changes("elsewhere", None, 10).await,
        Err(PimError::NotFound)
    ));
}

#[tokio::test]
async fn series_masters_are_fetched_with_their_exceptions() {
    let fake = FakeGraph::standard();
    let base = serve(fake.clone()).await;
    let mut master: Value =
        serde_json::from_slice(&sample(CollectionKind::Calendar, "series")).unwrap();
    master["type"] = json!("seriesMaster");
    fake.put(CAL, "series-1", master.to_string().as_bytes())
        .await;
    fake.put(CAL, "single-1", &sample(CollectionKind::Calendar, "single"))
        .await;
    let p = provider(&base);

    let mut s = p.connect().await.unwrap();
    let got = s
        .fetch(
            CAL,
            &[ItemRef {
                id: "series-1".into(),
                uid: None,
            }],
        )
        .await
        .unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].content_type, EVENT_MEDIA_TYPE);
    let expanded = |fake: &FakeGraph| {
        fake.requests()
            .iter()
            .filter(|(_, p, _)| p.contains("series-1") && p.contains("exceptionOccurrences"))
            .count()
    };
    assert_eq!(expanded(&fake), 1, "a master read plainly is asked again");

    let mut s = p.connect().await.unwrap();
    let changes = s.changes(CAL, None, 10).await.unwrap();
    assert_eq!(count(&changes.changes), (2, 0));
    fake.set(|s| s.requests.clear());
    let ids: Vec<ItemRef> = ["series-1", "single-1"]
        .iter()
        .map(|id| ItemRef {
            id: (*id).into(),
            uid: None,
        })
        .collect();
    assert_eq!(s.fetch(CAL, &ids).await.unwrap().len(), 2);
    let requests = fake.requests();
    assert_eq!(expanded(&fake), 1);
    assert_eq!(
        requests
            .iter()
            .filter(|(_, p, _)| p.contains("series-1"))
            .count(),
        1,
        "a master known from the listing is asked once, expanded"
    );
}

#[tokio::test]
async fn busy_reads_are_waited_out_then_throttled_and_busy_writes_throttle() {
    let fake = FakeGraph::standard();
    let base = serve(fake.clone()).await;
    let p = provider(&base);
    let mut s = p.connect().await.unwrap();
    fake.set(|s| s.busy = 2);
    assert_eq!(s.collections().await.unwrap().len(), 5);
    fake.set(|s| s.busy = 10);
    assert!(matches!(
        s.collections().await,
        Err(PimError::Throttled {
            retry_after: Some(d)
        }) if d == Duration::ZERO
    ));
    fake.set(|s| {
        s.busy = 1;
        s.busy_writes = true;
    });
    let create = PimWrite::Put {
        collection: CAL.into(),
        item: None,
        bytes: Bytes::from(sample(CollectionKind::Calendar, "busy")),
        if_version: None,
        key: "01KBUSY".into(),
        notify: false,
    };
    assert!(matches!(
        s.apply(&create).await,
        Err(PimError::Throttled { .. })
    ));
    fake.set(|s| s.busy = 0);
    assert!(matches!(
        s.apply(&create).await.unwrap(),
        WriteOutcome::Applied { .. }
    ));
}

#[tokio::test]
async fn links_to_another_host_are_refused_with_nothing_sent_there() {
    let elsewhere = FakeGraph::standard();
    let other = serve(elsewhere.clone()).await;
    let fake = FakeGraph::standard();
    let base = serve(fake.clone()).await;
    for n in 0..5 {
        fake.put(
            FOLDER,
            &format!("c{n}"),
            &sample(CollectionKind::AddressBook, "x"),
        )
        .await;
    }
    fake.set(|s| s.next_host = Some(other.clone()));
    let mut s = provider(&base).connect().await.unwrap();
    assert!(matches!(
        s.changes(FOLDER, None, 2).await,
        Err(PimError::Protocol(_))
    ));
    assert!(s.changes(CAL, None, 2).await.is_ok());
    fake.put(CAL, "e1", &sample(CollectionKind::Calendar, "1"))
        .await;
    fake.put(CAL, "e2", &sample(CollectionKind::Calendar, "2"))
        .await;
    fake.put(CAL, "e3", &sample(CollectionKind::Calendar, "3"))
        .await;
    assert!(matches!(
        s.changes(CAL, None, 2).await,
        Err(PimError::Protocol(_))
    ));

    let mut stolen = GraphCursor::fresh(FOLDER);
    stolen.link = Some(format!(
        "{other}/v1.0/me/contactFolders/fld-work/contacts/delta"
    ));
    fake.set(|s| {
        s.next_host = None;
        s.page = 100;
    });
    let changes = s
        .changes(FOLDER, Some(&stolen.encode()), 100)
        .await
        .unwrap();
    assert!(matches!(
        changes.changes.first(),
        Some(PimChange::Reset { .. })
    ));
    assert_eq!(count(&changes.changes), (5, 0));
    assert!(elsewhere.requests().is_empty(), "the token never left");
}

#[tokio::test]
async fn a_listing_that_repeats_its_page_is_refused() {
    let fake = FakeGraph::standard();
    let base = serve(fake.clone()).await;
    for n in 0..5 {
        fake.put(
            FOLDER,
            &format!("c{n}"),
            &sample(CollectionKind::AddressBook, "x"),
        )
        .await;
        fake.put(
            CAL,
            &format!("e{n}"),
            &sample(CollectionKind::Calendar, "x"),
        )
        .await;
    }
    fake.set(|s| s.repeat_next = true);
    let mut s = provider(&base).connect().await.unwrap();
    let first = s.changes(FOLDER, None, 2).await.unwrap();
    assert!(matches!(
        s.changes(FOLDER, Some(&first.cursor), 2).await,
        Err(PimError::Protocol(_))
    ));
    assert!(matches!(
        s.changes(CAL, None, 2).await,
        Err(PimError::Protocol(_))
    ));
}

#[tokio::test]
async fn oversized_objects_and_refused_tokens_are_errors() {
    let fake = FakeGraph::standard();
    let base = serve(fake.clone()).await;
    fake.put(CAL, "e1", &sample(CollectionKind::Calendar, "1"))
        .await;
    fake.set(|s| s.huge = true);
    let mut s = provider(&base).connect().await.unwrap();
    let one = [ItemRef {
        id: "e1".into(),
        uid: None,
    }];
    assert!(matches!(
        s.fetch(CAL, &one).await,
        Err(PimError::Protocol(_))
    ));

    let wrong = GraphPimProvider::new(
        GraphPimSettings {
            api_url: Some(format!("{base}/v1.0")),
            ..GraphPimSettings::default()
        },
        Credentials::AccessToken {
            token: "expired".into(),
        },
    )
    .unwrap();
    let mut s = wrong.connect().await.unwrap();
    assert!(matches!(s.collections().await, Err(PimError::Auth)));
    let put = PimWrite::Delete {
        collection: CAL.into(),
        item: one[0].clone(),
        if_version: None,
        notify: false,
    };
    assert!(matches!(s.apply(&put).await, Err(PimError::Auth)));
}

#[tokio::test]
async fn writes_the_server_refuses_fail_with_a_plain_reason() {
    let fake = FakeGraph::standard();
    let base = serve(fake.clone()).await;
    let mut s = provider(&base).connect().await.unwrap();
    let put = |collection: &str, bytes: Vec<u8>| PimWrite::Put {
        collection: collection.into(),
        item: None,
        bytes: Bytes::from(bytes),
        if_version: None,
        key: "01KREFUSED".into(),
        notify: false,
    };
    assert_eq!(
        s.apply(&put(SHARED, sample(CollectionKind::Calendar, "r")))
            .await
            .unwrap(),
        WriteOutcome::Failed {
            reason: "forbidden".into()
        }
    );
    assert_eq!(
        s.apply(&put(CAL, br#"{"subject":"x","refuseMe":true}"#.to_vec()))
            .await
            .unwrap(),
        WriteOutcome::Failed {
            reason: "ErrorInvalidProperty".into()
        },
        "Graph's code, never its message"
    );
    assert_eq!(
        s.apply(&put(CAL, b"BEGIN:VCALENDAR\r\n".to_vec()))
            .await
            .unwrap(),
        WriteOutcome::Failed {
            reason: "not_json".into()
        }
    );
    assert!(matches!(
        s.apply(&put(
            "calendars/gone",
            sample(CollectionKind::Calendar, "g")
        ))
        .await,
        Err(PimError::NotFound)
    ));
    let replace_gone = PimWrite::Put {
        collection: CAL.into(),
        item: Some(ItemRef {
            id: "never-there".into(),
            uid: None,
        }),
        bytes: Bytes::from(sample(CollectionKind::Calendar, "n")),
        if_version: Some("ck1".into()),
        key: "01KGONE".into(),
        notify: false,
    };
    assert_eq!(
        s.apply(&replace_gone).await.unwrap(),
        WriteOutcome::Conflict { current: None }
    );
    assert_eq!(fake.0.lock().unwrap().colls[CAL].items.len(), 0);
}

#[tokio::test]
async fn an_object_fetched_and_put_back_is_accepted() {
    let fake = FakeGraph::standard();
    let base = serve(fake.clone()).await;
    fake.put(CAL, "e1", &sample(CollectionKind::Calendar, "1"))
        .await;
    let mut s = provider(&base).connect().await.unwrap();
    let one = [ItemRef {
        id: "e1".into(),
        uid: None,
    }];
    let got = s.fetch(CAL, &one).await.unwrap().remove(0);
    let mut edited: Value = serde_json::from_slice(&got.bytes).unwrap();
    edited["subject"] = json!("Planning moved");
    let put = PimWrite::Put {
        collection: CAL.into(),
        item: Some(one[0].clone()),
        bytes: Bytes::from(edited.to_string()),
        if_version: got.version.clone(),
        key: "01KEDIT".into(),
        notify: false,
    };
    let WriteOutcome::Applied {
        current: Some(now), ..
    } = s.apply(&put).await.unwrap()
    else {
        panic!("the edit is applied");
    };
    let now: Value = serde_json::from_slice(&now.bytes).unwrap();
    assert_eq!(now["subject"], "Planning moved");
    assert_eq!(now["id"], "e1");
    let held = &fake.0.lock().unwrap().colls[CAL].items["e1"];
    assert!(!held.fields.contains_key("@odata.etag"));
    assert!(!held.fields.contains_key("changeKey"));
}

fn invitation(organizer: bool) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "subject": "Planning",
        "start": { "dateTime": "2026-12-01T10:00:00.0000000", "timeZone": "UTC" },
        "end": { "dateTime": "2026-12-01T11:00:00.0000000", "timeZone": "UTC" },
        "isOrganizer": organizer,
        "organizer": { "emailAddress": { "name": "Test Organizer", "address": "organizer@example.org" } },
        "attendees": [
            { "type": "required", "emailAddress": { "name": "Ada", "address": "ada@example.com" },
              "status": { "response": "none" } }
        ],
        "responseStatus": { "response": "notResponded" }
    }))
    .unwrap()
}

fn respond(
    item: &str,
    answer: PartStat,
    attendee: Option<&str>,
    if_version: Option<String>,
    notify: bool,
) -> PimWrite {
    PimWrite::Respond {
        collection: CAL.into(),
        item: ItemRef {
            id: item.into(),
            uid: None,
        },
        answer,
        attendee: attendee.map(str::to_owned),
        comment: Some("See you there".into()),
        if_version,
        notify,
    }
}

#[tokio::test]
async fn respond_answers_through_graph_actions() {
    let fake = FakeGraph::standard();
    let base = serve(fake.clone()).await;
    fake.put(CAL, "inv1", &invitation(false)).await;
    let mut s = provider(&base).connect().await.unwrap();
    let (version, _) = fake
        .read(
            CAL,
            &ItemRef {
                id: "inv1".into(),
                uid: None,
            },
        )
        .await
        .unwrap();

    let out = s
        .apply(&respond("inv1", PartStat::Accepted, None, None, true))
        .await
        .unwrap();
    let WriteOutcome::Applied {
        item: Some(answered),
        current: Some(current),
    } = out
    else {
        panic!("applied: {out:?}");
    };
    assert_eq!(answered.id, "inv1");
    let (held_version, held) = fake.read(CAL, &answered).await.unwrap();
    assert_eq!(current.bytes, held);
    assert_eq!(current.version, held_version);
    assert_ne!(current.version, version);
    assert_eq!(current.content_type, EVENT_MEDIA_TYPE);
    let now: Value = serde_json::from_slice(&current.bytes).unwrap();
    assert_eq!(now["responseStatus"]["response"], "accepted");
    let answers = fake.0.lock().unwrap().answers.clone();
    assert_eq!(
        answers[0],
        (
            "inv1".to_owned(),
            "accept".to_owned(),
            json!({ "comment": "See you there", "sendResponse": true })
        )
    );

    let out = s
        .apply(&respond(
            "inv1",
            PartStat::Tentative,
            Some("ADA@example.com"),
            held_version.clone(),
            false,
        ))
        .await
        .unwrap();
    assert!(matches!(out, WriteOutcome::Applied { .. }), "{out:?}");
    let answers = fake.0.lock().unwrap().answers.clone();
    assert_eq!(answers[1].1, "tentativelyAccept");
    assert_eq!(answers[1].2["sendResponse"], false);

    s.apply(&PimWrite::Respond {
        collection: CAL.into(),
        item: answered.clone(),
        answer: PartStat::Declined,
        attendee: None,
        comment: None,
        if_version: None,
        notify: true,
    })
    .await
    .unwrap();
    let answers = fake.0.lock().unwrap().answers.clone();
    assert_eq!(
        answers[2].2,
        json!({ "sendResponse": true }),
        "no comment, none sent"
    );
}

#[tokio::test]
async fn respond_refuses_what_it_cannot_answer() {
    let fake = FakeGraph::standard();
    let base = serve(fake.clone()).await;
    fake.put(CAL, "inv1", &invitation(false)).await;
    fake.put(CAL, "own1", &invitation(true)).await;
    let mut s = provider(&base).connect().await.unwrap();
    let held = |id: &str| {
        let st = fake.0.lock().unwrap();
        change_key(st.colls[CAL].items[id].seq)
    };
    let before = held("inv1");

    let out = s
        .apply(&respond(
            "inv1",
            PartStat::Accepted,
            None,
            Some("ck-old".into()),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(
        out,
        WriteOutcome::Conflict {
            current: Some(before.clone())
        }
    );
    let out = s
        .apply(&respond(
            "inv1",
            PartStat::Accepted,
            Some("nobody@example.org"),
            None,
            true,
        ))
        .await
        .unwrap();
    assert_eq!(
        out,
        WriteOutcome::Failed {
            reason: "attendee_not_found".into()
        }
    );
    assert!(
        fake.0.lock().unwrap().answers.is_empty(),
        "nothing answered"
    );
    assert_eq!(held("inv1"), before);

    let out = s
        .apply(&respond("own1", PartStat::Declined, None, None, true))
        .await
        .unwrap();
    assert_eq!(
        out,
        WriteOutcome::Failed {
            reason: "not_invited".into()
        }
    );
    let out = s
        .apply(&respond("gone1", PartStat::Declined, None, None, true))
        .await
        .unwrap();
    assert_eq!(out, WriteOutcome::Conflict { current: None });

    let out = s
        .apply(&PimWrite::Respond {
            collection: FOLDER.into(),
            item: ItemRef {
                id: "c1".into(),
                uid: None,
            },
            answer: PartStat::Accepted,
            attendee: None,
            comment: None,
            if_version: None,
            notify: true,
        })
        .await
        .unwrap();
    assert_eq!(
        out,
        WriteOutcome::Failed {
            reason: "not_a_calendar".into()
        }
    );
}

#[tokio::test]
async fn scheduling_and_addresses() {
    let fake = FakeGraph::standard();
    let base = serve(fake.clone()).await;
    let mut s = provider(&base).connect().await.unwrap();
    assert_eq!(s.scheduling(CAL).await.unwrap(), Scheduling::Server);
    assert_eq!(s.scheduling(FOLDER).await.unwrap(), Scheduling::Client);
    assert!(matches!(
        s.scheduling("elsewhere").await,
        Err(PimError::NotFound)
    ));

    assert_eq!(s.addresses().await.unwrap(), vec!["ada@example.com"]);
    let (_, asked, _) = fake.requests().last().unwrap().clone();
    assert!(asked.starts_with("/v1.0/me?"), "{asked}");
    assert!(asked.contains("mail") && asked.contains("userPrincipalName"));

    fake.set(|s| {
        s.user = Some(json!({ "mail": "Ada.Lovelace@Example.com", "userPrincipalName": "ADA@example.onmicrosoft.com" }))
    });
    assert_eq!(
        s.addresses().await.unwrap(),
        vec!["ada.lovelace@example.com", "ada@example.onmicrosoft.com"]
    );
    fake.set(|s| s.user = Some(json!({ "mail": null, "userPrincipalName": "ada-guest" })));
    assert!(s.addresses().await.unwrap().is_empty());
    fake.set(|s| s.user = None);
    assert!(s.addresses().await.unwrap().is_empty());

    fake.set(|s| s.user = Some(json!({ "mail": "shared@example.com" })));
    let mut shared = GraphPimProvider::new(
        GraphPimSettings {
            api_url: Some(format!("{base}/v1.0")),
            user: Some("shared@example.com".into()),
            ..GraphPimSettings::default()
        },
        token(),
    )
    .unwrap()
    .connect()
    .await
    .unwrap();
    assert_eq!(
        shared.addresses().await.unwrap(),
        vec!["shared@example.com"]
    );
    let (_, asked, _) = fake.requests().last().unwrap().clone();
    assert!(
        asked.starts_with("/v1.0/users/shared@example.com?"),
        "{asked}"
    );
}

#[test]
fn settings_refuse_passwords_plain_http_and_hide_secrets() {
    assert!(matches!(
        GraphPimProvider::new(
            GraphPimSettings::default(),
            Credentials::Password {
                secret: "pw".into()
            }
        ),
        Err(PimError::Config(_))
    ));
    assert!(matches!(
        GraphPimProvider::new(
            GraphPimSettings {
                api_url: Some("http://graph.example.com/v1.0".into()),
                ..GraphPimSettings::default()
            },
            token()
        ),
        Err(PimError::Config(_))
    ));
    let provider = GraphPimProvider::new(GraphPimSettings::default(), token()).unwrap();
    assert!(!format!("{provider:?}").contains(TOKEN));
    let settings = GraphPimSettings::from_json(&json!({
        "api_url": "https://graph.example.com/v1.0",
        "user": "shared@example.com",
        "other": 1
    }))
    .unwrap();
    assert!(!format!("{settings:?}").contains("shared@example.com"));
    assert!(matches!(Place::of("contacts/a/b"), Err(PimError::NotFound)));
    assert_eq!(Place::of(CAL).unwrap(), Place::Calendar("cal-work".into()));
}

#[tokio::test]
async fn waits_while_another_holder_pauses_the_throttle() {
    let fake = FakeGraph::standard();
    let base = serve(fake.clone()).await;
    let throttle = skein_throttle::Throttle::default();
    let mut s = provider(&base)
        .with_throttle(throttle.clone())
        .connect()
        .await
        .unwrap();
    throttle.pause(Duration::from_millis(300));
    let start = std::time::Instant::now();
    s.collections().await.unwrap();
    assert!(start.elapsed() >= Duration::from_millis(300));
}

#[tokio::test]
async fn a_busy_answer_pauses_the_shared_throttle_and_a_long_pause_ends_the_retries() {
    let fake = FakeGraph::standard();
    let base = serve(fake.clone()).await;
    let throttle = skein_throttle::Throttle::default();
    let mut s = provider(&base)
        .with_throttle(throttle.clone())
        .connect()
        .await
        .unwrap();
    fake.set(|s| {
        s.busy = 3;
        s.busy_after = Some("30");
    });
    let before = fake.requests().len();
    assert!(matches!(
        s.collections().await,
        Err(PimError::Throttled { retry_after: Some(d) }) if d == Duration::from_secs(30)
    ));
    assert_eq!(fake.requests().len(), before + 1);
    let left = throttle.paused_until().unwrap() - tokio::time::Instant::now();
    assert!(left > Duration::from_secs(29) && left <= Duration::from_secs(30));
}
