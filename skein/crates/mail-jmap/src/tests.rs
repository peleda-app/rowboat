use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::Router;
use axum::body::{Body, Bytes as RawBody};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Map;
use skein_mail::testing::{ServerControl, conformance, write_conformance};
use tokio::sync::broadcast;

use super::*;

const USER: &str = "ada@example.com";
const PASSWORD: &str = "correct-horse-0451";
const TOKEN: &str = "jmap-bearer-token-0451";
const ACCOUNT: &str = "acc-ada";
const INBOX: &str = "mb-inbox";

#[derive(Clone)]
struct Email {
    blob: String,
    mailboxes: BTreeSet<String>,
    keywords: BTreeSet<String>,
    received: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Created,
    Updated,
    Destroyed,
}

struct Fake {
    port: u16,
    mailboxes: Vec<(String, String, Option<String>, Option<String>)>,
    emails: BTreeMap<String, Email>,
    blobs: BTreeMap<String, Vec<u8>>,
    state: u64,
    floor: u64,
    history: Vec<(u64, String, Kind)>,
    next: u64,
    max_objects: usize,
    max_calls: usize,
    max_upload: u64,
    throttle: Vec<(u16, Option<&'static str>)>,
    stall_imports: bool,
    interfere: usize,
    no_events: bool,
    push: broadcast::Sender<()>,
    requests: usize,
    seen_auth_elsewhere: bool,
}

type Shared = Arc<Mutex<Fake>>;

fn keyword_of(flag: &str) -> String {
    write::keyword(flag).unwrap()
}

impl Fake {
    fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn record(&mut self, id: &str, kind: Kind) {
        self.state += 1;
        let state = self.state;
        self.history.push((state, id.to_owned(), kind));
        let _ = self.push.send(());
    }

    fn create(&mut self, mailbox: &str, raw: Vec<u8>, keywords: BTreeSet<String>) -> String {
        self.next += 1;
        let id = format!("M{:04}", self.next);
        let blob = format!("B{:04}", self.next);
        self.blobs.insert(blob.clone(), raw);
        self.emails.insert(
            id.clone(),
            Email {
                blob,
                mailboxes: BTreeSet::from([mailbox.to_owned()]),
                keywords,
                received: time::format_utc(1_700_000_000 + self.next as i64),
            },
        );
        self.record(&id, Kind::Created);
        id
    }

    fn find(&self, mailbox: &str, raw: &[u8]) -> Option<String> {
        self.emails
            .iter()
            .find(|(_, e)| e.mailboxes.contains(mailbox) && self.blobs[&e.blob] == raw)
            .map(|(id, _)| id.clone())
    }

    fn email_json(&self, id: &str, e: &Email, properties: Option<&Vec<Value>>) -> Value {
        let all = json!({
            "id": id,
            "blobId": e.blob,
            "receivedAt": e.received,
            "mailboxIds": e.mailboxes.iter().map(|m| (m.clone(), json!(true))).collect::<Map<_, _>>(),
            "keywords": e.keywords.iter().map(|k| (k.clone(), json!(true))).collect::<Map<_, _>>(),
        });
        match properties {
            None => all,
            Some(props) => {
                let mut out = Map::new();
                for p in props {
                    let p = p.as_str().unwrap();
                    if let Some(v) = all.get(p) {
                        out.insert(p.to_owned(), v.clone());
                    }
                }
                Value::Object(out)
            }
        }
    }
}

fn authorized(headers: &HeaderMap) -> bool {
    let basic = format!("Basic {}", STANDARD.encode(format!("{USER}:{PASSWORD}")));
    let bearer = format!("Bearer {TOKEN}");
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == basic || v == bearer)
}

fn gate(shared: &Shared, headers: &HeaderMap) -> Option<Response> {
    let mut fake = shared.lock().unwrap();
    fake.requests += 1;
    if !authorized(headers) {
        return Some(StatusCode::UNAUTHORIZED.into_response());
    }
    if !fake.throttle.is_empty() {
        let (status, after) = fake.throttle.remove(0);
        let mut response = (StatusCode::from_u16(status).unwrap(), "busy").into_response();
        if let Some(after) = after {
            response
                .headers_mut()
                .insert("retry-after", after.parse().unwrap());
        }
        return Some(response);
    }
    None
}

async fn well_known() -> Response {
    Redirect::temporary("/jmap/session").into_response()
}

async fn session(State(shared): State<Shared>, headers: HeaderMap) -> Response {
    if let Some(refused) = gate(&shared, &headers) {
        return refused;
    }
    let fake = shared.lock().unwrap();
    let mut out = json!({
        "capabilities": {
            CORE: {
                "maxObjectsInGet": fake.max_objects,
                "maxCallsInRequest": fake.max_calls,
                "maxObjectsInSet": fake.max_objects,
                "maxSizeUpload": fake.max_upload,
            },
            MAIL: {},
        },
        "accounts": { ACCOUNT: { "name": USER, "isPersonal": true } },
        "primaryAccounts": { MAIL: ACCOUNT },
        "username": USER,
        "apiUrl": "/jmap/api",
        "downloadUrl": format!("{}/jmap/download/{{accountId}}/{{blobId}}/{{name}}?type={{type}}", fake.base()),
        "uploadUrl": "/jmap/upload/{accountId}/",
        "state": "session-1",
    });
    if !fake.no_events {
        out["eventSourceUrl"] =
            json!("/jmap/events?types={types}&closeafter={closeafter}&ping={ping}");
    }
    axum::Json(out).into_response()
}

fn method_error(kind: &str, id: &Value) -> Value {
    json!(["error", { "type": kind }, id])
}

fn resolve_ids(args: &Value, answers: &[Value]) -> Vec<String> {
    if let Some(reference) = args.get("#ids") {
        let of = reference["resultOf"].as_str().unwrap();
        let found = answers
            .iter()
            .find(|a| a[2].as_str() == Some(of))
            .expect("a back-reference to an earlier call");
        return found[1]["ids"]
            .as_array()
            .map(|ids| ids.iter().map(|i| i.as_str().unwrap().to_owned()).collect())
            .unwrap_or_default();
    }
    args["ids"]
        .as_array()
        .map(|ids| ids.iter().map(|i| i.as_str().unwrap().to_owned()).collect())
        .unwrap_or_default()
}

fn email_changes(fake: &Fake, args: &Value, id: &Value) -> Value {
    let since: Option<u64> = args["sinceState"]
        .as_str()
        .and_then(|s| s.strip_prefix('s'))
        .and_then(|s| s.parse().ok());
    let Some(since) = since.filter(|s| *s >= fake.floor && *s <= fake.state) else {
        return method_error("cannotCalculateChanges", id);
    };
    let max = args["maxChanges"].as_u64().unwrap_or(1000) as usize;
    let window: Vec<&(u64, String, Kind)> =
        fake.history.iter().filter(|(s, _, _)| *s > since).collect();
    let more = window.len() > max;
    let taken = &window[..window.len().min(max)];
    let new_state = if more {
        taken.last().map(|(s, _, _)| *s).unwrap_or(since)
    } else {
        fake.state
    };
    let mut kinds: BTreeMap<&str, (Kind, Kind)> = BTreeMap::new();
    for (_, eid, kind) in taken {
        kinds
            .entry(eid.as_str())
            .and_modify(|(_, last)| *last = *kind)
            .or_insert((*kind, *kind));
    }
    let (mut created, mut updated, mut destroyed) = (vec![], vec![], vec![]);
    for (eid, (first, last)) in kinds {
        match (first, last) {
            (Kind::Created, Kind::Destroyed) => {}
            (_, Kind::Destroyed) => destroyed.push(eid),
            (Kind::Created, _) => created.push(eid),
            _ => updated.push(eid),
        }
    }
    json!(["Email/changes", {
        "accountId": ACCOUNT,
        "oldState": format!("s{since}"),
        "newState": format!("s{new_state}"),
        "hasMoreChanges": more,
        "created": created,
        "updated": updated,
        "destroyed": destroyed,
    }, id])
}

fn email_query(fake: &Fake, args: &Value, id: &Value) -> Value {
    let mailbox = args.pointer("/filter/inMailbox").and_then(Value::as_str);
    let mut hits: Vec<(&String, &Email)> = fake
        .emails
        .iter()
        .filter(|(_, e)| mailbox.is_none_or(|m| e.mailboxes.contains(m)))
        .collect();
    hits.sort_by(|a, b| (&a.1.received, a.0).cmp(&(&b.1.received, b.0)));
    let ids: Vec<&String> = hits.iter().map(|(id, _)| *id).collect();
    let start = match args.get("anchor").and_then(Value::as_str) {
        Some(anchor) => match ids.iter().position(|i| *i == anchor) {
            Some(at) => at + args["anchorOffset"].as_u64().unwrap_or(0) as usize,
            None => return method_error("anchorNotFound", id),
        },
        None => args["position"].as_u64().unwrap_or(0) as usize,
    };
    let limit = args["limit"].as_u64().unwrap_or(1000) as usize;
    assert!(
        limit <= fake.max_objects,
        "the query asks for no more than a get may return"
    );
    let page: Vec<&String> = ids.iter().skip(start).take(limit).copied().collect();
    json!(["Email/query", {
        "accountId": ACCOUNT,
        "ids": page,
        "position": start,
        "total": ids.len(),
        "queryState": format!("q{}", fake.state),
    }, id])
}

fn email_set(fake: &mut Fake, args: &Value, id: &Value) -> Value {
    let old = format!("s{}", fake.state);
    if fake.interfere > 0 && args.get("ifInState").is_some() {
        fake.interfere -= 1;
        let any = fake.emails.keys().next().cloned();
        if let Some(any) = any {
            fake.record(&any, Kind::Updated);
        }
    }
    if let Some(expected) = args["ifInState"].as_str()
        && expected != format!("s{}", fake.state)
    {
        return method_error("stateMismatch", id);
    }
    let mut updated = Map::new();
    let mut not_updated = Map::new();
    if let Some(update) = args["update"].as_object() {
        for (eid, patch) in update {
            let Some(email) = fake.emails.get_mut(eid) else {
                not_updated.insert(eid.clone(), json!({ "type": "notFound" }));
                continue;
            };
            for (path, value) in patch.as_object().unwrap() {
                if path == "mailboxIds" {
                    email.mailboxes = value.as_object().unwrap().keys().cloned().collect();
                    continue;
                }
                let (field, key) = path.split_once('/').unwrap();
                let set = match field {
                    "keywords" => &mut email.keywords,
                    "mailboxIds" => &mut email.mailboxes,
                    _ => panic!("unexpected patch {path}"),
                };
                if value.as_bool() == Some(true) {
                    set.insert(key.to_owned());
                } else {
                    set.remove(key);
                }
            }
            updated.insert(eid.clone(), Value::Null);
            fake.record(eid, Kind::Updated);
        }
    }
    let mut destroyed = Vec::new();
    let mut not_destroyed = Map::new();
    if let Some(destroy) = args["destroy"].as_array() {
        for eid in destroy {
            let eid = eid.as_str().unwrap();
            if fake.emails.remove(eid).is_some() {
                destroyed.push(eid.to_owned());
                fake.record(eid, Kind::Destroyed);
            } else {
                not_destroyed.insert(eid.to_owned(), json!({ "type": "notFound" }));
            }
        }
    }
    json!(["Email/set", {
        "accountId": ACCOUNT,
        "oldState": old,
        "newState": format!("s{}", fake.state),
        "updated": updated,
        "notUpdated": not_updated,
        "destroyed": destroyed,
        "notDestroyed": not_destroyed,
    }, id])
}

fn email_import(fake: &mut Fake, args: &Value, id: &Value) -> Value {
    let mut created = Map::new();
    let mut not_created = Map::new();
    for (key, spec) in args["emails"].as_object().unwrap() {
        let blob = spec["blobId"].as_str().unwrap();
        let Some(raw) = fake.blobs.get(blob).cloned() else {
            not_created.insert(key.clone(), json!({ "type": "blobNotFound" }));
            continue;
        };
        let mailbox = spec["mailboxIds"]
            .as_object()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .clone();
        let keywords = spec["keywords"]
            .as_object()
            .map(|k| k.keys().cloned().collect())
            .unwrap_or_default();
        let eid = fake.create(&mailbox, raw, keywords);
        if let Some(at) = spec["receivedAt"].as_str() {
            fake.emails.get_mut(&eid).unwrap().received = at.to_owned();
        }
        created.insert(key.clone(), json!({ "id": eid, "blobId": blob }));
    }
    json!(["Email/import", { "accountId": ACCOUNT, "created": created, "notCreated": not_created }, id])
}

fn mailbox_set(fake: &mut Fake, args: &Value, id: &Value) -> Value {
    let clash = |fake: &Fake, me: Option<&str>, name: &str, parent: &Option<String>| {
        fake.mailboxes
            .iter()
            .any(|(mid, n, p, _)| Some(mid.as_str()) != me && n == name && p == parent)
    };
    let mut created = Map::new();
    let mut not_created = Map::new();
    let mut made: BTreeMap<String, String> = BTreeMap::new();
    let parent_of = |spec: &Value, made: &BTreeMap<String, String>| -> Option<Option<String>> {
        match spec["parentId"].as_str() {
            None => Some(None),
            Some(r) => match r.strip_prefix('#') {
                Some(key) => made.get(key).cloned().map(Some),
                None => Some(Some(r.to_owned())),
            },
        }
    };
    if let Some(create) = args["create"].as_object() {
        for (key, spec) in create {
            let name = spec["name"].as_str().unwrap().to_owned();
            let Some(parent) = parent_of(spec, &made) else {
                not_created.insert(key.clone(), json!({ "type": "invalidProperties" }));
                continue;
            };
            if clash(fake, None, &name, &parent) {
                not_created.insert(key.clone(), json!({ "type": "alreadyExists" }));
                continue;
            }
            fake.next += 1;
            let mid = format!("mb-new{}", fake.next);
            fake.mailboxes.push((mid.clone(), name, parent, None));
            made.insert(key.clone(), mid.clone());
            created.insert(key.clone(), json!({ "id": mid }));
        }
    }
    let mut updated = Map::new();
    let mut not_updated = Map::new();
    if let Some(update) = args["update"].as_object() {
        for (mid, patch) in update {
            let Some(at) = fake.mailboxes.iter().position(|(m, ..)| m == mid) else {
                not_updated.insert(mid.clone(), json!({ "type": "notFound" }));
                continue;
            };
            let name = patch["name"].as_str().unwrap().to_owned();
            let Some(parent) = parent_of(patch, &made) else {
                not_updated.insert(mid.clone(), json!({ "type": "invalidProperties" }));
                continue;
            };
            if clash(fake, Some(mid), &name, &parent) {
                not_updated.insert(mid.clone(), json!({ "type": "alreadyExists" }));
                continue;
            }
            fake.mailboxes[at].1 = name;
            fake.mailboxes[at].2 = parent;
            updated.insert(mid.clone(), Value::Null);
        }
    }
    let mut destroyed = Vec::new();
    let mut not_destroyed = Map::new();
    let remove_emails = args["onDestroyRemoveEmails"].as_bool().unwrap_or(false);
    for mid in args["destroy"].as_array().into_iter().flatten() {
        let mid = mid.as_str().unwrap().to_owned();
        let refusal = if !fake.mailboxes.iter().any(|(m, ..)| *m == mid) {
            Some("notFound")
        } else if fake
            .mailboxes
            .iter()
            .any(|(_, _, p, _)| p.as_ref() == Some(&mid))
        {
            Some("mailboxHasChild")
        } else if fake
            .mailboxes
            .iter()
            .any(|(m, _, _, r)| *m == mid && r.is_some())
        {
            Some("forbidden")
        } else if !remove_emails && fake.emails.values().any(|e| e.mailboxes.contains(&mid)) {
            Some("mailboxHasEmail")
        } else {
            None
        };
        if let Some(kind) = refusal {
            not_destroyed.insert(mid, json!({ "type": kind }));
            continue;
        }
        let inside: Vec<String> = fake
            .emails
            .iter()
            .filter(|(_, e)| e.mailboxes.contains(&mid))
            .map(|(eid, _)| eid.clone())
            .collect();
        for eid in inside {
            let email = fake.emails.get_mut(&eid).unwrap();
            email.mailboxes.remove(&mid);
            if email.mailboxes.is_empty() {
                fake.emails.remove(&eid);
                fake.record(&eid, Kind::Destroyed);
            } else {
                fake.record(&eid, Kind::Updated);
            }
        }
        fake.mailboxes.retain(|(m, ..)| *m != mid);
        destroyed.push(mid);
    }
    json!(["Mailbox/set", {
        "accountId": ACCOUNT,
        "created": created,
        "notCreated": not_created,
        "updated": updated,
        "notUpdated": not_updated,
        "destroyed": destroyed,
        "notDestroyed": not_destroyed,
    }, id])
}

async fn api(State(shared): State<Shared>, headers: HeaderMap, body: RawBody) -> Response {
    if let Some(refused) = gate(&shared, &headers) {
        return refused;
    }
    let request: Value = serde_json::from_slice(&body).unwrap();
    let calls = request["methodCalls"].as_array().unwrap().clone();
    let stall = {
        let fake = shared.lock().unwrap();
        assert!(
            calls.len() <= fake.max_calls,
            "no more calls than the session allows"
        );
        fake.stall_imports && calls.iter().any(|c| c[0] == "Email/import")
    };
    if stall {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
    let mut fake = shared.lock().unwrap();
    let mut answers: Vec<Value> = Vec::new();
    for call in calls {
        let (name, args, id) = (call[0].as_str().unwrap(), &call[1], &call[2]);
        assert_eq!(args["accountId"], ACCOUNT);
        let answer = match name {
            "Mailbox/get" => {
                let wanted: Option<Vec<String>> = args["ids"]
                    .as_array()
                    .map(|ids| ids.iter().map(|i| i.as_str().unwrap().to_owned()).collect());
                let list: Vec<Value> = fake
                    .mailboxes
                    .iter()
                    .filter(|(mid, ..)| wanted.as_ref().is_none_or(|w| w.contains(mid)))
                    .map(|(mid, name, parent, role)| {
                        json!({ "id": mid, "name": name, "parentId": parent, "role": role })
                    })
                    .collect();
                let not_found: Vec<String> = wanted
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|w| !fake.mailboxes.iter().any(|(mid, ..)| mid == w))
                    .collect();
                json!(["Mailbox/get", { "accountId": ACCOUNT, "state": "m1", "list": list, "notFound": not_found }, id])
            }
            "Email/get" => {
                let ids = resolve_ids(args, &answers);
                assert!(
                    ids.len() <= fake.max_objects,
                    "no more ids than a get may take"
                );
                let props = args["properties"].as_array();
                let mut list = Vec::new();
                let mut not_found = Vec::new();
                for eid in ids {
                    match fake.emails.get(&eid) {
                        Some(e) => list.push(fake.email_json(&eid, e, props)),
                        None => not_found.push(eid),
                    }
                }
                json!(["Email/get", { "accountId": ACCOUNT, "state": format!("s{}", fake.state), "list": list, "notFound": not_found }, id])
            }
            "Email/query" => email_query(&fake, args, id),
            "Email/changes" => email_changes(&fake, args, id),
            "Email/set" => email_set(&mut fake, args, id),
            "Email/import" => email_import(&mut fake, args, id),
            "Mailbox/set" => mailbox_set(&mut fake, args, id),
            other => method_error(&format!("unknownMethod:{other}"), id),
        };
        answers.push(answer);
    }
    axum::Json(json!({ "methodResponses": answers, "sessionState": "session-1" })).into_response()
}

async fn download(
    State(shared): State<Shared>,
    headers: HeaderMap,
    Path((account, blob, _name)): Path<(String, String, String)>,
) -> Response {
    if let Some(refused) = gate(&shared, &headers) {
        return refused;
    }
    assert_eq!(account, ACCOUNT);
    match shared.lock().unwrap().blobs.get(&blob) {
        Some(raw) => raw.clone().into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn upload(
    State(shared): State<Shared>,
    headers: HeaderMap,
    Path(account): Path<String>,
    body: RawBody,
) -> Response {
    if let Some(refused) = gate(&shared, &headers) {
        return refused;
    }
    assert_eq!(account, ACCOUNT);
    let mut fake = shared.lock().unwrap();
    fake.next += 1;
    let blob = format!("U{:04}", fake.next);
    fake.blobs.insert(blob.clone(), body.to_vec());
    axum::Json(json!({ "accountId": ACCOUNT, "blobId": blob, "type": "message/rfc822", "size": body.len() }))
        .into_response()
}

async fn events(
    State(shared): State<Shared>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    if let Some(refused) = gate(&shared, &headers) {
        return refused;
    }
    assert_eq!(
        query.get("types").map(String::as_str),
        Some("Email,Mailbox")
    );
    assert_eq!(query.get("closeafter").map(String::as_str), Some("no"));
    let receiver = shared.lock().unwrap().push.subscribe();
    let stream = futures::stream::unfold(
        (receiver, shared.clone(), true),
        |(mut receiver, shared, first)| async move {
            if first {
                return Some((
                    Ok::<_, std::io::Error>(Bytes::from_static(b": hello\n\n")),
                    (receiver, shared, false),
                ));
            }
            receiver.recv().await.ok()?;
            let state = shared.lock().unwrap().state;
            let other =
                json!({ "@type": "StateChange", "changed": { "acc-other": { "Email": "x" } } });
            let change = json!({ "@type": "StateChange", "changed": { ACCOUNT: { "Email": format!("s{state}") } } });
            let text = format!("event: state\ndata: {other}\n\nevent: state\ndata: {change}\n\n");
            Some((Ok(Bytes::from(text)), (receiver, shared, false)))
        },
    );
    (
        [("content-type", "text/event-stream")],
        Body::from_stream(stream),
    )
        .into_response()
}

async fn elsewhere(State(shared): State<Shared>, headers: HeaderMap) -> Response {
    if headers.contains_key("authorization") {
        shared.lock().unwrap().seen_auth_elsewhere = true;
    }
    Redirect::temporary("/jmap/session").into_response()
}

#[derive(Clone)]
struct FakeJmap {
    shared: Shared,
}

impl FakeJmap {
    async fn start() -> Self {
        let (push, _) = broadcast::channel(64);
        let shared: Shared = Arc::new(Mutex::new(Fake {
            port: 0,
            mailboxes: vec![
                (INBOX.into(), "Inbox".into(), None, Some("inbox".into())),
                ("mb-sent".into(), "Sent".into(), None, Some("sent".into())),
                (
                    "mb-trash".into(),
                    "Trash".into(),
                    None,
                    Some("trash".into()),
                ),
                (
                    "mb-projects".into(),
                    "Projects".into(),
                    Some(INBOX.into()),
                    None,
                ),
            ],
            emails: BTreeMap::new(),
            blobs: BTreeMap::new(),
            state: 0,
            floor: 0,
            history: Vec::new(),
            next: 0,
            max_objects: 500,
            max_calls: 16,
            max_upload: 50_000_000,
            throttle: Vec::new(),
            stall_imports: false,
            interfere: 0,
            no_events: false,
            push,
            requests: 0,
            seen_auth_elsewhere: false,
        }));
        let app = Router::new()
            .route("/.well-known/jmap", get(well_known))
            .route("/jmap/session", get(session))
            .route("/jmap/api", post(api))
            .route("/jmap/download/{account}/{blob}/{name}", get(download))
            .route("/jmap/upload/{account}/", post(upload))
            .route("/jmap/events", get(events))
            .route("/moved", get(elsewhere))
            .with_state(shared.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        shared.lock().unwrap().port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { shared }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Fake> {
        self.shared.lock().unwrap()
    }

    fn provider(&self, credentials: Credentials) -> JmapProvider {
        JmapProvider::new(JmapSettings::new(self.lock().base(), USER), credentials).unwrap()
    }

    fn password(&self) -> JmapProvider {
        self.provider(Credentials::Password {
            secret: PASSWORD.into(),
        })
    }

    fn token(&self) -> JmapProvider {
        self.provider(Credentials::AccessToken {
            token: TOKEN.into(),
        })
    }
}

#[async_trait]
impl ServerControl for FakeJmap {
    async fn create_mailbox(&self, mailbox: &str) {
        let mut fake = self.lock();
        if !fake.mailboxes.iter().any(|(id, ..)| id == mailbox) {
            fake.mailboxes
                .push((mailbox.into(), mailbox.into(), None, None));
        }
    }

    async fn add(&self, mailbox: &str, bytes: &[u8], flags: Flags) {
        let keywords = flags.iter().map(keyword_of).collect();
        self.lock().create(mailbox, bytes.to_vec(), keywords);
    }

    async fn remove(&self, mailbox: &str, bytes: &[u8]) {
        let mut fake = self.lock();
        if let Some(id) = fake.find(mailbox, bytes) {
            fake.emails.remove(&id);
            fake.record(&id, Kind::Destroyed);
        }
    }

    async fn set_flags(&self, mailbox: &str, bytes: &[u8], flags: Flags) {
        let mut fake = self.lock();
        if let Some(id) = fake.find(mailbox, bytes) {
            fake.emails.get_mut(&id).unwrap().keywords = flags.iter().map(keyword_of).collect();
            fake.record(&id, Kind::Updated);
        }
    }

    async fn invalidate(&self, _mailbox: &str) {
        let mut fake = self.lock();
        fake.state += 1;
        fake.floor = fake.state;
        fake.history.clear();
    }

    async fn flags_of(&self, mailbox: &str, bytes: &[u8]) -> Option<Flags> {
        let fake = self.lock();
        let id = fake.find(mailbox, bytes)?;
        Some(flags(&fake.email_json(&id, &fake.emails[&id], None)))
    }
}

fn msg(n: u32) -> Vec<u8> {
    format!("From: ada@example.com\r\nTo: bob@example.org\r\nSubject: Note {n}\r\nMessage-ID: <n{n}@example.com>\r\n\r\nHello {n}\r\n").into_bytes()
}

async fn drain(
    session: &mut Box<dyn MailSession>,
    cursor: Option<Cursor>,
    limit: usize,
) -> (Cursor, Vec<MailChange>) {
    let mut cursor = cursor;
    let mut all = Vec::new();
    loop {
        let batch = session
            .changes(INBOX, cursor.as_ref(), limit)
            .await
            .unwrap();
        all.extend(batch.changes);
        cursor = Some(batch.cursor);
        if !batch.more {
            return (cursor.unwrap(), all);
        }
    }
}

#[tokio::test]
async fn keeps_the_mail_contract_with_a_password() {
    let fake = FakeJmap::start().await;
    conformance(Arc::new(fake.password()), Arc::new(fake.clone()), INBOX).await;
}

#[tokio::test]
async fn keeps_the_mail_contract_with_a_token_and_tight_limits() {
    let fake = FakeJmap::start().await;
    {
        let mut f = fake.lock();
        f.max_objects = 1;
        f.max_calls = 1;
    }
    conformance(Arc::new(fake.token()), Arc::new(fake.clone()), INBOX).await;
}

#[tokio::test]
async fn lists_mailboxes_with_paths_and_roles() {
    let fake = FakeJmap::start().await;
    let mut session = fake.password().connect().await.unwrap();
    let boxes = session.mailboxes().await.unwrap();
    let summary: Vec<(&str, &str, Option<MailboxRole>)> = boxes
        .iter()
        .map(|b| (b.id.as_str(), b.path.as_str(), b.role))
        .collect();
    assert_eq!(
        summary,
        vec![
            (INBOX, "Inbox", Some(MailboxRole::Inbox)),
            ("mb-projects", "Inbox/Projects", None),
            ("mb-sent", "Sent", Some(MailboxRole::Sent)),
            ("mb-trash", "Trash", Some(MailboxRole::Trash)),
        ]
    );
}

#[tokio::test]
async fn reports_moves_between_mailboxes_and_keeps_copies_apart() {
    let fake = FakeJmap::start().await;
    fake.add(INBOX, &msg(1), Flags::default()).await;
    let mut session = fake.password().connect().await.unwrap();
    let (cursor, changes) = drain(&mut session, None, 10).await;
    let MailChange::Added {
        item, received_at, ..
    } = &changes[0]
    else {
        panic!("{changes:?}");
    };
    assert_eq!(received_at, &Some(skein_core::Timestamp(1_700_000_001_000)));
    let outcome = session
        .apply(
            &CommandBody::Move {
                from: INBOX.into(),
                to: "mb-trash".into(),
                items: vec![item.clone()],
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(outcome, WriteOutcome::Applied);
    let (_, changes) = drain(&mut session, Some(cursor), 10).await;
    assert_eq!(changes, vec![MailChange::Removed { item: item.clone() }]);
    let trash = session.changes("mb-trash", None, 10).await.unwrap();
    assert!(matches!(&trash.changes[..], [MailChange::Added { item: i, .. }] if i.id == item.id));
}

#[tokio::test]
async fn changes_during_a_paged_listing_are_neither_lost_nor_repeated() {
    let fake = FakeJmap::start().await;
    for n in 1..=5 {
        fake.add(INBOX, &msg(n), Flags::default()).await;
    }
    let mut session = fake.password().connect().await.unwrap();
    let first = session.changes(INBOX, None, 2).await.unwrap();
    assert!(first.more);
    fake.remove(INBOX, &msg(2)).await;
    fake.add(INBOX, &msg(6), Flags::default()).await;
    fake.set_flags(INBOX, &msg(1), Flags::new(["\\Seen"])).await;
    let (_, rest) = drain(&mut session, Some(first.cursor), 2).await;
    let mut alive: BTreeSet<String> = BTreeSet::new();
    for change in first.changes.iter().chain(&rest) {
        match change {
            MailChange::Added { item, .. } => assert!(alive.insert(item.id.clone()), "added twice"),
            MailChange::Removed { item } => assert!(alive.remove(&item.id)),
            _ => {}
        }
    }
    let expected: BTreeSet<String> = fake.lock().emails.keys().cloned().collect();
    assert_eq!(alive, expected);
    assert!(
        rest.iter()
            .any(|c| matches!(c, MailChange::Flags { flags, .. } if flags.contains("\\Seen")))
    );
}

#[tokio::test]
async fn a_lost_anchor_lists_again_without_repeats() {
    let fake = FakeJmap::start().await;
    for n in 1..=4 {
        fake.add(INBOX, &msg(n), Flags::default()).await;
    }
    let mut session = fake.password().connect().await.unwrap();
    let first = session.changes(INBOX, None, 2).await.unwrap();
    fake.remove(INBOX, &msg(2)).await;
    let (_, rest) = drain(&mut session, Some(first.cursor), 2).await;
    let added = first
        .changes
        .iter()
        .chain(&rest)
        .filter(|c| matches!(c, MailChange::Added { .. }))
        .count();
    assert_eq!(added, 4);
    assert_eq!(
        rest.iter()
            .filter(|c| matches!(c, MailChange::Removed { .. }))
            .count(),
        1
    );
}

#[tokio::test]
async fn unreadable_cursors_and_unknown_mailboxes() {
    let fake = FakeJmap::start().await;
    fake.add(INBOX, &msg(1), Flags::default()).await;
    let mut session = fake.password().connect().await.unwrap();
    let batch = session
        .changes(INBOX, Some(&Cursor(Bytes::from_static(b"junk"))), 10)
        .await
        .unwrap();
    assert!(matches!(batch.changes[0], MailChange::Reset { .. }));
    assert_eq!(batch.changes.len(), 2);
    let other = session
        .changes("mb-sent", Some(&batch.cursor), 10)
        .await
        .unwrap();
    assert!(matches!(
        other.changes.first(),
        Some(MailChange::Reset { .. })
    ));
    assert!(matches!(
        session.changes("mb-gone", None, 10).await,
        Err(MailError::MailboxNotFound)
    ));
    let (cursor, _) = drain(&mut session, None, 10).await;
    fake.lock().mailboxes.retain(|(id, ..)| id != INBOX);
    assert!(matches!(
        session.changes(INBOX, Some(&cursor), 10).await,
        Err(MailError::MailboxNotFound)
    ));
}

#[tokio::test]
async fn discovery_follows_well_known_without_credentials_and_refuses_bad_addresses() {
    let fake = FakeJmap::start().await;
    let base = fake.lock().base();
    let provider = JmapProvider::new(
        JmapSettings::new(format!("{base}/moved"), USER),
        Credentials::Password {
            secret: PASSWORD.into(),
        },
    )
    .unwrap();
    assert!(matches!(
        provider.connect().await,
        Err(MailError::Protocol(_))
    ));
    assert!(
        fake.lock().seen_auth_elsewhere,
        "the session request itself carried credentials"
    );

    for url in [
        "http://jmap.example.com",
        "ftp://jmap.example.com",
        "https://ada:pw@jmap.example.com",
        "",
    ] {
        assert!(
            matches!(
                JmapProvider::new(
                    JmapSettings::new(url, USER),
                    Credentials::Password { secret: "x".into() }
                ),
                Err(MailError::Config(_))
            ),
            "{url}"
        );
    }
    assert_eq!(
        session_url("jmap.example.com").unwrap(),
        "https://jmap.example.com/.well-known/jmap"
    );
    assert!(matches!(
        JmapProvider::new(
            JmapSettings::new(base.clone(), ""),
            Credentials::Password { secret: "x".into() }
        ),
        Err(MailError::Config(_))
    ));
    assert!(matches!(
        fake.provider(Credentials::Password {
            secret: "wrong".into()
        })
        .connect()
        .await,
        Err(MailError::Auth)
    ));
}

#[tokio::test]
async fn throttling_becomes_throttled_with_the_delay() {
    let fake = FakeJmap::start().await;
    let provider = fake.password();
    let mut session = provider.connect().await.unwrap();
    fake.lock().throttle = vec![(429, Some("9"))];
    assert!(matches!(
        session.changes(INBOX, None, 10).await,
        Err(MailError::Throttled { retry_after: Some(d) }) if d == Duration::from_secs(9)
    ));
    fake.lock().throttle = vec![(503, Some("2"))];
    assert!(matches!(
        session.mailboxes().await,
        Err(MailError::Throttled {
            retry_after: Some(_)
        })
    ));
    fake.lock().throttle = vec![(503, None)];
    assert!(matches!(
        session.mailboxes().await,
        Err(MailError::Network(_))
    ));
    fake.lock().throttle = vec![(429, None)];
    assert!(matches!(
        session
            .apply(
                &CommandBody::SetFlags {
                    mailbox: INBOX.into(),
                    items: vec![item("M0001".into())],
                    add: Flags::new(["\\Seen"]),
                    remove: Flags::default(),
                },
                None
            )
            .await,
        Err(MailError::Throttled { retry_after: None })
    ));
    fake.lock().throttle = vec![(429, Some("1"))];
    assert!(matches!(
        provider.connect().await,
        Err(MailError::Throttled { .. })
    ));
}

#[tokio::test]
async fn downloads_above_the_limit_are_refused() {
    let fake = FakeJmap::start().await;
    fake.add(INBOX, &msg(1), Flags::default()).await;
    let id = fake.lock().find(INBOX, &msg(1)).unwrap();
    let mut session = fake
        .password()
        .with_max_download(10)
        .connect()
        .await
        .unwrap();
    assert!(matches!(
        session.fetch(INBOX, &[item(id)]).await,
        Err(MailError::Protocol(_))
    ));
}

#[tokio::test]
async fn writes_flags_moves_deletes_and_appends() {
    let fake = FakeJmap::start().await;
    fake.add(INBOX, &msg(1), Flags::default()).await;
    fake.add(INBOX, &msg(2), Flags::default()).await;
    let one = item(fake.lock().find(INBOX, &msg(1)).unwrap());
    let two = item(fake.lock().find(INBOX, &msg(2)).unwrap());
    let gone = item("M9999".into());
    let mut session = fake.password().connect().await.unwrap();

    let set = |add: &[&str], remove: &[&str], items: Vec<ItemRef>| CommandBody::SetFlags {
        mailbox: INBOX.into(),
        items,
        add: Flags::new(add.iter().copied()),
        remove: Flags::new(remove.iter().copied()),
    };
    assert_eq!(
        session
            .apply(
                &set(
                    &["\\Seen", "$Forwarded"],
                    &[],
                    vec![one.clone(), gone.clone()]
                ),
                None
            )
            .await
            .unwrap(),
        WriteOutcome::Applied
    );
    assert_eq!(
        fake.flags_of(INBOX, &msg(1)).await.unwrap(),
        Flags::new(["$Forwarded", "\\Seen"])
    );
    assert_eq!(
        session
            .apply(&set(&["\\Deleted"], &[], vec![one.clone()]), None)
            .await
            .unwrap(),
        WriteOutcome::Failed {
            reason: "unsupported_flag".into()
        }
    );
    assert_eq!(
        session
            .apply(
                &CommandBody::Move {
                    from: INBOX.into(),
                    to: "mb-nowhere".into(),
                    items: vec![two.clone()],
                },
                None
            )
            .await
            .unwrap(),
        WriteOutcome::Failed {
            reason: "no_such_mailbox".into()
        }
    );

    fake.lock()
        .emails
        .get_mut(&one.id)
        .unwrap()
        .mailboxes
        .insert("mb-projects".into());
    fake.lock().interfere = 1;
    assert_eq!(
        session
            .apply(
                &CommandBody::Delete {
                    mailbox: INBOX.into(),
                    items: vec![one.clone(), two.clone(), gone.clone()],
                    to_trash: false,
                },
                None
            )
            .await
            .unwrap(),
        WriteOutcome::Applied
    );
    {
        let f = fake.lock();
        assert_eq!(
            f.emails[&one.id].mailboxes,
            BTreeSet::from(["mb-projects".to_owned()]),
            "an email in another mailbox only leaves this one"
        );
        assert!(
            !f.emails.contains_key(&two.id),
            "an email only here is destroyed"
        );
    }

    let append = |flags: &[&str]| CommandBody::Append {
        mailbox: "mb-sent".into(),
        blob: skein_core::BlobHash::of(&msg(9)),
        flags: Flags::new(flags.iter().copied()),
        received_at: None,
    };
    assert_eq!(
        session
            .apply(&append(&["\\Seen"]), Some(Bytes::from(msg(9))))
            .await
            .unwrap(),
        WriteOutcome::Applied
    );
    assert_eq!(
        fake.flags_of("mb-sent", &msg(9)).await.unwrap(),
        Flags::new(["\\Seen"])
    );
    fake.lock().max_upload = 10;
    let mut session = fake.password().connect().await.unwrap();
    assert_eq!(
        session
            .apply(&append(&[]), Some(Bytes::from(msg(10))))
            .await
            .unwrap(),
        WriteOutcome::Failed {
            reason: "too_large".into()
        }
    );
    assert_eq!(
        session.apply(&append(&[]), None).await.unwrap(),
        WriteOutcome::Failed {
            reason: "missing_content".into()
        }
    );
    assert!(matches!(
        session
            .apply(
                &CommandBody::Append {
                    mailbox: "mb-nowhere".into(),
                    blob: skein_core::BlobHash::of(b"x"),
                    flags: Flags::default(),
                    received_at: None,
                },
                Some(Bytes::from_static(b"x"))
            )
            .await,
        Err(MailError::MailboxNotFound)
    ));
}

#[tokio::test]
async fn a_lost_import_answer_is_uncertain() {
    let fake = FakeJmap::start().await;
    let provider = fake
        .password()
        .with_timeout(Duration::from_millis(300))
        .unwrap();
    let mut session = provider.connect().await.unwrap();
    fake.lock().stall_imports = true;
    let outcome = session
        .apply(
            &CommandBody::Append {
                mailbox: INBOX.into(),
                blob: skein_core::BlobHash::of(&msg(1)),
                flags: Flags::default(),
                received_at: None,
            },
            Some(Bytes::from(msg(1))),
        )
        .await
        .unwrap();
    assert_eq!(outcome, WriteOutcome::Uncertain);
}

#[tokio::test]
async fn watches_through_the_event_source() {
    let fake = FakeJmap::start().await;
    let provider = fake.password();
    let mut watch = provider.watch(&[INBOX.into()]).await.unwrap().unwrap();
    let waiting = tokio::spawn(async move { watch.next().await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    fake.add(INBOX, &msg(1), Flags::default()).await;
    let changed = tokio::time::timeout(Duration::from_secs(5), waiting)
        .await
        .expect("the watch woke")
        .unwrap()
        .unwrap();
    assert_eq!(changed.mailboxes, None);

    let quiet = fake.password().with_push_ping(Duration::from_secs(1));
    let mut watch = quiet.watch(&[]).await.unwrap().unwrap();
    assert!(
        matches!(watch.next().await, Err(MailError::Network(_))),
        "silence ends the watch"
    );

    fake.lock().no_events = true;
    assert!(fake.password().watch(&[]).await.unwrap().is_none());
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn never_shows_secrets_or_content() {
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("skein_mail_jmap=trace")
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let fake = FakeJmap::start().await;
    let provider = fake.password();
    conformance(Arc::new(provider.clone()), Arc::new(fake.clone()), INBOX).await;
    write_conformance(
        Arc::new(provider.clone()),
        Arc::new(fake.clone()),
        INBOX,
        "mb-projects",
        None,
    )
    .await;
    let token = fake.token();
    let wrong = fake
        .provider(Credentials::Password {
            secret: "wrong-secret".into(),
        })
        .connect()
        .await
        .err()
        .unwrap();
    let settings = JmapSettings::new("https://jmap.example.org", USER);

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    let shown = format!("{logs}\n{provider:?}\n{token:?}\n{settings:?}\n{wrong}\n{wrong:?}");
    for secret in [
        PASSWORD,
        TOKEN,
        "wrong-secret",
        USER,
        "Subject",
        "Note 1",
        "Inbox",
        INBOX,
        "M0001",
    ] {
        assert!(!shown.contains(secret), "{secret} leaked: {shown}");
    }
}

#[tokio::test]
async fn keeps_the_write_contract() {
    let fake = FakeJmap::start().await;
    fake.add("mb-projects", &msg(1), Flags::default()).await;
    write_conformance(
        Arc::new(fake.password()),
        Arc::new(fake.clone()),
        INBOX,
        "mb-projects",
        None,
    )
    .await;
}

#[tokio::test]
async fn keeps_the_write_contract_under_tight_limits() {
    let fake = FakeJmap::start().await;
    {
        let mut f = fake.lock();
        f.max_objects = 1;
        f.max_calls = 1;
    }
    write_conformance(
        Arc::new(fake.token()),
        Arc::new(fake.clone()),
        INBOX,
        "mb-projects",
        None,
    )
    .await;
}

async fn run(session: &mut Box<dyn MailSession>, command: CommandBody) -> WriteOutcome {
    session.apply(&command, None).await.unwrap()
}

fn failed_with(reason: &str) -> WriteOutcome {
    WriteOutcome::Failed {
        reason: reason.into(),
    }
}

fn mailbox_named(fake: &FakeJmap, name: &str) -> Option<(String, Option<String>)> {
    fake.lock()
        .mailboxes
        .iter()
        .find(|(_, n, ..)| n == name)
        .map(|(id, _, parent, _)| (id.clone(), parent.clone()))
}

#[tokio::test]
async fn reports_capabilities_from_the_mailboxes() {
    let fake = FakeJmap::start().await;
    let mut session = fake.password().connect().await.unwrap();
    let caps = session.capabilities().await.unwrap();
    assert_eq!(
        caps.system_flags,
        vec!["\\Answered", "\\Draft", "\\Flagged", "\\Seen"]
    );
    assert!(caps.keywords && caps.trash && caps.copy && caps.append_received_at && caps.mailboxes);
    assert!(!caps.labels);
    fake.lock().mailboxes.retain(|(id, ..)| id != "mb-trash");
    assert!(!session.capabilities().await.unwrap().trash);
}

#[tokio::test]
async fn trashing_and_copying() {
    let fake = FakeJmap::start().await;
    fake.add(INBOX, &msg(1), Flags::default()).await;
    fake.add(INBOX, &msg(2), Flags::default()).await;
    let one = item(fake.lock().find(INBOX, &msg(1)).unwrap());
    let two = item(fake.lock().find(INBOX, &msg(2)).unwrap());
    let mut session = fake.password().connect().await.unwrap();

    let copy = |from: &str, to: &str| CommandBody::Copy {
        from: from.into(),
        to: to.into(),
        items: vec![one.clone()],
    };
    assert_eq!(
        run(&mut session, copy(INBOX, "mb-projects")).await,
        WriteOutcome::Applied
    );
    assert_eq!(
        fake.lock().emails[&one.id].mailboxes,
        BTreeSet::from([INBOX.to_owned(), "mb-projects".to_owned()])
    );
    assert_eq!(
        run(&mut session, copy(INBOX, "mb-nowhere")).await,
        failed_with("no_such_mailbox")
    );
    assert!(matches!(
        session.apply(&copy("mb-nowhere", INBOX), None).await,
        Err(MailError::MailboxNotFound)
    ));

    let trash = |mailbox: &str, items: Vec<ItemRef>| CommandBody::Delete {
        mailbox: mailbox.into(),
        items,
        to_trash: true,
    };
    assert_eq!(
        run(
            &mut session,
            trash(INBOX, vec![one.clone(), item("M9999".into())])
        )
        .await,
        WriteOutcome::Applied
    );
    assert_eq!(
        fake.lock().emails[&one.id].mailboxes,
        BTreeSet::from(["mb-trash".to_owned()]),
        "a trashed email is in the trash only"
    );
    assert_eq!(
        run(&mut session, trash("mb-trash", vec![one.clone()])).await,
        WriteOutcome::Applied
    );
    assert!(
        fake.lock().emails.contains_key(&one.id),
        "it stays in the trash"
    );
    assert!(matches!(
        session
            .apply(&trash("mb-nowhere", vec![two.clone()]), None)
            .await,
        Err(MailError::MailboxNotFound)
    ));
    fake.lock().mailboxes.retain(|(id, ..)| id != "mb-trash");
    assert_eq!(
        run(&mut session, trash(INBOX, vec![two.clone()])).await,
        failed_with("no_trash")
    );
    assert!(fake.lock().emails[&two.id].mailboxes.contains(INBOX));
}

#[tokio::test]
async fn missing_mailboxes_change_nothing() {
    let fake = FakeJmap::start().await;
    fake.add(INBOX, &msg(1), Flags::default()).await;
    let one = item(fake.lock().find(INBOX, &msg(1)).unwrap());
    let mut session = fake.password().connect().await.unwrap();
    for command in [
        CommandBody::SetFlags {
            mailbox: "mb-nowhere".into(),
            items: vec![one.clone()],
            add: Flags::new(["\\Seen"]),
            remove: Flags::default(),
        },
        CommandBody::Move {
            from: "mb-nowhere".into(),
            to: INBOX.into(),
            items: vec![one.clone()],
        },
        CommandBody::Delete {
            mailbox: "mb-nowhere".into(),
            items: vec![one.clone()],
            to_trash: false,
        },
        CommandBody::RenameMailbox {
            mailbox: "mb-nowhere".into(),
            path: "Elsewhere".into(),
        },
        CommandBody::DeleteMailbox {
            mailbox: "mb-nowhere".into(),
        },
    ] {
        assert!(
            matches!(
                session.apply(&command, None).await,
                Err(MailError::MailboxNotFound)
            ),
            "{command:?}"
        );
    }
    assert!(fake.flags_of(INBOX, &msg(1)).await.unwrap().is_empty());
}

#[tokio::test]
async fn creates_renames_and_deletes_mailboxes() {
    let fake = FakeJmap::start().await;
    let mut session = fake.password().connect().await.unwrap();
    let create = |path: &str| CommandBody::CreateMailbox { path: path.into() };

    assert_eq!(
        run(&mut session, create("Clients/North/Ada")).await,
        WriteOutcome::Applied
    );
    let (clients, top) = mailbox_named(&fake, "Clients").unwrap();
    let (north, under) = mailbox_named(&fake, "North").unwrap();
    let (ada, leaf) = mailbox_named(&fake, "Ada").unwrap();
    assert_eq!(
        (top, under, leaf),
        (None, Some(clients.clone()), Some(north.clone()))
    );
    assert_eq!(
        run(&mut session, create("Inbox/Projects")).await,
        failed_with("exists")
    );
    assert_eq!(
        run(&mut session, create("Inbox/Projects/2026")).await,
        WriteOutcome::Applied
    );
    for bad in ["", "a//b", "/top", "end/"] {
        assert_eq!(
            run(&mut session, create(bad)).await,
            failed_with("invalid_path"),
            "{bad}"
        );
    }

    let rename = |mailbox: &str, path: &str| CommandBody::RenameMailbox {
        mailbox: mailbox.into(),
        path: path.into(),
    };
    assert_eq!(
        run(&mut session, rename(INBOX, "Mail")).await,
        failed_with("protected")
    );
    assert_eq!(
        run(&mut session, rename(&ada, "Inbox/Projects")).await,
        failed_with("exists")
    );
    assert_eq!(
        run(&mut session, rename(&clients, "Clients/North/Deeper")).await,
        failed_with("invalid_path")
    );
    assert_eq!(
        run(&mut session, rename(&ada, "Clients/North/Ada")).await,
        WriteOutcome::Applied
    );
    assert_eq!(
        run(&mut session, rename(&ada, "Archive/2026/Ada Lovelace")).await,
        WriteOutcome::Applied
    );
    let (archive, _) = mailbox_named(&fake, "Archive").unwrap();
    let year = fake
        .lock()
        .mailboxes
        .iter()
        .find(|(_, n, p, _)| n == "2026" && p.as_deref() == Some(archive.as_str()))
        .map(|(id, ..)| id.clone())
        .unwrap();
    assert_eq!(
        mailbox_named(&fake, "Ada Lovelace"),
        Some((ada.clone(), Some(year)))
    );
    let paths: Vec<String> = session
        .mailboxes()
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.path)
        .collect();
    assert!(
        paths.contains(&"Archive/2026/Ada Lovelace".to_owned()),
        "{paths:?}"
    );

    let delete = |mailbox: &str| CommandBody::DeleteMailbox {
        mailbox: mailbox.into(),
    };
    assert_eq!(
        run(&mut session, delete("mb-trash")).await,
        failed_with("protected")
    );
    assert_eq!(
        run(&mut session, delete(&clients)).await,
        failed_with("has_children")
    );
    fake.add(&north, &msg(1), Flags::default()).await;
    fake.add(&north, &msg(2), Flags::default()).await;
    let kept = fake.lock().find(&north, &msg(2)).unwrap();
    fake.lock()
        .emails
        .get_mut(&kept)
        .unwrap()
        .mailboxes
        .insert(INBOX.into());
    assert_eq!(
        run(&mut session, delete(&north)).await,
        WriteOutcome::Applied
    );
    assert!(mailbox_named(&fake, "North").is_none());
    assert!(fake.lock().find(&north, &msg(1)).is_none());
    assert!(
        fake.lock().find(INBOX, &msg(1)).is_none(),
        "an email only there is gone"
    );
    assert_eq!(
        fake.lock().emails[&kept].mailboxes,
        BTreeSet::from([INBOX.to_owned()]),
        "an email also elsewhere stays there"
    );
}

#[tokio::test]
async fn appends_with_the_received_time() {
    let fake = FakeJmap::start().await;
    let mut session = fake.password().connect().await.unwrap();
    let outcome = session
        .apply(
            &CommandBody::Append {
                mailbox: INBOX.into(),
                blob: skein_core::BlobHash::of(&msg(1)),
                flags: Flags::new(["$Forwarded"]),
                received_at: Some(skein_core::Timestamp(1_740_821_405_250)),
            },
            Some(Bytes::from(msg(1))),
        )
        .await
        .unwrap();
    assert_eq!(outcome, WriteOutcome::Applied);
    let id = fake.lock().find(INBOX, &msg(1)).unwrap();
    assert_eq!(fake.lock().emails[&id].received, "2025-03-01T09:30:05Z");
    assert_eq!(
        fake.flags_of(INBOX, &msg(1)).await.unwrap(),
        Flags::new(["$Forwarded"])
    );
}
