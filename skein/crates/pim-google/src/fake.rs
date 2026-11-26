//! An in-process fake of the parts of the Calendar API v3 and People API v1 the provider uses:
//! sync tokens that can be expired, cancelled events, deleted contacts, `If-Match` and etag
//! preconditions, `sendUpdates`, attendee patches, the primary calendar, access roles,
//! throttling and redirects on demand. Objects are stored and served pretty-printed, so a
//! provider that re-serialized them would no longer match byte for byte.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};
use skein_core::ItemRef;
use skein_pim::testing::PimServerControl;

use crate::CONTACTS;

pub(crate) const TOKEN: &str = "ya29.test-token";
pub(crate) const PRIMARY: &str = "ada@example.com";
pub(crate) const HOLIDAYS: &str = "en.usa#holiday@group.v.calendar.example.com";

pub(crate) struct Event {
    seq: u64,
    fields: Map<String, Value>,
    cancelled: bool,
}

pub(crate) struct Cal {
    summary: String,
    color: String,
    role: &'static str,
    events: BTreeMap<String, Event>,
    generation: u64,
}

pub(crate) struct Person {
    seq: u64,
    fields: Map<String, Value>,
    deleted: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct Req {
    pub method: String,
    pub path: String,
    pub query: String,
    pub authorized: bool,
    pub if_match: Option<String>,
    pub send_updates: Option<String>,
    pub body: Vec<u8>,
}

#[derive(Default)]
pub(crate) struct FakeState {
    pub cals: BTreeMap<String, Cal>,
    pub people: BTreeMap<String, Person>,
    pub people_generation: u64,
    pub seq: u64,
    pub expire_with_410: bool,
    pub throttle: Option<(u16, &'static str, Option<u64>)>,
    pub redirect: Option<String>,
    pub primary: Option<String>,
    pub requests: Vec<Req>,
}

#[derive(Clone)]
pub(crate) struct FakeGoogle {
    pub state: Arc<Mutex<FakeState>>,
    pub url: String,
}

fn etag(seq: u64) -> String {
    format!("\"{seq}\"")
}

fn person_etag(seq: u64) -> String {
    format!("%EgUBAj0{seq}")
}

fn pretty(v: &Value) -> Vec<u8> {
    serde_json::to_vec_pretty(v).unwrap()
}

impl Event {
    fn render(&self, id: &str) -> Vec<u8> {
        if self.cancelled {
            return pretty(&json!({
                "kind": "calendar#event", "etag": etag(self.seq), "id": id, "status": "cancelled"
            }));
        }
        let mut m = self.fields.clone();
        m.insert("kind".into(), json!("calendar#event"));
        m.insert("id".into(), json!(id));
        m.insert("etag".into(), json!(etag(self.seq)));
        m.entry("status").or_insert(json!("confirmed"));
        pretty(&Value::Object(m))
    }
}

impl Person {
    fn render(&self, rn: &str) -> Vec<u8> {
        if self.deleted {
            return pretty(&json!({
                "resourceName": rn, "etag": person_etag(self.seq), "metadata": { "deleted": true }
            }));
        }
        let mut m = self.fields.clone();
        m.insert("resourceName".into(), json!(rn));
        m.insert("etag".into(), json!(person_etag(self.seq)));
        m.insert(
            "metadata".into(),
            json!({ "sources": [{ "type": "CONTACT", "id": rn.trim_start_matches("people/") }], "objectType": "PERSON" }),
        );
        pretty(&Value::Object(m))
    }
}

fn error(status: u16, reason: &str, status_name: &str) -> Response {
    let body = json!({ "error": {
        "code": status,
        "message": "ada@example.com: Planning meeting with Test Person",
        "errors": [{ "domain": "global", "reason": reason, "message": "secret" }],
        "status": status_name,
        "details": [{ "@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": reason }]
    } });
    (
        StatusCode::from_u16(status).unwrap(),
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

fn ok_bytes(bytes: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json; charset=UTF-8")],
        bytes,
    )
        .into_response()
}

fn decode(segment: &str) -> String {
    let b = segment.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(n) =
                u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16)
        {
            out.push(n);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap()
}

fn object(body: &[u8]) -> Option<Map<String, Value>> {
    match serde_json::from_slice(body) {
        Ok(Value::Object(m)) => Some(m),
        _ => None,
    }
}

fn valid_event_id(id: &str) -> bool {
    (5..=1024).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'v').contains(&b))
}

/// A listing page: `items` joined as they are, then the page or sync token.
fn page(list_key: &str, items: &[Vec<u8>], next: (&str, String), extra: &str) -> Vec<u8> {
    let mut out = format!("{{{extra}");
    if !items.is_empty() {
        out.push_str(&format!("\"{list_key}\": [\n"));
        let joined: Vec<String> = items
            .iter()
            .map(|b| String::from_utf8(b.clone()).unwrap())
            .collect();
        out.push_str(&joined.join(",\n"));
        out.push_str("\n],");
    }
    out.push_str(&format!(
        "\"{}\": {}}}",
        next.0,
        serde_json::to_string(&next.1).unwrap()
    ));
    out.into_bytes()
}

struct Window {
    since: Option<u64>,
    upto: u64,
    offset: usize,
}

enum TokenError {
    Expired,
    Invalid,
}

fn window(
    generation: u64,
    seq: u64,
    sync: Option<&String>,
    page: Option<&String>,
) -> Result<Window, TokenError> {
    if let Some(p) = page {
        let parts: Vec<&str> = p.split('|').collect();
        let [g, since, upto, offset] = parts[..] else {
            return Err(TokenError::Invalid);
        };
        if g.parse::<u64>().map_err(|_| TokenError::Invalid)? != generation {
            return Err(TokenError::Expired);
        }
        return Ok(Window {
            since: if since.is_empty() {
                None
            } else {
                Some(since.parse().map_err(|_| TokenError::Invalid)?)
            },
            upto: upto.parse().map_err(|_| TokenError::Invalid)?,
            offset: offset.parse().map_err(|_| TokenError::Invalid)?,
        });
    }
    if let Some(s) = sync {
        let (g, s) = s.split_once(':').ok_or(TokenError::Invalid)?;
        if g.parse::<u64>().map_err(|_| TokenError::Invalid)? != generation {
            return Err(TokenError::Expired);
        }
        return Ok(Window {
            since: Some(s.parse().map_err(|_| TokenError::Invalid)?),
            upto: seq,
            offset: 0,
        });
    }
    Ok(Window {
        since: None,
        upto: seq,
        offset: 0,
    })
}

fn next_token(generation: u64, w: &Window, max: usize, total: usize) -> (&'static str, String) {
    if w.offset + max < total {
        (
            "nextPageToken",
            format!(
                "{generation}|{}|{}|{}",
                w.since.map(|s| s.to_string()).unwrap_or_default(),
                w.upto,
                w.offset + max
            ),
        )
    } else {
        ("nextSyncToken", format!("{generation}:{}", w.upto))
    }
}

impl FakeState {
    fn bump(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    pub(crate) fn add_calendar(&mut self, id: &str, summary: &str, role: &'static str) {
        self.cals.insert(
            id.into(),
            Cal {
                summary: summary.into(),
                color: "#9fe1e7".into(),
                role,
                events: BTreeMap::new(),
                generation: 1,
            },
        );
    }

    pub(crate) fn put_event(&mut self, cal: &str, id: &str, fields: Map<String, Value>) -> u64 {
        let seq = self.bump();
        self.cals.get_mut(cal).unwrap().events.insert(
            id.into(),
            Event {
                seq,
                fields,
                cancelled: false,
            },
        );
        seq
    }

    fn calendar(
        &mut self,
        method: &Method,
        rest: &[String],
        q: &Query,
        h: &HeaderMap,
        body: &[u8],
    ) -> Response {
        match (method, rest) {
            (&Method::GET, [users, me, list])
                if users == "users" && me == "me" && list == "calendarList" =>
            {
                let items: Vec<Value> = self
                    .cals
                    .iter()
                    .map(|(id, c)| {
                        json!({ "kind": "calendar#calendarListEntry", "id": id, "summary": c.summary,
                                "backgroundColor": c.color, "accessRole": c.role })
                    })
                    .collect();
                let max = q
                    .get("maxResults")
                    .and_then(|m| m.parse().ok())
                    .unwrap_or(100usize);
                let offset = q
                    .get("pageToken")
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(0usize);
                let mut out = json!({ "kind": "calendar#calendarList",
                    "items": items.iter().skip(offset).take(max).collect::<Vec<_>>() });
                if offset + max < items.len() {
                    out["nextPageToken"] = json!((offset + max).to_string());
                }
                ok_bytes(out.to_string().into_bytes())
            }
            (&Method::GET, [users, me, list, primary])
                if users == "users"
                    && me == "me"
                    && list == "calendarList"
                    && primary == "primary" =>
            {
                match &self.primary {
                    Some(id) => ok_bytes(pretty(&json!({
                        "kind": "calendar#calendarListEntry", "id": id, "summary": "Ada",
                        "accessRole": "owner", "primary": true
                    }))),
                    None => error(404, "notFound", "NOT_FOUND"),
                }
            }
            (_, [cals, cal, events, tail @ ..]) if cals == "calendars" && events == "events" => {
                let seq = self.seq;
                let Some(c) = self.cals.get(cal) else {
                    return error(404, "notFound", "NOT_FOUND");
                };
                let writer = matches!(c.role, "owner" | "writer");
                match (method, tail) {
                    (&Method::GET, []) => {
                        let w =
                            match window(c.generation, seq, q.get("syncToken"), q.get("pageToken"))
                            {
                                Ok(w) => w,
                                Err(TokenError::Expired) => {
                                    return error(410, "fullSyncRequired", "GONE");
                                }
                                Err(TokenError::Invalid) => {
                                    return error(400, "invalid", "INVALID_ARGUMENT");
                                }
                            };
                        let show_deleted =
                            w.since.is_some() || q.get("showDeleted").is_some_and(|v| v == "true");
                        let mut evs: Vec<(&String, &Event)> = c
                            .events
                            .iter()
                            .filter(|(_, e)| e.seq <= w.upto && w.since.is_none_or(|s| e.seq > s))
                            .filter(|(_, e)| show_deleted || !e.cancelled)
                            .collect();
                        evs.sort_by_key(|(_, e)| e.seq);
                        let max = q
                            .get("maxResults")
                            .and_then(|m| m.parse().ok())
                            .unwrap_or(250usize)
                            .max(1);
                        let items: Vec<Vec<u8>> = evs
                            .iter()
                            .skip(w.offset)
                            .take(max)
                            .map(|(id, e)| e.render(id))
                            .collect();
                        let next = next_token(c.generation, &w, max, evs.len());
                        ok_bytes(page(
                            "items",
                            &items,
                            next,
                            "\"kind\": \"calendar#events\",\n\"summary\": \"Work\",\n",
                        ))
                    }
                    (&Method::POST, []) => {
                        if !writer {
                            return error(403, "requiredAccessLevel", "PERMISSION_DENIED");
                        }
                        let Some(mut fields) = object(body) else {
                            return error(400, "parseError", "INVALID_ARGUMENT");
                        };
                        let id = match fields.remove("id") {
                            Some(Value::String(id)) => id,
                            _ => format!("ev{:05}", self.seq + 1),
                        };
                        if !valid_event_id(&id) {
                            return error(400, "invalid", "INVALID_ARGUMENT");
                        }
                        if c.events.contains_key(&id) {
                            return error(409, "duplicate", "ALREADY_EXISTS");
                        }
                        fields.remove("etag");
                        let cal = cal.clone();
                        self.put_event(&cal, &id, fields);
                        ok_bytes(self.cals[&cal].events[&id].render(&id))
                    }
                    (_, [id]) => {
                        let id = id.clone();
                        let cal = cal.clone();
                        let Some(e) = c.events.get(&id) else {
                            return error(404, "notFound", "NOT_FOUND");
                        };
                        let if_match = h.get(header::IF_MATCH).and_then(|v| v.to_str().ok());
                        let stale = if_match.is_some_and(|m| m != etag(e.seq));
                        match *method {
                            Method::GET => ok_bytes(e.render(&id)),
                            Method::PUT => {
                                if !writer {
                                    return error(403, "requiredAccessLevel", "PERMISSION_DENIED");
                                }
                                if stale {
                                    return error(412, "conditionNotMet", "FAILED_PRECONDITION");
                                }
                                let Some(mut fields) = object(body) else {
                                    return error(400, "parseError", "INVALID_ARGUMENT");
                                };
                                fields.remove("id");
                                fields.remove("etag");
                                self.put_event(&cal, &id, fields);
                                ok_bytes(self.cals[&cal].events[&id].render(&id))
                            }
                            Method::PATCH => {
                                if e.cancelled {
                                    return error(410, "deleted", "GONE");
                                }
                                if stale {
                                    return error(412, "conditionNotMet", "FAILED_PRECONDITION");
                                }
                                let Some(patch) = object(body) else {
                                    return error(400, "parseError", "INVALID_ARGUMENT");
                                };
                                let mut fields = e.fields.clone();
                                for (k, v) in patch {
                                    if !matches!(k.as_str(), "id" | "etag" | "kind") {
                                        fields.insert(k, v);
                                    }
                                }
                                self.put_event(&cal, &id, fields);
                                ok_bytes(self.cals[&cal].events[&id].render(&id))
                            }
                            Method::DELETE => {
                                if !writer {
                                    return error(403, "requiredAccessLevel", "PERMISSION_DENIED");
                                }
                                if e.cancelled {
                                    return error(410, "deleted", "GONE");
                                }
                                if stale {
                                    return error(412, "conditionNotMet", "FAILED_PRECONDITION");
                                }
                                let seq = self.bump();
                                let e = self
                                    .cals
                                    .get_mut(&cal)
                                    .unwrap()
                                    .events
                                    .get_mut(&id)
                                    .unwrap();
                                e.seq = seq;
                                e.cancelled = true;
                                StatusCode::NO_CONTENT.into_response()
                            }
                            _ => error(405, "methodNotAllowed", "INVALID_ARGUMENT"),
                        }
                    }
                    _ => error(404, "notFound", "NOT_FOUND"),
                }
            }
            _ => error(404, "notFound", "NOT_FOUND"),
        }
    }

    fn people_api(&mut self, method: &Method, rest: &[String], q: &Query, body: &[u8]) -> Response {
        let segs: Vec<&str> = rest.iter().map(String::as_str).collect();
        match (method, segs.as_slice()) {
            (&Method::GET, ["people", "me", "connections"]) => {
                if q.get("personFields").is_none() {
                    return error(400, "personFields", "INVALID_ARGUMENT");
                }
                let w = match window(
                    self.people_generation,
                    self.seq,
                    q.get("syncToken"),
                    q.get("pageToken"),
                ) {
                    Ok(w) => w,
                    Err(TokenError::Expired) if self.expire_with_410 => {
                        return error(410, "EXPIRED_SYNC_TOKEN", "GONE");
                    }
                    Err(TokenError::Expired) => {
                        return error(400, "EXPIRED_SYNC_TOKEN", "FAILED_PRECONDITION");
                    }
                    Err(TokenError::Invalid) => {
                        return error(400, "badRequest", "INVALID_ARGUMENT");
                    }
                };
                let mut ps: Vec<(&String, &Person)> = self
                    .people
                    .iter()
                    .filter(|(_, p)| p.seq <= w.upto && w.since.is_none_or(|s| p.seq > s))
                    .filter(|(_, p)| w.since.is_some() || !p.deleted)
                    .collect();
                ps.sort_by_key(|(_, p)| p.seq);
                let max = q
                    .get("pageSize")
                    .and_then(|m| m.parse().ok())
                    .unwrap_or(100usize)
                    .max(1);
                let items: Vec<Vec<u8>> = ps
                    .iter()
                    .skip(w.offset)
                    .take(max)
                    .map(|(rn, p)| p.render(rn))
                    .collect();
                let next = next_token(self.people_generation, &w, max, ps.len());
                let extra = format!("\"totalPeople\": {},\n", ps.len());
                ok_bytes(page("connections", &items, next, &extra))
            }
            (&Method::GET, ["people:batchGet"]) => {
                let mut out = String::from("{\"responses\": [");
                let names = q.all("resourceNames");
                for (i, rn) in names.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    match self.people.get(rn.as_str()).filter(|p| !p.deleted) {
                        Some(p) => out.push_str(&format!(
                            "{{\"httpStatusCode\": 200, \"person\": {}, \"requestedResourceName\": {}}}",
                            String::from_utf8(p.render(rn)).unwrap(),
                            serde_json::to_string(rn).unwrap()
                        )),
                        None => out.push_str(&format!(
                            "{{\"httpStatusCode\": 404, \"requestedResourceName\": {}, \"status\": {{\"code\": 5, \"message\": \"Requested entity was not found.\"}}}}",
                            serde_json::to_string(rn).unwrap()
                        )),
                    }
                }
                out.push_str("]}");
                ok_bytes(out.into_bytes())
            }
            (&Method::POST, ["people:createContact"]) => {
                let Some(mut fields) = object(body) else {
                    return error(400, "invalid", "INVALID_ARGUMENT");
                };
                for k in ["resourceName", "etag", "metadata"] {
                    fields.remove(k);
                }
                let seq = self.bump();
                let rn = format!("people/c{seq}");
                self.people.insert(
                    rn.clone(),
                    Person {
                        seq,
                        fields,
                        deleted: false,
                    },
                );
                ok_bytes(self.people[&rn].render(&rn))
            }
            (_, ["people", tail]) => {
                let (contact, verb) = tail.split_once(':').unwrap_or((tail, ""));
                let rn = format!("people/{contact}");
                let Some(p) = self.people.get(&rn).filter(|p| !p.deleted) else {
                    return error(404, "notFound", "NOT_FOUND");
                };
                match (method, verb) {
                    (&Method::GET, "") => ok_bytes(p.render(&rn)),
                    (&Method::PATCH, "updateContact") => {
                        let Some(update) = q.get("updatePersonFields") else {
                            return error(400, "updatePersonFields", "INVALID_ARGUMENT");
                        };
                        let Some(fields) = object(body) else {
                            return error(400, "invalid", "INVALID_ARGUMENT");
                        };
                        match fields.get("etag").and_then(Value::as_str) {
                            None => return error(400, "etag", "INVALID_ARGUMENT"),
                            Some(e) if e != person_etag(p.seq) => {
                                return error(400, "failedPrecondition", "FAILED_PRECONDITION");
                            }
                            Some(_) => {}
                        }
                        let update: Vec<String> = update.split(',').map(str::to_owned).collect();
                        let seq = self.bump();
                        let p = self.people.get_mut(&rn).unwrap();
                        for f in update {
                            match fields.get(&f) {
                                Some(v) => {
                                    p.fields.insert(f, v.clone());
                                }
                                None => {
                                    p.fields.remove(&f);
                                }
                            }
                        }
                        p.seq = seq;
                        ok_bytes(p.render(&rn))
                    }
                    (&Method::DELETE, "deleteContact") => {
                        let seq = self.bump();
                        let p = self.people.get_mut(&rn).unwrap();
                        p.seq = seq;
                        p.deleted = true;
                        ok_bytes(b"{}".to_vec())
                    }
                    _ => error(404, "notFound", "NOT_FOUND"),
                }
            }
            _ => error(404, "notFound", "NOT_FOUND"),
        }
    }
}

pub(crate) struct Query(Vec<(String, String)>);

impl Query {
    fn get(&self, key: &str) -> Option<&String> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    fn all(&self, key: &str) -> Vec<String> {
        self.0
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .collect()
    }
}

async fn handle(
    State(fake): State<FakeGoogle>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut st = fake.state.lock().unwrap();
    let authorized = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        == Some(&format!("Bearer {TOKEN}"));
    st.requests.push(Req {
        method: method.to_string(),
        path: uri.path().to_owned(),
        query: uri.query().unwrap_or("").to_owned(),
        authorized,
        if_match: headers
            .get(header::IF_MATCH)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
        send_updates: url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes())
            .find(|(k, _)| k == "sendUpdates")
            .map(|(_, v)| v.into_owned()),
        body: body.to_vec(),
    });
    if headers.contains_key(header::AUTHORIZATION) && !authorized {
        return error(401, "authError", "UNAUTHENTICATED");
    }
    if let Some(to) = st.redirect.take() {
        return (StatusCode::FOUND, [(header::LOCATION, to)]).into_response();
    }
    if !authorized {
        return error(401, "required", "UNAUTHENTICATED");
    }
    if let Some((status, reason, retry)) = st.throttle.take() {
        let mut r = error(status, reason, "RESOURCE_EXHAUSTED");
        if let Some(s) = retry {
            r.headers_mut()
                .insert(header::RETRY_AFTER, s.to_string().parse().unwrap());
        }
        return r;
    }
    let query = Query(
        url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect(),
    );
    let segs: Vec<String> = uri
        .path()
        .trim_start_matches('/')
        .split('/')
        .map(decode)
        .collect();
    match segs.as_slice() {
        [c, v, rest @ ..] if c == "calendar" && v == "v3" => {
            st.calendar(&method, rest, &query, &headers, &body)
        }
        [v, rest @ ..] if v == "v1" => st.people_api(&method, rest, &query, &body),
        _ => error(404, "notFound", "NOT_FOUND"),
    }
}

impl FakeGoogle {
    /// Both APIs on one loopback port, with a writable primary calendar, a read-only holiday
    /// calendar and an empty address book.
    pub(crate) async fn start() -> Self {
        let mut st = FakeState {
            people_generation: 1,
            primary: Some(PRIMARY.into()),
            ..FakeState::default()
        };
        st.add_calendar(PRIMARY, "Ada", "owner");
        st.add_calendar(HOLIDAYS, "Holidays", "reader");
        let state = Arc::new(Mutex::new(st));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let fake = Self { state, url };
        let app = Router::new().fallback(handle).with_state(fake.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        fake
    }

    pub(crate) fn requests(&self) -> Vec<Req> {
        self.state.lock().unwrap().requests.clone()
    }

    pub(crate) fn clear_requests(&self) {
        self.state.lock().unwrap().requests.clear();
    }
}

#[async_trait]
impl PimServerControl for FakeGoogle {
    async fn put(&self, collection: &str, name: &str, bytes: &[u8]) {
        let fields = object(bytes).expect("the fake stores JSON objects");
        let mut st = self.state.lock().unwrap();
        if collection == CONTACTS {
            let seq = st.bump();
            st.people.insert(
                format!("people/{name}"),
                Person {
                    seq,
                    fields,
                    deleted: false,
                },
            );
        } else {
            st.put_event(collection, name, fields);
        }
    }

    async fn remove(&self, collection: &str, name: &str) {
        let mut st = self.state.lock().unwrap();
        let seq = st.seq + 1;
        if collection == CONTACTS {
            if let Some(p) = st
                .people
                .get_mut(&format!("people/{name}"))
                .filter(|p| !p.deleted)
            {
                p.deleted = true;
                p.seq = seq;
                st.seq = seq;
            }
        } else if let Some(e) = st
            .cals
            .get_mut(collection)
            .and_then(|c| c.events.get_mut(name))
            .filter(|e| !e.cancelled)
        {
            e.cancelled = true;
            e.seq = seq;
            st.seq = seq;
        }
    }

    async fn invalidate(&self, collection: &str) -> bool {
        let mut st = self.state.lock().unwrap();
        if collection == CONTACTS {
            st.people_generation += 1;
        } else if let Some(c) = st.cals.get_mut(collection) {
            c.generation += 1;
        }
        true
    }

    async fn read(
        &self,
        collection: &str,
        item: &ItemRef,
    ) -> Option<(Option<String>, bytes::Bytes)> {
        let st = self.state.lock().unwrap();
        if collection == CONTACTS {
            let p = st.people.get(&item.id).filter(|p| !p.deleted)?;
            return Some((
                Some(person_etag(p.seq)),
                bytes::Bytes::from(p.render(&item.id)),
            ));
        }
        let e = st
            .cals
            .get(collection)?
            .events
            .get(&item.id)
            .filter(|e| !e.cancelled)?;
        Some((Some(etag(e.seq)), bytes::Bytes::from(e.render(&item.id))))
    }

    async fn contents(&self, collection: &str) -> Vec<bytes::Bytes> {
        let st = self.state.lock().unwrap();
        let mut out: Vec<bytes::Bytes> = if collection == CONTACTS {
            st.people
                .iter()
                .filter(|(_, p)| !p.deleted)
                .map(|(rn, p)| bytes::Bytes::from(p.render(rn)))
                .collect()
        } else {
            st.cals
                .get(collection)
                .map(|c| {
                    c.events
                        .iter()
                        .filter(|(_, e)| !e.cancelled)
                        .map(|(id, e)| bytes::Bytes::from(e.render(id)))
                        .collect()
                })
                .unwrap_or_default()
        };
        out.sort();
        out
    }
}
