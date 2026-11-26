//! An in-process fake of the parts of the Gmail API the provider uses, with a growing history
//! log, history expiry, scopes, throttling and redirects on demand.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use serde_json::{Value, json};
use skein_core::Flags;
use skein_mail::testing::ServerControl;

use crate::labels;

pub(crate) const TOKEN: &str = "ya29.test-token";
/// The time the fake's watches start from.
pub(crate) const WATCH_NOW: i64 = 1_800_000_000_000;

#[derive(Clone)]
pub(crate) struct Msg {
    pub id: String,
    pub raw: Vec<u8>,
    pub labels: BTreeSet<String>,
    pub internal: i64,
}

pub(crate) struct FakeState {
    pub msgs: BTreeMap<u64, Msg>,
    pub labels: Vec<(String, String, &'static str)>,
    next_label: u32,
    next: u64,
    pub history_id: u64,
    pub expired_below: u64,
    pub history: Vec<(u64, Value)>,
    pub full_scope: bool,
    pub throttle: Option<(u16, Option<&'static str>, Option<u64>)>,
    pub fail_status: Option<u16>,
    pub redirect: Option<String>,
    pub requests: Vec<String>,
    pub authorized: Vec<bool>,
    pub watch: Option<(String, i64)>,
    pub watches: u32,
    pub stops: u32,
    pub publish_denied: bool,
}

#[derive(Clone)]
pub(crate) struct FakeGmail {
    pub state: Arc<Mutex<FakeState>>,
    pub url: String,
}

fn system(id: &str) -> (String, String, &'static str) {
    (id.into(), id.into(), "system")
}

fn flag_labels(flags: &Flags) -> Vec<&'static str> {
    let mut out = Vec::new();
    if !flags.contains("\\Seen") {
        out.push(labels::UNREAD);
    }
    if flags.contains("\\Flagged") {
        out.push(labels::STARRED);
    }
    if flags.contains("\\Draft") {
        out.push(labels::DRAFT);
    }
    out
}

fn msg_json(m: &Msg) -> Value {
    json!({ "id": m.id, "threadId": m.id, "labelIds": m.labels.iter().collect::<Vec<_>>() })
}

fn error(status: u16, reason: &str) -> Response {
    let body = json!({ "error": { "code": status, "message": "ada@example.com: Subject line here", "errors": [{ "reason": reason }] } });
    (
        StatusCode::from_u16(status).unwrap(),
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

fn ok(value: Value) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        value.to_string(),
    )
        .into_response()
}

fn empty() -> Response {
    StatusCode::NO_CONTENT.into_response()
}

impl FakeState {
    fn find(&self, id: &str) -> Option<u64> {
        self.msgs.iter().find(|(_, m)| m.id == id).map(|(k, _)| *k)
    }

    fn find_raw(&self, raw: &[u8]) -> Option<u64> {
        self.msgs
            .iter()
            .find(|(_, m)| m.raw == raw)
            .map(|(k, _)| *k)
    }

    fn record(&mut self, mut record: Value) {
        self.history_id += 1;
        record["id"] = json!(self.history_id.to_string());
        self.history.push((self.history_id, record));
    }

    pub(crate) fn insert(&mut self, raw: &[u8], labels: &[&str]) -> String {
        self.next += 1;
        let key = self.next;
        let id = format!("{:x}", 0x18c0_0000_0000_0000u64 + key * 0x10_0000);
        let m = Msg {
            id: id.clone(),
            raw: raw.to_vec(),
            labels: labels.iter().map(|l| (*l).to_owned()).collect(),
            internal: 1_700_000_000_000 + key as i64 * 1000,
        };
        let j = msg_json(&m);
        self.msgs.insert(key, m);
        self.record(json!({ "messages": [j.clone()], "messagesAdded": [{ "message": j }] }));
        id
    }

    pub(crate) fn delete(&mut self, key: u64) {
        if let Some(m) = self.msgs.remove(&key) {
            let j = msg_json(&m);
            self.record(json!({ "messages": [j.clone()], "messagesDeleted": [{ "message": j }] }));
        }
    }

    pub(crate) fn modify(&mut self, key: u64, add: &[String], remove: &[String]) {
        let Some(m) = self.msgs.get_mut(&key) else {
            return;
        };
        let before = m.labels.clone();
        for r in remove {
            m.labels.remove(r);
        }
        for a in add {
            m.labels.insert(a.clone());
        }
        let added: Vec<&String> = m.labels.difference(&before).collect();
        let removed: Vec<&String> = before.difference(&m.labels).collect();
        if added.is_empty() && removed.is_empty() {
            return;
        }
        let j = msg_json(m);
        let mut record = json!({ "messages": [j.clone()] });
        if !added.is_empty() {
            record["labelsAdded"] = json!([{ "message": j.clone(), "labelIds": added }]);
        }
        if !removed.is_empty() {
            record["labelsRemoved"] = json!([{ "message": j, "labelIds": removed }]);
        }
        self.record(record);
    }

    pub(crate) fn add_label(&mut self, name: &str) -> String {
        self.next_label += 1;
        let id = format!("Label_{}", self.next_label);
        self.labels.push((id.clone(), name.into(), "user"));
        id
    }

    fn name_taken(&self, name: &str, except: &str) -> bool {
        self.labels
            .iter()
            .any(|(id, n, _)| id != except && n.eq_ignore_ascii_case(name))
    }

    fn label_for(&self, mailbox: &str) -> Option<String> {
        if mailbox == crate::ALL {
            return Some(labels::INBOX.into());
        }
        self.labels
            .iter()
            .find(|(id, name, _)| id == mailbox || name == mailbox)
            .map(|(id, ..)| id.clone())
    }
}

impl FakeGmail {
    pub(crate) async fn start() -> Self {
        let state = Arc::new(Mutex::new(FakeState {
            msgs: BTreeMap::new(),
            labels: vec![
                system("INBOX"),
                system("SENT"),
                system("DRAFT"),
                system("IMPORTANT"),
                system("TRASH"),
                system("SPAM"),
                system("UNREAD"),
                system("STARRED"),
                system("CHAT"),
                system("CATEGORY_PERSONAL"),
            ],
            next_label: 0,
            next: 0,
            history_id: 1000,
            expired_below: 0,
            history: Vec::new(),
            full_scope: true,
            throttle: None,
            fail_status: None,
            redirect: None,
            requests: Vec::new(),
            authorized: Vec::new(),
            watch: None,
            watches: 0,
            stops: 0,
            publish_denied: false,
        }));
        let app = Router::new().fallback(handle).with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { state, url }
    }

    pub(crate) fn add_label(&self, name: &str) -> String {
        self.state.lock().unwrap().add_label(name)
    }

    pub(crate) fn insert(&self, raw: &[u8], labels: &[&str]) -> String {
        self.state.lock().unwrap().insert(raw, labels)
    }

    pub(crate) fn labels_of(&self, id: &str) -> Option<BTreeSet<String>> {
        let st = self.state.lock().unwrap();
        st.find(id).map(|k| st.msgs[&k].labels.clone())
    }

    pub(crate) fn modify(&self, id: &str, add: &[&str], remove: &[&str]) {
        let mut st = self.state.lock().unwrap();
        let key = st.find(id).expect("message exists");
        let add: Vec<String> = add.iter().map(|s| (*s).to_owned()).collect();
        let remove: Vec<String> = remove.iter().map(|s| (*s).to_owned()).collect();
        st.modify(key, &add, &remove);
    }

    pub(crate) fn requests(&self) -> Vec<String> {
        self.state.lock().unwrap().requests.clone()
    }
}

fn query(uri: &Uri) -> Vec<(String, String)> {
    url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes())
        .into_owned()
        .collect()
}

fn param<'a>(q: &'a [(String, String)], name: &str) -> Option<&'a str> {
    q.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

fn ids(body: &[u8]) -> (Vec<String>, Vec<String>, Vec<String>) {
    let v: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let list = |k: &str| -> Vec<String> {
        v[k].as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    (list("ids"), list("addLabelIds"), list("removeLabelIds"))
}

/// The JSON metadata and message bytes of a `multipart/related` upload.
fn multipart(content_type: &str, body: &[u8]) -> Option<(Value, Vec<u8>)> {
    let boundary = content_type.split("boundary=").nth(1)?.trim_matches('"');
    let delim = format!("--{boundary}");
    let find = |hay: &[u8], needle: &[u8], from: usize| {
        hay[from..]
            .windows(needle.len())
            .position(|w| w == needle)
            .map(|p| p + from)
    };
    let mut parts = Vec::new();
    let mut at = find(body, delim.as_bytes(), 0)? + delim.len();
    loop {
        if body[at..].starts_with(b"--") {
            break;
        }
        let next = find(body, format!("\r\n{delim}").as_bytes(), at)?;
        let part = &body[at..next];
        let head_end = find(part, b"\r\n\r\n", 0)?;
        parts.push(part[head_end + 4..].to_vec());
        at = next + 2 + delim.len();
    }
    let meta = serde_json::from_slice(parts.first()?).ok()?;
    Some((meta, parts.get(1)?.clone()))
}

async fn handle(
    State(state): State<Arc<Mutex<FakeState>>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut st = state.lock().unwrap();
    let authorized = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        == Some(&format!("Bearer {TOKEN}"));
    st.requests.push(format!("{method} {uri}"));
    st.authorized
        .push(headers.contains_key(header::AUTHORIZATION));
    if let Some(location) = st.redirect.take() {
        return (StatusCode::FOUND, [(header::LOCATION, location)]).into_response();
    }
    if !authorized {
        return error(401, "authError");
    }
    if let Some((status, reason, retry)) = st.throttle.take() {
        let mut r = error(status, reason.unwrap_or("rateLimitExceeded"));
        if let Some(s) = retry {
            r.headers_mut()
                .insert(header::RETRY_AFTER, s.to_string().parse().unwrap());
        }
        return r;
    }
    if let Some(status) = st.fail_status.take() {
        return error(status, "backendError");
    }
    let path = uri.path();
    let (upload, rest) = if let Some(r) = path.strip_prefix("/upload/gmail/v1/users/") {
        (true, r)
    } else if let Some(r) = path.strip_prefix("/gmail/v1/users/") {
        (false, r)
    } else {
        return error(404, "notFound");
    };
    let segs: Vec<&str> = rest.split('/').skip(1).collect();
    let q = query(&uri);
    match (method.as_str(), upload, segs.as_slice()) {
        ("GET", false, ["profile"]) => ok(json!({
            "emailAddress": "ada@example.com",
            "historyId": st.history_id.to_string(),
        })),
        ("GET", false, ["labels"]) => ok(json!({
            "labels": st.labels.iter().map(|(id, name, kind)| json!({ "id": id, "name": name, "type": kind })).collect::<Vec<_>>(),
        })),
        ("POST", false, ["labels"]) => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let Some(name) = v["name"].as_str().filter(|n| !n.is_empty()) else {
                return error(400, "invalidArgument");
            };
            if st.name_taken(name, "") {
                return error(409, "conflict");
            }
            let id = st.add_label(name);
            ok(json!({ "id": id, "name": name, "type": "user" }))
        }
        ("PATCH", false, ["labels", id]) => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let Some(name) = v["name"].as_str().filter(|n| !n.is_empty()) else {
                return error(400, "invalidArgument");
            };
            let Some(pos) = st.labels.iter().position(|(l, ..)| l == id) else {
                return error(404, "notFound");
            };
            if st.labels[pos].2 != "user" {
                return error(400, "invalidArgument");
            }
            if st.name_taken(name, id) {
                return error(409, "conflict");
            }
            st.labels[pos].1 = name.to_owned();
            ok(json!({ "id": id, "name": name, "type": "user" }))
        }
        ("DELETE", false, ["labels", id]) => {
            let Some(pos) = st.labels.iter().position(|(l, ..)| l == id) else {
                return error(404, "notFound");
            };
            if st.labels[pos].2 != "user" {
                return error(400, "invalidArgument");
            }
            st.labels.remove(pos);
            let id = (*id).to_owned();
            let keys: Vec<u64> = st
                .msgs
                .iter()
                .filter(|(_, m)| m.labels.contains(&id))
                .map(|(k, _)| *k)
                .collect();
            for key in keys {
                st.modify(key, &[], std::slice::from_ref(&id));
            }
            empty()
        }
        ("GET", false, ["messages"]) => {
            let wanted: Vec<&str> = q
                .iter()
                .filter(|(k, _)| k == "labelIds")
                .map(|(_, v)| v.as_str())
                .collect();
            let spam_trash = param(&q, "includeSpamTrash") == Some("true");
            let max: usize = param(&q, "maxResults")
                .and_then(|v| v.parse().ok())
                .unwrap_or(100);
            let offset: usize = match param(&q, "pageToken") {
                Some(t) => match t.strip_prefix("p").and_then(|n| n.parse().ok()) {
                    Some(n) => n,
                    None => return error(400, "invalidArgument"),
                },
                None => 0,
            };
            let all: Vec<&Msg> = st
                .msgs
                .values()
                .rev()
                .filter(|m| wanted.iter().all(|l| m.labels.contains(*l)))
                .filter(|m| {
                    spam_trash
                        || !(m.labels.contains(labels::SPAM) || m.labels.contains(labels::TRASH))
                })
                .collect();
            let page: Vec<Value> = all
                .iter()
                .skip(offset)
                .take(max)
                .map(|m| json!({ "id": m.id, "threadId": m.id }))
                .collect();
            let mut out = json!({ "resultSizeEstimate": all.len() });
            if !page.is_empty() {
                out["messages"] = json!(page);
            }
            if offset + max < all.len() {
                out["nextPageToken"] = json!(format!("p{}", offset + max));
            }
            ok(out)
        }
        ("GET", false, ["messages", id]) => {
            let Some(key) = st.find(id) else {
                return error(404, "notFound");
            };
            let m = &st.msgs[&key];
            match param(&q, "format") {
                Some("raw") => ok(json!({ "id": m.id, "raw": crate::base64url().encode(&m.raw) })),
                _ => ok(json!({
                    "id": m.id,
                    "threadId": m.id,
                    "labelIds": m.labels.iter().collect::<Vec<_>>(),
                    "internalDate": m.internal.to_string(),
                })),
            }
        }
        ("GET", false, ["history"]) => {
            let Some(start) = param(&q, "startHistoryId").and_then(|v| v.parse::<u64>().ok())
            else {
                return error(400, "invalidArgument");
            };
            if start < st.expired_below {
                return error(404, "notFound");
            }
            let max: usize = param(&q, "maxResults")
                .and_then(|v| v.parse().ok())
                .unwrap_or(100);
            let offset: usize = param(&q, "pageToken")
                .and_then(|t| t.strip_prefix("h"))
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            let all: Vec<&Value> = st
                .history
                .iter()
                .filter(|(id, _)| *id > start)
                .map(|(_, r)| r)
                .collect();
            let page: Vec<&Value> = all.iter().skip(offset).take(max).copied().collect();
            let mut out = json!({ "historyId": st.history_id.to_string() });
            if !page.is_empty() {
                out["history"] = json!(page);
            }
            if offset + max < all.len() {
                out["nextPageToken"] = json!(format!("h{}", offset + max));
            }
            ok(out)
        }
        ("POST", false, ["watch"]) => {
            let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let Some(topic) = v["topicName"].as_str() else {
                return error(400, "invalidArgument");
            };
            if st.publish_denied {
                return error(403, "forbidden");
            }
            st.watches += 1;
            let expiration = WATCH_NOW + 7 * 24 * 3600 * 1000 + i64::from(st.watches);
            st.watch = Some((topic.to_owned(), expiration));
            ok(json!({
                "historyId": st.history_id.to_string(),
                "expiration": expiration.to_string(),
            }))
        }
        ("POST", false, ["stop"]) => {
            st.stops += 1;
            st.watch = None;
            empty()
        }
        ("POST", false, ["messages", "batchModify"]) => {
            let (ids, add, remove) = ids(&body);
            if add.iter().any(|a| !st.labels.iter().any(|(l, ..)| l == a)) {
                return error(400, "invalidArgument");
            }
            for id in ids {
                if let Some(key) = st.find(&id) {
                    st.modify(key, &add, &remove);
                }
            }
            empty()
        }
        ("POST", false, ["messages", "batchDelete"]) => {
            if !st.full_scope {
                return error(403, "insufficientPermissions");
            }
            let (ids, ..) = ids(&body);
            for id in ids {
                if let Some(key) = st.find(&id) {
                    st.delete(key);
                }
            }
            empty()
        }
        ("POST", false, ["messages", id, action @ ("trash" | "untrash")]) => {
            let Some(key) = st.find(id) else {
                return error(404, "notFound");
            };
            let trash = vec![labels::TRASH.to_owned()];
            if *action == "trash" {
                st.modify(key, &trash, &[]);
            } else {
                st.modify(key, &[], &trash);
            }
            ok(msg_json(&st.msgs[&key]))
        }
        ("POST", true, ["messages"]) => {
            let content_type = headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if param(&q, "uploadType") != Some("multipart") {
                return error(400, "invalidArgument");
            }
            let Some((meta, raw)) = multipart(content_type, &body) else {
                return error(400, "invalidArgument");
            };
            let labels: Vec<String> = meta["labelIds"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
            let id = st.insert(&raw, &refs);
            ok(json!({ "id": id, "threadId": id, "labelIds": labels }))
        }
        _ => error(404, "notFound"),
    }
}

#[async_trait]
impl ServerControl for FakeGmail {
    async fn create_mailbox(&self, mailbox: &str) {
        self.add_label(mailbox);
    }

    async fn add(&self, mailbox: &str, bytes: &[u8], flags: Flags) {
        let mut st = self.state.lock().unwrap();
        let label = st.label_for(mailbox).expect("mailbox exists");
        let mut labels: Vec<&str> = vec![label.as_str()];
        labels.extend(flag_labels(&flags));
        st.insert(bytes, &labels);
    }

    async fn remove(&self, _mailbox: &str, bytes: &[u8]) {
        let mut st = self.state.lock().unwrap();
        if let Some(key) = st.find_raw(bytes) {
            st.delete(key);
        }
    }

    async fn set_flags(&self, _mailbox: &str, bytes: &[u8], flags: Flags) {
        let mut st = self.state.lock().unwrap();
        let Some(key) = st.find_raw(bytes) else {
            return;
        };
        let want: Vec<String> = flag_labels(&flags).into_iter().map(str::to_owned).collect();
        let remove: Vec<String> = [labels::UNREAD, labels::STARRED, labels::DRAFT]
            .into_iter()
            .map(str::to_owned)
            .filter(|l| !want.contains(l))
            .collect();
        st.modify(key, &want, &remove);
    }

    async fn invalidate(&self, _mailbox: &str) {
        let mut st = self.state.lock().unwrap();
        st.history_id += 1;
        st.expired_below = st.history_id;
    }

    async fn flags_of(&self, _mailbox: &str, bytes: &[u8]) -> Option<Flags> {
        let st = self.state.lock().unwrap();
        let key = st.find_raw(bytes)?;
        let labels: Vec<String> = st.msgs[&key].labels.iter().cloned().collect();
        Some(labels::flags(&labels))
    }
}
