use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::body::Bytes as Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine;
use serde_json::json;
use skein_mail::testing::{ServerControl, conformance, write_conformance};

use super::*;

const TOKEN: &str = "graph-secret-token-0451";
const INBOX: &str = "AAMkInbox";

struct FakeFolder {
    id: String,
    name: String,
    parent: Option<String>,
    well_known: Option<String>,
    search: bool,
}

#[derive(Clone)]
struct FakeMessage {
    id: String,
    folder: String,
    received: String,
    read: bool,
    flagged: bool,
    draft: bool,
    raw: Vec<u8>,
}

#[derive(Default)]
struct Fake {
    port: u16,
    folders: Vec<FakeFolder>,
    messages: Vec<FakeMessage>,
    log: Vec<(u64, String, String)>,
    seq: u64,
    epochs: HashMap<String, u64>,
    throttle: Vec<(u16, Option<&'static str>)>,
    stall_writes: bool,
    foreign_next: Option<String>,
    redirect_to: Option<String>,
    requests: Vec<String>,
    next_id: u64,
    clock: i64,
    subscriptions: HashMap<String, Value>,
    refuse_subscriptions: Option<u16>,
}

type Shared = Arc<Mutex<Fake>>;

impl Fake {
    fn touch(&mut self, folder: &str, id: &str) {
        self.seq += 1;
        let seq = self.seq;
        self.log.push((seq, folder.to_owned(), id.to_owned()));
    }

    fn arrive(&mut self, folder: &str, raw: Vec<u8>, read: bool, flagged: bool) -> FakeMessage {
        self.clock += 1;
        self.next_id += 1;
        let message = FakeMessage {
            id: format!("AAMkMsg-{:04}", self.next_id),
            folder: folder.to_owned(),
            received: time::format_utc(1_700_000_000 + self.clock),
            read,
            flagged,
            draft: false,
            raw,
        };
        self.messages.push(message.clone());
        self.touch(folder, &message.id);
        message
    }

    fn folder_id(&self, id_or_name: &str) -> Option<String> {
        self.folders
            .iter()
            .find(|f| f.id == id_or_name || f.well_known.as_deref() == Some(id_or_name))
            .map(|f| f.id.clone())
    }

    fn base(&self) -> String {
        format!("http://127.0.0.1:{}/v1.0", self.port)
    }
}

fn message_json(m: &FakeMessage) -> Value {
    json!({
        "id": m.id,
        "receivedDateTime": m.received,
        "isRead": m.read,
        "isDraft": m.draft,
        "flag": { "flagStatus": if m.flagged { "flagged" } else { "notFlagged" } },
    })
}

fn gate(fake: &Shared, headers: &HeaderMap, path: &str) -> Option<Response> {
    let mut fake = fake.lock().unwrap();
    fake.requests.push(path.to_owned());
    let bearer = format!("Bearer {TOKEN}");
    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(bearer.as_str()) {
        return Some(StatusCode::UNAUTHORIZED.into_response());
    }
    let prefer = headers
        .get("prefer")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(prefer.contains("IdType=\"ImmutableId\""), "{prefer}");
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
    if let Some(to) = fake.redirect_to.clone() {
        return Some((StatusCode::FOUND, [("location", to)]).into_response());
    }
    None
}

fn page_size(headers: &HeaderMap) -> usize {
    headers
        .get("prefer")
        .and_then(|v| v.to_str().ok())
        .and_then(|p| p.split("odata.maxpagesize=").nth(1))
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or(10)
}

async fn folders(
    State(fake): State<Shared>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    children(&fake, &headers, None, &query)
}

async fn child_folders(
    State(fake): State<Shared>,
    headers: HeaderMap,
    Path(parent): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    children(&fake, &headers, Some(parent), &query)
}

fn children(
    shared: &Shared,
    headers: &HeaderMap,
    parent: Option<String>,
    query: &HashMap<String, String>,
) -> Response {
    if let Some(refused) = gate(shared, headers, "folders") {
        return refused;
    }
    assert_eq!(
        query.get("includeHiddenFolders").map(String::as_str),
        Some("true")
    );
    let fake = shared.lock().unwrap();
    let skip: usize = query.get("$skip").and_then(|s| s.parse().ok()).unwrap_or(0);
    let all: Vec<Value> = fake
        .folders
        .iter()
        .filter(|f| f.parent == parent)
        .map(|f| {
            let mut out = json!({
                "id": f.id,
                "displayName": f.name,
                "childFolderCount": fake.folders.iter().filter(|c| c.parent.as_deref() == Some(&f.id)).count(),
            });
            if f.search {
                out["@odata.type"] = json!("#microsoft.graph.mailSearchFolder");
            }
            out
        })
        .collect();
    let mut out = json!({ "value": all.iter().skip(skip).take(2).cloned().collect::<Vec<_>>() });
    if skip + 2 < all.len() {
        let path = match &parent {
            Some(p) => format!("/me/mailFolders/{p}/childFolders"),
            None => "/me/mailFolders".into(),
        };
        out["@odata.nextLink"] = json!(format!(
            "{}{path}?includeHiddenFolders=true&$skip={}",
            fake.base(),
            skip + 2
        ));
    }
    axum::Json(out).into_response()
}

async fn folder(
    State(shared): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Some(refused) = gate(&shared, &headers, "folder") {
        return refused;
    }
    match shared.lock().unwrap().folder_id(&id) {
        Some(id) => axum::Json(json!({ "id": id })).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

impl Fake {
    fn sibling_named(&self, parent: &Option<String>, name: &str, except: &str) -> bool {
        self.folders.iter().any(|f| {
            &f.parent == parent && f.id != except && f.name.to_lowercase() == name.to_lowercase()
        })
    }

    fn make_folder(&mut self, parent: Option<String>, name: &str) -> Response {
        if self.sibling_named(&parent, name, "") {
            return (StatusCode::CONFLICT, "ErrorFolderExists").into_response();
        }
        self.next_id += 1;
        let id = format!("AAMkFolder-{:04}", self.next_id);
        self.folders.push(FakeFolder {
            id: id.clone(),
            name: name.to_owned(),
            parent,
            well_known: None,
            search: false,
        });
        (
            StatusCode::CREATED,
            axum::Json(json!({ "id": id, "displayName": name })),
        )
            .into_response()
    }
}

fn display_name(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<Value>(body).ok()?["displayName"]
        .as_str()
        .map(str::to_owned)
}

async fn folder_create(State(shared): State<Shared>, headers: HeaderMap, body: Body) -> Response {
    if let Some(refused) = gate(&shared, &headers, "folder_create") {
        return refused;
    }
    let Some(name) = display_name(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    shared.lock().unwrap().make_folder(None, &name)
}

async fn child_create(
    State(shared): State<Shared>,
    headers: HeaderMap,
    Path(parent): Path<String>,
    body: Body,
) -> Response {
    if let Some(refused) = gate(&shared, &headers, "folder_create") {
        return refused;
    }
    let Some(name) = display_name(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let mut fake = shared.lock().unwrap();
    let Some(parent) = fake.folder_id(&parent) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    fake.make_folder(Some(parent), &name)
}

async fn folder_patch(
    State(shared): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Body,
) -> Response {
    if let Some(refused) = gate(&shared, &headers, "folder_patch") {
        return refused;
    }
    let Some(name) = display_name(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let mut fake = shared.lock().unwrap();
    let Some(i) = fake.folders.iter().position(|f| f.id == id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let parent = fake.folders[i].parent.clone();
    if fake.sibling_named(&parent, &name, &id) {
        return (StatusCode::CONFLICT, "ErrorFolderExists").into_response();
    }
    fake.folders[i].name = name.clone();
    axum::Json(json!({ "id": id, "displayName": name })).into_response()
}

async fn folder_move(
    State(shared): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
    axum::Json(args): axum::Json<Value>,
) -> Response {
    if let Some(refused) = gate(&shared, &headers, "folder_move") {
        return refused;
    }
    let mut fake = shared.lock().unwrap();
    let Some(i) = fake.folders.iter().position(|f| f.id == id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let target = match args["destinationId"].as_str() {
        Some("msgfolderroot") => None,
        Some(t) => match fake.folder_id(t) {
            Some(t) => Some(t),
            None => return StatusCode::NOT_FOUND.into_response(),
        },
        None => return StatusCode::BAD_REQUEST.into_response(),
    };
    let name = fake.folders[i].name.clone();
    if fake.sibling_named(&target, &name, &id) {
        return (StatusCode::CONFLICT, "ErrorFolderExists").into_response();
    }
    fake.folders[i].parent = target;
    axum::Json(json!({ "id": id, "displayName": name })).into_response()
}

async fn folder_delete(
    State(shared): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Some(refused) = gate(&shared, &headers, "folder_delete") {
        return refused;
    }
    let mut fake = shared.lock().unwrap();
    let Some(i) = fake.folders.iter().position(|f| f.id == id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if fake.folders[i].well_known.is_some() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let trash = fake.folder_id("deleteditems");
    fake.folders[i].parent = trash;
    StatusCode::NO_CONTENT.into_response()
}

async fn delta(
    State(shared): State<Shared>,
    headers: HeaderMap,
    Path(folder): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    if let Some(refused) = gate(&shared, &headers, "delta") {
        return refused;
    }
    let mut fake = shared.lock().unwrap();
    if fake.folder_id(&folder).as_deref() != Some(folder.as_str()) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let epoch = fake.epochs.get(&folder).copied().unwrap_or(0);
    let parse = |raw: &str| -> Vec<String> { raw.split('.').map(str::to_owned).collect() };
    let (from, upto, offset): (Option<u64>, u64, usize) =
        if let Some(token) = query.get("$skiptoken") {
            let p = parse(token);
            if p[0].parse::<u64>().unwrap() != epoch {
                return (StatusCode::GONE, "syncStateNotFound").into_response();
            }
            (
                p[1].parse().ok(),
                p[2].parse().unwrap(),
                p[3].parse().unwrap(),
            )
        } else if let Some(token) = query.get("$deltatoken") {
            let p = parse(token);
            if p.len() != 2 || p[0].parse::<u64>().ok() != Some(epoch) {
                return (StatusCode::GONE, "syncStateNotFound").into_response();
            }
            (p[1].parse().ok(), fake.seq, 0)
        } else {
            assert!(query.get("$select").is_some_and(|s| s.contains("isRead")));
            (None, fake.seq, 0)
        };
    let items: Vec<Value> = match from {
        None => {
            let mut in_folder: Vec<&FakeMessage> = fake
                .messages
                .iter()
                .filter(|m| m.folder == folder)
                .collect();
            in_folder.sort_by(|a, b| a.id.cmp(&b.id));
            in_folder.into_iter().map(message_json).collect()
        }
        Some(from) => {
            let mut ids: Vec<String> = Vec::new();
            for (seq, f, id) in &fake.log {
                if *seq > from && *seq <= upto && *f == folder && !ids.contains(id) {
                    ids.push(id.clone());
                }
            }
            ids.iter()
                .map(|id| {
                    match fake
                        .messages
                        .iter()
                        .find(|m| &m.id == id && m.folder == folder)
                    {
                        Some(m) => message_json(m),
                        None => json!({ "id": id, "@removed": { "reason": "deleted" } }),
                    }
                })
                .collect()
        }
    };
    let size = page_size(&headers);
    let page: Vec<Value> = items.iter().skip(offset).take(size).cloned().collect();
    let base = format!("{}/me/mailFolders/{folder}/messages/delta", fake.base());
    let mut out = json!({ "value": page });
    if offset + size < items.len() {
        let from = from.map(|f| f.to_string()).unwrap_or_else(|| "full".into());
        let next = format!("{base}?$skiptoken={epoch}.{from}.{upto}.{}", offset + size);
        out["@odata.nextLink"] = json!(fake.foreign_next.take().unwrap_or(next));
    } else {
        out["@odata.deltaLink"] = json!(format!("{base}?$deltatoken={epoch}.{upto}"));
    }
    axum::Json(out).into_response()
}

async fn message_get(
    State(shared): State<Shared>,
    headers: HeaderMap,
    Path((id, action)): Path<(String, String)>,
) -> Response {
    if let Some(refused) = gate(&shared, &headers, "value") {
        return refused;
    }
    assert_eq!(action, "$value");
    let fake = shared.lock().unwrap();
    match fake.messages.iter().find(|m| m.id == id) {
        Some(m) => m.raw.clone().into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn stall(shared: &Shared) {
    let stall = shared.lock().unwrap().stall_writes;
    if stall {
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn message_patch(
    State(shared): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Body,
) -> Response {
    if let Some(refused) = gate(&shared, &headers, "patch") {
        return refused;
    }
    stall(&shared).await;
    let patch: Value = serde_json::from_slice(&body).unwrap();
    let mut fake = shared.lock().unwrap();
    let Some(m) = fake.messages.iter_mut().find(|m| m.id == id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Some(read) = patch.get("isRead").and_then(Value::as_bool) {
        m.read = read;
    }
    if let Some(status) = patch.pointer("/flag/flagStatus").and_then(Value::as_str) {
        m.flagged = status == "flagged";
    }
    let (folder, json) = (m.folder.clone(), message_json(m));
    fake.touch(&folder, &id);
    axum::Json(json).into_response()
}

async fn message_post(
    State(shared): State<Shared>,
    headers: HeaderMap,
    Path((id, action)): Path<(String, String)>,
    body: Body,
) -> Response {
    if let Some(refused) = gate(&shared, &headers, &action) {
        return refused;
    }
    stall(&shared).await;
    let mut fake = shared.lock().unwrap();
    let Some(index) = fake.messages.iter().position(|m| m.id == id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let from = fake.messages[index].folder.clone();
    match action.as_str() {
        "move" => {
            let args: Value = serde_json::from_slice(&body).unwrap();
            let Some(to) = fake.folder_id(args["destinationId"].as_str().unwrap()) else {
                return StatusCode::NOT_FOUND.into_response();
            };
            fake.messages[index].folder = to.clone();
            fake.touch(&from, &id);
            fake.touch(&to, &id);
            axum::Json(message_json(&fake.messages[index])).into_response()
        }
        "copy" => {
            let args: Value = serde_json::from_slice(&body).unwrap();
            let Some(to) = fake.folder_id(args["destinationId"].as_str().unwrap()) else {
                return StatusCode::NOT_FOUND.into_response();
            };
            let m = fake.messages[index].clone();
            let copy = fake.arrive(&to, m.raw, m.read, m.flagged);
            (StatusCode::CREATED, axum::Json(message_json(&copy))).into_response()
        }
        "permanentDelete" => {
            fake.messages.remove(index);
            fake.touch(&from, &id);
            StatusCode::NO_CONTENT.into_response()
        }
        _ => StatusCode::BAD_REQUEST.into_response(),
    }
}

async fn upload(
    State(shared): State<Shared>,
    headers: HeaderMap,
    Path(folder): Path<String>,
    body: Body,
) -> Response {
    if let Some(refused) = gate(&shared, &headers, "upload") {
        return refused;
    }
    assert_eq!(
        headers.get("content-type").and_then(|v| v.to_str().ok()),
        Some("text/plain")
    );
    stall(&shared).await;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&body)
        .unwrap();
    let mut fake = shared.lock().unwrap();
    let Some(folder) = fake.folder_id(&folder) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let m = fake.arrive(&folder, raw, false, false);
    (StatusCode::CREATED, axum::Json(message_json(&m))).into_response()
}

async fn subscription_create(
    State(fake): State<Shared>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    if let Some(refused) = gate(&fake, &headers, "subscriptions") {
        return refused;
    }
    let mut fake = fake.lock().unwrap();
    if let Some(status) = fake.refuse_subscriptions {
        return (StatusCode::from_u16(status).unwrap(), "no").into_response();
    }
    for key in [
        "changeType",
        "notificationUrl",
        "resource",
        "expirationDateTime",
        "clientState",
    ] {
        assert!(body[key].is_string(), "{key}");
    }
    assert!(time::parse_utc(body["expirationDateTime"].as_str().unwrap()).is_some());
    fake.next_id += 1;
    let id = format!("7f105c7d-2dc5-4530-97cd-{:012}", fake.next_id);
    let mut stored = body.clone();
    stored["id"] = json!(id);
    stored["expirationDateTime"] = json!(format!(
        "{}.0000000Z",
        body["expirationDateTime"]
            .as_str()
            .unwrap()
            .trim_end_matches('Z')
    ));
    fake.subscriptions.insert(id, stored.clone());
    (StatusCode::CREATED, axum::Json(stored)).into_response()
}

async fn subscription_patch(
    State(fake): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    if let Some(refused) = gate(&fake, &headers, "subscription") {
        return refused;
    }
    let mut fake = fake.lock().unwrap();
    let Some(stored) = fake.subscriptions.get_mut(&id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    stored["expirationDateTime"] = body["expirationDateTime"].clone();
    (StatusCode::OK, axum::Json(stored.clone())).into_response()
}

async fn subscription_delete(
    State(fake): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Some(refused) = gate(&fake, &headers, "subscription") {
        return refused;
    }
    match fake.lock().unwrap().subscriptions.remove(&id) {
        Some(_) => StatusCode::NO_CONTENT.into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[derive(Clone)]
struct FakeGraph {
    shared: Shared,
}

impl FakeGraph {
    async fn start() -> Self {
        let shared: Shared = Arc::default();
        {
            let mut fake = shared.lock().unwrap();
            let folder =
                |id: &str, name: &str, parent: Option<&str>, wk: Option<&str>| FakeFolder {
                    id: id.into(),
                    name: name.into(),
                    parent: parent.map(Into::into),
                    well_known: wk.map(Into::into),
                    search: false,
                };
            fake.folders = vec![
                folder(INBOX, "Inbox", None, Some("inbox")),
                folder("AAMkSent", "Sent Items", None, Some("sentitems")),
                folder("AAMkTrash", "Deleted Items", None, Some("deleteditems")),
                folder("AAMkProjects", "Projects", INBOX.into(), None),
                folder("AAMkHidden", "Conversation History", None, None),
                FakeFolder {
                    search: true,
                    ..folder("AAMkSearch", "Unread Mail", None, None)
                },
            ];
        }
        let app = Router::new()
            .route("/v1.0/me/mailFolders", get(folders).post(folder_create))
            .route(
                "/v1.0/me/mailFolders/{id}",
                get(folder).patch(folder_patch).delete(folder_delete),
            )
            .route(
                "/v1.0/me/mailFolders/{id}/childFolders",
                get(child_folders).post(child_create),
            )
            .route("/v1.0/me/mailFolders/{id}/move", post(folder_move))
            .route("/v1.0/me/mailFolders/{id}/messages", post(upload))
            .route("/v1.0/me/mailFolders/{id}/messages/delta", get(delta))
            .route(
                "/v1.0/me/messages/{id}",
                axum::routing::patch(message_patch),
            )
            .route(
                "/v1.0/me/messages/{id}/{action}",
                get(message_get).post(message_post),
            )
            .route("/v1.0/subscriptions", post(subscription_create))
            .route(
                "/v1.0/subscriptions/{id}",
                axum::routing::patch(subscription_patch).delete(subscription_delete),
            )
            .with_state(shared.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        shared.lock().unwrap().port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { shared }
    }

    fn settings(&self) -> GraphSettings {
        GraphSettings {
            api_url: Some(self.shared.lock().unwrap().base()),
            roots: TlsRoots::default(),
        }
    }

    fn provider(&self) -> GraphProvider {
        GraphProvider::new(
            self.settings(),
            Credentials::AccessToken {
                token: TOKEN.into(),
            },
        )
        .unwrap()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Fake> {
        self.shared.lock().unwrap()
    }

    fn find(&self, folder: &str, bytes: &[u8]) -> Option<FakeMessage> {
        self.lock()
            .messages
            .iter()
            .find(|m| m.folder == folder && m.raw == bytes)
            .cloned()
    }
}

#[async_trait]
impl ServerControl for FakeGraph {
    async fn create_mailbox(&self, mailbox: &str) {
        let mut fake = self.lock();
        if fake.folder_id(mailbox).is_none() {
            fake.folders.push(FakeFolder {
                id: mailbox.into(),
                name: mailbox.into(),
                parent: None,
                well_known: None,
                search: false,
            });
        }
    }

    async fn add(&self, mailbox: &str, bytes: &[u8], flags: Flags) {
        self.lock().arrive(
            mailbox,
            bytes.to_vec(),
            flags.contains("\\Seen"),
            flags.contains("\\Flagged"),
        );
    }

    async fn remove(&self, mailbox: &str, bytes: &[u8]) {
        let mut fake = self.lock();
        if let Some(i) = fake
            .messages
            .iter()
            .position(|m| m.folder == mailbox && m.raw == bytes)
        {
            let m = fake.messages.remove(i);
            fake.touch(mailbox, &m.id);
        }
    }

    async fn set_flags(&self, mailbox: &str, bytes: &[u8], flags: Flags) {
        let mut fake = self.lock();
        if let Some(m) = fake
            .messages
            .iter_mut()
            .find(|m| m.folder == mailbox && m.raw == bytes)
        {
            m.read = flags.contains("\\Seen");
            m.flagged = flags.contains("\\Flagged");
            let id = m.id.clone();
            fake.touch(mailbox, &id);
        }
    }

    async fn invalidate(&self, mailbox: &str) {
        *self.lock().epochs.entry(mailbox.to_owned()).or_default() += 1;
    }

    async fn flags_of(&self, mailbox: &str, bytes: &[u8]) -> Option<Flags> {
        self.find(mailbox, bytes).map(|m| flags(&message_json(&m)))
    }
}

fn msg(n: u32) -> Vec<u8> {
    format!("From: ada@example.com\r\nTo: bob@example.org\r\nSubject: Note {n}\r\nMessage-ID: <n{n}@example.com>\r\n\r\nHello {n}\r\n").into_bytes()
}

async fn drain(
    session: &mut Box<dyn MailSession>,
    cursor: Option<Cursor>,
) -> (Cursor, Vec<MailChange>) {
    let mut cursor = cursor;
    let mut all = Vec::new();
    loop {
        let batch = session.changes(INBOX, cursor.as_ref(), 100).await.unwrap();
        all.extend(batch.changes);
        cursor = Some(batch.cursor);
        if !batch.more {
            return (cursor.unwrap(), all);
        }
    }
}

#[tokio::test]
async fn keeps_the_mail_contract() {
    let fake = FakeGraph::start().await;
    conformance(Arc::new(fake.provider()), Arc::new(fake.clone()), INBOX).await;
}

#[tokio::test]
async fn keeps_the_write_contract() {
    let fake = FakeGraph::start().await;
    fake.create_mailbox("AAMkArchive").await;
    write_conformance(
        Arc::new(fake.provider()),
        Arc::new(fake.clone()),
        INBOX,
        "AAMkArchive",
        None,
    )
    .await;
}

#[tokio::test]
async fn lists_folders_with_paths_and_roles() {
    let fake = FakeGraph::start().await;
    let mut session = fake.provider().connect().await.unwrap();
    let boxes = session.mailboxes().await.unwrap();
    let summary: Vec<(&str, &str, Option<MailboxRole>)> = boxes
        .iter()
        .map(|b| (b.id.as_str(), b.path.as_str(), b.role))
        .collect();
    assert_eq!(
        summary,
        vec![
            ("AAMkHidden", "Conversation History", None),
            ("AAMkTrash", "Deleted Items", Some(MailboxRole::Trash)),
            (INBOX, "Inbox", Some(MailboxRole::Inbox)),
            ("AAMkProjects", "Inbox/Projects", None),
            ("AAMkSent", "Sent Items", Some(MailboxRole::Sent)),
        ]
    );
    assert!(boxes.iter().all(|b| b.selectable && !b.label));
}

#[tokio::test]
async fn reports_moves_out_and_in() {
    let fake = FakeGraph::start().await;
    fake.add(INBOX, &msg(1), Flags::default()).await;
    let provider = fake.provider();
    let mut session = provider.connect().await.unwrap();
    let (cursor, changes) = drain(&mut session, None).await;
    assert_eq!(changes.len(), 1);
    let MailChange::Added {
        item, received_at, ..
    } = &changes[0]
    else {
        panic!("{changes:?}");
    };
    assert_eq!(
        received_at,
        &Some(skein_core::Timestamp(1_700_000_001 * 1000))
    );
    assert_eq!(item.uid, None);
    let outcome = session
        .apply(
            &CommandBody::Move {
                from: INBOX.into(),
                to: "AAMkTrash".into(),
                items: vec![item.clone()],
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(outcome, WriteOutcome::Applied);
    let (_, changes) = drain(&mut session, Some(cursor)).await;
    assert_eq!(changes, vec![MailChange::Removed { item: item.clone() }]);
    let trash = session.changes("AAMkTrash", None, 10).await.unwrap();
    assert!(matches!(&trash.changes[..], [MailChange::Added { item: i, .. }] if i.id == item.id));
}

#[tokio::test]
async fn ignores_removals_of_messages_it_never_reported() {
    let fake = FakeGraph::start().await;
    let mut session = fake.provider().connect().await.unwrap();
    let (cursor, _) = drain(&mut session, None).await;
    fake.add(INBOX, &msg(1), Flags::default()).await;
    fake.remove(INBOX, &msg(1)).await;
    let (_, changes) = drain(&mut session, Some(cursor)).await;
    assert!(changes.is_empty(), "{changes:?}");
}

#[tokio::test]
async fn unreadable_or_foreign_cursors_reset_without_sending_the_token() {
    let fake = FakeGraph::start().await;
    fake.add(INBOX, &msg(1), Flags::default()).await;
    let elsewhere = FakeGraph::start().await;
    let mut session = fake.provider().connect().await.unwrap();

    let garbage = Cursor(Bytes::from_static(b"not a cursor"));
    let batch = session.changes(INBOX, Some(&garbage), 10).await.unwrap();
    assert!(matches!(batch.changes[0], MailChange::Reset { .. }));
    assert_eq!(batch.changes.len(), 2);

    let foreign = DeltaCursor {
        folder: INBOX.into(),
        link: format!(
            "{}/me/mailFolders/{INBOX}/messages/delta?$deltatoken=0.0",
            elsewhere.lock().base()
        ),
        known: Default::default(),
    }
    .encode();
    let batch = session.changes(INBOX, Some(&foreign), 10).await.unwrap();
    assert!(matches!(batch.changes[0], MailChange::Reset { .. }));
    assert!(
        elsewhere.lock().requests.is_empty(),
        "nothing went to the other host"
    );

    let (cursor, _) = drain(&mut session, None).await;
    let batch = session
        .changes("AAMkSent", Some(&cursor), 10)
        .await
        .unwrap();
    assert!(
        matches!(batch.changes.first(), Some(MailChange::Reset { .. })),
        "a cursor of another folder resets"
    );
}

#[tokio::test]
async fn refuses_links_and_redirects_to_other_hosts() {
    let fake = FakeGraph::start().await;
    let elsewhere = FakeGraph::start().await;
    for n in 1..=3 {
        fake.add(INBOX, &msg(n), Flags::default()).await;
    }
    let other = elsewhere.lock().base();
    fake.lock().foreign_next = Some(format!("{other}/me/mailFolders/{INBOX}/messages/delta"));
    let mut session = fake.provider().connect().await.unwrap();
    assert!(matches!(
        session.changes(INBOX, None, 1).await,
        Err(MailError::Protocol(_))
    ));

    fake.lock().redirect_to = Some(format!("{other}/me/mailFolders"));
    assert!(session.mailboxes().await.is_err());
    assert!(
        elsewhere.lock().requests.is_empty(),
        "the token stayed home"
    );
}

#[tokio::test]
async fn refuses_unsafe_settings() {
    let token = || Credentials::AccessToken {
        token: TOKEN.into(),
    };
    let with = |url: &str| GraphSettings {
        api_url: Some(url.into()),
        roots: TlsRoots::default(),
    };
    for url in [
        "http://graph.example.com/v1.0",
        "ftp://graph.example.com/v1.0",
        "https://user:pass@graph.example.com/v1.0",
        "not a url",
    ] {
        assert!(
            matches!(
                GraphProvider::new(with(url), token()),
                Err(MailError::Config(_))
            ),
            "{url}"
        );
    }
    assert!(GraphProvider::new(with("http://localhost:1/v1.0"), token()).is_ok());
    assert!(GraphProvider::new(GraphSettings::default(), token()).is_ok());
    assert!(matches!(
        GraphProvider::new(
            GraphSettings::default(),
            Credentials::Password {
                secret: "hunter2".into()
            }
        ),
        Err(MailError::Config(_))
    ));
    let settings = GraphSettings::from_json(
        &json!({ "api_url": "https://graph.example.com/v1.0", "oauth": {} }),
    )
    .unwrap();
    assert_eq!(
        settings.api_url.as_deref(),
        Some("https://graph.example.com/v1.0")
    );
}

#[tokio::test]
async fn throttling_becomes_throttled_with_the_delay() {
    let fake = FakeGraph::start().await;
    let mut session = fake.provider().connect().await.unwrap();
    fake.lock().throttle = vec![(429, Some("7"))];
    assert!(matches!(
        session.changes(INBOX, None, 10).await,
        Err(MailError::Throttled { retry_after: Some(d) }) if d == Duration::from_secs(7)
    ));
    fake.lock().throttle = vec![(503, Some("3"))];
    assert!(matches!(
        session.fetch(INBOX, &[ItemRef { id: "x".into(), uid: None }]).await,
        Err(MailError::Throttled { retry_after: Some(d) }) if d == Duration::from_secs(3)
    ));
    fake.lock().throttle = vec![(429, None)];
    assert!(matches!(
        session.mailboxes().await,
        Err(MailError::Throttled { retry_after: None })
    ));
    fake.lock().throttle = vec![(503, None)];
    assert!(matches!(
        session.changes(INBOX, None, 10).await,
        Err(MailError::Network(_))
    ));
    fake.lock().throttle = vec![(429, Some("1"))];
    assert!(matches!(
        session
            .apply(
                &CommandBody::Delete {
                    mailbox: INBOX.into(),
                    items: vec![ItemRef {
                        id: "x".into(),
                        uid: None
                    }],
                    to_trash: false,
                },
                None
            )
            .await,
        Err(MailError::Throttled { .. })
    ));
    assert!(session.changes(INBOX, None, 10).await.is_ok());
}

#[tokio::test]
async fn a_wrong_token_is_auth() {
    let fake = FakeGraph::start().await;
    let provider = GraphProvider::new(
        fake.settings(),
        Credentials::AccessToken {
            token: "expired".into(),
        },
    )
    .unwrap();
    let mut session = provider.connect().await.unwrap();
    assert!(matches!(session.mailboxes().await, Err(MailError::Auth)));
    assert!(matches!(
        session.changes(INBOX, None, 10).await,
        Err(MailError::Auth)
    ));
}

#[tokio::test]
async fn an_unknown_folder_is_not_found() {
    let fake = FakeGraph::start().await;
    let mut session = fake.provider().connect().await.unwrap();
    assert!(matches!(
        session.changes("AAMkGone", None, 10).await,
        Err(MailError::MailboxNotFound)
    ));
}

#[tokio::test]
async fn downloads_above_the_limit_are_refused() {
    let fake = FakeGraph::start().await;
    fake.add(INBOX, &msg(1), Flags::default()).await;
    let id = fake.find(INBOX, &msg(1)).unwrap().id;
    let mut session = fake
        .provider()
        .with_max_download(16)
        .connect()
        .await
        .unwrap();
    assert!(matches!(
        session.fetch(INBOX, &[ItemRef { id, uid: None }]).await,
        Err(MailError::Protocol(_))
    ));
}

#[tokio::test]
async fn writes_flags_moves_deletes_and_appends() {
    let fake = FakeGraph::start().await;
    fake.add(INBOX, &msg(1), Flags::default()).await;
    fake.add(INBOX, &msg(2), Flags::default()).await;
    let one = ItemRef {
        id: fake.find(INBOX, &msg(1)).unwrap().id,
        uid: None,
    };
    let two = ItemRef {
        id: fake.find(INBOX, &msg(2)).unwrap().id,
        uid: None,
    };
    let gone = ItemRef {
        id: "AAMkMsg-gone".into(),
        uid: None,
    };
    let mut session = fake.provider().connect().await.unwrap();

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
                    &["\\Seen", "\\Flagged"],
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
        Flags::new(["\\Flagged", "\\Seen"])
    );
    session
        .apply(&set(&[], &["\\Seen"], vec![one.clone()]), None)
        .await
        .unwrap();
    assert_eq!(
        fake.flags_of(INBOX, &msg(1)).await.unwrap(),
        Flags::new(["\\Flagged"])
    );
    assert_eq!(
        session
            .apply(&set(&["\\Answered"], &[], vec![one.clone()]), None)
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
                    to: "AAMkNowhere".into(),
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

    assert_eq!(
        session
            .apply(
                &CommandBody::Delete {
                    mailbox: INBOX.into(),
                    items: vec![two.clone(), gone.clone()],
                    to_trash: false,
                },
                None
            )
            .await
            .unwrap(),
        WriteOutcome::Applied
    );
    assert!(fake.find(INBOX, &msg(2)).is_none());

    let append = |flags: &[&str]| CommandBody::Append {
        mailbox: "AAMkSent".into(),
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
    let appended = fake.find("AAMkSent", &msg(9)).unwrap();
    assert!(appended.read && !appended.flagged);
    let before = fake.lock().requests.len();
    session
        .apply(&append(&[]), Some(Bytes::from(msg(10))))
        .await
        .unwrap();
    assert_eq!(
        fake.lock().requests.len(),
        before + 1,
        "no patch when the upload already has the flags"
    );
    assert_eq!(
        session
            .apply(
                &append(&[]),
                Some(Bytes::from(vec![b'x'; write::MAX_APPEND + 1]))
            )
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
                    mailbox: "AAMkNowhere".into(),
                    blob: skein_core::BlobHash::of(b"x"),
                    flags: Flags::default(),
                    received_at: None,
                },
                Some(Bytes::from(msg(11)))
            )
            .await,
        Err(MailError::MailboxNotFound)
    ));
}

#[tokio::test]
async fn a_lost_answer_is_uncertain() {
    let fake = FakeGraph::start().await;
    let provider = fake
        .provider()
        .with_timeout(Duration::from_millis(300))
        .unwrap();
    let mut session = provider.connect().await.unwrap();
    fake.lock().stall_writes = true;
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
        .with_env_filter("skein_mail_graph=trace")
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let fake = FakeGraph::start().await;
    let provider = fake.provider();
    conformance(Arc::new(provider.clone()), Arc::new(fake.clone()), INBOX).await;
    fake.lock().throttle = vec![(429, Some("2"))];
    let mut session = provider.connect().await.unwrap();
    let error = session.changes(INBOX, None, 10).await.unwrap_err();
    let mut session = GraphProvider::new(
        fake.settings(),
        Credentials::AccessToken {
            token: TOKEN.into(),
        },
    )
    .unwrap()
    .connect()
    .await
    .unwrap();
    fake.lock().foreign_next = Some(format!("http://127.0.0.1:1/{TOKEN}"));
    let protocol = session.changes(INBOX, None, 1).await.unwrap_err();

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    let shown = format!("{logs}\n{provider:?}\n{error}\n{error:?}\n{protocol}\n{protocol:?}");
    for secret in [
        TOKEN,
        "example.com",
        "Subject",
        "Test 1",
        "Inbox",
        INBOX,
        "AAMkMsg",
    ] {
        assert!(!shown.contains(secret), "{secret} leaked: {shown}");
    }
}

fn push_target() -> skein_mail::PushTarget {
    skein_mail::PushTarget {
        url: "https://skein.example.com/v1/push/graph".into(),
        client_state: "c1ient-state-0123456789".into(),
        gmail_topic: None,
    }
}

#[tokio::test]
async fn subscribes_renews_and_unsubscribes() {
    let fake = FakeGraph::start().await;
    let p = fake.provider();
    let before = skein_core::Timestamp::now();
    let sub = p.subscribe(&push_target()).await.unwrap().unwrap();
    assert_eq!(sub.provider_kind, skein_mail::PUSH_GRAPH);
    assert_eq!(sub.resource, "me/messages");
    let lifetime = sub.expires_at.0 - before.0;
    assert!(
        (4199 * 60_000..=4201 * 60_000).contains(&lifetime),
        "{lifetime}"
    );
    {
        let f = fake.lock();
        let stored = &f.subscriptions[&sub.id];
        assert_eq!(stored["changeType"], "created,updated,deleted");
        assert_eq!(stored["resource"], "me/messages");
        assert_eq!(stored["clientState"], "c1ient-state-0123456789");
        assert_eq!(
            stored["notificationUrl"],
            "https://skein.example.com/v1/push/graph"
        );
        assert_eq!(
            stored["lifecycleNotificationUrl"],
            stored["notificationUrl"]
        );
    }

    fake.lock().subscriptions.get_mut(&sub.id).unwrap()["expirationDateTime"] =
        json!("2020-01-01T00:00:00Z");
    let renewed = p.renew(&sub, &push_target()).await.unwrap().unwrap();
    assert_eq!(renewed.id, sub.id);
    assert!(renewed.expires_at.0 >= sub.expires_at.0 - 1000);
    assert_eq!(fake.lock().subscriptions.len(), 1);

    p.unsubscribe(&renewed).await.unwrap();
    assert!(fake.lock().subscriptions.is_empty());
    p.unsubscribe(&renewed).await.unwrap();

    let replaced = p.renew(&renewed, &push_target()).await.unwrap().unwrap();
    assert_ne!(
        replaced.id, renewed.id,
        "a forgotten subscription is made again"
    );
    assert_eq!(fake.lock().subscriptions.len(), 1);
}

#[tokio::test]
async fn subscription_settings_and_refusals() {
    let fake = FakeGraph::start().await;
    let p = fake.provider();
    for target in [
        skein_mail::PushTarget {
            url: "http://skein.example.com/v1/push/graph".into(),
            ..push_target()
        },
        skein_mail::PushTarget {
            client_state: String::new(),
            ..push_target()
        },
        skein_mail::PushTarget {
            client_state: "x".repeat(129),
            ..push_target()
        },
        skein_mail::PushTarget {
            client_state: "with space".into(),
            ..push_target()
        },
    ] {
        assert!(matches!(
            p.subscribe(&target).await,
            Err(MailError::Config(_))
        ));
    }
    assert!(fake.lock().requests.is_empty());
    assert!(!format!("{:?}", push_target()).contains("c1ient"));
    fake.lock().refuse_subscriptions = Some(400);
    assert!(matches!(
        p.subscribe(&push_target()).await,
        Err(MailError::Protocol(_))
    ));
    fake.lock().refuse_subscriptions = Some(403);
    assert!(matches!(
        p.subscribe(&push_target()).await,
        Err(MailError::Auth)
    ));
    let gmail = skein_mail::Subscription {
        id: "1".into(),
        provider_kind: skein_mail::PUSH_GMAIL.into(),
        expires_at: skein_core::Timestamp(0),
        resource: "ada@example.com".into(),
    };
    let requests = fake.lock().requests.len();
    p.unsubscribe(&gmail).await.unwrap();
    assert_eq!(fake.lock().requests.len(), requests);
}

#[tokio::test]
async fn waits_while_another_holder_pauses_the_throttle() {
    let fake = FakeGraph::start().await;
    let throttle = skein_throttle::Throttle::default();
    let mut session = fake
        .provider()
        .with_throttle(throttle.clone())
        .connect()
        .await
        .unwrap();
    throttle.pause(Duration::from_millis(300));
    let start = std::time::Instant::now();
    session.mailboxes().await.unwrap();
    assert!(start.elapsed() >= Duration::from_millis(300));
}

#[tokio::test]
async fn a_busy_answer_pauses_the_shared_throttle() {
    let fake = FakeGraph::start().await;
    let throttle = skein_throttle::Throttle::default();
    let mut session = fake
        .provider()
        .with_throttle(throttle.clone())
        .connect()
        .await
        .unwrap();
    fake.lock().throttle = vec![(429, Some("7"))];
    assert!(matches!(
        session.mailboxes().await,
        Err(MailError::Throttled { retry_after: Some(d) }) if d == Duration::from_secs(7)
    ));
    let left = throttle.paused_until().unwrap() - tokio::time::Instant::now();
    assert!(left > Duration::from_secs(6) && left <= Duration::from_secs(7));
    fake.lock().throttle = vec![(429, None)];
    let clone = skein_throttle::Throttle::default();
    let mut other = fake
        .provider()
        .with_throttle(clone.clone())
        .connect()
        .await
        .unwrap();
    assert!(other.mailboxes().await.is_err());
    assert!(clone.paused_until().is_none());
}

fn failed(reason: &str) -> WriteOutcome {
    WriteOutcome::Failed {
        reason: reason.into(),
    }
}

fn path_of(boxes: &[MailboxInfo], id: &str) -> Option<String> {
    boxes.iter().find(|b| b.id == id).map(|b| b.path.clone())
}

fn id_at(boxes: &[MailboxInfo], path: &str) -> Option<String> {
    boxes.iter().find(|b| b.path == path).map(|b| b.id.clone())
}

#[tokio::test]
async fn reports_its_capabilities() {
    let fake = FakeGraph::start().await;
    let mut session = fake.provider().connect().await.unwrap();
    let caps = session.capabilities().await.unwrap();
    assert_eq!(caps.system_flags, vec!["\\Flagged", "\\Seen"]);
    assert!(caps.trash && caps.copy && caps.mailboxes);
    assert!(!caps.labels && !caps.keywords && !caps.append_received_at);
}

#[tokio::test]
async fn trashes_copies_and_checks_the_source() {
    let fake = FakeGraph::start().await;
    fake.add(INBOX, &msg(1), Flags::new(["\\Seen"])).await;
    let one = ItemRef {
        id: fake.find(INBOX, &msg(1)).unwrap().id,
        uid: None,
    };
    let mut session = fake.provider().connect().await.unwrap();
    let copy = |from: &str, to: &str| CommandBody::Copy {
        from: from.into(),
        to: to.into(),
        items: vec![one.clone()],
    };
    assert_eq!(
        session
            .apply(&copy(INBOX, "AAMkProjects"), None)
            .await
            .unwrap(),
        WriteOutcome::Applied
    );
    let copied = fake.find("AAMkProjects", &msg(1)).expect("copied");
    assert!(copied.read && copied.id != one.id);
    assert!(fake.find(INBOX, &msg(1)).is_some());
    assert_eq!(
        session
            .apply(&copy(INBOX, "AAMkNowhere"), None)
            .await
            .unwrap(),
        failed("no_such_mailbox")
    );
    assert!(matches!(
        session.apply(&copy("AAMkNowhere", INBOX), None).await,
        Err(MailError::MailboxNotFound)
    ));
    assert!(matches!(
        session
            .apply(
                &CommandBody::SetFlags {
                    mailbox: "AAMkNowhere".into(),
                    items: vec![one.clone()],
                    add: Flags::new(["\\Seen"]),
                    remove: Flags::default(),
                },
                None
            )
            .await,
        Err(MailError::MailboxNotFound)
    ));

    let to_trash = |mailbox: &str, item: &ItemRef| CommandBody::Delete {
        mailbox: mailbox.into(),
        items: vec![item.clone()],
        to_trash: true,
    };
    assert_eq!(
        session.apply(&to_trash(INBOX, &one), None).await.unwrap(),
        WriteOutcome::Applied
    );
    assert!(fake.find(INBOX, &msg(1)).is_none());
    assert_eq!(fake.find("AAMkTrash", &msg(1)).unwrap().id, one.id);
    let before = fake.lock().requests.len();
    assert_eq!(
        session
            .apply(&to_trash("AAMkTrash", &one), None)
            .await
            .unwrap(),
        WriteOutcome::Applied,
        "already in the trash"
    );
    assert!(
        !fake.lock().requests[before..].iter().any(|r| r == "move"),
        "nothing is moved"
    );
    fake.lock()
        .folders
        .retain(|f| f.well_known.as_deref() != Some("deleteditems"));
    assert_eq!(
        session
            .apply(&to_trash("AAMkProjects", &copied_ref(&copied)), None)
            .await
            .unwrap(),
        failed("no_trash")
    );
}

fn copied_ref(m: &FakeMessage) -> ItemRef {
    ItemRef {
        id: m.id.clone(),
        uid: None,
    }
}

#[tokio::test]
async fn creates_renames_moves_and_deletes_folders() {
    let fake = FakeGraph::start().await;
    let mut session = fake.provider().connect().await.unwrap();
    let create = |path: &str| CommandBody::CreateMailbox { path: path.into() };
    let rename = |mailbox: &str, path: &str| CommandBody::RenameMailbox {
        mailbox: mailbox.into(),
        path: path.into(),
    };

    assert_eq!(
        session
            .apply(&create("Clients/Acme/2026"), None)
            .await
            .unwrap(),
        WriteOutcome::Applied,
        "missing levels are created"
    );
    let boxes = session.mailboxes().await.unwrap();
    let acme = id_at(&boxes, "Clients/Acme").expect("parent made");
    let year = id_at(&boxes, "Clients/Acme/2026").expect("folder made");
    assert_eq!(
        session
            .apply(&create("Inbox/projects"), None)
            .await
            .unwrap(),
        failed("exists"),
        "names compare without case"
    );
    assert_eq!(
        session.apply(&create("A//B"), None).await.unwrap(),
        failed("invalid_path")
    );
    fake.lock().folders.push(FakeFolder {
        id: "AAMkRaced".into(),
        name: "Raced".into(),
        parent: None,
        well_known: None,
        search: false,
    });
    assert_eq!(
        session.apply(&create("Raced"), None).await.unwrap(),
        failed("exists")
    );

    assert_eq!(
        session
            .apply(&rename(&year, "Clients/Acme/2027"), None)
            .await
            .unwrap(),
        WriteOutcome::Applied
    );
    assert!(fake.lock().requests.iter().any(|r| r == "folder_patch"));
    assert!(!fake.lock().requests.iter().any(|r| r == "folder_move"));
    let boxes = session.mailboxes().await.unwrap();
    assert_eq!(path_of(&boxes, &year).unwrap(), "Clients/Acme/2027");

    assert_eq!(
        session.apply(&rename(&acme, "Acme"), None).await.unwrap(),
        WriteOutcome::Applied,
        "a move to the top"
    );
    let boxes = session.mailboxes().await.unwrap();
    assert_eq!(path_of(&boxes, &acme).unwrap(), "Acme");
    assert_eq!(path_of(&boxes, &year).unwrap(), "Acme/2027");

    assert_eq!(
        session
            .apply(&rename(&year, "Inbox/Archive 2027"), None)
            .await
            .unwrap(),
        WriteOutcome::Applied,
        "a move and a rename"
    );
    let boxes = session.mailboxes().await.unwrap();
    assert_eq!(path_of(&boxes, &year).unwrap(), "Inbox/Archive 2027");

    assert_eq!(
        session
            .apply(&rename(&acme, "Inbox/Projects"), None)
            .await
            .unwrap(),
        failed("exists")
    );
    assert_eq!(
        session
            .apply(&rename(&acme, "Acme/Inner"), None)
            .await
            .unwrap(),
        failed("invalid_path"),
        "not into itself"
    );
    for protected in ["inbox", INBOX, "AAMkSent", "AAMkTrash"] {
        assert_eq!(
            session
                .apply(&rename(protected, "Elsewhere"), None)
                .await
                .unwrap(),
            failed("protected"),
            "{protected}"
        );
        assert_eq!(
            session
                .apply(
                    &CommandBody::DeleteMailbox {
                        mailbox: protected.into()
                    },
                    None
                )
                .await
                .unwrap(),
            failed("protected"),
            "{protected}"
        );
    }
    assert!(matches!(
        session.apply(&rename("AAMkGone", "X"), None).await,
        Err(MailError::MailboxNotFound)
    ));

    assert_eq!(
        session
            .apply(
                &CommandBody::DeleteMailbox {
                    mailbox: acme.clone()
                },
                None
            )
            .await
            .unwrap(),
        WriteOutcome::Applied
    );
    let boxes = session.mailboxes().await.unwrap();
    assert_eq!(
        path_of(&boxes, &acme).unwrap(),
        "Deleted Items/Acme",
        "Graph keeps deleted folders in Deleted Items"
    );
    assert!(matches!(
        session
            .apply(
                &CommandBody::DeleteMailbox {
                    mailbox: "AAMkGone".into()
                },
                None
            )
            .await,
        Err(MailError::MailboxNotFound)
    ));
}

#[tokio::test]
async fn a_conflict_from_graph_is_exists() {
    let fake = FakeGraph::start().await;
    let mut session = fake.provider().connect().await.unwrap();
    let id = {
        let mut f = fake.lock();
        f.make_folder(None, "Alpha");
        f.make_folder(None, "Beta");
        f.folders
            .iter()
            .find(|x| x.name == "Beta")
            .unwrap()
            .id
            .clone()
    };
    fake.lock()
        .folders
        .iter_mut()
        .find(|x| x.name == "Alpha")
        .unwrap()
        .search = true;
    assert_eq!(
        session
            .apply(
                &CommandBody::RenameMailbox {
                    mailbox: id,
                    path: "Alpha".into()
                },
                None
            )
            .await
            .unwrap(),
        failed("exists"),
        "a folder the listing hides still conflicts at Graph"
    );
}

#[test]
fn forbidden_writes_tell_missing_access_from_refusals() {
    use crate::http::access_denied;
    assert!(access_denied(b""));
    assert!(access_denied(br#"{"error":{"code":"ErrorAccessDenied"}}"#));
    assert!(!access_denied(
        br#"{"error":{"code":"ErrorDeleteDistinguishedFolder"}}"#
    ));
}
