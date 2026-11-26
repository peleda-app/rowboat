use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::Router;
use axum::body::Bytes as Body;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use skein_pim::testing::{PimServerControl, conformance, sample};

use super::*;

#[derive(Default)]
struct Coll {
    kind: Option<CollectionKind>,
    name: String,
    color: Option<String>,
    read_only: bool,
    items: BTreeMap<String, (u64, Vec<u8>)>,
    log: Vec<(u64, String)>,
}

#[derive(Default)]
struct DavState {
    collections: BTreeMap<String, Coll>,
    seq: u64,
    generation: u64,
    no_sync: bool,
    no_multiget: bool,
    no_ctag: bool,
    page: Option<usize>,
    busy: u32,
    redirect_root: Option<String>,
    well_known_to: Option<String>,
    requests: Vec<(String, String, bool)>,
    weak_put_etag: bool,
    entity_bomb: bool,
    auto_schedule: bool,
    schedule_reply: Vec<Option<String>>,
}

#[derive(Clone, Default)]
struct FakeDav(Arc<Mutex<DavState>>);

const BOOK: &str = "/dav/addressbooks/ada/contacts/";
const CAL: &str = "/dav/calendars/ada/work/";
const SHARED: &str = "/dav/calendars/ada/holidays/";

impl FakeDav {
    fn standard() -> Self {
        let fake = Self::default();
        {
            let mut s = fake.0.lock().unwrap();
            s.collections.insert(
                BOOK.into(),
                Coll {
                    kind: Some(CollectionKind::AddressBook),
                    name: "Contacts".into(),
                    ..Coll::default()
                },
            );
            s.collections.insert(
                CAL.into(),
                Coll {
                    kind: Some(CollectionKind::Calendar),
                    name: "Work & Life".into(),
                    color: Some("#336699FF".into()),
                    ..Coll::default()
                },
            );
            s.collections.insert(
                SHARED.into(),
                Coll {
                    kind: Some(CollectionKind::Calendar),
                    name: "Holidays".into(),
                    read_only: true,
                    ..Coll::default()
                },
            );
        }
        fake
    }

    fn requests(&self) -> Vec<(String, String, bool)> {
        self.0.lock().unwrap().requests.clone()
    }

    fn set(&self, f: impl FnOnce(&mut DavState)) {
        f(&mut self.0.lock().unwrap());
    }
}

fn locate(s: &DavState, path: &str) -> Option<(String, String)> {
    s.collections.keys().find_map(|c| {
        let name = path.strip_prefix(c.as_str())?;
        (!name.is_empty() && !name.contains('/')).then(|| (c.clone(), name.to_owned()))
    })
}

fn tag(seq: u64) -> String {
    format!("\"{seq}\"")
}

fn holds(headers: &HeaderMap, current: Option<u64>) -> bool {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    if header("if-none-match") == Some("*") && current.is_some() {
        return false;
    }
    match header("if-match") {
        Some("*") => current.is_some(),
        Some(expected) => current.is_some_and(|c| tag(c) == expected),
        None => true,
    }
}

fn write_item(s: &mut DavState, coll: &str, name: &str, raw: Option<Vec<u8>>) -> u64 {
    s.seq += 1;
    let seq = s.seq;
    let c = s.collections.get_mut(coll).unwrap();
    match raw {
        Some(raw) => {
            c.items.insert(name.into(), (seq, raw));
        }
        None => {
            c.items.remove(name);
        }
    }
    c.log.push((seq, name.into()));
    seq
}

#[async_trait]
impl PimServerControl for FakeDav {
    async fn put(&self, collection: &str, name: &str, bytes: &[u8]) {
        let mut s = self.0.lock().unwrap();
        write_item(&mut s, collection, name, Some(bytes.to_vec()));
    }

    async fn remove(&self, collection: &str, name: &str) {
        let mut s = self.0.lock().unwrap();
        if s.collections[collection].items.contains_key(name) {
            write_item(&mut s, collection, name, None);
        }
    }

    async fn invalidate(&self, _collection: &str) -> bool {
        let mut s = self.0.lock().unwrap();
        s.generation += 1;
        !s.no_sync
    }

    async fn read(&self, collection: &str, item: &ItemRef) -> Option<(Option<String>, Bytes)> {
        let s = self.0.lock().unwrap();
        let name = item.id.strip_prefix(collection)?;
        s.collections
            .get(collection)?
            .items
            .get(name)
            .map(|(seq, raw)| (Some(tag(*seq)), Bytes::from(raw.clone())))
    }

    async fn contents(&self, collection: &str) -> Vec<Bytes> {
        let s = self.0.lock().unwrap();
        let mut v: Vec<Bytes> = s.collections[collection]
            .items
            .values()
            .map(|(_, r)| Bytes::from(r.clone()))
            .collect();
        v.sort();
        v
    }
}

fn esc(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\r', "&#13;")
}

fn multistatus(inner: String) -> Response {
    (
        StatusCode::from_u16(207).unwrap(),
        [("content-type", "application/xml; charset=utf-8")],
        format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus xmlns:D=\"DAV:\" \
             xmlns:C=\"urn:ietf:params:xml:ns:carddav\" xmlns:K=\"urn:ietf:params:xml:ns:caldav\" \
             xmlns:CS=\"http://calendarserver.org/ns/\" xmlns:A=\"http://apple.com/ns/ical/\">\
             {inner}</D:multistatus>"
        ),
    )
        .into_response()
}

fn ok(href: &str, props: &str) -> String {
    format!(
        "<D:response><D:href>{}</D:href><D:propstat><D:prop>{props}</D:prop>\
         <D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>",
        path::encode(href)
    )
}

fn token(s: &DavState, seq: u64) -> String {
    format!("http://example.com/ns/sync/{}-{seq}", s.generation)
}

fn authorized(headers: &HeaderMap) -> bool {
    let Some(value) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("ada@example.com:app-secret")
    );
    value == basic || value == "Bearer token-1"
}

fn coll_props(s: &DavState, coll: &Coll) -> String {
    let last = coll.log.last().map_or(0, |(seq, _)| *seq);
    let kind = match coll.kind {
        Some(CollectionKind::AddressBook) => "<C:addressbook/>",
        _ => "<K:calendar/>",
    };
    let mut props = format!(
        "<D:resourcetype><D:collection/>{kind}</D:resourcetype>\
         <D:displayname>{}</D:displayname>",
        esc(&coll.name),
    );
    if !s.no_ctag {
        props.push_str(&format!(
            "<CS:getctag>ctag-{}-{last}</CS:getctag>",
            s.generation
        ));
    }
    let privileges = if coll.read_only {
        "<D:privilege><D:read/></D:privilege>"
    } else {
        "<D:privilege><D:read/></D:privilege><D:privilege><D:write/></D:privilege>"
    };
    props.push_str(&format!(
        "<D:current-user-privilege-set>{privileges}</D:current-user-privilege-set>"
    ));
    if let Some(color) = &coll.color {
        props.push_str(&format!("<A:calendar-color>{color}</A:calendar-color>"));
    }
    if coll.kind == Some(CollectionKind::Calendar) {
        props.push_str(
            "<K:supported-calendar-component-set><K:comp name=\"VEVENT\"/>\
             <K:comp name=\"vtodo\"/></K:supported-calendar-component-set>",
        );
    }
    props
}

async fn handle(
    State(fake): State<FakeDav>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let path = path::id(&Url::parse(&format!("http://x{}", uri.path())).unwrap());
    let mut s = fake.0.lock().unwrap();
    s.requests.push((
        method.to_string(),
        path.clone(),
        headers.contains_key("authorization"),
    ));
    if path.starts_with("/.well-known/") {
        let to = s.well_known_to.clone().unwrap_or_else(|| "/dav/".into());
        return (StatusCode::MOVED_PERMANENTLY, [("location", to)]).into_response();
    }
    if s.busy > 0 {
        s.busy -= 1;
        return (StatusCode::SERVICE_UNAVAILABLE, [("retry-after", "0")]).into_response();
    }
    if !authorized(&headers) {
        return (
            StatusCode::UNAUTHORIZED,
            [("www-authenticate", "Basic realm=\"dav\"")],
        )
            .into_response();
    }
    let depth = headers
        .get("depth")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("infinity")
        .to_owned();
    match (method.as_str(), path.as_str()) {
        ("PROPFIND", "/dav/") => {
            if let Some(to) = s.redirect_root.clone() {
                return (StatusCode::TEMPORARY_REDIRECT, [("location", to)]).into_response();
            }
            if s.entity_bomb {
                return (
                    StatusCode::from_u16(207).unwrap(),
                    "<?xml version=\"1.0\"?><!DOCTYPE m [<!ENTITY a \"aaaaaaaaaa\">]>\
                     <D:multistatus xmlns:D=\"DAV:\"><D:response><D:href>&a;</D:href>\
                     </D:response></D:multistatus>",
                )
                    .into_response();
            }
            multistatus(ok(
                "/dav/",
                "<D:current-user-principal><D:href>/dav/principals/ada/</D:href>\
                 </D:current-user-principal><D:resourcetype><D:collection/></D:resourcetype>",
            ))
        }
        ("PROPFIND", "/dav/principals/ada/") => multistatus(ok(
            "/dav/principals/ada/",
            "<C:addressbook-home-set><D:href>/dav/addressbooks/ada/</D:href></C:addressbook-home-set>\
             <K:calendar-home-set><D:href>/dav/calendars/ada/</D:href>\
             <D:href>https://elsewhere.example.org/dav/calendars/ada/</D:href></K:calendar-home-set>\
             <K:calendar-user-address-set><D:href>mailto:Ada@Example.com</D:href>\
             <D:href>/dav/principals/ada/</D:href><D:href>MAILTO:ada@example.org</D:href>\
             </K:calendar-user-address-set>\
             <K:schedule-inbox-URL><D:href>/dav/calendars/ada/inbox/</D:href></K:schedule-inbox-URL>",
        )),
        ("OPTIONS", p) if s.collections.contains_key(p) => {
            let dav = if s.auto_schedule {
                "1, 3, access-control, calendar-access, calendar-auto-schedule"
            } else {
                "1, 3, access-control, calendar-access"
            };
            (StatusCode::OK, [("dav", dav)]).into_response()
        }
        ("PROPFIND", home @ ("/dav/addressbooks/ada/" | "/dav/calendars/ada/")) => {
            let mut inner = ok(home, "<D:resourcetype><D:collection/></D:resourcetype>");
            if depth == "1" {
                for (p, coll) in s
                    .collections
                    .iter()
                    .filter(|(p, _)| p.starts_with(home) && !p.ends_with("/inbox/"))
                {
                    inner.push_str(&ok(p, &coll_props(&s, coll)));
                }
                inner.push_str(&ok(
                    &format!("{home}inbox/"),
                    "<D:resourcetype><D:collection/><K:schedule-inbox/></D:resourcetype>",
                ));
            }
            multistatus(inner)
        }
        ("PROPFIND", p) if s.collections.contains_key(p) => {
            let coll = &s.collections[p];
            let mut inner = ok(p, &coll_props(&s, coll));
            if depth == "1" {
                for (name, (etag, _)) in &coll.items {
                    inner.push_str(&ok(
                        &format!("{p}{name}"),
                        &format!("<D:getetag>\"{etag}\"</D:getetag><D:resourcetype/>"),
                    ));
                }
            }
            multistatus(inner)
        }
        ("REPORT", p) if s.collections.contains_key(p) => {
            let request = xml::parse(&body).unwrap();
            if request.is(DAV, "sync-collection") {
                if s.no_sync {
                    return StatusCode::NOT_IMPLEMENTED.into_response();
                }
                let raw = request
                    .child(DAV, "sync-token")
                    .and_then(Element::trimmed)
                    .unwrap_or("")
                    .to_owned();
                let since = if raw.is_empty() {
                    None
                } else {
                    let parsed = raw
                        .rsplit('/')
                        .next()
                        .and_then(|t| t.split_once('-'))
                        .and_then(|(g, q)| Some((g.parse::<u64>().ok()?, q.parse::<u64>().ok()?)));
                    match parsed {
                        Some((generation, seq)) if generation == s.generation => Some(seq),
                        _ => {
                            return (
                                StatusCode::FORBIDDEN,
                                "<?xml version=\"1.0\"?><d:error xmlns:d=\"DAV:\"><d:valid-sync-token/></d:error>",
                            )
                                .into_response();
                        }
                    }
                };
                let coll = &s.collections[p];
                let mut latest: BTreeMap<&String, u64> = BTreeMap::new();
                for (seq, name) in &coll.log {
                    if since.is_none_or(|since| *seq > since) {
                        latest.insert(name, *seq);
                    }
                }
                let mut touched: Vec<(u64, &String)> =
                    latest.into_iter().map(|(n, q)| (q, n)).collect();
                touched.sort();
                if since.is_none() {
                    touched.retain(|(_, n)| coll.items.contains_key(*n));
                }
                let mut upto = coll
                    .log
                    .last()
                    .map_or(0, |(q, _)| *q)
                    .max(since.unwrap_or(0));
                let mut truncated = false;
                if let Some(page) = s.page
                    && touched.len() > page
                {
                    touched.truncate(page);
                    upto = touched.last().unwrap().0;
                    truncated = true;
                }
                let mut inner = String::new();
                for (_, name) in &touched {
                    let href = format!("{p}{name}");
                    match coll.items.get(*name) {
                        Some((etag, _)) => inner
                            .push_str(&ok(&href, &format!("<D:getetag>\"{etag}\"</D:getetag>"))),
                        None => inner.push_str(&format!(
                            "<D:response><D:href>{}</D:href>\
                             <D:status>HTTP/1.1 404 Not Found</D:status></D:response>",
                            path::encode(&href)
                        )),
                    }
                }
                if truncated {
                    inner.push_str(&format!(
                        "<D:response><D:href>{p}</D:href>\
                         <D:status>HTTP/1.1 507 Insufficient Storage</D:status></D:response>"
                    ));
                }
                inner.push_str(&format!("<D:sync-token>{}</D:sync-token>", token(&s, upto)));
                return multistatus(inner);
            }
            if s.no_multiget {
                return StatusCode::NOT_IMPLEMENTED.into_response();
            }
            let coll = &s.collections[p];
            let tag_name = match coll.kind {
                Some(CollectionKind::AddressBook) => "C:address-data",
                _ => "K:calendar-data",
            };
            let mut inner = String::new();
            for href in request.children(DAV, "href").filter_map(Element::trimmed) {
                let id = path::id(&Url::parse(&format!("http://x{href}")).unwrap());
                match id.strip_prefix(p).and_then(|n| coll.items.get(n)) {
                    Some((etag, raw)) => inner.push_str(&ok(
                        &id,
                        &format!(
                            "<D:getetag>\"{etag}\"</D:getetag><{tag_name}>{}</{tag_name}>",
                            esc(&String::from_utf8_lossy(raw))
                        ),
                    )),
                    None => inner.push_str(&format!(
                        "<D:response><D:href>{href}</D:href>\
                         <D:status>HTTP/1.1 404 Not Found</D:status></D:response>"
                    )),
                }
            }
            multistatus(inner)
        }
        ("PROPFIND", p) if locate(&s, p).is_some() => {
            let (coll, name) = locate(&s, p).unwrap();
            match s.collections[&coll].items.get(&name) {
                Some((seq, _)) => {
                    multistatus(ok(p, &format!("<D:getetag>{}</D:getetag>", tag(*seq))))
                }
                None => StatusCode::NOT_FOUND.into_response(),
            }
        }
        ("PUT", p) => {
            let Some((coll, name)) = locate(&s, p) else {
                return StatusCode::CONFLICT.into_response();
            };
            if s.collections[&coll].read_only {
                return (
                    StatusCode::FORBIDDEN,
                    "<D:error xmlns:D=\"DAV:\"><D:need-privileges/></D:error>",
                )
                    .into_response();
            }
            let current = s.collections[&coll].items.get(&name).map(|(seq, _)| *seq);
            if !holds(&headers, current) {
                return StatusCode::PRECONDITION_FAILED.into_response();
            }
            let reply = headers
                .get("schedule-reply")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            s.schedule_reply.push(reply);
            let seq = write_item(&mut s, &coll, &name, Some(body.to_vec()));
            let status = if current.is_some() {
                StatusCode::NO_CONTENT
            } else {
                StatusCode::CREATED
            };
            if s.weak_put_etag {
                (status, [("etag", format!("W/{}", tag(seq)))]).into_response()
            } else {
                (status, [("etag", tag(seq))]).into_response()
            }
        }
        ("DELETE", p) if locate(&s, p).is_some() => {
            let (coll, name) = locate(&s, p).unwrap();
            let current = s.collections[&coll].items.get(&name).map(|(seq, _)| *seq);
            if current.is_none() {
                return StatusCode::NOT_FOUND.into_response();
            }
            if !holds(&headers, current) {
                return StatusCode::PRECONDITION_FAILED.into_response();
            }
            write_item(&mut s, &coll, &name, None);
            StatusCode::NO_CONTENT.into_response()
        }
        ("GET", p) => {
            match locate(&s, p).and_then(|(c, n)| s.collections[&c].items.get(&n).cloned()) {
                Some((seq, raw)) => ([("etag", tag(seq))], raw).into_response(),
                None => StatusCode::NOT_FOUND.into_response(),
            }
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn serve(fake: FakeDav) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new().fallback(handle).with_state(fake);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{address}")
}

fn password() -> Credentials {
    Credentials::Password {
        secret: "app-secret".into(),
    }
}

fn provider(url: &str) -> DavProvider {
    DavProvider::new(DavConfig::at(url, "ada@example.com", password())).unwrap()
}

async fn both(fake: &FakeDav, provider: DavProvider) {
    let provider: Arc<dyn PimProvider> = Arc::new(provider);
    let control: Arc<dyn PimServerControl> = Arc::new(fake.clone());
    conformance(
        provider.clone(),
        control.clone(),
        CAL,
        CollectionKind::Calendar,
    )
    .await;
    conformance(provider, control, BOOK, CollectionKind::AddressBook).await;
}

#[tokio::test]
async fn keeps_the_contract_through_discovery() {
    let fake = FakeDav::standard();
    let base = serve(fake.clone()).await;
    both(&fake, provider(&base)).await;
    let requests = fake.requests();
    assert!(
        requests
            .iter()
            .filter(|(_, p, _)| p.starts_with("/.well-known/"))
            .all(|(_, _, auth)| !auth),
        "the well-known lookup goes without credentials"
    );
    assert!(requests.iter().any(|(m, _, _)| m == "REPORT"));
}

#[tokio::test]
async fn keeps_the_contract_without_sync_or_multiget() {
    let fake = FakeDav::standard();
    fake.set(|s| {
        s.no_sync = true;
        s.no_multiget = true;
    });
    let base = serve(fake.clone()).await;
    both(&fake, provider(&format!("{base}/dav/"))).await;
    assert!(fake.requests().iter().any(|(m, _, _)| m == "GET"));
}

#[tokio::test]
async fn keeps_the_contract_without_sync_or_ctag() {
    let fake = FakeDav::standard();
    fake.set(|s| {
        s.no_sync = true;
        s.no_ctag = true;
    });
    let base = serve(fake.clone()).await;
    both(&fake, provider(&base)).await;
}

#[tokio::test]
async fn keeps_the_contract_when_the_server_pages_sync() {
    let fake = FakeDav::standard();
    fake.set(|s| s.page = Some(2));
    let base = serve(fake.clone()).await;
    both(&fake, provider(&base)).await;
}

#[tokio::test]
async fn lists_collections_with_names_colors_access_and_components() {
    let fake = FakeDav::standard();
    let base = serve(fake.clone()).await;
    let mut session = provider(&base).connect().await.unwrap();
    let listed = session.collections().await.unwrap();
    let ids: Vec<&str> = listed.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(
        ids,
        vec![SHARED, CAL, BOOK],
        "no inbox, nothing from elsewhere"
    );
    let cal = &listed[1];
    assert_eq!(cal.name, "Work & Life");
    assert_eq!(cal.color.as_deref(), Some("#336699FF"));
    assert_eq!(cal.components, vec!["VEVENT", "VTODO"]);
    assert!(!cal.read_only);
    assert!(listed[0].read_only);
    assert_eq!(listed[2].kind, CollectionKind::AddressBook);
    assert!(
        fake.requests()
            .iter()
            .all(|(_, p, _)| !p.contains("elsewhere")),
        "a home set on another origin is never asked"
    );
}

#[tokio::test]
async fn pages_never_exceed_the_limit_and_resume_from_the_cursor() {
    let fake = FakeDav::standard();
    for n in 0..7 {
        fake.put(
            CAL,
            &format!("e{n}.ics"),
            &sample(CollectionKind::Calendar, &format!("e{n}")),
        )
        .await;
    }
    let base = serve(fake.clone()).await;
    let mut session = provider(&base).connect().await.unwrap();
    let mut cursor = None;
    let mut seen = 0;
    let mut calls = 0;
    loop {
        let page = session.changes(CAL, cursor.as_ref(), 3).await.unwrap();
        assert!(page.changes.len() <= 3);
        seen += page.changes.len();
        calls += 1;
        cursor = Some(page.cursor);
        if !page.more {
            break;
        }
    }
    assert_eq!((seen, calls), (7, 3));
    let reports = fake
        .requests()
        .iter()
        .filter(|(m, _, _)| m == "REPORT")
        .count();
    assert_eq!(reports, 1, "pending changes are handed out from the cursor");
}

#[tokio::test]
async fn refused_credentials_are_an_auth_error() {
    let fake = FakeDav::standard();
    let base = serve(fake.clone()).await;
    let config = DavConfig::at(
        &base,
        "ada@example.com",
        Credentials::Password {
            secret: "wrong".into(),
        },
    );
    let mut session = DavProvider::new(config).unwrap().connect().await.unwrap();
    assert!(matches!(session.collections().await, Err(PimError::Auth)));
    let bearer = DavConfig::at(
        &base,
        "",
        Credentials::AccessToken {
            token: "token-1".into(),
        },
    );
    let mut session = DavProvider::new(bearer).unwrap().connect().await.unwrap();
    assert_eq!(session.collections().await.unwrap().len(), 3);
}

#[tokio::test]
async fn credentials_never_follow_a_redirect_to_another_origin() {
    let fake = FakeDav::standard();
    let base = serve(fake.clone()).await;
    let other = serve(fake.clone()).await;
    fake.set(|s| s.redirect_root = Some(format!("{other}/dav/")));
    let mut session = provider(&format!("{base}/dav/")).connect().await.unwrap();
    assert!(matches!(
        session.collections().await,
        Err(PimError::Protocol(_))
    ));
    let with_auth = fake.requests().iter().filter(|(_, _, a)| *a).count();
    assert_eq!(
        with_auth, 1,
        "only the configured origin got the credentials"
    );

    let fake = FakeDav::standard();
    let base = serve(fake.clone()).await;
    fake.set(|s| s.well_known_to = Some("https://elsewhere.example.org/dav/".into()));
    let mut session = provider(&base).connect().await.unwrap();
    assert!(
        matches!(session.collections().await, Err(PimError::Config(_))),
        "a well-known answer pointing elsewhere is not followed"
    );
}

#[tokio::test]
async fn busy_servers_are_waited_out_then_reported_as_throttled() {
    let fake = FakeDav::standard();
    let base = serve(fake.clone()).await;
    fake.set(|s| s.busy = 2);
    let mut session = provider(&format!("{base}/dav/")).connect().await.unwrap();
    assert_eq!(session.collections().await.unwrap().len(), 3);
    fake.set(|s| s.busy = 10);
    assert!(matches!(
        session.changes(CAL, None, 10).await,
        Err(PimError::Throttled { .. })
    ));
}

#[test]
fn only_https_or_loopback_addresses_unless_allowed() {
    let config = |url: &str| DavConfig::at(url, "ada@example.com", password());
    assert!(DavProvider::new(config("https://dav.example.com/")).is_ok());
    assert!(DavProvider::new(config("dav.example.com")).is_ok());
    assert!(DavProvider::new(config("http://127.0.0.1:5232/")).is_ok());
    assert!(matches!(
        DavProvider::new(config("http://dav.example.com/")),
        Err(PimError::Config(_))
    ));
    assert!(matches!(
        DavProvider::new(config("https://ada:pw@dav.example.com/")),
        Err(PimError::Config(_))
    ));
    let mut plain = config("http://dav.example.com/");
    plain.allow_insecure_plain = true;
    assert!(DavProvider::new(plain).is_ok());
    let mut none = config("https://dav.example.com/");
    none.calendars = None;
    none.contacts = None;
    assert!(matches!(DavProvider::new(none), Err(PimError::Config(_))));
    let debug = format!("{:?}", config("https://dav.example.com/"));
    assert!(!debug.contains("app-secret") && !debug.contains("ada@"));
}

#[tokio::test]
async fn entity_declarations_are_refused() {
    let fake = FakeDav::standard();
    fake.set(|s| s.entity_bomb = true);
    let base = serve(fake.clone()).await;
    let mut session = provider(&format!("{base}/dav/")).connect().await.unwrap();
    assert!(matches!(
        session.collections().await,
        Err(PimError::Protocol(_))
    ));
}

#[tokio::test]
async fn writes_refused_by_the_server_fail_and_puts_read_the_object_back() {
    let fake = FakeDav::standard();
    let base = serve(fake.clone()).await;
    let mut session = provider(&base).connect().await.unwrap();
    session.collections().await.unwrap();
    let put = |collection: &str, key: &str| PimWrite::Put {
        collection: collection.into(),
        item: None,
        bytes: Bytes::from(sample(CollectionKind::Calendar, key)),
        if_version: None,
        key: key.into(),
        notify: false,
    };
    assert_eq!(
        session.apply(&put(SHARED, "a")).await.unwrap(),
        WriteOutcome::Failed {
            reason: "need-privileges".into()
        }
    );
    let WriteOutcome::Applied { item, current } = session.apply(&put(CAL, "b")).await.unwrap()
    else {
        panic!("applied");
    };
    let item = item.unwrap();
    assert_eq!(item.id, format!("{CAL}b.ics"));
    let current = current.expect("the object is read back");
    let (version, held) = fake.read(CAL, &item).await.unwrap();
    assert_eq!((current.version, current.bytes), (version, held));
    fake.set(|s| s.weak_put_etag = true);
    assert!(matches!(
        session.apply(&put(CAL, "c")).await.unwrap(),
        WriteOutcome::Applied {
            current: Some(_),
            ..
        }
    ));
    let huge = PimWrite::Put {
        collection: CAL.into(),
        item: None,
        bytes: Bytes::from(vec![b'x'; MAX_ITEM + 1]),
        if_version: None,
        key: "d".into(),
        notify: false,
    };
    assert_eq!(
        session.apply(&huge).await.unwrap(),
        WriteOutcome::Failed {
            reason: "too_large".into()
        }
    );
    let outside = PimWrite::Delete {
        collection: CAL.into(),
        item: ItemRef {
            id: format!("{BOOK}x.vcf"),
            uid: None,
        },
        if_version: None,
        notify: false,
    };
    assert_eq!(
        session.apply(&outside).await.unwrap(),
        WriteOutcome::Failed {
            reason: "not_in_collection".into()
        }
    );
    assert!(matches!(
        session.changes("/dav/calendars/ada/gone/", None, 10).await,
        Err(PimError::NotFound)
    ));
}

const INVITE: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Example//EN\r\nBEGIN:VEVENT\r\n\
UID:sync-1@example.org\r\nDTSTAMP:20261101T000000Z\r\nDTSTART:20261130T090000Z\r\n\
SUMMARY:Sync\r\nORGANIZER:mailto:bob@example.org\r\n\
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:ada@example.com\r\n\
ATTENDEE;PARTSTAT=ACCEPTED:mailto:carol@example.org\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

#[tokio::test]
async fn reads_rfc_6638_scheduling_from_options_and_the_principal() {
    let fake = FakeDav::standard();
    let base = serve(fake.clone()).await;
    let mut session = provider(&base).connect().await.unwrap();
    session.collections().await.unwrap();
    assert_eq!(session.scheduling(CAL).await.unwrap(), Scheduling::Client);
    assert_eq!(session.scheduling(BOOK).await.unwrap(), Scheduling::Client);
    assert!(matches!(
        session.scheduling("/dav/calendars/ada/gone/").await,
        Err(PimError::NotFound)
    ));
    assert_eq!(
        session.addresses().await.unwrap(),
        vec!["ada@example.com", "ada@example.org"]
    );
    fake.set(|s| s.auto_schedule = true);
    let mut fresh = provider(&base).connect().await.unwrap();
    fresh.collections().await.unwrap();
    assert_eq!(fresh.scheduling(CAL).await.unwrap(), Scheduling::Server);
    fresh.scheduling(CAL).await.unwrap();
    let options = fake
        .requests()
        .iter()
        .filter(|(m, p, _)| m == "OPTIONS" && p == CAL)
        .count();
    assert_eq!(options, 2, "asked once per session");
}

#[tokio::test]
async fn answers_invitations_by_writing_the_attendee_copy() {
    let fake = FakeDav::standard();
    let base = serve(fake.clone()).await;
    fake.put(CAL, "sync.ics", INVITE.as_bytes()).await;
    let mut session = provider(&base).connect().await.unwrap();
    session.collections().await.unwrap();
    let item = ItemRef {
        id: format!("{CAL}sync.ics"),
        uid: None,
    };
    let respond =
        |attendee: Option<&str>, if_version: Option<&str>, notify: bool| PimWrite::Respond {
            collection: CAL.into(),
            item: item.clone(),
            answer: skein_core::PartStat::Accepted,
            attendee: attendee.map(str::to_owned),
            comment: Some("Fine".into()),
            if_version: if_version.map(str::to_owned),
            notify,
        };
    assert_eq!(
        session
            .apply(&respond(None, Some("\"999\""), true))
            .await
            .unwrap(),
        WriteOutcome::Conflict {
            current: Some(tag(1))
        }
    );
    let WriteOutcome::Applied {
        current: Some(current),
        ..
    } = session.apply(&respond(None, None, false)).await.unwrap()
    else {
        panic!("applied");
    };
    let held = String::from_utf8(current.bytes.to_vec()).unwrap();
    assert!(held.contains("PARTSTAT=ACCEPTED:mailto:ada@example.com"));
    assert!(held.contains("COMMENT:Fine"));
    assert!(held.contains("PARTSTAT=ACCEPTED:mailto:carol@example.org"));
    assert!(!held.contains("RSVP"));
    assert_eq!(
        fake.0.lock().unwrap().schedule_reply.last().cloned(),
        Some(Some("F".into()))
    );
    session
        .apply(&respond(Some("CAROL@example.org"), None, true))
        .await
        .unwrap();
    assert_eq!(
        fake.0.lock().unwrap().schedule_reply.last().cloned(),
        Some(None)
    );
    assert_eq!(
        session
            .apply(&respond(Some("eve@example.net"), None, true))
            .await
            .unwrap(),
        WriteOutcome::Failed {
            reason: "attendee_not_found".into()
        }
    );
    let book = PimWrite::Respond {
        collection: BOOK.into(),
        item: ItemRef {
            id: format!("{BOOK}x.vcf"),
            uid: None,
        },
        answer: skein_core::PartStat::Declined,
        attendee: None,
        comment: None,
        if_version: None,
        notify: true,
    };
    assert_eq!(
        session.apply(&book).await.unwrap(),
        WriteOutcome::Failed {
            reason: "not_a_calendar".into()
        }
    );
    let gone = PimWrite::Respond {
        collection: CAL.into(),
        item: ItemRef {
            id: format!("{CAL}gone.ics"),
            uid: None,
        },
        answer: skein_core::PartStat::Declined,
        attendee: None,
        comment: None,
        if_version: None,
        notify: true,
    };
    assert_eq!(
        session.apply(&gone).await.unwrap(),
        WriteOutcome::Conflict { current: None }
    );
}

#[tokio::test]
async fn lists_the_scheduling_inbox_when_asked() {
    let fake = FakeDav::standard();
    const INBOX: &str = "/dav/calendars/ada/inbox/";
    fake.set(|s| {
        s.collections.insert(
            INBOX.into(),
            Coll {
                kind: Some(CollectionKind::Calendar),
                name: "Inbox".into(),
                ..Coll::default()
            },
        );
    });
    fake.put(INBOX, "msg-1.ics", INVITE.as_bytes()).await;
    let base = serve(fake.clone()).await;
    let plain = provider(&base)
        .connect()
        .await
        .unwrap()
        .collections()
        .await
        .unwrap();
    assert!(plain.iter().all(|c| c.id != INBOX && c.role.is_none()));
    let mut config = DavConfig::at(&base, "ada@example.com", password());
    config.schedule_inbox = true;
    let mut session = DavProvider::new(config).unwrap().connect().await.unwrap();
    let listed = session.collections().await.unwrap();
    let inbox = listed
        .iter()
        .find(|c| c.id == INBOX)
        .expect("the inbox is listed");
    assert_eq!(inbox.role, Some(skein_core::CollectionRole::ScheduleInbox));
    assert_eq!(inbox.kind, CollectionKind::Calendar);
    assert_eq!(listed.len(), plain.len() + 1);
    let changes = session.changes(INBOX, None, 10).await.unwrap();
    assert_eq!(changes.changes.len(), 1);
    let gone = PimWrite::Delete {
        collection: INBOX.into(),
        item: ItemRef {
            id: format!("{INBOX}msg-1.ics"),
            uid: None,
        },
        if_version: None,
        notify: false,
    };
    assert!(matches!(
        session.apply(&gone).await.unwrap(),
        WriteOutcome::Applied { .. }
    ));
    assert!(fake.contents(INBOX).await.is_empty());
}
