//! Calendars and contacts on CalDAV (RFC 4791) and CardDAV (RFC 6352) servers behind the
//! [`skein_pim`] contract.
//!
//! Discovery follows RFC 6764 (`/.well-known/caldav`, `/.well-known/carddav`), then the current
//! user principal and its home sets. Changes come from `sync-collection` (RFC 6578) with the sync
//! token as the cursor, or from an ETag listing (`getctag` first) where the server lacks it;
//! bytes come from `calendar-multiget` and `addressbook-multiget`, or one `GET` each. Writes are
//! a `PUT` with `If-None-Match: *` (create) or `If-Match` (replace) and a `DELETE` with
//! `If-Match`.

mod cursor;
#[doc(hidden)]
pub mod fuzzing;
mod http;
mod path;
mod schedule;
mod write;
mod xml;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use reqwest::StatusCode;
use skein_core::{CollectionInfo, CollectionKind, Credentials, ItemRef, TlsRoots};
use skein_pim::{
    Cursor, PimChange, PimChanges, PimError, PimProvider, PimSession, PimWrite, RawObject,
    Scheduling, WriteOutcome,
};
use url::Url;

use crate::cursor::DavCursor;
use crate::http::{Auth, Http, MAX_ITEM, MAX_XML, allowed_scheme, status_error};
use crate::xml::{CALDAV, CARDDAV, DAV, Element};

/// Objects asked for in one multiget.
pub const BATCH: usize = 50;
const MAX_ITEMS: usize = 1_000_000;

/// Where to find a CalDAV and a CardDAV server and how to sign in.
#[derive(Clone)]
pub struct DavConfig {
    /// Where calendars are looked for: a server (`https://dav.example.com`, whose well-known
    /// address is asked), a DAV root, a principal, a home set or one calendar. `None` reads no
    /// calendars.
    pub calendars: Option<String>,
    /// The same for address books. `None` reads no contacts.
    pub contacts: Option<String>,
    /// The user name sent with a password; unused with an access token.
    pub username: String,
    /// A password (HTTP Basic) or an access token (Bearer).
    pub credentials: Credentials,
    /// Longest wait for one answer.
    pub timeout: Duration,
    /// Allows plain `http://` to hosts other than loopback. Off by default: credentials and
    /// objects would cross the network unencrypted.
    pub allow_insecure_plain: bool,
    /// Extra trusted roots for TLS, besides the built-in ones.
    pub roots: TlsRoots,
    /// Also lists the principal's scheduling inbox (RFC 6638), with the role `schedule_inbox`,
    /// when the server has one. Off by default.
    pub schedule_inbox: bool,
}

impl std::fmt::Debug for DavConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DavConfig")
            .field("calendars", &self.calendars.is_some())
            .field("contacts", &self.contacts.is_some())
            .field("credentials", &self.credentials)
            .field("timeout", &self.timeout)
            .field("allow_insecure_plain", &self.allow_insecure_plain)
            .finish_non_exhaustive()
    }
}

impl DavConfig {
    /// Both kinds at `url`, as Radicale, Baïkal and Nextcloud serve them, with a one-minute
    /// timeout and built-in TLS roots only.
    pub fn at(url: &str, username: &str, credentials: Credentials) -> Self {
        Self {
            calendars: Some(url.to_owned()),
            contacts: Some(url.to_owned()),
            username: username.to_owned(),
            credentials,
            timeout: Duration::from_secs(60),
            allow_insecure_plain: false,
            roots: TlsRoots::default(),
            schedule_inbox: false,
        }
    }
}

/// A CalDAV and CardDAV account.
///
/// Credentials go only to the origins of the configured addresses, over https (plain http only
/// to loopback unless [`DavConfig::allow_insecure_plain`]); a redirect, home set or well-known
/// answer that leads to another origin is not followed with them. Answers are capped at 64 MiB
/// for listings and 16 MiB per object; busy servers (`429`, `503`, `504`) are tried three times
/// within about ten seconds, then reported as `Throttled`. Logs carry counts and status codes,
/// never names, paths, objects or credentials.
pub struct DavProvider {
    inner: Arc<Inner>,
}

struct Inner {
    http: Http,
    calendars: Option<Url>,
    contacts: Option<Url>,
    schedule_inbox: bool,
}

fn parse_url(raw: &str, insecure: bool) -> Result<Url, PimError> {
    let raw = raw.trim();
    let with_scheme = if raw.contains("://") {
        raw.to_owned()
    } else {
        format!("https://{raw}")
    };
    let url = Url::parse(&with_scheme)
        .map_err(|_| PimError::Config("the DAV address is not a URL".into()))?;
    if !allowed_scheme(&url, insecure) || url.host_str().is_none() {
        return Err(PimError::Config(
            "the DAV address must use https (plain http only to loopback)".into(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(PimError::Config(
            "the DAV address must not hold a user name or password".into(),
        ));
    }
    Ok(url)
}

impl DavProvider {
    /// A provider for `config`. `Config` for an address that is not https (or allowed plain
    /// http), or when neither kind is configured. Nothing is sent before the first call.
    pub fn new(config: DavConfig) -> Result<Self, PimError> {
        let insecure = config.allow_insecure_plain;
        let calendars = config
            .calendars
            .as_deref()
            .map(|u| parse_url(u, insecure))
            .transpose()?;
        let contacts = config
            .contacts
            .as_deref()
            .map(|u| parse_url(u, insecure))
            .transpose()?;
        if calendars.is_none() && contacts.is_none() {
            return Err(PimError::Config("no calendars or contacts address".into()));
        }
        let origins = calendars
            .iter()
            .chain(contacts.iter())
            .map(Url::origin)
            .collect();
        let http = Http::new(
            Auth::new(&config.username, &config.credentials)?,
            origins,
            config.timeout,
            &config.roots,
            insecure,
        )?;
        Ok(Self {
            inner: Arc::new(Inner {
                http,
                calendars,
                contacts,
                schedule_inbox: config.schedule_inbox,
            }),
        })
    }
}

#[async_trait]
impl PimProvider for DavProvider {
    async fn connect(&self) -> Result<Box<dyn PimSession>, PimError> {
        Ok(Box::new(DavSession {
            inner: self.inner.clone(),
            found: HashMap::new(),
            listed: false,
            principal: None,
            auto: HashMap::new(),
        }))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Found {
    pub url: Url,
    pub kind: CollectionKind,
}

/// A session: the collections found so far and the shared client.
pub(crate) struct DavSession {
    inner: Arc<Inner>,
    found: HashMap<String, Found>,
    listed: bool,
    principal: Option<schedule::Principal>,
    auto: HashMap<String, bool>,
}

enum Start {
    Homes(Vec<Url>),
    Collection(Url),
}

fn kind_names(kind: CollectionKind) -> (&'static str, &'static str, &'static str, &'static str) {
    match kind {
        CollectionKind::AddressBook => (CARDDAV, "card", "addressbook-home-set", "addressbook"),
        CollectionKind::Calendar => (CALDAV, "cal", "calendar-home-set", "calendar"),
    }
}

fn well_known_path(kind: CollectionKind) -> &'static str {
    match kind {
        CollectionKind::AddressBook => "/.well-known/carddav",
        CollectionKind::Calendar => "/.well-known/caldav",
    }
}

/// The `prop` elements of a response whose `propstat` says 2xx, merged.
pub(crate) fn ok_props(response: &Element) -> Vec<&Element> {
    response
        .children(DAV, "propstat")
        .filter(|p| {
            xml::status_code(p.child(DAV, "status")).is_none_or(|s| (200..300).contains(&s))
        })
        .filter_map(|p| p.child(DAV, "prop"))
        .collect()
}

pub(crate) fn prop<'a>(props: &[&'a Element], ns: &str, name: &str) -> Option<&'a Element> {
    props.iter().find_map(|p| p.child(ns, name))
}

fn multistatus(answer: &http::Answer) -> Result<Element, PimError> {
    xml::parse(&answer.body)
        .filter(|root| root.is(DAV, "multistatus"))
        .ok_or_else(|| PimError::Protocol("the server did not answer with WebDAV".into()))
}

fn is_multistatus(status: StatusCode) -> bool {
    status.as_u16() == 207
}

pub(crate) fn etag(props: &[&Element]) -> Option<String> {
    prop(props, DAV, "getetag")
        .and_then(Element::trimmed)
        .map(str::to_owned)
}

fn item(id: String) -> ItemRef {
    ItemRef { id, uid: None }
}

fn read_only(props: &[&Element]) -> bool {
    let Some(set) = prop(props, DAV, "current-user-privilege-set") else {
        return false;
    };
    !set.children(DAV, "privilege").any(|p| {
        ["all", "write", "write-content"]
            .iter()
            .any(|name| p.child(DAV, name).is_some())
    })
}

enum SyncError {
    Expired,
    Unsupported,
    Other(PimError),
}

impl From<PimError> for SyncError {
    fn from(e: PimError) -> Self {
        Self::Other(e)
    }
}

/// One `sync-collection` answer: the objects changed (with their ETags) and removed since the
/// token, the next token, and whether the server cut the list short.
struct SyncPage {
    up: BTreeMap<String, Option<String>>,
    gone: BTreeSet<String>,
    token: String,
    truncated: bool,
}

impl DavSession {
    async fn propfind(
        &self,
        url: &Url,
        depth: &str,
        props: &str,
    ) -> Result<(Element, Url), PimError> {
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
             <d:propfind xmlns:d=\"DAV:\" xmlns:card=\"urn:ietf:params:xml:ns:carddav\" \
             xmlns:cal=\"urn:ietf:params:xml:ns:caldav\" xmlns:cs=\"http://calendarserver.org/ns/\" \
             xmlns:ical=\"http://apple.com/ns/ical/\"><d:prop>{props}</d:prop></d:propfind>"
        );
        let answer = self
            .inner
            .http
            .dav("PROPFIND", url, Some(depth), Some(&body), MAX_XML)
            .await?;
        if !is_multistatus(answer.status) {
            return Err(status_error(answer.status, &answer.url));
        }
        Ok((multistatus(&answer)?, answer.url))
    }

    async fn resolve(&self, kind: CollectionKind, configured: &Url) -> Result<Url, PimError> {
        let mut url = configured.clone();
        if matches!(url.path(), "" | "/") || url.path().starts_with("/.well-known/") {
            let mut probe = url.clone();
            if matches!(url.path(), "" | "/") {
                probe.set_path(well_known_path(kind));
            }
            if let Some(found) = self.inner.http.well_known(&probe).await? {
                url = found;
            } else if url.path().starts_with("/.well-known/") {
                url.set_path("/");
            }
        }
        Ok(url)
    }

    async fn start(&self, kind: CollectionKind, configured: &Url) -> Result<Start, PimError> {
        let url = self.resolve(kind, configured).await?;
        let (ns, p, home_set, collection) = kind_names(kind);
        let props = format!("<d:current-user-principal/><d:resourcetype/><{p}:{home_set}/>");
        let (root, url) = match self.propfind(&url, "0", &props).await {
            Ok(found) => found,
            Err(PimError::NotFound) => {
                return Err(PimError::Config(format!(
                    "no {} at the configured address",
                    if kind == CollectionKind::AddressBook {
                        "CardDAV"
                    } else {
                        "CalDAV"
                    }
                )));
            }
            Err(error) => return Err(error),
        };
        let Some(response) = root.child(DAV, "response") else {
            return Ok(Start::Homes(vec![url]));
        };
        let props = ok_props(response);
        let homes = |props: &[&Element], base: &Url| -> Vec<Url> {
            prop(props, ns, home_set)
                .map(|set| {
                    set.children(DAV, "href")
                        .filter_map(Element::trimmed)
                        .filter_map(|h| base.join(h).ok())
                        .collect()
                })
                .unwrap_or_default()
        };
        let found = homes(&props, &url);
        if !found.is_empty() {
            return Ok(Start::Homes(found));
        }
        if prop(&props, DAV, "resourcetype").is_some_and(|t| t.child(ns, collection).is_some()) {
            return Ok(Start::Collection(url));
        }
        if let Some(principal) = prop(&props, DAV, "current-user-principal")
            .and_then(|p| p.child(DAV, "href"))
            .and_then(Element::trimmed)
            .and_then(|h| url.join(h).ok())
            .filter(|u| self.inner.http.may_sign_in(u))
        {
            let (root, principal) = self
                .propfind(&principal, "0", &format!("<{p}:{home_set}/>"))
                .await?;
            if let Some(response) = root.child(DAV, "response") {
                let found = homes(&ok_props(response), &principal);
                if !found.is_empty() {
                    return Ok(Start::Homes(found));
                }
            }
        }
        Ok(Start::Homes(vec![url]))
    }

    async fn collections_of(
        &self,
        kind: CollectionKind,
        configured: &Url,
    ) -> Result<Vec<(CollectionInfo, Url)>, PimError> {
        let (urls, depth) = match self.start(kind, configured).await? {
            Start::Homes(homes) => (homes, "1"),
            Start::Collection(url) => (vec![url], "0"),
        };
        let (ns, _, _, collection_type) = kind_names(kind);
        let mut out = Vec::new();
        for url in urls {
            if !self.inner.http.may_sign_in(&url) {
                tracing::warn!("a DAV home set on another origin is skipped");
                continue;
            }
            let (root, base) = self
                .propfind(
                    &url,
                    depth,
                    "<d:resourcetype/><d:displayname/><ical:calendar-color/>\
                     <cal:supported-calendar-component-set/><d:current-user-privilege-set/>",
                )
                .await?;
            for response in root.children(DAV, "response") {
                let Some(href) = response.child(DAV, "href").and_then(Element::trimmed) else {
                    continue;
                };
                let Ok(at) = base.join(href) else { continue };
                if !self.inner.http.may_sign_in(&at) {
                    continue;
                }
                let props = ok_props(response);
                let is_kind = prop(&props, DAV, "resourcetype")
                    .is_some_and(|t| t.child(ns, collection_type).is_some());
                if !is_kind {
                    continue;
                }
                let id = path::id(&at);
                let name = prop(&props, DAV, "displayname")
                    .and_then(Element::trimmed)
                    .map(str::to_owned)
                    .unwrap_or_else(|| path::last_segment(&id));
                let components = if kind == CollectionKind::Calendar {
                    prop(&props, CALDAV, "supported-calendar-component-set")
                        .map(|set| {
                            set.children(CALDAV, "comp")
                                .filter_map(|c| c.attr("name"))
                                .map(str::to_ascii_uppercase)
                                .collect()
                        })
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };
                let color = props
                    .iter()
                    .find_map(|p| p.child_named("calendar-color"))
                    .and_then(Element::trimmed)
                    .map(str::to_owned);
                out.push((
                    CollectionInfo {
                        id,
                        kind,
                        name,
                        color,
                        read_only: read_only(&props),
                        components,
                        role: None,
                    },
                    at,
                ));
            }
        }
        Ok(out)
    }

    async fn found(&mut self, id: &str) -> Result<Found, PimError> {
        if !self.listed && !self.found.contains_key(id) {
            self.collections().await?;
        }
        self.found.get(id).cloned().ok_or(PimError::NotFound)
    }

    async fn ctag(&self, url: &Url) -> Result<Option<String>, PimError> {
        let (root, _) = self.propfind(url, "0", "<cs:getctag/>").await?;
        Ok(root
            .child(DAV, "response")
            .map(ok_props)
            .and_then(|props| props.iter().find_map(|p| p.child_named("getctag")))
            .and_then(Element::trimmed)
            .map(str::to_owned))
    }

    async fn sync_round(
        &self,
        url: &Url,
        id: &str,
        token: Option<&str>,
    ) -> Result<SyncPage, SyncError> {
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
             <d:sync-collection xmlns:d=\"DAV:\"><d:sync-token>{}</d:sync-token>\
             <d:sync-level>1</d:sync-level><d:prop><d:getetag/></d:prop></d:sync-collection>",
            xml::escape(token.unwrap_or(""))
        );
        let answer = self
            .inner
            .http
            .dav("REPORT", url, Some("0"), Some(&body), MAX_XML)
            .await?;
        if !is_multistatus(answer.status) {
            let says_token = String::from_utf8_lossy(&answer.body).contains("valid-sync-token");
            return Err(match answer.status.as_u16() {
                _ if says_token && token.is_some() => SyncError::Expired,
                400 | 403 | 409 | 412 if token.is_some() => SyncError::Expired,
                404 | 410 => SyncError::Other(PimError::NotFound),
                400 | 403 | 405 | 409 | 412 | 415 | 422 | 501 => SyncError::Unsupported,
                _ => SyncError::Other(status_error(answer.status, &answer.url)),
            });
        }
        let root = multistatus(&answer)?;
        let mut page = SyncPage {
            up: BTreeMap::new(),
            gone: BTreeSet::new(),
            token: String::new(),
            truncated: false,
        };
        for response in root.children(DAV, "response") {
            let Some(at) = response
                .child(DAV, "href")
                .and_then(Element::trimmed)
                .and_then(|h| answer.url.join(h).ok())
            else {
                continue;
            };
            let at_id = path::id(&at);
            let status = xml::status_code(response.child(DAV, "status"));
            if at_id == id || at_id.ends_with('/') {
                if status == Some(507) && at_id == id {
                    page.truncated = true;
                }
                continue;
            }
            if matches!(status, Some(404 | 410)) {
                page.up.remove(&at_id);
                page.gone.insert(at_id);
            } else {
                page.gone.remove(&at_id);
                page.up.insert(at_id, etag(&ok_props(response)));
            }
        }
        if page.up.len() + page.gone.len() > MAX_ITEMS {
            return Err(PimError::Protocol("the server listed too many changes".into()).into());
        }
        page.token = root
            .child(DAV, "sync-token")
            .and_then(Element::trimmed)
            .map(str::to_owned)
            .ok_or_else(|| PimError::Protocol("the server sent no sync token".into()))?;
        if page.truncated && token == Some(page.token.as_str()) {
            return Err(PimError::Protocol(
                "the server sent the same sync token for the next page".into(),
            )
            .into());
        }
        Ok(page)
    }

    /// Every object in the collection with its ETag, sorted by id.
    async fn list(
        &self,
        url: &Url,
        id: &str,
    ) -> Result<BTreeMap<String, Option<String>>, PimError> {
        let (root, base) = self
            .propfind(url, "1", "<d:getetag/><d:resourcetype/>")
            .await?;
        let mut out = BTreeMap::new();
        for response in root.children(DAV, "response") {
            let Some(at) = response
                .child(DAV, "href")
                .and_then(Element::trimmed)
                .and_then(|h| base.join(h).ok())
            else {
                continue;
            };
            let at_id = path::id(&at);
            let props = ok_props(response);
            let is_collection = prop(&props, DAV, "resourcetype")
                .is_some_and(|t| t.child(DAV, "collection").is_some());
            if at_id == id || at_id.ends_with('/') || is_collection {
                continue;
            }
            out.insert(at_id, etag(&props));
            if out.len() > MAX_ITEMS {
                return Err(PimError::Protocol(
                    "the collection holds too many objects".into(),
                ));
            }
        }
        Ok(out)
    }

    /// Reads the server's next changes into `state`: a sync round from its token, or a fresh
    /// listing, falling back to an ETag listing when `sync-collection` is missing. Pushes a
    /// `Reset` when the server no longer takes the token.
    async fn refill(
        &self,
        url: &Url,
        id: &str,
        state: &mut DavCursor,
        out: &mut Vec<PimChange>,
    ) -> Result<(), PimError> {
        if let Some(token) = state.token.clone() {
            match self.sync_round(url, id, Some(&token)).await {
                Ok(page) => {
                    state.gone = page.gone.into_iter().collect();
                    state.up = page.up.into_iter().collect();
                    state.token = Some(page.token);
                    state.truncated = page.truncated;
                    return Ok(());
                }
                Err(SyncError::Other(e)) => return Err(e),
                Err(SyncError::Expired) => out.push(PimChange::Reset {
                    reason: "sync_token".into(),
                }),
                Err(SyncError::Unsupported) => out.push(PimChange::Reset {
                    reason: "sync_unsupported".into(),
                }),
            }
            *state = DavCursor::fresh();
        }
        if let Some(known) = state.etags.clone() {
            let ctag = self.ctag(url).await?;
            if ctag.is_some() && ctag == state.ctag {
                return Ok(());
            }
            let now = self.list(url, id).await?;
            state.gone = known
                .keys()
                .filter(|k| !now.contains_key(*k))
                .cloned()
                .collect();
            state.up = now
                .iter()
                .filter(|(k, v)| known.get(*k) != Some(v) || v.is_none())
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            state.etags = Some(now);
            state.ctag = ctag;
            return Ok(());
        }
        match self.sync_round(url, id, None).await {
            Ok(page) => {
                state.up = page.up.into_iter().collect();
                state.gone = Vec::new();
                state.token = Some(page.token);
                state.truncated = page.truncated;
                Ok(())
            }
            Err(SyncError::Other(e)) => Err(e),
            Err(SyncError::Expired | SyncError::Unsupported) => {
                let ctag = self.ctag(url).await?;
                let now = self.list(url, id).await?;
                state.up = now.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                state.gone = Vec::new();
                state.etags = Some(now);
                state.ctag = ctag;
                Ok(())
            }
        }
    }

    async fn get_one(&self, url: &Url, id: &str, ct: &str) -> Result<Option<RawObject>, PimError> {
        let Ok(at) = url.join(&path::encode(id)) else {
            return Ok(None);
        };
        Ok(self.inner.http.get(&at).await?.map(|answer| RawObject {
            item: item(id.to_owned()),
            version: write::header_etag(&answer).filter(|t| !t.starts_with("W/")),
            bytes: answer.body,
            content_type: ct.to_owned(),
        }))
    }
}

#[async_trait]
impl PimSession for DavSession {
    async fn collections(&mut self) -> Result<Vec<CollectionInfo>, PimError> {
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        let mut found = HashMap::new();
        for (kind, configured) in [
            (CollectionKind::Calendar, self.inner.calendars.clone()),
            (CollectionKind::AddressBook, self.inner.contacts.clone()),
        ] {
            let Some(configured) = configured else {
                continue;
            };
            for (info, url) in self.collections_of(kind, &configured).await? {
                if seen.insert(info.id.clone()) {
                    found.insert(info.id.clone(), Found { url, kind });
                    out.push(info);
                }
            }
        }
        if self.inner.schedule_inbox
            && let Some(inbox) = self.principal().await?.inbox.clone()
        {
            let id = path::id(&inbox);
            if seen.insert(id.clone()) {
                found.insert(
                    id.clone(),
                    Found {
                        url: inbox,
                        kind: CollectionKind::Calendar,
                    },
                );
                out.push(CollectionInfo {
                    id,
                    kind: CollectionKind::Calendar,
                    name: "Scheduling inbox".into(),
                    color: None,
                    read_only: false,
                    components: Vec::new(),
                    role: Some(skein_core::CollectionRole::ScheduleInbox),
                });
            }
        }
        tracing::debug!(collections = out.len(), "DAV collections listed");
        self.found = found;
        self.listed = true;
        Ok(out)
    }

    async fn changes(
        &mut self,
        collection: &str,
        cursor: Option<&Cursor>,
        limit: usize,
    ) -> Result<PimChanges, PimError> {
        let found = self.found(collection).await?;
        let mut out = Vec::new();
        let mut state = match cursor {
            None => DavCursor::fresh(),
            Some(raw) => DavCursor::decode(raw).unwrap_or_else(|| {
                out.push(PimChange::Reset {
                    reason: "cursor".into(),
                });
                DavCursor::fresh()
            }),
        };
        if !state.pending() {
            self.refill(&found.url, collection, &mut state, &mut out)
                .await?;
        }
        let mut budget = limit.max(1);
        let gone = state.gone.len().min(budget);
        for id in state.gone.drain(..gone) {
            out.push(PimChange::Removed { item: item(id) });
        }
        budget -= gone;
        let up = state.up.len().min(budget);
        for (id, version) in state.up.drain(..up) {
            out.push(PimChange::Upserted {
                item: item(id),
                version,
            });
        }
        let more = state.pending() || state.truncated;
        if !state.pending() {
            state.truncated = false;
        }
        tracing::debug!(changes = out.len(), more, "DAV changes read");
        Ok(PimChanges {
            changes: out,
            cursor: state.encode(),
            more,
        })
    }

    async fn fetch(
        &mut self,
        collection: &str,
        items: &[ItemRef],
    ) -> Result<Vec<RawObject>, PimError> {
        let found = self.found(collection).await?;
        let mut wanted: Vec<String> = Vec::new();
        for it in items {
            if !wanted.contains(&it.id) {
                wanted.push(it.id.clone());
            }
        }
        let ct = found.kind.media_type();
        let (report, data, data_ns, data_name) = match found.kind {
            CollectionKind::AddressBook => (
                "card:addressbook-multiget",
                "card:address-data",
                CARDDAV,
                "address-data",
            ),
            CollectionKind::Calendar => (
                "cal:calendar-multiget",
                "cal:calendar-data",
                CALDAV,
                "calendar-data",
            ),
        };
        let mut out: Vec<RawObject> = Vec::new();
        let mut multiget = true;
        let mut too_large = 0usize;
        for batch in wanted.chunks(BATCH) {
            if multiget {
                let hrefs: String = batch
                    .iter()
                    .map(|id| format!("<d:href>{}</d:href>", xml::escape(&path::encode(id))))
                    .collect();
                let body = format!(
                    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
                     <{report} xmlns:d=\"DAV:\" xmlns:card=\"urn:ietf:params:xml:ns:carddav\" \
                     xmlns:cal=\"urn:ietf:params:xml:ns:caldav\"><d:prop><d:getetag/><{data}/>\
                     </d:prop>{hrefs}</{report}>"
                );
                let answer = self
                    .inner
                    .http
                    .dav("REPORT", &found.url, Some("1"), Some(&body), MAX_XML)
                    .await?;
                if is_multistatus(answer.status) {
                    let root = multistatus(&answer)?;
                    for response in root.children(DAV, "response") {
                        let Some(at) = response
                            .child(DAV, "href")
                            .and_then(Element::trimmed)
                            .and_then(|h| answer.url.join(h).ok())
                        else {
                            continue;
                        };
                        let id = path::id(&at);
                        if !batch.contains(&id) || out.iter().any(|o| o.item.id == id) {
                            continue;
                        }
                        let props = ok_props(response);
                        let Some(text) = prop(&props, data_ns, data_name).map(|e| e.text.as_str())
                        else {
                            continue;
                        };
                        if text.trim().is_empty() {
                            continue;
                        }
                        if text.len() > MAX_ITEM {
                            too_large += 1;
                            continue;
                        }
                        out.push(RawObject {
                            item: item(id),
                            version: etag(&props),
                            bytes: Bytes::copy_from_slice(text.as_bytes()),
                            content_type: ct.into(),
                        });
                    }
                    continue;
                }
                match answer.status.as_u16() {
                    400 | 403 | 405 | 415 | 422 | 501 => multiget = false,
                    500..=599 => {}
                    _ => return Err(status_error(answer.status, &answer.url)),
                }
            }
            for id in batch {
                if let Some(obj) = self.get_one(&found.url, id, ct).await? {
                    out.push(obj);
                }
            }
        }
        if too_large > 0 {
            tracing::warn!(too_large, "DAV objects over 16 MiB left out");
        }
        tracing::debug!(
            asked = wanted.len(),
            fetched = out.len(),
            "DAV objects fetched"
        );
        Ok(out)
    }

    async fn apply(&mut self, write: &PimWrite) -> Result<WriteOutcome, PimError> {
        let collection = write.collection();
        let found = self.found(collection).await?;
        let own = match write {
            PimWrite::Respond { attendee: None, .. } => self.principal().await?.addresses.clone(),
            _ => Vec::new(),
        };
        write::apply(&self.inner.http, &found, collection, write, &own).await
    }

    async fn scheduling(&mut self, collection: &str) -> Result<Scheduling, PimError> {
        let found = self.found(collection).await?;
        if found.kind != CollectionKind::Calendar {
            return Ok(Scheduling::Client);
        }
        Ok(if self.auto_schedules(&found.url).await? {
            Scheduling::Server
        } else {
            Scheduling::Client
        })
    }

    async fn addresses(&mut self) -> Result<Vec<String>, PimError> {
        Ok(self.principal().await?.addresses.clone())
    }

    async fn logout(&mut self) -> Result<(), PimError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
