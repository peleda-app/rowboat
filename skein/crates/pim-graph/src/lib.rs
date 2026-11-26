//! Calendars and contacts of Microsoft 365 and Outlook.com accounts through Microsoft Graph,
//! behind the [`skein_pim`] contract.
//!
//! Address books are the default contacts folder and every contact folder; calendars are the
//! account's calendars. Every object is the JSON resource exactly as Graph answers a `GET` for
//! it (`application/json; profile=graph-event` or `graph-contact`): Graph has no iCalendar or
//! vCard export, so Skein keeps Graph's own representation. Contact folders change through
//! delta queries whose links are the cursor; calendars are listed with every event's
//! `changeKey` and compared with the cursor, because Graph v1.0 has event deltas only for
//! `calendarView`, which needs a time window and expands series into occurrences. Writes are
//! `POST`, `PATCH` and `DELETE` with `If-Match`; answers to invitations are Graph's `accept`,
//! `decline` and `tentativelyAccept`.
//!
//! The token goes only to the origin of the configured API address: links in answers or
//! cursors that point anywhere else are refused, and redirects are never followed.

mod cursor;
#[doc(hidden)]
pub mod fuzzing;
mod http;
mod write;

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use skein_core::{CollectionInfo, CollectionKind, Credentials, ItemRef, TlsRoots};
use skein_pim::{
    Cursor, PimChange, PimChanges, PimError, PimProvider, PimSession, PimWrite, RawObject,
    Scheduling, WriteOutcome,
};
use skein_throttle::Throttle;
use url::Url;

use cursor::GraphCursor;
use http::{Http, MAX_ITEM, MAX_LISTING, Read, Scope};

/// Where Microsoft Graph answers for accounts in the global cloud.
pub const GRAPH_URL: &str = "https://graph.microsoft.com/v1.0";
/// The collection id of the default contacts folder (`/me/contacts`).
pub const DEFAULT_CONTACTS: &str = "contacts";
/// The media type of an event: Graph's `event` resource as JSON.
pub const EVENT_MEDIA_TYPE: &str = "application/json; profile=graph-event";
/// The media type of a contact: Graph's `contact` resource as JSON.
pub const CONTACT_MEDIA_TYPE: &str = "application/json; profile=graph-contact";

const DOWNLOADS: usize = 4;
const MAX_FOLDERS: usize = 1_000;
const MAX_PAGES: usize = 10_000;
const MAX_ITEMS: usize = 1_000_000;
const MAX_PAGE: usize = 1_000;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const EVENT_FIELDS: &str = "id,changeKey,iCalUId,subject,body,bodyPreview,start,end,\
originalStartTimeZone,originalEndTimeZone,isAllDay,isCancelled,isOrganizer,isReminderOn,\
reminderMinutesBeforeStart,type,seriesMasterId,originalStart,recurrence,attendees,organizer,\
location,locations,showAs,sensitivity,importance,categories,responseStatus,responseRequested,\
allowNewTimeProposals,createdDateTime,lastModifiedDateTime,isOnlineMeeting,onlineMeeting,\
onlineMeetingProvider,hideAttendees,webLink,transactionId,cancelledOccurrences";

/// Where the account is. The access token is passed separately and never stored here. Reads the
/// same JSON as the Graph mail provider's settings.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphPimSettings {
    /// The Graph endpoint with its version; [`GRAPH_URL`] when missing. Only `https`, or plain
    /// `http` to a loopback address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_url: Option<String>,
    /// The account to read: missing for the token's own (`/me`), else a user id or user
    /// principal name (`/users/{id}`), for app-only tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Certificates trusted besides the built-in roots. They never turn verification off.
    #[serde(skip)]
    pub roots: TlsRoots,
}

impl fmt::Debug for GraphPimSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GraphPimSettings")
            .field("api_url", &self.api_url)
            .field("user", &self.user.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

impl GraphPimSettings {
    /// Reads settings from JSON; other keys are ignored. `Config` when they do not parse.
    pub fn from_json(value: &Value) -> Result<Self, PimError> {
        serde_json::from_value(value.clone()).map_err(|e| PimError::Config(e.to_string()))
    }

    fn base(&self) -> Result<Url, PimError> {
        let raw = self.api_url.as_deref().unwrap_or(GRAPH_URL).trim();
        let mut url = Url::parse(raw)
            .map_err(|_| PimError::Config("the Graph address is not a web address".into()))?;
        if !http::allowed(&url) || url.host_str().is_none() {
            return Err(PimError::Config(
                "the Graph address must use https (plain http only to loopback)".into(),
            ));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(PimError::Config(
                "the Graph address must not hold credentials".into(),
            ));
        }
        if url.cannot_be_a_base() {
            return Err(PimError::Config(
                "the Graph address cannot take a path".into(),
            ));
        }
        if !url.path().ends_with('/') {
            let path = format!("{}/", url.path());
            url.set_path(&path);
        }
        url.set_query(None);
        url.set_fragment(None);
        Ok(url)
    }

    fn owner(&self) -> Result<Vec<String>, PimError> {
        match self.user.as_deref().map(str::trim) {
            None | Some("me") => Ok(vec!["me".into()]),
            Some(id)
                if !id.is_empty() && !id.chars().any(|c| c.is_whitespace() || c.is_control()) =>
            {
                Ok(vec!["users".into(), id.to_owned()])
            }
            Some(_) => Err(PimError::Config("the user is not a user id".into())),
        }
    }
}

/// Microsoft Graph calendars and contacts of one account, signed in with an access token that
/// holds `Calendars.Read` and `Contacts.Read` (`.ReadWrite` for writes). Cloning is cheap;
/// sessions share one HTTP client.
///
/// Listings are capped at 64 MiB per page, one object at 16 MiB, a listing at 10 000 pages and a
/// million objects. Busy answers to reads (`429`, or `503`/`504` with `Retry-After`) are waited
/// out three times within about ten seconds, then reported as `Throttled`; busy answers to writes
/// are `Throttled` at once. Logs carry counts and status codes, never names, ids, objects or the
/// token.
#[derive(Clone)]
pub struct GraphPimProvider {
    base: Url,
    owner: Vec<String>,
    http: Http,
}

impl fmt::Debug for GraphPimProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GraphPimProvider")
            .field("base", &self.base.as_str())
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl GraphPimProvider {
    /// A provider for the account behind `credentials`, which must be an access token. `Config`
    /// for a password, an empty token, an unusable API address or user, or an extra root that is
    /// not a certificate; nothing is sent before these checks.
    pub fn new(settings: GraphPimSettings, credentials: Credentials) -> Result<Self, PimError> {
        let Credentials::AccessToken { token } = credentials else {
            return Err(PimError::Config(
                "Microsoft Graph signs in with an access token, not a password".into(),
            ));
        };
        if token.trim().is_empty() {
            return Err(PimError::Config("the access token is empty".into()));
        }
        let base = settings.base()?;
        Ok(Self {
            owner: settings.owner()?,
            http: Http::new(token, &base, REQUEST_TIMEOUT, &settings.roots)?,
            base,
        })
    }

    /// Gives every request `timeout` instead of two minutes; a read without an answer by then is
    /// a `Network` error, a write that went out [`WriteOutcome::Uncertain`].
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, PimError> {
        self.http = self.http.with_timeout(timeout)?;
        Ok(self)
    }

    /// Sends every request to Graph through `throttle`: each waits for a slot and for any pause
    /// in effect, and a busy answer with `Retry-After` pauses it for every holder, such as the
    /// mail and sending providers of the same mailbox. A read gives up with `Throttled` at once
    /// when the recorded pause outlasts its own wait. Without a throttle requests go out at once.
    pub fn with_throttle(mut self, throttle: Throttle) -> Self {
        self.http.throttle = Some(throttle);
        self
    }
}

#[async_trait]
impl PimProvider for GraphPimProvider {
    async fn connect(&self) -> Result<Box<dyn PimSession>, PimError> {
        Ok(Box::new(GraphSession {
            base: self.base.clone(),
            owner: self.owner.clone(),
            http: self.http.clone(),
            types: HashMap::new(),
        }))
    }
}

/// Where a collection id points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Place {
    Contacts(Option<String>),
    Calendar(String),
}

impl Place {
    pub(crate) fn of(collection: &str) -> Result<Self, PimError> {
        if collection == DEFAULT_CONTACTS {
            return Ok(Self::Contacts(None));
        }
        let usable = |id: &str| !id.is_empty() && !id.contains('/');
        if let Some(id) = collection.strip_prefix("contacts/").filter(|id| usable(id)) {
            return Ok(Self::Contacts(Some(id.to_owned())));
        }
        if let Some(id) = collection
            .strip_prefix("calendars/")
            .filter(|id| usable(id))
        {
            return Ok(Self::Calendar(id.to_owned()));
        }
        Err(PimError::NotFound)
    }

    pub(crate) fn kind(&self) -> CollectionKind {
        match self {
            Self::Contacts(_) => CollectionKind::AddressBook,
            Self::Calendar(_) => CollectionKind::Calendar,
        }
    }

    pub(crate) fn media_type(&self) -> &'static str {
        match self {
            Self::Contacts(_) => CONTACT_MEDIA_TYPE,
            Self::Calendar(_) => EVENT_MEDIA_TYPE,
        }
    }

    /// The path of the collection's objects below the account.
    pub(crate) fn items(&self) -> Vec<&str> {
        match self {
            Self::Contacts(None) => vec!["contacts"],
            Self::Contacts(Some(id)) => vec!["contactFolders", id, "contacts"],
            Self::Calendar(id) => vec!["calendars", id, "events"],
        }
    }
}

pub(crate) fn protocol(what: &str) -> PimError {
    PimError::Protocol(what.to_owned())
}

pub(crate) fn json(body: &[u8]) -> Result<Value, PimError> {
    serde_json::from_slice(body).map_err(|_| protocol("Microsoft Graph did not answer with JSON"))
}

pub(crate) fn string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// A version tag without weak marker or quotes: Graph's `changeKey`, as `@odata.etag` and
/// `If-Match` wrap it in `W/"…"`.
pub(crate) fn bare(tag: &str) -> &str {
    tag.trim().trim_start_matches("W/").trim_matches('"')
}

pub(crate) struct Page {
    pub(crate) items: Vec<Value>,
    pub(crate) next: Option<String>,
    pub(crate) delta: Option<String>,
}

pub(crate) fn page(answer: &Value) -> Result<Page, PimError> {
    let link = |key: &str| answer.get(key).and_then(Value::as_str).map(str::to_owned);
    Ok(Page {
        items: answer
            .get("value")
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| protocol("a Graph answer has no value"))?,
        next: link("@odata.nextLink"),
        delta: link("@odata.deltaLink"),
    })
}

/// The objects a delta page changed, with their `changeKey`, and those it removed; removals are
/// left out of an initial round, which only lists what exists.
pub(crate) fn fold_delta(
    items: Vec<Value>,
    initial: bool,
) -> (BTreeMap<String, Option<String>>, BTreeMap<String, ()>) {
    let mut up: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut gone: BTreeMap<String, ()> = BTreeMap::new();
    for entry in items {
        let Some(id) = string(&entry, "id") else {
            continue;
        };
        if entry.get("@removed").is_some() {
            up.remove(&id);
            if !initial {
                gone.insert(id, ());
            }
        } else {
            gone.remove(&id);
            up.insert(id, string(&entry, "changeKey"));
        }
    }
    (up, gone)
}

fn item(id: String) -> ItemRef {
    ItemRef { id, uid: None }
}

pub(crate) struct GraphSession {
    pub(crate) base: Url,
    pub(crate) owner: Vec<String>,
    pub(crate) http: Http,
    /// Event types seen in listings (`seriesMaster` among them), so masters are fetched with
    /// their exceptions straight away.
    types: HashMap<String, String>,
}

impl GraphSession {
    pub(crate) fn endpoint(&self, tail: &[&str], query: &[(&str, &str)]) -> Result<Url, PimError> {
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|_| PimError::Config("the Graph address cannot take a path".into()))?
            .pop_if_empty()
            .extend(self.owner.iter().map(String::as_str))
            .extend(tail);
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }
        Ok(url)
    }

    pub(crate) fn item_url(&self, place: &Place, id: &str) -> Result<Url, PimError> {
        let mut tail = place.items();
        tail.push(id);
        self.endpoint(&tail, &[])
    }

    /// Every item of a listing, following `@odata.nextLink`; `None` when the first page is gone.
    pub(crate) async fn all(&self, first: Url) -> Result<Option<Vec<Value>>, PimError> {
        let mut items = Vec::new();
        let mut links = HashSet::from([first.to_string()]);
        let mut url = first;
        for _ in 0..MAX_PAGES {
            let answer = match self
                .http
                .get(url, Scope::Account, None, MAX_LISTING)
                .await?
            {
                Read::Found(body) => json(&body)?,
                Read::Missing | Read::Gone => return Ok(None),
                Read::Refused => return Err(protocol("Microsoft Graph refused a listing")),
            };
            let page = page(&answer)?;
            items.extend(page.items);
            if items.len() > MAX_ITEMS {
                return Err(protocol("a Graph listing has more than a million items"));
            }
            match page.next {
                Some(next) => {
                    url = self.http.url(&next)?;
                    if !links.insert(url.to_string()) {
                        return Err(protocol("a Graph listing named a page it already gave"));
                    }
                }
                None => return Ok(Some(items)),
            }
        }
        Err(protocol("a Graph listing does not end"))
    }

    async fn contact_folders(&self) -> Result<Vec<CollectionInfo>, PimError> {
        let query = [
            ("$select", "id,displayName,parentFolderId"),
            ("$top", "100"),
        ];
        let mut out = Vec::new();
        let mut queue =
            VecDeque::from([(self.endpoint(&["contactFolders"], &query)?, String::new())]);
        let mut seen = HashSet::new();
        while let Some((url, parent)) = queue.pop_front() {
            let Some(items) = self.all(url).await? else {
                continue;
            };
            for folder in items {
                let Some(id) = string(&folder, "id") else {
                    continue;
                };
                if !seen.insert(id.clone()) || id.contains('/') {
                    continue;
                }
                let name = string(&folder, "displayName").unwrap_or_else(|| "Contacts".into());
                let path = if parent.is_empty() {
                    name
                } else {
                    format!("{parent}/{name}")
                };
                queue.push_back((
                    self.endpoint(&["contactFolders", &id, "childFolders"], &query)?,
                    path.clone(),
                ));
                out.push(CollectionInfo {
                    id: format!("contacts/{id}"),
                    kind: CollectionKind::AddressBook,
                    name: path,
                    color: None,
                    read_only: false,
                    components: Vec::new(),
                    role: None,
                });
                if out.len() > MAX_FOLDERS {
                    return Err(protocol("the account has too many contact folders"));
                }
            }
        }
        Ok(out)
    }

    async fn calendars(&self) -> Result<Vec<CollectionInfo>, PimError> {
        let url = self.endpoint(
            &["calendars"],
            &[("$select", "id,name,hexColor,canEdit"), ("$top", "100")],
        )?;
        let mut out = Vec::new();
        for calendar in self.all(url).await?.unwrap_or_default() {
            let Some(id) = string(&calendar, "id").filter(|id| !id.contains('/')) else {
                continue;
            };
            out.push(CollectionInfo {
                id: format!("calendars/{id}"),
                kind: CollectionKind::Calendar,
                name: string(&calendar, "name").unwrap_or_else(|| "Calendar".into()),
                color: string(&calendar, "hexColor"),
                read_only: calendar.get("canEdit").and_then(Value::as_bool) == Some(false),
                components: vec!["VEVENT".into()],
                role: None,
            });
        }
        Ok(out)
    }

    fn delta_start(&self, place: &Place) -> Result<String, PimError> {
        let mut tail = place.items();
        tail.push("delta");
        Ok(self
            .endpoint(&tail, &[("$select", "id,changeKey")])?
            .to_string())
    }

    /// Reads the next delta page of a contact folder into `state`, pushing a `Reset` when Graph
    /// no longer accepts the stored link.
    async fn refill_delta(
        &self,
        place: &Place,
        state: &mut GraphCursor,
        limit: usize,
        out: &mut Vec<PimChange>,
    ) -> Result<(), PimError> {
        let mut fresh = state.link.is_none();
        if fresh {
            state.link = Some(self.delta_start(place)?);
            state.initial = true;
        }
        let answer = loop {
            let link = state.link.clone().expect("a delta link is set");
            let url = match self.http.url(&link) {
                Ok(url) => url,
                Err(_) if !fresh => {
                    out.push(PimChange::Reset {
                        reason: "cursor".into(),
                    });
                    *state = GraphCursor::fresh(&state.c);
                    state.link = Some(self.delta_start(place)?);
                    state.initial = true;
                    fresh = true;
                    continue;
                }
                Err(e) => return Err(e),
            };
            let page_size = limit.clamp(1, MAX_PAGE);
            match self
                .http
                .get(url, Scope::Account, Some(page_size), MAX_LISTING)
                .await?
            {
                Read::Found(body) => break json(&body)?,
                Read::Missing | Read::Gone if fresh => return Err(PimError::NotFound),
                Read::Refused if fresh => {
                    return Err(protocol("Microsoft Graph refused a delta query"));
                }
                Read::Missing | Read::Gone | Read::Refused => {
                    tracing::debug!("Graph no longer accepts a delta link; listing again");
                    out.push(PimChange::Reset {
                        reason: "delta_expired".into(),
                    });
                    *state = GraphCursor::fresh(&state.c);
                    state.link = Some(self.delta_start(place)?);
                    state.initial = true;
                    fresh = true;
                }
            }
        };
        let page = page(&answer)?;
        let (up, gone) = fold_delta(page.items, state.initial);
        let previous = state.link.clone();
        match (page.next, page.delta) {
            (Some(next), _) => {
                self.http.url(&next)?;
                if previous.as_deref() == Some(next.as_str()) {
                    return Err(protocol("a Graph delta named the page it just gave"));
                }
                state.link = Some(next);
                state.next = true;
            }
            (None, Some(delta)) => {
                self.http.url(&delta)?;
                state.link = Some(delta);
                state.next = false;
                state.initial = false;
            }
            (None, None) => return Err(protocol("a Graph delta ended without a delta link")),
        }
        state.up = up.into_iter().collect();
        state.gone = gone.into_keys().collect();
        Ok(())
    }

    /// Lists a calendar's events with their `changeKey` and compares them with the cursor's.
    async fn refill_listing(
        &mut self,
        place: &Place,
        state: &mut GraphCursor,
    ) -> Result<(), PimError> {
        let url = self.endpoint(
            &place.items(),
            &[("$select", "id,changeKey,type"), ("$top", "500")],
        )?;
        let items = self.all(url).await?.ok_or(PimError::NotFound)?;
        let mut now: BTreeMap<String, String> = BTreeMap::new();
        for event in items {
            let Some(id) = string(&event, "id") else {
                continue;
            };
            if let Some(kind) = string(&event, "type") {
                self.types.insert(id.clone(), kind);
            }
            now.insert(id, string(&event, "changeKey").unwrap_or_default());
        }
        let known = state.known.take().unwrap_or_default();
        state.gone = known
            .keys()
            .filter(|k| !now.contains_key(*k))
            .cloned()
            .collect();
        state.up = now
            .iter()
            .filter(|(k, v)| known.get(*k) != Some(v) || v.is_empty())
            .map(|(k, v)| (k.clone(), (!v.is_empty()).then(|| v.clone())))
            .collect();
        state.known = Some(now);
        Ok(())
    }

    async fn get_item(&self, url: Url) -> Result<Option<Bytes>, PimError> {
        match self.http.get(url, Scope::Item, None, MAX_ITEM).await? {
            Read::Found(body) => Ok(Some(body)),
            Read::Missing | Read::Gone => Ok(None),
            Read::Refused => Err(protocol("Microsoft Graph refused to read an object")),
        }
    }

    fn master_url(&self, place: &Place, id: &str) -> Result<Url, PimError> {
        let mut tail = place.items();
        tail.push(id);
        self.endpoint(
            &tail,
            &[
                ("$select", EVENT_FIELDS),
                ("$expand", "exceptionOccurrences"),
            ],
        )
    }

    /// One object as Graph answers for it. A series master is asked again with its exceptions
    /// expanded and its cancelled occurrences, which Graph gives only when asked by the master's
    /// id; the stored JSON then holds the whole series.
    pub(crate) async fn read_one(
        &self,
        place: &Place,
        id: &str,
    ) -> Result<Option<RawObject>, PimError> {
        let master = |raw: &Bytes| {
            serde_json::from_slice::<Value>(raw)
                .ok()
                .and_then(|v| string(&v, "type"))
                .is_some_and(|t| t == "seriesMaster")
        };
        let raw = match place {
            Place::Calendar(_)
                if self.types.get(id).map(String::as_str) == Some("seriesMaster") =>
            {
                self.get_item(self.master_url(place, id)?).await?
            }
            Place::Calendar(_) => match self.get_item(self.item_url(place, id)?).await? {
                Some(plain) if master(&plain) => self.get_item(self.master_url(place, id)?).await?,
                other => other,
            },
            Place::Contacts(_) => self.get_item(self.item_url(place, id)?).await?,
        };
        Ok(raw.map(|bytes| RawObject {
            item: item(id.to_owned()),
            version: serde_json::from_slice::<Value>(&bytes)
                .ok()
                .and_then(|v| string(&v, "changeKey")),
            bytes,
            content_type: place.media_type().to_owned(),
        }))
    }
}

#[async_trait]
impl PimSession for GraphSession {
    async fn collections(&mut self) -> Result<Vec<CollectionInfo>, PimError> {
        let mut out = vec![CollectionInfo {
            id: DEFAULT_CONTACTS.into(),
            kind: CollectionKind::AddressBook,
            name: "Contacts".into(),
            color: None,
            read_only: false,
            components: Vec::new(),
            role: None,
        }];
        out.extend(self.contact_folders().await?);
        out.extend(self.calendars().await?);
        tracing::debug!(collections = out.len(), "Graph collections listed");
        Ok(out)
    }

    async fn changes(
        &mut self,
        collection: &str,
        cursor: Option<&Cursor>,
        limit: usize,
    ) -> Result<PimChanges, PimError> {
        let place = Place::of(collection)?;
        let mut out = Vec::new();
        let mut state = match cursor {
            None => GraphCursor::fresh(collection),
            Some(raw) => GraphCursor::decode(raw, collection)
                .filter(|c| (place.kind() == CollectionKind::Calendar) == c.known.is_some())
                .unwrap_or_else(|| {
                    out.push(PimChange::Reset {
                        reason: "cursor".into(),
                    });
                    GraphCursor::fresh(collection)
                }),
        };
        if !state.pending() {
            match place {
                Place::Calendar(_) => self.refill_listing(&place, &mut state).await?,
                Place::Contacts(_) => {
                    self.refill_delta(&place, &mut state, limit, &mut out)
                        .await?
                }
            }
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
        let more = state.pending() || state.next;
        tracing::debug!(changes = out.len(), more, "Graph changes read");
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
        let place = Place::of(collection)?;
        let mut unique: Vec<String> = Vec::new();
        for it in items {
            if !unique.contains(&it.id) && !it.id.is_empty() && !it.id.contains('/') {
                unique.push(it.id.clone());
            }
        }
        let this = &*self;
        let place = &place;
        let results: Vec<Result<Option<RawObject>, PimError>> =
            futures::stream::iter(unique.iter().cloned())
                .map(|id| async move { this.read_one(place, &id).await })
                .buffered(DOWNLOADS)
                .collect()
                .await;
        let out: Vec<RawObject> = results
            .into_iter()
            .filter_map(Result::transpose)
            .collect::<Result<_, _>>()?;
        tracing::debug!(
            asked = unique.len(),
            fetched = out.len(),
            "Graph objects fetched"
        );
        Ok(out)
    }

    async fn apply(&mut self, write: &PimWrite) -> Result<WriteOutcome, PimError> {
        write::apply(self, write).await
    }

    /// Graph sends meeting messages itself for every calendar; contact folders never schedule.
    /// `NotFound` for an id that names no collection.
    async fn scheduling(&mut self, collection: &str) -> Result<Scheduling, PimError> {
        Ok(match Place::of(collection)? {
            Place::Calendar(_) => Scheduling::Server,
            Place::Contacts(_) => Scheduling::Client,
        })
    }

    /// The mailbox user's `mail` and `userPrincipalName` (`/me` or `/users/{id}`), lower case and
    /// each once, keeping only addresses; empty when the user is not found. Needs `User.Read`.
    async fn addresses(&mut self) -> Result<Vec<String>, PimError> {
        write::addresses(self).await
    }

    async fn logout(&mut self) -> Result<(), PimError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
