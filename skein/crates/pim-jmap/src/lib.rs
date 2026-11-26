//! Calendars and contacts on JMAP servers behind the [`skein_pim`] contract: JMAP for Contacts
//! (RFC 9610, `urn:ietf:params:jmap:contacts`) and JMAP Calendars
//! (draft-ietf-jmap-calendars, `urn:ietf:params:jmap:calendars`), such as Stalwart or Fastmail.
//!
//! Address books are `AddressBook`s and calendars `Calendar`s of the session's primary accounts
//! for the two capabilities. Every object is the JSContact card (`application/jscontact+json`) or
//! JSCalendar event (`application/jscalendar+json`) from the server's `/get` answer, written with
//! the keys of every object sorted: JMAP offers no iCalendar or vCard bytes for these objects,
//! and servers such as Stalwart order keys differently on every answer. Changes come from
//! `ContactCard/changes` and `CalendarEvent/changes` with the state as the cursor; writes go
//! through `/set` under `ifInState`, with `sendSchedulingMessages` set from `notify` on
//! calendars, whose server schedules ([`Scheduling::Server`]).

mod cursor;
#[doc(hidden)]
pub mod fuzzing;
mod http;
mod write;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use skein_core::{CollectionInfo, CollectionKind, Credentials, ItemRef, TlsRoots};
use skein_pim::{
    Cursor, PimChange, PimChanges, PimError, PimProvider, PimSession, PimWrite, RawObject,
    Scheduling, WriteOutcome,
};
use url::Url;

use cursor::JmapCursor;
use http::{Http, Posted};

/// The JMAP core capability.
pub const CORE: &str = "urn:ietf:params:jmap:core";
/// JMAP for Contacts (RFC 9610).
pub const CONTACTS: &str = "urn:ietf:params:jmap:contacts";
/// JMAP Calendars (draft-ietf-jmap-calendars).
pub const CALENDARS: &str = "urn:ietf:params:jmap:calendars";
/// The media type of a card: a JSContact object (RFC 9553).
pub const CARD_MEDIA_TYPE: &str = "application/jscontact+json";
/// The media type of an event: a JSCalendar object (RFC 8984).
pub const EVENT_MEDIA_TYPE: &str = "application/jscalendar+json";

const MAX_OBJECTS: usize = 500;
const MAX_CALLS: usize = 16;
const MAX_CHANGES: usize = 1_000;
const QUERY_PAGE: usize = 1_000;
const MAX_ROUNDS: usize = 10_000;
const MAX_ITEMS: usize = 1_000_000;
const MAX_RESTARTS: usize = 5;
pub(crate) const MAX_ITEM: usize = 16 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Where the account is and as whom to sign in. The password or token is passed separately and
/// never stored here. Reads the same JSON as the JMAP mail provider's settings.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JmapPimSettings {
    /// The session resource (`https://jmap.example.com/jmap/session`) or a server address, where
    /// `/.well-known/jmap` is asked; see [`session_url`].
    pub url: String,
    /// The user name for a password sign-in, often the address; unused with a token.
    #[serde(default)]
    pub username: String,
    /// Certificates trusted besides the built-in roots. They never turn verification off.
    #[serde(skip)]
    pub roots: TlsRoots,
}

impl fmt::Debug for JmapPimSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JmapPimSettings")
            .field("url", &self.url)
            .field("username", &"<redacted>")
            .field("roots", &self.roots)
            .finish()
    }
}

impl JmapPimSettings {
    /// Settings for the server at `url`, signing in as `username` when a password is used.
    pub fn new(url: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            username: username.into(),
            roots: TlsRoots::default(),
        }
    }

    /// Reads settings from JSON; other keys are ignored. `Config` when they do not parse.
    pub fn from_json(value: &Value) -> Result<Self, PimError> {
        serde_json::from_value(value.clone()).map_err(|e| PimError::Config(e.to_string()))
    }
}

/// The session resource for what someone typed: `https://` is added when no scheme is given,
/// and an address without a path gets `/.well-known/jmap`. Only `https`, or plain `http` to a
/// loopback address, and no credentials in the address; `Config` otherwise.
pub fn session_url(input: &str) -> Result<String, PimError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(PimError::Config("the JMAP address is empty".into()));
    }
    let with_scheme = if input.contains("://") {
        input.to_owned()
    } else {
        format!("https://{input}")
    };
    let mut url = Url::parse(&with_scheme)
        .map_err(|_| PimError::Config("the JMAP address is not a web address".into()))?;
    if !http::allowed(&url) || url.host_str().is_none() {
        return Err(PimError::Config(
            "the JMAP address must use https (plain http only to loopback)".into(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(PimError::Config(
            "the JMAP address must not hold credentials".into(),
        ));
    }
    url.set_fragment(None);
    if url.path().is_empty() || url.path() == "/" {
        url.set_path("/.well-known/jmap");
    }
    Ok(url.to_string())
}

/// A JMAP account's calendars and contacts. A password signs in with HTTP Basic, an access
/// token as a bearer token. Cloning is cheap; every [`connect`](PimProvider::connect) asks for
/// the session again.
///
/// A session address under `/.well-known/` is followed through its redirects without
/// credentials; the session is then asked with credentials and its `apiUrl` must be on the
/// session's own origin, so credentials never reach a host the configured address did not lead
/// to. Requests with credentials never follow redirects. Answers are capped at 1 MiB for the
/// session and 64 MiB per API answer; objects over 16 MiB are left out of fetches. Busy answers
/// to reads (`429`, or `503`/`504` with `Retry-After`) are waited out three times within about
/// ten seconds, then reported as `Throttled`; busy answers to writes are `Throttled` at once.
/// Logs carry counts only.
#[derive(Clone)]
pub struct JmapPimProvider {
    url: String,
    http: Http,
}

impl fmt::Debug for JmapPimProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JmapPimProvider")
            .field("url", &self.url)
            .field("credentials", &"<redacted>")
            .finish()
    }
}

impl JmapPimProvider {
    /// A provider for the account in `settings`. `Config` for an unusable address, a password
    /// without a user name, an empty token, or an extra root that is not a certificate; nothing
    /// is sent before these checks pass.
    pub fn new(settings: JmapPimSettings, credentials: Credentials) -> Result<Self, PimError> {
        let url = session_url(&settings.url)?;
        let auth = match credentials {
            Credentials::Password { secret } => {
                if settings.username.trim().is_empty() {
                    return Err(PimError::Config(
                        "signing in with a password needs a user name".into(),
                    ));
                }
                http::Auth::Basic(settings.username.trim().to_owned(), secret)
            }
            Credentials::AccessToken { token } => {
                if token.trim().is_empty() {
                    return Err(PimError::Config("the access token is empty".into()));
                }
                http::Auth::Bearer(token)
            }
            Credentials::AccessKey { .. } => {
                return Err(PimError::Config(
                    "JMAP signs in with a password or a token, not an access key".into(),
                ));
            }
        };
        Ok(Self {
            http: Http::new(auth, REQUEST_TIMEOUT, &settings.roots)?,
            url,
        })
    }

    /// Gives every request `timeout` instead of two minutes; a read without an answer by then is
    /// a `Network` error, a write that went out [`WriteOutcome::Uncertain`].
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, PimError> {
        self.http = self.http.with_timeout(timeout)?;
        Ok(self)
    }
}

/// One kind of collection and how JMAP names its parts.
pub(crate) struct Kind {
    pub kind: CollectionKind,
    pub capability: &'static str,
    pub collection: &'static str,
    pub item: &'static str,
    pub member: &'static str,
    pub filter: &'static str,
    pub prefix: &'static str,
    pub media: &'static str,
}

pub(crate) const BOOKS: Kind = Kind {
    kind: CollectionKind::AddressBook,
    capability: CONTACTS,
    collection: "AddressBook",
    item: "ContactCard",
    member: "addressBookIds",
    filter: "inAddressBook",
    prefix: "addressbook/",
    media: CARD_MEDIA_TYPE,
};

pub(crate) const CALENDARS_KIND: Kind = Kind {
    kind: CollectionKind::Calendar,
    capability: CALENDARS,
    collection: "Calendar",
    item: "CalendarEvent",
    member: "calendarIds",
    filter: "inCalendar",
    prefix: "calendar/",
    media: EVENT_MEDIA_TYPE,
};

/// The kind and JMAP id of a collection id; `NotFound` for one this provider never made.
pub(crate) fn split(collection: &str) -> Result<(&'static Kind, &str), PimError> {
    for kind in [&BOOKS, &CALENDARS_KIND] {
        if let Some(id) = collection
            .strip_prefix(kind.prefix)
            .filter(|id| !id.is_empty())
        {
            return Ok((kind, id));
        }
    }
    Err(PimError::NotFound)
}

pub(crate) fn protocol(what: &str) -> PimError {
    PimError::Protocol(what.to_owned())
}

/// The object with the keys of every object sorted: the bytes Skein keeps, stable however the
/// server orders its answer.
pub(crate) fn canonical(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(k, v)| (k, canonical(v)))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.into_iter().map(canonical).collect()),
        other => other,
    }
}

/// The version of an object: a hash of its canonical bytes. JMAP keeps no version per object,
/// so equal versions mean equal objects.
pub(crate) fn version(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex()[..32].to_owned()
}

pub(crate) fn member_of(value: &Value, member: &str, collection: &str) -> bool {
    value
        .get(member)
        .and_then(Value::as_object)
        .and_then(|m| m.get(collection))
        .is_some_and(|v| v.as_bool() != Some(false))
}

/// `forbidden` and the account errors mean the sign-in may not read this; the rest are protocol
/// errors carrying only the error type.
pub(crate) fn method_error(kind: &str) -> PimError {
    match kind {
        "forbidden" | "accountNotFound" | "accountNotSupportedByMethod" => PimError::Auth,
        _ => PimError::Protocol(format!("the JMAP server refused a request: {kind}")),
    }
}

fn error_type(args: &Value) -> String {
    args.get("type")
        .and_then(Value::as_str)
        .filter(|k| !k.is_empty() && k.len() <= 64 && k.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or("unknown")
        .to_owned()
}

fn limit(core: &Value, key: &str, default: usize, max: usize) -> usize {
    core.get(key)
        .and_then(Value::as_u64)
        .map_or(default, |v| usize::try_from(v).unwrap_or(max))
        .clamp(1, max)
}

fn strings(answer: &Value, key: &str) -> Vec<String> {
    answer
        .get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn list(answer: &Value) -> Result<Vec<Value>, PimError> {
    answer
        .get("list")
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| protocol("a JMAP get answer has no list"))
}

pub(crate) fn state_of(answer: &Value) -> Result<String, PimError> {
    answer
        .get("state")
        .or_else(|| answer.get("queryState"))
        .or_else(|| answer.get("newState"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| protocol("a JMAP answer has no state"))
}

/// The answers of a JMAP response to `count` calls, by call id.
pub(crate) fn answers_in_order(answer: &Value, count: usize) -> Result<Answers, PimError> {
    let responses = answer
        .get("methodResponses")
        .and_then(Value::as_array)
        .ok_or_else(|| protocol("the JMAP answer has no method responses"))?;
    let mut out: Vec<Option<Result<Value, String>>> = vec![None; count];
    for response in responses {
        let Some([name, args, id]) = response.as_array().map(Vec::as_slice) else {
            return Err(protocol("a JMAP method response is malformed"));
        };
        let Some(index) = id.as_str().and_then(|id| id.parse::<usize>().ok()) else {
            continue;
        };
        let answer = if name == "error" {
            Err(error_type(args))
        } else {
            Ok(args.clone())
        };
        if let Some(slot) = out.get_mut(index) {
            slot.get_or_insert(answer);
        }
    }
    out.into_iter()
        .map(|a| a.ok_or_else(|| protocol("the JMAP server left a call unanswered")))
        .collect()
}

/// A collection from one entry of an `AddressBook/get` or `Calendar/get` list; `None` without an
/// id.
pub(crate) fn collection_info(kind: &Kind, value: &Value) -> Option<CollectionInfo> {
    let id = value.get("id").and_then(Value::as_str)?;
    let text = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    let right = |key: &str| {
        value
            .pointer(&format!("/myRights/{key}"))
            .and_then(Value::as_bool)
    };
    let read_only = match kind.kind {
        CollectionKind::AddressBook => right("mayWrite") == Some(false),
        CollectionKind::Calendar => {
            right("mayWriteAll") == Some(false) && right("mayWriteOwn") != Some(true)
        }
    };
    Some(CollectionInfo {
        id: format!("{}{id}", kind.prefix),
        kind: kind.kind,
        name: text("name").unwrap_or_else(|| id.to_owned()),
        color: text("color"),
        read_only,
        components: match kind.kind {
            CollectionKind::Calendar => vec!["VEVENT".into()],
            CollectionKind::AddressBook => Vec::new(),
        },
        role: None,
    })
}

/// What the session offers, read once per [`PimProvider::connect`].
pub(crate) struct JmapSession {
    pub(crate) http: Http,
    pub(crate) api: Url,
    pub(crate) contacts: Option<String>,
    pub(crate) calendars: Option<String>,
    username: Option<String>,
    max_objects: usize,
    max_calls: usize,
}

#[async_trait]
impl PimProvider for JmapPimProvider {
    async fn connect(&self) -> Result<Box<dyn PimSession>, PimError> {
        let mut base = Url::parse(&self.url).map_err(|e| PimError::Config(e.to_string()))?;
        if base.path().starts_with("/.well-known/") {
            base = self.http.resolve(base).await?;
        }
        let session = self.http.session(&base).await?;
        Ok(Box::new(JmapSession::from_session(
            self.http.clone(),
            &base,
            &session,
        )?))
    }
}

/// One answer per call: its arguments, or the type of the method error the server gave.
pub(crate) type Answers = Vec<Result<Value, String>>;

impl JmapSession {
    fn from_session(http: Http, base: &Url, session: &Value) -> Result<Self, PimError> {
        let capabilities = session
            .get("capabilities")
            .and_then(Value::as_object)
            .ok_or_else(|| protocol("the address does not answer with a JMAP session"))?;
        let primary = |capability: &str| {
            capabilities.contains_key(capability).then_some(())?;
            session
                .get("primaryAccounts")?
                .get(capability)?
                .as_str()
                .filter(|a| !a.is_empty())
                .map(str::to_owned)
        };
        let contacts = primary(CONTACTS);
        let calendars = primary(CALENDARS);
        if contacts.is_none() && calendars.is_none() {
            return Err(PimError::Config(
                "the JMAP server offers neither calendars nor contacts for this user".into(),
            ));
        }
        let api = session
            .get("apiUrl")
            .and_then(Value::as_str)
            .and_then(|a| base.join(a).ok())
            .ok_or_else(|| protocol("the JMAP session has no API address"))?;
        if !http::allowed(&api) || api.origin() != base.origin() {
            return Err(protocol(
                "the JMAP session names an API address on another origin",
            ));
        }
        let core = capabilities.get(CORE).cloned().unwrap_or(Value::Null);
        let username = session
            .get("username")
            .and_then(Value::as_str)
            .map(write::address)
            .filter(|u| u.contains('@'));
        Ok(Self {
            http,
            api,
            contacts,
            calendars,
            username,
            max_objects: limit(&core, "maxObjectsInGet", MAX_OBJECTS, MAX_OBJECTS),
            max_calls: limit(&core, "maxCallsInRequest", MAX_CALLS, MAX_CALLS),
        })
    }

    pub(crate) fn account(&self, kind: &Kind) -> Result<&str, PimError> {
        match kind.kind {
            CollectionKind::AddressBook => self.contacts.as_deref(),
            CollectionKind::Calendar => self.calendars.as_deref(),
        }
        .ok_or(PimError::NotFound)
    }

    /// Sends the calls in one request. `None` when the request went out but the answer was lost.
    pub(crate) async fn post(
        &self,
        kind: &Kind,
        calls: Vec<(String, Value)>,
        repeatable: bool,
    ) -> Result<Option<Answers>, PimError> {
        let count = calls.len();
        let body = json!({
            "using": [CORE, kind.capability],
            "methodCalls": calls
                .into_iter()
                .enumerate()
                .map(|(i, (name, args))| json!([name, args, i.to_string()]))
                .collect::<Vec<_>>(),
        });
        match self.http.post(&self.api, &body, repeatable).await? {
            Posted::Answer(answer) => answers_in_order(&answer, count).map(Some),
            Posted::Lost => Ok(None),
        }
    }

    /// Read calls in one request; answers or method error types, in order.
    pub(crate) async fn read(
        &self,
        kind: &Kind,
        calls: Vec<(String, Value)>,
    ) -> Result<Answers, PimError> {
        self.post(kind, calls, true)
            .await?
            .ok_or_else(|| PimError::Network("the JMAP server broke off an answer".into()))
    }

    fn collection_check(&self, kind: &Kind, id: &str) -> Result<(String, Value), PimError> {
        Ok((
            format!("{}/get", kind.collection),
            json!({ "accountId": self.account(kind)?, "ids": [id], "properties": ["id"] }),
        ))
    }

    fn exists(answer: &Result<Value, String>) -> Result<bool, PimError> {
        match answer {
            Ok(a) => Ok(!list(a)?.is_empty()),
            Err(kind) => Err(method_error(kind)),
        }
    }

    /// `/get` of `ids`, at most `maxObjectsInGet` per call and `maxCallsInRequest` calls per
    /// request, with the state of the first answer. Ids the server no longer has are left out.
    pub(crate) async fn get(
        &self,
        kind: &Kind,
        ids: &[String],
        properties: Option<&[&str]>,
    ) -> Result<(Vec<Value>, Option<String>), PimError> {
        let account = self.account(kind)?;
        let mut out = Vec::with_capacity(ids.len());
        let mut state = None;
        for request in ids.chunks(self.max_objects * self.max_calls) {
            let calls = request
                .chunks(self.max_objects)
                .map(|chunk| {
                    let mut args = json!({ "accountId": account, "ids": chunk });
                    if let Some(p) = properties {
                        args["properties"] = json!(p);
                    }
                    (format!("{}/get", kind.item), args)
                })
                .collect();
            for answer in self.read(kind, calls).await? {
                let answer = answer.map_err(|k| method_error(&k))?;
                if state.is_none() {
                    state = state_of(&answer).ok();
                }
                out.extend(list(&answer)?);
            }
        }
        Ok((out, state))
    }

    /// The object as Skein keeps it: canonical bytes with their version.
    pub(crate) fn raw(kind: &Kind, value: Value) -> Option<RawObject> {
        let id = value.get("id").and_then(Value::as_str)?.to_owned();
        let bytes = serde_json::to_vec(&canonical(value)).ok()?;
        if bytes.len() > MAX_ITEM {
            return None;
        }
        Some(RawObject {
            item: ItemRef { id, uid: None },
            version: Some(version(&bytes)),
            bytes: Bytes::from(bytes),
            content_type: kind.media.to_owned(),
        })
    }

    /// Every id in the collection with the item state before the listing. A listing whose
    /// query state moves while it is paged starts again, so no object slips past.
    async fn listing(&self, kind: &Kind, id: &str) -> Result<(String, Vec<String>), PimError> {
        let account = self.account(kind)?;
        'restart: for _ in 0..MAX_RESTARTS {
            let mut ids: Vec<String> = Vec::new();
            let mut state = String::new();
            let mut query_state: Option<String> = None;
            let mut last: Option<Vec<String>> = None;
            for round in 0..MAX_ROUNDS {
                let query = (
                    format!("{}/query", kind.item),
                    json!({
                        "accountId": account,
                        "filter": { kind.filter: id },
                        "position": ids.len(),
                        "limit": QUERY_PAGE,
                        "calculateTotal": true,
                    }),
                );
                let calls = if round == 0 {
                    vec![
                        self.collection_check(kind, id)?,
                        (
                            format!("{}/get", kind.item),
                            json!({ "accountId": account, "ids": [], "properties": ["id"] }),
                        ),
                        query,
                    ]
                } else {
                    vec![query]
                };
                let answers = self.read(kind, calls).await?;
                let page = if round == 0 {
                    if !Self::exists(&answers[0])? {
                        return Err(PimError::NotFound);
                    }
                    state = state_of(answers[1].as_ref().map_err(|k| method_error(k))?)?;
                    &answers[2]
                } else {
                    &answers[0]
                };
                let page = page.as_ref().map_err(|k| method_error(k))?;
                let now = page
                    .get("queryState")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                if query_state.is_some() && now != query_state {
                    continue 'restart;
                }
                query_state = now;
                let found = strings(page, "ids");
                let total = page
                    .get("total")
                    .and_then(Value::as_u64)
                    .and_then(|t| usize::try_from(t).ok());
                if !found.is_empty() && last.as_ref() == Some(&found) {
                    return Err(protocol("a JMAP query answered the same page twice"));
                }
                ids.extend(found.iter().cloned());
                if ids.len() > MAX_ITEMS {
                    return Err(protocol("a JMAP query listed more than a million objects"));
                }
                let done = found.is_empty() || total.is_some_and(|t| ids.len() >= t);
                last = Some(found);
                if done {
                    let mut seen = BTreeSet::new();
                    ids.retain(|i| seen.insert(i.clone()));
                    return Ok((state, ids));
                }
            }
            return Err(protocol("a JMAP query does not end"));
        }
        Err(protocol("a JMAP query kept changing while it was read"))
    }

    /// The account's calendar addresses: the `mailto:` `calendarAddress` and `sendTo` values of
    /// its `ParticipantIdentity`s (none when the server does not know the method) and the session's
    /// user name when it is an address. Lower case, without `mailto:`, each once.
    pub(crate) async fn own_addresses(&self) -> Result<Vec<String>, PimError> {
        let mut out: Vec<String> = Vec::new();
        if let Ok(account) = self.account(&CALENDARS_KIND) {
            let answers = self
                .read(
                    &CALENDARS_KIND,
                    vec![(
                        "ParticipantIdentity/get".to_owned(),
                        json!({ "accountId": account, "ids": null }),
                    )],
                )
                .await?;
            match &answers[0] {
                Ok(answer) => {
                    for identity in list(answer)? {
                        let bis = identity.get("calendarAddress").and_then(Value::as_str);
                        let send_to = identity
                            .get("sendTo")
                            .and_then(Value::as_object)
                            .into_iter()
                            .flat_map(|m| m.values().filter_map(Value::as_str));
                        for uri in bis.into_iter().chain(send_to) {
                            if write::is_mailto(uri) {
                                out.push(write::address(uri.trim()));
                            }
                        }
                    }
                }
                Err(k) if k == "unknownMethod" => {}
                Err(k) => return Err(method_error(k)),
            }
        }
        out.extend(self.username.clone());
        let mut seen = BTreeSet::new();
        out.retain(|a| !a.is_empty() && seen.insert(a.clone()));
        Ok(out)
    }

    /// Reads the next changes into `state`: a fresh listing, or one round of `/changes`. Pushes a
    /// `Reset` when the server cannot give changes from the stored state.
    async fn refill(
        &self,
        kind: &Kind,
        id: &str,
        state: &mut JmapCursor,
        limit: usize,
        out: &mut Vec<PimChange>,
    ) -> Result<(), PimError> {
        if !state.state.is_empty() {
            let account = self.account(kind)?;
            let answers = self
                .read(
                    kind,
                    vec![
                        self.collection_check(kind, id)?,
                        (
                            format!("{}/changes", kind.item),
                            json!({
                                "accountId": account,
                                "sinceState": state.state,
                                "maxChanges": limit.clamp(1, MAX_CHANGES),
                            }),
                        ),
                    ],
                )
                .await?;
            if !Self::exists(&answers[0])? {
                return Err(PimError::NotFound);
            }
            match &answers[1] {
                Ok(answer) => {
                    let next = answer
                        .get("newState")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .ok_or_else(|| protocol("a JMAP changes answer has no new state"))?
                        .to_owned();
                    let more = answer.get("hasMoreChanges").and_then(Value::as_bool) == Some(true);
                    if more && next == state.state {
                        return Err(protocol("JMAP changes did not move past their state"));
                    }
                    let mut touched: BTreeMap<String, bool> = BTreeMap::new();
                    for item in strings(answer, "created")
                        .into_iter()
                        .chain(strings(answer, "updated"))
                    {
                        touched.insert(item, true);
                    }
                    for item in strings(answer, "destroyed") {
                        touched.insert(item, false);
                    }
                    if touched.len() > MAX_ITEMS {
                        return Err(protocol("JMAP changes listed more than a million objects"));
                    }
                    let alive: Vec<String> = touched
                        .iter()
                        .filter(|(_, alive)| **alive)
                        .map(|(i, _)| i.clone())
                        .collect();
                    let (found, _) = self.get(kind, &alive, Some(&["id", kind.member])).await?;
                    let here: BTreeSet<String> = found
                        .iter()
                        .filter(|v| member_of(v, kind.member, id))
                        .filter_map(|v| v.get("id").and_then(Value::as_str).map(str::to_owned))
                        .collect();
                    state.up.clear();
                    state.gone.clear();
                    for (item, _) in touched {
                        if here.contains(&item) {
                            state.up.push(item);
                        } else {
                            state.gone.push(item);
                        }
                    }
                    state.state = next;
                    state.more = more;
                    return Ok(());
                }
                Err(k) if k == "cannotCalculateChanges" || k == "invalidArguments" => {
                    tracing::debug!(
                        "the JMAP server cannot give changes from a state; listing again"
                    );
                    out.push(PimChange::Reset {
                        reason: "state".into(),
                    });
                    *state = JmapCursor::fresh(&state.c);
                }
                Err(k) => return Err(method_error(k)),
            }
        }
        let (now, ids) = self.listing(kind, id).await?;
        state.state = now;
        state.up = ids;
        state.gone = Vec::new();
        state.more = false;
        Ok(())
    }
}

#[async_trait]
impl PimSession for JmapSession {
    async fn collections(&mut self) -> Result<Vec<CollectionInfo>, PimError> {
        let mut out = Vec::new();
        for kind in [&CALENDARS_KIND, &BOOKS] {
            let Ok(account) = self.account(kind) else {
                continue;
            };
            let answers = self
                .read(
                    kind,
                    vec![(
                        format!("{}/get", kind.collection),
                        json!({ "accountId": account, "ids": null }),
                    )],
                )
                .await?;
            let answer = answers[0].as_ref().map_err(|k| method_error(k))?;
            out.extend(
                list(answer)?
                    .iter()
                    .filter_map(|v| collection_info(kind, v)),
            );
        }
        tracing::debug!(collections = out.len(), "JMAP collections listed");
        Ok(out)
    }

    async fn changes(
        &mut self,
        collection: &str,
        cursor: Option<&Cursor>,
        limit: usize,
    ) -> Result<PimChanges, PimError> {
        let (kind, id) = split(collection)?;
        self.account(kind)?;
        let mut out = Vec::new();
        let mut state = match cursor {
            None => JmapCursor::fresh(collection),
            Some(raw) => JmapCursor::decode(raw, collection).unwrap_or_else(|| {
                out.push(PimChange::Reset {
                    reason: "cursor".into(),
                });
                JmapCursor::fresh(collection)
            }),
        };
        if !state.pending() {
            self.refill(kind, id, &mut state, limit, &mut out).await?;
        }
        let mut budget = limit.max(1);
        let gone = state.gone.len().min(budget);
        for item in state.gone.drain(..gone) {
            out.push(PimChange::Removed {
                item: ItemRef {
                    id: item,
                    uid: None,
                },
            });
        }
        budget -= gone;
        let up = state.up.len().min(budget);
        for item in state.up.drain(..up) {
            out.push(PimChange::Upserted {
                item: ItemRef {
                    id: item,
                    uid: None,
                },
                version: None,
            });
        }
        let more = state.pending() || state.more;
        tracing::debug!(changes = out.len(), more, "JMAP changes read");
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
        let (kind, id) = split(collection)?;
        let mut unique: Vec<String> = Vec::new();
        for it in items {
            if !unique.contains(&it.id) {
                unique.push(it.id.clone());
            }
        }
        let answers = self
            .read(kind, vec![self.collection_check(kind, id)?])
            .await?;
        if !Self::exists(&answers[0])? {
            return Err(PimError::NotFound);
        }
        let (found, _) = self.get(kind, &unique, None).await?;
        let mut seen = BTreeSet::new();
        let mut too_large = 0usize;
        let mut out = Vec::new();
        for value in found {
            if !member_of(&value, kind.member, id) {
                continue;
            }
            let Some(item) = value.get("id").and_then(Value::as_str) else {
                continue;
            };
            if !unique.iter().any(|u| u == item) || !seen.insert(item.to_owned()) {
                continue;
            }
            match Self::raw(kind, value) {
                Some(raw) => out.push(raw),
                None => too_large += 1,
            }
        }
        if too_large > 0 {
            tracing::warn!(too_large, "JMAP objects over 16 MiB left out");
        }
        tracing::debug!(
            asked = unique.len(),
            fetched = out.len(),
            "JMAP objects fetched"
        );
        Ok(out)
    }

    async fn apply(&mut self, write: &PimWrite) -> Result<WriteOutcome, PimError> {
        write::apply(self, write).await
    }

    async fn scheduling(&mut self, collection: &str) -> Result<Scheduling, PimError> {
        let (kind, id) = split(collection)?;
        let answers = self
            .read(kind, vec![self.collection_check(kind, id)?])
            .await?;
        if !Self::exists(&answers[0])? {
            return Err(PimError::NotFound);
        }
        Ok(match kind.kind {
            CollectionKind::Calendar => Scheduling::Server,
            CollectionKind::AddressBook => Scheduling::Client,
        })
    }

    async fn addresses(&mut self) -> Result<Vec<String>, PimError> {
        self.own_addresses().await
    }

    async fn logout(&mut self) -> Result<(), PimError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
