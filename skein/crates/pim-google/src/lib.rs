//! Calendars and contacts on Google behind the [`skein_pim`] contract: Google Calendar API v3
//! for calendars and People API v1 for the account's contacts.
//!
//! Every calendar in `calendarList` is a calendar collection and the account's contacts
//! (`people/me` connections) are one address book, [`CONTACTS`]. Changes come from
//! `events.list` and `people.connections.list` with sync tokens; objects are the JSON resources
//! exactly as Google sent them ([`EVENT_TYPE`], [`PERSON_TYPE`]), since Google has no per-object
//! iCalendar or vCard export. Writes are `events.insert`/`update`/`delete` with `If-Match`,
//! answers are `events.patch` of the attendee's `responseStatus`, and contacts are
//! `people.createContact`/`updateContact`/`deleteContact` with the etag in the body. The token
//! goes only to the two configured origins, redirects are never followed, and every request
//! waits for room under a per-user limiter.

mod calendar;
mod cursor;
#[doc(hidden)]
pub mod fuzzing;
mod http;
mod limit;
mod people;

#[cfg(test)]
mod fake;
#[cfg(test)]
mod suite;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use skein_core::{CollectionInfo, CollectionKind, Credentials, ItemRef};
use skein_pim::{
    Cursor, PimChanges, PimError, PimProvider, PimSession, PimWrite, RawObject, Scheduling,
    WriteOutcome,
};
use url::Url;

use http::Http;
use limit::Limiter;

pub use calendar::EVENT_TYPE;
pub use people::{PERSON_TYPE, READ_FIELDS, UPDATE_FIELDS};

/// The id of the address book that holds the account's contacts. Google calendar ids always
/// contain `@`, so no calendar can have it.
pub const CONTACTS: &str = "contacts";
/// Largest object sent in a write; larger ones are `Failed { reason: "too_large" }`.
pub const MAX_OBJECT: usize = 4 * 1024 * 1024;
/// Largest answer read, a listing page or one object.
pub const MAX_RESPONSE: usize = 32 * 1024 * 1024;
/// Default average requests per minute to the Calendar API, per provider.
pub const CALENDAR_PER_MINUTE: u32 = 300;
/// Default average requests per minute to the People API, per provider.
pub const PEOPLE_PER_MINUTE: u32 = 60;
const BURST: u32 = 10;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

fn default_calendar_url() -> String {
    "https://www.googleapis.com/calendar/v3".into()
}

fn default_people_url() -> String {
    "https://people.googleapis.com/v1".into()
}

fn yes() -> bool {
    true
}

/// Where the two APIs are and which kinds to read. Credentials are passed separately.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoogleSettings {
    /// The Calendar API root; `https://www.googleapis.com/calendar/v3` when omitted. Plain
    /// `http` is accepted only for loopback hosts.
    #[serde(default = "default_calendar_url")]
    pub calendar_url: String,
    /// The People API root; `https://people.googleapis.com/v1` when omitted.
    #[serde(default = "default_people_url")]
    pub people_url: String,
    /// Whether calendars are listed and read.
    #[serde(default = "yes")]
    pub calendars: bool,
    /// Whether the [`CONTACTS`] address book is listed and read.
    #[serde(default = "yes")]
    pub contacts: bool,
}

impl Default for GoogleSettings {
    fn default() -> Self {
        Self {
            calendar_url: default_calendar_url(),
            people_url: default_people_url(),
            calendars: true,
            contacts: true,
        }
    }
}

impl GoogleSettings {
    /// Reads settings from JSON; `Config` when they do not parse.
    pub fn from_json(value: &serde_json::Value) -> Result<Self, PimError> {
        serde_json::from_value(value.clone()).map_err(|e| PimError::Config(e.to_string()))
    }
}

pub(crate) struct Inner {
    pub http: Http,
    pub calendar: Url,
    pub people: Url,
    pub calendars: bool,
    pub contacts: bool,
    pub max_object: usize,
    pub max_response: usize,
}

/// A Google account's calendars and contacts.
///
/// Cloning is cheap; clones and their sessions share the limiters. The token is sent only to
/// the origins of [`GoogleSettings::calendar_url`] and [`GoogleSettings::people_url`], over
/// https (plain http only to loopback); redirects are never followed. Answers are capped at
/// [`MAX_RESPONSE`], writes at [`MAX_OBJECT`]. Logs carry status codes, counts and timings,
/// never ids of people, names, addresses, event or contact content, or the token.
#[derive(Clone)]
pub struct GoogleProvider {
    settings: Arc<GoogleSettings>,
    credentials: Arc<Credentials>,
    calendar: Url,
    people: Url,
    timeout: Duration,
    calendar_limit: Arc<Limiter>,
    people_limit: Arc<Limiter>,
    max_object: usize,
    max_response: usize,
}

impl fmt::Debug for GoogleProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GoogleProvider")
            .field("settings", &self.settings)
            .field("credentials", &self.credentials)
            .finish_non_exhaustive()
    }
}

fn parse_base(raw: &str, name: &str) -> Result<Url, PimError> {
    let url = Url::parse(raw.trim())
        .map_err(|_| PimError::Config(format!("{name} is not a valid address")))?;
    if !http::allowed(&url) || url.cannot_be_a_base() || url.host_str().is_none() {
        return Err(PimError::Config(format!(
            "{name} must be https, or http to a loopback host"
        )));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(PimError::Config(format!(
            "{name} must not carry credentials"
        )));
    }
    Ok(url)
}

impl GoogleProvider {
    /// A provider for `settings`, signing in with an OAuth access token that carries the
    /// `calendar` and/or `contacts` scopes.
    ///
    /// `Config` before anything is sent when the credentials are a password, the token is empty,
    /// an address is not https (or http to loopback) or carries credentials, or both kinds are
    /// switched off.
    pub fn new(settings: GoogleSettings, credentials: Credentials) -> Result<Self, PimError> {
        match &credentials {
            Credentials::AccessToken { token } if !token.trim().is_empty() => {}
            Credentials::AccessToken { .. } => {
                return Err(PimError::Config("the access token is empty".into()));
            }
            Credentials::Password { .. } => {
                return Err(PimError::Config(
                    "Google calendars and contacts need an OAuth access token, not a password"
                        .into(),
                ));
            }
            Credentials::AccessKey { .. } => {
                return Err(PimError::Config(
                    "Google calendars and contacts need an OAuth access token, not an access key"
                        .into(),
                ));
            }
        }
        if !settings.calendars && !settings.contacts {
            return Err(PimError::Config(
                "neither calendars nor contacts are enabled".into(),
            ));
        }
        let calendar = parse_base(&settings.calendar_url, "calendar_url")?;
        let people = parse_base(&settings.people_url, "people_url")?;
        Ok(Self {
            settings: Arc::new(settings),
            credentials: Arc::new(credentials),
            calendar,
            people,
            timeout: REQUEST_TIMEOUT,
            calendar_limit: Arc::new(Limiter::new(CALENDAR_PER_MINUTE, BURST)),
            people_limit: Arc::new(Limiter::new(PEOPLE_PER_MINUTE, BURST)),
            max_object: MAX_OBJECT,
            max_response: MAX_RESPONSE,
        })
    }

    /// Gives every request `timeout` instead of one minute.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Keeps requests under `calendar` and `people` requests per minute on average instead of
    /// [`CALENDAR_PER_MINUTE`] and [`PEOPLE_PER_MINUTE`], with fresh limiters shared by this
    /// provider's clones made afterwards. Bursts reach ten requests or one second's worth.
    pub fn with_rate(mut self, calendar: u32, people: u32) -> Self {
        self.calendar_limit = Arc::new(Limiter::new(calendar, BURST.max(calendar / 60)));
        self.people_limit = Arc::new(Limiter::new(people, BURST.max(people / 60)));
        self
    }

    #[cfg(test)]
    pub(crate) fn with_limits(mut self, max_object: usize, max_response: usize) -> Self {
        self.max_object = max_object;
        self.max_response = max_response;
        self
    }
}

#[async_trait]
impl PimProvider for GoogleProvider {
    /// Opens a session without sending anything; a refused token shows on the first call.
    async fn connect(&self) -> Result<Box<dyn PimSession>, PimError> {
        let Credentials::AccessToken { token } = &*self.credentials else {
            return Err(PimError::Config("an access token is required".into()));
        };
        let http = Http::new(
            token.clone(),
            &self.calendar,
            &self.people,
            self.timeout,
            self.calendar_limit.clone(),
            self.people_limit.clone(),
        )?;
        Ok(Box::new(GoogleSession {
            inner: Arc::new(Inner {
                http,
                calendar: self.calendar.clone(),
                people: self.people.clone(),
                calendars: self.settings.calendars,
                contacts: self.settings.contacts,
                max_object: self.max_object,
                max_response: self.max_response,
            }),
            page: None,
            created: HashMap::new(),
        }))
    }
}

/// The objects of the last listed page, so `fetch` right after `changes` sends nothing.
pub(crate) struct Page {
    pub collection: String,
    pub objects: HashMap<String, (Option<String>, Bytes)>,
}

pub(crate) struct GoogleSession {
    pub inner: Arc<Inner>,
    pub page: Option<Page>,
    /// Contacts made in this session by create key. People has no client-chosen ids.
    pub created: HashMap<String, String>,
}

impl GoogleSession {
    pub(crate) fn cached(&self, collection: &str, id: &str) -> Option<(Option<String>, Bytes)> {
        let page = self.page.as_ref()?;
        if page.collection != collection {
            return None;
        }
        page.objects.get(id).cloned()
    }
}

enum Target {
    Calendar,
    Contacts,
}

impl GoogleSession {
    fn target(&self, collection: &str) -> Result<Target, PimError> {
        if collection == CONTACTS {
            return if self.inner.contacts {
                Ok(Target::Contacts)
            } else {
                Err(PimError::NotFound)
            };
        }
        if self.inner.calendars && !collection.is_empty() {
            Ok(Target::Calendar)
        } else {
            Err(PimError::NotFound)
        }
    }
}

#[async_trait]
impl PimSession for GoogleSession {
    async fn collections(&mut self) -> Result<Vec<CollectionInfo>, PimError> {
        let mut out = Vec::new();
        if self.inner.calendars {
            out.extend(calendar::collections(&self.inner).await?);
        }
        if self.inner.contacts {
            out.push(CollectionInfo {
                id: CONTACTS.into(),
                kind: CollectionKind::AddressBook,
                name: "Contacts".into(),
                color: None,
                read_only: false,
                components: Vec::new(),
                role: None,
            });
        }
        tracing::debug!(collections = out.len(), "google collections");
        Ok(out)
    }

    async fn changes(
        &mut self,
        collection: &str,
        cursor: Option<&Cursor>,
        limit: usize,
    ) -> Result<PimChanges, PimError> {
        match self.target(collection)? {
            Target::Calendar => calendar::changes(self, collection, cursor, limit).await,
            Target::Contacts => people::changes(self, cursor, limit).await,
        }
    }

    async fn fetch(
        &mut self,
        collection: &str,
        items: &[ItemRef],
    ) -> Result<Vec<RawObject>, PimError> {
        let out = match self.target(collection)? {
            Target::Calendar => calendar::fetch(self, collection, items).await?,
            Target::Contacts => people::fetch(self, items).await?,
        };
        tracing::debug!(asked = items.len(), fetched = out.len(), "google fetch");
        Ok(out)
    }

    async fn apply(&mut self, write: &PimWrite) -> Result<WriteOutcome, PimError> {
        match self.target(write.collection())? {
            Target::Calendar => calendar::apply(self, write).await,
            Target::Contacts => people::apply(self, write).await,
        }
    }

    /// Google sends invitations and answers itself for calendars (`sendUpdates`); contacts never
    /// schedule.
    async fn scheduling(&mut self, collection: &str) -> Result<Scheduling, PimError> {
        Ok(match self.target(collection)? {
            Target::Calendar => Scheduling::Server,
            Target::Contacts => Scheduling::Client,
        })
    }

    /// The primary calendar's id, which is the account's address; empty without calendars or
    /// when the primary calendar's id is not an address.
    async fn addresses(&mut self) -> Result<Vec<String>, PimError> {
        if !self.inner.calendars {
            return Ok(Vec::new());
        }
        calendar::addresses(&self.inner).await
    }

    async fn logout(&mut self) -> Result<(), PimError> {
        self.page = None;
        Ok(())
    }
}

pub(crate) fn item(id: &str) -> ItemRef {
    ItemRef {
        id: id.to_owned(),
        uid: None,
    }
}

pub(crate) fn failed(reason: &str) -> WriteOutcome {
    WriteOutcome::Failed {
        reason: reason.to_owned(),
    }
}

/// The blob as a JSON object, or the reason a write refuses it.
pub(crate) fn object(
    bytes: &[u8],
    max: usize,
) -> Result<serde_json::Map<String, serde_json::Value>, &'static str> {
    if bytes.len() > max {
        return Err("too_large");
    }
    match serde_json::from_slice::<serde_json::Value>(bytes) {
        Ok(serde_json::Value::Object(map)) => Ok(map),
        _ => Err("invalid_object"),
    }
}

/// `bytes` with the string field `key` set to `value`. Bytes that already carry it are sent
/// unchanged; a missing field is inserted right after the opening brace and the rest is kept
/// byte for byte; only a field with another value makes the object re-serialized.
pub(crate) fn with_field(
    bytes: &Bytes,
    map: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: &str,
) -> Bytes {
    match map.get(key) {
        Some(serde_json::Value::String(s)) if s == value => bytes.clone(),
        Some(_) => {
            let mut map = map.clone();
            map.insert(key.to_owned(), serde_json::Value::String(value.to_owned()));
            Bytes::from(serde_json::to_vec(&map).expect("a JSON object serializes"))
        }
        None => {
            let open = bytes
                .iter()
                .position(|b| !b.is_ascii_whitespace())
                .expect("a parsed object has a brace");
            let empty = map.is_empty();
            let mut out = Vec::with_capacity(bytes.len() + key.len() + value.len() + 8);
            out.extend_from_slice(&bytes[..=open]);
            out.extend_from_slice(&serde_json::to_vec(key).expect("a string serializes"));
            out.push(b':');
            out.extend_from_slice(&serde_json::to_vec(value).expect("a string serializes"));
            if !empty {
                out.push(b',');
            }
            out.extend_from_slice(&bytes[open + 1..]);
            Bytes::from(out)
        }
    }
}

pub(crate) fn reset(reason: &str) -> skein_pim::PimChange {
    skein_pim::PimChange::Reset {
        reason: reason.to_owned(),
    }
}
