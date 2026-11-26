//! The [`MailProvider`] contract on JMAP servers (RFC 8620, RFC 8621), such as Stalwart,
//! Fastmail or Cyrus.
//!
//! [`JmapProvider`] discovers the session, turns every mailbox into a change feed whose cursor
//! holds the account's `Email` state (`Email/changes`; a state the server no longer knows is a
//! `Reset`), downloads each email's original bytes as a blob, carries out writes with
//! `Email/set` and `Email/import`, and watches the account through the session's event source.
//! Keywords become flags: `$seen`, `$flagged`, `$answered` and `$draft` take IMAP's names.

mod cursor;
#[doc(hidden)]
pub mod fuzzing;
mod http;
mod time;
mod watch;
mod write;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use skein_core::{
    CommandBody, Credentials, Flags, ItemRef, MailCapabilities, MailboxInfo, MailboxRole, TlsRoots,
};
use skein_mail::{
    Cursor, MailChange, MailError, MailProvider, MailSession, MailWatch, MailboxChanges,
    RawMessage, WriteOutcome,
};
use url::Url;

use cursor::{JmapCursor, flags_key, id_key};
use http::{Http, Posted};

const CORE: &str = "urn:ietf:params:jmap:core";
const MAIL: &str = "urn:ietf:params:jmap:mail";
const MAX_OBJECTS: usize = 500;
const MAX_CALLS: usize = 16;
const DOWNLOADS: usize = 4;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
const EMAIL_FIELDS: [&str; 4] = ["id", "keywords", "mailboxIds", "receivedAt"];

/// Where the account is and as whom to sign in. The password or token is passed separately and
/// never stored here.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JmapSettings {
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

impl fmt::Debug for JmapSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JmapSettings")
            .field("url", &self.url)
            .field("username", &"<redacted>")
            .field("roots", &self.roots)
            .finish()
    }
}

impl JmapSettings {
    /// Settings for the server at `url`, signing in as `username` when a password is used.
    pub fn new(url: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            username: username.into(),
            roots: TlsRoots::default(),
        }
    }

    /// Reads settings from JSON; other keys are ignored. `Config` when they do not parse.
    pub fn from_json(value: &Value) -> Result<Self, MailError> {
        serde_json::from_value(value.clone()).map_err(|e| MailError::Config(e.to_string()))
    }
}

/// The session resource for what someone typed: `https://` is added when no scheme is given,
/// and an address without a path gets `/.well-known/jmap`. Only `https`, or plain `http` to a
/// loopback address, and no credentials in the address; `Config` otherwise.
pub fn session_url(input: &str) -> Result<String, MailError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(MailError::Config("the JMAP address is empty".into()));
    }
    let with_scheme = if input.contains("://") {
        input.to_owned()
    } else {
        format!("https://{input}")
    };
    let mut url = Url::parse(&with_scheme)
        .map_err(|_| MailError::Config("the JMAP address is not a web address".into()))?;
    if !http::allowed(&url) {
        return Err(MailError::Config(
            "the JMAP address must use https (plain http only to loopback)".into(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(MailError::Config(
            "the JMAP address must not hold credentials".into(),
        ));
    }
    url.set_fragment(None);
    if url.path().is_empty() || url.path() == "/" {
        url.set_path("/.well-known/jmap");
    }
    Ok(url.to_string())
}

/// A JMAP account. Cloning is cheap; every [`connect`](MailProvider::connect) asks for the
/// session again.
#[derive(Clone)]
pub struct JmapProvider {
    url: String,
    http: Http,
    ping: Duration,
}

impl fmt::Debug for JmapProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JmapProvider")
            .field("url", &self.url)
            .field("credentials", &"<redacted>")
            .finish()
    }
}

impl JmapProvider {
    /// A provider for the account in `settings`. A password signs in with HTTP Basic as
    /// `username`, an access token as a bearer token. `Config` for an unusable address, a
    /// password without a user name, or an extra root that is not a certificate; nothing is sent
    /// before these checks pass.
    pub fn new(settings: JmapSettings, credentials: Credentials) -> Result<Self, MailError> {
        let url = session_url(&settings.url)?;
        let auth = match credentials {
            Credentials::Password { secret } => {
                if settings.username.trim().is_empty() {
                    return Err(MailError::Config(
                        "signing in with a password needs a user name".into(),
                    ));
                }
                http::Auth::Basic(settings.username.trim().to_owned(), secret)
            }
            Credentials::AccessToken { token } => http::Auth::Bearer(token),
            Credentials::AccessKey { .. } => {
                return Err(MailError::Config(
                    "JMAP signs in with a password or a token, not an access key".into(),
                ));
            }
        };
        Ok(Self {
            http: Http::new(auth, REQUEST_TIMEOUT, &settings.roots)?,
            url,
            ping: watch::PING,
        })
    }

    /// Gives every request `timeout` instead of five minutes; a request without an answer by
    /// then is a `Network` error, or [`WriteOutcome::Uncertain`] for a write that went out.
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, MailError> {
        self.http = self.http.with_timeout(timeout)?;
        Ok(self)
    }

    /// Asks the event source for a ping every `ping` (at least a second) instead of every
    /// minute; a watch that hears nothing for two and a half pings ends with `Network`.
    pub fn with_push_ping(mut self, ping: Duration) -> Self {
        self.ping = ping.max(Duration::from_secs(1));
        self
    }

    /// Refuses blob downloads larger than `bytes` (256 MiB by default) as a `Protocol` error.
    pub fn with_max_download(mut self, bytes: usize) -> Self {
        self.http.max_download = bytes;
        self
    }

    async fn open(&self) -> Result<JmapSession, MailError> {
        let mut base = Url::parse(&self.url).map_err(|e| MailError::Config(e.to_string()))?;
        if base.path().starts_with("/.well-known/") {
            base = self.http.resolve(base).await?;
        }
        let session = self.http.session(&base).await?;
        JmapSession::from_session(self.http.clone(), &base, &session)
    }
}

#[async_trait]
impl MailProvider for JmapProvider {
    async fn connect(&self) -> Result<Box<dyn MailSession>, MailError> {
        Ok(Box::new(self.open().await?))
    }

    /// Listens to the session's event source for `Email` and `Mailbox` changes of the account,
    /// reported for every mailbox; `None` when the session names no event source.
    async fn watch(&self, mailboxes: &[String]) -> Result<Option<Box<dyn MailWatch>>, MailError> {
        let _ = mailboxes;
        let session = self.open().await?;
        let Some(template) = session.event_source_url.clone() else {
            return Ok(None);
        };
        let url = watch::event_url(&template, &["Email", "Mailbox"], self.ping);
        let response = self.http.stream(&url).await?;
        tracing::debug!("opened a JMAP event source");
        Ok(Some(Box::new(watch::JmapWatch::new(
            response,
            session.account.clone(),
            self.ping,
        ))))
    }
}

pub(crate) struct JmapSession {
    pub(crate) http: Http,
    api_url: String,
    download_url: String,
    pub(crate) upload_url: Option<String>,
    event_source_url: Option<String>,
    pub(crate) account: String,
    max_objects: usize,
    max_calls: usize,
    pub(crate) max_set: usize,
    pub(crate) max_upload: Option<u64>,
}

pub(crate) fn protocol(what: &str) -> MailError {
    MailError::Protocol(what.to_owned())
}

fn limit(core: &Value, key: &str, default: usize, max: usize) -> usize {
    core.get(key)
        .and_then(Value::as_u64)
        .map_or(default, |v| usize::try_from(v).unwrap_or(max))
        .clamp(1, max)
}

pub(crate) fn list(answer: &Value) -> Result<Vec<Value>, MailError> {
    answer
        .get("list")
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| protocol("a JMAP get answer has no list"))
}

fn strings(answer: &Value, key: &str) -> Result<Vec<String>, MailError> {
    answer
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| MailError::Protocol(format!("a JMAP answer has no {key}")))?
        .iter()
        .map(|id| {
            id.as_str()
                .map(str::to_owned)
                .ok_or_else(|| protocol("a JMAP id is not a string"))
        })
        .collect()
}

pub(crate) fn string(object: &Value, key: &str) -> Result<String, MailError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| MailError::Protocol(format!("a JMAP object has no {key}")))
}

pub(crate) fn in_mailbox(email: &Value, mailbox: &str) -> bool {
    email
        .pointer(&format!("/mailboxIds/{}", pointer_escape(mailbox)))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn pointer_escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

/// Fills a level-1 URI template (RFC 6570), percent-encoding each value.
pub(crate) fn expand(template: &str, values: &[(&str, &str)]) -> String {
    let mut out = template.to_owned();
    for (name, value) in values {
        let encoded: String = url::form_urlencoded::byte_serialize(value.as_bytes())
            .collect::<String>()
            .replace('+', "%20");
        out = out.replace(&format!("{{{name}}}"), &encoded);
    }
    out
}

/// Keywords from the IANA IMAP keyword registry, spelled as registered.
const REGISTERED: [&str; 21] = [
    "$Forwarded",
    "$MDNSent",
    "$Junk",
    "$NotJunk",
    "$Phishing",
    "$SubmitPending",
    "$Submitted",
    "$Important",
    "$Muted",
    "$Notify",
    "$HasAttachment",
    "$HasNoAttachment",
    "$AutoSent",
    "$Unsubscribed",
    "$CanUnsubscribe",
    "$Memo",
    "$HasMemo",
    "$InvitationOrResponse",
    "$MailFlagBit0",
    "$MailFlagBit1",
    "$MailFlagBit2",
];

/// IMAP's names for the keywords both protocols share, registered keywords in their registered
/// spelling (JMAP keywords are case-insensitive and servers lowercase them); others stay as
/// JMAP writes them.
fn flag(keyword: &str) -> String {
    match keyword.to_ascii_lowercase().as_str() {
        "$seen" => "\\Seen".into(),
        "$flagged" => "\\Flagged".into(),
        "$answered" => "\\Answered".into(),
        "$draft" => "\\Draft".into(),
        lower => REGISTERED
            .iter()
            .find(|r| r.eq_ignore_ascii_case(lower))
            .map_or_else(|| keyword.to_owned(), |r| (*r).to_owned()),
    }
}

pub(crate) fn flags(email: &Value) -> Flags {
    Flags::new(
        email
            .get("keywords")
            .and_then(Value::as_object)
            .map(|keywords| {
                keywords
                    .iter()
                    .filter(|(_, set)| set.as_bool().unwrap_or(false))
                    .map(|(keyword, _)| flag(keyword))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
    )
}

fn role(raw: &str) -> Option<MailboxRole> {
    Some(match raw.to_ascii_lowercase().as_str() {
        "inbox" => MailboxRole::Inbox,
        "sent" => MailboxRole::Sent,
        "drafts" => MailboxRole::Drafts,
        "trash" => MailboxRole::Trash,
        "junk" => MailboxRole::Junk,
        "archive" => MailboxRole::Archive,
        "all" => MailboxRole::All,
        "flagged" => MailboxRole::Flagged,
        _ => return None,
    })
}

fn item(id: String) -> ItemRef {
    ItemRef { id, uid: None }
}

enum Feed {
    Done { more: bool },
    UnknownState,
}

impl JmapSession {
    fn from_session(http: Http, base: &Url, session: &Value) -> Result<Self, MailError> {
        let capabilities = session
            .get("capabilities")
            .and_then(Value::as_object)
            .ok_or_else(|| protocol("the address does not answer with a JMAP session"))?;
        if !capabilities.contains_key(MAIL) {
            return Err(MailError::Config(
                "the JMAP server does not offer mail".into(),
            ));
        }
        let core = capabilities.get(CORE).cloned().unwrap_or(Value::Null);
        let account = session
            .pointer(&format!("/primaryAccounts/{}", pointer_escape(MAIL)))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                MailError::Config("the JMAP session has no mail account for this user".into())
            })?
            .to_owned();
        let resolve = |key: &str| -> Result<Option<String>, MailError> {
            let Some(raw) = session.get(key).and_then(Value::as_str) else {
                return Ok(None);
            };
            if raw.contains('{') {
                return Ok(Some(if raw.contains("://") {
                    raw.to_owned()
                } else {
                    format!("{}{}", base.origin().ascii_serialization(), raw)
                }));
            }
            base.join(raw).map(|u| Some(u.to_string())).map_err(|_| {
                MailError::Protocol(format!("the JMAP session's {key} is not an address"))
            })
        };
        Ok(Self {
            api_url: resolve("apiUrl")?
                .ok_or_else(|| protocol("the JMAP session has no apiUrl"))?,
            download_url: resolve("downloadUrl")?
                .ok_or_else(|| protocol("the JMAP session has no downloadUrl"))?,
            upload_url: resolve("uploadUrl")?,
            event_source_url: resolve("eventSourceUrl")?,
            http,
            account,
            max_objects: limit(&core, "maxObjectsInGet", MAX_OBJECTS, MAX_OBJECTS),
            max_calls: limit(&core, "maxCallsInRequest", MAX_CALLS, MAX_CALLS),
            max_set: limit(&core, "maxObjectsInSet", MAX_OBJECTS, MAX_OBJECTS),
            max_upload: core.get("maxSizeUpload").and_then(Value::as_u64),
        })
    }

    /// Sends the calls in one request: each answer, or the type of the method-level error the
    /// server gave for it, in order. `None` when the request went out but the answer was lost.
    pub(crate) async fn post_calls(
        &self,
        calls: Vec<(&str, Value)>,
    ) -> Result<Option<Vec<Result<Value, String>>>, MailError> {
        let count = calls.len();
        let body = json!({
            "using": [CORE, MAIL],
            "methodCalls": calls
                .into_iter()
                .enumerate()
                .map(|(i, (name, args))| json!([name, args, i.to_string()]))
                .collect::<Vec<_>>(),
        });
        match self.http.post(&self.api_url, &body).await? {
            Posted::Answer(answer) => answers_in_order(&answer, count).map(Some),
            Posted::Lost => Ok(None),
        }
    }

    /// Like [`Self::post_calls`], split into requests of at most `maxCallsInRequest` calls, so
    /// the calls must not refer to each other unless they fit in one request.
    async fn answers(
        &self,
        calls: Vec<(&str, Value)>,
    ) -> Result<Vec<Result<Value, String>>, MailError> {
        let mut out = Vec::with_capacity(calls.len());
        let mut calls = calls.into_iter().peekable();
        while calls.peek().is_some() {
            let chunk: Vec<_> = calls.by_ref().take(self.max_calls).collect();
            out.extend(
                self.post_calls(chunk).await?.ok_or_else(|| {
                    MailError::Network("the JMAP server broke off an answer".into())
                })?,
            );
        }
        Ok(out)
    }

    pub(crate) async fn call(&self, calls: Vec<(&str, Value)>) -> Result<Vec<Value>, MailError> {
        self.answers(calls)
            .await?
            .into_iter()
            .map(|a| {
                a.map_err(|kind| {
                    MailError::Protocol(format!("the JMAP server refused a request: {kind}"))
                })
            })
            .collect()
    }

    /// `Email/get` for `ids`, at most `maxObjectsInGet` per call and `maxCallsInRequest` calls
    /// per request, with the `Email` state of the first answer. Ids the server no longer has are
    /// left out.
    pub(crate) async fn emails(
        &self,
        ids: &[String],
        properties: &[&str],
    ) -> Result<(Vec<Value>, Option<String>), MailError> {
        let mut out = Vec::with_capacity(ids.len());
        let mut state = None;
        for request in ids.chunks(self.max_objects * self.max_calls) {
            let calls = request
                .chunks(self.max_objects)
                .map(|chunk| {
                    (
                        "Email/get",
                        json!({ "accountId": self.account, "ids": chunk, "properties": properties }),
                    )
                })
                .collect();
            for answer in self.call(calls).await? {
                if state.is_none() {
                    state = answer
                        .get("state")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                }
                out.extend(list(&answer)?);
            }
        }
        Ok((out, state))
    }

    fn mailbox_check(&self, mailbox: &str) -> (&'static str, Value) {
        (
            "Mailbox/get",
            json!({ "accountId": self.account, "ids": [mailbox], "properties": ["id"] }),
        )
    }

    /// Whether a `Mailbox/get` for one id found it.
    pub(crate) fn found(answer: &Value) -> bool {
        answer
            .get("list")
            .and_then(Value::as_array)
            .is_some_and(|l| !l.is_empty())
    }

    /// A cursor at the start of a listing, at the account's current `Email` state.
    async fn start(&self, mailbox: &str) -> Result<JmapCursor, MailError> {
        let answers = self
            .call(vec![
                self.mailbox_check(mailbox),
                (
                    "Email/get",
                    json!({ "accountId": self.account, "ids": [], "properties": ["id"] }),
                ),
            ])
            .await?;
        if !Self::found(&answers[0]) {
            return Err(MailError::MailboxNotFound);
        }
        Ok(JmapCursor {
            mailbox: mailbox.to_owned(),
            account: self.account.clone(),
            state: string(&answers[1], "state")?,
            listing: Some(None),
            known: Default::default(),
        })
    }

    fn see(
        cursor: &mut JmapCursor,
        email: &Value,
        changes: &mut Vec<MailChange>,
    ) -> Result<(), MailError> {
        let id = string(email, "id")?;
        let key = id_key(&id);
        if !in_mailbox(email, &cursor.mailbox) {
            if cursor.known.remove(&key).is_some() {
                changes.push(MailChange::Removed { item: item(id) });
            }
            return Ok(());
        }
        let flags = flags(email);
        let fkey = flags_key(&flags);
        match cursor.known.insert(key, fkey) {
            None => changes.push(MailChange::Added {
                received_at: email
                    .get("receivedAt")
                    .and_then(Value::as_str)
                    .and_then(time::parse_utc),
                item: item(id),
                flags,
                labels: None,
            }),
            Some(old) if old != fkey => changes.push(MailChange::Flags {
                item: item(id),
                flags,
            }),
            Some(_) => {}
        }
        Ok(())
    }

    /// One page of the first listing.
    async fn list_page(
        &self,
        cursor: &mut JmapCursor,
        changes: &mut Vec<MailChange>,
        limit: usize,
    ) -> Result<(), MailError> {
        let page = limit.clamp(1, self.max_objects);
        let mut restarted = false;
        let (ids, emails) = loop {
            let mut query = json!({
                "accountId": self.account,
                "filter": { "inMailbox": cursor.mailbox },
                "sort": [{ "property": "receivedAt", "isAscending": true }],
                "limit": page,
            });
            match cursor.listing.clone().flatten() {
                Some(anchor) => {
                    query["anchor"] = json!(anchor);
                    query["anchorOffset"] = json!(1);
                }
                None => query["position"] = json!(0),
            }
            let mut answers = if self.max_calls >= 2 {
                self.answers(vec![
                    ("Email/query", query),
                    (
                        "Email/get",
                        json!({
                            "accountId": self.account,
                            "#ids": { "resultOf": "0", "name": "Email/query", "path": "/ids" },
                            "properties": EMAIL_FIELDS,
                        }),
                    ),
                ])
                .await?
            } else {
                self.answers(vec![("Email/query", query)]).await?
            }
            .into_iter();
            let query = answers.next().unwrap_or(Err("unknown".into()));
            match query {
                Err(kind) if kind == "anchorNotFound" && !restarted => {
                    tracing::debug!("a JMAP listing lost its anchor; listing from the start");
                    cursor.listing = Some(None);
                    restarted = true;
                }
                Err(kind) => {
                    return Err(MailError::Protocol(format!(
                        "the JMAP server refused a request: {kind}"
                    )));
                }
                Ok(query) => {
                    let ids = strings(&query, "ids")?;
                    let emails = match answers.next() {
                        Some(Ok(get)) => list(&get)?,
                        Some(Err(kind)) => {
                            return Err(MailError::Protocol(format!(
                                "the JMAP server refused a request: {kind}"
                            )));
                        }
                        None => self.emails(&ids, &EMAIL_FIELDS).await?.0,
                    };
                    break (ids, emails);
                }
            }
        };
        for email in &emails {
            Self::see(cursor, email, changes)?;
        }
        cursor.listing = if ids.len() >= page {
            Some(ids.last().cloned())
        } else {
            None
        };
        Ok(())
    }

    async fn feed(
        &self,
        cursor: &mut JmapCursor,
        changes: &mut Vec<MailChange>,
        limit: usize,
    ) -> Result<Feed, MailError> {
        let answers = self
            .answers(vec![
                (
                    "Email/changes",
                    json!({
                        "accountId": self.account,
                        "sinceState": cursor.state,
                        "maxChanges": limit.max(1),
                    }),
                ),
                self.mailbox_check(&cursor.mailbox),
            ])
            .await?;
        let mut answers = answers.into_iter();
        let changed = match answers.next() {
            Some(Ok(changed)) => changed,
            Some(Err(kind)) if kind == "cannotCalculateChanges" => return Ok(Feed::UnknownState),
            Some(Err(kind)) => {
                return Err(MailError::Protocol(format!(
                    "the JMAP server refused a request: {kind}"
                )));
            }
            None => return Err(protocol("the JMAP server left a call unanswered")),
        };
        match answers.next() {
            Some(Ok(mailbox)) if Self::found(&mailbox) => {}
            Some(Ok(_)) => return Err(MailError::MailboxNotFound),
            _ => return Err(protocol("the JMAP server did not answer for the mailbox")),
        }
        let destroyed: HashSet<String> = strings(&changed, "destroyed")?.into_iter().collect();
        let mut seen = HashSet::new();
        let touched: Vec<String> = strings(&changed, "created")?
            .into_iter()
            .chain(strings(&changed, "updated")?)
            .filter(|id| !destroyed.contains(id) && seen.insert(id.clone()))
            .collect();
        for id in &destroyed {
            if cursor.known.remove(&id_key(id)).is_some() {
                changes.push(MailChange::Removed {
                    item: item(id.clone()),
                });
            }
        }
        let (emails, _) = self.emails(&touched, &EMAIL_FIELDS).await?;
        let mut by_id: HashMap<String, Value> = HashMap::with_capacity(emails.len());
        for email in emails {
            by_id.insert(string(&email, "id")?, email);
        }
        for id in touched {
            match by_id.get(&id) {
                Some(email) => Self::see(cursor, email, changes)?,
                None => {
                    if cursor.known.remove(&id_key(&id)).is_some() {
                        changes.push(MailChange::Removed { item: item(id) });
                    }
                }
            }
        }
        cursor.state = string(&changed, "newState")?;
        Ok(Feed::Done {
            more: changed
                .get("hasMoreChanges")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        })
    }

    async fn download(&self, blob: &str) -> Result<Option<Bytes>, MailError> {
        let url = expand(
            &self.download_url,
            &[
                ("accountId", &self.account),
                ("blobId", blob),
                ("type", "message/rfc822"),
                ("name", "message.eml"),
            ],
        );
        self.http.get_bytes(&url).await
    }
}

/// The answers of a JMAP response to `count` calls, by call id: each call's arguments, or the type
/// of the method-level error the server gave for it.
pub(crate) fn answers_in_order(
    answer: &Value,
    count: usize,
) -> Result<Vec<Result<Value, String>>, MailError> {
    let responses = answer
        .get("methodResponses")
        .and_then(Value::as_array)
        .ok_or_else(|| protocol("the JMAP answer has no method responses"))?;
    let mut out = vec![None; count];
    for response in responses {
        let Some([name, args, id]) = response.as_array().map(Vec::as_slice) else {
            return Err(protocol("a JMAP method response is malformed"));
        };
        let Some(index) = id.as_str().and_then(|id| id.parse::<usize>().ok()) else {
            continue;
        };
        let answer = if name == "error" {
            Err(args
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned())
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

/// Mailboxes from a `Mailbox/get` list, sorted by path.
pub(crate) fn mailbox_infos(raw: &[Value]) -> Result<Vec<MailboxInfo>, MailError> {
    let mut by_id = HashMap::new();
    for mailbox in raw {
        by_id.insert(
            string(mailbox, "id")?,
            (
                string(mailbox, "name")?,
                mailbox
                    .get("parentId")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            ),
        );
    }
    let mut out = Vec::with_capacity(raw.len());
    for mailbox in raw {
        let id = string(mailbox, "id")?;
        out.push(MailboxInfo {
            path: path(&id, &by_id)?,
            role: mailbox.get("role").and_then(Value::as_str).and_then(role),
            id,
            selectable: true,
            label: false,
        });
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

fn path(id: &str, by_id: &HashMap<String, (String, Option<String>)>) -> Result<String, MailError> {
    let mut names = Vec::new();
    let mut next = Some(id.to_owned());
    while let Some(current) = next {
        if names.len() > by_id.len() {
            return Err(protocol("the JMAP mailboxes form a loop"));
        }
        let Some((name, parent)) = by_id.get(&current) else {
            break;
        };
        names.push(name.clone());
        next = parent.clone();
    }
    names.reverse();
    Ok(names.join("/"))
}

#[async_trait]
impl MailSession for JmapSession {
    async fn mailboxes(&mut self) -> Result<Vec<MailboxInfo>, MailError> {
        let answer = self
            .call(vec![(
                "Mailbox/get",
                json!({
                    "accountId": self.account,
                    "ids": null,
                    "properties": ["id", "name", "parentId", "role"],
                }),
            )])
            .await?;
        let out = mailbox_infos(&list(&answer[0])?)?;
        tracing::debug!(mailboxes = out.len(), "listed JMAP mailboxes");
        Ok(out)
    }

    async fn changes(
        &mut self,
        mailbox: &str,
        cursor: Option<&Cursor>,
        limit: usize,
    ) -> Result<MailboxChanges, MailError> {
        let mut changes = Vec::new();
        let known = match cursor.map(JmapCursor::decode) {
            None => None,
            Some(Some(c)) if c.mailbox == mailbox && c.account == self.account => Some(c),
            Some(_) => {
                changes.push(MailChange::Reset {
                    reason: "cursor".into(),
                });
                None
            }
        };
        let mut state = match known {
            Some(c) => c,
            None => self.start(mailbox).await?,
        };
        if state.listing.is_none() {
            match self.feed(&mut state, &mut changes, limit).await? {
                Feed::Done { more } => {
                    tracing::debug!(changes = changes.len(), more, "read JMAP changes");
                    return Ok(MailboxChanges {
                        changes,
                        cursor: state.encode(),
                        more,
                    });
                }
                Feed::UnknownState => {
                    tracing::debug!("the JMAP server no longer knows the state; listing again");
                    changes.push(MailChange::Reset {
                        reason: "state".into(),
                    });
                    state = self.start(mailbox).await?;
                }
            }
        }
        self.list_page(&mut state, &mut changes, limit).await?;
        tracing::debug!(changes = changes.len(), "read a JMAP listing page");
        Ok(MailboxChanges {
            changes,
            cursor: state.encode(),
            more: true,
        })
    }

    async fn fetch(
        &mut self,
        mailbox: &str,
        items: &[ItemRef],
    ) -> Result<Vec<RawMessage>, MailError> {
        let ids: Vec<String> = items.iter().map(|i| i.id.clone()).collect();
        let (emails, _) = self.emails(&ids, &["id", "blobId", "mailboxIds"]).await?;
        let mut blobs = HashMap::new();
        for email in emails.iter().filter(|e| in_mailbox(e, mailbox)) {
            blobs.insert(string(email, "id")?, string(email, "blobId")?);
        }
        let wanted: Vec<(ItemRef, String)> = items
            .iter()
            .filter_map(|i| blobs.get(&i.id).map(|b| (i.clone(), b.clone())))
            .collect();
        let this = &*self;
        let results: Vec<Result<Option<RawMessage>, MailError>> = futures::stream::iter(wanted)
            .map(|(item, blob)| async move {
                Ok(this
                    .download(&blob)
                    .await?
                    .map(|bytes| RawMessage { item, bytes }))
            })
            .buffered(DOWNLOADS)
            .collect()
            .await;
        let out: Vec<RawMessage> = results
            .into_iter()
            .filter_map(Result::transpose)
            .collect::<Result<_, _>>()?;
        tracing::debug!(
            asked = items.len(),
            fetched = out.len(),
            "downloaded JMAP blobs"
        );
        Ok(out)
    }

    async fn apply(
        &mut self,
        command: &CommandBody,
        content: Option<Bytes>,
    ) -> Result<WriteOutcome, MailError> {
        write::apply(self, command, content).await
    }

    /// System flags `\Seen`, `\Flagged`, `\Answered` and `\Draft`; other keywords unless every
    /// mailbox refuses keywords (`myRights.maySetKeywords`); copies, `received_at` on append
    /// and mailbox changes always; the trash when a mailbox has the `trash` role; never labels.
    async fn capabilities(&mut self) -> Result<MailCapabilities, MailError> {
        write::capabilities(self).await
    }

    async fn logout(&mut self) -> Result<(), MailError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
