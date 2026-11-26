//! The [`MailProvider`] contract on Microsoft 365 and Outlook.com mailboxes through Microsoft
//! Graph.
//!
//! [`GraphProvider`] signs in with an OAuth access token (refreshing it is someone else's job),
//! lists mail folders, turns each folder's message delta query into a change feed whose cursor
//! holds the delta link, downloads each message's original MIME bytes from its `$value`, and
//! carries out writes with `PATCH`, `move`, `permanentDelete` and MIME uploads. `isRead`, `flag`
//! and `isDraft` become `\Seen`, `\Flagged` and `\Draft`. Reading only sends `GET` requests.
//!
//! The token goes only to the origin of the configured API address: links in answers or
//! cursors that point anywhere else are refused, and redirects are never followed.

mod cursor;
mod folders;
#[doc(hidden)]
pub mod fuzzing;
mod http;
mod push;
mod time;
mod write;

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use skein_core::{
    CommandBody, Credentials, Flags, ItemRef, MailCapabilities, MailboxInfo, MailboxRole, TlsRoots,
};
use skein_mail::{
    Cursor, MailChange, MailError, MailProvider, MailSession, MailboxChanges, PushTarget,
    RawMessage, Subscription, WriteOutcome,
};
use skein_throttle::Throttle;
use url::Url;

use cursor::{DeltaCursor, flags_key, id_key};
use http::{Answer, Http, Scope};

/// Where Microsoft Graph answers for accounts in the global cloud.
pub const GRAPH_URL: &str = "https://graph.microsoft.com/v1.0";

const DOWNLOADS: usize = 4;
const LIST_FIELDS: &str = "id,receivedDateTime,isRead,flag,isDraft";
const FOLDER_FIELDS: &str = "id,displayName,childFolderCount";
const MAX_FOLDERS: usize = 10_000;
const MAX_PAGE: usize = 1000;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
pub(crate) const WELL_KNOWN: [(&str, MailboxRole); 6] = [
    ("inbox", MailboxRole::Inbox),
    ("sentitems", MailboxRole::Sent),
    ("drafts", MailboxRole::Drafts),
    ("deleteditems", MailboxRole::Trash),
    ("junkemail", MailboxRole::Junk),
    ("archive", MailboxRole::Archive),
];

/// Where the mailbox is. The access token is passed separately and never stored here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphSettings {
    /// The Graph endpoint with its version; [`GRAPH_URL`] when missing. Only `https`, or plain
    /// `http` to a loopback address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_url: Option<String>,
    /// Certificates trusted besides the built-in roots. They never turn verification off.
    #[serde(skip)]
    pub roots: TlsRoots,
}

impl GraphSettings {
    /// Reads settings from JSON; other keys are ignored. `Config` when they do not parse.
    pub fn from_json(value: &Value) -> Result<Self, MailError> {
        serde_json::from_value(value.clone()).map_err(|e| MailError::Config(e.to_string()))
    }

    fn base(&self) -> Result<Url, MailError> {
        let raw = self.api_url.as_deref().unwrap_or(GRAPH_URL).trim();
        let mut url = Url::parse(raw)
            .map_err(|_| MailError::Config("the Graph address is not a web address".into()))?;
        if !http::allowed(&url) {
            return Err(MailError::Config(
                "the Graph address must use https (plain http only to loopback)".into(),
            ));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(MailError::Config(
                "the Graph address must not hold credentials".into(),
            ));
        }
        if url.cannot_be_a_base() {
            return Err(MailError::Config(
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
}

/// A Microsoft Graph mailbox, signed in as the owner of the access token. Cloning is cheap;
/// sessions share one HTTP client.
#[derive(Clone)]
pub struct GraphProvider {
    base: Url,
    http: Http,
}

impl fmt::Debug for GraphProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GraphProvider")
            .field("base", &self.base.as_str())
            .field("token", &"<redacted>")
            .finish()
    }
}

impl GraphProvider {
    /// A provider for the mailbox behind `credentials`, which must be an access token with
    /// `Mail.Read` (and `Mail.ReadWrite` for writes). `Config` for a password, an unusable API
    /// address or an extra root that is not a certificate; nothing is sent before these checks.
    pub fn new(settings: GraphSettings, credentials: Credentials) -> Result<Self, MailError> {
        let Credentials::AccessToken { token } = credentials else {
            return Err(MailError::Config(
                "Microsoft Graph signs in with an access token, not a password".into(),
            ));
        };
        if token.trim().is_empty() {
            return Err(MailError::Config("the access token is empty".into()));
        }
        let base = settings.base()?;
        Ok(Self {
            http: Http::new(token, &base, REQUEST_TIMEOUT, &settings.roots)?,
            base,
        })
    }

    /// Gives every request `timeout` instead of five minutes; a request without an answer by
    /// then is a `Network` error, or [`WriteOutcome::Uncertain`] for a write that went out.
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, MailError> {
        self.http = self.http.with_timeout(timeout)?;
        Ok(self)
    }

    /// Refuses message downloads larger than `bytes` (256 MiB by default) as a `Protocol` error.
    pub fn with_max_download(mut self, bytes: usize) -> Self {
        self.http.max_download = bytes;
        self
    }

    /// Sends every request to Graph through `throttle`: each waits for a slot and for any pause
    /// in effect, and a `429` or `503` with `Retry-After` pauses it for every holder, such as the
    /// calendar and sending providers of the same mailbox. The error returned is unchanged.
    /// Without a throttle requests go out at once.
    pub fn with_throttle(mut self, throttle: Throttle) -> Self {
        self.http.throttle = Some(throttle);
        self
    }
}

#[async_trait]
impl MailProvider for GraphProvider {
    async fn connect(&self) -> Result<Box<dyn MailSession>, MailError> {
        Ok(Box::new(GraphSession {
            base: self.base.clone(),
            http: self.http.clone(),
        }))
    }

    /// `POST /subscriptions` for `created,updated,deleted` on `me/messages`, with `target.url`
    /// as both the notification and the lifecycle address and `target.client_state` as
    /// `clientState` (1 to 128 printable characters, else `Config`). It lasts 4200 minutes, just
    /// under Graph's limit for messages. Graph checks the address first with a validation request
    /// that must be answered within 10 seconds, so the server has to be reachable before this is
    /// called; a failed check is a `Protocol` error.
    async fn subscribe(&self, target: &PushTarget) -> Result<Option<Subscription>, MailError> {
        push::subscribe(self, target).await
    }

    /// `PATCH /subscriptions/{id}` with a new expiry; a subscription Graph no longer knows
    /// (expired or removed) is replaced by a new one with a new id.
    async fn renew(
        &self,
        subscription: &Subscription,
        target: &PushTarget,
    ) -> Result<Option<Subscription>, MailError> {
        push::renew(self, subscription, target).await
    }

    /// `DELETE /subscriptions/{id}`; one Graph no longer knows counts as removed.
    async fn unsubscribe(&self, subscription: &Subscription) -> Result<(), MailError> {
        push::unsubscribe(self, subscription).await
    }
}

pub(crate) fn endpoint(
    base: &Url,
    segments: &[&str],
    query: &[(&str, &str)],
) -> Result<Url, MailError> {
    let mut url = base.clone();
    url.path_segments_mut()
        .map_err(|_| MailError::Config("the Graph address cannot take a path".into()))?
        .pop_if_empty()
        .extend(segments);
    if !query.is_empty() {
        url.query_pairs_mut().extend_pairs(query);
    }
    Ok(url)
}

fn protocol(what: &str) -> MailError {
    MailError::Protocol(what.to_owned())
}

pub(crate) fn string(object: &Value, key: &str) -> Result<String, MailError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| MailError::Protocol(format!("a Graph object has no {key}")))
}

pub(crate) fn flags(message: &Value) -> Flags {
    let mut out = Vec::new();
    if message.get("isRead").and_then(Value::as_bool) == Some(true) {
        out.push("\\Seen");
    }
    if message
        .pointer("/flag/flagStatus")
        .and_then(Value::as_str)
        .is_some_and(|s| s.eq_ignore_ascii_case("flagged"))
    {
        out.push("\\Flagged");
    }
    if message.get("isDraft").and_then(Value::as_bool) == Some(true) {
        out.push("\\Draft");
    }
    Flags::new(out)
}

pub(crate) struct Page {
    pub(crate) items: Vec<Value>,
    pub(crate) next: Option<String>,
    pub(crate) delta: Option<String>,
}

pub(crate) fn page(answer: &Value) -> Result<Page, MailError> {
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

/// Folds one delta page into the known messages and the changes it makes.
pub(crate) fn see(
    known: &mut BTreeMap<u64, u32>,
    items: Vec<Value>,
    changes: &mut Vec<MailChange>,
) -> Result<(), MailError> {
    for item in items {
        let id = string(&item, "id")?;
        let key = id_key(&id);
        if item.get("@removed").is_some() {
            if known.remove(&key).is_some() {
                changes.push(MailChange::Removed {
                    item: ItemRef { id, uid: None },
                });
            }
            continue;
        }
        let flags = flags(&item);
        let fkey = flags_key(&flags);
        match known.insert(key, fkey) {
            None => changes.push(MailChange::Added {
                received_at: item
                    .get("receivedDateTime")
                    .and_then(Value::as_str)
                    .and_then(time::parse_utc),
                item: ItemRef { id, uid: None },
                flags,
                labels: None,
            }),
            Some(old) if old != fkey => changes.push(MailChange::Flags {
                item: ItemRef { id, uid: None },
                flags,
            }),
            Some(_) => {}
        }
    }
    Ok(())
}

pub(crate) struct GraphSession {
    pub(crate) base: Url,
    pub(crate) http: Http,
}

impl GraphSession {
    async fn all(&self, first: Url) -> Result<Vec<Value>, MailError> {
        let mut items = Vec::new();
        let mut url = first;
        loop {
            let answer = match self.http.get_json(url, Scope::Mailbox, None).await? {
                Answer::Found(v) => v,
                _ => return Err(protocol("Microsoft Graph refused to list folders")),
            };
            let page = page(&answer)?;
            items.extend(page.items);
            if items.len() > MAX_FOLDERS {
                return Err(protocol("the mailbox has too many folders"));
            }
            match page.next {
                Some(next) => url = self.http.url(&next)?,
                None => return Ok(items),
            }
        }
    }

    async fn roles(&self) -> Result<HashMap<String, MailboxRole>, MailError> {
        let mut roles = HashMap::new();
        for (name, role) in WELL_KNOWN {
            let url = endpoint(
                &self.base,
                &["me", "mailFolders", name],
                &[("$select", "id")],
            )?;
            if let Answer::Found(folder) = self.http.get_json(url, Scope::Mailbox, None).await? {
                roles.insert(string(&folder, "id")?, role);
            }
        }
        Ok(roles)
    }

    fn fresh(&self, mailbox: &str) -> Result<DeltaCursor, MailError> {
        Ok(DeltaCursor {
            folder: mailbox.to_owned(),
            link: endpoint(
                &self.base,
                &["me", "mailFolders", mailbox, "messages", "delta"],
                &[("$select", LIST_FIELDS)],
            )?
            .to_string(),
            known: Default::default(),
        })
    }

    async fn download(&self, id: &str) -> Result<Option<Bytes>, MailError> {
        let url = endpoint(&self.base, &["me", "messages", id, "$value"], &[])?;
        Ok(match self.http.get_bytes(url).await? {
            Answer::Found(raw) => Some(raw),
            Answer::Missing => None,
            Answer::Refused => return Err(protocol("Microsoft Graph refused a download")),
        })
    }
}

#[async_trait]
impl MailSession for GraphSession {
    async fn mailboxes(&mut self) -> Result<Vec<MailboxInfo>, MailError> {
        let roles = self.roles().await?;
        let query = [
            ("includeHiddenFolders", "true"),
            ("$top", "250"),
            ("$select", FOLDER_FIELDS),
        ];
        let mut out = Vec::new();
        let mut queue = VecDeque::from([(
            endpoint(&self.base, &["me", "mailFolders"], &query)?,
            String::new(),
        )]);
        while let Some((url, parent)) = queue.pop_front() {
            for item in self.all(url).await? {
                if item
                    .get("@odata.type")
                    .and_then(Value::as_str)
                    .is_some_and(|t| t.ends_with("mailSearchFolder"))
                {
                    continue;
                }
                let id = string(&item, "id")?;
                let name = string(&item, "displayName")?;
                let path = if parent.is_empty() {
                    name
                } else {
                    format!("{parent}/{name}")
                };
                if item
                    .get("childFolderCount")
                    .and_then(Value::as_u64)
                    .is_some_and(|n| n > 0)
                {
                    queue.push_back((
                        endpoint(
                            &self.base,
                            &["me", "mailFolders", &id, "childFolders"],
                            &query,
                        )?,
                        path.clone(),
                    ));
                }
                out.push(MailboxInfo {
                    role: roles.get(&id).copied(),
                    id,
                    path,
                    selectable: true,
                    label: false,
                });
                if out.len() > MAX_FOLDERS {
                    return Err(protocol("the mailbox has too many folders"));
                }
            }
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        tracing::debug!(mailboxes = out.len(), "listed Graph folders");
        Ok(out)
    }

    async fn changes(
        &mut self,
        mailbox: &str,
        cursor: Option<&Cursor>,
        limit: usize,
    ) -> Result<MailboxChanges, MailError> {
        let mut changes = Vec::new();
        let mut state = match cursor {
            None => self.fresh(mailbox)?,
            Some(c) => match DeltaCursor::decode(c)
                .filter(|s| s.folder == mailbox && self.http.url(&s.link).is_ok())
            {
                Some(s) => s,
                None => {
                    changes.push(MailChange::Reset {
                        reason: "cursor".into(),
                    });
                    self.fresh(mailbox)?
                }
            },
        };
        let page_size = limit.clamp(1, MAX_PAGE);
        let mut fresh = cursor.is_none() || !changes.is_empty();
        let answer = loop {
            let url = self.http.url(&state.link)?;
            match self
                .http
                .get_json(url, Scope::Item, Some(page_size))
                .await?
            {
                Answer::Found(answer) => break answer,
                Answer::Missing if fresh => return Err(MailError::MailboxNotFound),
                Answer::Refused if fresh => {
                    return Err(protocol("Microsoft Graph refused a delta query"));
                }
                Answer::Missing | Answer::Refused => {
                    tracing::debug!("Graph no longer accepts a delta link; listing again");
                    changes.push(MailChange::Reset {
                        reason: "delta_expired".into(),
                    });
                    state = self.fresh(mailbox)?;
                    fresh = true;
                }
            }
        };
        let page = page(&answer)?;
        see(&mut state.known, page.items, &mut changes)?;
        let more = page.next.is_some();
        let link = page
            .next
            .or(page.delta)
            .ok_or_else(|| protocol("a Graph delta page has neither a next nor a delta link"))?;
        self.http.url(&link)?;
        state.link = link;
        tracing::debug!(changes = changes.len(), more, "read a Graph delta page");
        Ok(MailboxChanges {
            changes,
            cursor: state.encode(),
            more,
        })
    }

    async fn fetch(
        &mut self,
        _mailbox: &str,
        items: &[ItemRef],
    ) -> Result<Vec<RawMessage>, MailError> {
        let this = &*self;
        let results: Vec<Result<Option<RawMessage>, MailError>> =
            futures::stream::iter(items.iter().cloned())
                .map(|item| async move {
                    Ok(this
                        .download(&item.id)
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
            "downloaded Graph messages"
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

    /// `\Flagged` and `\Seen` (`isDraft` cannot be changed and there is no answered property),
    /// trash (Deleted Items), copy and folder management. Categories are not reported as labels
    /// and there are no keywords; an upload cannot set the received time.
    async fn capabilities(&mut self) -> Result<MailCapabilities, MailError> {
        Ok(MailCapabilities {
            system_flags: vec!["\\Flagged".into(), "\\Seen".into()],
            keywords: false,
            labels: false,
            trash: true,
            copy: true,
            append_received_at: false,
            mailboxes: true,
        })
    }

    async fn logout(&mut self) -> Result<(), MailError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
