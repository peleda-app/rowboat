//! The [`MailProvider`] contract on Gmail through the Gmail API.
//!
//! [`GmailProvider`] signs in with an OAuth access token, shows labels as mailboxes next to a
//! synthetic `ALL` mailbox, lists messages with `messages.list`, follows changes with
//! `history.list`, returns the exact RFC 5322 bytes from `format=raw`, and carries out writes
//! as label changes, trash, delete, insert and label management. Reading never changes the
//! server. The token is sent only to the origin of [`GmailSettings::api_url`], redirects are
//! never followed, and every request waits for room under Gmail's per-user quota.

mod changes;
mod cursor;
#[doc(hidden)]
pub mod fuzzing;
mod http;
mod labels;
mod push;
mod quota;
mod write;

#[cfg(test)]
mod fake;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use bytes::Bytes;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use skein_core::{CommandBody, Credentials, ItemRef, MailCapabilities, MailboxInfo};
use skein_mail::{
    Cursor, MailError, MailProvider, MailSession, MailWatch, MailboxChanges, PushTarget,
    RawMessage, Subscription, WriteOutcome,
};
use url::Url;

pub use quota::DEFAULT_UNITS_PER_SECOND;

use http::Http;
use labels::Label;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
/// Largest message `fetch` accepts, in bytes after base64 decoding.
pub const MAX_MESSAGE: usize = 64 * 1024 * 1024;
/// Requests one session keeps in flight for listings, metadata and raw messages.
pub const CONCURRENCY: usize = 8;

/// The synthetic mailbox of every message that is not in Spam or Trash. It is not a Gmail
/// label, so no label id can collide with it.
pub const ALL: &str = "ALL";

fn default_api_url() -> String {
    "https://gmail.googleapis.com".into()
}

fn default_user() -> String {
    "me".into()
}

/// Where the Gmail API is and whose mailbox to read. Credentials are passed separately.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GmailSettings {
    /// The API origin, optionally with a path prefix; `https://gmail.googleapis.com` when
    /// omitted. Plain `http` is accepted only for loopback hosts.
    #[serde(default = "default_api_url")]
    pub api_url: String,
    /// The user id in API paths; `me` (the token's owner) when omitted.
    #[serde(default = "default_user")]
    pub user: String,
}

impl Default for GmailSettings {
    fn default() -> Self {
        Self {
            api_url: default_api_url(),
            user: default_user(),
        }
    }
}

impl fmt::Debug for GmailSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let user = if self.user == "me" {
            "me"
        } else {
            "<redacted>"
        };
        f.debug_struct("GmailSettings")
            .field("api_url", &self.api_url)
            .field("user", &user)
            .finish()
    }
}

impl GmailSettings {
    /// Reads settings from JSON; `Config` when they do not parse.
    pub fn from_json(value: &serde_json::Value) -> Result<Self, MailError> {
        serde_json::from_value(value.clone()).map_err(|e| MailError::Config(e.to_string()))
    }
}

/// A Gmail account. Cloning is cheap; clones and their sessions share one quota limiter.
#[derive(Clone)]
pub struct GmailProvider {
    settings: Arc<GmailSettings>,
    credentials: Arc<Credentials>,
    base: Url,
    timeout: Duration,
    quota: Arc<quota::Quota>,
    max_message: usize,
}

impl fmt::Debug for GmailProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GmailProvider")
            .field("settings", &self.settings)
            .field("credentials", &self.credentials)
            .finish_non_exhaustive()
    }
}

impl GmailProvider {
    /// A provider for the account in `settings`, signing in with an access token.
    ///
    /// `Config` before anything is sent when the credentials are a password, the token is empty,
    /// `api_url` is not an `https` address (or `http` to loopback), or `user` is empty or not a
    /// plain path segment.
    pub fn new(settings: GmailSettings, credentials: Credentials) -> Result<Self, MailError> {
        match &credentials {
            Credentials::AccessToken { token } if !token.trim().is_empty() => {}
            Credentials::AccessToken { .. } => {
                return Err(MailError::Config("the access token is empty".into()));
            }
            Credentials::Password { .. } => {
                return Err(MailError::Config(
                    "the Gmail API needs an OAuth access token, not a password".into(),
                ));
            }
            Credentials::AccessKey { .. } => {
                return Err(MailError::Config(
                    "the Gmail API needs an OAuth access token, not an access key".into(),
                ));
            }
        }
        let base = Url::parse(&settings.api_url)
            .map_err(|_| MailError::Config("api_url is not a valid address".into()))?;
        if !http::allowed(&base) || base.cannot_be_a_base() {
            return Err(MailError::Config(
                "api_url must be https, or http to a loopback host".into(),
            ));
        }
        if !base.username().is_empty() || base.password().is_some() {
            return Err(MailError::Config(
                "api_url must not carry credentials".into(),
            ));
        }
        let user = settings.user.as_str();
        if user.is_empty() || user == "." || user == ".." || user.chars().any(char::is_control) {
            return Err(MailError::Config("user is not a valid user id".into()));
        }
        Ok(Self {
            settings: Arc::new(settings),
            credentials: Arc::new(credentials),
            base,
            timeout: REQUEST_TIMEOUT,
            quota: Arc::new(quota::Quota::new(DEFAULT_UNITS_PER_SECOND)),
            max_message: MAX_MESSAGE,
        })
    }

    /// Gives every request `timeout` instead of two minutes; a server that does not answer in
    /// time is a `Network` error (or `Uncertain` for a write that already left).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Keeps requests under `units` quota units per second instead of
    /// [`DEFAULT_UNITS_PER_SECOND`], with a fresh limiter shared by this provider's clones made
    /// afterwards.
    pub fn with_quota(mut self, units: u32) -> Self {
        self.quota = Arc::new(quota::Quota::new(units));
        self
    }

    #[cfg(test)]
    pub(crate) fn with_max_message(mut self, bytes: usize) -> Self {
        self.max_message = bytes;
        self
    }

    fn http(&self) -> Result<Http, MailError> {
        let Credentials::AccessToken { token } = &*self.credentials else {
            return Err(MailError::Config("an access token is required".into()));
        };
        Http::new(
            token.clone(),
            self.base.clone(),
            self.settings.user.clone(),
            self.timeout,
            self.quota.clone(),
        )
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Profile {
    history_id: Option<String>,
}

/// A message as `format=minimal` returns it, restricted to the fields asked for.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Meta {
    #[serde(default)]
    pub label_ids: Vec<String>,
    pub internal_date: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct Raw {
    pub(crate) raw: Option<String>,
}

pub(crate) fn parse_number(s: &str) -> Result<u64, MailError> {
    s.trim()
        .parse()
        .map_err(|_| MailError::Protocol("the Gmail API sent an invalid number".into()))
}

/// Ids that can be Gmail message ids. Anything else (another provider's id, a forged one) is
/// treated as a message that does not exist.
pub(crate) fn plausible_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[async_trait]
impl MailProvider for GmailProvider {
    async fn connect(&self) -> Result<Box<dyn MailSession>, MailError> {
        let http = self.http()?;
        let session = GmailSession {
            http,
            labels: None,
            max_message: self.max_message,
        };
        session.profile().await?;
        Ok(Box::new(session))
    }

    /// `Ok(None)`: Gmail holds no push connection; it pushes from outside through
    /// [`MailProvider::subscribe`].
    async fn watch(&self, mailboxes: &[String]) -> Result<Option<Box<dyn MailWatch>>, MailError> {
        let _ = mailboxes;
        Ok(None)
    }

    /// `users.watch` on every label with `target.gmail_topic`; `Ok(None)` without a topic. The
    /// subscription's `resource` is the mailbox address (from `users.getProfile`), which Gmail
    /// names in every notification, and it lasts about seven days. Watching again replaces the
    /// previous watch, so the default [`MailProvider::renew`] is right for Gmail. A topic Gmail
    /// may not publish to is `Config`.
    async fn subscribe(&self, target: &PushTarget) -> Result<Option<Subscription>, MailError> {
        push::subscribe(self, target).await
    }

    /// `users.stop`; ending a watch that is already gone succeeds.
    async fn unsubscribe(&self, subscription: &Subscription) -> Result<(), MailError> {
        push::unsubscribe(self, subscription).await
    }
}

pub(crate) struct GmailSession {
    pub(crate) http: Http,
    labels: Option<HashMap<String, Label>>,
    max_message: usize,
}

impl GmailSession {
    pub(crate) async fn profile(&self) -> Result<u64, MailError> {
        let url = self.http.endpoint(false, &["profile"]);
        let profile: Profile = self
            .http
            .get(url, quota::PROFILE, http::MAX_JSON)
            .await?
            .ok_or_else(|| MailError::Protocol("the Gmail API has no such user".into()))?;
        parse_number(
            profile
                .history_id
                .as_deref()
                .ok_or_else(|| MailError::Protocol("the profile has no history id".into()))?,
        )
    }

    async fn load_labels(&mut self) -> Result<&HashMap<String, Label>, MailError> {
        let url = self.http.endpoint(false, &["labels"]);
        let list: labels::LabelList = self
            .http
            .get(url, quota::LABELS_LIST, http::MAX_JSON)
            .await?
            .unwrap_or_default();
        let map = list.labels.into_iter().map(|l| (l.id.clone(), l)).collect();
        Ok(self.labels.insert(map))
    }

    pub(crate) async fn labels(&mut self) -> Result<&HashMap<String, Label>, MailError> {
        if self.labels.is_none() {
            self.load_labels().await?;
        }
        Ok(self.labels.as_ref().expect("loaded"))
    }

    /// Readable label names for label ids, reloading the label list once when one is unknown.
    pub(crate) async fn names(&mut self, ids: &[String]) -> Result<Vec<String>, MailError> {
        let stale = {
            let map = self.labels().await?;
            ids.iter()
                .any(|id| labels::needs_name(id) && !map.contains_key(id))
        };
        if stale {
            self.load_labels().await?;
        }
        Ok(labels::names(ids, self.labels.as_ref().expect("loaded")))
    }

    /// Whether `mailbox` exists: `ALL`, `TRASH`, `SPAM` or a label shown as a mailbox.
    pub(crate) async fn check_mailbox(&mut self, mailbox: &str) -> Result<(), MailError> {
        if labels::is_builtin(mailbox) {
            return Ok(());
        }
        if self
            .labels()
            .await?
            .get(mailbox)
            .is_some_and(labels::is_mailbox)
        {
            return Ok(());
        }
        if self
            .load_labels()
            .await?
            .get(mailbox)
            .is_some_and(labels::is_mailbox)
        {
            return Ok(());
        }
        Err(MailError::MailboxNotFound)
    }

    /// `format=minimal` for each id, [`CONCURRENCY`] at a time, in the order given; `None` for
    /// messages that are gone.
    pub(crate) async fn metas(&self, ids: &[String]) -> Result<Vec<Option<Meta>>, MailError> {
        futures::stream::iter(ids.to_vec())
            .map(|id| {
                let http = self.http.clone();
                async move {
                    let mut url = http.endpoint(false, &["messages", &id]);
                    url.query_pairs_mut()
                        .append_pair("format", "minimal")
                        .append_pair("fields", "id,labelIds,internalDate");
                    http.get::<Meta>(url, quota::MESSAGES_GET, http::MAX_JSON)
                        .await
                }
            })
            .buffered(CONCURRENCY)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect()
    }
}

#[async_trait]
impl MailSession for GmailSession {
    async fn mailboxes(&mut self) -> Result<Vec<MailboxInfo>, MailError> {
        let map = self.load_labels().await?;
        Ok(labels::mailboxes(map))
    }

    async fn changes(
        &mut self,
        mailbox: &str,
        cursor: Option<&Cursor>,
        limit: usize,
    ) -> Result<MailboxChanges, MailError> {
        changes::changes(self, mailbox, cursor, limit).await
    }

    async fn fetch(
        &mut self,
        mailbox: &str,
        items: &[ItemRef],
    ) -> Result<Vec<RawMessage>, MailError> {
        self.check_mailbox(mailbox).await?;
        let max = self.max_message;
        let limit = max / 3 * 4 + 8 + 64 * 1024;
        let wanted: Vec<ItemRef> = items
            .iter()
            .filter(|i| plausible_id(&i.id))
            .cloned()
            .collect();
        let got: Vec<Result<Option<RawMessage>, MailError>> = futures::stream::iter(wanted)
            .map(|item| {
                let http = self.http.clone();
                async move {
                    let mut url = http.endpoint(false, &["messages", &item.id]);
                    url.query_pairs_mut()
                        .append_pair("format", "raw")
                        .append_pair("fields", "raw");
                    let Some(raw) = http.get::<Raw>(url, quota::MESSAGES_GET, limit).await? else {
                        return Ok(None);
                    };
                    let encoded = raw.raw.ok_or_else(|| {
                        MailError::Protocol("the Gmail API sent a message without content".into())
                    })?;
                    if encoded.len() > limit {
                        return Err(too_large());
                    }
                    let bytes =
                        base64url()
                            .decode(encoded.trim_end_matches('='))
                            .map_err(|_| {
                                MailError::Protocol("the Gmail API sent invalid base64".into())
                            })?;
                    if bytes.len() > max {
                        return Err(too_large());
                    }
                    Ok(Some(RawMessage {
                        item,
                        bytes: Bytes::from(bytes),
                    }))
                }
            })
            .buffered(CONCURRENCY)
            .collect()
            .await;
        let mut out = Vec::with_capacity(got.len());
        for r in got {
            if let Some(m) = r? {
                out.push(m);
            }
        }
        tracing::debug!(asked = items.len(), fetched = out.len(), "gmail fetch");
        Ok(out)
    }

    async fn apply(
        &mut self,
        command: &CommandBody,
        content: Option<Bytes>,
    ) -> Result<WriteOutcome, MailError> {
        write::apply(self, command, content).await
    }

    /// `\Flagged` and `\Seen` (Gmail refuses to add or remove `DRAFT` on a message and has no
    /// answered label), labels, trash, copy (adding the target's label) and user label
    /// management. `Append` cannot set an arbitrary received time and there are no keywords.
    async fn capabilities(&mut self) -> Result<MailCapabilities, MailError> {
        Ok(MailCapabilities {
            system_flags: vec!["\\Flagged".into(), "\\Seen".into()],
            keywords: false,
            labels: true,
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

fn too_large() -> MailError {
    MailError::Protocol("a message is larger than the provider accepts".into())
}

pub(crate) fn base64url() -> base64::engine::GeneralPurpose {
    base64::engine::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireNone)
            .with_encode_padding(false),
    )
}
