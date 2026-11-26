//! The [`Sender`] contract on Gmail through the Gmail API.
//!
//! [`GmailSender`] hands the message to `users.messages.send` as `raw` (base64url RFC 5322).
//! Gmail keeps the sent copy under the `SENT` label, picks the return path from the account, and
//! takes the recipients from the To, Cc and Bcc fields, so envelope recipients the fields do not
//! name are added in one `Bcc` field to the bytes handed to Gmail, and only there; Gmail removes
//! `Bcc` from what recipients get. A header recipient that is not in the envelope is refused
//! before anything is sent.
//!
//! The token goes only to the origin of [`GmailSendSettings::api_url`], and redirects are never
//! followed.

mod bcc;
#[cfg(test)]
mod tests;

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE;
use reqwest::StatusCode;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, RETRY_AFTER};
use serde::{Deserialize, Serialize};
use skein_core::{Credentials, TlsRoots};
use skein_send::{Envelope, Limits, SendError, SendReport, Sender};
use url::{Host, Url};

/// The largest message `messages.send` takes, in bytes before encoding.
pub const MAX_SIZE: u64 = 35 * 1024 * 1024;

const MAX_ERROR_BODY: usize = 64 * 1024;

fn default_api_url() -> String {
    "https://gmail.googleapis.com".into()
}

fn default_user() -> String {
    "me".into()
}

/// Where the Gmail API is and whose mailbox sends. Credentials are passed separately. Reads the
/// same JSON as the Gmail mail provider's settings.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GmailSendSettings {
    /// The API origin, optionally with a path prefix; `https://gmail.googleapis.com` when
    /// omitted. Plain `http` is accepted only for loopback hosts.
    #[serde(default = "default_api_url")]
    pub api_url: String,
    /// The user id in API paths; `me` (the token's owner) when omitted.
    #[serde(default = "default_user")]
    pub user: String,
    /// The largest message to hand over, in bytes, counting an added `Bcc` field; capped at and
    /// defaulting to [`MAX_SIZE`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_size: Option<u64>,
    /// Certificates trusted besides the built-in roots. They never turn verification off.
    #[serde(skip)]
    pub roots: TlsRoots,
}

impl Default for GmailSendSettings {
    fn default() -> Self {
        Self {
            api_url: default_api_url(),
            user: default_user(),
            max_size: None,
            roots: TlsRoots::default(),
        }
    }
}

impl fmt::Debug for GmailSendSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let user = if self.user == "me" {
            "me"
        } else {
            "<redacted>"
        };
        f.debug_struct("GmailSendSettings")
            .field("api_url", &self.api_url)
            .field("user", &user)
            .finish_non_exhaustive()
    }
}

impl GmailSendSettings {
    /// Reads settings from JSON; other keys are ignored. `Invalid` when they do not parse.
    pub fn from_json(value: &serde_json::Value) -> Result<Self, SendError> {
        serde_json::from_value(value.clone()).map_err(|e| SendError::Invalid(e.to_string()))
    }
}

/// A [`Sender`] over the Gmail API. Gmail keeps the sent copy itself.
pub struct GmailSender {
    client: reqwest::Client,
    send_url: Url,
    check_url: Url,
    max_size: u64,
    token: String,
    roots: TlsRoots,
}

impl fmt::Debug for GmailSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GmailSender")
            .field("send_url", &self.send_url.origin().ascii_serialization())
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

fn allowed(url: &Url) -> bool {
    match url.scheme() {
        "https" => true,
        "http" => match url.host() {
            Some(Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
            Some(Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
            Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
            None => false,
        },
        _ => false,
    }
}

fn invalid(text: &str) -> SendError {
    SendError::Invalid(text.into())
}

fn client(timeout: Duration, roots: &TlsRoots) -> Result<reqwest::Client, SendError> {
    let certificates = roots
        .iter()
        .map(reqwest::Certificate::from_der)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid("an extra trusted certificate cannot be read"))?;
    reqwest::Client::builder()
        .connect_timeout(timeout.min(Duration::from_secs(30)))
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("Skein/", env!("CARGO_PKG_VERSION")))
        .tls_certs_merge(certificates)
        .build()
        .map_err(|_| invalid("the HTTP client cannot be built"))
}

impl GmailSender {
    /// A sender for `settings` with an access token holding `gmail.send` (or a broader scope).
    /// `Invalid` before anything is sent for a password, an empty token, an address that is not
    /// `https` (or `http` to loopback) or holds credentials, a user that is not a plain path
    /// segment, a zero size limit or an extra root that is not a certificate.
    pub fn new(settings: GmailSendSettings, credentials: Credentials) -> Result<Self, SendError> {
        let Credentials::AccessToken { token } = credentials else {
            return Err(invalid(
                "the Gmail API needs an OAuth access token, not a password",
            ));
        };
        if token.trim().is_empty() {
            return Err(invalid("the access token is empty"));
        }
        let mut base = Url::parse(settings.api_url.trim())
            .map_err(|_| invalid("the Gmail API address is not a web address"))?;
        if !allowed(&base) || base.cannot_be_a_base() {
            return Err(invalid(
                "the Gmail API address must use https (plain http only to loopback)",
            ));
        }
        if !base.username().is_empty() || base.password().is_some() {
            return Err(invalid("the Gmail API address must not hold credentials"));
        }
        base.set_query(None);
        base.set_fragment(None);
        let user = settings.user.trim();
        if user.is_empty()
            || user
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '/' | '?' | '#'))
            || user == "."
            || user == ".."
        {
            return Err(invalid("the Gmail user is not a user id"));
        }
        let max_size = settings.max_size.unwrap_or(MAX_SIZE).min(MAX_SIZE);
        if max_size == 0 {
            return Err(invalid("the size limit is zero"));
        }
        let endpoint = |tail: &[&str]| {
            let mut url = base.clone();
            url.path_segments_mut()
                .map_err(|_| invalid("the Gmail API address cannot take a path"))?
                .pop_if_empty()
                .extend(["gmail", "v1", "users", user].iter().chain(tail));
            Ok::<_, SendError>(url)
        };
        Ok(Self {
            client: client(Duration::from_secs(120), &settings.roots)?,
            send_url: endpoint(&["messages", "send"])?,
            check_url: endpoint(&["profile"])?,
            max_size,
            token,
            roots: settings.roots,
        })
    }

    /// Gives every request `timeout` instead of two minutes. A send without an answer by then is
    /// [`SendError::Uncertain`].
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, SendError> {
        self.client = client(timeout, &self.roots)?;
        Ok(self)
    }
}

#[async_trait]
impl Sender for GmailSender {
    async fn check(&self) -> Result<Limits, SendError> {
        let response = self
            .client
            .get(self.check_url.clone())
            .bearer_auth(&self.token)
            .header(ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| SendError::Unavailable("the Gmail API could not be reached".into()))?;
        let status = response.status();
        if status.is_success() {
            return Ok(Limits {
                max_size: Some(self.max_size),
                smtputf8: true,
                dsn: false,
            });
        }
        let wait = retry_after(response.headers());
        let reasons = reasons(response).await;
        Err(match refusal(status, wait, &reasons) {
            SendError::Uncertain(text) => SendError::Unavailable(text),
            other => other,
        })
    }

    async fn send(&self, envelope: &Envelope, message: &[u8]) -> Result<SendReport, SendError> {
        envelope.validate(message)?;
        let outgoing = bcc::with_bcc(envelope, message)?;
        if outgoing.len() as u64 > self.max_size {
            return Err(SendError::TooLarge {
                limit: Some(self.max_size),
            });
        }
        let body = serde_json::json!({ "raw": URL_SAFE.encode(&outgoing) }).to_string();
        let response = match self
            .client
            .post(self.send_url.clone())
            .bearer_auth(&self.token)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
        {
            Ok(response) => response,
            Err(e) if e.is_connect() || e.is_builder() => {
                return Err(SendError::Unavailable(
                    "the Gmail API could not be reached".into(),
                ));
            }
            Err(_) => {
                return Err(SendError::Uncertain(
                    "the connection to the Gmail API broke after the message was sent".into(),
                ));
            }
        };
        let status = response.status();
        if status.is_success() {
            let report = SendReport::all_accepted(envelope);
            return Ok(match sent_id(response).await {
                Some(id) => report.with_provider_message_id(id),
                None => report,
            });
        }
        let wait = retry_after(response.headers());
        let reasons = reasons(response).await;
        Err(refusal(status, wait, &reasons))
    }

    fn saves_to_sent(&self) -> bool {
        true
    }
}

/// The Gmail message id (`id`) of a sent message, when the answer holds a printable one.
async fn sent_id(mut response: reqwest::Response) -> Option<String> {
    let mut body = Vec::new();
    while let Ok(Some(chunk)) = response.chunk().await {
        if body.len() + chunk.len() > MAX_ERROR_BODY {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    let value: serde_json::Value = serde_json::from_slice(&body).ok()?;
    let id = value.get("id")?.as_str()?;
    (!id.is_empty() && id.len() <= 256 && id.bytes().all(|b| b.is_ascii_alphanumeric()))
        .then(|| id.to_owned())
}

/// The machine-readable reasons in a Google error body (`error.errors[].reason`,
/// `error.details[].reason`, `error.status`). Messages are never read: they can echo user data.
async fn reasons(mut response: reqwest::Response) -> Vec<String> {
    let mut body = Vec::new();
    while let Ok(Some(chunk)) = response.chunk().await {
        if body.len() + chunk.len() > MAX_ERROR_BODY {
            break;
        }
        body.extend_from_slice(&chunk);
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return Vec::new();
    };
    let error = &value["error"];
    let mut out = Vec::new();
    for list in ["errors", "details"] {
        if let Some(items) = error[list].as_array() {
            out.extend(
                items
                    .iter()
                    .filter_map(|e| e["reason"].as_str().map(str::to_owned)),
            );
        }
    }
    if let Some(status) = error["status"].as_str() {
        out.push(status.to_owned());
    }
    out
}

/// A `Retry-After` given in seconds; an HTTP date is ignored.
fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let seconds: u64 = headers
        .get(RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()?;
    Some(Duration::from_secs(seconds))
}

fn refusal(status: StatusCode, retry_after: Option<Duration>, reasons: &[String]) -> SendError {
    let has = |names: &[&str]| reasons.iter().any(|r| names.contains(&r.as_str()));
    let said = format!("the Gmail API answered {}", status.as_u16());
    let rate = has(&[
        "rateLimitExceeded",
        "userRateLimitExceeded",
        "dailyLimitExceeded",
        "quotaExceeded",
        "RATE_LIMIT_EXCEEDED",
        "RESOURCE_EXHAUSTED",
    ]);
    let permanent = |code: u16| SendError::Refused {
        permanent: true,
        code,
        text: match reasons.first() {
            Some(reason) => format!("{said} ({reason})"),
            None => said.clone(),
        },
    };
    match status {
        StatusCode::PAYLOAD_TOO_LARGE => SendError::TooLarge { limit: None },
        StatusCode::TOO_MANY_REQUESTS => SendError::Throttled { retry_after },
        StatusCode::FORBIDDEN if rate => SendError::Throttled { retry_after },
        StatusCode::UNAUTHORIZED => SendError::Auth(said),
        StatusCode::FORBIDDEN
            if has(&[
                "insufficientPermissions",
                "ACCESS_TOKEN_SCOPE_INSUFFICIENT",
                "PERMISSION_DENIED",
            ]) =>
        {
            SendError::Auth(said)
        }
        StatusCode::FORBIDDEN => permanent(554),
        StatusCode::NOT_FOUND => invalid("the Gmail API has no such user"),
        StatusCode::SERVICE_UNAVAILABLE if rate => SendError::Throttled { retry_after },
        s if s.is_server_error() => SendError::Uncertain(said),
        StatusCode::BAD_REQUEST if has(&["invalidArgument", "INVALID_ARGUMENT"]) => permanent(550),
        _ => permanent(554),
    }
}
