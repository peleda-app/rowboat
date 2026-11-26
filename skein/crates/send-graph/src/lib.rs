//! The [`Sender`] contract on Microsoft 365 and Outlook.com mailboxes through Microsoft Graph
//! `sendMail`.
//!
//! The message goes to `POST /me/sendMail` (or `/users/{id}/sendMail`) as base64 MIME. Graph
//! keeps the sent copy in Sent Items and takes the recipients from the To, Cc and Bcc fields, so
//! envelope recipients the fields do not name are added in one `Bcc` field to the bytes handed to
//! Graph, and only there; a header recipient that is not in the envelope is refused before
//! anything is sent. Graph picks the return path and refuses one recipient by refusing the whole
//! message.
//!
//! The token goes only to the origin of the configured API address, and redirects are never
//! followed.

mod bcc;
#[cfg(test)]
mod tests;

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use reqwest::StatusCode;
use reqwest::header::{CONTENT_TYPE, HeaderMap, RETRY_AFTER};
use serde::{Deserialize, Serialize};
use skein_core::{Credentials, TlsRoots};
use skein_send::{Envelope, Limits, SendError, SendReport, Sender};
use skein_throttle::{Permit, Throttle};
use url::{Host, Url};

/// Where Microsoft Graph answers for accounts in the global cloud.
pub const GRAPH_URL: &str = "https://graph.microsoft.com/v1.0";

/// The largest message `sendMail` takes: Graph refuses requests over 4 MiB, and base64 makes
/// 3 MiB of MIME into 4 MiB.
pub const MAX_SIZE: u64 = 3 * 1024 * 1024;

const MAX_ERROR_BODY: usize = 64 * 1024;

/// Where the mailbox is. The access token is passed separately and never stored here. Reads the
/// same JSON as the Graph mail provider's settings.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphSendSettings {
    /// The Graph endpoint with its version; [`GRAPH_URL`] when missing. Only `https`, or plain
    /// `http` to a loopback address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_url: Option<String>,
    /// The mailbox to send from: missing for the token's own (`/me`), else a user id or user
    /// principal name (`/users/{id}`), for app-only tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// The largest message to hand over, in bytes, counting an added `Bcc` field; capped at and
    /// defaulting to [`MAX_SIZE`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_size: Option<u64>,
    /// Certificates trusted besides the built-in roots. They never turn verification off.
    #[serde(skip)]
    pub roots: TlsRoots,
}

impl fmt::Debug for GraphSendSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GraphSendSettings")
            .field("api_url", &self.api_url)
            .field("user", &self.user.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

impl GraphSendSettings {
    /// Reads settings from JSON; other keys are ignored. `Invalid` when they do not parse.
    pub fn from_json(value: &serde_json::Value) -> Result<Self, SendError> {
        serde_json::from_value(value.clone()).map_err(|e| SendError::Invalid(e.to_string()))
    }
}

/// A [`Sender`] over Microsoft Graph `sendMail`. Graph keeps the sent copy itself.
pub struct GraphSender {
    client: reqwest::Client,
    send_url: Url,
    check_url: Url,
    max_size: u64,
    token: String,
    roots: TlsRoots,
    throttle: Option<Throttle>,
}

impl fmt::Debug for GraphSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GraphSender")
            .field("send_url", &self.send_url.as_str())
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

fn invalid(text: &str) -> SendError {
    SendError::Invalid(text.into())
}

impl GraphSender {
    /// A sender for `settings` with an access token holding `Mail.Send`. `Invalid` before
    /// anything is sent for a password, an empty token, an address that is not `https` (or
    /// `http` to loopback) or holds credentials, a malformed user, a zero size limit or an extra
    /// root that is not a certificate.
    pub fn new(settings: GraphSendSettings, credentials: Credentials) -> Result<Self, SendError> {
        let Credentials::AccessToken { token } = credentials else {
            return Err(invalid(
                "Microsoft Graph signs in with an access token, not a password",
            ));
        };
        if token.trim().is_empty() {
            return Err(invalid("the access token is empty"));
        }
        let raw = settings.api_url.as_deref().unwrap_or(GRAPH_URL).trim();
        let mut base =
            Url::parse(raw).map_err(|_| invalid("the Graph address is not a web address"))?;
        if !allowed(&base) || base.cannot_be_a_base() {
            return Err(invalid(
                "the Graph address must use https (plain http only to loopback)",
            ));
        }
        if !base.username().is_empty() || base.password().is_some() {
            return Err(invalid("the Graph address must not hold credentials"));
        }
        base.set_query(None);
        base.set_fragment(None);
        let mailbox: Vec<&str> = match settings.user.as_deref().map(str::trim) {
            None | Some("me") => vec!["me"],
            Some(id)
                if !id.is_empty() && !id.chars().any(|c| c.is_whitespace() || c.is_control()) =>
            {
                vec!["users", id]
            }
            Some(_) => return Err(invalid("the mailbox is not a user id")),
        };
        let max_size = settings.max_size.unwrap_or(MAX_SIZE).min(MAX_SIZE);
        if max_size == 0 {
            return Err(invalid("the size limit is zero"));
        }
        let endpoint = |tail: &[&str]| {
            let mut url = base.clone();
            url.path_segments_mut()
                .map_err(|_| invalid("the Graph address cannot take a path"))?
                .pop_if_empty()
                .extend(mailbox.iter().chain(tail));
            Ok::<_, SendError>(url)
        };
        let send_url = endpoint(&["sendMail"])?;
        let mut check_url = endpoint(&["mailFolders", "sentitems"])?;
        check_url.set_query(Some("$select=id"));
        let client = client(Duration::from_secs(120), &settings.roots)?;
        Ok(Self {
            client,
            send_url,
            check_url,
            max_size,
            token,
            roots: settings.roots,
            throttle: None,
        })
    }

    /// Gives every request `timeout` instead of two minutes. A send without an answer by then is
    /// [`SendError::Uncertain`].
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, SendError> {
        self.client = client(timeout, &self.roots)?;
        Ok(self)
    }

    /// Sends every request to Graph through `throttle`: each waits for a slot and for any pause
    /// in effect, and a `429` or `503` with `Retry-After` pauses it for every holder, such as the
    /// mail and calendar providers of the same mailbox. The error returned is unchanged. Without
    /// a throttle requests go out at once.
    pub fn with_throttle(mut self, throttle: Throttle) -> Self {
        self.throttle = Some(throttle);
        self
    }

    async fn permit(&self) -> Option<Permit> {
        match &self.throttle {
            Some(throttle) => Some(throttle.acquire().await),
            None => None,
        }
    }

    fn pause_on_busy(&self, status: StatusCode, wait: Option<Duration>) {
        if let (Some(throttle), Some(wait)) = (&self.throttle, wait)
            && matches!(
                status,
                StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
            )
        {
            throttle.pause(wait);
        }
    }

    fn limits(&self) -> Limits {
        Limits {
            max_size: Some(self.max_size),
            smtputf8: false,
            dsn: false,
        }
    }
}

#[async_trait]
impl Sender for GraphSender {
    async fn check(&self) -> Result<Limits, SendError> {
        let _permit = self.permit().await;
        let response = self
            .client
            .get(self.check_url.clone())
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|_| SendError::Unavailable("Microsoft Graph could not be reached".into()))?;
        let status = response.status();
        if status.is_success() {
            return Ok(self.limits());
        }
        let wait = retry_after(response.headers());
        self.pause_on_busy(status, wait);
        let (code, _) = graph_error(response).await;
        Err(match status {
            StatusCode::TOO_MANY_REQUESTS => SendError::Throttled { retry_after: wait },
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => SendError::Auth(format!(
                "Microsoft Graph refused the sign-in for this mailbox ({status}, {code})"
            )),
            StatusCode::NOT_FOUND => invalid("Microsoft Graph has no such mailbox"),
            s if s == StatusCode::TOO_MANY_REQUESTS || s.is_server_error() => {
                SendError::Unavailable(format!("Microsoft Graph answered {status}"))
            }
            _ => SendError::Invalid(format!("Microsoft Graph answered {status} ({code})")),
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
        let body = BASE64.encode(&outgoing);
        let _permit = self.permit().await;
        let response = match self
            .client
            .post(self.send_url.clone())
            .bearer_auth(&self.token)
            .header(CONTENT_TYPE, "text/plain")
            .body(body)
            .send()
            .await
        {
            Ok(response) => response,
            Err(e) if e.is_connect() || e.is_builder() => {
                return Err(SendError::Unavailable(
                    "Microsoft Graph could not be reached".into(),
                ));
            }
            Err(_) => {
                return Err(SendError::Uncertain(
                    "the connection to Microsoft Graph broke after the message was sent".into(),
                ));
            }
        };
        let status = response.status();
        if status.is_success() {
            return Ok(SendReport::all_accepted(envelope));
        }
        let retry_after = retry_after(response.headers());
        self.pause_on_busy(status, retry_after);
        let (code, text) = graph_error(response).await;
        Err(refusal(status, retry_after, &code, &text))
    }

    fn saves_to_sent(&self) -> bool {
        true
    }
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

async fn graph_error(mut response: reqwest::Response) -> (String, String) {
    let mut body = Vec::new();
    while let Ok(Some(chunk)) = response.chunk().await {
        if body.len() + chunk.len() > MAX_ERROR_BODY {
            break;
        }
        body.extend_from_slice(&chunk);
    }
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    let field = |name: &str| {
        value
            .pointer(&format!("/error/{name}"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    (field("code"), field("message"))
}

fn refusal(status: StatusCode, retry_after: Option<Duration>, code: &str, text: &str) -> SendError {
    let said = if code.is_empty() {
        format!("{status}")
    } else if text.is_empty() {
        code.to_owned()
    } else {
        format!("{code}: {text}")
    };
    let permanent = |smtp: u16| SendError::Refused {
        permanent: true,
        code: smtp,
        text: said.clone(),
    };
    if status == StatusCode::PAYLOAD_TOO_LARGE || code == "ErrorMessageSizeExceeded" {
        return SendError::TooLarge { limit: None };
    }
    match status {
        StatusCode::UNAUTHORIZED => SendError::Auth(format!(
            "Microsoft Graph refused the access token ({status})"
        )),
        StatusCode::FORBIDDEN => match code {
            "ErrorSendAsDenied" => permanent(550),
            "ErrorMessageSubmissionBlocked" => permanent(554),
            _ => SendError::Auth(format!(
                "the sign-in may not send from this mailbox ({status})"
            )),
        },
        StatusCode::NOT_FOUND => invalid("Microsoft Graph has no such mailbox"),
        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE => {
            SendError::Throttled { retry_after }
        }
        s if s.is_server_error() => SendError::Uncertain(format!(
            "Microsoft Graph answered {status} after it had the message"
        )),
        _ if code == "ErrorInvalidRecipients" => permanent(550),
        _ => permanent(554),
    }
}
