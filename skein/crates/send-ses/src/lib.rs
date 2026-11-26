//! The [`Sender`] contract on Amazon SES through the v2 `SendEmail` API.
//!
//! The message goes to `POST /v2/email/outbound-emails` as `Content.Raw`, byte for byte, with
//! every envelope recipient in `Destination`, so Bcc recipients reach SES without a `Bcc` field
//! in the bytes. A non-empty return path becomes `FromEmailAddress`, which SES uses for bounces
//! and complaints. SES refuses one recipient by refusing the whole message and keeps no copy in a
//! Sent mailbox, so the caller saves one through the account's mail provider.
//!
//! SES replaces the message's `Message-ID` with `<{MessageId}@{domain}>`, where `MessageId` is
//! what `SendEmail` answers and the domain is `email.amazonses.com` in `us-east-1` and
//! `{region}.amazonses.com` elsewhere. A successful send reports the `MessageId` and, when the
//! domain is known, the delivered `Message-ID`, so the caller can save a sent copy that
//! recipients' replies thread with.
//!
//! Requests are signed with AWS Signature Version 4 by this crate. The key goes only to the
//! configured endpoint, and redirects are never followed.

mod error;
mod sigv4;
#[cfg(test)]
mod tests;

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HOST};
use serde::{Deserialize, Serialize};
use skein_core::{Credentials, TlsRoots};
use skein_send::{Envelope, Limits, SendError, SendReport, Sender};
use url::{Host, Url};

use crate::error::{Failure, read_failure};
use crate::sigv4::{Key, Request};

/// The largest raw message handed over, in bytes. SES v2 takes 40 MB per request after base64,
/// and base64 makes 30,000,000 bytes into 40,000,000.
pub const MAX_SIZE: u64 = 30_000_000;

/// The most recipients SES takes for one message.
pub const MAX_RECIPIENTS: usize = 50;

const SERVICE: &str = "ses";
const SEND_PATH: &str = "/v2/email/outbound-emails";
const ACCOUNT_PATH: &str = "/v2/email/account";
const MAX_BODY: usize = 64 * 1024;

/// Where and how to send through SES. The access key is passed separately and never stored here.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SesSettings {
    /// The AWS region, such as `eu-west-1`: lowercase letters, digits and dashes.
    pub region: String,
    /// The API origin instead of `https://email.{region}.amazonaws.com`, for compatible services
    /// and tests. Only `https`, or plain `http` to a loopback address; no path, query or
    /// credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// The configuration set every message is sent with (`ConfigurationSetName`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration_set: Option<String>,
    /// The ARN of the sending identity when another AWS account authorized this one to send
    /// from it (`FromEmailAddressIdentityArn`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_identity_arn: Option<String>,
    /// The domain SES puts after the `MessageId` in the `Message-ID` it gives every message. On
    /// AWS's own endpoints it defaults to the region's (`email.amazonses.com` for `us-east-1`,
    /// `{region}.amazonses.com` elsewhere); with a custom endpoint and no domain the delivered
    /// `Message-ID` is not reported. A hostname.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id_domain: Option<String>,
    /// The largest raw message to hand over, in bytes; capped at and defaulting to [`MAX_SIZE`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_size: Option<u64>,
    /// Certificates trusted besides the built-in roots. They never turn verification off.
    #[serde(skip)]
    pub roots: TlsRoots,
}

impl fmt::Debug for SesSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SesSettings")
            .field("region", &self.region)
            .field("endpoint", &self.endpoint)
            .field("configuration_set", &self.configuration_set)
            .field("message_id_domain", &self.message_id_domain)
            .finish_non_exhaustive()
    }
}

impl SesSettings {
    /// Reads settings from JSON; other keys are ignored. `Invalid` when they do not parse.
    pub fn from_json(value: &serde_json::Value) -> Result<Self, SendError> {
        serde_json::from_value(value.clone()).map_err(|e| SendError::Invalid(e.to_string()))
    }
}

/// A [`Sender`] over the Amazon SES v2 API. SES keeps no sent copy.
pub struct SesSender {
    client: reqwest::Client,
    origin: Url,
    host: String,
    region: String,
    key: Key,
    configuration_set: Option<String>,
    from_identity_arn: Option<String>,
    message_id_domain: Option<String>,
    max_size: u64,
    roots: TlsRoots,
}

impl fmt::Debug for SesSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SesSender")
            .field("origin", &self.origin.as_str())
            .field("region", &self.region)
            .field("key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

fn invalid(text: &str) -> SendError {
    SendError::Invalid(text.into())
}

fn loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
        Some(Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
        Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

fn valid_region(region: &str) -> bool {
    (1..=32).contains(&region.len())
        && region.starts_with(|c: char| c.is_ascii_lowercase())
        && region.ends_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && region
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Whether `name` is a hostname: dot-separated labels of letters, digits and inner dashes, each
/// at most 63 characters, at most 253 in all.
pub fn valid_hostname(name: &str) -> bool {
    (1..=253).contains(&name.len())
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// The domain SES gives `Message-ID`s in `region` on AWS's own endpoints.
pub fn region_message_id_domain(region: &str) -> String {
    match region {
        "us-east-1" => "email.amazonses.com".to_owned(),
        _ => format!("{region}.amazonses.com"),
    }
}

fn aws_endpoint(url: &Url) -> bool {
    url.scheme() == "https"
        && url
            .host_str()
            .is_some_and(|host| host.to_ascii_lowercase().ends_with(".amazonaws.com"))
}

fn printable(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.bytes().all(|b| b.is_ascii_graphic())
}

fn origin(settings: &SesSettings) -> Result<Url, SendError> {
    let raw = match settings.endpoint.as_deref().map(str::trim) {
        Some(endpoint) => endpoint.to_owned(),
        None => format!("https://email.{}.amazonaws.com", settings.region),
    };
    let url = Url::parse(&raw).map_err(|_| invalid("the SES endpoint is not a web address"))?;
    let allowed = match url.scheme() {
        "https" => true,
        "http" => loopback(&url),
        _ => false,
    };
    if !allowed || url.host().is_none() {
        return Err(invalid(
            "the SES endpoint must use https (plain http only to loopback)",
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid("the SES endpoint must not hold credentials"));
    }
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err(invalid(
            "the SES endpoint is an origin without a path or query",
        ));
    }
    Ok(url)
}

fn key(credentials: Credentials) -> Result<Key, SendError> {
    let Credentials::AccessKey {
        id,
        secret,
        session_token,
    } = credentials
    else {
        return Err(invalid("Amazon SES signs requests with an access key"));
    };
    if id.is_empty() || id.len() > 128 || !id.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(invalid("the access key id is not an access key id"));
    }
    if !printable(&secret, 1024) {
        return Err(invalid("the secret access key is empty or not printable"));
    }
    if session_token
        .as_deref()
        .is_some_and(|t| !printable(t, 8192))
    {
        return Err(invalid("the session token is empty or not printable"));
    }
    Ok(Key {
        id,
        secret,
        session_token,
    })
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

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Destination<'a> {
    to_addresses: &'a [String],
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Raw {
    data: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Content {
    raw: Raw,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct SendEmail<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    from_email_address: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    from_email_address_identity_arn: Option<&'a str>,
    destination: Destination<'a>,
    content: Content,
    #[serde(skip_serializing_if = "Option::is_none")]
    configuration_set_name: Option<&'a str>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Sent {
    #[serde(default)]
    message_id: Option<String>,
}

fn provider_id(id: &str) -> bool {
    (1..=256).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Account {
    #[serde(default)]
    sending_enabled: Option<bool>,
    #[serde(default)]
    enforcement_status: Option<String>,
}

enum Exchange {
    Answer(reqwest::Response),
    NotSent(SendError),
    Broken,
}

impl SesSender {
    /// A sender for `settings` with an access key allowed `ses:SendRawEmail` (or
    /// `ses:SendEmail`) on the sending identity. `Invalid` before anything is sent for
    /// credentials that are not an access key or are malformed, a region that is not a region
    /// name, an endpoint that is not `https` (or `http` to loopback) or has a path, query or
    /// credentials, an empty configuration set or identity ARN, a `message_id_domain` that is not
    /// a hostname, a zero size limit or an extra root that is not a certificate.
    pub fn new(settings: SesSettings, credentials: Credentials) -> Result<Self, SendError> {
        let region = settings.region.trim().to_owned();
        if !valid_region(&region) {
            return Err(invalid("the region is not an AWS region name"));
        }
        let settings = SesSettings {
            region: region.clone(),
            ..settings
        };
        let origin = origin(&settings)?;
        let host = match origin.port() {
            Some(port) => format!("{}:{port}", origin.host_str().unwrap_or_default()),
            None => origin.host_str().unwrap_or_default().to_owned(),
        };
        let key = key(credentials)?;
        let name = |value: Option<String>, what: &str| match value.map(|v| v.trim().to_owned()) {
            Some(v) if !printable(&v, 2048) => Err(SendError::Invalid(format!(
                "the {what} is empty or not printable"
            ))),
            other => Ok(other),
        };
        let configuration_set = name(settings.configuration_set, "configuration set")?;
        let from_identity_arn = name(settings.from_identity_arn, "identity ARN")?;
        let message_id_domain = match settings.message_id_domain.as_deref().map(str::trim) {
            Some(domain) if !valid_hostname(domain) => {
                return Err(invalid("the Message-ID domain is not a hostname"));
            }
            Some(domain) => Some(domain.to_ascii_lowercase()),
            None if aws_endpoint(&origin) => Some(region_message_id_domain(&region)),
            None => None,
        };
        let max_size = settings.max_size.unwrap_or(MAX_SIZE).min(MAX_SIZE);
        if max_size == 0 {
            return Err(invalid("the size limit is zero"));
        }
        Ok(Self {
            client: client(Duration::from_secs(120), &settings.roots)?,
            origin,
            host,
            region,
            key,
            configuration_set,
            from_identity_arn,
            message_id_domain,
            max_size,
            roots: settings.roots,
        })
    }

    /// Gives every request `timeout` instead of two minutes. A send without an answer by then is
    /// [`SendError::Uncertain`].
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, SendError> {
        self.client = client(timeout, &self.roots)?;
        Ok(self)
    }

    /// What a successful `SendEmail` answer says about the message: the `MessageId` and, when
    /// the domain is known, the `Message-ID` recipients get.
    fn report(&self, envelope: &Envelope, body: &[u8]) -> SendReport {
        let report = SendReport::all_accepted(envelope);
        let Some(id) = serde_json::from_slice::<Sent>(body)
            .ok()
            .and_then(|sent| sent.message_id)
            .filter(|id| provider_id(id))
        else {
            return report;
        };
        let report = match &self.message_id_domain {
            Some(domain) => report.with_message_id(format!("<{id}@{domain}>")),
            None => report,
        };
        report.with_provider_message_id(id)
    }

    fn limits(&self) -> Limits {
        Limits {
            max_size: Some(self.max_size),
            smtputf8: false,
            dsn: false,
        }
    }

    async fn request(&self, method: reqwest::Method, path: &str, body: Vec<u8>) -> Exchange {
        let amz_date = sigv4::amz_date_now();
        let mut headers = vec![
            ("host".to_owned(), self.host.clone()),
            ("x-amz-date".to_owned(), amz_date.clone()),
        ];
        if !body.is_empty() {
            headers.push(("content-type".to_owned(), "application/json".to_owned()));
        }
        if let Some(token) = &self.key.session_token {
            headers.push(("x-amz-security-token".to_owned(), token.clone()));
        }
        let authorization = sigv4::authorization(
            &self.key,
            &self.region,
            SERVICE,
            &amz_date,
            &Request {
                method: method.as_str(),
                path,
                query: "",
                headers: &headers,
                payload: &body,
            },
        );
        let mut url = self.origin.clone();
        url.set_path(path);
        let mut builder = self
            .client
            .request(method, url)
            .header(AUTHORIZATION, authorization);
        for (name, value) in &headers {
            builder = match name.as_str() {
                "host" => builder.header(HOST, value),
                "content-type" => builder.header(CONTENT_TYPE, value),
                _ => builder.header(name, value),
            };
        }
        if !body.is_empty() {
            builder = builder.body(body);
        }
        match builder.send().await {
            Ok(response) => Exchange::Answer(response),
            Err(e) if e.is_connect() => Exchange::NotSent(SendError::Unavailable(
                "Amazon SES could not be reached".into(),
            )),
            Err(e) if e.is_builder() => Exchange::NotSent(invalid("the request cannot be built")),
            Err(_) => Exchange::Broken,
        }
    }
}

async fn read_body(mut response: reqwest::Response) -> Vec<u8> {
    let mut body = Vec::new();
    while let Ok(Some(chunk)) = response.chunk().await {
        if body.len() + chunk.len() > MAX_BODY {
            break;
        }
        body.extend_from_slice(&chunk);
    }
    body
}

fn address_ok(address: &str) -> bool {
    address.is_ascii()
}

#[async_trait]
impl Sender for SesSender {
    async fn check(&self) -> Result<Limits, SendError> {
        let response = match self
            .request(reqwest::Method::GET, ACCOUNT_PATH, Vec::new())
            .await
        {
            Exchange::Answer(response) => response,
            Exchange::NotSent(e) => return Err(e),
            Exchange::Broken => {
                return Err(SendError::Unavailable("Amazon SES did not answer".into()));
            }
        };
        if !response.status().is_success() {
            let failure = read_failure(response).await;
            return Err(match failure.to_error() {
                SendError::Uncertain(_) => {
                    SendError::Unavailable(format!("Amazon SES answered {}", failure.status))
                }
                other => other,
            });
        }
        let account: Account = serde_json::from_slice(&read_body(response).await)
            .map_err(|_| SendError::Unavailable("Amazon SES answered something else".into()))?;
        if account.sending_enabled == Some(false) {
            return Err(invalid("sending is paused for this Amazon SES account"));
        }
        if account.enforcement_status.as_deref() == Some("SHUTDOWN") {
            return Err(invalid("this Amazon SES account is shut down"));
        }
        Ok(self.limits())
    }

    async fn send(&self, envelope: &Envelope, message: &[u8]) -> Result<SendReport, SendError> {
        envelope.validate(message)?;
        if envelope.recipients.len() > MAX_RECIPIENTS {
            return Err(SendError::Invalid(format!(
                "Amazon SES takes at most {MAX_RECIPIENTS} recipients"
            )));
        }
        if !address_ok(&envelope.mail_from) || !envelope.recipients.iter().all(|r| address_ok(r)) {
            return Err(invalid(
                "Amazon SES takes only ASCII addresses (punycode for domains)",
            ));
        }
        if message.len() as u64 > self.max_size {
            return Err(SendError::TooLarge {
                limit: Some(self.max_size),
            });
        }
        let request = SendEmail {
            from_email_address: Some(envelope.mail_from.as_str()).filter(|f| !f.is_empty()),
            from_email_address_identity_arn: self.from_identity_arn.as_deref(),
            destination: Destination {
                to_addresses: &envelope.recipients,
            },
            content: Content {
                raw: Raw {
                    data: BASE64.encode(message),
                },
            },
            configuration_set_name: self.configuration_set.as_deref(),
        };
        let body =
            serde_json::to_vec(&request).map_err(|_| invalid("the request cannot be built"))?;
        let response = match self.request(reqwest::Method::POST, SEND_PATH, body).await {
            Exchange::Answer(response) => response,
            Exchange::NotSent(e) => return Err(e),
            Exchange::Broken => {
                return Err(SendError::Uncertain(
                    "the connection to Amazon SES broke after the message was sent".into(),
                ));
            }
        };
        if response.status().is_success() {
            return Ok(self.report(envelope, &read_body(response).await));
        }
        let failure: Failure = read_failure(response).await;
        Err(failure.to_error())
    }

    fn saves_to_sent(&self) -> bool {
        false
    }
}
