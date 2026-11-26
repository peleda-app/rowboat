//! The [`Sender`] contract over SMTP submission (RFC 6409).
//!
//! [`SmtpSender`] hands prebuilt messages to a submission server with implicit TLS (port 465)
//! or `STARTTLS` (port 587), signing in with `AUTH PLAIN`, `LOGIN` or `XOAUTH2`. Plain text is
//! allowed only to loopback hosts, so a password or token never crosses a network in the clear.
//! Delivery status notifications (RFC 3461) are asked for when the envelope wants them and the
//! server offers `DSN`; `SIZE`, `8BITMIME` and `SMTPUTF8` are used when offered.

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use skein_core::{Credentials, TlsRoots};
use skein_send::{Envelope, Limits, SendError, SendReport, Sender};
use tokio_rustls::rustls::ClientConfig;

#[doc(hidden)]
pub mod fuzzing;
mod session;

/// How the connection is protected.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Security {
    /// TLS from the first byte, usually port 465.
    #[default]
    Tls,
    /// A plain connection upgraded with `STARTTLS` before signing in, usually port 587. A server
    /// that does not offer it is refused; the client never falls back to plain text.
    Starttls,
    /// No encryption. Accepted only for loopback hosts, for tests and local relays.
    Plain,
}

/// Where the submission server is. Credentials are passed separately and never stored here.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmtpSettings {
    /// Server host name or IP address; also the name its certificate must carry.
    pub host: String,
    /// Port; 465 for `tls`, 587 otherwise when omitted.
    #[serde(default)]
    pub port: Option<u16>,
    /// Connection security; TLS when omitted.
    #[serde(default)]
    pub security: Security,
    /// The user name to sign in with; no sign-in when omitted.
    #[serde(default)]
    pub username: Option<String>,
    /// The name given in `EHLO`; `localhost` when omitted.
    #[serde(default)]
    pub helo: Option<String>,
    /// Certificates trusted besides the built-in web roots. They never turn verification off.
    #[serde(skip)]
    pub roots: TlsRoots,
}

impl fmt::Debug for SmtpSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmtpSettings")
            .field("host", &self.host)
            .field("port", &self.port())
            .field("security", &self.security)
            .field("username", &self.username.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

impl SmtpSettings {
    /// Settings for `host` with TLS on port 465 and no sign-in.
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: None,
            security: Security::Tls,
            username: None,
            helo: None,
            roots: TlsRoots::default(),
        }
    }

    /// Reads settings from JSON; other keys are ignored. `Invalid` when they do not parse.
    pub fn from_json(value: &serde_json::Value) -> Result<Self, SendError> {
        serde_json::from_value(value.clone()).map_err(|e| SendError::Invalid(e.to_string()))
    }

    /// The port to connect to: the configured one, else the default of `security`.
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(match self.security {
            Security::Tls => 465,
            Security::Starttls | Security::Plain => 587,
        })
    }
}

/// What the client signs in with.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Secret {
    Password(String),
    OAuthToken(String),
}

pub(crate) struct Config {
    pub host: String,
    pub port: u16,
    pub security: Security,
    pub login: Option<(String, Secret)>,
    pub helo: String,
    pub timeout: Duration,
    pub data_timeout: Duration,
}

/// An SMTP submission client. Every call opens its own connection and closes it afterwards, so
/// calls never share state. The sent copy is not kept: callers append one themselves.
pub struct SmtpSender {
    config: Config,
    tls: Arc<ClientConfig>,
}

impl fmt::Debug for SmtpSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmtpSender")
            .field("host", &self.config.host)
            .field("port", &self.config.port)
            .field("credentials", &"<redacted>")
            .finish()
    }
}

impl SmtpSender {
    /// A client for `settings` signing in with `credentials` when a user name is set: a password
    /// with `AUTH PLAIN` (or `LOGIN` when `PLAIN` is not offered), an access token with
    /// `XOAUTH2`. `Insecure` before anything is sent for plain text to a host that is not
    /// loopback; `Invalid` for a user name without credentials, an empty host, an `EHLO` name that is not a
    /// name, or an extra root that is not a certificate. Credentials without a user name are
    /// not used.
    pub fn new(
        settings: SmtpSettings,
        credentials: Option<Credentials>,
    ) -> Result<Self, SendError> {
        let host = settings.host.trim().to_owned();
        if host.is_empty() {
            return Err(SendError::Invalid("the host is empty".into()));
        }
        let helo = settings.helo.clone().unwrap_or_else(|| "localhost".into());
        if helo.is_empty() || helo.contains(|c: char| c.is_whitespace() || c.is_control()) {
            return Err(SendError::Invalid("the EHLO name is not a name".into()));
        }
        if settings.security == Security::Plain && !is_loopback(&host) {
            return Err(SendError::Insecure(
                "a connection without TLS is allowed only to loopback hosts".into(),
            ));
        }
        let login = match settings.username.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(user) if user.contains(|c: char| c.is_control()) => {
                return Err(SendError::Invalid(
                    "the user name holds control characters".into(),
                ));
            }
            Some(user) => {
                let secret = match credentials {
                    Some(Credentials::Password { secret }) => Secret::Password(secret),
                    Some(Credentials::AccessToken { token }) => Secret::OAuthToken(token),
                    Some(Credentials::AccessKey { .. }) => {
                        return Err(SendError::Invalid(
                            "SMTP signs in with a password or a token, not an access key".into(),
                        ));
                    }
                    None => {
                        return Err(SendError::Invalid(
                            "a user name needs a password or a token".into(),
                        ));
                    }
                };
                Some((user.to_owned(), secret))
            }
        };
        Ok(Self {
            tls: Arc::new(tls_config(&settings.roots)?),
            config: Config {
                port: settings.port(),
                security: settings.security,
                host,
                login,
                helo,
                timeout: Duration::from_secs(60),
                data_timeout: Duration::from_secs(600),
            },
        })
    }

    /// Gives connecting, the TLS handshake and every command reply `command`, and the reply to
    /// the whole message `data` (one and ten minutes by default). Silence after the whole
    /// message is [`SendError::Uncertain`].
    pub fn with_timeouts(mut self, command: Duration, data: Duration) -> Self {
        self.config.timeout = command;
        self.config.data_timeout = data;
        self
    }
}

#[async_trait]
impl Sender for SmtpSender {
    async fn check(&self) -> Result<Limits, SendError> {
        let session = session::Session::open(&self.config, self.tls.clone()).await?;
        let limits = session.limits();
        session.quit().await;
        Ok(limits)
    }

    async fn send(&self, envelope: &Envelope, message: &[u8]) -> Result<SendReport, SendError> {
        envelope.validate(message)?;
        let mut session = session::Session::open(&self.config, self.tls.clone()).await?;
        let result = session.send(envelope, message).await;
        if !matches!(result, Err(SendError::Uncertain(_))) {
            session.quit().await;
        }
        result
    }

    fn saves_to_sent(&self) -> bool {
        false
    }
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn tls_config(extra: &TlsRoots) -> Result<ClientConfig, SendError> {
    let mut roots = tokio_rustls::rustls::RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
    );
    for der in extra.iter() {
        roots
            .add(der.to_vec().into())
            .map_err(|e| SendError::Invalid(format!("an extra trusted certificate: {e}")))?;
    }
    Ok(ClientConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("aws-lc-rs supports the default TLS versions")
    .with_root_certificates(roots)
    .with_no_client_auth())
}

/// What a submission server said about itself before sign-in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpProbe {
    /// The `AUTH` mechanisms offered after TLS, upper case, at most 32.
    pub auth: Vec<String>,
    /// A password can sign in: `AUTH PLAIN` or `AUTH LOGIN` is offered after TLS.
    pub password_sign_in: bool,
    /// `AUTH XOAUTH2` or `AUTH OAUTHBEARER` is offered after TLS.
    pub oauth: bool,
    /// The largest message the server takes, when it said so.
    pub max_size: Option<u64>,
}

/// Checks a submission server without signing in: connects, verifies TLS against the web roots
/// and `roots` (after `STARTTLS` for [`Security::Starttls`]), reads the greeting, says `EHLO`
/// and `QUIT`. Nothing else is sent, never a user name, a secret or a message.
///
/// The whole probe ends within `timeout` ([`SendError::Timeout`]); replies keep the client's
/// caps (lines of 4 KiB, 128 lines a reply). [`Security::Plain`] and a server without
/// `STARTTLS` are [`SendError::Insecure`]; a failed handshake or certificate is
/// [`SendError::Tls`]; a greeting other than `220` is [`SendError::Unavailable`].
pub async fn probe(
    host: &str,
    port: u16,
    security: Security,
    roots: &TlsRoots,
    timeout: Duration,
) -> Result<SmtpProbe, SendError> {
    if security == Security::Plain {
        return Err(SendError::Insecure(
            "a probe never runs in plain text".into(),
        ));
    }
    let host = host.trim();
    if host.is_empty() || port == 0 {
        return Err(SendError::Invalid("the host or port is empty".into()));
    }
    let config = Config {
        host: host.to_owned(),
        port,
        security,
        login: None,
        helo: "localhost".into(),
        timeout,
        data_timeout: timeout,
    };
    let tls = Arc::new(tls_config(roots)?);
    tokio::time::timeout(timeout, async {
        let session = session::Session::open(&config, tls).await?;
        let probe = session.probe();
        session.quit().await;
        Ok(probe)
    })
    .await
    .map_err(|_| SendError::Timeout("the server did not answer the probe in time".into()))?
}

#[cfg(test)]
mod tests;
