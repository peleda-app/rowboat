//! The [`MailProvider`] contract on IMAP servers.
//!
//! [`ImapProvider`] signs in with `LOGIN` or `AUTHENTICATE XOAUTH2` over TLS or STARTTLS, turns
//! every mailbox into a change feed with an opaque cursor, returns the exact bytes of messages,
//! carries out writes and watches mailboxes with `IDLE` (and `NOTIFY` where the server has it).
//! Reading opens mailboxes with `EXAMINE` and fetches with `BODY.PEEK[]`, so it never sets
//! `\Seen` or changes anything else on the server.

mod cursor;
#[doc(hidden)]
pub mod fuzzing;
mod labels;
mod probe;
mod session;
mod stream;
mod utf7;
mod watch;
mod write;

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_imap::types::NameAttribute;
use async_trait::async_trait;
use futures::TryStreamExt;
use serde::{Deserialize, Serialize};
use skein_core::{Credentials, MailboxInfo, MailboxRole, TlsRoots};
use skein_mail::{MailError, MailProvider, MailSession, MailWatch};
use stream::ImapStream;

pub use probe::{
    ImapProbe, PROBE_BYTE_LIMIT, PROBE_CAPABILITIES, PROBE_LINE_COUNT, PROBE_LINE_LIMIT, probe,
};

type Session = async_imap::Session<ImapStream>;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
/// How long one `IDLE` lasts before it is renewed. RFC 2177 allows 29 minutes; NAT gateways and
/// firewalls often forget a silent connection sooner.
const IDLE_RENEW: Duration = Duration::from_secs(10 * 60);
/// Connections one watch opens at most when the server has no `NOTIFY`, one per mailbox: servers
/// limit connections per user (Dovecot 10, Gmail 15) and sessions need theirs.
pub const MAX_WATCH_CONNECTIONS: usize = 3;

/// How the connection is protected.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Security {
    /// TLS from the first byte, usually port 993.
    #[default]
    Tls,
    /// A plain connection upgraded with `STARTTLS`, usually port 143. A server that does not
    /// offer it is refused; the provider never falls back to plain text.
    Starttls,
    /// No encryption. Accepted only for loopback hosts unless
    /// [`ImapSettings::allow_insecure_plain`] is set.
    Plain,
}

/// Where and as whom to sign in. Credentials are passed separately and never stored here.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImapSettings {
    /// Server host name or IP address.
    pub host: String,
    /// Port; 993 for `tls`, 143 otherwise when omitted.
    #[serde(default)]
    pub port: Option<u16>,
    /// Connection security; TLS when omitted.
    #[serde(default)]
    pub security: Security,
    /// User name, often the address.
    pub username: String,
    /// Certificates trusted besides the built-in web roots. They never turn verification off.
    #[serde(skip)]
    pub roots: TlsRoots,
    /// Allows [`Security::Plain`] to a host that is not loopback, which sends the password or
    /// token in clear text. Off by default.
    #[serde(default)]
    pub allow_insecure_plain: bool,
}

impl fmt::Debug for ImapSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImapSettings")
            .field("host", &self.host)
            .field("port", &self.port())
            .field("security", &self.security)
            .field("username", &"<redacted>")
            .field("roots", &self.roots)
            .field("allow_insecure_plain", &self.allow_insecure_plain)
            .finish()
    }
}

impl ImapSettings {
    /// Settings for `host` with TLS on port 993.
    pub fn new(host: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: None,
            security: Security::Tls,
            username: username.into(),
            roots: TlsRoots::default(),
            allow_insecure_plain: false,
        }
    }

    /// Reads settings from JSON; `Config` when they do not parse. `roots` stay empty.
    pub fn from_json(value: &serde_json::Value) -> Result<Self, MailError> {
        serde_json::from_value(value.clone()).map_err(|e| MailError::Config(e.to_string()))
    }

    /// The port to connect to: the configured one, else the default of `security`.
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(match self.security {
            Security::Tls => 993,
            Security::Starttls | Security::Plain => 143,
        })
    }

    fn plain_allowed(&self) -> bool {
        self.allow_insecure_plain || is_loopback(&self.host)
    }
}

/// `localhost`, `127.0.0.0/8` and `::1`.
fn is_loopback(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || bare.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// An IMAP account. Cloning is cheap; every [`connect`](MailProvider::connect) opens a
/// connection of its own.
#[derive(Clone)]
pub struct ImapProvider {
    settings: Arc<ImapSettings>,
    credentials: Arc<Credentials>,
    tls: Arc<tokio_rustls::rustls::ClientConfig>,
    timeout: Duration,
    idle_renew: Duration,
}

impl fmt::Debug for ImapProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImapProvider")
            .field("settings", &self.settings)
            .field("credentials", &self.credentials)
            .finish_non_exhaustive()
    }
}

impl ImapProvider {
    /// A provider for the server in `settings`. A password signs in with `LOGIN`, an access
    /// token with `AUTHENTICATE XOAUTH2`.
    ///
    /// `Config` when the settings cannot be used safely: plain text to a host that is not
    /// loopback without `allow_insecure_plain`, an empty host, or an extra root that is not a
    /// usable CA certificate. Nothing is sent before these checks pass.
    pub fn new(settings: ImapSettings, credentials: Credentials) -> Result<Self, MailError> {
        if settings.host.trim().is_empty() {
            return Err(MailError::Config("the host is empty".into()));
        }
        if settings.security == Security::Plain && !settings.plain_allowed() {
            return Err(MailError::Insecure(
                "plain text is allowed only to loopback hosts; use tls or starttls, or set allow_insecure_plain"
                    .into(),
            ));
        }
        if matches!(credentials, Credentials::AccessKey { .. }) {
            return Err(MailError::Config(
                "IMAP signs in with a password or a token, not an access key".into(),
            ));
        }
        let tls = Arc::new(tls_config(&settings.roots)?);
        Ok(Self {
            settings: Arc::new(settings),
            credentials: Arc::new(credentials),
            tls,
            timeout: COMMAND_TIMEOUT,
            idle_renew: IDLE_RENEW,
        })
    }

    /// Gives every command, the connection and the sign-in `timeout` instead of two minutes; a
    /// server that does not answer within it is a `Network` error.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Renews a watch's `IDLE` after `renew` instead of ten minutes.
    pub fn with_idle_renew(mut self, renew: Duration) -> Self {
        self.idle_renew = renew;
        self
    }
}

fn tls_config(extra: &TlsRoots) -> Result<tokio_rustls::rustls::ClientConfig, MailError> {
    let mut roots = tokio_rustls::rustls::RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
    );
    for der in extra.iter() {
        roots
            .add(der.to_vec().into())
            .map_err(|e| MailError::Config(format!("an extra trusted certificate: {e}")))?;
    }
    Ok(
        tokio_rustls::rustls::ClientConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("aws-lc-rs supports the default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth(),
    )
}

/// What the server advertised after sign-in.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Caps {
    pub gmail: bool,
    pub idle: bool,
    pub notify: bool,
    pub uidplus: bool,
    pub moves: bool,
}

pub(crate) struct SignedIn {
    pub session: Session,
    pub caps: Caps,
}

impl ImapProvider {
    pub(crate) async fn sign_in(&self) -> Result<SignedIn, MailError> {
        let started = std::time::Instant::now();
        let settings = &self.settings;
        let greeting_wait = self.timeout.min(stream::GREETING_WAIT);
        let (stream, greeting) = timed(
            self.timeout + greeting_wait,
            ImapStream::connect(
                &settings.host,
                settings.port(),
                settings.security,
                self.tls.clone(),
                greeting_wait,
            ),
        )
        .await??;
        if !stream.is_encrypted() && !settings.plain_allowed() {
            return Err(MailError::Insecure(
                "refusing to send credentials in plain text to a remote host".into(),
            ));
        }
        let mut client = async_imap::Client::new(stream);
        if greeting {
            let response = timed(self.timeout, client.read_response())
                .await?
                .map_err(|e| MailError::Network(e.to_string()))?
                .ok_or_else(|| MailError::Network("closed before the greeting".into()))?;
            if let async_imap::imap_proto::Response::Data {
                status: async_imap::imap_proto::Status::Bye,
                ..
            } = response.parsed()
            {
                return Err(MailError::Refused(
                    "the server refused the connection at the greeting".into(),
                ));
            }
        }
        let signed_in = match &*self.credentials {
            Credentials::Password { secret } => {
                timed(self.timeout, client.login(&settings.username, secret)).await?
            }
            Credentials::AccessToken { token } => {
                timed(
                    self.timeout,
                    client.authenticate(
                        "XOAUTH2",
                        Xoauth2 {
                            response: xoauth2(&settings.username, token),
                            sent: false,
                        },
                    ),
                )
                .await?
            }
            Credentials::AccessKey { .. } => {
                return Err(MailError::Config(
                    "IMAP signs in with a password or a token, not an access key".into(),
                ));
            }
        };
        let mut session = signed_in.map_err(|(error, _)| match error {
            async_imap::error::Error::No(text) | async_imap::error::Error::Bad(text) => {
                if throttle_hint(&text) {
                    MailError::Throttled { retry_after: None }
                } else {
                    MailError::Auth
                }
            }
            async_imap::error::Error::Validate(_) => MailError::Config(
                "the user name or secret holds characters IMAP cannot send".into(),
            ),
            other => convert(other),
        })?;
        let capabilities = timed(self.timeout, session.capabilities())
            .await?
            .map_err(convert)?;
        let condstore = capabilities.has_str("CONDSTORE") || capabilities.has_str("QRESYNC");
        if condstore && capabilities.has_str("ENABLE") {
            match timed(
                self.timeout,
                session.run_command_and_check_ok("ENABLE CONDSTORE"),
            )
            .await?
            {
                Ok(())
                | Err(async_imap::error::Error::No(_) | async_imap::error::Error::Bad(_)) => {}
                Err(other) => return Err(convert(other)),
            }
        }
        let caps = Caps {
            gmail: capabilities.has_str("X-GM-EXT-1"),
            idle: capabilities.has_str("IDLE"),
            notify: capabilities.has_str("NOTIFY"),
            uidplus: capabilities.has_str("UIDPLUS"),
            moves: capabilities.has_str("MOVE"),
        };
        tracing::debug!(
            elapsed_ms = started.elapsed().as_millis() as u64,
            gmail = caps.gmail,
            condstore,
            "imap signed in"
        );
        Ok(SignedIn { session, caps })
    }
}

#[async_trait]
impl MailProvider for ImapProvider {
    async fn connect(&self) -> Result<Box<dyn MailSession>, MailError> {
        let signed_in = self.sign_in().await?;
        Ok(Box::new(session::ImapSession::new(signed_in, self.timeout)))
    }

    /// Watches with `IDLE` when the server has it: with `NOTIFY` (RFC 5465) on one connection
    /// for every mailbox, otherwise one connection per mailbox for the first
    /// [`MAX_WATCH_CONNECTIONS`] of them. Mailboxes that do not exist or cannot be selected are
    /// left out; with none left, or none named, `INBOX` is watched. `Ok(None)` without `IDLE`.
    async fn watch(&self, mailboxes: &[String]) -> Result<Option<Box<dyn MailWatch>>, MailError> {
        let SignedIn { mut session, caps } = self.sign_in().await?;
        if !caps.idle {
            let _ = timed(self.timeout, session.logout()).await;
            return Ok(None);
        }
        let listed = list_mailboxes(&mut session, caps.gmail, self.timeout).await?;
        let mut wanted: Vec<(String, String)> = Vec::new();
        for id in mailboxes {
            if let Some((info, raw)) = listed.iter().find(|(m, _)| &m.id == id)
                && info.selectable
                && !wanted.iter().any(|(p, _)| p == id)
            {
                wanted.push((info.id.clone(), raw.clone()));
            }
        }
        if wanted.is_empty() {
            let inbox = listed
                .iter()
                .find(|(_, raw)| raw.eq_ignore_ascii_case("INBOX"))
                .map_or_else(
                    || ("INBOX".to_owned(), "INBOX".to_owned()),
                    |(m, raw)| (m.id.clone(), raw.clone()),
                );
            wanted.push(inbox);
        }
        if wanted.len() > 1 && caps.notify {
            let command = watch::notify_command(wanted.iter().map(|(_, raw)| raw.as_str()));
            match timed(self.timeout, session.run_command_and_check_ok(&command)).await? {
                Ok(()) => {
                    let ids = wanted.into_iter().map(|(id, raw)| (raw, id)).collect();
                    return Ok(Some(Box::new(watch::ImapWatch::start(
                        vec![(session, watch::Target::Notify { ids })],
                        self.timeout,
                        self.idle_renew,
                    ))));
                }
                Err(async_imap::error::Error::No(_) | async_imap::error::Error::Bad(_)) => {}
                Err(other) => return Err(convert(other)),
            }
        }
        let mut connections = Vec::new();
        let mut first = Some(session);
        for (id, raw) in wanted.into_iter().take(MAX_WATCH_CONNECTIONS) {
            let session = match first.take() {
                Some(session) => session,
                None => match self.sign_in().await {
                    Ok(more) => more.session,
                    Err(error) => {
                        tracing::warn!(%error, watched = connections.len(), "no further imap watch connection");
                        break;
                    }
                },
            };
            connections.push((session, watch::Target::Mailbox { id, raw }));
        }
        Ok(Some(Box::new(watch::ImapWatch::start(
            connections,
            self.timeout,
            self.idle_renew,
        ))))
    }
}

/// Every mailbox with the server's own name for it.
pub(crate) async fn list_mailboxes(
    session: &mut Session,
    gmail: bool,
    timeout: Duration,
) -> Result<Vec<(MailboxInfo, String)>, MailError> {
    let names: Vec<_> = timed(timeout, async {
        session
            .list(Some(""), Some("*"))
            .await?
            .try_collect::<Vec<_>>()
            .await
    })
    .await?
    .map_err(convert)?;
    let mut out = Vec::with_capacity(names.len());
    for name in &names {
        let raw = name.name().to_owned();
        let decoded = utf7::decode(&raw);
        let path = match name.delimiter() {
            Some(delimiter) if delimiter != "/" => decoded.replace(delimiter, "/"),
            _ => decoded,
        };
        let mut role = None;
        let mut selectable = true;
        for attribute in name.attributes() {
            match attribute {
                NameAttribute::NoSelect => selectable = false,
                NameAttribute::All => role = Some(MailboxRole::All),
                NameAttribute::Archive => role = Some(MailboxRole::Archive),
                NameAttribute::Drafts => role = Some(MailboxRole::Drafts),
                NameAttribute::Flagged => role = Some(MailboxRole::Flagged),
                NameAttribute::Junk => role = Some(MailboxRole::Junk),
                NameAttribute::Sent => role = Some(MailboxRole::Sent),
                NameAttribute::Trash => role = Some(MailboxRole::Trash),
                NameAttribute::Extension(ext) if ext.eq_ignore_ascii_case("\\NonExistent") => {
                    selectable = false
                }
                _ => {}
            }
        }
        if raw.eq_ignore_ascii_case("INBOX") {
            role = Some(MailboxRole::Inbox);
        }
        let role = role.or_else(|| guess_role(&path));
        let label = gmail
            && selectable
            && !matches!(
                role,
                Some(MailboxRole::All | MailboxRole::Trash | MailboxRole::Junk)
            );
        out.push((
            MailboxInfo {
                id: path.clone(),
                path,
                role,
                selectable,
                label,
            },
            raw,
        ));
    }
    Ok(out)
}

/// A role from common English names of the last path level, for servers without RFC 6154.
pub(crate) fn guess_role(path: &str) -> Option<MailboxRole> {
    let last = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    Some(match last.as_str() {
        "sent" | "sent items" | "sent mail" | "sent messages" => MailboxRole::Sent,
        "drafts" | "draft" => MailboxRole::Drafts,
        "trash" | "deleted items" | "deleted messages" | "bin" => MailboxRole::Trash,
        "junk" | "spam" | "junk e-mail" | "junk email" => MailboxRole::Junk,
        "archive" | "archives" => MailboxRole::Archive,
        _ => return None,
    })
}

/// The SASL XOAUTH2 initial response for `user` and an access token.
fn xoauth2(user: &str, token: &str) -> String {
    format!("user={user}\x01auth=Bearer {token}\x01\x01")
}

/// Sends the XOAUTH2 response once. A server that refuses the token sends a continuation with
/// an error in JSON instead of a tagged `NO`; the empty answer to it makes the server finish with
/// `NO`, which becomes `MailError::Auth`.
struct Xoauth2 {
    response: String,
    sent: bool,
}

impl async_imap::Authenticator for Xoauth2 {
    type Response = String;

    fn process(&mut self, _challenge: &[u8]) -> String {
        if std::mem::replace(&mut self.sent, true) {
            String::new()
        } else {
            self.response.clone()
        }
    }
}

/// The RFC 9208 `OVERQUOTA` response code, or RFC 5530 `OVERQUOTA` (same token).
fn quota_hint(text: &str) -> bool {
    text.to_ascii_uppercase().contains("[OVERQUOTA]")
}

/// Response codes and texts servers use when they limit a user: RFC 5530 `LIMIT`,
/// `UNAVAILABLE` and `INUSE`, Gmail's "Too many simultaneous connections" and `THROTTLED`.
fn throttle_hint(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    ["LIMIT", "UNAVAILABLE", "INUSE", "THROTTL", "TOO MANY"]
        .iter()
        .any(|hint| upper.contains(hint))
}

pub(crate) async fn timed<T>(
    timeout: Duration,
    work: impl std::future::Future<Output = T>,
) -> Result<T, MailError> {
    tokio::time::timeout(timeout, work)
        .await
        .map_err(|_| MailError::Timeout("the server did not answer in time".into()))
}

/// Maps a library error without carrying server text, which may echo mailbox names.
pub(crate) fn convert(error: async_imap::error::Error) -> MailError {
    use async_imap::error::Error;
    match error {
        Error::Io(e) => MailError::Network(e.to_string()),
        Error::ConnectionLost => MailError::Network("connection lost".into()),
        Error::No(text) | Error::Bad(text) if throttle_hint(&text) => {
            MailError::Throttled { retry_after: None }
        }
        Error::No(text) if quota_hint(&text) => MailError::Quota,
        Error::No(_) => MailError::Refused("the server refused a command".into()),
        Error::Bad(_) => MailError::Protocol("the server rejected a command as malformed".into()),
        Error::Parse(_) => MailError::Protocol("unparsable server response".into()),
        Error::Validate(_) => MailError::Protocol("an argument IMAP cannot send".into()),
        Error::Append => MailError::Refused("append refused".into()),
        _ => MailError::Protocol("unexpected server response".into()),
    }
}

/// `1,2,3,7,9` becomes `1:3,7,9`. `uids` must be sorted without repeats.
pub(crate) fn uid_set(uids: &[u32]) -> String {
    let mut parts = Vec::new();
    let mut i = 0;
    while i < uids.len() {
        let start = uids[i];
        let mut end = start;
        while i + 1 < uids.len() && uids[i + 1] == end + 1 {
            i += 1;
            end = uids[i];
        }
        parts.push(if start == end {
            start.to_string()
        } else {
            format!("{start}:{end}")
        });
        i += 1;
    }
    parts.join(",")
}

pub(crate) fn quote(name: &str) -> String {
    format!("\"{}\"", name.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_watch;
