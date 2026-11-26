//! Discovery from the domain's own autoconfig file (the `clientConfig` format, version 1.1),
//! read over HTTPS from `autoconfig.<domain>` and from the domain's `/.well-known/autoconfig/`.
//!
//! Only the domain itself is asked: no third-party database, no address in the URL. The file is
//! untrusted input: [`parse`] is a bounded decoder, and every candidate it yields is still
//! probed by the node before it is offered.

use std::sync::Arc;

use async_trait::async_trait;
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use rowboat_discover::{
    AuthHint, Candidate, DiscoverError, DiscoverySource, Domain, Endpoint, HttpsFetcher, HttpsUrl,
    MAX_CANDIDATES, Security, Source, UsernameForm, valid_host,
};

/// Most bytes of an autoconfig file read.
pub const MAX_FILE_BYTES: usize = 64 * 1024;
/// Deepest element nesting accepted.
pub const MAX_DEPTH: usize = 16;
/// Most elements accepted in one file.
pub const MAX_ELEMENTS: usize = 2_000;
/// Most incoming (or outgoing) servers read from one file; the rest are ignored.
pub const MAX_SERVERS: usize = 4;
/// Longest text value kept.
pub const MAX_TEXT: usize = 255;

const PATH: &str = "/mail/config-v1.1.xml";
const WELL_KNOWN: &str = "/.well-known/autoconfig/mail/config-v1.1.xml";

/// The autoconfig source over an HTTPS fetcher.
pub struct AutoconfigSource {
    fetcher: Arc<dyn HttpsFetcher>,
}

impl AutoconfigSource {
    /// A source fetching with `fetcher`.
    pub fn new(fetcher: Arc<dyn HttpsFetcher>) -> Self {
        Self { fetcher }
    }

    /// The URLs asked for `domain`, in order: `https://autoconfig.<domain>/mail/config-v1.1.xml`,
    /// then `https://<domain>/.well-known/autoconfig/mail/config-v1.1.xml`.
    pub fn urls(domain: &Domain) -> Vec<HttpsUrl> {
        let auto = format!("autoconfig.{}", domain.as_str());
        [
            HttpsUrl::new(&auto, PATH).ok(),
            HttpsUrl::new(domain.as_str(), WELL_KNOWN).ok(),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

#[async_trait]
impl DiscoverySource for AutoconfigSource {
    async fn lookup(&self, domain: &Domain) -> Result<Vec<Candidate>, DiscoverError> {
        for url in Self::urls(domain) {
            if let Ok(body) = self.fetcher.get(&url, MAX_FILE_BYTES).await {
                let found = parse(&body, domain);
                if !found.is_empty() {
                    return Ok(found);
                }
            }
        }
        Ok(Vec::new())
    }

    fn name(&self) -> &'static str {
        "autoconfig"
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Imap,
    Smtp,
    Other,
}

#[derive(Debug, Default, Clone)]
struct Server {
    kind: Option<Kind>,
    host: String,
    port: String,
    socket: String,
    username: String,
    auth: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Usable {
    username: UsernameForm,
    auth: AuthHint,
}

fn element_name(raw: &str) -> String {
    raw.rsplit(':').next().unwrap_or(raw).to_owned()
}

fn push_text(target: &mut String, text: &str) -> bool {
    if target.len() + text.len() > MAX_TEXT {
        return false;
    }
    target.push_str(text);
    true
}

fn entity(name: &str) -> Option<char> {
    Some(match name {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        _ => return None,
    })
}

/// Reads the servers of a `clientConfig` document, or `None` when it is not one within the
/// limits.
fn servers(bytes: &[u8]) -> Option<(Vec<Server>, Vec<Server>)> {
    if bytes.len() > MAX_FILE_BYTES {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let mut reader = Reader::from_str(text);
    let mut stack: Vec<String> = Vec::new();
    let mut elements = 0usize;
    let mut incoming: Vec<Server> = Vec::new();
    let mut outgoing: Vec<Server> = Vec::new();
    let mut current: Option<(bool, Server)> = None;
    let mut field: Option<String> = None;
    let mut seen_root = false;
    loop {
        match reader.read_event().ok()? {
            Event::Start(start) => {
                elements += 1;
                if elements > MAX_ELEMENTS || stack.len() >= MAX_DEPTH {
                    return None;
                }
                let name = element_name(start.local_name().as_ref());
                if stack.is_empty() {
                    if name != "clientConfig" || seen_root {
                        return None;
                    }
                    seen_root = true;
                }
                let in_provider = stack.len() == 2 && stack[1] == "emailProvider";
                if in_provider && (name == "incomingServer" || name == "outgoingServer") {
                    let kind = start
                        .attributes()
                        .flatten()
                        .find(|a| a.key.local_name().as_ref() == "type")
                        .map(|a| match a.value.as_ref() {
                            "imap" => Kind::Imap,
                            "smtp" => Kind::Smtp,
                            _ => Kind::Other,
                        });
                    current = Some((
                        name == "incomingServer",
                        Server {
                            kind,
                            ..Server::default()
                        },
                    ));
                } else if current.is_some() && stack.len() == 3 {
                    field = Some(name.clone());
                }
                stack.push(name);
            }
            Event::Empty(_) => {
                elements += 1;
                if elements > MAX_ELEMENTS || stack.is_empty() {
                    return None;
                }
            }
            Event::End(_) => {
                let name = stack.pop()?;
                if stack.len() == 3 {
                    field = None;
                }
                if stack.len() == 2
                    && (name == "incomingServer" || name == "outgoingServer")
                    && let Some((is_in, server)) = current.take()
                {
                    let list = if is_in { &mut incoming } else { &mut outgoing };
                    if list.len() < MAX_SERVERS {
                        list.push(server);
                    }
                }
            }
            Event::Text(t) => {
                if let (Some(f), Some((_, server))) = (&field, current.as_mut()) {
                    let value = t.xml10_content();
                    if !write_field(server, f, value.trim()) {
                        return None;
                    }
                } else if stack.is_empty() && !t.xml10_content().trim().is_empty() {
                    return None;
                }
            }
            Event::CData(c) => {
                if let (Some(f), Some((_, server))) = (&field, current.as_mut()) {
                    let value = c.into_inner();
                    if !write_field(server, f, value.trim()) {
                        return None;
                    }
                }
            }
            Event::GeneralRef(reference) => {
                let c = match reference.resolve_char_ref().ok()? {
                    Some(c) => c,
                    None => entity(&reference.into_inner())?,
                };
                if let (Some(f), Some((_, server))) = (&field, current.as_mut()) {
                    let mut buf = [0u8; 4];
                    if !write_field(server, f, c.encode_utf8(&mut buf)) {
                        return None;
                    }
                }
            }
            Event::DocType(_) => return None,
            Event::Eof => break,
            _ => {}
        }
    }
    (seen_root && stack.is_empty()).then_some((incoming, outgoing))
}

fn write_field(server: &mut Server, field: &str, value: &str) -> bool {
    match field {
        "hostname" => push_text(&mut server.host, value),
        "port" => push_text(&mut server.port, value),
        "socketType" => push_text(&mut server.socket, value),
        "username" => push_text(&mut server.username, value),
        "authentication" => {
            if server.auth.len() < 8 && value.len() <= MAX_TEXT {
                server.auth.push(value.to_owned());
            }
            true
        }
        _ => true,
    }
}

fn endpoint(server: &Server, domain: &Domain, want: Kind) -> Option<Endpoint> {
    if server.kind != Some(want) {
        return None;
    }
    let host = server
        .host
        .replace("%EMAILDOMAIN%", domain.as_str())
        .to_ascii_lowercase();
    if !valid_host(&host) || host.contains('%') {
        return None;
    }
    let port: u16 = server.port.parse().ok().filter(|p| *p != 0)?;
    let security = match server.socket.as_str() {
        "SSL" | "TLS" => Security::Tls,
        "STARTTLS" => Security::StartTls,
        _ => return None,
    };
    Endpoint::new(&host, port, security).ok()
}

fn username(server: &Server) -> Option<UsernameForm> {
    match server.username.as_str() {
        "%EMAILADDRESS%" => Some(UsernameForm::Address),
        "%EMAILLOCALPART%" => Some(UsernameForm::LocalPart),
        _ => None,
    }
}

fn auth(server: &Server) -> Option<AuthHint> {
    let has = |m: &str| server.auth.iter().any(|a| a == m);
    if server.auth.is_empty() || has("password-cleartext") || has("password-encrypted") {
        Some(AuthHint::Password)
    } else if has("OAuth2") {
        Some(AuthHint::OAuthOnly)
    } else {
        None
    }
}

/// The candidates an autoconfig document gives for `domain`: every usable IMAP server paired
/// with every usable SMTP server, in document order, at most [`MAX_CANDIDATES`].
///
/// A server is usable when its type is `imap` (incoming) or `smtp` (outgoing), its host is a
/// valid host after `%EMAILDOMAIN%` is replaced, its port is a number from 1 to 65535, its
/// socket type is `SSL`, `TLS` or `STARTTLS` (plain is never used), its user name is
/// `%EMAILADDRESS%` or `%EMAILLOCALPART%`, and it signs in with a password or OAuth 2.0. A
/// candidate's user name form and sign-in hint come from its IMAP server.
///
/// Never panics; a document that is not UTF-8, larger than [`MAX_FILE_BYTES`], deeper than
/// [`MAX_DEPTH`], has more than [`MAX_ELEMENTS`] elements, a `DOCTYPE`, an entity other than the
/// five predefined ones, or a text value longer than [`MAX_TEXT`] gives no candidates.
/// Deterministic.
pub fn parse(bytes: &[u8], domain: &Domain) -> Vec<Candidate> {
    let Some((incoming, outgoing)) = servers(bytes) else {
        return Vec::new();
    };
    let imap: Vec<(Endpoint, Usable)> = incoming
        .iter()
        .filter_map(|s| {
            Some((
                endpoint(s, domain, Kind::Imap)?,
                Usable {
                    username: username(s)?,
                    auth: auth(s)?,
                },
            ))
        })
        .collect();
    let smtp: Vec<Endpoint> = outgoing
        .iter()
        .filter(|s| username(s).is_some() && auth(s).is_some())
        .filter_map(|s| endpoint(s, domain, Kind::Smtp))
        .collect();
    let mut out = Vec::new();
    for (i, usable) in &imap {
        for s in &smtp {
            if out.len() == MAX_CANDIDATES {
                return out;
            }
            out.push(Candidate {
                imap: i.clone(),
                smtp: s.clone(),
                username: usable.username,
                auth: usable.auth,
                help: None,
                source: Source::Autoconfig,
                verified: false,
                needs_confirmation: false,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests;
