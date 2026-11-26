//! Mail server discovery: candidate IMAP and SMTP servers for the domain of an address.
//!
//! A [`DiscoverySource`] answers for one domain with at most [`MAX_CANDIDATES`] candidates; the
//! node asks its sources in configured order and joins their answers with the pure [`merge`].
//! Discovery never signs in and never sees a credential. Implementations run
//! [`testing::source`].

use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[cfg(feature = "testing")]
pub mod testing;

/// Most candidates a source returns and [`merge`] keeps.
pub const MAX_CANDIDATES: usize = 16;

/// Why a lookup, fetch, resolution or probe failed. Carries no input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum DiscoverError {
    /// A domain, host, name, URL or topic breaks its rules.
    #[error("invalid input")]
    Invalid,
    /// The source cannot answer now; the node goes on with the next one.
    #[error("discovery source unavailable")]
    Unavailable,
    /// The server could not be reached or the connection broke.
    #[error("server unreachable")]
    Unreachable,
    /// The server did not answer within the deadline.
    #[error("timed out")]
    Timeout,
    /// The TLS handshake or the certificate check failed.
    #[error("TLS failed")]
    TlsFailed,
    /// The server offers no encryption (no TLS, no STARTTLS); it is never used.
    #[error("insecure server refused")]
    Insecure,
    /// The server answered, but not as a mail server of the asked kind, or it refused.
    #[error("not a mail server")]
    NotMail,
    /// An answer was larger than the caller's cap.
    #[error("answer too large")]
    TooLarge,
}

/// Most bytes [`HttpsFetcher::get`] may be asked to read.
pub const MAX_FETCH_BYTES: usize = 256 * 1024;
/// Most records a [`SrvResolver`] returns.
pub const MAX_SRV_RECORDS: usize = 32;
/// Ports on which STARTTLS is accepted from a source other than the table: 143 (IMAP) and 587
/// (submission). A STARTTLS endpoint elsewhere is dropped, so a hostile answer cannot steer a
/// client to an odd port that starts in plain text.
pub const STARTTLS_PORTS: [u16; 2] = [143, 587];

/// Whether `host` is a DNS host name: 1 to 253 bytes of lowercase ASCII labels of `[a-z0-9-]`,
/// each 1 to 63 bytes, not starting or ending with `-`, at least two labels.
pub fn valid_host(host: &str) -> bool {
    let labels: Vec<&str> = host.split('.').collect();
    !host.is_empty()
        && host.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// Whether `host` is `domain` or a name under it (`imap.example.com` under `example.com`).
pub fn within(host: &str, domain: &Domain) -> bool {
    host == domain.as_str()
        || host
            .strip_suffix(domain.as_str())
            .is_some_and(|rest| rest.ends_with('.'))
}

/// Whether `host` names an IP address rather than a DNS name (its last label is all digits).
/// Discovery never offers such a host from a networked source.
pub fn is_ip_literal(host: &str) -> bool {
    host.rsplit('.')
        .next()
        .is_some_and(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()))
}

/// The domain of an address, lower case, checked with [`valid_host`].
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Domain(String);

impl Domain {
    /// Lowercases and checks `domain`.
    pub fn new(domain: &str) -> Result<Self, DiscoverError> {
        let lower = domain.to_ascii_lowercase();
        if valid_host(&lower) {
            Ok(Self(lower))
        } else {
            Err(DiscoverError::Invalid)
        }
    }

    /// The domain of `address` (the part after the last `@`).
    pub fn of_address(address: &str) -> Result<Self, DiscoverError> {
        let (local, domain) = address.rsplit_once('@').ok_or(DiscoverError::Invalid)?;
        if local.is_empty() {
            return Err(DiscoverError::Invalid);
        }
        Self::new(domain)
    }

    /// The domain as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Domain({} bytes)", self.0.len())
    }
}

impl TryFrom<String> for Domain {
    type Error = DiscoverError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(&value)
    }
}

impl From<Domain> for String {
    fn from(value: Domain) -> Self {
        value.0
    }
}

/// How a connection is protected. Plain text is never offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Security {
    /// TLS from the first byte (993, 465).
    Tls,
    /// A plain connection upgraded with STARTTLS before anything else (143, 587).
    StartTls,
}

/// A server to connect to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    /// The host name, checked with [`valid_host`].
    pub host: String,
    /// The port, never 0.
    pub port: u16,
    /// How the connection is protected.
    pub security: Security,
}

impl Endpoint {
    /// An endpoint after checking `host` (lowercased) and `port`.
    pub fn new(host: &str, port: u16, security: Security) -> Result<Self, DiscoverError> {
        let host = host.to_ascii_lowercase();
        if valid_host(&host) && port != 0 {
            Ok(Self {
                host,
                port,
                security,
            })
        } else {
            Err(DiscoverError::Invalid)
        }
    }

    /// Whether the endpoint keeps the rules of [`Endpoint::new`].
    pub fn is_valid(&self) -> bool {
        valid_host(&self.host) && self.port != 0
    }
}

/// Which user name the servers expect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsernameForm {
    /// The whole address.
    Address,
    /// The part before the `@`.
    LocalPart,
}

/// How the provider lets mail clients sign in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthHint {
    /// The account password works.
    Password,
    /// The provider needs an app password created in its settings.
    AppPassword,
    /// Only OAuth works; the app says this comes later.
    OAuthOnly,
}

/// Where a candidate came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// A reviewed table of well-known providers.
    Table,
    /// A conventional host name guess (`imap.<domain>`, `smtp.<domain>`, `mail.<domain>`).
    Guess,
    /// The domain's own autoconfig file over HTTPS (`autoconfig.<domain>` or the domain's
    /// `/.well-known/autoconfig/`).
    Autoconfig,
    /// The domain's DNS SRV records (RFC 6186, RFC 8314).
    Srv,
}

/// One way to reach an account's servers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Candidate {
    /// Where mail is read.
    pub imap: Endpoint,
    /// Where mail is submitted.
    pub smtp: Endpoint,
    /// The user name form.
    pub username: UsernameForm,
    /// How sign-in works.
    pub auth: AuthHint,
    /// A help topic id the app maps to a page: 1 to 64 characters of `[a-z0-9-]`.
    pub help: Option<String>,
    /// Where it came from.
    pub source: Source,
    /// Both servers answered a probe (TLS verified, greeting read, no credentials sent).
    pub verified: bool,
    /// A server lies outside the address's domain and the known providers, so the app shows
    /// the candidate as "suggested by" its source and asks the person to confirm it.
    #[serde(default)]
    pub needs_confirmation: bool,
}

/// Whether `topic` is a help topic id.
pub fn valid_topic(topic: &str) -> bool {
    !topic.is_empty()
        && topic.len() <= 64
        && topic
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl Candidate {
    /// Whether every field keeps its rules.
    pub fn is_valid(&self) -> bool {
        self.imap.is_valid() && self.smtp.is_valid() && self.help.as_deref().is_none_or(valid_topic)
    }

    /// Whether both endpoints keep the rules for candidates from a networked source: no IP
    /// literal, and STARTTLS only on [`STARTTLS_PORTS`].
    pub fn fit_from_network(&self) -> bool {
        [&self.imap, &self.smtp].iter().all(|e| {
            !is_ip_literal(&e.host)
                && (e.security == Security::Tls || STARTTLS_PORTS.contains(&e.port))
        })
    }

    fn same_servers(&self, other: &Self) -> bool {
        self.imap == other.imap && self.smtp == other.smtp
    }
}

/// A place to look up candidates for a domain.
///
/// Guarantees: at most [`MAX_CANDIDATES`] candidates, each [`Candidate::is_valid`], best first,
/// equal answers for equal domains within one build; no credential is ever sent. A source that
/// reaches the network bounds every call by a timeout and fails with
/// [`DiscoverError::Unavailable`] rather than hanging.
#[async_trait]
pub trait DiscoverySource: Send + Sync {
    /// Candidates for `domain`, best first.
    async fn lookup(&self, domain: &Domain) -> Result<Vec<Candidate>, DiscoverError>;

    /// A short stable name for logs (`table`, `autoconfig`).
    fn name(&self) -> &'static str;
}

/// What a probe learnt about a server before sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Probed {
    /// A password can sign in (IMAP without `LOGINDISABLED`, SMTP offering `AUTH PLAIN` or
    /// `LOGIN`).
    pub password_sign_in: bool,
    /// The server offers OAuth sign-in (`XOAUTH2` or `OAUTHBEARER`).
    pub oauth: bool,
}

/// Checks a candidate's servers without signing in: connects, verifies TLS (after STARTTLS when
/// asked), reads the greeting and capabilities, sends nothing else and never a credential.
/// Implementations bound every call by a timeout and the bytes they read.
#[async_trait]
pub trait Prober: Send + Sync {
    /// The IMAP server at `endpoint`, or why it is not usable: [`DiscoverError::TlsFailed`],
    /// [`DiscoverError::Insecure`] (no STARTTLS), [`DiscoverError::Timeout`],
    /// [`DiscoverError::Unreachable`] or [`DiscoverError::NotMail`].
    async fn probe_imap(&self, endpoint: &Endpoint) -> Result<Probed, DiscoverError>;
    /// The SMTP submission server at `endpoint`, with the same errors.
    async fn probe_smtp(&self, endpoint: &Endpoint) -> Result<Probed, DiscoverError>;
}

/// An `https://` URL on a checked host with a fixed path; nothing a person typed beyond the
/// domain, never a query string.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct HttpsUrl {
    host: String,
    path: String,
}

impl HttpsUrl {
    /// A URL for `host` (checked with [`valid_host`]) and `path`: starts with `/`, at most 256
    /// bytes of `[A-Za-z0-9._~/-]`, no `..` segment.
    pub fn new(host: &str, path: &str) -> Result<Self, DiscoverError> {
        let path_ok = path.starts_with('/')
            && path.len() <= 256
            && !path.split('/').any(|s| s == "..")
            && path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._~/-".contains(&b));
        if valid_host(host) && !is_ip_literal(host) && path_ok {
            Ok(Self {
                host: host.to_owned(),
                path: path.to_owned(),
            })
        } else {
            Err(DiscoverError::Invalid)
        }
    }

    /// The host.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The whole URL.
    pub fn as_string(&self) -> String {
        format!("https://{}{}", self.host, self.path)
    }
}

impl fmt::Debug for HttpsUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HttpsUrl({} bytes)", self.host.len() + self.path.len())
    }
}

/// Reads one document over HTTPS for a discovery source.
///
/// Guarantees: `GET` only, certificate verified against the web roots, no redirect followed, no
/// cookie, credential or query sent, at most `max_bytes` read ([`DiscoverError::TooLarge`]
/// beyond, never a truncated body), every call bounded by a timeout. A status other than 200 is
/// [`DiscoverError::Unavailable`]. `max_bytes` above [`MAX_FETCH_BYTES`] is
/// [`DiscoverError::Invalid`].
#[async_trait]
pub trait HttpsFetcher: Send + Sync {
    /// The body at `url`.
    async fn get(&self, url: &HttpsUrl, max_bytes: usize) -> Result<Vec<u8>, DiscoverError>;
}

/// Whether `name` is an SRV owner name: `_service._tcp.` followed by a [`valid_host`].
pub fn valid_srv_name(name: &str) -> bool {
    let mut labels = name.splitn(3, '.');
    let (Some(service), Some(proto), Some(rest)) = (labels.next(), labels.next(), labels.next())
    else {
        return false;
    };
    service.len() >= 2
        && service.len() <= 63
        && service.starts_with('_')
        && service[1..]
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && proto == "_tcp"
        && valid_host(rest)
        && name.len() <= 253
}

/// One DNS SRV record (RFC 2782).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SrvRecord {
    /// Lower is tried first.
    pub priority: u16,
    /// Among equal priorities, higher is preferred.
    pub weight: u16,
    /// The port.
    pub port: u16,
    /// The target host, lower case without the final dot; `.` (the service is not offered) is
    /// returned as an empty string.
    pub target: String,
}

/// Looks up DNS SRV records for a discovery source.
///
/// Guarantees: at most [`MAX_SRV_RECORDS`] records, only records whose owner is `name`, every
/// call bounded by a timeout; a name that does not exist or has no SRV records is `Ok` and
/// empty; an invalid `name` ([`valid_srv_name`]) is [`DiscoverError::Invalid`]; a failure to
/// get an answer is [`DiscoverError::Unavailable`] or [`DiscoverError::Timeout`].
#[async_trait]
pub trait SrvResolver: Send + Sync {
    /// The SRV records of `name`, in any order.
    async fn srv(&self, name: &str) -> Result<Vec<SrvRecord>, DiscoverError>;
}

/// Joins the answers of several sources, given in the configured order: invalid candidates
/// dropped, a candidate whose IMAP and SMTP endpoints equal an earlier one's dropped (the
/// earlier one wins), `OAuthOnly` candidates kept, at most [`MAX_CANDIDATES`] in all. Pure and
/// deterministic.
pub fn merge(answers: Vec<Vec<Candidate>>) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();
    for answer in answers {
        for candidate in answer.into_iter().take(MAX_CANDIDATES) {
            if out.len() == MAX_CANDIDATES {
                return out;
            }
            if candidate.is_valid() && !out.iter().any(|c| c.same_servers(&candidate)) {
                out.push(candidate);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn cand(imap: &str, auth: AuthHint, source: Source) -> Candidate {
        Candidate {
            imap: Endpoint::new(imap, 993, Security::Tls).unwrap(),
            smtp: Endpoint::new("smtp.example.com", 465, Security::Tls).unwrap(),
            username: UsernameForm::Address,
            auth,
            help: None,
            source,
            verified: false,
            needs_confirmation: false,
        }
    }

    #[test]
    fn hosts_and_domains_follow_the_rules() {
        for good in ["example.com", "mail.example.org", "a-b.c9.example.net"] {
            assert!(valid_host(good), "{good}");
        }
        for bad in [
            "",
            "localhost",
            "-a.com",
            "a-.com",
            "a..com",
            "a.com.",
            "A.com",
            "a_b.com",
            "a b.com",
            "xn--.com.",
            "a.com/x",
            "1.2.3.4:5",
        ] {
            assert!(!valid_host(bad), "{bad}");
        }
        assert_eq!(
            Domain::of_address("Pat@Example.COM").unwrap().as_str(),
            "example.com"
        );
        assert!(Domain::of_address("@example.com").is_err());
        assert!(Domain::of_address("pat").is_err());
        assert!(Domain::of_address("pat@exa\r\nmple.com").is_err());
        assert!(serde_json::from_str::<Domain>("\"evil..com\"").is_err());
        assert_eq!(
            format!("{:?}", Domain::new("example.com").unwrap()),
            "Domain(11 bytes)"
        );
        assert!(Endpoint::new("imap.example.com", 0, Security::Tls).is_err());
    }

    #[test]
    fn merge_keeps_order_drops_duplicates_and_keeps_oauth_only() {
        let a = cand("imap.example.com", AuthHint::OAuthOnly, Source::Table);
        let b = cand("mail.example.com", AuthHint::Password, Source::Guess);
        let dup = Candidate {
            auth: AuthHint::Password,
            source: Source::Guess,
            ..a.clone()
        };
        let mut bad = b.clone();
        bad.imap.host = "BAD".into();
        let merged = merge(vec![vec![a.clone(), bad], vec![dup, b.clone()]]);
        assert_eq!(merged, vec![a, b]);
    }

    #[test]
    fn network_rules_hold() {
        let d = Domain::new("example.com").unwrap();
        assert!(within("example.com", &d) && within("imap.example.com", &d));
        assert!(!within("badexample.com", &d) && !within("example.com.evil.test", &d));
        assert!(is_ip_literal("10.0.0.1") && !is_ip_literal("imap.example.com"));
        let mut c = cand("imap.example.com", AuthHint::Password, Source::Autoconfig);
        assert!(c.fit_from_network());
        c.imap = Endpoint::new("imap.example.com", 2525, Security::StartTls).unwrap();
        assert!(!c.fit_from_network());
        c.imap = Endpoint::new("192.168.1.1", 993, Security::Tls).unwrap();
        assert!(!c.fit_from_network());
        assert!(
            serde_json::from_str::<Candidate>(
                r#"{"imap":{"host":"a.example","port":1,"security":"tls"},"smtp":{"host":"a.example","port":1,"security":"tls"},"username":"address","auth":"password","help":null,"source":"srv","verified":false}"#
            )
            .is_ok_and(|c| !c.needs_confirmation)
        );
    }

    #[test]
    fn urls_and_srv_names_follow_the_rules() {
        let u = HttpsUrl::new("autoconfig.example.com", "/mail/config-v1.1.xml").unwrap();
        assert_eq!(
            u.as_string(),
            "https://autoconfig.example.com/mail/config-v1.1.xml"
        );
        assert_eq!(format!("{u:?}"), "HttpsUrl(43 bytes)");
        for (host, path) in [
            ("autoconfig.example.com", "mail"),
            ("autoconfig.example.com", "/a?emailaddress=x"),
            ("autoconfig.example.com", "/a/../b"),
            ("autoconfig.example.com", "/a#b"),
            ("autoconfig.example.com", "/a b"),
            ("127.0.0.1", "/a"),
            ("Autoconfig.example.com", "/a"),
        ] {
            assert!(HttpsUrl::new(host, path).is_err(), "{host}{path}");
        }
        assert!(valid_srv_name("_imaps._tcp.example.com"));
        assert!(valid_srv_name("_submission._tcp.mail.example.org"));
        for bad in [
            "_imaps._udp.example.com",
            "imaps._tcp.example.com",
            "_imaps._tcp.localhost",
            "_._tcp.example.com",
            "_imaps._tcp.example.com.",
            "_IMAPS._tcp.example.com",
        ] {
            assert!(!valid_srv_name(bad), "{bad}");
        }
    }

    proptest! {
        #[test]
        fn merge_is_bounded_and_unique(hosts in proptest::collection::vec("[a-c]{1,2}", 0..60)) {
            let lists: Vec<Vec<Candidate>> = hosts
                .chunks(7)
                .map(|c| c.iter().map(|h| cand(&format!("{h}.example.com"), AuthHint::Password, Source::Guess)).collect())
                .collect();
            let merged = merge(lists.clone());
            prop_assert!(merged.len() <= MAX_CANDIDATES);
            for (i, x) in merged.iter().enumerate() {
                prop_assert!(!merged[..i].iter().any(|y| y.same_servers(x)));
            }
            prop_assert_eq!(merge(lists), merged);
        }
    }
}
