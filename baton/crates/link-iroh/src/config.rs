use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use baton_link::{LinkError, RelayUrl};
use iroh::address_lookup::{DnsAddressLookup, PkarrPublisher, PkarrResolver};
use iroh::endpoint::Builder;
use rustls::crypto::{CryptoProvider, aws_lc_rs};

/// How the TLS handshake of a peer connection must agree on its keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PostQuantum {
    /// Only the hybrid X25519MLKEM768 key exchange is accepted for peer connections; a peer that
    /// negotiates anything else is disconnected before any stream is accepted.
    #[default]
    Required,
    /// X25519MLKEM768 is offered first and negotiated whenever the peer supports it; a classical
    /// X25519 or P-256 exchange is accepted otherwise.
    Preferred,
}

/// How peers are found when no hint gives their address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Discovery {
    /// Only hints given to `add_hint` are used. Nothing about this node is published.
    #[default]
    Disabled,
    /// Publishes this node's key, relay and direct addresses as signed pkarr records to a pkarr
    /// relay, and resolves peers through it and, if given, through DNS under `dns_origin`. The
    /// operator of that relay learns which keys exist and where they are.
    Pkarr {
        /// The pkarr relay, such as `https://dns.example.com/pkarr`. Plain `http` is refused unless
        /// the host is a loopback address.
        relay: String,
        /// The DNS origin domain to resolve `_iroh.<key>.<origin>` records under, if any.
        dns_origin: Option<String>,
    },
}

impl Discovery {
    pub(crate) fn apply(&self, builder: Builder) -> Result<Builder, LinkError> {
        match self {
            Discovery::Disabled => Ok(builder.clear_address_lookup()),
            Discovery::Pkarr { relay, dns_origin } => {
                let url = checked_url(relay)?;
                let mut b = builder
                    .clear_address_lookup()
                    .address_lookup(PkarrPublisher::builder(url.clone()))
                    .address_lookup(PkarrResolver::builder(url));
                if let Some(origin) = dns_origin {
                    b = b.address_lookup(DnsAddressLookup::builder(origin.clone()));
                }
                Ok(b)
            }
        }
    }
}

/// Configuration of an [`IrohLink`](crate::IrohLink).
#[derive(Debug, Clone)]
pub struct IrohConfig {
    /// Relays to keep a home connection to and to reach peers through. Empty (the default)
    /// disables relays: only direct paths work. No public relay is used unless its URL is listed
    /// here. Plain `http` relays (here and in hints) are refused unless the host is a loopback
    /// address.
    pub relays: Vec<RelayUrl>,
    /// How peers without hints are found. Disabled by default.
    pub discovery: Discovery,
    /// Local socket addresses to bind. Empty (the default) binds every interface on IPv4 and,
    /// where available, IPv6, on random ports.
    pub bind: Vec<SocketAddr>,
    /// The key exchange policy for peer connections. [`PostQuantum::Required`] by default.
    pub post_quantum: PostQuantum,
    /// The total time one `open` may take (waiting for a pooled connection, connecting and the
    /// peer accepting the stream) before it fails with `Unreachable`. 10 seconds by default.
    pub open_timeout: Duration,
    /// The first part of every ALPN this link offers and accepts (`<prefix>/<protocol>/1`), so
    /// applications on Baton do not talk to each other by accident. `baton` by default.
    pub alpn_prefix: AlpnPrefix,
}

/// An ALPN prefix: 1–16 bytes of `[a-z0-9-]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlpnPrefix(String);

impl AlpnPrefix {
    /// Checks and wraps `value`.
    pub fn new(value: impl Into<String>) -> Result<Self, LinkError> {
        let value = value.into();
        let ok = !value.is_empty()
            && value.len() <= 16
            && value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if ok {
            Ok(Self(value))
        } else {
            Err(LinkError::InvalidProtocol)
        }
    }

    /// The prefix as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for AlpnPrefix {
    fn default() -> Self {
        Self("baton".to_owned())
    }
}

impl Default for IrohConfig {
    fn default() -> Self {
        Self {
            relays: Vec::new(),
            discovery: Discovery::Disabled,
            bind: Vec::new(),
            post_quantum: PostQuantum::Required,
            open_timeout: Duration::from_secs(10),
            alpn_prefix: AlpnPrefix::default(),
        }
    }
}

pub(crate) fn relay_url(url: &RelayUrl) -> Result<iroh::RelayUrl, LinkError> {
    checked_url(url.as_str())?;
    url.as_str().parse().map_err(|_| LinkError::InvalidHint)
}

/// `https` anywhere, plain `http` only to a loopback host: over plain HTTP an on-path observer
/// would see endpoint ids, peers and direct addresses.
fn checked_url(raw: &str) -> Result<url::Url, LinkError> {
    let url: url::Url = raw.parse().map_err(|_| LinkError::InvalidHint)?;
    let loopback = match url.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    match url.scheme() {
        "https" => Ok(url),
        "http" if loopback => Ok(url),
        _ => Err(LinkError::InvalidHint),
    }
}

/// aws-lc-rs with the hybrid group first. Classical groups stay in the list because the same
/// provider also serves TLS to relays and discovery servers, which may not offer ML-KEM; peer
/// connections are held to the policy by the handshake hook.
pub(crate) fn crypto_provider() -> Arc<CryptoProvider> {
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = vec![
        aws_lc_rs::kx_group::X25519MLKEM768,
        aws_lc_rs::kx_group::X25519,
        aws_lc_rs::kx_group::SECP256R1,
    ];
    Arc::new(provider)
}
