//! The contract of the channel between a person's nodes (app and cloud node, or any two members
//! of a mesh).
//!
//! A [`Link`] opens byte streams to a peer named by its Ed25519 key ([`PublicKey`]) and accepts
//! streams from peers, one listener per [`Protocol`]. Who may talk at all is decided by a
//! [`Trust`]: an implementation refuses an untrusted peer in both directions before a single
//! application byte crosses, and asks the trust again for every new stream, so a revocation
//! applies to the next stream at once.
//!
//! The channel authenticates both ends by their keys only; Web PKI plays no part. Confidentiality
//! and integrity of the bytes are the implementation's job (QUIC with TLS 1.3 keyed by the node
//! identities in `baton-link-iroh`; nothing in the in-process `baton-link-memory`).

mod trust;

#[cfg(feature = "testing")]
pub mod testing;

use std::fmt;
use std::net::SocketAddr;

use async_trait::async_trait;
pub use baton_identity::PublicKey;
use futures::stream::BoxStream;
use tokio_io::io::{AsyncRead, AsyncWrite};

pub use trust::{PinnedKeys, Trust};

/// Errors of the link contract. None of them carries key material or stream content.
#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    /// A protocol name outside the rules of [`Protocol::new`].
    #[error("invalid protocol name")]
    InvalidProtocol,
    /// A relay URL outside the rules of [`RelayUrl::new`], or a hint the implementation cannot
    /// use.
    #[error("invalid peer hint")]
    InvalidHint,
    /// This node does not trust the peer. Nothing was sent to it.
    #[error("peer is not trusted")]
    Untrusted,
    /// The peer refused the stream: it does not trust this node, or nothing listens for the
    /// protocol there. No application byte was exchanged.
    #[error("peer refused the stream")]
    Rejected,
    /// No path to the peer right now. The call may be retried.
    #[error("peer unreachable")]
    Unreachable,
    /// Something already listens for this protocol on this link.
    #[error("protocol already has a listener")]
    AlreadyListening,
    /// The link was closed with [`Link::close`].
    #[error("link closed")]
    Closed,
    /// The implementation failed in another way. The call may be retried.
    #[error("link failed: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl LinkError {
    /// Wraps any implementation error.
    pub fn backend(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self::Backend(e.into())
    }
}

/// The longest protocol name, in bytes.
pub const MAX_PROTOCOL_LEN: usize = 32;

/// The name of an application protocol carried over a link, such as `mesh` or `journal`.
///
/// Guarantees: 1 to [`MAX_PROTOCOL_LEN`] bytes of `[a-z0-9._-]`, starting with a letter or digit.
/// So it is plain ASCII, never contains `/`, and fits inside a TLS ALPN identifier.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Protocol(String);

impl Protocol {
    /// Checks and wraps a protocol name.
    pub fn new(name: &str) -> Result<Self, LinkError> {
        let bytes = name.as_bytes();
        let ok = !bytes.is_empty()
            && bytes.len() <= MAX_PROTOCOL_LEN
            && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
            && bytes.iter().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
            });
        if ok {
            Ok(Self(name.to_owned()))
        } else {
            Err(LinkError::InvalidProtocol)
        }
    }

    /// The name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Protocol({})", self.0)
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The URL of a relay that forwards encrypted packets between peers.
///
/// Guarantees: starts with `https://` or `http://`, has a non-empty host part, is at most 2048
/// bytes of printable ASCII without spaces. Whether the relay works is checked only on use.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RelayUrl(String);

impl RelayUrl {
    /// Checks and wraps a relay URL.
    pub fn new(url: &str) -> Result<Self, LinkError> {
        let rest = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"));
        let ok = url.len() <= 2048
            && url.bytes().all(|b| b.is_ascii_graphic())
            && rest.is_some_and(|r| !r.is_empty() && !r.starts_with('/'));
        if ok {
            Ok(Self(url.to_owned()))
        } else {
            Err(LinkError::InvalidHint)
        }
    }

    /// The URL.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RelayUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RelayUrl({})", self.0)
    }
}

/// Where a peer may be found. Hints only speed up or enable dialing; they never change who the
/// peer is, because the peer is always authenticated by its key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerHint {
    /// Socket addresses the peer may answer on directly.
    pub direct: Vec<SocketAddr>,
    /// A relay the peer is reachable through.
    pub relay: Option<RelayUrl>,
}

/// A bidirectional byte stream between two nodes.
///
/// Guarantees of every stream a [`Link`] hands out: bytes arrive in order, unchanged and exactly
/// once, or the stream fails; `shutdown` on one side makes the other side read end-of-stream after
/// everything written before it; a stream whose other side is gone, severed or closed fails or
/// ends instead of hanging forever.
pub trait Duplex: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> Duplex for T {}

/// A stream a peer opened to this node.
pub struct Incoming {
    /// The peer, authenticated by its key and trusted when the stream was accepted.
    pub peer: PublicKey,
    /// The stream.
    pub stream: Box<dyn Duplex>,
}

impl fmt::Debug for Incoming {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Incoming")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

/// The channel between this node and its peers.
///
/// Guarantees (checked by [`testing::link`]):
///
/// - **Pinned keys.** Every stream is bound to the peer's key; a peer cannot pose as another key.
/// - **Trust both ways.** [`Link::open`] to a peer this node does not trust fails with
///   [`LinkError::Untrusted`] before anything is sent. A stream from a peer this node does not
///   trust is refused before any application byte is read or written, and the opener gets
///   [`LinkError::Rejected`]. The [`Trust`] is asked again for every new stream, so a revocation
///   applies to the next stream immediately.
/// - **Open streams after a revocation** keep working until either side closes them, the link
///   is closed, or [`Link::disconnect_untrusted`] is called, which severs them.
/// - **Protocols are isolated.** A stream opened for one protocol reaches only that protocol's
///   listener; with no listener there, `open` fails with [`LinkError::Rejected`].
/// - **`open` returns only an accepted stream**: when it returns `Ok`, the peer's listener has the
///   stream (or will yield it next).
/// - **Close.** After [`Link::close`], `open` and `listen` fail with [`LinkError::Closed`],
///   listener streams end, open streams are severed, and peers can no longer reach this node.
///   `close` is idempotent.
#[async_trait]
pub trait Link: Send + Sync {
    /// This node's key.
    fn local(&self) -> PublicKey;

    /// Opens a stream to `peer` for `protocol`. Fails with [`LinkError::Untrusted`] without
    /// sending anything when this node does not trust `peer`.
    async fn open(
        &self,
        peer: &PublicKey,
        protocol: &Protocol,
    ) -> Result<Box<dyn Duplex>, LinkError>;

    /// Starts accepting streams for `protocol`. Every item comes from a peer the trust allowed
    /// when the stream arrived. Only one listener per protocol at a time: while the returned
    /// stream is alive, another `listen` for the same protocol fails with
    /// [`LinkError::AlreadyListening`]; dropping it stops accepting at once. The stream ends when
    /// the link closes.
    async fn listen(&self, protocol: &Protocol) -> Result<BoxStream<'static, Incoming>, LinkError>;

    /// Records where `peer` may be found. Later hints for the same peer add direct addresses and
    /// replace the relay.
    fn add_hint(&self, peer: &PublicKey, hint: PeerHint) -> Result<(), LinkError>;

    /// Severs every open stream and connection to peers the trust no longer allows. Returns how
    /// many distinct peers were cut off.
    async fn disconnect_untrusted(&self) -> Result<usize, LinkError>;

    /// Closes the link: see the trait guarantees. Idempotent.
    async fn close(&self);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_names() {
        for good in ["mesh", "journal-1", "a", "0.x_y-z", &"a".repeat(32)] {
            assert_eq!(Protocol::new(good).unwrap().as_str(), good);
        }
        for bad in [
            "",
            "Mesh",
            "mesh/1",
            "-mesh",
            ".mesh",
            "me sh",
            "mesh\u{e9}",
            &"a".repeat(33),
        ] {
            assert!(Protocol::new(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn relay_urls() {
        for good in [
            "https://relay.example.com",
            "http://127.0.0.1:3340/",
            "https://relay.example.org/path",
        ] {
            assert_eq!(RelayUrl::new(good).unwrap().as_str(), good);
        }
        for bad in [
            "",
            "relay.example.com",
            "ftp://relay.example.com",
            "https://",
            "https:///x",
            "https://relay example.com",
        ] {
            assert!(RelayUrl::new(bad).is_err(), "{bad:?}");
        }
    }
}
