//! A lease arbiter on a server node for a group with no shared store.
//!
//! [`LeaseServer`] runs [`CasLeases`](baton_lease_cas::CasLeases) and
//! [`CasLiveness`](baton_lease_cas::CasLiveness) over the server's own
//! [`StateStore`](baton_state::StateStore) and serves them over link protocol [`PROTOCOL`].
//! Clients use [`RemoteLeases`] (a [`Leases`](baton_lease::Leases)) and [`RemoteLiveness`] (a
//! [`Liveness`](baton_lease::Liveness)) over one [`LeaseClient`].
//!
//! The server is the single liveness observer for all its clients: heartbeats are recorded and
//! judged on the server's clock, never on a client's. A request speaks only for the node of the
//! link-authenticated peer, and [`Authorize`] decides every request again, so a revocation
//! applies to the next request on an open stream. While the server is down every call fails with
//! [`LeaseError::Unavailable`](baton_lease::LeaseError::Unavailable), so nothing new starts, and
//! a holder stops on its own once [`RemoteLiveness::valid_until`] passes.

mod client;
mod server;
pub mod wire;

#[cfg(test)]
mod tests;

use std::time::Duration;

use baton_core::{GroupId, LeaseKey, NodeId};
use baton_lease::NodeProfile;
use baton_link::PublicKey;

pub use client::{ClientConfig, LeaseClient, RemoteError, RemoteLeases, RemoteLiveness};
pub use server::LeaseServer;

/// The link protocol leases and liveness travel on.
pub const PROTOCOL: &str = "lease";

/// Decides what a link-authenticated peer may ask the server. Asked for every request, so an
/// implementation must answer from the current state (no caching that delays a revocation) and
/// never block on I/O.
pub trait Authorize: Send + Sync {
    /// The node `peer` speaks as, or `None` to refuse everything from it. The default is the
    /// node id derived from the key ([`PublicKey::node_id`]).
    fn node(&self, peer: &PublicKey) -> Option<NodeId> {
        Some(peer.node_id())
    }

    /// Whether `peer` may read liveness and lease holders of `group`.
    fn member(&self, peer: &PublicKey, group: &GroupId) -> bool;

    /// Whether `peer` may announce `profile` in `group` (for example: no stronger class than its
    /// certificate). The profile's node is already checked to be the peer's. The default is
    /// [`Authorize::member`].
    fn profile(&self, peer: &PublicKey, group: &GroupId, profile: &NodeProfile) -> bool {
        let _ = profile;
        self.member(peer, group)
    }

    /// Whether `peer` may acquire or ask to take over `key` in `group`. Releasing is allowed to the
    /// lease's own node without asking, so losing this right never strands a lease.
    fn lease(&self, peer: &PublicKey, group: &GroupId, key: &LeaseKey) -> bool;
}

/// Limits and timings of a [`LeaseServer`].
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// The liveness time-to-live, in milliseconds of the server's clock: what clients are told
    /// (in `Hello` and every heartbeat reply) and stop acting by.
    pub ttl_ms: u64,
    /// The largest time-to-live an earlier run of this server told clients that may still
    /// believe it (0 for none). The server judges holders gone only after
    /// `max(ttl_ms, previous_ttl_ms)`, so lowering the time-to-live across a restart never lets
    /// another node take a lease its holder still thinks valid.
    pub previous_ttl_ms: u64,
    /// How long a stream may stay idle between requests before it is closed.
    pub idle_timeout: Duration,
    /// How long a peer may take to send the rest of a request once its first byte arrived.
    pub header_timeout: Duration,
    /// How long a peer may take to read a reply.
    pub write_timeout: Duration,
    /// How long one request may take to decide.
    pub request_timeout: Duration,
    /// How many streams the server keeps open at once, across all peers.
    pub max_streams: usize,
    /// How many streams one peer may keep open at once.
    pub max_per_peer: usize,
    /// How many requests are decided at once.
    pub max_busy: usize,
    /// How long a request waits for a free slot before it is refused as busy.
    pub busy_wait: Duration,
    /// The largest reply body (an `Alive` list larger than this is refused as too large).
    pub max_reply: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            ttl_ms: 15_000,
            previous_ttl_ms: 0,
            idle_timeout: Duration::from_secs(60),
            header_timeout: Duration::from_secs(2),
            write_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(10),
            max_streams: 1024,
            max_per_peer: 8,
            max_busy: 256,
            busy_wait: Duration::from_secs(1),
            max_reply: wire::MAX_REPLY,
        }
    }
}
