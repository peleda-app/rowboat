//! Group logs held by a server node and served over link protocol [`PROTOCOL`].
//!
//! [`GroupLogs`] keeps the logs of a fixed set of groups, each pinned to the hash of its genesis
//! entry, verified in memory and stored in a [`StateStore`](baton_state::StateStore) through
//! `baton_group::store`. [`GroupServer`] serves them: members fetch entries after a position and
//! push new signed entries, which `baton-group` checks at the head before they are stored.
//! [`GroupClient`] is the member side; it trusts nothing the server says and verifies every
//! entry against the caller's own log.
//!
//! A blind server (`batond`) holds the log this way without any key or capability: it can
//! withhold entries or hand out a stale head, which members detect with
//! [`GroupClient::sync`], but it cannot forge, reorder or fork a log.

mod client;
mod logs;
mod server;
pub mod wire;

#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::time::Duration;

use baton_core::{GroupId, Timestamp};
use baton_link::{PinnedKeys, PublicKey, Trust};

pub use client::{ClientConfig, GroupClient, RemoteError};
pub use logs::{GroupLogs, LogLimits, Pushed};
pub use server::GroupServer;

/// The link protocol group logs travel on.
pub const PROTOCOL: &str = "group";

/// How far ahead of the receiver's clock an entry's time may be by default (5 minutes).
pub const DEFAULT_SKEW_MS: i64 = 5 * 60 * 1000;

/// A wall clock (milliseconds since the Unix epoch).
pub type Clock = Arc<dyn Fn() -> Timestamp + Send + Sync>;

/// Admits peers to a group's log although they are no node of it (yet): the founding node before
/// genesis, a recovering device. Asked for every request; must answer from current state and never
/// block.
pub trait Admit: Send + Sync {
    /// Whether `peer` may read and push `group`'s log.
    fn admits(&self, peer: &PublicKey, group: &GroupId) -> bool;
}

/// Pinned keys are admitted to every group.
impl Admit for PinnedKeys {
    fn admits(&self, peer: &PublicKey, _: &GroupId) -> bool {
        self.allows(peer)
    }
}

/// Limits and timings of a [`GroupServer`].
#[derive(Debug, Clone)]
pub struct ServerConfig {
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
    /// The most entries one fetch returns (at most [`wire::MAX_FETCH`]).
    pub max_fetch: u32,
    /// The largest reply body (at most [`wire::MAX_REPLY`]); a fetch stops before it.
    pub max_reply: usize,
    /// How far ahead of the server's clock a pushed entry's time may be.
    pub max_skew_ms: i64,
    /// Pushes one peer may sustain per second of the server's clock; more are refused as busy.
    pub push_per_second: u32,
    /// Pushes one peer may make at once after being quiet.
    pub push_burst: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(60),
            header_timeout: Duration::from_secs(10),
            write_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(10),
            max_streams: 256,
            max_per_peer: 4,
            max_busy: 64,
            busy_wait: Duration::from_secs(1),
            max_fetch: wire::MAX_FETCH,
            max_reply: wire::MAX_REPLY,
            max_skew_ms: DEFAULT_SKEW_MS,
            push_per_second: 20,
            push_burst: 100,
        }
    }
}
