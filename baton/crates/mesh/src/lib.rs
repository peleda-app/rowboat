//! Messages between the nodes of one mesh.
//!
//! A [`Transport`] sends small messages to a node by its id, hands incoming messages to
//! subscribers of a channel and lists the members it can reach. Every message is signed by the
//! sender's identity and checked on receipt against the roster the node trusts at that moment
//! ([`frame`]); a message that is unsigned, forged, replayed, addressed to another node or sent by
//! a non-member never reaches a subscriber.
//!
//! `baton-mesh-memory` is an in-process hub for tests that can split nodes into partitions;
//! `baton-mesh-link` carries frames over any `baton-link`.

pub mod frame;
#[cfg(feature = "testing")]
pub mod testing;

use async_trait::async_trait;
use baton_core::NodeId;
use bytes::Bytes;
use futures::stream::BoxStream;

/// Errors of the transport contract.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// The destination is known to be unreachable right now. Not getting this error does not
    /// mean the message arrived.
    #[error("node unreachable")]
    Unreachable,
    /// A channel name that is empty, longer than 64 bytes or outside `[a-z0-9/_.-]`.
    #[error("invalid channel name")]
    InvalidChannel,
    /// The message is larger than [`MAX_PAYLOAD`].
    #[error("payload too large")]
    TooLarge,
    /// The transport failed.
    #[error("transport failed: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// The largest payload a transport must carry: room for a full 64 KiB signal and its envelope.
pub const MAX_PAYLOAD: usize = 72 * 1024;

/// Messages a subscriber may have waiting before newer ones are dropped. Delivery is best
/// effort, so a subscriber that stops reading loses messages instead of growing memory.
pub const SUBSCRIBER_BUFFER: usize = 1024;

/// Checks a channel name.
pub fn check_channel(channel: &str) -> Result<(), TransportError> {
    let ok = !channel.is_empty()
        && channel.len() <= 64
        && channel.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'/' | b'_' | b'.' | b'-')
        });
    if ok {
        Ok(())
    } else {
        Err(TransportError::InvalidChannel)
    }
}

/// A message that passed every check: its sender is a member of the trusted roster and signed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// The member that sent it.
    pub from: NodeId,
    /// The channel it was sent on.
    pub channel: String,
    /// The content.
    pub payload: Bytes,
}

/// Messages between the members of one mesh.
///
/// Guarantees (checked by `testing::transport`):
///
/// - Delivery is best effort: a message may be lost, but never altered, duplicated or delivered
///   to a subscriber of another channel.
/// - Messages from one sender to one receiver arrive in the order they were sent.
/// - A subscriber gets only messages that arrived after `subscribe` returned, and only from
///   members of the roster the node trusts when the message arrives.
/// - A node never receives its own messages; components handle their local share directly.
#[async_trait]
pub trait Transport: Send + Sync {
    /// This node's id.
    fn local(&self) -> NodeId;

    /// Sends `payload` to `to` on `channel`.
    async fn send(&self, to: &NodeId, channel: &str, payload: Bytes) -> Result<(), TransportError>;

    /// Messages arriving on `channel` from now on. The stream ends when the transport shuts down.
    async fn subscribe(
        &self,
        channel: &str,
    ) -> Result<BoxStream<'static, Envelope>, TransportError>;

    /// Members of the trusted roster, other than this node, that look reachable right now. A
    /// listed peer can still lose a message.
    async fn peers(&self) -> Result<Vec<NodeId>, TransportError>;
}
