//! The node's group (GROUP.md, phases 2 and 3): who the node's peers are and how a node gets in.
//!
//! - [`Membership`]: the node's copy of the Baton group log ([`baton_group::GroupLog`]), kept in
//!   the node's `StateStore`, that only moves forward; the node's capabilities on its resources;
//!   certification of new nodes, revocation with key rotation and renewal of the node's own
//!   certificate; a [`baton_link::Trust`] that admits exactly the nodes the log counts.
//! - [`invite`]: the QR payload, the short code and the pairing address.
//! - [`pairing`]: pairing over a short-lived endpoint with CPace ([`baton_identity::Pake`]), key
//!   confirmation, a sealed channel, the fingerprint both screens show and the person confirms,
//!   and attempt limits.
//! - [`sync`]: the group log exchange between nodes over the node's link (`peleda/group/1`).
//! - [`notice`]: revocation notices for revoked nodes (`peleda/revoked/1`, B4).
//! - [`wire`]: the length-prefixed, canonically encoded frames the node's link protocols share.
//!
//! A library: storage, transports and the person's confirmation arrive as contracts
//! (`StateStore`, `Endpoints`/`Link`, [`pairing::Confirm`]); time arrives as a [`Now`].

pub mod invite;
mod membership;
pub mod notice;
pub mod pairing;
mod resources;
pub mod sync;
pub mod wire;

use std::sync::Arc;

use baton_core::Timestamp;

pub use membership::{
    MAX_SKEW_MS, Membership, MembershipEvent, NodeKeys, NodeView, PeerRecord, Revocation,
};
pub use resources::{ACCOUNT_KIND, account_resource, node_resource};

/// Where the group reads the time: certificate expiry, invite expiry and entry times.
pub type Now = Arc<dyn Fn() -> Timestamp + Send + Sync>;

/// A day in milliseconds.
pub const DAY_MS: i64 = 24 * 60 * 60 * 1000;

/// Why a group operation failed. Kinds only: never a code, a key, a label or an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MembershipError {
    /// Text, a frame or a message that does not decode, or breaks a cap.
    #[error("malformed input")]
    Malformed,
    /// The pairing code did not open the handshake: a wrong code, or an invite that expired, was
    /// used up, withdrawn or never existed. The joining side cannot tell these apart, by design.
    #[error("wrong pairing code")]
    WrongCode,
    /// The pairing failed after the code was accepted: the peer refused this node or broke the
    /// protocol.
    #[error("pairing refused")]
    Refused,
    /// The person said the fingerprints do not match, or did not answer in time.
    #[error("pairing rejected by the person")]
    Rejected,
    /// The peer could not be reached.
    #[error("unreachable")]
    Unreachable,
    /// A step took longer than its limit.
    #[error("timed out")]
    TimedOut,
    /// Too many pairings at once, or too many pending invites.
    #[error("busy")]
    Busy,
    /// This node may not do this: it holds no member key, does not count in the log, or lacks
    /// the capability.
    #[error("not authorized")]
    NotAuthorized,
    /// The node named does not exist in the group.
    #[error("not found")]
    NotFound,
    /// The change breaks a rule of the group log (revoking itself, a duplicate key, ...).
    #[error("invalid change")]
    Invalid,
    /// A log from a peer or the store that does not continue this one, or forks it.
    #[error("the group log forked")]
    Fork,
    /// The log from a peer or the store does not verify.
    #[error("the group log does not verify")]
    Unverified,
    /// The node's storage failed.
    #[error("storage failed")]
    Storage,
}

impl From<baton_group::GroupError> for MembershipError {
    fn from(e: baton_group::GroupError) -> Self {
        use baton_group::GroupError as G;
        match e {
            G::Malformed => Self::Malformed,
            G::Chain | G::Fork => Self::Fork,
            G::BadSignature => Self::Unverified,
            G::NotAuthorized(_) => Self::NotAuthorized,
            G::Invalid(_) => Self::Invalid,
            G::Backend(_) => Self::Storage,
        }
    }
}

#[cfg(test)]
pub(crate) mod fixtures;
