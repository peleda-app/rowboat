//! Who does the work of a resource or a job now.
//!
//! A [`Lease`] gives one node the right to work on one [`LeaseKey`], with a [`FencingToken`] that
//! grows on every change of holder, so storage can refuse a holder that lost the lease before it
//! notices. Nodes have a [`NodeClass`]: a server outranks a desktop, a desktop outranks a phone, a
//! blind node never leads. A stronger node does not steal a live lease: it asks for a takeover,
//! the holder hands over at a safe point, and the lease is reserved for the requester meanwhile.
//!
//! [`record`] holds the one implementation of these rules as a pure state machine; every
//! [`Leases`] implementation in Baton applies it, so they cannot drift apart.

pub mod record;
#[cfg(feature = "testing")]
pub mod testing;

use async_trait::async_trait;
use baton_core::{FencingToken, GroupId, LeaseKey, NodeId, Timestamp};
use serde::{Deserialize, Serialize};

/// Errors of the lease contracts.
#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    /// Leases cannot be decided right now (no quorum, arbiter unreachable); the caller must not
    /// act as holder and may retry later.
    #[error("leases cannot be decided now")]
    Unavailable,
    /// The stored lease record is unreadable or of an unknown version. Nothing is granted on top
    /// of it: a corrupted record never resets a fencing token.
    #[error("lease record is corrupted")]
    Corrupted,
    /// The backend failed; the call may be retried.
    #[error("lease backend failed: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl LeaseError {
    /// Wraps any backend error.
    pub fn backend(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self::Backend(e.into())
    }
}

/// What kind of node this is. Lower in the declaration order means stronger: `Server` outranks
/// `Desktop`, which outranks `Phone`. `Blind` nodes (storage, relay, arbiter without keys) never
/// hold a lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeClass {
    /// An always-on machine.
    Server,
    /// A desktop or laptop.
    Desktop,
    /// A phone or tablet: leads only as a last resort.
    Phone,
    /// Holds no keys and never leads.
    Blind,
}

impl NodeClass {
    /// Whether a node of this class may ever hold a lease.
    pub fn may_lead(self) -> bool {
        self != NodeClass::Blind
    }

    /// Whether `self` strictly outranks `other`.
    pub fn outranks(self, other: NodeClass) -> bool {
        self < other
    }
}

/// What a node can do now, announced with every heartbeat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeProfile {
    /// The node.
    pub node: NodeId,
    /// Its class.
    pub class: NodeClass,
    /// Relative capacity within its class; a node with twice the weight gets about twice the
    /// leases. Zero means it never leads.
    pub weight: u32,
    /// Whether it can run work right now (false for a phone in the background).
    pub can_run: bool,
}

impl NodeProfile {
    /// Whether this node may hold a lease at all right now.
    pub fn may_lead(&self) -> bool {
        self.class.may_lead() && self.can_run && self.weight > 0
    }
}

/// A stronger node waiting for a lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Takeover {
    /// The node that asked.
    pub node: NodeId,
    /// Its class when it asked.
    pub class: NodeClass,
}

/// A lease held by a node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    /// The group.
    pub group: GroupId,
    /// What the lease is on.
    pub key: LeaseKey,
    /// The holder.
    pub node: NodeId,
    /// The holder's class when it last acquired or renewed.
    pub class: NodeClass,
    /// The token storage checks; it grows on every change of holder.
    pub fence: FencingToken,
    /// A stronger node waiting for this lease, if any. The holder should reach a safe point and
    /// release.
    pub takeover: Option<Takeover>,
}

/// What [`Leases::request_takeover`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TakeoverOutcome {
    /// Recorded: the holder will see it on its next renewal and should release to the caller.
    Recorded,
    /// The caller already holds the lease.
    AlreadyHolder,
    /// No live holder: the caller should simply `acquire`.
    NotNeeded,
    /// Refused: the holder is as strong or stronger, or an equally strong or stronger node is
    /// already waiting, or the caller may not lead.
    Refused,
}

/// Decides who holds which lease.
///
/// Guarantees (checked by [`testing::leases`]):
///
/// - `acquire` grants when the key has no holder, when the caller already holds it (same token,
///   a renewal that also reports any pending takeover), or when the holder is no longer alive
///   (higher token). A dead holder's key with a pending takeover, or a released key reserved for
///   a takeover, is granted only to the requester, unless the requester is no longer alive or may
///   not lead, or the request has not been renewed within the liveness time-to-live. Otherwise
///   it returns `None`. A holder that announces it may not lead (for example a phone going to the
///   background) counts as gone. A node that may not
///   lead (blind, not able to run, weight zero) never gets a lease.
/// - A live holder is never replaced by `acquire`, whatever the caller's class.
/// - Tokens of one key only grow; no two grants share a token; the recorded holder is the grant
///   with the highest token, however many nodes call at once.
/// - `release` gives the lease up only if the caller still holds it with that token, and keeps
///   the token so the next holder gets a higher one.
/// - When leases cannot be decided, calls fail with [`LeaseError::Unavailable`]; a corrupted
///   record fails with [`LeaseError::Corrupted`] and grants nothing.
#[async_trait]
pub trait Leases: Send + Sync {
    /// Takes or renews a lease.
    async fn acquire(
        &self,
        group: &GroupId,
        key: &LeaseKey,
        profile: &NodeProfile,
    ) -> Result<Option<Lease>, LeaseError>;

    /// `acquire`, never below `floor` (the highest token the caller's own storage has seen for
    /// the key, perhaps from another arbiter): a new grant gets a token above `floor`, a renewal
    /// whose token is below it is granted again with one above it, and a renewal at or above it
    /// keeps its token. An implementation may ignore a floor it judges implausible (far above any
    /// token it could grant); the caller then gets a lease its storage refuses and gives it back.
    /// The default ignores the floor: callers check `lease.fence >= floor` themselves.
    async fn acquire_above(
        &self,
        group: &GroupId,
        key: &LeaseKey,
        profile: &NodeProfile,
        floor: FencingToken,
    ) -> Result<Option<Lease>, LeaseError> {
        let _ = floor;
        self.acquire(group, key, profile).await
    }

    /// Asks a weaker live holder to hand the lease over to the caller.
    async fn request_takeover(
        &self,
        group: &GroupId,
        key: &LeaseKey,
        profile: &NodeProfile,
    ) -> Result<TakeoverOutcome, LeaseError>;

    /// Gives a lease up.
    async fn release(&self, lease: &Lease) -> Result<(), LeaseError>;

    /// The current holder, if any (alive or not).
    async fn holder(&self, group: &GroupId, key: &LeaseKey) -> Result<Option<Lease>, LeaseError>;
}

/// Which nodes are alive, judged on the observer's own clock.
///
/// Guarantees (checked by [`testing::liveness`]):
///
/// - `now` is always the caller's own clock. No implementation compares one node's clock with
///   another's: a heartbeat's own timestamp never decides whether its node is alive.
/// - A node is alive for an observer while the observer has seen a new heartbeat from it within
///   [`Liveness::ttl_ms`] of its own clock. A heartbeat an observer sees for the first time (after
///   the observer started, for example) counts as new, so a restart only delays takeovers.
/// - `alive` reports the profile of the latest heartbeat, and only nodes of that group.
/// - Losing liveness data only moves leases earlier or later, never creates two writers, because
///   writes are fenced.
///
/// What a holder may rely on: after the start of its last successful heartbeat, no other node
/// treats it as gone for at least `ttl_ms` of real time. A holder therefore stops acting on a
/// lease `ttl_ms` minus a safety margin (for clock rate differences) after the start of its last
/// successful heartbeat, which is how side effects that storage cannot fence stay single.
#[async_trait]
pub trait Liveness: Send + Sync {
    /// Announces that `profile`'s node is alive in `group`.
    async fn heartbeat(
        &self,
        group: &GroupId,
        profile: &NodeProfile,
        now: Timestamp,
    ) -> Result<(), LeaseError>;

    /// Every node of `group` alive for this observer at its own time `now`.
    async fn alive(&self, group: &GroupId, now: Timestamp) -> Result<Vec<NodeProfile>, LeaseError>;

    /// The time-to-live in milliseconds.
    fn ttl_ms(&self) -> u64;
}

/// The node that should hold `key` among `nodes`: only nodes that may lead, the strongest class
/// first, and within that class weighted rendezvous hashing, so the result is the same on every
/// node that sees the same set, and when a node joins or leaves only the keys it gains or loses
/// move.
pub fn preferred<'a>(
    group: &GroupId,
    key: &LeaseKey,
    nodes: &'a [NodeProfile],
) -> Option<&'a NodeProfile> {
    let best = nodes
        .iter()
        .filter(|n| n.may_lead())
        .map(|n| n.class)
        .min()?;
    nodes
        .iter()
        .filter(|n| n.may_lead() && n.class == best)
        .map(|n| {
            let mut h = blake3::Hasher::new();
            h.update(group.as_str().as_bytes());
            h.update(&[0]);
            h.update(key.as_str().as_bytes());
            h.update(&[0]);
            h.update(n.node.as_str().as_bytes());
            let bytes = h.finalize();
            let x = u64::from_le_bytes(bytes.as_bytes()[..8].try_into().expect("8 bytes"));
            let unit = ((x >> 11) as f64 + 0.5) / (1u64 << 53) as f64;
            let score = -(n.weight as f64) / unit.ln();
            (score, n)
        })
        .max_by(|a, b| a.0.total_cmp(&b.0).then_with(|| b.1.node.cmp(&a.1.node)))
        .map(|(_, n)| n)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn node(name: &str, class: NodeClass, weight: u32) -> NodeProfile {
        NodeProfile {
            node: NodeId::new(name).unwrap(),
            class,
            weight,
            can_run: true,
        }
    }

    #[test]
    fn class_order() {
        assert!(NodeClass::Server.outranks(NodeClass::Desktop));
        assert!(NodeClass::Desktop.outranks(NodeClass::Phone));
        assert!(!NodeClass::Phone.outranks(NodeClass::Phone));
        assert!(!NodeClass::Blind.may_lead());
    }

    #[test]
    fn strongest_class_wins_and_weights_spread_within_it() {
        let g = GroupId::new("g").unwrap();
        let nodes = vec![
            node("s1", NodeClass::Server, 1),
            node("s2", NodeClass::Server, 2),
            node("d", NodeClass::Desktop, 100),
            node("p", NodeClass::Phone, 100),
            node("b", NodeClass::Blind, 100),
        ];
        let mut counts = HashMap::new();
        for i in 0..4000 {
            let k = LeaseKey::new(format!("k{i}")).unwrap();
            let p = preferred(&g, &k, &nodes).unwrap();
            *counts.entry(p.node.as_str().to_owned()).or_insert(0) += 1;
        }
        assert_eq!(counts.len(), 2, "only servers: {counts:?}");
        let ratio = counts["s2"] as f64 / counts["s1"] as f64;
        assert!((ratio - 2.0).abs() < 0.3, "{counts:?}");
    }

    #[test]
    fn falls_back_by_class_and_skips_nodes_that_cannot_run() {
        let g = GroupId::new("g").unwrap();
        let k = LeaseKey::new("k").unwrap();
        let mut phone = node("p", NodeClass::Phone, 1);
        let desktop_asleep = NodeProfile {
            can_run: false,
            ..node("d", NodeClass::Desktop, 1)
        };
        let nodes = vec![desktop_asleep.clone(), phone.clone()];
        assert_eq!(preferred(&g, &k, &nodes).unwrap().node, phone.node);
        phone.can_run = false;
        assert!(preferred(&g, &k, &[desktop_asleep, phone]).is_none());
        assert!(preferred(&g, &k, &[node("b", NodeClass::Blind, 9)]).is_none());
        assert!(preferred(&g, &k, &[node("z", NodeClass::Server, 0)]).is_none());
    }

    #[test]
    fn few_keys_move_when_a_node_leaves() {
        let g = GroupId::new("g").unwrap();
        let all = vec![
            node("a", NodeClass::Server, 1),
            node("b", NodeClass::Server, 1),
            node("c", NodeClass::Server, 1),
        ];
        let fewer = vec![all[0].clone(), all[1].clone()];
        let mut moved = 0;
        for i in 0..3000 {
            let k = LeaseKey::new(format!("k{i}")).unwrap();
            let before = preferred(&g, &k, &all).unwrap().node.clone();
            let after = preferred(&g, &k, &fewer).unwrap().node.clone();
            if before.as_str() != "c" && before != after {
                moved += 1;
            }
        }
        assert_eq!(moved, 0, "keys of the remaining nodes stay where they are");
    }
}
