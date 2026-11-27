//! Replication and commands between a person's nodes (GROUP.md, "Journal replication" and
//! "Commands from any node").
//!
//! - [`NodeAttestor`] signs every journal head this node writes with its node key
//!   (`rowboat-head-v1`); [`verify_remote`] checks a head from a peer: attested by a node that
//!   counts and holds `lead` on the account.
//! - [`heads`]: the head protocol, by which a reader asks for heads and an owner pushes them.
//! - [`PeerTier`] is a Skein `ReadTier` over `baton-fetch`: segments by hash with their name as the
//!   locator, blobs by hash under the account resources this node reads. [`Served`] is what this
//!   node serves to peers: segments of an account only to its readers, blobs only for the account
//!   they belong to.
//! - [`Replication`]: follows the journal of every account this node reads and does not lead,
//!   stages the missing segments, fetches their blobs and installs the owner's head (Skein's
//!   `Log::stage` and `Log::install`); carries commands to the owner through a durable outbox and
//!   runs the commands it receives for accounts it leads through Skein's command queue, once.
//!
//! - [`handover`]: an account's state (record, credentials, cursors, queue) sealed to the nodes
//!   that may lead it, offered by its holder and opened only by the next holder.
//!
//! A library: storage, the link, signals and the node's own knowledge arrive as contracts
//! (`Storage`, `Link`, `Signal`, [`Host`]); time arrives as a [`rowboat_group::Now`].

mod attest;
pub mod commands;
mod grant;
pub mod handover;
pub mod heads;
mod replica;
mod replication;
mod tier;

use async_trait::async_trait;
use baton_identity::PublicKey;
use skein_core::{AccountId, BlobHash};

pub use attest::{
    Grants, HEAD_CONTEXT, HEAD_CONTEXT_V2, MAX_ATTESTATION, MAX_FENCE_AHEAD_MS, NodeAttestor,
    attest, attest_granted, attestation_grant, attestation_signer, fuzz_attestation, head_grant,
    verify_remote,
};
pub use grant::{GRANT_CONTEXT, Grant, GrantKind, MAX_GRANT, fuzz_grant};
pub use heads::About;
pub use replica::Caught;
pub use replication::{Config, Replication};
pub use tier::{PeerTier, Peers, Served, fuzz_locator};

/// Why a replication or command step failed. Kinds only: never content, an address or a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SyncError {
    /// A message, head or record that does not decode or breaks a cap.
    #[error("malformed")]
    Malformed,
    /// A signature or attestation that does not verify.
    #[error("does not verify")]
    Unverified,
    /// The signer or sender may not do this in the group log.
    #[error("not authorized")]
    NotAuthorized,
    /// Two valid heads disagree: the journal forked.
    #[error("the journal forked")]
    Fork,
    /// No peer could be reached or had what was asked.
    #[error("unreachable")]
    Unreachable,
    /// A step took longer than its limit.
    #[error("timed out")]
    TimedOut,
    /// A cap was reached (the outbox is full).
    #[error("busy")]
    Busy,
    /// This node leads the account (or does not, for a command): the step belongs elsewhere.
    #[error("not here")]
    NotHere,
    /// The node's storage failed.
    #[error("storage failed")]
    Storage,
}

impl From<rowboat_group::MembershipError> for SyncError {
    fn from(e: rowboat_group::MembershipError) -> Self {
        use rowboat_group::MembershipError as M;
        match e {
            M::Malformed => Self::Malformed,
            M::TimedOut => Self::TimedOut,
            M::Unreachable => Self::Unreachable,
            M::Storage => Self::Storage,
            M::NotAuthorized => Self::NotAuthorized,
            _ => Self::Unverified,
        }
    }
}

/// How a command issued here ended without its outcome reaching this node through the journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Settled {
    /// The owner refused it, or it expired before reaching the owner; `reason` is one word of
    /// `[a-z0-9_]`.
    Failed {
        /// Why.
        reason: String,
    },
    /// It may or may not have run (the owner was interrupted between claiming and queueing it).
    Uncertain,
}

/// What the node tells replication about itself. Every method is cheap and never blocks on the
/// network.
#[async_trait]
pub trait Host: Send + Sync {
    /// Whether this node leads `account` (in wave 1: it added it). Replication never installs a
    /// head over an account this node leads, and serves commands only for those.
    fn leads(&self, account: &AccountId) -> bool;

    /// What this node says about an account it leads or whose journal it wrote last, for its
    /// readers.
    async fn about(&self, account: &AccountId) -> Option<About>;

    /// Whether `blob` belongs to `account` on this node (a message or object of it, or the blob
    /// of a command this node issued for it), so it may be served to the account's readers.
    async fn holds_blob(&self, account: &AccountId, blob: &BlobHash) -> bool;

    /// The owner of a followed account said what the account is, or said it again.
    async fn described(&self, account: &AccountId, owner: &PublicKey, about: &About);

    /// The replica of `account` moved to `seq`.
    fn installed(&self, account: &AccountId, seq: u64);

    /// Two valid heads of `account` disagree; replication stopped following it.
    fn forked(&self, account: &AccountId);

    /// A command issued here settled without its outcome coming through the journal.
    fn settled(&self, account: &AccountId, command: &str, outcome: Settled);

    /// `peer` issued a command under a group log newer than this node's: exchange logs with it.
    fn group_behind(&self, peer: &PublicKey) {
        let _ = peer;
    }

    /// Whether this node follows `signed`, a head of `account` that verified, given the grant
    /// behind its fence (`remote`, if it carries one) and the grant behind this node's own head
    /// of the account (`local`). A head refused here is ignored like a stale one: nothing is
    /// fetched, installed or dropped for it, and an offer that carries it is refused. May record
    /// what it learned (a fallback holder exists). Asked for every verified head, so it answers
    /// from memory or the node's own storage, never the network. The default admits every head.
    async fn admits(
        &self,
        account: &AccountId,
        signed: &skein_storage::SignedHead,
        remote: Option<&Grant>,
        local: Option<&Grant>,
    ) -> bool {
        let _ = (account, signed, remote, local);
        true
    }

    /// A head of `account`, which this node leads, verified and admitted under a fence above this
    /// node's own head: another arbiter or a later grant gave the account to another node, so
    /// this node no longer holds it and should stop at once. Nothing is followed for the account
    /// while this node still leads it.
    async fn superseded(&self, account: &AccountId, fence: u64) {
        let _ = (account, fence);
    }

    /// Whether this node took `account` over from an owner that went silent and may still have
    /// run what it was sent: a command this node delivered to that owner (since it started)
    /// without getting an answer then settles as [`Settled::Uncertain`] instead of being run
    /// here. False by default.
    fn previous_owner_silent(&self, account: &AccountId) -> bool {
        let _ = account;
        false
    }

    /// A holder under a higher fence continued `account` from a head before this node's own
    /// last writes: drop the local replica of the account (journal and what was derived from
    /// it), so it is followed again from the start. Nothing is followed for the account until
    /// this returns.
    async fn reset(&self, account: &AccountId) {
        let _ = account;
    }
}
