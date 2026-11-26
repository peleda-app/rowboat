//! The group log: who is in a group, which nodes they have, who may do what with each resource,
//! and which key epochs exist.
//!
//! The log is a hash-chained sequence of [`Entry`]s, each signed by a certified node (or, for
//! recovery actions, by a recovery key) and checked against the roles and capabilities in force
//! at the previous entry. [`GroupState`] is the result of applying a verified log; [`GroupLog`]
//! keeps the entries and builds new ones; [`store`] keeps a log in a `StateStore`, where
//! appending with `put_if_absent` orders concurrent writers; [`epochs`] seals resource keys to
//! exactly the authorized nodes and recovery keys.
//!
//! A pure library apart from [`store`], which works through the `StateStore` contract.

pub mod epochs;
mod state;
pub mod store;

use std::collections::BTreeSet;

use baton_core::{GroupId, ResourceId, Timestamp};
use baton_identity::{Identity, PublicKey, Signature};
use baton_keys::{KemPublic, RecoveryPublic, SealedBox};
use baton_lease::NodeClass;
use serde::{Deserialize, Serialize};

pub use state::{GroupState, HeadCheck, ResourceState};

/// The entry format version.
pub const ENTRY_VERSION: u8 = 1;

/// The largest encoded entry accepted, in bytes.
pub const MAX_ENTRY: usize = 1024 * 1024;

const ENTRY_CONTEXT: &str = "baton-group-entry-v1";
const CERT_CONTEXT: &str = "baton-node-cert-v1";

/// Why an entry or a log was refused. Carries no secret.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GroupError {
    /// Bytes that are not an entry, or an entry over [`MAX_ENTRY`].
    #[error("malformed entry")]
    Malformed,
    /// An entry of another group, out of sequence, or not chained to the previous one.
    #[error("entry does not continue this log")]
    Chain,
    /// A signature that does not verify.
    #[error("bad signature")]
    BadSignature,
    /// The signer may not make this change at this point of the log.
    #[error("not authorized: {0}")]
    NotAuthorized(&'static str),
    /// The change is inconsistent with the state (unknown member, duplicate, wrong epoch, ...).
    #[error("invalid change: {0}")]
    Invalid(&'static str),
    /// Two different entries claim the same place in the log.
    #[error("the log forked")]
    Fork,
    /// A store or a key operation failed.
    #[error("backend failed: {0}")]
    Backend(String),
}

/// A member's role in the group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Uses what they were granted, manages their own nodes and private resources.
    Member,
    /// Adds and removes members, certifies nodes for anyone, administers resources.
    Admin,
    /// Everything, including adding and removing admins and owners.
    Owner,
}

/// What a principal may do with one resource.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Open the resource's data, receive its signals, fetch its objects.
    Read,
    /// Hold the lease and use the resource's secrets.
    Lead,
    /// Grant and revoke on this resource, rotate its keys.
    Admin,
    /// Issue commands of one class (1–32 bytes of `[a-z0-9_-]`); needs `Read`.
    Command(String),
}

/// Who a grant names: a member (all their certified nodes) or one node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Principal {
    /// A member key.
    Member(PublicKey),
    /// A node key.
    Node(PublicKey),
}

/// A node certificate: signed by the member the node belongs to and by the node itself, so
/// nobody can certify a key they do not hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeCert {
    /// The node's signing key (its id).
    pub node: PublicKey,
    /// The node's KEM key, which key boxes are sealed to.
    pub kem: KemPublic,
    /// The node's class.
    pub class: NodeClass,
    /// The member the node belongs to.
    pub member: PublicKey,
    /// Until when the certificate is valid (by entry time).
    pub expires: Timestamp,
    /// The member's signature over the fields above.
    pub signature: Signature,
    /// The node's own signature over the fields above.
    pub node_signature: Signature,
}

#[derive(Serialize)]
struct CertBody<'a> {
    node: &'a PublicKey,
    kem: &'a KemPublic,
    class: NodeClass,
    member: &'a PublicKey,
    expires: Timestamp,
}

const NODE_PROOF_CONTEXT: &str = "baton-node-cert-proof-v1";

impl NodeCert {
    /// A certificate for `node` with KEM key `kem`, signed by `member` and by `node`.
    pub fn new(
        member: &Identity,
        node: &Identity,
        kem: KemPublic,
        class: NodeClass,
        expires: Timestamp,
    ) -> Self {
        let body = postcard::to_stdvec(&CertBody {
            node: &node.public(),
            kem: &kem,
            class,
            member: &member.public(),
            expires,
        })
        .expect("a certificate serializes");
        Self {
            node: node.public(),
            kem,
            class,
            member: member.public(),
            expires,
            signature: member.sign(CERT_CONTEXT, &body),
            node_signature: node.sign(NODE_PROOF_CONTEXT, &body),
        }
    }

    fn verify(&self) -> Result<(), GroupError> {
        let body = postcard::to_stdvec(&CertBody {
            node: &self.node,
            kem: &self.kem,
            class: self.class,
            member: &self.member,
            expires: self.expires,
        })
        .expect("a certificate serializes");
        self.member
            .verify(CERT_CONTEXT, &body, &self.signature)
            .map_err(|_| GroupError::BadSignature)?;
        self.node
            .verify(NODE_PROOF_CONTEXT, &body, &self.node_signature)
            .map_err(|_| GroupError::BadSignature)
    }
}

/// Commitments to one epoch's keys, recorded in the log: anyone opening a box can check that the
/// keys inside are the epoch's keys, so a forged or wrong box is detected instead of trusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitments {
    /// Commitment to the data key.
    pub data: [u8; 32],
    /// Commitment to the secret key.
    pub secret: [u8; 32],
}

impl Commitments {
    /// Commits to a data key and a secret key (BLAKE3 key derivation under fixed contexts,
    /// which reveals nothing about the keys).
    pub fn of(data: &[u8; 32], secret: &[u8; 32]) -> Self {
        Self {
            data: blake3::derive_key("baton-epoch-commit/v1 data", data),
            secret: blake3::derive_key("baton-epoch-commit/v1 secret", secret),
        }
    }
}

/// Who a key box is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Recipient {
    /// A certified node, by its signing key.
    Node(PublicKey),
    /// A recovery key, by its recovery signing key.
    Recovery(PublicKey),
}

/// One resource epoch's keys sealed to one recipient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyBox {
    /// Who can open it.
    pub recipient: Recipient,
    /// The data key.
    pub data: SealedBox,
    /// The secret key, for recipients that may lead (and recovery keys).
    pub secret: Option<SealedBox>,
}

/// A change to the group.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    /// The first entry: the founding owner, their recovery key, the group's recovery key and the
    /// founding node.
    Genesis {
        /// The owner's member key.
        owner: PublicKey,
        /// The owner's recovery key.
        owner_recovery: RecoveryPublic,
        /// The group's recovery key (covers shared resources).
        group_recovery: RecoveryPublic,
        /// The founding node, certified by the owner.
        founder: NodeCert,
    },
    /// A new member.
    AddMember {
        /// The member key.
        member: PublicKey,
        /// The member's recovery key.
        recovery: RecoveryPublic,
        /// The role.
        role: Role,
    },
    /// A member leaves or is removed; their nodes stop counting.
    RemoveMember {
        /// The member key.
        member: PublicKey,
    },
    /// A member's key is replaced (every device holding it was lost): signed by the member's
    /// recovery key; the role, recovery key and grants move to the new key, and the old key and
    /// its nodes stop counting.
    RekeyMember {
        /// The old member key.
        member: PublicKey,
        /// The new member key.
        new_key: PublicKey,
    },
    /// A node joins.
    CertifyNode {
        /// Its certificate.
        cert: NodeCert,
    },
    /// A node is revoked for good.
    RevokeNode {
        /// Its key.
        node: PublicKey,
    },
    /// A new resource; its creator's member gets read, lead and admin on it.
    CreateResource {
        /// Its id.
        resource: ResourceId,
    },
    /// Sets a principal's capabilities on a resource (replacing earlier ones).
    Grant {
        /// The resource.
        resource: ResourceId,
        /// Who.
        principal: Principal,
        /// What.
        capabilities: BTreeSet<Capability>,
    },
    /// A new key epoch of a resource, sealed to exactly the recipients authorized now.
    KeyEpoch {
        /// The resource.
        resource: ResourceId,
        /// The epoch number, one more than the last.
        epoch: u64,
        /// Commitments to the epoch's keys.
        commitments: Commitments,
        /// One box per recipient.
        boxes: Vec<KeyBox>,
    },
    /// Boxes of an existing epoch for recipients authorized now that lack them (a new device).
    ShareEpoch {
        /// The resource.
        resource: ResourceId,
        /// The epoch.
        epoch: u64,
        /// The added boxes.
        boxes: Vec<KeyBox>,
    },
    /// A point a recovery key vouches for; restores may start trusting from here.
    Checkpoint,
    /// A new recovery key for a member (`Some`) or the group (`None`).
    RotateRecovery {
        /// Whose.
        member: Option<PublicKey>,
        /// The new key.
        recovery: RecoveryPublic,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Body {
    v: u8,
    group: GroupId,
    seq: u64,
    prev: [u8; 32],
    at: Timestamp,
    signer: PublicKey,
    op: Op,
}

/// One signed entry of a group log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    body: Body,
    signature: Signature,
}

impl Entry {
    fn sign(
        identity: &Identity,
        group: &GroupId,
        seq: u64,
        prev: [u8; 32],
        at: Timestamp,
        op: Op,
    ) -> Self {
        let body = Body {
            v: ENTRY_VERSION,
            group: group.clone(),
            seq,
            prev,
            at,
            signer: identity.public(),
            op,
        };
        let bytes = postcard::to_stdvec(&body).expect("an entry serializes");
        let signature = identity.sign(ENTRY_CONTEXT, &bytes);
        Self { body, signature }
    }

    /// Parses an entry and checks its signature (not its place in a log).
    pub fn decode(bytes: &[u8]) -> Result<Self, GroupError> {
        if bytes.len() > MAX_ENTRY {
            return Err(GroupError::Malformed);
        }
        let entry: Entry = postcard::from_bytes(bytes).map_err(|_| GroupError::Malformed)?;
        if entry.body.v != ENTRY_VERSION || entry.encode() != bytes {
            return Err(GroupError::Malformed);
        }
        entry.verify_signature()?;
        Ok(entry)
    }

    /// The wire form.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("an entry serializes")
    }

    /// The BLAKE3 hash of the wire form; the next entry's `prev`.
    pub fn hash(&self) -> [u8; 32] {
        *blake3::hash(&self.encode()).as_bytes()
    }

    fn verify_signature(&self) -> Result<(), GroupError> {
        let bytes = postcard::to_stdvec(&self.body).expect("an entry serializes");
        self.body
            .signer
            .verify(ENTRY_CONTEXT, &bytes, &self.signature)
            .map_err(|_| GroupError::BadSignature)
    }

    /// The position in the log.
    pub fn seq(&self) -> u64 {
        self.body.seq
    }

    /// The group.
    pub fn group(&self) -> &GroupId {
        &self.body.group
    }

    /// Who signed it.
    pub fn signer(&self) -> &PublicKey {
        &self.body.signer
    }

    /// The change.
    pub fn op(&self) -> &Op {
        &self.body.op
    }

    /// The signer's time when it was made (informational, and the reference for certificate
    /// expiry).
    pub fn at(&self) -> Timestamp {
        self.body.at
    }
}

/// What a group starts from.
pub struct Founding<'a> {
    /// The founding owner's member key.
    pub owner: &'a Identity,
    /// The owner's recovery key.
    pub owner_recovery: RecoveryPublic,
    /// The group's recovery key.
    pub group_recovery: RecoveryPublic,
    /// The founding node, which signs genesis.
    pub node: &'a Identity,
    /// The founding node's KEM key.
    pub node_kem: KemPublic,
    /// The founding node's class.
    pub class: NodeClass,
    /// Until when the founding node's certificate is valid.
    pub expires: Timestamp,
}

/// A verified log and the state it produces.
#[derive(Debug, Clone)]
pub struct GroupLog {
    entries: Vec<Entry>,
    state: GroupState,
}

impl GroupLog {
    /// Starts a group from `founding`, signed at `at` by the founding node.
    pub fn genesis(
        group: GroupId,
        founding: Founding<'_>,
        at: Timestamp,
    ) -> Result<Self, GroupError> {
        let founder = NodeCert::new(
            founding.owner,
            founding.node,
            founding.node_kem,
            founding.class,
            founding.expires,
        );
        let op = Op::Genesis {
            owner: founding.owner.public(),
            owner_recovery: founding.owner_recovery,
            group_recovery: founding.group_recovery,
            founder,
        };
        let entry = Entry::sign(founding.node, &group, 0, [0; 32], at, op);
        Self::verify(vec![entry])
    }

    /// Verifies `entries` from genesis and returns the log.
    pub fn verify(entries: Vec<Entry>) -> Result<Self, GroupError> {
        let mut iter = entries.into_iter();
        let first = iter.next().ok_or(GroupError::Chain)?;
        first.verify_signature()?;
        let state = GroupState::from_genesis(&first)?;
        let mut log = Self {
            entries: vec![first],
            state,
        };
        for e in iter {
            log.apply(e)?;
        }
        Ok(log)
    }

    /// Verifies and appends one entry made elsewhere.
    pub fn apply(&mut self, entry: Entry) -> Result<(), GroupError> {
        entry.verify_signature()?;
        if entry.body.group != self.state.group
            || entry.body.seq != self.entries.len() as u64
            || entry.body.prev != self.head_hash()
        {
            return Err(GroupError::Chain);
        }
        self.state.apply(&entry)?;
        self.entries.push(entry);
        Ok(())
    }

    /// Like [`GroupLog::apply`] for an entry arriving now from a peer or a store: refuses entry
    /// times more than `max_skew_ms` ahead of `now`, so nobody can push the log into the future.
    pub fn apply_fresh(
        &mut self,
        entry: Entry,
        now: Timestamp,
        max_skew_ms: i64,
    ) -> Result<(), GroupError> {
        if entry.at() > now.plus_ms(max_skew_ms) {
            return Err(GroupError::Invalid("an entry from the future"));
        }
        self.apply(entry)
    }

    /// The hash of the genesis entry: the group's fingerprint, to keep on the recovery sheet so a
    /// restore can refuse a forged genesis.
    pub fn genesis_hash(&self) -> [u8; 32] {
        self.entries[0].hash()
    }

    /// Signs `op` with `signer` as the next entry, verifies it against the current state and
    /// appends it; returns the entry so it can be stored and shared.
    pub fn append(
        &mut self,
        signer: &Identity,
        op: Op,
        at: Timestamp,
    ) -> Result<Entry, GroupError> {
        let entry = Entry::sign(
            signer,
            &self.state.group,
            self.entries.len() as u64,
            self.head_hash(),
            at,
            op,
        );
        self.apply(entry.clone())?;
        Ok(entry)
    }

    /// The current state.
    pub fn state(&self) -> &GroupState {
        &self.state
    }

    /// Every entry, from genesis.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The sequence number of the last entry.
    pub fn head_seq(&self) -> u64 {
        self.entries.len() as u64 - 1
    }

    /// The hash of the last entry.
    pub fn head_hash(&self) -> [u8; 32] {
        self.entries.last().expect("a log has a genesis").hash()
    }

    /// How a head reported by a peer or a store relates to this log: the same, behind (a stale
    /// copy or a rollback), ahead (fetch the missing entries), or a fork (proof of a lying
    /// store, arbiter or member).
    pub fn check_head(&self, seq: u64, hash: [u8; 32]) -> HeadCheck {
        match self.entries.get(seq as usize) {
            Some(e) if e.hash() == hash && seq == self.head_seq() => HeadCheck::Same,
            Some(e) if e.hash() == hash => HeadCheck::Behind,
            Some(_) => HeadCheck::Fork,
            None => HeadCheck::Ahead,
        }
    }
}

#[cfg(test)]
mod review_tests;
#[cfg(test)]
mod tests;
