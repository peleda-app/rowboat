//! Lease grants signed by the arbiter that gave them (GROUP.md, "When the server is silent";
//! question 79), carried in head attestations so that a receiver knows which arbiter stands
//! behind a head's fence: the group's server, or a device acting as fallback arbiter while the
//! server was silent.

use baton_identity::{Identity, PublicKey, Signature};
use baton_lease::NodeClass;
use rowboat_group::Membership;
use serde::{Deserialize, Serialize};
use skein_storage::JournalHead;

use crate::SyncError;

/// The signing context of a grant.
pub const GRANT_CONTEXT: &str = "rowboat-grant-v1";
/// The largest encoded grant, in bytes.
pub const MAX_GRANT: usize = 512;
const VERSION: u8 = 1;

/// Which kind of arbiter gave a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantKind {
    /// The group's server node, its usual arbiter.
    Server,
    /// A desktop or phone arbitrating while the server was silent.
    Fallback,
}

#[derive(Serialize)]
struct Signed<'a> {
    v: u8,
    kind: GrantKind,
    arbiter: &'a PublicKey,
    group: &'a str,
    key: &'a str,
    node: &'a PublicKey,
    fence: u64,
}

/// A lease grant: `arbiter` gave `node` the lease on `key` in `group` with token `fence`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    v: u8,
    /// The arbiter's kind.
    pub kind: GrantKind,
    /// The arbiter's node key.
    pub arbiter: PublicKey,
    /// The group.
    pub group: String,
    /// The lease key (the account id).
    pub key: String,
    /// The holder.
    pub node: PublicKey,
    /// The token.
    pub fence: u64,
    signature: Signature,
}

impl Grant {
    fn message(&self) -> Vec<u8> {
        rowboat_group::wire::encode(&Signed {
            v: self.v,
            kind: self.kind,
            arbiter: &self.arbiter,
            group: &self.group,
            key: &self.key,
            node: &self.node,
            fence: self.fence,
        })
    }

    /// The encoded grant `arbiter` signs for `node`'s lease on `key` of `group` with `fence`.
    pub fn sign(
        arbiter: &Identity,
        kind: GrantKind,
        group: &str,
        key: &str,
        node: PublicKey,
        fence: u64,
    ) -> Vec<u8> {
        let mut g = Self {
            v: VERSION,
            kind,
            arbiter: arbiter.public(),
            group: group.to_owned(),
            key: key.to_owned(),
            node,
            fence,
            signature: arbiter.sign(GRANT_CONTEXT, b""),
        };
        g.signature = arbiter.sign(GRANT_CONTEXT, &g.message());
        rowboat_group::wire::encode(&g)
    }

    /// Decodes `bytes` and checks the arbiter's signature, nothing else.
    pub fn decode(bytes: &[u8]) -> Result<Self, SyncError> {
        if bytes.len() > MAX_GRANT {
            return Err(SyncError::Malformed);
        }
        let g: Self = rowboat_group::wire::decode(bytes).map_err(|_| SyncError::Malformed)?;
        if g.v != VERSION {
            return Err(SyncError::Malformed);
        }
        g.arbiter
            .verify(GRANT_CONTEXT, &g.message(), &g.signature)
            .map_err(|_| SyncError::Unverified)?;
        Ok(g)
    }

    /// Checks the grant against `head`, signed by `signer`, in `membership`'s group log now: the
    /// signature holds, it is for this group, this account, this signer and exactly this fence,
    /// and the arbiter counts and is of its kind's class (a server for [`GrantKind::Server`], a
    /// desktop or phone for [`GrantKind::Fallback`]). A revoked arbiter's grants never pass.
    pub fn check(
        bytes: &[u8],
        membership: &Membership,
        head: &JournalHead,
        signer: &PublicKey,
    ) -> Result<Self, SyncError> {
        let g = Self::decode(bytes)?;
        let matches = g.group == membership.group().as_str()
            && g.key == head.account.as_str()
            && &g.node == signer
            && g.fence == head.fence.0;
        if !matches {
            return Err(SyncError::Unverified);
        }
        let class_fits = matches!(
            (g.kind, membership.class_of(&g.arbiter)),
            (GrantKind::Server, Some(NodeClass::Server))
                | (
                    GrantKind::Fallback,
                    Some(NodeClass::Desktop | NodeClass::Phone)
                )
        );
        if !membership.counts(&g.arbiter) || !class_fits {
            return Err(SyncError::NotAuthorized);
        }
        Ok(g)
    }
}

/// Runs the grant decoder over `bytes`, for the fuzz target. Never panics.
pub fn fuzz_grant(bytes: &[u8]) {
    let _ = Grant::decode(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn a_grant_round_trips_and_its_fields_are_signed() {
        let arbiter = Identity::generate();
        let node = Identity::generate().public();
        let bytes = Grant::sign(&arbiter, GrantKind::Fallback, "g1", "acc", node, 77);
        assert!(bytes.len() <= MAX_GRANT);
        let g = Grant::decode(&bytes).unwrap();
        assert_eq!(
            (
                g.kind,
                g.arbiter,
                g.group.as_str(),
                g.key.as_str(),
                g.node,
                g.fence
            ),
            (GrantKind::Fallback, arbiter.public(), "g1", "acc", node, 77)
        );
        for fence in [76, 78] {
            let mut forged = g.clone();
            forged.fence = fence;
            assert!(Grant::decode(&rowboat_group::wire::encode(&forged)).is_err());
        }
        let mut promoted = g.clone();
        promoted.kind = GrantKind::Server;
        assert!(
            Grant::decode(&rowboat_group::wire::encode(&promoted)).is_err(),
            "the kind is signed"
        );
        let mut other = g.clone();
        other.arbiter = Identity::generate().public();
        assert!(Grant::decode(&rowboat_group::wire::encode(&other)).is_err());
        let mut v2 = g;
        v2.v = 2;
        assert!(Grant::decode(&rowboat_group::wire::encode(&v2)).is_err());
        assert!(Grant::decode(&[0; MAX_GRANT + 1]).is_err());
    }

    proptest! {
        #[test]
        fn any_bytes_decode_without_panicking(bytes in prop::collection::vec(any::<u8>(), 0..600)) {
            fuzz_grant(&bytes);
        }
    }
}
