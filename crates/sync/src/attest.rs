use std::sync::Arc;

use async_trait::async_trait;
use baton_group::Capability;
use baton_identity::{Identity, PublicKey, Signature};
use bytes::Bytes;
use rowboat_group::{Membership, account_resource};
use serde::{Deserialize, Serialize};
use skein_storage::{HeadAttestor, IntegrityError, JournalHead, SignedHead, StorageError};

use crate::SyncError;
use crate::grant::{Grant, MAX_GRANT};

/// The signing context of a journal head attestation of version 1 (no grant).
pub const HEAD_CONTEXT: &str = "rowboat-head-v1";
/// The signing context of a journal head attestation of version 2, which may carry the lease
/// grant behind the head's fence ([`crate::Grant`]).
pub const HEAD_CONTEXT_V2: &str = "rowboat-head-v2";
const VERSION: u8 = 1;
const VERSION_GRANTED: u8 = 2;
/// The largest attestation, in bytes.
pub const MAX_ATTESTATION: usize = 1024;
/// How far a peer's head fence may lie ahead of this node's clock, in milliseconds. Fences are
/// lease tokens, at least the granting arbiter's wall clock in microseconds; one far ahead would
/// make every later token too low to claim the journal, and the account would stall for good.
pub const MAX_FENCE_AHEAD_MS: u64 = 5 * 60_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Attestation {
    v: u8,
    signer: PublicKey,
    signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Granted {
    v: u8,
    signer: PublicKey,
    signature: Signature,
    grant: Option<Vec<u8>>,
}

fn decode(bytes: &[u8]) -> Result<Granted, SyncError> {
    if bytes.len() > MAX_ATTESTATION || bytes.is_empty() {
        return Err(SyncError::Malformed);
    }
    match bytes[0] {
        VERSION => {
            let a: Attestation =
                rowboat_group::wire::decode(bytes).map_err(|_| SyncError::Malformed)?;
            Ok(Granted {
                v: a.v,
                signer: a.signer,
                signature: a.signature,
                grant: None,
            })
        }
        VERSION_GRANTED => {
            let a: Granted =
                rowboat_group::wire::decode(bytes).map_err(|_| SyncError::Malformed)?;
            if a.v != VERSION_GRANTED || a.grant.as_ref().is_some_and(|g| g.len() > MAX_GRANT) {
                return Err(SyncError::Malformed);
            }
            Ok(a)
        }
        _ => Err(SyncError::Malformed),
    }
}

fn granted_message(head: &JournalHead, grant: Option<&[u8]>) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    match grant {
        None => h.update(&[0]),
        Some(g) => h.update(&[1]).update(g),
    };
    let mut out = head.digest().to_vec();
    out.extend_from_slice(h.finalize().as_bytes());
    out
}

/// The node whose signature `attestation` carries, when it decodes and the signature holds for
/// `head` (and for the grant it carries, in version 2).
pub fn attestation_signer(head: &JournalHead, attestation: &[u8]) -> Result<PublicKey, SyncError> {
    let a = decode(attestation)?;
    let ok = if a.v == VERSION {
        a.signer.verify(HEAD_CONTEXT, &head.digest(), &a.signature)
    } else {
        a.signer.verify(
            HEAD_CONTEXT_V2,
            &granted_message(head, a.grant.as_deref()),
            &a.signature,
        )
    };
    ok.map_err(|_| SyncError::Unverified)?;
    Ok(a.signer)
}

/// The grant `attestation` carries for `head`, when the attestation verifies and the grant's own
/// signature holds; its standing in the group log is [`Grant::check`]'s, which
/// [`verify_remote`] runs for heads from peers.
pub fn attestation_grant(head: &JournalHead, attestation: &[u8]) -> Option<Grant> {
    attestation_signer(head, attestation).ok()?;
    Grant::decode(decode(attestation).ok()?.grant.as_deref()?).ok()
}

/// The grant of a signed head (see [`attestation_grant`]).
pub fn head_grant(signed: &SignedHead) -> Option<Grant> {
    attestation_grant(&signed.head, signed.attestation.as_deref()?)
}

/// The attestation `identity` gives `head` without a grant (see [`attest_granted`]).
pub fn attest(identity: &Identity, head: &JournalHead) -> Bytes {
    attest_granted(identity, head, None)
}

/// The attestation `identity` gives `head`, carrying `grant` (the encoded [`Grant`] behind the
/// head's fence) when given: version 2, its signature under [`HEAD_CONTEXT_V2`] over
/// [`JournalHead::digest`] and the grant's hash, with its key.
pub fn attest_granted(identity: &Identity, head: &JournalHead, grant: Option<&[u8]>) -> Bytes {
    let grant = grant.filter(|g| g.len() <= MAX_GRANT);
    Bytes::from(rowboat_group::wire::encode(&Granted {
        v: VERSION_GRANTED,
        signer: identity.public(),
        signature: identity.sign(HEAD_CONTEXT_V2, &granted_message(head, grant)),
        grant: grant.map(<[u8]>::to_vec),
    }))
}

/// Checks a head from a peer before anything is fetched for it (GROUP.md, "Heads and
/// attestation"): well formed, attested, signed by a node that counts in this node's group log
/// now and holds `lead` on the account's resource, with a fence at most [`MAX_FENCE_AHEAD_MS`]
/// ahead of `now` in microseconds, and a grant, when it carries one, that [`Grant::check`]
/// accepts. Returns the signer. Ordering against heads this node already
/// accepted (fence, `seq`, forks) is the replica's check.
pub fn verify_remote(
    membership: &Membership,
    signed: &SignedHead,
    now: baton_core::Timestamp,
) -> Result<PublicKey, SyncError> {
    signed.head.check().map_err(|_| SyncError::Malformed)?;
    let limit = (now.0.max(0) as u64)
        .saturating_add(MAX_FENCE_AHEAD_MS)
        .saturating_mul(1000);
    if signed.head.fence.0 > limit {
        return Err(SyncError::Unverified);
    }
    let attestation = signed.attestation.as_deref().ok_or(SyncError::Unverified)?;
    let signer = attestation_signer(&signed.head, attestation)?;
    let resource =
        account_resource(signed.head.account.as_str()).ok_or(SyncError::NotAuthorized)?;
    if !membership.counts(&signer) || !membership.node_may(&signer, &resource, &Capability::Lead) {
        return Err(SyncError::NotAuthorized);
    }
    if let Some(grant) = decode(attestation)?.grant {
        Grant::check(&grant, membership, &signed.head, &signer)?;
    }
    Ok(signer)
}

/// Skein's [`HeadAttestor`] for the node's own journal: every head this node writes is signed
/// with its node key ([`attest`]). Reading its own storage, it accepts a head without an
/// attestation (journals written before attestation) and a head signed by any node the group log
/// ever certified (the history of a revoked former owner stays readable); it refuses anything
/// else. Heads from peers go through [`verify_remote`] first, which is strict.
pub struct NodeAttestor {
    membership: Arc<Membership>,
    grants: std::sync::OnceLock<Arc<dyn Grants>>,
}

impl NodeAttestor {
    /// Attests with the node key of `membership` and checks signers against its log.
    pub fn new(membership: Arc<Membership>) -> Self {
        Self {
            membership,
            grants: std::sync::OnceLock::new(),
        }
    }

    /// From now on attests every head with the grant `grants` holds for its account and fence.
    /// Set once; later calls do nothing.
    pub fn set_grants(&self, grants: Arc<dyn Grants>) {
        let _ = self.grants.set(grants);
    }
}

/// Where [`NodeAttestor`] finds the grant behind a head it attests.
pub trait Grants: Send + Sync {
    /// The encoded grant this node holds for its lease on `account` with exactly `fence`, if
    /// any. Answers from memory; never blocks.
    fn grant(&self, account: &skein_core::AccountId, fence: u64) -> Option<Vec<u8>>;
}

#[async_trait]
impl HeadAttestor for NodeAttestor {
    async fn attest(&self, head: &JournalHead) -> Result<Option<Bytes>, StorageError> {
        let grant = self
            .grants
            .get()
            .and_then(|g| g.grant(&head.account, head.fence.0));
        Ok(Some(attest_granted(
            &self.membership.keys().identity,
            head,
            grant.as_deref(),
        )))
    }

    async fn verify(
        &self,
        head: &JournalHead,
        attestation: Option<&[u8]>,
    ) -> Result<(), StorageError> {
        let Some(bytes) = attestation else {
            return Ok(());
        };
        let refused = |why: &str| StorageError::Integrity(IntegrityError::Attestation(why.into()));
        let signer = attestation_signer(head, bytes).map_err(|_| refused("bad signature"))?;
        if !self.membership.was_certified(&signer) {
            return Err(refused("unknown signer"));
        }
        Ok(())
    }
}

/// Runs the attestation decoder over `bytes`, for the fuzz target. Never panics.
pub fn fuzz_attestation(bytes: &[u8]) {
    let _ = decode(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use baton_core::{GroupId, Timestamp};
    use baton_keys::{KemSecret, RecoveryRoot};
    use baton_lease::NodeClass;
    use baton_state_memory::MemoryState;
    use proptest::prelude::*;
    use rowboat_group::{DAY_MS, NodeKeys};
    use skein_core::{AccountId, FencingToken, Seq, TenantId};

    async fn membership() -> Arc<Membership> {
        let member = Identity::generate();
        let now: rowboat_group::Now = Arc::new(|| Timestamp(1_800_000_000_000));
        Arc::new(
            Membership::found(
                Arc::new(MemoryState::new()),
                GroupId::new("gtestgroup").unwrap(),
                NodeKeys {
                    identity: Identity::generate(),
                    kem: KemSecret::generate(),
                    member: Some(member),
                },
                RecoveryRoot::generate().public(),
                RecoveryRoot::generate().public(),
                NodeClass::Desktop,
                Timestamp(1_800_000_000_000 + 400 * DAY_MS),
                now,
            )
            .await
            .unwrap(),
        )
    }

    fn head(seq: u64) -> JournalHead {
        JournalHead {
            seq: Seq(seq),
            fence: FencingToken(1),
            ..JournalHead::empty(TenantId::new("t").unwrap(), AccountId::new("a").unwrap())
        }
    }

    #[tokio::test]
    async fn the_node_attests_its_heads_and_refuses_others() {
        let m = membership().await;
        let attestor = NodeAttestor::new(m.clone());
        let h = JournalHead::empty(TenantId::new("t").unwrap(), AccountId::new("a").unwrap());
        let a = attestor.attest(&h).await.unwrap().unwrap();
        attestor.verify(&h, Some(&a)).await.unwrap();
        assert_eq!(attestation_signer(&h, &a).unwrap(), m.node());
        attestor.verify(&h, None).await.unwrap();
        let other = JournalHead {
            fence: FencingToken(9),
            ..h.clone()
        };
        assert!(
            attestor.verify(&other, Some(&a)).await.is_err(),
            "another head"
        );
        let mut flipped = a.to_vec();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        assert!(attestor.verify(&h, Some(&flipped)).await.is_err());
        let stranger = attest(&Identity::generate(), &h);
        assert!(
            attestor.verify(&h, Some(&stranger)).await.is_err(),
            "never certified"
        );
        let id = &m.keys().identity;
        let wrong_context = rowboat_group::wire::encode(&Attestation {
            v: VERSION,
            signer: id.public(),
            signature: id.sign("skein journal head v1", &h.digest()),
        });
        assert!(attestor.verify(&h, Some(&wrong_context)).await.is_err());
        let future = rowboat_group::wire::encode(&Attestation {
            v: 3,
            signer: id.public(),
            signature: id.sign(HEAD_CONTEXT, &h.digest()),
        });
        assert!(attestor.verify(&h, Some(&future)).await.is_err());
        assert!(
            attestor
                .verify(&h, Some(&[0; MAX_ATTESTATION + 1]))
                .await
                .is_err()
        );
        assert!(
            verify_remote(
                &m,
                &SignedHead {
                    head: head(3),
                    attestation: None
                },
                Timestamp(1_800_000_000_000)
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn a_grant_travels_signed_with_the_head() {
        let m = membership().await;
        let id = &m.keys().identity;
        let h = head(3);
        let v1 = rowboat_group::wire::encode(&Attestation {
            v: VERSION,
            signer: id.public(),
            signature: id.sign(HEAD_CONTEXT, &h.digest()),
        });
        assert_eq!(
            attestation_signer(&h, &v1).unwrap(),
            m.node(),
            "version 1 still reads"
        );
        assert!(attestation_grant(&h, &v1).is_none());
        let grant = Grant::sign(
            id,
            crate::GrantKind::Fallback,
            m.group().as_str(),
            "a",
            m.node(),
            h.fence.0,
        );
        let a = attest_granted(id, &h, Some(&grant));
        assert!(a.len() <= MAX_ATTESTATION);
        assert_eq!(attestation_signer(&h, &a).unwrap(), m.node());
        let g = attestation_grant(&h, &a).unwrap();
        Grant::check(&grant, &m, &h, &m.node()).unwrap();
        assert_eq!(g.fence, 1);
        let other = Grant::sign(
            id,
            crate::GrantKind::Fallback,
            m.group().as_str(),
            "a",
            m.node(),
            h.fence.0 + 1,
        );
        let mut swapped: Granted = rowboat_group::wire::decode(&a).unwrap();
        swapped.grant = Some(other.clone());
        let swapped = rowboat_group::wire::encode(&swapped);
        assert!(
            attestation_signer(&h, &swapped).is_err(),
            "a grant cannot be swapped under the signer's signature"
        );
        let mut stripped: Granted = rowboat_group::wire::decode(&a).unwrap();
        stripped.grant = None;
        assert!(
            attestation_signer(&h, &rowboat_group::wire::encode(&stripped)).is_err(),
            "nor stripped"
        );
        assert_eq!(
            Grant::check(&other, &m, &h, &m.node()),
            Err(SyncError::Unverified),
            "another fence"
        );
        let promoted = Grant::sign(
            id,
            crate::GrantKind::Server,
            m.group().as_str(),
            "a",
            m.node(),
            h.fence.0,
        );
        assert_eq!(
            Grant::check(&promoted, &m, &h, &m.node()),
            Err(SyncError::NotAuthorized),
            "a desktop never gives server grants"
        );
        let stranger = Identity::generate();
        let foreign = Grant::sign(
            &stranger,
            crate::GrantKind::Fallback,
            m.group().as_str(),
            "a",
            m.node(),
            h.fence.0,
        );
        assert_eq!(
            Grant::check(&foreign, &m, &h, &m.node()),
            Err(SyncError::NotAuthorized),
            "an arbiter that does not count"
        );
        let elsewhere = Grant::sign(id, crate::GrantKind::Fallback, "gother", "a", m.node(), 1);
        assert!(Grant::check(&elsewhere, &m, &h, &m.node()).is_err());
        let for_another = Grant::sign(
            id,
            crate::GrantKind::Fallback,
            m.group().as_str(),
            "a",
            stranger.public(),
            1,
        );
        assert!(Grant::check(&for_another, &m, &h, &m.node()).is_err());
        let big = vec![7; MAX_GRANT + 1];
        let a = attest_granted(id, &h, Some(&big));
        assert!(
            attestation_grant(&h, &a).is_none(),
            "an oversized grant is never attached"
        );
    }

    proptest! {
        #[test]
        fn any_bytes_decode_without_panicking(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
            fuzz_attestation(&bytes);
            let _ = attestation_signer(&head(1), &bytes);
        }
    }
}
