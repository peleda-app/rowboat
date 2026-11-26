use std::sync::{Arc, RwLock};

use baton_core::{GroupId, NodeId};
use serde::{Deserialize, Serialize};

use crate::{Identity, IdentityError, PublicKey, Signature};

const ROSTER_CONTEXT: &str = "baton-roster-v1";

#[derive(Serialize)]
struct Body<'a> {
    group: &'a GroupId,
    epoch: u64,
    members: &'a [PublicKey],
    revoked: &'a [PublicKey],
    signer: &'a PublicKey,
}

/// The signed list of a group's member nodes.
///
/// Guarantees, checked by [`Roster::verify`] and [`Roster::verify_successor`]:
///
/// - members are sorted and unique, there is at least one, and none of them is revoked;
/// - the signer is a member, and the signature covers group, epoch, members, revoked keys and
///   signer;
/// - a successor has the same group, a higher epoch, is signed by a member of the roster it
///   follows, and keeps every revoked key revoked, so a revoked key never comes back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roster {
    group: GroupId,
    epoch: u64,
    members: Vec<PublicKey>,
    revoked: Vec<PublicKey>,
    signer: PublicKey,
    signature: Signature,
}

impl Roster {
    /// The first roster of a group: epoch 1 with `founder` as the only member. Whoever receives
    /// it must trust it out of band (it is the founder's own device, or it arrives by pairing).
    pub fn genesis(founder: &Identity, group: GroupId) -> Self {
        Self::signed(founder, group, 1, vec![founder.public()], Vec::new())
    }

    fn signed(
        signer: &Identity,
        group: GroupId,
        epoch: u64,
        mut members: Vec<PublicKey>,
        mut revoked: Vec<PublicKey>,
    ) -> Self {
        members.sort();
        members.dedup();
        revoked.sort();
        revoked.dedup();
        let signer_key = signer.public();
        let body = encode_body(&group, epoch, &members, &revoked, &signer_key);
        Self {
            signature: signer.sign(ROSTER_CONTEXT, &body),
            group,
            epoch,
            members,
            revoked,
            signer: signer_key,
        }
    }

    /// The group.
    pub fn group(&self) -> &GroupId {
        &self.group
    }

    /// The epoch; every change of members raises it.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The members, sorted by key bytes.
    pub fn members(&self) -> &[PublicKey] {
        &self.members
    }

    /// Every key ever revoked in this group, sorted.
    pub fn revoked(&self) -> &[PublicKey] {
        &self.revoked
    }

    /// The member that signed this roster.
    pub fn signer(&self) -> &PublicKey {
        &self.signer
    }

    /// Whether `key` is a member.
    pub fn is_member(&self, key: &PublicKey) -> bool {
        self.members.binary_search(key).is_ok()
    }

    /// Whether the node with id `node` is a member.
    pub fn contains_node(&self, node: &NodeId) -> bool {
        PublicKey::from_node_id(node).is_ok_and(|k| self.is_member(&k))
    }

    /// The members' node ids, in member order.
    pub fn member_ids(&self) -> Vec<NodeId> {
        self.members.iter().map(PublicKey::node_id).collect()
    }

    /// The smallest number of members that forms a majority.
    pub fn quorum(&self) -> usize {
        self.members.len() / 2 + 1
    }

    /// Checks the roster on its own: structure and signature. Says nothing about whether the
    /// roster should be trusted; that needs [`Roster::verify_successor`] from a trusted roster.
    pub fn verify(&self) -> Result<(), IdentityError> {
        let sorted_unique = |v: &[PublicKey]| v.windows(2).all(|w| w[0] < w[1]);
        if self.members.is_empty()
            || !sorted_unique(&self.members)
            || !sorted_unique(&self.revoked)
            || self
                .members
                .iter()
                .any(|m| self.revoked.binary_search(m).is_ok())
            || !self.is_member(&self.signer)
        {
            return Err(IdentityError::InconsistentRoster);
        }
        let body = encode_body(
            &self.group,
            self.epoch,
            &self.members,
            &self.revoked,
            &self.signer,
        );
        self.signer.verify(ROSTER_CONTEXT, &body, &self.signature)
    }

    /// Checks that `next` may replace this roster.
    pub fn verify_successor(&self, next: &Roster) -> Result<(), IdentityError> {
        next.verify()?;
        if next.group != self.group {
            return Err(IdentityError::GroupMismatch);
        }
        if next.epoch <= self.epoch {
            return Err(IdentityError::StaleEpoch);
        }
        if self.revoked.binary_search(&next.signer).is_ok() {
            return Err(IdentityError::Revoked);
        }
        if !self.is_member(&next.signer) {
            return Err(IdentityError::NotMember);
        }
        if self
            .revoked
            .iter()
            .any(|r| next.revoked.binary_search(r).is_err())
        {
            return Err(IdentityError::InconsistentRoster);
        }
        Ok(())
    }

    /// The next roster with `key` added, signed by `signer`, who must be a member.
    pub fn with_member(&self, signer: &Identity, key: PublicKey) -> Result<Roster, IdentityError> {
        self.check_signer(signer)?;
        if self.revoked.binary_search(&key).is_ok() {
            return Err(IdentityError::Revoked);
        }
        if self.is_member(&key) {
            return Err(IdentityError::AlreadyMember);
        }
        let mut members = self.members.clone();
        members.push(key);
        Ok(Self::signed(
            signer,
            self.group.clone(),
            self.epoch + 1,
            members,
            self.revoked.clone(),
        ))
    }

    /// The next roster with `key` revoked, signed by `signer`, who must be another member.
    pub fn without_member(
        &self,
        signer: &Identity,
        key: &PublicKey,
    ) -> Result<Roster, IdentityError> {
        self.check_signer(signer)?;
        if *key == signer.public() {
            return Err(IdentityError::SelfRevocation);
        }
        if !self.is_member(key) {
            return Err(IdentityError::NotMember);
        }
        let members = self.members.iter().filter(|m| *m != key).copied().collect();
        let mut revoked = self.revoked.clone();
        revoked.push(*key);
        Ok(Self::signed(
            signer,
            self.group.clone(),
            self.epoch + 1,
            members,
            revoked,
        ))
    }

    fn check_signer(&self, signer: &Identity) -> Result<(), IdentityError> {
        if self.is_member(&signer.public()) {
            Ok(())
        } else {
            Err(IdentityError::NotMember)
        }
    }

    /// The wire form.
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("a roster always serializes")
    }

    /// Parses the wire form and runs [`Roster::verify`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Roster, IdentityError> {
        let roster: Roster = postcard::from_bytes(bytes).map_err(|_| IdentityError::Malformed)?;
        roster.verify()?;
        Ok(roster)
    }
}

fn encode_body(
    group: &GroupId,
    epoch: u64,
    members: &[PublicKey],
    revoked: &[PublicKey],
    signer: &PublicKey,
) -> Vec<u8> {
    postcard::to_stdvec(&Body {
        group,
        epoch,
        members,
        revoked,
        signer,
    })
    .expect("a roster body always serializes")
}

/// The roster a node currently trusts, shared by every part of the node.
///
/// Guarantees: it only ever holds a roster that passed [`Roster::verify`], and it only moves to a
/// roster that passes [`Roster::verify_successor`] from the one it holds, so its epoch only grows.
/// Readers always see a whole roster, never a mix of two.
#[derive(Debug, Clone)]
pub struct RosterHandle(Arc<RwLock<Roster>>);

impl RosterHandle {
    /// Starts from a roster trusted out of band (genesis, pairing or the node's own storage).
    pub fn new(trusted: Roster) -> Result<Self, IdentityError> {
        trusted.verify()?;
        Ok(Self(Arc::new(RwLock::new(trusted))))
    }

    /// A copy of the current roster.
    pub fn current(&self) -> Roster {
        self.0.read().expect("roster lock").clone()
    }

    /// Moves to `next` if it is a valid successor. Returns `false` without change when `next` is
    /// exactly the current roster, so receiving the same roster twice is harmless.
    pub fn update(&self, next: Roster) -> Result<bool, IdentityError> {
        let mut current = self.0.write().expect("roster lock");
        if *current == next {
            return Ok(false);
        }
        current.verify_successor(&next)?;
        *current = next;
        Ok(true)
    }

    /// Whether the node with id `node` is a member of the current roster.
    pub fn contains_node(&self, node: &NodeId) -> bool {
        self.0.read().expect("roster lock").contains_node(node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group() -> GroupId {
        GroupId::new("group-a").unwrap()
    }

    #[test]
    fn pairing_and_revocation_raise_the_epoch() {
        let a = Identity::generate();
        let b = Identity::generate();
        let g = Roster::genesis(&a, group());
        g.verify().unwrap();
        let r2 = g.with_member(&a, b.public()).unwrap();
        assert_eq!(r2.epoch(), 2);
        g.verify_successor(&r2).unwrap();
        assert!(r2.contains_node(&b.node_id()));
        assert_eq!(r2.quorum(), 2);

        let r3 = r2.without_member(&b, &a.public()).unwrap();
        r2.verify_successor(&r3).unwrap();
        assert!(!r3.is_member(&a.public()));
        assert_eq!(r3.revoked(), &[a.public()]);
        assert_eq!(
            r3.with_member(&b, a.public()),
            Err(IdentityError::Revoked),
            "a revoked key never comes back"
        );
    }

    #[test]
    fn rejects_forged_older_and_revoked_signers() {
        let a = Identity::generate();
        let b = Identity::generate();
        let c = Identity::generate();
        let outsider = Identity::generate();
        let r1 = Roster::genesis(&a, group());
        let r2 = r1.with_member(&a, b.public()).unwrap();
        let r3 = r2.with_member(&b, c.public()).unwrap();
        let handle = RosterHandle::new(r3.clone()).unwrap();

        assert_eq!(handle.update(r2.clone()), Err(IdentityError::StaleEpoch));
        assert_eq!(handle.update(r3.clone()), Ok(false));

        let forged = Roster::genesis(&outsider, group())
            .with_member(&outsider, a.public())
            .unwrap()
            .with_member(&outsider, b.public())
            .unwrap()
            .with_member(&outsider, c.public())
            .unwrap()
            .with_member(&outsider, Identity::generate().public())
            .unwrap();
        assert_eq!(handle.update(forged), Err(IdentityError::NotMember));

        let mut tampered = r3.with_member(&a, outsider.public()).unwrap();
        tampered.members.retain(|m| *m != c.public());
        assert_eq!(handle.update(tampered), Err(IdentityError::BadSignature));

        let r4 = r3.without_member(&a, &b.public()).unwrap();
        handle.update(r4.clone()).unwrap();
        let by_revoked = r3
            .with_member(&b, outsider.public())
            .unwrap()
            .with_member(&b, Identity::generate().public())
            .unwrap();
        assert!(by_revoked.epoch() > r4.epoch());
        assert_eq!(handle.update(by_revoked), Err(IdentityError::Revoked));

        let other_group = Roster::genesis(&a, GroupId::new("group-b").unwrap());
        assert!(r4.verify_successor(&other_group).is_err());
    }

    #[test]
    fn wire_form_round_trips_and_is_checked() {
        let a = Identity::generate();
        let r = Roster::genesis(&a, group())
            .with_member(&a, Identity::generate().public())
            .unwrap();
        assert_eq!(Roster::from_bytes(&r.to_bytes()).unwrap(), r);
        let mut bytes = r.to_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert!(Roster::from_bytes(&bytes).is_err());
    }

    #[test]
    fn a_member_cannot_revoke_itself_and_outsiders_cannot_sign() {
        let a = Identity::generate();
        let b = Identity::generate();
        let r = Roster::genesis(&a, group());
        assert_eq!(
            r.without_member(&a, &a.public()),
            Err(IdentityError::SelfRevocation)
        );
        assert_eq!(r.with_member(&b, b.public()), Err(IdentityError::NotMember));
    }
}
