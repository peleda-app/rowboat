use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use baton_core::{GroupId, Timestamp};
use hmac::{Hmac, KeyInit, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Identity, IdentityError, PublicKey, Roster, Signature};

const PROOF_CONTEXT: &[u8] = b"baton-invite-v1";
const JOIN_CONTEXT: &str = "baton-join-v1";

/// A one-time invitation to join a group's mesh, shown by a member (as a QR code) and read by
/// the new device. Whoever holds it before it expires can join, so it must travel only over a
/// channel the person trusts. `Debug` never shows the secret.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    /// The group to join.
    pub group: GroupId,
    /// The member that issued the invite and will sign the new roster.
    pub inviter: PublicKey,
    /// A public number that names the invite.
    pub id: u64,
    secret: [u8; 16],
    /// After this moment the invite is refused.
    pub expires_at: Timestamp,
}

impl Invite {
    /// The wire form, for a QR code. It contains the secret.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(postcard::to_stdvec(self).expect("an invite always serializes"))
    }

    /// Parses the wire form.
    pub fn from_bytes(bytes: &[u8]) -> Result<Invite, IdentityError> {
        postcard::from_bytes(bytes).map_err(|_| IdentityError::Malformed)
    }

    /// On the new device: checks that `roster` is what this invite promised, signed by the
    /// inviter, of the invite's group and listing `joiner`. The device then trusts it as its
    /// first roster.
    pub fn verify_roster(&self, joiner: &PublicKey, roster: &Roster) -> Result<(), IdentityError> {
        roster.verify()?;
        if roster.group() != &self.group {
            return Err(IdentityError::GroupMismatch);
        }
        if roster.signer() != &self.inviter {
            return Err(IdentityError::BadSignature);
        }
        if !roster.is_member(joiner) {
            return Err(IdentityError::NotMember);
        }
        Ok(())
    }

    fn proof(&self, joiner: &PublicKey) -> [u8; 32] {
        proof(&self.secret, &self.group, &self.inviter, self.id, joiner)
            .finalize()
            .into_bytes()
            .into()
    }
}

impl Drop for Invite {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.secret);
    }
}

impl fmt::Debug for Invite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Invite")
            .field("group", &self.group)
            .field("inviter", &self.inviter)
            .field("id", &self.id)
            .field("secret", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

fn proof(
    secret: &[u8; 16],
    group: &GroupId,
    inviter: &PublicKey,
    id: u64,
    joiner: &PublicKey,
) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(PROOF_CONTEXT);
    mac.update(&[0]);
    mac.update(group.as_str().as_bytes());
    mac.update(&[0]);
    mac.update(&inviter.to_bytes());
    mac.update(&id.to_be_bytes());
    mac.update(&joiner.to_bytes());
    mac
}

/// A new device's answer to an [`Invite`]: its public key, a proof that it knows the invite
/// secret (HMAC-SHA256 keyed by the secret over the invite and the key), and its signature
/// proving it holds the private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRequest {
    /// The invite being answered.
    pub invite_id: u64,
    /// The new device's key.
    pub joiner: PublicKey,
    proof: [u8; 32],
    signature: Signature,
}

impl JoinRequest {
    /// Answers `invite` as `joiner`.
    pub fn new(invite: &Invite, joiner: &Identity) -> Self {
        let key = joiner.public();
        let proof = invite.proof(&key);
        let signature = joiner.sign(JOIN_CONTEXT, &join_body(invite.id, &key, &proof));
        Self {
            invite_id: invite.id,
            joiner: key,
            proof,
            signature,
        }
    }

    /// The wire form.
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("a join request always serializes")
    }

    /// Parses the wire form; nothing is verified until [`Inviter::accept`].
    pub fn from_bytes(bytes: &[u8]) -> Result<JoinRequest, IdentityError> {
        postcard::from_bytes(bytes).map_err(|_| IdentityError::Malformed)
    }
}

fn join_body(id: u64, joiner: &PublicKey, proof: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(72);
    v.extend_from_slice(&id.to_be_bytes());
    v.extend_from_slice(&joiner.to_bytes());
    v.extend_from_slice(proof);
    v
}

struct Pending {
    group: GroupId,
    secret: Zeroizing<[u8; 16]>,
    expires_at: Timestamp,
}

/// The invites a member has issued and not yet seen used.
///
/// Guarantees: an invite is accepted at most once; any join attempt naming it uses it up, whether
/// it succeeds or not; an expired or cancelled invite is refused. Pending invites live in memory
/// only, so restarting the member cancels them.
#[derive(Default)]
pub struct Inviter {
    pending: Mutex<HashMap<u64, Pending>>,
}

impl Inviter {
    /// No pending invites.
    pub fn new() -> Self {
        Self::default()
    }

    /// Issues an invite from `member` to `group` with a fresh random 128-bit secret, valid until
    /// `now + ttl_ms`.
    pub fn invite(
        &self,
        member: &Identity,
        group: &GroupId,
        now: Timestamp,
        ttl_ms: i64,
    ) -> Invite {
        let mut secret = [0u8; 16];
        OsRng.fill_bytes(&mut secret);
        let mut pending = self.pending.lock().expect("invites lock");
        let id = loop {
            let id = OsRng.next_u64();
            if !pending.contains_key(&id) {
                break id;
            }
        };
        let expires_at = now.plus_ms(ttl_ms);
        pending.insert(
            id,
            Pending {
                group: group.clone(),
                secret: Zeroizing::new(secret),
                expires_at,
            },
        );
        let invite = Invite {
            group: group.clone(),
            inviter: member.public(),
            id,
            secret,
            expires_at,
        };
        zeroize::Zeroize::zeroize(&mut secret);
        invite
    }

    /// Withdraws an invite. Unknown ids are ignored.
    pub fn cancel(&self, id: u64) {
        self.pending.lock().expect("invites lock").remove(&id);
    }

    /// Drops every invite that has expired at `now`.
    pub fn prune(&self, now: Timestamp) {
        self.pending
            .lock()
            .expect("invites lock")
            .retain(|_, p| p.expires_at >= now);
    }

    /// Checks `request` and, if it answers a pending invite in time, returns the successor of
    /// `roster` with the new device added, signed by `member`. The caller then installs and
    /// spreads that roster and sends it to the new device.
    pub fn accept(
        &self,
        member: &Identity,
        roster: &Roster,
        request: &JoinRequest,
        now: Timestamp,
    ) -> Result<Roster, IdentityError> {
        let pending = self
            .pending
            .lock()
            .expect("invites lock")
            .remove(&request.invite_id)
            .ok_or(IdentityError::UnknownInvite)?;
        if now > pending.expires_at {
            return Err(IdentityError::InviteExpired);
        }
        if roster.group() != &pending.group {
            return Err(IdentityError::GroupMismatch);
        }
        proof(
            &pending.secret,
            &pending.group,
            &member.public(),
            request.invite_id,
            &request.joiner,
        )
        .verify_slice(&request.proof)
        .map_err(|_| IdentityError::BadProof)?;
        request.joiner.verify(
            JOIN_CONTEXT,
            &join_body(request.invite_id, &request.joiner, &request.proof),
            &request.signature,
        )?;
        roster.with_member(member, request.joiner)
    }
}

impl fmt::Debug for Inviter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self.pending.lock().map(|p| p.len()).unwrap_or(0);
        write!(f, "Inviter({n} pending)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RosterHandle;

    fn setup() -> (Identity, Roster, Inviter, GroupId) {
        let t = GroupId::new("group-a").unwrap();
        let member = Identity::generate();
        let roster = Roster::genesis(&member, t.clone());
        (member, roster, Inviter::new(), t)
    }

    #[test]
    fn a_device_joins_with_a_valid_invite() {
        let (member, roster, inviter, t) = setup();
        let now = Timestamp(1_000);
        let invite = inviter.invite(&member, &t, now, 120_000);
        let scanned = Invite::from_bytes(&invite.to_bytes()).unwrap();

        let device = Identity::generate();
        let request =
            JoinRequest::from_bytes(&JoinRequest::new(&scanned, &device).to_bytes()).unwrap();
        let next = inviter
            .accept(&member, &roster, &request, now.plus_ms(5_000))
            .unwrap();
        assert_eq!(next.epoch(), 2);
        RosterHandle::new(roster)
            .unwrap()
            .update(next.clone())
            .unwrap();

        scanned.verify_roster(&device.public(), &next).unwrap();
        let other = Roster::genesis(&Identity::generate(), t);
        assert!(scanned.verify_roster(&device.public(), &other).is_err());
    }

    #[test]
    fn invites_are_one_time_and_expire() {
        let (member, roster, inviter, t) = setup();
        let now = Timestamp(1_000);
        let invite = inviter.invite(&member, &t, now, 1_000);
        let request = JoinRequest::new(&invite, &Identity::generate());
        assert_eq!(
            inviter.accept(&member, &roster, &request, now.plus_ms(1_001)),
            Err(IdentityError::InviteExpired)
        );
        assert_eq!(
            inviter.accept(&member, &roster, &request, now),
            Err(IdentityError::UnknownInvite)
        );

        let invite = inviter.invite(&member, &t, now, 60_000);
        let request = JoinRequest::new(&invite, &Identity::generate());
        inviter.accept(&member, &roster, &request, now).unwrap();
        assert_eq!(
            inviter.accept(&member, &roster, &request, now),
            Err(IdentityError::UnknownInvite)
        );

        let invite = inviter.invite(&member, &t, now, 60_000);
        inviter.cancel(invite.id);
        let request = JoinRequest::new(&invite, &Identity::generate());
        assert_eq!(
            inviter.accept(&member, &roster, &request, now),
            Err(IdentityError::UnknownInvite)
        );
    }

    #[test]
    fn requires_the_secret_and_the_private_key() {
        let (member, roster, inviter, t) = setup();
        let now = Timestamp(1_000);

        let invite = inviter.invite(&member, &t, now, 60_000);
        let mut guessed = invite.clone();
        guessed.secret = [7; 16];
        let request = JoinRequest::new(&guessed, &Identity::generate());
        assert_eq!(
            inviter.accept(&member, &roster, &request, now),
            Err(IdentityError::BadProof)
        );
        assert_eq!(
            inviter.accept(
                &member,
                &roster,
                &JoinRequest::new(&invite, &Identity::generate()),
                now
            ),
            Err(IdentityError::UnknownInvite),
            "a failed attempt used the invite up"
        );

        let invite = inviter.invite(&member, &t, now, 60_000);
        let mut swapped = JoinRequest::new(&invite, &Identity::generate());
        swapped.joiner = Identity::generate().public();
        assert_eq!(
            inviter.accept(&member, &roster, &swapped, now),
            Err(IdentityError::BadProof),
            "the proof binds the joiner's key"
        );

        let invite = inviter.invite(&member, &t, now, 60_000);
        let device = Identity::generate();
        let mut unsigned = JoinRequest::new(&invite, &device);
        unsigned.signature = Identity::generate().sign(JOIN_CONTEXT, b"x");
        assert_eq!(
            inviter.accept(&member, &roster, &unsigned, now),
            Err(IdentityError::BadSignature)
        );
    }

    #[test]
    fn debug_hides_the_secret() {
        let (member, _, inviter, t) = setup();
        let invite = inviter.invite(&member, &t, Timestamp(0), 1_000);
        let hex: String = invite.secret.iter().map(|b| format!("{b:02x}")).collect();
        let shown = format!("{invite:?}");
        assert!(shown.contains("redacted"));
        assert!(!shown.contains(&hex));
    }
}
