//! The signed wire form of a message, shared by every transport implementation.

use std::collections::HashMap;
use std::sync::Mutex;

use baton_core::NodeId;
use baton_identity::{Identity, PublicKey, RosterHandle, Signature};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::{Envelope, MAX_PAYLOAD, check_channel};

const FRAME_CONTEXT: &str = "baton-frame-v1";

#[derive(Serialize, Deserialize)]
struct Body {
    from: PublicKey,
    to: NodeId,
    channel: String,
    seq: u64,
    payload: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Frame {
    body: Vec<u8>,
    signature: Signature,
}

/// Why a frame was dropped. Carries no content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// The bytes are not a frame.
    #[error("malformed frame")]
    Malformed,
    /// The frame is addressed to another node.
    #[error("frame for another node")]
    WrongDestination,
    /// The sender is not a member of the trusted roster.
    #[error("sender is not a member")]
    NotMember,
    /// The signature does not verify.
    #[error("bad frame signature")]
    BadSignature,
    /// A sequence number not higher than the last one accepted from this sender.
    #[error("replayed frame")]
    Replayed,
    /// The frame names a sender other than the one that delivered it.
    #[error("frame from an unexpected sender")]
    WrongSender,
}

/// The largest sealed frame accepted: a full payload plus room for the envelope.
pub const MAX_FRAME: usize = MAX_PAYLOAD + 4096;

/// Seals a message from `identity` to `to`. `seq` must grow with every frame the sender sends to
/// the same receiver; receivers drop frames whose number does not.
pub fn seal(identity: &Identity, to: &NodeId, channel: &str, seq: u64, payload: &[u8]) -> Vec<u8> {
    let body = postcard::to_stdvec(&Body {
        from: identity.public(),
        to: to.clone(),
        channel: channel.to_owned(),
        seq,
        payload: payload.to_vec(),
    })
    .expect("a frame body always serializes");
    let signature = identity.sign(FRAME_CONTEXT, &body);
    postcard::to_stdvec(&Frame { body, signature }).expect("a frame always serializes")
}

/// Checks incoming frames for one node.
///
/// Guarantees: [`Opener::open`] returns an envelope only for a frame of at most [`MAX_FRAME`]
/// bytes with a valid channel and a payload of at most [`MAX_PAYLOAD`], addressed to this node,
/// from the expected sender when one is given, signed by a member of the roster held by the handle
/// at that moment, with a sequence number higher than any accepted before from the same sender.
/// The counter moves only after every other check passed. Concurrent calls are safe. Counters live
/// in memory: after a restart a receiver accepts any newer-looking frame again, which is safe on a
/// carrier that authenticates the sender per connection (as `mesh-link` does) and must be revisited
/// for store-and-forward carriers.
#[derive(Debug)]
pub struct Opener {
    local: NodeId,
    roster: RosterHandle,
    last_seq: Mutex<HashMap<PublicKey, u64>>,
}

impl Opener {
    /// An opener for node `local` that trusts `roster`.
    pub fn new(local: NodeId, roster: RosterHandle) -> Self {
        Self {
            local,
            roster,
            last_seq: Mutex::new(HashMap::new()),
        }
    }

    /// Forgets the replay counter of `sender`, so its next frame is accepted whatever its
    /// sequence number. Call it only when a new channel authenticated as `sender` begins (a new
    /// stream on a link keyed by node identities): nobody but `sender` can write there, so this
    /// opens no replay path, and it lets a sender that restarted with its clock behind be heard
    /// again at once.
    pub fn reset(&self, sender: &PublicKey) {
        self.last_seq.lock().expect("sequence lock").remove(sender);
    }

    /// Checks a frame and unwraps it. `sender` is the key the caller already knows sent these
    /// bytes (the peer that authenticated the stream they came on), or `None` when the carrier
    /// authenticates nobody. Every check runs before the sequence number is recorded, so a frame
    /// that fails any of them, including a sender other than the expected one, never moves the
    /// replay counter.
    pub fn open(&self, raw: &[u8], sender: Option<&PublicKey>) -> Result<Envelope, FrameError> {
        if raw.len() > MAX_FRAME {
            return Err(FrameError::Malformed);
        }
        let frame: Frame = postcard::from_bytes(raw).map_err(|_| FrameError::Malformed)?;
        let body: Body = postcard::from_bytes(&frame.body).map_err(|_| FrameError::Malformed)?;
        if body.payload.len() > MAX_PAYLOAD || check_channel(&body.channel).is_err() {
            return Err(FrameError::Malformed);
        }
        if body.to != self.local {
            return Err(FrameError::WrongDestination);
        }
        if sender.is_some_and(|s| s != &body.from) {
            return Err(FrameError::WrongSender);
        }
        if !self.roster.current().is_member(&body.from) {
            return Err(FrameError::NotMember);
        }
        body.from
            .verify(FRAME_CONTEXT, &frame.body, &frame.signature)
            .map_err(|_| FrameError::BadSignature)?;
        let mut last = self.last_seq.lock().expect("sequence lock");
        let seen = last.entry(body.from).or_insert(0);
        if body.seq <= *seen {
            return Err(FrameError::Replayed);
        }
        *seen = body.seq;
        Ok(Envelope {
            from: body.from.node_id(),
            channel: body.channel,
            payload: Bytes::from(body.payload),
        })
    }
}
#[cfg(test)]
mod tests {
    use baton_core::GroupId;
    use baton_identity::Roster;
    use proptest::prelude::*;

    use super::*;

    fn pair() -> (Identity, Identity, Opener) {
        let a = Identity::generate();
        let b = Identity::generate();
        let roster = Roster::genesis(&a, GroupId::new("t").unwrap())
            .with_member(&a, b.public())
            .unwrap();
        let opener = Opener::new(b.node_id(), RosterHandle::new(roster).unwrap());
        (a, b, opener)
    }

    #[test]
    fn opens_only_valid_frames() {
        let (a, b, opener) = pair();
        let outsider = Identity::generate();
        let ok = seal(&a, &b.node_id(), "test", 5, b"hi");
        let env = opener.open(&ok, None).unwrap();
        assert_eq!(env.from, a.node_id());
        assert_eq!(&env.payload[..], b"hi");
        assert_eq!(opener.open(&ok, None), Err(FrameError::Replayed));
        assert_eq!(
            opener.open(&seal(&a, &b.node_id(), "test", 4, b"hi"), None),
            Err(FrameError::Replayed)
        );
        assert_eq!(
            opener.open(&seal(&a, &a.node_id(), "test", 9, b"hi"), None),
            Err(FrameError::WrongDestination)
        );
        assert_eq!(
            opener.open(&seal(&outsider, &b.node_id(), "test", 9, b"hi"), None),
            Err(FrameError::NotMember)
        );
        assert_eq!(opener.open(b"garbage", None), Err(FrameError::Malformed));
        let mut forged: Frame =
            postcard::from_bytes(&seal(&a, &b.node_id(), "test", 9, b"hi")).unwrap();
        forged.signature = a.sign("other-context", &forged.body);
        assert_eq!(
            opener.open(&postcard::to_stdvec(&forged).unwrap(), None),
            Err(FrameError::BadSignature)
        );
        assert!(
            opener
                .open(&seal(&a, &b.node_id(), "test", 6, b"again"), None)
                .is_ok()
        );
    }

    #[test]
    fn a_frame_relayed_by_another_member_does_not_burn_the_senders_counter() {
        let (a, b, opener) = pair();
        let relay = Identity::generate();
        let high = seal(&a, &b.node_id(), "test", 1_000, b"relayed");
        assert_eq!(
            opener.open(&high, Some(&relay.public())),
            Err(FrameError::WrongSender),
            "a frame arriving from someone other than its signer is refused"
        );
        let next = seal(&a, &b.node_id(), "test", 10, b"direct");
        assert!(
            opener.open(&next, Some(&a.public())).is_ok(),
            "the refused frame did not move a's counter, so a's real next frame still opens"
        );
        assert_eq!(
            opener.open(&high, Some(&a.public())).map(|e| e.payload),
            Ok(Bytes::from_static(b"relayed"))
        );
    }

    #[test]
    fn failed_checks_never_move_the_counter() {
        let (a, b, opener) = pair();
        let mut bad_sig: Frame =
            postcard::from_bytes(&seal(&a, &b.node_id(), "test", 500, b"x")).unwrap();
        bad_sig.signature = a.sign("other", &bad_sig.body);
        assert_eq!(
            opener.open(&postcard::to_stdvec(&bad_sig).unwrap(), None),
            Err(FrameError::BadSignature)
        );
        assert!(
            opener
                .open(&seal(&a, &b.node_id(), "test", 2, b"ok"), None)
                .is_ok()
        );
    }

    #[test]
    fn oversized_frames_and_bad_channels_are_malformed() {
        let (a, b, opener) = pair();
        assert_eq!(
            opener.open(&vec![0u8; MAX_FRAME + 1], None),
            Err(FrameError::Malformed)
        );
        let big = seal(&a, &b.node_id(), "test", 1, &vec![0u8; MAX_PAYLOAD + 1]);
        assert_eq!(opener.open(&big, None), Err(FrameError::Malformed));
        let channel = seal(&a, &b.node_id(), "Bad Channel", 2, b"x");
        assert_eq!(opener.open(&channel, None), Err(FrameError::Malformed));
        assert!(
            opener
                .open(
                    &seal(&a, &b.node_id(), "test", 3, &vec![0u8; MAX_PAYLOAD]),
                    None
                )
                .is_ok()
        );
    }

    #[test]
    fn reset_lets_a_restarted_sender_with_a_clock_behind_be_heard() {
        let (a, b, opener) = pair();
        assert!(
            opener
                .open(
                    &seal(&a, &b.node_id(), "test", 1_000_000, b"x"),
                    Some(&a.public())
                )
                .is_ok()
        );
        let behind = seal(&a, &b.node_id(), "test", 5, b"after restart");
        assert_eq!(
            opener.open(&behind, Some(&a.public())),
            Err(FrameError::Replayed)
        );
        opener.reset(&a.public());
        assert!(opener.open(&behind, Some(&a.public())).is_ok());
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_open(raw in proptest::collection::vec(any::<u8>(), 0..600)) {
            let (_, _, opener) = pair();
            prop_assert!(opener.open(&raw, None).is_err());
        }

        #[test]
        fn any_flipped_bit_is_refused(pos in 0usize..10_000, bit in 0u8..8) {
            let (a, b, opener) = pair();
            let mut f = seal(&a, &b.node_id(), "test", 7, b"payload");
            let i = pos % f.len();
            f[i] ^= 1 << bit;
            prop_assert!(opener.open(&f, None).is_err());
        }
    }
}
