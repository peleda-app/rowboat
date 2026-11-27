use std::fmt;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use hmac::{Hmac, KeyInit, Mac};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::IdentityError;

const DSI: &[u8] = b"CPaceRistretto255";
const DSI_ISK: &[u8] = b"CPaceRistretto255_ISK";
const S_IN_BYTES: usize = 128;
const CONFIRM_LABEL: &[u8] = b"baton-pake-confirm-v1";
const KEY_LABEL: &[u8] = b"baton-pake-key-v1";

/// The length of a PAKE message (an encoded ristretto255 point), in bytes.
pub const PAKE_MESSAGE_LEN: usize = 32;

/// The length of a key confirmation tag, in bytes.
pub const PAKE_TAG_LEN: usize = 32;

/// Which side of a PAKE run this party plays. The initiator's message comes first in the
/// transcript; the two sides must pick different roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PakeRole {
    /// Sends the first message.
    Initiator,
    /// Answers it.
    Responder,
}

impl PakeRole {
    fn byte(self) -> u8 {
        match self {
            Self::Initiator => b'i',
            Self::Responder => b'r',
        }
    }

    fn other(self) -> Self {
        match self {
            Self::Initiator => Self::Responder,
            Self::Responder => Self::Initiator,
        }
    }
}

fn prepend_len(data: &[u8], out: &mut Vec<u8>) {
    let mut n = data.len();
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
    out.extend_from_slice(data);
}

fn lv_cat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        prepend_len(p, &mut out);
    }
    out
}

fn prepended_len(data: &[u8]) -> usize {
    let mut v = Vec::new();
    prepend_len(&[], &mut v);
    let mut n = data.len() >> 7;
    let mut extra = 0;
    while n > 0 {
        extra += 1;
        n >>= 7;
    }
    v.len() + extra + data.len()
}

fn sha512(data: &[u8]) -> [u8; 64] {
    let digest = Sha512::digest(data);
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

fn generator(password: &[u8], channel: &[u8], sid: &[u8]) -> RistrettoPoint {
    let zpad =
        vec![0u8; S_IN_BYTES.saturating_sub(1 + prepended_len(password) + prepended_len(DSI))];
    let mut gen_str = Zeroizing::new(lv_cat(&[DSI, password, &zpad, channel, sid]));
    let mut hash = Zeroizing::new(sha512(&gen_str));
    let g = RistrettoPoint::from_uniform_bytes(&hash);
    gen_str.zeroize();
    hash.zeroize();
    g
}

/// One side of a CPace run (`draft-irtf-cfrg-cpace`, ristretto255 with SHA-512, initiator and
/// responder ordering) over a low-entropy password, such as a short code a person types.
///
/// Guarantees:
///
/// - An eavesdropper who records a whole run learns nothing that lets them test password guesses
///   offline; an active attacker gets exactly one guess per run.
/// - Both sides derive the same [`PakeSession`] only when they used the same password, channel
///   identifier and session id; the session is bound to both messages and both sides' associated
///   data.
/// - A peer message that is not a canonical encoding of a ristretto255 point, or that leads to
///   the identity, is refused with [`IdentityError::InvalidKey`].
/// - The ephemeral scalar is zeroized when the run is dropped or finished; `Debug` shows nothing
///   secret.
///
/// Key confirmation is not part of CPace itself: after [`Pake::finish`] each side sends
/// [`PakeSession::confirmation`] and checks the peer's with [`PakeSession::check_confirmation`]
/// before trusting anything sealed under the session.
pub struct Pake {
    role: PakeRole,
    scalar: Scalar,
    own: [u8; PAKE_MESSAGE_LEN],
    own_ad: Vec<u8>,
    sid: Vec<u8>,
}

impl Pake {
    /// Starts a run as `role` with a fresh scalar from the operating system's random source.
    /// `channel` names the channel both sides see (for example both endpoints' keys), `sid` the
    /// session (for example the invite), `ad` this side's public associated data.
    pub fn start(role: PakeRole, password: &[u8], channel: &[u8], sid: &[u8], ad: &[u8]) -> Self {
        let mut seed = Zeroizing::new([0u8; 64]);
        OsRng.fill_bytes(&mut seed[..]);
        Self::start_seeded(role, password, channel, sid, ad, &seed)
    }

    /// [`Pake::start`] with the scalar derived from 64 caller-chosen bytes (reduced modulo the
    /// group order). Only for test vectors and reproducible tests: a reused seed breaks the
    /// protocol.
    pub fn start_seeded(
        role: PakeRole,
        password: &[u8],
        channel: &[u8],
        sid: &[u8],
        ad: &[u8],
        seed: &[u8; 64],
    ) -> Self {
        let scalar = Scalar::from_bytes_mod_order_wide(seed);
        let g = generator(password, channel, sid);
        let own = (scalar * g).compress().to_bytes();
        Self {
            role,
            scalar,
            own,
            own_ad: ad.to_vec(),
            sid: sid.to_vec(),
        }
    }

    /// This side's message, to send to the peer.
    pub fn message(&self) -> [u8; PAKE_MESSAGE_LEN] {
        self.own
    }

    /// Finishes the run with the peer's message and associated data.
    pub fn finish(mut self, peer: &[u8], peer_ad: &[u8]) -> Result<PakeSession, IdentityError> {
        let point = CompressedRistretto::from_slice(peer)
            .map_err(|_| IdentityError::InvalidKey)?
            .decompress()
            .ok_or(IdentityError::InvalidKey)?;
        if point.is_identity() {
            return Err(IdentityError::InvalidKey);
        }
        let shared = self.scalar * point;
        if shared.is_identity() {
            return Err(IdentityError::InvalidKey);
        }
        let k = Zeroizing::new(shared.compress().to_bytes());
        let (ya, ada, yb, adb): (&[u8], &[u8], &[u8], &[u8]) = match self.role {
            PakeRole::Initiator => (&self.own, &self.own_ad, peer, peer_ad),
            PakeRole::Responder => (peer, peer_ad, &self.own, &self.own_ad),
        };
        let mut input = Zeroizing::new(lv_cat(&[DSI_ISK, &self.sid, &k[..]]));
        input.extend(lv_cat(&[ya, ada]));
        input.extend(lv_cat(&[yb, adb]));
        let isk = Zeroizing::new(sha512(&input));
        self.scalar.zeroize();
        Ok(PakeSession {
            role: self.role,
            isk,
        })
    }
}

impl Drop for Pake {
    fn drop(&mut self) {
        self.scalar.zeroize();
    }
}

impl fmt::Debug for Pake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pake({:?}, <secret redacted>)", self.role)
    }
}

/// The result of a finished [`Pake`] run: the intermediate session key (`ISK`), from which the
/// confirmation tags and any further keys are derived. Zeroized on drop; `Debug` shows nothing
/// secret.
pub struct PakeSession {
    role: PakeRole,
    isk: Zeroizing<[u8; 64]>,
}

impl PakeSession {
    fn mac(&self, label: &[u8], role: Option<PakeRole>, info: &[u8]) -> [u8; 32] {
        let mut mac =
            Hmac::<Sha512>::new_from_slice(&self.isk[..]).expect("HMAC takes any key length");
        mac.update(label);
        mac.update(&[0]);
        if let Some(r) = role {
            mac.update(&[r.byte()]);
        }
        mac.update(info);
        let out = mac.finalize().into_bytes();
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&out[..32]);
        tag
    }

    /// This side's key confirmation tag, to send to the peer.
    pub fn confirmation(&self) -> [u8; PAKE_TAG_LEN] {
        self.mac(CONFIRM_LABEL, Some(self.role), &[])
    }

    /// Checks the peer's key confirmation tag in constant time. A wrong password on either side,
    /// a swapped message or a different channel or session id fails with
    /// [`IdentityError::BadProof`].
    pub fn check_confirmation(&self, tag: &[u8]) -> Result<(), IdentityError> {
        let expected = self.mac(CONFIRM_LABEL, Some(self.role.other()), &[]);
        if tag.len() == PAKE_TAG_LEN && bool::from(expected.ct_eq(tag)) {
            Ok(())
        } else {
            Err(IdentityError::BadProof)
        }
    }

    /// A 32-byte key for `label`, the same on both sides and independent for every label. Use it
    /// only after the peer's confirmation checked.
    pub fn derive(&self, label: &str) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.mac(KEY_LABEL, None, label.as_bytes()))
    }
}

impl fmt::Debug for PakeSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PakeSession({:?}, <secret redacted>)", self.role)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn run(
        pa: &[u8],
        pb: &[u8],
        ca: &[u8],
        cb: &[u8],
        sa: &[u8],
        sb: &[u8],
    ) -> Result<(PakeSession, PakeSession), IdentityError> {
        let a = Pake::start(PakeRole::Initiator, pa, ca, sa, b"ad-a");
        let b = Pake::start(PakeRole::Responder, pb, cb, sb, b"ad-b");
        let (ma, mb) = (a.message(), b.message());
        Ok((a.finish(&mb, b"ad-b")?, b.finish(&ma, b"ad-a")?))
    }

    fn confirmed(a: &PakeSession, b: &PakeSession) -> bool {
        a.check_confirmation(&b.confirmation()).is_ok()
            && b.check_confirmation(&a.confirmation()).is_ok()
    }

    #[test]
    fn same_password_agrees_and_confirms() {
        let (a, b) = run(b"7KQ2-M9XA", b"7KQ2-M9XA", b"ch", b"ch", b"sid", b"sid").unwrap();
        assert!(confirmed(&a, &b));
        assert_eq!(*a.derive("seal"), *b.derive("seal"));
        assert_ne!(*a.derive("seal"), *a.derive("other"));
        assert_ne!(a.confirmation(), b.confirmation(), "tags differ by role");
    }

    #[test]
    fn wrong_password_channel_or_session_fails_confirmation() {
        for (pb, cb, sb) in [
            (&b"7KQ2-M9XB"[..], &b"ch"[..], &b"sid"[..]),
            (b"7KQ2-M9XA", b"other", b"sid"),
            (b"7KQ2-M9XA", b"ch", b"other"),
        ] {
            let (a, b) = run(b"7KQ2-M9XA", pb, b"ch", cb, b"sid", sb).unwrap();
            assert!(!confirmed(&a, &b));
            assert_eq!(
                a.check_confirmation(&b.confirmation()),
                Err(IdentityError::BadProof)
            );
        }
    }

    #[test]
    fn swapped_or_replayed_messages_fail() {
        let a = Pake::start(PakeRole::Initiator, b"pw", b"ch", b"sid", b"");
        let b = Pake::start(PakeRole::Responder, b"pw", b"ch", b"sid", b"");
        let attacker = Pake::start(PakeRole::Responder, b"pw", b"ch", b"sid", b"");
        let ma = a.message();
        let sa = a.finish(&attacker.message(), b"").unwrap();
        let sb = b.finish(&ma, b"").unwrap();
        assert!(
            !confirmed(&sa, &sb),
            "a message from a third party breaks the run"
        );

        let a = Pake::start(PakeRole::Initiator, b"pw", b"ch", b"sid", b"");
        let b1 = Pake::start(PakeRole::Responder, b"pw", b"ch", b"sid", b"");
        let ma = a.message();
        let mb = b1.message();
        let sb1 = b1.finish(&ma, b"").unwrap();
        let sa = a.finish(&mb, b"").unwrap();
        let replay = Pake::start(PakeRole::Responder, b"pw", b"ch", b"sid", b"")
            .finish(&ma, b"")
            .unwrap();
        assert!(confirmed(&sa, &sb1));
        assert!(
            sa.check_confirmation(&replay.confirmation()).is_err(),
            "replaying the initiator's message to a new responder gives another session"
        );
        assert!(replay.check_confirmation(&sa.confirmation()).is_err());
    }

    #[test]
    fn associated_data_is_bound() {
        let a = Pake::start(PakeRole::Initiator, b"pw", b"ch", b"sid", b"a");
        let b = Pake::start(PakeRole::Responder, b"pw", b"ch", b"sid", b"b");
        let (ma, mb) = (a.message(), b.message());
        let sa = a.finish(&mb, b"b").unwrap();
        let sb = b.finish(&ma, b"forged").unwrap();
        assert!(!confirmed(&sa, &sb));
    }

    #[test]
    fn invalid_points_are_refused() {
        let identity = [0u8; 32];
        let non_canonical = [0xffu8; 32];
        for bad in [
            &identity[..],
            &non_canonical[..],
            &[1u8; 31][..],
            &[][..],
            &[2u8; 33][..],
        ] {
            let a = Pake::start(PakeRole::Initiator, b"pw", b"ch", b"sid", b"");
            assert_eq!(a.finish(bad, b"").err(), Some(IdentityError::InvalidKey));
        }
    }

    #[test]
    fn seeded_runs_are_reproducible() {
        let seed = [9u8; 64];
        let a = Pake::start_seeded(PakeRole::Initiator, b"pw", b"ch", b"sid", b"", &seed);
        let b = Pake::start_seeded(PakeRole::Initiator, b"pw", b"ch", b"sid", b"", &seed);
        assert_eq!(a.message(), b.message());
        let c = Pake::start_seeded(PakeRole::Initiator, b"pv", b"ch", b"sid", b"", &seed);
        assert_ne!(
            a.message(),
            c.message(),
            "the password changes the generator"
        );
    }

    #[test]
    fn length_prefixes_follow_leb128() {
        let mut out = Vec::new();
        prepend_len(&[7u8; 200], &mut out);
        assert_eq!(&out[..2], &[0xc8, 0x01]);
        assert_eq!(out.len(), 202);
        assert_eq!(prepended_len(&[7u8; 200]), 202);
        assert_eq!(prepended_len(b""), 1);
        assert_eq!(lv_cat(&[b"ab", b""]), vec![2, b'a', b'b', 0]);
    }

    #[test]
    fn an_eavesdropper_finds_no_distinguisher_for_four_digit_codes() {
        let code = b"4711";
        let a = Pake::start(PakeRole::Initiator, code, b"ch", b"sid", b"");
        let b = Pake::start(PakeRole::Responder, code, b"ch", b"sid", b"");
        let (ma, mb) = (a.message(), b.message());
        let sa = a.finish(&mb, b"").unwrap();
        let recorded_tag = sa.confirmation();
        let mut hits = 0;
        for guess in 0..10_000u32 {
            let guess = format!("{guess:04}");
            let g = generator(guess.as_bytes(), b"ch", b"sid");
            let candidates = [
                g.compress().to_bytes(),
                ma,
                mb,
                (CompressedRistretto(ma).decompress().unwrap()
                    + CompressedRistretto(mb).decompress().unwrap())
                .compress()
                .to_bytes(),
            ];
            for k in candidates {
                let mut input = lv_cat(&[DSI_ISK, b"sid", &k]);
                input.extend(lv_cat(&[&ma, b""]));
                input.extend(lv_cat(&[&mb, b""]));
                let fake = PakeSession {
                    role: PakeRole::Initiator,
                    isk: Zeroizing::new(sha512(&input)),
                };
                if fake.confirmation() == recorded_tag {
                    hits += 1;
                }
            }
            if g.compress().to_bytes() == ma || g.compress().to_bytes() == mb {
                hits += 1;
            }
        }
        assert_eq!(hits, 0);
    }

    #[test]
    fn debug_hides_secrets() {
        let a = Pake::start(PakeRole::Initiator, b"pw", b"ch", b"sid", b"");
        assert!(format!("{a:?}").contains("redacted"));
        let b = Pake::start(PakeRole::Responder, b"pw", b"ch", b"sid", b"");
        let s = b.finish(&a.message(), b"").unwrap();
        assert!(format!("{s:?}").contains("redacted"));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]
        #[test]
        fn agreement_iff_same_password(pa in proptest::collection::vec(any::<u8>(), 0..40),
                                       pb in proptest::collection::vec(any::<u8>(), 0..40)) {
            let (a, b) = run(&pa, &pb, b"ch", b"ch", b"sid", b"sid").unwrap();
            prop_assert_eq!(confirmed(&a, &b), pa == pb);
        }

        #[test]
        fn hostile_peer_messages_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let a = Pake::start(PakeRole::Initiator, b"pw", b"ch", b"sid", b"");
            let _ = a.finish(&bytes, &bytes);
        }
    }
}
