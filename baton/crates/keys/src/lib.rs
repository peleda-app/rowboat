//! Key material for groups: hybrid post-quantum key boxes, recovery roots and resource keys.
//!
//! - A [`KemSecret`]/[`KemPublic`] pair is an X-Wing key pair (X25519 combined with ML-KEM-768),
//!   used through HPKE (RFC 9180, `hpke` crate: X-Wing, HKDF-SHA256, ChaCha20-Poly1305). A
//!   [`SealedBox`] is HPKE single-shot encryption to one public key, bound to associated data
//!   that names what is inside, so a box for one resource and epoch never opens as another.
//! - A [`RecoveryRoot`] is 32 random bytes kept offline. Its signing key (Ed25519) and its KEM
//!   key are derived from it with HKDF-SHA256 under fixed labels, so the root alone restores
//!   them; their public parts are recorded in the group log.
//! - A resource key is a `baton_seal::Key`, generated at random per resource and epoch.
//!
//! A pure library: no I/O beyond the operating system's random source.

use baton_identity::{Identity, PublicKey};
use hkdf::Hkdf;
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::XWing;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The HPKE `info` of every box.
const INFO: &[u8] = b"baton-box/v1";

/// The length of a KEM secret key (an X-Wing seed), in bytes.
pub const KEM_SECRET_LEN: usize = 32;

/// The longest sealed payload a box accepts, in bytes.
pub const MAX_BOX_PLAINTEXT: usize = 4096;

/// Errors of key handling.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeysError {
    /// Bytes that are not a valid key of the expected kind.
    #[error("invalid key")]
    InvalidKey,
    /// A box that does not open with this key and associated data, or is malformed.
    #[error("box cannot be opened")]
    Invalid,
    /// A plaintext over [`MAX_BOX_PLAINTEXT`].
    #[error("plaintext too large")]
    TooLarge,
}

/// A node's or a recovery root's KEM secret key. Wiped on drop; `Debug` hides it.
pub struct KemSecret(Zeroizing<[u8; KEM_SECRET_LEN]>);

impl std::fmt::Debug for KemSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KemSecret(<redacted>)")
    }
}

impl KemSecret {
    /// A fresh key from the operating system's random source.
    pub fn generate() -> Self {
        let (sk, _) = XWing::gen_keypair();
        let mut b = Zeroizing::new([0u8; KEM_SECRET_LEN]);
        b.copy_from_slice(&sk.to_bytes());
        Self(b)
    }

    /// The key whose seed is `bytes` (for keys kept in a secret store or derived from a root).
    pub fn from_bytes(bytes: &[u8; KEM_SECRET_LEN]) -> Result<Self, KeysError> {
        <XWing as Kem>::PrivateKey::from_bytes(bytes).map_err(|_| KeysError::InvalidKey)?;
        Ok(Self(Zeroizing::new(*bytes)))
    }

    /// The seed, only for storing the key in a secret store.
    pub fn expose(&self) -> &[u8; KEM_SECRET_LEN] {
        &self.0
    }

    /// The public key.
    pub fn public(&self) -> KemPublic {
        let sk = <XWing as Kem>::PrivateKey::from_bytes(&self.0[..]).expect("a validated key");
        KemPublic(XWing::sk_to_pk(&sk).to_bytes().to_vec())
    }
}

/// A KEM public key. Construction checks it parses as an X-Wing public key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct KemPublic(Vec<u8>);

impl KemPublic {
    /// Checks and wraps `bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeysError> {
        <XWing as Kem>::PublicKey::from_bytes(bytes).map_err(|_| KeysError::InvalidKey)?;
        Ok(Self(bytes.to_vec()))
    }

    /// The encoded key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for KemPublic {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = Vec::<u8>::deserialize(d)?;
        KemPublic::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// A payload encrypted to one KEM public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedBox {
    /// The encapsulated key.
    pub enc: Vec<u8>,
    /// The ciphertext and tag.
    pub ct: Vec<u8>,
}

/// Seals `plaintext` to `recipient`, bound to `aad`.
///
/// Guarantees: only the holder of the matching secret key can open it, and only with the same
/// `aad`; every call uses a fresh encapsulation.
pub fn seal_box(
    recipient: &KemPublic,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<SealedBox, KeysError> {
    if plaintext.len() > MAX_BOX_PLAINTEXT {
        return Err(KeysError::TooLarge);
    }
    let pk =
        <XWing as Kem>::PublicKey::from_bytes(&recipient.0).map_err(|_| KeysError::InvalidKey)?;
    let (enc, ct) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeS::Base,
        &pk,
        INFO,
        plaintext,
        aad,
    )
    .map_err(|_| KeysError::InvalidKey)?;
    Ok(SealedBox {
        enc: enc.to_bytes().to_vec(),
        ct,
    })
}

/// Opens a box sealed to `secret`'s public key with the same `aad`.
///
/// Guarantees: returns the plaintext (wiped on drop) only when every byte is as sealed, for this
/// key and `aad`; otherwise [`KeysError::Invalid`].
pub fn open_box(
    secret: &KemSecret,
    aad: &[u8],
    sealed: &SealedBox,
) -> Result<Zeroizing<Vec<u8>>, KeysError> {
    if sealed.ct.len() > MAX_BOX_PLAINTEXT + 64 {
        return Err(KeysError::Invalid);
    }
    let sk =
        <XWing as Kem>::PrivateKey::from_bytes(&secret.0[..]).map_err(|_| KeysError::InvalidKey)?;
    let enc =
        <XWing as Kem>::EncappedKey::from_bytes(&sealed.enc).map_err(|_| KeysError::Invalid)?;
    hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeR::Base,
        &sk,
        &enc,
        INFO,
        &sealed.ct,
        aad,
    )
    .map(Zeroizing::new)
    .map_err(|_| KeysError::Invalid)
}

/// A recovery root: 32 random bytes from which a recovery signing key and KEM key derive. Wiped on
/// drop; `Debug` hides it.
pub struct RecoveryRoot(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for RecoveryRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryRoot(<redacted>)")
    }
}

/// The keys a recovery root derives.
#[derive(Debug)]
pub struct RecoveryKeys {
    /// Signs recovery actions (certifying a node after a loss, checkpoints, rotation).
    pub sign: Identity,
    /// Opens key boxes sealed to the recovery key.
    pub kem: KemSecret,
}

/// The public parts of a recovery root's keys, recorded in the group log. The signing key signs
/// the KEM key, so nobody can pair someone's recovery signing key with a KEM key of their own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryPublic {
    /// The recovery signing key.
    pub sign: PublicKey,
    /// The recovery KEM key.
    pub kem: KemPublic,
    /// The signing key's signature over the KEM key.
    pub proof: baton_identity::Signature,
}

const RECOVERY_CONTEXT: &str = "baton-recovery-public-v1";

impl RecoveryPublic {
    /// Checks that the signing key vouches for the KEM key.
    pub fn verify(&self) -> Result<(), KeysError> {
        self.sign
            .verify(RECOVERY_CONTEXT, self.kem.as_bytes(), &self.proof)
            .map_err(|_| KeysError::InvalidKey)
    }
}

impl RecoveryRoot {
    /// A fresh root from the operating system's random source.
    pub fn generate() -> Self {
        let mut b = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut b[..]).expect("the operating system provides randomness");
        Self(b)
    }

    /// The root `bytes` (typed in from a recovery sheet, or combined from shares).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The root, only to write it on a recovery sheet or split it into shares.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    fn derive(&self, label: &[u8]) -> Zeroizing<[u8; 32]> {
        let hk = Hkdf::<sha2::Sha256>::new(Some(b"baton-recovery/v1"), &self.0[..]);
        let mut out = Zeroizing::new([0u8; 32]);
        hk.expand(label, &mut out[..])
            .expect("32 bytes is a valid HKDF length");
        out
    }

    /// The derived keys; the same root always derives the same keys.
    pub fn keys(&self) -> RecoveryKeys {
        let sign = Identity::from_secret_bytes(&self.derive(b"sign"));
        let kem =
            KemSecret::from_bytes(&self.derive(b"kem")).expect("any 32 bytes are an X-Wing seed");
        RecoveryKeys { sign, kem }
    }

    /// The public parts of the derived keys.
    pub fn public(&self) -> RecoveryPublic {
        let k = self.keys();
        let kem = k.kem.public();
        let proof = k.sign.sign(RECOVERY_CONTEXT, kem.as_bytes());
        RecoveryPublic {
            sign: k.sign.public(),
            kem,
            proof,
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn a_box_opens_only_for_its_key_and_aad() {
        let a = KemSecret::generate();
        let b = KemSecret::generate();
        let sealed = seal_box(&a.public(), b"res-1/epoch-1", b"secret key").unwrap();
        assert_eq!(
            &open_box(&a, b"res-1/epoch-1", &sealed).unwrap()[..],
            b"secret key"
        );
        assert_eq!(
            open_box(&b, b"res-1/epoch-1", &sealed),
            Err(KeysError::Invalid)
        );
        assert_eq!(
            open_box(&a, b"res-1/epoch-2", &sealed),
            Err(KeysError::Invalid)
        );
        let again = seal_box(&a.public(), b"res-1/epoch-1", b"secret key").unwrap();
        assert_ne!(
            again.enc, sealed.enc,
            "every box uses a fresh encapsulation"
        );
        assert_eq!(
            seal_box(&a.public(), b"", &vec![0; MAX_BOX_PLAINTEXT + 1]),
            Err(KeysError::TooLarge)
        );
    }

    #[test]
    fn recovery_keys_derive_deterministically_and_independently() {
        let root = RecoveryRoot::from_bytes([7; 32]);
        assert_eq!(root.public(), RecoveryRoot::from_bytes([7; 32]).public());
        assert_ne!(root.public(), RecoveryRoot::from_bytes([8; 32]).public());
        let k = root.keys();
        assert_ne!(
            k.sign.secret_bytes()[..],
            k.kem.expose()[..],
            "labels separate the keys"
        );
        let sealed = seal_box(&root.public().kem, b"x", b"for recovery").unwrap();
        assert_eq!(
            &open_box(&root.keys().kem, b"x", &sealed).unwrap()[..],
            b"for recovery"
        );
        assert_ne!(
            RecoveryRoot::generate().expose(),
            RecoveryRoot::generate().expose()
        );
    }

    #[test]
    fn public_keys_are_validated() {
        assert_eq!(KemPublic::from_bytes(&[0; 10]), Err(KeysError::InvalidKey));
        let ok = KemSecret::generate().public();
        assert_eq!(KemPublic::from_bytes(ok.as_bytes()).unwrap(), ok);
        assert!(format!("{:?}", KemSecret::generate()).contains("redacted"));
        assert!(format!("{:?}", RecoveryRoot::generate()).contains("redacted"));
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]
        #[test]
        fn tampered_boxes_never_open(pos in 0usize..4000, bit in 0u8..8, in_enc in any::<bool>()) {
            let a = KemSecret::generate();
            let mut sealed = seal_box(&a.public(), b"aad", b"payload").unwrap();
            let target = if in_enc { &mut sealed.enc } else { &mut sealed.ct };
            let i = pos % target.len();
            target[i] ^= 1 << bit;
            prop_assert!(open_box(&a, b"aad", &sealed).is_err());
        }

        #[test]
        fn arbitrary_boxes_never_open(enc in proptest::collection::vec(any::<u8>(), 0..1200), ct in proptest::collection::vec(any::<u8>(), 0..200)) {
            let a = KemSecret::generate();
            let b = SealedBox { enc, ct };
            let opened = open_box(&a, b"", &b).is_err();
            prop_assert!(opened);
        }
    }
}
