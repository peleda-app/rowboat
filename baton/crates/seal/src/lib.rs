//! Sealing bytes at rest: a versioned XChaCha20-Poly1305 envelope, 256-bit keys that are wiped
//! on drop, HKDF-SHA256 subkeys per purpose and associated data that binds every envelope to
//! its purpose and object id.
//!
//! Envelope v1: `0x01 || nonce (24) || ciphertext || tag (16)`. The associated data is
//! `"baton-seal/v1" || len(purpose) || purpose || len(object) || object` with 4-byte big-endian
//! lengths, so no two (purpose, object) pairs share it.

use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// The only envelope version this crate writes.
pub const VERSION: u8 = 1;
/// Length of a key in bytes.
pub const KEY_LEN: usize = 32;
/// Length of the random nonce in an envelope.
pub const NONCE_LEN: usize = 24;
/// Length of the authentication tag in an envelope.
pub const TAG_LEN: usize = 16;
/// Bytes an envelope adds to the plaintext: version, nonce and tag.
pub const OVERHEAD: usize = 1 + NONCE_LEN + TAG_LEN;

const AAD_LABEL: &[u8] = b"baton-seal/v1";
const SUBKEY_LABEL: &[u8] = b"baton-seal/v1 subkey ";

/// Errors of sealing and opening.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SealError {
    /// The envelope is shorter than the smallest valid envelope.
    #[error("sealed data is truncated")]
    Truncated,
    /// The envelope was written by a version this build does not know.
    #[error("unsupported envelope version {0}")]
    UnsupportedVersion(u8),
    /// Authentication failed: the bytes were changed, or sealed with another key, purpose or
    /// object id. Nothing about the plaintext is revealed.
    #[error("sealed data cannot be opened")]
    Invalid,
    /// The operating system could not supply random bytes.
    #[error("no randomness available")]
    Random,
    /// A key had the wrong length.
    #[error("a key must be {KEY_LEN} bytes")]
    KeyLength,
}

/// A 256-bit secret key.
///
/// Guarantees: the bytes are overwritten with zeros when the key is dropped, `Debug` never prints
/// them, and equality is not offered so keys are not compared in variable time by accident.
#[derive(Clone)]
pub struct Key([u8; KEY_LEN]);

impl Drop for Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for Key {}

impl Key {
    /// A fresh key from the operating system's random source.
    pub fn generate() -> Result<Self, SealError> {
        let mut bytes = [0u8; KEY_LEN];
        getrandom::fill(&mut bytes).map_err(|_| SealError::Random)?;
        let key = Self(bytes);
        bytes.zeroize();
        Ok(key)
    }

    /// Takes ownership of raw key bytes.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Copies a key from a slice, for example one read back from a vault. Fails unless the slice
    /// is exactly [`KEY_LEN`] bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, SealError> {
        let arr: [u8; KEY_LEN] = bytes.try_into().map_err(|_| SealError::KeyLength)?;
        Ok(Self(arr))
    }

    /// The raw bytes, for storing the key in a vault. Callers must not log or persist them in
    /// clear.
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// A subkey for `purpose` derived with HKDF-SHA256. The same key and purpose always give the
    /// same subkey; different purposes give independent keys.
    pub fn derive(&self, purpose: &str) -> Key {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut okm = [0u8; KEY_LEN];
        hk.expand_multi_info(&[SUBKEY_LABEL, purpose.as_bytes()], &mut okm)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        let key = Key(okm);
        okm.zeroize();
        key
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

/// What an envelope is bound to: a purpose label (`"vault-file item"`, `"snapshot"`) and the id
/// of the object it protects. Opening with any other pair fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context<'a> {
    /// The kind of data, also the HKDF label of the subkey used for it.
    pub purpose: &'a str,
    /// The id of the object within that purpose.
    pub object: &'a [u8],
}

impl<'a> Context<'a> {
    /// A context for `purpose` and `object`.
    pub fn new(purpose: &'a str, object: &'a [u8]) -> Self {
        Self { purpose, object }
    }

    fn aad(&self) -> Vec<u8> {
        let mut aad =
            Vec::with_capacity(AAD_LABEL.len() + 8 + self.purpose.len() + self.object.len());
        aad.extend_from_slice(AAD_LABEL);
        push_len_prefixed(&mut aad, self.purpose.as_bytes());
        push_len_prefixed(&mut aad, self.object);
        aad
    }
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("context fields are shorter than 4 GiB");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// A parsed envelope. Parsing checks the version and length only; authenticity is checked by
/// [`open`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Envelope<'a> {
    /// The envelope version, always [`VERSION`] after a successful decode.
    pub version: u8,
    /// The random nonce.
    pub nonce: &'a [u8; NONCE_LEN],
    /// The ciphertext followed by the tag.
    pub ciphertext: &'a [u8],
}

impl<'a> Envelope<'a> {
    /// Splits `bytes` into an envelope. Fails with [`SealError::Truncated`] when the input is
    /// shorter than [`OVERHEAD`] and with [`SealError::UnsupportedVersion`] for any version other
    /// than [`VERSION`].
    pub fn decode(bytes: &'a [u8]) -> Result<Self, SealError> {
        let (&version, rest) = bytes.split_first().ok_or(SealError::Truncated)?;
        if version != VERSION {
            return Err(SealError::UnsupportedVersion(version));
        }
        if bytes.len() < OVERHEAD {
            return Err(SealError::Truncated);
        }
        let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
        Ok(Self {
            version,
            nonce: nonce.try_into().expect("split at NONCE_LEN"),
            ciphertext,
        })
    }

    /// The wire form of the envelope.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + NONCE_LEN + self.ciphertext.len());
        out.push(self.version);
        out.extend_from_slice(self.nonce);
        out.extend_from_slice(self.ciphertext);
        out
    }
}

/// Seals `plaintext` under the subkey of `key` for `context.purpose`, bound to `context`.
///
/// Guarantees: a fresh random nonce per call, so sealing the same plaintext twice gives different
/// bytes; the output is exactly `plaintext.len() + OVERHEAD` bytes.
pub fn seal(key: &Key, context: Context<'_>, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| SealError::Random)?;
    seal_with_nonce(key, context, plaintext, nonce)
}

fn seal_with_nonce(
    key: &Key,
    context: Context<'_>,
    plaintext: &[u8],
    nonce: [u8; NONCE_LEN],
) -> Result<Vec<u8>, SealError> {
    let cipher = cipher(key, context.purpose);
    let aad = context.aad();
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| SealError::Invalid)?;
    Ok(Envelope {
        version: VERSION,
        nonce: &nonce,
        ciphertext: &ciphertext,
    }
    .encode())
}

/// Opens an envelope made by [`seal`] with the same key and context.
///
/// Guarantees: returns the plaintext only when every byte is as sealed and the key and context
/// match; otherwise [`SealError::Invalid`], [`SealError::Truncated`] or
/// [`SealError::UnsupportedVersion`]. The plaintext is wiped on drop.
pub fn open(
    key: &Key,
    context: Context<'_>,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let envelope = Envelope::decode(sealed)?;
    let cipher = cipher(key, context.purpose);
    let aad = context.aad();
    cipher
        .decrypt(
            &XNonce::from(*envelope.nonce),
            Payload {
                msg: envelope.ciphertext,
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| SealError::Invalid)
}

fn cipher(key: &Key, purpose: &str) -> XChaCha20Poly1305 {
    let sub = key.derive(purpose);
    XChaCha20Poly1305::new(&sub.0.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn key(b: u8) -> Key {
        Key::from_bytes([b; KEY_LEN])
    }

    const CTX: Context<'static> = Context {
        purpose: "test",
        object: b"object-1",
    };

    #[test]
    fn round_trip() {
        let k = key(7);
        let sealed = seal(&k, CTX, b"hello").unwrap();
        assert_eq!(sealed.len(), 5 + OVERHEAD);
        assert_eq!(sealed[0], VERSION);
        assert_eq!(&open(&k, CTX, &sealed).unwrap()[..], b"hello");
        for i in 0..sealed.len() {
            for bit in 0..8 {
                let mut bad = sealed.clone();
                bad[i] ^= 1 << bit;
                assert!(open(&k, CTX, &bad).is_err(), "byte {i} bit {bit}");
            }
        }
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let k = key(1);
        let sealed = seal(&k, CTX, b"").unwrap();
        assert_eq!(sealed.len(), OVERHEAD);
        assert!(open(&k, CTX, &sealed).unwrap().is_empty());
    }

    #[test]
    fn nonces_are_random() {
        let k = key(7);
        let a = seal(&k, CTX, b"same").unwrap();
        let b = seal(&k, CTX, b"same").unwrap();
        assert_ne!(a, b);
        assert_ne!(a[1..1 + NONCE_LEN], b[1..1 + NONCE_LEN]);
    }

    #[test]
    fn plaintext_does_not_show() {
        let sealed = seal(&key(3), CTX, b"secret-token-value").unwrap();
        assert!(!sealed.windows(6).any(|w| w == b"secret"));
    }

    #[test]
    fn wrong_key_purpose_or_object_fails() {
        let sealed = seal(&key(7), CTX, b"x").unwrap();
        assert_eq!(open(&key(8), CTX, &sealed).unwrap_err(), SealError::Invalid);
        assert_eq!(
            open(&key(7), Context::new("other", b"object-1"), &sealed).unwrap_err(),
            SealError::Invalid
        );
        assert_eq!(
            open(&key(7), Context::new("test", b"object-2"), &sealed).unwrap_err(),
            SealError::Invalid
        );
    }

    #[test]
    fn length_prefixes_keep_contexts_apart() {
        let sealed = seal(&key(7), Context::new("ab", b"c"), b"x").unwrap();
        assert!(open(&key(7), Context::new("a", b"bc"), &sealed).is_err());
    }

    #[test]
    fn truncated_and_unknown_versions_are_rejected() {
        let k = key(7);
        let sealed = seal(&k, CTX, b"payload").unwrap();
        assert_eq!(open(&k, CTX, &[]).unwrap_err(), SealError::Truncated);
        assert_eq!(open(&k, CTX, &[VERSION]).unwrap_err(), SealError::Truncated);
        assert_eq!(
            open(&k, CTX, &sealed[..OVERHEAD - 1]).unwrap_err(),
            SealError::Truncated
        );
        for cut in OVERHEAD..sealed.len() {
            assert_eq!(
                open(&k, CTX, &sealed[..cut]).unwrap_err(),
                SealError::Invalid
            );
        }
        for v in [0u8, 2, 0xff] {
            let mut bad = sealed.clone();
            bad[0] = v;
            assert_eq!(
                open(&k, CTX, &bad).unwrap_err(),
                SealError::UnsupportedVersion(v)
            );
        }
    }

    #[test]
    fn appended_bytes_are_rejected() {
        let k = key(7);
        let mut sealed = seal(&k, CTX, b"payload").unwrap();
        sealed.push(0);
        assert_eq!(open(&k, CTX, &sealed).unwrap_err(), SealError::Invalid);
    }

    #[test]
    fn subkeys_are_deterministic_and_separated() {
        let k = key(9);
        assert_eq!(k.derive("a").expose(), k.derive("a").expose());
        assert_ne!(k.derive("a").expose(), k.derive("b").expose());
        assert_ne!(k.derive("a").expose(), k.expose());
    }

    #[test]
    fn known_nonce_is_stable() {
        let a = seal_with_nonce(&key(1), CTX, b"abc", [5; NONCE_LEN]).unwrap();
        let b = seal_with_nonce(&key(1), CTX, b"abc", [5; NONCE_LEN]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn debug_hides_key_bytes() {
        let k = key(0xab);
        let shown = format!("{k:?}");
        assert_eq!(shown, "Key(<redacted>)");
        assert!(!shown.contains("171"));
    }

    #[test]
    fn key_from_slice_checks_length() {
        assert!(Key::from_slice(&[0; 31]).is_err());
        assert!(Key::from_slice(&[0; 33]).is_err());
        assert!(Key::from_slice(&[0; 32]).is_ok());
        assert!(Key::generate().is_ok());
    }

    #[test]
    fn envelope_encode_decode_round_trips() {
        let sealed = seal(&key(2), CTX, b"xyz").unwrap();
        let env = Envelope::decode(&sealed).unwrap();
        assert_eq!(env.encode(), sealed);
    }

    proptest! {
        #[test]
        fn any_flipped_bit_is_detected(
            plaintext in proptest::collection::vec(any::<u8>(), 0..256),
            index in any::<prop::sample::Index>(),
            bit in 0u8..8,
        ) {
            let k = key(4);
            let sealed = seal(&k, CTX, &plaintext).unwrap();
            let i = index.index(sealed.len());
            let mut bad = sealed.clone();
            bad[i] ^= 1 << bit;
            prop_assert!(open(&k, CTX, &bad).is_err());
            prop_assert_eq!(&open(&k, CTX, &sealed).unwrap()[..], &plaintext[..]);
        }

        #[test]
        fn random_bytes_never_open(bytes in proptest::collection::vec(any::<u8>(), 0..128)) {
            prop_assert!(open(&key(4), CTX, &bytes).is_err());
        }
    }
}
