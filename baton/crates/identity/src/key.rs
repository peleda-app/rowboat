use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

use baton_core::NodeId;
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::IdentityError;

fn framed(context: &str, message: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(context.len() + 1 + message.len());
    v.extend_from_slice(context.as_bytes());
    v.push(0);
    v.extend_from_slice(message);
    v
}

/// A node's Ed25519 key pair. `Debug` shows only the node id; the secret half is zeroized on drop.
#[derive(Clone)]
pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    /// A fresh identity from the operating system's random source.
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    /// Restores an identity from the 32 secret bytes returned by [`Identity::secret_bytes`].
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(secret),
        }
    }

    /// The secret bytes, for storing the identity in the node's keyring. Zeroized on drop.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }

    /// The public half.
    pub fn public(&self) -> PublicKey {
        PublicKey(self.signing.verifying_key())
    }

    /// The node id of the public half.
    pub fn node_id(&self) -> NodeId {
        self.public().node_id()
    }

    /// Signs `message` under `context`. A signature made under one context never verifies under
    /// another, so signatures cannot be replayed across protocols.
    pub fn sign(&self, context: &str, message: &[u8]) -> Signature {
        Signature(self.signing.sign(&framed(context, message)))
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identity({}, <secret redacted>)", self.node_id())
    }
}

/// An Ed25519 public key: the identity of a node. Ordered and compared by its bytes.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    /// Checks and wraps 32 key bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, IdentityError> {
        VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| IdentityError::InvalidKey)
    }

    /// The 32 key bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// The node id: the key in lowercase unpadded base32, 52 characters of `[a-z2-7]`. It fits
    /// the id rules of `baton-core` and maps back to exactly this key.
    pub fn node_id(&self) -> NodeId {
        NodeId::new(BASE32_NOPAD.encode(self.0.as_bytes()).to_ascii_lowercase())
            .expect("base32 of a key is a valid node id")
    }

    /// The key a node id names, if it was made by [`PublicKey::node_id`].
    pub fn from_node_id(id: &NodeId) -> Result<Self, IdentityError> {
        let bytes = BASE32_NOPAD
            .decode(id.as_str().to_ascii_uppercase().as_bytes())
            .map_err(|_| IdentityError::InvalidKey)?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| IdentityError::InvalidKey)?;
        Self::from_bytes(&bytes)
    }

    /// Checks a signature made by [`Identity::sign`] with the same `context` and `message`.
    /// Uses strict verification, so malleated signatures and weak keys are refused.
    pub fn verify(
        &self,
        context: &str,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), IdentityError> {
        self.0
            .verify_strict(&framed(context, message), &signature.0)
            .map_err(|_| IdentityError::BadSignature)
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_bytes().hash(state);
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.node_id())
    }
}

/// An Ed25519 signature made under a context by [`Identity::sign`].
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Signature(ed25519_dalek::Signature);

impl Signature {
    /// The 64 signature bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.to_bytes()
    }

    /// Wraps 64 signature bytes; whether they verify is checked by [`PublicKey::verify`].
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        Self(ed25519_dalek::Signature::from_bytes(bytes))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Signature(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_round_trips_and_fits_id_rules() {
        let id = Identity::generate();
        let node = id.node_id();
        assert_eq!(node.as_str().len(), 52);
        assert!(
            node.as_str()
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        );
        assert_eq!(PublicKey::from_node_id(&node).unwrap(), id.public());
        assert!(PublicKey::from_node_id(&NodeId::new("node-a").unwrap()).is_err());
    }

    #[test]
    fn signatures_are_bound_to_context_and_key() {
        let a = Identity::generate();
        let b = Identity::generate();
        let sig = a.sign("ctx-1", b"hello");
        assert!(a.public().verify("ctx-1", b"hello", &sig).is_ok());
        assert!(a.public().verify("ctx-2", b"hello", &sig).is_err());
        assert!(a.public().verify("ctx-1", b"hellO", &sig).is_err());
        assert!(b.public().verify("ctx-1", b"hello", &sig).is_err());
    }

    #[test]
    fn secret_round_trips_and_debug_redacts() {
        let a = Identity::generate();
        let restored = Identity::from_secret_bytes(&a.secret_bytes());
        assert_eq!(restored.public(), a.public());
        let secret_hex: String = a
            .secret_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let shown = format!("{a:?}");
        assert!(!shown.contains(&secret_hex));
        assert!(shown.contains("redacted"));
    }
}
