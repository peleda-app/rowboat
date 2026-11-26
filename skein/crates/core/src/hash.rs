use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Text that is not 64 lowercase hex digits.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("a blob hash is 64 lowercase hex digits")]
pub struct InvalidHash;

/// The BLAKE3 hash of a blob's bytes, its address in every blob store.
///
/// Serialized and displayed as 64 lowercase hex digits, which is also safe as a storage key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlobHash([u8; 32]);

impl BlobHash {
    /// The hash of `bytes`.
    pub fn of(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }

    /// Wraps raw hash bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw hash bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Whether `bytes` hash to this value; compared in constant time.
    pub fn matches(&self, bytes: &[u8]) -> bool {
        blake3::hash(bytes) == blake3::Hash::from_bytes(self.0)
    }

    /// Parses 64 lowercase hex digits.
    pub fn parse(text: &str) -> Result<Self, InvalidHash> {
        if text.len() != 64 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(InvalidHash);
        }
        let mut out = [0u8; 32];
        for (i, chunk) in text.as_bytes().chunks(2).enumerate() {
            let hi = (chunk[0] as char).to_digit(16).ok_or(InvalidHash)?;
            let lo = (chunk[1] as char).to_digit(16).ok_or(InvalidHash)?;
            out[i] = (hi * 16 + lo) as u8;
        }
        Ok(Self(out))
    }

    /// The hash as 64 lowercase hex digits.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl fmt::Display for BlobHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for BlobHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlobHash({})", &self.to_hex()[..12])
    }
}

impl Serialize for BlobHash {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for BlobHash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_hex() {
        let h = BlobHash::of(b"hello");
        assert_eq!(BlobHash::parse(&h.to_hex()).unwrap(), h);
        assert!(h.matches(b"hello"));
        assert!(!h.matches(b"hello!"));
    }

    #[test]
    fn refuses_bad_hex() {
        assert!(BlobHash::parse("").is_err());
        assert!(BlobHash::parse(&"A".repeat(64)).is_err());
        assert!(BlobHash::parse(&"0".repeat(63)).is_err());
        assert!(BlobHash::parse(&format!("{}/", "0".repeat(63))).is_err());
    }
}
