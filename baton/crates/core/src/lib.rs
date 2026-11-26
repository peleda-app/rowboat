//! Ids, fencing tokens and time shared by every Baton crate and by applications built on Baton.
//!
//! No I/O, no traits: only the small value types that cross contract boundaries.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Deserializer, Serialize};

/// An id that is empty, too long or holds characters outside `[a-z0-9_-]`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("an id is 1 to 64 characters of a-z, 0-9, '_' and '-', not starting with '-'")]
pub struct InvalidId;

/// The longest id, in bytes.
pub const MAX_ID_LEN: usize = 64;

fn check(value: &str) -> Result<(), InvalidId> {
    let ok = !value.is_empty()
        && value.len() <= MAX_ID_LEN
        && !value.starts_with('-')
        && !reserved_name(value)
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
    if ok { Ok(()) } else { Err(InvalidId) }
}

/// Whether `segment` is a name Windows reserves for a device (`con`, `prn`, `aux`, `nul`,
/// `conin$`, `conout$`, `com0`–`com9`, `lpt0`–`lpt9`), with or without an extension, compared in
/// lowercase. Such names cannot be used as a file name there, so no id and no record name segment
/// may be one.
pub fn reserved_name(segment: &str) -> bool {
    let stem = segment.split('.').next().unwrap_or(segment);
    matches!(stem, "con" | "prn" | "aux" | "nul" | "conin$" | "conout$")
        || ((stem.starts_with("com") || stem.starts_with("lpt"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit())
}

macro_rules! id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        ///
        /// Ids are 1 to 64 characters of `[a-z0-9_-]`, never start with `-` and are never a Windows
        /// device name, so they are safe as a single path segment in any storage key or file system:
        /// no separators, no `.` or `..`, no case folding, no reserved names.
        /// Deserializing checks the same rules, so an id read from untrusted bytes is always valid.
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Checks and wraps `value`.
            pub fn new(value: impl Into<String>) -> Result<Self, InvalidId> {
                let value = value.into();
                check(&value)?;
                Ok(Self(value))
            }

            /// The id as text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl std::str::FromStr for $name {
            type Err = InvalidId;
            fn from_str(s: &str) -> Result<Self, InvalidId> {
                Self::new(s)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                Self::new(s).map_err(serde::de::Error::custom)
            }
        }
    };
}

id!(
    /// A group: the trust domain of one person or one team. Applications that speak of tenants map
    /// a tenant to a group.
    GroupId
);
id!(
    /// A node: one device or server. With `baton-identity` it is the node's public key in
    /// lowercase unpadded base32.
    NodeId
);
id!(
    /// What a lease is held on: a resource or a job, named by the application.
    LeaseKey
);
id!(
    /// A resource: a unit of data and work with its own capabilities and keys.
    ResourceId
);

/// Milliseconds since the Unix epoch, UTC.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Timestamp(pub i64);

impl Timestamp {
    /// The current time from the system clock.
    pub fn now() -> Self {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        Self(ms)
    }

    /// This time plus `ms` milliseconds, saturating.
    pub fn plus_ms(self, ms: i64) -> Self {
        Self(self.0.saturating_add(ms))
    }
}

/// A token that grows every time a lease changes holder. Storage that a leaseholder writes to
/// must refuse writes carrying a token lower than one it has already seen for that key, so a node
/// that lost a lease cannot write any more, even before it notices.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct FencingToken(pub u64);

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn ids_refuse_anything_that_could_escape_a_path_segment() {
        for bad in [
            "", "-a", "A", "a/b", "a\\b", "..", ".", "a.b", "a b", "a\0b", "ä", "a:b", "a%2f",
            "con", "nul", "aux", "prn", "com1", "lpt9",
        ] {
            assert_eq!(NodeId::new(bad), Err(InvalidId), "{bad:?}");
        }
        assert!(NodeId::new("a".repeat(MAX_ID_LEN)).is_ok());
        assert_eq!(NodeId::new("a".repeat(MAX_ID_LEN + 1)), Err(InvalidId));
        for good in ["a", "0", "_a", "a-b_c9"] {
            assert!(GroupId::new(good).is_ok(), "{good:?}");
        }
    }

    #[test]
    fn deserializing_checks_the_rules() {
        assert!(serde_json::from_str::<LeaseKey>("\"res-1\"").is_ok());
        assert!(serde_json::from_str::<LeaseKey>("\"../etc\"").is_err());
        assert!(serde_json::from_str::<LeaseKey>("\"\"").is_err());
    }

    #[test]
    fn plus_ms_saturates() {
        assert_eq!(Timestamp(i64::MAX).plus_ms(1), Timestamp(i64::MAX));
        assert_eq!(Timestamp(i64::MIN).plus_ms(-1), Timestamp(i64::MIN));
    }

    proptest! {
        #[test]
        fn any_string_either_fails_or_round_trips(s in "\\PC{0,80}") {
            if let Ok(id) = NodeId::new(s.clone()) {
                prop_assert_eq!(id.as_str(), s.as_str());
                let json = serde_json::to_string(&id).unwrap();
                prop_assert_eq!(serde_json::from_str::<NodeId>(&json).unwrap(), id);
                prop_assert!(!s.contains('/') && !s.contains('.'));
            }
        }
    }
}
