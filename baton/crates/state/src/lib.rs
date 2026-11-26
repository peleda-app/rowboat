//! The durable state Baton hands to the application.
//!
//! Baton has no storage of its own. Everything it must keep across restarts (lease records,
//! heartbeats when nodes cannot reach each other, later the group log and key boxes) goes through
//! a [`StateStore`] the application implements: on a local disk, in object storage, anywhere that
//! can do compare-and-swap on small records.

#[cfg(feature = "testing")]
pub mod testing;

use async_trait::async_trait;
use baton_core::GroupId;
use bytes::Bytes;

/// The largest record value, in bytes.
pub const MAX_VALUE: usize = 1024 * 1024;

/// The longest record name, in bytes.
pub const MAX_NAME: usize = 256;

/// Errors of the state contract.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// A record name that breaks [`RecordName`]'s rules.
    #[error("invalid record name")]
    InvalidName,
    /// A value larger than [`MAX_VALUE`]; nothing was written.
    #[error("record value too large")]
    TooLarge,
    /// The expectation did not hold; nothing was written.
    #[error("record changed concurrently")]
    Conflict,
    /// The backend failed; the call may be retried. A failed `put` may or may not have been
    /// written, as with any storage.
    #[error("state backend failed: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl StateError {
    /// Wraps any backend error.
    pub fn backend(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self::Backend(e.into())
    }
}

/// The name of a record within a group: segments of 1–64 bytes of `[a-z0-9_.-]` joined by `/`,
/// at most [`MAX_NAME`] bytes in all. No empty segment, no segment starting or ending with `.`
/// (so no `.` or `..`, and nothing a Windows file system would strip), no Windows device name
/// (`con`, `nul`, `com1`, ... with or without an extension), no leading or trailing `/`, so a name
/// maps to a storage key or a file path without any way to escape its group or alias another name.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct RecordName(String);

impl RecordName {
    /// Checks and wraps `value`.
    pub fn new(value: impl Into<String>) -> Result<Self, StateError> {
        let value = value.into();
        let ok = !value.is_empty()
            && value.len() <= MAX_NAME
            && value.split('/').all(|seg| {
                !seg.is_empty()
                    && seg.len() <= 64
                    && !seg.starts_with('.')
                    && !seg.ends_with('.')
                    && !baton_core::reserved_name(seg)
                    && seg.bytes().all(|b| {
                        b.is_ascii_lowercase()
                            || b.is_ascii_digit()
                            || matches!(b, b'_' | b'.' | b'-')
                    })
            });
        if ok {
            Ok(Self(value))
        } else {
            Err(StateError::InvalidName)
        }
    }

    /// The name as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this name lies under `prefix`: equal segments up to the prefix's length, so
    /// `lease` covers `lease/a` but not `leases/a`.
    pub fn is_under(&self, prefix: &RecordName) -> bool {
        self.0
            .strip_prefix(prefix.as_str())
            .is_some_and(|rest| rest.starts_with('/'))
    }
}

impl std::fmt::Display for RecordName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The version of a stored record, opaque to callers (an ETag, a counter). Every successful write
/// produces a version different from every earlier version of that record.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Version(pub String);

/// What must hold for a write to happen.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Expect {
    /// Write whatever is there.
    Any,
    /// Only if the record does not exist.
    Absent,
    /// Only if the record exists at exactly this version.
    Version(Version),
}

/// Small records with compare-and-swap, scoped to a group.
///
/// Guarantees (checked by [`testing::state`]):
///
/// - Records of different groups never mix, whatever the names.
/// - A `put` or `delete` whose [`Expect`] does not hold returns [`StateError::Conflict`] and
///   changes nothing. Of any number of concurrent writes expecting the same state, at most one
///   succeeds.
/// - A write that returned `Ok` is durable: it survives a crash or power loss of the process and
///   the machine, and every later `get` sees it or a later write.
/// - `get` returns the value and version of the last successful write, or `None` after a delete.
/// - `list` returns names under the prefix in ascending byte order, strictly after `after` (which
///   need not exist), at most `limit` of them. A page shorter than `limit` does not mean the end:
///   callers page with the last name until a page comes back empty.
/// - A value over [`MAX_VALUE`] is refused with [`StateError::TooLarge`] before anything is
///   written.
#[async_trait]
pub trait StateStore: Send + Sync {
    /// The record's value and version, if it exists.
    async fn get(
        &self,
        group: &GroupId,
        name: &RecordName,
    ) -> Result<Option<(Bytes, Version)>, StateError>;

    /// Writes a record if `expect` holds; returns its new version.
    async fn put(
        &self,
        group: &GroupId,
        name: &RecordName,
        value: Bytes,
        expect: Expect,
    ) -> Result<Version, StateError>;

    /// Removes a record if `expect` holds. Removing a missing record with [`Expect::Any`] is not
    /// an error.
    async fn delete(
        &self,
        group: &GroupId,
        name: &RecordName,
        expect: Expect,
    ) -> Result<(), StateError>;

    /// Names under `prefix`, in ascending order, after `after`, at most `limit`.
    async fn list(
        &self,
        group: &GroupId,
        prefix: &RecordName,
        after: Option<&RecordName>,
        limit: usize,
    ) -> Result<Vec<RecordName>, StateError>;
}

/// The largest secret a [`SecretStore`] keeps, in bytes.
pub const MAX_SECRET: usize = 16 * 1024;

/// Named secrets on this device: node keys, opened resource keys. Never exported in clear.
///
/// Guarantees (checked by [`testing::secrets`]): `get` returns what the last `put` stored, or
/// `None` after `delete`; a secret over [`MAX_SECRET`] is refused with [`StateError::TooLarge`]
/// and nothing is stored; returned secrets are wiped from memory when dropped; implementations
/// never put secret bytes in errors or logs.
#[async_trait]
pub trait SecretStore: Send + Sync {
    /// Stores or replaces a secret.
    async fn put(
        &self,
        name: &RecordName,
        secret: zeroize::Zeroizing<Vec<u8>>,
    ) -> Result<(), StateError>;

    /// The secret, if present.
    async fn get(
        &self,
        name: &RecordName,
    ) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, StateError>;

    /// Removes a secret; removing a missing one is fine.
    async fn delete(&self, name: &RecordName) -> Result<(), StateError>;
}

/// Refuses a value over [`MAX_VALUE`]; implementations call it before writing.
pub fn check_value(value: &[u8]) -> Result<(), StateError> {
    if value.len() > MAX_VALUE {
        Err(StateError::TooLarge)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn names_cannot_escape_or_alias() {
        for bad in [
            "", "/", "a/", "/a", "a//b", ".", "..", "a/../b", "a/./b", "A", "a b", "a\\b", "a\0",
            "ä", "a:b", "a.", "...", ".a", "x/a.", "con", "nul.txt", "x/aux", "com1", "lpt9.log",
            "prn",
        ] {
            assert!(RecordName::new(bad).is_err(), "{bad:?}");
        }
        assert!(RecordName::new("a".repeat(65)).is_err());
        let long = vec!["a".repeat(64); 4].join("/");
        assert!(long.len() > MAX_NAME);
        assert!(RecordName::new(long).is_err());
        for good in [
            "a",
            "lease/res-1",
            "nodes/x.y",
            "a/b/c_d-e",
            "com",
            "com10",
            "console",
            "a.b.c",
        ] {
            assert!(RecordName::new(good).is_ok(), "{good:?}");
        }
    }

    #[test]
    fn prefixes_match_whole_segments() {
        let lease = RecordName::new("lease").unwrap();
        assert!(RecordName::new("lease/a").unwrap().is_under(&lease));
        assert!(!RecordName::new("leases/a").unwrap().is_under(&lease));
        assert!(!RecordName::new("lease").unwrap().is_under(&lease));
    }

    #[test]
    fn value_limit() {
        assert!(check_value(&vec![0; MAX_VALUE]).is_ok());
        assert!(matches!(
            check_value(&vec![0; MAX_VALUE + 1]),
            Err(StateError::TooLarge)
        ));
    }

    proptest! {
        #[test]
        fn every_valid_id_makes_a_valid_record_name(s in "[a-z0-9_-]{1,64}") {
            if let Ok(id) = baton_core::LeaseKey::new(s.clone()) {
                let ok = RecordName::new(format!("lease/{}", id)).is_ok();
                prop_assert!(ok);
                let ok = RecordName::new(format!("quorum/{}", id)).is_ok();
                prop_assert!(ok);
                let ok = RecordName::new(format!("nodes/{}", id)).is_ok();
                prop_assert!(ok);
            }
        }

        #[test]
        fn valid_names_never_hold_traversal(s in "\\PC{0,300}") {
            if let Ok(n) = RecordName::new(s) {
                prop_assert!(n.as_str().split('/').all(|seg| !seg.is_empty() && !seg.starts_with('.') && !seg.ends_with('.')));
                prop_assert!(n.as_str().len() <= MAX_NAME);
            }
        }
    }
}
