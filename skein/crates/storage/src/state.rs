use std::sync::Arc;

use async_trait::async_trait;
use baton_core::GroupId;
use baton_state::{RecordName, StateError, StateStore};
use bytes::{BufMut, Bytes, BytesMut};
use skein_core::TenantId;

use crate::{ControlStore, Expect, StorageError, Version};

/// The area of a tenant's control records that holds [`ControlState`] records.
pub const STATE_AREA: &str = "baton";

const FORMAT: u8 = 1;
const NONCE_LEN: usize = 16;
pub(crate) const HEADER_LEN: usize = 1 + NONCE_LEN;

/// Baton's [`StateStore`] over any [`ControlStore`], so Baton's leases and liveness live in the
/// same store as the rest of a tenant's control records.
///
/// Guarantees, on top of the [`StateStore`] contract (checked by [`crate::testing::control_state`]
/// on every backend):
///
/// - A group maps to the tenant of the same id, and record `name` to a control path under
///   `baton/`, so records of different groups never mix and never collide with Skein's own
///   control records. [`ControlStore::purge`] removes them with the tenant's other records.
/// - In the path, `-` is written `--`, `.` is written `-.` and the separator `/` is written `-/`.
///   This keeps the byte order of names, so listings and paging follow the contract, and no path
///   is ever a prefix of another (`a` next to `a/b` becomes `a` next to `a-/b`), which stores
///   backed by a file system (S3 gateways over POSIX) cannot hold. A name with a non-final segment
///   of 64 bytes made only of `-` and `.` does not fit a storage key segment and is refused with
///   [`StateError::InvalidName`].
/// - Every record is stored as a format byte, 16 random bytes and the value, so every write
///   changes the stored bytes and the backend's version, even on stores whose version is a content
///   hash (S3 ETags): a version is never reused for a record, also after delete and recreate.
/// - A stored object that is not such a record (a foreign object, a truncated or unknown-format
///   one) is never returned as a value: `get` fails with [`StateError::Backend`], and `list` skips
///   names that are not valid [`RecordName`]s.
/// - `Ok` means durable exactly when the underlying store's writes are durable (`storage-fs` and
///   `storage-s3` are; `storage-memory` is not).
/// - Deletes with [`baton_state::Expect::Version`] inherit the store's delete semantics: stores
///   without conditional deletes (S3) check the version first and leave a short race.
pub struct ControlState {
    control: Arc<dyn ControlStore>,
}

impl ControlState {
    /// Baton state in `control`.
    pub fn new(control: Arc<dyn ControlStore>) -> Self {
        Self { control }
    }
}

fn tenant(group: &GroupId) -> TenantId {
    skein_core::coordination::tenant(group)
}

fn encode(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 8);
    for c in name.chars() {
        match c {
            '-' => out.push_str("--"),
            '.' => out.push_str("-."),
            '/' => out.push_str("-/"),
            c => out.push(c),
        }
    }
    out
}

fn decode(encoded: &str) -> Option<RecordName> {
    let mut out = String::with_capacity(encoded.len());
    let mut chars = encoded.chars();
    while let Some(c) = chars.next() {
        match c {
            '-' => match chars.next()? {
                '-' => out.push('-'),
                '.' => out.push('.'),
                '/' => out.push('/'),
                _ => return None,
            },
            '.' | '/' => return None,
            c => out.push(c),
        }
    }
    RecordName::new(out).ok()
}

pub(crate) fn path(name: &RecordName) -> String {
    format!("{STATE_AREA}/{}", encode(name.as_str()))
}

pub(crate) fn name(path: &str) -> Option<RecordName> {
    decode(path.strip_prefix(STATE_AREA)?.strip_prefix('/')?)
}

fn expect(e: baton_state::Expect) -> Expect {
    match e {
        baton_state::Expect::Any => Expect::Any,
        baton_state::Expect::Absent => Expect::Absent,
        baton_state::Expect::Version(v) => Expect::Version(Version(v.0)),
    }
}

fn error(e: StorageError) -> StateError {
    match e {
        StorageError::Conflict => StateError::Conflict,
        StorageError::InvalidKey(_) => StateError::InvalidName,
        other => StateError::backend(other),
    }
}

pub(crate) fn seal(value: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(HEADER_LEN + value.len());
    out.put_u8(FORMAT);
    out.put_slice(&ulid::Ulid::generate().0.to_be_bytes());
    out.put_slice(value);
    out.freeze()
}

pub(crate) fn open(stored: Bytes) -> Result<Bytes, StateError> {
    if stored.len() < HEADER_LEN || stored[0] != FORMAT {
        return Err(StateError::backend(StorageError::Corrupt(
            "not a state record".into(),
        )));
    }
    Ok(stored.slice(HEADER_LEN..))
}

#[async_trait]
impl StateStore for ControlState {
    async fn get(
        &self,
        group: &GroupId,
        name: &RecordName,
    ) -> Result<Option<(Bytes, baton_state::Version)>, StateError> {
        match self
            .control
            .get(&tenant(group), &path(name))
            .await
            .map_err(error)?
        {
            None => Ok(None),
            Some((stored, version)) => Ok(Some((open(stored)?, baton_state::Version(version.0)))),
        }
    }

    async fn put(
        &self,
        group: &GroupId,
        name: &RecordName,
        value: Bytes,
        e: baton_state::Expect,
    ) -> Result<baton_state::Version, StateError> {
        baton_state::check_value(&value)?;
        let version = self
            .control
            .put(&tenant(group), &path(name), seal(&value), expect(e))
            .await
            .map_err(error)?;
        Ok(baton_state::Version(version.0))
    }

    async fn delete(
        &self,
        group: &GroupId,
        name: &RecordName,
        e: baton_state::Expect,
    ) -> Result<(), StateError> {
        self.control
            .delete(&tenant(group), &path(name), expect(e))
            .await
            .map_err(error)
    }

    async fn list(
        &self,
        group: &GroupId,
        prefix: &RecordName,
        after: Option<&RecordName>,
        limit: usize,
    ) -> Result<Vec<RecordName>, StateError> {
        let tenant = tenant(group);
        let base = format!("{}-", path(prefix));
        let mut out = Vec::new();
        let mut cursor = after.map(path);
        while out.len() < limit {
            let want = limit - out.len();
            let page = self
                .control
                .list(&tenant, &base, cursor.as_deref(), want)
                .await
                .map_err(error)?;
            let done = page.len() < want;
            out.extend(page.iter().filter_map(|p| name(p)));
            if done {
                break;
            }
            cursor = page.last().cloned();
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::ObjectKey;

    #[test]
    fn foreign_and_truncated_objects_are_not_records() {
        for bad in [
            &b""[..],
            &[FORMAT][..],
            &[FORMAT; HEADER_LEN - 1][..],
            &[2; 40][..],
            b"{\"fence\":1}",
        ] {
            assert!(
                matches!(
                    open(Bytes::copy_from_slice(bad)),
                    Err(StateError::Backend(_))
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn paths_escape_dashes_dots_and_separators() {
        let n = |s: &str| RecordName::new(s).unwrap();
        assert_eq!(path(&n("lease/res-1")), "baton/lease-/res--1");
        assert_eq!(path(&n("nodes/a.b")), "baton/nodes-/a-.b");
        assert_eq!(path(&n("list")), "baton/list");
        for bad in [
            "baton/a-",
            "baton/a-x",
            "baton/a.b",
            "baton/A",
            "baton/a-/",
            "other/a",
            "baton",
        ] {
            assert_eq!(name(bad), None, "{bad}");
        }
        let longest = "-".repeat(64);
        assert!(
            ObjectKey::root("t")
                .unwrap()
                .join_path(&path(&n(&longest)))
                .is_ok()
        );
        assert!(
            ObjectKey::root("t")
                .unwrap()
                .join_path(&path(&n(&format!("{longest}/a"))))
                .is_err()
        );
    }

    #[test]
    fn identical_values_are_stored_as_different_bytes() {
        assert_ne!(seal(b"same"), seal(b"same"));
    }

    proptest! {
        #[test]
        fn records_round_trip(value in proptest::collection::vec(any::<u8>(), 0..512)) {
            prop_assert_eq!(&open(seal(&value)).unwrap()[..], &value[..]);
        }

        #[test]
        fn any_stored_bytes_either_fail_or_open(stored in proptest::collection::vec(any::<u8>(), 0..64)) {
            if let Ok(value) = open(Bytes::from(stored.clone())) {
                prop_assert_eq!(stored[0], FORMAT);
                prop_assert_eq!(&value[..], &stored[HEADER_LEN..]);
            }
        }

        #[test]
        fn names_round_trip_through_paths(s in "[a-z0-9_./-]{1,200}") {
            if let Ok(n) = RecordName::new(s) {
                let p = path(&n);
                prop_assert_eq!(name(&p), Some(n.clone()));
                if n.as_str().split('/').all(|seg| seg.len() < 64) {
                    let key = ObjectKey::root("t").unwrap().join_path(&p).unwrap();
                    prop_assert!(key.segments().all(|seg| !seg.starts_with('.')));
                }
            }
        }

        #[test]
        fn paths_keep_the_order_of_names_and_never_nest(
            a in "[a-z0-9_./-]{1,40}",
            b in "[a-z0-9_./-]{1,40}",
        ) {
            if let (Ok(a), Ok(b)) = (RecordName::new(a), RecordName::new(b)) {
                let (pa, pb) = (path(&a), path(&b));
                prop_assert_eq!(a.cmp(&b), pa.cmp(&pb));
                let (nested, under) = (format!("{pa}/"), format!("{pa}-/"));
                prop_assert!(!pb.starts_with(&nested));
                prop_assert_eq!(b.is_under(&a), pb.starts_with(&under));
            }
        }

        #[test]
        fn foreign_paths_decode_to_valid_names_or_nothing(s in "[a-zA-Z0-9_./-]{0,80}") {
            if let Some(n) = decode(&s) {
                prop_assert_eq!(encode(n.as_str()), s);
            }
        }

        #[test]
        fn every_group_is_a_tenant(s in "[a-z0-9_-]{1,64}") {
            if let Ok(g) = GroupId::new(s) {
                let t = tenant(&g);
                prop_assert_eq!(t.as_str(), g.as_str());
            }
        }
    }
}
