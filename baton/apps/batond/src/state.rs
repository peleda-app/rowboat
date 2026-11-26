//! [`RedbState`]: batond's `StateStore` in one redb file.

use std::ops::Bound;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use baton_core::GroupId;
use baton_state::{Expect, RecordName, StateError, StateStore, Version, check_value};
use bytes::Bytes;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

const RECORDS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("records");
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");
const LAST_VERSION: &str = "last_version";

/// A [`StateStore`] in one redb file.
///
/// Records live under `group ‖ 0x00 ‖ name` (neither contains a zero byte, so groups never mix
/// and names sort as the contract asks); each value is `version (u64 big endian) ‖ bytes`, the
/// version drawn from one store-wide counter, so no write ever repeats an earlier version of a
/// record, even after a delete. Every call is one redb transaction on a blocking thread, flushed
/// before it returns.
pub struct RedbState {
    db: Arc<Database>,
}

fn backend(e: impl std::error::Error + Send + Sync + 'static) -> StateError {
    StateError::backend(e)
}

#[derive(Debug, thiserror::Error)]
#[error("corrupted record")]
struct Corrupted;

fn key(group: &GroupId, name: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(group.as_str().len() + 1 + name.len());
    k.extend_from_slice(group.as_str().as_bytes());
    k.push(0);
    k.extend_from_slice(name.as_bytes());
    k
}

fn split(raw: &[u8]) -> Result<(u64, &[u8]), StateError> {
    if raw.len() < 8 {
        return Err(backend(Corrupted));
    }
    let (v, rest) = raw.split_at(8);
    Ok((u64::from_be_bytes(v.try_into().expect("8 bytes")), rest))
}

fn version_of(v: u64) -> Version {
    Version(v.to_string())
}

fn holds(current: Option<u64>, expect: &Expect) -> bool {
    match (expect, current) {
        (Expect::Any, _) => true,
        (Expect::Absent, None) => true,
        (Expect::Version(want), Some(v)) => *want == version_of(v),
        _ => false,
    }
}

impl RedbState {
    /// Opens (or creates) the store at `path`.
    pub fn open(path: &Path) -> Result<Self, StateError> {
        let db = Database::create(path).map_err(backend)?;
        let tx = db.begin_write().map_err(backend)?;
        {
            tx.open_table(RECORDS).map_err(backend)?;
            tx.open_table(META).map_err(backend)?;
        }
        tx.commit().map_err(backend)?;
        Ok(Self { db: Arc::new(db) })
    }

    async fn blocking<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Database) -> Result<T, StateError> + Send + 'static,
    ) -> Result<T, StateError> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || f(&db))
            .await
            .map_err(backend)?
    }
}

#[async_trait]
impl StateStore for RedbState {
    async fn get(
        &self,
        group: &GroupId,
        name: &RecordName,
    ) -> Result<Option<(Bytes, Version)>, StateError> {
        let k = key(group, name.as_str());
        self.blocking(move |db| {
            let tx = db.begin_read().map_err(backend)?;
            let t = tx.open_table(RECORDS).map_err(backend)?;
            match t.get(&k[..]).map_err(backend)? {
                Some(raw) => {
                    let (v, value) = split(raw.value())?;
                    Ok(Some((Bytes::copy_from_slice(value), version_of(v))))
                }
                None => Ok(None),
            }
        })
        .await
    }

    async fn put(
        &self,
        group: &GroupId,
        name: &RecordName,
        value: Bytes,
        expect: Expect,
    ) -> Result<Version, StateError> {
        check_value(&value)?;
        let k = key(group, name.as_str());
        self.blocking(move |db| {
            let tx = db.begin_write().map_err(backend)?;
            let next = {
                let mut t = tx.open_table(RECORDS).map_err(backend)?;
                let current = match t.get(&k[..]).map_err(backend)? {
                    Some(raw) => Some(split(raw.value())?.0),
                    None => None,
                };
                if !holds(current, &expect) {
                    return Err(StateError::Conflict);
                }
                let mut meta = tx.open_table(META).map_err(backend)?;
                let last = meta
                    .get(LAST_VERSION)
                    .map_err(backend)?
                    .map_or(0, |v| v.value());
                let next = last.checked_add(1).ok_or_else(|| backend(Corrupted))?;
                meta.insert(LAST_VERSION, next).map_err(backend)?;
                let mut stored = Vec::with_capacity(8 + value.len());
                stored.extend_from_slice(&next.to_be_bytes());
                stored.extend_from_slice(&value);
                t.insert(&k[..], &stored[..]).map_err(backend)?;
                next
            };
            tx.commit().map_err(backend)?;
            Ok(version_of(next))
        })
        .await
    }

    async fn delete(
        &self,
        group: &GroupId,
        name: &RecordName,
        expect: Expect,
    ) -> Result<(), StateError> {
        let k = key(group, name.as_str());
        self.blocking(move |db| {
            let tx = db.begin_write().map_err(backend)?;
            {
                let mut t = tx.open_table(RECORDS).map_err(backend)?;
                let current = match t.get(&k[..]).map_err(backend)? {
                    Some(raw) => Some(split(raw.value())?.0),
                    None => None,
                };
                if !holds(current, &expect) {
                    return Err(StateError::Conflict);
                }
                if current.is_some() {
                    t.remove(&k[..]).map_err(backend)?;
                }
            }
            tx.commit().map_err(backend)
        })
        .await
    }

    async fn list(
        &self,
        group: &GroupId,
        prefix: &RecordName,
        after: Option<&RecordName>,
        limit: usize,
    ) -> Result<Vec<RecordName>, StateError> {
        let start_name = format!("{}/", prefix.as_str());
        let lo = key(group, &start_name);
        let hi = key(group, &format!("{}0", prefix.as_str()));
        let skip = key(group, "");
        let after = after.map(|a| key(group, a.as_str()));
        let skip_len = skip.len();
        self.blocking(move |db| {
            let tx = db.begin_read().map_err(backend)?;
            let t = tx.open_table(RECORDS).map_err(backend)?;
            let start = match after {
                Some(a) if a >= lo => Bound::Excluded(a),
                _ => Bound::Included(lo),
            };
            let mut out = Vec::new();
            if let Bound::Excluded(a) | Bound::Included(a) = &start
                && *a >= hi
            {
                return Ok(out);
            }
            let from: Bound<&[u8]> = start.as_ref().map(|v| &v[..]);
            let to: Bound<&[u8]> = Bound::Excluded(&hi[..]);
            let range = t.range((from, to)).map_err(backend)?;
            for item in range {
                if out.len() >= limit {
                    break;
                }
                let (k, _) = item.map_err(backend)?;
                let name =
                    std::str::from_utf8(&k.value()[skip_len..]).map_err(|_| backend(Corrupted))?;
                out.push(RecordName::new(name).map_err(|_| backend(Corrupted))?);
            }
            Ok(out)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(dir: &tempfile::TempDir) -> Arc<dyn StateStore> {
        Arc::new(RedbState::open(&dir.path().join("state.redb")).unwrap())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn passes_the_state_store_suite() {
        let dir = tempfile::tempdir().unwrap();
        baton_state::testing::state(open(&dir)).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn records_and_versions_survive_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let g = GroupId::new("g").unwrap();
        let n = RecordName::new("lease/k").unwrap();
        let v1 = {
            let s = open(&dir);
            let v1 = s
                .put(&g, &n, Bytes::from_static(b"a"), Expect::Absent)
                .await
                .unwrap();
            s.delete(&g, &n, Expect::Any).await.unwrap();
            s.put(&g, &n, Bytes::from_static(b"b"), Expect::Absent)
                .await
                .unwrap();
            v1
        };
        let s = open(&dir);
        let (value, v2) = s.get(&g, &n).await.unwrap().unwrap();
        assert_eq!(&value[..], b"b");
        assert_ne!(v1, v2, "a re-created record never repeats a version");
        let v3 = s
            .put(
                &g,
                &n,
                Bytes::from_static(b"c"),
                Expect::Version(v2.clone()),
            )
            .await
            .unwrap();
        assert_ne!(v3, v2);
        assert!(matches!(
            s.put(&g, &n, Bytes::from_static(b"d"), Expect::Version(v1))
                .await,
            Err(StateError::Conflict)
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn prefixes_and_groups_do_not_leak() {
        let dir = tempfile::tempdir().unwrap();
        let s = open(&dir);
        let g = GroupId::new("g").unwrap();
        let g2 = GroupId::new("g2").unwrap();
        for (grp, name) in [
            (&g, "lease/a"),
            (&g, "lease/b/c"),
            (&g, "leases/x"),
            (&g, "lease"),
            (&g, "lease0"),
            (&g2, "lease/z"),
        ] {
            s.put(
                grp,
                &RecordName::new(name).unwrap(),
                Bytes::new(),
                Expect::Any,
            )
            .await
            .unwrap();
        }
        let p = RecordName::new("lease").unwrap();
        let names: Vec<String> = s
            .list(&g, &p, None, 10)
            .await
            .unwrap()
            .into_iter()
            .map(|n| n.as_str().to_owned())
            .collect();
        assert_eq!(names, vec!["lease/a", "lease/b/c"]);
        let after = RecordName::new("lease/a").unwrap();
        assert_eq!(s.list(&g, &p, Some(&after), 10).await.unwrap().len(), 1);
        let far = RecordName::new("zzz").unwrap();
        assert!(s.list(&g, &p, Some(&far), 10).await.unwrap().is_empty());
        let early = RecordName::new("a").unwrap();
        assert_eq!(s.list(&g, &p, Some(&early), 10).await.unwrap().len(), 2);
        assert_eq!(s.list(&g, &p, None, 1).await.unwrap().len(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_corrupted_record_is_a_backend_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.redb");
        let g = GroupId::new("g").unwrap();
        {
            let db = Database::create(&path).unwrap();
            let tx = db.begin_write().unwrap();
            tx.open_table(RECORDS)
                .unwrap()
                .insert(&key(&g, "x")[..], &b"short"[..])
                .unwrap();
            tx.commit().unwrap();
        }
        let s = RedbState::open(&path).unwrap();
        assert!(matches!(
            s.get(&g, &RecordName::new("x").unwrap()).await,
            Err(StateError::Backend(_))
        ));
    }
}
