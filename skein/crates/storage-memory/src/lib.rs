//! [`Objects`] in memory. Nothing survives the process; meant for tests, load tests and the
//! library mode where the journal feeds a consumer directly.

use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;
use bytes::Bytes;
use skein_storage::{Expect, ObjectKey, Objects, StorageError, Version};

/// An object store in memory. Versions are a counter that grows with every write.
#[derive(Default)]
pub struct MemoryObjects {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    map: BTreeMap<String, (Bytes, u64)>,
    next: u64,
}

impl MemoryObjects {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many objects are stored.
    pub fn len(&self) -> usize {
        self.inner.lock().expect("lock").map.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total bytes stored.
    pub fn bytes(&self) -> u64 {
        let inner = self.inner.lock().expect("lock");
        inner.map.values().map(|(b, _)| b.len() as u64).sum()
    }
}

fn holds(current: Option<u64>, expect: &Expect) -> bool {
    match (expect, current) {
        (Expect::Any, _) => true,
        (Expect::Absent, None) => true,
        (Expect::Absent, Some(_)) => false,
        (Expect::Version(v), Some(c)) => v.0 == c.to_string(),
        (Expect::Version(_), None) => false,
    }
}

#[async_trait]
impl Objects for MemoryObjects {
    async fn get(&self, key: &ObjectKey) -> Result<Option<(Bytes, Version)>, StorageError> {
        let inner = self.inner.lock().expect("lock");
        Ok(inner
            .map
            .get(key.as_str())
            .map(|(b, v)| (b.clone(), Version(v.to_string()))))
    }

    async fn put(
        &self,
        key: &ObjectKey,
        value: Bytes,
        expect: Expect,
    ) -> Result<Version, StorageError> {
        let mut inner = self.inner.lock().expect("lock");
        let current = inner.map.get(key.as_str()).map(|(_, v)| *v);
        if !holds(current, &expect) {
            return Err(StorageError::Conflict);
        }
        inner.next += 1;
        let v = inner.next;
        inner.map.insert(key.as_str().to_owned(), (value, v));
        Ok(Version(v.to_string()))
    }

    async fn delete(&self, key: &ObjectKey, expect: Expect) -> Result<(), StorageError> {
        let mut inner = self.inner.lock().expect("lock");
        let current = inner.map.get(key.as_str()).map(|(_, v)| *v);
        if current.is_none() && matches!(expect, Expect::Any | Expect::Absent) {
            return Ok(());
        }
        if !holds(current, &expect) {
            return Err(StorageError::Conflict);
        }
        inner.map.remove(key.as_str());
        Ok(())
    }

    async fn list(
        &self,
        prefix: &ObjectKey,
        start_after: Option<&ObjectKey>,
        limit: usize,
    ) -> Result<Vec<ObjectKey>, StorageError> {
        let inner = self.inner.lock().expect("lock");
        let lower = format!("{}/", prefix.as_str());
        let mut out = Vec::new();
        for (k, _) in inner.map.range(lower.clone()..) {
            if !k.starts_with(&lower) {
                break;
            }
            if let Some(after) = start_after
                && k.as_str() <= after.as_str()
            {
                continue;
            }
            out.push(ObjectKey::parse(k)?);
            if out.len() == limit {
                break;
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[tokio::test]
    async fn conformance() {
        skein_storage::testing::all_over_objects(Arc::new(MemoryObjects::new())).await;
    }
}
