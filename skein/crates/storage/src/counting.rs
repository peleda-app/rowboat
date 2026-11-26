use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use bytes::Bytes;

use crate::{Expect, ObjectKey, Objects, StorageError, Version};

/// How many requests of each kind reached an object store, and how many bytes were written.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ObjectCounts {
    /// `get` calls.
    pub gets: u64,
    /// `put` calls.
    pub puts: u64,
    /// `delete` calls.
    pub deletes: u64,
    /// `list` calls.
    pub lists: u64,
    /// Bytes passed to `put`.
    pub bytes_written: u64,
}

/// Wraps an [`Objects`] and counts requests, for metrics and load tests. Behaves exactly like the
/// wrapped store.
pub struct CountingObjects {
    inner: Arc<dyn Objects>,
    gets: AtomicU64,
    puts: AtomicU64,
    deletes: AtomicU64,
    lists: AtomicU64,
    bytes: AtomicU64,
}

impl CountingObjects {
    /// Counts requests to `inner`.
    pub fn new(inner: Arc<dyn Objects>) -> Self {
        Self {
            inner,
            gets: AtomicU64::new(0),
            puts: AtomicU64::new(0),
            deletes: AtomicU64::new(0),
            lists: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
        }
    }

    /// The counts so far.
    pub fn counts(&self) -> ObjectCounts {
        ObjectCounts {
            gets: self.gets.load(Ordering::Relaxed),
            puts: self.puts.load(Ordering::Relaxed),
            deletes: self.deletes.load(Ordering::Relaxed),
            lists: self.lists.load(Ordering::Relaxed),
            bytes_written: self.bytes.load(Ordering::Relaxed),
        }
    }
}

#[async_trait]
impl Objects for CountingObjects {
    async fn get(&self, key: &ObjectKey) -> Result<Option<(Bytes, Version)>, StorageError> {
        self.gets.fetch_add(1, Ordering::Relaxed);
        self.inner.get(key).await
    }

    async fn put(
        &self,
        key: &ObjectKey,
        value: Bytes,
        expect: Expect,
    ) -> Result<Version, StorageError> {
        self.puts.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(value.len() as u64, Ordering::Relaxed);
        self.inner.put(key, value, expect).await
    }

    async fn delete(&self, key: &ObjectKey, expect: Expect) -> Result<(), StorageError> {
        self.deletes.fetch_add(1, Ordering::Relaxed);
        self.inner.delete(key, expect).await
    }

    async fn list(
        &self,
        prefix: &ObjectKey,
        start_after: Option<&ObjectKey>,
        limit: usize,
    ) -> Result<Vec<ObjectKey>, StorageError> {
        self.lists.fetch_add(1, Ordering::Relaxed);
        self.inner.list(prefix, start_after, limit).await
    }
}
