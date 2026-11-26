use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;

use crate::{Expect, ObjectKey, Objects, StorageError, Version};

/// Wraps an [`Objects`] and sleeps before every call, to simulate a remote store such as S3 in
/// load tests. Each call waits `base` plus a pseudo-random part in `0..=jitter`; the sequence is
/// deterministic for a given `seed`. Results are exactly those of the wrapped store.
pub struct SlowObjects {
    inner: Arc<dyn Objects>,
    base: Duration,
    jitter: Duration,
    state: AtomicU64,
}

impl SlowObjects {
    /// Delays every call to `inner` by `base` plus up to `jitter`.
    pub fn new(inner: Arc<dyn Objects>, base: Duration, jitter: Duration, seed: u64) -> Self {
        Self {
            inner,
            base,
            jitter,
            state: AtomicU64::new(seed | 1),
        }
    }

    async fn pause(&self) {
        let mut x = self
            .state
            .fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
        x ^= x >> 33;
        x = x.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
        x ^= x >> 33;
        let span = self.jitter.as_micros() as u64;
        let extra = if span == 0 { 0 } else { x % (span + 1) };
        let wait = self.base + Duration::from_micros(extra);
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
}

#[async_trait]
impl Objects for SlowObjects {
    async fn get(&self, key: &ObjectKey) -> Result<Option<(Bytes, Version)>, StorageError> {
        self.pause().await;
        self.inner.get(key).await
    }

    async fn put(
        &self,
        key: &ObjectKey,
        value: Bytes,
        expect: Expect,
    ) -> Result<Version, StorageError> {
        self.pause().await;
        self.inner.put(key, value, expect).await
    }

    async fn delete(&self, key: &ObjectKey, expect: Expect) -> Result<(), StorageError> {
        self.pause().await;
        self.inner.delete(key, expect).await
    }

    async fn list(
        &self,
        prefix: &ObjectKey,
        start_after: Option<&ObjectKey>,
        limit: usize,
    ) -> Result<Vec<ObjectKey>, StorageError> {
        self.pause().await;
        self.inner.list(prefix, start_after, limit).await
    }
}
