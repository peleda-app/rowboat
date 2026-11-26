//! Storage that reads journal segments and blobs from local storage first, then from untrusted
//! read-only [`ReadTier`]s in order, and hands out only bytes that match the hash they were asked
//! for.
//!
//! [`Tiered::build`] wraps a local [`Storage`]: control records, commands and every write stay
//! local, and tiers are never written to. A segment is asked for by [`SegmentRef`], whose hash
//! comes from the verified chain or a trusted head; a blob by its [`BlobHash`]. Bytes that do not
//! match, are larger than the configured limit, or take longer than the timeout are refused and the
//! next tier is asked.
//!
//! [`StorageTier`] is a tier over another [`Storage`] (a mirror or a backup bucket).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use skein_core::{AccountId, BlobHash, FencingToken, Seq, TenantId};
use skein_storage::{
    BlobStore, IntegrityError, Log, ReadTier, SegmentHash, SegmentRef, SegmentSource, SignedHead,
    Snapshot, Storage, StorageError,
};
use tracing::warn;

/// The default limit on a segment fetched from a tier, the same as the journal's own limit.
pub const DEFAULT_MAX_SEGMENT_BYTES: usize = 256 * 1024 * 1024;
/// The default limit on a blob fetched from a tier.
pub const DEFAULT_MAX_BLOB_BYTES: usize = 128 * 1024 * 1024;
/// The default time one tier gets to answer one request.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Builds a [`Storage`] that reads through tiers after the local one.
pub struct Tiered {
    local: Storage,
    reader: Reader,
    fill: bool,
}

struct Reader {
    tiers: Vec<Arc<dyn ReadTier>>,
    timeout: Duration,
    max_segment: usize,
    max_blob: usize,
}

enum Outcome {
    Found(Bytes),
    Refused,
    Failed(StorageError),
    Missing,
}

impl Reader {
    async fn ask(
        &self,
        index: usize,
        fetch: impl Future<Output = Result<Option<Bytes>, StorageError>>,
        max: usize,
        matches: impl Fn(&[u8]) -> bool,
    ) -> Outcome {
        match tokio::time::timeout(self.timeout, fetch).await {
            Err(_) => {
                warn!(tier = index, "read tier timed out");
                Outcome::Failed(StorageError::backend(format!(
                    "read tier {index} timed out"
                )))
            }
            Ok(Err(e)) => Outcome::Failed(e),
            Ok(Ok(None)) => Outcome::Missing,
            Ok(Ok(Some(bytes))) if bytes.len() <= max && matches(&bytes) => Outcome::Found(bytes),
            Ok(Ok(Some(bytes))) => {
                warn!(
                    tier = index,
                    len = bytes.len(),
                    "read tier returned bytes that do not match"
                );
                Outcome::Refused
            }
        }
    }
}

impl Tiered {
    /// Reads from `local` only, until tiers are added.
    pub fn new(local: Storage) -> Self {
        Self {
            local,
            reader: Reader {
                tiers: Vec::new(),
                timeout: DEFAULT_TIMEOUT,
                max_segment: DEFAULT_MAX_SEGMENT_BYTES,
                max_blob: DEFAULT_MAX_BLOB_BYTES,
            },
            fill: true,
        }
    }

    /// Adds a tier, asked after local storage and every tier added before it.
    pub fn with_tier(mut self, tier: Arc<dyn ReadTier>) -> Self {
        self.reader.tiers.push(tier);
        self
    }

    /// How long one tier gets to answer one request ([`DEFAULT_TIMEOUT`] by default); a tier that
    /// takes longer counts as failed and the next one is asked.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.reader.timeout = timeout;
        self
    }

    /// The largest segment and blob accepted from a tier, passed to it as `max_len`
    /// ([`DEFAULT_MAX_SEGMENT_BYTES`] and [`DEFAULT_MAX_BLOB_BYTES`] by default).
    pub fn with_limits(mut self, max_segment: usize, max_blob: usize) -> Self {
        self.reader.max_segment = max_segment;
        self.reader.max_blob = max_blob;
        self
    }

    /// Does not store blobs fetched from a tier in local storage. By default a verified blob
    /// that local storage did not have is stored there, so the next read is local.
    pub fn without_fill(mut self) -> Self {
        self.fill = false;
        self
    }

    /// The storage: local control records and commands, a log and a blob store that read through
    /// the tiers.
    pub fn build(self) -> Storage {
        let reader = Arc::new(self.reader);
        Storage {
            control: self.local.control,
            commands: self.local.commands,
            log: Arc::new(TieredLog {
                local: self.local.log,
                reader: reader.clone(),
            }),
            blobs: Arc::new(TieredBlobs {
                local: self.local.blobs,
                reader,
                fill: self.fill,
            }),
        }
    }
}

/// The local journal, with segments the local copy lacks or holds damaged fetched from tiers.
///
/// Every [`Log`] method is the local log's, except [`SegmentSource::segment`]: it returns the
/// local bytes when they hash to `segment.hash`, otherwise the first tier's bytes that do and are
/// within the limit. When none do it fails with [`IntegrityError::HashMismatch`] if some source
/// returned wrong bytes, with the last error if some source failed, and returns `None` otherwise.
pub struct TieredLog {
    local: Arc<dyn Log>,
    reader: Arc<Reader>,
}

#[async_trait]
impl SegmentSource for TieredLog {
    async fn segment(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        segment: &SegmentRef,
    ) -> Result<Option<Bytes>, StorageError> {
        let matches = |bytes: &[u8]| SegmentHash::of(bytes) == segment.hash;
        let mut refused = false;
        let mut failure = None;
        match self.local.segment(tenant, account, segment).await {
            Ok(Some(bytes)) if matches(&bytes) => return Ok(Some(bytes)),
            Ok(Some(_)) => refused = true,
            Ok(None) => {}
            Err(e) => failure = Some(e),
        }
        let max = self.reader.max_segment;
        for (index, tier) in self.reader.tiers.iter().enumerate() {
            let fetch = tier.segment(tenant, account, segment, max);
            match self.reader.ask(index, fetch, max, matches).await {
                Outcome::Found(bytes) => return Ok(Some(bytes)),
                Outcome::Refused => refused = true,
                Outcome::Failed(e) => failure = Some(e),
                Outcome::Missing => {}
            }
        }
        if refused {
            return Err(IntegrityError::HashMismatch {
                segment: segment.name(),
            }
            .into());
        }
        failure.map_or(Ok(None), Err)
    }
}

#[async_trait]
impl Log for TieredLog {
    async fn append(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        fence: FencingToken,
        events: Vec<skein_core::Event>,
    ) -> Result<Vec<skein_core::Event>, StorageError> {
        self.local.append(tenant, account, fence, events).await
    }

    async fn claim(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        fence: FencingToken,
    ) -> Result<(), StorageError> {
        self.local.claim(tenant, account, fence).await
    }

    async fn head(&self, tenant: &TenantId, account: &AccountId) -> Result<Seq, StorageError> {
        self.local.head(tenant, account).await
    }

    async fn signed_head(
        &self,
        tenant: &TenantId,
        account: &AccountId,
    ) -> Result<SignedHead, StorageError> {
        self.local.signed_head(tenant, account).await
    }

    async fn read(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        from: Seq,
        limit: usize,
    ) -> Result<Vec<skein_core::Event>, StorageError> {
        self.local.read(tenant, account, from, limit).await
    }

    async fn heads(&self, tenant: &TenantId) -> Result<Vec<(AccountId, Seq)>, StorageError> {
        self.local.heads(tenant).await
    }

    async fn put_snapshot(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        snapshot: &Snapshot,
    ) -> Result<(), StorageError> {
        self.local.put_snapshot(tenant, account, snapshot).await
    }

    async fn latest_snapshot(
        &self,
        tenant: &TenantId,
        account: &AccountId,
    ) -> Result<Option<Snapshot>, StorageError> {
        self.local.latest_snapshot(tenant, account).await
    }

    async fn compact(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        before: Seq,
    ) -> Result<u64, StorageError> {
        self.local.compact(tenant, account, before).await
    }

    async fn purge(&self, tenant: &TenantId) -> Result<u64, StorageError> {
        self.local.purge(tenant).await
    }
}

/// Local blobs, with blobs the local store lacks or holds damaged fetched from tiers.
///
/// `put`, `contains` and `purge` are the local store's (`contains` does not ask tiers). `get`
/// returns the local blob when it matches its hash, otherwise the first tier's bytes that match
/// and are within the limit, stored locally unless [`Tiered::without_fill`] was set. When none
/// match it fails with [`StorageError::Corrupt`] if some source returned wrong bytes, with the last
/// error if some source failed, and returns `None` otherwise.
pub struct TieredBlobs {
    local: Arc<dyn BlobStore>,
    reader: Arc<Reader>,
    fill: bool,
}

#[async_trait]
impl BlobStore for TieredBlobs {
    async fn put(&self, tenant: &TenantId, bytes: Bytes) -> Result<BlobHash, StorageError> {
        self.local.put(tenant, bytes).await
    }

    async fn get(&self, tenant: &TenantId, hash: &BlobHash) -> Result<Option<Bytes>, StorageError> {
        let matches = |bytes: &[u8]| hash.matches(bytes);
        let mut refused = false;
        let mut failure = None;
        match self.local.get(tenant, hash).await {
            Ok(Some(bytes)) if matches(&bytes) => return Ok(Some(bytes)),
            Ok(Some(_)) | Err(StorageError::Corrupt(_)) => refused = true,
            Ok(None) => {}
            Err(e) => failure = Some(e),
        }
        let max = self.reader.max_blob;
        for (index, tier) in self.reader.tiers.iter().enumerate() {
            let fetch = tier.blob(tenant, hash, max);
            match self.reader.ask(index, fetch, max, matches).await {
                Outcome::Found(bytes) => {
                    if self.fill
                        && let Err(e) = self.local.put(tenant, bytes.clone()).await
                    {
                        warn!(tenant = %tenant, error = %e, "storing a blob fetched from a tier failed");
                    }
                    return Ok(Some(bytes));
                }
                Outcome::Refused => refused = true,
                Outcome::Failed(e) => failure = Some(e),
                Outcome::Missing => {}
            }
        }
        if refused {
            return Err(StorageError::Corrupt(format!(
                "no source holds blob {hash} intact"
            )));
        }
        failure.map_or(Ok(None), Err)
    }

    async fn contains(&self, tenant: &TenantId, hash: &BlobHash) -> Result<bool, StorageError> {
        self.local.contains(tenant, hash).await
    }

    async fn purge(&self, tenant: &TenantId) -> Result<u64, StorageError> {
        self.local.purge(tenant).await
    }
}

/// A [`ReadTier`] over another [`Storage`]: segments from its log, blobs from its blob store. It
/// only reads. Bytes longer than `max_len` are reported as missing; the whole object is read
/// before the length is checked, so it suits stores whose objects are already bounded.
pub struct StorageTier {
    source: Storage,
}

impl StorageTier {
    /// Serves what `source` holds.
    pub fn new(source: Storage) -> Self {
        Self { source }
    }
}

#[async_trait]
impl ReadTier for StorageTier {
    async fn segment(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        segment: &SegmentRef,
        max_len: usize,
    ) -> Result<Option<Bytes>, StorageError> {
        Ok(self
            .source
            .log
            .segment(tenant, account, segment)
            .await?
            .filter(|b| b.len() <= max_len))
    }

    async fn blob(
        &self,
        tenant: &TenantId,
        hash: &BlobHash,
        max_len: usize,
    ) -> Result<Option<Bytes>, StorageError> {
        Ok(self
            .source
            .blobs
            .get(tenant, hash)
            .await?
            .filter(|b| b.len() <= max_len))
    }
}

#[cfg(test)]
mod tests;
