use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use skein_core::{BlobHash, TenantId};

use crate::{Expect, ObjectKey, Objects, StorageError};

/// Content addressed by its BLAKE3 hash, deduplicated within a tenant.
///
/// - `put` is idempotent: storing the same bytes twice returns the same hash and stores once.
/// - `get` returns exactly the bytes that hash to the requested value, or fails with
///   [`StorageError::Corrupt`]; tampered or damaged content is never handed out.
/// - Blobs of different tenants never share storage, so a tenant cannot probe whether another one
///   holds a message, and deleting a tenant removes its blobs.
#[async_trait]
pub trait BlobStore: Send + Sync {
    /// Stores `bytes` and returns their hash.
    async fn put(&self, tenant: &TenantId, bytes: Bytes) -> Result<BlobHash, StorageError>;

    /// The blob, `None` when missing (never stored, or expired).
    async fn get(&self, tenant: &TenantId, hash: &BlobHash) -> Result<Option<Bytes>, StorageError>;

    /// Whether the blob is stored.
    async fn contains(&self, tenant: &TenantId, hash: &BlobHash) -> Result<bool, StorageError>;

    /// Deletes every blob of the tenant; returns how many.
    async fn purge(&self, tenant: &TenantId) -> Result<u64, StorageError>;
}

/// A [`BlobStore`] on top of [`Objects`], under `tenants/{tenant}/blobs/{hash}`.
pub struct ObjectBlobs {
    objects: Arc<dyn Objects>,
}

impl ObjectBlobs {
    /// Blobs in `objects`.
    pub fn new(objects: Arc<dyn Objects>) -> Self {
        Self { objects }
    }

    fn key(tenant: &TenantId, hash: &BlobHash) -> ObjectKey {
        ObjectKey::tenant(tenant)
            .join("blobs")
            .and_then(|k| k.join(&hash.to_hex()))
            .expect("hex hashes are valid segments")
    }
}

#[async_trait]
impl BlobStore for ObjectBlobs {
    async fn put(&self, tenant: &TenantId, bytes: Bytes) -> Result<BlobHash, StorageError> {
        let hash = BlobHash::of(&bytes);
        match self
            .objects
            .put(&Self::key(tenant, &hash), bytes, Expect::Absent)
            .await
        {
            Ok(_) | Err(StorageError::Conflict) => Ok(hash),
            Err(e) => Err(e),
        }
    }

    async fn get(&self, tenant: &TenantId, hash: &BlobHash) -> Result<Option<Bytes>, StorageError> {
        let Some((bytes, _)) = self.objects.get(&Self::key(tenant, hash)).await? else {
            return Ok(None);
        };
        if !hash.matches(&bytes) {
            return Err(StorageError::Corrupt(format!(
                "blob {hash} does not match its hash"
            )));
        }
        Ok(Some(bytes))
    }

    async fn contains(&self, tenant: &TenantId, hash: &BlobHash) -> Result<bool, StorageError> {
        Ok(self.objects.get(&Self::key(tenant, hash)).await?.is_some())
    }

    async fn purge(&self, tenant: &TenantId) -> Result<u64, StorageError> {
        let prefix = ObjectKey::tenant(tenant).join("blobs")?;
        crate::delete_prefix(&*self.objects, &prefix, |_| false).await
    }
}
