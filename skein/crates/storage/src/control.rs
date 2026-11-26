use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use skein_core::TenantId;

use crate::{Expect, ObjectKey, Objects, StorageError, Version};

/// Small records with compare-and-swap: accounts, sealed credentials, cursors, owners, keys.
///
/// Paths are `/`-separated and checked segment by segment; every path is scoped to its tenant,
/// so one tenant can never read or overwrite another's records. Same guarantees as [`Objects`].
#[async_trait]
pub trait ControlStore: Send + Sync {
    /// The record and its version, `None` when missing.
    async fn get(
        &self,
        tenant: &TenantId,
        path: &str,
    ) -> Result<Option<(Bytes, Version)>, StorageError>;

    /// Writes the record if `expect` holds.
    async fn put(
        &self,
        tenant: &TenantId,
        path: &str,
        value: Bytes,
        expect: Expect,
    ) -> Result<Version, StorageError>;

    /// Deletes the record if `expect` holds.
    async fn delete(
        &self,
        tenant: &TenantId,
        path: &str,
        expect: Expect,
    ) -> Result<(), StorageError>;

    /// Paths under `prefix` (relative to the tenant's control area), ascending, after
    /// `start_after` when given.
    async fn list(
        &self,
        tenant: &TenantId,
        prefix: &str,
        start_after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>, StorageError>;

    /// Deletes every record of the tenant except those under `keys/`; returns how many.
    async fn purge(&self, tenant: &TenantId) -> Result<u64, StorageError>;
}

/// A [`ControlStore`] on top of [`Objects`], under `tenants/{tenant}/control/`.
pub struct ObjectControl {
    objects: Arc<dyn Objects>,
}

impl ObjectControl {
    /// Control records in `objects`.
    pub fn new(objects: Arc<dyn Objects>) -> Self {
        Self { objects }
    }

    fn base(tenant: &TenantId) -> ObjectKey {
        ObjectKey::tenant(tenant)
            .join("control")
            .expect("constant segment")
    }

    fn key(tenant: &TenantId, path: &str) -> Result<ObjectKey, StorageError> {
        Ok(Self::base(tenant).join_path(path)?)
    }
}

#[async_trait]
impl ControlStore for ObjectControl {
    async fn get(
        &self,
        tenant: &TenantId,
        path: &str,
    ) -> Result<Option<(Bytes, Version)>, StorageError> {
        self.objects.get(&Self::key(tenant, path)?).await
    }

    async fn put(
        &self,
        tenant: &TenantId,
        path: &str,
        value: Bytes,
        expect: Expect,
    ) -> Result<Version, StorageError> {
        self.objects
            .put(&Self::key(tenant, path)?, value, expect)
            .await
    }

    async fn delete(
        &self,
        tenant: &TenantId,
        path: &str,
        expect: Expect,
    ) -> Result<(), StorageError> {
        self.objects.delete(&Self::key(tenant, path)?, expect).await
    }

    async fn list(
        &self,
        tenant: &TenantId,
        prefix: &str,
        start_after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>, StorageError> {
        let base = Self::base(tenant);
        let prefix_key = base.join_path(prefix)?;
        let after = start_after.map(|p| base.join_path(p)).transpose()?;
        let keys = self
            .objects
            .list(&prefix_key, after.as_ref(), limit)
            .await?;
        let strip = base.as_str().len() + 1;
        Ok(keys
            .into_iter()
            .map(|k| k.as_str()[strip..].to_owned())
            .collect())
    }

    async fn purge(&self, tenant: &TenantId) -> Result<u64, StorageError> {
        let base = Self::base(tenant);
        let keys = base.join("keys")?;
        crate::delete_prefix(&*self.objects, &base, |k| k.starts_with(&keys)).await
    }
}
