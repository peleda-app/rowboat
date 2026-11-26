use async_trait::async_trait;
use bytes::Bytes;
use skein_core::{AccountId, BlobHash, TenantId};

use crate::{SegmentRef, StorageError};

/// A read-only source of journal segments and blobs that is not trusted: a mirror, a backup,
/// another store that holds copies. Every request names what it wants and pins it by hash (the
/// [`SegmentRef`] of a segment, the [`BlobHash`] of a blob), so the caller verifies whatever comes
/// back and a tier can at worst withhold data or be slow.
///
/// What an implementation must do (checked by [`crate::testing::read_tier`]):
///
/// - Hand out the exact bytes it holds under the requested name, or `None` when it has none.
/// - Never return more than `max_len` bytes: anything larger is `None` or an error, and an
///   implementation that fetches over a network should stop reading after `max_len` bytes.
/// - Never write: neither to where it reads from nor to the caller's storage.
/// - Return [`StorageError::Backend`] for failures the caller may retry elsewhere.
#[async_trait]
pub trait ReadTier: Send + Sync {
    /// The stored bytes of the account's `segment`, `None` when the tier does not have it.
    async fn segment(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        segment: &SegmentRef,
        max_len: usize,
    ) -> Result<Option<Bytes>, StorageError>;

    /// The tenant's blob `hash`, `None` when the tier does not have it.
    async fn blob(
        &self,
        tenant: &TenantId,
        hash: &BlobHash,
        max_len: usize,
    ) -> Result<Option<Bytes>, StorageError>;
}
