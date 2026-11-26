//! Storage contracts for Skein.
//!
//! Two levels:
//!
//! - [`Objects`]: a key–value store with compare-and-swap, the only thing a backend (memory,
//!   files, S3) has to implement.
//! - The typed contracts the engine uses: [`ControlStore`], [`Log`], [`BlobStore`] and
//!   [`CommandQueue`]. [`Storage::over`] builds all four on top of any [`Objects`]; other
//!   implementations (replicated, database-backed) can implement them directly.
//!
//! The journal is a hash chain: every segment names the one before it by BLAKE3 hash and the head
//! names the last one, optionally attested by a [`HeadAttestor`]; [`Chain`], [`locate`],
//! [`verify_segment`] and [`verify_extends`] verify segments from any [`SegmentSource`] against a
//! trusted [`JournalHead`].
//!
//! A [`ReadTier`] hands out segments and blobs by name with an expected hash from an untrusted,
//! read-only source; `skein-storage-tiered` reads through such tiers after local storage.
//!
//! [`ControlState`] implements Baton's `StateStore` over any [`ControlStore`], so Baton's leases
//! and liveness keep their records next to the tenant's other control records.

mod blobs;
mod commands;
mod control;
mod counting;
#[doc(hidden)]
pub mod fuzzing;
mod journal;
mod key;
mod log;
mod record;
mod snapshot;
mod state;
#[cfg(feature = "testing")]
pub mod testing;
mod tier;

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;

pub use blobs::{BlobStore, ObjectBlobs};
pub use commands::{CommandQueue, ObjectCommands, Submitted};
pub use control::{ControlStore, ObjectControl};
pub use counting::{CountingObjects, ObjectCounts};
pub use journal::{
    Chain, HeadAttestor, IntegrityError, JournalHead, NoAttestor, SegmentHash, SegmentRef,
    SegmentSource, SignedHead, VerifiedSegment, locate, verify_extends, verify_head,
    verify_segment,
};
pub use key::{InvalidKey, ObjectKey};
pub use log::{Log, MAX_SEGMENT_EVENTS, ObjectLog};
pub use record::{Migrate, Record, decode_record, encode_record};
pub use snapshot::{
    CollectionState, ItemState, MailboxState, ObjectState, SNAPSHOT_VERSION, Snapshot,
};
pub use state::{ControlState, STATE_AREA};
pub use tier::ReadTier;

/// An opaque version of a stored value. It changes whenever the value changes; a backend may give
/// the same version to identical bytes written again (S3 ETags are content hashes), which is
/// harmless for compare-and-swap because the value is the same.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Version(pub String);

/// What a write expects to find.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expect {
    /// The key must not exist.
    Absent,
    /// The key must hold exactly this version.
    Version(Version),
    /// Write whatever is there.
    Any,
}

/// Errors of every storage contract.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// The expectation of a write did not hold.
    #[error("the stored value changed")]
    Conflict,
    /// A newer owner has written to this account; this writer must stop.
    #[error("a newer owner holds this account")]
    Fenced,
    /// The requested part of the log was compacted away; start from the latest snapshot, whose
    /// `seq` is at least `first - 1`.
    #[error("the log was compacted; it now starts at {first}")]
    Compacted {
        /// The first event still in the log.
        first: u64,
    },
    /// Stored data does not decode or does not match its hash.
    #[error("stored data is corrupt: {0}")]
    Corrupt(String),
    /// Journal data failed verification: tampered, reordered, mixed up, rolled back, withheld or
    /// carrying a refused attestation.
    #[error(transparent)]
    Integrity(#[from] IntegrityError),
    /// A key or path that storage refuses.
    #[error(transparent)]
    InvalidKey(#[from] InvalidKey),
    /// The backend failed; the operation may be retried.
    #[error("storage backend failed: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl StorageError {
    /// Wraps any backend error.
    pub fn backend(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self::Backend(e.into())
    }
}

/// A key–value store with compare-and-swap.
///
/// Guarantees every implementation keeps (checked by [`testing::objects`] behind the `testing`
/// feature):
///
/// - A successful write is visible to every later read, from any process (read-after-write).
/// - `put` with [`Expect::Absent`] fails with [`StorageError::Conflict`] when the key exists, and
///   with [`Expect::Version`] when the key holds another version or none; of two concurrent writes
///   with the same expectation at most one succeeds.
/// - `list` returns keys strictly under a prefix in ascending byte order, starting after
///   `start_after`; keys that differ only in case are different keys.
/// - Values are stored as given, byte for byte.
///
/// Callers never store or read a key that is also a prefix of another stored key (`a` next to
/// `a/b`), so backends that map keys to files need not support it. Every layout in Skein follows this.
#[async_trait]
pub trait Objects: Send + Sync {
    /// The value and its version, `None` when the key does not exist.
    async fn get(&self, key: &ObjectKey) -> Result<Option<(Bytes, Version)>, StorageError>;

    /// Writes `value` if `expect` holds, returning the new version.
    async fn put(
        &self,
        key: &ObjectKey,
        value: Bytes,
        expect: Expect,
    ) -> Result<Version, StorageError>;

    /// Deletes the key if `expect` holds. Deleting a missing key with [`Expect::Any`] or
    /// [`Expect::Absent`] succeeds; [`Expect::Absent`] on an existing key is a conflict.
    /// Backends without conditional deletes check the version first, which leaves a short race;
    /// callers only delete keys no one else writes any more.
    async fn delete(&self, key: &ObjectKey, expect: Expect) -> Result<(), StorageError>;

    /// Up to `limit` keys strictly under `prefix` (never `prefix` itself) in ascending order,
    /// after `start_after` when given.
    async fn list(
        &self,
        prefix: &ObjectKey,
        start_after: Option<&ObjectKey>,
        limit: usize,
    ) -> Result<Vec<ObjectKey>, StorageError>;
}

/// The four typed stores the engine works with.
#[derive(Clone)]
pub struct Storage {
    /// Accounts, sealed credentials, cursors, owners.
    pub control: Arc<dyn ControlStore>,
    /// The journal.
    pub log: Arc<dyn Log>,
    /// Content by hash.
    pub blobs: Arc<dyn BlobStore>,
    /// Write requests.
    pub commands: Arc<dyn CommandQueue>,
}

/// Deletes every object under `prefix` and returns how many there were.
pub(crate) async fn delete_prefix(
    objects: &dyn Objects,
    prefix: &ObjectKey,
    keep: impl Fn(&ObjectKey) -> bool,
) -> Result<u64, StorageError> {
    let mut removed = 0;
    let mut after: Option<ObjectKey> = None;
    loop {
        let page = objects.list(prefix, after.as_ref(), 1000).await?;
        for key in &page {
            if !keep(key) {
                objects.delete(key, Expect::Any).await?;
                removed += 1;
            }
        }
        if page.len() < 1000 {
            return Ok(removed);
        }
        after = page.last().cloned();
    }
}

/// The control paths under which Skein keeps records of one account, each followed by
/// `/{account}`: whole subtrees for the first list, single records for the second.
const ACCOUNT_CONTROL_TREES: [&str; 5] = [
    "cursors",
    "started",
    "sending",
    "credentials",
    "pim-cursors",
];
const ACCOUNT_CONTROL_RECORDS: [&str; 6] =
    ["accounts", "status", "state", "pim-state", "push", "oauth"];

/// Deletes everything one account has in the journal (head, segments, snapshots), the command
/// queue and the tenant's control records Skein keeps per account (the record, sealed
/// credentials, cursors, status, start markers, push and OAuth records), from storage laid out by
/// [`Storage::over`]. Blobs are shared by content address and stay; the keyring's key records
/// (`keys/`) and other accounts are never touched. Idempotent: purging again removes nothing and
/// succeeds. Returns how many objects were removed.
pub async fn purge_account(
    objects: &dyn Objects,
    tenant: &skein_core::TenantId,
    account: &skein_core::AccountId,
) -> Result<u64, StorageError> {
    let mut removed = 0;
    let head = ObjectKey::account(tenant, "heads", account)?;
    if objects.get(&head).await?.is_some() {
        objects.delete(&head, Expect::Any).await?;
        removed += 1;
    }
    for area in ["log", "snapshots", "commands"] {
        let prefix = ObjectKey::account(tenant, area, account)?;
        removed += delete_prefix(objects, &prefix, |_| false).await?;
    }
    let control = ObjectKey::tenant(tenant).join("control")?;
    for tree in ACCOUNT_CONTROL_TREES {
        let prefix = control.join(tree)?.join(account.as_str())?;
        removed += delete_prefix(objects, &prefix, |_| false).await?;
    }
    for record in ACCOUNT_CONTROL_RECORDS {
        let key = control.join(record)?.join(account.as_str())?;
        if objects.get(&key).await?.is_some() {
            objects.delete(&key, Expect::Any).await?;
            removed += 1;
        }
    }
    Ok(removed)
}

impl Storage {
    /// Deletes everything the tenant has in the four stores, except the record of its keyring
    /// key (`keys/` in its control area), which must survive so a destroyed key stays destroyed.
    /// Returns how many objects or records were removed.
    pub async fn purge_tenant(&self, tenant: &skein_core::TenantId) -> Result<u64, StorageError> {
        Ok(self.log.purge(tenant).await?
            + self.blobs.purge(tenant).await?
            + self.commands.purge(tenant).await?
            + self.control.purge(tenant).await?)
    }

    /// All four stores on top of one object store, with unattested journal heads.
    pub fn over(objects: Arc<dyn Objects>) -> Self {
        Self::over_attested(objects, Arc::new(NoAttestor))
    }

    /// All four stores on top of one object store; the journal attests and verifies its heads
    /// with `attestor`.
    pub fn over_attested(objects: Arc<dyn Objects>, attestor: Arc<dyn HeadAttestor>) -> Self {
        Self {
            control: Arc::new(ObjectControl::new(objects.clone())),
            log: Arc::new(ObjectLog::with_attestor(objects.clone(), attestor)),
            blobs: Arc::new(ObjectBlobs::new(objects.clone())),
            commands: Arc::new(ObjectCommands::new(objects)),
        }
    }
}
