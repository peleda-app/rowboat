//! The drop service's storage seam.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use async_trait::async_trait;
use baton_core::Timestamp;
use baton_identity::PublicKey;
use baton_mailbox::{BoxId, BoxPolicy, Message, MessageId};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// Errors of a [`DropStore`].
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A live box with this id exists.
    #[error("box exists")]
    Exists,
    /// No live box with this id.
    #[error("no such box")]
    Missing,
    /// The writer is not in the box's writers.
    #[error("not a writer")]
    Denied,
    /// The box is full.
    #[error("quota exceeded")]
    Quota,
    /// The writer version is not above the stored one.
    #[error("stale writer version")]
    Conflict,
    /// The backend failed; nothing or everything of the call happened.
    #[error("store backend failed: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl StoreError {
    /// Wraps any backend error.
    pub fn backend(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self::Backend(e.into())
    }
}

/// How a box's creation was admitted, which decides the quotas it may ask for and the share of
/// store-wide capacity it competes for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Admitted {
    /// An operator token.
    Token,
    /// A proof of work.
    Work,
    /// An open service: no admission.
    Open,
}

impl Admitted {
    /// Whether anybody can create such boxes (work or open), so they get the smaller quotas and
    /// a bounded share of the store.
    pub fn untrusted(self) -> bool {
        !matches!(self, Self::Token)
    }
}

/// What a store keeps about a box besides its messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoxInfo {
    /// The policy, with the current writers.
    pub policy: BoxPolicy,
    /// How the creation was admitted.
    pub admitted: Admitted,
    /// The version of the last writer change (0 at creation).
    pub writers_version: u64,
    /// The highest message id ever assigned (0 before the first).
    pub last_id: u64,
    /// Messages stored (expired ones count until they are removed).
    pub count: u32,
    /// Bytes stored, as `count`.
    pub bytes: u64,
    /// When the box was created.
    pub created_at: Timestamp,
    /// When the reader last used it (creation, take, ack, writer change).
    pub touched_at: Timestamp,
}

impl BoxInfo {
    /// A new box.
    pub fn new(policy: BoxPolicy, admitted: Admitted, now: Timestamp) -> Self {
        Self {
            policy,
            admitted,
            writers_version: 0,
            last_id: 0,
            count: 0,
            bytes: 0,
            created_at: now,
            touched_at: now,
        }
    }

    /// Whether the reader has left the box unused for its whole time-to-live, which removes it.
    pub fn idle(&self, now: Timestamp) -> bool {
        now.0.saturating_sub(self.touched_at.0) >= self.policy.ttl_ms as i64
    }

    /// Whether a message stored at `stored_at` has expired at `now`.
    pub fn expired(&self, stored_at: Timestamp, now: Timestamp) -> bool {
        now.0.saturating_sub(stored_at.0) >= self.policy.ttl_ms as i64
    }

    /// Whether one more message of `len` bytes fits the quotas.
    pub fn fits(&self, len: usize) -> bool {
        self.count < self.policy.max_messages
            && self.bytes.saturating_add(len as u64) <= self.policy.max_bytes
    }
}

/// Where the drop service keeps boxes and messages. Each method is atomic.
///
/// Guarantees (checked by `testing::store`):
///
/// - A box whose reader has not used it for its time-to-live ([`BoxInfo::idle`]) is treated as
///   absent by every method (and `create` may replace it); `sweep` removes it.
/// - `append` checks that `writer` is in the current writers and that the message fits the quotas
///   after removing the box's expired messages, then assigns `last_id + 1`, atomically: two
///   appends never get the same id and ids never repeat, also after acknowledgements.
/// - `read` returns unexpired messages after `after` in id order, at most `limit`, and marks the
///   box used; `ack` removes messages up to `up_to` and marks the box used.
/// - `set_writers` replaces the writers only with a `version` above the stored one and marks the
///   box used.
/// - `delete` removes the box and its messages.
#[async_trait]
pub trait DropStore: Send + Sync {
    /// Creates a box admitted as `admitted`; [`StoreError::Exists`] if a live one exists.
    async fn create(
        &self,
        id: &BoxId,
        policy: &BoxPolicy,
        admitted: Admitted,
        now: Timestamp,
    ) -> Result<(), StoreError>;

    /// The box, if it exists and is not idle.
    async fn get(&self, id: &BoxId, now: Timestamp) -> Result<Option<BoxInfo>, StoreError>;

    /// Replaces the writers if `version` is above the stored one.
    async fn set_writers(
        &self,
        id: &BoxId,
        writers: &[PublicKey],
        version: u64,
        now: Timestamp,
    ) -> Result<(), StoreError>;

    /// Stores a message from `writer`.
    async fn append(
        &self,
        id: &BoxId,
        writer: &PublicKey,
        bytes: Bytes,
        now: Timestamp,
    ) -> Result<MessageId, StoreError>;

    /// Unexpired messages after `after`.
    async fn read(
        &self,
        id: &BoxId,
        after: Option<MessageId>,
        limit: u32,
        now: Timestamp,
    ) -> Result<Vec<Message>, StoreError>;

    /// Removes messages up to and including `up_to`.
    async fn ack(&self, id: &BoxId, up_to: MessageId, now: Timestamp) -> Result<(), StoreError>;

    /// Removes the box.
    async fn delete(&self, id: &BoxId, now: Timestamp) -> Result<(), StoreError>;

    /// Removes idle boxes and expired messages; returns how many boxes and messages it removed.
    async fn sweep(&self, now: Timestamp) -> Result<u64, StoreError>;
}

struct MemBox {
    info: BoxInfo,
    messages: BTreeMap<u64, (Timestamp, Bytes)>,
}

impl MemBox {
    fn prune(&mut self, now: Timestamp) -> u64 {
        let expired: Vec<u64> = self
            .messages
            .iter()
            .filter(|(_, (at, _))| self.info.expired(*at, now))
            .map(|(id, _)| *id)
            .collect();
        for id in &expired {
            self.remove(*id);
        }
        expired.len() as u64
    }

    fn remove(&mut self, id: u64) {
        if let Some((_, b)) = self.messages.remove(&id) {
            self.info.count -= 1;
            self.info.bytes -= b.len() as u64;
        }
    }
}

/// A [`DropStore`] in memory: for tests, the in-process mailbox and examples. Keeps nothing across
/// a restart and has no store-wide limits.
#[derive(Default)]
pub struct MemoryDropStore {
    boxes: Mutex<HashMap<BoxId, MemBox>>,
}

impl MemoryDropStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn with_live<T>(
        &self,
        id: &BoxId,
        now: Timestamp,
        f: impl FnOnce(&mut MemBox) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let mut boxes = self.boxes.lock().expect("drop store lock");
        match boxes.get_mut(id) {
            Some(b) if !b.info.idle(now) => f(b),
            Some(_) => {
                boxes.remove(id);
                Err(StoreError::Missing)
            }
            None => Err(StoreError::Missing),
        }
    }
}

#[async_trait]
impl DropStore for MemoryDropStore {
    async fn create(
        &self,
        id: &BoxId,
        policy: &BoxPolicy,
        admitted: Admitted,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        let mut boxes = self.boxes.lock().expect("drop store lock");
        if boxes.get(id).is_some_and(|b| !b.info.idle(now)) {
            return Err(StoreError::Exists);
        }
        boxes.insert(
            *id,
            MemBox {
                info: BoxInfo::new(policy.clone(), admitted, now),
                messages: BTreeMap::new(),
            },
        );
        Ok(())
    }

    async fn get(&self, id: &BoxId, now: Timestamp) -> Result<Option<BoxInfo>, StoreError> {
        match self.with_live(id, now, |b| Ok(b.info.clone())) {
            Ok(i) => Ok(Some(i)),
            Err(StoreError::Missing) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn set_writers(
        &self,
        id: &BoxId,
        writers: &[PublicKey],
        version: u64,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        self.with_live(id, now, |b| {
            if version <= b.info.writers_version {
                return Err(StoreError::Conflict);
            }
            b.info.policy.writers = writers.to_vec();
            b.info.writers_version = version;
            b.info.touched_at = now;
            Ok(())
        })
    }

    async fn append(
        &self,
        id: &BoxId,
        writer: &PublicKey,
        bytes: Bytes,
        now: Timestamp,
    ) -> Result<MessageId, StoreError> {
        self.with_live(id, now, |b| {
            if !b.info.policy.writers.contains(writer) {
                return Err(StoreError::Denied);
            }
            if !b.info.fits(bytes.len()) {
                b.prune(now);
            }
            if !b.info.fits(bytes.len()) {
                return Err(StoreError::Quota);
            }
            let next = b.info.last_id.checked_add(1).ok_or(StoreError::Quota)?;
            b.info.last_id = next;
            b.info.count += 1;
            b.info.bytes += bytes.len() as u64;
            b.messages.insert(next, (now, bytes));
            Ok(MessageId(next))
        })
    }

    async fn read(
        &self,
        id: &BoxId,
        after: Option<MessageId>,
        limit: u32,
        now: Timestamp,
    ) -> Result<Vec<Message>, StoreError> {
        self.with_live(id, now, |b| {
            b.info.touched_at = now;
            let from = after.map_or(0, |a| a.0.saturating_add(1));
            Ok(b.messages
                .range(from..)
                .filter(|(_, (at, _))| !b.info.expired(*at, now))
                .take(limit as usize)
                .map(|(id, (at, bytes))| Message {
                    id: MessageId(*id),
                    bytes: bytes.clone(),
                    stored_at: *at,
                })
                .collect())
        })
    }

    async fn ack(&self, id: &BoxId, up_to: MessageId, now: Timestamp) -> Result<(), StoreError> {
        self.with_live(id, now, |b| {
            b.info.touched_at = now;
            let gone: Vec<u64> = b.messages.range(..=up_to.0).map(|(id, _)| *id).collect();
            for id in gone {
                b.remove(id);
            }
            Ok(())
        })
    }

    async fn delete(&self, id: &BoxId, now: Timestamp) -> Result<(), StoreError> {
        self.with_live(id, now, |_| Ok(()))?;
        self.boxes.lock().expect("drop store lock").remove(id);
        Ok(())
    }

    async fn sweep(&self, now: Timestamp) -> Result<u64, StoreError> {
        let mut boxes = self.boxes.lock().expect("drop store lock");
        let before = boxes.len();
        boxes.retain(|_, b| !b.info.idle(now));
        let mut removed = (before - boxes.len()) as u64;
        for b in boxes.values_mut() {
            removed += b.prune(now);
        }
        Ok(removed)
    }
}
