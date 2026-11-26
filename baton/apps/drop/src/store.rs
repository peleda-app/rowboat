//! [`RedbDropStore`]: the drop service's store in one redb file.

use std::ops::Bound;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use baton_core::Timestamp;
use baton_drop::record::{
    decode_box, decode_message, encode_box, encode_message, message_key, split_message_key,
};
use baton_drop::{Admitted, BoxInfo, DropStore, StoreError};
use baton_identity::PublicKey;
use baton_mailbox::{BoxId, BoxPolicy, Message, MessageId};
use bytes::Bytes;
use redb::{
    Database, Durability, ReadableDatabase, ReadableTable, Table, TableDefinition, WriteTransaction,
};

const BOXES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("boxes");
const MESSAGES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("messages");
const TOTALS: TableDefinition<&str, u64> = TableDefinition::new("totals");
const SETTINGS: TableDefinition<&str, &[u8]> = TableDefinition::new("settings");

const TOTAL_BOXES: &str = "boxes";
const TOTAL_BYTES: &str = "bytes";
const UNTRUSTED_BOXES: &str = "untrusted_boxes";
const UNTRUSTED_BYTES: &str = "untrusted_bytes";

/// Limits over the whole store, on top of each box's own quotas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreLimits {
    /// Boxes kept at once; creations beyond it are refused with a quota error (default 100,000).
    pub max_boxes: u64,
    /// Message bytes kept at once; puts beyond it are refused with a quota error (default 8 GiB).
    pub max_bytes: u64,
    /// Of `max_boxes`, how many may be boxes anybody can create (proof of work or open
    /// admission), so they never lock out token holders (default 50,000).
    pub max_untrusted_boxes: u64,
    /// Of `max_bytes`, how many bytes such boxes may hold together (default 2 GiB).
    pub max_untrusted_bytes: u64,
    /// Boxes one sweep transaction looks at (default 256).
    pub sweep_boxes: usize,
    /// Messages one sweep transaction removes (default 4,096).
    pub sweep_messages: usize,
}

impl Default for StoreLimits {
    fn default() -> Self {
        Self {
            max_boxes: 100_000,
            max_bytes: 8 * 1024 * 1024 * 1024,
            max_untrusted_boxes: 50_000,
            max_untrusted_bytes: 2 * 1024 * 1024 * 1024,
            sweep_boxes: 256,
            sweep_messages: 4096,
        }
    }
}

/// A [`DropStore`] in one redb file. Every call is one redb transaction, run on a blocking thread;
/// changes to boxes and messages are durable when the call returns. Marking a box used on a take
/// is committed without a flush, so a crash can only make a box look idle earlier. A sweep runs as
/// many short transactions of at most [`StoreLimits::sweep_boxes`] boxes and
/// [`StoreLimits::sweep_messages`] messages each, so puts and takes wait for one batch at most.
pub struct RedbDropStore {
    db: Arc<Database>,
    limits: StoreLimits,
}

fn backend(e: impl std::error::Error + Send + Sync + 'static) -> StoreError {
    StoreError::backend(e)
}

type Tables<'t> = (
    Table<'t, &'static [u8], &'static [u8]>,
    Table<'t, &'static [u8], &'static [u8]>,
    Table<'t, &'static str, u64>,
);

fn tables(tx: &WriteTransaction) -> Result<Tables<'_>, StoreError> {
    Ok((
        tx.open_table(BOXES).map_err(backend)?,
        tx.open_table(MESSAGES).map_err(backend)?,
        tx.open_table(TOTALS).map_err(backend)?,
    ))
}

fn total(t: &impl ReadableTable<&'static str, u64>, name: &str) -> Result<u64, StoreError> {
    Ok(t.get(name).map_err(backend)?.map_or(0, |v| v.value()))
}

fn add(t: &mut Table<&'static str, u64>, name: &str, delta: i128) -> Result<(), StoreError> {
    let next = (i128::from(total(t, name)?) + delta).clamp(0, i128::from(u64::MAX)) as u64;
    t.insert(name, next).map_err(backend)?;
    Ok(())
}

fn load(
    boxes: &Table<&'static [u8], &'static [u8]>,
    id: &BoxId,
) -> Result<Option<BoxInfo>, StoreError> {
    match boxes.get(&id.as_bytes()[..]).map_err(backend)? {
        Some(v) => Ok(Some(decode_box(v.value())?)),
        None => Ok(None),
    }
}

fn save(
    boxes: &mut Table<&'static [u8], &'static [u8]>,
    id: &BoxId,
    info: &BoxInfo,
) -> Result<(), StoreError> {
    boxes
        .insert(&id.as_bytes()[..], &encode_box(info)[..])
        .map_err(backend)?;
    Ok(())
}

/// Adds `delta` bytes to the store's totals and, for a box anybody could create, to the
/// untrusted share.
fn account(
    totals: &mut Table<&'static str, u64>,
    admitted: Admitted,
    delta: i128,
) -> Result<(), StoreError> {
    add(totals, TOTAL_BYTES, delta)?;
    if admitted.untrusted() {
        add(totals, UNTRUSTED_BYTES, delta)?;
    }
    Ok(())
}

/// Removes at most `max` messages of `id` with ids in `from..=to`, while `keep_going` says so
/// for each (stored_at); returns (count, bytes) removed.
fn remove_messages(
    messages: &mut Table<&'static [u8], &'static [u8]>,
    id: &BoxId,
    from: u64,
    to: u64,
    max: usize,
    mut keep_going: impl FnMut(Timestamp) -> bool,
) -> Result<(u32, u64), StoreError> {
    let (lo, hi) = (message_key(id, from), message_key(id, to));
    let mut gone = Vec::new();
    let mut bytes = 0u64;
    for entry in messages.range(&lo[..]..=&hi[..]).map_err(backend)? {
        if gone.len() >= max {
            break;
        }
        let (k, v) = entry.map_err(backend)?;
        let (at, body) = decode_message(v.value())?;
        if !keep_going(at) {
            break;
        }
        bytes += body.len() as u64;
        gone.push(k.value().to_vec());
    }
    for k in &gone {
        messages.remove(&k[..]).map_err(backend)?;
    }
    Ok((gone.len() as u32, bytes))
}

/// Removes the front of `id`'s messages that expired; ids increase with storage time, so expired
/// messages are at the front (a clock that went back leaves some for later, and reads skip them).
fn prune(
    messages: &mut Table<&'static [u8], &'static [u8]>,
    totals: &mut Table<&'static str, u64>,
    id: &BoxId,
    info: &mut BoxInfo,
    now: Timestamp,
    max: usize,
) -> Result<u64, StoreError> {
    let check = info.clone();
    let (n, bytes) = remove_messages(messages, id, 0, u64::MAX, max, |at| check.expired(at, now))?;
    info.count -= n.min(info.count);
    info.bytes -= bytes.min(info.bytes);
    account(totals, info.admitted, -i128::from(bytes))?;
    Ok(u64::from(n))
}

/// Removes at most `max` messages of box `id`, and the box itself once it has none left;
/// returns how many messages it removed and whether the box is gone.
fn drop_box(
    boxes: &mut Table<&'static [u8], &'static [u8]>,
    messages: &mut Table<&'static [u8], &'static [u8]>,
    totals: &mut Table<&'static str, u64>,
    id: &BoxId,
    info: &mut BoxInfo,
    max: usize,
) -> Result<(u64, bool), StoreError> {
    let (n, bytes) = remove_messages(messages, id, 0, u64::MAX, max, |_| true)?;
    account(totals, info.admitted, -i128::from(bytes))?;
    info.count -= n.min(info.count);
    info.bytes -= bytes.min(info.bytes);
    if (n as usize) < max || info.count == 0 {
        boxes.remove(&id.as_bytes()[..]).map_err(backend)?;
        add(totals, TOTAL_BOXES, -1)?;
        if info.admitted.untrusted() {
            add(totals, UNTRUSTED_BOXES, -1)?;
        }
        Ok((u64::from(n), true))
    } else {
        save(boxes, id, info)?;
        Ok((u64::from(n), false))
    }
}

/// The live box `id`, removing it first if it is idle.
fn live(t: &mut Tables<'_>, id: &BoxId, now: Timestamp) -> Result<BoxInfo, StoreError> {
    let (boxes, messages, totals) = t;
    match load(boxes, id)? {
        Some(info) if !info.idle(now) => Ok(info),
        Some(mut info) => {
            drop_box(boxes, messages, totals, id, &mut info, usize::MAX)?;
            Err(StoreError::Missing)
        }
        None => Err(StoreError::Missing),
    }
}

impl RedbDropStore {
    /// Opens (or creates) the store at `path`.
    pub fn open(path: &Path, limits: StoreLimits) -> Result<Self, StoreError> {
        let db = Database::create(path).map_err(backend)?;
        let tx = db.begin_write().map_err(backend)?;
        {
            tables(&tx)?;
            tx.open_table(SETTINGS).map_err(backend)?;
        }
        tx.commit().map_err(backend)?;
        Ok(Self {
            db: Arc::new(db),
            limits,
        })
    }

    /// A stored setting.
    pub fn setting(&self, name: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let tx = self.db.begin_read().map_err(backend)?;
        let t = tx.open_table(SETTINGS).map_err(backend)?;
        Ok(t.get(name).map_err(backend)?.map(|v| v.value().to_vec()))
    }

    /// Stores a setting durably.
    pub fn set_setting(&self, name: &str, value: &[u8]) -> Result<(), StoreError> {
        let tx = self.db.begin_write().map_err(backend)?;
        tx.open_table(SETTINGS)
            .map_err(backend)?
            .insert(name, value)
            .map_err(backend)?;
        tx.commit().map_err(backend)
    }

    /// Boxes and message bytes kept now.
    pub fn totals(&self) -> Result<(u64, u64), StoreError> {
        let tx = self.db.begin_read().map_err(backend)?;
        let t = tx.open_table(TOTALS).map_err(backend)?;
        Ok((total(&t, TOTAL_BOXES)?, total(&t, TOTAL_BYTES)?))
    }

    /// Boxes and message bytes kept now by boxes anybody could create.
    pub fn untrusted_totals(&self) -> Result<(u64, u64), StoreError> {
        let tx = self.db.begin_read().map_err(backend)?;
        let t = tx.open_table(TOTALS).map_err(backend)?;
        Ok((total(&t, UNTRUSTED_BOXES)?, total(&t, UNTRUSTED_BYTES)?))
    }

    async fn write<T: Send + 'static>(
        &self,
        flush: bool,
        f: impl FnOnce(&mut Tables<'_>, &StoreLimits) -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError> {
        let db = self.db.clone();
        let limits = self.limits;
        tokio::task::spawn_blocking(move || {
            let mut tx = db.begin_write().map_err(backend)?;
            if !flush {
                tx.set_durability(Durability::None).map_err(backend)?;
            }
            let out = {
                let mut t = tables(&tx)?;
                f(&mut t, &limits)?
            };
            tx.commit().map_err(backend)?;
            Ok(out)
        })
        .await
        .map_err(backend)?
    }
}

#[async_trait]
impl DropStore for RedbDropStore {
    async fn create(
        &self,
        id: &BoxId,
        policy: &BoxPolicy,
        admitted: Admitted,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        let (id, policy) = (*id, policy.clone());
        self.write(true, move |t, limits| {
            match live(t, &id, now) {
                Ok(_) => return Err(StoreError::Exists),
                Err(StoreError::Missing) => {}
                Err(e) => return Err(e),
            }
            let (boxes, _, totals) = t;
            if total(totals, TOTAL_BOXES)? >= limits.max_boxes
                || (admitted.untrusted()
                    && total(totals, UNTRUSTED_BOXES)? >= limits.max_untrusted_boxes)
            {
                return Err(StoreError::Quota);
            }
            save(boxes, &id, &BoxInfo::new(policy, admitted, now))?;
            add(totals, TOTAL_BOXES, 1)?;
            if admitted.untrusted() {
                add(totals, UNTRUSTED_BOXES, 1)?;
            }
            Ok(())
        })
        .await
    }

    async fn get(&self, id: &BoxId, now: Timestamp) -> Result<Option<BoxInfo>, StoreError> {
        let (db, id) = (self.db.clone(), *id);
        tokio::task::spawn_blocking(move || {
            let tx = db.begin_read().map_err(backend)?;
            let boxes = tx.open_table(BOXES).map_err(backend)?;
            let v = boxes.get(&id.as_bytes()[..]).map_err(backend)?;
            match v {
                Some(v) => {
                    let info = decode_box(v.value())?;
                    Ok((!info.idle(now)).then_some(info))
                }
                None => Ok(None),
            }
        })
        .await
        .map_err(backend)?
    }

    async fn set_writers(
        &self,
        id: &BoxId,
        writers: &[PublicKey],
        version: u64,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        let (id, writers) = (*id, writers.to_vec());
        self.write(true, move |t, _| {
            let mut info = live(t, &id, now)?;
            if version <= info.writers_version {
                return Err(StoreError::Conflict);
            }
            info.policy.writers = writers;
            info.writers_version = version;
            info.touched_at = now;
            save(&mut t.0, &id, &info)
        })
        .await
    }

    async fn append(
        &self,
        id: &BoxId,
        writer: &PublicKey,
        bytes: Bytes,
        now: Timestamp,
    ) -> Result<MessageId, StoreError> {
        let (id, writer) = (*id, *writer);
        self.write(true, move |t, limits| {
            let mut info = live(t, &id, now)?;
            if !info.policy.writers.contains(&writer) {
                return Err(StoreError::Denied);
            }
            let (boxes, messages, totals) = t;
            let len = bytes.len() as u64;
            let untrusted = info.admitted.untrusted();
            let over_total = |totals: &Table<&'static str, u64>| -> Result<bool, StoreError> {
                Ok(
                    total(totals, TOTAL_BYTES)?.saturating_add(len) > limits.max_bytes
                        || (untrusted
                            && total(totals, UNTRUSTED_BYTES)?.saturating_add(len)
                                > limits.max_untrusted_bytes),
                )
            };
            if !info.fits(bytes.len()) || over_total(totals)? {
                prune(messages, totals, &id, &mut info, now, usize::MAX)?;
            }
            if !info.fits(bytes.len()) || over_total(totals)? {
                return Err(StoreError::Quota);
            }
            let next = info.last_id.checked_add(1).ok_or(StoreError::Quota)?;
            info.last_id = next;
            info.count += 1;
            info.bytes += len;
            messages
                .insert(
                    &message_key(&id, next)[..],
                    &encode_message(now, &bytes)[..],
                )
                .map_err(backend)?;
            account(totals, info.admitted, i128::from(len))?;
            save(boxes, &id, &info)?;
            Ok(MessageId(next))
        })
        .await
    }

    async fn read(
        &self,
        id: &BoxId,
        after: Option<MessageId>,
        limit: u32,
        now: Timestamp,
    ) -> Result<Vec<Message>, StoreError> {
        let id = *id;
        self.write(false, move |t, _| {
            let mut info = live(t, &id, now)?;
            info.touched_at = now;
            save(&mut t.0, &id, &info)?;
            let from = after.map_or(0, |a| a.0.saturating_add(1));
            let (lo, hi) = (message_key(&id, from), message_key(&id, u64::MAX));
            let mut out = Vec::new();
            for entry in t.1.range(&lo[..]..=&hi[..]).map_err(backend)? {
                if out.len() >= limit as usize {
                    break;
                }
                let (k, v) = entry.map_err(backend)?;
                let (_, n) = split_message_key(k.value())?;
                let (at, body) = decode_message(v.value())?;
                if info.expired(at, now) {
                    continue;
                }
                out.push(Message {
                    id: MessageId(n),
                    bytes: Bytes::copy_from_slice(body),
                    stored_at: at,
                });
            }
            Ok(out)
        })
        .await
    }

    async fn ack(&self, id: &BoxId, up_to: MessageId, now: Timestamp) -> Result<(), StoreError> {
        let id = *id;
        self.write(true, move |t, _| {
            let mut info = live(t, &id, now)?;
            let (boxes, messages, totals) = t;
            let (n, bytes) = remove_messages(messages, &id, 0, up_to.0, usize::MAX, |_| true)?;
            info.count -= n.min(info.count);
            info.bytes -= bytes.min(info.bytes);
            info.touched_at = now;
            account(totals, info.admitted, -i128::from(bytes))?;
            save(boxes, &id, &info)
        })
        .await
    }

    async fn delete(&self, id: &BoxId, now: Timestamp) -> Result<(), StoreError> {
        let id = *id;
        self.write(true, move |t, _| {
            let mut info = live(t, &id, now)?;
            let (boxes, messages, totals) = t;
            drop_box(boxes, messages, totals, &id, &mut info, usize::MAX).map(|_| ())
        })
        .await
    }

    async fn sweep(&self, now: Timestamp) -> Result<u64, StoreError> {
        let mut after: Option<BoxId> = None;
        let mut removed = 0u64;
        loop {
            let (n, next) = self
                .write(true, move |t, limits| sweep_batch(t, limits, after, now))
                .await?;
            removed += n;
            match next {
                Some(next) => after = next,
                None => return Ok(removed),
            }
        }
    }
}

/// One sweep transaction over the boxes after `after`: removes idle boxes and the expired front
/// of live ones within the batch limits. Returns how many idle boxes and expired messages of live
/// boxes it removed and where
/// the next batch starts (`Some(None)` from the beginning), or `None` when the sweep is done.
#[allow(clippy::type_complexity)]
fn sweep_batch(
    t: &mut Tables<'_>,
    limits: &StoreLimits,
    after: Option<BoxId>,
    now: Timestamp,
) -> Result<(u64, Option<Option<BoxId>>), StoreError> {
    let (boxes, messages, totals) = t;
    let start = after.map(|a| *a.as_bytes());
    let lower: Bound<&[u8]> = match &start {
        Some(k) => Bound::Excluded(&k[..]),
        None => Bound::Unbounded,
    };
    let upper: Bound<&[u8]> = Bound::Unbounded;
    let mut batch = Vec::new();
    for entry in boxes.range((lower, upper)).map_err(backend)? {
        if batch.len() >= limits.sweep_boxes.max(1) {
            break;
        }
        let (k, v) = entry.map_err(backend)?;
        let id: [u8; 32] = k
            .value()
            .try_into()
            .map_err(|_| StoreError::backend("bad box key"))?;
        batch.push((BoxId(id), decode_box(v.value())?));
    }
    let full = batch.len() >= limits.sweep_boxes.max(1);
    let mut removed = 0u64;
    let mut budget = limits.sweep_messages.max(1);
    let mut last = after;
    for (id, mut info) in batch {
        if budget == 0 {
            return Ok((removed, Some(last)));
        }
        if info.idle(now) {
            let (n, gone) = drop_box(boxes, messages, totals, &id, &mut info, budget)?;
            budget -= (n as usize).min(budget);
            removed += u64::from(gone);
            if !gone {
                return Ok((removed, Some(last)));
            }
        } else {
            let n = prune(messages, totals, &id, &mut info, now, budget)?;
            if n > 0 {
                save(boxes, &id, &info)?;
                removed += n;
                budget -= (n as usize).min(budget);
                if budget == 0 {
                    return Ok((removed, Some(last)));
                }
            }
        }
        last = Some(id);
    }
    Ok((removed, full.then_some(last)))
}

#[cfg(test)]
mod tests {
    use baton_mailbox::BoxKey;

    use super::*;

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn conformance() {
        let d = dir();
        let s = RedbDropStore::open(&d.path().join("drop.redb"), StoreLimits::default()).unwrap();
        baton_drop::testing::store(Arc::new(s)).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn conformance_twice_on_one_file_after_reopening() {
        let d = dir();
        let path = d.path().join("drop.redb");
        {
            let s = RedbDropStore::open(&path, StoreLimits::default()).unwrap();
            baton_drop::testing::store(Arc::new(s)).await;
        }
        let s = RedbDropStore::open(&path, StoreLimits::default()).unwrap();
        baton_drop::testing::store(Arc::new(s)).await;
    }

    const T: Timestamp = Timestamp(1_800_000_000_000);

    fn policy() -> (BoxPolicy, PublicKey) {
        let w = BoxKey::generate().public();
        (BoxPolicy::new(BoxKey::generate().public(), vec![w]), w)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn messages_survive_a_restart() {
        let d = dir();
        let path = d.path().join("drop.redb");
        let id = BoxId::random();
        let (p, w) = policy();
        {
            let s = RedbDropStore::open(&path, StoreLimits::default()).unwrap();
            s.create(&id, &p, Admitted::Token, T).await.unwrap();
            s.append(&id, &w, Bytes::from_static(b"kept"), T)
                .await
                .unwrap();
        }
        let s = RedbDropStore::open(&path, StoreLimits::default()).unwrap();
        let got = s.read(&id, None, 10, T).await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].bytes, Bytes::from_static(b"kept"));
        assert_eq!(
            s.append(&id, &w, Bytes::new(), T).await.unwrap(),
            MessageId(2)
        );
        assert_eq!(s.totals().unwrap(), (1, 4));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn store_wide_limits_hold() {
        let d = dir();
        let s = RedbDropStore::open(
            &d.path().join("drop.redb"),
            StoreLimits {
                max_boxes: 2,
                max_bytes: 10,
                ..StoreLimits::default()
            },
        )
        .unwrap();
        let (p, w) = policy();
        let (a, b) = (BoxId::random(), BoxId::random());
        s.create(&a, &p, Admitted::Token, T).await.unwrap();
        s.create(&b, &p, Admitted::Token, T).await.unwrap();
        assert!(matches!(
            s.create(&BoxId::random(), &p, Admitted::Token, T).await,
            Err(StoreError::Quota)
        ));
        s.append(&a, &w, Bytes::from(vec![0u8; 6]), T)
            .await
            .unwrap();
        assert!(matches!(
            s.append(&b, &w, Bytes::from(vec![0u8; 5]), T).await,
            Err(StoreError::Quota)
        ));
        s.append(&b, &w, Bytes::from(vec![0u8; 4]), T)
            .await
            .unwrap();
        s.ack(&a, MessageId(1), T).await.unwrap();
        s.append(&b, &w, Bytes::from(vec![0u8; 5]), T)
            .await
            .unwrap();
        s.delete(&b, T).await.unwrap();
        assert_eq!(s.totals().unwrap(), (1, 0));
        s.create(&BoxId::random(), &p, Admitted::Token, T)
            .await
            .unwrap();
        let later = T.plus_ms(p.ttl_ms as i64);
        assert_eq!(s.sweep(later).await.unwrap(), 2);
        assert_eq!(s.totals().unwrap(), (0, 0));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_corrupted_record_is_a_backend_error_not_a_belief() {
        let d = dir();
        let s = RedbDropStore::open(&d.path().join("drop.redb"), StoreLimits::default()).unwrap();
        let id = BoxId::random();
        let (p, w) = policy();
        s.create(&id, &p, Admitted::Token, T).await.unwrap();
        {
            let tx = s.db.begin_write().unwrap();
            tx.open_table(BOXES)
                .unwrap()
                .insert(&id.as_bytes()[..], &b"\x01garbage"[..])
                .unwrap();
            tx.commit().unwrap();
        }
        assert!(matches!(s.get(&id, T).await, Err(StoreError::Backend(_))));
        assert!(matches!(
            s.append(&id, &w, Bytes::new(), T).await,
            Err(StoreError::Backend(_))
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn boxes_anybody_can_create_stay_within_their_share() {
        let d = dir();
        let s = RedbDropStore::open(
            &d.path().join("drop.redb"),
            StoreLimits {
                max_boxes: 10,
                max_bytes: 100,
                max_untrusted_boxes: 3,
                max_untrusted_bytes: 30,
                ..StoreLimits::default()
            },
        )
        .unwrap();
        let (p, w) = policy();
        let mut cheap = Vec::new();
        for admitted in [Admitted::Work, Admitted::Open, Admitted::Work] {
            let id = BoxId::random();
            s.create(&id, &p, admitted, T).await.unwrap();
            cheap.push(id);
        }
        assert!(
            matches!(
                s.create(&BoxId::random(), &p, Admitted::Work, T).await,
                Err(StoreError::Quota)
            ),
            "the untrusted box share is full"
        );
        for id in &cheap {
            s.append(id, &w, Bytes::from(vec![0u8; 10]), T)
                .await
                .unwrap();
        }
        assert!(
            matches!(
                s.append(&cheap[0], &w, Bytes::from(vec![0u8; 1]), T).await,
                Err(StoreError::Quota)
            ),
            "the untrusted byte share is full"
        );
        assert_eq!(s.untrusted_totals().unwrap(), (3, 30));
        let paid = BoxId::random();
        s.create(&paid, &p, Admitted::Token, T)
            .await
            .expect("token holders are not locked out");
        s.append(&paid, &w, Bytes::from(vec![0u8; 70]), T)
            .await
            .expect("nor are their puts");
        assert_eq!(s.totals().unwrap(), (4, 100));
        s.ack(&cheap[0], MessageId(1), T).await.unwrap();
        s.delete(&cheap[1], T).await.unwrap();
        assert_eq!(s.untrusted_totals().unwrap(), (2, 10));
        let later = T.plus_ms(p.ttl_ms as i64);
        s.sweep(later).await.unwrap();
        assert_eq!(s.untrusted_totals().unwrap(), (0, 0));
        assert_eq!(s.totals().unwrap(), (0, 0));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_sweep_runs_in_small_batches_and_still_removes_everything() {
        let d = dir();
        let s = RedbDropStore::open(
            &d.path().join("drop.redb"),
            StoreLimits {
                sweep_boxes: 2,
                sweep_messages: 3,
                ..StoreLimits::default()
            },
        )
        .unwrap();
        let (mut p, w) = policy();
        p.ttl_ms = 60_000;
        let mut idle = Vec::new();
        for _ in 0..5 {
            let id = BoxId::random();
            s.create(&id, &p, Admitted::Token, T).await.unwrap();
            for _ in 0..7 {
                s.append(&id, &w, Bytes::from_static(b"m"), T)
                    .await
                    .unwrap();
            }
            idle.push(id);
        }
        let live = BoxId::random();
        s.create(&live, &p, Admitted::Token, T).await.unwrap();
        for _ in 0..8 {
            s.append(&live, &w, Bytes::from_static(b"old"), T)
                .await
                .unwrap();
        }
        let later = T.plus_ms(60_000);
        s.read(&live, None, 1, T.plus_ms(30_000)).await.unwrap();
        s.append(&live, &w, Bytes::from_static(b"new"), later)
            .await
            .unwrap();
        assert_eq!(s.sweep(later).await.unwrap(), 5 + 8);
        for id in &idle {
            assert!(s.get(id, later).await.unwrap().is_none());
        }
        let left = s.read(&live, None, 100, later).await.unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(s.totals().unwrap(), (1, 3));
        use redb::ReadableTableMetadata;
        let tx = s.db.begin_read().unwrap();
        let m = tx.open_table(MESSAGES).unwrap();
        assert_eq!(
            m.len().unwrap(),
            1,
            "no message of a swept box is left behind"
        );
    }

    #[test]
    fn settings_persist() {
        let d = dir();
        let path = d.path().join("drop.redb");
        {
            let s = RedbDropStore::open(&path, StoreLimits::default()).unwrap();
            assert_eq!(s.setting("salt").unwrap(), None);
            s.set_setting("salt", b"abc").unwrap();
        }
        let s = RedbDropStore::open(&path, StoreLimits::default()).unwrap();
        assert_eq!(s.setting("salt").unwrap(), Some(b"abc".to_vec()));
    }
}
