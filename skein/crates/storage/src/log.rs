use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use skein_core::{AccountId, Event, FencingToken, Seq, TenantId};

use crate::journal::{check_events, check_header};
use crate::{
    Expect, HeadAttestor, IntegrityError, JournalHead, NoAttestor, ObjectKey, Objects, SegmentHash,
    SegmentRef, SegmentSource, SignedHead, Snapshot, StorageError, Version,
};

/// Most events one segment holds; larger appends are refused so readers can find the segment
/// holding any position by listing a bounded range of keys.
pub const MAX_SEGMENT_EVENTS: u64 = 5_000;

/// The per-account journal.
///
/// Guarantees (checked by [`crate::testing::log`]):
///
/// - Events of an account get consecutive numbers starting at 1, in append order.
/// - An append either commits every event it carries or none.
/// - An append or claim with a fencing token lower than one the account has already seen fails
///   with [`StorageError::Fenced`] and writes nothing; once a higher token has been seen, a lower
///   one is refused forever.
/// - `read` returns committed events only, in order, starting at `from`.
/// - Appends with the same token from two writers at once are not supported: the token stands for
///   one owner.
/// - The journal is a hash chain: every segment an append writes names the segment before it by
///   hash, and [`Log::signed_head`] names the last one, so [`crate::Chain`] can verify every event
///   from the head back to the first chained segment, from this log or any other
///   [`SegmentSource`].
#[async_trait]
pub trait Log: SegmentSource {
    /// Appends `events` (their `seq` is ignored and assigned) and returns them as committed.
    async fn append(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        fence: FencingToken,
        events: Vec<Event>,
    ) -> Result<Vec<Event>, StorageError>;

    /// Raises the account's fencing token without appending, so writers with lower tokens are
    /// refused from now on.
    async fn claim(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        fence: FencingToken,
    ) -> Result<(), StorageError>;

    /// The number of the last committed event, `Seq(0)` when the log is empty.
    async fn head(&self, tenant: &TenantId, account: &AccountId) -> Result<Seq, StorageError>;

    /// The committed head with its tip and attestation. Its `seq` equals [`Log::head`]'s; after an
    /// append its tip names the segment that append wrote, and a claim keeps the tip.
    async fn signed_head(
        &self,
        tenant: &TenantId,
        account: &AccountId,
    ) -> Result<SignedHead, StorageError>;

    /// Up to `limit` committed events starting at `from`.
    async fn read(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        from: Seq,
        limit: usize,
    ) -> Result<Vec<Event>, StorageError>;

    /// The head of every account of the tenant that has a log.
    async fn heads(&self, tenant: &TenantId) -> Result<Vec<(AccountId, Seq)>, StorageError>;

    /// Stores a snapshot of the account at `snapshot.seq`, which must not be beyond the head.
    /// Storing one that exists already changes nothing; older snapshots beyond the last two may
    /// be dropped.
    async fn put_snapshot(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        snapshot: &Snapshot,
    ) -> Result<(), StorageError>;

    /// The snapshot with the highest `seq`, if any.
    async fn latest_snapshot(
        &self,
        tenant: &TenantId,
        account: &AccountId,
    ) -> Result<Option<Snapshot>, StorageError>;

    /// Removes events before `before`, which must not be beyond the latest snapshot's `seq + 1`
    /// ([`StorageError::Conflict`] otherwise). Reads that start before the first remaining event
    /// fail with [`StorageError::Compacted`] from then on. Returns how many events were removed;
    /// implementations may keep more than asked (whole segments).
    async fn compact(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        before: Seq,
    ) -> Result<u64, StorageError>;

    /// Deletes the logs, heads and snapshots of every account of the tenant; returns how many
    /// objects were removed. Afterwards every account reads as empty.
    async fn purge(&self, tenant: &TenantId) -> Result<u64, StorageError>;
}

pub(crate) const SEGMENT_FORMAT: u32 = 1;
const HEADER_PREFIX: &str = "{\"skein_segment\":";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SegmentHeader {
    pub(crate) skein_segment: u32,
    pub(crate) tenant: TenantId,
    pub(crate) account: AccountId,
    pub(crate) start: Seq,
    pub(crate) end: Seq,
    pub(crate) fence: FencingToken,
    pub(crate) prev: Option<SegmentRef>,
}

#[derive(Debug, PartialEq)]
pub(crate) struct Decoded {
    pub(crate) header: Option<SegmentHeader>,
    pub(crate) events: Vec<Event>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Head {
    pub(crate) seq: u64,
    pub(crate) fence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) tip: Option<SegmentRef>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "ser_attestation",
        deserialize_with = "de_attestation"
    )]
    pub(crate) attestation: Option<Bytes>,
}

fn ser_attestation<S: Serializer>(value: &Option<Bytes>, s: S) -> Result<S::Ok, S::Error> {
    match value {
        Some(bytes) => s.serialize_str(&STANDARD.encode(bytes)),
        None => s.serialize_none(),
    }
}

fn de_attestation<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Bytes>, D::Error> {
    let Some(text) = Option::<String>::deserialize(d)? else {
        return Ok(None);
    };
    STANDARD
        .decode(text)
        .map(|b| Some(Bytes::from(b)))
        .map_err(serde::de::Error::custom)
}

impl Head {
    fn same(&self, other: &Head) -> bool {
        self.seq == other.seq && self.fence == other.fence && self.tip == other.tip
    }

    fn journal(&self, tenant: &TenantId, account: &AccountId) -> JournalHead {
        JournalHead {
            tenant: tenant.clone(),
            account: account.clone(),
            seq: Seq(self.seq),
            fence: FencingToken(self.fence),
            tip: self.tip.clone(),
        }
    }
}

pub(crate) fn decode_head(bytes: &[u8]) -> Result<Head, StorageError> {
    serde_json::from_slice(bytes).map_err(|e| StorageError::Corrupt(format!("log head: {e}")))
}

struct Seen {
    head: Head,
    stamp: u64,
}

#[derive(Default)]
struct Watermarks {
    clock: AtomicU64,
    seen: Mutex<HashMap<(TenantId, AccountId), Seen>>,
}

impl Watermarks {
    fn tick(&self) -> u64 {
        self.clock.fetch_add(1, Ordering::SeqCst)
    }

    fn verified(&self, tenant: &TenantId, account: &AccountId, head: &Head) -> bool {
        let seen = self.seen.lock().expect("not poisoned");
        seen.get(&(tenant.clone(), account.clone()))
            .is_some_and(|s| &s.head == head)
    }

    fn check(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        head: &Head,
        started: u64,
    ) -> Result<(), IntegrityError> {
        let seen = self.seen.lock().expect("not poisoned");
        match seen.get(&(tenant.clone(), account.clone())) {
            Some(s) if s.stamp < started => s
                .head
                .journal(tenant, account)
                .check_successor(&head.journal(tenant, account)),
            _ => Ok(()),
        }
    }

    fn observe(&self, tenant: &TenantId, account: &AccountId, head: &Head) {
        let stamp = self.tick();
        let mut seen = self.seen.lock().expect("not poisoned");
        let entry = seen
            .entry((tenant.clone(), account.clone()))
            .or_insert_with(|| Seen {
                head: head.clone(),
                stamp,
            });
        if (head.seq, head.fence) > (entry.head.seq, entry.head.fence) {
            *entry = Seen {
                head: head.clone(),
                stamp,
            };
        } else if entry.head.same(head) {
            entry.head.attestation = head.attestation.clone();
        }
    }

    fn forget(&self, tenant: &TenantId) {
        self.seen
            .lock()
            .expect("not poisoned")
            .retain(|(t, _), _| t != tenant);
    }
}

/// A [`Log`] on top of [`Objects`].
///
/// Layout: `tenants/{t}/heads/{account}` holds the committed head, the highest fencing token, the
/// tip (the segment ending at the head) and the head's attestation;
/// `tenants/{t}/log/{account}/{start}-{end}-{fence}` holds zstd-compressed NDJSON segments whose
/// first line names the tenant, account, range, token and previous segment. A segment counts only
/// once the head covers it; of two segments starting at the same position the one with the higher
/// token is the committed one, since a lower token can never commit after a higher one was seen.
///
/// Every head it writes goes through its [`HeadAttestor`] ([`NoAttestor`] unless
/// [`ObjectLog::with_attestor`] gives one), and every head it reads is checked with it. It also
/// remembers the newest head it has read or written for each account and refuses a head read
/// later that is behind it or disagrees with it ([`IntegrityError::Rollback`],
/// [`IntegrityError::Fork`]), so a rolled-back head never makes it write over committed events.
/// `read` checks the link between every two consecutive segments it reads and the tip against the
/// head.
pub struct ObjectLog {
    objects: Arc<dyn Objects>,
    attestor: Arc<dyn HeadAttestor>,
    marks: Watermarks,
}

impl ObjectLog {
    /// A log in `objects` whose heads are not attested.
    pub fn new(objects: Arc<dyn Objects>) -> Self {
        Self::with_attestor(objects, Arc::new(NoAttestor))
    }

    /// A log in `objects` that attests every head it writes and verifies every head it reads with
    /// `attestor`.
    pub fn with_attestor(objects: Arc<dyn Objects>, attestor: Arc<dyn HeadAttestor>) -> Self {
        Self {
            objects,
            attestor,
            marks: Watermarks::default(),
        }
    }

    fn head_key(tenant: &TenantId, account: &AccountId) -> ObjectKey {
        ObjectKey::account(tenant, "heads", account).expect("ids are valid segments")
    }

    fn seg_prefix(tenant: &TenantId, account: &AccountId) -> ObjectKey {
        ObjectKey::account(tenant, "log", account).expect("ids are valid segments")
    }

    fn seg_key(
        tenant: &TenantId,
        account: &AccountId,
        start: u64,
        end: u64,
        fence: u64,
    ) -> ObjectKey {
        Self::seg_prefix(tenant, account)
            .join(&format!("{start:020}-{end:020}-{fence:020}"))
            .expect("digits are valid segments")
    }

    fn snap_prefix(tenant: &TenantId, account: &AccountId) -> ObjectKey {
        ObjectKey::account(tenant, "snapshots", account).expect("ids are valid segments")
    }

    async fn snapshot_keys(
        &self,
        tenant: &TenantId,
        account: &AccountId,
    ) -> Result<Vec<(u64, ObjectKey)>, StorageError> {
        let prefix = Self::snap_prefix(tenant, account);
        let mut out = Vec::new();
        let mut after = None;
        loop {
            let page = self.objects.list(&prefix, after.as_ref(), 1000).await?;
            for key in &page {
                if let Ok(seq) = key.last().parse::<u64>() {
                    out.push((seq, key.clone()));
                }
            }
            if page.len() < 1000 {
                break;
            }
            after = page.last().cloned();
        }
        out.sort();
        Ok(out)
    }

    async fn load_head(
        &self,
        tenant: &TenantId,
        account: &AccountId,
    ) -> Result<(Head, Expect), StorageError> {
        let started = self.marks.tick();
        let (head, expect) = match self.objects.get(&Self::head_key(tenant, account)).await? {
            None => (Head::default(), Expect::Absent),
            Some((bytes, version)) => (decode_head(&bytes)?, Expect::Version(version)),
        };
        let journal = head.journal(tenant, account);
        journal.check()?;
        self.marks.check(tenant, account, &head, started)?;
        if matches!(expect, Expect::Absent) {
            return Ok((head, expect));
        }
        if !self.marks.verified(tenant, account, &head) {
            self.attestor
                .verify(&journal, head.attestation.as_deref())
                .await?;
        }
        self.marks.observe(tenant, account, &head);
        Ok((head, expect))
    }

    async fn store_head(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        mut head: Head,
        expect: Expect,
    ) -> Result<(Head, Version), StorageError> {
        head.attestation = self.attestor.attest(&head.journal(tenant, account)).await?;
        let bytes = Bytes::from(serde_json::to_vec(&head).expect("plain struct"));
        let version = self
            .objects
            .put(&Self::head_key(tenant, account), bytes, expect)
            .await?;
        self.marks.observe(tenant, account, &head);
        Ok((head, version))
    }

    async fn segments_from(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        from: u64,
    ) -> Result<Vec<(u64, u64, u64, ObjectKey)>, StorageError> {
        let prefix = Self::seg_prefix(tenant, account);
        let lower = from.saturating_sub(MAX_SEGMENT_EVENTS);
        let mut after = if lower == 0 {
            None
        } else {
            Some(prefix.join(&format!("{lower:020}")).expect("digits"))
        };
        let mut out = Vec::new();
        loop {
            let page = self.objects.list(&prefix, after.as_ref(), 1000).await?;
            let done = page.len() < 1000;
            for key in &page {
                if let Some((s, e, f)) = parse_segment(key.last()) {
                    out.push((s, e, f, key.clone()));
                }
            }
            if done {
                break;
            }
            after = page.last().cloned();
        }
        Ok(out)
    }

    async fn committed_from(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        from: u64,
        head: &Head,
    ) -> Result<BTreeMap<u64, (u64, u64, ObjectKey)>, StorageError> {
        let mut best: BTreeMap<u64, (u64, u64, ObjectKey)> = BTreeMap::new();
        for (s, e, f, key) in self.segments_from(tenant, account, from).await? {
            if e > head.seq || f > head.fence {
                continue;
            }
            match best.get(&s) {
                Some((_, bf, _)) if *bf >= f => {}
                _ => {
                    best.insert(s, (e, f, key));
                }
            }
        }
        Ok(best)
    }

    async fn remove_own_orphans(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        start: u64,
        fence: u64,
    ) -> Result<(), StorageError> {
        for (s, _, f, key) in self.segments_from(tenant, account, start).await? {
            if s == start && f == fence {
                self.objects.delete(&key, Expect::Any).await?;
            }
        }
        Ok(())
    }
}

fn parse_segment(name: &str) -> Option<(u64, u64, u64)> {
    let mut parts = name.split('-');
    let s = parts.next()?.parse().ok()?;
    let e = parts.next()?.parse().ok()?;
    let f = parts.next()?.parse().ok()?;
    if parts.next().is_some() || e < s {
        return None;
    }
    Some((s, e, f))
}

pub(crate) fn encode_segment(
    header: Option<&SegmentHeader>,
    events: &[Event],
) -> Result<Bytes, StorageError> {
    let mut encoder = zstd::Encoder::new(Vec::new(), 3).map_err(StorageError::backend)?;
    if let Some(header) = header {
        serde_json::to_writer(&mut encoder, header)
            .map_err(|e| StorageError::Corrupt(e.to_string()))?;
        encoder.write_all(b"\n").map_err(StorageError::backend)?;
    }
    for event in events {
        serde_json::to_writer(&mut encoder, event)
            .map_err(|e| StorageError::Corrupt(e.to_string()))?;
        encoder.write_all(b"\n").map_err(StorageError::backend)?;
    }
    Ok(Bytes::from(
        encoder.finish().map_err(StorageError::backend)?,
    ))
}

const MAX_SEGMENT_BYTES: u64 = 256 * 1024 * 1024;

pub(crate) fn decode_segment(bytes: &[u8]) -> Result<Decoded, StorageError> {
    let decoder = zstd::Decoder::new(bytes).map_err(|e| StorageError::Corrupt(e.to_string()))?;
    let mut text = String::new();
    decoder
        .take(MAX_SEGMENT_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| StorageError::Corrupt(e.to_string()))?;
    if text.len() as u64 > MAX_SEGMENT_BYTES {
        return Err(StorageError::Corrupt("segment is too large".into()));
    }
    let mut lines = text.lines().filter(|l| !l.is_empty()).peekable();
    let header = match lines.peek() {
        Some(line) if line.starts_with(HEADER_PREFIX) => {
            let header: SegmentHeader = serde_json::from_str(line)
                .map_err(|e| StorageError::Corrupt(format!("segment header: {e}")))?;
            if header.skein_segment != SEGMENT_FORMAT {
                return Err(StorageError::Corrupt("unknown segment format".into()));
            }
            lines.next();
            Some(header)
        }
        _ => None,
    };
    let mut events = Vec::new();
    for line in lines {
        events.push(serde_json::from_str(line).map_err(|e| StorageError::Corrupt(e.to_string()))?);
    }
    Ok(Decoded { header, events })
}

pub(crate) struct ReadLink {
    segment: SegmentRef,
    chained: bool,
}

pub(crate) fn check_read(
    tenant: &TenantId,
    account: &AccountId,
    head: &Head,
    last: Option<&ReadLink>,
    this: &SegmentRef,
    decoded: &Decoded,
) -> Result<(), IntegrityError> {
    let name = this.name();
    match &decoded.header {
        Some(header) => {
            check_header(
                tenant, account, &name, this.start, this.end, this.fence, header,
            )?;
            if let Some(last) = last {
                let expected = last.chained.then_some(&last.segment);
                if header.prev.as_ref() != expected {
                    return Err(IntegrityError::Link { seq: this.start.0 });
                }
            }
        }
        None if last.is_some_and(|l| l.chained) => {
            return Err(IntegrityError::Link { seq: this.start.0 });
        }
        None => {}
    }
    if this.end.0 == head.seq {
        match &head.tip {
            Some(tip) if tip.name() == name && tip.hash != this.hash => {
                return Err(IntegrityError::HashMismatch { segment: name });
            }
            Some(tip) if tip != this => return Err(IntegrityError::Fork { seq: head.seq }),
            None if decoded.header.is_some() => {
                return Err(IntegrityError::Fork { seq: head.seq });
            }
            _ => {}
        }
    }
    check_events(account, &name, this.start, this.end, &decoded.events)
}

#[async_trait]
impl SegmentSource for ObjectLog {
    async fn segment(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        segment: &SegmentRef,
    ) -> Result<Option<Bytes>, StorageError> {
        let key = Self::seg_key(
            tenant,
            account,
            segment.start.0,
            segment.end.0,
            segment.fence.0,
        );
        Ok(self.objects.get(&key).await?.map(|(bytes, _)| bytes))
    }
}

#[async_trait]
impl Log for ObjectLog {
    async fn append(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        fence: FencingToken,
        mut events: Vec<Event>,
    ) -> Result<Vec<Event>, StorageError> {
        if events.is_empty() {
            return Ok(events);
        }
        let n = events.len() as u64;
        if n > MAX_SEGMENT_EVENTS {
            return Err(StorageError::backend(format!(
                "an append holds at most {MAX_SEGMENT_EVENTS} events"
            )));
        }
        loop {
            let (mut head, mut expect) = self.load_head(tenant, account).await?;
            if head.fence > fence.0 {
                return Err(StorageError::Fenced);
            }
            if head.fence < fence.0 {
                head.fence = fence.0;
                match self.store_head(tenant, account, head, expect).await {
                    Ok((stored, v)) => {
                        head = stored;
                        expect = Expect::Version(v);
                    }
                    Err(StorageError::Conflict) => continue,
                    Err(e) => return Err(e),
                }
            }
            let start = head.seq + 1;
            let end = head.seq + n;
            self.remove_own_orphans(tenant, account, start, fence.0)
                .await?;
            for (i, event) in events.iter_mut().enumerate() {
                event.seq = Seq(start + i as u64);
                event.account = account.clone();
            }
            let header = SegmentHeader {
                skein_segment: SEGMENT_FORMAT,
                tenant: tenant.clone(),
                account: account.clone(),
                start: Seq(start),
                end: Seq(end),
                fence,
                prev: head.tip.clone(),
            };
            let bytes = encode_segment(Some(&header), &events)?;
            let tip = SegmentRef {
                start: Seq(start),
                end: Seq(end),
                fence,
                hash: SegmentHash::of(&bytes),
            };
            let key = Self::seg_key(tenant, account, start, end, fence.0);
            self.objects.put(&key, bytes, Expect::Any).await?;
            let committed = Head {
                seq: end,
                fence: fence.0,
                tip: Some(tip),
                attestation: None,
            };
            match self
                .store_head(tenant, account, committed.clone(), expect)
                .await
            {
                Ok(_) => return Ok(events),
                Err(StorageError::Conflict) => {
                    let (now, _) = self.load_head(tenant, account).await?;
                    if now.same(&committed) {
                        return Ok(events);
                    }
                    self.objects.delete(&key, Expect::Any).await?;
                    if now.fence > fence.0 {
                        return Err(StorageError::Fenced);
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn claim(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        fence: FencingToken,
    ) -> Result<(), StorageError> {
        loop {
            let (mut head, expect) = self.load_head(tenant, account).await?;
            if head.fence > fence.0 {
                return Err(StorageError::Fenced);
            }
            if head.fence == fence.0 && !matches!(expect, Expect::Absent) {
                return Ok(());
            }
            head.fence = fence.0;
            match self.store_head(tenant, account, head, expect).await {
                Ok(_) => return Ok(()),
                Err(StorageError::Conflict) => continue,
                Err(e) => return Err(e),
            }
        }
    }

    async fn head(&self, tenant: &TenantId, account: &AccountId) -> Result<Seq, StorageError> {
        Ok(Seq(self.load_head(tenant, account).await?.0.seq))
    }

    async fn signed_head(
        &self,
        tenant: &TenantId,
        account: &AccountId,
    ) -> Result<SignedHead, StorageError> {
        let (head, _) = self.load_head(tenant, account).await?;
        Ok(SignedHead {
            head: head.journal(tenant, account),
            attestation: head.attestation,
        })
    }

    async fn read(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        from: Seq,
        limit: usize,
    ) -> Result<Vec<Event>, StorageError> {
        let from = from.0.max(1);
        let (head, _) = self.load_head(tenant, account).await?;
        if from > head.seq || limit == 0 {
            return Ok(Vec::new());
        }
        let mut best = self.committed_from(tenant, account, from, &head).await?;
        let mut out = Vec::new();
        let mut want = from;
        let mut last: Option<ReadLink> = None;
        let mut cursor = best.range(..=from).next_back().map(|(s, _)| *s);
        if cursor.is_none()
            || best
                .get(&cursor.unwrap_or(0))
                .is_some_and(|(e, _, _)| *e < from)
        {
            let first = best
                .range(from + 1..)
                .next()
                .map(|(&first, _)| first)
                .unwrap_or(head.seq + 1);
            return Err(StorageError::Compacted { first });
        }
        while let Some(start) = cursor {
            let Some((end, fence, key)) = best.get(&start).cloned() else {
                break;
            };
            if end >= want {
                let Some((bytes, _)) = self.objects.get(&key).await? else {
                    return Err(StorageError::Corrupt(format!("segment {key} vanished")));
                };
                let this = SegmentRef {
                    start: Seq(start),
                    end: Seq(end),
                    fence: FencingToken(fence),
                    hash: SegmentHash::of(&bytes),
                };
                let decoded = decode_segment(&bytes)?;
                check_read(tenant, account, &head, last.as_ref(), &this, &decoded)?;
                last = Some(ReadLink {
                    segment: this,
                    chained: decoded.header.is_some(),
                });
                for event in decoded.events {
                    if event.seq.0 >= want {
                        out.push(event);
                        want += 1;
                        if out.len() == limit {
                            return Ok(out);
                        }
                    }
                }
            }
            if want > head.seq {
                break;
            }
            cursor = best.contains_key(&want).then_some(want);
            if cursor.is_none() {
                best = self.committed_from(tenant, account, want, &head).await?;
                cursor = best.contains_key(&want).then_some(want);
                if cursor.is_none() {
                    if let Some((&first, _)) = best.range(want + 1..).next() {
                        return Err(StorageError::Compacted { first });
                    }
                    return Err(StorageError::Corrupt(format!(
                        "no committed segment starts at {want}"
                    )));
                }
            }
        }
        Ok(out)
    }

    async fn heads(&self, tenant: &TenantId) -> Result<Vec<(AccountId, Seq)>, StorageError> {
        let prefix = ObjectKey::tenant(tenant).join("heads").expect("constant");
        let mut out = Vec::new();
        let mut after = None;
        loop {
            let page = self.objects.list(&prefix, after.as_ref(), 1000).await?;
            for key in &page {
                let Ok(account) = AccountId::new(key.last()) else {
                    continue;
                };
                out.push((account.clone(), self.head(tenant, &account).await?));
            }
            if page.len() < 1000 {
                break;
            }
            after = page.last().cloned();
        }
        Ok(out)
    }

    async fn put_snapshot(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        snapshot: &Snapshot,
    ) -> Result<(), StorageError> {
        let (head, _) = self.load_head(tenant, account).await?;
        if snapshot.seq.0 > head.seq || &snapshot.account != account {
            return Err(StorageError::Conflict);
        }
        let json =
            serde_json::to_vec(snapshot).map_err(|e| StorageError::Corrupt(e.to_string()))?;
        let bytes = zstd::encode_all(&json[..], 3).map_err(StorageError::backend)?;
        let key = Self::snap_prefix(tenant, account)
            .join(&format!("{:020}", snapshot.seq.0))
            .expect("digits");
        match self
            .objects
            .put(&key, Bytes::from(bytes), Expect::Absent)
            .await
        {
            Ok(_) | Err(StorageError::Conflict) => {}
            Err(e) => return Err(e),
        }
        let keys = self.snapshot_keys(tenant, account).await?;
        if keys.len() > 2 {
            for (_, old) in &keys[..keys.len() - 2] {
                self.objects.delete(old, Expect::Any).await?;
            }
        }
        Ok(())
    }

    async fn latest_snapshot(
        &self,
        tenant: &TenantId,
        account: &AccountId,
    ) -> Result<Option<Snapshot>, StorageError> {
        let keys = self.snapshot_keys(tenant, account).await?;
        let Some((_, key)) = keys.last() else {
            return Ok(None);
        };
        let Some((bytes, _)) = self.objects.get(key).await? else {
            return Ok(None);
        };
        let json =
            zstd::decode_all(&bytes[..]).map_err(|e| StorageError::Corrupt(e.to_string()))?;
        let snapshot: Snapshot =
            serde_json::from_slice(&json).map_err(|e| StorageError::Corrupt(e.to_string()))?;
        if &snapshot.account != account {
            return Err(StorageError::Corrupt(format!(
                "{key} holds another account"
            )));
        }
        Ok(Some(snapshot))
    }

    async fn compact(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        before: Seq,
    ) -> Result<u64, StorageError> {
        let covered = self
            .snapshot_keys(tenant, account)
            .await?
            .last()
            .map(|(s, _)| *s)
            .unwrap_or(0);
        if before.0 > covered + 1 {
            return Err(StorageError::Conflict);
        }
        let mut removed = 0;
        for (s, e, _, key) in self.segments_from(tenant, account, 0).await? {
            if e < before.0 {
                self.objects.delete(&key, Expect::Any).await?;
                removed += e - s + 1;
            }
        }
        Ok(removed)
    }

    async fn purge(&self, tenant: &TenantId) -> Result<u64, StorageError> {
        let mut removed = 0;
        for area in ["heads", "log", "snapshots"] {
            let prefix = ObjectKey::tenant(tenant).join(area)?;
            removed += crate::delete_prefix(&*self.objects, &prefix, |_| false).await?;
        }
        self.marks.forget(tenant);
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use skein_core::{EventBody, Flags, ItemRef, Timestamp};

    use super::*;

    const OLD_SEGMENT: &[u8] = &[
        0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x58, 0x25, 0x04, 0x00, 0x52, 0x88, 0x1a, 0x1d, 0x60, 0x8b,
        0x33, 0x06, 0xc5, 0x3c, 0x7e, 0x09, 0x7c, 0xd6, 0x6b, 0xd1, 0x50, 0xb8, 0x46, 0x10, 0x72,
        0x96, 0xdf, 0x10, 0x0b, 0x97, 0xa6, 0x7c, 0x40, 0x41, 0x88, 0x95, 0x1c, 0x6b, 0xad, 0xb5,
        0x00, 0xd3, 0x84, 0x18, 0xee, 0x16, 0x10, 0xe4, 0x83, 0x9e, 0x93, 0xd2, 0xdd, 0x83, 0xce,
        0x95, 0xaa, 0x75, 0xf7, 0x96, 0xf4, 0x66, 0xe3, 0x3b, 0x37, 0x10, 0x02, 0x03, 0xc1, 0xfa,
        0xc3, 0x49, 0x98, 0xc7, 0x9a, 0x73, 0xb7, 0x0a, 0x64, 0x8b, 0x96, 0x78, 0x14, 0xc6, 0x28,
        0xd6, 0x97, 0x11, 0xc5, 0x25, 0x3d, 0x72, 0x4e, 0x72, 0xae, 0x96, 0xf5, 0x68, 0x97, 0x73,
        0xb6, 0x1e, 0x21, 0xe4, 0xb4, 0x16, 0x59, 0x63, 0x9f, 0x53, 0xe9, 0x8e, 0xa5, 0x09, 0x00,
        0xa0, 0x0a, 0x78, 0x0f, 0x00, 0xca, 0x40, 0x15, 0xc0, 0x2e, 0x8a, 0x9d, 0x4a, 0x06, 0x61,
        0x44, 0x95, 0xc1, 0xbb, 0x8a, 0x17,
    ];

    #[test]
    fn reads_a_segment_written_by_zstd_0_13() {
        let account = AccountId::new("a").unwrap();
        let decoded = decode_segment(OLD_SEGMENT).unwrap();
        assert!(decoded.header.is_none());
        let events = decoded.events;
        let expected: Vec<Event> = (1..=2)
            .map(|n| Event {
                v: 1,
                seq: Seq(n),
                at: Timestamp(n as i64),
                account: account.clone(),
                key: format!("k{n}"),
                origin: None,
                trace: None,
                body: EventBody::FlagsChanged {
                    mailbox: "INBOX".into(),
                    item: ItemRef {
                        id: format!("1:{n}"),
                        uid: Some(n as u32),
                    },
                    flags: Flags::new(["\\Seen"]),
                },
            })
            .collect();
        assert_eq!(events, expected);
        assert_eq!(
            decode_segment(&encode_segment(None, &events).unwrap())
                .unwrap()
                .events,
            expected
        );
    }

    #[test]
    fn oversized_segment_is_corrupt() {
        let mut encoder = zstd::Encoder::new(Vec::new(), 1).unwrap();
        let chunk = vec![b' '; 1024 * 1024];
        for _ in 0..=MAX_SEGMENT_BYTES / chunk.len() as u64 {
            encoder.write_all(&chunk).unwrap();
        }
        let bytes = encoder.finish().unwrap();
        assert!(matches!(
            decode_segment(&bytes),
            Err(StorageError::Corrupt(m)) if m.contains("too large")
        ));
    }

    #[test]
    fn the_header_line_is_told_apart_from_events() {
        let account = AccountId::new("a").unwrap();
        let header = SegmentHeader {
            skein_segment: SEGMENT_FORMAT,
            tenant: TenantId::new("t").unwrap(),
            account: account.clone(),
            start: Seq(1),
            end: Seq(1),
            fence: FencingToken(1),
            prev: None,
        };
        let event = decode_segment(OLD_SEGMENT).unwrap().events.remove(0);
        assert!(
            !serde_json::to_string(&event)
                .unwrap()
                .starts_with(HEADER_PREFIX)
        );
        let bytes = encode_segment(Some(&header), std::slice::from_ref(&event)).unwrap();
        let decoded = decode_segment(&bytes).unwrap();
        assert_eq!(decoded.header, Some(header.clone()));
        assert_eq!(decoded.events, vec![event.clone()]);

        let line = serde_json::to_string(&header).unwrap();
        let future = line.replacen("\"skein_segment\":1", "\"skein_segment\":2", 1);
        let framed = |first: String| zstd::encode_all(format!("{first}\n").as_bytes(), 1).unwrap();
        assert!(matches!(
            decode_segment(&framed(future)),
            Err(StorageError::Corrupt(m)) if m.contains("unknown segment format")
        ));
        let extra = line.replacen('{', "{\"skein_segment\":1,\"more\":1,", 1);
        assert!(decode_segment(&framed(extra)).is_err());
    }
}
