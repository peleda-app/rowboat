use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use skein_core::{AccountId, BlobHash, FencingToken, Seq, TenantId};
use skein_storage::testing::{self, sample_event};
use skein_storage::{
    Chain, CountingObjects, Expect, IntegrityError, JournalHead, ObjectKey, Objects, ReadTier,
    SegmentRef, SegmentSource, Storage, StorageError,
};
use skein_storage_memory::MemoryObjects;

use crate::{StorageTier, Tiered};

fn t() -> TenantId {
    TenantId::new("t").unwrap()
}

fn a() -> AccountId {
    AccountId::new("a").unwrap()
}

fn memory() -> (Arc<dyn Objects>, Storage) {
    let objects: Arc<dyn Objects> = Arc::new(MemoryObjects::new());
    (objects.clone(), Storage::over(objects))
}

const BODY: &[u8] = b"From: ada@example.com\r\n\r\nkept on another tier\r\n";

struct Origin {
    storage: Storage,
    counts: Arc<CountingObjects>,
    head: JournalHead,
    blob: BlobHash,
}

async fn origin() -> Origin {
    let counts = Arc::new(CountingObjects::new(Arc::new(MemoryObjects::new())));
    let storage = Storage::over(counts.clone());
    let mut n = 0;
    for (fence, size) in [(1, 3), (1, 1), (2, 4)] {
        let events = (0..size)
            .map(|_| {
                n += 1;
                sample_event(&a(), n)
            })
            .collect();
        storage
            .log
            .append(&t(), &a(), FencingToken(fence), events)
            .await
            .unwrap();
    }
    let blob = storage
        .blobs
        .put(&t(), Bytes::from_static(BODY))
        .await
        .unwrap();
    let head = storage.log.signed_head(&t(), &a()).await.unwrap().head;
    Origin {
        storage,
        counts,
        head,
        blob,
    }
}

async fn walk(source: &dyn SegmentSource, head: &JournalHead) -> Result<Vec<u64>, StorageError> {
    let mut chain = Chain::new(source, head);
    let mut seqs = Vec::new();
    while let Some(segment) = chain.next().await? {
        seqs.splice(0..0, segment.events.iter().map(|e| e.seq.0));
    }
    Ok(seqs)
}

#[derive(Clone, Copy, Debug)]
enum Attack {
    WrongBytes,
    Truncated,
    Extended,
    BitFlip,
    OtherAccount,
    Oversized,
    Slow,
    Failing,
    Withheld,
}

const ATTACKS: [Attack; 9] = [
    Attack::WrongBytes,
    Attack::Truncated,
    Attack::Extended,
    Attack::BitFlip,
    Attack::OtherAccount,
    Attack::Oversized,
    Attack::Slow,
    Attack::Failing,
    Attack::Withheld,
];

struct Hostile {
    attack: Attack,
    truth: Storage,
    asked: AtomicUsize,
}

impl Hostile {
    fn new(attack: Attack, truth: Storage) -> Arc<Self> {
        Arc::new(Self {
            attack,
            truth,
            asked: AtomicUsize::new(0),
        })
    }

    async fn answer(&self, truth: Option<Bytes>) -> Result<Option<Bytes>, StorageError> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        let truth = truth.unwrap_or_else(|| Bytes::from_static(b"nothing"));
        let mut bytes = truth.to_vec();
        match self.attack {
            Attack::WrongBytes => bytes = b"forged".to_vec(),
            Attack::Truncated => {
                bytes.pop();
            }
            Attack::Extended => bytes.push(b'\n'),
            Attack::BitFlip => {
                let middle = bytes.len() / 2;
                bytes[middle] ^= 1;
            }
            Attack::OtherAccount => {
                let other = AccountId::new("other").unwrap();
                self.truth
                    .log
                    .append(&t(), &other, FencingToken(1), vec![sample_event(&other, 1)])
                    .await
                    .ok();
                let head = self.truth.log.signed_head(&t(), &other).await?.head;
                bytes = self
                    .truth
                    .log
                    .segment(&t(), &other, head.tip.as_ref().unwrap())
                    .await?
                    .unwrap()
                    .to_vec();
            }
            Attack::Oversized => bytes.resize(bytes.len() + (1 << 20), b' '),
            Attack::Slow => {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
            Attack::Failing => return Err(StorageError::backend("tier is down")),
            Attack::Withheld => return Ok(None),
        }
        Ok(Some(Bytes::from(bytes)))
    }
}

#[async_trait]
impl ReadTier for Hostile {
    async fn segment(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        segment: &SegmentRef,
        _: usize,
    ) -> Result<Option<Bytes>, StorageError> {
        let truth = self.truth.log.segment(tenant, account, segment).await?;
        self.answer(truth).await
    }

    async fn blob(
        &self,
        tenant: &TenantId,
        hash: &BlobHash,
        _: usize,
    ) -> Result<Option<Bytes>, StorageError> {
        let truth = self.truth.blobs.get(tenant, hash).await?;
        self.answer(truth).await
    }
}

#[tokio::test]
async fn conformance_without_tiers() {
    let (_, local) = memory();
    let storage = Tiered::new(local).build();
    testing::control(storage.control.clone()).await;
    testing::blobs(storage.blobs.clone()).await;
    testing::commands(storage.commands.clone()).await;
    testing::log(storage.log.clone()).await;
    testing::snapshots(storage.log.clone()).await;
    testing::replica(storage.log.clone()).await;
    testing::purge(storage).await;
}

#[tokio::test]
async fn conformance_with_a_tier_that_has_nothing() {
    let (_, local) = memory();
    let (_, empty) = memory();
    let storage = Tiered::new(local)
        .with_tier(Arc::new(StorageTier::new(empty)))
        .build();
    testing::blobs(storage.blobs.clone()).await;
    testing::log(storage.log.clone()).await;
    testing::snapshots(storage.log.clone()).await;
    testing::purge(storage).await;
}

#[tokio::test]
async fn a_storage_tier_keeps_the_read_tier_contract() {
    let counts = Arc::new(CountingObjects::new(Arc::new(MemoryObjects::new())));
    let origin = Storage::over(counts.clone());
    testing::read_tier(Arc::new(StorageTier::new(origin.clone())), origin, counts).await;
}

#[tokio::test]
async fn segments_and_blobs_missing_locally_come_from_a_tier_verified() {
    let origin = origin().await;
    let (_, local) = memory();
    let storage = Tiered::new(local.clone())
        .with_tier(Arc::new(StorageTier::new(origin.storage.clone())))
        .build();
    let writes = origin.counts.counts();

    assert_eq!(
        walk(&*storage.log, &origin.head).await.unwrap(),
        (1..=8).collect::<Vec<_>>()
    );
    assert!(matches!(
        walk(&*local.log, &origin.head).await,
        Err(StorageError::Integrity(IntegrityError::Missing { .. }))
    ));
    assert_eq!(
        storage
            .blobs
            .get(&t(), &origin.blob)
            .await
            .unwrap()
            .unwrap(),
        BODY
    );
    assert!(
        local.blobs.contains(&t(), &origin.blob).await.unwrap(),
        "a verified blob is kept locally"
    );
    let after = origin.counts.counts();
    assert_eq!(
        (after.puts, after.deletes),
        (writes.puts, writes.deletes),
        "tiers are never written to"
    );
}

#[tokio::test]
async fn without_fill_nothing_is_stored_locally() {
    let origin = origin().await;
    let (_, local) = memory();
    let storage = Tiered::new(local.clone())
        .with_tier(Arc::new(StorageTier::new(origin.storage.clone())))
        .without_fill()
        .build();
    assert!(
        storage
            .blobs
            .get(&t(), &origin.blob)
            .await
            .unwrap()
            .is_some()
    );
    assert!(!local.blobs.contains(&t(), &origin.blob).await.unwrap());
    assert!(
        !storage.blobs.contains(&t(), &origin.blob).await.unwrap(),
        "contains asks local storage only"
    );
}

#[tokio::test(start_paused = true)]
async fn every_attack_falls_back_to_the_next_tier() {
    for attack in ATTACKS {
        let origin = origin().await;
        let (_, local) = memory();
        let hostile = Hostile::new(attack, origin.storage.clone());
        let storage = Tiered::new(local)
            .with_tier(hostile.clone())
            .with_tier(Arc::new(StorageTier::new(origin.storage.clone())))
            .with_limits(64 * 1024, 64 * 1024)
            .with_timeout(Duration::from_secs(5))
            .build();
        assert_eq!(
            walk(&*storage.log, &origin.head).await.unwrap(),
            (1..=8).collect::<Vec<_>>(),
            "{attack:?}"
        );
        assert_eq!(
            storage
                .blobs
                .get(&t(), &origin.blob)
                .await
                .unwrap()
                .unwrap(),
            BODY,
            "{attack:?}"
        );
        assert!(hostile.asked.load(Ordering::SeqCst) >= 4, "{attack:?}");
    }
}

#[tokio::test(start_paused = true)]
async fn an_attack_alone_is_refused() {
    for attack in ATTACKS {
        let origin = origin().await;
        let (_, local) = memory();
        let storage = Tiered::new(local)
            .with_tier(Hostile::new(attack, origin.storage.clone()))
            .with_limits(64 * 1024, 64 * 1024)
            .with_timeout(Duration::from_secs(5))
            .build();
        let tip = origin.head.tip.clone().unwrap();
        let segment = storage.log.segment(&t(), &a(), &tip).await;
        let blob = storage.blobs.get(&t(), &origin.blob).await;
        match attack {
            Attack::Withheld => {
                assert!(matches!(segment, Ok(None)));
                assert!(matches!(blob, Ok(None)));
            }
            Attack::Slow | Attack::Failing => {
                assert!(
                    matches!(segment, Err(StorageError::Backend(_))),
                    "{attack:?}"
                );
                assert!(matches!(blob, Err(StorageError::Backend(_))), "{attack:?}");
            }
            _ => {
                assert!(
                    matches!(
                        segment,
                        Err(StorageError::Integrity(IntegrityError::HashMismatch { .. }))
                    ),
                    "{attack:?}"
                );
                assert!(matches!(blob, Err(StorageError::Corrupt(_))), "{attack:?}");
            }
        }
    }
}

#[tokio::test]
async fn bytes_over_the_limit_are_refused_even_when_they_match() {
    let origin = origin().await;
    let (_, local) = memory();
    let storage = Tiered::new(local.clone())
        .with_tier(Hostile::new(Attack::Withheld, origin.storage.clone()))
        .with_tier(Arc::new(Unbounded(origin.storage.clone())))
        .with_limits(16, 16)
        .build();
    let tip = origin.head.tip.clone().unwrap();
    assert!(matches!(
        storage.log.segment(&t(), &a(), &tip).await,
        Err(StorageError::Integrity(IntegrityError::HashMismatch { .. }))
    ));
    assert!(matches!(
        storage.blobs.get(&t(), &origin.blob).await,
        Err(StorageError::Corrupt(_))
    ));
    assert!(!local.blobs.contains(&t(), &origin.blob).await.unwrap());
}

struct Unbounded(Storage);

#[async_trait]
impl ReadTier for Unbounded {
    async fn segment(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        segment: &SegmentRef,
        _: usize,
    ) -> Result<Option<Bytes>, StorageError> {
        self.0.log.segment(tenant, account, segment).await
    }

    async fn blob(
        &self,
        tenant: &TenantId,
        hash: &BlobHash,
        _: usize,
    ) -> Result<Option<Bytes>, StorageError> {
        self.0.blobs.get(tenant, hash).await
    }
}

async fn tamper_local(objects: &dyn Objects, suffix: &str) {
    let prefix = ObjectKey::tenant(&t());
    let keys = objects.list(&prefix, None, 1000).await.unwrap();
    let key = keys
        .iter()
        .find(|k| k.as_str().ends_with(suffix))
        .expect("the local object");
    objects
        .put(key, Bytes::from_static(b"tampered"), Expect::Any)
        .await
        .unwrap();
}

#[tokio::test]
async fn damaged_local_copies_are_replaced_by_a_tier() {
    let origin = origin().await;
    let (objects, local) = memory();
    let mut n = 0;
    for (fence, size) in [(1, 3), (1, 1), (2, 4)] {
        let events = (0..size)
            .map(|_| {
                n += 1;
                sample_event(&a(), n)
            })
            .collect();
        local
            .log
            .append(&t(), &a(), FencingToken(fence), events)
            .await
            .unwrap();
    }
    local
        .blobs
        .put(&t(), Bytes::from_static(BODY))
        .await
        .unwrap();
    assert_eq!(
        local.log.signed_head(&t(), &a()).await.unwrap().head,
        origin.head,
        "the same journal on both sides"
    );
    let tip = origin.head.tip.clone().unwrap();
    tamper_local(&*objects, &tip.name()).await;
    tamper_local(&*objects, &origin.blob.to_hex()).await;
    assert!(walk(&*local.log, &origin.head).await.is_err());
    assert!(local.blobs.get(&t(), &origin.blob).await.is_err());

    let storage = Tiered::new(local)
        .with_tier(Arc::new(StorageTier::new(origin.storage.clone())))
        .build();
    assert_eq!(
        walk(&*storage.log, &origin.head).await.unwrap(),
        (1..=8).collect::<Vec<_>>()
    );
    assert_eq!(
        storage
            .blobs
            .get(&t(), &origin.blob)
            .await
            .unwrap()
            .unwrap(),
        BODY
    );
}

#[tokio::test]
async fn tiers_are_asked_in_order_and_only_until_one_answers() {
    let origin = origin().await;
    let (_, local) = memory();
    let first = Hostile::new(Attack::Withheld, origin.storage.clone());
    let honest = Arc::new(StorageTier::new(origin.storage.clone()));
    let never = Hostile::new(Attack::WrongBytes, origin.storage.clone());
    let storage = Tiered::new(local)
        .with_tier(first.clone())
        .with_tier(honest)
        .with_tier(never.clone())
        .build();
    walk(&*storage.log, &origin.head).await.unwrap();
    storage.blobs.get(&t(), &origin.blob).await.unwrap();
    assert_eq!(first.asked.load(Ordering::SeqCst), 4);
    assert_eq!(never.asked.load(Ordering::SeqCst), 0);
    assert_eq!(
        storage
            .blobs
            .get(&t(), &origin.blob)
            .await
            .unwrap()
            .unwrap(),
        BODY
    );
    assert_eq!(
        first.asked.load(Ordering::SeqCst),
        4,
        "a filled blob is read locally"
    );
}

#[tokio::test(start_paused = true)]
async fn a_slow_tier_costs_at_most_the_timeout() {
    let origin = origin().await;
    let (_, local) = memory();
    let storage = Tiered::new(local)
        .with_tier(Hostile::new(Attack::Slow, origin.storage.clone()))
        .with_tier(Arc::new(StorageTier::new(origin.storage.clone())))
        .with_timeout(Duration::from_millis(250))
        .build();
    let start = tokio::time::Instant::now();
    assert!(
        storage
            .blobs
            .get(&t(), &origin.blob)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(start.elapsed(), Duration::from_millis(250));
}

#[tokio::test(start_paused = true)]
async fn many_concurrent_reads_through_a_slow_tier() {
    let origin = origin().await;
    let (_, local) = memory();
    let storage = Tiered::new(local)
        .with_tier(Hostile::new(Attack::Slow, origin.storage.clone()))
        .with_tier(Arc::new(StorageTier::new(origin.storage.clone())))
        .with_timeout(Duration::from_secs(1))
        .without_fill()
        .build();
    let read = |storage: Storage| {
        let head = origin.head.clone();
        let blob = origin.blob;
        async move {
            let seqs = walk(&*storage.log, &head).await.unwrap();
            let body = storage.blobs.get(&t(), &blob).await.unwrap().unwrap();
            (seqs.len(), body.len())
        }
    };
    let start = tokio::time::Instant::now();
    assert_eq!(read(storage.clone()).await, (8, BODY.len()));
    let one = start.elapsed();
    assert!(one >= Duration::from_secs(1), "the slow tier was asked");

    let start = tokio::time::Instant::now();
    let results = futures_join_all((0..512).map(|_| read(storage.clone()))).await;
    assert!(results.iter().all(|r| *r == (8, BODY.len())));
    assert_eq!(
        start.elapsed(),
        one,
        "reads wait on the timeout concurrently, not one after another"
    );
    assert_eq!(origin.head.seq, Seq(8));
}

async fn futures_join_all<F: Future + Send + 'static>(
    futures: impl Iterator<Item = F>,
) -> Vec<F::Output>
where
    F::Output: Send + 'static,
{
    let handles: Vec<_> = futures.map(tokio::spawn).collect();
    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        out.push(h.await.unwrap());
    }
    out
}
