use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use skein_core::{AccountId, BlobHash, FencingToken, Seq, TenantId};

use super::{account, sample_event, tenant};
use crate::{
    Chain, CountingObjects, ReadTier, SegmentRef, SegmentSource, Storage, StorageError,
    verify_segment,
};

struct Source(Arc<dyn ReadTier>);

#[async_trait]
impl SegmentSource for Source {
    async fn segment(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        segment: &SegmentRef,
    ) -> Result<Option<Bytes>, StorageError> {
        self.0.segment(tenant, account, segment, usize::MAX).await
    }
}

fn within(result: &Result<Option<Bytes>, StorageError>, max: usize) -> bool {
    !matches!(result, Ok(Some(b)) if b.len() > max)
}

/// The [`ReadTier`] contract. `tier` must serve what `origin` holds, and `origin` must be built
/// over `objects`, which the suite uses to check that the tier never writes.
pub async fn read_tier(tier: Arc<dyn ReadTier>, origin: Storage, objects: Arc<CountingObjects>) {
    let t = tenant("conf-tier");
    let other_tenant = tenant("conf-tier-other");
    let a = account("a");
    let body = Bytes::from_static(b"From: ada@example.com\r\n\r\nfrom a tier\r\n");
    let hash = origin.blobs.put(&t, body.clone()).await.unwrap();
    origin
        .log
        .append(
            &t,
            &a,
            FencingToken(1),
            (1..=3).map(|n| sample_event(&a, n)).collect(),
        )
        .await
        .unwrap();
    origin
        .log
        .append(
            &t,
            &a,
            FencingToken(2),
            (4..=5).map(|n| sample_event(&a, n)).collect(),
        )
        .await
        .unwrap();
    let head = origin.log.signed_head(&t, &a).await.unwrap().head;
    let tip = head.tip.clone().unwrap();
    let before = objects.counts();

    assert_eq!(
        tier.blob(&t, &hash, 1 << 20).await.unwrap(),
        Some(body.clone())
    );
    assert_eq!(
        tier.blob(&t, &BlobHash::of(b"never stored"), 1 << 20)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        tier.blob(&other_tenant, &hash, 1 << 20).await.unwrap(),
        None,
        "tenants are isolated"
    );
    let small = body.len() - 1;
    assert!(
        within(&tier.blob(&t, &hash, small).await, small),
        "a blob over max_len is never handed out"
    );

    let source = Source(tier.clone());
    let mut chain = Chain::new(&source, &head);
    let mut walked = Vec::new();
    while let Some(segment) = chain.next().await.unwrap() {
        walked.splice(0..0, segment.events);
    }
    assert_eq!(walked, origin.log.read(&t, &a, Seq(1), 100).await.unwrap());

    let bytes = tier
        .segment(&t, &a, &tip, 1 << 20)
        .await
        .unwrap()
        .expect("the tip");
    verify_segment(&t, &a, &tip, &bytes).unwrap();
    assert!(
        within(&tier.segment(&t, &a, &tip, 8).await, 8),
        "a segment over max_len is never handed out"
    );
    let beyond = SegmentRef {
        start: Seq(6),
        end: Seq(6),
        ..tip.clone()
    };
    assert_eq!(tier.segment(&t, &a, &beyond, 1 << 20).await.unwrap(), None);
    assert_eq!(
        tier.segment(&t, &account("b"), &tip, 1 << 20)
            .await
            .unwrap(),
        None,
        "another account's name holds nothing"
    );
    assert_eq!(
        tier.segment(&other_tenant, &a, &tip, 1 << 20)
            .await
            .unwrap(),
        None
    );

    let after = objects.counts();
    assert_eq!(
        (after.puts, after.deletes),
        (before.puts, before.deletes),
        "a read tier never writes"
    );
}
