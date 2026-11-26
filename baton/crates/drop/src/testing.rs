//! Conformance suite for [`DropStore`] implementations.

use std::sync::Arc;

use baton_core::Timestamp;
use baton_mailbox::{BoxId, BoxKey, BoxPolicy, MessageId};
use bytes::Bytes;

use crate::store::{Admitted, DropStore, StoreError};

fn policy(writers: usize, max_messages: u32, max_bytes: u64, ttl_ms: u64) -> BoxPolicy {
    BoxPolicy {
        reader: BoxKey::generate().public(),
        writers: (0..writers).map(|_| BoxKey::generate().public()).collect(),
        max_bytes,
        max_messages,
        ttl_ms,
    }
}

const T0: Timestamp = Timestamp(1_800_000_000_000);

fn at(ms: i64) -> Timestamp {
    T0.plus_ms(ms)
}

/// The [`DropStore`] contract, including concurrent appends. Every box it makes has a fresh random
/// id, so a store with data in it can be tested.
pub async fn store(s: Arc<dyn DropStore>) {
    basics(&*s).await;
    quotas(&*s).await;
    expiry(&*s).await;
    writers(&*s).await;
    missing(&*s).await;
    concurrent(&s).await;
}

async fn basics(s: &dyn DropStore) {
    let id = BoxId::random();
    let p = policy(2, 100, 1 << 20, 60_000);
    let w = p.writers[0];
    assert!(s.get(&id, at(0)).await.unwrap().is_none());
    s.create(&id, &p, Admitted::Token, at(0)).await.unwrap();
    assert!(matches!(
        s.create(&id, &p, Admitted::Token, at(1)).await,
        Err(StoreError::Exists)
    ));
    let info = s.get(&id, at(1)).await.unwrap().unwrap();
    assert_eq!(info.policy, p);
    assert_eq!(info.admitted, Admitted::Token);
    let worked = BoxId::random();
    s.create(&worked, &p, Admitted::Work, at(0)).await.unwrap();
    assert_eq!(
        s.get(&worked, at(1)).await.unwrap().unwrap().admitted,
        Admitted::Work,
        "the admission class is kept"
    );
    s.delete(&worked, at(1)).await.unwrap();
    assert_eq!((info.last_id, info.count, info.bytes), (0, 0, 0));

    let a = s
        .append(&id, &w, Bytes::from_static(b"aa"), at(2))
        .await
        .unwrap();
    let b = s
        .append(&id, &p.writers[1], Bytes::from_static(b"bbb"), at(3))
        .await
        .unwrap();
    let c = s.append(&id, &w, Bytes::new(), at(4)).await.unwrap();
    assert_eq!((a, b, c), (MessageId(1), MessageId(2), MessageId(3)));
    let info = s.get(&id, at(5)).await.unwrap().unwrap();
    assert_eq!((info.last_id, info.count, info.bytes), (3, 3, 5));
    assert!(matches!(
        s.append(&id, &p.reader, Bytes::from_static(b"x"), at(5))
            .await,
        Err(StoreError::Denied)
    ));

    let all = s.read(&id, None, 10, at(6)).await.unwrap();
    assert_eq!(all.iter().map(|m| m.id).collect::<Vec<_>>(), vec![a, b, c]);
    assert_eq!(all[0].bytes, Bytes::from_static(b"aa"));
    assert_eq!(all[1].stored_at, at(3));
    let after = s.read(&id, Some(a), 1, at(6)).await.unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].id, b);
    assert!(
        s.read(&id, Some(MessageId(u64::MAX)), 10, at(6))
            .await
            .unwrap()
            .is_empty()
    );

    s.ack(&id, b, at(7)).await.unwrap();
    let left = s.read(&id, None, 10, at(7)).await.unwrap();
    assert_eq!(left.iter().map(|m| m.id).collect::<Vec<_>>(), vec![c]);
    let info = s.get(&id, at(7)).await.unwrap().unwrap();
    assert_eq!((info.last_id, info.count, info.bytes), (3, 1, 0));
    s.ack(&id, MessageId(u64::MAX), at(8)).await.unwrap();
    let d = s
        .append(&id, &w, Bytes::from_static(b"d"), at(9))
        .await
        .unwrap();
    assert_eq!(d, MessageId(4), "ids never repeat");

    s.delete(&id, at(10)).await.unwrap();
    assert!(s.get(&id, at(10)).await.unwrap().is_none());
    s.create(&id, &p, Admitted::Token, at(11)).await.unwrap();
    assert_eq!(
        s.get(&id, at(11)).await.unwrap().unwrap().count,
        0,
        "a deleted box keeps no messages"
    );
}

async fn quotas(s: &dyn DropStore) {
    let id = BoxId::random();
    let p = policy(1, 2, 10, 60_000);
    let w = p.writers[0];
    s.create(&id, &p, Admitted::Token, at(0)).await.unwrap();
    s.append(&id, &w, Bytes::from(vec![0; 4]), at(1))
        .await
        .unwrap();
    assert!(matches!(
        s.append(&id, &w, Bytes::from(vec![0; 7]), at(1)).await,
        Err(StoreError::Quota)
    ));
    let m = s
        .append(&id, &w, Bytes::from(vec![0; 6]), at(1))
        .await
        .unwrap();
    assert!(matches!(
        s.append(&id, &w, Bytes::new(), at(1)).await,
        Err(StoreError::Quota)
    ));
    s.ack(&id, m, at(2)).await.unwrap();
    s.append(&id, &w, Bytes::from(vec![0; 10]), at(3))
        .await
        .unwrap();
}

async fn expiry(s: &dyn DropStore) {
    let id = BoxId::random();
    let p = policy(1, 2, 1 << 20, 1_000);
    let w = p.writers[0];
    s.create(&id, &p, Admitted::Token, at(0)).await.unwrap();
    s.append(&id, &w, Bytes::from_static(b"old"), at(0))
        .await
        .unwrap();
    s.append(&id, &w, Bytes::from_static(b"new"), at(500))
        .await
        .unwrap();
    assert_eq!(s.read(&id, None, 10, at(999)).await.unwrap().len(), 2);
    let left = s.read(&id, None, 10, at(1_000)).await.unwrap();
    assert_eq!(left.len(), 1, "expired at exactly the time-to-live");
    assert_eq!(left[0].bytes, Bytes::from_static(b"new"));
    s.append(&id, &w, Bytes::from_static(b"room"), at(1_001))
        .await
        .expect("expired messages do not count against quotas");

    assert!(s.get(&id, at(1_999)).await.unwrap().is_some());
    assert!(
        s.get(&id, at(2_000)).await.unwrap().is_none(),
        "a box the reader left alone for its time-to-live is gone"
    );
    assert!(matches!(
        s.append(&id, &w, Bytes::new(), at(2_001)).await,
        Err(StoreError::Missing)
    ));
    s.create(&id, &p, Admitted::Token, at(2_002))
        .await
        .expect("an idle box may be replaced");

    let swept_box = BoxId::random();
    s.create(&swept_box, &p, Admitted::Token, at(10_000))
        .await
        .unwrap();
    s.append(&swept_box, &w, Bytes::from_static(b"x"), at(10_000))
        .await
        .unwrap();
    let kept = BoxId::random();
    s.create(&kept, &p, Admitted::Token, at(10_000))
        .await
        .unwrap();
    s.append(&kept, &w, Bytes::from_static(b"x"), at(10_000))
        .await
        .unwrap();
    s.read(&kept, None, 1, at(10_600)).await.unwrap();
    assert!(s.sweep(at(11_000)).await.unwrap() >= 2);
    assert!(
        s.get(&swept_box, at(10_000)).await.unwrap().is_none(),
        "sweep removed it"
    );
    let k = s
        .get(&kept, at(11_000))
        .await
        .unwrap()
        .expect("a used box stays");
    assert_eq!((k.count, k.bytes), (0, 0), "sweep removed expired messages");
}

async fn writers(s: &dyn DropStore) {
    let id = BoxId::random();
    let p = policy(2, 10, 1 << 20, 60_000);
    let (w1, w2) = (p.writers[0], p.writers[1]);
    s.create(&id, &p, Admitted::Token, at(0)).await.unwrap();
    s.set_writers(&id, &[w1], 5, at(1)).await.unwrap();
    assert!(matches!(
        s.append(&id, &w2, Bytes::new(), at(2)).await,
        Err(StoreError::Denied)
    ));
    s.append(&id, &w1, Bytes::new(), at(2)).await.unwrap();
    for stale in [5, 4, 0] {
        assert!(matches!(
            s.set_writers(&id, &[w1, w2], stale, at(3)).await,
            Err(StoreError::Conflict)
        ));
    }
    let info = s.get(&id, at(3)).await.unwrap().unwrap();
    assert_eq!(info.policy.writers, vec![w1]);
    assert_eq!(info.writers_version, 5);
    s.set_writers(&id, &[w2], 6, at(4)).await.unwrap();
    s.append(&id, &w2, Bytes::new(), at(5)).await.unwrap();
}

async fn missing(s: &dyn DropStore) {
    let id = BoxId::random();
    let k = BoxKey::generate().public();
    assert!(matches!(
        s.append(&id, &k, Bytes::new(), at(0)).await,
        Err(StoreError::Missing)
    ));
    assert!(matches!(
        s.read(&id, None, 1, at(0)).await,
        Err(StoreError::Missing)
    ));
    assert!(matches!(
        s.ack(&id, MessageId(1), at(0)).await,
        Err(StoreError::Missing)
    ));
    assert!(matches!(
        s.set_writers(&id, &[], 1, at(0)).await,
        Err(StoreError::Missing)
    ));
    assert!(matches!(
        s.delete(&id, at(0)).await,
        Err(StoreError::Missing)
    ));
}

async fn concurrent(s: &Arc<dyn DropStore>) {
    let id = BoxId::random();
    let p = policy(8, 1000, 1 << 20, 60_000);
    s.create(&id, &p, Admitted::Token, at(0)).await.unwrap();
    let mut tasks = Vec::new();
    for w in p.writers.clone() {
        let s = s.clone();
        tasks.push(tokio::spawn(async move {
            let mut ids = Vec::new();
            for _ in 0..25 {
                ids.push(
                    s.append(&id, &w, Bytes::from_static(b"c"), at(1))
                        .await
                        .unwrap(),
                );
            }
            ids
        }));
    }
    let mut ids = Vec::new();
    for t in tasks {
        ids.extend(t.await.unwrap());
    }
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 200, "concurrent appends get distinct ids");
    assert_eq!(ids.last(), Some(&MessageId(200)));
    assert_eq!(s.get(&id, at(1)).await.unwrap().unwrap().count, 200);
}
