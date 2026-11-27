use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use skein_core::{AccountId, FencingToken, Seq, TenantId};

use super::{KeyedAttestor, sample_event};
use crate::{
    Chain, Expect, IntegrityError, JournalHead, Log, ObjectKey, ObjectLog, Objects, SegmentRef,
    SegmentSource, SignedHead, StorageError, Version,
};

/// A plain in-memory [`Objects`] for the journal a suite replicates from.
#[derive(Default)]
struct MapObjects(Mutex<BTreeMap<String, (Bytes, u64)>>, Mutex<u64>);

#[async_trait]
impl Objects for MapObjects {
    async fn get(&self, key: &ObjectKey) -> Result<Option<(Bytes, Version)>, StorageError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .get(key.as_str())
            .map(|(b, v)| (b.clone(), Version(v.to_string()))))
    }

    async fn put(
        &self,
        key: &ObjectKey,
        value: Bytes,
        expect: Expect,
    ) -> Result<Version, StorageError> {
        let mut map = self.0.lock().unwrap();
        let current = map.get(key.as_str()).map(|(_, v)| *v);
        let ok = match (&expect, current) {
            (Expect::Any, _) | (Expect::Absent, None) => true,
            (Expect::Version(want), Some(v)) => want.0 == v.to_string(),
            _ => false,
        };
        if !ok {
            return Err(StorageError::Conflict);
        }
        let mut n = self.1.lock().unwrap();
        *n += 1;
        map.insert(key.as_str().to_owned(), (value, *n));
        Ok(Version(n.to_string()))
    }

    async fn delete(&self, key: &ObjectKey, _: Expect) -> Result<(), StorageError> {
        self.0.lock().unwrap().remove(key.as_str());
        Ok(())
    }

    async fn list(
        &self,
        prefix: &ObjectKey,
        start_after: Option<&ObjectKey>,
        limit: usize,
    ) -> Result<Vec<ObjectKey>, StorageError> {
        let below = format!("{}/", prefix.as_str());
        Ok(self
            .0
            .lock()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with(&below))
            .filter(|k| start_after.is_none_or(|a| k.as_str() > a.as_str()))
            .take(limit)
            .map(|k| ObjectKey::parse(k).unwrap())
            .collect())
    }
}

fn origin(attestor: Option<[u8; 32]>) -> ObjectLog {
    let objects: Arc<dyn Objects> = Arc::new(MapObjects::default());
    match attestor {
        Some(k) => ObjectLog::with_attestor(objects, Arc::new(KeyedAttestor(k))),
        None => ObjectLog::new(objects),
    }
}

async fn write(log: &dyn Log, t: &TenantId, a: &AccountId, fence: u64, from: u64, n: u64) {
    log.append(
        t,
        a,
        FencingToken(fence),
        (from..from + n).map(|i| sample_event(a, i)).collect(),
    )
    .await
    .unwrap();
}

/// The segments from `head` back to (not including) the segment `stop`, newest first.
async fn segments_since(
    log: &ObjectLog,
    head: &JournalHead,
    stop: Option<&SegmentRef>,
) -> Vec<(SegmentRef, Bytes)> {
    let mut out = Vec::new();
    let mut chain = Chain::new(log, head);
    while let Some(s) = chain.next().await.unwrap() {
        if Some(&s.segment) == stop {
            break;
        }
        let bytes = log
            .segment(&head.tenant, &head.account, &s.segment)
            .await
            .unwrap()
            .unwrap();
        out.push((s.segment, bytes));
    }
    out
}

async fn stage_all(replica: &dyn Log, t: &TenantId, a: &AccountId, list: &[(SegmentRef, Bytes)]) {
    for (r, b) in list {
        replica.stage(t, a, r, b.clone()).await.unwrap();
    }
}

fn integrity(r: Result<(), StorageError>) -> IntegrityError {
    match r {
        Err(StorageError::Integrity(e)) => e,
        other => panic!("expected an integrity error, got {other:?}"),
    }
}

/// [`Log::stage`] and [`Log::install`] on `replica`, a log whose attestor accepts unattested
/// heads: a replica follows another log's journal byte for byte and refuses gaps, broken links,
/// forks, rollbacks, lower tokens, another account's or tenant's data and staging over committed
/// events.
pub async fn replica(replica: Arc<dyn Log>) {
    let t = TenantId::new("conf-replica").unwrap();
    let a = AccountId::new("a").unwrap();
    let source = origin(None);
    write(&source, &t, &a, 1, 1, 3).await;
    write(&source, &t, &a, 1, 4, 2).await;
    write(&source, &t, &a, 2, 6, 4).await;
    let first = source.signed_head(&t, &a).await.unwrap();

    assert!(matches!(
        replica.install(&t, &a, &first).await,
        Err(StorageError::Integrity(IntegrityError::Missing { .. }))
    ));
    let all = segments_since(&source, &first.head, None).await;
    assert_eq!(all.len(), 3);
    stage_all(&*replica, &t, &a, &all[..1]).await;
    assert!(
        matches!(
            replica.install(&t, &a, &first).await,
            Err(StorageError::Integrity(IntegrityError::Missing { .. }))
        ),
        "a gap in the staged chain"
    );
    assert_eq!(
        replica.head(&t, &a).await.unwrap(),
        Seq(0),
        "staged is invisible"
    );
    assert!(replica.read(&t, &a, Seq(1), 10).await.unwrap().is_empty());

    let other = AccountId::new("b").unwrap();
    let (r0, b0) = &all[2];
    assert!(
        replica.stage(&t, &other, r0, b0.clone()).await.is_err(),
        "another account's segment"
    );
    let mut flipped = b0.to_vec();
    let mid = flipped.len() / 2;
    flipped[mid] ^= 1;
    assert!(
        replica
            .stage(&t, &a, r0, Bytes::from(flipped))
            .await
            .is_err()
    );
    let truncated = b0.slice(..b0.len() - 1);
    assert!(replica.stage(&t, &a, r0, truncated).await.is_err());
    let misnamed = SegmentRef {
        start: Seq(r0.start.0 + 1),
        end: Seq(r0.end.0 + 1),
        ..r0.clone()
    };
    assert!(
        replica.stage(&t, &a, &misnamed, b0.clone()).await.is_err(),
        "a segment at the wrong position"
    );

    stage_all(&*replica, &t, &a, &all).await;
    replica.install(&t, &a, &first).await.unwrap();
    assert_eq!(replica.signed_head(&t, &a).await.unwrap(), first);
    assert_eq!(
        replica.read(&t, &a, Seq(1), 100).await.unwrap(),
        source.read(&t, &a, Seq(1), 100).await.unwrap()
    );
    replica.install(&t, &a, &first).await.unwrap();
    stage_all(&*replica, &t, &a, &all).await;

    let (r_mid, b_mid) = &all[1];
    let mut other_bytes = b_mid.to_vec();
    other_bytes.push(0);
    assert!(
        replica
            .stage(&t, &a, r_mid, Bytes::from(other_bytes))
            .await
            .is_err(),
        "other bytes over a committed segment"
    );

    write(&source, &t, &a, 2, 10, 2).await;
    write(&source, &t, &a, 3, 12, 1).await;
    let second = source.signed_head(&t, &a).await.unwrap();
    let newer = segments_since(&source, &second.head, first.head.tip.as_ref()).await;
    assert_eq!(newer.len(), 2);
    stage_all(&*replica, &t, &a, &newer).await;
    replica.install(&t, &a, &second).await.unwrap();
    assert_eq!(replica.head(&t, &a).await.unwrap(), Seq(12));

    assert!(
        matches!(
            replica.install(&t, &a, &first).await,
            Err(StorageError::Fenced)
        ),
        "an older head under a lower token"
    );
    let rolled = SignedHead {
        head: JournalHead {
            seq: Seq(11),
            tip: newer[1].0.clone().into(),
            ..second.head.clone()
        },
        attestation: None,
    };
    assert!(
        replica.install(&t, &a, &rolled).await.is_err(),
        "a lower seq"
    );
    let lower = SignedHead {
        head: JournalHead {
            fence: FencingToken(2),
            ..second.head.clone()
        },
        attestation: None,
    };
    assert!(replica.install(&t, &a, &lower).await.is_err());
    assert_eq!(replica.signed_head(&t, &a).await.unwrap(), second);
    assert!(
        matches!(
            replica.stage(&t, &a, &newer[0].0, newer[0].1.clone()).await,
            Ok(())
        ),
        "staging committed bytes again changes nothing"
    );

    let forked = origin(None);
    write(&forked, &t, &a, 1, 1, 3).await;
    write(&forked, &t, &a, 1, 4, 2).await;
    write(&forked, &t, &a, 2, 106, 4).await;
    write(&forked, &t, &a, 3, 110, 4).await;
    let fork_head = forked.signed_head(&t, &a).await.unwrap();
    let fork_segments = segments_since(&forked, &fork_head.head, None).await;
    for (r, b) in &fork_segments {
        let _ = replica.stage(&t, &a, r, b.clone()).await;
    }
    assert!(
        replica.install(&t, &a, &fork_head).await.is_err(),
        "a head whose chain does not reach the local tip"
    );
    assert_eq!(replica.signed_head(&t, &a).await.unwrap(), second);

    let malformed = SignedHead {
        head: JournalHead {
            seq: Seq(99),
            ..second.head.clone()
        },
        attestation: None,
    };
    assert!(replica.install(&t, &a, &malformed).await.is_err());
    let elsewhere = SignedHead {
        head: JournalHead {
            account: other.clone(),
            ..second.head.clone()
        },
        attestation: None,
    };
    assert_eq!(
        integrity(replica.install(&t, &a, &elsewhere).await),
        IntegrityError::Scope
    );
    let u = TenantId::new("conf-replica-other").unwrap();
    assert_eq!(
        integrity(replica.install(&u, &a, &second).await),
        IntegrityError::Scope
    );

    let c = AccountId::new("c").unwrap();
    let late = origin(None);
    write(&late, &t, &c, 1, 1, 2).await;
    write(&late, &t, &c, 1, 3, 2).await;
    let late_head = late.signed_head(&t, &c).await.unwrap();
    let late_segments = segments_since(&late, &late_head.head, None).await;
    stage_all(&*replica, &t, &c, &late_segments[..1]).await;
    assert!(
        replica.install(&t, &c, &late_head).await.is_err(),
        "an empty replica cannot start in the middle of a journal"
    );
    stage_all(&*replica, &t, &c, &late_segments).await;
    replica.install(&t, &c, &late_head).await.unwrap();
    assert_eq!(replica.read(&t, &c, Seq(1), 10).await.unwrap().len(), 4);
}

/// [`Log::install`] checks attestations with the replica's attestor: a head attested by the
/// expected key installs, one attested by another key or stripped of its attestation does not.
pub async fn replica_attested(objects: Arc<dyn Objects>) {
    let t = TenantId::new("conf-replica-attested").unwrap();
    let a = AccountId::new("a").unwrap();
    let source = origin(Some([1; 32]));
    write(&source, &t, &a, 1, 1, 2).await;
    let head = source.signed_head(&t, &a).await.unwrap();
    assert!(head.attestation.is_some());
    let segments = segments_since(&source, &head.head, None).await;

    let stranger = ObjectLog::with_attestor(objects.clone(), Arc::new(KeyedAttestor([2; 32])));
    stage_all(&stranger, &t, &a, &segments).await;
    assert!(matches!(
        stranger.install(&t, &a, &head).await,
        Err(StorageError::Integrity(IntegrityError::Attestation(_)))
    ));
    let replica = ObjectLog::with_attestor(objects, Arc::new(KeyedAttestor([1; 32])));
    let stripped = SignedHead {
        attestation: None,
        ..head.clone()
    };
    assert!(replica.install(&t, &a, &stripped).await.is_err());
    replica.install(&t, &a, &head).await.unwrap();
    assert_eq!(replica.signed_head(&t, &a).await.unwrap(), head);
}
