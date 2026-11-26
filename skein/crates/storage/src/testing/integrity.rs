use std::sync::Arc;

use bytes::Bytes;
use skein_core::{AccountId, FencingToken, Seq, TenantId};

use super::{KeyedAttestor, account, key, sample_event, tenant};
use crate::log::{SEGMENT_FORMAT, SegmentHeader, decode_segment, encode_segment};
use crate::{
    Chain, Expect, IntegrityError, JournalHead, Log, ObjectKey, ObjectLog, Objects, SegmentRef,
    SignedHead, StorageError, locate, verify_extends, verify_head, verify_segment,
};

fn seg_key(t: &TenantId, a: &AccountId, r: &SegmentRef) -> ObjectKey {
    key(&format!("tenants/{t}/log/{a}/{}", r.name()))
}

fn head_key(t: &TenantId, a: &AccountId) -> ObjectKey {
    key(&format!("tenants/{t}/heads/{a}"))
}

fn integrity(r: Result<impl std::fmt::Debug, StorageError>) -> IntegrityError {
    match r {
        Err(StorageError::Integrity(e)) => e,
        other => panic!("expected an integrity error, got {other:?}"),
    }
}

async fn fill(log: &ObjectLog, t: &TenantId, a: &AccountId, fence: u64) -> Vec<SegmentRef> {
    let mut tips = Vec::new();
    for n in [1u64, 3, 5] {
        log.append(
            t,
            a,
            FencingToken(fence),
            vec![sample_event(a, n), sample_event(a, n + 1)],
        )
        .await
        .unwrap();
        tips.push(log.signed_head(t, a).await.unwrap().head.tip.unwrap());
    }
    tips
}

async fn walk(log: &ObjectLog, head: &JournalHead) -> Result<u64, StorageError> {
    let mut chain = Chain::new(log, head);
    let mut n = 0;
    while let Some(segment) = chain.next().await? {
        n += segment.events.len() as u64;
    }
    Ok(n)
}

async fn get(objects: &dyn Objects, k: &ObjectKey) -> Bytes {
    objects.get(k).await.unwrap().unwrap().0
}

async fn put(objects: &dyn Objects, k: &ObjectKey, v: Bytes) {
    objects.put(k, v, Expect::Any).await.unwrap();
}

fn retouched(bytes: &[u8]) -> Bytes {
    let mut decoded = decode_segment(bytes).unwrap();
    decoded.events[0].key = "forged".into();
    encode_segment(decoded.header.as_ref(), &decoded.events).unwrap()
}

/// Attacks on [`ObjectLog`]'s chain through the raw object store: tampered, reordered, removed
/// and mixed-up segments, rolled-back and forked heads, forged attestations, and a downgrade to
/// unchained segments. Also checks that data written before chaining still reads.
pub async fn object_log_integrity(objects: Arc<dyn Objects>) {
    tampered(objects.clone()).await;
    reordered_and_removed(objects.clone()).await;
    rolled_back(objects.clone()).await;
    forged_attestation(objects.clone()).await;
    mixed_scopes(objects.clone()).await;
    legacy(objects).await;
}

async fn tampered(objects: Arc<dyn Objects>) {
    let log = ObjectLog::new(objects.clone());
    let t = tenant("conf-integrity-tamper");
    let a = account("a");
    let tips = fill(&log, &t, &a, 1).await;
    let head = log.signed_head(&t, &a).await.unwrap().head;
    assert_eq!(walk(&log, &head).await.unwrap(), 6);

    let middle = seg_key(&t, &a, &tips[1]);
    let original = get(&*objects, &middle).await;
    put(&*objects, &middle, retouched(&original)).await;
    assert_eq!(
        integrity(log.read(&t, &a, Seq(1), 10).await),
        IntegrityError::Link { seq: 5 },
        "the next segment no longer links to a retouched one"
    );
    assert!(matches!(
        integrity(walk(&log, &head).await),
        IntegrityError::HashMismatch { .. }
    ));
    assert!(matches!(
        integrity(locate(&log, &head, Seq(3)).await),
        IntegrityError::HashMismatch { .. }
    ));
    let mut flipped = original.to_vec();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x40;
    put(&*objects, &middle, Bytes::from(flipped)).await;
    assert!(log.read(&t, &a, Seq(1), 10).await.is_err());
    put(&*objects, &middle, original).await;
    assert_eq!(log.read(&t, &a, Seq(1), 10).await.unwrap().len(), 6);

    let tip = seg_key(&t, &a, &tips[2]);
    let original = get(&*objects, &tip).await;
    put(&*objects, &tip, retouched(&original)).await;
    assert!(
        matches!(
            integrity(log.read(&t, &a, Seq(5), 10).await),
            IntegrityError::HashMismatch { .. }
        ),
        "a retouched tip no longer matches the head, even read on its own"
    );
    assert!(matches!(
        integrity(
            ObjectLog::new(objects.clone())
                .read(&t, &a, Seq(6), 1)
                .await
        ),
        IntegrityError::HashMismatch { .. }
    ));
    put(&*objects, &tip, original).await;
    assert_eq!(log.read(&t, &a, Seq(5), 10).await.unwrap().len(), 2);
}

async fn reordered_and_removed(objects: Arc<dyn Objects>) {
    let log = ObjectLog::new(objects.clone());
    let t = tenant("conf-integrity-order");
    let a = account("a");
    let tips = fill(&log, &t, &a, 1).await;
    let head = log.signed_head(&t, &a).await.unwrap().head;
    let keys: Vec<_> = tips.iter().map(|r| seg_key(&t, &a, r)).collect();
    let first = get(&*objects, &keys[0]).await;
    let second = get(&*objects, &keys[1]).await;

    put(&*objects, &keys[0], second.clone()).await;
    put(&*objects, &keys[1], first.clone()).await;
    assert!(matches!(
        integrity(log.read(&t, &a, Seq(1), 10).await),
        IntegrityError::Mismatch { .. }
    ));
    assert!(matches!(
        integrity(walk(&log, &head).await),
        IntegrityError::HashMismatch { .. }
    ));
    put(&*objects, &keys[0], first).await;
    put(&*objects, &keys[1], second.clone()).await;

    objects.delete(&keys[1], Expect::Any).await.unwrap();
    assert!(
        log.read(&t, &a, Seq(1), 10).await.is_err(),
        "a removed segment never reads as a gapless journal"
    );
    assert!(matches!(
        integrity(walk(&log, &head).await),
        IntegrityError::Missing { .. }
    ));
    let renamed = SegmentRef {
        fence: FencingToken(0),
        ..tips[1].clone()
    };
    put(&*objects, &seg_key(&t, &a, &renamed), second.clone()).await;
    assert!(matches!(
        integrity(log.read(&t, &a, Seq(3), 10).await),
        IntegrityError::Mismatch { .. }
    ));
    objects
        .delete(&seg_key(&t, &a, &renamed), Expect::Any)
        .await
        .unwrap();
    put(&*objects, &keys[1], second).await;
    assert_eq!(walk(&log, &head).await.unwrap(), 6);
}

async fn rolled_back(objects: Arc<dyn Objects>) {
    let log = ObjectLog::new(objects.clone());
    let t = tenant("conf-integrity-rollback");
    let a = account("a");
    let hk = head_key(&t, &a);
    log.append(&t, &a, FencingToken(2), vec![sample_event(&a, 1)])
        .await
        .unwrap();
    let old_bytes = get(&*objects, &hk).await;
    let old = log.signed_head(&t, &a).await.unwrap().head;
    log.append(
        &t,
        &a,
        FencingToken(2),
        vec![sample_event(&a, 2), sample_event(&a, 3)],
    )
    .await
    .unwrap();
    let trusted = log.signed_head(&t, &a).await.unwrap().head;
    let trusted_bytes = get(&*objects, &hk).await;
    let committed = seg_key(&t, &a, trusted.tip.as_ref().unwrap());

    put(&*objects, &hk, old_bytes.clone()).await;
    assert_eq!(
        integrity(log.head(&t, &a).await),
        IntegrityError::Rollback {
            trusted: 3,
            seen: 1
        }
    );
    assert!(matches!(
        integrity(
            log.append(&t, &a, FencingToken(2), vec![sample_event(&a, 9)])
                .await
        ),
        IntegrityError::Rollback { .. }
    ));
    assert!(
        objects.get(&committed).await.unwrap().is_some(),
        "a rolled-back head never makes the writer remove committed events"
    );

    let fresh = ObjectLog::new(objects.clone());
    let seen = fresh.signed_head(&t, &a).await.unwrap().head;
    assert_eq!(seen, old);
    assert!(matches!(
        trusted.check_successor(&seen),
        Err(IntegrityError::Rollback { .. })
    ));
    assert!(matches!(
        integrity(verify_extends(&fresh, &trusted, &seen).await),
        IntegrityError::Rollback { .. }
    ));

    let mut lowered: serde_json::Value = serde_json::from_slice(&trusted_bytes).unwrap();
    lowered["fence"] = 1.into();
    put(&*objects, &hk, Bytes::from(lowered.to_string())).await;
    assert!(
        log.head(&t, &a).await.is_err(),
        "a head with a lower token is a rollback or malformed"
    );

    let mut forked = trusted.clone();
    forked.tip.as_mut().unwrap().hash.0[0] ^= 1;
    assert_eq!(
        trusted.check_successor(&forked),
        Err(IntegrityError::Fork { seq: 3 })
    );
    let mut stripped: serde_json::Value = serde_json::from_slice(&trusted_bytes).unwrap();
    stripped.as_object_mut().unwrap().remove("tip");
    put(&*objects, &hk, Bytes::from(stripped.to_string())).await;
    assert_eq!(
        integrity(log.head(&t, &a).await),
        IntegrityError::Fork { seq: 3 },
        "a head that drops its tip is refused"
    );
    assert_eq!(
        integrity(
            ObjectLog::new(objects.clone())
                .read(&t, &a, Seq(2), 10)
                .await
        ),
        IntegrityError::Fork { seq: 3 }
    );

    put(&*objects, &hk, trusted_bytes).await;
    assert_eq!(log.head(&t, &a).await.unwrap(), Seq(3));
    log.append(&t, &a, FencingToken(3), vec![sample_event(&a, 4)])
        .await
        .unwrap();
    let newer = log.signed_head(&t, &a).await.unwrap().head;
    verify_extends(&log, &trusted, &newer).await.unwrap();
    verify_extends(&log, &old, &newer).await.unwrap();

    put(&*objects, &hk, old_bytes).await;
    let forker = ObjectLog::new(objects.clone());
    forker
        .append(
            &t,
            &a,
            FencingToken(4),
            vec![sample_event(&a, 20), sample_event(&a, 30)],
        )
        .await
        .unwrap();
    forker
        .append(&t, &a, FencingToken(4), vec![sample_event(&a, 40)])
        .await
        .unwrap();
    let fork = forker.signed_head(&t, &a).await.unwrap().head;
    assert_eq!(fork.seq, Seq(4));
    assert_eq!(
        integrity(verify_extends(&forker, &trusted, &fork).await),
        IntegrityError::Fork { seq: 3 },
        "a head whose chain does not pass through the trusted tip is a fork"
    );
    assert_eq!(
        integrity(verify_extends(&forker, &newer, &fork).await),
        IntegrityError::Fork { seq: 4 }
    );
    verify_extends(&forker, &old, &fork).await.unwrap();
}

async fn forged_attestation(objects: Arc<dyn Objects>) {
    let signer = Arc::new(KeyedAttestor([1; 32]));
    let log = ObjectLog::with_attestor(objects.clone(), signer.clone());
    let t = tenant("conf-integrity-attest");
    let (a, b) = (account("a"), account("b"));
    for acc in [&a, &b] {
        log.append(&t, acc, FencingToken(1), vec![sample_event(acc, 1)])
            .await
            .unwrap();
    }
    let signed = log.signed_head(&t, &a).await.unwrap();
    assert_eq!(signed.attestation.as_ref().map(|x| x.len()), Some(32));
    verify_head(&*signer, &signed).await.unwrap();
    log.claim(&t, &a, FencingToken(2)).await.unwrap();
    let claimed = log.signed_head(&t, &a).await.unwrap();
    assert_ne!(
        claimed.attestation, signed.attestation,
        "a claim re-attests"
    );
    verify_head(&*signer, &claimed).await.unwrap();

    let hk = head_key(&t, &a);
    let good = get(&*objects, &hk).await;
    let value: serde_json::Value = serde_json::from_slice(&good).unwrap();
    let mut forgeries = Vec::new();
    let mut flipped = value.clone();
    flipped["attestation"] = format!("{}=", "A".repeat(43)).into();
    forgeries.push(flipped);
    let mut stripped = value.clone();
    stripped.as_object_mut().unwrap().remove("attestation");
    forgeries.push(stripped);
    let mut raised = value.clone();
    raised["fence"] = 9.into();
    forgeries.push(raised);
    let mut borrowed = value.clone();
    let other: serde_json::Value =
        serde_json::from_slice(&get(&*objects, &head_key(&t, &b)).await).unwrap();
    borrowed["attestation"] = other["attestation"].clone();
    forgeries.push(borrowed);
    for forged in forgeries {
        put(&*objects, &hk, Bytes::from(forged.to_string())).await;
        assert!(
            matches!(
                integrity(log.head(&t, &a).await),
                IntegrityError::Attestation(_)
            ),
            "{forged}"
        );
        assert!(matches!(
            integrity(
                ObjectLog::with_attestor(objects.clone(), signer.clone())
                    .read(&t, &a, Seq(1), 1)
                    .await
            ),
            IntegrityError::Attestation(_)
        ));
    }
    put(&*objects, &hk, good).await;
    assert_eq!(log.head(&t, &a).await.unwrap(), Seq(1));

    let stranger = ObjectLog::with_attestor(objects.clone(), Arc::new(KeyedAttestor([2; 32])));
    assert!(matches!(
        integrity(stranger.head(&t, &a).await),
        IntegrityError::Attestation(_)
    ));
    assert!(matches!(
        integrity(
            stranger
                .append(&t, &a, FencingToken(5), vec![sample_event(&a, 2)])
                .await
        ),
        IntegrityError::Attestation(_)
    ));
    let mut tampered = claimed.clone();
    tampered.head.seq = Seq(2);
    assert!(verify_head(&*signer, &tampered).await.is_err());
    let unsigned = SignedHead {
        head: claimed.head.clone(),
        attestation: None,
    };
    assert!(matches!(
        integrity(verify_head(&*signer, &unsigned).await),
        IntegrityError::Attestation(_)
    ));
}

async fn mixed_scopes(objects: Arc<dyn Objects>) {
    let log = ObjectLog::new(objects.clone());
    let t = tenant("conf-integrity-mix");
    let u = tenant("conf-integrity-mix-other");
    let (a, b) = (account("a"), account("b"));
    let tips = fill(&log, &t, &a, 1).await;
    let head = log.signed_head(&t, &a).await.unwrap().head;
    let bytes = get(&*objects, &seg_key(&t, &a, &tips[2])).await;

    for (tt, acc) in [(&t, &b), (&u, &a)] {
        for r in &tips {
            let seg = get(&*objects, &seg_key(&t, &a, r)).await;
            put(&*objects, &seg_key(tt, acc, r), seg).await;
        }
        put(
            &*objects,
            &head_key(tt, acc),
            get(&*objects, &head_key(&t, &a)).await,
        )
        .await;
        let fresh = ObjectLog::new(objects.clone());
        assert!(
            matches!(
                integrity(fresh.read(tt, acc, Seq(1), 10).await),
                IntegrityError::Mismatch { .. }
            ),
            "segments copied to another account or tenant do not read there"
        );
        assert!(matches!(
            integrity(verify_segment(tt, acc, &tips[2], &bytes)),
            IntegrityError::Mismatch { .. }
        ));
        let mut moved = head.clone();
        moved.tenant = tt.clone();
        moved.account = acc.clone();
        assert!(matches!(
            integrity(walk(&fresh, &moved).await),
            IntegrityError::Mismatch { .. }
        ));
        assert_eq!(
            head.check_successor(&moved),
            Err(IntegrityError::Scope),
            "heads of different accounts never compare"
        );
    }

    let mut header = decode_segment(&bytes).unwrap().header.unwrap();
    header.account = b.clone();
    let mut events = decode_segment(&bytes).unwrap().events;
    for e in &mut events {
        e.account = b.clone();
    }
    let relabelled = encode_segment(Some(&header), &events).unwrap();
    put(&*objects, &seg_key(&t, &a, &tips[2]), relabelled).await;
    assert!(log.read(&t, &a, Seq(5), 10).await.is_err());
    put(&*objects, &seg_key(&t, &a, &tips[2]), bytes).await;

    let signer = Arc::new(KeyedAttestor([3; 32]));
    let signed_log = ObjectLog::with_attestor(objects.clone(), signer.clone());
    let s = tenant("conf-integrity-mix-signed");
    signed_log
        .append(&s, &a, FencingToken(1), vec![sample_event(&a, 1)])
        .await
        .unwrap();
    let theirs = get(&*objects, &head_key(&s, &a)).await;
    put(&*objects, &head_key(&s, &b), theirs).await;
    assert!(matches!(
        integrity(signed_log.head(&s, &b).await),
        IntegrityError::Attestation(_)
    ));
}

async fn legacy(objects: Arc<dyn Objects>) {
    let t = tenant("conf-integrity-legacy");
    let a = account("a");
    let mut events: Vec<_> = (1..=3).map(|n| sample_event(&a, n)).collect();
    for (i, e) in events.iter_mut().enumerate() {
        e.seq = Seq(i as u64 + 1);
    }
    put(
        &*objects,
        &key(&format!(
            "tenants/{t}/log/{a}/{:020}-{:020}-{:020}",
            1, 2, 1
        )),
        encode_segment(None, &events[..2]).unwrap(),
    )
    .await;
    put(
        &*objects,
        &key(&format!(
            "tenants/{t}/log/{a}/{:020}-{:020}-{:020}",
            3, 3, 1
        )),
        encode_segment(None, &events[2..]).unwrap(),
    )
    .await;
    put(
        &*objects,
        &head_key(&t, &a),
        Bytes::from_static(br#"{"seq":3,"fence":1}"#),
    )
    .await;

    let log = ObjectLog::new(objects.clone());
    assert_eq!(log.read(&t, &a, Seq(1), 10).await.unwrap(), events);
    let before = log.signed_head(&t, &a).await.unwrap().head;
    assert_eq!((before.seq, before.tip.clone()), (Seq(3), None));
    log.append(
        &t,
        &a,
        FencingToken(1),
        vec![sample_event(&a, 4), sample_event(&a, 5)],
    )
    .await
    .unwrap();
    log.append(&t, &a, FencingToken(1), vec![sample_event(&a, 6)])
        .await
        .unwrap();
    let all = log.read(&t, &a, Seq(1), 10).await.unwrap();
    assert_eq!(
        all.iter().map(|e| e.seq.0).collect::<Vec<_>>(),
        [1, 2, 3, 4, 5, 6]
    );
    let head = log.signed_head(&t, &a).await.unwrap().head;
    let root = locate(&log, &head, Seq(4)).await.unwrap();
    assert_eq!(
        (root.segment.start, root.prev),
        (Seq(4), None),
        "the chain starts at the first segment written after the upgrade"
    );
    assert_eq!(walk(&log, &head).await.unwrap(), 3);
    assert_eq!(
        integrity(locate(&log, &head, Seq(2)).await),
        IntegrityError::Unchained { seq: 2 }
    );
    verify_extends(&log, &before, &head).await.unwrap();

    let header = SegmentHeader {
        skein_segment: SEGMENT_FORMAT,
        tenant: t.clone(),
        account: a.clone(),
        start: Seq(7),
        end: Seq(7),
        fence: FencingToken(1),
        prev: None,
    };
    let mut seventh = sample_event(&a, 7);
    seventh.seq = Seq(7);
    let unlinked = encode_segment(Some(&header), std::slice::from_ref(&seventh)).unwrap();
    let mut forged = head.clone();
    forged.seq = Seq(7);
    let r7 = SegmentRef {
        start: Seq(7),
        end: Seq(7),
        fence: FencingToken(1),
        hash: crate::SegmentHash::of(&unlinked),
    };
    forged.tip = Some(r7.clone());
    put(&*objects, &seg_key(&t, &a, &r7), unlinked).await;
    put(
        &*objects,
        &head_key(&t, &a),
        Bytes::from(format!(
            r#"{{"seq":7,"fence":1,"tip":{}}}"#,
            serde_json::to_string(&r7).unwrap()
        )),
    )
    .await;
    assert_eq!(
        integrity(
            ObjectLog::new(objects.clone())
                .read(&t, &a, Seq(6), 10)
                .await
        ),
        IntegrityError::Link { seq: 7 },
        "a new chain root after a chained segment is refused"
    );
    assert!(verify_extends(&log, &head, &forged).await.is_err());

    put(
        &*objects,
        &key(&format!(
            "tenants/{t}/log/{a}/{:020}-{:020}-{:020}",
            7, 7, 1
        )),
        encode_segment(None, std::slice::from_ref(&seventh)).unwrap(),
    )
    .await;
    put(
        &*objects,
        &head_key(&t, &a),
        Bytes::from_static(br#"{"seq":7,"fence":1}"#),
    )
    .await;
    let fresh = ObjectLog::new(objects.clone());
    assert_eq!(
        integrity(fresh.read(&t, &a, Seq(6), 10).await),
        IntegrityError::Link { seq: 7 },
        "an unchained segment after a chained one is a downgrade"
    );
    assert!(matches!(
        integrity(log.head(&t, &a).await),
        IntegrityError::Fork { .. }
    ));
}
