//! Conformance suites for every storage contract.
//!
//! An implementation proves it keeps a contract by running the matching suite in its own tests:
//!
//! ```ignore
//! #[tokio::test]
//! async fn conformance() {
//!     skein_storage::testing::objects(Arc::new(MyObjects::new())).await;
//! }
//! ```
//!
//! Every suite uses its own tenant ids, so suites can share one store.

mod integrity;
mod slow;
mod tier;

use std::sync::Arc;

use bytes::Bytes;
use skein_core::{
    AccountId, BlobHash, Command, CommandBody, CommandId, Event, EventBody, FencingToken, Flags,
    ItemRef, SCHEMA_VERSION, Seq, TenantId, Timestamp,
};

pub use slow::SlowObjects;
pub use tier::read_tier;

use crate::{
    BlobStore, Chain, CommandQueue, ControlState, ControlStore, Expect, HeadAttestor,
    IntegrityError, JournalHead, Log, MAX_SEGMENT_EVENTS, NoAttestor, ObjectBlobs, ObjectKey,
    ObjectLog, Objects, SegmentRef, Snapshot, Storage, StorageError, Submitted, verify_extends,
    verify_segment,
};

fn tenant(name: &str) -> TenantId {
    TenantId::new(name).unwrap()
}

fn account(name: &str) -> AccountId {
    AccountId::new(name).unwrap()
}

fn key(text: &str) -> ObjectKey {
    ObjectKey::parse(text).unwrap()
}

/// An event for tests; its number is assigned on append.
pub fn sample_event(account_id: &AccountId, n: u64) -> Event {
    Event {
        v: SCHEMA_VERSION,
        seq: Seq(0),
        at: Timestamp(n as i64),
        account: account_id.clone(),
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
    }
}

/// The [`Objects`] contract.
pub async fn objects(store: Arc<dyn Objects>) {
    let a = key("conf-objects/a");
    assert!(store.get(&a).await.unwrap().is_none());

    let v1 = store
        .put(&a, Bytes::from_static(b"one"), Expect::Absent)
        .await
        .unwrap();
    let (value, version) = store.get(&a).await.unwrap().unwrap();
    assert_eq!(&value[..], b"one");
    assert_eq!(version, v1);

    assert!(matches!(
        store
            .put(&a, Bytes::from_static(b"x"), Expect::Absent)
            .await,
        Err(StorageError::Conflict)
    ));
    let v2 = store
        .put(&a, Bytes::from_static(b"two"), Expect::Version(v1.clone()))
        .await
        .unwrap();
    assert_ne!(v1, v2);
    assert!(matches!(
        store
            .put(
                &a,
                Bytes::from_static(b"stale"),
                Expect::Version(v1.clone())
            )
            .await,
        Err(StorageError::Conflict)
    ));
    assert!(matches!(
        store
            .put(
                &key("conf-objects/missing"),
                Bytes::from_static(b"x"),
                Expect::Version(v2.clone())
            )
            .await,
        Err(StorageError::Conflict)
    ));
    let v3 = store
        .put(&a, Bytes::from_static(b"three"), Expect::Any)
        .await
        .unwrap();
    assert_eq!(&store.get(&a).await.unwrap().unwrap().0[..], b"three");

    let binary: Vec<u8> = (0..=255u8).collect();
    let b = key("conf-objects/binary");
    store
        .put(&b, Bytes::from(binary.clone()), Expect::Any)
        .await
        .unwrap();
    assert_eq!(&store.get(&b).await.unwrap().unwrap().0[..], &binary[..]);

    assert!(matches!(
        store.delete(&a, Expect::Version(v2)).await,
        Err(StorageError::Conflict)
    ));
    store.delete(&a, Expect::Version(v3)).await.unwrap();
    assert!(store.get(&a).await.unwrap().is_none());
    store.delete(&a, Expect::Any).await.unwrap();

    for name in ["l/b", "l/a", "l/c/1", "l/c/2", "lx/z", "l/d"] {
        store
            .put(
                &key(&format!("conf-objects/{name}")),
                Bytes::new(),
                Expect::Any,
            )
            .await
            .unwrap();
    }
    let all = store.list(&key("conf-objects/l"), None, 100).await.unwrap();
    let names: Vec<_> = all.iter().map(|k| k.as_str().to_owned()).collect();
    assert_eq!(
        names,
        [
            "conf-objects/l/a",
            "conf-objects/l/b",
            "conf-objects/l/c/1",
            "conf-objects/l/c/2",
            "conf-objects/l/d"
        ],
        "list is ascending, recursive, and stays inside the prefix"
    );
    let page = store
        .list(&key("conf-objects/l"), Some(&key("conf-objects/l/b")), 2)
        .await
        .unwrap();
    let names: Vec<_> = page.iter().map(|k| k.as_str().to_owned()).collect();
    assert_eq!(names, ["conf-objects/l/c/1", "conf-objects/l/c/2"]);

    let upper = key("conf-objects/case/01ARZ3NDEKTSV4RRFFQ69G5FAV");
    let lower = key("conf-objects/case/01arz3ndektsv4rrffq69g5fav");
    store
        .put(&upper, Bytes::from_static(b"U"), Expect::Absent)
        .await
        .unwrap();
    store
        .put(&lower, Bytes::from_static(b"l"), Expect::Absent)
        .await
        .unwrap();
    assert_eq!(
        &store.get(&upper).await.unwrap().unwrap().0[..],
        b"U",
        "keys are case-sensitive"
    );
    assert_eq!(&store.get(&lower).await.unwrap().unwrap().0[..], b"l");

    let parent = key("conf-objects/nest");
    let child = key("conf-objects/nest/child");
    store
        .put(&child, Bytes::from_static(b"c"), Expect::Any)
        .await
        .unwrap();
    let under = store.list(&parent, None, 10).await.unwrap();
    assert_eq!(
        under,
        vec![child.clone()],
        "list returns keys under the prefix"
    );

    let same = key("conf-objects/same");
    let v = store
        .put(&same, Bytes::from_static(b"x"), Expect::Any)
        .await
        .unwrap();
    let v = store
        .put(&same, Bytes::from_static(b"x"), Expect::Version(v))
        .await
        .unwrap();
    store
        .put(&same, Bytes::from_static(b"y"), Expect::Version(v))
        .await
        .unwrap();
    store
        .delete(&key("conf-objects/never"), Expect::Absent)
        .await
        .unwrap();
    assert!(matches!(
        store.delete(&same, Expect::Absent).await,
        Err(StorageError::Conflict)
    ));

    let race = key("conf-objects/race");
    let mut tasks = Vec::new();
    for i in 0..16u8 {
        let store = store.clone();
        let race = race.clone();
        tasks.push(tokio::spawn(async move {
            store
                .put(&race, Bytes::from(vec![i]), Expect::Absent)
                .await
                .is_ok()
        }));
    }
    let mut winners = 0;
    for t in tasks {
        if t.await.unwrap() {
            winners += 1;
        }
    }
    assert_eq!(winners, 1, "exactly one of concurrent creates wins");

    let (_, base) = store.get(&race).await.unwrap().unwrap();
    let mut tasks = Vec::new();
    for i in 0..16u8 {
        let store = store.clone();
        let race = race.clone();
        let base = base.clone();
        tasks.push(tokio::spawn(async move {
            store
                .put(&race, Bytes::from(vec![100 + i]), Expect::Version(base))
                .await
                .is_ok()
        }));
    }
    let mut winners = 0;
    for t in tasks {
        if t.await.unwrap() {
            winners += 1;
        }
    }
    assert_eq!(winners, 1, "exactly one of concurrent swaps wins");
}

/// The [`ControlStore`] contract.
pub async fn control(store: Arc<dyn ControlStore>) {
    let t1 = tenant("conf-control-1");
    let t2 = tenant("conf-control-2");
    let v = store
        .put(&t1, "accounts/a", Bytes::from_static(b"a"), Expect::Absent)
        .await
        .unwrap();
    assert!(
        store.get(&t2, "accounts/a").await.unwrap().is_none(),
        "tenants are isolated"
    );
    store
        .put(
            &t1,
            "accounts/a",
            Bytes::from_static(b"b"),
            Expect::Version(v),
        )
        .await
        .unwrap();
    store
        .put(&t1, "accounts/b", Bytes::from_static(b"c"), Expect::Absent)
        .await
        .unwrap();
    store
        .put(
            &t1,
            "cursors/a/INBOX",
            Bytes::from_static(b"c"),
            Expect::Absent,
        )
        .await
        .unwrap();
    assert_eq!(
        store.list(&t1, "accounts", None, 10).await.unwrap(),
        vec!["accounts/a".to_owned(), "accounts/b".to_owned()]
    );
    assert_eq!(
        store
            .list(&t1, "accounts", Some("accounts/a"), 10)
            .await
            .unwrap(),
        vec!["accounts/b".to_owned()]
    );
    for bad in ["../x", "a/../../b", "", "a//b", ".hidden"] {
        assert!(
            matches!(store.get(&t1, bad).await, Err(StorageError::InvalidKey(_))),
            "{bad:?} must be refused"
        );
    }
    store.delete(&t1, "accounts/a", Expect::Any).await.unwrap();
    assert!(store.get(&t1, "accounts/a").await.unwrap().is_none());
}

/// Baton's `StateStore` contract over this [`ControlStore`] through [`ControlState`], plus what
/// the adapter adds: records never collide with Skein's own control records, foreign or truncated
/// objects are never returned as values, identical values still get new versions, no stored path
/// is a prefix of another (so stores backed by a file system can hold them), and purging a tenant
/// removes its state. Uses groups and tenants starting with `conf-state` and `conf-cstate`.
pub async fn control_state(control: Arc<dyn ControlStore>) {
    use baton_core::GroupId;
    use baton_state::{RecordName, StateError, StateStore};

    let state: Arc<dyn StateStore> = Arc::new(ControlState::new(control.clone()));
    baton_state::testing::state(state.clone()).await;

    let suite = tenant("conf-state");
    let mut stored = std::collections::HashSet::new();
    let mut after: Option<String> = None;
    loop {
        let page = control
            .list(&suite, crate::STATE_AREA, after.as_deref(), 100)
            .await
            .unwrap();
        let Some(last) = page.last().cloned() else {
            break;
        };
        stored.extend(page);
        after = Some(last);
    }
    assert!(stored.len() > 3);
    for path in &stored {
        let mut cut = path.as_str();
        while let Some((parent, _)) = cut.rsplit_once('/') {
            assert!(
                !stored.contains(parent),
                "no stored path is a prefix of another: {parent} and {path}"
            );
            cut = parent;
        }
    }

    let g = GroupId::new("conf-cstate").unwrap();
    let t = tenant("conf-cstate");
    let name = |s: &str| RecordName::new(s).unwrap();
    let state_expect = |e: Expect| match e {
        Expect::Any => baton_state::Expect::Any,
        Expect::Absent => baton_state::Expect::Absent,
        Expect::Version(v) => baton_state::Expect::Version(baton_state::Version(v.0)),
    };

    state
        .put(
            &g,
            &name("accounts/a"),
            Bytes::from_static(b"state"),
            state_expect(Expect::Absent),
        )
        .await
        .unwrap();
    assert!(
        control.get(&t, "accounts/a").await.unwrap().is_none(),
        "state records never land on Skein's control paths"
    );
    control
        .put(
            &t,
            "accounts/b",
            Bytes::from_static(b"skein"),
            Expect::Absent,
        )
        .await
        .unwrap();
    assert!(state.get(&g, &name("accounts/b")).await.unwrap().is_none());

    let same = name("same/value");
    let v1 = state
        .put(
            &g,
            &same,
            Bytes::from_static(b"x"),
            state_expect(Expect::Absent),
        )
        .await
        .unwrap();
    let v2 = state
        .put(
            &g,
            &same,
            Bytes::from_static(b"y"),
            baton_state::Expect::Version(v1.clone()),
        )
        .await
        .unwrap();
    let v3 = state
        .put(
            &g,
            &same,
            Bytes::from_static(b"x"),
            baton_state::Expect::Version(v2),
        )
        .await
        .unwrap();
    assert_ne!(v1, v3, "writing the same bytes again yields a new version");
    assert!(
        matches!(
            state
                .put(
                    &g,
                    &same,
                    Bytes::from_static(b"z"),
                    baton_state::Expect::Version(v1)
                )
                .await,
            Err(StateError::Conflict)
        ),
        "a version from before an A-B-A sequence is stale"
    );

    for (i, forged) in [
        &b""[..],
        b"\x01short",
        b"\x02 unknown format version byte",
        b"{\"node\":\"mallory\",\"fence\":999}",
    ]
    .into_iter()
    .enumerate()
    {
        let path = crate::state::path(&name(&format!("forged/{i}")));
        control
            .put(&t, &path, Bytes::copy_from_slice(forged), Expect::Any)
            .await
            .unwrap();
        assert!(
            matches!(
                state.get(&g, &name(&format!("forged/{i}"))).await,
                Err(StateError::Backend(_))
            ),
            "a foreign object is never read as a record: {forged:?}"
        );
    }

    for n in ["paged/a", "paged/c"] {
        state
            .put(&g, &name(n), Bytes::new(), baton_state::Expect::Any)
            .await
            .unwrap();
    }
    for foreign in ["paged-/B", "paged-/b-x", "paged-/b."] {
        control
            .put(
                &t,
                &format!("{}/{foreign}", crate::STATE_AREA),
                Bytes::new(),
                Expect::Any,
            )
            .await
            .unwrap();
    }
    let mut seen = Vec::new();
    let mut after: Option<RecordName> = None;
    loop {
        let page = state
            .list(&g, &name("paged"), after.as_ref(), 1)
            .await
            .unwrap();
        let Some(last) = page.last().cloned() else {
            break;
        };
        seen.extend(page.iter().map(|n| n.as_str().to_owned()));
        after = Some(last);
    }
    assert_eq!(
        seen,
        ["paged/a", "paged/c"],
        "names that are not record names are skipped without ending the listing"
    );
    assert!(
        state
            .list(&g, &name("paged"), None, 0)
            .await
            .unwrap()
            .is_empty()
    );

    control.purge(&t).await.unwrap();
    assert!(
        state.get(&g, &name("paged/a")).await.unwrap().is_none(),
        "purging the tenant removes its state"
    );
}

/// The [`BlobStore`] contract.
pub async fn blobs(store: Arc<dyn BlobStore>) {
    let t1 = tenant("conf-blobs-1");
    let t2 = tenant("conf-blobs-2");
    let body = Bytes::from_static(b"From: ada@example.com\r\n\r\nhello\r\n");
    let h = store.put(&t1, body.clone()).await.unwrap();
    assert_eq!(h, BlobHash::of(&body));
    assert_eq!(store.put(&t1, body.clone()).await.unwrap(), h, "idempotent");
    assert_eq!(store.get(&t1, &h).await.unwrap().unwrap(), body);
    assert!(store.contains(&t1, &h).await.unwrap());
    assert!(
        !store.contains(&t2, &h).await.unwrap(),
        "tenants are isolated"
    );
    assert!(store.get(&t2, &h).await.unwrap().is_none());
    assert!(
        store
            .get(&t1, &BlobHash::of(b"never stored"))
            .await
            .unwrap()
            .is_none()
    );
}

/// [`ObjectBlobs`] refuses content that does not match its hash.
pub async fn object_blobs_detect_tampering(objects: Arc<dyn Objects>) {
    let blobs = ObjectBlobs::new(objects.clone());
    let t = tenant("conf-tamper");
    let h = blobs
        .put(&t, Bytes::from_static(b"original"))
        .await
        .unwrap();
    let k = key(&format!("tenants/conf-tamper/blobs/{h}"));
    objects
        .put(&k, Bytes::from_static(b"tampered"), Expect::Any)
        .await
        .unwrap();
    assert!(matches!(
        blobs.get(&t, &h).await,
        Err(StorageError::Corrupt(_))
    ));
}

/// The [`CommandQueue`] contract.
pub async fn commands(store: Arc<dyn CommandQueue>) {
    let t = tenant("conf-commands");
    let a = account("a");
    let make = |mailbox: &str| Command {
        id: CommandId::generate(),
        account: a.clone(),
        created_at: Timestamp(1),
        trace: None,
        body: CommandBody::SetFlags {
            mailbox: mailbox.into(),
            items: vec![ItemRef {
                id: "1:1".into(),
                uid: Some(1),
            }],
            add: Flags::new(["\\Seen"]),
            remove: Flags::default(),
        },
    };
    let first = make("INBOX");
    std::thread::sleep(std::time::Duration::from_millis(2));
    let second = make("Archive");
    assert_eq!(store.submit(&t, &second).await.unwrap(), Submitted::New);
    assert_eq!(store.submit(&t, &first).await.unwrap(), Submitted::New);
    assert_eq!(
        store.submit(&t, &first).await.unwrap(),
        Submitted::Duplicate
    );
    let mut changed = first.clone();
    changed.body = CommandBody::Unknown;
    assert!(matches!(
        store.submit(&t, &changed).await,
        Err(StorageError::Conflict)
    ));

    let page = store.pending(&t, &a, 1).await.unwrap();
    assert_eq!(page, vec![first.clone()]);
    let next = store
        .pending_after(&t, &a, Some(&first.id), 10)
        .await
        .unwrap();
    assert_eq!(
        next,
        vec![second.clone()],
        "paging continues after the given id"
    );
    assert_eq!(store.get(&t, &a, &first.id).await.unwrap().unwrap(), first);
    assert!(
        store
            .get(&t, &account("b"), &first.id)
            .await
            .unwrap()
            .is_none()
    );
    let pending = store.pending(&t, &a, 10).await.unwrap();
    assert_eq!(pending, vec![first.clone(), second.clone()], "oldest first");
    store.complete(&t, &a, &first.id).await.unwrap();
    store.complete(&t, &a, &first.id).await.unwrap();
    assert_eq!(store.pending(&t, &a, 10).await.unwrap(), vec![second]);
    assert!(
        store
            .pending(&t, &account("b"), 10)
            .await
            .unwrap()
            .is_empty()
    );
}

/// The [`Log`] contract.
pub async fn log(log: Arc<dyn Log>) {
    let t = tenant("conf-log");
    let a = account("a");
    assert_eq!(log.head(&t, &a).await.unwrap(), Seq(0));
    assert!(log.read(&t, &a, Seq(1), 10).await.unwrap().is_empty());

    let committed = log
        .append(
            &t,
            &a,
            FencingToken(1),
            (1..=3).map(|n| sample_event(&a, n)).collect(),
        )
        .await
        .unwrap();
    assert_eq!(
        committed.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![Seq(1), Seq(2), Seq(3)]
    );
    log.append(&t, &a, FencingToken(1), vec![sample_event(&a, 4)])
        .await
        .unwrap();
    assert_eq!(log.head(&t, &a).await.unwrap(), Seq(4));
    let read = log.read(&t, &a, Seq(2), 10).await.unwrap();
    assert_eq!(
        read.iter().map(|e| e.key.as_str()).collect::<Vec<_>>(),
        ["k2", "k3", "k4"]
    );
    assert_eq!(log.read(&t, &a, Seq(1), 2).await.unwrap().len(), 2);
    assert!(log.read(&t, &a, Seq(5), 10).await.unwrap().is_empty());

    log.claim(&t, &a, FencingToken(5)).await.unwrap();
    assert!(matches!(
        log.append(&t, &a, FencingToken(1), vec![sample_event(&a, 99)])
            .await,
        Err(StorageError::Fenced)
    ));
    assert!(matches!(
        log.claim(&t, &a, FencingToken(2)).await,
        Err(StorageError::Fenced)
    ));
    log.append(&t, &a, FencingToken(5), vec![sample_event(&a, 5)])
        .await
        .unwrap();
    assert_eq!(log.head(&t, &a).await.unwrap(), Seq(5));
    assert_eq!(
        log.read(&t, &a, Seq(1), 100)
            .await
            .unwrap()
            .iter()
            .map(|e| e.seq.0)
            .collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5]
    );
    chain_guarantees(&log, &t, &a).await;

    let b = account("b");
    let mut n = 0;
    for chunk in [1u64, 7, 250, 1, 900] {
        let events = (0..chunk).map(|_| {
            n += 1;
            sample_event(&b, n)
        });
        log.append(&t, &b, FencingToken(1), events.collect())
            .await
            .unwrap();
    }
    let all = log.read(&t, &b, Seq(1), 10_000).await.unwrap();
    assert_eq!(all.len() as u64, n);
    assert!(all.iter().enumerate().all(|(i, e)| e.seq.0 == i as u64 + 1));
    let middle = log.read(&t, &b, Seq(200), 30).await.unwrap();
    assert_eq!(middle.first().unwrap().seq, Seq(200));
    assert_eq!(middle.len(), 30);

    let too_many = (0..=MAX_SEGMENT_EVENTS)
        .map(|i| sample_event(&b, i))
        .collect();
    assert!(log.append(&t, &b, FencingToken(1), too_many).await.is_err());

    let c = account("c");
    let low = {
        let log = log.clone();
        let (t, c) = (t.clone(), c.clone());
        tokio::spawn(async move {
            let mut ok = 0u64;
            for i in 0..20 {
                let mut e = sample_event(&c, i);
                e.key = format!("low{i}");
                match log.append(&t, &c, FencingToken(1), vec![e]).await {
                    Ok(_) => ok += 1,
                    Err(StorageError::Fenced) => break,
                    Err(e) => panic!("{e}"),
                }
            }
            ok
        })
    };
    let high = {
        let log = log.clone();
        let (t, c) = (t.clone(), c.clone());
        tokio::spawn(async move {
            for i in 0..20 {
                let mut e = sample_event(&c, i);
                e.key = format!("high{i}");
                log.append(&t, &c, FencingToken(2), vec![e]).await.unwrap();
            }
        })
    };
    let low_ok = low.await.unwrap();
    high.await.unwrap();
    let events = log.read(&t, &c, Seq(1), 1000).await.unwrap();
    assert_eq!(events.len() as u64, low_ok + 20);
    assert!(
        events
            .iter()
            .enumerate()
            .all(|(i, e)| e.seq.0 == i as u64 + 1)
    );
    let first_high = events
        .iter()
        .position(|e| e.key.starts_with("high"))
        .unwrap();
    assert!(
        events[first_high..]
            .iter()
            .all(|e| e.key.starts_with("high")),
        "once the higher token wrote, the lower one never did again"
    );

    let signed = log.signed_head(&t, &b).await.unwrap();
    for at in [1u64, 2, 8, 9, 200, 258, n] {
        let found = crate::locate(&*log, &signed.head, Seq(at)).await.unwrap();
        assert!(found.segment.start.0 <= at && at <= found.segment.end.0);
        assert_eq!(
            found.events[(at - found.segment.start.0) as usize].seq,
            Seq(at)
        );
    }
    let signed = log.signed_head(&t, &c).await.unwrap();
    let mut walked = 0;
    let mut chain = Chain::new(&*log, &signed.head);
    while let Some(segment) = chain.next().await.unwrap() {
        walked += segment.events.len();
    }
    assert_eq!(
        walked,
        events.len(),
        "the chain covers every committed event after a race"
    );

    let heads = log.heads(&t).await.unwrap();
    let mut names: Vec<_> = heads.iter().map(|(a, _)| a.as_str().to_owned()).collect();
    names.sort();
    assert_eq!(names, ["a", "b", "c"]);
}

async fn chain_guarantees(log: &Arc<dyn Log>, t: &TenantId, a: &AccountId) {
    let empty = log.signed_head(t, &account("never")).await.unwrap();
    assert_eq!(empty.head, JournalHead::empty(t.clone(), account("never")));

    let signed = log.signed_head(t, a).await.unwrap();
    assert_eq!(signed.head.seq, log.head(t, a).await.unwrap());
    assert_eq!(signed.head.fence, FencingToken(5));
    let tip = signed.head.tip.clone().expect("an append leaves a tip");
    assert_eq!(
        (tip.start, tip.end, tip.fence),
        (Seq(5), Seq(5), FencingToken(5))
    );
    signed.head.check().unwrap();

    let mut chain = Chain::new(&**log, &signed.head);
    let mut walked = Vec::new();
    let mut first = None;
    while let Some(segment) = chain.next().await.unwrap() {
        first = Some(segment.segment.clone());
        walked.splice(0..0, segment.events);
    }
    assert_eq!(
        first.unwrap().start,
        Seq(1),
        "the chain reaches the first event"
    );
    assert_eq!(walked, log.read(t, a, Seq(1), 100).await.unwrap());

    let bytes = log.segment(t, a, &tip).await.unwrap().unwrap();
    let verified = verify_segment(t, a, &tip, &bytes).unwrap();
    assert_eq!(verified.events.len(), 1);
    assert!(
        log.segment(
            t,
            a,
            &SegmentRef {
                fence: FencingToken(4),
                ..tip.clone()
            }
        )
        .await
        .unwrap()
        .is_none()
    );

    log.claim(t, a, FencingToken(6)).await.unwrap();
    let claimed = log.signed_head(t, a).await.unwrap().head;
    assert_eq!(claimed.tip.as_ref(), Some(&tip), "a claim keeps the tip");
    assert_eq!(claimed.fence, FencingToken(6));
    signed.head.check_successor(&claimed).unwrap();
    verify_extends(&**log, &signed.head, &claimed)
        .await
        .unwrap();

    log.append(
        t,
        a,
        FencingToken(6),
        vec![sample_event(a, 6), sample_event(a, 7)],
    )
    .await
    .unwrap();
    let newer = log.signed_head(t, a).await.unwrap().head;
    let newer_tip = newer.tip.clone().unwrap();
    assert_eq!((newer_tip.start, newer_tip.end), (Seq(6), Seq(7)));
    verify_extends(&**log, &signed.head, &newer).await.unwrap();
    verify_extends(&**log, &claimed, &newer).await.unwrap();
    assert!(matches!(
        verify_extends(&**log, &newer, &signed.head).await,
        Err(StorageError::Integrity(IntegrityError::Rollback { .. }))
    ));
    assert!(matches!(
        crate::locate(&**log, &newer, Seq(8)).await,
        Err(StorageError::Integrity(IntegrityError::Unchained {
            seq: 8
        }))
    ));
}

/// The [`HeadAttestor`] contract: an attestation verifies for its head, and when the attestor
/// attests at all, for no other head, no other bytes and not when missing.
pub async fn head_attestor(attestor: Arc<dyn HeadAttestor>) {
    let head = JournalHead {
        tenant: tenant("conf-attest"),
        account: account("a"),
        seq: Seq(9),
        fence: FencingToken(4),
        tip: Some(SegmentRef {
            start: Seq(7),
            end: Seq(9),
            fence: FencingToken(3),
            hash: crate::SegmentHash::of(b"segment"),
        }),
    };
    let attestation = attestor.attest(&head).await.unwrap();
    attestor
        .verify(&head, attestation.as_deref())
        .await
        .unwrap();
    attestor
        .verify(&head, attestation.as_deref())
        .await
        .unwrap();
    let Some(attestation) = attestation else {
        return;
    };
    let refused = |r: Result<(), StorageError>| {
        matches!(
            r,
            Err(StorageError::Integrity(IntegrityError::Attestation(_)))
        )
    };
    let mut others = Vec::new();
    for change in 0..7 {
        let mut other = head.clone();
        let tip = other.tip.as_mut().unwrap();
        match change {
            0 => other.tenant = tenant("conf-attest-other"),
            1 => other.account = account("b"),
            2 => other.seq = Seq(10),
            3 => other.fence = FencingToken(5),
            4 => tip.hash.0[31] ^= 1,
            5 => tip.start = Seq(8),
            _ => other.tip = None,
        }
        others.push(other);
    }
    for other in &others {
        assert!(
            refused(attestor.verify(other, Some(&attestation)).await),
            "an attestation vouches for one head only: {other:?}"
        );
    }
    let mut flipped = attestation.to_vec();
    flipped[0] ^= 1;
    assert!(refused(attestor.verify(&head, Some(&flipped)).await));
    assert!(refused(attestor.verify(&head, Some(&[])).await));
    assert!(refused(attestor.verify(&head, None).await));
    let mut longer = attestation.to_vec();
    longer.push(0);
    assert!(refused(attestor.verify(&head, Some(&longer)).await));
}

/// A [`HeadAttestor`] for tests: a BLAKE3 keyed hash of [`JournalHead::digest`] under a 32-byte
/// key. Anyone holding the key can attest, so it only stands in for a real signer.
pub struct KeyedAttestor(pub [u8; 32]);

#[async_trait::async_trait]
impl HeadAttestor for KeyedAttestor {
    async fn attest(&self, head: &JournalHead) -> Result<Option<Bytes>, StorageError> {
        Ok(Some(Bytes::copy_from_slice(
            blake3::keyed_hash(&self.0, &head.digest()).as_bytes(),
        )))
    }

    async fn verify(
        &self,
        head: &JournalHead,
        attestation: Option<&[u8]>,
    ) -> Result<(), StorageError> {
        let expected = blake3::keyed_hash(&self.0, &head.digest());
        match attestation.and_then(|a| <[u8; 32]>::try_from(a).ok()) {
            Some(given) if blake3::Hash::from_bytes(given) == expected => Ok(()),
            _ => Err(IntegrityError::Attestation("not attested by this key".into()).into()),
        }
    }
}

/// Snapshots and compaction of the [`Log`] contract.
pub async fn snapshots(log: Arc<dyn Log>) {
    let t = tenant("conf-snapshots");
    let a = account("a");
    assert!(log.latest_snapshot(&t, &a).await.unwrap().is_none());
    for n in 1..=10 {
        log.append(&t, &a, FencingToken(1), vec![sample_event(&a, n)])
            .await
            .unwrap();
    }
    let events = log.read(&t, &a, Seq(1), 100).await.unwrap();
    let mut snap = Snapshot::empty(a.clone());
    for e in &events[..6] {
        snap.apply(e);
    }
    assert_eq!(snap.seq, Seq(6));
    log.put_snapshot(&t, &a, &snap).await.unwrap();
    log.put_snapshot(&t, &a, &snap).await.unwrap();
    assert_eq!(log.latest_snapshot(&t, &a).await.unwrap().unwrap(), snap);

    let mut beyond = snap.clone();
    beyond.seq = Seq(99);
    assert!(
        log.put_snapshot(&t, &a, &beyond).await.is_err(),
        "no snapshot beyond the head"
    );

    assert!(
        matches!(
            log.compact(&t, &a, Seq(8)).await,
            Err(StorageError::Conflict)
        ),
        "compaction never goes past the latest snapshot"
    );
    log.compact(&t, &a, Seq(7)).await.unwrap();
    match log.read(&t, &a, Seq(1), 100).await {
        Err(StorageError::Compacted { first }) => assert!(first <= 7),
        other => panic!("reading compacted events must say so: {other:?}"),
    }
    let rest = log.read(&t, &a, Seq(7), 100).await.unwrap();
    assert_eq!(rest.first().unwrap().seq, Seq(7));
    assert_eq!(rest.len(), 4);
    log.append(&t, &a, FencingToken(1), vec![sample_event(&a, 11)])
        .await
        .unwrap();
    assert_eq!(
        log.head(&t, &a).await.unwrap(),
        Seq(11),
        "appending continues after compaction"
    );

    for upto in [8usize, 9, 10] {
        let mut s = Snapshot::empty(a.clone());
        for e in &events[..upto] {
            s.apply(e);
        }
        log.put_snapshot(&t, &a, &s).await.unwrap();
    }
    assert_eq!(
        log.latest_snapshot(&t, &a).await.unwrap().unwrap().seq,
        Seq(10)
    );
    log.compact(&t, &a, Seq(11)).await.unwrap();
    assert!(
        matches!(
            log.read(&t, &a, Seq(5), 10).await,
            Err(StorageError::Compacted { .. })
        ),
        "reading a fully compacted range says so instead of returning nothing"
    );
    assert_eq!(log.read(&t, &a, Seq(11), 10).await.unwrap().len(), 1);
}

/// [`ObjectLog`] ignores segments that were written but never committed, including ones left by a
/// writer that lost its account.
pub async fn object_log_orphans(objects: Arc<dyn Objects>) {
    let log = ObjectLog::new(objects.clone());
    let t = tenant("conf-orphans");
    let a = account("a");
    log.append(&t, &a, FencingToken(3), vec![sample_event(&a, 1)])
        .await
        .unwrap();
    let ghost = vec![sample_event(&a, 666)];
    let mut encoder = zstd::Encoder::new(Vec::new(), 1).unwrap();
    for e in &ghost {
        let mut e = e.clone();
        e.seq = Seq(2);
        serde_json::to_writer(&mut encoder, &e).unwrap();
        std::io::Write::write_all(&mut encoder, b"\n").unwrap();
    }
    let bytes = Bytes::from(encoder.finish().unwrap());
    for fence in [2u64, 3] {
        let k = key(&format!(
            "tenants/conf-orphans/log/a/{:020}-{:020}-{:020}",
            2, 2, fence
        ));
        objects.put(&k, bytes.clone(), Expect::Any).await.unwrap();
    }
    assert_eq!(log.head(&t, &a).await.unwrap(), Seq(1));
    assert_eq!(
        log.read(&t, &a, Seq(1), 10).await.unwrap().len(),
        1,
        "uncommitted segments are invisible"
    );
    log.append(
        &t,
        &a,
        FencingToken(3),
        vec![sample_event(&a, 2), sample_event(&a, 3)],
    )
    .await
    .unwrap();
    let keys: Vec<_> = log
        .read(&t, &a, Seq(1), 10)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.key)
        .collect();
    assert_eq!(
        keys,
        ["k1", "k2", "k3"],
        "the committed segment wins over orphans at the same start"
    );
}

/// [`Storage::purge_tenant`] removes one tenant's data and nothing else, and keeps its keyring
/// record.
pub async fn purge(storage: Storage) {
    let gone = tenant("conf-purge-gone");
    let kept = tenant("conf-purge-kept");
    for t in [&gone, &kept] {
        let a = account("a");
        storage
            .log
            .append(t, &a, FencingToken(1), vec![sample_event(&a, 1)])
            .await
            .unwrap();
        storage
            .blobs
            .put(t, Bytes::from_static(b"blob"))
            .await
            .unwrap();
        storage
            .control
            .put(t, "accounts/a", Bytes::from_static(b"{}"), Expect::Any)
            .await
            .unwrap();
        storage
            .control
            .put(
                t,
                "keys/data",
                Bytes::from_static(b"tombstone"),
                Expect::Any,
            )
            .await
            .unwrap();
        storage
            .commands
            .submit(
                t,
                &Command {
                    id: CommandId::generate(),
                    account: a.clone(),
                    created_at: Timestamp(1),
                    trace: None,
                    body: CommandBody::Unknown,
                },
            )
            .await
            .unwrap();
    }
    let removed = storage.purge_tenant(&gone).await.unwrap();
    assert!(removed >= 5, "removed {removed}");
    let a = account("a");
    assert_eq!(storage.log.head(&gone, &a).await.unwrap(), Seq(0));
    assert!(storage.log.heads(&gone).await.unwrap().is_empty());
    assert!(
        !storage
            .blobs
            .contains(&gone, &BlobHash::of(b"blob"))
            .await
            .unwrap()
    );
    assert!(
        storage
            .control
            .get(&gone, "accounts/a")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        storage
            .commands
            .pending(&gone, &a, 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        storage
            .control
            .get(&gone, "keys/data")
            .await
            .unwrap()
            .is_some(),
        "the keyring record survives"
    );
    assert_eq!(
        storage.log.head(&kept, &a).await.unwrap(),
        Seq(1),
        "other tenants are untouched"
    );
    assert!(
        storage
            .blobs
            .contains(&kept, &BlobHash::of(b"blob"))
            .await
            .unwrap()
    );
    assert_eq!(
        storage.commands.pending(&kept, &a, 10).await.unwrap().len(),
        1
    );
}

/// Every suite against one object store, through [`Storage::over`].
pub async fn all_over_objects(objects: Arc<dyn Objects>) {
    self::objects(objects.clone()).await;
    let storage = Storage::over(objects.clone());
    control(storage.control.clone()).await;
    control_state(storage.control.clone()).await;
    blobs(storage.blobs.clone()).await;
    object_blobs_detect_tampering(objects.clone()).await;
    commands(storage.commands.clone()).await;
    log(storage.log.clone()).await;
    snapshots(storage.log.clone()).await;
    purge(storage.clone()).await;
    object_log_orphans(objects.clone()).await;
    head_attestor(Arc::new(NoAttestor)).await;
    head_attestor(Arc::new(KeyedAttestor([7; 32]))).await;
    integrity::object_log_integrity(objects).await;
}
