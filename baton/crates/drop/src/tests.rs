use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use baton_core::Timestamp;
use baton_mailbox::{
    Admission, BoxId, BoxKey, BoxPolicy, Mailbox, MailboxError, testing::small_policy,
};
use bytes::Bytes;
use proptest::prelude::*;
use zeroize::Zeroizing;

use crate::admission::{AdmissionConfig, WorkParams};
use crate::wire::{self, Body, CONTEXT, Head, Op, Reply, WireAdmission, WireMessage};
use crate::{
    Clock, DropConfig, DropError, DropMailbox, DropService, DropStore, Exchange, MemoryDropStore,
};

const REALM: &str = "drop.example.com";
const TOKEN: &[u8] = b"operator-token-for-tests";
const T0: i64 = 1_800_000_000_000;

fn manual() -> (Arc<AtomicI64>, Clock) {
    let a = Arc::new(AtomicI64::new(T0));
    let b = a.clone();
    (a, Arc::new(move || Timestamp(b.load(Ordering::SeqCst))))
}

fn work() -> WorkParams {
    WorkParams::generate(4, 64, 1).unwrap()
}

struct Env {
    svc: Arc<DropService>,
    store: Arc<MemoryDropStore>,
    now: Arc<AtomicI64>,
    clock: Clock,
    work: WorkParams,
}

fn env_with(edit: impl FnOnce(&mut DropConfig)) -> Env {
    let (now, clock) = manual();
    let work = work();
    let admission = AdmissionConfig::closed()
        .with_token(TOKEN)
        .unwrap()
        .with_work(work.clone())
        .unwrap();
    let mut config = DropConfig::new(REALM, admission);
    edit(&mut config);
    let store = Arc::new(MemoryDropStore::new());
    let svc = Arc::new(DropService::new(store.clone(), config, clock.clone()).unwrap());
    Env {
        svc,
        store,
        now,
        clock,
        work,
    }
}

fn env() -> Env {
    env_with(|_| {})
}

impl Env {
    fn at(&self) -> Timestamp {
        Timestamp(self.now.load(Ordering::SeqCst))
    }

    fn req(&self, key: &BoxKey, id: &BoxId, body: Body) -> Vec<u8> {
        wire::seal(REALM, key, id, &body, self.at(), wire::nonce())
    }

    async fn run(&self, key: &BoxKey, id: &BoxId, body: Body) -> Result<Reply, DropError> {
        self.svc.execute(&self.req(key, id, body)).await
    }

    async fn new_box(&self) -> (BoxId, BoxKey, BoxKey) {
        let (reader, writer) = (BoxKey::generate(), BoxKey::generate());
        let id = BoxId::of_reader(&reader.public());
        let mut policy = small_policy(reader.public(), vec![writer.public()]);
        policy.ttl_ms = 3_600_000;
        self.run(
            &reader,
            &id,
            Body::Create {
                policy,
                admission: WireAdmission::Token(TOKEN.to_vec()),
            },
        )
        .await
        .unwrap();
        (id, reader, writer)
    }

    async fn messages(&self, id: &BoxId, reader: &BoxKey) -> Vec<WireMessage> {
        match self
            .run(
                reader,
                id,
                Body::Take {
                    after: None,
                    limit: 1000,
                    wait_ms: 0,
                },
            )
            .await
            .unwrap()
        {
            Reply::Messages(m) => m,
            r => panic!("unexpected {r:?}"),
        }
    }

    fn head(&self, key: &BoxKey, id: &BoxId, op: Op, body: &[u8]) -> Head {
        Head {
            op,
            box_id: *id,
            at: self.at(),
            nonce: wire::nonce(),
            key: key.public(),
            body_hash: *blake3::hash(body).as_bytes(),
        }
    }
}

fn put(bytes: &'static [u8]) -> Body {
    Body::Put {
        bytes: Bytes::from_static(bytes),
    }
}

fn enc(b: &Body) -> Bytes {
    Bytes::from(postcard::to_stdvec(b).unwrap())
}

#[tokio::test]
async fn memory_store_conformance() {
    crate::testing::store(Arc::new(MemoryDropStore::new())).await;
}

#[tokio::test]
async fn unsigned_forged_and_wrong_context_requests_are_refused() {
    let e = env();
    let (id, _reader, writer) = e.new_box().await;
    let body = enc(&put(b"x"));
    let head = e.head(&writer, &id, Op::Put, &body);

    let unsigned = wire::seal_parts(REALM, CONTEXT, None, &head, body.clone());
    assert_eq!(e.svc.execute(&unsigned).await, Err(DropError::BadSignature));

    let stranger = BoxKey::generate();
    let forged = wire::seal_parts(REALM, CONTEXT, Some(&stranger), &head, body.clone());
    assert_eq!(
        e.svc.execute(&forged).await,
        Err(DropError::BadSignature),
        "a writer's name signed by another key"
    );

    let other_realm = wire::seal_parts(
        "drop.example.org",
        CONTEXT,
        Some(&writer),
        &head,
        body.clone(),
    );
    assert_eq!(
        e.svc.execute(&other_realm).await,
        Err(DropError::BadSignature)
    );
    let other_context = wire::seal_parts(
        REALM,
        "baton/mesh/frame/1",
        Some(&writer),
        &head,
        body.clone(),
    );
    assert_eq!(
        e.svc.execute(&other_context).await,
        Err(DropError::BadSignature)
    );

    let genuine = wire::seal_parts(REALM, CONTEXT, Some(&writer), &head, body);
    assert!(e.svc.execute(&genuine).await.is_ok());
    assert_eq!(
        e.store_count(&id).await,
        1,
        "only the genuine request stored"
    );
}

impl Env {
    async fn store_count(&self, id: &BoxId) -> u32 {
        use crate::DropStore;
        self.store.get(id, self.at()).await.unwrap().unwrap().count
    }
}

#[tokio::test]
async fn mismatched_op_hash_version_and_trailing_bytes_are_malformed() {
    let e = env();
    let (id, _reader, writer) = e.new_box().await;
    let body = enc(&put(b"x"));

    let wrong_op = e.head(&writer, &id, Op::Ack, &body);
    let raw = wire::seal_parts(REALM, CONTEXT, Some(&writer), &wrong_op, body.clone());
    assert_eq!(e.svc.execute(&raw).await, Err(DropError::Malformed));

    let mut wrong_hash = e.head(&writer, &id, Op::Put, &body);
    wrong_hash.body_hash[0] ^= 1;
    let raw = wire::seal_parts(REALM, CONTEXT, Some(&writer), &wrong_hash, body.clone());
    assert_eq!(e.svc.execute(&raw).await, Err(DropError::Malformed));

    let mut trailing_body = body.to_vec();
    trailing_body.push(0);
    let head = e.head(&writer, &id, Op::Put, &trailing_body);
    let raw = wire::seal_parts(REALM, CONTEXT, Some(&writer), &head, trailing_body.into());
    assert_eq!(e.svc.execute(&raw).await, Err(DropError::Malformed));

    let mut raw = e.req(&writer, &id, put(b"x"));
    raw.push(0);
    assert_eq!(e.svc.execute(&raw).await, Err(DropError::Malformed));
    let mut raw = e.req(&writer, &id, put(b"x"));
    raw[0] = 2;
    assert_eq!(e.svc.execute(&raw).await, Err(DropError::Version));
    assert_eq!(e.svc.execute(&[]).await, Err(DropError::Malformed));
    assert_eq!(e.store_count(&id).await, 0);
}

#[tokio::test]
async fn every_bit_flip_and_truncation_fails_or_changes_nothing() {
    let e = env();
    let (id, _reader, writer) = e.new_box().await;
    let raw = e.req(&writer, &id, put(b"payload"));
    let now = e.at();
    let original = wire::open(&raw, REALM, now, 300_000, 1 << 20).unwrap();
    for i in 0..raw.len() {
        for bit in 0..8 {
            let mut m = raw.clone();
            m[i] ^= 1 << bit;
            if let Ok(o) = wire::open(&m, REALM, now, 300_000, 1 << 20) {
                assert_eq!(o, original, "flip at {i}.{bit} changed a verified request");
            }
        }
    }
    for len in 0..raw.len() {
        assert!(wire::open(&raw[..len], REALM, now, 300_000, 1 << 20).is_err());
    }
}

#[tokio::test]
async fn replayed_requests_are_refused() {
    let e = env();
    let (id, reader, writer) = e.new_box().await;
    let raw = e.req(&writer, &id, put(b"once"));
    assert!(e.svc.execute(&raw).await.is_ok());
    assert_eq!(e.svc.execute(&raw).await, Err(DropError::Replayed));
    e.now.fetch_add(299_000, Ordering::SeqCst);
    assert_eq!(e.svc.execute(&raw).await, Err(DropError::Replayed));
    e.now.fetch_add(2_000, Ordering::SeqCst);
    assert_eq!(
        e.svc.execute(&raw).await,
        Err(DropError::Stale),
        "after the window freshness refuses it"
    );
    assert_eq!(e.messages(&id, &reader).await.len(), 1);
}

#[tokio::test]
async fn stale_and_future_timestamps_are_refused_at_the_window_edge() {
    let e = env();
    let (id, _reader, writer) = e.new_box().await;
    let window = 300_000;
    for (offset, ok) in [
        (-window - 1, false),
        (-window, true),
        (window, true),
        (window + 1, false),
    ] {
        let raw = wire::seal(
            REALM,
            &writer,
            &id,
            &put(b"t"),
            e.at().plus_ms(offset),
            wire::nonce(),
        );
        let r = e.svc.execute(&raw).await;
        if ok {
            assert!(r.is_ok(), "offset {offset}");
        } else {
            assert_eq!(r, Err(DropError::Stale), "offset {offset}");
        }
    }
}

#[tokio::test]
async fn keys_outside_their_role_are_denied() {
    let e = env();
    let (id, reader, writer) = e.new_box().await;
    e.run(&writer, &id, put(b"kept")).await.unwrap();
    let stranger = BoxKey::generate();
    for k in [&stranger, &reader] {
        assert_eq!(e.run(k, &id, put(b"x")).await, Err(DropError::Denied));
    }
    for k in [&stranger, &writer] {
        for body in [
            Body::Take {
                after: None,
                limit: 1,
                wait_ms: 0,
            },
            Body::Ack { up_to: 1 },
            Body::SetWriters {
                writers: vec![k.public()],
                version: u64::MAX,
            },
            Body::Delete,
        ] {
            assert_eq!(e.run(k, &id, body).await, Err(DropError::Denied));
        }
    }
    assert_eq!(e.messages(&id, &reader).await.len(), 1);
    let policy = small_policy(reader.public(), vec![]);
    let other = BoxId::random();
    assert_eq!(
        e.run(
            &stranger,
            &other,
            Body::Create {
                policy,
                admission: WireAdmission::Token(TOKEN.to_vec())
            }
        )
        .await,
        Err(DropError::Denied),
        "only the policy's reader creates"
    );
}

#[tokio::test]
async fn a_removed_writer_stays_removed_even_after_a_restart_and_a_replay() {
    let e = env();
    let (id, reader, writer) = e.new_box().await;
    let w2 = BoxKey::generate();
    let both = e.req(
        &reader,
        &id,
        Body::SetWriters {
            writers: vec![writer.public(), w2.public()],
            version: 10,
        },
    );
    e.svc.execute(&both).await.unwrap();
    e.run(&w2, &id, put(b"ok")).await.unwrap();
    e.run(
        &reader,
        &id,
        Body::SetWriters {
            writers: vec![writer.public()],
            version: 11,
        },
    )
    .await
    .unwrap();
    assert_eq!(e.run(&w2, &id, put(b"no")).await, Err(DropError::Denied));

    let restarted =
        DropService::new(e.store.clone(), e.svc.config().clone(), e.clock.clone()).unwrap();
    assert_eq!(
        restarted.execute(&both).await,
        Err(DropError::Conflict),
        "a replayed older writer list never restores a removed writer"
    );
    assert_eq!(
        restarted
            .execute(&wire::seal(
                REALM,
                &w2,
                &id,
                &put(b"no"),
                e.at(),
                wire::nonce()
            ))
            .await,
        Err(DropError::Denied)
    );
}

#[tokio::test]
async fn quotas_and_sizes_are_enforced() {
    let e = env_with(|c| {
        c.max_message = 1000;
        c.max_box_messages = 3;
        c.max_box_bytes = 100_000;
    });
    let (reader, writer) = (BoxKey::generate(), BoxKey::generate());
    let id = BoxId::of_reader(&reader.public());
    let mut policy = small_policy(reader.public(), vec![writer.public()]);
    let create = |policy: BoxPolicy| Body::Create {
        policy,
        admission: WireAdmission::Token(TOKEN.to_vec()),
    };
    policy.max_messages = 4;
    assert_eq!(
        e.run(&reader, &id, create(policy.clone())).await,
        Err(DropError::InvalidPolicy),
        "a quota above the operator's cap"
    );
    policy.max_messages = 3;
    policy.max_bytes = 100_001;
    assert_eq!(
        e.run(&reader, &id, create(policy.clone())).await,
        Err(DropError::InvalidPolicy)
    );
    policy.max_bytes = 2_000;
    e.run(&reader, &id, create(policy)).await.unwrap();

    let big = Body::Put {
        bytes: Bytes::from(vec![0; 1001]),
    };
    assert_eq!(e.run(&writer, &id, big).await, Err(DropError::TooLarge));
    let huge = vec![0u8; e.svc.max_request() + 1];
    assert_eq!(e.svc.execute(&huge).await, Err(DropError::TooLarge));
    for _ in 0..2 {
        e.run(
            &writer,
            &id,
            Body::Put {
                bytes: Bytes::from(vec![1; 1000]),
            },
        )
        .await
        .unwrap();
    }
    assert_eq!(e.run(&writer, &id, put(b"x")).await, Err(DropError::Quota));
}

#[tokio::test]
async fn proof_of_work_is_bound_to_salt_box_and_difficulty() {
    let e = env();
    let reader = BoxKey::generate();
    let id = BoxId::of_reader(&reader.public());
    let policy = small_policy(reader.public(), vec![]);
    let create = |n: u64| Body::Create {
        policy: policy.clone(),
        admission: WireAdmission::Work(n),
    };

    let mut other_salt = e.work.clone();
    other_salt.salt[0] ^= 0xff;
    let n = loop {
        let n = other_salt.solve(&id).unwrap();
        if !e.work.verify(&id, n) {
            break n;
        }
    };
    assert_eq!(
        e.run(&reader, &id, create(n)).await,
        Err(DropError::Admission)
    );

    let other_box = BoxId::random();
    let n = loop {
        let n = e.work.solve(&other_box).unwrap();
        if !e.work.verify(&id, n) {
            break n;
        }
    };
    assert_eq!(
        e.run(&reader, &id, create(n)).await,
        Err(DropError::Admission)
    );

    let mut easier = e.work.clone();
    easier.difficulty = 1;
    let n = loop {
        let n = easier.solve(&id).unwrap();
        if !e.work.verify(&id, n) {
            break n;
        }
    };
    assert_eq!(
        e.run(&reader, &id, create(n)).await,
        Err(DropError::Admission),
        "insufficient difficulty"
    );

    let n = e.work.solve(&id).unwrap();
    e.run(&reader, &id, create(n)).await.unwrap();
    assert_eq!(e.run(&reader, &id, create(n)).await, Err(DropError::Exists));
}

#[tokio::test]
async fn tokens_must_match() {
    let e = env();
    let reader = BoxKey::generate();
    let id = BoxId::of_reader(&reader.public());
    let policy = small_policy(reader.public(), vec![]);
    for admission in [
        WireAdmission::None,
        WireAdmission::Token(b"operator-token-for-test".to_vec()),
        WireAdmission::Token(b"operator-token-for-tests!".to_vec()),
        WireAdmission::Token(vec![]),
    ] {
        assert_eq!(
            e.run(
                &reader,
                &id,
                Body::Create {
                    policy: policy.clone(),
                    admission
                }
            )
            .await,
            Err(DropError::Admission)
        );
    }
    let closed = env_with(|c| c.admission = AdmissionConfig::closed());
    assert_eq!(
        closed
            .run(
                &reader,
                &id,
                Body::Create {
                    policy: policy.clone(),
                    admission: WireAdmission::Work(0)
                }
            )
            .await,
        Err(DropError::Admission),
        "no work accepted where none is configured"
    );
    let open = env_with(|c| c.admission = AdmissionConfig::open());
    open.run(
        &reader,
        &id,
        Body::Create {
            policy,
            admission: WireAdmission::None,
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn a_full_replay_cache_refuses_instead_of_forgetting() {
    let e = env_with(|c| c.replay_capacity = 3);
    let (id, _reader, writer) = e.new_box().await;
    let stranger = BoxKey::generate();
    for _ in 0..10 {
        assert_eq!(
            e.run(&stranger, &id, put(b"x")).await,
            Err(DropError::Denied)
        );
        assert_eq!(
            e.run(&stranger, &BoxId::random(), put(b"x")).await,
            Err(DropError::UnknownBox)
        );
    }
    let first = e.req(&writer, &id, put(b"1"));
    e.svc.execute(&first).await.unwrap();
    e.run(&writer, &id, put(b"2")).await.unwrap();
    assert_eq!(
        e.run(&writer, &id, put(b"3")).await,
        Err(DropError::Busy),
        "creation plus two puts fill it; refused requests never entered"
    );
    assert_eq!(e.svc.execute(&first).await, Err(DropError::Replayed));
    e.now.fetch_add(300_001, Ordering::SeqCst);
    e.run(&writer, &id, put(b"4"))
        .await
        .expect("expired nonces make room");
}

#[tokio::test]
async fn takes_are_clamped_trimmed_and_bounded_in_waiters() {
    let e = env_with(|c| {
        c.max_take = 2;
        c.max_message = 100;
        c.max_take_bytes = 150;
        c.max_waiters = 0;
    });
    let (id, reader, writer) = e.new_box().await;
    let empty = tokio::time::timeout(
        Duration::from_secs(10),
        e.run(
            &reader,
            &id,
            Body::Take {
                after: None,
                limit: 10,
                wait_ms: u32::MAX,
            },
        ),
    )
    .await
    .expect("no waiter slot: the take returns at once")
    .unwrap();
    assert_eq!(empty, Reply::Messages(vec![]));
    for _ in 0..3 {
        e.run(
            &writer,
            &id,
            Body::Put {
                bytes: Bytes::from(vec![0; 100]),
            },
        )
        .await
        .unwrap();
    }
    assert_eq!(
        e.messages(&id, &reader).await.len(),
        1,
        "byte cap, at least one"
    );
    let e = env_with(|c| c.max_take = 2);
    let (id, reader, writer) = e.new_box().await;
    for _ in 0..3 {
        e.run(&writer, &id, put(b"m")).await.unwrap();
    }
    assert_eq!(e.messages(&id, &reader).await.len(), 2, "count cap");
}

#[tokio::test]
async fn a_waiting_take_ends_when_the_box_is_deleted() {
    let e = env();
    let (id, reader, _writer) = e.new_box().await;
    let svc = e.svc.clone();
    let raw = e.req(
        &reader,
        &id,
        Body::Take {
            after: None,
            limit: 1,
            wait_ms: 25_000,
        },
    );
    let waiting = tokio::spawn(async move { svc.execute(&raw).await });
    tokio::task::yield_now().await;
    for _ in 0..50 {
        if !e.svc.waiters.lock().unwrap().is_empty() {
            break;
        }
        tokio::task::yield_now().await;
    }
    e.run(&reader, &id, Body::Delete).await.unwrap();
    let r = tokio::time::timeout(Duration::from_secs(20), waiting)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(r, Err(DropError::UnknownBox));
    assert!(
        e.svc.waiters.lock().unwrap().is_empty(),
        "no waiter left behind"
    );
}

#[tokio::test]
async fn sweeping_removes_idle_boxes() {
    let e = env();
    let (id, reader, writer) = e.new_box().await;
    e.run(&writer, &id, put(b"x")).await.unwrap();
    e.now.fetch_add(3_600_000, Ordering::SeqCst);
    assert!(e.svc.sweep().await.unwrap() >= 1);
    assert_eq!(
        e.run(&reader, &id, Body::Delete).await,
        Err(DropError::UnknownBox)
    );
}

#[test]
fn configurations_out_of_range_are_refused() {
    let ok = DropConfig::new(REALM, AdmissionConfig::open());
    assert!(ok.check().is_ok());
    for edit in [
        (|c: &mut DropConfig| c.realm = String::new()) as fn(&mut DropConfig),
        |c| c.realm = "a b".into(),
        |c| c.max_message = 0,
        |c| c.max_message = 2 * 1024 * 1024,
        |c| c.max_take_bytes = c.max_message - 1,
        |c| c.max_take = 0,
        |c| c.max_ttl_ms = baton_mailbox::MAX_TTL_MS + 1,
        |c| c.freshness_ms = 0,
        |c| c.replay_capacity = 0,
    ] {
        let mut c = ok.clone();
        edit(&mut c);
        assert!(c.check().is_err());
    }
}

struct Local(Arc<DropService>);

#[async_trait]
impl Exchange for Local {
    async fn info(&self) -> Result<Vec<u8>, MailboxError> {
        Ok(wire::encode_info(&self.0.info()))
    }
    async fn exchange(&self, request: Vec<u8>, _wait: Duration) -> Result<Vec<u8>, MailboxError> {
        Ok(self.0.handle(&request).await)
    }
}

struct Lying {
    info: Vec<u8>,
    reply: Vec<u8>,
}

#[async_trait]
impl Exchange for Lying {
    async fn info(&self) -> Result<Vec<u8>, MailboxError> {
        Ok(self.info.clone())
    }
    async fn exchange(&self, _: Vec<u8>, _: Duration) -> Result<Vec<u8>, MailboxError> {
        Ok(self.reply.clone())
    }
}

#[tokio::test]
async fn the_client_checks_service_info_and_replies() {
    let e = env();
    let good = e.svc.info();
    assert!(
        DropMailbox::connect(
            Arc::new(Local(e.svc.clone())),
            "drop.example.org",
            e.clock.clone()
        )
        .await
        .is_err(),
        "a realm other than the configured one"
    );
    let mut evil = good.clone();
    evil.work.as_mut().unwrap().difficulty = 60;
    let lying = |info: &wire::ServiceInfo, reply: Result<Reply, DropError>| Lying {
        info: wire::encode_info(info),
        reply: wire::encode_reply(&reply),
    };
    assert!(
        DropMailbox::connect(
            Arc::new(lying(&evil, Ok(Reply::Done))),
            REALM,
            e.clock.clone()
        )
        .await
        .is_err(),
        "a challenge beyond the client's caps"
    );

    let id = BoxId::random();
    let reader = BoxKey::generate();
    let msg = |id: u64, len: usize| WireMessage {
        id,
        at: Timestamp(0),
        bytes: Bytes::from(vec![0; len]),
    };
    for bad in [
        Reply::Messages(vec![msg(2, 1), msg(1, 1)]),
        Reply::Messages(vec![msg(1, 1), msg(1, 1)]),
        Reply::Messages(vec![msg(5, good.max_message as usize + 1)]),
        Reply::Stored(3),
    ] {
        let mb = DropMailbox::connect(Arc::new(lying(&good, Ok(bad))), REALM, e.clock.clone())
            .await
            .unwrap();
        assert!(
            mb.take(&id, &reader, None, 10, Duration::ZERO)
                .await
                .is_err(),
            "a lying reply is not believed"
        );
    }
    let mb = DropMailbox::connect(
        Arc::new(lying(&good, Ok(Reply::Messages(vec![msg(5, 1)])))),
        REALM,
        e.clock.clone(),
    )
    .await
    .unwrap();
    assert!(
        mb.take(
            &id,
            &reader,
            Some(baton_mailbox::MessageId(5)),
            10,
            Duration::ZERO
        )
        .await
        .is_err(),
        "nothing at or before the cursor"
    );
    let oversized = Lying {
        info: wire::encode_info(&good),
        reply: vec![1; crate::service::max_reply(&good) + 1],
    };
    let mb = DropMailbox::connect(Arc::new(oversized), REALM, e.clock.clone())
        .await
        .unwrap();
    assert!(
        mb.take(&id, &reader, None, 1, Duration::ZERO)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn the_client_solves_work_and_presents_tokens() {
    let e = env();
    let mb = DropMailbox::connect(Arc::new(Local(e.svc.clone())), REALM, e.clock.clone())
        .await
        .unwrap();
    for admission in [
        Admission::Work,
        Admission::Token(Zeroizing::new(TOKEN.to_vec())),
    ] {
        let reader = BoxKey::generate();
        mb.create(
            &BoxId::of_reader(&reader.public()),
            &small_policy(reader.public(), vec![]),
            &reader,
            &admission,
        )
        .await
        .unwrap();
    }
    let reader = BoxKey::generate();
    assert!(matches!(
        mb.create(
            &BoxId::of_reader(&reader.public()),
            &small_policy(reader.public(), vec![]),
            &reader,
            &Admission::Token(Zeroizing::new(vec![0; 300]))
        )
        .await,
        Err(MailboxError::Admission)
    ));
}

fn arb_body() -> impl Strategy<Value = Body> {
    prop_oneof![
        proptest::collection::vec(any::<u8>(), 0..512).prop_map(|b| Body::Put { bytes: b.into() }),
        (any::<Option<u64>>(), any::<u32>(), any::<u32>()).prop_map(|(after, limit, wait_ms)| {
            Body::Take {
                after,
                limit,
                wait_ms,
            }
        }),
        any::<u64>().prop_map(|up_to| Body::Ack { up_to }),
        any::<u64>().prop_map(|version| Body::SetWriters {
            writers: vec![BoxKey::generate().public()],
            version
        }),
        Just(Body::Delete),
    ]
}

proptest! {
    #[test]
    fn sealed_requests_open_to_what_was_sealed(body in arb_body(), at in 0i64..i64::MAX / 2) {
        let key = BoxKey::generate();
        let id = BoxId::random();
        let raw = wire::seal(REALM, &key, &id, &body, Timestamp(at), [7; 16]);
        let o = wire::open(&raw, REALM, Timestamp(at), 1, 1 << 20).unwrap();
        prop_assert_eq!(o.body, body);
        prop_assert_eq!(o.head.box_id, id);
        prop_assert_eq!(o.head.key, key.public());
    }

    #[test]
    fn arbitrary_bytes_never_open_or_panic(raw in proptest::collection::vec(any::<u8>(), 0..2048)) {
        prop_assert!(wire::open(&raw, REALM, Timestamp(T0), 300_000, 1 << 20).is_err());
        let _ = wire::wait_ms(&raw);
        let _ = wire::decode_reply(&raw, 1 << 20);
        let _ = wire::decode_info(&raw);
    }

    #[test]
    fn replies_round_trip(ids in proptest::collection::vec(any::<u64>(), 0..20)) {
        let r = Ok(Reply::Messages(ids.iter().map(|&id| WireMessage {
            id, at: Timestamp(1), bytes: Bytes::from_static(b"m"),
        }).collect()));
        prop_assert_eq!(wire::decode_reply(&wire::encode_reply(&r), 1 << 20).unwrap(), r);
        let e: Result<Reply, DropError> = Err(DropError::Quota);
        prop_assert_eq!(wire::decode_reply(&wire::encode_reply(&e), 1 << 20).unwrap(), e);
    }
}

#[tokio::test]
async fn one_boxs_requests_cannot_make_other_boxes_busy() {
    assert_eq!(env().svc.config().replay_per_box, 4096);
    let e = env_with(|c| {
        c.replay_capacity = 64;
        c.replay_per_box = 16;
    });
    let (a, a_reader, _) = e.new_box().await;
    let mut busy = false;
    for _ in 0..200 {
        let r = e
            .run(
                &a_reader,
                &a,
                Body::Take {
                    after: None,
                    limit: 1,
                    wait_ms: 0,
                },
            )
            .await;
        if r == Err(DropError::Busy) {
            busy = true;
            break;
        }
        r.unwrap();
    }
    assert!(busy, "one box runs out of its own share");
    let (b, b_reader, b_writer) = e.new_box().await;
    e.run(&b_writer, &b, put(b"still served")).await.unwrap();
    assert_eq!(e.messages(&b, &b_reader).await.len(), 1);
}

#[tokio::test]
async fn an_expired_box_cannot_be_squatted_by_another_key() {
    let e = env();
    let reader = BoxKey::generate();
    let id = BoxId::of_reader(&reader.public());
    let mut policy = small_policy(reader.public(), vec![]);
    policy.ttl_ms = 60_000;
    let create = |p: BoxPolicy| Body::Create {
        policy: p,
        admission: WireAdmission::Token(TOKEN.to_vec()),
    };
    e.run(&reader, &id, create(policy.clone())).await.unwrap();
    e.now.fetch_add(60_001, Ordering::SeqCst);
    let squatter = BoxKey::generate();
    let squat = small_policy(squatter.public(), vec![]);
    assert_eq!(
        e.run(&squatter, &id, create(squat.clone())).await,
        Err(DropError::Denied),
        "the id of an idle box stays bound to its reader key"
    );
    assert_eq!(
        e.run(&squatter, &BoxId::random(), create(squat)).await,
        Err(DropError::Denied),
        "any id not derived from the reader key"
    );
    e.run(&reader, &id, create(policy))
        .await
        .expect("only the reader re-creates it");
}

#[tokio::test]
async fn boxes_anybody_can_create_get_the_smaller_quotas() {
    let e = env();
    let reader = BoxKey::generate();
    let id = BoxId::of_reader(&reader.public());
    let mut big = small_policy(reader.public(), vec![]);
    big.max_bytes = 2 * 1024 * 1024;
    let n = e.work.solve(&id).unwrap();
    assert_eq!(
        e.run(
            &reader,
            &id,
            Body::Create {
                policy: big.clone(),
                admission: WireAdmission::Work(n)
            }
        )
        .await,
        Err(DropError::InvalidPolicy),
        "a proof of work buys at most the untrusted quota"
    );
    let mut long = small_policy(reader.public(), vec![]);
    long.ttl_ms = 8 * 24 * 3600 * 1000;
    assert_eq!(
        e.run(
            &reader,
            &id,
            Body::Create {
                policy: long,
                admission: WireAdmission::Work(n)
            }
        )
        .await,
        Err(DropError::InvalidPolicy)
    );
    e.run(
        &reader,
        &id,
        Body::Create {
            policy: big,
            admission: WireAdmission::Token(TOKEN.to_vec()),
        },
    )
    .await
    .expect("a token buys the large quota");
    assert_eq!(
        e.store.get(&id, e.at()).await.unwrap().unwrap().admitted,
        crate::Admitted::Token
    );
    let r2 = BoxKey::generate();
    let id2 = BoxId::of_reader(&r2.public());
    let n2 = e.work.solve(&id2).unwrap();
    e.run(
        &r2,
        &id2,
        Body::Create {
            policy: small_policy(r2.public(), vec![]),
            admission: WireAdmission::Work(n2),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        e.store.get(&id2, e.at()).await.unwrap().unwrap().admitted,
        crate::Admitted::Work
    );
}

#[tokio::test]
async fn waiters_are_capped_per_box() {
    let e = env_with(|c| c.max_waiters_per_box = 2);
    let (id, reader, writer) = e.new_box().await;
    let (other, other_reader, _) = e.new_box().await;
    let take = |key: &BoxKey, id: &BoxId| {
        e.req(
            key,
            id,
            Body::Take {
                after: None,
                limit: 1,
                wait_ms: 25_000,
            },
        )
    };
    let mut waiting = Vec::new();
    for _ in 0..2 {
        let (svc, raw) = (e.svc.clone(), take(&reader, &id));
        waiting.push(tokio::spawn(async move { svc.execute(&raw).await }));
    }
    for _ in 0..100 {
        if e.svc.waiters.lock().unwrap().get(&id).map(|w| w.1) == Some(2) {
            break;
        }
        tokio::task::yield_now().await;
    }
    let third = tokio::time::timeout(Duration::from_secs(5), e.svc.execute(&take(&reader, &id)))
        .await
        .expect("a third take on the box returns at once")
        .unwrap();
    assert_eq!(third, Reply::Messages(vec![]));
    let (svc, raw) = (e.svc.clone(), take(&other_reader, &other));
    let elsewhere = tokio::spawn(async move { svc.execute(&raw).await });
    for _ in 0..100 {
        if e.svc.waiters.lock().unwrap().contains_key(&other) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        e.svc.waiters.lock().unwrap().contains_key(&other),
        "another box still gets its own waiter"
    );
    e.run(&writer, &id, put(b"wake")).await.unwrap();
    for w in waiting {
        let r = tokio::time::timeout(Duration::from_secs(5), w)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(matches!(r, Reply::Messages(m) if m.len() == 1));
    }
    e.run(&other_reader, &other, Body::Delete).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), elsewhere).await;
}

#[test]
fn wait_ms_peeks_takes_only() {
    let key = BoxKey::generate();
    let id = BoxId::of_reader(&key.public());
    let take = wire::seal(
        REALM,
        &key,
        &id,
        &Body::Take {
            after: None,
            limit: 1,
            wait_ms: 7,
        },
        Timestamp(T0),
        wire::nonce(),
    );
    assert_eq!(wire::wait_ms(&take), Some(7));
    let p = wire::seal(REALM, &key, &id, &put(b"x"), Timestamp(T0), wire::nonce());
    assert_eq!(wire::wait_ms(&p), None);
    assert_eq!(wire::wait_ms(&take[..take.len() - 1]), None);
}
