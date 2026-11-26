//! Conformance suite for [`Mailbox`], including the hostile cases.

use std::sync::Arc;
use std::time::Duration;

use baton_identity::PublicKey;
use bytes::Bytes;
use zeroize::Zeroizing;

use crate::{
    Admission, BoxId, BoxKey, BoxPolicy, MAX_TTL_MS, Mailbox, MailboxError, Message, MessageId,
};

/// What the suite needs besides the implementation.
pub trait Harness: Send + Sync {
    /// An admission the mailbox under test accepts for any new box. The mailbox must be
    /// configured to refuse [`Admission::None`] and unknown tokens.
    fn admission(&self) -> Admission;
    /// Moves the clock the mailbox judges time-to-lives by (and the one requests are stamped
    /// with) forward by `ms`.
    fn advance(&self, ms: u64);
}

/// A small policy for the suites: 60 s time-to-live, 64 messages, 64 KiB.
pub fn small_policy(reader: PublicKey, writers: Vec<PublicKey>) -> BoxPolicy {
    BoxPolicy {
        reader,
        writers,
        max_bytes: 64 * 1024,
        max_messages: 64,
        ttl_ms: 60_000,
    }
}

struct Fixture {
    id: BoxId,
    reader: BoxKey,
    w1: BoxKey,
    w2: BoxKey,
}

async fn fixture(
    mb: &Arc<dyn Mailbox>,
    h: &dyn Harness,
    edit: impl FnOnce(&mut BoxPolicy),
) -> Fixture {
    let reader = BoxKey::generate();
    let f = Fixture {
        id: BoxId::of_reader(&reader.public()),
        reader,
        w1: BoxKey::generate(),
        w2: BoxKey::generate(),
    };
    let mut p = small_policy(f.reader.public(), vec![f.w1.public(), f.w2.public()]);
    edit(&mut p);
    mb.create(&f.id, &p, &f.reader, &h.admission())
        .await
        .expect("a valid creation is accepted");
    f
}

async fn all(mb: &Arc<dyn Mailbox>, f: &Fixture) -> Vec<Message> {
    mb.take(&f.id, &f.reader, None, 1000, Duration::ZERO)
        .await
        .unwrap()
}

fn b(s: &'static str) -> Bytes {
    Bytes::from_static(s.as_bytes())
}

/// The [`Mailbox`] contract.
pub async fn mailbox<H: Harness + 'static>(mb: Arc<dyn Mailbox>, h: Arc<H>) {
    admission(&mb, &*h).await;
    round_trip(&mb, &*h).await;
    denied(&mb, &*h).await;
    revocation(&mb, &*h).await;
    sizes_and_quotas(&mb, &*h).await;
    expiry(&mb, &*h).await;
    unknown_and_deleted(&mb, &*h).await;
    long_poll(&mb, &*h).await;
    concurrent_writers(&mb, &*h).await;
}

async fn admission(mb: &Arc<dyn Mailbox>, h: &dyn Harness) {
    let reader = BoxKey::generate();
    let id = BoxId::of_reader(&reader.public());
    let writer = BoxKey::generate();
    let p = small_policy(reader.public(), vec![writer.public()]);
    assert!(matches!(
        mb.create(&id, &p, &reader, &Admission::None).await,
        Err(MailboxError::Admission)
    ));
    assert!(matches!(
        mb.create(
            &id,
            &p,
            &reader,
            &Admission::Token(Zeroizing::new(b"not-the-token".to_vec()))
        )
        .await,
        Err(MailboxError::Admission)
    ));
    assert!(
        matches!(
            mb.put(&id, &writer, b("x")).await,
            Err(MailboxError::UnknownBox)
        ),
        "a refused creation creates nothing"
    );
    let stranger = BoxKey::generate();
    assert!(
        mb.create(&id, &p, &stranger, &h.admission()).await.is_err(),
        "only the policy's reader creates"
    );
    let mut long = p.clone();
    long.ttl_ms = MAX_TTL_MS + 1;
    assert!(matches!(
        mb.create(&id, &long, &reader, &h.admission()).await,
        Err(MailboxError::InvalidPolicy)
    ));
    let mut dup = p.clone();
    dup.writers = vec![writer.public(), writer.public()];
    assert!(matches!(
        mb.create(&id, &dup, &reader, &h.admission()).await,
        Err(MailboxError::InvalidPolicy)
    ));
    let squatter = BoxKey::generate();
    let squat = small_policy(squatter.public(), vec![writer.public()]);
    assert!(
        matches!(
            mb.create(&id, &squat, &squatter, &h.admission()).await,
            Err(MailboxError::Denied)
        ),
        "an id bound to another reader key"
    );
    assert!(
        matches!(
            mb.create(&BoxId::random(), &p, &reader, &h.admission())
                .await,
            Err(MailboxError::Denied)
        ),
        "an id not derived from the reader key"
    );
    mb.create(&id, &p, &reader, &h.admission()).await.unwrap();
    assert!(matches!(
        mb.create(&id, &p, &reader, &h.admission()).await,
        Err(MailboxError::Exists)
    ));
}

async fn round_trip(mb: &Arc<dyn Mailbox>, h: &dyn Harness) {
    let f = fixture(mb, h, |_| {}).await;
    assert!(all(mb, &f).await.is_empty());
    let m1 = mb.put(&f.id, &f.w1, b("one")).await.unwrap();
    let m2 = mb.put(&f.id, &f.w2, b("two")).await.unwrap();
    let m3 = mb.put(&f.id, &f.w1, Bytes::new()).await.unwrap();
    assert!(m1 < m2 && m2 < m3, "ids grow");

    let got = all(mb, &f).await;
    let bodies: Vec<_> = got.iter().map(|m| (m.id, m.bytes.clone())).collect();
    assert_eq!(
        bodies,
        vec![(m1, b("one")), (m2, b("two")), (m3, Bytes::new())]
    );
    assert_eq!(
        all(mb, &f).await,
        got,
        "at least once: unacknowledged stays"
    );

    let after = mb
        .take(&f.id, &f.reader, Some(m1), 1000, Duration::ZERO)
        .await
        .unwrap();
    assert_eq!(after.iter().map(|m| m.id).collect::<Vec<_>>(), vec![m2, m3]);
    let one = mb
        .take(&f.id, &f.reader, None, 1, Duration::ZERO)
        .await
        .unwrap();
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].id, m1);

    mb.ack(&f.id, &f.reader, m2).await.unwrap();
    assert_eq!(
        all(mb, &f).await.iter().map(|m| m.id).collect::<Vec<_>>(),
        vec![m3],
        "ack removes everything up to its id"
    );
    mb.ack(&f.id, &f.reader, m2).await.unwrap();
    mb.ack(&f.id, &f.reader, m3).await.unwrap();
    assert!(all(mb, &f).await.is_empty());
    let m4 = mb.put(&f.id, &f.w2, b("four")).await.unwrap();
    assert!(m4 > m3, "ids are never reused after acknowledgements");
    assert_eq!(all(mb, &f).await[0].bytes, b("four"));
}

async fn denied(mb: &Arc<dyn Mailbox>, h: &dyn Harness) {
    let f = fixture(mb, h, |_| {}).await;
    let m = mb.put(&f.id, &f.w1, b("kept")).await.unwrap();
    let stranger = BoxKey::generate();
    for key in [&stranger, &f.reader] {
        assert!(
            matches!(mb.put(&f.id, key, b("x")).await, Err(MailboxError::Denied)),
            "only writers put"
        );
    }
    for key in [&stranger, &f.w1] {
        assert!(matches!(
            mb.take(&f.id, key, None, 10, Duration::ZERO).await,
            Err(MailboxError::Denied)
        ));
        assert!(matches!(
            mb.ack(&f.id, key, m).await,
            Err(MailboxError::Denied)
        ));
        assert!(matches!(
            mb.set_writers(&f.id, key, &[key.public()]).await,
            Err(MailboxError::Denied)
        ));
        assert!(matches!(
            mb.delete_box(&f.id, key).await,
            Err(MailboxError::Denied)
        ));
    }
    let left = all(mb, &f).await;
    assert_eq!(left.len(), 1, "refused calls changed nothing");
    assert_eq!(left[0].bytes, b("kept"));
}

async fn revocation(mb: &Arc<dyn Mailbox>, h: &dyn Harness) {
    let f = fixture(mb, h, |_| {}).await;
    mb.put(&f.id, &f.w2, b("before")).await.unwrap();
    mb.set_writers(&f.id, &f.reader, &[f.w1.public()])
        .await
        .unwrap();
    assert!(
        matches!(
            mb.put(&f.id, &f.w2, b("after")).await,
            Err(MailboxError::Denied)
        ),
        "a removed writer is refused"
    );
    mb.put(&f.id, &f.w1, b("still")).await.unwrap();
    let left: Vec<_> = all(mb, &f).await.into_iter().map(|m| m.bytes).collect();
    assert_eq!(left, vec![b("before"), b("still")], "stored messages stay");
    assert!(matches!(
        mb.set_writers(&f.id, &f.reader, &[f.w1.public(), f.w1.public()])
            .await,
        Err(MailboxError::InvalidPolicy)
    ));
    mb.set_writers(&f.id, &f.reader, &[f.w1.public(), f.w2.public()])
        .await
        .unwrap();
    mb.put(&f.id, &f.w2, b("back")).await.unwrap();
    mb.set_writers(&f.id, &f.reader, &[]).await.unwrap();
    assert!(matches!(
        mb.put(&f.id, &f.w1, b("x")).await,
        Err(MailboxError::Denied)
    ));
}

async fn sizes_and_quotas(mb: &Arc<dyn Mailbox>, h: &dyn Harness) {
    let max = mb.limits().max_message;
    let f = fixture(mb, h, |p| p.max_bytes = 4 * max as u64).await;
    assert!(matches!(
        mb.put(&f.id, &f.w1, Bytes::from(vec![0u8; max + 1])).await,
        Err(MailboxError::TooLarge)
    ));
    mb.put(&f.id, &f.w1, Bytes::from(vec![7u8; max]))
        .await
        .expect("a message of exactly the maximum fits");
    assert_eq!(all(mb, &f).await[0].bytes.len(), max);

    let f = fixture(mb, h, |p| p.max_messages = 3).await;
    let mut ids = Vec::new();
    for _ in 0..3 {
        ids.push(mb.put(&f.id, &f.w1, b("m")).await.unwrap());
    }
    assert!(matches!(
        mb.put(&f.id, &f.w1, b("m")).await,
        Err(MailboxError::Quota)
    ));
    mb.ack(&f.id, &f.reader, ids[0]).await.unwrap();
    mb.put(&f.id, &f.w1, b("m"))
        .await
        .expect("acknowledging frees quota");

    let f = fixture(mb, h, |p| p.max_bytes = 100).await;
    let first = mb
        .put(&f.id, &f.w1, Bytes::from(vec![1u8; 60]))
        .await
        .unwrap();
    assert!(matches!(
        mb.put(&f.id, &f.w2, Bytes::from(vec![2u8; 60])).await,
        Err(MailboxError::Quota)
    ));
    mb.put(&f.id, &f.w2, Bytes::from(vec![3u8; 40]))
        .await
        .unwrap();
    assert!(matches!(
        mb.put(&f.id, &f.w2, Bytes::from(vec![4u8; 1])).await,
        Err(MailboxError::Quota)
    ));
    mb.ack(&f.id, &f.reader, first).await.unwrap();
    mb.put(&f.id, &f.w2, Bytes::from(vec![5u8; 60]))
        .await
        .unwrap();
}

async fn expiry(mb: &Arc<dyn Mailbox>, h: &dyn Harness) {
    let f = fixture(mb, h, |p| {
        p.ttl_ms = 2_000;
        p.max_messages = 2;
    })
    .await;
    mb.put(&f.id, &f.w1, b("old")).await.unwrap();
    h.advance(1_000);
    mb.put(&f.id, &f.w1, b("new")).await.unwrap();
    assert!(matches!(
        mb.put(&f.id, &f.w1, b("full")).await,
        Err(MailboxError::Quota)
    ));
    h.advance(999);
    assert_eq!(all(mb, &f).await.len(), 2, "alive up to the time-to-live");
    h.advance(1);
    let left: Vec<_> = all(mb, &f).await.into_iter().map(|m| m.bytes).collect();
    assert_eq!(left, vec![b("new")], "expired messages are never returned");
    mb.put(&f.id, &f.w1, b("room"))
        .await
        .expect("expired messages free their quota");
    h.advance(1_000);
    assert_eq!(all(mb, &f).await.len(), 1);
    h.advance(1_000);
    assert!(all(mb, &f).await.is_empty());
}

async fn unknown_and_deleted(mb: &Arc<dyn Mailbox>, h: &dyn Harness) {
    let f = fixture(mb, h, |_| {}).await;
    let m = mb.put(&f.id, &f.w1, b("x")).await.unwrap();
    let unknown = BoxId::random();
    assert!(matches!(
        mb.put(&unknown, &f.w1, b("x")).await,
        Err(MailboxError::UnknownBox)
    ));
    assert!(matches!(
        mb.take(&unknown, &f.reader, None, 1, Duration::ZERO).await,
        Err(MailboxError::UnknownBox)
    ));
    assert!(matches!(
        mb.ack(&unknown, &f.reader, m).await,
        Err(MailboxError::UnknownBox)
    ));
    assert!(matches!(
        mb.set_writers(&unknown, &f.reader, &[]).await,
        Err(MailboxError::UnknownBox)
    ));
    assert!(matches!(
        mb.delete_box(&unknown, &f.reader).await,
        Err(MailboxError::UnknownBox)
    ));
    mb.delete_box(&f.id, &f.reader).await.unwrap();
    assert!(matches!(
        mb.take(&f.id, &f.reader, None, 1, Duration::ZERO).await,
        Err(MailboxError::UnknownBox)
    ));
    assert!(matches!(
        mb.put(&f.id, &f.w1, b("x")).await,
        Err(MailboxError::UnknownBox)
    ));
}

async fn long_poll(mb: &Arc<dyn Mailbox>, h: &dyn Harness) {
    let f = Arc::new(fixture(mb, h, |_| {}).await);
    let waiting = {
        let (mb, f) = (mb.clone(), f.clone());
        tokio::spawn(async move {
            mb.take(&f.id, &f.reader, None, 10, Duration::from_secs(20))
                .await
                .unwrap()
        })
    };
    tokio::task::yield_now().await;
    mb.put(&f.id, &f.w1, b("wake")).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(15), waiting)
        .await
        .expect("a waiting take returns once a message arrives")
        .unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].bytes, b("wake"));

    let seen = got[0].id;
    let empty = tokio::time::timeout(
        Duration::from_secs(15),
        mb.take(&f.id, &f.reader, Some(seen), 10, Duration::from_millis(50)),
    )
    .await
    .expect("a short wait ends")
    .unwrap();
    assert!(empty.is_empty());
}

async fn concurrent_writers(mb: &Arc<dyn Mailbox>, h: &dyn Harness) {
    let keys: Vec<_> = (0..4).map(|_| BoxKey::generate()).collect();
    let reader = BoxKey::generate();
    let id = BoxId::of_reader(&reader.public());
    let p = small_policy(reader.public(), keys.iter().map(|k| k.public()).collect());
    mb.create(&id, &p, &reader, &h.admission()).await.unwrap();
    let mut tasks = Vec::new();
    for (i, k) in keys.into_iter().enumerate() {
        let mb = mb.clone();
        tasks.push(tokio::spawn(async move {
            let mut ids = Vec::new();
            for j in 0..10u8 {
                ids.push(
                    mb.put(&id, &k, Bytes::from(vec![i as u8, j]))
                        .await
                        .unwrap(),
                );
            }
            ids
        }));
    }
    let mut ids: Vec<MessageId> = Vec::new();
    for t in tasks {
        let mine = t.await.unwrap();
        assert!(mine.windows(2).all(|w| w[0] < w[1]));
        ids.extend(mine);
    }
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 40, "every put gets its own id");
    let got = mb
        .take(&id, &reader, None, 1000, Duration::ZERO)
        .await
        .unwrap();
    let mut got_ids: Vec<_> = got.iter().map(|m| m.id).collect();
    assert!(got_ids.windows(2).all(|w| w[0] < w[1]), "taken in id order");
    got_ids.sort();
    assert_eq!(got_ids, ids);
}
