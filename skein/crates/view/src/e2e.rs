use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use baton_signal::Signal;
use baton_signal_local::LocalSignal;
use bytes::Bytes;
use serde_json::{Value, json};
use skein_core::{
    AccountId, BlobHash, CollectionInfo, CollectionKind, Event, EventBody, FencingToken, Flags,
    ItemRef, MailboxInfo, MailboxRole, SCHEMA_VERSION, Seq, TenantId, Timestamp,
};
use skein_storage::{
    Expect, HeadAttestor, IntegrityError, JournalHead, ObjectKey, Objects, Snapshot, Storage,
    StorageError,
};
use skein_storage_memory::MemoryObjects;

use crate::follower::{FollowError, Follower, Timing};
use crate::parse::tests::fixture;
use crate::store::{Range, Store};
use crate::threads::{Link, tree};

struct Journal {
    objects: Arc<dyn Objects>,
    storage: Storage,
    signal: Arc<LocalSignal>,
}

fn t() -> TenantId {
    TenantId::new("acme").unwrap()
}

fn a() -> AccountId {
    AccountId::new("box").unwrap()
}

fn event(body: EventBody) -> Event {
    Event {
        v: SCHEMA_VERSION,
        seq: Seq(0),
        at: Timestamp(1_700_000_000_000),
        account: a(),
        key: "k".into(),
        origin: None,
        trace: None,
        body,
    }
}

fn mailbox(id: &str, role: Option<MailboxRole>) -> Event {
    event(EventBody::MailboxUpserted {
        mailbox: MailboxInfo {
            id: id.into(),
            path: id.into(),
            role,
            selectable: true,
            label: false,
        },
    })
}

fn item(id: &str) -> ItemRef {
    ItemRef {
        id: id.into(),
        uid: None,
    }
}

fn collection(id: &str, kind: CollectionKind, name: &str) -> Event {
    event(EventBody::CollectionUpserted {
        collection: CollectionInfo {
            id: id.into(),
            kind,
            name: name.into(),
            color: None,
            read_only: false,
            components: Vec::new(),
            role: None,
        },
    })
}

fn v<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap()
}

impl Journal {
    fn new() -> Self {
        let objects: Arc<dyn Objects> = Arc::new(MemoryObjects::new());
        Self {
            storage: Storage::over(objects.clone()),
            objects,
            signal: Arc::new(LocalSignal::new()),
        }
    }

    async fn added(&self, mailbox: &str, id: &str, bytes: &[u8], at: i64) -> Event {
        let blob = self
            .storage
            .blobs
            .put(&t(), Bytes::copy_from_slice(bytes))
            .await
            .unwrap();
        assert_eq!(blob, BlobHash::of(bytes));
        event(EventBody::MessageAdded {
            mailbox: mailbox.into(),
            item: item(id),
            blob,
            size: bytes.len() as u64,
            flags: Flags::default(),
            labels: None,
            received_at: Some(Timestamp(at)),
        })
    }

    async fn object(&self, collection: &str, id: &str, ct: &str, bytes: &[u8]) -> Event {
        let blob = self
            .storage
            .blobs
            .put(&t(), Bytes::copy_from_slice(bytes))
            .await
            .unwrap();
        event(EventBody::ObjectUpserted {
            collection: collection.into(),
            item: item(id),
            blob,
            size: bytes.len() as u64,
            version: Some(format!("etag-{id}")),
            content_type: ct.into(),
        })
    }

    async fn hint(&self) {
        let head = self.storage.log.head(&t(), &a()).await.unwrap();
        self.signal
            .publish(
                &skein_core::coordination::group(&t()),
                "heads/box",
                Bytes::from(head.0.to_string()),
            )
            .await
            .unwrap();
    }

    async fn append(&self, events: Vec<Event>) {
        self.storage
            .log
            .append(&t(), &a(), FencingToken(1), events)
            .await
            .unwrap();
    }

    async fn snapshot_and_compact(&self) -> u64 {
        let log = &self.storage.log;
        let head = log.head(&t(), &a()).await.unwrap();
        let mut snap = Snapshot::empty(a());
        for e in log.read(&t(), &a(), Seq(1), 10_000).await.unwrap() {
            snap.apply(&e);
        }
        assert_eq!(snap.seq, head);
        log.put_snapshot(&t(), &a(), &snap).await.unwrap();
        log.compact(&t(), &a(), Seq(head.0 + 1)).await.unwrap();
        head.0
    }

    fn view(&self, dir: &tempfile::TempDir, name: &str) -> (Arc<Store>, Follower) {
        let store = Arc::new(Store::open(&dir.path().join(name)).unwrap());
        let follower = Follower::new(Storage::over(self.objects.clone()), t(), store.clone())
            .with_page_size(2);
        (store, follower)
    }

    async fn keys(&self, area: &str) -> Vec<ObjectKey> {
        let prefix = ObjectKey::account(&t(), area, &a()).unwrap();
        self.objects.list(&prefix, None, 1000).await.unwrap()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn follows_the_journal_from_storage_and_answers_queries() {
    let j = Journal::new();
    let plain = fixture("plain.eml");
    let multi = fixture("multipart.eml");
    let parent = fixture("parent.eml");
    let reply = fixture("reply.eml");
    let reply2 = fixture("reply2.eml");
    let mut first = vec![
        mailbox("INBOX", Some(MailboxRole::Inbox)),
        mailbox("Sent", Some(MailboxRole::Sent)),
    ];
    first.push(j.added("INBOX", "1", &plain, 1_000).await);
    first.push(j.added("INBOX", "2", &multi, 2_000).await);
    first.push(j.added("INBOX", "3", &reply2, 3_000).await);
    first.push(j.added("INBOX", "4", &parent, 4_000).await);
    first.push(j.added("Sent", "5", &reply, 5_000).await);
    first.push(j.added("Sent", "6", &plain, 1_000).await);
    first.push(event(EventBody::FirstSyncCompleted));
    j.append(first).await;

    let dir = tempfile::tempdir().unwrap();
    let (store, follower) = j.view(&dir, "view.sqlite");
    follower.sync_once().await.unwrap();

    assert_eq!(
        v(&store.accounts().unwrap()[0]),
        json!({"account": "box", "checkpoint": 9, "head": 9, "lag": 0, "first_sync_completed": true})
    );
    let boxes = store.mailboxes("box").unwrap();
    assert_eq!(
        (
            &boxes[0].id,
            boxes[0].role.as_deref(),
            boxes[0].total,
            boxes[0].unread
        ),
        (&"INBOX".to_owned(), Some("inbox"), 4, 4)
    );

    let page = store.messages("box", Some("INBOX"), None, 3).unwrap();
    assert_eq!(page.len(), 3);
    assert_eq!(page[0].subject.as_deref(), Some("Lunch on Friday"));
    let last = &page[2];
    let rest = store
        .messages(
            "box",
            Some("INBOX"),
            Some((last.sort_date, last.id.clone())),
            3,
        )
        .unwrap();
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].subject.as_deref(), Some("Quarterly garden report"));
    assert_eq!(rest[0].mailboxes, vec!["INBOX", "Sent"]);

    let id = BlobHash::of(&multi).to_string();
    let m = v(&store.message("box", &id).unwrap().unwrap());
    assert_eq!(m["attachments"][0]["name"], "seating.pdf");
    assert_eq!(m["has_attachments"], true);
    assert!(m["html"].as_str().unwrap().contains("<b>seating plan</b>"));
    assert_eq!(m["memberships"][0]["mailbox"], "INBOX");
    assert!(store.has_message("box", &id).unwrap());

    let threads = store.threads("box", None, None, 50).unwrap();
    assert_eq!(threads.len(), 3);
    assert_eq!(threads[0].count, 3);
    assert_eq!(
        threads[0].latest.subject.as_deref(),
        Some("Re: Lunch on Friday")
    );
    let rows = store.thread("box", threads[0].id, 1000).unwrap();
    let ids: Vec<&str> = rows
        .iter()
        .map(|m| m.envelope.message_id.as_deref().unwrap())
        .collect();
    assert_eq!(
        ids,
        vec![
            "reply2@example.com",
            "root@example.com",
            "reply1@example.com"
        ]
    );
    let links: Vec<Link<'_>> = rows
        .iter()
        .map(|m| Link {
            id: &m.envelope.id,
            message_id: m.envelope.message_id.as_deref(),
            references: &m.references,
            in_reply_to: &m.in_reply_to,
            sort_date: m.envelope.sort_date,
        })
        .collect();
    let root = BlobHash::of(&parent).to_string();
    let r1 = BlobHash::of(&reply).to_string();
    let r2 = BlobHash::of(&reply2).to_string();
    assert_eq!(
        v(&tree(&links)),
        json!([{"id": root, "message_id": "root@example.com", "children": [
            {"id": r1, "message_id": "reply1@example.com", "children": [
                {"id": r2, "message_id": "reply2@example.com"}
            ]}
        ]}])
    );
    assert_eq!(
        store.threads("box", Some("Sent"), None, 50).unwrap().len(),
        2
    );

    let q = crate::fts_query("noodle").unwrap();
    assert_eq!(store.search("box", &q, 20).unwrap().len(), 2);
    let q = crate::fts_query("\"(OR NEAR").unwrap();
    assert!(store.search("box", &q, 20).unwrap().is_empty());
    assert!(crate::fts_query(" \" ").is_none());
    assert!(!store.has_account("nobody").unwrap());
    assert!(store.thread("box", 99_999, 10).unwrap().is_empty());
    assert!(
        store
            .message("box", &BlobHash::of(b"x").to_string())
            .unwrap()
            .is_none()
    );

    j.append(vec![
        event(EventBody::FlagsChanged {
            mailbox: "INBOX".into(),
            item: item("1"),
            flags: Flags::new(["\\Seen"]),
        }),
        event(EventBody::MessageRemoved {
            mailbox: "INBOX".into(),
            item: item("2"),
        }),
        event(EventBody::Unknown),
    ])
    .await;
    follower.sync_once().await.unwrap();
    let boxes = store.mailboxes("box").unwrap();
    assert_eq!((boxes[0].total, boxes[0].unread), (3, 2));
    assert!(store.message("box", &id).unwrap().is_none());
    assert_eq!(store.checkpoint("box").unwrap(), 12);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unbounded_limit_is_capped() {
    let j = Journal::new();
    let mut events = vec![mailbox("INBOX", None)];
    for (n, name) in ["plain.eml", "multipart.eml", "parent.eml"]
        .iter()
        .enumerate()
    {
        events.push(
            j.added("INBOX", &n.to_string(), &fixture(name), n as i64)
                .await,
        );
    }
    j.append(events).await;
    let dir = tempfile::tempdir().unwrap();
    let (store, follower) = j.view(&dir, "view.sqlite");
    follower.sync_once().await.unwrap();
    assert_eq!(
        store.messages("box", None, None, usize::MAX).unwrap().len(),
        3
    );
    assert_eq!(
        store.threads("box", None, None, usize::MAX).unwrap().len(),
        3
    );
    assert_eq!(store.messages("box", None, None, 2).unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn compacted_journal_is_rebuilt_from_the_snapshot() {
    let j = Journal::new();
    let plain = fixture("plain.eml");
    let multi = fixture("multipart.eml");
    let parent = fixture("parent.eml");
    let reply = fixture("reply.eml");
    j.append(vec![
        mailbox("INBOX", Some(MailboxRole::Inbox)),
        j.added("INBOX", "1", &plain, 1_000).await,
        j.added("INBOX", "2", &multi, 2_000).await,
    ])
    .await;
    j.append(vec![
        event(EventBody::MessageRemoved {
            mailbox: "INBOX".into(),
            item: item("1"),
        }),
        j.added("INBOX", "3", &parent, 3_000).await,
    ])
    .await;

    let dir = tempfile::tempdir().unwrap();
    let (old_store, old_follower) = j.view(&dir, "old.sqlite");
    old_follower.sync_once().await.unwrap();
    assert_eq!(old_store.checkpoint("box").unwrap(), 5);
    assert!(old_store.tip("box").unwrap().is_some());

    assert_eq!(j.snapshot_and_compact().await, 5);
    assert!(matches!(
        j.storage.log.read(&t(), &a(), Seq(1), 10).await,
        Err(StorageError::Compacted { .. })
    ));
    j.append(vec![j.added("INBOX", "4", &reply, 4_000).await])
        .await;

    let (store, follower) = j.view(&dir, "fresh.sqlite");
    follower.sync_once().await.unwrap();
    assert_eq!(store.checkpoint("box").unwrap(), 6);
    let subjects: Vec<String> = store
        .messages("box", None, None, 50)
        .unwrap()
        .into_iter()
        .map(|m| m.subject.unwrap())
        .collect();
    assert_eq!(
        subjects,
        vec!["Re: Lunch on Friday", "Lunch on Friday", "Seating plan"]
    );
    assert_eq!(store.threads("box", None, None, 50).unwrap()[0].count, 2);
    assert_eq!(
        store.mailboxes("box").unwrap()[0].role.as_deref(),
        Some("inbox")
    );

    old_follower.sync_once().await.unwrap();
    assert_eq!(
        old_store.checkpoint("box").unwrap(),
        6,
        "a follower past the snapshot reads on without the compacted segments"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn calendars_and_contacts_through_a_rebuild() {
    let j = Journal::new();
    let ics = fixture("event.ics");
    let allday = fixture("allday.ics");
    let vcf = fixture("contact.vcf");
    let google = fixture("google-event.json");
    j.append(vec![
        collection("/cal/home/", CollectionKind::Calendar, "Home"),
        collection("/book/", CollectionKind::AddressBook, "Contacts"),
        j.object("/cal/home/", "/cal/home/swap.ics", "text/calendar", &ics)
            .await,
        j.object(
            "/cal/home/",
            "/cal/home/closed.ics",
            "text/calendar",
            &allday,
        )
        .await,
        j.object(
            "primary",
            "seedexchange01",
            "application/json; profile=google-calendar-event",
            &google,
        )
        .await,
        j.object("/book/", "/book/jordan.vcf", "text/vcard", &vcf)
            .await,
    ])
    .await;

    let dir = tempfile::tempdir().unwrap();
    let (store, follower) = j.view(&dir, "view.sqlite");
    follower.sync_once().await.unwrap();

    let cols = store.collections("box").unwrap();
    let names: Vec<&str> = cols.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["Contacts", "Home", "primary"]);
    assert_eq!(cols[1].count, 2);

    let page = v(&store
        .objects("box", "/cal/home/", None, Range::default(), 1)
        .unwrap());
    assert_eq!(page[0]["item"], "/cal/home/closed.ics");
    assert_eq!(page[0]["all_day"], true);
    assert_eq!(page[0]["format"], "icalendar");
    let page = v(&store
        .objects(
            "box",
            "/cal/home/",
            Some("/cal/home/closed.ics"),
            Range::default(),
            1,
        )
        .unwrap());
    let swap = &page[0];
    assert_eq!(swap["summary"], "Plant swap, garden shed");
    assert_eq!(swap["recurring"], true);
    assert_eq!(swap["version"], "etag-/cal/home/swap.ics");
    assert_eq!(
        swap["attendees"],
        json!(["sam@example.org", "lee@example.com"])
    );
    assert!(
        store
            .objects(
                "box",
                "/cal/home/",
                Some("/cal/home/swap.ics"),
                Range::default(),
                1
            )
            .unwrap()
            .is_empty()
    );

    let dec24 = 1_798_070_400_000i64;
    let ranged = Range {
        from: Some(dec24),
        to: Some(dec24 + 86_400_000),
    };
    assert_eq!(
        store
            .objects("box", "/cal/home/", None, ranged, 50)
            .unwrap()
            .len(),
        2
    );
    let before = Range {
        from: Some(0),
        to: Some(1000),
    };
    assert!(
        store
            .objects("box", "/cal/home/", None, before, 50)
            .unwrap()
            .is_empty()
    );

    let google_page = v(&store
        .objects("box", "primary", None, Range::default(), 50)
        .unwrap());
    assert_eq!(google_page[0]["format"], "google_event");
    assert_eq!(google_page[0]["summary"], "Seed exchange");

    let card = BlobHash::of(&vcf).to_string();
    let detail = v(&store.object("box", &card).unwrap().unwrap());
    assert_eq!(detail["full_name"], "Jordan Example");
    assert_eq!(detail["kind"], "contact");
    assert_eq!(
        detail["placements"],
        json!([{"collection": "/book/", "item": "/book/jordan.vcf", "version": "etag-/book/jordan.vcf"}])
    );
    let raw = j
        .storage
        .blobs
        .get(&t(), &BlobHash::of(&vcf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(raw.as_ref(), vcf.as_slice());

    let q = crate::fts_query("jordan@example.com").unwrap();
    assert_eq!(
        v(&store.search_contacts("box", &q, 20).unwrap())[0]["id"],
        card
    );
    let q = crate::fts_query("greenh*").unwrap();
    assert_eq!(store.search_contacts("box", &q, 20).unwrap().len(), 1);
    assert!(!store.has_collection("box", "nope").unwrap());
    assert!(
        store
            .object("box", &BlobHash::of(b"x").to_string())
            .unwrap()
            .is_none()
    );

    j.append(vec![event(EventBody::ObjectRemoved {
        collection: "/cal/home/".into(),
        item: item("/cal/home/closed.ics"),
    })])
    .await;
    j.snapshot_and_compact().await;
    let (fresh, follower) = j.view(&dir, "fresh.sqlite");
    follower.sync_once().await.unwrap();
    assert_eq!(fresh.checkpoint("box").unwrap(), 7);
    let cols = fresh.collections("box").unwrap();
    assert_eq!((cols[1].name.as_str(), cols[1].count), ("Home", 1));
    let q = crate::fts_query("jordan").unwrap();
    assert_eq!(fresh.search_contacts("box", &q, 20).unwrap().len(), 1);
}

async fn eventually(what: &str, check: impl Fn() -> bool) {
    for _ in 0..200 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test(flavor = "multi_thread")]
async fn signal_hints_drive_reads_without_polling() {
    let j = Journal::new();
    let plain = fixture("plain.eml");
    let multi = fixture("multipart.eml");
    let parent = fixture("parent.eml");
    j.append(vec![
        mailbox("INBOX", None),
        j.added("INBOX", "1", &plain, 1_000).await,
    ])
    .await;
    let dir = tempfile::tempdir().unwrap();
    let (store, follower) = j.view(&dir, "view.sqlite");
    let follower = follower.with_signal(j.signal.clone());
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let hour = Duration::from_secs(3600);
    let run = tokio::spawn(follower.run(
        Timing {
            poll: hour,
            safety: hour,
        },
        stop_rx,
    ));
    eventually("the first round", || store.checkpoint("box").unwrap() == 2).await;

    j.append(vec![j.added("INBOX", "2", &multi, 2_000).await])
        .await;
    j.hint().await;
    eventually("a hinted read", || store.checkpoint("box").unwrap() == 3).await;
    j.append(vec![j.added("INBOX", "3", &parent, 3_000).await])
        .await;
    j.hint().await;
    eventually("a second hinted read", || {
        store.checkpoint("box").unwrap() == 4
    })
    .await;

    stop_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_signal_accounts_are_polled() {
    let j = Journal::new();
    let plain = fixture("plain.eml");
    let multi = fixture("multipart.eml");
    j.append(vec![j.added("INBOX", "1", &plain, 1_000).await])
        .await;
    let dir = tempfile::tempdir().unwrap();
    let (store, follower) = j.view(&dir, "view.sqlite");
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let run = tokio::spawn(follower.run(
        Timing {
            poll: Duration::from_millis(50),
            safety: Duration::from_secs(3600),
        },
        stop_rx,
    ));
    eventually("the first round", || store.checkpoint("box").unwrap() == 1).await;
    j.append(vec![j.added("INBOX", "2", &multi, 2_000).await])
        .await;
    eventually("a polled read", || store.checkpoint("box").unwrap() == 2).await;
    stop_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn only_the_chosen_accounts_are_followed() {
    let j = Journal::new();
    let plain = fixture("plain.eml");
    j.append(vec![j.added("INBOX", "1", &plain, 1_000).await])
        .await;
    let dir = tempfile::tempdir().unwrap();
    let (store, follower) = j.view(&dir, "view.sqlite");
    let follower = follower.with_accounts(BTreeSet::from([AccountId::new("other").unwrap()]));
    follower.sync_once().await.unwrap();
    assert!(!store.has_account("box").unwrap());
}

fn integrity(r: Result<(), FollowError>) -> IntegrityError {
    match r {
        Err(FollowError::Storage(StorageError::Integrity(e))) => e,
        other => panic!("expected an integrity error, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tampered_segment_is_refused_and_nothing_is_applied() {
    let j = Journal::new();
    let plain = fixture("plain.eml");
    j.append(vec![
        mailbox("INBOX", None),
        j.added("INBOX", "1", &plain, 1_000).await,
    ])
    .await;
    let key = j.keys("log").await.remove(0);
    let (bytes, version) = j.objects.get(&key).await.unwrap().unwrap();
    let mut flipped = bytes.to_vec();
    let at = flipped.len() / 2;
    flipped[at] ^= 0x01;
    j.objects
        .put(&key, Bytes::from(flipped), Expect::Version(version))
        .await
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let (store, follower) = j.view(&dir, "view.sqlite");
    let e = integrity(follower.sync_account(&a()).await);
    assert!(matches!(e, IntegrityError::HashMismatch { .. }), "{e:?}");
    assert_eq!(store.checkpoint("box").unwrap(), 0);
    assert!(store.mailboxes("box").unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rolled_back_head_is_refused() {
    let j = Journal::new();
    let plain = fixture("plain.eml");
    let multi = fixture("multipart.eml");
    j.append(vec![j.added("INBOX", "1", &plain, 1_000).await])
        .await;
    let head_key = ObjectKey::account(&t(), "heads", &a()).unwrap();
    let (old_head, _) = j.objects.get(&head_key).await.unwrap().unwrap();
    j.append(vec![j.added("INBOX", "2", &multi, 2_000).await])
        .await;

    let dir = tempfile::tempdir().unwrap();
    let (store, follower) = j.view(&dir, "view.sqlite");
    follower.sync_once().await.unwrap();
    assert_eq!(store.checkpoint("box").unwrap(), 2);

    j.objects
        .put(&head_key, old_head, Expect::Any)
        .await
        .unwrap();
    let (_, follower) = j.view(&dir, "view.sqlite");
    let e = integrity(follower.sync_account(&a()).await);
    assert!(matches!(e, IntegrityError::Rollback { .. }), "{e:?}");
    assert_eq!(store.checkpoint("box").unwrap(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_swapped_history_is_refused_as_a_fork() {
    let honest = Journal::new();
    let plain = fixture("plain.eml");
    let multi = fixture("multipart.eml");
    let parent = fixture("parent.eml");
    honest
        .append(vec![honest.added("INBOX", "1", &plain, 1_000).await])
        .await;
    let dir = tempfile::tempdir().unwrap();
    let (store, follower) = honest.view(&dir, "view.sqlite");
    follower.sync_once().await.unwrap();
    assert_eq!(store.checkpoint("box").unwrap(), 1);

    let forged = Journal::new();
    forged
        .append(vec![forged.added("INBOX", "1", &multi, 1_000).await])
        .await;
    forged
        .append(vec![forged.added("INBOX", "2", &parent, 2_000).await])
        .await;
    let follower = Follower::new(forged.storage.clone(), t(), store.clone());
    let e = integrity(follower.sync_account(&a()).await);
    assert!(matches!(e, IntegrityError::Fork { .. }), "{e:?}");
    assert_eq!(store.checkpoint("box").unwrap(), 1);
    assert_eq!(
        store.messages("box", None, None, 10).unwrap()[0].id,
        BlobHash::of(&plain).to_string()
    );
}

async fn forge_snapshot(j: &Journal, seq: u64, bytes: &[u8]) {
    let mut snap = Snapshot::empty(a());
    snap.apply(&mailbox("Forged", None));
    let mut added = j.added("Forged", "f", bytes, 9_000).await;
    added.seq = Seq(1);
    snap.apply(&added);
    snap.seq = Seq(seq);
    let scratch = Journal::new();
    scratch
        .append((0..seq).map(|i| mailbox(&format!("m{i}"), None)).collect())
        .await;
    scratch
        .storage
        .log
        .put_snapshot(&t(), &a(), &snap)
        .await
        .unwrap();
    for key in scratch.keys("snapshots").await {
        let (bytes, _) = scratch.objects.get(&key).await.unwrap().unwrap();
        j.objects.put(&key, bytes, Expect::Any).await.unwrap();
    }
}

async fn drop_segment_starting_at(j: &Journal, start: u64) {
    let prefix = format!("{start:020}-");
    let key = j
        .keys("log")
        .await
        .into_iter()
        .find(|k| {
            k.to_string()
                .rsplit('/')
                .next()
                .unwrap()
                .starts_with(&prefix)
        })
        .expect("segment present");
    j.objects.delete(&key, Expect::Any).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_segment_and_an_older_snapshot_cannot_roll_a_follower_back() {
    let j = Journal::new();
    let plain = fixture("plain.eml");
    let multi = fixture("multipart.eml");
    let parent = fixture("parent.eml");
    j.append(vec![
        mailbox("INBOX", None),
        j.added("INBOX", "1", &plain, 1_000).await,
    ])
    .await;
    j.append(vec![j.added("INBOX", "2", &multi, 2_000).await])
        .await;
    let dir = tempfile::tempdir().unwrap();
    let (store, follower) = j.view(&dir, "view.sqlite");
    follower.sync_once().await.unwrap();
    assert_eq!(store.checkpoint("box").unwrap(), 3);
    let tip = store.tip("box").unwrap();
    assert!(tip.is_some());

    j.append(vec![j.added("INBOX", "3", &parent, 3_000).await])
        .await;
    drop_segment_starting_at(&j, 4).await;
    forge_snapshot(&j, 1, &parent).await;

    let e = integrity(follower.sync_account(&a()).await);
    assert!(matches!(e, IntegrityError::Rollback { .. }), "{e:?}");
    assert_eq!(store.checkpoint("box").unwrap(), 3);
    assert_eq!(store.tip("box").unwrap(), tip);
    let boxes: Vec<String> = store
        .mailboxes("box")
        .unwrap()
        .into_iter()
        .map(|m| m.id)
        .collect();
    assert_eq!(boxes, vec!["INBOX"]);
    assert_eq!(store.messages("box", None, None, 10).unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_snapshot_past_the_attested_head_is_refused() {
    let j = Journal::new();
    let plain = fixture("plain.eml");
    let multi = fixture("multipart.eml");
    j.append(vec![
        mailbox("INBOX", None),
        j.added("INBOX", "1", &plain, 1_000).await,
    ])
    .await;
    drop_segment_starting_at(&j, 1).await;
    forge_snapshot(&j, 50, &multi).await;

    let dir = tempfile::tempdir().unwrap();
    let (store, follower) = j.view(&dir, "view.sqlite");
    let e = integrity(follower.sync_account(&a()).await);
    assert!(matches!(e, IntegrityError::Mismatch { .. }), "{e:?}");
    assert_eq!(store.checkpoint("box").unwrap(), 0);
    assert!(store.mailboxes("box").unwrap().is_empty());
}

struct Refuse;

#[async_trait]
impl HeadAttestor for Refuse {
    async fn attest(&self, _: &JournalHead) -> Result<Option<Bytes>, StorageError> {
        Ok(None)
    }

    async fn verify(&self, _: &JournalHead, _: Option<&[u8]>) -> Result<(), StorageError> {
        Err(IntegrityError::Attestation("refused in tests".into()).into())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_head_the_attestor_refuses_is_never_read() {
    let j = Journal::new();
    let plain = fixture("plain.eml");
    j.append(vec![j.added("INBOX", "1", &plain, 1_000).await])
        .await;
    let dir = tempfile::tempdir().unwrap();
    let (store, follower) = j.view(&dir, "view.sqlite");
    let follower = follower.with_attestor(Arc::new(Refuse));
    let e = integrity(follower.sync_account(&a()).await);
    assert!(matches!(e, IntegrityError::Attestation(_)), "{e:?}");
    assert_eq!(store.checkpoint("box").unwrap(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_corrupt_or_oversized_original_is_kept_as_unavailable() {
    let j = Journal::new();
    let plain = fixture("plain.eml");
    let multi = fixture("multipart.eml");
    let added = j.added("INBOX", "1", &plain, 1_000).await;
    let blob_key = {
        let prefix = ObjectKey::tenant(&t());
        let mut found = None;
        let mut after: Option<ObjectKey> = None;
        loop {
            let keys = j.objects.list(&prefix, after.as_ref(), 100).await.unwrap();
            if keys.is_empty() {
                break;
            }
            for k in &keys {
                if k.last() == BlobHash::of(&plain).to_string() {
                    found = Some(k.clone());
                }
            }
            after = keys.last().cloned();
        }
        found.expect("the blob is stored")
    };
    j.objects
        .put(
            &blob_key,
            Bytes::from_static(b"not the original"),
            Expect::Any,
        )
        .await
        .unwrap();
    j.append(vec![
        mailbox("INBOX", None),
        added,
        j.added("INBOX", "2", &multi, 2_000).await,
    ])
    .await;
    let dir = tempfile::tempdir().unwrap();
    let (store, follower) = j.view(&dir, "view.sqlite");
    let follower = follower.with_max_blob_bytes(plain.len().max(16) as u64);
    follower.sync_once().await.unwrap();
    assert_eq!(store.checkpoint("box").unwrap(), 3);
    let all = store.messages("box", None, None, 10).unwrap();
    assert_eq!(all.len(), 2);
    assert!(all.iter().all(|m| !m.available));
}
