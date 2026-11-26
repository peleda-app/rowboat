use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use baton_lease::Leases;
use bytes::Bytes;
use skein_core::coordination;
use skein_core::{
    AccountHealth, AccountId, Command, CommandBody, CommandId, Event, EventBody, Flags, Seq,
    TenantId, Timestamp,
};
use skein_mail::testing::{FakeMail, ServerControl};
use skein_mail::{MailError, MailProvider};
use skein_storage::{ControlStore, Expect, ObjectControl, Objects, Storage, StorageError, Version};
use skein_storage_memory::MemoryObjects;

use crate::test_support::{
    ManualClock, control_leases, engine_with, profile, signal, single_leases,
};
use crate::{AccountConfig, AccountDirectory, AccountEntry, Engine, EngineError, RunConfig, run};

fn tenant() -> TenantId {
    TenantId::new("t").unwrap()
}

fn account(name: &str) -> AccountId {
    AccountId::new(name).unwrap()
}

fn engine_over(storage: Storage, leases: Arc<dyn Leases>, node: &str) -> Engine {
    engine_with(storage, leases, node)
}

fn single() -> (Engine, Storage) {
    let storage = Storage::over(Arc::new(MemoryObjects::new()));
    (engine_over(storage.clone(), single_leases(), "n1"), storage)
}

async fn all_events(storage: &Storage, acc: &AccountId) -> Vec<Event> {
    storage
        .log
        .read(&tenant(), acc, Seq(1), 100_000)
        .await
        .unwrap()
}

fn count(events: &[Event], pred: impl Fn(&EventBody) -> bool) -> usize {
    events.iter().filter(|e| pred(&e.body)).count()
}

fn added(b: &EventBody) -> bool {
    matches!(b, EventBody::MessageAdded { .. })
}

#[tokio::test]
async fn first_sync_journals_every_message_once_with_its_bytes() {
    let (engine, storage) = single();
    let fake = FakeMail::new();
    fake.fill("INBOX", 120, 800);
    let mut config = AccountConfig::new(tenant(), account("a"));
    config.page = 50;
    let report = engine.sync_account(&config, &fake).await.unwrap();
    assert_eq!(report.mailboxes[0].added, 120);

    let events = all_events(&storage, &account("a")).await;
    assert_eq!(count(&events, added), 120);
    assert_eq!(
        count(&events, |b| matches!(b, EventBody::FirstSyncCompleted)),
        1
    );
    assert_eq!(
        count(&events, |b| matches!(b, EventBody::MailboxUpserted { .. })),
        1
    );
    for e in &events {
        if let EventBody::MessageAdded { blob, size, .. } = &e.body {
            let bytes = storage.blobs.get(&tenant(), blob).await.unwrap().unwrap();
            assert_eq!(bytes.len() as u64, *size);
        }
    }

    let again = engine.sync_account(&config, &fake).await.unwrap();
    assert_eq!(again.events, 0, "nothing changed, nothing journaled");
    assert_eq!(
        all_events(&storage, &account("a")).await.len(),
        events.len()
    );
}

#[tokio::test]
async fn incremental_changes_and_resets_are_journaled() {
    let (engine, storage) = single();
    let fake = FakeMail::new();
    let a = b"From: a@example.com\r\n\r\na\r\n";
    let b = b"From: b@example.com\r\n\r\nb\r\n";
    fake.add("INBOX", a, Flags::default()).await;
    fake.add("INBOX", b, Flags::default()).await;
    let config = AccountConfig::new(tenant(), account("a"));
    engine.sync_account(&config, &fake).await.unwrap();

    fake.remove("INBOX", a).await;
    fake.set_flags("INBOX", b, Flags::new(["\\Seen"])).await;
    fake.add(
        "INBOX",
        b"From: c@example.com\r\n\r\nc\r\n",
        Flags::default(),
    )
    .await;
    let r = engine.sync_account(&config, &fake).await.unwrap();
    assert_eq!(
        (
            r.mailboxes[0].added,
            r.mailboxes[0].removed,
            r.mailboxes[0].changed
        ),
        (1, 1, 1)
    );

    fake.invalidate("INBOX").await;
    let r = engine.sync_account(&config, &fake).await.unwrap();
    assert!(r.mailboxes[0].reset);
    let events = all_events(&storage, &account("a")).await;
    assert_eq!(
        count(&events, |b| matches!(b, EventBody::ResyncRequired { .. })),
        1
    );
}

struct FailCursorPut {
    inner: Arc<dyn ControlStore>,
    remaining_ok: AtomicUsize,
}

#[async_trait]
impl ControlStore for FailCursorPut {
    async fn get(&self, t: &TenantId, p: &str) -> Result<Option<(Bytes, Version)>, StorageError> {
        self.inner.get(t, p).await
    }
    async fn put(
        &self,
        t: &TenantId,
        p: &str,
        v: Bytes,
        e: Expect,
    ) -> Result<Version, StorageError> {
        if p.starts_with("cursors/") {
            let left = self.remaining_ok.load(Ordering::SeqCst);
            if left == 0 {
                self.remaining_ok.store(usize::MAX, Ordering::SeqCst);
                return Err(StorageError::backend(
                    "simulated crash before the cursor was saved",
                ));
            }
            if left != usize::MAX {
                self.remaining_ok.store(left - 1, Ordering::SeqCst);
            }
        }
        self.inner.put(t, p, v, e).await
    }
    async fn delete(&self, t: &TenantId, p: &str, e: Expect) -> Result<(), StorageError> {
        self.inner.delete(t, p, e).await
    }
    async fn list(
        &self,
        t: &TenantId,
        p: &str,
        a: Option<&str>,
        l: usize,
    ) -> Result<Vec<String>, StorageError> {
        self.inner.list(t, p, a, l).await
    }
    async fn purge(&self, t: &TenantId) -> Result<u64, StorageError> {
        self.inner.purge(t).await
    }
}

#[tokio::test]
async fn a_crash_between_journal_and_cursor_never_duplicates_events() {
    let objects: Arc<dyn Objects> = Arc::new(MemoryObjects::new());
    let mut storage = Storage::over(objects.clone());
    storage.control = Arc::new(FailCursorPut {
        inner: Arc::new(ObjectControl::new(objects)),
        remaining_ok: AtomicUsize::new(1),
    });
    let engine = engine_over(storage.clone(), single_leases(), "n1");
    let fake = FakeMail::new();
    fake.fill("INBOX", 100, 300);
    let mut config = AccountConfig::new(tenant(), account("a"));
    config.page = 30;
    assert!(
        engine.sync_account(&config, &fake).await.is_err(),
        "the second batch crashes"
    );
    let report = engine.sync_account(&config, &fake).await.unwrap();
    assert_eq!(
        report.mailboxes[0].replayed, 30,
        "the batch journaled before the crash is dropped"
    );
    let events = all_events(&storage, &account("a")).await;
    assert_eq!(count(&events, added), 100, "every message exactly once");
}

#[tokio::test]
async fn a_node_that_lost_the_account_cannot_write() {
    let objects: Arc<dyn Objects> = Arc::new(MemoryObjects::new());
    let storage = Storage::over(objects.clone());
    let clock = ManualClock::new();
    let (leases, liveness) = control_leases(&storage, 30_000, Some(clock.clock()));
    let nodes = coordination::group(&tenant());
    liveness
        .heartbeat(&nodes, &profile("n1"), clock.now())
        .await
        .unwrap();
    liveness
        .heartbeat(&nodes, &profile("n2"), clock.now())
        .await
        .unwrap();
    let e1 = engine_over(storage.clone(), leases.clone(), "n1");
    let e2 = engine_over(storage.clone(), leases.clone(), "n2");
    let fake = FakeMail::new();
    fake.fill("INBOX", 10, 200);
    let config = AccountConfig::new(tenant(), account("a"));

    e1.sync_account(&config, &fake).await.unwrap();
    assert!(matches!(
        e2.sync_account(&config, &fake).await,
        Err(EngineError::NotOwner)
    ));
    clock.advance(30_001);
    liveness
        .heartbeat(&nodes, &profile("n2"), clock.now())
        .await
        .unwrap();
    fake.fill("INBOX", 5, 200);
    e2.sync_account(&config, &fake).await.unwrap();
    liveness
        .heartbeat(&nodes, &profile("n1"), clock.now())
        .await
        .unwrap();
    fake.fill("INBOX", 5, 200);
    assert!(matches!(
        e1.sync_account(&config, &fake).await,
        Err(EngineError::NotOwner)
    ));
    let events = all_events(&storage, &account("a")).await;
    assert_eq!(
        count(&events, added),
        15,
        "the old owner wrote nothing after losing the account"
    );
}

fn command(acc: &AccountId, body: CommandBody) -> Command {
    Command {
        id: CommandId::generate(),
        account: acc.clone(),
        created_at: Timestamp::now(),
        trace: Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".into()),
        body,
    }
}

#[tokio::test]
async fn commands_run_once_and_record_their_outcome() {
    let (engine, storage) = single();
    let fake = FakeMail::new();
    let a = b"From: a@example.com\r\n\r\na\r\n";
    fake.add("INBOX", a, Flags::default()).await;
    fake.create_mailbox("Archive").await;
    let acc = account("a");
    let config = AccountConfig::new(tenant(), acc.clone());
    engine.sync_account(&config, &fake).await.unwrap();
    let item = all_events(&storage, &acc)
        .await
        .into_iter()
        .find_map(|e| match e.body {
            EventBody::MessageAdded { item, .. } => Some(item),
            _ => None,
        })
        .unwrap();

    let flag = command(
        &acc,
        CommandBody::SetFlags {
            mailbox: "INBOX".into(),
            items: vec![item.clone()],
            add: Flags::new(["\\Seen"]),
            remove: Flags::default(),
        },
    );
    storage.commands.submit(&tenant(), &flag).await.unwrap();
    let r = engine.run_commands(&config, &fake).await.unwrap();
    assert_eq!(r.applied, 1);
    assert_eq!(
        fake.flags_of("INBOX", a).await.unwrap(),
        Flags::new(["\\Seen"])
    );
    let events = all_events(&storage, &acc).await;
    let result = events
        .iter()
        .find(|e| e.origin.as_ref() == Some(&flag.id))
        .unwrap();
    assert!(matches!(result.body, EventBody::WriteApplied { .. }));
    assert_eq!(result.trace, flag.trace, "the trace follows the command");
    assert!(
        storage
            .commands
            .pending(&tenant(), &acc, 10)
            .await
            .unwrap()
            .is_empty()
    );

    let mv = command(
        &acc,
        CommandBody::Move {
            from: "INBOX".into(),
            to: "Archive".into(),
            items: vec![item],
        },
    );
    storage.commands.submit(&tenant(), &mv).await.unwrap();
    storage
        .control
        .put(
            &tenant(),
            &format!("started/{acc}/{}", mv.id),
            Bytes::from_static(b"started"),
            Expect::Any,
        )
        .await
        .unwrap();
    let r = engine.run_commands(&config, &fake).await.unwrap();
    assert_eq!(
        r.uncertain, 1,
        "a move that may have run before a crash is not run again"
    );
    assert!(
        fake.flags_of("INBOX", a).await.is_some(),
        "the message did not move twice"
    );
}

#[tokio::test]
async fn failed_sign_in_is_reported_once_as_health() {
    let (engine, storage) = single();
    let fake = FakeMail::new();
    let config = AccountConfig::new(tenant(), account("a"));
    engine.sync_account(&config, &fake).await.unwrap();
    for _ in 0..3 {
        fake.fail_next(MailError::Auth);
        assert!(engine.sync_account(&config, &fake).await.is_err());
    }
    let events = all_events(&storage, &account("a")).await;
    let reauth = count(&events, |b| {
        matches!(
            b,
            EventBody::AccountHealthChanged {
                health: AccountHealth::ReauthRequired
            }
        )
    });
    assert_eq!(reauth, 1);
    engine.sync_account(&config, &fake).await.unwrap();
    let events = all_events(&storage, &account("a")).await;
    assert!(
        matches!(
            events.last().unwrap().body,
            EventBody::AccountHealthChanged {
                health: AccountHealth::Healthy
            } | EventBody::FirstSyncCompleted
        ) || count(&events, |b| matches!(
            b,
            EventBody::AccountHealthChanged {
                health: AccountHealth::Healthy
            }
        )) == 2
    );
}

struct Directory(Vec<AccountEntry>);

#[async_trait]
impl AccountDirectory for Directory {
    async fn accounts(&self) -> Result<Vec<AccountEntry>, EngineError> {
        Ok(self.0.clone())
    }
}

#[tokio::test]
async fn two_nodes_split_accounts_and_each_account_has_one_writer() {
    let objects: Arc<dyn Objects> = Arc::new(MemoryObjects::new());
    let storage = Storage::over(objects.clone());
    let mut entries = Vec::new();
    for i in 0..8 {
        let fake = FakeMail::new();
        fake.fill("INBOX", 5, 200);
        let provider: Arc<dyn MailProvider> = Arc::new(fake);
        entries.push(AccountEntry {
            config: AccountConfig::new(tenant(), account(&format!("acc{i}"))),
            provider,
            pim: None,
        });
    }
    let directory = Arc::new(Directory(entries));
    let (tx, _) = tokio::sync::broadcast::channel::<()>(1);
    let mut handles = Vec::new();
    let mut observer = None;
    for n in ["n1", "n2"] {
        let (leases, liveness) = control_leases(&storage, 5_000, None);
        observer.get_or_insert(leases.clone());
        let engine = engine_over(storage.clone(), leases, n);
        let mut config = RunConfig::new(liveness);
        config.heartbeat = Duration::from_millis(50);
        config.interval = Duration::from_millis(100);
        let mut rx = tx.subscribe();
        let directory = directory.clone();
        handles.push(tokio::spawn(async move {
            run(engine, directory, config, async move {
                let _ = rx.recv().await;
            })
            .await
        }));
    }
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let holder = |acc: AccountId| {
        let leases = observer.clone().unwrap();
        async move {
            leases
                .holder(
                    &coordination::group(&tenant()),
                    &coordination::lease_key(&acc),
                )
                .await
                .unwrap()
        }
    };
    let mut owners = std::collections::HashSet::new();
    for i in 0..8 {
        if let Some(lease) = holder(account(&format!("acc{i}"))).await {
            assert!(lease.takeover.is_none());
            owners.insert(lease.node);
        }
    }
    assert_eq!(owners.len(), 2, "both nodes got accounts");
    let _ = tx.send(());
    for h in handles {
        h.await.unwrap();
    }
    for i in 0..8 {
        let acc = account(&format!("acc{i}"));
        let events = all_events(&storage, &acc).await;
        assert_eq!(count(&events, added), 5, "acc{i} journaled once");
        assert!(holder(acc).await.is_none(), "acc{i} released on shutdown");
    }
}

#[tokio::test]
async fn snapshots_fold_the_journal_and_compaction_keeps_reads_honest() {
    let (engine, storage) = single();
    let fake = FakeMail::new();
    fake.fill("INBOX", 40, 200);
    let acc = account("a");
    let config = AccountConfig::new(tenant(), acc.clone());
    engine.sync_account(&config, &fake).await.unwrap();

    assert_eq!(
        engine
            .snapshot_account(&tenant(), &acc, 1000)
            .await
            .unwrap(),
        None,
        "too few new events"
    );
    let seq = engine
        .snapshot_account(&tenant(), &acc, 1)
        .await
        .unwrap()
        .unwrap();
    let snap = storage
        .log
        .latest_snapshot(&tenant(), &acc)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(snap.seq, seq);
    assert_eq!(snap.message_count(), 40);

    assert_eq!(
        engine
            .compact_account(&tenant(), &acc, Duration::from_secs(3600))
            .await
            .unwrap(),
        0,
        "a fresh snapshot keeps the events it covers"
    );
    let removed = engine
        .compact_account(&tenant(), &acc, Duration::ZERO)
        .await
        .unwrap();
    assert!(removed > 0);
    assert!(matches!(
        storage.log.read(&tenant(), &acc, Seq(1), 10).await,
        Err(StorageError::Compacted { .. })
    ));

    fake.fill("INBOX", 3, 200);
    let mut config_small = config.clone();
    config_small.page = 2;
    engine.sync_account(&config_small, &fake).await.unwrap();
    let next = engine
        .snapshot_account(&tenant(), &acc, 1)
        .await
        .unwrap()
        .unwrap();
    assert!(next > seq);
    let snap = storage
        .log
        .latest_snapshot(&tenant(), &acc)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        snap.message_count(),
        43,
        "a snapshot continues from the previous one after compaction"
    );
}

#[tokio::test]
async fn refetch_downloads_a_message_again() {
    let (engine, storage) = single();
    let fake = FakeMail::new();
    let bytes = b"From: a@example.com\r\n\r\nrefetch me\r\n";
    fake.add("INBOX", bytes, Flags::default()).await;
    let acc = account("a");
    let config = AccountConfig::new(tenant(), acc.clone());
    engine.sync_account(&config, &fake).await.unwrap();
    let item = all_events(&storage, &acc)
        .await
        .into_iter()
        .find_map(|e| match e.body {
            EventBody::MessageAdded { item, .. } => Some(item),
            _ => None,
        })
        .unwrap();
    let objects: Arc<dyn Objects> = Arc::new(MemoryObjects::new());
    let fresh = Storage::over(objects);
    let mut emptied = storage.clone();
    emptied.blobs = fresh.blobs.clone();
    let engine2 = engine_over(emptied, single_leases(), "n2");
    let cmd = command(
        &acc,
        CommandBody::Refetch {
            mailbox: "INBOX".into(),
            item: item.clone(),
        },
    );
    storage.commands.submit(&tenant(), &cmd).await.unwrap();
    assert_eq!(
        engine2.run_commands(&config, &fake).await.unwrap().applied,
        1
    );
    assert_eq!(
        fresh
            .blobs
            .get(&tenant(), &skein_core::BlobHash::of(bytes))
            .await
            .unwrap()
            .unwrap(),
        &bytes[..],
        "the blob is back"
    );
    let gone = command(
        &acc,
        CommandBody::Refetch {
            mailbox: "INBOX".into(),
            item: skein_core::ItemRef {
                id: "9:9".into(),
                uid: Some(9),
            },
        },
    );
    storage.commands.submit(&tenant(), &gone).await.unwrap();
    assert_eq!(
        engine2.run_commands(&config, &fake).await.unwrap().failed,
        1
    );
}

#[tokio::test]
async fn a_run_pages_past_the_first_hundred_commands() {
    let (engine, storage) = single();
    let fake = FakeMail::new();
    fake.add(
        "INBOX",
        b"From: a@example.com\r\n\r\nx\r\n",
        Flags::default(),
    )
    .await;
    let acc = account("a");
    let config = AccountConfig::new(tenant(), acc.clone());
    engine.sync_account(&config, &fake).await.unwrap();
    for _ in 0..150 {
        let cmd = command(
            &acc,
            CommandBody::SetFlags {
                mailbox: "INBOX".into(),
                items: vec![],
                add: Flags::new(["\\Seen"]),
                remove: Flags::default(),
            },
        );
        storage.commands.submit(&tenant(), &cmd).await.unwrap();
    }
    let r = engine.run_commands(&config, &fake).await.unwrap();
    assert_eq!(r.applied, 150);
    assert!(
        storage
            .commands
            .pending(&tenant(), &acc, 10)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_command_cancelled_before_it_starts_never_runs() {
    let (engine, storage) = single();
    let fake = FakeMail::new();
    let bytes = b"From: a@example.com\r\n\r\nkeep\r\n";
    fake.add("INBOX", bytes, Flags::default()).await;
    let acc = account("a");
    let config = AccountConfig::new(tenant(), acc.clone());
    engine.sync_account(&config, &fake).await.unwrap();
    let item = all_events(&storage, &acc)
        .await
        .into_iter()
        .find_map(|e| match e.body {
            EventBody::MessageAdded { item, .. } => Some(item),
            _ => None,
        })
        .unwrap();
    let del = command(
        &acc,
        CommandBody::Delete {
            mailbox: "INBOX".into(),
            items: vec![item],
            to_trash: false,
        },
    );
    storage.commands.submit(&tenant(), &del).await.unwrap();
    storage
        .control
        .put(
            &tenant(),
            &format!("started/{acc}/{}", del.id),
            Bytes::from_static(b"cancelled"),
            Expect::Absent,
        )
        .await
        .unwrap();
    let r = engine.run_commands(&config, &fake).await.unwrap();
    assert_eq!((r.applied, r.failed, r.uncertain), (0, 0, 0));
    assert!(
        fake.flags_of("INBOX", bytes).await.is_some(),
        "the message was not deleted"
    );
    assert!(
        storage
            .commands
            .pending(&tenant(), &acc, 10)
            .await
            .unwrap()
            .is_empty()
    );
}

struct NoWatch(FakeMail);

#[async_trait]
impl MailProvider for NoWatch {
    async fn connect(&self) -> Result<Box<dyn skein_mail::MailSession>, MailError> {
        self.0.connect().await
    }
}

#[tokio::test]
async fn a_push_hint_wakes_the_worker_without_waiting_for_the_interval() {
    let objects: Arc<dyn Objects> = Arc::new(MemoryObjects::new());
    let storage = Storage::over(objects.clone());
    let (leases, liveness) = control_leases(&storage, 5_000, None);
    let signal = signal();
    let engine = Engine::new(storage.clone(), leases, signal.clone(), profile("n1"));
    let fake = FakeMail::new();
    let provider: Arc<dyn MailProvider> = Arc::new(NoWatch(fake.clone()));
    let acc = account("pushed");
    let directory = Arc::new(Directory(vec![AccountEntry {
        config: AccountConfig::new(tenant(), acc.clone()),
        provider,
        pim: None,
    }]));
    let mut config = RunConfig::new(liveness);
    config.heartbeat = Duration::from_millis(50);
    config.interval = Duration::from_secs(3600);
    let (tx, mut rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(run(engine, directory, config, async move {
        let _ = rx.wait_for(|s| *s).await;
    }));
    tokio::time::sleep(Duration::from_millis(400)).await;
    fake.fill("INBOX", 3, 100);
    signal
        .publish(
            &coordination::group(&tenant()),
            &skein_push::hint_topic(&acc),
            Bytes::from_static(b"1"),
        )
        .await
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let events = all_events(&storage, &acc).await;
        if count(&events, added) == 3 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the hint did not wake the worker"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = tx.send(true);
    handle.await.unwrap();
}

#[tokio::test]
async fn account_events_are_not_repeated_after_a_crash_before_the_state_was_saved() {
    let (engine, storage) = single();
    let fake = FakeMail::new();
    fake.create_mailbox("INBOX").await;
    fake.create_mailbox("Archive").await;
    fake.add("INBOX", b"Subject: one\r\n\r\nx\r\n", Flags::default())
        .await;
    let config = AccountConfig::new(tenant(), account("a"));
    engine.sync_account(&config, &fake).await.unwrap();
    storage
        .control
        .delete(&tenant(), "state/a", Expect::Any)
        .await
        .unwrap();
    engine.sync_account(&config, &fake).await.unwrap();
    let events = all_events(&storage, &account("a")).await;
    let mut keys: Vec<&str> = events.iter().map(|e| e.key.as_str()).collect();
    let all = keys.len();
    keys.sort();
    keys.dedup();
    assert_eq!(keys.len(), all, "no event key appears twice");
    assert_eq!(
        count(&events, |b| matches!(b, EventBody::FirstSyncCompleted)),
        1
    );
    assert_eq!(
        count(&events, |b| matches!(b, EventBody::MailboxUpserted { .. })),
        2
    );
}

#[tokio::test]
async fn capabilities_are_journaled_when_they_change() {
    let (engine, storage) = single();
    let fake = FakeMail::new();
    let config = AccountConfig::new(tenant(), account("a"));
    engine.sync_account(&config, &fake).await.unwrap();
    engine.sync_account(&config, &fake).await.unwrap();
    let events = all_events(&storage, &account("a")).await;
    let caps: Vec<_> = events
        .iter()
        .filter_map(|e| match &e.body {
            EventBody::AccountCapabilities { mail } => Some(mail.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(caps.len(), 1);
    assert!(caps[0].copy && caps[0].trash && caps[0].keywords);
}

#[tokio::test]
async fn a_write_refused_before_it_ran_runs_again_instead_of_turning_uncertain() {
    let (engine, storage) = single();
    let fake = FakeMail::new();
    fake.create_mailbox("Archive").await;
    let config = AccountConfig::new(tenant(), account("a"));
    let command = Command {
        id: CommandId::generate(),
        account: account("a"),
        created_at: Timestamp::now(),
        trace: None,
        body: CommandBody::CreateMailbox {
            path: "Projects".into(),
        },
    };
    storage.commands.submit(&tenant(), &command).await.unwrap();
    fake.fail_next(MailError::Throttled { retry_after: None });
    assert!(engine.run_commands(&config, &fake).await.is_err());
    let report = engine.run_commands(&config, &fake).await.unwrap();
    assert_eq!(report.applied, 1, "{report:?}");
    assert_eq!(report.uncertain, 0);
    let events = all_events(&storage, &account("a")).await;
    assert!(
        events
            .iter()
            .any(|e| matches!(&e.body, EventBody::WriteApplied { command: c } if *c == command.id))
    );
}

#[tokio::test]
async fn status_record_follows_failures_and_recovery() {
    use skein_core::SyncOutcome;
    let (engine, storage) = single();
    let fake = FakeMail::new();
    let config = AccountConfig::new(tenant(), account("a"));
    assert!(
        crate::load_status(&*storage.control, &tenant(), &account("a"))
            .await
            .unwrap()
            .is_none()
    );
    engine.sync_account(&config, &fake).await.unwrap();
    let ok = crate::load_status(&*storage.control, &tenant(), &account("a"))
        .await
        .unwrap()
        .unwrap();
    let mail = ok.mail.clone().unwrap();
    assert_eq!(mail.outcome, SyncOutcome::Ok);
    assert!(mail.last_ok_at.is_some() && mail.last_error_at.is_none());
    assert!(ok.pim.is_none() && ok.send.is_none());

    let (_, version) = storage
        .control
        .get(&tenant(), "status/a")
        .await
        .unwrap()
        .unwrap();
    engine.sync_account(&config, &fake).await.unwrap();
    let (_, again) = storage
        .control
        .get(&tenant(), "status/a")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        version, again,
        "an unchanged outcome is not rewritten within a minute"
    );

    fake.fail_next(MailError::Auth);
    assert!(engine.sync_account(&config, &fake).await.is_err());
    let failed = crate::load_status(&*storage.control, &tenant(), &account("a"))
        .await
        .unwrap()
        .unwrap();
    let mail = failed.mail.clone().unwrap();
    assert_eq!(mail.outcome, SyncOutcome::AuthFailed);
    assert_eq!(mail.error, Some(SyncOutcome::AuthFailed));
    assert!(mail.last_error_at.is_some());
    assert_eq!(failed.health(), Some(AccountHealth::ReauthRequired));

    engine.sync_account(&config, &fake).await.unwrap();
    let back = crate::load_status(&*storage.control, &tenant(), &account("a"))
        .await
        .unwrap()
        .unwrap()
        .mail
        .unwrap();
    assert_eq!(back.outcome, SyncOutcome::Ok);
    assert_eq!(back.error, Some(SyncOutcome::AuthFailed));
    assert!(!back.resync_required);
}

#[tokio::test]
async fn an_older_owner_never_overwrites_the_status() {
    use skein_core::{AccountStatus, FencingToken, SyncOutcome};
    let (engine, storage) = single();
    let newer = AccountStatus {
        fence: FencingToken(u64::MAX),
        ..Default::default()
    };
    storage
        .control
        .put(
            &tenant(),
            "status/a",
            Bytes::from(serde_json::to_vec(&newer).unwrap()),
            Expect::Absent,
        )
        .await
        .unwrap();
    let config = AccountConfig::new(tenant(), account("a"));
    engine
        .record_status(
            &config,
            FencingToken(1),
            crate::status::Area::Mail,
            SyncOutcome::Network,
            false,
        )
        .await;
    let status = crate::load_status(&*storage.control, &tenant(), &account("a"))
        .await
        .unwrap()
        .unwrap();
    assert!(status.mail.is_none());
}

fn lease_name(acc: &AccountId) -> baton_state::RecordName {
    baton_state::RecordName::new(format!("lease/{acc}")).unwrap()
}

#[tokio::test]
async fn a_forged_lease_record_grants_nothing_and_writes_nothing() {
    use baton_state::StateStore as _;
    let storage = Storage::over(Arc::new(MemoryObjects::new()));
    let state = skein_storage::ControlState::new(storage.control.clone());
    let (leases, _) = control_leases(&storage, 5_000, None);
    let engine = engine_over(storage.clone(), leases, "n1");
    let fake = FakeMail::new();
    fake.fill("INBOX", 3, 100);
    let config = AccountConfig::new(tenant(), account("a"));
    engine.sync_account(&config, &fake).await.unwrap();
    let head = storage.log.head(&tenant(), &account("a")).await.unwrap();
    let group = coordination::group(&tenant());
    for forged in [
        &b"{\"v\":1,\"holder\":null,\"fence\":0"[..],
        b"{\"v\":9,\"holder\":null,\"fence\":0,\"takeover\":null,\"reserved\":null,\"seq\":0}",
        b"",
    ] {
        state
            .put(
                &group,
                &lease_name(&account("a")),
                Bytes::copy_from_slice(forged),
                baton_state::Expect::Any,
            )
            .await
            .unwrap();
        fake.fill("INBOX", 1, 100);
        assert!(
            matches!(
                engine.sync_account(&config, &fake).await,
                Err(EngineError::Lease(_))
            ),
            "{}",
            String::from_utf8_lossy(forged)
        );
        assert_eq!(
            storage.log.head(&tenant(), &account("a")).await.unwrap(),
            head,
            "nothing is journaled over a forged lease"
        );
    }
}

#[tokio::test]
async fn a_lost_lease_record_never_lowers_the_token() {
    use baton_state::StateStore as _;
    let storage = Storage::over(Arc::new(MemoryObjects::new()));
    let state = skein_storage::ControlState::new(storage.control.clone());
    let (leases, _) = control_leases(&storage, 5_000, None);
    let e1 = engine_over(storage.clone(), leases.clone(), "n1");
    let e2 = engine_over(storage.clone(), leases.clone(), "n2");
    let fake = FakeMail::new();
    fake.fill("INBOX", 3, 100);
    let acc = account("a");
    let config = AccountConfig::new(tenant(), acc.clone());
    e1.sync_account(&config, &fake).await.unwrap();
    let group = coordination::group(&tenant());
    let key = coordination::lease_key(&acc);
    let first = leases.holder(&group, &key).await.unwrap().unwrap();
    state
        .delete(&group, &lease_name(&acc), baton_state::Expect::Any)
        .await
        .unwrap();
    fake.fill("INBOX", 2, 100);
    e2.sync_account(&config, &fake).await.unwrap();
    let second = leases.holder(&group, &key).await.unwrap().unwrap();
    assert_eq!(second.node.as_str(), "n2");
    assert!(
        second.fence > first.fence,
        "a lost record never lowers tokens"
    );
    assert!(matches!(
        e1.sync_account(&config, &fake).await,
        Err(EngineError::NotOwner)
    ));
    let replay = all_events(&storage, &acc).await.pop().into_iter().collect();
    assert!(matches!(
        storage
            .log
            .append(&tenant(), &acc, first.fence, replay)
            .await,
        Err(StorageError::Fenced)
    ));
    assert_eq!(count(&all_events(&storage, &acc).await, added), 5);
}

#[tokio::test]
async fn a_stronger_node_asking_for_the_account_gets_it_at_the_next_run() {
    let storage = Storage::over(Arc::new(MemoryObjects::new()));
    let clock = ManualClock::new();
    let (leases, liveness) = control_leases(&storage, 5_000, Some(clock.clock()));
    let desktop = Engine::new(
        storage.clone(),
        leases.clone(),
        signal(),
        crate::node_profile(skein_core::NodeId::new("desk").unwrap(), 1, false),
    );
    let fake = FakeMail::new();
    fake.fill("INBOX", 2, 100);
    let acc = account("a");
    let config = AccountConfig::new(tenant(), acc.clone());
    let group = coordination::group(&tenant());
    let key = coordination::lease_key(&acc);
    for p in [desktop.profile().clone(), profile("srv")] {
        liveness.heartbeat(&group, &p, clock.now()).await.unwrap();
    }
    desktop.sync_account(&config, &fake).await.unwrap();
    assert_eq!(
        leases
            .request_takeover(&group, &key, &profile("srv"))
            .await
            .unwrap(),
        baton_lease::TakeoverOutcome::Recorded
    );
    assert!(matches!(
        desktop.sync_account(&config, &fake).await,
        Err(EngineError::NotOwner)
    ));
    let server = engine_over(storage.clone(), leases.clone(), "srv");
    fake.fill("INBOX", 1, 100);
    server.sync_account(&config, &fake).await.unwrap();
    assert_eq!(
        leases
            .holder(&group, &key)
            .await
            .unwrap()
            .unwrap()
            .node
            .as_str(),
        "srv"
    );
    assert!(matches!(
        desktop.sync_account(&config, &fake).await,
        Err(EngineError::NotOwner)
    ));
    assert_eq!(count(&all_events(&storage, &acc).await, added), 3);
}
