//! Several processes on one directory: children of this test binary write concurrently through
//! their own handles (one owner, the rest shared) and the parent checks that no update was lost and
//! no record was torn.

use std::process::{Command, Stdio};
use std::sync::Arc;

use bytes::Bytes;
use skein_core::{
    AccountId, CommandBody, CommandId, Event, FencingToken, Seq, TenantId, Timestamp,
};
use skein_storage::{Expect, ObjectKey, Objects, Storage, StorageError, Submitted};
use skein_storage_fs::FsObjects;

const CHILDREN: usize = 4;
const ROUNDS: u64 = 25;
const TAKES: u32 = 3;
const PAD: usize = 64 * 1024;
const ROLE: &str = "SKEIN_FS_CHILD_ROLE";
const ROOT: &str = "SKEIN_FS_CHILD_ROOT";
const ID: &str = "SKEIN_FS_CHILD_ID";

fn key(text: &str) -> ObjectKey {
    ObjectKey::parse(text).unwrap()
}

fn tenant() -> TenantId {
    TenantId::new("acme").unwrap()
}

fn account() -> AccountId {
    AccountId::new("box").unwrap()
}

fn padded(n: u64) -> Bytes {
    let mut v = n.to_be_bytes().to_vec();
    v.extend(std::iter::repeat_n((n % 251) as u8, PAD));
    v.extend(n.to_be_bytes());
    Bytes::from(v)
}

fn unpadded(bytes: &[u8]) -> u64 {
    assert_eq!(bytes.len(), PAD + 16, "a torn record");
    let n = u64::from_be_bytes(bytes[..8].try_into().unwrap());
    assert_eq!(&bytes[bytes.len() - 8..], n.to_be_bytes(), "a torn record");
    assert!(
        bytes[8..8 + PAD].iter().all(|b| *b == (n % 251) as u8),
        "a torn record"
    );
    n
}

async fn increment(objects: &dyn Objects, k: &ObjectKey) -> u64 {
    loop {
        let (next, expect) = match objects.get(k).await.unwrap() {
            Some((bytes, v)) => (unpadded(&bytes) + 1, Expect::Version(v)),
            None => (1, Expect::Absent),
        };
        match objects.put(k, padded(next), expect).await {
            Ok(_) => return next,
            Err(StorageError::Conflict) => continue,
            Err(e) => panic!("{e}"),
        }
    }
}

fn event(child: usize, i: u64) -> Event {
    let mut e = skein_storage::testing::sample_event(&account(), i);
    e.key = format!("c{child}-{i}");
    e
}

fn command(id: CommandId, child: usize) -> skein_core::Command {
    skein_core::Command {
        id,
        account: account(),
        created_at: Timestamp(child as i64),
        trace: None,
        body: CommandBody::Unknown,
    }
}

async fn child(role: &str, root: &str, id: usize) {
    let objects: Arc<dyn Objects> = Arc::new(if id == 0 {
        FsObjects::open(root).unwrap()
    } else {
        FsObjects::open_shared(root).unwrap()
    });
    match role {
        "cas" => {
            for _ in 0..ROUNDS {
                increment(&*objects, &key("t/counter")).await;
            }
        }
        "absent" => {
            let mut wins = 0;
            for i in 0..ROUNDS {
                let k = key(&format!("t/once/k{i}"));
                match objects.put(&k, padded(id as u64), Expect::Absent).await {
                    Ok(_) => wins += 1,
                    Err(StorageError::Conflict) => {}
                    Err(e) => panic!("{e}"),
                }
            }
            println!("wins={wins}");
        }
        "append" => {
            let log = Storage::over(objects.clone()).log;
            let mut fence = None;
            let mut done = 0;
            let mut takes = 0;
            while done < ROUNDS {
                let f = match fence {
                    Some(f) => f,
                    None if takes < TAKES => {
                        takes += 1;
                        increment(&*objects, &key("t/fence")).await
                    }
                    None => break,
                };
                fence = Some(f);
                match log
                    .append(
                        &tenant(),
                        &account(),
                        FencingToken(f),
                        vec![event(id, done)],
                    )
                    .await
                {
                    Ok(_) => done += 1,
                    Err(StorageError::Fenced) => fence = None,
                    Err(e) => panic!("{e}"),
                }
            }
            println!("appended={done}");
        }
        "commands" => {
            let queue = Storage::over(objects.clone()).commands;
            for _ in 0..ROUNDS {
                let submitted = queue
                    .submit(&tenant(), &command(CommandId::generate(), id))
                    .await
                    .unwrap();
                assert_eq!(submitted, Submitted::New);
            }
            let shared = CommandId::new("01JAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
            let first = queue.submit(&tenant(), &command(shared, 0)).await.unwrap();
            println!("shared={}", first == Submitted::New);
        }
        other => panic!("unknown role {other}"),
    }
}

#[tokio::test]
async fn child_process_entry() {
    let (Ok(role), Ok(root), Ok(id)) =
        (std::env::var(ROLE), std::env::var(ROOT), std::env::var(ID))
    else {
        return;
    };
    child(&role, &root, id.parse().unwrap()).await;
}

fn run_children(role: &str, root: &std::path::Path) -> Vec<String> {
    let exe = std::env::current_exe().unwrap();
    let children: Vec<_> = (0..CHILDREN)
        .map(|id| {
            Command::new(&exe)
                .args(["child_process_entry", "--exact", "--nocapture"])
                .env(ROLE, role)
                .env(ROOT, root)
                .env(ID, id.to_string())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    children
        .into_iter()
        .map(|c| {
            let out = c.wait_with_output().unwrap();
            assert!(
                out.status.success(),
                "a {role} child failed: {}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap()
        })
        .collect()
}

fn printed(outputs: &[String], name: &str) -> Vec<String> {
    let prefix = format!("{name}=");
    outputs
        .iter()
        .flat_map(|o| o.lines())
        .filter_map(|l| l.strip_prefix(&prefix).map(str::to_owned))
        .collect()
}

#[tokio::test]
async fn concurrent_compare_and_swap_loses_no_update() {
    let dir = tempfile::tempdir().unwrap();
    run_children("cas", dir.path());
    let objects = FsObjects::open(dir.path()).unwrap();
    let (bytes, _) = objects.get(&key("t/counter")).await.unwrap().unwrap();
    assert_eq!(unpadded(&bytes), CHILDREN as u64 * ROUNDS);
}

#[tokio::test]
async fn concurrent_creates_have_one_winner_each() {
    let dir = tempfile::tempdir().unwrap();
    let outputs = run_children("absent", dir.path());
    let wins: u64 = printed(&outputs, "wins")
        .iter()
        .map(|w| w.parse::<u64>().unwrap())
        .sum();
    assert_eq!(wins, ROUNDS);
    let objects = FsObjects::open(dir.path()).unwrap();
    for i in 0..ROUNDS {
        let (bytes, _) = objects
            .get(&key(&format!("t/once/k{i}")))
            .await
            .unwrap()
            .unwrap();
        assert!(unpadded(&bytes) < CHILDREN as u64);
    }
}

#[tokio::test]
async fn concurrent_journal_appends_keep_one_chain() {
    let dir = tempfile::tempdir().unwrap();
    let outputs = run_children("append", dir.path());
    let appended: Vec<u64> = printed(&outputs, "appended")
        .iter()
        .map(|a| a.parse().unwrap())
        .collect();
    assert_eq!(appended.len(), CHILDREN);
    assert!(appended.contains(&ROUNDS), "the last fence holder finishes");
    let total: u64 = appended.iter().sum();
    let storage = Storage::over(Arc::new(FsObjects::open(dir.path()).unwrap()));
    assert_eq!(
        storage.log.head(&tenant(), &account()).await.unwrap(),
        Seq(total)
    );
    let events = storage
        .log
        .read(&tenant(), &account(), Seq(1), total as usize + 10)
        .await
        .unwrap();
    assert_eq!(events.len() as u64, total);
    for (i, e) in events.iter().enumerate() {
        assert_eq!(e.seq, Seq(i as u64 + 1));
    }
    let mut keys: Vec<_> = events.iter().map(|e| e.key.clone()).collect();
    keys.sort();
    keys.dedup();
    assert_eq!(keys.len() as u64, total, "every append landed exactly once");
    let mut counted = 0;
    for child in 0..CHILDREN {
        let mine: Vec<_> = events
            .iter()
            .filter(|e| e.key.starts_with(&format!("c{child}-")))
            .map(|e| e.key.clone())
            .collect();
        let expected: Vec<_> = (0..mine.len()).map(|i| format!("c{child}-{i}")).collect();
        assert_eq!(mine, expected, "each writer's appends stay in order");
        counted += mine.len() as u64;
    }
    assert_eq!(
        counted, total,
        "every acknowledged append is in the journal"
    );
    let head = storage
        .log
        .signed_head(&tenant(), &account())
        .await
        .unwrap();
    let mut chain = skein_storage::Chain::new(&*storage.log, &head.head);
    let mut chained = 0;
    while let Some(segment) = chain.next().await.unwrap() {
        chained += segment.events.len() as u64;
    }
    assert_eq!(chained, total, "the hash chain covers every event");
}

#[tokio::test]
async fn concurrent_command_submissions_are_all_queued_once() {
    let dir = tempfile::tempdir().unwrap();
    let outputs = run_children("commands", dir.path());
    let firsts = printed(&outputs, "shared");
    assert_eq!(firsts.iter().filter(|f| *f == "true").count(), 1);
    let storage = Storage::over(Arc::new(FsObjects::open(dir.path()).unwrap()));
    let pending = storage
        .commands
        .pending(&tenant(), &account(), 10_000)
        .await
        .unwrap();
    assert_eq!(pending.len() as u64, CHILDREN as u64 * ROUNDS + 1);
    let mut ids: Vec<_> = pending.iter().map(|c| c.id.clone()).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), pending.len());
}
