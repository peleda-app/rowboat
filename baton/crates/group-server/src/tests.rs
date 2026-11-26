use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use baton_core::{GroupId, Timestamp};
use baton_group::{Entry, Founding, GroupLog, NodeCert, Op, Role};
use baton_identity::Identity;
use baton_keys::{KemSecret, RecoveryRoot};
use baton_lease::NodeClass;
use baton_link::{Duplex, Link, PinnedKeys, Protocol, PublicKey, Trust};
use baton_link_memory::{MemoryLink, MemoryLinkHub};
use baton_state::{Expect, RecordName, StateError, StateStore, Version};
use baton_state_memory::MemoryState;
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::wire::{self, Head, Refusal, Reply, Request};
use crate::*;

const T0: i64 = 1_700_000_000_000;
const LATER: Timestamp = Timestamp(1_800_000_000_000);

struct AllowAll;

impl Trust for AllowAll {
    fn allows(&self, _: &PublicKey) -> bool {
        true
    }
}

struct Device {
    id: Identity,
    kem: KemSecret,
}

impl Device {
    fn new() -> Self {
        Self {
            id: Identity::generate(),
            kem: KemSecret::generate(),
        }
    }

    fn cert(&self, member: &Identity, class: NodeClass) -> NodeCert {
        NodeCert::new(member, &self.id, self.kem.public(), class, LATER)
    }
}

fn group() -> GroupId {
    GroupId::new("family").unwrap()
}

struct World {
    owner: Identity,
    laptop: Device,
    log: GroupLog,
}

fn world() -> World {
    let owner = Identity::generate();
    let laptop = Device::new();
    let log = GroupLog::genesis(
        group(),
        Founding {
            owner: &owner,
            owner_recovery: RecoveryRoot::generate().public(),
            group_recovery: RecoveryRoot::generate().public(),
            node: &laptop.id,
            node_kem: laptop.kem.public(),
            class: NodeClass::Desktop,
            expires: LATER,
        },
        Timestamp(T0),
    )
    .unwrap();
    World { owner, laptop, log }
}

struct Net {
    hub: MemoryLinkHub,
    server_id: Identity,
    links: std::sync::Mutex<std::collections::HashMap<PublicKey, Arc<dyn Link>>>,
    now: Arc<AtomicI64>,
    store: Arc<dyn StateStore>,
    logs: Arc<GroupLogs>,
    bootstrap: Arc<PinnedKeys>,
    server: GroupServer,
}

impl Net {
    async fn new(genesis: [u8; 32], config: ServerConfig) -> Self {
        Self::over(genesis, config, Arc::new(MemoryState::new()), 100).await
    }

    async fn over(
        genesis: [u8; 32],
        config: ServerConfig,
        store: Arc<dyn StateStore>,
        max_entries: u64,
    ) -> Self {
        let hub = MemoryLinkHub::new();
        let server_id = Identity::generate();
        let server_link: Arc<dyn Link> = Arc::new(hub.join(server_id.public(), Arc::new(AllowAll)));
        let now = Arc::new(AtomicI64::new(T0));
        let logs = Arc::new(GroupLogs::new(
            [(group(), genesis)],
            store.clone(),
            max_entries,
        ));
        logs.load().await.unwrap();
        let bootstrap = Arc::new(PinnedKeys::default());
        let clock = {
            let now = now.clone();
            Arc::new(move || Timestamp(now.load(Ordering::SeqCst))) as Clock
        };
        let server = GroupServer::start(
            server_link.clone(),
            logs.clone(),
            bootstrap.clone(),
            clock,
            config,
        )
        .await
        .unwrap();
        Self {
            hub,
            server_id,
            links: Default::default(),
            now,
            store,
            logs,
            bootstrap,
            server,
        }
    }

    fn link(&self, id: &Identity) -> Arc<dyn Link> {
        self.links
            .lock()
            .unwrap()
            .entry(id.public())
            .or_insert_with(|| Arc::new(self.hub.join(id.public(), Arc::new(AllowAll))))
            .clone()
    }

    async fn client(&self, id: &Identity) -> GroupClient {
        GroupClient::connect(
            self.link(id),
            self.server_id.public(),
            ClientConfig::default(),
        )
        .await
        .unwrap()
    }

    async fn raw(&self, link: &Arc<dyn Link>) -> Box<dyn Duplex> {
        link.open(&self.server_id.public(), &Protocol::new(PROTOCOL).unwrap())
            .await
            .unwrap()
    }
}

fn refused<T: std::fmt::Debug>(r: Result<T, RemoteError>) -> Refusal {
    match r {
        Err(RemoteError::Refused(x)) => x,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn now() -> Timestamp {
    Timestamp(T0)
}

async fn closed(s: &mut Box<dyn Duplex>) -> bool {
    let mut buf = [0u8; 64];
    loop {
        match s.read(&mut buf).await {
            Ok(0) | Err(_) => return true,
            Ok(_) => continue,
        }
    }
}

async fn ask(s: &mut Box<dyn Duplex>, r: &Request) -> Option<Reply> {
    wire::write_frame(s, &wire::encode_request(r)).await.ok()?;
    let body = wire::read_frame(s, wire::MAX_REPLY).await.ok()?;
    wire::decode_reply(&body, wire::MAX_REPLY).ok()
}

#[tokio::test]
async fn members_push_and_fetch_and_sync_a_log() {
    let mut w = world();
    let net = Net::new(w.log.genesis_hash(), ServerConfig::default()).await;
    net.bootstrap.insert(w.laptop.id.public());
    let laptop = net.client(&w.laptop.id).await;
    assert_eq!(laptop.head(&group()).await.unwrap(), None);
    let (head, new) = laptop.push(&w.log.entries()[0]).await.unwrap();
    assert!(new);
    assert_eq!(head.seq, 0);

    let phone = Device::new();
    let e = w
        .log
        .append(
            &w.laptop.id,
            Op::CertifyNode {
                cert: phone.cert(&w.owner, NodeClass::Phone),
            },
            now(),
        )
        .unwrap();
    laptop.push(&e).await.unwrap();
    net.bootstrap.remove(&w.laptop.id.public());

    let p = net.client(&phone.id).await;
    let synced = p
        .sync(&group(), w.log.genesis_hash(), None, now())
        .await
        .unwrap();
    assert_eq!(synced.head_hash(), w.log.head_hash());
    assert_eq!(
        p.head(&group()).await.unwrap(),
        Some(Head {
            seq: 1,
            hash: w.log.head_hash()
        })
    );
    let again = p
        .sync(&group(), w.log.genesis_hash(), Some(&synced), now())
        .await
        .unwrap();
    assert_eq!(again.head_seq(), 1);
    assert!(net.logs.counts(&group(), &phone.id.public(), now()));
    assert_eq!(
        net.logs.counting_nodes(now()),
        [w.laptop.id.public(), phone.id.public()]
            .into_iter()
            .collect()
    );
}

#[tokio::test]
async fn fetches_page_by_count_and_size() {
    let mut w = world();
    let net = Net::new(
        w.log.genesis_hash(),
        ServerConfig {
            max_fetch: 3,
            ..ServerConfig::default()
        },
    )
    .await;
    net.bootstrap.insert(w.laptop.id.public());
    let c = net.client(&w.laptop.id).await;
    c.push(&w.log.entries()[0]).await.unwrap();
    for _ in 0..10 {
        let d = Device::new();
        let e = w
            .log
            .append(
                &w.laptop.id,
                Op::CertifyNode {
                    cert: d.cert(&w.owner, NodeClass::Desktop),
                },
                now(),
            )
            .unwrap();
        c.push(&e).await.unwrap();
    }
    let page = c.fetch(&group(), None, 100).await.unwrap();
    assert_eq!(page.len(), 3, "capped by the server's max_fetch");
    let page = c.fetch(&group(), Some(8), 100).await.unwrap();
    assert_eq!(
        page.iter().map(|e| e.seq()).collect::<Vec<_>>(),
        vec![9, 10]
    );
    assert!(c.fetch(&group(), Some(10), 3).await.unwrap().is_empty());
    assert!(
        c.fetch(&group(), Some(u64::MAX), 3)
            .await
            .unwrap()
            .is_empty()
    );
    let all = c
        .sync(&group(), w.log.genesis_hash(), None, now())
        .await
        .unwrap();
    assert_eq!(all.head_seq(), 10);

    let one = net.logs.fetch(&group(), None, 100, 1).unwrap();
    assert_eq!(one.len(), 1, "a byte budget still returns one entry");
}

#[tokio::test]
async fn the_genesis_is_pinned_and_strangers_are_refused() {
    let w = world();
    let other = world();
    let net = Net::new(w.log.genesis_hash(), ServerConfig::default()).await;
    let stranger = Identity::generate();
    let s = net.client(&stranger).await;
    assert_eq!(refused(s.head(&group()).await), Refusal::Denied);
    assert_eq!(
        refused(s.push(&w.log.entries()[0]).await),
        Refusal::Denied,
        "before genesis only bootstrap peers may push"
    );
    assert_eq!(
        refused(s.head(&GroupId::new("elsewhere").unwrap()).await),
        Refusal::Unknown
    );

    net.bootstrap.insert(other.laptop.id.public());
    let o = net.client(&other.laptop.id).await;
    assert_eq!(
        refused(o.push(&other.log.entries()[0]).await),
        Refusal::Fork,
        "another genesis of the same group id"
    );
    assert_eq!(net.logs.head(&group()), None);

    net.bootstrap.insert(w.laptop.id.public());
    let c = net.client(&w.laptop.id).await;
    let mut ahead = w.log.clone();
    let e = ahead
        .append(
            &w.laptop.id,
            Op::CertifyNode {
                cert: Device::new().cert(&w.owner, NodeClass::Desktop),
            },
            now(),
        )
        .unwrap();
    assert_eq!(refused(c.push(&e).await), Refusal::Chain(None));
    c.push(&w.log.entries()[0]).await.unwrap();
    net.bootstrap.remove(&other.laptop.id.public());
    assert_eq!(
        refused(o.head(&group()).await),
        Refusal::Denied,
        "a node of another group does not count in this one"
    );
}

fn cert_op(w: &World) -> Op {
    Op::CertifyNode {
        cert: Device::new().cert(&w.owner, NodeClass::Desktop),
    }
}

#[tokio::test]
async fn forged_replayed_forked_stale_future_and_unauthorized_entries_are_refused() {
    let mut w = world();
    let net = Net::new(w.log.genesis_hash(), ServerConfig::default()).await;
    net.bootstrap.insert(w.laptop.id.public());
    let c = net.client(&w.laptop.id).await;
    c.push(&w.log.entries()[0]).await.unwrap();
    net.bootstrap.remove(&w.laptop.id.public());

    let alice = Identity::generate();
    let stale_base = w.log.clone();
    let add = w
        .log
        .append(
            &w.laptop.id,
            Op::AddMember {
                member: alice.public(),
                recovery: RecoveryRoot::generate().public(),
                role: Role::Member,
            },
            now(),
        )
        .unwrap();

    let mut s = net.raw(&net.link(&w.laptop.id)).await;
    let mut forged = add.encode();
    let n = forged.len();
    forged[n - 1] ^= 1;
    assert_eq!(
        ask(&mut s, &Request::Push { entry: forged }).await,
        Some(Reply::Refused(Refusal::Malformed)),
        "a broken signature"
    );
    let mut padded = add.encode();
    padded.push(0);
    assert_eq!(
        ask(&mut s, &Request::Push { entry: padded }).await,
        Some(Reply::Refused(Refusal::Malformed)),
        "non-canonical bytes"
    );
    assert_eq!(
        ask(&mut s, &Request::Push { entry: vec![] }).await,
        Some(Reply::Refused(Refusal::Malformed))
    );

    let (head, new) = c.push(&add).await.unwrap();
    assert!(new);
    let (again, new) = c.push(&add).await.unwrap();
    assert!(!new, "a replayed entry changes nothing");
    assert_eq!(again, head);
    let (_, new) = c.push(&w.log.entries()[0]).await.unwrap();
    assert!(!new, "a replayed genesis changes nothing");

    let mut stale = stale_base.clone();
    let on_old_head = stale.append(&w.laptop.id, cert_op(&w), now()).unwrap();
    assert_eq!(
        refused(c.push(&on_old_head).await),
        Refusal::Fork,
        "an entry made on a stale head takes a position already held"
    );

    let mut gap = w.log.clone();
    gap.append(&w.laptop.id, cert_op(&w), now()).unwrap();
    let skipped = gap.append(&w.laptop.id, cert_op(&w), now()).unwrap();
    assert_eq!(refused(c.push(&skipped).await), Refusal::Chain(Some(head)));

    let mut ahead = w.log.clone();
    let future = ahead
        .append(
            &w.laptop.id,
            cert_op(&w),
            Timestamp(T0 + DEFAULT_SKEW_MS + 1),
        )
        .unwrap();
    assert_eq!(
        refused(c.push(&future).await),
        Refusal::Invalid,
        "an entry from the future"
    );
    net.now.store(T0 + 2, Ordering::SeqCst);
    let mut edge = w.log.clone();
    let at_edge = edge
        .append(
            &w.laptop.id,
            cert_op(&w),
            Timestamp(T0 + 2 + DEFAULT_SKEW_MS),
        )
        .unwrap();
    c.push(&at_edge).await.unwrap();
    w.log = edge;

    let stranger = Identity::generate();
    let next = |l: &GroupLog, signer: &Identity, at: Timestamp, op: Op| {
        craft(signer, l.head_seq() + 1, l.head_hash(), at, op)
    };
    let by_stranger = next(
        &w.log,
        &stranger,
        Timestamp(T0 + 2),
        Op::AddMember {
            member: Identity::generate().public(),
            recovery: RecoveryRoot::generate().public(),
            role: Role::Owner,
        },
    );
    assert_eq!(
        refused(c.push(&by_stranger).await),
        Refusal::Invalid,
        "a signer that is no node of the group"
    );
    let backdated = next(&w.log, &w.laptop.id, Timestamp(T0), cert_op(&w));
    assert_eq!(
        refused(c.push(&backdated).await),
        Refusal::Invalid,
        "entry times never go back"
    );
    let elsewhere = craft_in(
        &GroupId::new("elsewhere").unwrap(),
        &w.laptop.id,
        w.log.head_seq() + 1,
        w.log.head_hash(),
        Timestamp(T0 + 2),
        cert_op(&w),
    );
    assert_eq!(refused(c.push(&elsewhere).await), Refusal::Unknown);

    let mut other = world();
    let alien = other
        .log
        .append(&other.laptop.id, cert_op(&other), now())
        .unwrap();
    assert_eq!(
        refused(c.push(&alien).await),
        Refusal::Fork,
        "an entry of another log of the same group id"
    );
    assert_eq!(net.logs.head(&group()).unwrap().seq, w.log.head_seq());
    assert_eq!(net.logs.head(&group()).unwrap().hash, w.log.head_hash());
}

fn craft(signer: &Identity, seq: u64, prev: [u8; 32], at: Timestamp, op: Op) -> Entry {
    craft_in(&group(), signer, seq, prev, at, op)
}

fn craft_in(
    group: &GroupId,
    signer: &Identity,
    seq: u64,
    prev: [u8; 32],
    at: Timestamp,
    op: Op,
) -> Entry {
    #[derive(serde::Serialize)]
    struct Body<'a> {
        v: u8,
        group: &'a GroupId,
        seq: u64,
        prev: [u8; 32],
        at: Timestamp,
        signer: PublicKey,
        op: &'a Op,
    }
    #[derive(serde::Serialize)]
    struct Signed<'a> {
        body: Body<'a>,
        signature: baton_identity::Signature,
    }
    let body = Body {
        v: baton_group::ENTRY_VERSION,
        group,
        seq,
        prev,
        at,
        signer: signer.public(),
        op: &op,
    };
    let signature = signer.sign("baton-group-entry-v1", &postcard::to_stdvec(&body).unwrap());
    Entry::decode(&postcard::to_stdvec(&Signed { body, signature }).unwrap()).unwrap()
}

async fn founded(config: ServerConfig) -> (World, Net, GroupClient) {
    let w = world();
    let net = Net::new(w.log.genesis_hash(), config).await;
    net.bootstrap.insert(w.laptop.id.public());
    let c = net.client(&w.laptop.id).await;
    c.push(&w.log.entries()[0]).await.unwrap();
    net.bootstrap.remove(&w.laptop.id.public());
    (w, net, c)
}

#[tokio::test]
async fn a_revoked_node_is_refused_on_its_open_stream() {
    let (mut w, net, c) = founded(ServerConfig::default()).await;
    let phone = Device::new();
    let e = w
        .log
        .append(
            &w.laptop.id,
            Op::CertifyNode {
                cert: phone.cert(&w.owner, NodeClass::Phone),
            },
            now(),
        )
        .unwrap();
    c.push(&e).await.unwrap();
    let p = net.client(&phone.id).await;
    let synced = p
        .sync(&group(), w.log.genesis_hash(), None, now())
        .await
        .unwrap();
    let e = w
        .log
        .append(
            &w.laptop.id,
            Op::RevokeNode {
                node: phone.id.public(),
            },
            now(),
        )
        .unwrap();
    c.push(&e).await.unwrap();
    assert_eq!(refused(p.head(&group()).await), Refusal::Denied);
    assert_eq!(
        refused(
            p.sync(&group(), w.log.genesis_hash(), Some(&synced), now())
                .await
        ),
        Refusal::Denied
    );
    assert!(!net.logs.counts(&group(), &phone.id.public(), now()));

    net.now.store(LATER.0 + 1, Ordering::SeqCst);
    assert_eq!(
        refused(c.head(&group()).await),
        Refusal::Denied,
        "an expired certificate no longer counts"
    );
}

#[tokio::test]
async fn bad_frames_close_the_stream_and_the_server_keeps_serving() {
    let (w, net, c) = founded(ServerConfig::default()).await;
    let link = net.link(&w.laptop.id);

    let mut s = net.raw(&link).await;
    s.write_all(&((wire::MAX_REQUEST + 1) as u32).to_be_bytes())
        .await
        .unwrap();
    assert!(closed(&mut s).await, "oversized announced length");

    let mut s = net.raw(&link).await;
    s.write_all(&0u32.to_be_bytes()).await.unwrap();
    assert!(closed(&mut s).await, "empty frame");

    let mut s = net.raw(&link).await;
    wire::write_frame(&mut s, &[wire::VERSION, 0xff, 0xff, 0xff])
        .await
        .unwrap();
    assert!(closed(&mut s).await, "garbage body");

    let mut s = net.raw(&link).await;
    let mut body = wire::encode_request(&Request::Hello);
    body.push(0);
    wire::write_frame(&mut s, &body).await.unwrap();
    assert!(closed(&mut s).await, "trailing bytes");

    let mut s = net.raw(&link).await;
    wire::write_frame(&mut s, &[9, 0]).await.unwrap();
    let reply = wire::read_frame(&mut s, wire::MAX_REPLY).await.unwrap();
    assert_eq!(
        wire::decode_reply(&reply, wire::MAX_REPLY).unwrap(),
        Reply::Refused(Refusal::Version)
    );
    assert!(closed(&mut s).await, "closed after a version refusal");

    for i in 0..200u32 {
        let mut s = net.raw(&link).await;
        let junk: Vec<u8> = (0..(i % 50 + 1))
            .map(|j| (i.wrapping_mul(31).wrapping_add(j * 7)) as u8)
            .collect();
        let _ = s.write_all(&junk).await;
        let _ = s.shutdown().await;
    }
    assert_eq!(c.head(&group()).await.unwrap().unwrap().seq, 0);
}

#[tokio::test(start_paused = true)]
async fn slow_and_idle_streams_are_closed_and_free_their_slot() {
    let (w, net, _) = founded(ServerConfig {
        max_per_peer: 1,
        idle_timeout: Duration::from_secs(60),
        header_timeout: Duration::from_secs(2),
        ..ServerConfig::default()
    })
    .await;
    let link = net.link(&w.laptop.id);
    let mut slow = net.raw(&link).await;
    slow.write_all(&[0, 0]).await.unwrap();
    let started = tokio::time::Instant::now();
    assert!(closed(&mut slow).await);
    assert!(started.elapsed() <= Duration::from_millis(2_100));

    let mut drip = net.raw(&link).await;
    let started = tokio::time::Instant::now();
    for b in [0u8, 0, 0, 2, 1, 0] {
        if drip.write_all(&[b]).await.is_err() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(900)).await;
    }
    assert!(closed(&mut drip).await, "a frame dripped too slowly");
    assert!(started.elapsed() <= Duration::from_millis(5_500));

    let mut idle = net.raw(&link).await;
    let started = tokio::time::Instant::now();
    assert!(closed(&mut idle).await);
    assert!(started.elapsed() >= Duration::from_secs(60));

    let c = GroupClient::connect(link, net.server_id.public(), ClientConfig::default())
        .await
        .unwrap();
    assert_eq!(c.head(&group()).await.unwrap().unwrap().seq, 0);
}

#[tokio::test(start_paused = true)]
async fn per_peer_and_total_stream_caps_hold() {
    let (w, net, _) = founded(ServerConfig {
        max_per_peer: 2,
        max_streams: 8,
        idle_timeout: Duration::from_secs(30),
        ..ServerConfig::default()
    })
    .await;
    let greedy = net.link(&w.laptop.id);
    let mut open = Vec::new();
    for _ in 0..6 {
        let mut s = net.raw(&greedy).await;
        let alive = ask(&mut s, &Request::Hello).await.is_some();
        open.push((s, alive));
    }
    assert_eq!(open.iter().filter(|(_, a)| *a).count(), 2);
    let mut crowd = Vec::new();
    for _ in 0..20 {
        let link = net.link(&Identity::generate());
        let mut s = net.raw(&link).await;
        let alive = ask(&mut s, &Request::Hello).await.is_some();
        crowd.push((link, s, alive));
    }
    assert_eq!(crowd.iter().filter(|(_, _, a)| *a).count(), 6);
    let late = net.link(&Identity::generate());
    assert!(matches!(
        GroupClient::connect(
            late.clone(),
            net.server_id.public(),
            ClientConfig::default()
        )
        .await,
        Err(RemoteError::Unavailable)
    ));
    tokio::time::sleep(Duration::from_secs(31)).await;
    assert!(
        GroupClient::connect(late, net.server_id.public(), ClientConfig::default())
            .await
            .is_ok()
    );
    drop((open, crowd));
}

#[tokio::test]
async fn logs_survive_a_restart_and_a_foreign_store_is_refused() {
    let (mut w, net, c) = founded(ServerConfig::default()).await;
    let e = w.log.append(&w.laptop.id, cert_op(&w), now()).unwrap();
    c.push(&e).await.unwrap();
    let store = net.store.clone();
    net.server.stop().await;

    let again = GroupLogs::new([(group(), w.log.genesis_hash())], store.clone(), 100);
    again.load().await.unwrap();
    assert_eq!(again.head(&group()).unwrap().hash, w.log.head_hash());

    let other = world();
    let pinned_elsewhere = GroupLogs::new([(group(), other.log.genesis_hash())], store, 100);
    assert!(
        pinned_elsewhere.load().await.is_err(),
        "a store holding another genesis"
    );
}

#[tokio::test]
async fn logs_are_capped() {
    let w = world();
    let net = Net::over(
        w.log.genesis_hash(),
        ServerConfig::default(),
        Arc::new(MemoryState::new()),
        2,
    )
    .await;
    net.bootstrap.insert(w.laptop.id.public());
    let c = net.client(&w.laptop.id).await;
    let mut log = w.log.clone();
    c.push(&log.entries()[0]).await.unwrap();
    let e = log.append(&w.laptop.id, cert_op(&w), now()).unwrap();
    c.push(&e).await.unwrap();
    let e = log.append(&w.laptop.id, cert_op(&w), now()).unwrap();
    assert_eq!(refused(c.push(&e).await), Refusal::Full);
}

struct Flaky {
    inner: MemoryState,
    fail: AtomicBool,
}

#[async_trait]
impl StateStore for Flaky {
    async fn get(
        &self,
        group: &GroupId,
        name: &RecordName,
    ) -> Result<Option<(Bytes, Version)>, StateError> {
        self.inner.get(group, name).await
    }

    async fn put(
        &self,
        group: &GroupId,
        name: &RecordName,
        value: Bytes,
        expect: Expect,
    ) -> Result<Version, StateError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(StateError::backend("disk full"));
        }
        self.inner.put(group, name, value, expect).await
    }

    async fn delete(
        &self,
        group: &GroupId,
        name: &RecordName,
        expect: Expect,
    ) -> Result<(), StateError> {
        self.inner.delete(group, name, expect).await
    }

    async fn list(
        &self,
        group: &GroupId,
        prefix: &RecordName,
        after: Option<&RecordName>,
        limit: usize,
    ) -> Result<Vec<RecordName>, StateError> {
        self.inner.list(group, prefix, after, limit).await
    }
}

#[tokio::test]
async fn a_failed_write_leaves_the_log_as_stored() {
    let w = world();
    let flaky = Arc::new(Flaky {
        inner: MemoryState::new(),
        fail: AtomicBool::new(false),
    });
    let net = Net::over(
        w.log.genesis_hash(),
        ServerConfig::default(),
        flaky.clone(),
        100,
    )
    .await;
    net.bootstrap.insert(w.laptop.id.public());
    let c = net.client(&w.laptop.id).await;
    let mut log = w.log.clone();
    c.push(&log.entries()[0]).await.unwrap();
    let e = log.append(&w.laptop.id, cert_op(&w), now()).unwrap();
    flaky.fail.store(true, Ordering::SeqCst);
    assert_eq!(refused(c.push(&e).await), Refusal::Backend);
    assert_eq!(net.logs.head(&group()).unwrap().seq, 0, "nothing kept");
    flaky.fail.store(false, Ordering::SeqCst);
    c.push(&e).await.unwrap();
    assert_eq!(net.logs.head(&group()).unwrap().seq, 1);
}

#[tokio::test]
async fn a_server_behind_or_forked_is_detected_by_sync() {
    let (mut w, net, c) = founded(ServerConfig::default()).await;
    let mine = {
        let mut l = w.log.clone();
        l.append(&w.laptop.id, cert_op(&w), now()).unwrap();
        l
    };
    assert_eq!(
        c.sync(&group(), w.log.genesis_hash(), Some(&mine), now())
            .await
            .unwrap_err(),
        RemoteError::Rollback,
        "the server lacks an entry this node already has"
    );
    let theirs = w.log.append(&w.laptop.id, cert_op(&w), now()).unwrap();
    c.push(&theirs).await.unwrap();
    assert_eq!(
        c.sync(&group(), w.log.genesis_hash(), Some(&mine), now())
            .await
            .unwrap_err(),
        RemoteError::Fork
    );
    let mut longer = mine.clone();
    longer.append(&w.laptop.id, cert_op(&w), now()).unwrap();
    let mut also = w.log.clone();
    let e = also.append(&w.laptop.id, cert_op(&w), now()).unwrap();
    c.push(&e).await.unwrap();
    assert_eq!(
        c.sync(&group(), w.log.genesis_hash(), Some(&longer), now())
            .await
            .unwrap_err(),
        RemoteError::Fork
    );
    assert_eq!(
        c.sync(&group(), [0; 32], None, now()).await.unwrap_err(),
        RemoteError::Fork,
        "a genesis other than the pinned one"
    );
    let _ = net;
}

async fn liar(reply: Reply) -> (MemoryLinkHub, PublicKey, Arc<dyn Link>) {
    let hub = MemoryLinkHub::new();
    let sid = Identity::generate();
    let slink: MemoryLink = hub.join(sid.public(), Arc::new(AllowAll));
    let slink: Arc<dyn Link> = Arc::new(slink);
    let mut inc = slink
        .listen(&Protocol::new(PROTOCOL).unwrap())
        .await
        .unwrap();
    tokio::spawn(async move {
        use futures::StreamExt;
        let _keep = slink;
        while let Some(mut i) = inc.next().await {
            let reply = reply.clone();
            tokio::spawn(async move {
                while let Ok(body) = wire::read_frame(&mut i.stream, wire::MAX_REQUEST).await {
                    let out = match wire::decode_request(&body) {
                        Ok(Request::Hello) => Reply::Hello {
                            max_request: 1,
                            max_reply: 1,
                            max_fetch: 4,
                        },
                        _ => reply.clone(),
                    };
                    if wire::write_frame(&mut i.stream, &wire::encode_reply(&out))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    let me = Identity::generate();
    let link: Arc<dyn Link> = Arc::new(hub.join(me.public(), Arc::new(AllowAll)));
    (hub, sid.public(), link)
}

#[tokio::test]
async fn the_client_trusts_nothing_from_the_server() {
    let mut w = world();
    let e1 = w.log.append(&w.laptop.id, cert_op(&w), now()).unwrap();
    let e2 = w.log.append(&w.laptop.id, cert_op(&w), now()).unwrap();
    let genesis = w.log.entries()[0].encode();
    let cases = [
        Reply::Entries(vec![e1.encode()]),
        Reply::Entries(vec![genesis.clone(), e2.encode()]),
        Reply::Entries(vec![genesis.clone(); 5]),
        Reply::Entries(vec![vec![1, 2, 3]]),
        Reply::Head(None),
    ];
    for (i, reply) in cases.into_iter().enumerate() {
        let (_hub, server, link) = liar(reply).await;
        let c = GroupClient::connect(link, server, ClientConfig::default())
            .await
            .unwrap();
        let r = c.fetch(&group(), None, 4).await;
        assert!(
            matches!(r, Err(RemoteError::Protocol | RemoteError::Invalid(_))),
            "case {i}: {r:?}"
        );
    }
    let (_hub, server, link) = liar(Reply::Accepted {
        head: Head {
            seq: 0,
            hash: [0; 32],
        },
        new: true,
    })
    .await;
    let c = GroupClient::connect(link, server, ClientConfig::default())
        .await
        .unwrap();
    assert_eq!(c.push(&e2).await.unwrap_err(), RemoteError::Protocol);

    let (_hub, server, link) = liar(Reply::Entries(vec![vec![0; 2048]; 4])).await;
    let c = GroupClient::connect(
        link,
        server,
        ClientConfig {
            max_reply: 1024,
            ..ClientConfig::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        c.fetch(&group(), None, 4).await.unwrap_err(),
        RemoteError::Protocol,
        "a reply over the client's limit is refused before it is read"
    );
}

#[tokio::test]
async fn a_member_filling_the_log_cannot_block_a_revocation() {
    let w = world();
    let net = Net::over(
        w.log.genesis_hash(),
        ServerConfig::default(),
        Arc::new(MemoryState::new()),
        6,
    )
    .await;
    net.bootstrap.insert(w.laptop.id.public());
    let owner = net.client(&w.laptop.id).await;
    let mut log = w.log.clone();
    owner.push(&log.entries()[0]).await.unwrap();
    net.bootstrap.remove(&w.laptop.id.public());
    let alice = Identity::generate();
    let (rogue, spare) = (Device::new(), Device::new());
    for op in [
        Op::AddMember {
            member: alice.public(),
            recovery: RecoveryRoot::generate().public(),
            role: Role::Member,
        },
        Op::CertifyNode {
            cert: rogue.cert(&alice, NodeClass::Desktop),
        },
        Op::CertifyNode {
            cert: spare.cert(&alice, NodeClass::Desktop),
        },
    ] {
        let e = log.append(&w.laptop.id, op, now()).unwrap();
        owner.push(&e).await.unwrap();
    }
    let attacker = net.client(&rogue.id).await;
    let mut n = 0;
    loop {
        let e = log
            .clone()
            .append(
                &rogue.id,
                Op::CreateResource {
                    resource: baton_core::ResourceId::new(format!("junk-{n}")).unwrap(),
                },
                now(),
            )
            .unwrap();
        match attacker.push(&e).await {
            Ok(_) => {
                log.apply(e).unwrap();
                n += 1;
            }
            Err(r) => {
                assert_eq!(refused(Err::<(), _>(r)), Refusal::Full);
                break;
            }
        }
    }
    assert!(n >= 1, "the member filled the log");
    let own_revoke = log
        .clone()
        .append(
            &rogue.id,
            Op::RevokeNode {
                node: spare.id.public(),
            },
            now(),
        )
        .unwrap();
    assert_eq!(
        refused(attacker.push(&own_revoke).await),
        Refusal::Full,
        "a plain member cannot spend the reserve"
    );
    let revoke = log
        .append(
            &w.laptop.id,
            Op::RevokeNode {
                node: rogue.id.public(),
            },
            now(),
        )
        .unwrap();
    owner
        .push(&revoke)
        .await
        .expect("the owner's revocation is stored although the log is full");
    assert!(!net.logs.counts(&group(), &rogue.id.public(), now()));
    assert_eq!(refused(attacker.head(&group()).await), Refusal::Denied);
}

struct Gate {
    inner: MemoryState,
    hold: AtomicBool,
    fail: AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Semaphore,
}

#[async_trait]
impl StateStore for Gate {
    async fn get(
        &self,
        group: &GroupId,
        name: &RecordName,
    ) -> Result<Option<(Bytes, Version)>, StateError> {
        self.inner.get(group, name).await
    }

    async fn put(
        &self,
        group: &GroupId,
        name: &RecordName,
        value: Bytes,
        expect: Expect,
    ) -> Result<Version, StateError> {
        if self.hold.load(Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.acquire().await.unwrap().forget();
            if self.fail.load(Ordering::SeqCst) {
                return Err(StateError::backend("disk full"));
            }
        }
        self.inner.put(group, name, value, expect).await
    }

    async fn delete(
        &self,
        group: &GroupId,
        name: &RecordName,
        expect: Expect,
    ) -> Result<(), StateError> {
        self.inner.delete(group, name, expect).await
    }

    async fn list(
        &self,
        group: &GroupId,
        prefix: &RecordName,
        after: Option<&RecordName>,
        limit: usize,
    ) -> Result<Vec<RecordName>, StateError> {
        self.inner.list(group, prefix, after, limit).await
    }
}

#[tokio::test]
async fn a_push_cancelled_while_storing_still_reloads_when_the_write_fails() {
    let w = world();
    let gate = Arc::new(Gate {
        inner: MemoryState::new(),
        hold: AtomicBool::new(false),
        fail: AtomicBool::new(false),
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Semaphore::new(0),
    });
    let net = Net::over(
        w.log.genesis_hash(),
        ServerConfig::default(),
        gate.clone(),
        100,
    )
    .await;
    let mut log = w.log.clone();
    net.logs
        .push(log.entries()[0].clone(), now(), DEFAULT_SKEW_MS)
        .await
        .unwrap();
    let e = log.append(&w.laptop.id, cert_op(&w), now()).unwrap();
    gate.hold.store(true, Ordering::SeqCst);
    gate.fail.store(true, Ordering::SeqCst);
    {
        let push = net.logs.push(e.clone(), now(), DEFAULT_SKEW_MS);
        tokio::select! {
            _ = push => panic!("the store holds the write"),
            () = gate.entered.notified() => {}
        }
    }
    gate.release.add_permits(1);
    for _ in 0..1000 {
        if net.logs.head(&group()).unwrap().seq == 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        net.logs.head(&group()).unwrap().seq,
        0,
        "memory matches the store after the cancelled push's write failed"
    );
    gate.hold.store(false, Ordering::SeqCst);
    gate.fail.store(false, Ordering::SeqCst);
    net.logs
        .push(e, now(), DEFAULT_SKEW_MS)
        .await
        .expect("the entry can be pushed again");
    assert_eq!(net.logs.head(&group()).unwrap().seq, 1);
}

#[tokio::test]
async fn a_revoked_nodes_entry_on_the_current_head_is_refused_also_when_relayed() {
    let (mut w, net, c) = founded(ServerConfig::default()).await;
    let phone = Device::new();
    let e = w
        .log
        .append(
            &w.laptop.id,
            Op::CertifyNode {
                cert: phone.cert(&w.owner, NodeClass::Phone),
            },
            now(),
        )
        .unwrap();
    c.push(&e).await.unwrap();
    let e = w
        .log
        .append(
            &w.laptop.id,
            Op::RevokeNode {
                node: phone.id.public(),
            },
            now(),
        )
        .unwrap();
    c.push(&e).await.unwrap();
    let by_revoked = craft(
        &phone.id,
        w.log.head_seq() + 1,
        w.log.head_hash(),
        now(),
        cert_op(&w),
    );
    assert_eq!(
        refused(c.push(&by_revoked).await),
        Refusal::Invalid,
        "the revoked signer is refused by the log rules, not by position"
    );
    assert_eq!(net.logs.head(&group()).unwrap().seq, w.log.head_seq());
    assert_eq!(net.logs.head(&group()).unwrap().hash, w.log.head_hash());
}

#[tokio::test]
async fn pushes_are_rate_limited_per_peer_on_the_servers_clock() {
    let (mut w, net, c) = founded(ServerConfig {
        push_per_second: 2,
        push_burst: 3,
        ..ServerConfig::default()
    })
    .await;
    let mut accepted = 0;
    let mut last = None;
    for _ in 0..5 {
        let e = w
            .log
            .clone()
            .append(&w.laptop.id, cert_op(&w), now())
            .unwrap();
        match c.push(&e).await {
            Ok(_) => {
                w.log.apply(e).unwrap();
                accepted += 1;
            }
            Err(r) => last = Some(r),
        }
    }
    assert_eq!(accepted, 2, "the genesis push and two more spend the burst");
    assert_eq!(
        last,
        Some(RemoteError::Unavailable),
        "busy reaches the client as unavailable"
    );
    net.now.fetch_add(500, Ordering::SeqCst);
    let e = w.log.append(&w.laptop.id, cert_op(&w), now()).unwrap();
    c.push(&e).await.expect("half a second refills one push");
    let e = w
        .log
        .clone()
        .append(&w.laptop.id, cert_op(&w), now())
        .unwrap();
    let mut s = net.raw(&net.link(&w.laptop.id)).await;
    assert_eq!(
        ask(&mut s, &Request::Push { entry: e.encode() }).await,
        Some(Reply::Refused(Refusal::Busy))
    );
}

#[tokio::test]
async fn byte_and_entry_budgets_hold_and_the_reserve_is_bounded() {
    let w = world();
    let store: Arc<dyn StateStore> = Arc::new(MemoryState::new());
    let genesis_len = w.log.entries()[0].encode().len() as u64;
    let by_bytes = Arc::new(GroupLogs::with_limits(
        [(group(), w.log.genesis_hash())],
        store,
        LogLimits {
            max_entries: 100,
            max_bytes: genesis_len + 10,
            reserve: 1,
        },
    ));
    let mut log = w.log.clone();
    by_bytes
        .push(log.entries()[0].clone(), now(), DEFAULT_SKEW_MS)
        .await
        .unwrap();
    let e = log
        .clone()
        .append(&w.laptop.id, cert_op(&w), now())
        .unwrap();
    assert_eq!(
        by_bytes.push(e, now(), DEFAULT_SKEW_MS).await,
        Err(Refusal::Full),
        "over the byte budget"
    );
    let phone = Device::new();
    let by_entries = Arc::new(GroupLogs::with_limits(
        [(group(), w.log.genesis_hash())],
        Arc::new(MemoryState::new()),
        LogLimits {
            max_entries: 2,
            max_bytes: u64::MAX,
            reserve: 1,
        },
    ));
    by_entries
        .push(log.entries()[0].clone(), now(), DEFAULT_SKEW_MS)
        .await
        .unwrap();
    let cert = log
        .append(
            &w.laptop.id,
            Op::CertifyNode {
                cert: phone.cert(&w.owner, NodeClass::Phone),
            },
            now(),
        )
        .unwrap();
    by_entries.push(cert, now(), DEFAULT_SKEW_MS).await.unwrap();
    let full = log
        .clone()
        .append(&w.laptop.id, cert_op(&w), now())
        .unwrap();
    assert_eq!(
        by_entries.push(full, now(), DEFAULT_SKEW_MS).await,
        Err(Refusal::Full)
    );
    let revoke = log
        .append(
            &w.laptop.id,
            Op::RevokeNode {
                node: phone.id.public(),
            },
            now(),
        )
        .unwrap();
    by_entries
        .push(revoke, now(), DEFAULT_SKEW_MS)
        .await
        .expect("an owner's revocation uses the reserve");
    let more = log
        .append(
            &w.laptop.id,
            Op::RevokeNode {
                node: w.laptop.id.public(),
            },
            now(),
        )
        .unwrap();
    assert_eq!(
        by_entries.push(more, now(), DEFAULT_SKEW_MS).await,
        Err(Refusal::Full),
        "the reserve is bounded too"
    );
}
