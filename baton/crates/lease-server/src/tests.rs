use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use baton_core::{GroupId, LeaseKey, NodeId, Timestamp};
use baton_identity::Identity;
use baton_lease::testing::{self, Harness, profile};
use baton_lease::{Lease, LeaseError, Leases, Liveness, NodeClass, NodeProfile, TakeoverOutcome};
use baton_lease_cas::Clock;
use baton_link::{Duplex, Link, Protocol, PublicKey, Trust};
use baton_link_memory::{MemoryLink, MemoryLinkHub};
use baton_state::StateStore;
use baton_state_memory::MemoryState;
use futures::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::wire::{self, Refusal, Reply, Request};
use crate::*;

const TTL: u64 = 10_000;
const T0: i64 = 1_700_000_000_000;

struct AllowAll;

impl Trust for AllowAll {
    fn allows(&self, _: &PublicKey) -> bool {
        true
    }
}

#[derive(Default)]
struct Rules {
    names: Mutex<HashMap<PublicKey, NodeId>>,
    revoked: Mutex<HashSet<PublicKey>>,
    denied_keys: Mutex<HashSet<String>>,
    denied_groups: Mutex<HashSet<String>>,
    caps: Mutex<HashMap<PublicKey, NodeClass>>,
}

impl Authorize for Rules {
    fn node(&self, peer: &PublicKey) -> Option<NodeId> {
        if self.revoked.lock().unwrap().contains(peer) {
            return None;
        }
        self.names.lock().unwrap().get(peer).cloned()
    }

    fn member(&self, _: &PublicKey, group: &GroupId) -> bool {
        !self.denied_groups.lock().unwrap().contains(group.as_str())
    }

    fn profile(&self, peer: &PublicKey, group: &GroupId, profile: &NodeProfile) -> bool {
        let cap = self.caps.lock().unwrap().get(peer).copied();
        self.member(peer, group) && cap.is_none_or(|c| profile.class >= c)
    }

    fn lease(&self, peer: &PublicKey, group: &GroupId, key: &LeaseKey) -> bool {
        self.member(peer, group) && !self.denied_keys.lock().unwrap().contains(key.as_str())
    }
}

fn g() -> GroupId {
    GroupId::new("conf-lease").unwrap()
}

fn key(k: &str) -> LeaseKey {
    LeaseKey::new(k).unwrap()
}

fn config() -> ServerConfig {
    ServerConfig {
        ttl_ms: TTL,
        ..ServerConfig::default()
    }
}

fn remote(e: &LeaseError) -> Option<RemoteError> {
    match e {
        LeaseError::Backend(b) => b.downcast_ref::<RemoteError>().copied(),
        _ => None,
    }
}

fn denied<T>(r: Result<T, LeaseError>) -> bool {
    r.err().and_then(|e| remote(&e)) == Some(RemoteError::Denied)
}

fn unavailable<T>(r: Result<T, LeaseError>) -> bool {
    matches!(r, Err(LeaseError::Unavailable))
}

#[derive(Clone)]
struct Node {
    id: Arc<Identity>,
    link: Arc<dyn Link>,
    leases: Arc<RemoteLeases>,
    live: Arc<RemoteLiveness>,
    me: NodeProfile,
}

impl Node {
    async fn seen(&self) {
        self.beat(&g()).await.unwrap();
        self.live.alive(&g(), Timestamp(0)).await.unwrap();
    }

    async fn beat(&self, group: &GroupId) -> Result<(), LeaseError> {
        self.live.heartbeat(group, &self.me, Timestamp(0)).await
    }

    async fn take(&self, k: &str) -> Result<Option<Lease>, LeaseError> {
        self.leases.acquire(&g(), &key(k), &self.me).await
    }
}

struct Net {
    hub: MemoryLinkHub,
    server_id: Identity,
    server_link: MemoryLink,
    rules: Arc<Rules>,
    now: Arc<AtomicI64>,
    state: Arc<MemoryState>,
    server: tokio::sync::Mutex<Option<LeaseServer>>,
}

impl Net {
    async fn new(config: ServerConfig) -> Arc<Self> {
        let hub = MemoryLinkHub::new();
        let server_id = Identity::generate();
        let server_link = hub.join(server_id.public(), Arc::new(AllowAll));
        let net = Arc::new(Self {
            hub,
            server_id,
            server_link,
            rules: Arc::default(),
            now: Arc::new(AtomicI64::new(T0)),
            state: Arc::new(MemoryState::new()),
            server: tokio::sync::Mutex::new(None),
        });
        net.start(config).await;
        net
    }

    fn clock(&self) -> Clock {
        let now = self.now.clone();
        Arc::new(move || Timestamp(now.load(Ordering::SeqCst)))
    }

    fn at(&self) -> Timestamp {
        Timestamp(self.now.load(Ordering::SeqCst))
    }

    fn advance(&self, ms: i64) {
        self.now.fetch_add(ms, Ordering::SeqCst);
    }

    async fn start(&self, config: ServerConfig) {
        let server = LeaseServer::start(
            Arc::new(self.server_link.clone()),
            self.state.clone() as Arc<dyn StateStore>,
            self.rules.clone(),
            self.clock(),
            config,
        )
        .await
        .unwrap();
        *self.server.lock().await = Some(server);
    }

    async fn stop(&self) {
        if let Some(s) = self.server.lock().await.take() {
            s.stop().await;
        }
    }

    fn server_key(&self) -> PublicKey {
        self.server_id.public()
    }

    fn peer(&self, name: &str) -> (Arc<Identity>, Arc<dyn Link>) {
        let id = Arc::new(Identity::generate());
        self.rules
            .names
            .lock()
            .unwrap()
            .insert(id.public(), NodeId::new(name).unwrap());
        let link: Arc<dyn Link> = Arc::new(self.hub.join(id.public(), Arc::new(AllowAll)));
        (id, link)
    }

    async fn node(&self, name: &str, class: NodeClass) -> Node {
        let (id, link) = self.peer(name);
        let client = LeaseClient::connect(link.clone(), self.server_key(), ClientConfig::default())
            .await
            .unwrap();
        Node {
            id,
            link,
            leases: Arc::new(RemoteLeases::new(client.clone())),
            live: Arc::new(RemoteLiveness::new(client)),
            me: profile(name, class),
        }
    }

    async fn raw(&self, link: &Arc<dyn Link>) -> Box<dyn Duplex> {
        link.open(&self.server_key(), &Protocol::new(PROTOCOL).unwrap())
            .await
            .unwrap()
    }
}

async fn ask(s: &mut Box<dyn Duplex>, request: &Request) -> Option<Reply> {
    wire::write_frame(s, &wire::encode_request(request))
        .await
        .ok()?;
    let body = wire::read_frame(s, wire::MAX_REPLY).await.ok()?;
    wire::decode_reply(&body, wire::MAX_REPLY).ok()
}

async fn closed(s: &mut Box<dyn Duplex>) -> bool {
    let mut buf = [0u8; 16];
    matches!(
        tokio::time::timeout(Duration::from_secs(120), s.read(&mut buf)).await,
        Ok(Ok(0)) | Ok(Err(_))
    )
}

async fn kept(s: &mut Box<dyn Duplex>) -> bool {
    let mut buf = [0u8; 16];
    tokio::time::timeout(Duration::from_millis(50), s.read(&mut buf))
        .await
        .is_err()
}

/// Dispatches every call to the client of the node it names, so each suite node speaks for
/// itself through its own link identity. `alive` moves the server's clock to the observer time
/// the suite passes, because the server is the observer.
struct Routed {
    net: Arc<Net>,
    nodes: tokio::sync::Mutex<HashMap<NodeId, Node>>,
    registered: Mutex<Vec<NodeProfile>>,
}

impl Routed {
    fn new(net: Arc<Net>) -> Arc<Self> {
        Arc::new(Self {
            net,
            nodes: tokio::sync::Mutex::new(HashMap::new()),
            registered: Mutex::new(Vec::new()),
        })
    }

    async fn get(&self, node: &NodeId) -> Node {
        let mut nodes = self.nodes.lock().await;
        if let Some(n) = nodes.get(node) {
            return n.clone();
        }
        let n = self.net.node(node.as_str(), NodeClass::Desktop).await;
        nodes.insert(node.clone(), n.clone());
        n
    }

    async fn observer(&self) -> Node {
        self.get(&NodeId::new("suite-observer").unwrap()).await
    }
}

#[async_trait]
impl Leases for Routed {
    async fn acquire(
        &self,
        group: &GroupId,
        key: &LeaseKey,
        profile: &NodeProfile,
    ) -> Result<Option<Lease>, LeaseError> {
        let n = self.get(&profile.node).await;
        n.leases.acquire(group, key, profile).await
    }

    async fn request_takeover(
        &self,
        group: &GroupId,
        key: &LeaseKey,
        profile: &NodeProfile,
    ) -> Result<TakeoverOutcome, LeaseError> {
        let n = self.get(&profile.node).await;
        n.leases.request_takeover(group, key, profile).await
    }

    async fn release(&self, lease: &Lease) -> Result<(), LeaseError> {
        self.get(&lease.node).await.leases.release(lease).await
    }

    async fn holder(&self, group: &GroupId, key: &LeaseKey) -> Result<Option<Lease>, LeaseError> {
        self.observer().await.leases.holder(group, key).await
    }
}

#[async_trait]
impl Liveness for Routed {
    async fn heartbeat(
        &self,
        group: &GroupId,
        profile: &NodeProfile,
        now: Timestamp,
    ) -> Result<(), LeaseError> {
        let n = self.get(&profile.node).await;
        n.live.heartbeat(group, profile, now).await
    }

    async fn alive(&self, group: &GroupId, now: Timestamp) -> Result<Vec<NodeProfile>, LeaseError> {
        self.net.now.store(now.0, Ordering::SeqCst);
        self.observer().await.live.alive(group, now).await
    }

    fn ttl_ms(&self) -> u64 {
        TTL
    }
}

impl Harness for Routed {
    async fn alive(&self, p: &NodeProfile) {
        self.registered.lock().unwrap().push(p.clone());
        Liveness::heartbeat(self, &g(), p, self.net.at())
            .await
            .unwrap();
    }

    async fn kill(&self, node: &NodeId) {
        Liveness::alive(self, &g(), self.net.at()).await.unwrap();
        self.registered.lock().unwrap().retain(|p| &p.node != node);
        self.net.advance(TTL as i64 + 1);
        let others = self.registered.lock().unwrap().clone();
        for p in &others {
            Liveness::heartbeat(self, &g(), p, self.net.at())
                .await
                .unwrap();
        }
        Liveness::alive(self, &g(), self.net.at()).await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lease_suite_through_the_server() {
    let routed = Routed::new(Net::new(config()).await);
    testing::leases(routed.clone(), routed).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn liveness_suite_through_the_server() {
    let routed = Routed::new(Net::new(config()).await);
    testing::liveness(routed).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_cannot_act_for_another_node() {
    let net = Net::new(config()).await;
    let a = net.node("node-a", NodeClass::Desktop).await;
    let b = net.node("node-b", NodeClass::Desktop).await;
    b.beat(&g()).await.unwrap();
    a.beat(&g()).await.unwrap();
    let held = b.take("k").await.unwrap().unwrap();

    assert!(denied(a.leases.acquire(&g(), &key("k2"), &b.me).await));
    assert!(denied(
        a.leases.request_takeover(&g(), &key("k"), &b.me).await
    ));
    assert!(denied(a.live.heartbeat(&g(), &b.me, Timestamp(0)).await));
    assert!(denied(a.leases.release(&held).await));
    assert_eq!(
        a.leases.holder(&g(), &key("k")).await.unwrap(),
        Some(held.clone())
    );
    assert!(a.leases.holder(&g(), &key("k2")).await.unwrap().is_none());

    let (_, stranger) = net.peer("unused");
    net.rules.names.lock().unwrap().clear();
    assert!(denied(
        LeaseClient::connect(stranger, net.server_key(), ClientConfig::default()).await
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn unauthorized_keys_groups_and_classes_are_refused() {
    let net = Net::new(config()).await;
    net.rules.denied_keys.lock().unwrap().insert("vault".into());
    let a = net.node("node-a", NodeClass::Desktop).await;
    let b = net.node("node-b", NodeClass::Desktop).await;
    a.beat(&g()).await.unwrap();
    b.beat(&g()).await.unwrap();
    assert!(denied(a.take("vault").await));
    assert!(denied(
        a.leases.request_takeover(&g(), &key("vault"), &a.me).await
    ));
    assert!(
        a.leases
            .holder(&g(), &key("vault"))
            .await
            .unwrap()
            .is_none()
    );

    net.rules.denied_keys.lock().unwrap().clear();
    let held = b.take("vault").await.unwrap().unwrap();
    net.rules.denied_keys.lock().unwrap().insert("vault".into());
    assert!(denied(b.take("vault").await));
    b.leases
        .release(&held)
        .await
        .expect("a holder that lost the right to the key may still release it");
    assert!(
        b.leases
            .holder(&g(), &key("vault"))
            .await
            .unwrap()
            .is_none()
    );

    let closed = GroupId::new("closed").unwrap();
    net.rules
        .denied_groups
        .lock()
        .unwrap()
        .insert("closed".into());
    assert!(denied(a.beat(&closed).await));
    assert!(denied(a.live.alive(&closed, Timestamp(0)).await));
    assert!(denied(a.leases.holder(&closed, &key("k")).await));
    assert!(denied(a.leases.acquire(&closed, &key("k"), &a.me).await));

    net.rules
        .caps
        .lock()
        .unwrap()
        .insert(a.id.public(), NodeClass::Desktop);
    let inflated = NodeProfile {
        class: NodeClass::Server,
        ..a.me.clone()
    };
    assert!(denied(
        a.live.heartbeat(&g(), &inflated, Timestamp(0)).await
    ));
    assert!(denied(a.leases.acquire(&g(), &key("k"), &inflated).await));
    let humbler = NodeProfile {
        class: NodeClass::Phone,
        ..a.me.clone()
    };
    a.live
        .heartbeat(&g(), &humbler, Timestamp(0))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revocation_applies_to_the_next_request_on_an_open_stream() {
    let net = Net::new(config()).await;
    let a = net.node("node-a", NodeClass::Desktop).await;
    let b = net.node("node-b", NodeClass::Desktop).await;
    a.beat(&g()).await.unwrap();
    b.beat(&g()).await.unwrap();
    let held = a.take("k").await.unwrap().unwrap();

    let mut s = net.raw(&a.link).await;
    let hb = Request::Heartbeat {
        group: g(),
        profile: a.me.clone(),
    };
    assert_eq!(
        ask(&mut s, &hb).await,
        Some(Reply::Beat { ttl_ms: TTL }),
        "a heartbeat reply states the time-to-live"
    );
    net.rules.revoked.lock().unwrap().insert(a.id.public());
    assert_eq!(
        ask(&mut s, &hb).await,
        Some(Reply::Refused(Refusal::Denied)),
        "same stream, next request"
    );
    assert!(denied(a.take("k").await));
    assert!(denied(a.beat(&g()).await));
    assert!(denied(a.leases.release(&held).await));

    b.seen().await;
    net.advance(TTL as i64 + 1);
    b.seen().await;
    let taken = b.take("k").await.unwrap().unwrap();
    assert!(taken.fence > held.fence, "the revoked holder lapses");
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_garbage_and_wrong_version_frames_close_the_stream() {
    let net = Net::new(config()).await;
    let (_, link) = net.peer("node-x");

    let mut s = net.raw(&link).await;
    s.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
    assert!(closed(&mut s).await, "huge announced length");

    let mut s = net.raw(&link).await;
    s.write_all(&((wire::MAX_REQUEST + 1) as u32).to_be_bytes())
        .await
        .unwrap();
    assert!(closed(&mut s).await, "one byte over the limit");

    let mut s = net.raw(&link).await;
    s.write_all(&0u32.to_be_bytes()).await.unwrap();
    assert!(closed(&mut s).await, "empty frame");

    let mut s = net.raw(&link).await;
    wire::write_frame(&mut s, &[wire::VERSION, 200, 1, 2, 3])
        .await
        .unwrap();
    assert!(closed(&mut s).await, "garbage body");

    let mut s = net.raw(&link).await;
    let mut body = wire::encode_request(&Request::Hello);
    body.push(0);
    wire::write_frame(&mut s, &body).await.unwrap();
    assert!(closed(&mut s).await, "trailing bytes");

    let mut s = net.raw(&link).await;
    let mut body = wire::encode_request(&Request::Hello);
    body[0] = 2;
    wire::write_frame(&mut s, &body).await.unwrap();
    let reply = wire::read_frame(&mut s, wire::MAX_REPLY).await.unwrap();
    assert_eq!(
        wire::decode_reply(&reply, wire::MAX_REPLY).unwrap(),
        Reply::Refused(Refusal::Version)
    );
    assert!(
        closed(&mut s).await,
        "unknown version is answered, then closed"
    );

    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..200 {
        let mut s = net.raw(&link).await;
        let mut junk = Vec::new();
        for _ in 0..(seed % 64) {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            junk.push(seed as u8);
        }
        let _ = wire::write_frame(&mut s, &junk).await;
        let _ = s.shutdown().await;
        let mut sink = Vec::new();
        let _ = s.read_to_end(&mut sink).await;
    }

    let n = net.node("node-y", NodeClass::Desktop).await;
    n.beat(&g()).await.unwrap();
    assert!(
        n.take("k").await.unwrap().is_some(),
        "the server still serves"
    );
}

#[tokio::test(start_paused = true)]
async fn slow_and_idle_streams_are_closed_and_free_their_slot() {
    let net = Net::new(ServerConfig {
        max_per_peer: 1,
        idle_timeout: Duration::from_secs(60),
        header_timeout: Duration::from_secs(2),
        ..config()
    })
    .await;
    let (id, link) = net.peer("node-s");

    let mut slow = net.raw(&link).await;
    slow.write_all(&[0, 0]).await.unwrap();
    let blocked = LeaseClient::connect(link.clone(), net.server_key(), ClientConfig::default());
    assert!(
        unavailable(blocked.await),
        "the slow stream holds the peer's only slot"
    );
    let started = tokio::time::Instant::now();
    assert!(closed(&mut slow).await);
    assert!(started.elapsed() <= Duration::from_millis(2_100));

    let mut drip = net.raw(&link).await;
    let started = tokio::time::Instant::now();
    for b in [0u8, 0, 0, 2] {
        if drip.write_all(&[b]).await.is_err() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(900)).await;
    }
    assert!(closed(&mut drip).await, "a frame dripped too slowly");
    assert!(started.elapsed() <= Duration::from_millis(3_700));

    let mut idle = net.raw(&link).await;
    let started = tokio::time::Instant::now();
    assert!(closed(&mut idle).await);
    assert!(started.elapsed() >= Duration::from_secs(60));

    let client = LeaseClient::connect(link, net.server_key(), ClientConfig::default())
        .await
        .unwrap();
    let live = RemoteLiveness::new(client);
    live.heartbeat(&g(), &profile("node-s", NodeClass::Desktop), Timestamp(0))
        .await
        .unwrap();
    let _ = id;
}

#[tokio::test(start_paused = true)]
async fn per_peer_and_total_stream_caps_hold_against_many_peers() {
    let net = Net::new(ServerConfig {
        max_per_peer: 2,
        max_streams: 16,
        idle_timeout: Duration::from_secs(30),
        ..config()
    })
    .await;
    let (_, greedy) = net.peer("greedy");
    let mut streams = Vec::new();
    for _ in 0..10 {
        streams.push(net.raw(&greedy).await);
    }
    let mut kept_n = 0;
    for s in &mut streams {
        if kept(s).await {
            kept_n += 1;
        }
    }
    assert_eq!(kept_n, 2, "one peer keeps at most max_per_peer streams");

    let mut crowd = Vec::new();
    for i in 0..40 {
        let (_, link) = net.peer(&format!("crowd-{i}"));
        let s = net.raw(&link).await;
        crowd.push((link, s));
    }
    let mut kept_n = 0;
    for (_, s) in &mut crowd {
        if kept(s).await {
            kept_n += 1;
        }
    }
    assert_eq!(kept_n, 14, "all peers together keep at most max_streams");
    let (_, late) = net.peer("late");
    assert!(unavailable(
        LeaseClient::connect(late.clone(), net.server_key(), ClientConfig::default()).await
    ));

    tokio::time::sleep(Duration::from_secs(31)).await;
    let n = LeaseClient::connect(late, net.server_key(), ClientConfig::default())
        .await
        .expect("idle streams expired and freed their slots");
    RemoteLiveness::new(n)
        .heartbeat(&g(), &profile("late", NodeClass::Desktop), Timestamp(0))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restart_keeps_tokens_growing_and_only_delays_takeovers() {
    let net = Net::new(config()).await;
    let a = net.node("node-a", NodeClass::Desktop).await;
    let b = net.node("node-b", NodeClass::Desktop).await;
    a.seen().await;
    b.seen().await;
    let held = a.take("k").await.unwrap().unwrap();

    net.stop().await;
    assert!(unavailable(a.take("k").await));
    assert!(unavailable(a.beat(&g()).await));

    net.now.store(T0 - 3_600_000, Ordering::SeqCst);
    net.start(config()).await;
    a.seen().await;
    let renewed = a.take("k").await.unwrap().expect("the clients reconnect");
    assert_eq!(renewed.fence, held.fence, "state survived in the store");
    assert!(
        b.take("k").await.unwrap().is_none(),
        "a fresh observer keeps the holder for a time-to-live"
    );

    b.seen().await;
    net.advance(TTL as i64 + 1);
    b.seen().await;
    let taken = b.take("k").await.unwrap().unwrap();
    assert!(
        taken.fence > held.fence,
        "tokens never go down, even with the server's clock an hour back"
    );
}

#[tokio::test(start_paused = true)]
async fn with_the_server_down_calls_fail_and_the_holder_expires_itself() {
    let net = Net::new(config()).await;
    let a = net.node("node-a", NodeClass::Desktop).await;
    let margin = Duration::from_secs(2);
    assert!(!a.live.holding(&g(), margin));
    a.beat(&g()).await.unwrap();
    let held = a.take("k").await.unwrap().unwrap();
    let until = a.live.valid_until(&g(), margin).unwrap();
    assert!(a.live.holding(&g(), margin));

    net.stop().await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(unavailable(a.beat(&g()).await));
    assert!(unavailable(a.take("k").await));
    assert!(unavailable(a.leases.holder(&g(), &key("k")).await));
    assert!(unavailable(a.leases.release(&held).await));
    assert!(unavailable(a.live.alive(&g(), Timestamp(0)).await));
    assert_eq!(
        a.live.valid_until(&g(), margin),
        Some(until),
        "failed heartbeats extend nothing"
    );
    assert!(a.live.holding(&g(), margin));
    tokio::time::sleep_until(until).await;
    assert!(
        !a.live.holding(&g(), margin),
        "ttl minus the margin after the last confirmed heartbeat, the holder stops"
    );

    net.start(config()).await;
    a.beat(&g()).await.unwrap();
    assert!(
        a.live.holding(&g(), margin),
        "a confirmed heartbeat resumes"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_alive_list_larger_than_the_reply_limit_is_refused() {
    let net = Net::new(ServerConfig {
        max_reply: 256,
        ..config()
    })
    .await;
    let mut nodes = Vec::new();
    for i in 0..12 {
        let n = net
            .node(&format!("node-with-a-long-name-{i}"), NodeClass::Desktop)
            .await;
        n.beat(&g()).await.unwrap();
        nodes.push(n);
    }
    let e = nodes[0].live.alive(&g(), Timestamp(0)).await.unwrap_err();
    assert_eq!(remote(&e), Some(RemoteError::TooLarge));
    nodes[0].beat(&g()).await.unwrap();
}

async fn liar(net: &Net, replies: Vec<Vec<u8>>) -> Arc<LeaseClient> {
    let hub = &net.hub;
    let fake = Identity::generate();
    let link = hub.join(fake.public(), Arc::new(AllowAll));
    let mut incoming = link
        .listen(&Protocol::new(PROTOCOL).unwrap())
        .await
        .unwrap();
    tokio::spawn(async move {
        let _keep = link;
        let replies = Arc::new(replies);
        while let Some(mut inc) = incoming.next().await {
            let replies = replies.clone();
            tokio::spawn(async move {
                for r in replies.iter() {
                    if wire::read_frame(&mut inc.stream, wire::MAX_REQUEST)
                        .await
                        .is_err()
                    {
                        return;
                    }
                    let _ = inc.stream.write_all(r).await;
                }
            });
        }
    });
    let (_, me) = net.peer("victim");
    LeaseClient::connect(me, fake.public(), ClientConfig::default())
        .await
        .unwrap()
}

fn framed(reply: &Reply) -> Vec<u8> {
    let body = wire::encode_reply(reply);
    let mut out = (body.len() as u32).to_be_bytes().to_vec();
    out.extend(body);
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lying_server_gets_protocol_errors() {
    let net = Net::new(config()).await;
    let hello = framed(&Reply::Hello {
        ttl_ms: TTL,
        max_request: 1024,
        max_reply: 1024,
    });
    let me = profile("victim", NodeClass::Desktop);
    let other_lease = Lease {
        group: g(),
        key: key("other"),
        node: me.node.clone(),
        class: NodeClass::Desktop,
        fence: baton_core::FencingToken(1),
        takeover: None,
    };
    let cases = vec![
        framed(&Reply::Lease(Some(other_lease.clone()))),
        framed(&Reply::Lease(Some(Lease {
            key: key("k"),
            node: NodeId::new("someone-else").unwrap(),
            ..other_lease
        }))),
        framed(&Reply::Done),
        u32::MAX.to_be_bytes().to_vec(),
        vec![0, 0, 0, 3, wire::VERSION, 250, 250],
    ];
    for case in cases {
        let client = liar(&net, vec![hello.clone(), case]).await;
        let e = RemoteLeases::new(client)
            .acquire(&g(), &key("k"), &me)
            .await
            .unwrap_err();
        assert_eq!(remote(&e), Some(RemoteError::Protocol));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restart_with_a_shorter_ttl_never_lets_two_nodes_hold_at_once() {
    let net = Net::new(ServerConfig {
        ttl_ms: 15_000,
        ..config()
    })
    .await;
    let h = net.node("holder", NodeClass::Desktop).await;
    let b = net.node("other", NodeClass::Desktop).await;
    h.beat(&g()).await.unwrap();
    b.beat(&g()).await.unwrap();
    let held = h.take("k").await.unwrap().unwrap();
    assert_eq!(h.live.ttl_ms(), 15_000);
    net.stop().await;
    net.start(ServerConfig {
        ttl_ms: 5_000,
        previous_ttl_ms: 15_000,
        ..config()
    })
    .await;
    b.seen().await;
    assert!(b.take("k").await.unwrap().is_none());
    net.advance(6_000);
    b.seen().await;
    assert!(
        b.take("k").await.unwrap().is_none(),
        "the holder may still believe 15 s, so 6 s of silence is not enough"
    );
    net.advance(9_001);
    b.seen().await;
    let taken = b
        .take("k")
        .await
        .unwrap()
        .expect("after the old time-to-live of silence it moves");
    assert!(taken.fence > held.fence);

    let started = tokio::time::Instant::now();
    h.beat(&g()).await.unwrap();
    assert_eq!(
        h.live.ttl_ms(),
        5_000,
        "the heartbeat reply carries the new time-to-live"
    );
    let until = h.live.valid_until(&g(), Duration::ZERO).unwrap();
    assert!(
        until <= started + Duration::from_millis(5_000) + Duration::from_millis(500),
        "self-expiry follows the shorter time-to-live at once"
    );
}
