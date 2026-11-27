//! Load scenarios. Each returns a [`Report`] and fails with a message when an invariant breaks or
//! a number falls below what the scenario expects, so a regression is visible.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use baton_core::{GroupId, LeaseKey, NodeId, Timestamp};
use baton_lease::{Leases, Liveness, NodeClass, NodeProfile, TakeoverOutcome};
use baton_lease_cas::{CasLeases, CasLiveness};
use baton_signal::Signal;
use baton_signal_local::LocalSignal;
use baton_state::StateStore;
use baton_state_memory::MemoryState;
use bytes::Bytes;
use futures::StreamExt;

/// What a scenario measured.
#[derive(Debug)]
pub struct Report {
    /// The scenario.
    pub name: &'static str,
    /// Operations performed.
    pub ops: u64,
    /// Wall time.
    pub elapsed: Duration,
    /// Free-form facts worth printing.
    pub notes: String,
}

impl Report {
    /// Operations per second.
    pub fn rate(&self) -> f64 {
        self.ops as f64 / self.elapsed.as_secs_f64().max(1e-9)
    }
}

fn profile(name: &str, class: NodeClass) -> NodeProfile {
    NodeProfile {
        node: NodeId::new(name).unwrap(),
        class,
        weight: 1,
        can_run: true,
    }
}

fn group() -> GroupId {
    GroupId::new("load").unwrap()
}

async fn setup(nodes: &[NodeProfile]) -> Arc<CasLeases> {
    let state: Arc<dyn StateStore> = Arc::new(MemoryState::new());
    let live = Arc::new(CasLiveness::new(state.clone(), 60_000));
    for n in nodes {
        live.heartbeat(&group(), n, Timestamp::now()).await.unwrap();
    }
    Arc::new(CasLeases::new(state, live))
}

/// `nodes` nodes race for `keys` keys at once, each node trying every key. Expects one holder per
/// key and at least `min_rate` acquire calls per second.
pub async fn contention(nodes: usize, keys: usize, min_rate: f64) -> Result<Report, String> {
    let profiles: Vec<_> = (0..nodes)
        .map(|i| profile(&format!("n{i}"), NodeClass::Server))
        .collect();
    let leases = setup(&profiles).await;
    let started = Instant::now();
    let mut tasks = Vec::new();
    for p in profiles {
        let leases = leases.clone();
        tasks.push(tokio::spawn(async move {
            let mut won = Vec::new();
            for k in 0..keys {
                let key = LeaseKey::new(format!("k{k}")).unwrap();
                if let Some(l) = leases.acquire(&group(), &key, &p).await.unwrap() {
                    won.push(l);
                }
            }
            won
        }));
    }
    let mut holders = HashMap::new();
    for t in tasks {
        for l in t.await.unwrap() {
            if let Some(prev) = holders.insert(l.key.clone(), l.clone()) {
                return Err(format!("two holders for {}: {prev:?} and {l:?}", l.key));
            }
        }
    }
    let elapsed = started.elapsed();
    if holders.len() != keys {
        return Err(format!("{} of {keys} keys got a holder", holders.len()));
    }
    let report = Report {
        name: "contention",
        ops: (nodes * keys) as u64,
        elapsed,
        notes: format!("{nodes} nodes x {keys} keys, one holder each"),
    };
    if report.rate() < min_rate {
        return Err(format!(
            "{:.0} acquires/s, expected at least {min_rate:.0}",
            report.rate()
        ));
    }
    Ok(report)
}

/// `keys` keys held by phones are handed over to one server. Expects every key on the server with
/// a higher token, within `max` time.
pub async fn handover(keys: usize, max: Duration) -> Result<Report, String> {
    let phones: Vec<_> = (0..8)
        .map(|i| profile(&format!("phone{i}"), NodeClass::Phone))
        .collect();
    let server = profile("server", NodeClass::Server);
    let mut all = phones.clone();
    all.push(server.clone());
    let leases = setup(&all).await;
    let mut held = Vec::new();
    for k in 0..keys {
        let key = LeaseKey::new(format!("h{k}")).unwrap();
        let p = &phones[k % phones.len()];
        held.push(leases.acquire(&group(), &key, p).await.unwrap().unwrap());
    }
    let started = Instant::now();
    for l in &held {
        let o = leases
            .request_takeover(&group(), &l.key, &server)
            .await
            .unwrap();
        if o != TakeoverOutcome::Recorded {
            return Err(format!("takeover of {} was {o:?}", l.key));
        }
    }
    for l in &held {
        let p = phones.iter().find(|p| p.node == l.node).unwrap();
        let renewed = leases.acquire(&group(), &l.key, p).await.unwrap().unwrap();
        if renewed.takeover.as_ref().map(|t| &t.node) != Some(&server.node) {
            return Err(format!("{} did not see the takeover", l.key));
        }
        leases.release(&renewed).await.unwrap();
        let got = leases
            .acquire(&group(), &l.key, &server)
            .await
            .unwrap()
            .ok_or_else(|| format!("server did not get {}", l.key))?;
        if got.fence <= l.fence {
            return Err(format!(
                "{}: token {} after {}",
                l.key, got.fence.0, l.fence.0
            ));
        }
    }
    let elapsed = started.elapsed();
    if elapsed > max {
        return Err(format!(
            "handover of {keys} keys took {elapsed:?}, expected under {max:?}"
        ));
    }
    Ok(Report {
        name: "handover",
        ops: keys as u64 * 4,
        elapsed,
        notes: format!("{keys} keys from 8 phones to one server"),
    })
}

/// One publisher, `subscribers` subscribers reading as fast as they can, `messages` messages.
/// Expects at least `min_rate` publishes per second and every subscriber to see the last message.
pub async fn fanout(subscribers: usize, messages: usize, min_rate: f64) -> Result<Report, String> {
    if messages == 0 {
        return Err("fanout needs at least one message".to_owned());
    }
    let sig = Arc::new(LocalSignal::new());
    let g = group();
    let mut readers = Vec::new();
    for _ in 0..subscribers {
        let mut sub = sig.subscribe(&g, "fan").await.unwrap();
        let last = (messages - 1) as u32;
        readers.push(tokio::spawn(async move {
            let mut seen = 0u64;
            while let Some(m) = sub.next().await {
                seen += 1;
                if u32::from_be_bytes(m[..4].try_into().unwrap()) == last {
                    return seen;
                }
            }
            seen
        }));
    }
    let started = Instant::now();
    for i in 0..messages as u32 {
        sig.publish(&g, "fan", Bytes::from(i.to_be_bytes().to_vec()))
            .await
            .unwrap();
        if i % 512 == 0 {
            tokio::task::yield_now().await;
        }
    }
    let elapsed = started.elapsed();
    let mut min_seen = u64::MAX;
    for r in readers {
        let seen = tokio::time::timeout(Duration::from_secs(30), r)
            .await
            .map_err(|_| "a subscriber never saw the last message".to_owned())?
            .unwrap();
        min_seen = min_seen.min(seen);
    }
    let report = Report {
        name: "fanout",
        ops: messages as u64,
        elapsed,
        notes: format!("{subscribers} subscribers; the slowest saw {min_seen} of {messages}"),
    };
    if report.rate() < min_rate {
        return Err(format!(
            "{:.0} publishes/s, expected at least {min_rate:.0}",
            report.rate()
        ));
    }
    Ok(report)
}

/// Nodes go offline in turns (longer than the time-to-live) while others acquire. Expects tokens
/// of every key to only grow, no token held by two nodes, and a holder replaced only after it has
/// been silent for the whole time-to-live.
pub async fn churn(rounds: usize) -> Result<Report, String> {
    const TTL: i64 = 1_000;
    const STEP: i64 = 250;
    let state: Arc<dyn StateStore> = Arc::new(MemoryState::new());
    let live = Arc::new(CasLiveness::new(state.clone(), TTL as u64));
    let now = Arc::new(std::sync::atomic::AtomicI64::new(1_000_000));
    let clock_now = now.clone();
    let leases = Arc::new(
        CasLeases::new(state, live.clone()).with_clock(Arc::new(move || {
            Timestamp(clock_now.load(std::sync::atomic::Ordering::SeqCst))
        })),
    );
    let nodes: Vec<_> = (0..6)
        .map(|i| profile(&format!("c{i}"), NodeClass::Desktop))
        .collect();
    let keys: Vec<_> = (0..20)
        .map(|k| LeaseKey::new(format!("c{k}")).unwrap())
        .collect();
    let mut seen: HashMap<(LeaseKey, u64), NodeId> = HashMap::new();
    let mut last: HashMap<LeaseKey, (u64, NodeId)> = HashMap::new();
    let mut last_beat: HashMap<NodeId, i64> = HashMap::new();
    let started = Instant::now();
    let mut ops = 0u64;
    let mut moves = 0u64;
    for round in 0..rounds {
        let t = 1_000_000 + round as i64 * STEP;
        now.store(t, std::sync::atomic::Ordering::SeqCst);
        for (i, n) in nodes.iter().enumerate() {
            let offline = (round / 12 + i) % 3 == 0;
            if !offline {
                live.heartbeat(&group(), n, Timestamp(t)).await.unwrap();
                last_beat.insert(n.node.clone(), t);
            }
        }
        for (i, k) in keys.iter().enumerate() {
            let n = &nodes[(round * 7 + i) % nodes.len()];
            ops += 1;
            if let Some(l) = leases.acquire(&group(), k, n).await.unwrap() {
                if let Some(other) = seen.insert((k.clone(), l.fence.0), l.node.clone())
                    && other != l.node
                {
                    return Err(format!(
                        "{k}: token {} held by {other} and {}",
                        l.fence.0, l.node
                    ));
                }
                if let Some((prev_fence, prev_node)) = last.get(k) {
                    if l.fence.0 < *prev_fence {
                        return Err(format!(
                            "{k}: token went back from {prev_fence} to {}",
                            l.fence.0
                        ));
                    }
                    if prev_node != &l.node {
                        moves += 1;
                        let silent = t - last_beat.get(prev_node).copied().unwrap_or(i64::MIN / 2);
                        if silent < TTL {
                            return Err(format!(
                                "{k}: {prev_node} replaced by {} after only {silent} ms of silence",
                                l.node
                            ));
                        }
                    }
                }
                last.insert(k.clone(), (l.fence.0, l.node.clone()));
            }
        }
    }
    if rounds >= 100 && moves == 0 {
        return Err("no lease ever moved, so the scenario tested nothing".to_owned());
    }
    Ok(Report {
        name: "churn",
        ops,
        elapsed: started.elapsed(),
        notes: format!(
            "{rounds} rounds, 6 nodes offline in turns, 20 keys, {moves} handovers after silence"
        ),
    })
}

/// A group with `nodes` devices and `resources` resources, each granted to every node and given a
/// key epoch sealed to all of them, then verified from genesis as a fresh device would. Expects
/// verification within `max`.
pub async fn group_log(nodes: usize, resources: usize, max: Duration) -> Result<Report, String> {
    use baton_group::{Capability, Founding, GroupLog, NodeCert, Op, Principal, epochs};
    use baton_identity::Identity;
    use baton_keys::{KemSecret, RecoveryRoot};
    let t = Timestamp(1_700_000_000_000);
    let later = Timestamp(1_900_000_000_000);
    let owner = Identity::generate();
    let laptop = Identity::generate();
    let mut log = GroupLog::genesis(
        GroupId::new("load").unwrap(),
        Founding {
            owner: &owner,
            owner_recovery: RecoveryRoot::generate().public(),
            group_recovery: RecoveryRoot::generate().public(),
            node: &laptop,
            node_kem: KemSecret::generate().public(),
            class: NodeClass::Desktop,
            expires: later,
        },
        t,
    )
    .map_err(|e| e.to_string())?;
    for _ in 0..nodes {
        let cert = NodeCert::new(
            &owner,
            &Identity::generate(),
            KemSecret::generate().public(),
            NodeClass::Phone,
            later,
        );
        log.append(&laptop, Op::CertifyNode { cert }, t)
            .map_err(|e| e.to_string())?;
    }
    for i in 0..resources {
        let r = baton_core::ResourceId::new(format!("r{i}")).unwrap();
        log.append(
            &laptop,
            Op::CreateResource {
                resource: r.clone(),
            },
            t,
        )
        .map_err(|e| e.to_string())?;
        log.append(
            &laptop,
            Op::Grant {
                resource: r.clone(),
                principal: Principal::Member(owner.public()),
                capabilities: [Capability::Read, Capability::Lead, Capability::Admin]
                    .into_iter()
                    .collect(),
            },
            t,
        )
        .map_err(|e| e.to_string())?;
        let (op, _) = epochs::new_epoch(log.state(), &r, t).map_err(|e| e.to_string())?;
        log.append(&laptop, op, t).map_err(|e| e.to_string())?;
    }
    let entries = log.entries().to_vec();
    let bytes: usize = entries.iter().map(|e| e.encode().len()).sum();
    let started = Instant::now();
    let verified = GroupLog::verify(entries).map_err(|e| e.to_string())?;
    let elapsed = started.elapsed();
    if verified.head_hash() != log.head_hash() {
        return Err("the verified log differs".into());
    }
    if elapsed > max {
        return Err(format!(
            "verifying {} entries took {elapsed:?}, expected under {max:?}",
            verified.entries().len()
        ));
    }
    Ok(Report {
        name: "group",
        ops: verified.entries().len() as u64,
        elapsed,
        notes: format!(
            "{nodes} nodes, {resources} resources with epochs, {:.1} MB of log verified from genesis",
            bytes as f64 / 1e6
        ),
    })
}

struct Objects(std::collections::HashMap<baton_fetch::ContentId, Bytes>);

#[async_trait::async_trait]
impl baton_fetch::LocalObjects for Objects {
    async fn get(
        &self,
        _: &baton_core::ResourceId,
        id: &baton_fetch::ContentId,
        _: &[u8],
    ) -> Option<Bytes> {
        self.0.get(id).cloned()
    }
}

/// `count` objects of `size` bytes fetched one after another from a peer over the in-memory link,
/// each verified. Expects at least `min_mb_s` megabytes per second.
pub async fn fetch(count: usize, size: usize, min_mb_s: f64) -> Result<Report, String> {
    use baton_fetch::{ContentId, FetchConfig, Fetcher, serve};
    use baton_identity::Identity;
    use baton_link::{Link, PinnedKeys};
    let hub = baton_link_memory::MemoryLinkHub::new();
    let (a, b) = (Identity::generate(), Identity::generate());
    let trust = || Arc::new(PinnedKeys::new([a.public(), b.public()]));
    let la: Arc<dyn Link> = Arc::new(hub.join(a.public(), trust()));
    let lb: Arc<dyn Link> = Arc::new(hub.join(b.public(), trust()));
    let mut objects = std::collections::HashMap::new();
    let mut ids = Vec::new();
    for i in 0..count {
        let mut v = vec![(i % 251) as u8; size];
        v[..8].copy_from_slice(&(i as u64).to_be_bytes());
        let id = ContentId::of(&v);
        ids.push(id);
        objects.insert(id, Bytes::from(v));
    }
    let _server = serve(
        lb,
        Arc::new(Objects(objects)),
        Arc::new(|_, _| true),
        FetchConfig::default(),
    )
    .await
    .map_err(|e| e.to_string())?;
    let f = Fetcher::new(la, None, FetchConfig::default());
    let r = baton_core::ResourceId::new("load").unwrap();
    let started = Instant::now();
    for id in &ids {
        f.fetch(&r, id, &[b.public()])
            .await
            .map_err(|e| e.to_string())?;
    }
    let elapsed = started.elapsed();
    let mb_s = (count * size) as f64 / 1e6 / elapsed.as_secs_f64().max(1e-9);
    if mb_s < min_mb_s {
        return Err(format!("{mb_s:.1} MB/s, expected at least {min_mb_s:.1}"));
    }
    Ok(Report {
        name: "fetch",
        ops: count as u64,
        elapsed,
        notes: format!("{count} objects of {size} bytes, {mb_s:.0} MB/s verified"),
    })
}

/// `boxes` boxes, each with its own reader and writer, filled with `per_box` messages of 64 bytes
/// concurrently through `mailbox-memory` (the drop service with its memory store, every request
/// signed, checked and replay-cached), then drained with takes and acknowledgements. Expects every
/// message exactly once and in order, empty boxes at the end, and at least `min_rate` messages
/// per second (puts plus taken messages).
pub async fn drop_memory(boxes: usize, per_box: usize, min_rate: f64) -> Result<Report, String> {
    use baton_drop::admission::AdmissionConfig;
    use baton_mailbox_memory::MemoryMailbox;
    let mb: Arc<dyn baton_mailbox::Mailbox> = Arc::new(
        MemoryMailbox::new(AdmissionConfig::open(), baton_drop::system_clock())
            .await
            .map_err(|e| e.to_string())?,
    );
    drop_exercise("drop_memory", mb, boxes, per_box, boxes, min_rate).await
}

/// `boxes` boxes with `per_box` messages each through `mailbox-drop` over HTTP/1.1 to a
/// `drop-http` server on 127.0.0.1 (memory store, no rate limit), 32 boxes at a time (so the
/// test stays within default file descriptor limits), put concurrently, then drained
/// with takes and acks; fails on a lost, repeated or reordered message or under `min_rate`
/// messages per second.
pub async fn drop_http(boxes: usize, per_box: usize, min_rate: f64) -> Result<Report, String> {
    use baton_drop::admission::AdmissionConfig;
    use baton_drop::{DropConfig, DropService, MemoryDropStore};
    use baton_drop_http::HttpConfig;
    let clock = baton_drop::system_clock();
    let service = Arc::new(
        DropService::new(
            Arc::new(MemoryDropStore::new()),
            DropConfig::new("drop.example.com", AdmissionConfig::open()),
            clock.clone(),
        )
        .map_err(|e| e.to_string())?,
    );
    let config = HttpConfig {
        rate: None,
        ..HttpConfig::default()
    };
    let router = baton_drop_http::router(service, config.clone(), clock.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        baton_drop_http::serve(listener, router, &config, None, async {
            let _ = stopped.await;
        })
        .await
    });
    let url = url::Url::parse(&format!("http://{addr}/")).map_err(|e| e.to_string())?;
    let mb = baton_mailbox_drop::connect(
        &url,
        "drop.example.com",
        clock,
        &baton_mailbox_drop::ClientConfig::default(),
    )
    .await
    .map_err(|e| e.to_string())?;
    let report = drop_exercise("drop_http", Arc::new(mb), boxes, per_box, 32, min_rate).await;
    let _ = stop.send(());
    let _ = server.await;
    report
}

async fn drop_exercise(
    name: &'static str,
    mb: Arc<dyn baton_mailbox::Mailbox>,
    boxes: usize,
    per_box: usize,
    parallel: usize,
    min_rate: f64,
) -> Result<Report, String> {
    use baton_mailbox::{Admission, BoxId, BoxKey, BoxPolicy};
    let slots = Arc::new(tokio::sync::Semaphore::new(parallel.max(1)));
    let mut setup = Vec::new();
    for _ in 0..boxes {
        let (reader, writer) = (BoxKey::generate(), BoxKey::generate());
        let id = BoxId::of_reader(&reader.public());
        let mut policy = BoxPolicy::new(reader.public(), vec![writer.public()]);
        policy.max_messages = per_box as u32;
        policy.max_bytes = 1 << 20;
        policy.ttl_ms = 24 * 3600 * 1000;
        mb.create(&id, &policy, &reader, &Admission::None)
            .await
            .map_err(|e| e.to_string())?;
        setup.push((id, reader, writer));
    }
    let started = Instant::now();
    let mut tasks = Vec::new();
    for (id, reader, writer) in setup {
        let mb = mb.clone();
        let slots = slots.clone();
        tasks.push(tokio::spawn(async move {
            let _slot = slots.acquire_owned().await.map_err(|e| e.to_string())?;
            for i in 0..per_box {
                let mut body = vec![0u8; 64];
                body[..8].copy_from_slice(&(i as u64).to_be_bytes());
                mb.put(&id, &writer, Bytes::from(body))
                    .await
                    .map_err(|e| format!("put: {e}"))?;
            }
            let mut seen = 0usize;
            loop {
                let got = mb
                    .take(&id, &reader, None, 256, Duration::ZERO)
                    .await
                    .map_err(|e| format!("take: {e}"))?;
                let Some(last) = got.last().map(|m| m.id) else {
                    break;
                };
                for m in &got {
                    let n = u64::from_be_bytes(m.bytes[..8].try_into().unwrap()) as usize;
                    if n != seen {
                        return Err(format!("message {n} where {seen} was expected"));
                    }
                    seen += 1;
                }
                mb.ack(&id, &reader, last)
                    .await
                    .map_err(|e| format!("ack: {e}"))?;
            }
            if seen != per_box {
                return Err(format!("{seen} of {per_box} messages came back"));
            }
            Ok::<_, String>(())
        }));
    }
    for t in tasks {
        t.await.map_err(|e| e.to_string())??;
    }
    let elapsed = started.elapsed();
    let report = Report {
        name,
        ops: (2 * boxes * per_box) as u64,
        elapsed,
        notes: format!("{boxes} boxes x {per_box} messages, put then take and ack"),
    };
    if report.rate() < min_rate {
        return Err(format!(
            "{:.0} messages/s, expected at least {min_rate:.0}",
            report.rate()
        ));
    }
    Ok(report)
}

/// `clients` nodes, each with its own link identity, race through a lease server over the
/// in-memory link for `keys` keys, every node trying every key (requests checked against the
/// link-authenticated peer and the authorization callback, decided by `CasLeases` on the
/// server's store). Expects one holder per key with distinct tokens, the server agreeing on every
/// holder, and at least `min_rate` acquire calls per second.
pub async fn lease_server(clients: usize, keys: usize, min_rate: f64) -> Result<Report, String> {
    use baton_identity::Identity;
    use baton_lease_server::{
        Authorize, ClientConfig, LeaseClient, LeaseServer, RemoteLeases, RemoteLiveness,
        ServerConfig,
    };
    use baton_link::{Link, PublicKey, Trust};

    struct Open;
    impl Trust for Open {
        fn allows(&self, _: &PublicKey) -> bool {
            true
        }
    }
    impl Authorize for Open {
        fn member(&self, _: &PublicKey, _: &GroupId) -> bool {
            true
        }
        fn lease(&self, _: &PublicKey, _: &GroupId, _: &LeaseKey) -> bool {
            true
        }
    }

    let hub = baton_link_memory::MemoryLinkHub::new();
    let server_id = Identity::generate();
    let server_link: Arc<dyn Link> = Arc::new(hub.join(server_id.public(), Arc::new(Open)));
    let _server = LeaseServer::start(
        server_link,
        Arc::new(MemoryState::new()),
        Arc::new(Open),
        baton_lease_cas::monotonic_clock(),
        ServerConfig {
            ttl_ms: 60_000,
            ..ServerConfig::default()
        },
    )
    .await
    .map_err(|e| e.to_string())?;
    let mut nodes = Vec::new();
    for _ in 0..clients {
        let id = Identity::generate();
        let link: Arc<dyn Link> = Arc::new(hub.join(id.public(), Arc::new(Open)));
        let client = LeaseClient::connect(link, server_id.public(), ClientConfig::default())
            .await
            .map_err(|e| e.to_string())?;
        let me = NodeProfile {
            node: id.node_id(),
            class: NodeClass::Server,
            weight: 1,
            can_run: true,
        };
        RemoteLiveness::new(client.clone())
            .heartbeat(&group(), &me, Timestamp::now())
            .await
            .map_err(|e| e.to_string())?;
        nodes.push((RemoteLeases::new(client), me));
    }
    let started = Instant::now();
    let mut tasks = Vec::new();
    for (leases, me) in nodes {
        tasks.push(tokio::spawn(async move {
            let mut won = Vec::new();
            for k in 0..keys {
                let key = LeaseKey::new(format!("k{k}")).unwrap();
                if let Some(l) = leases.acquire(&group(), &key, &me).await? {
                    won.push(l);
                }
            }
            Ok::<_, baton_lease::LeaseError>((leases, won))
        }));
    }
    let mut holders = HashMap::new();
    let mut fences = std::collections::HashSet::new();
    let mut observer = None;
    for t in tasks {
        let (leases, won) = t.await.unwrap().map_err(|e| e.to_string())?;
        for l in won {
            if !fences.insert(l.fence) {
                return Err(format!("token {:?} granted twice", l.fence));
            }
            if let Some(prev) = holders.insert(l.key.clone(), l.clone()) {
                return Err(format!("two holders for {}: {prev:?} and {l:?}", l.key));
            }
        }
        observer = Some(leases);
    }
    let elapsed = started.elapsed();
    if holders.len() != keys {
        return Err(format!("{} of {keys} keys got a holder", holders.len()));
    }
    if let Some(observer) = observer {
        for (key, l) in &holders {
            let seen = observer
                .holder(&group(), key)
                .await
                .map_err(|e| e.to_string())?;
            if seen.as_ref() != Some(l) {
                return Err(format!("the server disagrees on {key}: {seen:?}"));
            }
        }
    }
    let report = Report {
        name: "lease_server",
        ops: (clients * keys) as u64,
        elapsed,
        notes: format!("{clients} clients x {keys} keys over the link, one holder each"),
    };
    if report.rate() < min_rate {
        return Err(format!(
            "{:.0} remote acquires/s, expected at least {min_rate:.0}",
            report.rate()
        ));
    }
    Ok(report)
}

/// One member pushes `entries` signed entries to a group server over the in-memory link, then
/// `clients` members sync the whole log at once, each verifying every entry from genesis.
/// Expects every member to end at the pushed head, and at least `min_rate` entries verified per
/// second across members.
pub async fn group_server(entries: usize, clients: usize, min_rate: f64) -> Result<Report, String> {
    use baton_group::{Founding, GroupLog, NodeCert, Op};
    use baton_group_server::{
        Admit, ClientConfig, GroupClient, GroupLogs, GroupServer, ServerConfig,
    };
    use baton_identity::Identity;
    use baton_keys::{KemSecret, RecoveryRoot};
    use baton_link::{Link, PublicKey, Trust};

    struct Open;
    impl Trust for Open {
        fn allows(&self, _: &PublicKey) -> bool {
            true
        }
    }
    impl Admit for Open {
        fn admits(&self, _: &PublicKey, _: &GroupId) -> bool {
            true
        }
    }

    let now = Timestamp::now();
    let owner = Identity::generate();
    let founder = Identity::generate();
    let mut log = GroupLog::genesis(
        group(),
        Founding {
            owner: &owner,
            owner_recovery: RecoveryRoot::generate().public(),
            group_recovery: RecoveryRoot::generate().public(),
            node: &founder,
            node_kem: KemSecret::generate().public(),
            class: NodeClass::Desktop,
            expires: now.plus_ms(86_400_000),
        },
        now,
    )
    .map_err(|e| e.to_string())?;
    let hub = baton_link_memory::MemoryLinkHub::new();
    let server_id = Identity::generate();
    let server_link: Arc<dyn Link> = Arc::new(hub.join(server_id.public(), Arc::new(Open)));
    let logs = Arc::new(GroupLogs::new(
        [(group(), log.genesis_hash())],
        Arc::new(MemoryState::new()),
        entries as u64 + 10,
    ));
    let _server = GroupServer::start(
        server_link,
        logs,
        Arc::new(Open),
        Arc::new(Timestamp::now),
        ServerConfig {
            push_per_second: u32::MAX,
            push_burst: u32::MAX,
            ..ServerConfig::default()
        },
    )
    .await
    .map_err(|e| e.to_string())?;
    let link: Arc<dyn Link> = Arc::new(hub.join(founder.public(), Arc::new(Open)));
    let pusher = GroupClient::connect(link, server_id.public(), ClientConfig::default())
        .await
        .map_err(|e| e.to_string())?;
    pusher
        .push(&log.entries()[0])
        .await
        .map_err(|e| e.to_string())?;
    let started = Instant::now();
    for _ in 0..entries {
        let node = Identity::generate();
        let e = log
            .append(
                &founder,
                Op::CertifyNode {
                    cert: NodeCert::new(
                        &owner,
                        &node,
                        KemSecret::generate().public(),
                        NodeClass::Server,
                        now.plus_ms(86_400_000),
                    ),
                },
                now,
            )
            .map_err(|e| e.to_string())?;
        pusher.push(&e).await.map_err(|e| e.to_string())?;
    }
    let pushed = started.elapsed();
    let genesis = log.genesis_hash();
    let head = log.head_hash();
    let mut tasks = Vec::new();
    for _ in 0..clients {
        let id = Identity::generate();
        let link: Arc<dyn Link> = Arc::new(hub.join(id.public(), Arc::new(Open)));
        let server = server_id.public();
        tasks.push(tokio::spawn(async move {
            let c = GroupClient::connect(link, server, ClientConfig::default())
                .await
                .map_err(|e| e.to_string())?;
            c.sync(&group(), genesis, None, Timestamp::now())
                .await
                .map_err(|e| e.to_string())
        }));
    }
    let started = Instant::now();
    for t in tasks {
        let synced = t.await.map_err(|e| e.to_string())??;
        if synced.head_hash() != head {
            return Err("a member synced to another head".to_owned());
        }
    }
    let elapsed = started.elapsed();
    let report = Report {
        name: "group_server",
        ops: ((entries + 1) * clients) as u64,
        elapsed,
        notes: format!(
            "{clients} members synced {} entries each; {entries} pushes in {pushed:.3?} ({:.0}/s)",
            entries + 1,
            entries as f64 / pushed.as_secs_f64().max(1e-9)
        ),
    };
    if report.rate() < min_rate {
        return Err(format!(
            "{:.0} entries verified/s, expected at least {min_rate:.0}",
            report.rate()
        ));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn small_versions_pass_in_ci() {
        contention(8, 200, 0.0).await.unwrap();
        handover(100, Duration::from_secs(60)).await.unwrap();
        fanout(8, 5_000, 0.0).await.unwrap();
        churn(400).await.unwrap();
        assert!(fanout(1, 0, 0.0).await.is_err());
        group_log(5, 5, Duration::from_secs(120)).await.unwrap();
        fetch(50, 16 * 1024, 0.0).await.unwrap();
        drop_memory(20, 50, 0.0).await.unwrap();
        drop_http(10, 20, 0.0).await.unwrap();
        lease_server(8, 100, 0.0).await.unwrap();
        group_server(20, 4, 0.0).await.unwrap();
    }
}
