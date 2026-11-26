use std::sync::atomic::AtomicI64;

use baton_identity::{Identity, Roster};
use baton_lease::NodeClass;
use baton_lease::testing::{self, Harness, profile};
use baton_liveness_mesh::MeshLiveness;
use baton_mesh_memory::MemoryHub;
use baton_state_memory::MemoryState;

use super::*;

const TTL: u64 = 1_000;

fn g() -> GroupId {
    GroupId::new("conf-lease").unwrap()
}

struct Node {
    id: Identity,
    leases: Arc<QuorumLeases>,
    live: Arc<MeshLiveness>,
    state: Arc<MemoryState>,
}

struct Mesh {
    hub: MemoryHub,
    now: Arc<AtomicI64>,
    roster: Roster,
    handles: Vec<RosterHandle>,
    nodes: Vec<Node>,
}

fn clock(now: &Arc<AtomicI64>) -> Clock {
    let n = now.clone();
    Arc::new(move || Timestamp(n.load(Ordering::SeqCst)))
}

async fn start_node(
    hub: &MemoryHub,
    now: &Arc<AtomicI64>,
    id: &Identity,
    handle: &RosterHandle,
    state: Arc<MemoryState>,
) -> Node {
    let t: Arc<dyn Transport> = Arc::new(hub.join(id.clone(), handle.clone()));
    let live = Arc::new(
        MeshLiveness::start(
            t.clone(),
            g(),
            handle.clone(),
            TTL,
            Duration::from_millis(200),
        )
        .await
        .unwrap(),
    );
    let leases = Arc::new(
        QuorumLeases::start(
            g(),
            t,
            handle.clone(),
            live.clone(),
            state.clone(),
            clock(now),
            QuorumConfig {
                phase_timeout: Duration::from_millis(200),
                max_attempts: 16,
            },
        )
        .await
        .unwrap(),
    );
    Node {
        id: id.clone(),
        leases,
        live,
        state,
    }
}

async fn mesh(n: usize) -> Mesh {
    let ids: Vec<_> = (0..n).map(|_| Identity::generate()).collect();
    let mut roster = Roster::genesis(&ids[0], g());
    for id in &ids[1..] {
        roster = roster.with_member(&ids[0], id.public()).unwrap();
    }
    let hub = MemoryHub::new();
    let now = Arc::new(AtomicI64::new(1_700_000_000_000));
    let handles: Vec<_> = ids
        .iter()
        .map(|_| RosterHandle::new(roster.clone()).unwrap())
        .collect();
    let mut nodes = Vec::new();
    for (id, h) in ids.iter().zip(&handles) {
        nodes.push(start_node(&hub, &now, id, h, Arc::new(MemoryState::new())).await);
    }
    Mesh {
        hub,
        now,
        roster,
        handles,
        nodes,
    }
}

impl Mesh {
    fn at(&self) -> Timestamp {
        Timestamp(self.now.load(Ordering::SeqCst))
    }
}

struct H {
    live: Arc<MeshLiveness>,
    now: Arc<AtomicI64>,
    registered: Mutex<Vec<NodeProfile>>,
}

impl Harness for H {
    async fn alive(&self, p: &NodeProfile) {
        self.registered.lock().unwrap().push(p.clone());
        self.live
            .heartbeat(&g(), p, Timestamp(self.now.load(Ordering::SeqCst)))
            .await
            .unwrap();
    }

    async fn kill(&self, node: &NodeId) {
        let t = Timestamp(self.now.load(Ordering::SeqCst));
        self.live.alive(&g(), t).await.unwrap();
        self.registered.lock().unwrap().retain(|p| &p.node != node);
        self.now.fetch_add(TTL as i64 + 1, Ordering::SeqCst);
        let others = self.registered.lock().unwrap().clone();
        let t = Timestamp(self.now.load(Ordering::SeqCst));
        for p in &others {
            self.live.heartbeat(&g(), p, t).await.unwrap();
        }
        self.live.alive(&g(), t).await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn conformance_on_one_node_and_on_a_three_node_mesh() {
    for n in [1, 3] {
        let m = mesh(n).await;
        let h = Arc::new(H {
            live: m.nodes[0].live.clone(),
            now: m.now.clone(),
            registered: Mutex::new(Vec::new()),
        });
        testing::leases(m.nodes[0].leases.clone(), h).await;
    }
}

fn me(node: &Node, class: NodeClass) -> NodeProfile {
    NodeProfile {
        node: node.id.node_id(),
        ..profile("x", class)
    }
}

async fn beat_all(m: &Mesh) {
    for observer in &m.nodes {
        for n in &m.nodes {
            observer
                .live
                .heartbeat(&g(), &me(n, NodeClass::Desktop), m.at())
                .await
                .ok();
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn only_a_majority_decides_and_tokens_keep_growing_after_healing() {
    let m = mesh(5).await;
    beat_all(&m).await;
    let k = LeaseKey::new("k").unwrap();
    let ids: Vec<_> = m.nodes.iter().map(|n| n.id.node_id()).collect();
    let first = m.nodes[0]
        .leases
        .acquire(&g(), &k, &me(&m.nodes[0], NodeClass::Desktop))
        .await
        .unwrap()
        .unwrap();
    m.hub.partition(&[&ids[..3], &ids[3..]]);
    assert!(matches!(
        m.nodes[3]
            .leases
            .acquire(&g(), &k, &me(&m.nodes[3], NodeClass::Server))
            .await,
        Err(LeaseError::Unavailable)
    ));
    assert!(
        matches!(
            m.nodes[4].leases.holder(&g(), &k).await,
            Err(LeaseError::Unavailable)
        ),
        "a minority cannot even read"
    );
    m.now.fetch_add(TTL as i64 * 3, Ordering::SeqCst);
    for observer in &m.nodes[..3] {
        observer.live.alive(&g(), m.at()).await.unwrap();
        for n in &m.nodes[1..3] {
            observer
                .live
                .heartbeat(&g(), &me(n, NodeClass::Desktop), m.at())
                .await
                .ok();
        }
    }
    m.nodes[1].leases.holder(&g(), &k).await.unwrap();
    m.now.fetch_add(TTL as i64 + 1, Ordering::SeqCst);
    for observer in &m.nodes[..3] {
        for n in &m.nodes[1..3] {
            observer
                .live
                .heartbeat(&g(), &me(n, NodeClass::Desktop), m.at())
                .await
                .ok();
        }
    }
    let second = m.nodes[1]
        .leases
        .acquire(&g(), &k, &me(&m.nodes[1], NodeClass::Desktop))
        .await
        .unwrap()
        .unwrap();
    assert!(second.fence > first.fence);
    m.hub.heal();
    let seen = m.nodes[4].leases.holder(&g(), &k).await.unwrap().unwrap();
    assert_eq!(
        seen.node, second.node,
        "after healing every node sees the majority's holder"
    );
    assert_eq!(seen.fence, second.fence);
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_acquires_from_five_nodes_have_one_winner() {
    let m = mesh(5).await;
    beat_all(&m).await;
    let k = LeaseKey::new("race").unwrap();
    let mut tasks = Vec::new();
    for n in &m.nodes {
        let leases = n.leases.clone();
        let p = me(n, NodeClass::Desktop);
        let k = k.clone();
        tasks.push(tokio::spawn(
            async move { leases.acquire(&g(), &k, &p).await },
        ));
    }
    let mut won = Vec::new();
    for t in tasks {
        if let Ok(Some(l)) = t.await.unwrap() {
            won.push(l);
        }
    }
    assert_eq!(won.len(), 1, "{won:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restarted_acceptor_keeps_its_promises_so_tokens_are_never_reused() {
    let mut m = mesh(3).await;
    beat_all(&m).await;
    let k = LeaseKey::new("k").unwrap();
    let ids: Vec<_> = m.nodes.iter().map(|n| n.id.node_id()).collect();
    let first = m.nodes[0]
        .leases
        .acquire(&g(), &k, &me(&m.nodes[0], NodeClass::Desktop))
        .await
        .unwrap()
        .unwrap();
    let state = m.nodes[1].state.clone();
    let id1 = m.nodes[1].id.clone();
    let restarted = start_node(&m.hub, &m.now, &id1, &m.handles[1], state).await;
    m.nodes[1] = restarted;
    m.hub.partition(&[&ids[1..]]);
    m.now.fetch_add(TTL as i64 * 3, Ordering::SeqCst);
    for observer in &m.nodes[1..] {
        observer.live.alive(&g(), m.at()).await.unwrap();
    }
    m.nodes[2].leases.holder(&g(), &k).await.unwrap();
    m.now.fetch_add(TTL as i64 + 1, Ordering::SeqCst);
    for observer in &m.nodes[1..] {
        for n in &m.nodes[1..] {
            observer
                .live
                .heartbeat(&g(), &me(n, NodeClass::Desktop), m.at())
                .await
                .ok();
        }
    }
    let second = m.nodes[2]
        .leases
        .acquire(&g(), &k, &me(&m.nodes[2], NodeClass::Desktop))
        .await
        .unwrap()
        .unwrap();
    assert!(
        second.fence > first.fence,
        "the restarted acceptor still knew the accepted record, so the new token is higher"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_member_loses_its_vote() {
    let m = mesh(3).await;
    beat_all(&m).await;
    let revoked = m
        .roster
        .without_member(&m.nodes[0].id, &m.nodes[2].id.public())
        .unwrap();
    for h in &m.handles {
        h.update(revoked.clone()).unwrap();
    }
    let k = LeaseKey::new("k").unwrap();
    assert!(
        matches!(
            m.nodes[2]
                .leases
                .acquire(&g(), &k, &me(&m.nodes[2], NodeClass::Desktop))
                .await,
            Err(LeaseError::Backend(_))
        ),
        "a revoked node takes no part"
    );
    let ids: Vec<_> = m.nodes.iter().map(|n| n.id.node_id()).collect();
    m.hub.partition(&[&ids[..1], &ids[1..]]);
    assert!(
        matches!(
            m.nodes[0]
                .leases
                .acquire(&g(), &k, &me(&m.nodes[0], NodeClass::Desktop))
                .await,
            Err(LeaseError::Unavailable)
        ),
        "the two remaining members need each other"
    );
    m.hub.heal();
    assert!(
        m.nodes[0]
            .leases
            .acquire(&g(), &k, &me(&m.nodes[0], NodeClass::Desktop))
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn another_group_is_refused() {
    let m = mesh(1).await;
    let other = GroupId::new("other").unwrap();
    let k = LeaseKey::new("k").unwrap();
    assert!(
        m.nodes[0]
            .leases
            .acquire(&other, &k, &me(&m.nodes[0], NodeClass::Server))
            .await
            .is_err()
    );
    assert!(m.nodes[0].leases.holder(&other, &k).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_isolated_holder_learns_it_must_stop_and_the_majority_waits_out_its_last_heartbeat() {
    let m = mesh(3).await;
    beat_all(&m).await;
    let k = LeaseKey::new("smtp").unwrap();
    let holder = me(&m.nodes[0], NodeClass::Desktop);
    let first = m.nodes[0]
        .leases
        .acquire(&g(), &k, &holder)
        .await
        .unwrap()
        .unwrap();
    m.nodes[0]
        .live
        .heartbeat(&g(), &holder, m.at())
        .await
        .expect("acknowledged by a majority");
    for n in &m.nodes {
        n.live.alive(&g(), m.at()).await.unwrap();
    }
    let ids: Vec<_> = m.nodes.iter().map(|n| n.id.node_id()).collect();
    m.hub.partition(&[&ids[..1], &ids[1..]]);
    assert!(
        matches!(
            m.nodes[0].live.heartbeat(&g(), &holder, m.at()).await,
            Err(LeaseError::Unavailable)
        ),
        "cut off, the holder's heartbeat fails, so it must stop within the time-to-live"
    );
    m.now.fetch_add(TTL as i64 / 2, Ordering::SeqCst);
    let rival = me(&m.nodes[1], NodeClass::Server);
    assert!(
        !matches!(
            m.nodes[1].leases.acquire(&g(), &k, &rival).await,
            Ok(Some(_))
        ),
        "within the time-to-live of the holder's last successful heartbeat nobody else gets the key"
    );
    m.now.fetch_add(TTL as i64 * 2, Ordering::SeqCst);
    for observer in &m.nodes[1..] {
        observer.live.alive(&g(), m.at()).await.unwrap();
        for n in &m.nodes[1..] {
            observer
                .live
                .heartbeat(&g(), &me(n, NodeClass::Server), m.at())
                .await
                .ok();
        }
    }
    m.nodes[2].leases.holder(&g(), &k).await.unwrap();
    m.now.fetch_add(TTL as i64 + 1, Ordering::SeqCst);
    for observer in &m.nodes[1..] {
        observer.live.alive(&g(), m.at()).await.unwrap();
        for n in &m.nodes[1..] {
            observer
                .live
                .heartbeat(&g(), &me(n, NodeClass::Server), m.at())
                .await
                .ok();
        }
    }
    let second = m.nodes[1]
        .leases
        .acquire(&g(), &k, &rival)
        .await
        .unwrap()
        .unwrap();
    assert!(second.fence > first.fence);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_member_cannot_poison_another_nodes_acceptor() {
    let m = mesh(2).await;
    let target = m.nodes[0].id.node_id();
    let send = |msg: &Msg, seq: u64| {
        m.hub.inject(
            &target,
            &baton_mesh::frame::seal(
                &m.nodes[1].id,
                &target,
                CHANNEL,
                seq,
                &postcard::to_stdvec(msg).unwrap(),
            ),
        );
    };
    let ballot = |round| Ballot {
        round,
        proposer: m.nodes[1].id.node_id(),
    };
    send(
        &Msg::Prepare {
            id: 1,
            group: g(),
            key: LeaseKey::new("k").unwrap(),
            ballot: ballot(u64::MAX),
        },
        1,
    );
    let mut forged = baton_lease::record::LeaseRecord::decode(
        b"{\"v\":1,\"holder\":null,\"fence\":1,\"takeover\":null,\"reserved\":null,\"seq\":1}",
    )
    .unwrap();
    forged.fence = u64::MAX;
    send(
        &Msg::Accept {
            id: 2,
            group: g(),
            key: LeaseKey::new("k").unwrap(),
            ballot: ballot(1),
            base: None,
            value: Some(forged),
        },
        2,
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    beat_all(&m).await;
    let got = m.nodes[0]
        .leases
        .acquire(
            &g(),
            &LeaseKey::new("k").unwrap(),
            &me(&m.nodes[0], NodeClass::Server),
        )
        .await;
    assert!(
        matches!(got, Ok(Some(_))),
        "a maximal ballot and a maximal token were refused: {got:?}"
    );
}
