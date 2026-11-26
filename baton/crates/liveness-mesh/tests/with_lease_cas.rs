//! lease-cas over mesh liveness: leases in a shared store, heartbeats only between nodes.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use baton_core::{GroupId, LeaseKey, NodeId, Timestamp};
use baton_identity::{Identity, Roster, RosterHandle};
use baton_lease::testing::{self, Harness, profile};
use baton_lease::{LeaseError, Leases, Liveness, NodeClass, NodeProfile};
use baton_lease_cas::CasLeases;
use baton_liveness_mesh::MeshLiveness;
use baton_mesh_memory::MemoryHub;
use baton_state::{Expect, RecordName, StateError, StateStore, Version};
use baton_state_memory::MemoryState;
use bytes::Bytes;

const TTL: u64 = 1_000;

fn g() -> GroupId {
    GroupId::new("conf-lease").unwrap()
}

#[derive(Default)]
struct Counted {
    inner: MemoryState,
    writes: AtomicU64,
    reads: AtomicU64,
    lists: AtomicU64,
}

#[async_trait]
impl StateStore for Counted {
    async fn get(
        &self,
        group: &GroupId,
        name: &RecordName,
    ) -> Result<Option<(Bytes, Version)>, StateError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.get(group, name).await
    }

    async fn put(
        &self,
        group: &GroupId,
        name: &RecordName,
        value: Bytes,
        expect: Expect,
    ) -> Result<Version, StateError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.put(group, name, value, expect).await
    }

    async fn delete(
        &self,
        group: &GroupId,
        name: &RecordName,
        expect: Expect,
    ) -> Result<(), StateError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.delete(group, name, expect).await
    }

    async fn list(
        &self,
        group: &GroupId,
        prefix: &RecordName,
        after: Option<&RecordName>,
        limit: usize,
    ) -> Result<Vec<RecordName>, StateError> {
        self.lists.fetch_add(1, Ordering::SeqCst);
        self.inner.list(group, prefix, after, limit).await
    }
}

struct Node {
    id: Identity,
    live: Arc<MeshLiveness>,
    leases: Arc<CasLeases>,
}

struct Mesh {
    hub: MemoryHub,
    now: Arc<AtomicI64>,
    store: Arc<Counted>,
    nodes: Vec<Node>,
}

async fn mesh(n: usize) -> Mesh {
    let ids: Vec<_> = (0..n).map(|_| Identity::generate()).collect();
    let mut roster = Roster::genesis(&ids[0], g());
    for id in &ids[1..] {
        roster = roster.with_member(&ids[0], id.public()).unwrap();
    }
    let hub = MemoryHub::new();
    let now = Arc::new(AtomicI64::new(1_700_000_000_000));
    let store = Arc::new(Counted::default());
    let mut nodes = Vec::new();
    for id in &ids {
        let handle = RosterHandle::new(roster.clone()).unwrap();
        let t = Arc::new(hub.join(id.clone(), handle.clone()));
        let live = Arc::new(
            MeshLiveness::start(t, g(), handle, TTL, Duration::from_millis(200))
                .await
                .unwrap(),
        );
        let clock_now = now.clone();
        let leases = Arc::new(
            CasLeases::new(store.clone(), live.clone()).with_clock(Arc::new(move || {
                Timestamp(clock_now.load(Ordering::SeqCst))
            })),
        );
        nodes.push(Node {
            id: id.clone(),
            live,
            leases,
        });
    }
    Mesh {
        hub,
        now,
        store,
        nodes,
    }
}

impl Mesh {
    fn at(&self) -> Timestamp {
        Timestamp(self.now.load(Ordering::SeqCst))
    }

    fn profile(&self, i: usize) -> NodeProfile {
        NodeProfile {
            node: self.nodes[i].id.node_id(),
            ..profile("x", NodeClass::Server)
        }
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
async fn lease_cas_over_mesh_liveness_passes_the_lease_suite() {
    for n in [1, 3] {
        let m = mesh(n).await;
        let h = Arc::new(H {
            live: m.nodes[0].live.clone(),
            now: m.now.clone(),
            registered: Mutex::new(Vec::new()),
        });
        testing::leases(m.nodes[0].leases.clone(), h).await;
        let heartbeats = m
            .store
            .list(&g(), &RecordName::new("nodes").unwrap(), None, 10)
            .await
            .unwrap();
        assert!(heartbeats.is_empty(), "no heartbeat ever reaches the store");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_holder_renewing_over_mesh_liveness_never_writes_or_lists_the_store() {
    let m = mesh(3).await;
    let key = LeaseKey::new("account-1").unwrap();
    for i in 0..3 {
        m.nodes[i]
            .live
            .heartbeat(&g(), &m.profile(i), m.at())
            .await
            .unwrap();
    }
    let first = m.nodes[0]
        .leases
        .acquire(&g(), &key, &m.profile(0))
        .await
        .unwrap()
        .expect("free key");
    let writes = m.store.writes.load(Ordering::SeqCst);
    let reads = m.store.reads.load(Ordering::SeqCst);
    assert_eq!(writes, 1);
    const TICKS: u64 = 50;
    for _ in 0..TICKS {
        m.now.fetch_add(100, Ordering::SeqCst);
        for i in 0..3 {
            m.nodes[i]
                .live
                .heartbeat(&g(), &m.profile(i), m.at())
                .await
                .unwrap();
        }
        let again = m.nodes[0]
            .leases
            .acquire(&g(), &key, &m.profile(0))
            .await
            .unwrap()
            .expect("still the holder");
        assert_eq!(again.fence, first.fence);
        assert!(
            m.nodes[1]
                .leases
                .acquire(&g(), &key, &m.profile(1))
                .await
                .unwrap()
                .is_none(),
            "a live holder is never displaced"
        );
    }
    assert_eq!(
        m.store.writes.load(Ordering::SeqCst),
        writes,
        "renewals and refusals write nothing"
    );
    assert_eq!(m.store.lists.load(Ordering::SeqCst), 0, "nothing is listed");
    assert_eq!(
        m.store.reads.load(Ordering::SeqCst) - reads,
        2 * TICKS,
        "one read of the lease record per acquire"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_isolated_holder_stops_and_another_node_takes_over_with_a_higher_fence() {
    let m = mesh(3).await;
    let key = LeaseKey::new("account-2").unwrap();
    for i in 0..3 {
        m.nodes[i]
            .live
            .heartbeat(&g(), &m.profile(i), m.at())
            .await
            .unwrap();
    }
    let old = m.nodes[0]
        .leases
        .acquire(&g(), &key, &m.profile(0))
        .await
        .unwrap()
        .expect("free key");
    m.nodes[1].live.alive(&g(), m.at()).await.unwrap();
    assert!(
        m.nodes[1]
            .leases
            .acquire(&g(), &key, &m.profile(1))
            .await
            .unwrap()
            .is_none()
    );

    m.hub.partition(&[
        &[m.nodes[0].id.node_id()],
        &[m.nodes[1].id.node_id(), m.nodes[2].id.node_id()],
    ]);
    assert!(
        matches!(
            m.nodes[0].live.heartbeat(&g(), &m.profile(0), m.at()).await,
            Err(LeaseError::Unavailable)
        ),
        "the isolated holder learns its heartbeats failed, so it must stop"
    );

    m.now.fetch_add(TTL as i64 + 1, Ordering::SeqCst);
    for i in 1..3 {
        m.nodes[i]
            .live
            .heartbeat(&g(), &m.profile(i), m.at())
            .await
            .unwrap();
    }
    m.nodes[1].live.alive(&g(), m.at()).await.unwrap();
    let _ = m.nodes[1].leases.acquire(&g(), &key, &m.profile(1)).await;
    m.now.fetch_add(TTL as i64 + 1, Ordering::SeqCst);
    for i in 1..3 {
        m.nodes[i]
            .live
            .heartbeat(&g(), &m.profile(i), m.at())
            .await
            .unwrap();
    }
    let new = m.nodes[1]
        .leases
        .acquire(&g(), &key, &m.profile(1))
        .await
        .unwrap()
        .expect("the holder is gone for the majority");
    assert!(new.fence > old.fence);
    assert_eq!(new.node, m.nodes[1].id.node_id());
}
