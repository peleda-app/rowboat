use std::future::Future;

use baton_identity::{Identity, Roster, RosterHandle};
use baton_mesh::frame::seal;
use baton_mesh_memory::{MemoryHub, MemoryTransport};
use baton_signal_local::{Limits, LocalSignal};

use super::*;

fn group(name: &str) -> GroupId {
    GroupId::new(name).unwrap()
}

fn mesh(n: usize) -> (MemoryHub, Vec<Identity>, Vec<MemoryTransport>) {
    let ids: Vec<_> = (0..n).map(|_| Identity::generate()).collect();
    let mut roster = Roster::genesis(&ids[0], group("g"));
    for id in &ids[1..] {
        roster = roster.with_member(&ids[0], id.public()).unwrap();
    }
    let hub = MemoryHub::new();
    let nodes = ids
        .iter()
        .map(|id| hub.join(id.clone(), RosterHandle::new(roster.clone()).unwrap()))
        .collect();
    (hub, ids, nodes)
}

async fn nodes_for(
    g: &GroupId,
    n: usize,
    limits: Limits,
) -> (MemoryHub, Vec<Identity>, Vec<Arc<MeshSignal>>) {
    let (hub, ids, transports) = mesh(n);
    let mut out = Vec::new();
    for t in transports {
        let local: Arc<dyn Signal> = Arc::new(LocalSignal::with_limits(limits));
        out.push(Arc::new(
            MeshSignal::start(Arc::new(t), g.clone(), local)
                .await
                .unwrap(),
        ));
    }
    (hub, ids, out)
}

/// Routes each group to its own mesh, and within a group writes through one node and reads
/// through another, so the conformance suite checks delivery across the mesh.
struct Split {
    groups: Vec<(GroupId, Arc<MeshSignal>, Arc<MeshSignal>)>,
}

impl Split {
    fn pick(&self, g: &GroupId) -> (&Arc<MeshSignal>, &Arc<MeshSignal>) {
        let (_, w, r) = self
            .groups
            .iter()
            .find(|(x, _, _)| x == g)
            .expect("a group the suite uses");
        (w, r)
    }
}

#[async_trait]
impl Signal for Split {
    async fn publish(&self, g: &GroupId, topic: &str, p: Bytes) -> Result<(), SignalError> {
        self.pick(g).0.publish(g, topic, p).await
    }
    async fn subscribe(
        &self,
        g: &GroupId,
        topic: &str,
    ) -> Result<BoxStream<'static, Bytes>, SignalError> {
        self.pick(g).1.subscribe(g, topic).await
    }
    async fn put(&self, g: &GroupId, k: &str, v: Bytes, ttl: Duration) -> Result<(), SignalError> {
        self.pick(g).0.put(g, k, v, ttl).await
    }
    async fn get(&self, g: &GroupId, k: &str) -> Result<Option<Bytes>, SignalError> {
        self.pick(g).0.get(g, k).await
    }
    async fn delete(&self, g: &GroupId, k: &str) -> Result<(), SignalError> {
        self.pick(g).0.delete(g, k).await
    }
}

async fn split(same_node: bool) -> (Split, Vec<MemoryHub>) {
    let mut groups = Vec::new();
    let mut hubs = Vec::new();
    for name in ["conf-sig-1", "conf-sig-2"] {
        let g = group(name);
        let (hub, _, n) = nodes_for(&g, 3, Limits::default()).await;
        let reader = if same_node {
            n[0].clone()
        } else {
            n[2].clone()
        };
        groups.push((g, n[1].clone(), reader));
        hubs.push(hub);
    }
    (Split { groups }, hubs)
}

#[tokio::test(flavor = "multi_thread")]
async fn conformance_on_one_node_and_across_nodes() {
    let (one, _h1) = split(true).await;
    let one = Split {
        groups: one
            .groups
            .into_iter()
            .map(|(g, _, r)| (g, r.clone(), r))
            .collect(),
    };
    baton_signal::testing::signal(Arc::new(one), Duration::from_millis(200)).await;
    let (across, _h2) = split(false).await;
    baton_signal::testing::signal(Arc::new(across), Duration::from_millis(200)).await;
}

async fn eventually<F: Fn() -> Fut, Fut: Future<Output = bool>>(f: F) -> bool {
    for _ in 0..100 {
        if f().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

#[tokio::test]
async fn values_replicate_expire_and_delete_across_nodes() {
    let g = group("g");
    let (_hub, _, n) = nodes_for(&g, 3, Limits::default()).await;
    n[0].put(
        &g,
        "token:res",
        Bytes::from_static(b"v"),
        Duration::from_millis(300),
    )
    .await
    .unwrap();
    assert!(eventually(|| async { n[2].get(&g, "token:res").await.unwrap().is_some() }).await);
    assert!(eventually(|| async { n[2].get(&g, "token:res").await.unwrap().is_none() }).await);
    n[1].put(&g, "k", Bytes::from_static(b"v"), Duration::from_secs(60))
        .await
        .unwrap();
    assert!(eventually(|| async { n[0].get(&g, "k").await.unwrap().is_some() }).await);
    n[2].delete(&g, "k").await.unwrap();
    assert!(eventually(|| async { n[0].get(&g, "k").await.unwrap().is_none() }).await);
}

#[tokio::test]
async fn a_partition_isolates_and_healing_resumes() {
    let g = group("g");
    let (hub, ids, n) = nodes_for(&g, 3, Limits::default()).await;
    let node_ids: Vec<_> = ids.iter().map(|i| i.node_id()).collect();
    let mut far = n[2].subscribe(&g, "presence").await.unwrap();
    let mut near = n[1].subscribe(&g, "presence").await.unwrap();
    hub.partition(&[&node_ids[..2], &node_ids[2..]]);
    n[0].publish(&g, "presence", Bytes::from_static(b"a"))
        .await
        .unwrap();
    assert_eq!(&near.next().await.unwrap()[..], b"a");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), far.next())
            .await
            .is_err()
    );
    hub.heal();
    n[0].publish(&g, "presence", Bytes::from_static(b"b"))
        .await
        .unwrap();
    assert_eq!(&far.next().await.unwrap()[..], b"b");
}

#[tokio::test]
async fn another_group_is_refused_locally_and_ignored_from_members() {
    let g = group("g");
    let (hub, ids, n) = nodes_for(&g, 2, Limits::default()).await;
    let other = group("other");
    assert!(
        n[0].put(&other, "k", Bytes::new(), Duration::from_secs(9))
            .await
            .is_err()
    );
    assert!(n[0].subscribe(&other, "t").await.is_err());
    let target = ids[0].node_id();
    let msg = postcard::to_stdvec(&Msg::Put {
        group: other.clone(),
        key: "k".into(),
        value: b"x".to_vec(),
        ttl_ms: 9_000,
    })
    .unwrap();
    hub.inject(
        &target,
        &seal(&ids[1], &target, CHANNEL, u64::MAX - 10, &msg),
    );
    let same = postcard::to_stdvec(&Msg::Put {
        group: g.clone(),
        key: "k".into(),
        value: b"y".to_vec(),
        ttl_ms: 9_000,
    })
    .unwrap();
    hub.inject(
        &target,
        &seal(&ids[1], &target, CHANNEL, u64::MAX - 9, &same),
    );
    assert!(eventually(|| async { n[0].get(&g, "k").await.unwrap().is_some() }).await);
    assert!(
        n[0].local.get(&other, "k").await.unwrap().is_none(),
        "a member cannot write into another group"
    );
}

#[tokio::test]
async fn hostile_members_cannot_overflow_ttls_names_or_memory() {
    let g = group("g");
    let limits = Limits {
        max_values: 50,
        ..Limits::default()
    };
    let (hub, ids, n) = nodes_for(&g, 2, limits).await;
    let target = ids[0].node_id();
    let mut seq = 1u64 << 60;
    let mut send = |m: &Msg| {
        seq += 1;
        hub.inject(
            &target,
            &seal(
                &ids[1],
                &target,
                CHANNEL,
                seq,
                &postcard::to_stdvec(m).unwrap(),
            ),
        );
    };
    send(&Msg::Put {
        group: g.clone(),
        key: "forever".into(),
        value: b"x".to_vec(),
        ttl_ms: u64::MAX,
    });
    send(&Msg::Put {
        group: g.clone(),
        key: "bad name".into(),
        value: b"x".to_vec(),
        ttl_ms: 1_000,
    });
    send(&Msg::Put {
        group: g.clone(),
        key: "big".into(),
        value: vec![0u8; 70_000],
        ttl_ms: 1_000,
    });
    for i in 0..500 {
        send(&Msg::Put {
            group: g.clone(),
            key: format!("flood{i}"),
            value: b"x".to_vec(),
            ttl_ms: 60_000,
        });
    }
    hub.inject(
        &target,
        &seal(
            &ids[1],
            &target,
            CHANNEL,
            seq + 1,
            b"\xff\xfe not a message",
        ),
    );
    assert!(
        eventually(|| async { n[0].get(&g, "forever").await.unwrap().is_some() }).await,
        "a huge remote ttl is clamped, not a panic"
    );
    assert!(
        n[0].get(&g, "big").await.unwrap().is_none(),
        "oversized remote values are refused"
    );
    let mut held = 0;
    for i in 0..500 {
        if n[0].get(&g, &format!("flood{i}")).await.unwrap().is_some() {
            held += 1;
        }
    }
    assert!(
        held < 50,
        "the local backend's limits bound what members can make this node hold ({held})"
    );
    n[0].put(&g, "still-works", Bytes::new(), Duration::from_secs(1))
        .await
        .ok();
}

#[tokio::test]
async fn counters_are_not_shared_across_the_mesh() {
    let g = group("g");
    let (_hub, _, n) = nodes_for(&g, 2, Limits::default()).await;
    assert_eq!(
        n[0].incr(&g, "c", 1, Duration::from_secs(1)).await.unwrap(),
        None
    );
}
