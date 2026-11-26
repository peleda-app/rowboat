use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::AtomicI64;

use baton_core::{GroupId, LeaseKey};
use baton_identity::Roster;
use baton_lease::{LeaseError, Leases, Liveness, NodeClass, NodeProfile};
use baton_lease_quorum::{QuorumConfig, QuorumLeases};
use baton_link::{PeerHint, PinnedKeys, Trust};
use baton_link_iroh::{IrohConfig, IrohLink};
use baton_link_memory::MemoryLinkHub;
use baton_liveness_mesh::MeshLiveness;
use baton_signal::{Signal, SignalError};
use baton_signal_local::LocalSignal;
use baton_signal_mesh::MeshSignal;
use baton_state_memory::MemoryState;

use super::*;

fn config() -> LinkTransportConfig {
    LinkTransportConfig {
        send_timeout: Duration::from_secs(2),
        probe_timeout: Duration::from_millis(300),
        retry_after: Duration::from_millis(100),
    }
}

fn roster(ids: &[Identity]) -> Roster {
    let mut roster = Roster::genesis(&ids[0], GroupId::new("t").unwrap());
    for id in &ids[1..] {
        roster = roster.with_member(&ids[0], id.public()).unwrap();
    }
    roster
}

struct Mesh {
    hub: MemoryLinkHub,
    ids: Vec<Identity>,
    handles: Vec<RosterHandle>,
    links: Vec<Arc<dyn Link>>,
    nodes: Vec<Arc<LinkTransport>>,
}

impl Mesh {
    fn keys(&self) -> Vec<PublicKey> {
        self.ids.iter().map(Identity::public).collect()
    }
}

async fn mesh(n: usize) -> Mesh {
    let ids: Vec<_> = (0..n).map(|_| Identity::generate()).collect();
    let roster = roster(&ids);
    let hub = MemoryLinkHub::new();
    let mut handles = Vec::new();
    let mut links = Vec::new();
    let mut nodes = Vec::new();
    for id in &ids {
        let handle = RosterHandle::new(roster.clone()).unwrap();
        let link: Arc<dyn Link> = Arc::new(hub.join(id.public(), Arc::new(handle.clone())));
        let node = LinkTransport::start(link.clone(), id.clone(), handle.clone(), config())
            .await
            .unwrap();
        handles.push(handle);
        links.push(link);
        nodes.push(Arc::new(node));
    }
    Mesh {
        hub,
        ids,
        handles,
        links,
        nodes,
    }
}

async fn next(s: &mut BoxStream<'static, Envelope>) -> Option<Envelope> {
    tokio::time::timeout(Duration::from_millis(500), s.next())
        .await
        .ok()
        .flatten()
}

#[tokio::test]
async fn refuses_a_link_of_another_identity() {
    let hub = MemoryLinkHub::new();
    let id = Identity::generate();
    let link: Arc<dyn Link> = Arc::new(hub.join(
        Identity::generate().public(),
        Arc::new(PinnedKeys::default()),
    ));
    let handle = RosterHandle::new(Roster::genesis(&id, GroupId::new("t").unwrap())).unwrap();
    assert!(matches!(
        LinkTransport::start(link, id, handle, config()).await,
        Err(StartError::WrongIdentity)
    ));
}

#[tokio::test]
async fn delivers_in_order_to_the_right_channel() {
    let m = mesh(2).await;
    let mut sub = m.nodes[1].subscribe("chan/a").await.unwrap();
    let mut other = m.nodes[1].subscribe("chan/b").await.unwrap();
    let to = m.nodes[1].local();
    for i in 0..50u8 {
        m.nodes[0]
            .send(&to, "chan/a", Bytes::from(vec![i]))
            .await
            .unwrap();
    }
    for i in 0..50u8 {
        let env = next(&mut sub).await.unwrap();
        assert_eq!(env.from, m.nodes[0].local());
        assert_eq!(&env.payload[..], &[i]);
    }
    assert!(next(&mut other).await.is_none());
    let big = Bytes::from(vec![7u8; MAX_PAYLOAD]);
    m.nodes[0].send(&to, "chan/a", big.clone()).await.unwrap();
    assert_eq!(next(&mut sub).await.unwrap().payload, big);
    assert!(matches!(
        m.nodes[0]
            .send(&to, "chan/a", Bytes::from(vec![0u8; MAX_PAYLOAD + 1]))
            .await,
        Err(TransportError::TooLarge)
    ));
    assert_eq!(m.nodes[0].peers().await.unwrap(), vec![to.clone()]);
    assert!(
        m.nodes[0]
            .send(&m.nodes[0].local(), "chan/a", Bytes::new())
            .await
            .is_err()
    );
    assert!(matches!(
        m.nodes[0].send(&to, "Bad Name", Bytes::new()).await,
        Err(TransportError::InvalidChannel)
    ));
}

#[tokio::test]
async fn partitions_cut_and_heal() {
    let m = mesh(3).await;
    let keys = m.keys();
    let ids: Vec<_> = m.nodes.iter().map(|n| n.local()).collect();
    let mut sub = m.nodes[2].subscribe("x").await.unwrap();
    m.nodes[0].send(&ids[2], "x", Bytes::new()).await.unwrap();
    assert!(next(&mut sub).await.is_some());

    m.hub.partition(&[&keys[..2], &keys[2..]]);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(m.nodes[0].peers().await.unwrap(), vec![ids[1].clone()]);
    assert!(m.nodes[2].peers().await.unwrap().is_empty());
    assert!(matches!(
        m.nodes[0].send(&ids[2], "x", Bytes::new()).await,
        Err(TransportError::Unreachable)
    ));
    m.hub.heal();
    tokio::time::sleep(config().retry_after).await;
    assert_eq!(m.nodes[2].peers().await.unwrap().len(), 2);
    m.nodes[0]
        .send(&ids[2], "x", Bytes::from_static(b"again"))
        .await
        .unwrap();
    assert_eq!(&next(&mut sub).await.unwrap().payload[..], b"again");
}

#[tokio::test]
async fn drops_outsiders_relayed_and_revoked_traffic() {
    let m = mesh(3).await;
    let target = m.nodes[0].local();
    let mut sub = m.nodes[0].subscribe("x").await.unwrap();

    let outsider = Identity::generate();
    let everyone: Arc<dyn Trust> = Arc::new(PinnedKeys::new(m.keys()));
    let olink: Arc<dyn Link> = Arc::new(m.hub.join(outsider.public(), everyone));
    let stranger = LinkTransport::start(
        olink,
        outsider.clone(),
        RosterHandle::new(roster(&[outsider.clone(), m.ids[0].clone()])).unwrap(),
        config(),
    )
    .await
    .unwrap();
    assert!(matches!(
        stranger.send(&target, "x", Bytes::from_static(b"no")).await,
        Err(TransportError::Unreachable)
    ));
    assert!(
        !m.nodes[0]
            .peers()
            .await
            .unwrap()
            .contains(&outsider.node_id())
    );

    let protocol = Protocol::new(MESH_PROTOCOL).unwrap();
    let mut relay = m.links[1]
        .open(&m.ids[0].public(), &protocol)
        .await
        .unwrap();
    let forged = frame::seal(&m.ids[2], &target, "x", u64::MAX - 1, b"relayed");
    relay
        .write_all(&(forged.len() as u32).to_be_bytes())
        .await
        .unwrap();
    relay.write_all(&forged).await.unwrap();
    let mut eof = [0u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(500), relay.read(&mut eof))
            .await
            .unwrap()
            .unwrap_or(0),
        0,
        "a stream carrying another sender's frame is dropped"
    );
    let mut oversized = m.links[1]
        .open(&m.ids[0].public(), &protocol)
        .await
        .unwrap();
    oversized.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
    assert!(
        next(&mut sub).await.is_none(),
        "a member cannot relay another's frames"
    );
    assert_eq!(
        m.nodes[0].dropped(),
        2,
        "relayed frame and oversized length"
    );

    m.nodes[2]
        .send(&target, "x", Bytes::from_static(b"before"))
        .await
        .unwrap();
    assert_eq!(&next(&mut sub).await.unwrap().payload[..], b"before");
    let revoked = m.handles[0]
        .current()
        .without_member(&m.ids[0], &m.ids[2].public())
        .unwrap();
    m.handles[0].update(revoked).unwrap();
    m.nodes[2]
        .send(&target, "x", Bytes::from_static(b"open stream"))
        .await
        .unwrap();
    assert!(next(&mut sub).await.is_none(), "the roster check drops it");
    assert_eq!(m.nodes[0].dropped(), 3);
    assert_eq!(m.links[0].disconnect_untrusted().await.unwrap(), 1);
    tokio::time::sleep(Duration::from_millis(50)).await;
    tokio::time::sleep(config().retry_after).await;
    assert!(matches!(
        m.nodes[2]
            .send(&target, "x", Bytes::from_static(b"new stream"))
            .await,
        Err(TransportError::Unreachable)
    ));
    m.nodes[1]
        .send(&target, "x", Bytes::from_static(b"yes"))
        .await
        .unwrap();
    assert_eq!(&next(&mut sub).await.unwrap().payload[..], b"yes");
    assert!(
        !m.nodes[0]
            .peers()
            .await
            .unwrap()
            .contains(&m.ids[2].node_id())
    );
}

fn manual_clock() -> (baton_lease_quorum::Clock, Arc<AtomicI64>) {
    let now = Arc::new(AtomicI64::new(1_700_000_000_000));
    let n = now.clone();
    (Arc::new(move || Timestamp(n.load(Ordering::SeqCst))), now)
}

fn group() -> GroupId {
    GroupId::new("conf-lease").unwrap()
}

async fn leases_on(
    transports: Vec<Arc<dyn Transport>>,
    handles: &[RosterHandle],
    clock: baton_lease_quorum::Clock,
) -> Vec<(Arc<QuorumLeases>, Arc<MeshLiveness>)> {
    let mut out = Vec::new();
    for (t, h) in transports.into_iter().zip(handles) {
        let live = Arc::new(
            MeshLiveness::start(
                t.clone(),
                group(),
                h.clone(),
                10_000,
                Duration::from_millis(500),
            )
            .await
            .unwrap(),
        );
        let leases = QuorumLeases::start(
            group(),
            t,
            h.clone(),
            live.clone(),
            Arc::new(MemoryState::new()),
            clock.clone(),
            QuorumConfig {
                phase_timeout: Duration::from_millis(500),
                max_attempts: 16,
            },
        )
        .await
        .unwrap();
        out.push((Arc::new(leases), live));
    }
    out
}

fn as_transports(nodes: &[Arc<LinkTransport>]) -> Vec<Arc<dyn Transport>> {
    nodes
        .iter()
        .map(|n| n.clone() as Arc<dyn Transport>)
        .collect()
}

struct MemoryLinks(MemoryLinkHub);

impl baton_mesh::testing::Harness for MemoryLinks {
    async fn join(&self, identity: Identity, roster: RosterHandle) -> Arc<dyn Transport> {
        let link: Arc<dyn Link> =
            Arc::new(self.0.join(identity.public(), Arc::new(roster.clone())));
        Arc::new(
            LinkTransport::start(link, identity, roster, config())
                .await
                .unwrap(),
        )
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transport_conformance_over_link_memory() {
    baton_mesh::testing::transport(&MemoryLinks(MemoryLinkHub::new())).await;
}

#[derive(Default)]
struct IrohLinks {
    links: Mutex<Vec<Arc<IrohLink>>>,
}

impl baton_mesh::testing::Harness for IrohLinks {
    async fn join(&self, identity: Identity, roster: RosterHandle) -> Arc<dyn Transport> {
        let link = Arc::new(
            IrohLink::bind(
                &identity,
                Arc::new(roster.clone()),
                IrohConfig {
                    bind: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 0))],
                    ..IrohConfig::default()
                },
            )
            .await
            .unwrap(),
        );
        {
            let mut links = self.links.lock().unwrap();
            for other in links.iter() {
                other
                    .add_hint(
                        &link.local(),
                        PeerHint {
                            direct: link.bound_addrs(),
                            relay: None,
                        },
                    )
                    .unwrap();
                link.add_hint(
                    &other.local(),
                    PeerHint {
                        direct: other.bound_addrs(),
                        relay: None,
                    },
                )
                .unwrap();
            }
            links.push(link.clone());
        }
        let link: Arc<dyn Link> = link;
        Arc::new(
            LinkTransport::start(link, identity, roster, config())
                .await
                .unwrap(),
        )
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transport_conformance_over_iroh_on_loopback() {
    let h = IrohLinks::default();
    baton_mesh::testing::transport(&h).await;
    let links = h.links.lock().unwrap().clone();
    for link in links {
        link.close().await;
    }
}

struct QuorumHarness {
    live: Arc<MeshLiveness>,
    now: Arc<AtomicI64>,
    registered: Mutex<Vec<NodeProfile>>,
}

impl baton_lease::testing::Harness for QuorumHarness {
    async fn alive(&self, p: &NodeProfile) {
        self.registered.lock().unwrap().push(p.clone());
        self.live
            .heartbeat(&group(), p, Timestamp(self.now.load(Ordering::SeqCst)))
            .await
            .unwrap();
    }

    async fn kill(&self, node: &NodeId) {
        let t = Timestamp(self.now.load(Ordering::SeqCst));
        self.live.alive(&group(), t).await.unwrap();
        self.registered.lock().unwrap().retain(|p| &p.node != node);
        self.now.fetch_add(10_001, Ordering::SeqCst);
        let t = Timestamp(self.now.load(Ordering::SeqCst));
        let others = self.registered.lock().unwrap().clone();
        for p in &others {
            self.live.heartbeat(&group(), p, t).await.unwrap();
        }
        self.live.alive(&group(), t).await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lease_conformance_over_a_link_mesh() {
    let m = mesh(3).await;
    let (clock, now) = manual_clock();
    let leases = leases_on(as_transports(&m.nodes), &m.handles, clock).await;
    let h = Arc::new(QuorumHarness {
        live: leases[0].1.clone(),
        now,
        registered: Mutex::new(Vec::new()),
    });
    baton_lease::testing::leases(leases[0].0.clone(), h).await;
}

fn me(id: &Identity) -> NodeProfile {
    NodeProfile {
        node: id.node_id(),
        class: NodeClass::Desktop,
        weight: 1,
        can_run: true,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn majority_decides_across_partitions_over_link_memory() {
    let m = mesh(5).await;
    let (clock, now) = manual_clock();
    let leases = leases_on(as_transports(&m.nodes), &m.handles, clock).await;
    let at = || Timestamp(now.load(Ordering::SeqCst));
    for (_, live) in &leases {
        for id in &m.ids {
            live.heartbeat(&group(), &me(id), at()).await.unwrap();
        }
    }
    let k = LeaseKey::new("acc").unwrap();
    let keys = m.keys();
    m.hub.partition(&[&keys[..3], &keys[3..]]);
    assert!(matches!(
        leases[3].0.acquire(&group(), &k, &me(&m.ids[3])).await,
        Err(LeaseError::Unavailable)
    ));
    let won = leases[0]
        .0
        .acquire(&group(), &k, &me(&m.ids[0]))
        .await
        .unwrap()
        .unwrap();
    m.hub.heal();
    tokio::time::sleep(config().retry_after).await;
    assert_eq!(leases[4].0.holder(&group(), &k).await.unwrap(), Some(won));
}

/// Writes and publishes through one node, subscribes through another.
struct Split {
    writer: Arc<MeshSignal>,
    reader: Arc<MeshSignal>,
    other: Arc<LocalSignal>,
}

#[async_trait]
impl Signal for Split {
    async fn publish(&self, g: &GroupId, topic: &str, p: Bytes) -> Result<(), SignalError> {
        if g == &group() {
            self.writer.publish(g, topic, p).await
        } else {
            self.other.publish(g, topic, p).await
        }
    }
    async fn subscribe(
        &self,
        g: &GroupId,
        topic: &str,
    ) -> Result<BoxStream<'static, Bytes>, SignalError> {
        if g == &group() {
            self.reader.subscribe(g, topic).await
        } else {
            self.other.subscribe(g, topic).await
        }
    }
    async fn put(&self, g: &GroupId, k: &str, v: Bytes, ttl: Duration) -> Result<(), SignalError> {
        if g == &group() {
            self.writer.put(g, k, v, ttl).await
        } else {
            self.other.put(g, k, v, ttl).await
        }
    }
    async fn get(&self, g: &GroupId, k: &str) -> Result<Option<Bytes>, SignalError> {
        if g == &group() {
            self.writer.get(g, k).await
        } else {
            self.other.get(g, k).await
        }
    }
    async fn delete(&self, g: &GroupId, k: &str) -> Result<(), SignalError> {
        if g == &group() {
            self.writer.delete(g, k).await
        } else {
            self.other.delete(g, k).await
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signals_reach_another_node_over_a_link() {
    let m = mesh(2).await;
    let writer = Arc::new(
        MeshSignal::start(m.nodes[0].clone(), group(), Arc::new(LocalSignal::new()))
            .await
            .unwrap(),
    );
    let reader = Arc::new(
        MeshSignal::start(m.nodes[1].clone(), group(), Arc::new(LocalSignal::new()))
            .await
            .unwrap(),
    );
    let mut sub = reader.subscribe(&group(), "hints/res").await.unwrap();
    writer
        .publish(&group(), "hints/res", Bytes::from_static(b"1"))
        .await
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), sub.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&got[..], b"1");
    let _ = Split {
        writer,
        reader,
        other: Arc::new(LocalSignal::new()),
    };
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leases_over_iroh_on_loopback() {
    let ids: Vec<_> = (0..3).map(|_| Identity::generate()).collect();
    let roster = roster(&ids);
    let mut handles = Vec::new();
    let mut links = Vec::new();
    for id in &ids {
        let handle = RosterHandle::new(roster.clone()).unwrap();
        let link = IrohLink::bind(
            id,
            Arc::new(handle.clone()),
            IrohConfig {
                bind: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 0))],
                ..IrohConfig::default()
            },
        )
        .await
        .unwrap();
        handles.push(handle);
        links.push(Arc::new(link));
    }
    for a in &links {
        for b in &links {
            if a.local() != b.local() {
                a.add_hint(
                    &b.local(),
                    PeerHint {
                        direct: b.bound_addrs(),
                        relay: None,
                    },
                )
                .unwrap();
            }
        }
    }
    let mut nodes = Vec::new();
    for (link, (id, handle)) in links.iter().zip(ids.iter().zip(&handles)) {
        let link: Arc<dyn Link> = link.clone();
        nodes.push(Arc::new(
            LinkTransport::start(link, id.clone(), handle.clone(), config())
                .await
                .unwrap(),
        ));
    }
    let (clock, now) = manual_clock();
    let leases = leases_on(as_transports(&nodes), &handles, clock).await;
    let at = Timestamp(now.load(Ordering::SeqCst));
    for (_, live) in &leases {
        for id in &ids {
            live.heartbeat(&group(), &me(id), at).await.unwrap();
        }
    }
    let k = LeaseKey::new("acc").unwrap();
    let lease = leases[1]
        .0
        .acquire(&group(), &k, &me(&ids[1]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(leases[0].0.holder(&group(), &k).await.unwrap(), Some(lease));
    assert_eq!(
        leases[2]
            .0
            .acquire(&group(), &k, &me(&ids[2]))
            .await
            .unwrap(),
        None
    );
    for link in &links {
        link.close().await;
    }
}

struct Stall {
    inner: Box<dyn Duplex>,
    stall: Arc<AtomicBool>,
    stalled: bool,
}

impl tokio::io::AsyncRead for Stall {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for Stall {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.stall.load(Ordering::SeqCst) {
            if self.stalled {
                return std::task::Poll::Pending;
            }
            self.stalled = true;
            let half = buf.len() / 2;
            return std::pin::Pin::new(&mut self.inner).poll_write(cx, &buf[..half]);
        }
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct StallLink {
    inner: Arc<dyn Link>,
    stall: Arc<AtomicBool>,
}

#[async_trait]
impl Link for StallLink {
    fn local(&self) -> PublicKey {
        self.inner.local()
    }

    async fn open(
        &self,
        peer: &PublicKey,
        protocol: &Protocol,
    ) -> Result<Box<dyn Duplex>, LinkError> {
        let inner = self.inner.open(peer, protocol).await?;
        Ok(Box::new(Stall {
            inner,
            stall: self.stall.clone(),
            stalled: false,
        }))
    }

    async fn listen(&self, protocol: &Protocol) -> Result<BoxStream<'static, Incoming>, LinkError> {
        self.inner.listen(protocol).await
    }

    fn add_hint(&self, peer: &PublicKey, hint: PeerHint) -> Result<(), LinkError> {
        self.inner.add_hint(peer, hint)
    }

    async fn disconnect_untrusted(&self) -> Result<usize, LinkError> {
        self.inner.disconnect_untrusted().await
    }

    async fn close(&self) {
        self.inner.close().await
    }
}

#[tokio::test]
async fn a_send_cut_short_mid_frame_does_not_break_later_frames() {
    let ids = [Identity::generate(), Identity::generate()];
    let roster = roster(&ids);
    let hub = MemoryLinkHub::new();
    let stall = Arc::new(AtomicBool::new(false));
    let fast = LinkTransportConfig {
        send_timeout: Duration::from_millis(200),
        ..config()
    };
    let h0 = RosterHandle::new(roster.clone()).unwrap();
    let h1 = RosterHandle::new(roster).unwrap();
    let l0: Arc<dyn Link> = Arc::new(StallLink {
        inner: Arc::new(hub.join(ids[0].public(), Arc::new(h0.clone()))),
        stall: stall.clone(),
    });
    let l1: Arc<dyn Link> = Arc::new(hub.join(ids[1].public(), Arc::new(h1.clone())));
    let a = LinkTransport::start(l0, ids[0].clone(), h0, fast.clone())
        .await
        .unwrap();
    let b = LinkTransport::start(l1, ids[1].clone(), h1, fast)
        .await
        .unwrap();
    let mut sub = b.subscribe("x").await.unwrap();
    let to = b.local();

    a.send(&to, "x", Bytes::from_static(b"one")).await.unwrap();
    assert_eq!(&next(&mut sub).await.unwrap().payload[..], b"one");

    stall.store(true, Ordering::SeqCst);
    assert!(matches!(
        a.send(&to, "x", Bytes::from(vec![0u8; 4096])).await,
        Err(TransportError::Unreachable)
    ));
    stall.store(false, Ordering::SeqCst);

    for i in 0..5u8 {
        a.send(&to, "x", Bytes::from(vec![i])).await.unwrap();
    }
    for i in 0..5u8 {
        assert_eq!(&next(&mut sub).await.unwrap().payload[..], &[i]);
    }
}
