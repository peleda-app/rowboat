//! An in-process [`Link`] for tests: links join a [`MemoryLinkHub`], which can split them into
//! partitions. Trust is enforced exactly as the contract asks, on both ends, for every stream; the
//! bytes themselves are not encrypted because they never leave the process.

use std::collections::{HashMap, HashSet};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use async_trait::async_trait;
use baton_link::{Duplex, Incoming, Link, LinkError, PeerHint, Protocol, PublicKey, Trust};
use futures::Stream;
use futures::stream::BoxStream;
use futures::task::AtomicWaker;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::mpsc;

/// The buffer of each direction of an in-memory stream.
pub const STREAM_BUFFER: usize = 64 * 1024;

#[derive(Default)]
struct Cut {
    flag: AtomicBool,
    wakers: [AtomicWaker; 4],
}

impl Cut {
    fn sever(&self) {
        self.flag.store(true, Ordering::SeqCst);
        for w in &self.wakers {
            w.wake();
        }
    }

    fn is_cut(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

struct Severable {
    inner: DuplexStream,
    cut: Arc<Cut>,
    end: usize,
}

fn severed() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, "stream severed")
}

impl Severable {
    fn check(&self, cx: &Context<'_>, slot: usize) -> Result<(), io::Error> {
        if self.cut.is_cut() {
            return Err(severed());
        }
        self.cut.wakers[self.end * 2 + slot].register(cx.waker());
        if self.cut.is_cut() {
            return Err(severed());
        }
        Ok(())
    }
}

impl AsyncRead for Severable {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Err(e) = self.check(cx, 0) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Severable {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(e) = self.check(cx, 1) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(e) = self.check(cx, 1) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(e) = self.check(cx, 1) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

type Listeners = Mutex<HashMap<Protocol, (u64, mpsc::UnboundedSender<Incoming>)>>;

struct Node {
    key: PublicKey,
    trust: Arc<dyn Trust>,
    listeners: Listeners,
    next_listener: AtomicU64,
    closed: AtomicBool,
}

struct Record {
    ends: [PublicKey; 2],
    cut: Arc<Cut>,
}

#[derive(Default)]
struct HubState {
    nodes: HashMap<PublicKey, Arc<Node>>,
    groups: HashMap<PublicKey, usize>,
    streams: Vec<Record>,
}

impl HubState {
    fn group(&self, key: &PublicKey) -> usize {
        self.groups.get(key).copied().unwrap_or(0)
    }

    fn sever_where(&mut self, mut pred: impl FnMut(&Record) -> bool) -> HashSet<[PublicKey; 2]> {
        let mut cut = HashSet::new();
        self.streams.retain(|r| {
            if Arc::strong_count(&r.cut) == 1 || r.cut.is_cut() {
                return false;
            }
            if pred(r) {
                r.cut.sever();
                cut.insert(r.ends);
                return false;
            }
            true
        });
        cut
    }
}

/// The in-process network. Cloning shares it.
///
/// Guarantees: a stream can be opened exactly when both links are joined and open, sit in the
/// same partition, trust each other and the acceptor listens for the protocol. Splitting the
/// network severs every open stream between partitions; healing lets new streams through.
#[derive(Clone, Default)]
pub struct MemoryLinkHub {
    state: Arc<Mutex<HubState>>,
}

impl MemoryLinkHub {
    /// An empty network with every link in one partition.
    pub fn new() -> Self {
        Self::default()
    }

    /// Joins a link with key `key` that trusts what `trust` allows. Joining again with the same
    /// key closes the earlier link first.
    pub fn join(&self, key: PublicKey, trust: Arc<dyn Trust>) -> MemoryLink {
        let node = Arc::new(Node {
            key,
            trust,
            listeners: Mutex::new(HashMap::new()),
            next_listener: AtomicU64::new(0),
            closed: AtomicBool::new(false),
        });
        let old = self
            .state
            .lock()
            .expect("hub lock")
            .nodes
            .insert(key, node.clone());
        if let Some(old) = old {
            self.shut(&old);
        }
        MemoryLink {
            hub: self.clone(),
            node,
        }
    }

    /// Splits the network: links in the same group reach each other, links in different groups
    /// do not, and streams between groups are severed now. Links in no group form one more
    /// partition together.
    pub fn partition(&self, groups: &[&[PublicKey]]) {
        let mut state = self.state.lock().expect("hub lock");
        state.groups.clear();
        for (i, group) in groups.iter().enumerate() {
            for key in group.iter() {
                state.groups.insert(*key, i + 1);
            }
        }
        let groups = state.groups.clone();
        let g = |k: &PublicKey| groups.get(k).copied().unwrap_or(0);
        state.sever_where(|r| g(&r.ends[0]) != g(&r.ends[1]));
    }

    /// Joins every partition back together. Severed streams stay severed.
    pub fn heal(&self) {
        self.state.lock().expect("hub lock").groups.clear();
    }

    fn shut(&self, node: &Arc<Node>) {
        node.closed.store(true, Ordering::SeqCst);
        node.listeners.lock().expect("listeners lock").clear();
        let mut state = self.state.lock().expect("hub lock");
        if state
            .nodes
            .get(&node.key)
            .is_some_and(|n| Arc::ptr_eq(n, node))
        {
            state.nodes.remove(&node.key);
        }
        state.sever_where(|r| r.ends.contains(&node.key));
    }
}

/// One node's link on a [`MemoryLinkHub`]. Cloning shares it.
#[derive(Clone)]
pub struct MemoryLink {
    hub: MemoryLinkHub,
    node: Arc<Node>,
}

struct Listener {
    rx: mpsc::UnboundedReceiver<Incoming>,
    node: Arc<Node>,
    protocol: Protocol,
    id: u64,
}

impl Stream for Listener {
    type Item = Incoming;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Incoming>> {
        self.rx.poll_recv(cx)
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let mut listeners = self.node.listeners.lock().expect("listeners lock");
        if listeners
            .get(&self.protocol)
            .is_some_and(|(id, _)| *id == self.id)
        {
            listeners.remove(&self.protocol);
        }
    }
}

impl MemoryLink {
    fn ensure_open(&self) -> Result<(), LinkError> {
        if self.node.closed.load(Ordering::SeqCst) {
            Err(LinkError::Closed)
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl Link for MemoryLink {
    fn local(&self) -> PublicKey {
        self.node.key
    }

    async fn open(
        &self,
        peer: &PublicKey,
        protocol: &Protocol,
    ) -> Result<Box<dyn Duplex>, LinkError> {
        self.ensure_open()?;
        if !self.node.trust.allows(peer) {
            return Err(LinkError::Untrusted);
        }
        let mut state = self.hub.state.lock().expect("hub lock");
        let remote = state
            .nodes
            .get(peer)
            .filter(|n| !n.closed.load(Ordering::SeqCst) && *peer != self.node.key)
            .cloned()
            .ok_or(LinkError::Unreachable)?;
        if state.group(peer) != state.group(&self.node.key) {
            return Err(LinkError::Unreachable);
        }
        if !remote.trust.allows(&self.node.key) {
            return Err(LinkError::Rejected);
        }
        let tx = remote
            .listeners
            .lock()
            .expect("listeners lock")
            .get(protocol)
            .map(|(_, tx)| tx.clone())
            .ok_or(LinkError::Rejected)?;
        let (near, far) = tokio::io::duplex(STREAM_BUFFER);
        let cut = Arc::new(Cut::default());
        let incoming = Incoming {
            peer: self.node.key,
            stream: Box::new(Severable {
                inner: far,
                cut: cut.clone(),
                end: 1,
            }),
        };
        tx.send(incoming).map_err(|_| LinkError::Rejected)?;
        state.streams.push(Record {
            ends: [self.node.key, *peer],
            cut: cut.clone(),
        });
        Ok(Box::new(Severable {
            inner: near,
            cut,
            end: 0,
        }))
    }

    async fn listen(&self, protocol: &Protocol) -> Result<BoxStream<'static, Incoming>, LinkError> {
        self.ensure_open()?;
        let mut listeners = self.node.listeners.lock().expect("listeners lock");
        if listeners.contains_key(protocol) {
            return Err(LinkError::AlreadyListening);
        }
        let id = self.node.next_listener.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::unbounded_channel();
        listeners.insert(protocol.clone(), (id, tx));
        drop(listeners);
        self.ensure_open()?;
        Ok(Box::pin(Listener {
            rx,
            node: self.node.clone(),
            protocol: protocol.clone(),
            id,
        }))
    }

    fn add_hint(&self, _peer: &PublicKey, _hint: PeerHint) -> Result<(), LinkError> {
        self.ensure_open()
    }

    async fn disconnect_untrusted(&self) -> Result<usize, LinkError> {
        self.ensure_open()?;
        let me = self.node.key;
        let trust = self.node.trust.clone();
        let mut state = self.hub.state.lock().expect("hub lock");
        let cut = state.sever_where(|r| {
            let other = if r.ends[0] == me {
                r.ends[1]
            } else if r.ends[1] == me {
                r.ends[0]
            } else {
                return false;
            };
            !trust.allows(&other)
        });
        let peers: HashSet<PublicKey> = cut
            .into_iter()
            .map(|ends| if ends[0] == me { ends[1] } else { ends[0] })
            .collect();
        Ok(peers.len())
    }

    async fn close(&self) {
        self.hub.shut(&self.node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use baton_identity::Identity;
    use baton_link::PinnedKeys;
    use baton_link::testing::{self, Harness};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct Hub(MemoryLinkHub);

    #[async_trait]
    impl Harness for Hub {
        async fn link(&self, identity: Identity, trust: Arc<dyn Trust>) -> Arc<dyn Link> {
            Arc::new(self.0.join(identity.public(), trust))
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn conformance() {
        testing::link(&Hub(MemoryLinkHub::new())).await;
    }

    #[tokio::test]
    async fn partitions_sever_and_heal() {
        let hub = MemoryLinkHub::new();
        let (a, b) = (Identity::generate().public(), Identity::generate().public());
        let la = hub.join(a, Arc::new(PinnedKeys::new([b])));
        let lb = hub.join(b, Arc::new(PinnedKeys::new([a])));
        let p = Protocol::new("x").unwrap();
        let mut listener = lb.listen(&p).await.unwrap();
        let mut s = la.open(&b, &p).await.unwrap();
        let mut inc = futures::StreamExt::next(&mut listener).await.unwrap();
        s.write_all(b"1").await.unwrap();
        let mut one = [0u8; 1];
        inc.stream.read_exact(&mut one).await.unwrap();

        hub.partition(&[&[a], &[b]]);
        assert!(s.write_all(b"2").await.is_err());
        assert!(inc.stream.read(&mut one).await.is_err());
        assert!(matches!(la.open(&b, &p).await, Err(LinkError::Unreachable)));
        hub.heal();
        assert!(la.open(&b, &p).await.is_ok());
    }
}
