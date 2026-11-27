//! Conformance suite for [`Link`].
//!
//! Run it from an implementation's tests with a [`Harness`] that builds links able to reach each
//! other: `baton_link::testing::link(&harness).await`.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use baton_identity::Identity;
use futures::StreamExt;
use futures::stream::BoxStream;
use tokio_io::io::{AsyncReadExt, AsyncWriteExt};
use tokio_io::task::JoinHandle;

use crate::{Incoming, Link, LinkError, PinnedKeys, Protocol, Trust};

const PATIENCE: Duration = Duration::from_secs(20);
const QUIET: Duration = Duration::from_millis(300);
const BIG: usize = 8 * 1024 * 1024;
const STREAMS: usize = 64;

/// Builds the links the suite runs on.
#[async_trait]
pub trait Harness: Send + Sync {
    /// A new link for `identity` that trusts exactly what `trust` allows. Every link built by one
    /// harness must be able to reach every other one it built (the harness adds hints if the
    /// implementation needs them).
    async fn link(&self, identity: Identity, trust: Arc<dyn Trust>) -> Arc<dyn Link>;
}

struct Node {
    link: Arc<dyn Link>,
    pins: Arc<PinnedKeys>,
}

impl Node {
    async fn new(h: &dyn Harness) -> Self {
        let identity = Identity::generate();
        let key = identity.public();
        let pins = Arc::new(PinnedKeys::default());
        let link = h.link(identity, pins.clone()).await;
        assert_eq!(link.local(), key, "local() is the identity's key");
        Self { link, pins }
    }

    fn trust(&self, other: &Node) {
        self.pins.insert(other.link.local());
    }
}

async fn pair(h: &dyn Harness) -> (Node, Node) {
    let a = Node::new(h).await;
    let b = Node::new(h).await;
    a.trust(&b);
    b.trust(&a);
    (a, b)
}

fn proto(name: &str) -> Protocol {
    Protocol::new(name).unwrap()
}

async fn within<T>(what: &str, f: impl Future<Output = T>) -> T {
    tokio_io::time::timeout(PATIENCE, f)
        .await
        .unwrap_or_else(|_| panic!("timed out: {what}"))
}

async fn next(listener: &mut BoxStream<'static, Incoming>) -> Incoming {
    within("incoming stream", listener.next())
        .await
        .expect("listener ended")
}

async fn quiet(listener: &mut BoxStream<'static, Incoming>, why: &str) {
    if let Ok(Some(inc)) = tokio_io::time::timeout(QUIET, listener.next()).await {
        panic!("{why}: got a stream from {:?}", inc.peer);
    }
}

/// Echoes every stream back until end-of-stream.
fn echo(mut listener: BoxStream<'static, Incoming>) -> JoinHandle<()> {
    tokio_io::spawn(async move {
        while let Some(mut inc) = listener.next().await {
            tokio_io::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match inc.stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if inc.stream.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
                let _ = inc.stream.shutdown().await;
            });
        }
    })
}

async fn round_trip(link: &dyn Link, peer: &Node, p: &Protocol, payload: &[u8]) -> Vec<u8> {
    let mut s = within("open", link.open(&peer.link.local(), p))
        .await
        .expect("open to a trusted peer");
    let (mut r, mut w) = tokio_io::io::split(&mut s);
    let writer = async {
        w.write_all(payload).await.unwrap();
        w.shutdown().await.unwrap();
    };
    let reader = async {
        let mut got = Vec::new();
        r.read_to_end(&mut got).await.unwrap();
        got
    };
    let ((), got) = within("round trip", async { tokio_io::join!(writer, reader) }).await;
    got
}

/// Runs every check of the [`Link`] contract. Builds fresh links for each check.
pub async fn link(h: &dyn Harness) {
    protocol_names();
    both_ways(h).await;
    untrusted_on_open(h).await;
    untrusted_on_accept(h).await;
    protocols_are_isolated(h).await;
    one_listener_per_protocol(h).await;
    many_concurrent_streams(h).await;
    big_transfer(h).await;
    revocation(h).await;
    one_protocol_only(h).await;
    close(h).await;
}

struct OnlyOn(crate::PublicKey, Protocol);

impl Trust for OnlyOn {
    fn allows(&self, _: &crate::PublicKey) -> bool {
        false
    }

    fn allows_on(&self, peer: &crate::PublicKey, protocol: &Protocol) -> bool {
        *peer == self.0 && *protocol == self.1
    }

    fn reachable(&self, peer: &crate::PublicKey) -> bool {
        *peer == self.0
    }
}

async fn one_protocol_only(h: &dyn Harness) {
    let b = Node::new(h).await;
    let open = proto("conf-only-open");
    let closed = proto("conf-only-closed");
    let a_id = Identity::generate();
    let a_key = a_id.public();
    let a = h
        .link(a_id, Arc::new(OnlyOn(b.link.local(), open.clone())))
        .await;
    b.pins.insert(a_key);
    let mut la_open = a.listen(&open).await.unwrap();
    let mut la_closed = a.listen(&closed).await.unwrap();
    let mut lb_closed = b.link.listen(&closed).await.unwrap();
    let mut lb_open = b.link.listen(&open).await.unwrap();

    let mut s = within("open on the admitted protocol", b.link.open(&a_key, &open))
        .await
        .expect("a peer admitted on one protocol reaches it");
    s.write_all(b"k").await.unwrap();
    s.shutdown().await.unwrap();
    let inc = next(&mut la_open).await;
    assert_eq!(inc.peer, b.link.local());

    let res = within("open on another protocol", b.link.open(&a_key, &closed)).await;
    assert!(
        matches!(res, Err(LinkError::Rejected)),
        "every other protocol refuses it, got {:?}",
        res.err()
    );
    quiet(
        &mut la_closed,
        "no stream on a protocol the peer is not admitted on",
    )
    .await;
    assert!(matches!(
        within(
            "open out on another protocol",
            a.open(&b.link.local(), &closed)
        )
        .await,
        Err(LinkError::Untrusted)
    ));
    quiet(
        &mut lb_closed,
        "nothing leaves on a protocol the peer is not admitted on",
    )
    .await;
    let mut s = within(
        "open out on the admitted protocol",
        a.open(&b.link.local(), &open),
    )
    .await
    .expect("streams out on the admitted protocol work");
    s.write_all(b"k").await.unwrap();
    s.shutdown().await.unwrap();
    next(&mut lb_open).await;
    a.close().await;
    b.link.close().await;
}

fn protocol_names() {
    assert!(Protocol::new("mesh").is_ok());
    for bad in ["", "Mesh", "a/b", "-x", &"a".repeat(33), "caf\u{e9}"] {
        assert!(matches!(
            Protocol::new(bad),
            Err(LinkError::InvalidProtocol)
        ));
    }
}

async fn both_ways(h: &dyn Harness) {
    let (a, b) = pair(h).await;
    let p = proto("conf-both");
    let mut la = a.link.listen(&p).await.unwrap();
    let mut lb = b.link.listen(&p).await.unwrap();

    let mut s = within("open a->b", a.link.open(&b.link.local(), &p))
        .await
        .unwrap();
    s.write_all(b"ping from a").await.unwrap();
    let mut inc = next(&mut lb).await;
    assert_eq!(
        inc.peer,
        a.link.local(),
        "the acceptor learns the opener's key"
    );
    let mut buf = [0u8; 11];
    within("read at b", inc.stream.read_exact(&mut buf))
        .await
        .unwrap();
    assert_eq!(&buf, b"ping from a");
    inc.stream.write_all(b"pong from b").await.unwrap();
    inc.stream.shutdown().await.unwrap();
    let mut back = Vec::new();
    within("read at a", s.read_to_end(&mut back)).await.unwrap();
    assert_eq!(back, b"pong from b");

    let mut s = within("open b->a", b.link.open(&a.link.local(), &p))
        .await
        .unwrap();
    s.write_all(b"x").await.unwrap();
    s.shutdown().await.unwrap();
    let mut inc = next(&mut la).await;
    assert_eq!(inc.peer, b.link.local());
    let mut got = Vec::new();
    within("read at a", inc.stream.read_to_end(&mut got))
        .await
        .unwrap();
    assert_eq!(got, b"x");

    a.link.close().await;
    b.link.close().await;
}

async fn untrusted_on_open(h: &dyn Harness) {
    let a = Node::new(h).await;
    let c = Node::new(h).await;
    c.trust(&a);
    let p = proto("conf-untrusted-open");
    let mut lc = c.link.listen(&p).await.unwrap();
    assert!(matches!(
        within("open", a.link.open(&c.link.local(), &p)).await,
        Err(LinkError::Untrusted)
    ));
    quiet(&mut lc, "an untrusted peer never sees a stream from us").await;
    a.link.close().await;
    c.link.close().await;
}

async fn untrusted_on_accept(h: &dyn Harness) {
    let a = Node::new(h).await;
    let c = Node::new(h).await;
    c.trust(&a);
    let p = proto("conf-untrusted-accept");
    let mut la = a.link.listen(&p).await.unwrap();
    let res = within("open", c.link.open(&a.link.local(), &p)).await;
    assert!(
        matches!(res, Err(LinkError::Rejected)),
        "a peer that does not trust us refuses the stream, got {:?}",
        res.err()
    );
    quiet(&mut la, "a stream from an untrusted peer is never accepted").await;
    a.link.close().await;
    c.link.close().await;
}

async fn protocols_are_isolated(h: &dyn Harness) {
    let (a, b) = pair(h).await;
    let p1 = proto("conf-p1");
    let p2 = proto("conf-p2");
    let mut l1 = b.link.listen(&p1).await.unwrap();
    let mut l2 = b.link.listen(&p2).await.unwrap();

    let mut s = within("open p1", a.link.open(&b.link.local(), &p1))
        .await
        .unwrap();
    s.write_all(b"one").await.unwrap();
    s.shutdown().await.unwrap();
    let mut inc = next(&mut l1).await;
    let mut got = Vec::new();
    within("read p1", inc.stream.read_to_end(&mut got))
        .await
        .unwrap();
    assert_eq!(got, b"one");
    quiet(&mut l2, "a stream for p1 never reaches p2").await;

    let res = within("open p3", a.link.open(&b.link.local(), &proto("conf-p3"))).await;
    assert!(
        matches!(res, Err(LinkError::Rejected)),
        "no listener means rejected, got {:?}",
        res.err()
    );
    quiet(&mut l1, "nothing leaks from p3").await;
    quiet(&mut l2, "nothing leaks from p3").await;
    a.link.close().await;
    b.link.close().await;
}

async fn one_listener_per_protocol(h: &dyn Harness) {
    let (a, b) = pair(h).await;
    let p = proto("conf-one");
    let first = b.link.listen(&p).await.unwrap();
    assert!(matches!(
        b.link.listen(&p).await,
        Err(LinkError::AlreadyListening)
    ));
    drop(first);
    let res = within("open", a.link.open(&b.link.local(), &p)).await;
    assert!(
        matches!(res, Err(LinkError::Rejected)),
        "a dropped listener accepts nothing, got {:?}",
        res.err()
    );
    let second = b.link.listen(&p).await.unwrap();
    let server = echo(second);
    assert_eq!(round_trip(&*a.link, &b, &p, b"again").await, b"again");
    server.abort();
    a.link.close().await;
    b.link.close().await;
}

async fn many_concurrent_streams(h: &dyn Harness) {
    let (a, b) = pair(h).await;
    let a = Arc::new(a);
    let b = Arc::new(b);
    let p = proto("conf-many");
    let server = echo(b.link.listen(&p).await.unwrap());
    let mut tasks = Vec::new();
    for i in 0..STREAMS {
        let (a, b, p) = (a.clone(), b.clone(), p.clone());
        tasks.push(tokio_io::spawn(async move {
            let payload: Vec<u8> = (0..4096).map(|j| (i * 31 + j) as u8).collect();
            let got = round_trip(&*a.link, &b, &p, &payload).await;
            assert_eq!(got, payload, "stream {i} keeps its own bytes");
        }));
    }
    for t in tasks {
        within("concurrent stream", t).await.unwrap();
    }
    server.abort();
    a.link.close().await;
    b.link.close().await;
}

async fn big_transfer(h: &dyn Harness) {
    let (a, b) = pair(h).await;
    let p = proto("conf-big");
    let server = echo(b.link.listen(&p).await.unwrap());
    let payload: Vec<u8> = (0..BIG).map(|i| (i % 251) as u8).collect();
    let got = round_trip(&*a.link, &b, &p, &payload).await;
    assert_eq!(got.len(), BIG);
    assert!(got == payload, "8 MiB arrive unchanged both ways");
    server.abort();
    a.link.close().await;
    b.link.close().await;
}

async fn revocation(h: &dyn Harness) {
    let (a, b) = pair(h).await;
    let p = proto("conf-revoke");
    let server = echo(b.link.listen(&p).await.unwrap());
    let mut la = a.link.listen(&p).await.unwrap();

    let mut open = within("open", a.link.open(&b.link.local(), &p))
        .await
        .unwrap();
    open.write_all(b"before").await.unwrap();
    let mut buf = [0u8; 6];
    within("echo", open.read_exact(&mut buf)).await.unwrap();

    b.pins.remove(&a.link.local());
    let res = within("open after revocation", a.link.open(&b.link.local(), &p)).await;
    assert!(
        matches!(res, Err(LinkError::Rejected)),
        "the revoking side refuses new streams at once, got {:?}",
        res.err()
    );
    assert!(matches!(
        within("open to revoked", b.link.open(&a.link.local(), &p)).await,
        Err(LinkError::Untrusted)
    ));
    quiet(&mut la, "nothing from the revoking side").await;

    assert_eq!(b.link.disconnect_untrusted().await.unwrap(), 1);
    let severed = within("severed stream", async {
        let mut sink = Vec::new();
        let _ = open.write_all(b"after").await;
        match open.read_to_end(&mut sink).await {
            Ok(_) => !sink.windows(5).any(|w| w == b"after"),
            Err(_) => true,
        }
    })
    .await;
    assert!(severed, "disconnect_untrusted severs open streams");
    assert_eq!(b.link.disconnect_untrusted().await.unwrap(), 0);

    b.pins.insert(a.link.local());
    assert_eq!(round_trip(&*a.link, &b, &p, b"back").await, b"back");
    server.abort();
    a.link.close().await;
    b.link.close().await;
}

async fn close(h: &dyn Harness) {
    let (a, b) = pair(h).await;
    let p = proto("conf-close");
    let server = echo(b.link.listen(&p).await.unwrap());
    let mut la = a.link.listen(&p).await.unwrap();
    let mut s = within("open", a.link.open(&b.link.local(), &p))
        .await
        .unwrap();
    s.write_all(b"hi").await.unwrap();
    let mut buf = [0u8; 2];
    within("echo", s.read_exact(&mut buf)).await.unwrap();

    a.link.close().await;
    a.link.close().await;
    assert!(matches!(
        a.link.open(&b.link.local(), &p).await,
        Err(LinkError::Closed)
    ));
    assert!(matches!(a.link.listen(&p).await, Err(LinkError::Closed)));
    assert!(
        within("listener ends", la.next()).await.is_none(),
        "listeners end on close"
    );
    let ended = within("stream ends", async {
        let mut rest = Vec::new();
        s.read_to_end(&mut rest).await.is_err() || rest.is_empty()
    })
    .await;
    assert!(ended, "open streams are severed on close");
    assert!(
        within("open to closed", b.link.open(&a.link.local(), &p))
            .await
            .is_err(),
        "a closed link is unreachable"
    );
    server.abort();
    b.link.close().await;
}
