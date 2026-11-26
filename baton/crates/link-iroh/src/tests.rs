use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use baton_link::PinnedKeys;
use baton_link::testing::{self, Harness};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

fn loopback() -> IrohConfig {
    IrohConfig {
        bind: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 0))],
        open_timeout: Duration::from_secs(5),
        ..IrohConfig::default()
    }
}

fn hint_for(link: &IrohLink) -> PeerHint {
    PeerHint {
        direct: link.bound_addrs(),
        relay: None,
    }
}

#[derive(Default)]
struct Loopback {
    links: Mutex<Vec<Arc<IrohLink>>>,
}

#[async_trait]
impl Harness for Loopback {
    async fn link(&self, identity: Identity, trust: Arc<dyn Trust>) -> Arc<dyn Link> {
        let link = Arc::new(IrohLink::bind(&identity, trust, loopback()).await.unwrap());
        let mut links = self.links.lock().unwrap();
        links.retain(|other| !other.inner.closed.load(Ordering::SeqCst));
        for other in links.iter() {
            other.add_hint(&link.local(), hint_for(&link)).unwrap();
            link.add_hint(&other.local(), hint_for(other)).unwrap();
        }
        links.push(link.clone());
        link
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conformance_on_loopback() {
    testing::link(&Loopback::default()).await;
}

#[test]
fn alpn_round_trips() {
    let p = Protocol::new("mesh").unwrap();
    let baton = AlpnPrefix::default();
    assert_eq!(alpn(&baton, &p), b"baton/mesh/1");
    assert_eq!(generic_alpn(&baton), b"baton/link/1");
    assert_eq!(protocol_of(&baton, b"baton/mesh/1"), Some(p.clone()));
    assert_eq!(protocol_of(&baton, b"baton/Mesh/1"), None);
    assert_eq!(protocol_of(&baton, b"other/mesh/1"), None);
    assert_eq!(protocol_of(&baton, b"batonx/mesh/1"), None);
    assert_eq!(protocol_of(&baton, b"baton//1"), None);
    assert_eq!(protocol_of(&baton, b"baton/mesh/2"), None);
    let app = AlpnPrefix::new("peleda").unwrap();
    assert_eq!(alpn(&app, &p), b"peleda/mesh/1");
    assert_eq!(protocol_of(&app, b"baton/mesh/1"), None);
    for bad in ["", "Baton", "a/b", "a b", &"x".repeat(17)] {
        assert!(AlpnPrefix::new(bad).is_err(), "{bad:?}");
    }
}

#[tokio::test]
async fn endpoint_id_is_the_identity_key() {
    let id = Identity::generate();
    let link = IrohLink::bind(&id, Arc::new(PinnedKeys::default()), loopback())
        .await
        .unwrap();
    assert_eq!(link.local(), id.public());
    assert_eq!(link.inner.endpoint.id().as_bytes(), &id.public().to_bytes());
    link.close().await;
}

async fn pair(pq: PostQuantum) -> (IrohLink, IrohLink) {
    let (ia, ib) = (Identity::generate(), Identity::generate());
    let config = IrohConfig {
        post_quantum: pq,
        ..loopback()
    };
    let a = IrohLink::bind(
        &ia,
        Arc::new(PinnedKeys::new([ib.public()])),
        config.clone(),
    )
    .await
    .unwrap();
    let b = IrohLink::bind(&ib, Arc::new(PinnedKeys::new([ia.public()])), config)
        .await
        .unwrap();
    a.add_hint(&b.local(), hint_for(&b)).unwrap();
    b.add_hint(&a.local(), hint_for(&a)).unwrap();
    (a, b)
}

#[tokio::test]
async fn peer_connections_negotiate_the_hybrid_group() {
    for pq in [PostQuantum::Required, PostQuantum::Preferred] {
        let (a, b) = pair(pq).await;
        let p = Protocol::new("pq").unwrap();
        let mut listener = b.listen(&p).await.unwrap();
        let mut s = a.open(&b.local(), &p).await.unwrap();
        s.write_all(b"q").await.unwrap();
        let mut inc = futures::StreamExt::next(&mut listener).await.unwrap();
        let mut one = [0u8; 1];
        inc.stream.read_exact(&mut one).await.unwrap();
        let conns: Vec<Connection> = a
            .inner
            .live
            .lock()
            .unwrap()
            .values()
            .map(|(_, c)| c.clone())
            .collect();
        assert!(!conns.is_empty());
        assert!(conns.iter().all(gate::negotiated_hybrid), "{pq:?}");
        a.close().await;
        b.close().await;
    }
}

async fn classical_dial(pq: PostQuantum) -> (Option<u8>, bool) {
    let (ia, ib) = (Identity::generate(), Identity::generate());
    let config = IrohConfig {
        post_quantum: pq,
        ..loopback()
    };
    let a = IrohLink::bind(&ia, Arc::new(PinnedKeys::new([ib.public()])), config)
        .await
        .unwrap();
    let p = Protocol::new("pq").unwrap();
    let mut listener = a.listen(&p).await.unwrap();

    let mut classical = rustls::crypto::aws_lc_rs::default_provider();
    classical.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    let raw = Endpoint::builder(iroh::endpoint::presets::Empty)
        .crypto_provider(Arc::new(classical))
        .secret_key(SecretKey::from_bytes(&ib.secret_bytes()))
        .clear_ip_transports()
        .bind_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .unwrap()
        .bind()
        .await
        .unwrap();
    let mut addr = EndpointAddr::new(gate::to_iroh(&ia.public()).unwrap());
    for s in a.bound_addrs() {
        addr = addr.with_ip_addr(s);
    }
    let outcome = async {
        let conn = raw
            .connect(addr, &alpn(&AlpnPrefix::default(), &p))
            .await
            .ok()?;
        let (mut send, mut recv) = conn.open_bi().await.ok()?;
        send.write_all(&hello(&p)).await.ok()?;
        let mut ack = [0u8; 1];
        recv.read_exact(&mut ack).await.ok()?;
        Some(ack[0])
    };
    let got = tokio::time::timeout(Duration::from_secs(5), outcome)
        .await
        .unwrap();
    let accepted = tokio::time::timeout(
        Duration::from_millis(300),
        futures::StreamExt::next(&mut listener),
    )
    .await
    .is_ok();
    raw.close().await;
    a.close().await;
    (got, accepted)
}

#[tokio::test]
async fn a_classical_only_peer_is_refused_when_hybrid_is_required() {
    assert_eq!(
        classical_dial(PostQuantum::Required).await,
        (None, false),
        "a trusted key with a classical handshake gets nothing"
    );
    assert_eq!(
        classical_dial(PostQuantum::Preferred).await,
        (Some(ACCEPT), true),
        "the same peer is served when classical key exchange is allowed"
    );
}

async fn dial_classical(pq: PostQuantum) -> (Result<(), LinkError>, bool) {
    let (ia, ib) = (Identity::generate(), Identity::generate());
    let p = Protocol::new("pq").unwrap();
    let mut classical = rustls::crypto::aws_lc_rs::default_provider();
    classical.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    let raw = Endpoint::builder(iroh::endpoint::presets::Empty)
        .crypto_provider(Arc::new(classical))
        .secret_key(SecretKey::from_bytes(&ib.secret_bytes()))
        .alpns(vec![
            alpn(&AlpnPrefix::default(), &p),
            generic_alpn(&AlpnPrefix::default()),
        ])
        .clear_ip_transports()
        .bind_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .unwrap()
        .bind()
        .await
        .unwrap();
    let hello_seen = Arc::new(AtomicBool::new(false));
    let server = {
        let raw = raw.clone();
        let hello_seen = hello_seen.clone();
        tokio::spawn(async move {
            while let Some(incoming) = raw.accept().await {
                let Ok(accepting) = incoming.accept() else {
                    continue;
                };
                let Ok(conn) = accepting.await else { continue };
                let hello_seen = hello_seen.clone();
                tokio::spawn(async move {
                    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        if read_hello(&mut recv).await.is_some() {
                            hello_seen.store(true, Ordering::SeqCst);
                            let _ = send.write_all(&[ACCEPT]).await;
                        }
                    }
                });
            }
        })
    };
    let config = IrohConfig {
        post_quantum: pq,
        ..loopback()
    };
    let a = IrohLink::bind(&ia, Arc::new(PinnedKeys::new([ib.public()])), config)
        .await
        .unwrap();
    a.add_hint(
        &ib.public(),
        PeerHint {
            direct: raw.bound_sockets(),
            relay: None,
        },
    )
    .unwrap();
    let opened = a.open(&ib.public(), &p).await.map(|_| ());
    tokio::time::sleep(Duration::from_millis(100)).await;
    let seen = hello_seen.load(Ordering::SeqCst);
    server.abort();
    a.close().await;
    raw.close().await;
    (opened, seen)
}

#[tokio::test]
async fn dialing_a_classical_only_peer_fails_when_hybrid_is_required() {
    let (opened, seen) = dial_classical(PostQuantum::Required).await;
    assert!(matches!(opened, Err(LinkError::Rejected)), "{opened:?}");
    assert!(!seen, "no stream reaches a classical peer");
    let (opened, seen) = dial_classical(PostQuantum::Preferred).await;
    assert!(opened.is_ok(), "{opened:?}");
    assert!(seen);
}

#[test]
fn plain_http_is_only_allowed_to_loopback() {
    for good in [
        "https://relay.example.com",
        "http://127.0.0.1:3340",
        "http://localhost:3340",
        "http://[::1]:3340",
    ] {
        let url = baton_link::RelayUrl::new(good).unwrap();
        assert!(config::relay_url(&url).is_ok(), "{good}");
    }
    let bad = baton_link::RelayUrl::new("http://relay.example.com").unwrap();
    assert!(matches!(
        config::relay_url(&bad),
        Err(LinkError::InvalidHint)
    ));
    for (relay, ok) in [
        ("http://dns.example.com/pkarr", false),
        ("http://127.0.0.1:8080/pkarr", true),
        ("https://dns.example.com/pkarr", true),
    ] {
        let discovery = Discovery::Pkarr {
            relay: relay.into(),
            dns_origin: None,
        };
        assert_eq!(
            discovery
                .apply(Endpoint::builder(iroh::endpoint::presets::Empty))
                .is_ok(),
            ok,
            "{relay}"
        );
    }
}

#[tokio::test]
async fn hints_validate_relays_and_merge() {
    let link = IrohLink::bind(
        &Identity::generate(),
        Arc::new(PinnedKeys::default()),
        loopback(),
    )
    .await
    .unwrap();
    let peer = Identity::generate().public();
    let a1: SocketAddr = "127.0.0.1:1000".parse().unwrap();
    let a2: SocketAddr = "127.0.0.1:2000".parse().unwrap();
    link.add_hint(
        &peer,
        PeerHint {
            direct: vec![a1],
            relay: Some(baton_link::RelayUrl::new("https://relay.example.com").unwrap()),
        },
    )
    .unwrap();
    link.add_hint(
        &peer,
        PeerHint {
            direct: vec![a1, a2],
            relay: None,
        },
    )
    .unwrap();
    let addr = link.inner.address(&peer).unwrap();
    assert_eq!(addr.ip_addrs().count(), 2);
    assert_eq!(addr.relay_urls().count(), 1);
    link.close().await;
    assert!(matches!(
        link.add_hint(&peer, PeerHint::default()),
        Err(LinkError::Closed)
    ));
}

#[test]
fn discovery_urls_are_checked() {
    let bad = Discovery::Pkarr {
        relay: "ftp://dns.example.com".into(),
        dns_origin: None,
    };
    assert!(matches!(
        bad.apply(Endpoint::builder(iroh::endpoint::presets::Empty)),
        Err(LinkError::InvalidHint)
    ));
}
