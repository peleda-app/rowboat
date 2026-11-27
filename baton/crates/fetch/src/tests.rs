use std::collections::HashMap;

use baton_identity::Identity;
use baton_link::PinnedKeys;
use baton_link_memory::MemoryLinkHub;

use super::*;

#[derive(Default)]
struct Held(
    Mutex<HashMap<(ResourceId, ContentId), Bytes>>,
    Option<Duration>,
);

impl Held {
    fn with(items: &[&[u8]]) -> Arc<Self> {
        Self::for_resource(&res(), items)
    }
    fn for_resource(r: &ResourceId, items: &[&[u8]]) -> Arc<Self> {
        let s = Self::default();
        for i in items {
            s.0.lock()
                .unwrap()
                .insert((r.clone(), ContentId::of(i)), Bytes::copy_from_slice(i));
        }
        Arc::new(s)
    }
}

#[async_trait]
impl LocalObjects for Held {
    async fn get(&self, r: &ResourceId, id: &ContentId, _: &[u8]) -> Option<Bytes> {
        if let Some(d) = self.1 {
            tokio::time::sleep(d).await;
        }
        self.0.lock().unwrap().get(&(r.clone(), *id)).cloned()
    }
}

struct Liar;

#[async_trait]
impl LocalObjects for Liar {
    async fn get(&self, _: &ResourceId, _: &ContentId, _: &[u8]) -> Option<Bytes> {
        Some(Bytes::from_static(b"not what you asked for"))
    }
}

struct Src(Option<Bytes>);

#[async_trait]
impl Source for Src {
    async fn fetch(&self, _: &ResourceId, _: &ContentId) -> Result<Option<Bytes>, FetchError> {
        Ok(self.0.clone())
    }
}

fn res() -> ResourceId {
    ResourceId::new("mail").unwrap()
}

struct Net {
    hub: MemoryLinkHub,
    ids: Vec<Identity>,
}

impl Net {
    fn new(n: usize) -> Self {
        Self {
            hub: MemoryLinkHub::new(),
            ids: (0..n).map(|_| Identity::generate()).collect(),
        }
    }
    fn link(&self, i: usize) -> Arc<dyn Link> {
        let keys = self.ids.iter().map(Identity::public).collect::<Vec<_>>();
        Arc::new(
            self.hub
                .join(self.ids[i].public(), Arc::new(PinnedKeys::new(keys))),
        )
    }
    fn key(&self, i: usize) -> PublicKey {
        self.ids[i].public()
    }
}

fn allow_all() -> Authorize {
    Arc::new(|_, _| true)
}

fn cfg() -> FetchConfig {
    FetchConfig {
        peer_timeout: Duration::from_millis(300),
        ..FetchConfig::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_object_comes_from_a_peer_that_holds_it() {
    let net = Net::new(2);
    let _s = serve(net.link(1), Held::with(&[b"hello"]), allow_all(), cfg())
        .await
        .unwrap();
    let f = Fetcher::new(net.link(0), None, cfg());
    let (bytes, from) = f
        .fetch(&res(), &ContentId::of(b"hello"), &[net.key(1)])
        .await
        .unwrap();
    assert_eq!(&bytes[..], b"hello");
    assert_eq!(from, Origin::Peer(net.key(1)));
    assert!(matches!(
        f.fetch(&res(), &ContentId::of(b"missing"), &[net.key(1)])
            .await,
        Err(FetchError::NotFound)
    ));
}

/// Serves only what the locator names, ignoring the content id, like a store keyed by name.
struct ByName(HashMap<Vec<u8>, Bytes>);

#[async_trait]
impl LocalObjects for ByName {
    async fn get(&self, _: &ResourceId, _: &ContentId, locator: &[u8]) -> Option<Bytes> {
        self.0.get(locator).cloned()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_locator_finds_the_object_but_never_overrides_its_id() {
    let net = Net::new(2);
    let held = ByName(
        [
            (b"seg-1".to_vec(), Bytes::from_static(b"first")),
            (b"seg-2".to_vec(), Bytes::from_static(b"second")),
        ]
        .into(),
    );
    let _s = serve(net.link(1), Arc::new(held), allow_all(), cfg())
        .await
        .unwrap();
    let f = Fetcher::new(net.link(0), None, cfg());
    let (bytes, _) = f
        .fetch_located(&res(), &ContentId::of(b"first"), b"seg-1", &[net.key(1)])
        .await
        .unwrap();
    assert_eq!(&bytes[..], b"first");
    assert!(
        matches!(
            f.fetch_located(&res(), &ContentId::of(b"first"), b"seg-2", &[net.key(1)])
                .await,
            Err(FetchError::NotFound)
        ),
        "the bytes the locator names are checked against the id"
    );
    assert_eq!(f.liars(&res()), vec![net.key(1)]);
    let g = Fetcher::new(net.link(0), None, cfg());
    assert!(matches!(
        g.fetch_located(
            &res(),
            &ContentId::of(b"first"),
            &[0u8; MAX_LOCATOR + 1],
            &[net.key(1)]
        )
        .await,
        Err(FetchError::NotFound)
    ));
    assert!(g.liars(&res()).is_empty(), "nobody was asked");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_with_an_oversized_locator_is_answered_not_here() {
    let net = Net::new(2);
    let _s = serve(net.link(1), Held::with(&[b"x"]), allow_all(), cfg())
        .await
        .unwrap();
    let mut s = net
        .link(0)
        .open(&net.key(1), &Protocol::new(PROTOCOL).unwrap())
        .await
        .unwrap();
    let req = postcard::to_stdvec(&Request {
        v: VERSION,
        resource: res(),
        id: ContentId::of(b"x"),
        locator: vec![7; MAX_LOCATOR + 1],
    })
    .unwrap();
    s.write_u16(req.len() as u16).await.unwrap();
    s.write_all(&req).await.unwrap();
    assert_eq!(s.read_u8().await.unwrap(), NOT_HERE);
    let mut s = net
        .link(0)
        .open(&net.key(1), &Protocol::new(PROTOCOL).unwrap())
        .await
        .unwrap();
    let old = postcard::to_stdvec(&Request {
        v: 1,
        resource: res(),
        id: ContentId::of(b"x"),
        locator: Vec::new(),
    })
    .unwrap();
    s.write_u16(old.len() as u16).await.unwrap();
    s.write_all(&old).await.unwrap();
    assert_eq!(s.read_u8().await.unwrap(), NOT_HERE, "an unknown version");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lying_peer_is_skipped_and_remembered() {
    let net = Net::new(3);
    let _liar = serve(net.link(1), Arc::new(Liar), allow_all(), cfg())
        .await
        .unwrap();
    let _honest = serve(net.link(2), Held::with(&[b"real"]), allow_all(), cfg())
        .await
        .unwrap();
    let f = Fetcher::new(
        net.link(0),
        None,
        FetchConfig {
            parallel: 1,
            ..cfg()
        },
    );
    let (bytes, from) = f
        .fetch(&res(), &ContentId::of(b"real"), &[net.key(1), net.key(2)])
        .await
        .unwrap();
    assert_eq!(&bytes[..], b"real");
    assert_eq!(from, Origin::Peer(net.key(2)));
    assert_eq!(f.liars(&res()), vec![net.key(1)]);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unauthorized_peer_gets_nothing_and_cannot_tell_why() {
    let net = Net::new(2);
    let reader = net.key(0);
    let refuse: Authorize = Arc::new(move |peer, _| *peer != reader);
    let _s = serve(net.link(1), Held::with(&[b"private"]), refuse, cfg())
        .await
        .unwrap();
    let f = Fetcher::new(net.link(0), None, cfg());
    assert!(matches!(
        f.fetch(&res(), &ContentId::of(b"private"), &[net.key(1)])
            .await,
        Err(FetchError::NotFound)
    ));
    assert!(f.liars(&res()).is_empty(), "a refusal is not a lie");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_source_is_the_last_step_and_is_verified_too() {
    let net = Net::new(2);
    let _s = serve(net.link(1), Held::with(&[]), allow_all(), cfg())
        .await
        .unwrap();
    let good = Fetcher::new(
        net.link(0),
        Some(Arc::new(Src(Some(Bytes::from_static(b"from s3"))))),
        cfg(),
    );
    let (bytes, from) = good
        .fetch(&res(), &ContentId::of(b"from s3"), &[net.key(1)])
        .await
        .unwrap();
    assert_eq!((&bytes[..], from), (&b"from s3"[..], Origin::Source));
    let lying = Fetcher::new(
        net.link(0),
        Some(Arc::new(Src(Some(Bytes::from_static(b"tampered"))))),
        cfg(),
    );
    assert!(matches!(
        lying.fetch(&res(), &ContentId::of(b"from s3"), &[]).await,
        Err(FetchError::NotFound)
    ));
}

#[tokio::test(start_paused = true)]
async fn a_stalled_peer_costs_only_its_timeout() {
    let net = Net::new(3);
    let slow = Arc::new(Held(
        Mutex::new(HashMap::from([(
            (res(), ContentId::of(b"x")),
            Bytes::from_static(b"x"),
        )])),
        Some(Duration::from_secs(30)),
    ));
    let _slow = serve(net.link(1), slow, allow_all(), cfg()).await.unwrap();
    let _fast = serve(net.link(2), Held::with(&[b"x"]), allow_all(), cfg())
        .await
        .unwrap();
    let f = Fetcher::new(
        net.link(0),
        None,
        FetchConfig {
            parallel: 1,
            ..cfg()
        },
    );
    let started = tokio::time::Instant::now();
    let (_, from) = f
        .fetch(&res(), &ContentId::of(b"x"), &[net.key(1), net.key(2)])
        .await
        .unwrap();
    assert_eq!(from, Origin::Peer(net.key(2)));
    assert_eq!(started.elapsed(), cfg().peer_timeout);
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_objects_are_neither_served_nor_accepted() {
    let net = Net::new(2);
    let big = vec![7u8; 4096];
    let small = FetchConfig {
        max_object: 1024,
        ..cfg()
    };
    let _s = serve(net.link(1), Held::with(&[&big]), allow_all(), small.clone())
        .await
        .unwrap();
    let generous = Fetcher::new(net.link(0), None, cfg());
    assert!(
        matches!(
            generous
                .fetch(&res(), &ContentId::of(&big), &[net.key(1)])
                .await,
            Err(FetchError::NotFound)
        ),
        "not served"
    );
    let f = Fetcher::new(
        net.link(0),
        Some(Arc::new(Src(Some(Bytes::from(big.clone()))))),
        small,
    );
    assert!(
        matches!(
            f.fetch(&res(), &ContentId::of(&big), &[]).await,
            Err(FetchError::NotFound)
        ),
        "not accepted"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn garbage_requests_do_not_crash_the_server() {
    let net = Net::new(2);
    let _s = serve(net.link(1), Held::with(&[b"ok"]), allow_all(), cfg())
        .await
        .unwrap();
    let raw = net.link(0);
    let protocol = Protocol::new(PROTOCOL).unwrap();
    for bad in [&[0xff, 0xff][..], &[0x00, 0x05, 1, 2, 3, 4, 5][..], &[][..]] {
        let mut s = raw.open(&net.key(1), &protocol).await.unwrap();
        s.write_all(bad).await.unwrap();
        s.shutdown().await.ok();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut out)).await;
    }
    let f = Fetcher::new(net.link(0), None, cfg());
    assert!(
        f.fetch(&res(), &ContentId::of(b"ok"), &[net.key(1)])
            .await
            .is_ok(),
        "the server still serves"
    );
}

mod review {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn idle_streams_from_one_peer_cannot_starve_others() {
        let net = Net::new(3);
        let mallory = net.key(2);
        let refuse: Authorize = Arc::new(move |p, _| *p != mallory);
        let config = FetchConfig {
            max_serving: 4,
            max_per_peer: 2,
            ..cfg()
        };
        let _s = serve(net.link(1), Held::with(&[b"x"]), refuse, config.clone())
            .await
            .unwrap();
        let attacker = net.link(2);
        let protocol = Protocol::new(PROTOCOL).unwrap();
        let mut idle = Vec::new();
        for _ in 0..10 {
            if let Ok(s) = attacker.open(&net.key(1), &protocol).await {
                idle.push(s);
            }
        }
        let f = Fetcher::new(net.link(0), None, config);
        let started = tokio::time::Instant::now();
        assert!(
            f.fetch(&res(), &ContentId::of(b"x"), &[net.key(1)])
                .await
                .is_ok(),
            "an authorized reader is still served"
        );
        assert_eq!(
            started.elapsed(),
            Duration::ZERO,
            "served without waiting for the idle streams to time out"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_reader_of_one_resource_cannot_probe_another() {
        let net = Net::new(2);
        let other = ResourceId::new("other").unwrap();
        let only_mail: Authorize = Arc::new(|_, r| r.as_str() == "mail");
        let _s = serve(
            net.link(1),
            Held::for_resource(&other, &[b"secret"]),
            only_mail,
            cfg(),
        )
        .await
        .unwrap();
        let f = Fetcher::new(net.link(0), None, cfg());
        assert!(matches!(
            f.fetch(&res(), &ContentId::of(b"secret"), &[net.key(1)])
                .await,
            Err(FetchError::NotFound)
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_liar_is_skipped_only_for_the_resource_it_lied_about() {
        let net = Net::new(2);
        let _liar = serve(net.link(1), Arc::new(Liar), allow_all(), cfg())
            .await
            .unwrap();
        let f = Fetcher::new(net.link(0), None, cfg());
        let _ = f.fetch(&res(), &ContentId::of(b"a"), &[net.key(1)]).await;
        assert_eq!(f.liars(&res()), vec![net.key(1)]);
        assert!(f.liars(&ResourceId::new("other").unwrap()).is_empty());
        let short = Fetcher::new(
            net.link(0),
            None,
            FetchConfig {
                liar_ttl: Duration::from_millis(1),
                ..cfg()
            },
        );
        let _ = short
            .fetch(&res(), &ContentId::of(b"a"), &[net.key(1)])
            .await;
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(short.liars(&res()).is_empty(), "the mark expires");
    }

    struct Claims;

    #[async_trait]
    impl LocalObjects for Claims {
        async fn get(&self, _: &ResourceId, _: &ContentId, _: &[u8]) -> Option<Bytes> {
            None
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_server_announcing_a_huge_object_then_stalling_costs_only_the_timeout() {
        let net = Net::new(2);
        let link = net.link(1);
        let protocol = Protocol::new(PROTOCOL).unwrap();
        let mut incoming = link.listen(&protocol).await.unwrap();
        tokio::spawn(async move {
            while let Some(mut inc) = incoming.next().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    let _ = inc.stream.read(&mut buf).await;
                    let _ = inc.stream.write_u8(FOUND).await;
                    let _ = inc.stream.write_u64(64 * 1024 * 1024).await;
                    let _ = inc.stream.write_all(b"tiny").await;
                    tokio::time::sleep(Duration::from_secs(30)).await;
                });
            }
        });
        let _ = Claims;
        let f = Fetcher::new(net.link(0), None, cfg());
        let started = tokio::time::Instant::now();
        assert!(matches!(
            f.fetch(&res(), &ContentId::of(b"x"), &[net.key(1)]).await,
            Err(FetchError::NotFound)
        ));
        assert_eq!(started.elapsed(), cfg().peer_timeout);
    }

    async fn trickle(net: &Net, body: Vec<u8>, chunk: usize, every: Duration) {
        let link = net.link(1);
        let protocol = Protocol::new(PROTOCOL).unwrap();
        let mut incoming = link.listen(&protocol).await.unwrap();
        tokio::spawn(async move {
            let _link = link;
            while let Some(mut inc) = incoming.next().await {
                let body = body.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    let _ = inc.stream.read(&mut buf).await;
                    let _ = inc.stream.write_u8(FOUND).await;
                    let _ = inc.stream.write_u64(body.len() as u64).await;
                    for part in body.chunks(chunk) {
                        tokio::time::sleep(every).await;
                        let _ = inc.stream.write_all(part).await;
                    }
                    let _ = inc.stream.flush().await;
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                });
            }
        });
    }

    #[tokio::test(start_paused = true)]
    async fn a_large_object_gets_time_in_proportion_to_its_size() {
        let net = Net::new(2);
        let body = vec![7u8; 1024 * 1024];
        trickle(&net, body.clone(), 128 * 1024, Duration::from_secs(1)).await;
        let slow_ok = FetchConfig {
            min_rate: 64 * 1024,
            ..cfg()
        };
        let f = Fetcher::new(net.link(0), None, slow_ok.clone());
        let (bytes, _) = f
            .fetch(&res(), &ContentId::of(&body), &[net.key(1)])
            .await
            .unwrap();
        assert_eq!(bytes.len(), body.len());
        let strict = Fetcher::new(net.link(0), None, cfg());
        let started = tokio::time::Instant::now();
        assert!(matches!(
            strict
                .fetch(&res(), &ContentId::of(&body), &[net.key(1)])
                .await,
            Err(FetchError::NotFound)
        ));
        assert_eq!(started.elapsed(), cfg().peer_timeout);
    }

    #[tokio::test(start_paused = true)]
    async fn a_trickle_slower_than_the_minimum_rate_is_cut_at_its_deadline() {
        let net = Net::new(2);
        let body = vec![7u8; 1024 * 1024];
        trickle(&net, body.clone(), 16 * 1024, Duration::from_secs(1)).await;
        let config = FetchConfig {
            min_rate: 64 * 1024,
            ..cfg()
        };
        let f = Fetcher::new(net.link(0), None, config.clone());
        let started = tokio::time::Instant::now();
        assert!(matches!(
            f.fetch(&res(), &ContentId::of(&body), &[net.key(1)]).await,
            Err(FetchError::NotFound)
        ));
        assert_eq!(
            started.elapsed(),
            cfg().peer_timeout + Duration::from_secs(16)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_server_gives_a_large_object_the_same_time() {
        let net = Net::new(2);
        let body = vec![9u8; 512 * 1024];
        let config = FetchConfig {
            min_rate: 64 * 1024,
            ..cfg()
        };
        let _s = serve(
            net.link(1),
            Held::with(&[&body]),
            allow_all(),
            config.clone(),
        )
        .await
        .unwrap();
        let link = net.link(0);
        let protocol = Protocol::new(PROTOCOL).unwrap();
        let mut s = link.open(&net.key(1), &protocol).await.unwrap();
        let req = postcard::to_stdvec(&Request {
            v: VERSION,
            resource: res(),
            id: ContentId::of(&body),
            locator: Vec::new(),
        })
        .unwrap();
        s.write_u16(req.len() as u16).await.unwrap();
        s.write_all(&req).await.unwrap();
        assert_eq!(s.read_u8().await.unwrap(), FOUND);
        assert_eq!(s.read_u64().await.unwrap(), body.len() as u64);
        tokio::time::sleep(cfg().peer_timeout * 2).await;
        let mut got = Vec::new();
        s.read_to_end(&mut got).await.unwrap();
        assert_eq!(
            got.len(),
            body.len(),
            "the server kept sending past peer_timeout"
        );
    }
}

#[test]
fn request_and_reply_headers_decode_safely() {
    let req = postcard::to_stdvec(&Request {
        v: VERSION,
        resource: res(),
        id: ContentId::of(b"x"),
        locator: vec![1; MAX_LOCATOR],
    })
    .unwrap();
    assert!(decode_request(&req).is_some());
    assert!(decode_request(&vec![0; MAX_REQUEST + 1]).is_none());
    let mut framed = (req.len() as u16).to_be_bytes().to_vec();
    framed.extend(&req);
    fuzz_decoders(&framed);
    let mut reply = vec![FOUND];
    reply.extend(64u64.to_be_bytes());
    assert_eq!(reply_len(&reply, 64), Some(64));
    assert_eq!(reply_len(&reply, 63), None);
    reply[0] = NOT_HERE;
    assert_eq!(reply_len(&reply, 64), None);
    assert_eq!(reply_len(&[FOUND, 0], 64), None);
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    for n in 0..2000 {
        let bytes: Vec<u8> = (0..n % 300)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed as u8
            })
            .collect();
        fuzz_decoders(&bytes);
    }
}
