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
    async fn get(&self, r: &ResourceId, id: &ContentId) -> Option<Bytes> {
        if let Some(d) = self.1 {
            tokio::time::sleep(d).await;
        }
        self.0.lock().unwrap().get(&(r.clone(), *id)).cloned()
    }
}

struct Liar;

#[async_trait]
impl LocalObjects for Liar {
    async fn get(&self, _: &ResourceId, _: &ContentId) -> Option<Bytes> {
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

#[tokio::test(flavor = "multi_thread")]
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
    let started = std::time::Instant::now();
    let (_, from) = f
        .fetch(&res(), &ContentId::of(b"x"), &[net.key(1), net.key(2)])
        .await
        .unwrap();
    assert_eq!(from, Origin::Peer(net.key(2)));
    assert!(started.elapsed() < Duration::from_secs(3));
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

    #[tokio::test(flavor = "multi_thread")]
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
        let started = std::time::Instant::now();
        assert!(
            f.fetch(&res(), &ContentId::of(b"x"), &[net.key(1)])
                .await
                .is_ok(),
            "an authorized reader is still served"
        );
        assert!(started.elapsed() < Duration::from_secs(1));
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
        async fn get(&self, _: &ResourceId, _: &ContentId) -> Option<Bytes> {
            None
        }
    }

    #[tokio::test(flavor = "multi_thread")]
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
        let started = std::time::Instant::now();
        assert!(
            f.fetch(&res(), &ContentId::of(b"x"), &[net.key(1)])
                .await
                .is_err()
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
