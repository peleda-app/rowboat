use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::body::Bytes as AxumBytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::post;
use bytes::Bytes;
use skein_core::{
    AccountId, Event, EventBody, FencingToken, SCHEMA_VERSION, Seq, TenantId, Timestamp,
};
use skein_keyring::Keyring;
use skein_keyring_local::LocalKeyring;
use skein_storage::Storage;
use skein_storage_memory::MemoryObjects;

use crate::*;

fn t() -> TenantId {
    TenantId::new("acme").unwrap()
}

fn a(id: &str) -> AccountId {
    AccountId::new(id).unwrap()
}

fn loopback() -> WebhookPolicy {
    WebhookPolicy {
        allow_http_loopback: true,
        ..Default::default()
    }
}

struct Setup {
    storage: Storage,
    store: WebhookStore,
}

fn setup() -> Setup {
    let storage = Storage::over(Arc::new(MemoryObjects::new()));
    let keyring: Arc<dyn Keyring> =
        Arc::new(LocalKeyring::from_master([9; 32], storage.control.clone()));
    let store = WebhookStore::new(storage.control.clone(), storage.log.clone(), keyring);
    Setup { storage, store }
}

fn event(account: &str, body: EventBody) -> Event {
    Event {
        v: SCHEMA_VERSION,
        seq: Seq(0),
        at: Timestamp(1_700_000_000_000),
        account: a(account),
        key: String::new(),
        origin: None,
        trace: None,
        body,
    }
}

fn deleted(account: &str, n: u64) -> Event {
    let mut e = event(
        account,
        EventBody::MailboxDeleted {
            mailbox: format!("m{n}"),
        },
    );
    e.key = format!("k{n}");
    e
}

impl Setup {
    async fn append(&self, account: &str, events: Vec<Event>) {
        self.storage
            .log
            .append(&t(), &a(account), FencingToken(1), events)
            .await
            .unwrap();
    }

    async fn append_n(&self, account: &str, from: u64, to: u64) {
        self.append(account, (from..=to).map(|n| deleted(account, n)).collect())
            .await;
    }

    async fn endpoint(&self, url: &str) -> (Endpoint, String) {
        self.endpoint_with(url, None, None).await
    }

    async fn endpoint_with(
        &self,
        url: &str,
        events: Option<Vec<&str>>,
        accounts: Option<Vec<&str>>,
    ) -> (Endpoint, String) {
        self.store
            .create(
                &t(),
                NewEndpoint {
                    url: url.into(),
                    events: events.map(|e| e.into_iter().map(String::from).collect()),
                    accounts: accounts.map(|v| v.into_iter().map(a).collect()),
                },
                &loopback(),
            )
            .await
            .unwrap()
    }

    async fn cursor(&self, endpoint: &str, account: &str) -> Cursor {
        self.store
            .cursor(&t(), &cursor_path(endpoint, &a(account)))
            .await
            .unwrap()
            .map(|(c, _)| c)
            .unwrap_or_default()
    }
}

#[derive(Clone, Debug)]
struct Received {
    headers: HeaderMap,
    body: Bytes,
}

#[derive(Clone)]
struct Receiver {
    addr: SocketAddr,
    status: Arc<AtomicU16>,
    received: Arc<Mutex<Vec<Received>>>,
}

impl Receiver {
    async fn start() -> Self {
        let status = Arc::new(AtomicU16::new(200));
        let received = Arc::new(Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let receiver = Receiver {
            addr,
            status,
            received,
        };
        let app = Router::new()
            .route("/hook", post(record))
            .route("/other", post(record))
            .route("/target", post(record))
            .route(
                "/moved",
                post(|| async {
                    (
                        StatusCode::TEMPORARY_REDIRECT,
                        [(header::LOCATION, "/target")],
                    )
                }),
            )
            .route(
                "/big",
                post(|| async { (StatusCode::OK, vec![b'x'; 1024 * 1024]) }),
            )
            .route(
                "/slow",
                post(|| async {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    StatusCode::OK
                }),
            )
            .with_state(receiver.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        receiver
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    fn received(&self) -> Vec<Received> {
        self.received.lock().unwrap().clone()
    }
}

async fn record(
    State(r): State<Receiver>,
    headers: HeaderMap,
    body: AxumBytes,
) -> impl IntoResponse {
    r.received.lock().unwrap().push(Received { headers, body });
    StatusCode::from_u16(r.status.load(Ordering::SeqCst)).unwrap()
}

fn header<'a>(h: &'a HeaderMap, name: &str) -> &'a str {
    h.get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
}

fn batch(r: &Received) -> Batch {
    serde_json::from_slice(&r.body).unwrap()
}

fn seqs(b: &Batch) -> Vec<u64> {
    b.events.iter().map(|e| e.seq.0).collect()
}

fn http() -> Arc<dyn Transport> {
    Arc::new(HttpTransport::new(loopback()).unwrap())
}

struct FakeClock(AtomicI64);

impl FakeClock {
    fn at(ms: i64) -> Arc<Self> {
        Arc::new(Self(AtomicI64::new(ms)))
    }

    fn advance_secs(&self, s: i64) {
        self.0.fetch_add(s * 1000, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Timestamp {
        Timestamp(self.0.load(Ordering::SeqCst))
    }
}

/// Answers per URL from a script; the last answer repeats.
#[derive(Default)]
struct FakeTransport {
    answers: Mutex<std::collections::HashMap<String, Vec<Result<u16, SendError>>>>,
    calls: Mutex<Vec<(String, Bytes)>>,
}

impl FakeTransport {
    fn script(&self, url: &str, answers: Vec<Result<u16, SendError>>) {
        self.answers.lock().unwrap().insert(url.into(), answers);
    }

    fn calls(&self, url: &str) -> Vec<Batch> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(u, _)| u == url)
            .map(|(_, b)| serde_json::from_slice(b).unwrap())
            .collect()
    }
}

#[async_trait]
impl Transport for FakeTransport {
    async fn post(
        &self,
        url: &str,
        _headers: &[(&'static str, String)],
        body: Bytes,
    ) -> Result<u16, SendError> {
        self.calls.lock().unwrap().push((url.into(), body));
        let mut answers = self.answers.lock().unwrap();
        let script = answers.entry(url.into()).or_insert_with(|| vec![Ok(200)]);
        if script.len() > 1 {
            script.remove(0)
        } else {
            script[0]
        }
    }
}

const A: &str = "https://a.example.com/hook";
const B: &str = "https://b.example.com/hook";

async fn fake_endpoint(s: &Setup, url: &str) -> Endpoint {
    let (mut endpoint, _) = s.endpoint("http://127.0.0.1:9/placeholder").await;
    endpoint.url = url.into();
    s.storage
        .control
        .put(
            &t(),
            &endpoint_path(&endpoint.id),
            skein_storage::encode_record(&endpoint).unwrap(),
            skein_storage::Expect::Any,
        )
        .await
        .unwrap();
    endpoint
}

#[tokio::test]
async fn delivers_in_log_order_in_signed_batches() {
    let s = setup();
    let receiver = Receiver::start().await;
    s.append_n("box", 1, 5).await;
    let (endpoint, secret) = s.endpoint(&receiver.url("/hook")).await;
    assert!(secret.starts_with(SECRET_PREFIX));
    s.append_n("box", 6, 255).await;

    let delivery = WebhookDelivery::new(s.store.clone(), http());
    let report = delivery.deliver(&t(), &a("box")).await.unwrap();
    assert_eq!((report.batches, report.events), (3, 250));
    let got = receiver.received();
    assert_eq!(got.len(), 3);
    let mut all = Vec::new();
    for r in &got {
        let b = batch(r);
        assert_eq!(b.endpoint, endpoint.id);
        assert_eq!(b.tenant, t());
        assert_eq!(b.account, Some(a("box")));
        assert!(b.compacted.is_none() && !b.ping);
        assert!(b.events.len() <= BATCH_SIZE);
        all.extend(seqs(&b));
        let ts = header(&r.headers, "skein-timestamp");
        let now = Timestamp::now().0 / 1000;
        verify(
            &secret,
            ts,
            &r.body,
            header(&r.headers, "skein-signature"),
            now,
        )
        .unwrap();
        assert!(!header(&r.headers, "skein-webhook-id").is_empty());
        assert!(header(&r.headers, "content-type").starts_with("application/json"));
        assert!(r.headers.get("cookie").is_none());
        assert!(r.headers.get("authorization").is_none());
    }
    assert_eq!(
        all,
        (6..=255).collect::<Vec<_>>(),
        "new events only, in order"
    );
    assert_eq!(s.cursor(&endpoint.id, "box").await.seq, 255);

    let again = delivery.deliver(&t(), &a("box")).await.unwrap();
    assert_eq!(again, DeliveryReport::default(), "nothing new");
    s.append_n("box", 256, 257).await;
    delivery.deliver(&t(), &a("box")).await.unwrap();
    assert_eq!(seqs(&batch(&receiver.received()[3])), vec![256, 257]);

    s.append_n("late", 1, 2).await;
    delivery.deliver(&t(), &a("late")).await.unwrap();
    let late = batch(receiver.received().last().unwrap());
    assert_eq!(
        (late.account.clone(), seqs(&late)),
        (Some(a("late")), vec![1, 2]),
        "accounts without a log at creation start at the beginning"
    );
}

#[tokio::test]
async fn retries_keep_the_batch_id_and_back_off_until_paused() {
    let s = setup();
    let transport = Arc::new(FakeTransport::default());
    let endpoint = fake_endpoint(&s, A).await;
    s.append_n("box", 1, 3).await;
    transport.script(A, vec![Ok(500)]);
    let clock = FakeClock::at(1_000_000_000_000);
    let delivery =
        WebhookDelivery::new(s.store.clone(), transport.clone()).with_clock(clock.clone());

    let r = delivery.deliver(&t(), &a("box")).await.unwrap();
    assert_eq!(r.failures, 1);
    let c = s.cursor(&endpoint.id, "box").await;
    assert_eq!(
        (c.seq, c.failures, c.last_error.as_deref(), c.last_status),
        (0, 1, Some("http_status"), Some(500))
    );
    assert_eq!(c.next_attempt_at, Some(clock.now().plus_ms(10_000)));

    clock.advance_secs(5);
    let r = delivery.deliver(&t(), &a("box")).await.unwrap();
    assert_eq!(
        (r.waiting, transport.calls(A).len()),
        (1, 1),
        "still backing off"
    );

    let mut expected = 10;
    for failures in 2..=9u32 {
        clock.advance_secs(expected);
        delivery.deliver(&t(), &a("box")).await.unwrap();
        let c = s.cursor(&endpoint.id, "box").await;
        assert_eq!(c.failures, failures);
        expected = backoff_secs(failures) as i64;
        assert_eq!(
            c.next_attempt_at,
            Some(clock.now().plus_ms(expected * 1000))
        );
    }
    assert_eq!(expected, 2560);
    assert_eq!(backoff_secs(10), 3600);
    assert_eq!(backoff_secs(100), 3600);
    let calls = transport.calls(A);
    assert_eq!(calls.len(), 9);
    assert!(calls.iter().all(|b| seqs(b) == vec![1, 2, 3]));

    transport.script(A, vec![Err(SendError::Timeout)]);
    clock.advance_secs(3 * 24 * 3600);
    delivery.deliver(&t(), &a("box")).await.unwrap();
    let (paused, _) = s.store.get(&t(), &endpoint.id).await.unwrap().unwrap();
    assert!(paused.paused);
    assert!(
        paused
            .paused_reason
            .as_deref()
            .is_some_and(|r| r.contains("box") && r.contains("timeout")),
        "{:?}",
        paused.paused_reason
    );
    clock.advance_secs(7200);
    delivery.deliver(&t(), &a("box")).await.unwrap();
    assert_eq!(transport.calls(A).len(), 10, "paused endpoints get nothing");

    transport.script(A, vec![Ok(204)]);
    let resumed = s
        .store
        .update(
            &t(),
            &endpoint.id,
            EndpointPatch {
                paused: Some(false),
                ..Default::default()
            },
            &loopback(),
        )
        .await
        .unwrap();
    assert!(!resumed.paused && resumed.paused_reason.is_none());
    let c = s.cursor(&endpoint.id, "box").await;
    assert_eq!((c.failures, c.next_attempt_at), (0, None));
    delivery.deliver(&t(), &a("box")).await.unwrap();
    let c = s.cursor(&endpoint.id, "box").await;
    assert_eq!((c.seq, c.failures, c.last_status), (3, 0, Some(204)));
}

#[tokio::test]
async fn retried_batches_carry_the_same_id() {
    let s = setup();
    let receiver = Receiver::start().await;
    let clock = FakeClock::at(Timestamp::now().0);
    s.endpoint(&receiver.url("/hook")).await;
    s.append_n("box", 1, 2).await;
    receiver.status.store(503, Ordering::SeqCst);
    let delivery = WebhookDelivery::new(s.store.clone(), http()).with_clock(clock.clone());
    delivery.deliver(&t(), &a("box")).await.unwrap();
    receiver.status.store(200, Ordering::SeqCst);
    clock.advance_secs(10);
    delivery.deliver(&t(), &a("box")).await.unwrap();
    let got = receiver.received();
    assert_eq!(got.len(), 2);
    assert_eq!(
        header(&got[0].headers, "skein-webhook-id"),
        header(&got[1].headers, "skein-webhook-id")
    );
    assert_eq!(got[0].body, got[1].body);
}

#[tokio::test]
async fn a_failing_endpoint_does_not_hold_up_others() {
    let s = setup();
    let transport = Arc::new(FakeTransport::default());
    let failing = fake_endpoint(&s, A).await;
    let healthy = fake_endpoint(&s, B).await;
    transport.script(A, vec![Err(SendError::Unreachable)]);
    s.append_n("box", 1, 4).await;
    let delivery = WebhookDelivery::new(s.store.clone(), transport.clone());
    let r = delivery.deliver(&t(), &a("box")).await.unwrap();
    assert_eq!((r.batches, r.failures), (1, 1));
    assert_eq!(s.cursor(&healthy.id, "box").await.seq, 4);
    let c = s.cursor(&failing.id, "box").await;
    assert_eq!((c.seq, c.last_error.as_deref()), (0, Some("unreachable")));
}

#[tokio::test]
async fn compacted_logs_get_one_notice_then_the_rest() {
    let s = setup();
    let transport = Arc::new(FakeTransport::default());
    let endpoint = fake_endpoint(&s, A).await;
    s.append_n("box", 1, 5).await;
    let log = &s.storage.log;
    let mut snap = skein_storage::Snapshot::empty(a("box"));
    for e in log.read(&t(), &a("box"), Seq(1), 10).await.unwrap() {
        snap.apply(&e);
    }
    log.put_snapshot(&t(), &a("box"), &snap).await.unwrap();
    log.compact(&t(), &a("box"), Seq(6)).await.unwrap();
    s.append_n("box", 6, 8).await;

    let delivery = WebhookDelivery::new(s.store.clone(), transport.clone());
    delivery.deliver(&t(), &a("box")).await.unwrap();
    let calls = transport.calls(A);
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].compacted, Some(Compacted { first: 6 }));
    assert!(calls[0].events.is_empty());
    assert_eq!(seqs(&calls[1]), vec![6, 7, 8]);
    assert_eq!(s.cursor(&endpoint.id, "box").await.seq, 8);
}

#[tokio::test]
async fn filters_pick_event_types_and_accounts() {
    let s = setup();
    let receiver = Receiver::start().await;
    let (only_sync, _) = s
        .endpoint_with(
            &receiver.url("/hook"),
            Some(vec!["first_sync_completed"]),
            Some(vec!["box"]),
        )
        .await;
    s.append_n("box", 1, 3).await;
    s.append("box", vec![event("box", EventBody::FirstSyncCompleted)])
        .await;
    s.append_n("box", 5, 6).await;
    s.append_n("other", 1, 3).await;
    let delivery = WebhookDelivery::new(s.store.clone(), http());
    delivery.deliver(&t(), &a("box")).await.unwrap();
    delivery.deliver(&t(), &a("other")).await.unwrap();
    let got = receiver.received();
    assert_eq!(got.len(), 1);
    assert_eq!(seqs(&batch(&got[0])), vec![4]);
    assert_eq!(
        s.cursor(&only_sync.id, "box").await.seq,
        6,
        "filtered events still move the cursor"
    );
    assert!(
        s.store
            .cursor(&t(), &cursor_path(&only_sync.id, &a("other")))
            .await
            .unwrap()
            .is_none()
    );

    s.append_n("box", 7, 9).await;
    delivery.deliver(&t(), &a("box")).await.unwrap();
    assert_eq!(
        receiver.received().len(),
        1,
        "nothing matching, nothing sent"
    );
    assert_eq!(s.cursor(&only_sync.id, "box").await.seq, 9);

    for (events, accounts) in [
        (Some(vec!["message_exploded"]), None),
        (Some(vec![]), None),
        (None, Some(vec![])),
    ] {
        let r = s
            .store
            .create(
                &t(),
                NewEndpoint {
                    url: receiver.url("/hook"),
                    events: events.map(|e| e.into_iter().map(String::from).collect()),
                    accounts: accounts.map(|v: Vec<&str>| v.into_iter().map(a).collect()),
                },
                &loopback(),
            )
            .await;
        assert!(matches!(r, Err(WebhookError::Invalid(_))));
    }
}

#[tokio::test]
async fn redirects_are_answers_not_followed() {
    let s = setup();
    let receiver = Receiver::start().await;
    let (endpoint, _) = s.endpoint(&receiver.url("/moved")).await;
    s.append_n("box", 1, 1).await;
    let delivery = WebhookDelivery::new(s.store.clone(), http());
    let r = delivery.deliver(&t(), &a("box")).await.unwrap();
    assert_eq!(r.failures, 1);
    assert!(receiver.received().is_empty(), "the target was not asked");
    let c = s.cursor(&endpoint.id, "box").await;
    assert_eq!((c.seq, c.last_status), (0, Some(307)));
}

#[tokio::test]
async fn http_transport_limits_answers_and_time() {
    let receiver = Receiver::start().await;
    let transport = HttpTransport::new(WebhookPolicy {
        timeout: Duration::from_millis(300),
        ..loopback()
    })
    .unwrap();
    assert_eq!(
        transport
            .post(&receiver.url("/big"), &[], Bytes::from_static(b"{}"))
            .await,
        Ok(200)
    );
    assert_eq!(
        transport
            .post(&receiver.url("/slow"), &[], Bytes::from_static(b"{}"))
            .await,
        Err(SendError::Timeout)
    );
    assert_eq!(
        transport
            .post("http://127.0.0.1:1/hook", &[], Bytes::from_static(b"{}"))
            .await,
        Err(SendError::Unreachable)
    );
}

#[tokio::test]
async fn ssrf_rules_hold_at_creation_and_on_send() {
    let s = setup();
    let strict = WebhookPolicy::default();
    let transport = HttpTransport::new(strict.clone()).unwrap();
    let receiver = Receiver::start().await;
    let port = receiver.addr.port();
    for (url, kind) in [
        (receiver.url("/hook"), "invalid_url"),
        (format!("https://127.0.0.1:{port}/hook"), "address_refused"),
        (format!("https://localhost:{port}/hook"), "address_refused"),
        (format!("https://[::1]:{port}/hook"), "address_refused"),
        (
            format!("https://[::ffff:127.0.0.1]:{port}/hook"),
            "address_refused",
        ),
        ("https://10.1.2.3/hook".into(), "address_refused"),
        ("https://192.168.0.10/hook".into(), "address_refused"),
        ("https://169.254.169.254/latest".into(), "address_refused"),
        ("https://100.100.0.1/hook".into(), "address_refused"),
        ("https://[fd00::1]/hook".into(), "address_refused"),
        ("https://[fe80::1]/hook".into(), "address_refused"),
        ("https://0.0.0.0/hook".into(), "address_refused"),
        ("https://user:pw@a.example.com/hook".into(), "invalid_url"),
    ] {
        let sent = transport.post(&url, &[], Bytes::new()).await;
        assert_eq!(sent.map_err(|e| e.kind()), Err(kind), "send {url}");
        let created = s
            .store
            .create(
                &t(),
                NewEndpoint {
                    url: url.clone(),
                    events: None,
                    accounts: None,
                },
                &strict,
            )
            .await;
        match created {
            Err(WebhookError::Url(e)) => assert_eq!(e.kind(), kind, "create {url}"),
            other => panic!("create {url}: {other:?}"),
        }
    }
    assert!(receiver.received().is_empty());
    assert!(s.store.list(&t()).await.unwrap().is_empty());
}

#[tokio::test]
async fn secrets_are_sealed_rotated_and_used_for_pings() {
    let s = setup();
    let receiver = Receiver::start().await;
    let (endpoint, secret) = s.endpoint(&receiver.url("/hook")).await;
    let (raw, _) = s
        .storage
        .control
        .get(&t(), &endpoint_path(&endpoint.id))
        .await
        .unwrap()
        .unwrap();
    let raw = String::from_utf8_lossy(&raw).into_owned();
    assert!(!raw.contains(&secret), "the secret is sealed");
    assert!(!raw.contains(&secret[SECRET_PREFIX.len()..]));
    assert_eq!(s.store.secret(&t(), &endpoint).await.unwrap(), secret);
    assert!(valid_id(&endpoint.id));

    let status = s.store.ping(&t(), &endpoint.id, &*http()).await.unwrap();
    assert_eq!(status, Ok(200));
    let rotated = s.store.rotate(&t(), &endpoint.id).await.unwrap();
    assert_ne!(rotated, secret);
    s.store
        .ping(&t(), &endpoint.id, &*http())
        .await
        .unwrap()
        .unwrap();
    let got = receiver.received();
    assert_eq!(got.len(), 2);
    let now = Timestamp::now().0 / 1000;
    for (r, key, other) in [(&got[0], &secret, &rotated), (&got[1], &rotated, &secret)] {
        let b = batch(r);
        assert!(b.ping && b.events.is_empty() && b.account.is_none());
        let ts = header(&r.headers, "skein-timestamp");
        let sig = header(&r.headers, "skein-signature");
        assert_eq!(verify(key, ts, &r.body, sig, now), Ok(()));
        assert_eq!(
            verify(other, ts, &r.body, sig, now),
            Err(VerifyError::Mismatch)
        );
    }
    assert!(matches!(
        s.store.rotate(&t(), "01hzzzzzzzzzzzzzzzzzzzzzzz").await,
        Err(WebhookError::NotFound)
    ));
}

#[tokio::test]
async fn deleting_an_endpoint_removes_its_cursors() {
    let s = setup();
    s.append_n("box", 1, 2).await;
    s.append_n("other", 1, 2).await;
    let (endpoint, _) = s.endpoint("http://127.0.0.1:9/hook").await;
    let (kept, _) = s.endpoint("http://127.0.0.1:9/kept").await;
    let states = s.store.deliveries(&t(), &endpoint.id).await.unwrap();
    assert_eq!(
        states
            .iter()
            .map(|d| (d.account.as_str(), d.cursor.seq))
            .collect::<Vec<_>>(),
        vec![("box", 2), ("other", 2)],
        "new endpoints start at the heads"
    );
    assert!(s.store.delete(&t(), &endpoint.id).await.unwrap());
    assert!(!s.store.delete(&t(), &endpoint.id).await.unwrap());
    assert!(s.store.get(&t(), &endpoint.id).await.unwrap().is_none());
    assert!(
        s.store
            .deliveries(&t(), &endpoint.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(s.store.deliveries(&t(), &kept.id).await.unwrap().len(), 2);
    assert_eq!(s.store.list(&t()).await.unwrap().len(), 1);
    assert!(s.store.get(&t(), "../etc").await.unwrap().is_none());
}

#[tokio::test]
async fn updates_check_addresses_and_filters() {
    let s = setup();
    let (endpoint, _) = s.endpoint("http://127.0.0.1:9/hook").await;
    let updated = s
        .store
        .update(
            &t(),
            &endpoint.id,
            EndpointPatch {
                url: Some("http://127.0.0.1:9/new".into()),
                events: Some(Some(vec!["message_added".into()])),
                accounts: Some(Some(vec![a("box")])),
                paused: Some(true),
            },
            &loopback(),
        )
        .await
        .unwrap();
    assert_eq!(updated.url, "http://127.0.0.1:9/new");
    assert!(updated.paused);
    assert_eq!(updated.events, Some(vec!["message_added".into()]));
    let cleared = s
        .store
        .update(
            &t(),
            &endpoint.id,
            EndpointPatch {
                events: Some(None),
                ..Default::default()
            },
            &loopback(),
        )
        .await
        .unwrap();
    assert_eq!(cleared.events, None);
    assert_eq!(cleared.accounts, Some(vec![a("box")]));
    assert!(matches!(
        s.store
            .update(
                &t(),
                &endpoint.id,
                EndpointPatch {
                    url: Some("https://10.0.0.1/".into()),
                    ..Default::default()
                },
                &WebhookPolicy::default(),
            )
            .await,
        Err(WebhookError::Url(SendError::AddressRefused(_)))
    ));
}

#[tokio::test]
async fn the_engine_observer_delivers() {
    use skein_engine::AccountObserver;
    let s = setup();
    let transport = Arc::new(FakeTransport::default());
    fake_endpoint(&s, A).await;
    s.append_n("box", 1, 2).await;
    let delivery = WebhookDelivery::new(s.store.clone(), transport.clone());
    delivery.after_run(&t(), &a("box")).await.unwrap();
    assert_eq!(seqs(&transport.calls(A)[0]), vec![1, 2]);
}
