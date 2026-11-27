//! The whole service on 127.0.0.1: the mailbox suite through `mailbox-drop` against the redb
//! store in a temporary directory, restarts, TLS, graceful shutdown, the sweeper and startup
//! refusals.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant};

use baton_core::Timestamp;
use baton_drop::Clock;
use baton_drop_service::{Config, ServiceError, start};
use baton_mailbox::testing::{Harness, mailbox};
use baton_mailbox::{Admission, BoxId, BoxKey, BoxPolicy, Mailbox};
use baton_mailbox_drop::{ClientConfig, connect};
use bytes::Bytes;
use url::Url;
use zeroize::Zeroizing;

const REALM: &str = "drop.example.com";
const TOKEN: &str = "service-operator-token";

struct H {
    now: Arc<AtomicI64>,
    admission: Admission,
}

impl Harness for H {
    fn admission(&self) -> Admission {
        self.admission.clone()
    }
    fn advance(&self, ms: u64) {
        self.now.fetch_add(ms as i64, Ordering::SeqCst);
    }
}

fn manual() -> (Arc<AtomicI64>, Clock) {
    let now = Arc::new(AtomicI64::new(1_800_000_000_000));
    let n = now.clone();
    (now, Arc::new(move || Timestamp(n.load(Ordering::SeqCst))))
}

fn secret(path: &Path, content: &str) {
    std::fs::write(path, content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn config(dir: &Path, extra: &str) -> Config {
    let tokens = dir.join("tokens");
    secret(&tokens, &format!("# operator tokens\n{TOKEN}\n\n"));
    Config::parse(&format!(
        r#"
listen = "127.0.0.1:0"
data_dir = {data:?}
realm = "{REALM}"
[admission]
tokens_file = {tokens:?}
[http]
rate_per_second = 0
{extra}
"#,
        data = dir.join("data"),
    ))
    .unwrap()
}

fn url(addr: std::net::SocketAddr) -> Url {
    Url::parse(&format!("http://{addr}/")).unwrap()
}

fn token() -> Admission {
    Admission::Token(Zeroizing::new(TOKEN.as_bytes().to_vec()))
}

#[tokio::test(flavor = "multi_thread")]
async fn conformance_through_http_on_the_redb_store() {
    let dir = tempfile::tempdir().unwrap();
    let (now, clock) = manual();
    let running = start(&config(dir.path(), ""), clock.clone()).await.unwrap();
    let mb = connect(&url(running.addr), REALM, clock, &ClientConfig::default())
        .await
        .unwrap();
    mailbox(
        Arc::new(mb),
        Arc::new(H {
            now,
            admission: token(),
        }),
    )
    .await;
    running.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn conformance_with_proof_of_work_and_the_salt_survives_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let (now, clock) = manual();
    let mut c = config(dir.path(), "");
    c.admission.work_difficulty = 3;
    c.admission.work_memory_kib = 64;
    let running = start(&c, clock.clone()).await.unwrap();
    let mb = connect(
        &url(running.addr),
        REALM,
        clock.clone(),
        &ClientConfig::default(),
    )
    .await
    .unwrap();
    let salt = mb.info().work.clone().unwrap().salt;
    mailbox(
        Arc::new(mb),
        Arc::new(H {
            now,
            admission: Admission::Work,
        }),
    )
    .await;
    running.stop().await;
    let running = start(&c, clock.clone()).await.unwrap();
    let mb = connect(&url(running.addr), REALM, clock, &ClientConfig::default())
        .await
        .unwrap();
    assert_eq!(mb.info().work.clone().unwrap().salt, salt);
    running.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn messages_survive_a_restart_of_the_service() {
    let dir = tempfile::tempdir().unwrap();
    let (_now, clock) = manual();
    let c = config(dir.path(), "");
    let (reader, writer) = (BoxKey::generate(), BoxKey::generate());
    let id = BoxId::of_reader(&reader.public());
    {
        let running = start(&c, clock.clone()).await.unwrap();
        let mb = connect(
            &url(running.addr),
            REALM,
            clock.clone(),
            &ClientConfig::default(),
        )
        .await
        .unwrap();
        let p = BoxPolicy::new(reader.public(), vec![writer.public()]);
        mb.create(&id, &p, &reader, &token()).await.unwrap();
        mb.put(&id, &writer, Bytes::from_static(b"kept"))
            .await
            .unwrap();
        running.stop().await;
    }
    let running = start(&c, clock.clone()).await.unwrap();
    let mb = connect(&url(running.addr), REALM, clock, &ClientConfig::default())
        .await
        .unwrap();
    let got = mb
        .take(&id, &reader, None, 10, Duration::ZERO)
        .await
        .unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].bytes, Bytes::from_static(b"kept"));
    running.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn serves_tls_with_its_own_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
    let (cert, key) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
    std::fs::write(&cert, ck.cert.pem()).unwrap();
    secret(&key, &ck.signing_key.serialize_pem());
    let extra = format!("[tls]\ncert = {cert:?}\nkey = {key:?}\n");
    let (_now, clock) = manual();
    let running = start(&config(dir.path(), &extra), clock.clone())
        .await
        .unwrap();
    let base = Url::parse(&format!("https://{}/", running.addr)).unwrap();
    let trusted = ClientConfig {
        roots: vec![ck.cert.der().to_vec()],
        ..ClientConfig::default()
    };
    let mb = connect(&base, REALM, clock.clone(), &trusted)
        .await
        .unwrap();
    let (reader, writer) = (BoxKey::generate(), BoxKey::generate());
    let id = BoxId::of_reader(&reader.public());
    let p = BoxPolicy::new(reader.public(), vec![writer.public()]);
    mb.create(&id, &p, &reader, &token()).await.unwrap();
    mb.put(&id, &writer, Bytes::from_static(b"over tls"))
        .await
        .unwrap();
    assert_eq!(
        mb.take(&id, &reader, None, 1, Duration::ZERO)
            .await
            .unwrap()[0]
            .bytes,
        Bytes::from_static(b"over tls")
    );
    assert!(
        connect(&base, REALM, clock.clone(), &ClientConfig::default())
            .await
            .is_err(),
        "an untrusted certificate is refused"
    );
    assert!(
        connect(&url(running.addr), REALM, clock, &ClientConfig::default())
            .await
            .is_err(),
        "plain http to the tls port fails"
    );
    running.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_lets_a_long_poll_finish() {
    let dir = tempfile::tempdir().unwrap();
    let (_now, clock) = manual();
    let running = start(
        &config(dir.path(), "[limits]\nmax_wait_secs = 2\n"),
        clock.clone(),
    )
    .await
    .unwrap();
    let mb = Arc::new(
        connect(&url(running.addr), REALM, clock, &ClientConfig::default())
            .await
            .unwrap(),
    );
    let reader = BoxKey::generate();
    let id = BoxId::of_reader(&reader.public());
    let p = BoxPolicy::new(reader.public(), vec![]);
    mb.create(&id, &p, &reader, &token()).await.unwrap();
    let poll = {
        let mb = mb.clone();
        tokio::spawn(async move { mb.take(&id, &reader, None, 1, Duration::from_secs(2)).await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    tokio::time::timeout(Duration::from_secs(30), running.stop())
        .await
        .expect("stop ends once the poll in flight is answered");
    assert!(
        poll.await.unwrap().unwrap().is_empty(),
        "the poll in flight got its answer"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_sweeper_removes_expired_boxes() {
    let dir = tempfile::tempdir().unwrap();
    let (now, clock) = manual();
    let running = start(&config(dir.path(), "").tap_sweep(), clock.clone())
        .await
        .unwrap();
    let mb = connect(&url(running.addr), REALM, clock, &ClientConfig::default())
        .await
        .unwrap();
    let (reader, writer) = (BoxKey::generate(), BoxKey::generate());
    let id = BoxId::of_reader(&reader.public());
    let mut p = BoxPolicy::new(reader.public(), vec![writer.public()]);
    p.ttl_ms = 60_000;
    mb.create(&id, &p, &reader, &token()).await.unwrap();
    mb.put(&id, &writer, Bytes::from_static(b"old"))
        .await
        .unwrap();
    assert_eq!(running.store.totals().unwrap(), (1, 3));
    now.fetch_add(60_000, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(10);
    while running.store.totals().unwrap() != (0, 0) {
        assert!(Instant::now() < deadline, "the sweeper ran");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    running.stop().await;
}

trait TapSweep {
    fn tap_sweep(self) -> Self;
}

impl TapSweep for Config {
    fn tap_sweep(mut self) -> Self {
        self.sweep_secs = 1;
        self
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn startup_refuses_unsafe_or_empty_configurations() {
    let dir = tempfile::tempdir().unwrap();
    let (_now, clock) = manual();
    let mut c = config(dir.path(), "");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let tokens = c.admission.tokens_file.clone().unwrap();
        std::fs::set_permissions(&tokens, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            start(&c, clock.clone()).await,
            Err(ServiceError::Config(_))
        ));
    }
    c.admission.tokens_file = None;
    assert!(matches!(
        start(&c, clock.clone()).await,
        Err(ServiceError::Config(_))
    ));
    let short = dir.path().join("short");
    secret(&short, "too-short\n");
    c.admission.tokens_file = Some(short);
    assert!(matches!(
        start(&c, clock.clone()).await,
        Err(ServiceError::Config(_))
    ));
    c.admission.tokens_file = None;
    c.admission.work_difficulty = 30;
    assert!(matches!(
        start(&c, clock.clone()).await,
        Err(ServiceError::Config(_))
    ));
    c.admission.work_difficulty = 0;
    c.admission.open = true;
    c.realm = String::new();
    assert!(matches!(
        start(&c, clock).await,
        Err(ServiceError::Config(_))
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&c.data_dir), 0o700);
        assert_eq!(mode(&c.data_dir.join("drop.redb")), 0o600);
    }
}
