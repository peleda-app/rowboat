//! The mailbox suite and transport attacks against a real `drop-http` server on 127.0.0.1.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use baton_core::Timestamp;
use baton_drop::admission::{AdmissionConfig, WorkParams};
use baton_drop::{Clock, DropConfig, DropService, MemoryDropStore};
use baton_drop_http::{HttpConfig, router, serve};
use baton_mailbox::testing::{Harness, mailbox};
use baton_mailbox::{Admission, BoxId, BoxKey, BoxPolicy, Mailbox, MailboxError};
use baton_mailbox_drop::{ClientConfig, connect};
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use url::Url;
use zeroize::Zeroizing;

const REALM: &str = "drop.example.com";
const TOKEN: &[u8] = b"http-operator-token";

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

struct Server {
    url: Url,
    _stop: oneshot::Sender<()>,
}

async fn start(admission: AdmissionConfig, clock: Clock) -> Server {
    let service = DropService::new(
        Arc::new(MemoryDropStore::new()),
        DropConfig::new(REALM, admission),
        clock.clone(),
    )
    .unwrap();
    let config = HttpConfig {
        rate: None,
        ..HttpConfig::default()
    };
    let app = router(Arc::new(service), config.clone(), clock);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        serve(listener, app, &config, None, async {
            let _ = rx.await;
        })
        .await
    });
    Server {
        url: Url::parse(&format!("http://{addr}/")).unwrap(),
        _stop: tx,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn conformance_over_http_with_token() {
    let (now, clock) = manual();
    let s = start(
        AdmissionConfig::closed().with_token(TOKEN).unwrap(),
        clock.clone(),
    )
    .await;
    let mb = connect(&s.url, REALM, clock, &ClientConfig::default())
        .await
        .unwrap();
    let h = H {
        now,
        admission: Admission::Token(Zeroizing::new(TOKEN.to_vec())),
    };
    mailbox(Arc::new(mb), Arc::new(h)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn conformance_over_http_with_proof_of_work() {
    let (now, clock) = manual();
    let work = WorkParams::generate(3, 64, 1).unwrap();
    let s = start(
        AdmissionConfig::closed().with_work(work).unwrap(),
        clock.clone(),
    )
    .await;
    let mb = connect(&s.url, REALM, clock, &ClientConfig::default())
        .await
        .unwrap();
    let h = H {
        now,
        admission: Admission::Work,
    };
    mailbox(Arc::new(mb), Arc::new(h)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_realm_is_refused_at_connect() {
    let (_now, clock) = manual();
    let s = start(AdmissionConfig::open(), clock.clone()).await;
    assert!(matches!(
        connect(&s.url, "other.example.com", clock, &ClientConfig::default()).await,
        Err(MailboxError::Rejected(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dead_server_is_unavailable() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let (_now, clock) = manual();
    let url = Url::parse(&format!("http://{addr}/")).unwrap();
    assert!(matches!(
        connect(&url, REALM, clock, &ClientConfig::default()).await,
        Err(MailboxError::Unavailable(_))
    ));
}

/// A server that answers every request with `status` and `body` (raw HTTP/1.1).
async fn liar(status: u16, body: Vec<u8>, declare_length: bool) -> Url {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let body = Arc::new(body);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                let _ = s.read(&mut buf).await;
                let head = if declare_length {
                    format!(
                        "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    )
                } else {
                    format!("HTTP/1.1 {status} X\r\nconnection: close\r\n\r\n")
                };
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(&body).await;
                let _ = s.shutdown().await;
            });
        }
    });
    Url::parse(&format!("http://{addr}/")).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_and_garbage_info_is_refused() {
    let (_now, clock) = manual();
    for declare in [true, false] {
        let url = liar(200, vec![7u8; 2 * 1024 * 1024], declare).await;
        assert!(matches!(
            connect(&url, REALM, clock.clone(), &ClientConfig::default()).await,
            Err(MailboxError::Unavailable(_))
        ));
    }
    let url = liar(200, b"not a service info".to_vec(), true).await;
    assert!(matches!(
        connect(&url, REALM, clock.clone(), &ClientConfig::default()).await,
        Err(MailboxError::Unavailable(_))
    ));
    let url = liar(302, Vec::new(), true).await;
    assert!(matches!(
        connect(&url, REALM, clock.clone(), &ClientConfig::default()).await,
        Err(MailboxError::Unavailable(_))
    ));
    let url = liar(429, Vec::new(), true).await;
    assert!(matches!(
        connect(&url, REALM, clock.clone(), &ClientConfig::default()).await,
        Err(MailboxError::Busy)
    ));
    let url = liar(504, Vec::new(), true).await;
    assert!(
        matches!(
            connect(&url, REALM, clock, &ClientConfig::default()).await,
            Err(MailboxError::Unavailable(_))
        ),
        "a deadline whose outcome is unknown is never reported as busy (never reached)"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_that_stops_answering_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = listener.accept().await {
            held.push(s);
        }
    });
    let (_now, clock) = manual();
    let config = ClientConfig {
        margin: Duration::from_millis(300),
        ..ClientConfig::default()
    };
    let url = Url::parse(&format!("http://{addr}/")).unwrap();
    let r = tokio::time::timeout(
        Duration::from_secs(10),
        connect(&url, REALM, clock, &config),
    )
    .await
    .expect("the client's own timeout fires");
    assert!(matches!(r, Err(MailboxError::Unavailable(_))));
}

#[tokio::test(flavor = "multi_thread")]
async fn messages_survive_between_clients() {
    let (_now, clock) = manual();
    let s = start(AdmissionConfig::open(), clock.clone()).await;
    let a = connect(&s.url, REALM, clock.clone(), &ClientConfig::default())
        .await
        .unwrap();
    let b = connect(&s.url, REALM, clock, &ClientConfig::default())
        .await
        .unwrap();
    let (reader, writer) = (BoxKey::generate(), BoxKey::generate());
    let id = BoxId::of_reader(&reader.public());
    let p = BoxPolicy {
        max_bytes: 1 << 20,
        max_messages: 1000,
        ttl_ms: 24 * 3600 * 1000,
        ..BoxPolicy::new(reader.public(), vec![writer.public()])
    };
    a.create(&id, &p, &reader, &Admission::None).await.unwrap();
    let max = a.limits().max_message;
    b.put(&id, &writer, Bytes::from(vec![1u8; max]))
        .await
        .unwrap();
    assert!(matches!(
        b.put(&id, &writer, Bytes::from(vec![1u8; max + 1])).await,
        Err(MailboxError::TooLarge)
    ));
    let got = a
        .take(&id, &reader, None, 10, Duration::ZERO)
        .await
        .unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].bytes.len(), max);
}
