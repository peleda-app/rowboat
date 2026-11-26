//! Helpers shared by the HTTP attack tests: a real server on 127.0.0.1 and a raw HTTP/1.1 client.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use baton_core::Timestamp;
use baton_drop::admission::AdmissionConfig;
use baton_drop::wire::{self, Body, Reply, WireAdmission};
use baton_drop::{Clock, DropConfig, DropError, DropService, MemoryDropStore};
use baton_drop_http::{HttpConfig, router, serve};
use baton_mailbox::{BoxId, BoxKey, BoxPolicy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

pub const REALM: &str = "drop.example.com";

pub struct Server {
    pub addr: SocketAddr,
    pub now: Arc<AtomicI64>,
    pub clock: Clock,
    pub service: Arc<DropService>,
    _stop: oneshot::Sender<()>,
}

pub async fn start(edit_drop: impl FnOnce(&mut DropConfig), http: HttpConfig) -> Server {
    let now = Arc::new(AtomicI64::new(1_800_000_000_000));
    let n = now.clone();
    let clock: Clock = Arc::new(move || Timestamp(n.load(Ordering::SeqCst)));
    let mut config = DropConfig::new(REALM, AdmissionConfig::open());
    edit_drop(&mut config);
    let service = Arc::new(
        DropService::new(Arc::new(MemoryDropStore::new()), config, clock.clone()).unwrap(),
    );
    let app = router(service.clone(), http.clone(), clock.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        serve(listener, app, &http, None, async {
            let _ = rx.await;
        })
        .await
    });
    Server {
        addr,
        now,
        clock,
        service,
        _stop: tx,
    }
}

pub fn quick() -> HttpConfig {
    HttpConfig {
        header_timeout: Duration::from_millis(300),
        body_timeout: Duration::from_millis(300),
        rate: None,
        ..HttpConfig::default()
    }
}

/// One HTTP/1.1 exchange on a fresh connection; returns the status and body.
pub async fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    extra: &str,
    body: &[u8],
) -> (u16, Vec<u8>) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "{method} {path} HTTP/1.1\r\nhost: drop.example.com\r\ncontent-length: {}\r\nconnection: close\r\n{extra}\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).await.unwrap();
    s.write_all(body).await.unwrap();
    read_response(&mut s).await
}

pub async fn read_response(s: &mut TcpStream) -> (u16, Vec<u8>) {
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(20), s.read_to_end(&mut raw)).await;
    parse(&raw)
}

pub fn parse(raw: &[u8]) -> (u16, Vec<u8>) {
    let text = String::from_utf8_lossy(raw);
    let status = text
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let body = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| raw[i + 4..].to_vec())
        .unwrap_or_default();
    (status, body)
}

pub struct Fixture {
    pub id: BoxId,
    pub reader: BoxKey,
    pub writer: BoxKey,
}

pub fn sealed(s: &Server, key: &BoxKey, id: &BoxId, body: &Body) -> Vec<u8> {
    wire::seal(REALM, key, id, body, (s.clock)(), wire::nonce())
}

pub async fn call(s: &Server, raw: &[u8]) -> Result<Reply, DropError> {
    let (status, body) = http(s.addr, "POST", "/v1/request", "", raw).await;
    assert_eq!(status, 200);
    wire::decode_reply(&body, 1 << 24).unwrap()
}

pub async fn fixture(s: &Server) -> Fixture {
    let reader = BoxKey::generate();
    let f = Fixture {
        id: BoxId::of_reader(&reader.public()),
        reader,
        writer: BoxKey::generate(),
    };
    let body = Body::Create {
        policy: BoxPolicy {
            max_bytes: 1 << 20,
            max_messages: 1000,
            ttl_ms: 24 * 3600 * 1000,
            ..BoxPolicy::new(f.reader.public(), vec![f.writer.public()])
        },
        admission: WireAdmission::None,
    };
    assert_eq!(
        call(s, &sealed(s, &f.reader, &f.id, &body)).await,
        Ok(Reply::Done)
    );
    f
}

pub fn take(s: &Server, f: &Fixture, wait_ms: u32) -> Vec<u8> {
    sealed(
        s,
        &f.reader,
        &f.id,
        &Body::Take {
            after: None,
            limit: 10,
            wait_ms,
        },
    )
}
