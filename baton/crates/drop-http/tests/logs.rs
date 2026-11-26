//! Logs of a real `drop-http` server under normal use and attacks carry no box ids, keys,
//! content or client addresses. Alone in its binary, so no other test races the subscriber.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use baton_drop::DropError;
use baton_drop::wire::{Body, Reply};
use baton_drop_http::{HttpConfig, RateLimit};
use baton_mailbox::BoxKey;
use common::*;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn logs_carry_no_box_ids_keys_or_addresses() {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(capture.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (id, keys) = rt.block_on(async {
        let s = start(
            |c| c.max_wait = Duration::from_millis(100),
            HttpConfig {
                rate: Some(RateLimit {
                    per_second: 1,
                    burst: 20,
                    in_flight: 16,
                    polls: 4,
                    max_tracked: 1024,
                }),
                ..quick()
            },
        )
        .await;
        let f = fixture(&s).await;
        let put = sealed(
            &s,
            &f.writer,
            &f.id,
            &Body::Put {
                bytes: bytes::Bytes::from_static(b"secret-content"),
            },
        );
        assert!(matches!(call(&s, &put).await, Ok(Reply::Stored(_))));
        assert_eq!(call(&s, &put).await, Err(DropError::Replayed));
        let stranger = BoxKey::generate();
        let denied = sealed(&s, &stranger, &f.id, &Body::Delete);
        assert_eq!(call(&s, &denied).await, Err(DropError::Denied));
        let _ = call(&s, &take(&s, &f, 50)).await;
        let _ = call(&s, b"garbage").await;
        let mut slow = TcpStream::connect(s.addr).await.unwrap();
        slow.write_all(b"POST /v1/request HTTP/1.1\r\n")
            .await
            .unwrap();
        let _ = read_response(&mut slow).await;
        for _ in 0..30 {
            let _ = http(s.addr, "GET", "/v1/info", "", b"").await;
        }
        (
            f.id,
            [f.reader.public(), f.writer.public(), stranger.public()],
        )
    });
    drop(rt);
    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    let mut forbidden = vec![
        "127.0.0.1".to_owned(),
        "secret-content".to_owned(),
        id.to_string(),
        format!("{:?}", id),
        hex(id.as_bytes()),
    ];
    for k in keys {
        forbidden.push(format!("{k:?}"));
        forbidden.push(hex(&k.to_bytes()));
    }
    assert!(
        logs.contains("connection ended"),
        "the test saw logging: {logs}"
    );
    for f in forbidden {
        assert!(!logs.contains(&f), "logs contain {f}:\n{logs}");
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
