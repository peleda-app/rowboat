//! Attacks on the HTTP layer of a real `drop-http` server on 127.0.0.1: oversized and slow
//! bodies, slow headers, rate and concurrency limits, long-poll caps and malformed requests.

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use baton_drop::DropError;
use baton_drop::wire::{Body, Reply};
use baton_drop_http::{ClientIp, HttpConfig, RateLimit};
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const HANG: Duration = Duration::from_secs(30);

#[tokio::test(flavor = "multi_thread")]
async fn oversized_bodies_are_refused_and_the_server_keeps_serving() {
    let s = start(|_| {}, quick()).await;
    let max = s.service.max_request();
    let (status, _) = http(s.addr, "POST", "/v1/request", "", &vec![0u8; max + 1]).await;
    assert_eq!(status, 413);

    let mut c = TcpStream::connect(s.addr).await.unwrap();
    c.write_all(b"POST /v1/request HTTP/1.1\r\nhost: x\r\ncontent-length: 999999999\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(
        read_response(&mut c).await.0,
        413,
        "declared length alone is refused"
    );

    let mut c = TcpStream::connect(s.addr).await.unwrap();
    c.write_all(b"POST /v1/request HTTP/1.1\r\nhost: x\r\ntransfer-encoding: chunked\r\n\r\n")
        .await
        .unwrap();
    let chunk = vec![b'a'; 64 * 1024];
    for _ in 0..(max / chunk.len() + 2) {
        let mut piece = format!("{:x}\r\n", chunk.len()).into_bytes();
        piece.extend_from_slice(&chunk);
        piece.extend_from_slice(b"\r\n");
        if c.write_all(&piece).await.is_err() {
            break;
        }
    }
    assert_eq!(
        read_response(&mut c).await.0,
        413,
        "chunked bodies are cut at the limit"
    );

    let f = fixture(&s).await;
    assert!(matches!(call(&s, &take(&s, &f, 0)).await, Ok(Reply::Messages(m)) if m.is_empty()));
}

async fn slow_header_clients(s: &Server, n: usize) -> Vec<TcpStream> {
    let mut slow = Vec::new();
    for _ in 0..n {
        let mut c = TcpStream::connect(s.addr).await.unwrap();
        c.write_all(b"POST /v1/request HTTP/1.1\r\nhost: drop.exa")
            .await
            .unwrap();
        slow.push(c);
    }
    slow
}

fn still_open(c: &TcpStream) -> bool {
    let mut buf = [0u8; 1];
    matches!(c.try_read(&mut buf), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
}

async fn closed_by_server(c: &mut TcpStream) -> bool {
    let mut raw = Vec::new();
    tokio::time::timeout(HANG, c.read_to_end(&mut raw))
        .await
        .is_ok()
}

#[tokio::test(flavor = "multi_thread")]
async fn slow_headers_are_cut_off_and_do_not_block_others() {
    let patient = start(
        |_| {},
        HttpConfig {
            max_connections: 64,
            header_timeout: Duration::from_secs(600),
            ..quick()
        },
    )
    .await;
    let slow = slow_header_clients(&patient, 40).await;
    let (status, _) = tokio::time::timeout(HANG, http(patient.addr, "GET", "/v1/info", "", b""))
        .await
        .expect("served without waiting for the slow clients");
    assert_eq!(status, 200);
    assert!(
        slow.iter().all(still_open),
        "served while every slow client still holds its connection"
    );

    let s = start(
        |_| {},
        HttpConfig {
            max_connections: 64,
            ..quick()
        },
    )
    .await;
    for mut c in slow_header_clients(&s, 40).await {
        assert!(
            closed_by_server(&mut c).await,
            "the server closes a connection that never finishes its headers"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn slow_clients_filling_every_connection_are_freed() {
    let s = start(
        |_| {},
        HttpConfig {
            max_connections: 8,
            ..quick()
        },
    )
    .await;
    let mut slow = Vec::new();
    for _ in 0..8 {
        let mut c = TcpStream::connect(s.addr).await.unwrap();
        c.write_all(b"GET /v1/in").await.unwrap();
        slow.push(c);
    }
    let (status, _) = tokio::time::timeout(HANG, http(s.addr, "GET", "/v1/info", "", b""))
        .await
        .expect("a slot frees up once the header timeout fires");
    assert_eq!(status, 200);
    for mut c in slow {
        assert!(
            closed_by_server(&mut c).await,
            "the slots were freed by cutting the slow clients"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn slow_bodies_time_out_and_do_not_block_others() {
    let s = start(|_| {}, quick()).await;
    let mut c = TcpStream::connect(s.addr).await.unwrap();
    c.write_all(b"POST /v1/request HTTP/1.1\r\nhost: x\r\ncontent-length: 100\r\n\r\n0123456789")
        .await
        .unwrap();
    let f = fixture(&s).await;
    assert!(matches!(
        call(&s, &take(&s, &f, 0)).await,
        Ok(Reply::Messages(_))
    ));
    let (status, _) = tokio::time::timeout(HANG, read_response(&mut c))
        .await
        .expect("the slow body is cut off");
    assert_eq!(status, 408);
}

#[tokio::test(flavor = "multi_thread")]
async fn clients_are_rate_limited_and_recover_with_time() {
    let s = start(
        |_| {},
        HttpConfig {
            rate: Some(RateLimit {
                per_second: 1,
                burst: 3,
                in_flight: 16,
                polls: 4,
                max_tracked: 1024,
            }),
            ..quick()
        },
    )
    .await;
    for _ in 0..3 {
        assert_eq!(http(s.addr, "GET", "/v1/info", "", b"").await.0, 200);
    }
    assert_eq!(http(s.addr, "GET", "/v1/info", "", b"").await.0, 429);
    assert_eq!(http(s.addr, "POST", "/v1/request", "", b"x").await.0, 429);
    s.now.fetch_add(1000, Ordering::SeqCst);
    assert_eq!(http(s.addr, "GET", "/v1/info", "", b"").await.0, 200);
    assert_eq!(http(s.addr, "GET", "/v1/info", "", b"").await.0, 429);
}

#[tokio::test(flavor = "multi_thread")]
async fn forwarded_for_limits_each_client_behind_a_proxy() {
    let s = start(
        |_| {},
        HttpConfig {
            rate: Some(RateLimit {
                per_second: 1,
                burst: 1,
                in_flight: 16,
                polls: 4,
                max_tracked: 1024,
            }),
            client_ip: ClientIp::ForwardedFor,
            ..quick()
        },
    )
    .await;
    let a = "x-forwarded-for: 198.51.100.1\r\n";
    let b = "x-forwarded-for: 203.0.113.9, 198.51.100.2\r\n";
    assert_eq!(http(s.addr, "GET", "/v1/info", a, b"").await.0, 200);
    assert_eq!(http(s.addr, "GET", "/v1/info", a, b"").await.0, 429);
    assert_eq!(http(s.addr, "GET", "/v1/info", b, b"").await.0, 200);
    let spoof = "x-forwarded-for: 198.51.100.2, 198.51.100.1\r\n";
    assert_eq!(
        http(s.addr, "GET", "/v1/info", spoof, b"").await.0,
        429,
        "only the proxy's own entry counts"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn long_polls_are_capped_in_time() {
    let s = start(|c| c.max_wait = Duration::from_millis(300), quick()).await;
    let f = fixture(&s).await;
    let started = Instant::now();
    let r = tokio::time::timeout(HANG, call(&s, &take(&s, &f, u32::MAX)))
        .await
        .expect("a poll asking for 49 days ends at the cap");
    assert!(matches!(r, Ok(Reply::Messages(m)) if m.is_empty()));
    let took = started.elapsed();
    assert!(took >= Duration::from_millis(300), "it did wait: {took:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_long_polls_are_bounded_per_client_and_overall() {
    let s = Arc::new(
        start(
            |c| c.max_wait = Duration::from_secs(300),
            HttpConfig {
                rate: Some(RateLimit {
                    per_second: 1000,
                    burst: 1000,
                    in_flight: 4,
                    polls: 4,
                    max_tracked: 1024,
                }),
                ..quick()
            },
        )
        .await,
    );
    let f = Arc::new(fixture(&s).await);
    let mut polls = Vec::new();
    for _ in 0..4 {
        let raw = take(&s, &f, 300_000);
        let addr = s.addr;
        polls.push(tokio::spawn(async move {
            http(addr, "POST", "/v1/request", "", &raw).await.0
        }));
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        http(s.addr, "GET", "/v1/info", "", b"").await.0,
        429,
        "a client's fifth request in flight is refused"
    );
    assert!(
        polls.iter().all(|p| !p.is_finished()),
        "refused while all four polls were still open"
    );
    let put = sealed(
        &s,
        &f.writer,
        &f.id,
        &Body::Put {
            bytes: bytes::Bytes::from_static(b"wake"),
        },
    );
    assert!(matches!(
        s.service.execute(&put).await,
        Ok(Reply::Stored(_))
    ));
    for p in polls {
        let status = tokio::time::timeout(HANG, p)
            .await
            .expect("the put wakes every poll")
            .unwrap();
        assert_eq!(status, 200);
    }

    let g = start(
        |_| {},
        HttpConfig {
            max_in_flight: 3,
            body_timeout: Duration::from_secs(5),
            ..quick()
        },
    )
    .await;
    let mut held = Vec::new();
    for _ in 0..3 {
        let mut c = TcpStream::connect(g.addr).await.unwrap();
        c.write_all(b"POST /v1/request HTTP/1.1\r\nhost: x\r\ncontent-length: 100\r\n\r\n0123")
            .await
            .unwrap();
        held.push(c);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        http(g.addr, "GET", "/v1/info", "", b"").await.0,
        503,
        "the server's in-flight cap holds"
    );
    drop(held);
}

#[tokio::test(flavor = "multi_thread")]
async fn long_polls_from_many_clients_cannot_starve_short_requests() {
    let s = Arc::new(
        start(
            |c| c.max_wait = Duration::from_secs(300),
            HttpConfig {
                max_in_flight: 4,
                max_polls: 2,
                ..quick()
            },
        )
        .await,
    );
    let mut boxes = Vec::new();
    for _ in 0..4 {
        boxes.push(Arc::new(fixture(&s).await));
    }
    let mut polls = Vec::new();
    for f in &boxes {
        for _ in 0..4 {
            let raw = take(&s, f, 300_000);
            let addr = s.addr;
            polls.push(tokio::spawn(async move {
                http(addr, "POST", "/v1/request", "", &raw).await.0
            }));
        }
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let put = |f: &Fixture| {
        sealed(
            &s,
            &f.writer,
            &f.id,
            &Body::Put {
                bytes: bytes::Bytes::from_static(b"through"),
            },
        )
    };
    let short = async {
        assert!(
            matches!(call(&s, &put(&boxes[0])).await, Ok(Reply::Stored(_))),
            "a put is served while sixteen long polls are open"
        );
        assert_eq!(http(s.addr, "GET", "/v1/info", "", b"").await.0, 200);
    };
    tokio::time::timeout(HANG, short)
        .await
        .expect("short requests do not wait for the polls to expire");
    for f in &boxes[1..] {
        assert!(matches!(call(&s, &put(f)).await, Ok(Reply::Stored(_))));
    }
    for p in polls {
        let status = tokio::time::timeout(HANG, p)
            .await
            .expect("the puts wake every poll")
            .unwrap();
        assert!(
            status == 200 || status == 503,
            "a poll is answered or, arriving in the burst as a short request, refused: {status}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_never_reads_its_reply_loses_its_connection() {
    let s = start(
        |c| {
            c.untrusted = baton_drop::BoxLimits {
                max_box_bytes: c.max_box_bytes,
                max_box_messages: c.max_box_messages,
                max_ttl_ms: c.max_ttl_ms,
            };
        },
        HttpConfig {
            max_connections: 1,
            write_timeout: Duration::from_millis(500),
            ..quick()
        },
    )
    .await;
    let reader = baton_mailbox::BoxKey::generate();
    let writer = baton_mailbox::BoxKey::generate();
    let id = baton_mailbox::BoxId::of_reader(&reader.public());
    let policy = baton_mailbox::BoxPolicy {
        max_bytes: 16 * 1024 * 1024,
        ..baton_mailbox::BoxPolicy::new(reader.public(), vec![writer.public()])
    };
    let create = Body::Create {
        policy,
        admission: baton_drop::wire::WireAdmission::None,
    };
    assert_eq!(
        call(&s, &sealed(&s, &reader, &id, &create)).await,
        Ok(Reply::Done)
    );
    let chunk = bytes::Bytes::from(vec![7u8; 64 * 1024]);
    for _ in 0..64 {
        let put = Body::Put {
            bytes: chunk.clone(),
        };
        assert!(matches!(
            call(&s, &sealed(&s, &writer, &id, &put)).await,
            Ok(Reply::Stored(_))
        ));
    }
    let big = sealed(
        &s,
        &reader,
        &id,
        &Body::Take {
            after: None,
            limit: 256,
            wait_ms: 0,
        },
    );
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(1024).unwrap();
    let mut stuck = socket.connect(s.addr).await.unwrap();
    let head = format!(
        "POST /v1/request HTTP/1.1\r\nhost: drop.example.com\r\ncontent-length: {}\r\n\r\n",
        big.len()
    );
    stuck.write_all(head.as_bytes()).await.unwrap();
    stuck.write_all(&big).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (status, _) = tokio::time::timeout(HANG, http(s.addr, "GET", "/v1/info", "", b""))
        .await
        .expect("the stuck reply is dropped and its connection slot freed");
    assert_eq!(status, 200);
    let mut raw = Vec::new();
    let read = tokio::time::timeout(HANG, stuck.read_to_end(&mut raw))
        .await
        .expect("the stuck connection was closed by the server");
    assert!(
        read.is_err() || raw.len() < 64 * chunk.len(),
        "the reply was cut, not delivered whole"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn one_client_cannot_hold_more_than_its_connections() {
    let s = start(
        |_| {},
        HttpConfig {
            max_connections_per_client: 2,
            header_timeout: Duration::from_secs(5),
            ..quick()
        },
    )
    .await;
    let mut idle = Vec::new();
    for _ in 0..2 {
        idle.push(TcpStream::connect(s.addr).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut third = TcpStream::connect(s.addr).await.unwrap();
    let mut buf = [0u8; 16];
    let closed = tokio::time::timeout(Duration::from_secs(2), third.read(&mut buf))
        .await
        .expect("the third connection is closed at once");
    assert!(matches!(closed, Ok(0) | Err(_)));
    drop(idle);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(http(s.addr, "GET", "/v1/info", "", b"").await.0, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn waiters_beyond_the_service_cap_return_at_once() {
    let s = start(
        |c| {
            c.max_wait = Duration::from_secs(300);
            c.max_waiters = 2;
        },
        quick(),
    )
    .await;
    let f = fixture(&s).await;
    let mut polls = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let raw = take(&s, &f, 300_000);
        let addr = s.addr;
        polls.spawn(async move { http(addr, "POST", "/v1/request", "", &raw).await });
    }
    let messages = |(status, body): (u16, Vec<u8>)| {
        assert_eq!(status, 200);
        match baton_drop::wire::decode_reply(&body, 1 << 24).unwrap() {
            Ok(Reply::Messages(m)) => m.len(),
            other => panic!("not a take reply: {other:?}"),
        }
    };
    for _ in 0..6 {
        let done = tokio::time::timeout(HANG, polls.join_next())
            .await
            .expect("six of eight polls return at once")
            .unwrap()
            .unwrap();
        assert_eq!(messages(done), 0);
    }
    assert_eq!(polls.len(), 2, "two are still waiting");
    let put = sealed(
        &s,
        &f.writer,
        &f.id,
        &Body::Put {
            bytes: bytes::Bytes::from_static(b"wake"),
        },
    );
    assert!(matches!(call(&s, &put).await, Ok(Reply::Stored(_))));
    while let Some(done) = tokio::time::timeout(HANG, polls.join_next())
        .await
        .expect("the put wakes both waiters")
    {
        assert_eq!(messages(done.unwrap()), 1, "a waiter, not a returned poll");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_requests_get_malformed_replies() {
    let s = start(|_| {}, quick()).await;
    for body in [&b""[..], b"garbage", &[1u8; 100], &[0xff; 4096]] {
        assert!(matches!(
            call(&s, body).await,
            Err(DropError::Malformed | DropError::Version)
        ));
    }
    assert_eq!(http(s.addr, "GET", "/v1/request", "", b"").await.0, 405);
    assert_eq!(http(s.addr, "POST", "/v1/info", "", b"").await.0, 405);
    assert_eq!(http(s.addr, "GET", "/", "", b"").await.0, 404);
    assert_eq!(
        http(s.addr, "GET", "/v1/../etc/passwd", "", b"").await.0,
        404
    );
    let mut c = TcpStream::connect(s.addr).await.unwrap();
    c.write_all(b"\x00\x01\x02 not http at all\r\n\r\n")
        .await
        .unwrap();
    let (status, _) = read_response(&mut c).await;
    assert!(status == 400 || status == 0);
    let f = fixture(&s).await;
    assert!(matches!(
        call(&s, &take(&s, &f, 0)).await,
        Ok(Reply::Messages(_))
    ));
}
