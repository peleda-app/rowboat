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

#[tokio::test(flavor = "multi_thread")]
async fn slow_headers_are_cut_off_and_do_not_block_others() {
    let s = start(
        |_| {},
        HttpConfig {
            max_connections: 64,
            ..quick()
        },
    )
    .await;
    let mut slow = Vec::new();
    for _ in 0..40 {
        let mut c = TcpStream::connect(s.addr).await.unwrap();
        c.write_all(b"POST /v1/request HTTP/1.1\r\nhost: drop.exa")
            .await
            .unwrap();
        slow.push(c);
    }
    let started = Instant::now();
    let (status, _) = http(s.addr, "GET", "/v1/info", "", b"").await;
    assert_eq!(status, 200);
    assert!(started.elapsed() < Duration::from_secs(2));
    for mut c in slow {
        let mut buf = [0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf))
            .await
            .expect("the server closes a connection that never finishes its headers");
        assert!(matches!(n, Ok(_) | Err(_)));
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
    let started = Instant::now();
    let (status, _) = tokio::time::timeout(
        Duration::from_secs(10),
        http(s.addr, "GET", "/v1/info", "", b""),
    )
    .await
    .expect("a slot frees up once the header timeout fires");
    assert_eq!(status, 200);
    assert!(started.elapsed() < Duration::from_secs(5));
    drop(slow);
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
    let started = Instant::now();
    assert_eq!(read_response(&mut c).await.0, 408);
    assert!(started.elapsed() < Duration::from_secs(5));
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
    let r = call(&s, &take(&s, &f, u32::MAX)).await;
    assert!(matches!(r, Ok(Reply::Messages(m)) if m.is_empty()));
    let took = started.elapsed();
    assert!(took >= Duration::from_millis(250), "it did wait: {took:?}");
    assert!(
        took < Duration::from_secs(5),
        "but no longer than the cap: {took:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_long_polls_are_bounded_per_client_and_overall() {
    let s = Arc::new(
        start(
            |c| c.max_wait = Duration::from_secs(3),
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
        let raw = take(&s, &f, 3000);
        let addr = s.addr;
        polls.push(tokio::spawn(async move {
            http(addr, "POST", "/v1/request", "", &raw).await.0
        }));
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let started = Instant::now();
    assert_eq!(
        http(s.addr, "GET", "/v1/info", "", b"").await.0,
        429,
        "a client's fifth request in flight is refused"
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    let put = sealed(
        &s,
        &f.writer,
        &f.id,
        &Body::Put {
            bytes: bytes::Bytes::from_static(b"wake"),
        },
    );
    for p in polls {
        assert_eq!(p.await.unwrap(), 200);
    }
    assert!(matches!(call(&s, &put).await, Ok(Reply::Stored(_))));

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
            |c| c.max_wait = Duration::from_secs(3),
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
            let raw = take(&s, f, 3000);
            let addr = s.addr;
            polls.push(tokio::spawn(async move {
                http(addr, "POST", "/v1/request", "", &raw).await.0
            }));
        }
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let started = Instant::now();
    let put = sealed(
        &s,
        &boxes[0].writer,
        &boxes[0].id,
        &Body::Put {
            bytes: bytes::Bytes::from_static(b"through"),
        },
    );
    assert!(
        matches!(call(&s, &put).await, Ok(Reply::Stored(_))),
        "a put is served while sixteen long polls are open"
    );
    assert_eq!(http(s.addr, "GET", "/v1/info", "", b"").await.0, 200);
    assert!(started.elapsed() < Duration::from_secs(2));
    for p in polls {
        let status = p.await.unwrap();
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
    let started = Instant::now();
    let (status, _) = tokio::time::timeout(
        Duration::from_secs(10),
        http(s.addr, "GET", "/v1/info", "", b""),
    )
    .await
    .expect("the stuck reply is dropped and its connection slot freed");
    assert_eq!(status, 200);
    assert!(started.elapsed() < Duration::from_secs(5));
    drop(stuck);
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
            c.max_wait = Duration::from_secs(2);
            c.max_waiters = 2;
        },
        quick(),
    )
    .await;
    let f = fixture(&s).await;
    let started = Instant::now();
    let mut polls = Vec::new();
    for _ in 0..8 {
        let raw = take(&s, &f, 2000);
        let addr = s.addr;
        polls.push(tokio::spawn(async move {
            let t = Instant::now();
            let (status, _) = http(addr, "POST", "/v1/request", "", &raw).await;
            (status, t.elapsed())
        }));
    }
    let mut fast = 0;
    for p in polls {
        let (status, took) = p.await.unwrap();
        assert_eq!(status, 200);
        if took < Duration::from_millis(1500) {
            fast += 1;
        }
    }
    assert!(fast >= 6, "only two may wait, {fast} returned at once");
    assert!(started.elapsed() < Duration::from_secs(10));
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
