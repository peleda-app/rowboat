use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use baton_signal_local::LocalSignal;
use bytes::Bytes;
use skein_push::PushRegistry;
use skein_storage::{Objects, Storage};
use skein_storage_memory::MemoryObjects;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

use crate::*;

fn app(config: &ServerConfig) -> Router {
    let objects: Arc<dyn Objects> = Arc::new(MemoryObjects::new());
    let storage = Storage::over(objects.clone());
    let registry = PushRegistry::new(objects, storage.control.clone());
    router(Arc::new(LocalSignal::new()), Some(registry), config)
}

async fn send(router: &Router, method: Method, uri: &str, body: Body) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(body)
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn health_answers_and_nothing_else_is_served() {
    let r = app(&ServerConfig::default());
    let ok = send(&r, Method::GET, "/v1/health", Body::empty()).await;
    assert_eq!(ok.status(), StatusCode::OK);
    for (method, uri) in [
        (Method::GET, "/"),
        (Method::GET, "/v1/tenants"),
        (Method::PUT, "/v1/tenants/acme"),
        (Method::GET, "/v1/openapi.json"),
        (Method::GET, "/v1/tenants/acme/accounts/box/events"),
        (Method::POST, "/v1/tenants/acme/accounts/box/commands"),
        (Method::GET, "/v1/oauth/callback?state=x&code=y"),
        (Method::GET, "/metrics"),
    ] {
        let answer = send(&r, method.clone(), uri, Body::empty()).await;
        assert!(
            matches!(
                answer.status(),
                StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
            ),
            "{method} {uri}: {}",
            answer.status()
        );
    }
}

#[tokio::test]
async fn answers_carry_security_headers() {
    let r = app(&ServerConfig::default());
    for uri in [
        "/v1/health",
        "/v1/nothing",
        "/v1/push/graph?validationToken=abc",
    ] {
        let answer = send(&r, Method::GET, uri, Body::empty()).await;
        let h = answer.headers();
        assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff", "{uri}");
        assert_eq!(h[header::X_FRAME_OPTIONS], "DENY", "{uri}");
        assert!(
            h[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'"),
            "{uri}"
        );
        assert_eq!(h[header::CACHE_CONTROL], "no-store", "{uri}");
    }
}

#[tokio::test(start_paused = true)]
async fn a_body_that_stalls_is_given_up() {
    let r = app(&ServerConfig::default());
    let stalled = Body::from_stream(futures::stream::pending::<Result<Bytes, std::io::Error>>());
    let answer = tokio::time::timeout(
        Duration::from_secs(120),
        send(&r, Method::POST, "/v1/push/graph", stalled),
    )
    .await
    .expect("the server gives up on a stalled body");
    assert!(answer.status().is_client_error(), "{}", answer.status());
}

#[tokio::test(start_paused = true)]
async fn push_requests_over_the_rate_are_refused_until_tokens_refill() {
    let r = app(&ServerConfig {
        push_rate_per_second: 3,
        ..Default::default()
    });
    let body = || Body::from(r#"{"value":[]}"#);
    for _ in 0..3 {
        let answer = send(&r, Method::POST, "/v1/push/graph", body()).await;
        assert_eq!(answer.status(), StatusCode::ACCEPTED);
    }
    let refused = send(&r, Method::POST, "/v1/push/graph", body()).await;
    assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(refused.headers()[header::RETRY_AFTER], "1");
    let gmail = send(&r, Method::POST, "/v1/push/gmail/whatever", body()).await;
    assert_eq!(
        gmail.status(),
        StatusCode::NOT_FOUND,
        "gmail has its own budget"
    );
    let health = send(&r, Method::GET, "/v1/health", Body::empty()).await;
    assert_eq!(
        health.status(),
        StatusCode::OK,
        "health is not rate limited"
    );
    tokio::time::advance(Duration::from_millis(400)).await;
    let again = send(&r, Method::POST, "/v1/push/graph", body()).await;
    assert_eq!(again.status(), StatusCode::ACCEPTED);
}

#[tokio::test(start_paused = true)]
async fn unauthenticated_push_floods_do_not_spend_the_budget_of_genuine_gmail_pushes() {
    let r = app(&ServerConfig {
        push_rate_per_second: 3,
        gmail_push_token_hash: Some(hash_token("genuine-secret")),
        ..Default::default()
    });
    let body = || Body::from(r#"{"value":[]}"#);
    for _ in 0..20 {
        let answer = send(&r, Method::POST, "/v1/push/gmail/forged", body()).await;
        assert_eq!(answer.status(), StatusCode::NOT_FOUND);
    }
    for _ in 0..20 {
        send(&r, Method::POST, "/v1/push/graph", body()).await;
    }
    let genuine = send(&r, Method::POST, "/v1/push/gmail/genuine-secret", body()).await;
    assert_eq!(genuine.status(), StatusCode::NO_CONTENT);
}

#[test]
fn config_validation_refuses_what_the_router_would_misread() {
    assert!(ServerConfig::default().validate().is_ok());
    let zero = ServerConfig {
        push_rate_per_second: 0,
        ..Default::default()
    };
    assert!(zero.validate().is_err());
    let upper = ServerConfig {
        gmail_push_token_hash: Some(hash_token("x").to_uppercase()),
        ..Default::default()
    };
    assert!(upper.validate().is_err());
    let plain_http = ServerConfig {
        gmail_push_oidc: Some(oidc::OidcConfig {
            audience: "a".into(),
            email: "push@example.com".into(),
            jwks_url: "http://keys.example.com/certs".into(),
        }),
        ..Default::default()
    };
    assert!(plain_http.validate().is_err());
}

#[tokio::test]
async fn the_listener_drops_clients_that_send_headers_slowly() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(listen::serve_with(
        listener,
        app(&ServerConfig::default()),
        async {
            let _ = stopped.await;
        },
        Duration::from_millis(300),
        2,
    ));
    let mut slow = tokio::net::TcpStream::connect(addr).await.unwrap();
    slow.write_all(b"GET /v1/health HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), slow.read_to_end(&mut buf)).await;
    assert!(
        read.is_ok(),
        "the connection is closed after the header timeout"
    );
    assert!(
        buf.is_empty() || String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 408"),
        "{}",
        String::from_utf8_lossy(&buf)
    );

    let mut fast = tokio::net::TcpStream::connect(addr).await.unwrap();
    fast.write_all(b"GET /v1/health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut answer = String::new();
    fast.read_to_string(&mut answer).await.unwrap();
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(answer.contains("nosniff"));
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn the_listener_serves_at_most_its_connection_limit() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(listen::serve_with(
        listener,
        app(&ServerConfig::default()),
        std::future::pending(),
        Duration::from_secs(30),
        1,
    ));
    let held = tokio::net::TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut second = tokio::net::TcpStream::connect(addr).await.unwrap();
    second
        .write_all(b"GET /v1/health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 16];
    let waited = tokio::time::timeout(Duration::from_millis(300), second.read(&mut buf)).await;
    assert!(
        waited.is_err(),
        "the second connection waits while the first holds the only slot"
    );
    drop(held);
    let n = tokio::time::timeout(Duration::from_secs(5), second.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
}
