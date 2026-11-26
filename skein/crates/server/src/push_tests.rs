use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode, header};
use base64::Engine;
use baton_signal::Signal;
use baton_signal_local::LocalSignal;
use bytes::Bytes;
use futures::StreamExt;
use skein_core::{AccountId, TenantId, Timestamp};
use skein_push::{PUSH_GMAIL, PUSH_GRAPH, PushRegistry, Subscription};
use skein_storage::{Objects, Storage};
use skein_storage_memory::MemoryObjects;
use tower::ServiceExt;

use crate::*;

const GMAIL_TOKEN: &str = "pubsub-push-secret-4f9a1c";
const SUB: &str = "7f105c7d-2dc5-4530-97cd-4e7ae6534c07";
const STATE: &str = "client-state-for-tests";

struct Setup {
    router: Router,
    registry: PushRegistry,
    signal: Arc<LocalSignal>,
}

fn setup_with(push: bool, gmail: bool) -> Setup {
    setup_oidc(push, gmail, None)
}

fn setup_oidc(push: bool, gmail: bool, oidc: Option<crate::oidc::OidcConfig>) -> Setup {
    let objects: Arc<dyn Objects> = Arc::new(MemoryObjects::new());
    let storage = Storage::over(objects.clone());
    let signal = Arc::new(LocalSignal::new());
    let config = ServerConfig {
        gmail_push_token_hash: gmail.then(|| hash_token(GMAIL_TOKEN)),
        gmail_push_oidc: oidc,
        ..Default::default()
    };
    assert!(config.validate().is_ok());
    let registry = PushRegistry::new(objects, storage.control.clone());
    let router = router(signal.clone(), push.then(|| registry.clone()), &config);
    Setup {
        router,
        registry,
        signal,
    }
}

fn setup() -> Setup {
    setup_with(true, true)
}

fn t() -> TenantId {
    TenantId::new("acme").unwrap()
}

fn a() -> AccountId {
    AccountId::new("box").unwrap()
}

struct Answer {
    status: StatusCode,
    content_type: Option<String>,
    body: Bytes,
}

impl Setup {
    async fn call(&self, method: Method, uri: &str, body: impl Into<Body>) -> Answer {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.into())
            .unwrap();
        request.extensions_mut().insert(ConnectInfo::<SocketAddr>(
            "203.0.113.20:443".parse().unwrap(),
        ));
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        Answer {
            status,
            content_type,
            body,
        }
    }

    async fn register_graph(&self) {
        let sub = Subscription {
            id: SUB.into(),
            provider_kind: PUSH_GRAPH.into(),
            expires_at: Timestamp::now().plus_ms(3_600_000),
            resource: "me/messages".into(),
        };
        self.registry
            .register(&sub, &t(), &a(), STATE)
            .await
            .unwrap();
    }

    async fn register_gmail(&self) {
        let sub = Subscription {
            id: "1000".into(),
            provider_kind: PUSH_GMAIL.into(),
            expires_at: Timestamp::now().plus_ms(3_600_000),
            resource: "ada@example.com".into(),
        };
        self.registry.register(&sub, &t(), &a(), "").await.unwrap();
    }

    async fn hints(&self) -> futures::stream::BoxStream<'static, Bytes> {
        self.signal
            .subscribe(&skein_core::coordination::group(&t()), "push/box")
            .await
            .unwrap()
    }
}

async fn quiet(hints: &mut futures::stream::BoxStream<'static, Bytes>) -> bool {
    tokio::time::timeout(Duration::from_millis(50), hints.next())
        .await
        .is_err()
}

fn graph_body(id: &str, state: &str) -> String {
    format!(
        r#"{{"value":[{{"subscriptionId":"{id}","clientState":"{state}","changeType":"created","resource":"Users/x/Messages/y","tenantId":"z"}}]}}"#
    )
}

fn envelope(email: &str) -> String {
    let data = format!(r#"{{"emailAddress":"{email}","historyId":9876543210}}"#);
    format!(
        r#"{{"message":{{"data":"{}","messageId":"1","publishTime":"2026-11-21T10:00:00Z"}},"subscription":"projects/acme/subscriptions/push"}}"#,
        base64::engine::general_purpose::STANDARD.encode(data)
    )
}

#[tokio::test]
async fn graph_validation_echoes_the_token() {
    let s = setup();
    let token = "Validation%3A%20Testing%20client%20application%20reachability";
    for method in [Method::GET, Method::POST] {
        let r = s
            .call(
                method,
                &format!("/v1/push/graph?validationToken={token}"),
                Body::empty(),
            )
            .await;
        assert_eq!(r.status, StatusCode::OK);
        assert!(r.content_type.unwrap().starts_with("text/plain"));
        assert_eq!(
            &r.body[..],
            b"Validation: Testing client application reachability"
        );
    }
    let long = "x".repeat(1025);
    for bad in [long.as_str(), "", "a%0Ab", "%3Cscript%3E%7F"] {
        let r = s
            .call(
                Method::GET,
                &format!("/v1/push/graph?validationToken={bad}"),
                Body::empty(),
            )
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let r = s.call(Method::GET, "/v1/push/graph", Body::empty()).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn graph_notifications_hint_only_with_the_right_client_state() {
    let s = setup();
    s.register_graph().await;
    let mut hints = s.hints().await;

    let r = s
        .call(
            Method::POST,
            "/v1/push/graph",
            graph_body(SUB, "wrong-state"),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    assert!(quiet(&mut hints).await);

    let r = s
        .call(
            Method::POST,
            "/v1/push/graph",
            graph_body("unknown-id", STATE),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "unknown ids look the same");
    assert!(quiet(&mut hints).await);

    let r = s
        .call(Method::POST, "/v1/push/graph", graph_body(SUB, STATE))
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    assert!(r.body.is_empty());
    assert_eq!(&hints.next().await.unwrap()[..], br#"{"provider":"graph"}"#);

    let lifecycle = format!(
        r#"{{"value":[{{"subscriptionId":"{SUB}","clientState":"{STATE}","lifecycleEvent":"reauthorizationRequired"}}]}}"#
    );
    let r = s.call(Method::POST, "/v1/push/graph", lifecycle).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    hints.next().await.unwrap();

    let r = s.call(Method::POST, "/v1/push/graph", "not json").await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn gmail_needs_the_token_and_hints_the_account() {
    let s = setup();
    s.register_gmail().await;
    let mut hints = s.hints().await;
    for bad in [
        "wrong",
        "pubsub-push-secret-4f9a1",
        "pubsub-push-secret-4f9a1cc",
        "",
    ] {
        let r = s
            .call(
                Method::POST,
                &format!("/v1/push/gmail/{bad}"),
                envelope("ada@example.com"),
            )
            .await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{bad}");
    }
    assert!(quiet(&mut hints).await);

    let path = format!("/v1/push/gmail/{GMAIL_TOKEN}");
    let r = s
        .call(Method::POST, &path, envelope("eve@example.org"))
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert!(quiet(&mut hints).await);

    let r = s.call(Method::POST, &path, "garbage").await;
    assert_eq!(
        r.status,
        StatusCode::NO_CONTENT,
        "malformed envelopes are acknowledged"
    );

    let r = s
        .call(Method::POST, &path, envelope("Ada@Example.com"))
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(&hints.next().await.unwrap()[..], br#"{"provider":"gmail"}"#);
}

#[tokio::test]
async fn oversized_bodies_are_refused() {
    let s = setup();
    let big = format!(
        r#"{{"value":[],"pad":"{}"}}"#,
        "x".repeat(push::BODY_LIMIT + 1)
    );
    let r = s.call(Method::POST, "/v1/push/graph", big.clone()).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    let r = s
        .call(Method::POST, &format!("/v1/push/gmail/{GMAIL_TOKEN}"), big)
        .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn push_is_off_without_a_registry_or_token() {
    let s = setup_with(false, true);
    let r = s
        .call(Method::POST, "/v1/push/graph", graph_body(SUB, STATE))
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = s
        .call(
            Method::GET,
            "/v1/push/graph?validationToken=abc",
            Body::empty(),
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = s
        .call(
            Method::POST,
            &format!("/v1/push/gmail/{GMAIL_TOKEN}"),
            envelope("ada@example.com"),
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    let s = setup_with(true, false);
    let r = s
        .call(
            Method::POST,
            &format!("/v1/push/gmail/{GMAIL_TOKEN}"),
            envelope("ada@example.com"),
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[test]
fn the_push_token_hash_is_checked() {
    let config = ServerConfig {
        gmail_push_token_hash: Some("not-a-hash".into()),
        ..Default::default()
    };
    assert!(config.validate().is_err());
    assert!(
        !format!(
            "{:?}",
            ServerConfig {
                gmail_push_token_hash: Some(hash_token(GMAIL_TOKEN)),
                ..Default::default()
            }
        )
        .contains(GMAIL_TOKEN)
    );
}

mod oidc {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde_json::json;

    use super::*;

    const KEY: &str = include_str!("../tests/fixtures/oidc-test-key.pem");
    const N: &str = include_str!("../tests/fixtures/oidc-test-key.n");
    const AUD: &str = "https://skein.example.com/v1/push/gmail";
    const EMAIL: &str = "push@example-project.iam.gserviceaccount.com";

    async fn jwks() -> String {
        jwks_padded(0).await
    }

    async fn jwks_padded(pad: usize) -> String {
        let body = json!({"keys": [{"kty": "RSA", "kid": "test-key", "alg": "RS256", "use": "sig", "n": N.trim(), "e": "AQAB"}], "pad": "x".repeat(pad)}).to_string();
        let app = Router::new().route(
            "/certs",
            axum::routing::get(move || {
                let body = body.clone();
                async move {
                    let chunks: Vec<Result<bytes::Bytes, std::io::Error>> = body
                        .into_bytes()
                        .chunks(16 * 1024)
                        .map(|c| Ok(bytes::Bytes::copy_from_slice(c)))
                        .collect();
                    Body::from_stream(futures::stream::iter(chunks))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/certs")
    }

    fn token(aud: &str, email: &str, exp_offset: i64, kid: &str) -> String {
        let now = Timestamp::now().0 / 1000;
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());
        encode(
            &header,
            &json!({"iss": "https://accounts.google.com", "aud": aud, "email": email, "email_verified": true, "iat": now, "exp": now + exp_offset}),
            &EncodingKey::from_rsa_pem(KEY.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    async fn post(s: &Setup, bearer: Option<String>) -> StatusCode {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(format!("/v1/push/gmail/{GMAIL_TOKEN}"))
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(b) = bearer {
            req = req.header(header::AUTHORIZATION, format!("Bearer {b}"));
        }
        let mut req = req.body(Body::from(envelope("ada@example.com"))).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 9))));
        s.router.clone().oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn gmail_push_needs_a_valid_pubsub_token_when_configured() {
        let s = setup_oidc(
            true,
            true,
            Some(crate::oidc::OidcConfig {
                audience: AUD.into(),
                email: EMAIL.into(),
                jwks_url: jwks().await,
            }),
        );
        assert_eq!(
            post(&s, Some(token(AUD, EMAIL, 300, "test-key"))).await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(post(&s, None).await, StatusCode::UNAUTHORIZED, "no token");
        assert_eq!(
            post(
                &s,
                Some(token("https://other.example.com", EMAIL, 300, "test-key"))
            )
            .await,
            StatusCode::UNAUTHORIZED,
            "another audience"
        );
        assert_eq!(
            post(&s, Some(token(AUD, "other@example.com", 300, "test-key"))).await,
            StatusCode::UNAUTHORIZED,
            "another service account"
        );
        assert_eq!(
            post(&s, Some(token(AUD, EMAIL, -600, "test-key"))).await,
            StatusCode::UNAUTHORIZED,
            "expired"
        );
        let forged = encode(
            &Header::new(Algorithm::HS256),
            &json!({"iss": "https://accounts.google.com", "aud": AUD, "email": EMAIL, "email_verified": true, "exp": Timestamp::now().0 / 1000 + 300}),
            &EncodingKey::from_secret(N.trim().as_bytes()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            post(&s, Some(forged)).await,
            StatusCode::UNAUTHORIZED,
            "HMAC with the public key is refused"
        );
        assert_eq!(
            post(&s, Some(token(AUD, EMAIL, 300, "unknown-key"))).await,
            StatusCode::UNAUTHORIZED,
            "unknown key id"
        );
    }

    #[tokio::test]
    async fn an_oversized_key_set_is_never_used() {
        let s = setup_oidc(
            true,
            true,
            Some(crate::oidc::OidcConfig {
                audience: AUD.into(),
                email: EMAIL.into(),
                jwks_url: jwks_padded(300 * 1024).await,
            }),
        );
        assert_eq!(
            post(&s, Some(token(AUD, EMAIL, 300, "test-key"))).await,
            StatusCode::UNAUTHORIZED
        );
    }
}
