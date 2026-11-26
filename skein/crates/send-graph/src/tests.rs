use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use mail_parser::MessageParser;
use skein_send::testing::{Behavior, Deliveries, Delivery, Fake, Profile, Receiver, conformance};

use super::*;

const TOKEN: &str = "graph-send-token";
const ADA: &str = "ada@example.com";
const BOB: &str = "bob@example.org";
const CAROL: &str = "carol@example.org";

struct Seen {
    path: String,
    authorization: String,
    content_type: String,
    mime: Vec<u8>,
}

struct Server {
    behavior: Behavior,
    deliveries: Deliveries,
    requests: Mutex<Vec<Seen>>,
    status: Mutex<Option<(u16, String, Option<u64>)>>,
}

type Shared = Arc<Server>;

fn strip_bcc(mime: &[u8]) -> Vec<u8> {
    if !mime.starts_with(b"Bcc:") {
        return mime.to_vec();
    }
    let mut lines = mime.split_inclusive(|b| *b == b'\n');
    lines.next();
    let mut rest: Vec<u8> = Vec::new();
    let mut folded = true;
    for line in lines {
        if folded && (line.starts_with(b" ") || line.starts_with(b"\t")) {
            continue;
        }
        folded = false;
        rest.extend_from_slice(line);
    }
    rest
}

fn header_recipients(mime: &[u8]) -> Vec<String> {
    let parsed = MessageParser::new().parse_headers(mime).expect("headers");
    let headers = parsed.headers();
    headers
        .all_to()
        .chain(headers.all_cc())
        .chain(headers.all_bcc())
        .flat_map(|list| {
            list.mailboxes()
                .filter_map(|m| m.address().map(str::to_owned))
                .collect::<Vec<_>>()
        })
        .collect()
}

fn error(status: u16, code: &str) -> Response {
    (
        StatusCode::from_u16(status).unwrap(),
        axum::Json(serde_json::json!({"error": {"code": code, "message": "refused by the fake"}})),
    )
        .into_response()
}

async fn send_mail(
    State(server): State<Shared>,
    path: axum::extract::OriginalUri,
    headers: HeaderMap,
    body: String,
) -> Response {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    };
    let mime = BASE64.decode(body.trim()).expect("base64 body");
    server.requests.lock().unwrap().push(Seen {
        path: path.path().to_owned(),
        authorization: header("authorization"),
        content_type: header("content-type"),
        mime: mime.clone(),
    });
    if header("authorization") != format!("Bearer {TOKEN}") {
        return error(401, "InvalidAuthenticationToken");
    }
    if let Some((status, code, retry)) = server.status.lock().unwrap().clone() {
        let mut response = error(status, &code);
        if let Some(seconds) = retry {
            response
                .headers_mut()
                .insert("retry-after", seconds.to_string().parse().unwrap());
        }
        return response;
    }
    let recipients = header_recipients(&mime);
    match &server.behavior {
        Behavior::RefuseRecipient(r) if recipients.contains(r) => {
            return error(400, "ErrorInvalidRecipients");
        }
        Behavior::TemporaryFailure => {
            let mut response = error(429, "ApplicationThrottled");
            response
                .headers_mut()
                .insert("retry-after", "3".parse().unwrap());
            return response;
        }
        Behavior::PermanentFailure => return error(403, "ErrorMessageSubmissionBlocked"),
        _ => {}
    }
    server.deliveries.push(Delivery {
        mail_from: String::new(),
        recipients,
        bytes: strip_bcc(&mime),
    });
    if server.behavior == Behavior::DropAfterData {
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
    StatusCode::ACCEPTED.into_response()
}

async fn sent_items(
    State(_): State<Shared>,
    Path(_): Path<String>,
    headers: HeaderMap,
) -> Response {
    if headers.get("authorization").and_then(|v| v.to_str().ok())
        != Some(&format!("Bearer {TOKEN}"))
    {
        return error(401, "InvalidAuthenticationToken");
    }
    axum::Json(serde_json::json!({"id": "sentitems-id"})).into_response()
}

async fn start(behavior: Behavior) -> (u16, Shared) {
    let server = Arc::new(Server {
        behavior,
        deliveries: Deliveries::default(),
        requests: Mutex::new(Vec::new()),
        status: Mutex::new(None),
    });
    let app = Router::new()
        .route("/v1.0/me/sendMail", post(send_mail))
        .route("/v1.0/users/{id}/sendMail", post(send_mail))
        .route("/v1.0/me/mailFolders/{folder}", get(sent_items))
        .with_state(server.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await });
    (port, server)
}

fn settings(port: u16) -> GraphSendSettings {
    GraphSendSettings {
        api_url: Some(format!("http://127.0.0.1:{port}/v1.0")),
        ..GraphSendSettings::default()
    }
}

fn token() -> Credentials {
    Credentials::AccessToken {
        token: TOKEN.into(),
    }
}

struct GraphReceiver;

#[async_trait]
impl Receiver for GraphReceiver {
    async fn start(&self, behavior: Behavior) -> Fake {
        let max_size = match behavior {
            Behavior::SizeLimit(n) => Some(n),
            _ => None,
        };
        let (port, server) = start(behavior).await;
        let sender = GraphSender::new(
            GraphSendSettings {
                max_size,
                ..settings(port)
            },
            token(),
        )
        .unwrap()
        .with_timeout(Duration::from_secs(1))
        .unwrap();
        Fake {
            sender: Box::new(sender),
            deliveries: server.deliveries.clone(),
        }
    }

    fn profile(&self) -> Profile {
        Profile::HEADER_ONLY
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn keeps_the_send_contract() {
    conformance(&GraphReceiver).await;
}

const MESSAGE: &[u8] =
    b"From: Ada <ada@example.com>\r\nTo: Bob <bob@example.org>\r\nSubject: Hi\r\n\r\nHello\r\n";

#[tokio::test]
async fn sends_base64_mime_with_the_token_and_a_bcc_field() {
    let (port, server) = start(Behavior::AcceptAll).await;
    let sender = GraphSender::new(settings(port), token()).unwrap();
    assert!(sender.saves_to_sent());
    sender.check().await.unwrap();
    let envelope = Envelope::new(ADA, vec![BOB.into(), CAROL.into()]);
    let report = sender.send(&envelope, MESSAGE).await.unwrap();
    assert_eq!(report.refused().count(), 0);
    let requests = server.requests.lock().unwrap();
    let seen = requests.last().unwrap();
    assert_eq!(seen.path, "/v1.0/me/sendMail");
    assert_eq!(seen.authorization, format!("Bearer {TOKEN}"));
    assert_eq!(seen.content_type, "text/plain");
    let mut expected = format!("Bcc: {CAROL}\r\n").into_bytes();
    expected.extend_from_slice(MESSAGE);
    assert_eq!(seen.mime, expected, "only a Bcc field is added");
}

#[tokio::test]
async fn sends_from_another_user_for_app_only_tokens() {
    let (port, server) = start(Behavior::AcceptAll).await;
    let sender = GraphSender::new(
        GraphSendSettings {
            user: Some("shared@example.com".into()),
            ..settings(port)
        },
        token(),
    )
    .unwrap();
    sender
        .send(&Envelope::new(ADA, vec![BOB.into()]), MESSAGE)
        .await
        .unwrap();
    assert_eq!(
        server.requests.lock().unwrap()[0].path,
        "/v1.0/users/shared@example.com/sendMail"
    );
}

type Case = (u16, &'static str, Option<u64>, fn(&SendError) -> bool);

#[tokio::test]
async fn maps_graph_answers() {
    let cases: [Case; 9] = [
        (401, "InvalidAuthenticationToken", None, |e| {
            matches!(e, SendError::Auth(_))
        }),
        (403, "ErrorAccessDenied", None, |e| {
            matches!(e, SendError::Auth(_))
        }),
        (403, "ErrorSendAsDenied", None, |e| {
            matches!(
                e,
                SendError::Refused {
                    permanent: true,
                    code: 550,
                    ..
                }
            )
        }),
        (503, "ServiceUnavailable", Some(5), |e| {
            e.retry_after() == Some(Duration::from_secs(5)) && e.is_retryable()
        }),
        (429, "ApplicationThrottled", Some(120), |e| {
            matches!(e, SendError::Throttled { .. })
                && e.retry_after() == Some(Duration::from_secs(120))
                && !e.may_have_been_sent()
        }),
        (429, "ApplicationThrottled", None, |e| {
            matches!(e, SendError::Throttled { retry_after: None })
        }),
        (500, "InternalServerError", None, |e| e.may_have_been_sent()),
        (413, "", None, |e| matches!(e, SendError::TooLarge { .. })),
        (400, "ErrorInvalidRecipients", None, |e| {
            matches!(
                e,
                SendError::Refused {
                    permanent: true,
                    ..
                }
            ) && !e.is_retryable()
        }),
    ];
    for (status, code, retry, expect) in cases {
        let (port, server) = start(Behavior::AcceptAll).await;
        *server.status.lock().unwrap() = Some((status, code.to_owned(), retry));
        let error = GraphSender::new(settings(port), token())
            .unwrap()
            .send(&Envelope::new(ADA, vec![BOB.into()]), MESSAGE)
            .await
            .unwrap_err();
        assert!(expect(&error), "{status} {code} mapped to {error:?}");
    }
}

#[tokio::test]
async fn an_unreachable_server_is_not_sent() {
    let unused = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = unused.local_addr().unwrap().port();
    drop(unused);
    let error = GraphSender::new(settings(port), token())
        .unwrap()
        .send(&Envelope::new(ADA, vec![BOB.into()]), MESSAGE)
        .await
        .unwrap_err();
    assert!(matches!(error, SendError::Unavailable(_)), "{error:?}");
    assert!(error.is_retryable());
}

#[tokio::test]
async fn refuses_header_recipients_outside_the_envelope_before_sending() {
    let (port, server) = start(Behavior::AcceptAll).await;
    let error = GraphSender::new(settings(port), token())
        .unwrap()
        .send(&Envelope::new(ADA, vec![CAROL.into()]), MESSAGE)
        .await
        .unwrap_err();
    assert!(matches!(error, SendError::Invalid(_)));
    assert!(server.requests.lock().unwrap().is_empty());
}

#[test]
fn refuses_unsafe_settings_and_hides_the_token() {
    let password = Credentials::Password { secret: "x".into() };
    assert!(GraphSender::new(GraphSendSettings::default(), password).is_err());
    for url in [
        "http://graph.example.com/v1.0",
        "ftp://graph.example.com",
        "https://user:pass@graph.example.com/v1.0",
    ] {
        let s = GraphSendSettings {
            api_url: Some(url.into()),
            ..GraphSendSettings::default()
        };
        assert!(GraphSender::new(s, token()).is_err(), "{url}");
    }
    let s = GraphSendSettings {
        user: Some("a b".into()),
        ..GraphSendSettings::default()
    };
    assert!(GraphSender::new(s, token()).is_err());
    let sender = GraphSender::new(GraphSendSettings::default(), token()).unwrap();
    assert!(!format!("{sender:?}").contains(TOKEN));
    let parsed = GraphSendSettings::from_json(
        &serde_json::json!({"api_url": "https://graph.microsoft.com/v1.0", "other": 1}),
    )
    .unwrap();
    assert_eq!(parsed.api_url.as_deref(), Some(GRAPH_URL));
}

#[tokio::test]
async fn waits_while_another_holder_pauses_the_throttle() {
    let (port, server) = start(Behavior::AcceptAll).await;
    let throttle = skein_throttle::Throttle::default();
    let sender = GraphSender::new(settings(port), token())
        .unwrap()
        .with_throttle(throttle.clone());
    throttle.pause(Duration::from_millis(300));
    let start = std::time::Instant::now();
    sender
        .send(&Envelope::new(ADA, vec![BOB.into()]), MESSAGE)
        .await
        .unwrap();
    assert!(start.elapsed() >= Duration::from_millis(300));
    assert_eq!(server.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_busy_answer_pauses_the_shared_throttle() {
    let (port, server) = start(Behavior::AcceptAll).await;
    let throttle = skein_throttle::Throttle::default();
    let sender = GraphSender::new(settings(port), token())
        .unwrap()
        .with_throttle(throttle.clone());
    *server.status.lock().unwrap() = Some((429, "ApplicationThrottled".into(), Some(120)));
    let error = sender
        .send(&Envelope::new(ADA, vec![BOB.into()]), MESSAGE)
        .await
        .unwrap_err();
    assert!(matches!(error, SendError::Throttled { .. }));
    let left = throttle.paused_until().unwrap() - tokio::time::Instant::now();
    assert!(left > Duration::from_secs(119) && left <= Duration::from_secs(120));
}
