use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use mail_parser::MessageParser;
use skein_send::testing::{Behavior, Deliveries, Delivery, Fake, Profile, Receiver, conformance};

use super::*;

const TOKEN: &str = "ya29.gmail-send-token";
const ADA: &str = "ada@example.com";
const BOB: &str = "bob@example.org";
const CAROL: &str = "carol@example.org";

struct Seen {
    path: String,
    authorization: String,
    raw: Vec<u8>,
}

struct Server {
    behavior: Behavior,
    deliveries: Deliveries,
    requests: Mutex<Vec<Seen>>,
    answer: Mutex<Option<(u16, &'static str)>>,
    retry_after: Mutex<Option<&'static str>>,
}

type Shared = Arc<Server>;

/// What recipients get: Gmail removes `Bcc`.
fn without_bcc(mime: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut in_bcc = false;
    let mut in_header = true;
    for line in mime.split_inclusive(|b| *b == b'\n') {
        if in_header {
            if line == b"\r\n" {
                in_header = false;
            } else if line.starts_with(b" ") || line.starts_with(b"\t") {
                if in_bcc {
                    continue;
                }
            } else {
                in_bcc = line.len() >= 4 && line[..4].eq_ignore_ascii_case(b"bcc:");
                if in_bcc {
                    continue;
                }
            }
        }
        out.extend_from_slice(line);
    }
    out
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

fn google_error(status: u16, reason: &str) -> Response {
    (
        StatusCode::from_u16(status).unwrap(),
        axum::Json(serde_json::json!({
            "error": {"code": status, "message": "refused by the fake", "errors": [{"reason": reason}]}
        })),
    )
        .into_response()
}

fn authorized(headers: &HeaderMap) -> bool {
    headers.get("authorization").and_then(|v| v.to_str().ok()) == Some(&format!("Bearer {TOKEN}"))
}

async fn send(
    State(server): State<Shared>,
    uri: OriginalUri,
    headers: HeaderMap,
    body: String,
) -> Response {
    let json: serde_json::Value = serde_json::from_str(&body).expect("json body");
    let raw = URL_SAFE
        .decode(json["raw"].as_str().expect("raw"))
        .expect("base64url");
    server.requests.lock().unwrap().push(Seen {
        path: uri.path().to_owned(),
        authorization: headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned(),
        raw: raw.clone(),
    });
    if !authorized(&headers) {
        return google_error(401, "authError");
    }
    if let Some((status, reason)) = *server.answer.lock().unwrap() {
        let mut response = google_error(status, reason);
        if let Some(wait) = *server.retry_after.lock().unwrap() {
            response
                .headers_mut()
                .insert("retry-after", wait.parse().unwrap());
        }
        return response;
    }
    let recipients = header_recipients(&raw);
    match &server.behavior {
        Behavior::RefuseRecipient(r) if recipients.contains(r) => {
            return google_error(400, "invalidArgument");
        }
        Behavior::TemporaryFailure => return google_error(429, "rateLimitExceeded"),
        Behavior::PermanentFailure => return google_error(403, "forbidden"),
        _ => {}
    }
    server.deliveries.push(Delivery {
        mail_from: String::new(),
        recipients,
        bytes: without_bcc(&raw),
    });
    if server.behavior == Behavior::DropAfterData {
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
    axum::Json(serde_json::json!({"id": "m1", "threadId": "t1", "labelIds": ["SENT"]}))
        .into_response()
}

async fn profile(headers: HeaderMap) -> Response {
    if !authorized(&headers) {
        return google_error(401, "authError");
    }
    axum::Json(serde_json::json!({"emailAddress": ADA, "historyId": "1"})).into_response()
}

async fn start(behavior: Behavior) -> (u16, Shared) {
    let server = Arc::new(Server {
        behavior,
        deliveries: Deliveries::default(),
        requests: Mutex::new(Vec::new()),
        answer: Mutex::new(None),
        retry_after: Mutex::new(None),
    });
    let app = Router::new()
        .route("/gmail/v1/users/{user}/messages/send", post(send))
        .route("/gmail/v1/users/{user}/profile", get(profile))
        .with_state(server.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await });
    (port, server)
}

fn settings(port: u16) -> GmailSendSettings {
    GmailSendSettings {
        api_url: format!("http://127.0.0.1:{port}"),
        ..GmailSendSettings::default()
    }
}

fn token() -> Credentials {
    Credentials::AccessToken {
        token: TOKEN.into(),
    }
}

struct GmailReceiver;

#[async_trait]
impl Receiver for GmailReceiver {
    async fn start(&self, behavior: Behavior) -> Fake {
        let max_size = match behavior {
            Behavior::SizeLimit(n) => Some(n),
            _ => None,
        };
        let (port, server) = start(behavior).await;
        let sender = GmailSender::new(
            GmailSendSettings {
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
    conformance(&GmailReceiver).await;
}

const MESSAGE: &[u8] =
    b"From: Ada <ada@example.com>\r\nTo: Bob <bob@example.org>\r\nSubject: Hi\r\n\r\nHello\r\n";

#[tokio::test]
async fn sends_raw_with_the_token_and_a_bcc_field() {
    let (port, server) = start(Behavior::AcceptAll).await;
    let sender = GmailSender::new(settings(port), token()).unwrap();
    assert!(sender.saves_to_sent());
    assert_eq!(sender.check().await.unwrap().max_size, Some(MAX_SIZE));
    let report = sender
        .send(&Envelope::new(ADA, vec![BOB.into(), CAROL.into()]), MESSAGE)
        .await
        .unwrap();
    assert_eq!(report.provider_message_id.as_deref(), Some("m1"));
    assert_eq!(report.message_id, None, "Gmail keeps the Message-ID");
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests[0].path, "/gmail/v1/users/me/messages/send");
    assert_eq!(requests[0].authorization, format!("Bearer {TOKEN}"));
    let mut expected = format!("Bcc: {CAROL}\r\n").into_bytes();
    expected.extend_from_slice(MESSAGE);
    assert_eq!(requests[0].raw, expected, "only a Bcc field is added");
    assert_eq!(server.deliveries.all()[0].bytes, MESSAGE);
}

type Case = (u16, &'static str, fn(&SendError) -> bool);

#[tokio::test]
async fn maps_gmail_answers() {
    let cases: [Case; 7] = [
        (401, "authError", |e| matches!(e, SendError::Auth(_))),
        (403, "insufficientPermissions", |e| {
            matches!(e, SendError::Auth(_))
        }),
        (403, "userRateLimitExceeded", |e| {
            matches!(e, SendError::Throttled { retry_after: None })
        }),
        (429, "rateLimitExceeded", |e| e.is_retryable()),
        (500, "backendError", |e| e.may_have_been_sent()),
        (413, "", |e| matches!(e, SendError::TooLarge { .. })),
        (400, "failedPrecondition", |e| {
            matches!(
                e,
                SendError::Refused {
                    permanent: true,
                    ..
                }
            )
        }),
    ];
    for (status, reason, expect) in cases {
        let (port, server) = start(Behavior::AcceptAll).await;
        *server.answer.lock().unwrap() = Some((status, reason));
        let error = GmailSender::new(settings(port), token())
            .unwrap()
            .send(&Envelope::new(ADA, vec![BOB.into()]), MESSAGE)
            .await
            .unwrap_err();
        assert!(expect(&error), "{status} {reason} mapped to {error:?}");
        assert!(server.deliveries.all().is_empty());
    }
}

#[tokio::test]
async fn throttling_carries_the_requested_wait() {
    let cases = [
        (429, "rateLimitExceeded", Some("30"), Some(30)),
        (503, "RATE_LIMIT_EXCEEDED", Some(" 7 "), Some(7)),
        (
            429,
            "rateLimitExceeded",
            Some("Wed, 21 Oct 2026 07:28:00 GMT"),
            None,
        ),
        (429, "rateLimitExceeded", None, None),
    ];
    for (status, reason, header, expect) in cases {
        let (port, server) = start(Behavior::AcceptAll).await;
        *server.answer.lock().unwrap() = Some((status, reason));
        *server.retry_after.lock().unwrap() = header;
        let error = GmailSender::new(settings(port), token())
            .unwrap()
            .send(&Envelope::new(ADA, vec![BOB.into()]), MESSAGE)
            .await
            .unwrap_err();
        assert!(
            matches!(error, SendError::Throttled { .. }),
            "{status} mapped to {error:?}"
        );
        assert!(!error.may_have_been_sent());
        assert_eq!(error.retry_after(), expect.map(Duration::from_secs));
    }
}

#[tokio::test]
async fn an_unreachable_api_is_not_sent() {
    let unused = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = unused.local_addr().unwrap().port();
    drop(unused);
    let error = GmailSender::new(settings(port), token())
        .unwrap()
        .send(&Envelope::new(ADA, vec![BOB.into()]), MESSAGE)
        .await
        .unwrap_err();
    assert!(matches!(error, SendError::Unavailable(_)), "{error:?}");
}

#[test]
fn refuses_unsafe_settings_and_hides_the_token() {
    let password = Credentials::Password { secret: "x".into() };
    assert!(GmailSender::new(GmailSendSettings::default(), password).is_err());
    for url in [
        "http://gmail.example.com",
        "file:///etc",
        "https://u:p@gmail.googleapis.com",
    ] {
        let s = GmailSendSettings {
            api_url: url.into(),
            ..GmailSendSettings::default()
        };
        assert!(GmailSender::new(s, token()).is_err(), "{url}");
    }
    for user in ["", "a/b", "..", "a b"] {
        let s = GmailSendSettings {
            user: user.into(),
            ..GmailSendSettings::default()
        };
        assert!(GmailSender::new(s, token()).is_err(), "{user:?}");
    }
    let sender = GmailSender::new(GmailSendSettings::default(), token()).unwrap();
    assert!(!format!("{sender:?}").contains("ya29"));
    let parsed = GmailSendSettings::from_json(&serde_json::json!({"user": "me"})).unwrap();
    assert_eq!(parsed, GmailSendSettings::default());
}
