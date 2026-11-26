use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use skein_send::testing::{Behavior, Deliveries, Delivery, Fake, Profile, Receiver, conformance};

use super::*;

const KEY_ID: &str = "AKIDEXAMPLESKEIN";
const SECRET: &str = "ses-secret/EXAMPLE+key";
const TOKEN: &str = "session-token-EXAMPLE";
const REGION: &str = "eu-west-1";
const ADA: &str = "ada@example.com";
const BOB: &str = "bob@example.org";
const CAROL: &str = "carol@example.org";
const MESSAGE: &[u8] =
    b"From: Ada <ada@example.com>\r\nTo: Bob <bob@example.org>\r\nSubject: Hi\r\n\r\nHello\r\n";

#[derive(Clone)]
enum Answer {
    Header(u16, String),
    Body(u16, serde_json::Value),
}

struct Seen {
    signed: bool,
    token: Option<String>,
    body: serde_json::Value,
}

struct Server {
    behavior: Behavior,
    deliveries: Deliveries,
    seen: Mutex<Vec<Seen>>,
    answer: Mutex<Option<(Answer, Option<u64>)>>,
    account: Mutex<serde_json::Value>,
}

type Shared = Arc<Server>;

/// Recomputes the signature from the request as it arrived, so a mismatch between what was
/// signed and what went on the wire fails.
fn signature_holds(method: &Method, uri: &Uri, headers: &HeaderMap, body: &[u8]) -> bool {
    let Some(authorization) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let field = |name: &str| {
        authorization
            .split([' ', ','])
            .find_map(|part| part.strip_prefix(name))
            .unwrap_or_default()
            .to_owned()
    };
    let credential = field("Credential=");
    let mut scope = credential.split('/');
    let (Some(id), Some(_), Some(region), Some("ses"), Some("aws4_request")) = (
        scope.next(),
        scope.next(),
        scope.next(),
        scope.next(),
        scope.next(),
    ) else {
        return false;
    };
    if id != KEY_ID || region != REGION {
        return false;
    }
    let signed: Vec<(String, String)> = field("SignedHeaders=")
        .split(';')
        .map(|name| {
            let value = headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            (name.to_owned(), value.to_owned())
        })
        .collect();
    if !signed.iter().any(|(n, _)| n == "host") || !signed.iter().any(|(n, _)| n == "x-amz-date") {
        return false;
    }
    let amz_date = headers
        .get("x-amz-date")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if amz_date.len() != 16 {
        return false;
    }
    let key = sigv4::Key {
        id: KEY_ID.into(),
        secret: SECRET.into(),
        session_token: None,
    };
    let expected = sigv4::authorization(
        &key,
        REGION,
        "ses",
        amz_date,
        &sigv4::Request {
            method: method.as_str(),
            path: uri.path(),
            query: uri.query().unwrap_or_default(),
            headers: &signed,
            payload: body,
        },
    );
    expected == authorization
}

fn error(answer: &Answer, retry: Option<u64>) -> Response {
    let mut response = match answer {
        Answer::Header(status, code) => {
            let mut r = (
                StatusCode::from_u16(*status).unwrap(),
                axum::Json(
                    serde_json::json!({"message": "refused by the fake for bob@example.org"}),
                ),
            )
                .into_response();
            r.headers_mut().insert(
                "x-amzn-errortype",
                format!("{code}:http://internal.amazon.com/coral/com.amazonaws.sesv2/")
                    .parse()
                    .unwrap(),
            );
            r
        }
        Answer::Body(status, body) => (
            StatusCode::from_u16(*status).unwrap(),
            axum::Json(body.clone()),
        )
            .into_response(),
    };
    if let Some(seconds) = retry {
        response
            .headers_mut()
            .insert("retry-after", seconds.to_string().parse().unwrap());
    }
    response
}

fn ses_error(status: u16, code: &str) -> Response {
    error(&Answer::Header(status, code.into()), None)
}

async fn outbound(
    State(server): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let signed = signature_holds(&method, &uri, &headers, &body);
    let request: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    server.seen.lock().unwrap().push(Seen {
        signed,
        token: headers
            .get("x-amz-security-token")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
        body: request.clone(),
    });
    if !signed {
        return ses_error(403, "InvalidSignatureException");
    }
    if headers.get("content-type").and_then(|v| v.to_str().ok()) != Some("application/json") {
        return ses_error(400, "BadRequestException");
    }
    if let Some((answer, retry)) = server.answer.lock().unwrap().clone() {
        return error(&answer, retry);
    }
    let recipients: Vec<String> = request
        .pointer("/Destination/ToAddresses")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let Some(bytes) = request
        .pointer("/Content/Raw/Data")
        .and_then(|v| v.as_str())
        .and_then(|d| BASE64.decode(d).ok())
    else {
        return ses_error(400, "BadRequestException");
    };
    match &server.behavior {
        Behavior::RefuseRecipient(r) if recipients.contains(r) => {
            return ses_error(400, "MessageRejected");
        }
        Behavior::TemporaryFailure => {
            return error(
                &Answer::Header(429, "TooManyRequestsException".into()),
                Some(3),
            );
        }
        Behavior::PermanentFailure => return ses_error(400, "MessageRejected"),
        _ => {}
    }
    server.deliveries.push(Delivery {
        mail_from: request
            .get("FromEmailAddress")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned(),
        recipients,
        bytes,
    });
    if server.behavior == Behavior::DropAfterData {
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
    axum::Json(serde_json::json!({"MessageId": "0100018c-example-message-id"})).into_response()
}

async fn account(
    State(server): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !signature_holds(&method, &uri, &headers, &body) {
        return ses_error(403, "InvalidSignatureException");
    }
    if let Some((answer, retry)) = server.answer.lock().unwrap().clone() {
        return error(&answer, retry);
    }
    axum::Json(server.account.lock().unwrap().clone()).into_response()
}

async fn start(behavior: Behavior) -> (u16, Shared) {
    let server = Arc::new(Server {
        behavior,
        deliveries: Deliveries::default(),
        seen: Mutex::new(Vec::new()),
        answer: Mutex::new(None),
        account: Mutex::new(serde_json::json!({
            "SendingEnabled": true,
            "EnforcementStatus": "HEALTHY",
            "ProductionAccessEnabled": true,
            "SendQuota": {"Max24HourSend": 50000.0, "MaxSendRate": 14.0, "SentLast24Hours": 0.0}
        })),
    });
    let app = Router::new()
        .route(SEND_PATH, post(outbound))
        .route(ACCOUNT_PATH, get(account))
        .with_state(server.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await });
    (port, server)
}

fn settings(port: u16) -> SesSettings {
    SesSettings {
        region: REGION.into(),
        endpoint: Some(format!("http://127.0.0.1:{port}")),
        ..SesSettings::default()
    }
}

fn access_key() -> Credentials {
    Credentials::AccessKey {
        id: KEY_ID.into(),
        secret: SECRET.into(),
        session_token: None,
    }
}

struct SesReceiver;

#[async_trait]
impl Receiver for SesReceiver {
    async fn start(&self, behavior: Behavior) -> Fake {
        let max_size = match behavior {
            Behavior::SizeLimit(n) => Some(n),
            _ => None,
        };
        let (port, server) = start(behavior).await;
        let sender = SesSender::new(
            SesSettings {
                max_size,
                ..settings(port)
            },
            access_key(),
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
        Profile {
            return_path: true,
            per_recipient: false,
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn keeps_the_send_contract() {
    conformance(&SesReceiver).await;
}

struct NamedDomainReceiver;

#[async_trait]
impl Receiver for NamedDomainReceiver {
    async fn start(&self, behavior: Behavior) -> Fake {
        let max_size = match behavior {
            Behavior::SizeLimit(n) => Some(n),
            _ => None,
        };
        let (port, server) = start(behavior).await;
        let sender = SesSender::new(
            SesSettings {
                max_size,
                message_id_domain: Some("ses.example.net".into()),
                ..settings(port)
            },
            access_key(),
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
        SesReceiver.profile()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn keeps_the_send_contract_while_reporting_the_delivered_id() {
    conformance(&NamedDomainReceiver).await;
}

#[test]
fn derives_the_message_id_domain_from_the_region_on_aws_only() {
    let domain = |region: &str, endpoint: Option<&str>, named: Option<&str>| {
        SesSender::new(
            SesSettings {
                region: region.into(),
                endpoint: endpoint.map(str::to_owned),
                message_id_domain: named.map(str::to_owned),
                ..SesSettings::default()
            },
            access_key(),
        )
        .map(|s| s.message_id_domain)
    };
    assert_eq!(
        domain("us-east-1", None, None).unwrap().as_deref(),
        Some("email.amazonses.com")
    );
    assert_eq!(
        domain("eu-west-1", None, None).unwrap().as_deref(),
        Some("eu-west-1.amazonses.com")
    );
    assert_eq!(
        domain(
            "us-west-2",
            Some("https://email-fips.us-west-2.amazonaws.com"),
            None
        )
        .unwrap()
        .as_deref(),
        Some("us-west-2.amazonses.com")
    );
    assert_eq!(
        domain("eu-west-1", Some("https://ses.example.com"), None).unwrap(),
        None,
        "a compatible service's domain is unknown"
    );
    assert_eq!(
        domain(
            "eu-west-1",
            Some("https://ses.example.com"),
            Some(" Mail.Example.NET ")
        )
        .unwrap()
        .as_deref(),
        Some("mail.example.net")
    );
    assert_eq!(
        domain("eu-west-1", None, Some("ses.example.net"))
            .unwrap()
            .as_deref(),
        Some("ses.example.net")
    );
    for bad in [
        "",
        "-ses.example.net",
        "ses..example.net",
        "ses.example.net.",
        "ses example.net",
        "ses.example.net>\r\nBcc: x",
        "a@b",
    ] {
        assert!(domain("eu-west-1", None, Some(bad)).is_err(), "{bad:?}");
    }
}

#[tokio::test]
async fn reports_the_message_id_ses_delivers() {
    let (port, _server) = start(Behavior::AcceptAll).await;
    let envelope = Envelope::new(ADA, vec![BOB.into()]);
    let unnamed = SesSender::new(settings(port), access_key()).unwrap();
    let report = unnamed.send(&envelope, MESSAGE).await.unwrap();
    assert_eq!(
        report.provider_message_id.as_deref(),
        Some("0100018c-example-message-id")
    );
    assert_eq!(
        report.message_id, None,
        "a custom endpoint without a domain reports no delivered Message-ID"
    );

    let named = SesSender::new(
        SesSettings {
            message_id_domain: Some("eu-west-1.amazonses.com".into()),
            ..settings(port)
        },
        access_key(),
    )
    .unwrap();
    let report = named.send(&envelope, MESSAGE).await.unwrap();
    assert_eq!(
        report.message_id.as_deref(),
        Some("<0100018c-example-message-id@eu-west-1.amazonses.com>")
    );
    assert_eq!(
        report.provider_message_id.as_deref(),
        Some("0100018c-example-message-id")
    );
}

#[test]
fn ignores_a_message_id_answer_it_cannot_use() {
    let sender = SesSender::new(
        SesSettings {
            region: REGION.into(),
            ..SesSettings::default()
        },
        access_key(),
    )
    .unwrap();
    let envelope = Envelope::new(ADA, vec![BOB.into()]);
    for body in [
        &b""[..],
        b"{}",
        b"not json",
        br#"{"MessageId": ""}"#,
        br#"{"MessageId": "a b"}"#,
        br#"{"MessageId": "a>\r\nBcc: x"}"#,
        br#"{"MessageId": "a@b"}"#,
    ] {
        let report = sender.report(&envelope, body);
        assert_eq!(report.recipients.len(), 1);
        assert_eq!(report.message_id, None, "{body:?}");
        assert_eq!(report.provider_message_id, None, "{body:?}");
    }
    let report = sender.report(&envelope, br#"{"MessageId": "0102-abc-000000"}"#);
    assert_eq!(
        report.message_id.as_deref(),
        Some("<0102-abc-000000@eu-west-1.amazonses.com>")
    );
}

#[tokio::test]
async fn sends_raw_bytes_with_the_envelope_and_a_valid_signature() {
    let (port, server) = start(Behavior::AcceptAll).await;
    let sender = SesSender::new(
        SesSettings {
            configuration_set: Some("transactional".into()),
            from_identity_arn: Some(
                "arn:aws:ses:eu-west-1:123456789012:identity/example.com".into(),
            ),
            ..settings(port)
        },
        Credentials::AccessKey {
            id: KEY_ID.into(),
            secret: SECRET.into(),
            session_token: Some(TOKEN.into()),
        },
    )
    .unwrap();
    assert!(!sender.saves_to_sent());
    let limits = sender.check().await.unwrap();
    assert_eq!(limits.max_size, Some(MAX_SIZE));
    let envelope = Envelope::new(ADA, vec![BOB.into(), CAROL.into()]);
    let report = sender.send(&envelope, MESSAGE).await.unwrap();
    assert_eq!(report.refused().count(), 0);
    assert_eq!(report.recipients.len(), 2);

    let seen = server.seen.lock().unwrap();
    let last = seen.last().unwrap();
    assert!(last.signed);
    assert_eq!(last.token.as_deref(), Some(TOKEN));
    assert_eq!(
        last.body,
        serde_json::json!({
            "FromEmailAddress": ADA,
            "FromEmailAddressIdentityArn": "arn:aws:ses:eu-west-1:123456789012:identity/example.com",
            "Destination": {"ToAddresses": [BOB, CAROL]},
            "Content": {"Raw": {"Data": BASE64.encode(MESSAGE)}},
            "ConfigurationSetName": "transactional",
        })
    );
    let delivered = server.deliveries.all();
    assert_eq!(delivered[0].bytes, MESSAGE, "no Bcc field is added");
}

#[tokio::test]
async fn a_wrong_secret_is_an_auth_failure() {
    let (port, server) = start(Behavior::AcceptAll).await;
    let sender = SesSender::new(
        settings(port),
        Credentials::AccessKey {
            id: KEY_ID.into(),
            secret: "another-secret".into(),
            session_token: None,
        },
    )
    .unwrap();
    let error = sender
        .send(&Envelope::new(ADA, vec![BOB.into()]), MESSAGE)
        .await
        .unwrap_err();
    assert!(matches!(error, SendError::Auth(_)), "{error:?}");
    assert!(!error.may_have_been_sent());
    assert!(!server.seen.lock().unwrap()[0].signed);
    assert!(matches!(sender.check().await, Err(SendError::Auth(_))));
    assert!(server.deliveries.all().is_empty());
}

type Case = (Answer, Option<u64>, fn(&SendError) -> bool);

fn header(status: u16, code: &str) -> Answer {
    Answer::Header(status, code.into())
}

#[tokio::test]
async fn maps_ses_answers() {
    let not_sent_config = |e: &SendError| matches!(e, SendError::Invalid(_)) && !e.is_retryable();
    let auth = |e: &SendError| matches!(e, SendError::Auth(_));
    let cases: Vec<Case> = vec![
        (header(429, "TooManyRequestsException"), Some(30), |e| {
            e.retry_after() == Some(Duration::from_secs(30)) && !e.may_have_been_sent()
        }),
        (header(429, "TooManyRequestsException"), None, |e| {
            matches!(e, SendError::Throttled { retry_after: None })
        }),
        (header(400, "ThrottlingException"), None, |e| {
            matches!(e, SendError::Throttled { .. })
        }),
        (header(400, "LimitExceededException"), None, |e| {
            matches!(e, SendError::Throttled { .. }) && e.is_retryable()
        }),
        (header(400, "MessageRejected"), None, |e| {
            matches!(e, SendError::Refused { permanent: true, code: 554, text } if text.starts_with("MessageRejected"))
                && !e.may_have_been_sent()
        }),
        (
            header(400, "MailFromDomainNotVerifiedException"),
            None,
            not_sent_config,
        ),
        (
            header(400, "AccountSuspendedException"),
            None,
            not_sent_config,
        ),
        (header(400, "SendingPausedException"), None, not_sent_config),
        (header(404, "NotFoundException"), None, not_sent_config),
        (header(403, "OptInRequired"), None, not_sent_config),
        (header(400, "BadRequestException"), None, |e| {
            matches!(
                e,
                SendError::Refused {
                    permanent: true,
                    ..
                }
            ) && !e.is_retryable()
        }),
        (header(403, "UnrecognizedClientException"), None, auth),
        (header(403, "InvalidSignatureException"), None, auth),
        (header(403, "SignatureDoesNotMatch"), None, auth),
        (header(403, "ExpiredTokenException"), None, auth),
        (header(403, "AccessDeniedException"), None, auth),
        (header(413, "RequestEntityTooLargeException"), None, |e| {
            matches!(e, SendError::TooLarge { .. })
        }),
        (header(408, "RequestTimeoutException"), None, |e| {
            matches!(e, SendError::Temporary(_)) && !e.may_have_been_sent()
        }),
        (header(500, "InternalFailure"), None, |e| {
            e.may_have_been_sent()
        }),
        (header(503, "ServiceUnavailable"), None, |e| {
            e.may_have_been_sent()
        }),
        (
            Answer::Body(
                400,
                serde_json::json!({"__type": "com.amazonaws.sesv2#MessageRejected", "message": "x"}),
            ),
            None,
            |e| matches!(e, SendError::Refused { code: 554, .. }),
        ),
        (
            Answer::Body(400, serde_json::json!({"code": "SendingPausedException"})),
            None,
            not_sent_config,
        ),
        (Answer::Body(429, serde_json::json!({})), None, |e| {
            matches!(e, SendError::Throttled { .. })
        }),
        (Answer::Body(502, serde_json::json!({})), None, |e| {
            e.may_have_been_sent()
        }),
        (Answer::Body(401, serde_json::json!({})), None, auth),
        (Answer::Body(422, serde_json::json!({})), None, |e| {
            matches!(
                e,
                SendError::Refused {
                    permanent: true,
                    ..
                }
            )
        }),
    ];
    for (answer, retry, expect) in cases {
        let (port, server) = start(Behavior::AcceptAll).await;
        *server.answer.lock().unwrap() = Some((answer.clone(), retry));
        let error = SesSender::new(settings(port), access_key())
            .unwrap()
            .send(&Envelope::new(ADA, vec![BOB.into()]), MESSAGE)
            .await
            .unwrap_err();
        let shown = match &answer {
            Answer::Header(s, c) => format!("{s} {c}"),
            Answer::Body(s, b) => format!("{s} {b}"),
        };
        assert!(expect(&error), "{shown} mapped to {error:?}");
        assert!(
            !error.to_string().contains("bob@example.org"),
            "{shown}: an address reached the error text"
        );
    }
}

#[tokio::test]
async fn check_reports_a_paused_account_and_never_maps_to_uncertain() {
    let (port, server) = start(Behavior::AcceptAll).await;
    let sender = SesSender::new(settings(port), access_key()).unwrap();
    *server.account.lock().unwrap() = serde_json::json!({"SendingEnabled": false});
    assert!(matches!(sender.check().await, Err(SendError::Invalid(_))));
    *server.account.lock().unwrap() =
        serde_json::json!({"SendingEnabled": true, "EnforcementStatus": "SHUTDOWN"});
    assert!(matches!(sender.check().await, Err(SendError::Invalid(_))));
    *server.answer.lock().unwrap() = Some((header(500, "InternalFailure"), None));
    assert!(matches!(
        sender.check().await,
        Err(SendError::Unavailable(_))
    ));
    assert!(server.seen.lock().unwrap().is_empty(), "check sent nothing");
}

#[tokio::test]
async fn refuses_what_ses_cannot_take_before_sending() {
    let (port, server) = start(Behavior::AcceptAll).await;
    let sender = SesSender::new(
        SesSettings {
            max_size: Some(MESSAGE.len() as u64 - 1),
            ..settings(port)
        },
        access_key(),
    )
    .unwrap();
    let error = sender
        .send(&Envelope::new(ADA, vec![BOB.into()]), MESSAGE)
        .await
        .unwrap_err();
    assert_eq!(
        error,
        SendError::TooLarge {
            limit: Some(MESSAGE.len() as u64 - 1)
        }
    );

    let sender = SesSender::new(settings(port), access_key()).unwrap();
    let many: Vec<String> = (0..=MAX_RECIPIENTS)
        .map(|n| format!("r{n}@example.org"))
        .collect();
    assert!(matches!(
        sender.send(&Envelope::new(ADA, many), MESSAGE).await,
        Err(SendError::Invalid(_))
    ));
    assert!(matches!(
        sender
            .send(
                &Envelope::new(ADA, vec!["b\u{f6}b@example.org".into()]),
                MESSAGE
            )
            .await,
        Err(SendError::Invalid(_))
    ));
    assert!(server.seen.lock().unwrap().is_empty());
    assert!(
        SesSender::new(
            SesSettings {
                max_size: Some(u64::MAX),
                ..settings(port)
            },
            access_key()
        )
        .unwrap()
        .max_size
            == MAX_SIZE
    );
}

#[tokio::test]
async fn an_unreachable_endpoint_is_not_sent() {
    let unused = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = unused.local_addr().unwrap().port();
    drop(unused);
    let error = SesSender::new(settings(port), access_key())
        .unwrap()
        .send(&Envelope::new(ADA, vec![BOB.into()]), MESSAGE)
        .await
        .unwrap_err();
    assert!(matches!(error, SendError::Unavailable(_)), "{error:?}");
    assert!(error.is_retryable());
}

#[test]
fn refuses_unsafe_settings_and_hides_the_key() {
    let with = |s: SesSettings| SesSender::new(s, access_key());
    let base = SesSettings {
        region: REGION.into(),
        ..SesSettings::default()
    };
    let ok = with(base.clone()).unwrap();
    assert_eq!(ok.origin.as_str(), "https://email.eu-west-1.amazonaws.com/");
    assert_eq!(ok.host, "email.eu-west-1.amazonaws.com");
    for region in [
        "",
        "EU-WEST-1",
        "eu-west-1.evil.example",
        "eu west",
        "-eu",
        "eu-",
    ] {
        assert!(
            with(SesSettings {
                region: region.into(),
                ..base.clone()
            })
            .is_err(),
            "{region:?}"
        );
    }
    for endpoint in [
        "http://ses.example.com",
        "ftp://ses.example.com",
        "https://user:pass@ses.example.com",
        "https://ses.example.com/v2",
        "https://ses.example.com/?a=b",
        "not a url",
    ] {
        assert!(
            with(SesSettings {
                endpoint: Some(endpoint.into()),
                ..base.clone()
            })
            .is_err(),
            "{endpoint}"
        );
    }
    let local = with(SesSettings {
        endpoint: Some("http://localhost:4566".into()),
        ..base.clone()
    })
    .unwrap();
    assert_eq!(local.host, "localhost:4566");
    assert!(
        with(SesSettings {
            configuration_set: Some(" ".into()),
            ..base.clone()
        })
        .is_err()
    );
    assert!(
        with(SesSettings {
            max_size: Some(0),
            ..base.clone()
        })
        .is_err()
    );
    for credentials in [
        Credentials::Password { secret: "x".into() },
        Credentials::AccessToken { token: "t".into() },
        Credentials::AccessKey {
            id: "AKID EXAMPLE".into(),
            secret: SECRET.into(),
            session_token: None,
        },
        Credentials::AccessKey {
            id: KEY_ID.into(),
            secret: String::new(),
            session_token: None,
        },
        Credentials::AccessKey {
            id: KEY_ID.into(),
            secret: SECRET.into(),
            session_token: Some("a\nb".into()),
        },
    ] {
        assert!(SesSender::new(base.clone(), credentials).is_err());
    }
    let shown = format!("{ok:?}");
    assert!(!shown.contains(KEY_ID) && !shown.contains(SECRET));
    let parsed = SesSettings::from_json(&serde_json::json!({
        "region": "us-east-1",
        "configuration_set": "default",
        "other": 1
    }))
    .unwrap();
    assert_eq!(parsed.region, "us-east-1");
    assert_eq!(parsed.configuration_set.as_deref(), Some("default"));
    assert!(SesSettings::from_json(&serde_json::json!({})).is_err());
}

#[test]
fn parses_error_codes_from_headers_and_bodies() {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        "x-amzn-errortype",
        "MessageRejected:http://internal.amazon.com/coral/com.amazonaws.sesv2/"
            .parse()
            .unwrap(),
    );
    let f = error::parse_failure(StatusCode::BAD_REQUEST, &headers, b"{\"message\":\"no\"}");
    assert_eq!(
        (f.code.as_str(), f.message.as_str()),
        ("MessageRejected", "no")
    );
    let f = error::parse_failure(
        StatusCode::BAD_REQUEST,
        &reqwest::header::HeaderMap::new(),
        br#"{"__type":"com.amazonaws.sesv2#AccountSuspendedException","Message":"x"}"#,
    );
    assert_eq!(f.code, "AccountSuspendedException");
    let f = error::parse_failure(
        StatusCode::BAD_GATEWAY,
        &reqwest::header::HeaderMap::new(),
        b"<html>",
    );
    assert!(f.code.is_empty() && f.message.is_empty());
}
