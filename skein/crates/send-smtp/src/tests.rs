use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use skein_core::tls::testing::TestCa;
use skein_core::{Credentials, Dsn, DsnNotify, DsnReturn};
use skein_send::testing::{Behavior, Deliveries, Delivery, Fake, Receiver, conformance};
use skein_send::{Envelope, RecipientOutcome, SendError, Sender};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::{Security, SmtpSender, SmtpSettings};

const MESSAGE: &[u8] =
    b"From: Ada <ada@example.com>\r\nTo: Bob <bob@example.org>\r\nSubject: Hi\r\n\r\nHello\r\n";

fn envelope() -> Envelope {
    Envelope::new("ada@example.com", vec!["bob@example.org".into()])
}

fn plain(port: u16) -> SmtpSettings {
    SmtpSettings {
        port: Some(port),
        security: Security::Plain,
        ..SmtpSettings::new("127.0.0.1")
    }
}

fn sender(settings: SmtpSettings, credentials: Option<Credentials>) -> SmtpSender {
    SmtpSender::new(settings, credentials)
        .expect("settings")
        .with_timeouts(Duration::from_secs(5), Duration::from_secs(5))
}

fn password(p: &str) -> Option<Credentials> {
    Some(Credentials::Password { secret: p.into() })
}

#[derive(Clone, Copy)]
enum OnDot {
    Reply(&'static str),
    Drop,
    Hang,
}

#[derive(Clone)]
struct Script {
    greeting: &'static str,
    extensions: Vec<String>,
    login: Option<(&'static str, &'static str)>,
    plain: Option<(&'static str, &'static str)>,
    xoauth2: Option<String>,
    refuse: Option<String>,
    max_size: Option<usize>,
    close_on_data: bool,
    on_dot: OnDot,
    tls: Option<TlsAcceptor>,
    starttls: Option<TlsAcceptor>,
}

impl Script {
    fn new() -> Self {
        Self {
            greeting: "220 fake.example.org ESMTP",
            extensions: vec!["8BITMIME".into()],
            login: None,
            plain: None,
            xoauth2: None,
            refuse: None,
            max_size: None,
            close_on_data: false,
            on_dot: OnDot::Reply("250 2.0.0 queued"),
            tls: None,
            starttls: None,
        }
    }

    fn with(behavior: Behavior) -> Self {
        let mut script = Self::new();
        match behavior {
            Behavior::AcceptAll => {}
            Behavior::RefuseRecipient(r) => script.refuse = Some(r),
            Behavior::TemporaryFailure => script.on_dot = OnDot::Reply("451 4.3.0 try later"),
            Behavior::PermanentFailure => script.on_dot = OnDot::Reply("554 5.7.1 rejected"),
            Behavior::DropAfterData => script.on_dot = OnDot::Drop,
            Behavior::SizeLimit(n) => {
                script.max_size = Some(n as usize);
                script.extensions.push(format!("SIZE {n}"));
            }
        }
        script
    }
}

#[derive(Clone, Default)]
struct Seen {
    deliveries: Deliveries,
    commands: Arc<Mutex<Vec<String>>>,
}

impl Seen {
    fn commands(&self) -> Vec<String> {
        self.commands.lock().expect("commands").clone()
    }
}

async fn serve(script: Script) -> (u16, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("address").port();
    let seen = Seen::default();
    let shared = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let script = script.clone();
            let seen = shared.clone();
            tokio::spawn(async move {
                match script.tls.clone() {
                    Some(acceptor) => {
                        if let Ok(tls) = acceptor.accept(tcp).await {
                            let mut io = BufReader::new(tls);
                            let _ = session(&mut io, &script, &seen, true).await;
                        }
                    }
                    None => {
                        let mut io = BufReader::new(tcp);
                        if let Ok(Some(())) = session(&mut io, &script, &seen, false).await {
                            let acceptor = script.starttls.clone().expect("acceptor");
                            if let Ok(tls) = acceptor.accept(io.into_inner()).await {
                                let mut io = BufReader::new(tls);
                                let _ = session(&mut io, &script, &seen, true).await;
                            }
                        }
                    }
                }
            });
        }
    });
    (port, seen)
}

async fn read_line<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut BufReader<S>,
) -> std::io::Result<Option<String>> {
    let mut line = String::new();
    if io.read_line(&mut line).await? == 0 {
        return Ok(None);
    }
    Ok(Some(line.trim_end_matches(['\r', '\n']).to_owned()))
}

async fn say<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut BufReader<S>,
    line: &str,
) -> std::io::Result<()> {
    io.get_mut()
        .write_all(format!("{line}\r\n").as_bytes())
        .await?;
    io.get_mut().flush().await
}

/// Runs one SMTP session. `Ok(Some(()))` when the client asked for STARTTLS and the caller
/// should continue over TLS.
async fn session<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut BufReader<S>,
    script: &Script,
    seen: &Seen,
    secure: bool,
) -> std::io::Result<Option<()>> {
    let resumed = secure && script.tls.is_none();
    if !resumed {
        say(io, script.greeting).await?;
    }
    let mut from = String::new();
    let mut recipients = Vec::new();
    while let Some(line) = read_line(io).await? {
        let upper = line.to_ascii_uppercase();
        seen.commands.lock().expect("commands").push(line.clone());
        if upper.starts_with("EHLO") {
            let mut lines = vec!["fake.example.org".to_owned()];
            lines.extend(script.extensions.iter().cloned());
            if script.starttls.is_some() && !secure {
                lines.push("STARTTLS".into());
            }
            let last = lines.len() - 1;
            for (at, text) in lines.iter().enumerate() {
                let sep = if at == last { ' ' } else { '-' };
                say(io, &format!("250{sep}{text}")).await?;
            }
        } else if upper == "STARTTLS" {
            say(io, "220 2.0.0 go ahead").await?;
            return Ok(Some(()));
        } else if let Some(initial) = line.strip_prefix("AUTH PLAIN ") {
            let (user, pass) = script.plain.unwrap_or_default();
            if initial == BASE64.encode(format!("\0{user}\0{pass}")) {
                say(io, "235 2.7.0 OK").await?;
            } else {
                say(io, "535 5.7.8 bad credentials").await?;
            }
        } else if upper == "AUTH LOGIN" {
            let (user, pass) = script.login.unwrap_or_default();
            say(io, "334 VXNlcm5hbWU6").await?;
            let given_user = read_line(io).await?.unwrap_or_default();
            say(io, "334 UGFzc3dvcmQ6").await?;
            let given_pass = read_line(io).await?.unwrap_or_default();
            if given_user == BASE64.encode(user) && given_pass == BASE64.encode(pass) {
                say(io, "235 2.7.0 OK").await?;
            } else {
                say(io, "535 5.7.8 bad credentials").await?;
            }
        } else if let Some(initial) = line.strip_prefix("AUTH XOAUTH2 ") {
            if script.xoauth2.as_deref() == Some(initial) {
                say(io, "235 2.7.0 OK").await?;
            } else {
                say(io, "334 eyJzdGF0dXMiOiI0MDEifQ==").await?;
                read_line(io).await?;
                say(io, "535 5.7.8 bad token").await?;
            }
        } else if upper.starts_with("MAIL FROM:") {
            from = line[11..line.find('>').unwrap_or(11)].to_owned();
            say(io, "250 2.1.0 OK").await?;
        } else if upper.starts_with("RCPT TO:") {
            let address = line[9..line.find('>').unwrap_or(9)].to_owned();
            if script.refuse.as_ref() == Some(&address) {
                say(io, "550 5.1.1 no such user").await?;
            } else {
                recipients.push(address);
                say(io, "250 2.1.5 OK").await?;
            }
        } else if upper == "DATA" {
            if script.close_on_data {
                return Ok(None);
            }
            say(io, "354 go ahead").await?;
            let mut bytes = Vec::new();
            loop {
                let mut raw = Vec::new();
                if io.read_until(b'\n', &mut raw).await? == 0 {
                    return Ok(None);
                }
                if raw == b".\r\n" {
                    break;
                }
                bytes.extend_from_slice(raw.strip_prefix(b".").unwrap_or(&raw));
            }
            if script.max_size.is_some_and(|n| bytes.len() > n) {
                say(io, "552 5.3.4 too big").await?;
                continue;
            }
            let failing = matches!(script.on_dot, OnDot::Reply(r) if !r.starts_with('2'));
            if !failing {
                seen.deliveries.push(Delivery {
                    mail_from: std::mem::take(&mut from),
                    recipients: std::mem::take(&mut recipients),
                    bytes,
                });
            }
            match script.on_dot {
                OnDot::Reply(text) => say(io, text).await?,
                OnDot::Drop => return Ok(None),
                OnDot::Hang => {
                    let mut rest = Vec::new();
                    io.read_to_end(&mut rest).await?;
                    return Ok(None);
                }
            }
        } else if upper == "QUIT" {
            say(io, "221 2.0.0 bye").await?;
            return Ok(None);
        } else if upper == "RSET" {
            from.clear();
            recipients.clear();
            say(io, "250 2.0.0 OK").await?;
        } else {
            say(io, "500 5.5.2 what").await?;
        }
    }
    Ok(None)
}

struct SmtpReceiver;

#[async_trait]
impl Receiver for SmtpReceiver {
    async fn start(&self, behavior: Behavior) -> Fake {
        let (port, seen) = serve(Script::with(behavior)).await;
        Fake {
            sender: Box::new(sender(plain(port), None)),
            deliveries: seen.deliveries,
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn keeps_the_send_contract() {
    conformance(&SmtpReceiver).await;
}

#[tokio::test]
async fn starttls_and_auth_plain_with_a_test_ca() {
    let ca = TestCa::new(&["localhost"]);
    let (port, seen) = serve(Script {
        extensions: vec!["AUTH PLAIN LOGIN".into()],
        plain: Some(("ada", "correct horse")),
        starttls: Some(ca.acceptor()),
        ..Script::new()
    })
    .await;
    let settings = || SmtpSettings {
        port: Some(port),
        security: Security::Starttls,
        username: Some("ada".into()),
        roots: ca.roots(),
        ..SmtpSettings::new("localhost")
    };

    let trusted = sender(settings(), password("correct horse"));
    trusted.check().await.expect("check");
    trusted.send(&envelope(), MESSAGE).await.expect("send");
    assert_eq!(seen.deliveries.all()[0].bytes, MESSAGE);
    let commands = seen.commands();
    let tls_at = commands.iter().position(|c| c == "STARTTLS").unwrap();
    let auth_at = commands.iter().position(|c| c.starts_with("AUTH")).unwrap();
    assert!(tls_at < auth_at, "signed in before STARTTLS");

    let wrong = sender(settings(), password("wrong"));
    assert!(matches!(wrong.check().await, Err(SendError::Auth(_))));

    let untrusted = sender(
        SmtpSettings {
            roots: Default::default(),
            ..settings()
        },
        password("correct horse"),
    );
    assert!(matches!(untrusted.check().await, Err(SendError::Tls(_))));
    let other = TestCa::new(&["localhost"]);
    let wrong_ca = sender(
        SmtpSettings {
            roots: other.roots(),
            ..settings()
        },
        password("correct horse"),
    );
    assert!(matches!(
        wrong_ca.send(&envelope(), MESSAGE).await,
        Err(SendError::Tls(_))
    ));
    assert_eq!(seen.deliveries.all().len(), 1);
}

#[tokio::test]
async fn refuses_a_server_without_starttls() {
    let (port, seen) = serve(Script {
        extensions: vec!["AUTH PLAIN".into()],
        ..Script::new()
    })
    .await;
    let settings = SmtpSettings {
        port: Some(port),
        security: Security::Starttls,
        username: Some("ada".into()),
        ..SmtpSettings::new("localhost")
    };
    assert!(matches!(
        sender(settings, password("secret")).check().await,
        Err(SendError::Insecure(_))
    ));
    assert!(
        !seen.commands().iter().any(|c| c.starts_with("AUTH")),
        "the password went out in plain text"
    );
}

#[tokio::test]
async fn implicit_tls() {
    let ca = TestCa::new(&["localhost"]);
    let (port, seen) = serve(Script {
        tls: Some(ca.acceptor()),
        ..Script::new()
    })
    .await;
    let settings = SmtpSettings {
        port: Some(port),
        roots: ca.roots(),
        ..SmtpSettings::new("localhost")
    };
    sender(settings, None)
        .send(&envelope(), MESSAGE)
        .await
        .expect("send");
    assert_eq!(seen.deliveries.all()[0].bytes, MESSAGE);
}

#[tokio::test]
async fn auth_login_when_plain_is_not_offered() {
    let (port, seen) = serve(Script {
        extensions: vec!["AUTH LOGIN".into()],
        login: Some(("ada", "secret")),
        ..Script::new()
    })
    .await;
    let settings = || SmtpSettings {
        username: Some("ada".into()),
        ..plain(port)
    };
    sender(settings(), password("secret"))
        .check()
        .await
        .expect("login");
    assert!(matches!(
        sender(settings(), password("nope")).check().await,
        Err(SendError::Auth(_))
    ));
    assert!(seen.commands().iter().any(|c| c == "AUTH LOGIN"));
}

#[tokio::test]
async fn auth_xoauth2() {
    let expected = BASE64.encode("user=ada@example.com\x01auth=Bearer token-1\x01\x01");
    let (port, _) = serve(Script {
        extensions: vec!["AUTH PLAIN XOAUTH2".into()],
        xoauth2: Some(expected),
        ..Script::new()
    })
    .await;
    let settings = || SmtpSettings {
        username: Some("ada@example.com".into()),
        ..plain(port)
    };
    let token = |t: &str| Some(Credentials::AccessToken { token: t.into() });
    sender(settings(), token("token-1"))
        .send(&envelope(), MESSAGE)
        .await
        .expect("xoauth2");
    assert!(matches!(
        sender(settings(), token("expired")).check().await,
        Err(SendError::Auth(_))
    ));

    let (port, _) = serve(Script {
        extensions: vec!["AUTH PLAIN".into()],
        ..Script::new()
    })
    .await;
    let settings = SmtpSettings {
        username: Some("ada@example.com".into()),
        ..plain(port)
    };
    assert!(matches!(
        sender(settings, token("token-1")).check().await,
        Err(SendError::Auth(_))
    ));
}

#[tokio::test]
async fn asks_for_dsn_only_when_offered() {
    let mut envelope = envelope();
    envelope.dsn = Some(Dsn {
        notify: vec![DsnNotify::Failure, DsnNotify::Delay],
        ret: Some(DsnReturn::Headers),
    });
    envelope.envid = Some("01JD0000000000000000000000".into());

    let (port, seen) = serve(Script {
        extensions: vec!["8BITMIME".into(), "DSN".into()],
        ..Script::new()
    })
    .await;
    let client = sender(plain(port), None);
    assert!(client.check().await.unwrap().dsn);
    client.send(&envelope, MESSAGE).await.expect("send");
    let commands = seen.commands();
    assert!(
        commands
            .iter()
            .any(|c| c == "MAIL FROM:<ada@example.com> RET=HDRS ENVID=01JD0000000000000000000000"),
        "{commands:?}"
    );
    assert!(
        commands
            .iter()
            .any(|c| c
                == "RCPT TO:<bob@example.org> NOTIFY=FAILURE,DELAY ORCPT=rfc822;bob@example.org"),
        "{commands:?}"
    );

    let (port, seen) = serve(Script::new()).await;
    sender(plain(port), None)
        .send(&envelope, MESSAGE)
        .await
        .expect("send without DSN");
    assert!(
        seen.commands()
            .iter()
            .filter(|c| c.starts_with("MAIL") || c.starts_with("RCPT"))
            .all(|c| !c.contains('=')),
        "DSN parameters sent to a server that does not offer DSN"
    );
}

#[tokio::test]
async fn maps_failures_around_the_session() {
    let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = unused.local_addr().unwrap().port();
    drop(unused);
    assert!(matches!(
        sender(plain(port), None).check().await,
        Err(SendError::Unavailable(_))
    ));

    let (port, _) = serve(Script {
        greeting: "421 4.3.2 shutting down",
        ..Script::new()
    })
    .await;
    let error = sender(plain(port), None)
        .send(&envelope(), MESSAGE)
        .await
        .unwrap_err();
    assert!(matches!(error, SendError::Unavailable(_)), "{error:?}");
    assert_eq!(error.retry_after(), None);

    let (port, _) = serve(Script {
        on_dot: OnDot::Reply("451 4.3.0 try later"),
        ..Script::new()
    })
    .await;
    let error = sender(plain(port), None)
        .send(&envelope(), MESSAGE)
        .await
        .unwrap_err();
    assert!(error.is_retryable(), "{error:?}");
    assert_eq!(error.retry_after(), None);

    let (port, seen) = serve(Script {
        close_on_data: true,
        ..Script::new()
    })
    .await;
    let error = sender(plain(port), None)
        .send(&envelope(), MESSAGE)
        .await
        .unwrap_err();
    assert!(matches!(error, SendError::Temporary(_)), "{error:?}");
    assert!(seen.deliveries.all().is_empty());
}

#[tokio::test]
async fn silence_after_the_message_is_uncertain() {
    let (port, seen) = serve(Script {
        on_dot: OnDot::Hang,
        ..Script::new()
    })
    .await;
    let client = SmtpSender::new(plain(port), None)
        .unwrap()
        .with_timeouts(Duration::from_secs(5), Duration::from_millis(200));
    let error = client.send(&envelope(), MESSAGE).await.unwrap_err();
    assert!(matches!(error, SendError::Uncertain(_)), "{error:?}");
    assert_eq!(seen.deliveries.all().len(), 1);
}

#[tokio::test]
async fn too_large_after_the_message_without_size() {
    let (port, _) = serve(Script {
        on_dot: OnDot::Reply("552 5.3.4 too big"),
        ..Script::new()
    })
    .await;
    assert_eq!(
        sender(plain(port), None).send(&envelope(), MESSAGE).await,
        Err(SendError::TooLarge { limit: None })
    );
}

#[tokio::test]
async fn needs_8bitmime_and_smtputf8_for_such_mail() {
    let eight_bit = "Subject: Hi\r\n\r\nGr\u{fc}\u{df}e\r\n".as_bytes();
    let international = "Subject: Gr\u{fc}\u{df}e\r\n\r\nHi\r\n".as_bytes();

    let (port, _) = serve(Script {
        extensions: vec![],
        ..Script::new()
    })
    .await;
    let bare = sender(plain(port), None);
    assert!(matches!(
        bare.send(&envelope(), eight_bit).await,
        Err(SendError::Invalid(_))
    ));
    assert!(matches!(
        bare.send(&envelope(), international).await,
        Err(SendError::Invalid(_))
    ));
    bare.send(&envelope(), MESSAGE).await.expect("7-bit");

    let (port, seen) = serve(Script {
        extensions: vec!["8BITMIME".into(), "SMTPUTF8".into(), "SIZE 100000".into()],
        ..Script::new()
    })
    .await;
    let full = sender(plain(port), None);
    full.send(&envelope(), eight_bit).await.expect("8-bit");
    let utf8 = Envelope::new("ada@example.com", vec!["j\u{f6}rg@example.org".into()]);
    full.send(&utf8, international).await.expect("SMTPUTF8");
    let mails: Vec<_> = seen
        .commands()
        .into_iter()
        .filter(|c| c.starts_with("MAIL"))
        .collect();
    assert_eq!(
        mails[0],
        format!(
            "MAIL FROM:<ada@example.com> SIZE={} BODY=8BITMIME",
            eight_bit.len()
        )
    );
    assert!(mails[1].ends_with(" SMTPUTF8"), "{}", mails[1]);
}

#[tokio::test]
async fn reports_each_recipient() {
    let (port, _) = serve(Script {
        refuse: Some("nobody@example.org".into()),
        ..Script::new()
    })
    .await;
    let both = Envelope::new(
        "ada@example.com",
        vec!["nobody@example.org".into(), "bob@example.org".into()],
    );
    let report = sender(plain(port), None)
        .send(&both, MESSAGE)
        .await
        .expect("send");
    let RecipientOutcome::Refused(refusal) = &report.recipients[0].outcome else {
        panic!("not refused");
    };
    assert_eq!(refusal.code, 550);
    assert!(refusal.permanent && refusal.text.starts_with("5.1.1"));
    assert_eq!(report.recipients[1].outcome, RecipientOutcome::Accepted);
}

#[test]
fn refuses_unsafe_settings_and_hides_secrets() {
    let open = SmtpSettings {
        security: Security::Plain,
        ..SmtpSettings::new("smtp.example.org")
    };
    assert!(matches!(
        SmtpSender::new(open, None),
        Err(SendError::Insecure(_))
    ));
    for host in ["localhost", "127.0.0.1", "[::1]"] {
        let local = SmtpSettings {
            security: Security::Plain,
            ..SmtpSettings::new(host)
        };
        assert!(SmtpSender::new(local, None).is_ok(), "{host}");
    }
    let half = SmtpSettings {
        username: Some("ada".into()),
        ..SmtpSettings::new("smtp.example.org")
    };
    assert!(SmtpSender::new(half, None).is_err());
    let bad_helo = SmtpSettings {
        helo: Some("a b".into()),
        ..SmtpSettings::new("smtp.example.org")
    };
    assert!(SmtpSender::new(bad_helo, None).is_err());

    let settings = SmtpSettings {
        username: Some("ada@example.com".into()),
        ..SmtpSettings::new("smtp.example.org")
    };
    assert!(!format!("{settings:?}").contains("ada@"));
    let client = SmtpSender::new(settings, password("hunter2")).unwrap();
    assert!(!format!("{client:?}").contains("hunter2"));

    let parsed = SmtpSettings::from_json(&serde_json::json!({
        "host": "smtp.example.org", "security": "starttls", "username": "ada"
    }))
    .unwrap();
    assert_eq!(parsed.port(), 587);
    assert_eq!(SmtpSettings::new("smtp.example.org").port(), 465);
}

#[test]
fn fuzz_entry_reads_replies_until_the_bytes_end_or_one_is_malformed() {
    crate::fuzzing::replies(
        b"220 ready\r\n250-mx.example.org\r\n250-SIZE 0\r\n250-AUTH plain login\r\n250 DSN\r\n",
    );
    crate::fuzzing::replies(b"250-a\r\n251 b\r\n250 after\r\n");
    crate::fuzzing::replies(b"25");
    crate::fuzzing::replies(b"250 no newline");
    crate::fuzzing::replies(b"\xff\xfe\xfd 1\r\n");
    crate::fuzzing::replies(&b"250-x\r\n".repeat(200));
    crate::fuzzing::replies(&[b'5'; 10_000]);
}

#[tokio::test]
async fn probes_without_credentials_over_tls_and_starttls() {
    let ca = TestCa::new(&["localhost"]);
    for (security, script) in [
        (
            Security::Starttls,
            Script {
                extensions: vec!["AUTH PLAIN LOGIN XOAUTH2".into(), "SIZE 1000".into()],
                plain: Some(("ada", "correct horse")),
                starttls: Some(ca.acceptor()),
                ..Script::new()
            },
        ),
        (
            Security::Tls,
            Script {
                extensions: vec!["AUTH PLAIN LOGIN XOAUTH2".into(), "SIZE 1000".into()],
                tls: Some(ca.acceptor()),
                ..Script::new()
            },
        ),
    ] {
        let (port, seen) = serve(script).await;
        let report = crate::probe(
            "localhost",
            port,
            security,
            &ca.roots(),
            Duration::from_secs(5),
        )
        .await
        .expect("probe");
        assert!(report.password_sign_in && report.oauth);
        assert_eq!(report.max_size, Some(1000));
        let commands = seen.commands();
        assert!(
            commands
                .iter()
                .all(|c| c.starts_with("EHLO") || c == "STARTTLS" || c == "QUIT"),
            "{commands:?}"
        );
    }
}

#[tokio::test]
async fn probes_refuse_plain_servers_bad_certificates_and_silence() {
    let ca = TestCa::new(&["localhost"]);
    let (plain_port, seen) = serve(Script {
        extensions: vec!["AUTH PLAIN".into()],
        ..Script::new()
    })
    .await;
    let insecure = crate::probe(
        "localhost",
        plain_port,
        Security::Starttls,
        &ca.roots(),
        Duration::from_secs(5),
    )
    .await;
    assert!(
        matches!(insecure, Err(SendError::Insecure(_))),
        "{insecure:?}"
    );
    let plain = crate::probe(
        "localhost",
        plain_port,
        Security::Plain,
        &ca.roots(),
        Duration::from_secs(5),
    )
    .await;
    assert!(matches!(plain, Err(SendError::Insecure(_))));
    assert!(!seen.commands().iter().any(|c| c.starts_with("AUTH")));

    let (tls_port, _) = serve(Script {
        tls: Some(ca.acceptor()),
        ..Script::new()
    })
    .await;
    let untrusted = crate::probe(
        "localhost",
        tls_port,
        Security::Tls,
        &TestCa::new(&["localhost"]).roots(),
        Duration::from_secs(5),
    )
    .await;
    assert!(matches!(untrusted, Err(SendError::Tls(_))), "{untrusted:?}");

    let (refusing, _) = serve(Script {
        greeting: "554 5.3.2 go away",
        tls: Some(ca.acceptor()),
        ..Script::new()
    })
    .await;
    let refused = crate::probe(
        "localhost",
        refusing,
        Security::Tls,
        &ca.roots(),
        Duration::from_secs(5),
    )
    .await;
    assert!(
        matches!(refused, Err(SendError::Unavailable(_))),
        "{refused:?}"
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let silent = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    tokio::spawn(async move {
        let mut open = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            open.push(socket);
        }
    });
    let roots = ca.roots();
    let probe = crate::probe(
        "localhost",
        silent,
        Security::Tls,
        &roots,
        Duration::from_millis(300),
    );
    let timed_out = tokio::time::timeout(Duration::from_secs(30), probe)
        .await
        .expect("the probe's own timeout fires");
    assert!(
        matches!(timed_out, Err(SendError::Timeout(_))),
        "{timed_out:?}"
    );
    assert!(
        accepted.load(Ordering::SeqCst) >= 1,
        "the probe reached the server"
    );
}
