use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use skein_core::{DsnNotify, DsnReturn};
use skein_send::{
    Envelope, Limits, RecipientOutcome, RecipientResult, Refusal, SendError, SendReport,
};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::{Config, Secret, Security};

const MAX_LINE: u64 = 4096;
const MAX_LINES: usize = 128;

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

struct Reply {
    code: u16,
    lines: Vec<String>,
}

impl Reply {
    fn text(&self) -> String {
        self.lines.join(" ")
    }

    fn ok(&self) -> bool {
        (200..300).contains(&self.code)
    }

    fn refusal(&self) -> Refusal {
        Refusal {
            permanent: self.code >= 500,
            code: self.code,
            text: self.text(),
        }
    }

    fn refused(&self) -> SendError {
        SendError::Refused {
            permanent: self.code >= 500,
            code: self.code,
            text: self.text(),
        }
    }

    fn describe(&self) -> String {
        format!("{} {}", self.code, self.text())
    }
}

#[derive(Default)]
struct Extensions {
    size: Option<u64>,
    eight_bit: bool,
    smtputf8: bool,
    starttls: bool,
    dsn: bool,
    auth: Vec<String>,
}

impl Extensions {
    fn parse(lines: &[String]) -> Self {
        let mut ext = Self::default();
        for line in lines.iter().skip(1) {
            let mut words = line.split_whitespace();
            let Some(keyword) = words.next() else {
                continue;
            };
            match keyword.to_ascii_uppercase().as_str() {
                "SIZE" => ext.size = words.next().and_then(|n| n.parse().ok()),
                "8BITMIME" => ext.eight_bit = true,
                "SMTPUTF8" => ext.smtputf8 = true,
                "STARTTLS" => ext.starttls = true,
                "DSN" => ext.dsn = true,
                "AUTH" => {
                    ext.auth = words
                        .filter(|w| w.len() <= 64 && w.bytes().all(|b| b.is_ascii_graphic()))
                        .take(32)
                        .map(str::to_ascii_uppercase)
                        .collect()
                }
                _ => {}
            }
        }
        ext
    }
}

pub(crate) struct Session<'a> {
    config: &'a Config,
    io: BufReader<Box<dyn Io>>,
    ext: Extensions,
}

impl<'a> Session<'a> {
    pub(crate) async fn open(
        config: &'a Config,
        tls: Arc<ClientConfig>,
    ) -> Result<Self, SendError> {
        let tcp = within(
            config.timeout,
            TcpStream::connect((config.host.as_str(), config.port)),
        )
        .await
        .map_err(|e| {
            opening(
                &e,
                format!("connecting to {}:{}: {e}", config.host, config.port),
            )
        })?;
        let io: Box<dyn Io> = match config.security {
            Security::Tls => Box::new(handshake(config, tls.clone(), tcp).await?),
            Security::Starttls | Security::Plain => Box::new(tcp),
        };
        let mut session = Self {
            config,
            io: BufReader::new(io),
            ext: Extensions::default(),
        };
        let greeting = session
            .reply(config.timeout)
            .await
            .map_err(|e| opening(&e, format!("reading the greeting: {e}")))?;
        if !greeting.ok() {
            return Err(SendError::Unavailable(format!(
                "the server greeted with {}",
                greeting.describe()
            )));
        }
        session.hello().await?;
        if config.security == Security::Starttls {
            session.starttls(tls).await?;
        }
        session.authenticate().await?;
        Ok(session)
    }

    pub(crate) fn probe(&self) -> crate::SmtpProbe {
        let auth: Vec<String> = self.ext.auth.iter().take(32).cloned().collect();
        let offers = |m: &str| auth.iter().any(|a| a == m);
        crate::SmtpProbe {
            password_sign_in: offers("PLAIN") || offers("LOGIN"),
            oauth: offers("XOAUTH2") || offers("OAUTHBEARER"),
            max_size: self.ext.size.filter(|n| *n > 0),
            auth,
        }
    }

    pub(crate) fn limits(&self) -> Limits {
        Limits {
            max_size: self.ext.size.filter(|n| *n > 0),
            smtputf8: self.ext.smtputf8,
            dsn: self.ext.dsn,
        }
    }

    pub(crate) async fn send(
        &mut self,
        envelope: &Envelope,
        message: &[u8],
    ) -> Result<SendReport, SendError> {
        let limit = self.limits().max_size;
        if limit.is_some_and(|limit| message.len() as u64 > limit) {
            return Err(SendError::TooLarge { limit });
        }
        let international = !envelope.mail_from.is_ascii()
            || envelope.recipients.iter().any(|r| !r.is_ascii())
            || !header_section(message).is_ascii();
        let eight_bit = !message.is_ascii();
        if international && !self.ext.smtputf8 {
            return Err(SendError::Invalid(
                "the server does not take internationalized mail (SMTPUTF8)".into(),
            ));
        }
        if eight_bit && !self.ext.eight_bit && !international {
            return Err(SendError::Invalid(
                "the server does not take 8-bit mail (8BITMIME)".into(),
            ));
        }

        let mut mail = format!("MAIL FROM:<{}>", envelope.mail_from);
        if self.ext.size.is_some() {
            mail.push_str(&format!(" SIZE={}", message.len()));
        }
        if eight_bit && self.ext.eight_bit {
            mail.push_str(" BODY=8BITMIME");
        }
        if international {
            mail.push_str(" SMTPUTF8");
        }
        let dsn = envelope.dsn.as_ref().filter(|_| self.ext.dsn);
        if let Some(dsn) = dsn {
            match dsn.ret {
                Some(DsnReturn::Full) => mail.push_str(" RET=FULL"),
                Some(DsnReturn::Headers) => mail.push_str(" RET=HDRS"),
                None => {}
            }
            if let Some(envid) = &envelope.envid {
                mail.push_str(&format!(" ENVID={}", xtext(envid)));
            }
        }
        let reply = self.command(&mail).await?;
        if !reply.ok() {
            return Err(match reply.code {
                552 => SendError::TooLarge { limit },
                530 | 535 => SendError::Auth(reply.text()),
                _ => reply.refused(),
            });
        }

        let mut recipients = Vec::with_capacity(envelope.recipients.len());
        for address in &envelope.recipients {
            let mut rcpt = format!("RCPT TO:<{address}>");
            if let Some(dsn) = dsn {
                if !dsn.notify.is_empty() {
                    rcpt.push_str(" NOTIFY=");
                    rcpt.push_str(&notify(&dsn.notify));
                }
                if address.is_ascii() {
                    rcpt.push_str(&format!(" ORCPT=rfc822;{}", xtext(address)));
                }
            }
            let reply = self.command(&rcpt).await?;
            if reply.code == 421 {
                return Err(reply.refused());
            }
            let outcome = if reply.ok() {
                RecipientOutcome::Accepted
            } else {
                RecipientOutcome::Refused(reply.refusal())
            };
            recipients.push(RecipientResult {
                address: address.clone(),
                outcome,
            });
        }
        if !recipients
            .iter()
            .any(|r| r.outcome == RecipientOutcome::Accepted)
        {
            let _ = self.command("RSET").await;
            return Err(SendError::RecipientsRefused(recipients));
        }

        let reply = self.command("DATA").await?;
        if reply.code != 354 {
            return Err(match reply.code {
                552 => SendError::TooLarge { limit },
                200..400 => {
                    SendError::Temporary(format!("unexpected reply to DATA: {}", reply.describe()))
                }
                _ => reply.refused(),
            });
        }
        let stuffed = dot_stuff(message);
        within(self.config.data_timeout, self.io.write_all(&stuffed))
            .await
            .map_err(|e| exchange(&e, format!("sending the message: {e}")))?;
        within(self.config.timeout, async {
            self.io.write_all(b".\r\n").await?;
            self.io.flush().await
        })
        .await
        .map_err(|e| SendError::Uncertain(format!("ending the message: {e}")))?;
        let reply = self
            .reply(self.config.data_timeout)
            .await
            .map_err(|e| SendError::Uncertain(format!("waiting for the reply: {e}")))?;
        match reply.code {
            200..300 => Ok(SendReport::new(recipients)),
            552 => Err(SendError::TooLarge { limit }),
            400..600 => Err(reply.refused()),
            _ => Err(SendError::Uncertain(format!(
                "unexpected reply to the message: {}",
                reply.describe()
            ))),
        }
    }

    pub(crate) async fn quit(mut self) {
        if self.write_line("QUIT").await.is_ok() {
            let _ = self.reply(self.config.timeout).await;
        }
        let _ = within(self.config.timeout, self.io.get_mut().shutdown()).await;
    }

    async fn hello(&mut self) -> Result<(), SendError> {
        let reply = self
            .open_command(&format!("EHLO {}", self.config.helo))
            .await?;
        if reply.ok() {
            self.ext = Extensions::parse(&reply.lines);
            return Ok(());
        }
        let reply = self
            .open_command(&format!("HELO {}", self.config.helo))
            .await?;
        if !reply.ok() {
            return Err(SendError::Unavailable(format!(
                "the server refused EHLO and HELO: {}",
                reply.describe()
            )));
        }
        self.ext = Extensions::default();
        Ok(())
    }

    async fn starttls(&mut self, tls: Arc<ClientConfig>) -> Result<(), SendError> {
        if !self.ext.starttls {
            return Err(SendError::Insecure(
                "the server does not offer STARTTLS".into(),
            ));
        }
        let reply = self.open_command("STARTTLS").await?;
        if reply.code != 220 {
            return Err(SendError::Insecure(format!(
                "the server refused STARTTLS: {}",
                reply.describe()
            )));
        }
        if !self.io.buffer().is_empty() {
            return Err(SendError::Tls(
                "the server sent data before the TLS handshake".into(),
            ));
        }
        let plain = std::mem::replace(
            &mut self.io,
            BufReader::new(Box::new(tokio::io::empty()) as Box<dyn Io>),
        )
        .into_inner();
        let secured = handshake(self.config, tls, plain).await?;
        self.io = BufReader::new(Box::new(secured));
        self.hello().await
    }

    async fn authenticate(&mut self) -> Result<(), SendError> {
        let Some((username, secret)) = &self.config.login else {
            return Ok(());
        };
        let offers = |mechanism: &str| self.ext.auth.iter().any(|m| m == mechanism);
        let (plain, login, xoauth2) = (offers("PLAIN"), offers("LOGIN"), offers("XOAUTH2"));
        let reply = match secret {
            Secret::OAuthToken(token) => {
                if !xoauth2 {
                    return Err(SendError::Auth(
                        "the server does not offer AUTH XOAUTH2".into(),
                    ));
                }
                let initial =
                    BASE64.encode(format!("user={username}\x01auth=Bearer {token}\x01\x01"));
                let reply = self
                    .open_command(&format!("AUTH XOAUTH2 {initial}"))
                    .await?;
                if reply.code == 334 {
                    self.open_command("").await?
                } else {
                    reply
                }
            }
            Secret::Password(password) if plain => {
                let initial = BASE64.encode(format!("\0{username}\0{password}"));
                self.open_command(&format!("AUTH PLAIN {initial}")).await?
            }
            Secret::Password(password) if login => {
                let mut reply = self.open_command("AUTH LOGIN").await?;
                if reply.code == 334 {
                    reply = self.open_command(&BASE64.encode(username)).await?;
                }
                if reply.code == 334 {
                    reply = self.open_command(&BASE64.encode(password)).await?;
                }
                reply
            }
            Secret::Password(_) => {
                return Err(SendError::Auth(
                    "the server offers neither AUTH PLAIN nor AUTH LOGIN".into(),
                ));
            }
        };
        match reply.code {
            200..300 => Ok(()),
            400..500 => Err(SendError::Temporary(format!(
                "signing in: {}",
                reply.describe()
            ))),
            334 => {
                let _ = self.open_command("*").await;
                Err(SendError::Auth(
                    "the server asked for more than the mechanism sends".into(),
                ))
            }
            _ => Err(SendError::Auth(reply.describe())),
        }
    }

    async fn open_command(&mut self, line: &str) -> Result<Reply, SendError> {
        self.write_line(line)
            .await
            .map_err(|e| opening(&e, format!("sending a command: {e}")))?;
        self.reply(self.config.timeout)
            .await
            .map_err(|e| opening(&e, format!("reading a reply: {e}")))
    }

    async fn command(&mut self, line: &str) -> Result<Reply, SendError> {
        self.write_line(line)
            .await
            .map_err(|e| exchange(&e, format!("sending a command: {e}")))?;
        self.reply(self.config.timeout)
            .await
            .map_err(|e| exchange(&e, format!("reading a reply: {e}")))
    }

    async fn write_line(&mut self, line: &str) -> std::io::Result<()> {
        within(self.config.timeout, async {
            self.io.write_all(line.as_bytes()).await?;
            self.io.write_all(b"\r\n").await?;
            self.io.flush().await
        })
        .await
    }

    async fn reply(&mut self, limit: Duration) -> std::io::Result<Reply> {
        within(limit, async {
            let mut code = None;
            let mut lines = Vec::new();
            loop {
                let mut raw = Vec::new();
                (&mut self.io)
                    .take(MAX_LINE)
                    .read_until(b'\n', &mut raw)
                    .await?;
                if raw.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "the server closed the connection",
                    ));
                }
                let line = String::from_utf8_lossy(&raw);
                let line = line.trim_end_matches(['\r', '\n']);
                let malformed = || std::io::Error::other("a malformed reply");
                let this: u16 = line
                    .get(..3)
                    .filter(|c| c.bytes().all(|b| b.is_ascii_digit()))
                    .and_then(|c| c.parse().ok())
                    .ok_or_else(malformed)?;
                if code.is_some_and(|c| c != this) || !raw.ends_with(b"\n") {
                    return Err(malformed());
                }
                code = Some(this);
                lines.push(line.get(4..).unwrap_or("").to_owned());
                match line.as_bytes().get(3) {
                    Some(b'-') if lines.len() < MAX_LINES => continue,
                    Some(b'-') => return Err(std::io::Error::other("a reply that never ends")),
                    None | Some(b' ') => return Ok(Reply { code: this, lines }),
                    Some(_) => return Err(malformed()),
                }
            }
        })
        .await
    }
}

pub(crate) fn fuzz_replies(bytes: &[u8]) {
    let config = Config {
        host: "fuzz.invalid".into(),
        port: 587,
        security: Security::Plain,
        login: None,
        helo: "fuzz.invalid".into(),
        timeout: Duration::from_secs(60),
        data_timeout: Duration::from_secs(60),
    };
    let io: Box<dyn Io> = Box::new(std::io::Cursor::new(bytes.to_vec()));
    let mut session = Session {
        config: &config,
        io: BufReader::new(io),
        ext: Extensions::default(),
    };
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
    else {
        return;
    };
    runtime.block_on(async {
        while let Ok(reply) = session.reply(config.timeout).await {
            assert!(reply.code < 1000);
            assert!(!reply.lines.is_empty() && reply.lines.len() <= MAX_LINES);
            let refusal = reply.refusal();
            assert_eq!(refusal.permanent, reply.code >= 500);
            let _ = reply.describe();
            session.ext = Extensions::parse(&reply.lines);
            let limits = session.limits();
            assert!(limits.max_size != Some(0));
        }
    });
}

fn timed_out(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::TimedOut
}

/// A failure before a session was open: nothing can have been sent.
fn opening(e: &std::io::Error, text: String) -> SendError {
    if timed_out(e) {
        SendError::Timeout(text)
    } else {
        SendError::Unavailable(text)
    }
}

/// A failure before the whole message was sent: the service cannot have taken it.
fn exchange(e: &std::io::Error, text: String) -> SendError {
    if timed_out(e) {
        SendError::Timeout(text)
    } else {
        SendError::Temporary(text)
    }
}

async fn within<T>(
    limit: Duration,
    work: impl Future<Output = std::io::Result<T>>,
) -> std::io::Result<T> {
    tokio::time::timeout(limit, work).await.unwrap_or_else(|_| {
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out",
        ))
    })
}

async fn handshake<S: AsyncRead + AsyncWrite + Unpin + Send>(
    config: &Config,
    tls: Arc<ClientConfig>,
    stream: S,
) -> Result<tokio_rustls::client::TlsStream<S>, SendError> {
    let host = config.host.trim_start_matches('[').trim_end_matches(']');
    let name = ServerName::try_from(host.to_owned())
        .map_err(|_| SendError::Invalid(format!("{host} is not a valid host name")))?;
    within(
        config.timeout,
        TlsConnector::from(tls).connect(name, stream),
    )
    .await
    .map_err(|e| {
        if timed_out(&e) {
            SendError::Timeout(format!("TLS with {host}: {e}"))
        } else {
            SendError::Tls(format!("TLS with {host}: {e}"))
        }
    })
}

fn notify(when: &[DsnNotify]) -> String {
    if when.contains(&DsnNotify::Never) {
        return "NEVER".into();
    }
    let mut out: Vec<&str> = Vec::new();
    for (kind, word) in [
        (DsnNotify::Success, "SUCCESS"),
        (DsnNotify::Failure, "FAILURE"),
        (DsnNotify::Delay, "DELAY"),
    ] {
        if when.contains(&kind) {
            out.push(word);
        }
    }
    out.join(",")
}

/// RFC 3461 xtext: `+` and `=`, and anything outside printable ASCII, as `+XX`.
fn xtext(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if (b'!'..=b'~').contains(&b) && b != b'+' && b != b'=' {
            out.push(b as char);
        } else {
            out.push_str(&format!("+{b:02X}"));
        }
    }
    out
}

fn header_section(message: &[u8]) -> &[u8] {
    message
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(message, |end| &message[..end])
}

fn dot_stuff(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + message.len() / 64);
    for line in message.split_inclusive(|b| *b == b'\n') {
        if line.first() == Some(&b'.') {
            out.push(b'.');
        }
        out.extend_from_slice(line);
    }
    out
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn stuffs_dots_at_line_starts_only() {
        assert_eq!(
            dot_stuff(b".a\r\nb.c\r\n.\r\n..\r\n"),
            b"..a\r\nb.c\r\n..\r\n...\r\n"
        );
    }

    #[test]
    fn reads_extensions() {
        let lines: Vec<String> = [
            "mx.example.org Hello",
            "SIZE 1000",
            "8BITMIME",
            "AUTH plain LOGIN XOAUTH2",
            "STARTTLS",
            "DSN",
        ]
        .map(String::from)
        .into();
        let ext = Extensions::parse(&lines);
        assert_eq!(ext.size, Some(1000));
        assert!(ext.eight_bit && ext.starttls && ext.dsn && !ext.smtputf8);
        assert_eq!(ext.auth, ["PLAIN", "LOGIN", "XOAUTH2"]);
    }

    #[test]
    fn encodes_dsn_parameters() {
        assert_eq!(xtext("a+b=c@example.org"), "a+2Bb+3Dc@example.org");
        assert_eq!(xtext("a b"), "a+20b");
        assert_eq!(
            notify(&[DsnNotify::Delay, DsnNotify::Success]),
            "SUCCESS,DELAY"
        );
        assert_eq!(notify(&[DsnNotify::Never, DsnNotify::Failure]), "NEVER");
    }

    #[test]
    fn finds_the_header_section() {
        assert_eq!(header_section(b"A: b\r\n\r\nbody\r\n"), b"A: b");
        assert_eq!(header_section(b"A: b\r\n"), b"A: b\r\n");
    }
}
