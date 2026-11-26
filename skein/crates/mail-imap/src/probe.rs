use std::sync::Arc;
use std::time::Duration;

use skein_core::TlsRoots;
use skein_mail::MailError;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};

use crate::stream::{self, ImapStream};
use crate::{Security, tls_config};

/// Longest line a probe reads.
pub const PROBE_LINE_LIMIT: usize = 8 * 1024;
/// Most bytes a probe reads from one server.
pub const PROBE_BYTE_LIMIT: usize = 64 * 1024;
/// Most lines a probe reads from one server.
pub const PROBE_LINE_COUNT: usize = 64;
/// Most capabilities a probe keeps.
pub const PROBE_CAPABILITIES: usize = 64;

/// What an IMAP server said about itself before sign-in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImapProbe {
    /// The capabilities after TLS, upper case, each 1 to 64 visible ASCII characters, at most
    /// [`PROBE_CAPABILITIES`], in the server's order without repeats.
    pub capabilities: Vec<String>,
    /// The server lets a client sign in with a password: it does not announce `LOGINDISABLED`.
    pub password_sign_in: bool,
    /// The server announced `AUTH=XOAUTH2` or `AUTH=OAUTHBEARER`.
    pub oauth: bool,
}

/// Checks an IMAP server without signing in: connects, verifies TLS against the web roots and
/// `roots` (after `STARTTLS` for [`Security::Starttls`]), reads the greeting, asks for
/// `CAPABILITY` and says `LOGOUT`. Nothing else is sent, never a user name or a secret.
///
/// The whole probe ends within `timeout` ([`MailError::Timeout`]); it reads at most
/// [`PROBE_BYTE_LIMIT`] bytes in at most [`PROBE_LINE_COUNT`] lines of at most
/// [`PROBE_LINE_LIMIT`] bytes ([`MailError::Protocol`] beyond). [`Security::Plain`] and a server
/// without `STARTTLS` are [`MailError::Insecure`]; a failed handshake or certificate is
/// [`MailError::Tls`]; a `BYE` greeting is [`MailError::Refused`]; a server that does not speak
/// IMAP4rev1 or IMAP4rev2 is [`MailError::Protocol`].
pub async fn probe(
    host: &str,
    port: u16,
    security: Security,
    roots: &TlsRoots,
    timeout: Duration,
) -> Result<ImapProbe, MailError> {
    if security == Security::Plain {
        return Err(MailError::Insecure(
            "a probe never runs in plain text".into(),
        ));
    }
    if host.trim().is_empty() || port == 0 {
        return Err(MailError::Config("the host or port is empty".into()));
    }
    let tls = Arc::new(tls_config(roots)?);
    tokio::time::timeout(timeout, async {
        let wait = timeout.min(stream::GREETING_WAIT);
        let (stream, greeting) = ImapStream::connect(host, port, security, tls, wait).await?;
        if !stream.is_encrypted() {
            return Err(MailError::Insecure(
                "the connection is not encrypted".into(),
            ));
        }
        let mut reader = BufReader::new(stream);
        let result = converse(&mut reader, greeting).await;
        let _ = reader.get_mut().shutdown().await;
        result
    })
    .await
    .map_err(|_| MailError::Timeout("the server did not answer the probe in time".into()))?
}

async fn converse<S>(io: &mut S, greeting: bool) -> Result<ImapProbe, MailError>
where
    S: AsyncBufRead + AsyncWrite + Unpin,
{
    let mut budget = Budget::default();
    let mut capabilities = None;
    if greeting {
        let line = budget.line(io).await?;
        match classify(&line) {
            Line::Greeting(caps) => capabilities = caps,
            Line::Bye => {
                return Err(MailError::Refused(
                    "the server said BYE at the greeting".into(),
                ));
            }
            _ => return Err(MailError::Protocol("not an IMAP greeting".into())),
        }
    }
    let starttls_caps = capabilities.is_none();
    if starttls_caps {
        write(io, b"p1 CAPABILITY\r\n").await?;
        loop {
            let line = budget.line(io).await?;
            match classify(&line) {
                Line::Capability(caps) => capabilities = Some(caps),
                Line::Tagged(true) => break,
                Line::Tagged(false) => {
                    return Err(MailError::Refused("the server refused CAPABILITY".into()));
                }
                Line::Bye => return Err(MailError::Refused("the server said BYE".into())),
                _ => {}
            }
        }
    }
    let _ = write(io, b"p2 LOGOUT\r\n").await;
    report(capabilities.unwrap_or_default())
}

fn report(capabilities: Vec<String>) -> Result<ImapProbe, MailError> {
    if !capabilities
        .iter()
        .any(|c| c == "IMAP4REV1" || c == "IMAP4REV2")
    {
        return Err(MailError::Protocol(
            "the server does not speak IMAP4rev1".into(),
        ));
    }
    Ok(ImapProbe {
        password_sign_in: !capabilities.iter().any(|c| c == "LOGINDISABLED"),
        oauth: capabilities
            .iter()
            .any(|c| c == "AUTH=XOAUTH2" || c == "AUTH=OAUTHBEARER"),
        capabilities,
    })
}

async fn write<S: AsyncWrite + Unpin>(io: &mut S, bytes: &[u8]) -> Result<(), MailError> {
    io.write_all(bytes)
        .await
        .map_err(|e| MailError::Network(e.to_string()))?;
    io.flush()
        .await
        .map_err(|e| MailError::Network(e.to_string()))
}

#[derive(Default)]
struct Budget {
    bytes: usize,
    lines: usize,
}

impl Budget {
    async fn line<S: AsyncBufRead + Unpin>(&mut self, io: &mut S) -> Result<Vec<u8>, MailError> {
        if self.lines >= PROBE_LINE_COUNT || self.bytes >= PROBE_BYTE_LIMIT {
            return Err(MailError::Protocol("the server said too much".into()));
        }
        let cap = PROBE_LINE_LIMIT.min(PROBE_BYTE_LIMIT - self.bytes);
        let mut raw = Vec::new();
        let read = (&mut *io)
            .take(cap as u64)
            .read_until(b'\n', &mut raw)
            .await
            .map_err(|e| MailError::Network(e.to_string()))?;
        if read == 0 {
            return Err(MailError::Network(
                "the server closed the connection".into(),
            ));
        }
        if !raw.ends_with(b"\n") {
            return Err(MailError::Protocol("an overlong line".into()));
        }
        self.lines += 1;
        self.bytes += read;
        Ok(raw)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Line {
    Greeting(Option<Vec<String>>),
    Capability(Vec<String>),
    Bye,
    Tagged(bool),
    Other,
}

fn classify(raw: &[u8]) -> Line {
    let line = trim_crlf(raw);
    if let Some(rest) = strip_ci(line, b"* OK").or_else(|| strip_ci(line, b"* PREAUTH")) {
        let caps = rest
            .iter()
            .position(|b| *b == b'[')
            .map(|at| &rest[at + 1..])
            .and_then(|code| strip_ci(code, b"CAPABILITY "))
            .map(|code| {
                let end = code.iter().position(|b| *b == b']').unwrap_or(code.len());
                capabilities(&code[..end])
            });
        return Line::Greeting(caps);
    }
    if strip_ci(line, b"* BYE").is_some() {
        return Line::Bye;
    }
    if let Some(rest) = strip_ci(line, b"* CAPABILITY ") {
        return Line::Capability(capabilities(rest));
    }
    if let Some(rest) = strip_ci(line, b"p1 ") {
        return Line::Tagged(strip_ci(rest, b"OK").is_some());
    }
    Line::Other
}

fn trim_crlf(raw: &[u8]) -> &[u8] {
    let mut end = raw.len();
    while end > 0 && matches!(raw[end - 1], b'\r' | b'\n') {
        end -= 1;
    }
    &raw[..end]
}

fn strip_ci<'a>(line: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    (line.len() >= prefix.len() && line[..prefix.len()].eq_ignore_ascii_case(prefix))
        .then(|| &line[prefix.len()..])
}

/// Capability atoms from a space-separated list: upper case, visible ASCII without brackets,
/// 1 to 64 bytes each, repeats dropped, at most [`PROBE_CAPABILITIES`].
fn capabilities(list: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for word in list.split(|b| *b == b' ') {
        if out.len() == PROBE_CAPABILITIES {
            break;
        }
        if word.is_empty()
            || word.len() > 64
            || !word
                .iter()
                .all(|b| b.is_ascii_graphic() && !matches!(b, b'[' | b']' | b'(' | b')'))
        {
            continue;
        }
        let atom = String::from_utf8_lossy(word).to_ascii_uppercase();
        if !out.contains(&atom) {
            out.push(atom);
        }
    }
    out
}

/// Runs the probe's reader over `bytes` as a server's answer to a TLS connection.
pub(crate) fn fuzz_probe(bytes: &[u8]) {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread().build() else {
        return;
    };
    runtime.block_on(async {
        let mut io = tokio::io::join(BufReader::new(bytes), tokio::io::sink());
        if let Ok(probe) = converse(&mut io, true).await {
            assert!(probe.capabilities.len() <= PROBE_CAPABILITIES);
            assert!(
                probe
                    .capabilities
                    .iter()
                    .all(|c| !c.is_empty() && c.len() <= 64)
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn run(server: &[u8], greeting: bool) -> (Result<ImapProbe, MailError>, Vec<u8>) {
        let (client, mut server_end) = tokio::io::duplex(1 << 20);
        server_end.write_all(server).await.unwrap();
        drop(server_end.shutdown().await);
        let (read, write_half) = tokio::io::split(client);
        let mut io = tokio::io::join(BufReader::new(read), write_half);
        let result = converse(&mut io, greeting).await;
        let (_, mut w) = io.into_inner();
        let _ = w.shutdown().await;
        let mut sent = Vec::new();
        let _ = tokio::io::AsyncReadExt::read_to_end(&mut server_end, &mut sent).await;
        (result, sent)
    }

    #[tokio::test]
    async fn reads_capabilities_from_the_greeting_without_asking() {
        let (probe, sent) = run(
            b"* OK [CAPABILITY IMAP4rev1 IDLE AUTH=PLAIN auth=xoauth2 IDLE] ready\r\n",
            true,
        )
        .await;
        let probe = probe.unwrap();
        assert_eq!(
            probe.capabilities,
            ["IMAP4REV1", "IDLE", "AUTH=PLAIN", "AUTH=XOAUTH2"]
        );
        assert!(probe.password_sign_in && probe.oauth);
        assert_eq!(sent, b"p2 LOGOUT\r\n");
    }

    #[tokio::test]
    async fn asks_for_capabilities_and_never_sends_credentials() {
        let (probe, sent) = run(
            b"* OK ready\r\n* CAPABILITY IMAP4rev2 LOGINDISABLED\r\np1 OK done\r\n",
            true,
        )
        .await;
        let probe = probe.unwrap();
        assert!(!probe.password_sign_in && !probe.oauth);
        let sent = String::from_utf8(sent).unwrap();
        assert_eq!(sent, "p1 CAPABILITY\r\np2 LOGOUT\r\n");
        assert!(!sent.contains("LOGIN ") && !sent.contains("AUTHENTICATE"));
    }

    #[tokio::test]
    async fn after_starttls_there_is_no_greeting() {
        let (probe, _) = run(b"* CAPABILITY IMAP4rev1\r\np1 OK\r\n", false).await;
        assert!(probe.is_ok());
    }

    #[tokio::test]
    async fn hostile_greetings_are_refused_without_a_panic() {
        let long = [b"* OK ".as_slice(), &vec![b'a'; PROBE_LINE_LIMIT], b"\r\n"].concat();
        let flood: Vec<u8> = std::iter::once(b"* OK hi\r\n".to_vec())
            .chain(std::iter::repeat_n(
                b"* NOISE x\r\n".to_vec(),
                PROBE_LINE_COUNT + 5,
            ))
            .flatten()
            .collect();
        let wide = [
            b"* OK [CAPABILITY IMAP4rev1 ".as_slice(),
            &b"X ".repeat(4000),
            b"] hi\r\n",
        ]
        .concat();
        type Expect = fn(&MailError) -> bool;
        let cases: Vec<(&[u8], Expect)> = vec![
            (b"", |e| matches!(e, MailError::Network(_))),
            (b"* BYE go away\r\n", |e| matches!(e, MailError::Refused(_))),
            (b"220 smtp.example.com ESMTP\r\n", |e| {
                matches!(e, MailError::Protocol(_))
            }),
            (b"* OK no newline", |e| matches!(e, MailError::Protocol(_))),
            (&long, |e| matches!(e, MailError::Protocol(_))),
            (&flood, |e| matches!(e, MailError::Protocol(_))),
            (b"* OK hi\r\np1 NO\r\n", |e| {
                matches!(e, MailError::Refused(_))
            }),
            (b"* OK hi\r\n* CAPABILITY POP3\r\np1 OK\r\n", |e| {
                matches!(e, MailError::Protocol(_))
            }),
            (b"* OK [CAPABILITY \x00\xff\x1b[31m] hi\r\n", |e| {
                matches!(e, MailError::Protocol(_))
            }),
        ];
        for (server, expect) in cases {
            let (result, _) = run(server, true).await;
            let error = result.unwrap_err();
            assert!(expect(&error), "{error:?}");
        }
        let (result, _) = run(&wide, true).await;
        assert_eq!(result.unwrap().capabilities.len(), 2);
    }

    #[tokio::test]
    async fn plain_text_is_never_probed() {
        let error = probe(
            "127.0.0.1",
            143,
            Security::Plain,
            &TlsRoots::default(),
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, MailError::Insecure(_)));
    }
}
