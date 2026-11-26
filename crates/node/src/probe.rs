use std::time::Duration;

use async_trait::async_trait;
use rowboat_discover::{DiscoverError, Endpoint, Probed, Prober, Security};
use skein_core::TlsRoots;
use skein_mail::{MailCause, MailError};
use skein_send::{SendCause, SendError};

/// The desktop profile's [`Prober`]: Skein's IMAP and SMTP `probe` functions, TLS verified
/// against the web roots, greeting and capabilities read, no credential sent, each probe within
/// its timeout (10 s by default).
#[derive(Debug, Clone)]
pub struct ServerProber {
    roots: TlsRoots,
    timeout: Duration,
}

pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

impl Default for ServerProber {
    fn default() -> Self {
        Self {
            roots: TlsRoots::default(),
            timeout: PROBE_TIMEOUT,
        }
    }
}

impl ServerProber {
    /// A prober trusting only the web roots, with `timeout` per probe.
    pub fn new(timeout: Duration) -> Self {
        Self::trusting(TlsRoots::default(), timeout)
    }

    pub(crate) fn trusting(roots: TlsRoots, timeout: Duration) -> Self {
        Self { roots, timeout }
    }

    /// A prober trusting `roots` (a test CA) besides the web roots, with `timeout` per probe.
    #[cfg(feature = "testing")]
    pub fn with_test_roots(roots: TlsRoots, timeout: Duration) -> Self {
        Self::trusting(roots, timeout)
    }
}

fn mail_failure(e: &MailError) -> DiscoverError {
    match e.cause() {
        MailCause::Tls => DiscoverError::TlsFailed,
        MailCause::Insecure => DiscoverError::Insecure,
        MailCause::Timeout => DiscoverError::Timeout,
        MailCause::Unreachable => DiscoverError::Unreachable,
        MailCause::Config => DiscoverError::Invalid,
        MailCause::Auth
        | MailCause::Throttled
        | MailCause::MailboxNotFound
        | MailCause::Quota
        | MailCause::Refused
        | MailCause::Protocol => DiscoverError::NotMail,
    }
}

fn send_failure(e: &SendError) -> DiscoverError {
    match e.cause() {
        SendCause::Tls => DiscoverError::TlsFailed,
        SendCause::Insecure => DiscoverError::Insecure,
        SendCause::Timeout => DiscoverError::Timeout,
        SendCause::Unreachable | SendCause::Temporary => DiscoverError::Unreachable,
        SendCause::Invalid => DiscoverError::Invalid,
        _ => DiscoverError::NotMail,
    }
}

#[async_trait]
impl Prober for ServerProber {
    async fn probe_imap(&self, endpoint: &Endpoint) -> Result<Probed, DiscoverError> {
        let security = match endpoint.security {
            Security::Tls => skein_mail_imap::Security::Tls,
            Security::StartTls => skein_mail_imap::Security::Starttls,
        };
        let report = skein_mail_imap::probe(
            &endpoint.host,
            endpoint.port,
            security,
            &self.roots,
            self.timeout,
        )
        .await
        .map_err(|e| mail_failure(&e))?;
        Ok(Probed {
            password_sign_in: report.password_sign_in,
            oauth: report.oauth,
        })
    }

    async fn probe_smtp(&self, endpoint: &Endpoint) -> Result<Probed, DiscoverError> {
        let security = match endpoint.security {
            Security::Tls => skein_send_smtp::Security::Tls,
            Security::StartTls => skein_send_smtp::Security::Starttls,
        };
        let report = skein_send_smtp::probe(
            &endpoint.host,
            endpoint.port,
            security,
            &self.roots,
            self.timeout,
        )
        .await
        .map_err(|e| send_failure(&e))?;
        Ok(Probed {
            password_sign_in: report.password_sign_in,
            oauth: report.oauth,
        })
    }
}

#[cfg(test)]
mod tests {
    use skein_core::tls::testing::TestCa;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    use super::*;

    async fn serve(
        ca: &TestCa,
        greeting: &'static [u8],
        answers: &'static [(&'static str, &'static [u8])],
    ) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = ca.acceptor();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut io = BufReader::new(tls);
                    if io.get_mut().write_all(greeting).await.is_err() {
                        return;
                    }
                    let mut line = String::new();
                    while matches!(io.read_line(&mut line).await, Ok(n) if n > 0) {
                        assert!(!line.contains("secret"), "a credential reached the server");
                        for (prefix, answer) in answers {
                            if line.to_ascii_uppercase().contains(prefix) {
                                let _ = io.get_mut().write_all(answer).await;
                            }
                        }
                        line.clear();
                    }
                });
            }
        });
        port
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn probes_both_kinds_and_maps_failures_to_kinds() {
        let ca = TestCa::new(&["localhost"]);
        let imap = serve(
            &ca,
            b"* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] ready\r\n",
            &[("LOGOUT", b"* BYE\r\np2 OK\r\n")],
        )
        .await;
        let smtp = serve(
            &ca,
            b"220 smtp.example.com ESMTP\r\n",
            &[
                ("EHLO", b"250-smtp.example.com\r\n250 AUTH PLAIN LOGIN\r\n"),
                ("QUIT", b"221 bye\r\n"),
            ],
        )
        .await;
        let prober = ServerProber::trusting(ca.roots(), Duration::from_secs(5));
        let at = |port| -> Option<Endpoint> {
            Some(Endpoint {
                host: "localhost".into(),
                port,
                security: Security::Tls,
            })
        };
        let probed = prober.probe_imap(&at(imap).unwrap()).await.unwrap();
        assert!(probed.password_sign_in && !probed.oauth);
        let probed = prober.probe_smtp(&at(smtp).unwrap()).await.unwrap();
        assert!(probed.password_sign_in);
        assert_eq!(
            prober.probe_smtp(&at(imap).unwrap()).await,
            Err(DiscoverError::Unreachable)
        );
        assert_eq!(
            prober.probe_imap(&at(smtp).unwrap()).await,
            Err(DiscoverError::NotMail)
        );
        let untrusted = ServerProber::new(Duration::from_secs(5));
        assert_eq!(
            untrusted.probe_imap(&at(imap).unwrap()).await,
            Err(DiscoverError::TlsFailed)
        );
        assert_eq!(
            untrusted.probe_smtp(&at(smtp).unwrap()).await,
            Err(DiscoverError::TlsFailed)
        );
    }

    #[test]
    fn every_cause_has_a_kind() {
        assert_eq!(
            mail_failure(&MailError::Insecure("x".into())),
            DiscoverError::Insecure
        );
        assert_eq!(
            mail_failure(&MailError::Timeout("x".into())),
            DiscoverError::Timeout
        );
        assert_eq!(
            mail_failure(&MailError::Refused("x".into())),
            DiscoverError::NotMail
        );
        assert_eq!(
            send_failure(&SendError::Insecure("x".into())),
            DiscoverError::Insecure
        );
        assert_eq!(
            send_failure(&SendError::Timeout("x".into())),
            DiscoverError::Timeout
        );
        assert_eq!(
            send_failure(&SendError::Unavailable("x".into())),
            DiscoverError::Unreachable
        );
    }
}
