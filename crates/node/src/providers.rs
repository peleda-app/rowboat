use std::sync::Arc;

use rowboat_api::{AccountSetup, NodeError, Secret};
use rowboat_discover::Security;
use serde_json::json;
use skein_accounts::{
    AccountRecord, Auth, ProviderFactory, ProviderKind, SendSettings, SenderFactory, SenderKind,
};
use skein_core::{AccountId, Credentials, TenantId, TlsRoots};
use skein_mail::{MailError, MailProvider};
use skein_send::{SendError, Sender};

use crate::errors;

/// The provider and sender factories a profile runs with. Desktop: IMAP and SMTP; tests: Skein's
/// fakes (`testing::FakeProviders`). Any account kind other than IMAP with SMTP is refused.
#[derive(Clone)]
pub struct Providers {
    /// Builds mail providers.
    pub mail: Arc<dyn ProviderFactory>,
    /// Builds senders.
    pub send: Arc<dyn SenderFactory>,
}

/// IMAP and SMTP from Skein's provider crates, TLS or STARTTLS verified against the web roots.
#[derive(Debug, Clone, Default)]
pub struct ImapSmtp {
    roots: TlsRoots,
}

impl ImapSmtp {
    pub(crate) fn with_roots(roots: TlsRoots) -> Self {
        Self { roots }
    }
}

impl ProviderFactory for ImapSmtp {
    fn build(
        &self,
        record: &AccountRecord,
        credentials: Credentials,
    ) -> Result<Arc<dyn MailProvider>, MailError> {
        match record.provider {
            ProviderKind::Imap => {
                let mut settings = skein_mail_imap::ImapSettings::from_json(&record.settings)?;
                settings.roots = self.roots.clone();
                Ok(Arc::new(skein_mail_imap::ImapProvider::new(
                    settings,
                    credentials,
                )?))
            }
            _ => Err(MailError::Config("only IMAP accounts are supported".into())),
        }
    }
}

impl SenderFactory for ImapSmtp {
    fn build(
        &self,
        _: &AccountRecord,
        kind: SenderKind,
        settings: &serde_json::Value,
        credentials: Credentials,
    ) -> Result<Arc<dyn Sender>, SendError> {
        match kind {
            SenderKind::Smtp => {
                let mut settings = skein_send_smtp::SmtpSettings::from_json(settings)?;
                settings.roots = self.roots.clone();
                Ok(Arc::new(skein_send_smtp::SmtpSender::new(
                    settings,
                    Some(credentials),
                )?))
            }
            _ => Err(SendError::Invalid("only SMTP sending is supported".into())),
        }
    }
}

impl Providers {
    /// IMAP and SMTP.
    pub fn imap_smtp() -> Self {
        Self::over(ImapSmtp::default())
    }

    pub(crate) fn over(factory: ImapSmtp) -> Self {
        let factory = Arc::new(factory);
        Self {
            mail: factory.clone(),
            send: factory,
        }
    }
}

fn security(s: Security) -> &'static str {
    match s {
        Security::Tls => "tls",
        Security::StartTls => "starttls",
    }
}

/// Skein's account record for a setup: IMAP with a password, SMTP submission with the same user
/// name, TLS or STARTTLS only. Holds no secret.
pub(crate) fn record_for(account: &AccountId, setup: &AccountSetup) -> AccountRecord {
    AccountRecord {
        account: account.clone(),
        provider: ProviderKind::Imap,
        settings: json!({
            "host": setup.imap.host,
            "port": setup.imap.port,
            "security": security(setup.imap.security),
            "username": setup.username,
        }),
        auth: Auth::Password,
        include: None,
        exclude: Vec::new(),
        paused: false,
        send: Some(SendSettings {
            kind: SenderKind::Smtp,
            settings: json!({
                "host": setup.smtp.host,
                "port": setup.smtp.port,
                "security": security(setup.smtp.security),
                "username": setup.username,
            }),
        }),
        pim: None,
    }
}

/// Signs in to the account's IMAP server (opening a session lists capabilities and signs in;
/// listing mailboxes proves the session works) and checks its SMTP server, with `secret`.
/// Nothing is stored.
pub(crate) async fn sign_in(
    providers: &Providers,
    tenant: &TenantId,
    record: &AccountRecord,
    secret: &Secret,
) -> Result<(), NodeError> {
    let password = secret
        .expose_str()
        .ok_or(NodeError::InvalidInput)?
        .to_owned();
    let provider = providers
        .mail
        .build_in(
            tenant,
            record,
            Credentials::Password {
                secret: password.clone(),
            },
        )
        .map_err(|e| errors::mail(&e))?;
    let mut session = provider.connect().await.map_err(|e| errors::mail(&e))?;
    session.mailboxes().await.map_err(|e| errors::mail(&e))?;
    let (kind, settings) = record.sender().ok_or(NodeError::NoSender)?;
    let sender = providers
        .send
        .build_in(
            tenant,
            record,
            kind,
            &settings,
            Credentials::Password { secret: password },
        )
        .map_err(|e| errors::send(&e))?;
    sender.check().await.map_err(|e| errors::send(&e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use skein_core::tls::testing::TestCa;
    use skein_mail::MailCause;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    use super::*;

    async fn refusing_imap(ca: &TestCa) -> u16 {
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
                    let _ = io
                        .get_mut()
                        .write_all(b"* OK [CAPABILITY IMAP4rev1] ready\r\n")
                        .await;
                    let mut line = String::new();
                    while matches!(io.read_line(&mut line).await, Ok(n) if n > 0) {
                        let tag = line.split(' ').next().unwrap_or("x").to_owned();
                        let answer = if line.to_ascii_uppercase().contains("CAPABILITY") {
                            format!("* CAPABILITY IMAP4rev1\r\n{tag} OK done\r\n")
                        } else {
                            format!("{tag} NO [AUTHENTICATIONFAILED] no\r\n")
                        };
                        let _ = io.get_mut().write_all(answer.as_bytes()).await;
                        line.clear();
                    }
                });
            }
        });
        port
    }

    fn record(port: u16, security: &str) -> AccountRecord {
        let mut record = record_for(
            &AccountId::new("a1").unwrap(),
            &AccountSetup {
                address: rowboat_api::EmailAddress::new("ada@example.com").unwrap(),
                display_name: None,
                username: "ada".into(),
                imap: rowboat_api::Endpoint::new("127.0.0.1", port, Security::Tls).unwrap(),
                smtp: rowboat_api::Endpoint::new("127.0.0.1", port, Security::Tls).unwrap(),
            },
        );
        record.settings["security"] = json!(security);
        record
    }

    async fn connect(factory: &ImapSmtp, record: &AccountRecord) -> MailCause {
        let provider = ProviderFactory::build(
            factory,
            record,
            Credentials::Password {
                secret: "pw".into(),
            },
        );
        match provider {
            Err(e) => e.cause(),
            Ok(p) => p.connect().await.err().expect("refused").cause(),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn extra_roots_are_trusted_and_verification_stays_on() {
        let ca = TestCa::new(&["127.0.0.1"]);
        let port = refusing_imap(&ca).await;
        let tls = record(port, "tls");
        assert_eq!(
            connect(&ImapSmtp::with_roots(ca.roots()), &tls).await,
            MailCause::Auth
        );
        assert_eq!(connect(&ImapSmtp::default(), &tls).await, MailCause::Tls);
        let other = TestCa::new(&["127.0.0.1"]);
        assert_eq!(
            connect(&ImapSmtp::with_roots(other.roots()), &tls).await,
            MailCause::Tls
        );
    }

    #[test]
    fn extra_roots_never_allow_plain_text_to_a_remote_host() {
        let ca = TestCa::new(&["127.0.0.1"]);
        let mut plain = record(143, "plain");
        plain.settings["host"] = json!("imap.example.com");
        let built = ProviderFactory::build(
            &ImapSmtp::with_roots(ca.roots()),
            &plain,
            Credentials::Password {
                secret: "pw".into(),
            },
        );
        assert_eq!(built.err().map(|e| e.cause()), Some(MailCause::Insecure));
    }
}
