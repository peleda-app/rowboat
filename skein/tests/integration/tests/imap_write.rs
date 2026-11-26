//! The write half of the mail contract against real IMAP servers in containers.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use skein_core::{BlobHash, CommandBody, Credentials, Flags, ItemRef};
use skein_integration::{enabled, env};
use skein_mail::testing::{ServerControl, write_conformance};
use skein_mail::{MailChange, MailProvider, MailSession, WriteOutcome};
use skein_mail_imap::{ImapProvider, ImapSettings, Security};

const OTHER: &str = "skein-other";

fn imap(port: &str, user: &str, password: &str) -> ImapProvider {
    let mut settings = ImapSettings::new("127.0.0.1", user);
    settings.port = Some(port.parse().unwrap());
    settings.security = Security::Plain;
    ImapProvider::new(
        settings,
        Credentials::Password {
            secret: password.to_owned(),
        },
    )
    .unwrap()
}

/// Changes the server through a session of the provider under test, which is as far behind the
/// tested session's back as a real server without an admin API allows.
struct Control(ImapProvider);

impl Control {
    async fn session(&self) -> Box<dyn MailSession> {
        self.0.connect().await.expect("connect")
    }

    async fn find(
        session: &mut Box<dyn MailSession>,
        mailbox: &str,
        bytes: &[u8],
    ) -> Option<(ItemRef, Flags)> {
        let batch = session.changes(mailbox, None, 10_000).await.unwrap();
        let added: Vec<(ItemRef, Flags)> = batch
            .changes
            .into_iter()
            .filter_map(|c| match c {
                MailChange::Added { item, flags, .. } => Some((item, flags)),
                _ => None,
            })
            .collect();
        let items: Vec<ItemRef> = added.iter().map(|(i, _)| i.clone()).collect();
        let raw = session.fetch(mailbox, &items).await.unwrap();
        let item = raw.into_iter().find(|m| m.bytes.as_ref() == bytes)?.item;
        added.into_iter().find(|(i, _)| *i == item)
    }

    async fn write(
        session: &mut Box<dyn MailSession>,
        command: CommandBody,
        content: Option<Bytes>,
    ) {
        let outcome = session.apply(&command, content).await.unwrap();
        assert!(
            matches!(outcome, WriteOutcome::Applied)
                || outcome
                    == WriteOutcome::Failed {
                        reason: "exists".into()
                    },
            "{outcome:?}"
        );
    }
}

#[async_trait]
impl ServerControl for Control {
    async fn create_mailbox(&self, mailbox: &str) {
        let mut session = self.session().await;
        Self::write(
            &mut session,
            CommandBody::CreateMailbox {
                path: mailbox.to_owned(),
            },
            None,
        )
        .await;
        session.logout().await.unwrap();
    }

    async fn add(&self, mailbox: &str, bytes: &[u8], flags: Flags) {
        let mut session = self.session().await;
        Self::write(
            &mut session,
            CommandBody::Append {
                mailbox: mailbox.to_owned(),
                blob: BlobHash::of(bytes),
                flags,
                received_at: None,
            },
            Some(Bytes::copy_from_slice(bytes)),
        )
        .await;
        session.logout().await.unwrap();
    }

    async fn remove(&self, mailbox: &str, bytes: &[u8]) {
        let mut session = self.session().await;
        if let Some((item, _)) = Self::find(&mut session, mailbox, bytes).await {
            Self::write(
                &mut session,
                CommandBody::Delete {
                    mailbox: mailbox.to_owned(),
                    items: vec![item],
                    to_trash: false,
                },
                None,
            )
            .await;
        }
        session.logout().await.unwrap();
    }

    async fn set_flags(&self, mailbox: &str, bytes: &[u8], flags: Flags) {
        let mut session = self.session().await;
        if let Some((item, now)) = Self::find(&mut session, mailbox, bytes).await {
            Self::write(
                &mut session,
                CommandBody::SetFlags {
                    mailbox: mailbox.to_owned(),
                    items: vec![item],
                    add: flags.clone(),
                    remove: now,
                },
                None,
            )
            .await;
        }
        session.logout().await.unwrap();
    }

    async fn invalidate(&self, _mailbox: &str) {
        unimplemented!("a real server cannot be made to change UIDVALIDITY from a client");
    }

    async fn flags_of(&self, mailbox: &str, bytes: &[u8]) -> Option<Flags> {
        let mut session = self.session().await;
        let found = Self::find(&mut session, mailbox, bytes).await;
        session.logout().await.unwrap();
        found.map(|(_, flags)| flags)
    }
}

/// Runs the suite on `INBOX` and [`OTHER`], creating `extra` mailboxes first (GreenMail starts
/// with nothing but `INBOX`, so it gets a `Trash` found by its name).
async fn run(provider: ImapProvider, extra: &[&str]) {
    let control = Arc::new(Control(provider.clone()));
    for mailbox in [OTHER].iter().chain(extra) {
        control.create_mailbox(mailbox).await;
    }
    let mut session = provider.connect().await.unwrap();
    let caps = session.capabilities().await.unwrap();
    session.logout().await.unwrap();
    eprintln!("capabilities: {caps:?}");
    assert!(caps.trash && caps.copy && caps.mailboxes && caps.append_received_at);
    write_conformance(Arc::new(provider), control, "INBOX", OTHER, None).await;
}

#[tokio::test]
async fn imap_writes_against_greenmail() {
    if !enabled() {
        eprintln!("SKEIN_IT is not set; skipping");
        return;
    }
    run(
        imap(
            &env("SKEIN_IT_IMAP_PORT"),
            &env("SKEIN_IT_IMAP_USER"),
            &env("SKEIN_IT_IMAP_PASSWORD"),
        ),
        &["Trash"],
    )
    .await;
}

#[tokio::test]
async fn imap_writes_against_dovecot() {
    if !enabled() {
        eprintln!("SKEIN_IT is not set; skipping");
        return;
    }
    run(
        imap(
            &env("SKEIN_IT_DOVECOT_PORT"),
            &env("SKEIN_IT_DOVECOT_USER"),
            &env("SKEIN_IT_DOVECOT_PASSWORD"),
        ),
        &[],
    )
    .await;
}

#[tokio::test]
async fn imap_writes_against_stalwart() {
    if !enabled() {
        eprintln!("SKEIN_IT is not set; skipping");
        return;
    }
    run(
        imap(
            &env("SKEIN_IT_STALWART_IMAP_PORT"),
            &env("SKEIN_IT_STALWART_USER"),
            &env("SKEIN_IT_STALWART_PASSWORD"),
        ),
        &[],
    )
    .await;
}
