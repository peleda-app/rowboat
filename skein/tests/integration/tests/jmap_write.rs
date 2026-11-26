//! The mail write conformance suite against Stalwart over JMAP.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use skein_core::{BlobHash, CommandBody, Credentials, Flags, MailboxRole};
use skein_integration::{enabled, env, mailbox_with_role};
use skein_mail::testing::{ServerControl, write_conformance};
use skein_mail::{MailProvider, WriteOutcome};
use skein_mail_jmap::{JmapProvider, JmapSettings};

const OTHER: &str = "skein-write-other";

fn provider() -> JmapProvider {
    JmapProvider::new(
        JmapSettings::new(env("SKEIN_IT_STALWART_URL"), env("SKEIN_IT_STALWART_USER")),
        Credentials::Password {
            secret: env("SKEIN_IT_STALWART_PASSWORD"),
        },
    )
    .unwrap()
}

/// Adds messages through the provider's own `Append` (upload and `Email/import`); the suite
/// calls nothing else.
struct Control(JmapProvider);

#[async_trait]
impl ServerControl for Control {
    async fn create_mailbox(&self, _mailbox: &str) {
        unimplemented!("write_conformance does not create mailboxes through the control")
    }

    async fn add(&self, mailbox: &str, bytes: &[u8], flags: Flags) {
        let mut session = self.0.connect().await.unwrap();
        let outcome = session
            .apply(
                &CommandBody::Append {
                    mailbox: mailbox.to_owned(),
                    blob: BlobHash::of(bytes),
                    flags,
                    received_at: None,
                },
                Some(Bytes::copy_from_slice(bytes)),
            )
            .await
            .unwrap();
        assert_eq!(outcome, WriteOutcome::Applied);
    }

    async fn remove(&self, _mailbox: &str, _bytes: &[u8]) {
        unimplemented!("write_conformance does not remove through the control")
    }

    async fn set_flags(&self, _mailbox: &str, _bytes: &[u8], _flags: Flags) {
        unimplemented!("write_conformance does not set flags through the control")
    }

    async fn invalidate(&self, _mailbox: &str) {
        unimplemented!("JMAP states cannot be invalidated from outside")
    }

    async fn flags_of(&self, _mailbox: &str, _bytes: &[u8]) -> Option<Flags> {
        unimplemented!("write_conformance does not read flags through the control")
    }
}

async fn other_mailbox(provider: &JmapProvider) -> String {
    let mut session = provider.connect().await.unwrap();
    let find = |boxes: Vec<skein_core::MailboxInfo>| {
        boxes.into_iter().find(|b| b.path == OTHER).map(|b| b.id)
    };
    if let Some(id) = find(session.mailboxes().await.unwrap()) {
        return id;
    }
    let outcome = session
        .apply(
            &CommandBody::CreateMailbox {
                path: OTHER.to_owned(),
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(outcome, WriteOutcome::Applied);
    find(session.mailboxes().await.unwrap()).expect("the created mailbox is listed")
}

#[tokio::test]
async fn jmap_writes_keep_the_contract_against_stalwart() {
    if !enabled() {
        eprintln!("SKEIN_IT is not set; skipping");
        return;
    }
    let provider = provider();
    let inbox = mailbox_with_role(&provider, MailboxRole::Inbox).await;
    let other = other_mailbox(&provider).await;
    write_conformance(
        Arc::new(provider.clone()),
        Arc::new(Control(provider)),
        &inbox,
        &other,
        None,
    )
    .await;
}
