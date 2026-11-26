#![allow(dead_code)]

use std::future::Future;
use std::time::Duration;

use rowboat_api::{AccountId, AccountSetup, EmailAddress, Endpoint, NodeApi, Secret, Security};
use rowboat_node::testing::TestNode;
use skein_core::Flags;
use skein_mail::testing::ServerControl;

pub const PASSWORD: &str = "correct-horse-battery-1";

pub async fn until<F, Fut>(what: &str, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for {what}");
}

pub fn setup(user: &str) -> AccountSetup {
    AccountSetup {
        address: EmailAddress::new(format!("{user}@example.com")).unwrap(),
        display_name: Some("Ada Example".into()),
        username: user.into(),
        imap: Endpoint::new("imap.example.com", 993, Security::Tls).unwrap(),
        smtp: Endpoint::new("smtp.example.com", 465, Security::Tls).unwrap(),
    }
}

pub fn message(n: usize, subject: &str) -> Vec<u8> {
    format!(
        "From: Sender {n} <sender{n}@example.org>\r\nTo: ada@example.com\r\nSubject: {subject}\r\nMessage-ID: <m{n}@example.org>\r\nDate: Mon, 2 Nov 2026 09:{:02}:00 +0000\r\n\r\nBody of message {n} about gardens.\r\n",
        n % 60
    )
    .into_bytes()
}

pub async fn seed(t: &TestNode, user: &str, mailbox: &str, count: usize) {
    let server = t.fakes.server(user);
    for n in 0..count {
        server
            .add(
                mailbox,
                &message(n, &format!("Note {n} for {user}")),
                Flags::default(),
            )
            .await;
    }
}

pub async fn add(t: &TestNode, user: &str) -> AccountId {
    t.node
        .api()
        .add_account(setup(user), Secret::from_text(PASSWORD))
        .await
        .unwrap()
}

pub async fn wait_messages(api: &dyn NodeApi, account: &AccountId, n: usize) {
    until("messages to sync", || async {
        api.list_messages(rowboat_api::ListQuery {
            scope: rowboat_api::Scope::All {
                account: Some(account.clone()),
            },
            unread_only: false,
            cursor: None,
            limit: 200,
        })
        .await
        .map(|p| p.items.len() >= n)
        .unwrap_or(false)
    })
    .await;
}
