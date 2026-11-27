//! Two nodes of one group: the owner syncs a fake provider, the second node follows its journal
//! and acts on its mail through commands the owner runs.

mod common;

use std::sync::Arc;

use futures::StreamExt;
use rowboat_api::*;
use rowboat_endpoint::Endpoints;
use rowboat_endpoint_iroh::IrohEndpoints;
use rowboat_endpoint_memory::MemoryEndpoints;
use rowboat_node::testing::{TestNode, reopen_on, test_node_on};
use rowboat_node::{Clock, SystemClock};
use skein_mail::testing::ServerControl;

use common::{add, seed, until, wait_messages, within};

fn system() -> Arc<dyn Clock> {
    Arc::new(SystemClock)
}

fn all(account: &AccountId) -> ListQuery {
    ListQuery {
        scope: Scope::All {
            account: Some(account.clone()),
        },
        unread_only: false,
        cursor: None,
        limit: 200,
    }
}

async fn pair(a: &TestNode, b: &mut TestNode, endpoints: &Arc<dyn Endpoints>) {
    let api = a.node.api();
    let mut events = api.group_events();
    let answer = tokio::spawn(async move {
        while let Some(e) = events.next().await {
            if let GroupEvent::PairingCheck {
                pairing,
                confirm: true,
                ..
            } = e
            {
                let _ = api.confirm_pairing(&pairing, true).await;
                break;
            }
        }
    });
    let invite = a.node.api().create_invite().await.unwrap();
    let r = b.node.api().accept_invite(&invite.qr, None).await.unwrap();
    assert!(r.restart_required);
    answer.await.unwrap();
    b.node.shutdown().await;
    let placeholder = rowboat_node::testing::test_node(0).await.unwrap();
    let old = std::mem::replace(&mut b.node, placeholder.node);
    drop(old);
    b.node = reopen_on(
        &b.dir,
        &b.fakes,
        &b.keystore,
        0,
        system(),
        Some(endpoints.clone()),
    )
    .await
    .unwrap();
}

async fn follow_and_act(endpoints: Arc<dyn Endpoints>) {
    let a = test_node_on(system(), endpoints.clone()).await.unwrap();
    seed(&a, "ada", "INBOX", 5).await;
    let account = add(&a, "ada").await;
    wait_messages(&*a.node.api(), &account, 5).await;
    let mut b = test_node_on(system(), endpoints.clone()).await.unwrap();
    pair(&a, &mut b, &endpoints).await;
    let owner = a.node.api();
    let reader = b.node.api();

    until("the second node to follow the account", || async {
        reader
            .list_accounts()
            .await
            .map(|l| l.iter().any(|i| i.id == account))
            .unwrap_or(false)
    })
    .await;
    wait_messages(&*reader, &account, 5).await;
    let info = &reader.list_accounts().await.unwrap()[0];
    assert_eq!(info.address.as_str(), "ada@example.com");
    let names = |l: Vec<MailboxInfo>| {
        let mut v: Vec<String> = l.into_iter().map(|m| m.id.to_string()).collect();
        v.sort();
        v
    };
    assert_eq!(
        names(reader.list_mailboxes(&account).await.unwrap()),
        names(owner.list_mailboxes(&account).await.unwrap())
    );
    let first = reader.list_messages(all(&account)).await.unwrap().items[0].clone();
    assert!(first.unread);
    assert_eq!(
        reader.message_raw(&account, &first.id).await.unwrap(),
        owner.message_raw(&account, &first.id).await.unwrap(),
        "the blob came over"
    );

    let mut events = reader.events();
    let queued = reader
        .set_read(
            Targets(vec![MessageRef {
                account: account.clone(),
                message: first.id.clone(),
            }]),
            true,
        )
        .await
        .unwrap();
    assert!(
        !reader
            .get_message(&account, &first.id)
            .await
            .unwrap()
            .envelope
            .unread,
        "the overlay shows it at once"
    );
    let command = queued.commands[0].clone();
    let settled = within("the command to settle", async {
        while let Some(e) = events.next().await {
            if let NodeEvent::CommandSettled {
                command: c,
                outcome,
                ..
            } = e
                && c == command
            {
                return outcome;
            }
        }
        panic!("events ended");
    })
    .await;
    assert_eq!(settled, CommandOutcome::Applied);
    let raw = owner.message_raw(&account, &first.id).await.unwrap();
    let flags = a.fakes.server("ada").flags_of("INBOX", &raw).await.unwrap();
    assert!(flags.contains("\\Seen"), "the owner ran it at the provider");
    until("the second node's database to agree", || async {
        reader
            .get_message(&account, &first.id)
            .await
            .unwrap()
            .memberships
            .iter()
            .all(|m| m.flags.iter().any(|f| f == "\\Seen"))
    })
    .await;

    until("the sent mailbox to be known", || async {
        reader
            .list_mailboxes(&account)
            .await
            .unwrap()
            .iter()
            .any(|m| m.role == Some(MailboxRole::Sent))
    })
    .await;
    let draft = Draft {
        id: None,
        account: account.clone(),
        to: vec![Recipient {
            name: Some("Sam".into()),
            address: EmailAddress::new("sam@example.org").unwrap(),
        }],
        cc: vec![],
        bcc: vec![],
        subject: "From the second desk".into(),
        text: "Sent through the owner.".into(),
        reply: None,
        attachments: vec![],
    };
    let mut events = reader.events();
    let sent = reader.send(draft).await.unwrap();
    let outcome = within("the send to settle", async {
        while let Some(e) = events.next().await {
            if let NodeEvent::SendSettled {
                command, outcome, ..
            } = e
                && command == sent.command
                && !matches!(outcome, SendOutcome::Waiting { .. })
            {
                return outcome;
            }
        }
        panic!("events ended");
    })
    .await;
    assert_eq!(outcome, SendOutcome::Sent { refused: 0 });
    let deliveries = a.fakes.sender().deliveries();
    assert_eq!(deliveries.len(), 1, "sent once, by the owner");
    assert_eq!(deliveries[0].recipients, vec!["sam@example.org"]);
    assert!(b.fakes.sender().deliveries().is_empty());
    until("the draft to go away", || async {
        reader.list_drafts().await.unwrap().is_empty()
    })
    .await;

    assert_eq!(
        reader
            .update_account(&account, AccountPatch::default())
            .await,
        Err(NodeError::Unavailable),
        "the owner manages the account"
    );
    a.node.shutdown().await;
    b.node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_node_reads_and_acts_in_memory() {
    follow_and_act(Arc::new(MemoryEndpoints::new())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_node_reads_and_acts_over_iroh_on_loopback() {
    follow_and_act(Arc::new(IrohEndpoints::loopback())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_account_added_after_pairing_is_followed_and_survives_a_restart() {
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let a = test_node_on(system(), endpoints.clone()).await.unwrap();
    let mut b = test_node_on(system(), endpoints.clone()).await.unwrap();
    pair(&a, &mut b, &endpoints).await;
    seed(&a, "bea", "INBOX", 3).await;
    let account = add(&a, "bea").await;
    wait_messages(&*b.node.api(), &account, 3).await;
    b.node.shutdown().await;
    let placeholder = rowboat_node::testing::test_node(0).await.unwrap();
    let old = std::mem::replace(&mut b.node, placeholder.node);
    drop(old);
    b.node = reopen_on(
        &b.dir,
        &b.fakes,
        &b.keystore,
        0,
        system(),
        Some(endpoints.clone()),
    )
    .await
    .unwrap();
    assert_eq!(
        b.node
            .api()
            .list_messages(all(&account))
            .await
            .unwrap()
            .items
            .len(),
        3,
        "the replica reads after a restart"
    );
    let server = a.fakes.server("bea");
    for n in 10..12 {
        server
            .add(
                "INBOX",
                &common::message(n, "Later"),
                skein_core::Flags::default(),
            )
            .await;
    }
    a.node.api().sync_now(Some(&account)).await.unwrap();
    wait_messages(&*b.node.api(), &account, 5).await;
    a.node.shutdown().await;
    b.node.shutdown().await;
}
