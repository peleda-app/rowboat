//! The node end to end on the test profile.

mod common;

use std::sync::Arc;

use futures::StreamExt;
use rowboat_api::*;
use rowboat_node::testing::{reopen, test_node};
use rowboat_node::{BuildError, Node, Profile};
use skein_mail::testing::ServerControl;

use common::*;

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

fn target(account: &AccountId, message: &MessageId) -> Targets {
    Targets(vec![MessageRef {
        account: account.clone(),
        message: message.clone(),
    }])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conformance_on_the_test_profile() {
    let t = test_node(0).await.unwrap();
    let api = t.node.api();
    rowboat_api::testing::validation(&*api).await;
    seed(&t, "ada", "INBOX", 5).await;
    let account = add(&t, "ada").await;
    wait_messages(&*api, &account, 5).await;
    rowboat_api::testing::seeded(&*api, &account).await;
    t.node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn first_run_sync_threads_search_and_restart() {
    let t = test_node(0).await.unwrap();
    let api = t.node.api();
    let info = api.node_info().await.unwrap();
    assert_eq!(info.node_id.len(), 52);
    assert!(info.group_id.starts_with('g') && info.group_id.len() == 27);
    assert!(
        t.keystore
            .class_of(&rowboat_keystore::KeyName::new("rowboat.master").unwrap())
            .is_some()
    );

    seed(&t, "ada", "INBOX", 3).await;
    let reply = b"From: Ada <ada@example.com>\r\nTo: sender0@example.org\r\nSubject: Re: Note 0\r\nMessage-ID: <r0@example.com>\r\nIn-Reply-To: <m0@example.org>\r\nReferences: <m0@example.org>\r\n\r\nThanks!\r\n";
    t.fakes
        .server("ada")
        .add("Sent", reply, skein_core::Flags::new(["\\Seen"]))
        .await;
    let account = add(&t, "ada").await;
    wait_messages(&*api, &account, 4).await;

    let accounts = api.list_accounts().await.unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].address.as_str(), "ada@example.com");
    until("first sync", || async {
        api.list_accounts().await.unwrap()[0].first_sync_completed
    })
    .await;

    let boxes = api.list_mailboxes(&account).await.unwrap();
    let inbox = boxes
        .iter()
        .find(|b| b.role == Some(MailboxRole::Inbox))
        .unwrap();
    assert_eq!((inbox.total, inbox.unread), (3, 3));

    let threads = api.list_threads(all(&account)).await.unwrap();
    assert_eq!(
        threads.items.len(),
        3,
        "the reply joins its parent's thread"
    );
    let joined = threads.items.iter().find(|t| t.count == 2).unwrap();
    let detail = api.get_thread(&account, joined.id).await.unwrap();
    assert_eq!(detail.messages.len(), 2);
    assert_eq!(detail.tree.len(), 1);
    assert_eq!(detail.tree[0].children.len(), 1);

    let found = api
        .search(SearchQuery {
            account: None,
            text: "gardens".into(),
            filter: SearchFilter {
                role: Some(MailboxRole::Inbox),
                ..SearchFilter::default()
            },
            limit: 10,
        })
        .await
        .unwrap();
    assert_eq!(found.len(), 3);
    let by_role = api
        .list_messages(ListQuery {
            scope: Scope::Role {
                account: None,
                role: MailboxRole::Sent,
            },
            unread_only: false,
            cursor: None,
            limit: 10,
        })
        .await
        .unwrap();
    assert_eq!(by_role.items.len(), 1);
    let suggestions = api.suggest_addresses("sender", 5).await.unwrap();
    assert!(!suggestions.is_empty());
    assert!(
        api.knows_address(&account, &EmailAddress::new("sender0@example.org").unwrap())
            .await
            .unwrap()
    );
    assert!(
        !api.knows_address(&account, &EmailAddress::new("sender1@example.org").unwrap())
            .await
            .unwrap(),
        "an address that only wrote in is not known"
    );

    let raw = api
        .message_raw(&account, &by_role.items[0].id)
        .await
        .unwrap();
    assert_eq!(&raw[..], &reply[..]);

    let node_id = t.node.node_id().to_owned();
    t.node.shutdown().await;
    drop(api);
    let rowboat_node::testing::TestNode {
        node,
        fakes,
        keystore,
        dir,
    } = t;
    drop(node);
    let again = reopen(&dir, &fakes, &keystore, 0).await.unwrap();
    assert_eq!(again.node_id(), node_id);
    let api = again.api();
    assert_eq!(api.list_accounts().await.unwrap().len(), 1);
    assert_eq!(
        api.list_messages(all(&account)).await.unwrap().items.len(),
        4
    );
    again.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mark_read_shows_at_once_and_settles() {
    let t = test_node(0).await.unwrap();
    let api = t.node.api();
    seed(&t, "ada", "INBOX", 2).await;
    let account = add(&t, "ada").await;
    wait_messages(&*api, &account, 2).await;
    let mut events = api.events();
    let first = api.list_messages(all(&account)).await.unwrap().items[0].clone();
    assert!(first.unread);
    let queued = api
        .set_read(target(&account, &first.id), true)
        .await
        .unwrap();
    assert_eq!(queued.commands.len(), 1);
    assert!(
        !api.get_message(&account, &first.id)
            .await
            .unwrap()
            .envelope
            .unread
    );
    let command = queued.commands[0].clone();
    let settled = tokio::time::timeout(std::time::Duration::from_secs(20), async {
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
    .await
    .unwrap();
    assert_eq!(settled, CommandOutcome::Applied);
    let raw = api.message_raw(&account, &first.id).await.unwrap();
    let flags = t.fakes.server("ada").flags_of("INBOX", &raw).await.unwrap();
    assert!(flags.contains("\\Seen"));
    until("the database to agree", || async {
        let d = api.get_message(&account, &first.id).await.unwrap();
        d.memberships
            .iter()
            .all(|m| m.flags.iter().any(|f| f == "\\Seen"))
    })
    .await;
    assert!(
        !api.get_message(&account, &first.id)
            .await
            .unwrap()
            .envelope
            .unread
    );
    t.node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn move_archive_and_delete() {
    let t = test_node(0).await.unwrap();
    let api = t.node.api();
    seed(&t, "ada", "INBOX", 4).await;
    let account = add(&t, "ada").await;
    wait_messages(&*api, &account, 4).await;
    let items = api.list_messages(all(&account)).await.unwrap().items;
    let inbox_scope = ListQuery {
        scope: Scope::Role {
            account: Some(account.clone()),
            role: MailboxRole::Inbox,
        },
        unread_only: false,
        cursor: None,
        limit: 50,
    };

    let trash = MailboxId::new("Trash").unwrap();
    api.move_to(target(&account, &items[0].id), &trash)
        .await
        .unwrap();
    api.archive(target(&account, &items[1].id)).await.unwrap();
    api.delete(target(&account, &items[2].id), false)
        .await
        .unwrap();
    api.delete(target(&account, &items[3].id), true)
        .await
        .unwrap();
    assert!(
        api.list_messages(inbox_scope.clone())
            .await
            .unwrap()
            .items
            .is_empty(),
        "every change shows at once"
    );
    let server = t.fakes.server("ada");
    until("the provider to apply everything", || async {
        let raw0 = message_bytes(&server, "Trash").await;
        let archived = message_bytes(&server, "Archive").await;
        raw0 == 2 && archived == 1 && message_bytes(&server, "INBOX").await == 0
    })
    .await;
    until("the database to follow", || async {
        api.list_messages(all(&account)).await.unwrap().items.len() == 3
    })
    .await;
    assert!(
        api.list_messages(inbox_scope)
            .await
            .unwrap()
            .items
            .is_empty()
    );

    let other = MailboxId::new("Nowhere").unwrap();
    assert_eq!(
        api.move_to(target(&account, &items[1].id), &other).await,
        Err(NodeError::NotFound)
    );
    t.node.shutdown().await;
}

async fn message_bytes(server: &skein_mail::testing::FakeMail, mailbox: &str) -> usize {
    use skein_mail::MailProvider;
    let mut s = server.connect().await.unwrap();
    s.changes(mailbox, None, 1000)
        .await
        .map(|c| {
            c.changes
                .iter()
                .filter(|c| matches!(c, skein_mail::MailChange::Added { .. }))
                .count()
        })
        .unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn send_with_an_undo_window() {
    let t = test_node(1_500).await.unwrap();
    let api = t.node.api();
    let account = add(&t, "ada").await;
    until("the mailboxes to be known", || async {
        api.list_mailboxes(&account)
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
        bcc: vec![Recipient {
            name: None,
            address: EmailAddress::new("hidden@example.net").unwrap(),
        }],
        subject: "Plans".into(),
        text: "See you at the garden.".into(),
        reply: None,
        attachments: vec![],
    };
    let id = api.save_draft(draft.clone()).await.unwrap();
    assert_eq!(api.list_drafts().await.unwrap().len(), 1);
    let mut saved = api.get_draft(&id).await.unwrap();

    let queued = api.send(saved.clone()).await.unwrap();
    assert_eq!(queued.draft, id);
    assert!(api.list_drafts().await.unwrap().is_empty());
    assert_eq!(api.outbox().await.unwrap().len(), 1);
    api.cancel_send(&account, &queued.command).await.unwrap();
    assert_eq!(
        api.list_drafts().await.unwrap().len(),
        1,
        "a cancelled send is a draft again"
    );

    let quick = api.send(draft.clone()).await.unwrap();
    api.cancel_send(&account, &quick.command).await.unwrap();
    let back = api.get_draft(&quick.draft).await.unwrap();
    assert_eq!(back.id.as_ref(), Some(&quick.draft));
    assert_eq!(back.subject, "Plans");
    assert!(api.delete_draft(&quick.draft).await.unwrap());
    assert_eq!(api.list_drafts().await.unwrap().len(), 1);
    assert!(t.fakes.sender().deliveries().is_empty());
    assert_eq!(
        api.cancel_send(&account, &queued.command).await,
        Ok(()),
        "cancelling again succeeds"
    );

    saved.subject = "Plans, again".into();
    let queued = api.send(saved).await.unwrap();
    until("the message to leave", || async {
        !t.fakes.sender().deliveries().is_empty()
    })
    .await;
    let d = &t.fakes.sender().deliveries()[0];
    assert_eq!(d.recipients, vec!["sam@example.org", "hidden@example.net"]);
    assert!(!String::from_utf8_lossy(&d.bytes).contains("hidden@example.net"));
    assert!(matches!(
        api.cancel_send(&account, &queued.command).await,
        Err(NodeError::NotFound | NodeError::AlreadyStarted)
    ));
    until("the sent copy to appear", || async {
        api.list_messages(ListQuery {
            scope: Scope::Role {
                account: Some(account.clone()),
                role: MailboxRole::Sent,
            },
            unread_only: false,
            cursor: None,
            limit: 10,
        })
        .await
        .map(|p| p.items.len() == 1)
        .unwrap_or(false)
    })
    .await;
    until("the draft to go", || async {
        api.list_drafts().await.unwrap().is_empty()
    })
    .await;
    assert!(api.outbox().await.unwrap().is_empty());
    t.node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removing_an_account_sweeps_its_mail() {
    let t = test_node(0).await.unwrap();
    let api = t.node.api();
    seed(&t, "ada", "INBOX", 3).await;
    seed(&t, "bob", "INBOX", 2).await;
    let ada = add(&t, "ada").await;
    let bob = add(&t, "bob").await;
    wait_messages(&*api, &ada, 3).await;
    wait_messages(&*api, &bob, 2).await;
    let ada_msg = api.list_messages(all(&ada)).await.unwrap().items[0]
        .id
        .clone();
    api.remove_account(&ada).await.unwrap();
    assert_eq!(api.list_accounts().await.unwrap().len(), 1);
    assert_eq!(api.list_mailboxes(&ada).await, Err(NodeError::NotFound));
    until("the removal to finish", || async {
        let blobs = t.dir.path().join("node/objects/tenants");
        count_files(&blobs, ada_msg.as_str()) == 0
    })
    .await;
    until("the account's records to go", || async {
        let tenants = t.dir.path().join("node/objects/tenants");
        count_files(&tenants, ada.as_str()) == keyring_tombstones(&tenants, ada.as_str())
    })
    .await;
    assert_eq!(api.list_messages(all(&bob)).await.unwrap().items.len(), 2);
    let again = add(&t, "ada").await;
    assert_ne!(again, ada);
    t.node.shutdown().await;
}

fn keyring_tombstones(tenants: &std::path::Path, account: &str) -> usize {
    std::fs::read_dir(tenants)
        .into_iter()
        .flatten()
        .flatten()
        .map(|t| count_files(&t.path().join("control/keys/accounts"), account))
        .sum()
}

fn count_files(dir: &std::path::Path, name: &str) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .map(|e| {
            let p = e.path();
            if p.is_dir() {
                count_files(&p, name)
            } else {
                usize::from(
                    p.file_name()
                        .and_then(|f| f.to_str())
                        .is_some_and(|f| f.contains(name)),
                )
            }
        })
        .sum()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lagging_subscriber_does_not_hold_up_sync() {
    let t = test_node(0).await.unwrap();
    let api = t.node.api();
    let _never_read = api.events();
    seed(&t, "ada", "INBOX", 120).await;
    let account = add(&t, "ada").await;
    wait_messages(&*api, &account, 120).await;
    t.node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_process_over_the_directory_is_locked() {
    let t = test_node(0).await.unwrap();
    let second = reopen(&t.dir, &t.fakes, &t.keystore, 0).await;
    assert!(matches!(second, Err(BuildError::Locked)));
    t.node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_or_wrong_keys_are_never_replaced() {
    let t = test_node(0).await.unwrap();
    t.node.shutdown().await;
    let dir = t.dir.clone();
    let fakes = t.fakes.clone();
    let keystore = t.keystore.clone();
    drop(t);
    let master = rowboat_keystore::KeyName::new("rowboat.master").unwrap();
    let original = {
        use rowboat_keystore::Keystore;
        keystore.get(&master).await.unwrap().unwrap()
    };
    keystore.tamper(&master, rowboat_keystore::Secret::new(vec![7; 32]));
    assert!(matches!(
        reopen(&dir, &fakes, &keystore, 0).await,
        Err(BuildError::KeysLost)
    ));
    keystore.tamper(&master, rowboat_keystore::Secret::new(vec![7; 31]));
    assert!(matches!(
        reopen(&dir, &fakes, &keystore, 0).await,
        Err(BuildError::KeysLost)
    ));
    {
        use rowboat_keystore::Keystore;
        keystore.delete(&master).await.unwrap();
    }
    assert!(matches!(
        reopen(&dir, &fakes, &keystore, 0).await,
        Err(BuildError::KeysLost)
    ));
    {
        use rowboat_keystore::{KeyClass, Keystore};
        assert!(
            keystore.get(&master).await.unwrap().is_none(),
            "no new key was made"
        );
        keystore
            .put(&master, &original, KeyClass::Background)
            .await
            .unwrap();
    }
    keystore.set_locked(true);
    assert!(matches!(
        reopen(&dir, &fakes, &keystore, 0).await,
        Err(BuildError::KeystoreLocked)
    ));
    keystore.set_locked(false);
    let node = reopen(&dir, &fakes, &keystore, 0).await.unwrap();
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_foreign_directory_is_not_reused() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("node")).unwrap();
    std::fs::write(dir.path().join("node/notes.txt"), b"someone else's").unwrap();
    let fakes = rowboat_node::testing::FakeProviders::new();
    let keystore = rowboat_keystore_memory::MemoryKeystore::new();
    assert!(matches!(
        reopen(&dir, &fakes, &keystore, 0).await,
        Err(BuildError::NotEmpty)
    ));
    let missing = Node::builder()
        .profile(Profile::Test(rowboat_node::testing::fast(0)))
        .data_dir(dir.path().join("x"))
        .build()
        .await;
    assert!(matches!(missing, Err(BuildError::Missing(_))));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_sign_in_stores_nothing() {
    let t = test_node(0).await.unwrap();
    t.fakes.require_password(PASSWORD);
    let api = t.node.api();
    assert_eq!(
        api.add_account(setup("ada"), Secret::from_text("wrong-password"))
            .await,
        Err(NodeError::AuthFailed)
    );
    assert!(api.list_accounts().await.unwrap().is_empty());
    let account = add(&t, "ada").await;
    assert_eq!(
        api.add_account(setup("ada"), Secret::from_text(PASSWORD))
            .await,
        Err(NodeError::AccountExists)
    );
    assert_eq!(
        api.update_password(&account, Secret::from_text("wrong-password"))
            .await,
        Err(NodeError::AuthFailed)
    );
    api.update_password(&account, Secret::from_text(PASSWORD))
        .await
        .unwrap();
    t.node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn targets_of_several_accounts_cannot_be_moved_together() {
    let t = test_node(0).await.unwrap();
    let api = t.node.api();
    seed(&t, "ada", "INBOX", 1).await;
    seed(&t, "bob", "INBOX", 1).await;
    let ada = add(&t, "ada").await;
    let bob = add(&t, "bob").await;
    wait_messages(&*api, &ada, 1).await;
    wait_messages(&*api, &bob, 1).await;
    let a = api.list_messages(all(&ada)).await.unwrap().items[0]
        .id
        .clone();
    let b = api.list_messages(all(&bob)).await.unwrap().items[0]
        .id
        .clone();
    let mixed = Targets(vec![
        MessageRef {
            account: ada.clone(),
            message: a.clone(),
        },
        MessageRef {
            account: bob.clone(),
            message: b.clone(),
        },
    ]);
    assert_eq!(
        api.move_to(mixed.clone(), &MailboxId::new("Trash").unwrap())
            .await,
        Err(NodeError::InvalidInput)
    );
    let crossed = Targets(vec![MessageRef {
        account: ada.clone(),
        message: b,
    }]);
    let q = api.set_read(crossed, true).await.unwrap();
    assert!(
        q.commands.is_empty() && q.skipped.len() == 1,
        "another account's message is not found in this one"
    );
    let both = api.set_read(mixed, true).await.unwrap();
    assert_eq!(both.commands.len(), 2);
    t.node.shutdown().await;
}

struct Lying(Arc<dyn rinse_mail::Content>);

#[async_trait::async_trait]
impl rinse_mail::Content for Lying {
    async fn render(
        &self,
        request: rinse_mail::RenderRequest,
    ) -> Result<rinse_mail::Rendered, rinse_mail::ContentError> {
        let mut r = self.0.render(request).await?;
        r.headers.subject = Some("forged\u{202e}subject\nwith a break".into());
        Ok(r)
    }

    async fn decode_part(
        &self,
        request: rinse_mail::PartRequest,
    ) -> Result<rinse_mail::DecodedPart, rinse_mail::ContentError> {
        self.0.decode_part(request).await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_output_failing_verification_leaves_the_message_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let fakes = rowboat_node::testing::FakeProviders::new();
    let keystore = rowboat_keystore_memory::MemoryKeystore::new();
    let node = Node::builder()
        .profile(Profile::Test(rowboat_node::testing::fast(0)))
        .data_dir(dir.path().join("node"))
        .keystore(Arc::new(keystore))
        .content(Arc::new(Lying(Arc::new(
            rinse_mail_direct::DirectContent::new(),
        ))))
        .providers(fakes.providers())
        .build()
        .await
        .unwrap();
    node.start().await;
    let api = node.api();
    fakes
        .server("ada")
        .add("INBOX", &message(1, "Hello"), skein_core::Flags::default())
        .await;
    let account = api
        .add_account(setup("ada"), Secret::from_text(PASSWORD))
        .await
        .unwrap();
    wait_messages(&*api, &account, 1).await;
    let e = &api.list_messages(all(&account)).await.unwrap().items[0];
    assert!(!e.available);
    assert!(
        e.subject.is_none(),
        "nothing of the refused output reaches the database"
    );
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_calendar_part_is_never_parsed_in_the_node_process() {
    let t = test_node(0).await.unwrap();
    let api = t.node.api();
    let message = include_bytes!("../../../skein/crates/itip/tests/fixtures/invitation.eml");
    t.fakes
        .server("ada")
        .add("INBOX", message, skein_core::Flags::default())
        .await;
    let account = add(&t, "ada").await;
    wait_messages(&*api, &account, 1).await;
    let blobs = t.dir.path().join("node/objects/tenants");
    let whole = skein_core::BlobHash::of(message).to_hex();
    let calendar = skein_itip::imip::find(message).unwrap().calendar;
    let part = skein_core::BlobHash::of(&calendar).to_hex();
    assert_eq!(count_files(&blobs, &whole), 1);
    assert_eq!(count_files(&blobs, &part), 0);
    t.node.shutdown().await;
}

async fn next_new_mail(events: &mut EventStream, secs: u64) -> Option<(AccountId, Vec<NewMail>)> {
    tokio::time::timeout(std::time::Duration::from_secs(secs), async {
        while let Some(e) = events.next().await {
            if let NodeEvent::NewMail { account, items } = e {
                return Some((account, items));
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn new_mail_after_the_first_sync_notifies_and_backfill_does_not() {
    let clock = rowboat_node::ManualClock::at(60_000);
    let t = rowboat_node::testing::test_node_with_clock(0, Arc::new(clock))
        .await
        .unwrap();
    let api = t.node.api();
    let mut events = api.events();
    seed(&t, "ada", "INBOX", 3).await;
    let account = add(&t, "ada").await;
    until("the first sync", || async {
        api.list_accounts()
            .await
            .map(|a| a.iter().any(|a| a.first_sync_completed))
            .unwrap_or(false)
    })
    .await;
    wait_messages(&*api, &account, 3).await;
    assert!(
        next_new_mail(&mut events, 1).await.is_none(),
        "backfill notified"
    );

    let server = t.fakes.server("ada");
    server
        .add(
            "INBOX",
            &message(41, "Fresh note"),
            skein_core::Flags::default(),
        )
        .await;
    api.sync_now(Some(&account)).await.unwrap();
    let (who, items) = next_new_mail(&mut events, 20)
        .await
        .expect("no notification");
    assert_eq!(who, account);
    assert_eq!(items.len(), 1);
    let detail = api.get_message(&account, &items[0].message).await.unwrap();
    assert_eq!(detail.envelope.subject.as_deref(), Some("Fresh note"));
    assert_eq!(items[0].thread, detail.envelope.thread);

    api.update_account(
        &account,
        AccountPatch {
            notify: Some(false),
            ..AccountPatch::default()
        },
    )
    .await
    .unwrap();
    assert!(!api.list_accounts().await.unwrap()[0].notify);
    server
        .add(
            "INBOX",
            &message(42, "Muted note"),
            skein_core::Flags::default(),
        )
        .await;
    api.sync_now(Some(&account)).await.unwrap();
    wait_messages(&*api, &account, 5).await;
    assert!(
        next_new_mail(&mut events, 1).await.is_none(),
        "a muted account notified"
    );
    t.node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn folder_settings_show_in_the_account() {
    let t = test_node(0).await.unwrap();
    let api = t.node.api();
    seed(&t, "ada", "INBOX", 1).await;
    let account = add(&t, "ada").await;
    let info = &api.list_accounts().await.unwrap()[0];
    assert!(info.skipped_mailboxes.is_empty() && info.archive_mailbox.is_none() && info.notify);
    let spam = MailboxId::new("Spam").unwrap();
    let keep = MailboxId::new("Keep").unwrap();
    api.update_account(
        &account,
        AccountPatch {
            skip_mailboxes: Some(vec![spam.clone()]),
            archive_mailbox: Some(Some(keep.clone())),
            ..AccountPatch::default()
        },
    )
    .await
    .unwrap();
    let info = &api.list_accounts().await.unwrap()[0];
    assert_eq!(info.skipped_mailboxes, vec![spam]);
    assert_eq!(info.archive_mailbox, Some(keep));
    t.node.shutdown().await;
}

struct BulkIsJunk;

impl rowboat_spam::SpamFilter for BulkIsJunk {
    fn verdict(&self, input: &rowboat_spam::SpamInput<'_>) -> rowboat_spam::SpamVerdict {
        if input.in_junk
            || input
                .rendered
                .headers
                .from
                .iter()
                .any(|a| a.address.ends_with("@example.net"))
        {
            rowboat_spam::SpamVerdict::Junk
        } else {
            rowboat_spam::SpamVerdict::NotChecked
        }
    }

    fn version(&self) -> String {
        "bulk-is-junk-1".into()
    }
}

fn bulk(n: usize) -> Vec<u8> {
    format!(
        "From: Bulk Offers <offers{n}@example.net>\r\nTo: ada@example.com\r\nSubject: Offer {n}\r\nMessage-ID: <b{n}@example.net>\r\nDate: Mon, 2 Nov 2026 10:00:00 +0000\r\n\r\nInvented offer {n}.\r\n"
    )
    .into_bytes()
}

async fn subjects(api: &dyn NodeApi, account: &AccountId) -> Vec<String> {
    api.list_messages(all(account))
        .await
        .map(|p| p.items.into_iter().filter_map(|e| e.subject).collect())
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spam_stays_silent_end_to_end() {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let fakes = rowboat_node::testing::FakeProviders::new();
    let keystore = rowboat_keystore_memory::MemoryKeystore::new();
    let node = Node::builder()
        .profile(Profile::Test(rowboat_node::testing::fast(0)))
        .data_dir(dir.path().join("node"))
        .keystore(Arc::new(keystore.clone()))
        .content(Arc::new(rinse_mail_direct::DirectContent::new()))
        .providers(fakes.providers())
        .spam(Arc::new(BulkIsJunk))
        .clock(Arc::new(rowboat_node::ManualClock::at(60_000)))
        .build()
        .await
        .unwrap();
    node.start().await;
    let api = node.api();
    let mut events = api.events();
    let server = fakes.server("ada");
    server.create_mailbox("Junk").await;
    server
        .add(
            "INBOX",
            &message(1, "First note"),
            skein_core::Flags::default(),
        )
        .await;
    let account = api
        .add_account(setup("ada"), Secret::from_text(PASSWORD))
        .await
        .unwrap();
    until("the first sync", || async {
        api.list_accounts()
            .await
            .map(|a| a.iter().any(|a| a.first_sync_completed))
            .unwrap_or(false)
    })
    .await;
    wait_messages(&*api, &account, 1).await;
    assert!(next_new_mail(&mut events, 1).await.is_none());

    server
        .add(
            "Junk",
            &message(2, "Placed in junk"),
            skein_core::Flags::default(),
        )
        .await;
    server
        .add("INBOX", &bulk(3), skein_core::Flags::default())
        .await;
    api.sync_now(Some(&account)).await.unwrap();
    wait_messages(&*api, &account, 3).await;
    assert!(
        next_new_mail(&mut events, 2).await.is_none(),
        "spam notified"
    );

    server
        .add(
            "INBOX",
            &message(4, "Real note"),
            skein_core::Flags::default(),
        )
        .await;
    api.sync_now(Some(&account)).await.unwrap();
    let (_, items) = next_new_mail(&mut events, 20)
        .await
        .expect("a clean message did not notify");
    assert_eq!(items.len(), 1);
    let detail = api.get_message(&account, &items[0].message).await.unwrap();
    assert_eq!(detail.envelope.subject.as_deref(), Some("Real note"));
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn skipping_a_mailbox_reaches_the_running_sync() {
    let t = test_node(0).await.unwrap();
    let api = t.node.api();
    let server = t.fakes.server("ada");
    seed(&t, "ada", "INBOX", 1).await;
    server.create_mailbox("Lists").await;
    server
        .add(
            "Lists",
            &message(5, "List note"),
            skein_core::Flags::default(),
        )
        .await;
    let account = add(&t, "ada").await;
    wait_messages(&*api, &account, 2).await;

    api.update_account(
        &account,
        AccountPatch {
            skip_mailboxes: Some(vec![MailboxId::new("Lists").unwrap()]),
            ..AccountPatch::default()
        },
    )
    .await
    .unwrap();
    let mut skipped = None;
    for n in 0..10 {
        let probe = format!("Probe {n}");
        server
            .add(
                "Lists",
                &message(100 + n, &probe),
                skein_core::Flags::default(),
            )
            .await;
        for (m, run) in ["a", "b"].into_iter().enumerate() {
            let marker = format!("Run {n}{run}");
            server
                .add(
                    "INBOX",
                    &message(200 + 2 * n + m, &marker),
                    skein_core::Flags::default(),
                )
                .await;
            api.sync_now(Some(&account)).await.unwrap();
            until("an inbox run", || async {
                subjects(&*api, &account).await.contains(&marker)
            })
            .await;
        }
        if !subjects(&*api, &account).await.contains(&probe) {
            skipped = Some(probe);
            break;
        }
    }
    let skipped = skipped.expect("a skipped mailbox kept syncing");

    api.update_account(
        &account,
        AccountPatch {
            skip_mailboxes: Some(vec![]),
            ..AccountPatch::default()
        },
    )
    .await
    .unwrap();
    api.sync_now(Some(&account)).await.unwrap();
    until("the skipped probe after unskipping", || async {
        subjects(&*api, &account).await.contains(&skipped)
    })
    .await;
    t.node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn key_names_are_every_key_and_deleting_them_shreds_the_data() {
    use rowboat_keystore::{KeyName, Keystore};
    let t = test_node(0).await.unwrap();
    t.node.shutdown().await;
    let (dir, fakes, keystore) = (t.dir.clone(), t.fakes.clone(), t.keystore.clone());
    drop(t);
    for name in rowboat_node::KEY_NAMES {
        let name = KeyName::new(name).unwrap();
        assert!(keystore.get(&name).await.unwrap().is_some());
        assert!(keystore.delete(&name).await.unwrap());
    }
    let reopened = reopen(&dir, &fakes, &keystore, 0).await;
    assert!(matches!(reopened, Err(BuildError::KeysLost)));
}
