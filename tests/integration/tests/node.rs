//! The node against Dovecot, Stalwart and GreenMail in local containers, over TLS verified with
//! the stack's test CA. Skips unless `ROWBOAT_IT=1` (`mise run it`).

use std::sync::Arc;
use std::time::Duration;

use rinse_mail::{Content, ContentLimits, RenderOptions, RenderRequest};
use rowboat_api::{
    Draft, EmailAddress, ListQuery, MailboxId, MailboxInfo, MailboxRole, MessageRef, NodeApi,
    NodeError, NodeEvent, Recipient, Scope, SearchFilter, SearchQuery, SendOutcome, Targets,
};
use rowboat_discover::testing::FakeFetcher;
use rowboat_discover::{DiscoverError, Endpoint, Prober, Security};
use rowboat_integration::*;
use rowboat_keystore_memory::MemoryKeystore;
use rowboat_node::{ServerProber, TestTiming};
use skein_core::TlsRoots;

const INBOX: usize = 240;
const PROJECTS: usize = 60;

macro_rules! per_server {
    ($scenario:ident: $($name:ident => $kind:expr),+) => {
        $(
            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            async fn $name() {
                if enabled() {
                    $scenario(Server::of($kind)).await;
                }
            }
        )+
    };
}

per_server!(mail_flow:
    mail_flow_dovecot => Kind::Dovecot,
    mail_flow_stalwart => Kind::Stalwart,
    mail_flow_greenmail => Kind::GreenMail);
per_server!(lifecycle:
    lifecycle_dovecot => Kind::Dovecot,
    lifecycle_stalwart => Kind::Stalwart,
    lifecycle_greenmail => Kind::GreenMail);
per_server!(discovery:
    discovery_dovecot => Kind::Dovecot,
    discovery_stalwart => Kind::Stalwart,
    discovery_greenmail => Kind::GreenMail);

fn all(account: &rowboat_api::AccountId) -> ListQuery {
    ListQuery {
        scope: Scope::All {
            account: Some(account.clone()),
        },
        unread_only: false,
        cursor: None,
        limit: 200,
    }
}

fn one(account: &rowboat_api::AccountId, message: &rowboat_api::MessageId) -> Targets {
    Targets(vec![MessageRef {
        account: account.clone(),
        message: message.clone(),
    }])
}

fn tag() -> String {
    format!(
        "t{}",
        &ulid::Ulid::generate().to_string().to_lowercase()[14..]
    )
}

/// Makes sure the user has a sent, trash and archive mailbox (by special use or by name) and a
/// `Projects` folder.
async fn prepare(imap: &mut Imap) {
    let existing = imap.mailboxes().await;
    for (role, name) in [("sent", "Sent"), ("trash", "Trash"), ("archive", "Archive")] {
        let has = existing.iter().any(|(n, attrs)| {
            attrs.iter().any(|a| a.contains(role)) || n.eq_ignore_ascii_case(name)
        });
        if !has {
            imap.ensure(name).await;
        }
    }
    imap.ensure("Projects").await;
}

async fn seed(imap: &mut Imap, mailbox: &str, tag: &str, range: std::ops::Range<usize>, to: &str) {
    for n in range {
        imap.append(mailbox, &message(tag, n, to), n % 3 == 0).await;
    }
}

async fn mailbox_of(
    api: &dyn NodeApi,
    account: &rowboat_api::AccountId,
    role: MailboxRole,
) -> MailboxInfo {
    api.list_mailboxes(account)
        .await
        .unwrap()
        .into_iter()
        .find(|m| m.role == Some(role))
        .unwrap_or_else(|| panic!("no {} mailbox", role.as_str()))
}

async fn only_in(
    api: &dyn NodeApi,
    account: &rowboat_api::AccountId,
    message: &rowboat_api::MessageId,
    mailbox: &MailboxId,
) -> bool {
    api.get_message(account, message)
        .await
        .is_ok_and(|d| d.memberships.len() == 1 && d.memberships[0].mailbox == *mailbox)
}

async fn first_sync(api: &dyn NodeApi, messages: u64, secs: u64) {
    until("the first sync", secs, async || {
        account(api)
            .await
            .is_some_and(|a| a.first_sync_completed && a.messages >= messages)
    })
    .await;
}

async fn mail_flow(server: Server) {
    let ada = server.user("ada").await;
    let bob = server.user("bob").await;
    let tag = tag();
    let mut imap = server.imap(&ada).await;
    prepare(&mut imap).await;
    seed(&mut imap, "INBOX", &tag, 0..INBOX, &ada.address).await;
    seed(
        &mut imap,
        "Projects",
        &tag,
        INBOX..INBOX + PROJECTS,
        &ada.address,
    )
    .await;
    let id = |n: usize| message_id(&message(&tag, n, &ada.address));
    let mid = |n: usize| format!("{tag}-{n}@example.org");

    let dir = tempfile::tempdir().unwrap();
    let keystore = MemoryKeystore::new();
    let node = node(dir.path(), &keystore, ca()).await;
    let api = node.api();
    let mut events = api.events();
    let account = api
        .add_account(
            server.setup(&ada),
            rowboat_api::Secret::from_text(&ada.password),
        )
        .await
        .unwrap();
    first_sync(&*api, (INBOX + PROJECTS) as u64, 180).await;

    let boxes = api.list_mailboxes(&account).await.unwrap();
    let inbox = boxes
        .iter()
        .find(|m| m.role == Some(MailboxRole::Inbox))
        .unwrap();
    assert_eq!(inbox.total, INBOX as u64);
    assert_eq!(inbox.total, u64::from(imap.count("INBOX").await));
    assert_eq!(inbox.unread, (INBOX - INBOX.div_ceil(3)) as u64);
    let projects = boxes.iter().find(|m| m.path == "Projects").unwrap();
    assert_eq!(projects.total, PROJECTS as u64);
    assert_eq!(projects.total, u64::from(imap.count("Projects").await));
    let info = rowboat_integration::account(&*api).await.unwrap();
    assert_eq!(info.messages, (INBOX + PROJECTS) as u64);

    let raw = api.message_raw(&account, &id(5)).await.unwrap();
    assert_eq!(&raw[..], &message(&tag, 5, &ada.address)[..]);
    let content = rinse_mail_direct::DirectContent::new();
    let request = RenderRequest {
        raw: raw.clone(),
        options: RenderOptions::default(),
        limits: ContentLimits::default(),
    };
    let rendered = content.render(request.clone()).await.unwrap();
    rinse_mail::verify_rendered(&request, &rendered).unwrap();
    assert!(
        rendered
            .text
            .contains(&format!("Body 5 about tulips and {tag}"))
    );
    assert_eq!(
        rendered.headers.message_id.as_deref(),
        Some(mid(5).as_str())
    );
    let detail = api.get_message(&account, &id(5)).await.unwrap();
    assert_eq!(
        detail.envelope.subject,
        Some(format!("Garden note 5 {tag}"))
    );
    assert!(detail.envelope.available);
    let hits = api
        .search(SearchQuery {
            account: Some(account.clone()),
            text: marker(5),
            filter: SearchFilter::default(),
            limit: 20,
        })
        .await
        .unwrap();
    assert_eq!(
        hits.iter().map(|h| &h.id).collect::<Vec<_>>(),
        vec![&id(5)],
        "a word only message 5's body holds"
    );

    api.set_read(one(&account, &id(1)), true).await.unwrap();
    api.set_flagged(one(&account, &id(1)), true).await.unwrap();
    until("read and flagged on the server", 60, async || {
        imap.flags("INBOX", &mid(1)).await.is_some_and(|f| {
            f.iter().any(|x| x.contains("seen")) && f.iter().any(|x| x.contains("flagged"))
        })
    })
    .await;

    api.move_to(one(&account, &id(2)), &MailboxId::new("Projects").unwrap())
        .await
        .unwrap();
    api.archive(one(&account, &id(4))).await.unwrap();
    api.delete(one(&account, &id(7)), false).await.unwrap();
    api.delete(one(&account, &id(8)), true).await.unwrap();
    let archive = mailbox_of(&*api, &account, MailboxRole::Archive).await;
    let trash = mailbox_of(&*api, &account, MailboxRole::Trash).await;
    until("move, archive and deletes on the server", 60, async || {
        imap.flags("INBOX", &mid(2)).await.is_none()
            && imap.flags("Projects", &mid(2)).await.is_some()
            && imap.flags("INBOX", &mid(4)).await.is_none()
            && imap.flags(&archive.path, &mid(4)).await.is_some()
            && imap.flags("INBOX", &mid(7)).await.is_none()
            && imap.flags(&trash.path, &mid(7)).await.is_some()
            && imap.flags("INBOX", &mid(8)).await.is_none()
            && imap.flags(&trash.path, &mid(8)).await.is_none()
    })
    .await;
    let inbox_id = inbox.id.clone();
    let projects_id = MailboxId::new("Projects").unwrap();
    until("the node to see every change", 60, async || {
        let read = api.get_message(&account, &id(1)).await.is_ok_and(|d| {
            let flags: Vec<String> = d
                .memberships
                .iter()
                .filter(|m| m.mailbox == inbox_id)
                .flat_map(|m| m.flags.iter().map(|f| f.to_lowercase()))
                .collect();
            !d.envelope.unread
                && d.envelope.flagged
                && flags.iter().any(|f| f.contains("seen"))
                && flags.iter().any(|f| f.contains("flagged"))
        });
        read && only_in(&*api, &account, &id(2), &projects_id).await
            && only_in(&*api, &account, &id(4), &archive.id).await
            && only_in(&*api, &account, &id(7), &trash.id).await
            && api.get_message(&account, &id(8)).await == Err(NodeError::NotFound)
    })
    .await;

    let bob_account = if server.delivers_locally {
        let b = api
            .add_account(
                server.setup(&bob),
                rowboat_api::Secret::from_text(&bob.password),
            )
            .await
            .unwrap();
        Some(b)
    } else {
        None
    };
    let subject = format!("Lunch plans {tag}");
    let queued = api
        .send(Draft {
            id: None,
            account: account.clone(),
            to: vec![Recipient {
                name: Some("Bob Example".into()),
                address: EmailAddress::new(&bob.address).unwrap(),
            }],
            cc: vec![],
            bcc: vec![],
            subject: subject.clone(),
            text: "Shall we meet by the greenhouse at noon?".into(),
            reply: None,
            attachments: vec![],
        })
        .await
        .unwrap();
    let outcome = event(&mut events, 90, "the send to settle", |e| match e {
        NodeEvent::SendSettled {
            command, outcome, ..
        } if *command == queued.command && !matches!(outcome, SendOutcome::Waiting { .. }) => {
            Some(outcome.clone())
        }
        _ => None,
    })
    .await;
    assert_eq!(outcome, SendOutcome::Sent { refused: 0 });
    let sent = mailbox_of(&*api, &account, MailboxRole::Sent).await.path;
    until("the Sent copy on the server", 60, async || {
        imap.flags_by_subject(&sent, &subject).await.is_some()
    })
    .await;
    until("the Sent copy in the node", 60, async || {
        api.list_messages(ListQuery {
            scope: Scope::Role {
                account: Some(account.clone()),
                role: MailboxRole::Sent,
            },
            unread_only: false,
            cursor: None,
            limit: 50,
        })
        .await
        .is_ok_and(|p| {
            p.items
                .iter()
                .any(|m| m.subject.as_deref() == Some(&subject))
        })
    })
    .await;
    if let Some(bob_account) = &bob_account {
        let mut bob_imap = server.imap(&bob).await;
        until(
            "delivery to the other account on the server",
            60,
            async || bob_imap.flags_by_subject("INBOX", &subject).await.is_some(),
        )
        .await;
        bob_imap.logout().await;
        until(
            "the other account to receive it in the node",
            60,
            async || {
                api.list_messages(ListQuery {
                    scope: Scope::Role {
                        account: Some(bob_account.clone()),
                        role: MailboxRole::Inbox,
                    },
                    unread_only: false,
                    cursor: None,
                    limit: 50,
                })
                .await
                .is_ok_and(|p| {
                    p.items
                        .iter()
                        .any(|m| m.subject.as_deref() == Some(&subject))
                })
            },
        )
        .await;
    }

    let arrival = message(&tag, 9_999, &ada.address);
    let arrival_id = message_id(&arrival);
    imap.append("INBOX", &arrival, false).await;
    let started = tokio::time::Instant::now();
    event(&mut events, 60, "NewMail for the arrival", |e| match e {
        NodeEvent::NewMail { account: a, items }
            if *a == account && items.iter().any(|i| i.message == arrival_id) =>
        {
            Some(())
        }
        _ => None,
    })
    .await;
    eprintln!(
        "{:?}: new mail reached the node in {} ms",
        server.kind,
        started.elapsed().as_millis()
    );

    imap.logout().await;
    node.shutdown().await;
}

async fn lifecycle(server: Server) {
    let ada = server.user("ada").await;
    let tag = tag();
    let mut imap = server.imap(&ada).await;
    prepare(&mut imap).await;
    seed(&mut imap, "INBOX", &tag, 0..150, &ada.address).await;
    seed(&mut imap, "Projects", &tag, 150..200, &ada.address).await;

    let dir = tempfile::tempdir().unwrap();
    let keystore = MemoryKeystore::new();
    let relay = Relay::start(server.imap.port).await;
    let mut setup = server.setup(&ada);
    setup.imap = rowboat_api::Endpoint::new(HOST, relay.port, server.imap.security).unwrap();

    let first = node(dir.path(), &keystore, ca()).await;
    let api = first.api();
    let objects = dir.path().join("node/objects");
    let stored = |objects: &std::path::Path| {
        files(objects)
            .into_iter()
            .filter(|f| !f.contains("/.lock") && !f.contains("/_nodes/"))
            .collect::<Vec<_>>()
    };
    let before = stored(&objects);
    assert_eq!(
        api.add_account(
            setup.clone(),
            rowboat_api::Secret::from_text("not-the-password")
        )
        .await,
        Err(NodeError::AuthFailed)
    );
    assert!(api.list_accounts().await.unwrap().is_empty());
    assert_eq!(stored(&objects), before, "a refused sign-in stored nothing");

    let account = api
        .add_account(setup, rowboat_api::Secret::from_text(&ada.password))
        .await
        .unwrap();
    first_sync(&*api, 200, 120).await;
    let first_bytes = relay.received();
    first.shutdown().await;
    drop((api, first));
    let resumed_at = relay.received();

    let quiet = TestTiming {
        interval: Duration::from_secs(3_600),
        ..timing()
    };
    let second = node_timed(dir.path(), &keystore, ca(), quiet).await;
    let api = second.api();
    let info = rowboat_integration::account(&*api)
        .await
        .expect("the account survives a restart");
    assert_eq!(info.id, account);
    assert!(info.first_sync_completed);
    assert_eq!(info.messages, 200);
    let arrival = message(&tag, 500, &ada.address);
    imap.append("INBOX", &arrival, false).await;
    let arrival_id = message_id(&arrival);
    api.sync_now(Some(&account)).await.unwrap();
    until("the arrival after the restart", 60, async || {
        api.get_message(&account, &arrival_id).await.is_ok()
    })
    .await;
    let resumed = relay.received() - resumed_at;
    eprintln!(
        "{:?}: first sync {first_bytes} bytes, resumed {resumed} bytes",
        server.kind
    );
    assert!(
        resumed * 4 < first_bytes,
        "the restart refetched: {resumed} bytes after {first_bytes}"
    );
    assert_eq!(
        api.list_messages(all(&account)).await.unwrap().items.len(),
        200
    );

    let blob = message_id(&message(&tag, 3, &ada.address));
    api.message_raw(&account, &blob).await.unwrap();
    let held = files(&objects);
    assert!(
        held.iter().any(|f| f.contains(blob.as_str())),
        "message 3's original is stored before the removal"
    );
    assert!(
        held.iter()
            .any(|f| f.contains(account.as_str()) && !f.contains("/control/keys/accounts/")),
        "the account's records are stored before the removal"
    );
    api.remove_account(&account).await.unwrap();
    assert!(api.list_accounts().await.unwrap().is_empty());
    assert_eq!(api.list_mailboxes(&account).await, Err(NodeError::NotFound));
    until("the account's data to be deleted", 60, async || {
        files(&objects).iter().all(|f| {
            !f.contains(blob.as_str())
                && (!f.contains(account.as_str()) || f.contains("/control/keys/accounts/"))
        })
    })
    .await;
    let everything = ListQuery {
        scope: Scope::All { account: None },
        unread_only: false,
        cursor: None,
        limit: 10,
    };
    assert!(
        api.list_messages(everything)
            .await
            .unwrap()
            .items
            .is_empty()
    );
    second.shutdown().await;
    imap.logout().await;
}

fn autoconfig(server: &Server, imap_port: u16) -> Vec<u8> {
    format!(
        r#"<clientConfig version="1.1"><emailProvider id="example.com">
<incomingServer type="imap"><hostname>{HOST}</hostname><port>{imap_port}</port><socketType>SSL</socketType><username>%EMAILADDRESS%</username></incomingServer>
<outgoingServer type="smtp"><hostname>{HOST}</hostname><port>{}</port><socketType>SSL</socketType><username>%EMAILADDRESS%</username></outgoingServer>
</emailProvider></clientConfig>"#,
        server.smtps_port
    )
    .into_bytes()
}

async fn discovery(server: Server) {
    let ada = server.user("ada").await;
    let imap_tls = Endpoint::new(HOST, server.imaps_port, Security::Tls).unwrap();
    let smtp = server.smtp.clone();
    let closed = Endpoint::new(HOST, 1, Security::Tls).unwrap();

    let trusted = ServerProber::with_test_roots(ca(), Duration::from_secs(10));
    assert!(
        trusted
            .probe_imap(&imap_tls)
            .await
            .unwrap()
            .password_sign_in
    );
    assert!(
        trusted
            .probe_imap(&server.imap)
            .await
            .unwrap()
            .password_sign_in
    );
    assert!(trusted.probe_smtp(&smtp).await.unwrap().password_sign_in);
    let wrong = ServerProber::with_test_roots(
        skein_core::tls::testing::TestCa::new(&[HOST]).roots(),
        Duration::from_secs(10),
    );
    assert_eq!(
        wrong.probe_imap(&imap_tls).await,
        Err(DiscoverError::TlsFailed)
    );
    assert_eq!(wrong.probe_smtp(&smtp).await, Err(DiscoverError::TlsFailed));
    let web = ServerProber::new(Duration::from_secs(10));
    assert_eq!(
        web.probe_imap(&server.imap).await,
        Err(DiscoverError::TlsFailed)
    );
    assert_eq!(
        trusted.probe_imap(&closed).await,
        Err(DiscoverError::Unreachable)
    );
    assert_eq!(
        trusted.probe_smtp(&closed).await,
        Err(DiscoverError::Unreachable)
    );

    let fetcher = |port: u16| {
        Arc::new(FakeFetcher::new([(
            "https://autoconfig.example.com/mail/config-v1.1.xml".to_owned(),
            autoconfig(&server, port),
        )]))
    };
    let address = EmailAddress::new(&ada.address).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let keystore = MemoryKeystore::new();
    let found = try_node(
        dir.path(),
        &keystore,
        ca(),
        timing(),
        Some(vec![Arc::new(
            rowboat_discover_autoconfig::AutoconfigSource::new(fetcher(server.imaps_port)),
        )]),
    )
    .await
    .unwrap();
    let candidates = found.api().discover(&address).await.unwrap();
    assert_eq!(candidates.len(), 1, "{candidates:?}");
    assert!(candidates[0].verified);
    assert!(candidates[0].needs_confirmation);
    assert_eq!(candidates[0].imap, imap_tls);
    assert_eq!(
        candidates[0].smtp,
        Endpoint::new(HOST, server.smtps_port, Security::Tls).unwrap()
    );
    found.shutdown().await;

    let dir = tempfile::tempdir().unwrap();
    let dead = try_node(
        dir.path(),
        &MemoryKeystore::new(),
        ca(),
        timing(),
        Some(vec![Arc::new(
            rowboat_discover_autoconfig::AutoconfigSource::new(fetcher(1)),
        )]),
    )
    .await
    .unwrap();
    assert!(dead.api().discover(&address).await.unwrap().is_empty());
    dead.shutdown().await;

    let dir = tempfile::tempdir().unwrap();
    let untrusting = node(dir.path(), &MemoryKeystore::new(), TlsRoots::default()).await;
    let api = untrusting.api();
    assert_eq!(
        api.add_account(
            server.setup(&ada),
            rowboat_api::Secret::from_text(&ada.password)
        )
        .await,
        Err(NodeError::TlsFailed)
    );
    assert!(api.list_accounts().await.unwrap().is_empty());
    let mut closed_setup = server.setup(&ada);
    closed_setup.imap = closed;
    let dir2 = tempfile::tempdir().unwrap();
    let trusting = node(dir2.path(), &MemoryKeystore::new(), ca()).await;
    assert_eq!(
        trusting
            .api()
            .add_account(closed_setup, rowboat_api::Secret::from_text(&ada.password))
            .await,
        Err(NodeError::ServerUnreachable)
    );
    untrusting.shutdown().await;
    trusting.shutdown().await;
}
