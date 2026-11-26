//! Integration suites against the containers in `compose.yaml`. They skip unless `SKEIN_IT=1`.

use std::sync::Arc;

use skein_core::{AccountId, EventBody, NodeId, Seq, TenantId, Timestamp};
use std::sync::atomic::{AtomicI64, Ordering};

use baton_lease::{Liveness, NodeProfile};
use skein_engine::{AccountConfig, Engine, EngineError, node_profile};
use skein_integration::{enabled, s3, single_engine, storage_engine};
use skein_mail::testing::FakeMail;
use skein_storage::{CountingObjects, Objects, Storage};

fn tenant() -> TenantId {
    TenantId::new("it").unwrap()
}

fn node(
    objects: Arc<dyn Objects>,
    name: &str,
    clock: &Arc<AtomicI64>,
) -> (Engine, Arc<dyn Liveness>) {
    let c = clock.clone();
    storage_engine(
        Storage::over(objects),
        name,
        20_000,
        Some(Arc::new(move || {
            baton_core::Timestamp(c.load(Ordering::SeqCst))
        })),
    )
}

fn profile(name: &str) -> NodeProfile {
    node_profile(NodeId::new(name).unwrap(), 1, true)
}

fn nodes() -> skein_core::GroupId {
    skein_core::coordination::group(&tenant())
}

#[tokio::test]
async fn journal_on_s3_is_readable_by_another_process_and_fenced() {
    if !enabled() {
        eprintln!("SKEIN_IT is not set; skipping");
        return;
    }
    let objects = s3();
    let counting = Arc::new(CountingObjects::new(objects.clone()));
    let clock1 = Arc::new(AtomicI64::new(Timestamp::now().0));
    let clock2 = Arc::new(AtomicI64::new(Timestamp::now().0));
    let (n1, live1) = node(counting.clone(), "n1", &clock1);
    let (n2, live2) = node(objects.clone(), "n2", &clock2);
    live1
        .heartbeat(&nodes(), &profile("n1"), baton_core::Timestamp::now())
        .await
        .unwrap();
    live2
        .heartbeat(&nodes(), &profile("n2"), baton_core::Timestamp::now())
        .await
        .unwrap();

    let fake = FakeMail::new();
    fake.fill("INBOX", 300, 4_000);
    let acc = AccountId::new("acc").unwrap();
    let mut config = AccountConfig::new(tenant(), acc.clone());
    config.page = 100;
    let report = n1.sync_account(&config, &fake).await.unwrap();
    assert_eq!(report.mailboxes[0].added, 300);
    let counts = counting.counts();
    assert!(
        (counts.puts as f64) < 300.0 * 1.15,
        "about one PUT per message on real S3: {counts:?}"
    );

    let consumer = Storage::over(objects.clone());
    let events = consumer
        .log
        .read(&tenant(), &acc, Seq(1), 10_000)
        .await
        .unwrap();
    let added: Vec<_> = events
        .iter()
        .filter_map(|e| match &e.body {
            EventBody::MessageAdded { blob, .. } => Some(*blob),
            _ => None,
        })
        .collect();
    assert_eq!(added.len(), 300);
    for blob in added.iter().take(20) {
        assert!(consumer.blobs.get(&tenant(), blob).await.unwrap().is_some());
    }

    assert!(matches!(
        n2.sync_account(&config, &fake).await,
        Err(EngineError::NotOwner)
    ));
    clock2.fetch_add(20_001, Ordering::SeqCst);
    fake.fill("INBOX", 10, 1_000);
    n2.sync_account(&config, &fake).await.unwrap();
    live1
        .heartbeat(&nodes(), &profile("n1"), baton_core::Timestamp::now())
        .await
        .unwrap();
    fake.fill("INBOX", 10, 1_000);
    assert!(matches!(
        n1.sync_account(&config, &fake).await,
        Err(EngineError::NotOwner)
    ));
    let events = consumer
        .log
        .read(&tenant(), &acc, Seq(1), 10_000)
        .await
        .unwrap();
    let added = events
        .iter()
        .filter(|e| matches!(e.body, EventBody::MessageAdded { .. }))
        .count();
    assert_eq!(added, 310);
    assert!(
        events
            .iter()
            .enumerate()
            .all(|(i, e)| e.seq.0 == i as u64 + 1)
    );
}

#[tokio::test]
async fn imap_round_trip_against_greenmail() {
    if !enabled() {
        eprintln!("SKEIN_IT is not set; skipping");
        return;
    }
    use skein_integration::env;
    use skein_mail_imap::{ImapProvider, ImapSettings, Security};
    let mut settings = ImapSettings::new(env("SKEIN_IT_IMAP_HOST"), env("SKEIN_IT_IMAP_USER"));
    settings.port = Some(env("SKEIN_IT_IMAP_PORT").parse().unwrap());
    settings.security = Security::Plain;
    let provider = ImapProvider::new(
        settings,
        skein_core::Credentials::Password {
            secret: env("SKEIN_IT_IMAP_PASSWORD"),
        },
    )
    .unwrap();
    skein_integration::mail_round_trip(&provider, "INBOX").await;
}

fn imap(host: &str, port: &str, user: &str, password: &str) -> skein_mail_imap::ImapProvider {
    use skein_mail_imap::{ImapProvider, ImapSettings, Security};
    let mut settings = ImapSettings::new(host, user);
    settings.port = Some(port.parse().unwrap());
    settings.security = Security::Plain;
    ImapProvider::new(
        settings,
        skein_core::Credentials::Password {
            secret: password.to_owned(),
        },
    )
    .unwrap()
}

#[tokio::test]
async fn imap_round_trip_against_dovecot() {
    if !enabled() {
        eprintln!("SKEIN_IT is not set; skipping");
        return;
    }
    use skein_integration::env;
    let provider = imap(
        "127.0.0.1",
        &env("SKEIN_IT_DOVECOT_PORT"),
        &env("SKEIN_IT_DOVECOT_USER"),
        &env("SKEIN_IT_DOVECOT_PASSWORD"),
    );
    skein_integration::mail_round_trip(&provider, "INBOX").await;
}

#[tokio::test]
async fn imap_round_trip_against_stalwart() {
    if !enabled() {
        eprintln!("SKEIN_IT is not set; skipping");
        return;
    }
    use skein_integration::env;
    let provider = imap(
        "127.0.0.1",
        &env("SKEIN_IT_STALWART_IMAP_PORT"),
        &env("SKEIN_IT_STALWART_USER"),
        &env("SKEIN_IT_STALWART_PASSWORD"),
    );
    skein_integration::mail_round_trip(&provider, "INBOX").await;
}

#[tokio::test]
async fn jmap_round_trip_against_stalwart() {
    if !enabled() {
        eprintln!("SKEIN_IT is not set; skipping");
        return;
    }
    use skein_integration::{env, mailbox_with_role};
    use skein_mail_jmap::{JmapProvider, JmapSettings};
    let settings = JmapSettings::new(env("SKEIN_IT_STALWART_URL"), env("SKEIN_IT_STALWART_USER"));
    let provider = JmapProvider::new(
        settings,
        skein_core::Credentials::Password {
            secret: env("SKEIN_IT_STALWART_PASSWORD"),
        },
    )
    .unwrap();
    let inbox = mailbox_with_role(&provider, skein_core::MailboxRole::Inbox).await;
    skein_integration::mail_round_trip(&provider, &inbox).await;
}

#[tokio::test]
async fn jmap_watch_wakes_on_new_mail_in_stalwart() {
    if !enabled() {
        eprintln!("SKEIN_IT is not set; skipping");
        return;
    }
    use bytes::Bytes;
    use skein_core::{BlobHash, CommandBody, Flags};
    use skein_integration::{env, mailbox_with_role};
    use skein_mail::{MailProvider, WriteOutcome};
    use skein_mail_jmap::{JmapProvider, JmapSettings};
    let provider = JmapProvider::new(
        JmapSettings::new(env("SKEIN_IT_STALWART_URL"), env("SKEIN_IT_STALWART_USER")),
        skein_core::Credentials::Password {
            secret: env("SKEIN_IT_STALWART_PASSWORD"),
        },
    )
    .unwrap();
    let inbox = mailbox_with_role(&provider, skein_core::MailboxRole::Inbox).await;
    let mut watch = provider
        .watch(std::slice::from_ref(&inbox))
        .await
        .unwrap()
        .expect("an event source");
    let waiting = tokio::spawn(async move { watch.next().await });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let tag = ulid::Ulid::generate().to_string().to_lowercase();
    let message = format!(
        "From: skein-test@example.com\r\nTo: skein-test@example.com\r\nSubject: watch {tag}\r\nMessage-ID: <{tag}@example.com>\r\n\r\nWatch test.\r\n"
    );
    let mut session = provider.connect().await.unwrap();
    let outcome = session
        .apply(
            &CommandBody::Append {
                mailbox: inbox.clone(),
                blob: BlobHash::of(message.as_bytes()),
                flags: Flags::default(),
                received_at: None,
            },
            Some(Bytes::from(message.clone())),
        )
        .await
        .unwrap();
    assert_eq!(outcome, WriteOutcome::Applied);
    tokio::time::timeout(std::time::Duration::from_secs(20), waiting)
        .await
        .expect("the watch woke")
        .unwrap()
        .unwrap();

    let mut cursor = None;
    let mut found = None;
    loop {
        let batch = session.changes(&inbox, cursor.as_ref(), 500).await.unwrap();
        for change in &batch.changes {
            if let skein_mail::MailChange::Added { item, .. } = change {
                let raw = session
                    .fetch(&inbox, std::slice::from_ref(item))
                    .await
                    .unwrap();
                if raw.first().is_some_and(|r| r.bytes == message.as_bytes()) {
                    found = Some(item.clone());
                }
            }
        }
        cursor = Some(batch.cursor);
        if !batch.more {
            break;
        }
    }
    let item = found.expect("the appended message is listed with its exact bytes");
    let outcome = session
        .apply(
            &CommandBody::Delete {
                mailbox: inbox,
                items: vec![item],
                to_trash: false,
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(outcome, WriteOutcome::Applied);
}

struct OneSender(Arc<dyn skein_send::Sender>);

#[async_trait::async_trait]
impl skein_engine::SenderDirectory for OneSender {
    async fn sender(
        &self,
        _: &TenantId,
        _: &AccountId,
    ) -> Result<Option<Arc<dyn skein_send::Sender>>, skein_send::SendError> {
        Ok(Some(self.0.clone()))
    }
}

#[tokio::test]
async fn send_through_greenmail_smtp_arrives_over_imap() {
    if !enabled() {
        eprintln!("SKEIN_IT is not set; skipping");
        return;
    }
    use bytes::Bytes;
    use skein_core::{Command, CommandBody, CommandId, SendEnvelope};
    use skein_integration::env;
    use skein_mail::{MailChange, MailProvider};
    use skein_send_smtp::{Security, SmtpSender, SmtpSettings};

    let smtp = SmtpSender::new(
        SmtpSettings {
            port: Some(env("SKEIN_IT_SMTP_PORT").parse().unwrap()),
            security: Security::Plain,
            ..SmtpSettings::new(env("SKEIN_IT_IMAP_HOST"))
        },
        None,
    )
    .unwrap();
    let storage = Storage::over(Arc::new(skein_storage_memory::MemoryObjects::new()));
    let engine =
        single_engine(storage.clone(), "it").with_senders(Arc::new(OneSender(Arc::new(smtp))));
    let imap = imap(
        &env("SKEIN_IT_IMAP_HOST"),
        &env("SKEIN_IT_IMAP_PORT"),
        &env("SKEIN_IT_IMAP_USER"),
        &env("SKEIN_IT_IMAP_PASSWORD"),
    );

    let tag = ulid::Ulid::generate().to_string().to_lowercase();
    let message = format!(
        "From: Skein Test <skein-test@example.com>\r\nTo: Ada <ada@example.com>\r\nSubject: skein send {tag}\r\nMessage-ID: <{tag}@example.com>\r\nDate: Thu, 20 Nov 2025 10:00:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nSent by the Skein integration suite.\r\n"
    );
    let blob = storage
        .blobs
        .put(&tenant(), Bytes::from(message.clone()))
        .await
        .unwrap();
    let account = AccountId::new("send").unwrap();
    let command = Command {
        id: CommandId::generate(),
        account: account.clone(),
        created_at: Timestamp::now(),
        trace: None,
        body: CommandBody::Send {
            blob,
            envelope: SendEnvelope {
                from: "skein-test@example.com".into(),
                to: vec!["ada@example.com".into()],
                dsn: None,
            },
            save_to_sent: None,
            send_at: None,
            dry_run: false,
        },
    };
    storage.commands.submit(&tenant(), &command).await.unwrap();
    let config = AccountConfig::new(tenant(), account.clone());
    let report = engine.run_commands(&config, &imap).await.unwrap();
    assert_eq!(report.applied, 1, "{report:?}");
    let events = storage
        .log
        .read(&tenant(), &account, Seq(1), 100)
        .await
        .unwrap();
    assert!(matches!(&events[0].body, EventBody::WriteApplied { command: c } if *c == command.id));

    let needle = format!("Message-ID: <{tag}@example.com>");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let found = loop {
        let mut session = imap.connect().await.unwrap();
        let mut cursor = None;
        let mut found = None;
        loop {
            let batch = session
                .changes("INBOX", cursor.as_ref(), 500)
                .await
                .unwrap();
            let items: Vec<_> = batch
                .changes
                .iter()
                .filter_map(|c| match c {
                    MailChange::Added { item, .. } => Some(item.clone()),
                    _ => None,
                })
                .collect();
            for raw in session.fetch("INBOX", &items).await.unwrap() {
                if raw
                    .bytes
                    .windows(needle.len())
                    .any(|w| w == needle.as_bytes())
                {
                    found = Some((raw.item, raw.bytes));
                }
            }
            cursor = Some(batch.cursor);
            if !batch.more {
                break;
            }
        }
        if let Some(found) = found {
            break (session, found);
        }
        session.logout().await.unwrap();
        assert!(
            std::time::Instant::now() < deadline,
            "the message never arrived"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    };
    let (mut session, (item, bytes)) = found;
    let body = String::from_utf8_lossy(&bytes);
    assert!(body.contains("Sent by the Skein integration suite."));
    let outcome = session
        .apply(
            &CommandBody::Delete {
                mailbox: "INBOX".into(),
                items: vec![item],
                to_trash: false,
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(outcome, skein_mail::WriteOutcome::Applied);
    session.logout().await.unwrap();
}

#[tokio::test]
async fn jmap_send_to_stalwart_keeps_a_sent_copy_and_arrives() {
    if !enabled() {
        eprintln!("SKEIN_IT is not set; skipping");
        return;
    }
    use skein_integration::{env, mailbox_with_role};
    use skein_mail::{MailChange, MailProvider};
    use skein_mail_jmap::{JmapProvider, JmapSettings};
    use skein_send::{Envelope, Sender};
    use skein_send_jmap::{JmapSendSettings, JmapSender};

    let user = env("SKEIN_IT_STALWART_USER");
    let password = || skein_core::Credentials::Password {
        secret: env("SKEIN_IT_STALWART_PASSWORD"),
    };
    let sender = JmapSender::new(
        JmapSendSettings::new(env("SKEIN_IT_STALWART_URL"), user.clone()),
        password(),
    )
    .unwrap();
    assert!(sender.saves_to_sent());
    sender.check().await.expect("check");
    let provider = JmapProvider::new(
        JmapSettings::new(env("SKEIN_IT_STALWART_URL"), user.clone()),
        password(),
    )
    .unwrap();
    let inbox = mailbox_with_role(&provider, skein_core::MailboxRole::Inbox).await;
    let sent = mailbox_with_role(&provider, skein_core::MailboxRole::Sent).await;

    let tag = ulid::Ulid::generate().to_string().to_lowercase();
    let message = format!(
        "From: Ada <{user}>\r\nTo: Ada <{user}>\r\nSubject: skein jmap send {tag}\r\nMessage-ID: <{tag}@example.com>\r\nDate: Thu, 20 Nov 2025 10:00:00 +0000\r\n\r\nSent by the Skein integration suite.\r\n"
    );
    let report = sender
        .send(
            &Envelope::new(user.clone(), vec![user.clone()]),
            message.as_bytes(),
        )
        .await
        .expect("send");
    assert_eq!(report.refused().count(), 0);

    let needle = format!("<{tag}@example.com>");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    for mailbox in [&sent, &inbox] {
        loop {
            let mut session = provider.connect().await.unwrap();
            let mut cursor = None;
            let mut found = Vec::new();
            loop {
                let batch = session
                    .changes(mailbox, cursor.as_ref(), 500)
                    .await
                    .unwrap();
                let items: Vec<_> = batch
                    .changes
                    .iter()
                    .filter_map(|c| match c {
                        MailChange::Added { item, .. } => Some(item.clone()),
                        _ => None,
                    })
                    .collect();
                for raw in session.fetch(mailbox, &items).await.unwrap() {
                    if raw
                        .bytes
                        .windows(needle.len())
                        .any(|w| w == needle.as_bytes())
                    {
                        found.push(raw.item);
                    }
                }
                cursor = Some(batch.cursor);
                if !batch.more {
                    break;
                }
            }
            if !found.is_empty() {
                session
                    .apply(
                        &skein_core::CommandBody::Delete {
                            mailbox: mailbox.clone(),
                            items: found,
                            to_trash: false,
                        },
                        None,
                    )
                    .await
                    .unwrap();
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the message never showed up in {mailbox}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
}

fn radicale() -> (String, String, String) {
    (
        skein_integration::env("SKEIN_IT_RADICALE_URL"),
        skein_integration::env("SKEIN_IT_RADICALE_USER"),
        skein_integration::env("SKEIN_IT_RADICALE_PASSWORD"),
    )
}

async fn dav(method: &str, url: &str, user: &str, password: &str, body: &str) -> u16 {
    reqwest::Client::new()
        .request(reqwest::Method::from_bytes(method.as_bytes()).unwrap(), url)
        .basic_auth(user, Some(password))
        .header("content-type", "application/xml; charset=utf-8")
        .body(body.to_owned())
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

async fn dav_get(url: &str, user: &str, password: &str) -> Option<bytes::Bytes> {
    let r = reqwest::Client::new()
        .get(url)
        .basic_auth(user, Some(password))
        .send()
        .await
        .unwrap();
    if !r.status().is_success() {
        return None;
    }
    r.bytes().await.ok()
}

#[tokio::test]
async fn pim_round_trip_against_radicale() {
    use bytes::Bytes;
    use skein_core::{Command, CommandBody, CommandId, Credentials, ItemRef};
    use skein_pim_dav::{DavConfig, DavProvider};
    use skein_storage_memory::MemoryObjects;

    if !enabled() {
        eprintln!("SKEIN_IT is not set; skipping");
        return;
    }
    let (base, user, password) = radicale();
    let run = ulid::Ulid::generate().to_string().to_lowercase();
    let cal = format!("/{user}/cal-{run}/");
    let book = format!("/{user}/book-{run}/");
    let _ = dav("PROPFIND", &format!("{base}/{user}/"), &user, &password, "").await;
    assert_eq!(
        dav("MKCALENDAR", &format!("{base}{cal}"), &user, &password, "").await,
        201
    );
    let mkbook = "<?xml version=\"1.0\"?><d:mkcol xmlns:d=\"DAV:\" \
                  xmlns:c=\"urn:ietf:params:xml:ns:carddav\"><d:set><d:prop><d:resourcetype>\
                  <d:collection/><c:addressbook/></d:resourcetype><d:displayname>Book</d:displayname>\
                  </d:prop></d:set></d:mkcol>";
    assert_eq!(
        dav("MKCOL", &format!("{base}{book}"), &user, &password, mkbook).await,
        201
    );

    let provider = DavProvider::new(DavConfig::at(
        &base,
        &user,
        Credentials::Password {
            secret: password.clone(),
        },
    ))
    .expect("DAV config");
    let storage = Storage::over(Arc::new(MemoryObjects::new()));
    let engine = single_engine(storage.clone(), "it");
    let acc = AccountId::new("pim").unwrap();
    let mut config = AccountConfig::new(tenant(), acc.clone());
    config.include = Some(vec![cal.clone(), book.clone()]);
    engine.sync_collections(&config, &provider).await.unwrap();
    let events = |storage: Storage, acc: AccountId| async move {
        storage
            .log
            .read(&tenant(), &acc, Seq(1), 100_000)
            .await
            .unwrap()
    };
    let journal = events(storage.clone(), acc.clone()).await;
    for id in [&cal, &book] {
        assert!(
            journal.iter().any(|e| matches!(&e.body, EventBody::CollectionUpserted { collection } if &collection.id == id)),
            "both collections are journaled"
        );
    }

    let event = format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Skein//IT//EN\r\nBEGIN:VEVENT\r\n\
         UID:it-{run}@example.com\r\nDTSTAMP:20261201T090000Z\r\nDTSTART:20261201T100000Z\r\n\
         DTEND:20261201T110000Z\r\nSUMMARY:Planning\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
    );
    let contact = format!(
        "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:it-{run}@example.com\r\nFN:Ada Example\r\n\
         N:Example;Ada;;;\r\nEMAIL:ada@example.org\r\nEND:VCARD\r\n"
    );
    let command = |body: CommandBody| Command {
        id: CommandId::generate(),
        account: acc.clone(),
        created_at: Timestamp::now(),
        trace: None,
        body,
    };
    let mut created = Vec::new();
    for (collection, bytes) in [(&cal, &event), (&book, &contact)] {
        let blob = storage
            .blobs
            .put(&tenant(), Bytes::from(bytes.clone()))
            .await
            .unwrap();
        let c = command(CommandBody::PutObject {
            collection: collection.clone(),
            item: None,
            blob,
            if_version: None,
            notify: false,
        });
        storage.commands.submit(&tenant(), &c).await.unwrap();
        created.push(c.id);
    }
    let r = engine.run_pim_commands(&config, &provider).await.unwrap();
    assert_eq!(r.applied, 2);

    let report = engine.sync_collections(&config, &provider).await.unwrap();
    assert_eq!(
        report.collections.iter().map(|c| c.upserted).sum::<u64>(),
        2
    );
    let journal = events(storage.clone(), acc.clone()).await;
    let mut objects = Vec::new();
    for collection in [&cal, &book] {
        let (item, blob, version) = journal
            .iter()
            .rev()
            .find_map(|e| match &e.body {
                EventBody::ObjectUpserted {
                    collection: c,
                    item,
                    blob,
                    version,
                    ..
                } if c == collection && e.origin.is_none() => {
                    Some((item.clone(), *blob, version.clone()))
                }
                _ => None,
            })
            .expect("the object is journaled by the sync");
        let journaled = storage.blobs.get(&tenant(), &blob).await.unwrap().unwrap();
        let held = dav_get(&format!("{base}{}", item.id), &user, &password)
            .await
            .expect("the object is on the server");
        assert_eq!(
            journaled, held,
            "the journal holds the server's exact bytes"
        );
        assert!(version.is_some(), "Radicale gives versions");
        objects.push((collection.clone(), item, version));
    }
    for id in &created {
        assert!(
            journal.iter().any(|e| e.origin.as_ref() == Some(id)
                && matches!(e.body, EventBody::ObjectUpserted { .. })),
            "the command's object is journaled with the command as origin"
        );
    }

    let (collection, item, _): (String, ItemRef, Option<String>) = objects[0].clone();
    let moved = event.replace("SUMMARY:Planning", "SUMMARY:Planning moved");
    let blob = storage
        .blobs
        .put(&tenant(), Bytes::from(moved))
        .await
        .unwrap();
    let stale = command(CommandBody::PutObject {
        collection: collection.clone(),
        item: Some(item.clone()),
        blob,
        if_version: Some("\"stale-version\"".into()),
        notify: false,
    });
    storage.commands.submit(&tenant(), &stale).await.unwrap();
    let r = engine.run_pim_commands(&config, &provider).await.unwrap();
    assert_eq!(r.failed, 1);
    let journal = events(storage.clone(), acc.clone()).await;
    let conflict = journal
        .iter()
        .find(|e| e.key == format!("command-{}", stale.id))
        .unwrap();
    let EventBody::Conflict { server_blob, .. } = &conflict.body else {
        panic!("a stale version conflicts: {:?}", conflict.body);
    };
    assert!(
        server_blob.is_some(),
        "the conflict carries the server's bytes"
    );

    for (collection, item, version) in objects {
        let delete = command(CommandBody::DeleteObject {
            collection,
            item: item.clone(),
            if_version: version,
            notify: false,
        });
        storage.commands.submit(&tenant(), &delete).await.unwrap();
    }
    let r = engine.run_pim_commands(&config, &provider).await.unwrap();
    assert_eq!(r.applied, 2);
    let report = engine.sync_collections(&config, &provider).await.unwrap();
    assert_eq!(report.collections.iter().map(|c| c.removed).sum::<u64>(), 2);
    let mut snapshot = skein_storage::Snapshot::empty(acc.clone());
    for e in events(storage.clone(), acc.clone()).await {
        snapshot.apply(&e);
    }
    assert_eq!(snapshot.object_count(), 0);
    assert!(
        snapshot.collections.contains_key(&cal) && snapshot.collections.contains_key(&book),
        "both collections are in the snapshot (other tests may add their own)"
    );

    for id in [&cal, &book] {
        dav("DELETE", &format!("{base}{id}"), &user, &password, "").await;
    }
    eprintln!("radicale round trip: 2 created, 1 conflict, 2 deleted");
}

async fn stalwart_jmap(body: serde_json::Value) -> serde_json::Value {
    use skein_integration::env;
    reqwest::Client::new()
        .post(format!("{}/jmap/", env("SKEIN_IT_STALWART_URL")))
        .basic_auth(
            env("SKEIN_IT_STALWART_USER"),
            Some(env("SKEIN_IT_STALWART_PASSWORD")),
        )
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .map(|b| serde_json::from_slice(&b).unwrap())
        .unwrap()
}

#[tokio::test]
async fn pim_jmap_round_trip_against_stalwart() {
    use bytes::Bytes;
    use serde_json::{Value, json};
    use skein_core::{CollectionKind, Credentials, ItemRef};
    use skein_integration::env;
    use skein_pim::{PimChange, PimProvider, PimWrite, WriteOutcome};
    use skein_pim_jmap::{CALENDARS, CONTACTS, CORE, JmapPimProvider, JmapPimSettings};

    if !enabled() {
        eprintln!("SKEIN_IT is not set; skipping");
        return;
    }
    let run = ulid::Ulid::generate().to_string().to_lowercase();
    let account = "b";
    let using = json!([CORE, CONTACTS, CALENDARS]);
    let made = stalwart_jmap(json!({
        "using": using,
        "methodCalls": [
            ["AddressBook/set", { "accountId": account, "create": { "b": { "name": format!("Book {run}") } } }, "0"],
            ["Calendar/set", { "accountId": account, "create": { "c": { "name": format!("Calendar {run}") } } }, "1"],
        ],
    }))
    .await;
    let book = made
        .pointer("/methodResponses/0/1/created/b/id")
        .and_then(Value::as_str)
        .expect("Stalwart makes an address book")
        .to_owned();
    let cal = made
        .pointer("/methodResponses/1/1/created/c/id")
        .and_then(Value::as_str)
        .expect("Stalwart makes a calendar")
        .to_owned();
    let book_id = format!("addressbook/{book}");
    let cal_id = format!("calendar/{cal}");

    let provider = JmapPimProvider::new(
        JmapPimSettings::new(env("SKEIN_IT_STALWART_URL"), env("SKEIN_IT_STALWART_USER")),
        Credentials::Password {
            secret: env("SKEIN_IT_STALWART_PASSWORD"),
        },
    )
    .unwrap();
    let mut session = provider.connect().await.unwrap();
    let listed = session.collections().await.unwrap();
    for (id, kind) in [
        (&book_id, CollectionKind::AddressBook),
        (&cal_id, CollectionKind::Calendar),
    ] {
        let info = listed
            .iter()
            .find(|c| &c.id == id)
            .expect("the new collection is listed");
        assert_eq!(info.kind, kind);
        assert!(!info.read_only);
    }

    let card = |tag: &str| {
        json!({
            "@type": "Card",
            "version": "1.0",
            "uid": format!("it-{run}@example.com"),
            "name": { "full": format!("Ada Example {tag}") },
            "emails": { "e1": { "address": "ada@example.org" } },
        })
    };
    let event = |tag: &str| {
        json!({
            "@type": "Event",
            "uid": format!("it-{run}@example.com"),
            "title": format!("Planning {tag}"),
            "start": "2026-12-01T10:00:00",
            "timeZone": "Etc/UTC",
            "duration": "PT1H",
        })
    };
    let item_type = |kind: CollectionKind| match kind {
        CollectionKind::AddressBook => "ContactCard",
        CollectionKind::Calendar => "CalendarEvent",
    };
    let member = |kind: CollectionKind| match kind {
        CollectionKind::AddressBook => "addressBookIds",
        CollectionKind::Calendar => "calendarIds",
    };
    for (collection, jmap_id, kind, object) in [
        (
            &book_id,
            &book,
            CollectionKind::AddressBook,
            &card as &dyn Fn(&str) -> Value,
        ),
        (&cal_id, &cal, CollectionKind::Calendar, &event),
    ] {
        let start = session.changes(collection, None, 100).await.unwrap();
        assert!(start.changes.is_empty(), "a new collection is empty");

        let create = PimWrite::Put {
            collection: collection.clone(),
            item: None,
            bytes: Bytes::from(object("one").to_string()),
            if_version: None,
            key: format!("01KIT{run}"),
            notify: false,
        };
        let WriteOutcome::Applied {
            item: Some(created),
            current: Some(current),
        } = session.apply(&create).await.unwrap()
        else {
            panic!("a create is applied and read back");
        };
        let again = session.apply(&create).await.unwrap();
        assert!(
            matches!(&again, WriteOutcome::Applied { item: Some(i), .. } if *i == created),
            "repeating a create answers with the same object: {again:?}"
        );

        let changes = session
            .changes(collection, Some(&start.cursor), 100)
            .await
            .unwrap();
        assert_eq!(
            changes.changes,
            vec![PimChange::Upserted {
                item: created.clone(),
                version: None
            }]
        );
        let fetched = session
            .fetch(collection, std::slice::from_ref(&created))
            .await
            .unwrap();
        assert_eq!(fetched.len(), 1);
        assert_eq!(
            fetched[0].bytes, current.bytes,
            "the bytes are stable across reads"
        );
        assert_eq!(fetched[0].version, current.version);
        let again = session
            .fetch(collection, std::slice::from_ref(&created))
            .await
            .unwrap();
        assert_eq!(
            again[0].bytes, fetched[0].bytes,
            "Stalwart's key order does not leak"
        );

        let mut edited: Value = serde_json::from_slice(&fetched[0].bytes).unwrap();
        let moved = object("two");
        for key in ["name", "title"] {
            if let Some(v) = moved.get(key) {
                edited[key] = v.clone();
            }
        }
        let stale = PimWrite::Put {
            collection: collection.clone(),
            item: Some(created.clone()),
            bytes: Bytes::from(edited.to_string()),
            if_version: Some("stale-version".into()),
            key: format!("01KITSTALE{run}"),
            notify: false,
        };
        assert!(matches!(
            session.apply(&stale).await.unwrap(),
            WriteOutcome::Conflict { current: Some(_) }
        ));
        let update = PimWrite::Put {
            collection: collection.clone(),
            item: Some(created.clone()),
            bytes: Bytes::from(edited.to_string()),
            if_version: fetched[0].version.clone(),
            key: format!("01KITUPDATE{run}"),
            notify: false,
        };
        let WriteOutcome::Applied {
            current: Some(updated),
            ..
        } = session.apply(&update).await.unwrap()
        else {
            panic!("the current version is accepted");
        };
        assert_ne!(updated.version, fetched[0].version);
        let held: Value = serde_json::from_slice(&updated.bytes).unwrap();
        for key in ["name", "title"] {
            if let Some(v) = moved.get(key) {
                assert_eq!(&held[key], v, "the change is on the server");
            }
        }

        let mut outside = object("outside");
        outside["uid"] = json!(format!("outside-{run}@example.com"));
        outside[member(kind)] = json!({ jmap_id.as_str(): true });
        stalwart_jmap(json!({
            "using": using,
            "methodCalls": [[format!("{}/set", item_type(kind)), { "accountId": account, "create": { "o": outside } }, "0"]],
        }))
        .await;
        let seen = session
            .changes(collection, Some(&changes.cursor), 100)
            .await
            .unwrap();
        let ups: Vec<&ItemRef> = seen
            .changes
            .iter()
            .filter_map(|c| match c {
                PimChange::Upserted { item, .. } => Some(item),
                _ => None,
            })
            .collect();
        assert_eq!(
            ups.len(),
            2,
            "our update and the object made elsewhere: {seen:?}"
        );

        let stale_delete = PimWrite::Delete {
            collection: collection.clone(),
            item: created.clone(),
            if_version: fetched[0].version.clone(),
            notify: false,
        };
        assert!(matches!(
            session.apply(&stale_delete).await.unwrap(),
            WriteOutcome::Conflict { .. }
        ));
        let delete = PimWrite::Delete {
            collection: collection.clone(),
            item: created.clone(),
            if_version: updated.version.clone(),
            notify: false,
        };
        assert!(matches!(
            session.apply(&delete).await.unwrap(),
            WriteOutcome::Applied { .. }
        ));
        let after = session
            .changes(collection, Some(&seen.cursor), 100)
            .await
            .unwrap();
        assert_eq!(
            after.changes,
            vec![PimChange::Removed {
                item: created.clone()
            }]
        );
        let garbage = skein_pim::Cursor(Bytes::from_static(b"not a cursor"));
        let reset = session
            .changes(collection, Some(&garbage), 100)
            .await
            .unwrap();
        assert!(matches!(
            reset.changes.first(),
            Some(PimChange::Reset { .. })
        ));
        assert_eq!(
            reset.changes.len(),
            2,
            "the reset lists the one object left"
        );
    }

    assert_eq!(
        session.scheduling(&cal_id).await.unwrap(),
        skein_pim::Scheduling::Server
    );
    let own = session.addresses().await.unwrap();
    eprintln!("stalwart calendar addresses: {}", own.len());
    let invited = json!({
        "@type": "Event",
        "uid": format!("invite-{run}@example.com"),
        "title": format!("Invited {run}"),
        "start": "2026-12-02T10:00:00",
        "timeZone": "Etc/UTC",
        "duration": "PT1H",
        "organizerCalendarAddress": "mailto:bob@example.org",
        "recurrenceRule": { "@type": "RecurrenceRule", "frequency": "weekly", "count": 3 },
        "recurrenceOverrides": {
            "2026-12-09T10:00:00": { "participants/a/participationStatus": "declined" },
        },
        "participants": {
            "o": { "@type": "Participant", "name": "Bob", "calendarAddress": "mailto:bob@example.org",
                   "roles": { "owner": true, "attendee": true }, "participationStatus": "accepted" },
            "a": { "@type": "Participant", "calendarAddress": "mailto:ada@example.com",
                   "roles": { "attendee": true }, "participationStatus": "needs-action", "expectReply": true },
        },
    });
    let WriteOutcome::Applied {
        item: Some(invite), ..
    } = session
        .apply(&PimWrite::Put {
            collection: cal_id.clone(),
            item: None,
            bytes: Bytes::from(invited.to_string()),
            if_version: None,
            key: format!("01KITINVITE{run}"),
            notify: false,
        })
        .await
        .unwrap()
    else {
        panic!("the invitation is stored");
    };
    let answered = session
        .apply(&PimWrite::Respond {
            collection: cal_id.clone(),
            item: invite.clone(),
            answer: skein_core::PartStat::Tentative,
            attendee: Some("ada@example.com".into()),
            comment: Some("Maybe".into()),
            if_version: None,
            notify: false,
        })
        .await
        .unwrap();
    let WriteOutcome::Applied {
        current: Some(current),
        ..
    } = answered
    else {
        panic!("the answer is applied: {answered:?}");
    };
    let held: Value = serde_json::from_slice(&current.bytes).unwrap();
    let statuses: Vec<(String, String)> = held["participants"]
        .as_object()
        .unwrap()
        .values()
        .map(|p| {
            (
                p["calendarAddress"].as_str().unwrap_or_default().to_owned(),
                p["participationStatus"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            )
        })
        .collect();
    assert!(
        statuses.contains(&("mailto:ada@example.com".into(), "tentative".into())),
        "{statuses:?}"
    );
    assert!(
        statuses.contains(&("mailto:bob@example.org".into(), "accepted".into())),
        "{statuses:?}"
    );
    eprintln!(
        "stalwart override after answer: {}",
        held["recurrenceOverrides"]
    );
    assert!(
        held["recurrenceOverrides"]
            .to_string()
            .contains("tentative"),
        "the instance with its own answer follows: {}",
        held["recurrenceOverrides"]
    );

    stalwart_jmap(json!({
        "using": using,
        "methodCalls": [
            ["AddressBook/set", { "accountId": account, "destroy": [book], "onDestroyRemoveContents": true }, "0"],
            ["Calendar/set", { "accountId": account, "destroy": [cal], "onDestroyRemoveEvents": true }, "1"],
        ],
    }))
    .await;
    eprintln!("jmap pim round trip: a card and an event created, changed and deleted");
}

async fn wait_for_mail(
    provider: &skein_mail_imap::ImapProvider,
    needle: &str,
    count: usize,
) -> Vec<bytes::Bytes> {
    use skein_mail::{MailChange, MailProvider};
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let mut found = Vec::new();
        if let Ok(mut session) = provider.connect().await {
            let mut cursor = None;
            loop {
                let Ok(batch) = session.changes("INBOX", cursor.as_ref(), 500).await else {
                    break;
                };
                let items: Vec<_> = batch
                    .changes
                    .iter()
                    .filter_map(|c| match c {
                        MailChange::Added { item, .. } => Some(item.clone()),
                        _ => None,
                    })
                    .collect();
                for raw in session.fetch("INBOX", &items).await.unwrap_or_default() {
                    if raw
                        .bytes
                        .windows(needle.len())
                        .any(|w| w == needle.as_bytes())
                    {
                        found.push(raw.bytes);
                    }
                }
                cursor = Some(batch.cursor);
                if !batch.more {
                    break;
                }
            }
            let _ = session.logout().await;
        }
        if found.len() >= count {
            return found;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{count} messages never arrived"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

#[tokio::test]
async fn itip_over_radicale_and_greenmail() {
    use bytes::Bytes;
    use skein_core::{
        Command, CommandBody, CommandId, Credentials, PartStat, ScheduleStatus, ScheduleVia,
    };
    use skein_integration::env;
    use skein_pim_dav::{DavConfig, DavProvider};
    use skein_send_smtp::{Security, SmtpSender, SmtpSettings};
    use skein_storage_memory::MemoryObjects;

    if !enabled() {
        eprintln!("SKEIN_IT is not set; skipping");
        return;
    }
    let (base, user, password) = radicale();
    let run = ulid::Ulid::generate().to_string().to_lowercase();
    let cal = format!("/{user}/itip-{run}/");
    let _ = dav("PROPFIND", &format!("{base}/{user}/"), &user, &password, "").await;
    assert_eq!(
        dav("MKCALENDAR", &format!("{base}{cal}"), &user, &password, "").await,
        201
    );
    let organizer = format!("org-{run}@example.com");
    let uid = format!("itip-{run}@example.com");
    let event = format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Skein IT//EN\r\nBEGIN:VEVENT\r\nUID:{uid}\r\n\
         DTSTAMP:20261101T000000Z\r\nDTSTART:20261130T090000Z\r\nDTEND:20261130T100000Z\r\n\
         SUMMARY:Integration {run}\r\nORGANIZER:mailto:{organizer}\r\n\
         ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:ada@example.com\r\n\
         END:VEVENT\r\nEND:VCALENDAR\r\n"
    );

    let smtp = SmtpSender::new(
        SmtpSettings {
            port: Some(env("SKEIN_IT_SMTP_PORT").parse().unwrap()),
            security: Security::Plain,
            ..SmtpSettings::new(env("SKEIN_IT_IMAP_HOST"))
        },
        None,
    )
    .unwrap();
    let storage = Storage::over(Arc::new(MemoryObjects::new()));
    let engine =
        single_engine(storage.clone(), "it").with_senders(Arc::new(OneSender(Arc::new(smtp))));
    let dav_provider = DavProvider::new(DavConfig::at(
        &base,
        &user,
        Credentials::Password {
            secret: password.clone(),
        },
    ))
    .unwrap();
    let acc = AccountId::new("itip").unwrap();
    let config = AccountConfig::new(tenant(), acc.clone());
    let submit = |body: CommandBody| {
        let storage = storage.clone();
        let acc = acc.clone();
        async move {
            let command = Command {
                id: CommandId::generate(),
                account: acc,
                created_at: Timestamp::now(),
                trace: None,
                body,
            };
            storage.commands.submit(&tenant(), &command).await.unwrap();
            command.id
        }
    };
    let journal = || {
        let storage = storage.clone();
        let acc = acc.clone();
        async move {
            storage
                .log
                .read(&tenant(), &acc, Seq(1), 100_000)
                .await
                .unwrap()
        }
    };
    let schedule_of = |all: &[skein_core::Event], id: &CommandId| {
        all.iter()
            .filter(|e| e.origin.as_ref() == Some(id))
            .find_map(|e| match &e.body {
                EventBody::ScheduleResult { via, messages, .. } => Some((*via, messages.clone())),
                _ => None,
            })
    };

    let blob = storage
        .blobs
        .put(&tenant(), Bytes::from(event.clone()))
        .await
        .unwrap();
    let put = submit(CommandBody::PutObject {
        collection: cal.clone(),
        item: None,
        blob,
        if_version: None,
        notify: true,
    })
    .await;
    engine
        .run_pim_commands(&config, &dav_provider)
        .await
        .unwrap();
    let all = journal().await;
    let (via, messages) = schedule_of(&all, &put).expect("schedule_result");
    assert_eq!(via, ScheduleVia::Mail, "Radicale does not schedule");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].method, "REQUEST");
    assert_eq!(messages[0].status, ScheduleStatus::Sent, "{messages:?}");
    let created = all
        .iter()
        .find_map(|e| match &e.body {
            EventBody::ObjectUpserted { item, .. } if e.origin.as_ref() == Some(&put) => {
                Some(item.clone())
            }
            _ => None,
        })
        .expect("the created event");

    let ada = imap(
        &env("SKEIN_IT_IMAP_HOST"),
        &env("SKEIN_IT_IMAP_PORT"),
        &env("SKEIN_IT_IMAP_USER"),
        &env("SKEIN_IT_IMAP_PASSWORD"),
    );
    let needle = format!("Integration {run}");
    wait_for_mail(&ada, &needle, 1).await;
    let inbox = AccountId::new("itip-ada").unwrap();
    let mut ada_config = AccountConfig::new(tenant(), inbox.clone());
    ada_config.include = Some(vec!["INBOX".into()]);
    engine.sync_account(&ada_config, &ada).await.unwrap();
    let ada_journal = storage
        .log
        .read(&tenant(), &inbox, Seq(1), 100_000)
        .await
        .unwrap();
    let (message_blob, summary) = ada_journal
        .windows(2)
        .find_map(|w| match (&w[0].body, &w[1].body) {
            (EventBody::MessageAdded { blob, .. }, EventBody::ItipReceived { itip, .. })
                if itip.uid == uid =>
            {
                Some((*blob, itip.clone()))
            }
            _ => None,
        })
        .expect("itip_received after the invitation");
    assert_eq!(summary.method, "REQUEST");
    assert_eq!(summary.organizer.as_deref(), Some(organizer.as_str()));

    let answer = CommandBody::RespondInvitation {
        invitation: message_blob,
        answer: PartStat::Accepted,
        attendee: None,
        comment: Some("See you".into()),
        save_to_sent: None,
    };
    let answered = Command {
        id: CommandId::generate(),
        account: inbox.clone(),
        created_at: Timestamp::now(),
        trace: None,
        body: answer,
    };
    storage.commands.submit(&tenant(), &answered).await.unwrap();
    let report = engine.run_commands(&ada_config, &ada).await.unwrap();
    assert_eq!(report.applied, 1, "{report:?}");

    let respond = submit(CommandBody::RespondObject {
        collection: cal.clone(),
        item: created.clone(),
        answer: PartStat::Declined,
        attendee: Some("ada@example.com".into()),
        comment: None,
        if_version: None,
        notify: true,
    })
    .await;
    engine
        .run_pim_commands(&config, &dav_provider)
        .await
        .unwrap();
    let (via, messages) = schedule_of(&journal().await, &respond).expect("schedule_result");
    assert_eq!(via, ScheduleVia::Mail);
    assert_eq!(messages[0].method, "REPLY");
    assert_eq!(messages[0].status, ScheduleStatus::Sent, "{messages:?}");
    let held = dav_get(&format!("{base}{}", created.id), &user, &password)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&held).contains("PARTSTAT=DECLINED"));

    let org = imap(
        &env("SKEIN_IT_IMAP_HOST"),
        &env("SKEIN_IT_IMAP_PORT"),
        &organizer,
        &organizer,
    );
    let replies = wait_for_mail(&org, &format!("{}.itip@example.com", answered.id), 1).await;
    let reply = skein_itip::imip::find(&replies[0]).expect("an iMIP reply");
    let facts = skein_itip::summary(&reply.calendar).unwrap();
    assert_eq!(facts.method, "REPLY");
    assert_eq!(facts.uid, uid);
    assert_eq!(facts.attendees[0].partstat.as_deref(), Some("ACCEPTED"));
    let declined = wait_for_mail(&org, &format!("{respond}-0.itip@example.com"), 1).await;
    let reply = skein_itip::imip::find(&declined[0]).expect("an iMIP reply");
    assert_eq!(
        skein_itip::summary(&reply.calendar).unwrap().attendees[0]
            .partstat
            .as_deref(),
        Some("DECLINED")
    );

    dav("DELETE", &format!("{base}{cal}"), &user, &password, "").await;
    eprintln!("itip round trip: request, itip_received, two replies");
}

#[tokio::test]
async fn caldav_scheduling_against_stalwart() {
    use bytes::Bytes;
    use skein_core::{
        CollectionRole, Command, CommandBody, CommandId, Credentials, PartStat, ScheduleVia,
    };
    use skein_integration::env;
    use skein_pim::{PimProvider, Scheduling};
    use skein_pim_dav::{DavConfig, DavProvider};
    use skein_storage_memory::MemoryObjects;

    if !enabled() {
        eprintln!("SKEIN_IT is not set; skipping");
        return;
    }
    let base = env("SKEIN_IT_STALWART_URL");
    let user = env("SKEIN_IT_STALWART_USER");
    let password = env("SKEIN_IT_STALWART_PASSWORD");
    let run = ulid::Ulid::generate().to_string().to_lowercase();
    let cal = format!("/dav/cal/{user}/itip-{run}/");
    let encoded = cal.replace('@', "%40");
    assert_eq!(
        dav(
            "MKCALENDAR",
            &format!("{base}{encoded}"),
            &user,
            &password,
            ""
        )
        .await,
        201
    );
    let mut config = DavConfig::at(
        &base,
        &user,
        Credentials::Password {
            secret: password.clone(),
        },
    );
    config.contacts = None;
    config.schedule_inbox = true;
    let provider = DavProvider::new(config).unwrap();
    let mut session = provider.connect().await.unwrap();
    let listed = session.collections().await.unwrap();
    assert!(listed.iter().any(|c| c.id == cal), "{listed:?}");
    assert!(
        listed
            .iter()
            .any(|c| c.role == Some(CollectionRole::ScheduleInbox)),
        "the scheduling inbox is listed"
    );
    assert_eq!(session.scheduling(&cal).await.unwrap(), Scheduling::Server);
    assert!(
        session
            .addresses()
            .await
            .unwrap()
            .contains(&user.to_lowercase()),
        "calendar-user-address-set names the account"
    );

    let storage = Storage::over(Arc::new(MemoryObjects::new()));
    let engine = single_engine(storage.clone(), "it");
    let acc = AccountId::new("stalwart-dav").unwrap();
    let account = AccountConfig::new(tenant(), acc.clone());
    let submit = |body: CommandBody| {
        let storage = storage.clone();
        let acc = acc.clone();
        async move {
            let command = Command {
                id: CommandId::generate(),
                account: acc,
                created_at: Timestamp::now(),
                trace: None,
                body,
            };
            storage.commands.submit(&tenant(), &command).await.unwrap();
            command.id
        }
    };
    let event = |uid: &str, organizer: &str, attendee: &str| {
        format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Skein IT//EN\r\nBEGIN:VEVENT\r\nUID:{uid}\r\n\
             DTSTAMP:20261101T000000Z\r\nDTSTART:20261203T090000Z\r\nDTEND:20261203T100000Z\r\n\
             SUMMARY:Stalwart {run}\r\nORGANIZER:mailto:{organizer}\r\n\
             ATTENDEE;PARTSTAT=ACCEPTED:mailto:{organizer}\r\n\
             ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:{attendee}\r\n\
             END:VEVENT\r\nEND:VCALENDAR\r\n"
        )
    };
    let blob = storage
        .blobs
        .put(
            &tenant(),
            Bytes::from(event(
                &format!("org-{run}@example.com"),
                &user,
                "bob@example.org",
            )),
        )
        .await
        .unwrap();
    let organized = submit(CommandBody::PutObject {
        collection: cal.clone(),
        item: None,
        blob,
        if_version: None,
        notify: true,
    })
    .await;
    let blob = storage
        .blobs
        .put(
            &tenant(),
            Bytes::from(event(
                &format!("inv-{run}@example.org"),
                "bob@example.org",
                &user,
            )),
        )
        .await
        .unwrap();
    let invited = submit(CommandBody::PutObject {
        collection: cal.clone(),
        item: None,
        blob,
        if_version: None,
        notify: false,
    })
    .await;
    engine.run_pim_commands(&account, &provider).await.unwrap();
    let journal = storage
        .log
        .read(&tenant(), &acc, Seq(1), 100_000)
        .await
        .unwrap();
    let applied = |id: &CommandId| {
        journal
            .iter()
            .any(|e| matches!(&e.body, EventBody::WriteApplied { command } if command == id))
    };
    assert!(applied(&organized) && applied(&invited), "{journal:?}");
    assert!(journal.iter().any(|e| e.origin.as_ref() == Some(&organized)
        && matches!(
            &e.body,
            EventBody::ScheduleResult {
                via: ScheduleVia::Server,
                ..
            }
        )));
    let item = journal
        .iter()
        .find_map(|e| match &e.body {
            EventBody::ObjectUpserted { item, .. } if e.origin.as_ref() == Some(&invited) => {
                Some(item.clone())
            }
            _ => None,
        })
        .expect("the invitation is stored");

    let respond = submit(CommandBody::RespondObject {
        collection: cal.clone(),
        item: item.clone(),
        answer: PartStat::Accepted,
        attendee: None,
        comment: None,
        if_version: None,
        notify: true,
    })
    .await;
    engine.run_pim_commands(&account, &provider).await.unwrap();
    let journal = storage
        .log
        .read(&tenant(), &acc, Seq(1), 100_000)
        .await
        .unwrap();
    assert!(
        journal
            .iter()
            .any(|e| matches!(&e.body, EventBody::WriteApplied { command } if *command == respond)),
        "{journal:?}"
    );
    assert!(journal.iter().any(|e| e.origin.as_ref() == Some(&respond)
        && matches!(
            &e.body,
            EventBody::ScheduleResult {
                via: ScheduleVia::Server,
                ..
            }
        )));
    let held = journal
        .iter()
        .rev()
        .find_map(|e| match &e.body {
            EventBody::ObjectUpserted { blob, .. } if e.origin.as_ref() == Some(&respond) => {
                Some(*blob)
            }
            _ => None,
        })
        .expect("the answered copy is read back");
    let held = storage.blobs.get(&tenant(), &held).await.unwrap().unwrap();
    let facts = skein_itip::facts(&held).unwrap();
    assert_eq!(
        facts
            .own_attendee(std::slice::from_ref(&user))
            .and_then(|a| a.partstat.clone())
            .as_deref(),
        Some("ACCEPTED")
    );

    dav("DELETE", &format!("{base}{encoded}"), &user, &password, "").await;
    eprintln!("caldav scheduling against stalwart: auto-schedule, addresses, inbox, answer");
}
