use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use skein_core::{
    AccountId, Command, CommandBody, CommandId, Event, EventBody, SendEnvelope, SentCopy, Seq,
    TenantId, Timestamp,
};
use skein_mail::testing::{FakeMail, ServerControl};
use skein_send::testing::FakeSender;
use skein_send::{RecipientOutcome, RecipientResult, Refusal, SendError, SendReport, Sender};
use skein_storage::{Expect, Storage};
use skein_storage_memory::MemoryObjects;

use crate::{AccountConfig, Engine, SendPolicy, SenderDirectory};

const MESSAGE: &[u8] =
    b"From: Ada <ada@example.com>\r\nTo: Bob <bob@example.org>\r\nSubject: Hi\r\n\r\nHello\r\n";

struct One(Option<Arc<dyn Sender>>);

#[async_trait]
impl SenderDirectory for One {
    async fn sender(
        &self,
        _: &TenantId,
        _: &AccountId,
    ) -> Result<Option<Arc<dyn Sender>>, SendError> {
        Ok(self.0.clone())
    }
}

fn tenant() -> TenantId {
    TenantId::new("t").unwrap()
}

fn acc() -> AccountId {
    AccountId::new("a").unwrap()
}

fn config() -> AccountConfig {
    AccountConfig::new(tenant(), acc())
}

fn build(sender: Option<FakeSender>, policy: SendPolicy) -> (Engine, Storage) {
    let storage = Storage::over(Arc::new(MemoryObjects::new()));
    (over(&storage, sender, policy), storage)
}

fn over(storage: &Storage, sender: Option<FakeSender>, policy: SendPolicy) -> Engine {
    Engine::new(
        storage.clone(),
        crate::test_support::single_leases(),
        crate::test_support::signal(),
        crate::test_support::profile("n1"),
    )
    .with_senders(Arc::new(
        One(sender.map(|s| Arc::new(s) as Arc<dyn Sender>)),
    ))
    .with_send_policy(policy)
}

fn fast() -> SendPolicy {
    SendPolicy {
        undo_ms: 0,
        max_attempts: 3,
        first_delay_ms: 0,
        max_delay_ms: 0,
    }
}

async fn queue_send(
    storage: &Storage,
    save_to_sent: Option<&str>,
    send_at: Option<Timestamp>,
) -> CommandId {
    queue(storage, Timestamp::now(), save_to_sent, send_at, false).await
}

async fn queue(
    storage: &Storage,
    created_at: Timestamp,
    save_to_sent: Option<&str>,
    send_at: Option<Timestamp>,
    dry_run: bool,
) -> CommandId {
    let blob = storage
        .blobs
        .put(&tenant(), Bytes::from_static(MESSAGE))
        .await
        .unwrap();
    let command = Command {
        id: CommandId::generate(),
        account: acc(),
        created_at,
        trace: None,
        body: CommandBody::Send {
            blob,
            envelope: SendEnvelope {
                from: "ada@example.com".into(),
                to: vec!["bob@example.org".into(), "carol@example.org".into()],
                dsn: None,
            },
            save_to_sent: save_to_sent.map(str::to_owned),
            send_at,
            dry_run,
        },
    };
    storage.commands.submit(&tenant(), &command).await.unwrap();
    command.id
}

async fn events(storage: &Storage) -> Vec<Event> {
    storage
        .log
        .read(&tenant(), &acc(), Seq(1), 10_000)
        .await
        .unwrap()
}

async fn pending(storage: &Storage) -> usize {
    storage
        .commands
        .pending(&tenant(), &acc(), 100)
        .await
        .unwrap()
        .len()
}

#[tokio::test]
async fn a_sent_message_records_its_outcome_once() {
    let sender = FakeSender::new();
    let (engine, storage) = build(Some(sender.clone()), fast());
    let id = queue_send(&storage, None, None).await;
    let report = engine
        .run_commands(&config(), &FakeMail::new())
        .await
        .unwrap();
    assert_eq!(report.applied, 1);
    let delivered = sender.deliveries();
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].bytes, MESSAGE);
    assert_eq!(delivered[0].mail_from, "ada@example.com");
    assert_eq!(
        delivered[0].recipients,
        vec!["bob@example.org", "carol@example.org"]
    );
    let events = events(&storage).await;
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[0].body,
        EventBody::WriteApplied {
            command: id.clone()
        }
    );
    assert_eq!(
        events[1].body,
        EventBody::SendResult {
            command: id.clone(),
            refused: vec![],
            sent_copy: None,
            message_id: None,
            provider_message_id: None,
            dry_run: false,
        }
    );
    assert!(events.iter().all(|e| e.origin.as_ref() == Some(&id)));
    assert_eq!(pending(&storage).await, 0);

    engine
        .run_commands(&config(), &FakeMail::new())
        .await
        .unwrap();
    assert_eq!(sender.calls(), 1);
}

#[tokio::test]
async fn a_scheduled_send_waits_without_holding_up_the_queue() {
    let sender = FakeSender::new();
    let (engine, storage) = build(Some(sender.clone()), fast());
    let later = Timestamp::now().plus_ms(60_000);
    let scheduled = queue_send(&storage, None, Some(later)).await;
    let now = queue_send(&storage, None, Some(Timestamp(0))).await;
    let report = engine
        .run_commands(&config(), &FakeMail::new())
        .await
        .unwrap();
    assert_eq!(report.applied, 1);
    assert_eq!(report.waiting, 1);
    assert_eq!(report.next_due, Some(later));
    assert_eq!(sender.calls(), 1);
    let events = events(&storage).await;
    assert!(matches!(&events[0].body, EventBody::WriteApplied { command } if *command == now));
    let left = storage
        .commands
        .pending(&tenant(), &acc(), 100)
        .await
        .unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].id, scheduled);
}

#[tokio::test]
async fn a_send_that_did_not_go_out_is_tried_again_then_given_up() {
    let sender = FakeSender::new();
    for _ in 0..3 {
        sender.script(Err(SendError::Unavailable("down".into())));
    }
    let (engine, storage) = build(Some(sender.clone()), fast());
    let id = queue_send(&storage, None, None).await;
    let mail = FakeMail::new();
    let first = engine.run_commands(&config(), &mail).await.unwrap();
    assert_eq!(first.waiting, 1);
    assert!(
        events(&storage).await.is_empty(),
        "nothing recorded while retrying"
    );
    assert_eq!(pending(&storage).await, 1);
    engine.run_commands(&config(), &mail).await.unwrap();
    let last = engine.run_commands(&config(), &mail).await.unwrap();
    assert_eq!(last.failed, 1);
    assert_eq!(sender.calls(), 3);
    assert_eq!(
        events(&storage).await[0].body,
        EventBody::WriteFailed {
            command: id,
            reason: "gave_up".into()
        }
    );
    assert_eq!(pending(&storage).await, 0);
    let left = storage
        .control
        .list(&tenant(), "sending", None, 10)
        .await
        .unwrap();
    assert!(left.is_empty(), "the attempt counter stayed: {left:?}");
}

#[tokio::test]
async fn a_retry_waits_for_its_backoff() {
    let sender = FakeSender::new();
    sender.script(Err(SendError::Temporary("broke".into())));
    let policy = SendPolicy {
        first_delay_ms: 3_600_000,
        max_delay_ms: 3_600_000,
        ..fast()
    };
    let (engine, storage) = build(Some(sender.clone()), policy);
    queue_send(&storage, None, None).await;
    let mail = FakeMail::new();
    let first = engine.run_commands(&config(), &mail).await.unwrap();
    assert!(first.next_due.unwrap() > Timestamp::now().plus_ms(3_000_000));
    let second = engine.run_commands(&config(), &mail).await.unwrap();
    assert_eq!(second.waiting, 1);
    assert_eq!(sender.calls(), 1, "tried again before the backoff ended");
}

#[tokio::test]
async fn a_send_that_may_have_gone_out_is_uncertain_and_never_sent_again() {
    let sender = FakeSender::new();
    sender.script(Err(SendError::Uncertain("silence".into())));
    let (engine, storage) = build(Some(sender.clone()), fast());
    let id = queue_send(&storage, None, None).await;
    let mail = FakeMail::new();
    let report = engine.run_commands(&config(), &mail).await.unwrap();
    assert_eq!(report.uncertain, 1);
    engine.run_commands(&config(), &mail).await.unwrap();
    assert_eq!(sender.calls(), 1);
    let events = events(&storage).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].body, EventBody::WriteUncertain { command: id });
}

#[tokio::test]
async fn a_crash_after_sending_never_sends_twice() {
    let sender = FakeSender::new();
    let (engine, storage) = build(Some(sender.clone()), fast());
    let id = queue_send(&storage, None, None).await;
    storage
        .control
        .put(
            &tenant(),
            &format!("started/{}/{id}", acc()),
            Bytes::from_static(b"started"),
            Expect::Any,
        )
        .await
        .unwrap();
    let report = engine
        .run_commands(&config(), &FakeMail::new())
        .await
        .unwrap();
    assert_eq!(report.uncertain, 1);
    assert_eq!(sender.calls(), 0);
    assert_eq!(pending(&storage).await, 0);
}

#[tokio::test]
async fn permanent_refusals_fail_with_their_recipients() {
    let sender = FakeSender::new();
    let refusal = |address: &str| RecipientResult {
        address: address.into(),
        outcome: RecipientOutcome::Refused(Refusal {
            permanent: true,
            code: 550,
            text: "5.1.1 unknown".into(),
        }),
    };
    sender.script(Err(SendError::RecipientsRefused(vec![
        refusal("bob@example.org"),
        refusal("carol@example.org"),
    ])));
    let (engine, storage) = build(Some(sender.clone()), fast());
    let id = queue_send(&storage, None, None).await;
    engine
        .run_commands(&config(), &FakeMail::new())
        .await
        .unwrap();
    let events = events(&storage).await;
    assert_eq!(
        events[0].body,
        EventBody::WriteFailed {
            command: id.clone(),
            reason: "recipients_refused".into()
        }
    );
    let EventBody::SendResult {
        refused, sent_copy, ..
    } = &events[1].body
    else {
        panic!("no send result");
    };
    assert_eq!(refused.len(), 2);
    assert_eq!(refused[0].code, 550);
    assert_eq!(sent_copy, &None);

    let partial = FakeSender::new();
    partial.script(Ok(SendReport::new(vec![
        RecipientResult {
            address: "bob@example.org".into(),
            outcome: RecipientOutcome::Accepted,
        },
        refusal("carol@example.org"),
    ])));
    let (engine, storage) = build(Some(partial), fast());
    queue_send(&storage, None, None).await;
    let report = engine
        .run_commands(&config(), &FakeMail::new())
        .await
        .unwrap();
    assert_eq!(report.applied, 1);
    let EventBody::SendResult { refused, .. } = &events_of(&storage).await[1].body else {
        panic!("no send result");
    };
    assert_eq!(refused[0].address, "carol@example.org");
}

async fn events_of(storage: &Storage) -> Vec<Event> {
    events(storage).await
}

#[tokio::test]
async fn saves_to_sent_only_when_the_service_does_not() {
    let mail = FakeMail::new();
    mail.create_mailbox("Sent").await;
    let (engine, storage) = build(Some(FakeSender::new()), fast());
    queue_send(&storage, Some("Sent"), None).await;
    engine.run_commands(&config(), &mail).await.unwrap();
    assert!(
        mail.flags_of("Sent", MESSAGE)
            .await
            .is_some_and(|f| f.contains("\\Seen")),
        "no seen copy in Sent"
    );
    let EventBody::SendResult { sent_copy, .. } = &events(&storage).await[1].body else {
        panic!("no send result");
    };
    assert_eq!(sent_copy, &Some(SentCopy::Saved));

    let mail = FakeMail::new();
    mail.create_mailbox("Sent").await;
    let (engine, storage) = build(Some(FakeSender::new().saving_to_sent()), fast());
    queue_send(&storage, Some("Sent"), None).await;
    engine.run_commands(&config(), &mail).await.unwrap();
    assert!(
        mail.flags_of("Sent", MESSAGE).await.is_none(),
        "copied twice"
    );
    assert_eq!(mail.connects(), 0, "connected to the mailbox for nothing");
    let EventBody::SendResult { sent_copy, .. } = &events(&storage).await[1].body else {
        panic!("no send result");
    };
    assert_eq!(sent_copy, &Some(SentCopy::Provider));

    let mail = FakeMail::new();
    let (engine, storage) = build(Some(FakeSender::new()), fast());
    queue_send(&storage, Some("Missing"), None).await;
    let report = engine.run_commands(&config(), &mail).await.unwrap();
    assert_eq!(report.applied, 1, "the message went out all the same");
    let EventBody::SendResult { sent_copy, .. } = &events(&storage).await[1].body else {
        panic!("no send result");
    };
    assert_eq!(sent_copy, &Some(SentCopy::Failed));
}

#[tokio::test]
async fn the_sent_copy_carries_the_message_id_the_service_delivered() {
    const OWN: &[u8] = b"From: Ada <ada@example.com>\r\nTo: Bob <bob@example.org>\r\nMessage-ID:\r\n <own-1@example.com>\r\nSubject: Hi\r\n\r\nHello\r\n";
    const SES: &str = "<0102-abc-000000@eu-west-1.amazonses.com>";
    let rewritten = format!(
        "From: Ada <ada@example.com>\r\nTo: Bob <bob@example.org>\r\nMessage-ID: {SES}\r\nX-Skein-Original-Message-ID: <own-1@example.com>\r\nSubject: Hi\r\n\r\nHello\r\n"
    );
    let mail = FakeMail::new();
    mail.create_mailbox("Sent").await;
    let sender = FakeSender::new().replacing_message_id(SES, "0102-abc-000000");
    let (engine, storage) = build(Some(sender.clone()), fast());
    let blob = storage
        .blobs
        .put(&tenant(), Bytes::from_static(OWN))
        .await
        .unwrap();
    let command = Command {
        id: CommandId::generate(),
        account: acc(),
        created_at: Timestamp::now(),
        trace: None,
        body: CommandBody::Send {
            blob,
            envelope: SendEnvelope {
                from: "ada@example.com".into(),
                to: vec!["bob@example.org".into()],
                dsn: None,
            },
            save_to_sent: Some("Sent".into()),
            send_at: None,
            dry_run: false,
        },
    };
    storage.commands.submit(&tenant(), &command).await.unwrap();
    engine.run_commands(&config(), &mail).await.unwrap();

    assert_eq!(
        sender.deliveries()[0].bytes,
        OWN,
        "the service got the client's bytes"
    );
    assert!(
        mail.flags_of("Sent", rewritten.as_bytes()).await.is_some(),
        "the sent copy does not carry the delivered Message-ID"
    );
    assert!(mail.flags_of("Sent", OWN).await.is_none());
    assert_eq!(
        storage
            .blobs
            .get(&tenant(), &blob)
            .await
            .unwrap()
            .as_deref(),
        Some(OWN),
        "the command's blob changed"
    );
    assert_eq!(
        events(&storage).await[1].body,
        EventBody::SendResult {
            command: command.id.clone(),
            refused: vec![],
            sent_copy: Some(SentCopy::Saved),
            message_id: Some(SES.into()),
            provider_message_id: Some("0102-abc-000000".into()),
            dry_run: false,
        }
    );

    let mail = FakeMail::new();
    mail.create_mailbox("Sent").await;
    let keeps = FakeSender::new()
        .replacing_message_id(SES, "0102-abc-000000")
        .saving_to_sent();
    let (engine, storage) = build(Some(keeps), fast());
    queue_send(&storage, Some("Sent"), None).await;
    engine.run_commands(&config(), &mail).await.unwrap();
    assert_eq!(
        mail.connects(),
        0,
        "a service that keeps the copy is left alone"
    );
    let EventBody::SendResult {
        sent_copy,
        message_id,
        ..
    } = &events(&storage).await[1].body
    else {
        panic!("no send result");
    };
    assert_eq!(sent_copy, &Some(SentCopy::Provider));
    assert_eq!(message_id.as_deref(), Some(SES));
}

#[tokio::test]
async fn sends_without_a_sender_or_with_a_bad_envelope_fail() {
    let (engine, storage) = build(None, fast());
    let id = queue_send(&storage, None, None).await;
    engine
        .run_commands(&config(), &FakeMail::new())
        .await
        .unwrap();
    assert_eq!(
        events(&storage).await[0].body,
        EventBody::WriteFailed {
            command: id,
            reason: "no_sender".into()
        }
    );

    let sender = FakeSender::new();
    let (engine, storage) = build(Some(sender.clone()), fast());
    let blob = storage
        .blobs
        .put(&tenant(), Bytes::from_static(MESSAGE))
        .await
        .unwrap();
    let bad = Command {
        id: CommandId::generate(),
        account: acc(),
        created_at: Timestamp::now(),
        trace: None,
        body: CommandBody::Send {
            blob,
            envelope: SendEnvelope {
                from: "ada@example.com\r\nBcc: eve@example.org".into(),
                to: vec!["bob@example.org".into()],
                dsn: None,
            },
            save_to_sent: None,
            send_at: None,
            dry_run: false,
        },
    };
    storage.commands.submit(&tenant(), &bad).await.unwrap();
    engine
        .run_commands(&config(), &FakeMail::new())
        .await
        .unwrap();
    assert_eq!(
        events(&storage).await[0].body,
        EventBody::WriteFailed {
            command: bad.id,
            reason: "invalid_envelope".into()
        }
    );
    assert_eq!(sender.calls(), 0);
}

fn undo(ms: i64) -> SendPolicy {
    SendPolicy {
        undo_ms: ms,
        ..fast()
    }
}

async fn cancel(storage: &Storage, id: &CommandId) {
    storage
        .control
        .put(
            &tenant(),
            &format!("started/{}/{id}", acc()),
            Bytes::from_static(b"cancelled"),
            Expect::Absent,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn a_send_waits_for_the_undo_window_and_can_be_cancelled_in_it() {
    let sender = FakeSender::new();
    let (engine, storage) = build(Some(sender.clone()), undo(60_000));
    let created = Timestamp::now();
    let id = queue(&storage, created, None, None, false).await;
    let report = engine
        .run_commands(&config(), &FakeMail::new())
        .await
        .unwrap();
    assert_eq!(report.waiting, 1);
    assert_eq!(report.next_due, Some(created.plus_ms(60_000)));
    assert_eq!(sender.calls(), 0, "sent inside the undo window");

    cancel(&storage, &id).await;
    let after_window = over(&storage, Some(sender.clone()), undo(0));
    after_window
        .run_commands(&config(), &FakeMail::new())
        .await
        .unwrap();
    assert_eq!(sender.calls(), 0, "a cancelled send went out");
    assert_eq!(pending(&storage).await, 0);
    assert!(events(&storage).await.is_empty());
}

#[tokio::test]
async fn a_send_goes_out_once_the_undo_window_is_over() {
    let sender = FakeSender::new();
    let (engine, storage) = build(Some(sender.clone()), undo(60_000));
    let id = queue(
        &storage,
        Timestamp::now().plus_ms(-120_000),
        None,
        None,
        false,
    )
    .await;
    let report = engine
        .run_commands(&config(), &FakeMail::new())
        .await
        .unwrap();
    assert_eq!(report.applied, 1);
    assert_eq!(sender.calls(), 1);
    assert_eq!(
        events(&storage).await[0].body,
        EventBody::WriteApplied { command: id }
    );
}

#[tokio::test]
async fn the_undo_window_moves_an_earlier_send_at_and_keeps_a_later_one() {
    let sender = FakeSender::new();
    let (engine, storage) = build(Some(sender.clone()), undo(60_000));
    let created = Timestamp::now();
    queue(&storage, created, None, Some(Timestamp(0)), false).await;
    let report = engine
        .run_commands(&config(), &FakeMail::new())
        .await
        .unwrap();
    assert_eq!(report.next_due, Some(created.plus_ms(60_000)));

    let (engine, storage) = build(Some(sender.clone()), undo(60_000));
    let later = created.plus_ms(600_000);
    queue(&storage, created, None, Some(later), false).await;
    let report = engine
        .run_commands(&config(), &FakeMail::new())
        .await
        .unwrap();
    assert_eq!(report.next_due, Some(later));
    assert_eq!(sender.calls(), 0);
}

#[tokio::test]
async fn a_dry_run_checks_everything_and_sends_nothing() {
    let mail = FakeMail::new();
    mail.create_mailbox("Sent").await;
    let sender = FakeSender::new();
    let (engine, storage) = build(Some(sender.clone()), undo(60_000));
    let id = queue(&storage, Timestamp::now(), Some("Sent"), None, true).await;
    let report = engine.run_commands(&config(), &mail).await.unwrap();
    assert_eq!(report.applied, 1, "a dry run waited for the undo window");
    assert_eq!(sender.calls(), 0);
    assert!(mail.flags_of("Sent", MESSAGE).await.is_none());
    let events = events(&storage).await;
    assert_eq!(
        events[0].body,
        EventBody::WriteApplied {
            command: id.clone()
        }
    );
    assert_eq!(
        events[1].body,
        EventBody::SendResult {
            command: id,
            refused: vec![],
            sent_copy: None,
            message_id: None,
            provider_message_id: None,
            dry_run: true,
        }
    );
    assert_eq!(pending(&storage).await, 0);
}

#[tokio::test]
async fn a_dry_run_fails_like_a_real_send() {
    let (engine, storage) = build(None, fast());
    let id = queue(&storage, Timestamp::now(), None, None, true).await;
    engine
        .run_commands(&config(), &FakeMail::new())
        .await
        .unwrap();
    assert_eq!(events(&storage).await.len(), 1);
    assert_eq!(
        events(&storage).await[0].body,
        EventBody::WriteFailed {
            command: id,
            reason: "no_sender".into()
        }
    );

    let sender = FakeSender::new();
    let (engine, storage) = build(Some(sender.clone()), fast());
    let missing = Command {
        id: CommandId::generate(),
        account: acc(),
        created_at: Timestamp::now(),
        trace: None,
        body: CommandBody::Send {
            blob: skein_core::BlobHash::of(b"never stored"),
            envelope: SendEnvelope {
                from: "ada@example.com".into(),
                to: vec!["bob@example.org".into()],
                dsn: None,
            },
            save_to_sent: None,
            send_at: None,
            dry_run: true,
        },
    };
    let id = missing.id.clone();
    storage.commands.submit(&tenant(), &missing).await.unwrap();
    engine
        .run_commands(&config(), &FakeMail::new())
        .await
        .unwrap();
    assert_eq!(
        events(&storage).await[0].body,
        EventBody::WriteFailed {
            command: id,
            reason: "blob_missing".into()
        }
    );
    assert_eq!(sender.calls(), 0);
}

#[tokio::test]
async fn a_throttled_send_waits_as_long_as_the_service_asked() {
    let sender = FakeSender::new();
    sender.script(Err(SendError::Throttled {
        retry_after: Some(std::time::Duration::from_secs(600)),
    }));
    let (engine, storage) = build(Some(sender.clone()), fast());
    queue_send(&storage, None, None).await;
    let before = Timestamp::now();
    let first = engine
        .run_commands(&config(), &FakeMail::new())
        .await
        .unwrap();
    let due = first.next_due.unwrap();
    assert!(due >= before.plus_ms(600_000) && due <= Timestamp::now().plus_ms(600_000));
    let second = engine
        .run_commands(&config(), &FakeMail::new())
        .await
        .unwrap();
    assert_eq!(second.waiting, 1);
    assert_eq!(sender.calls(), 1);
}

#[tokio::test]
async fn a_requested_wait_is_capped_at_an_hour_and_never_shortens_the_backoff() {
    let sender = FakeSender::new();
    sender.script(Err(SendError::Throttled {
        retry_after: Some(std::time::Duration::from_secs(86_400)),
    }));
    let (engine, storage) = build(Some(sender.clone()), fast());
    queue_send(&storage, None, None).await;
    let first = engine
        .run_commands(&config(), &FakeMail::new())
        .await
        .unwrap();
    assert!(first.next_due.unwrap() <= Timestamp::now().plus_ms(3_600_000));
    assert!(first.next_due.unwrap() > Timestamp::now().plus_ms(3_500_000));

    let sender = FakeSender::new();
    sender.script(Err(SendError::Throttled {
        retry_after: Some(std::time::Duration::from_secs(1)),
    }));
    let policy = SendPolicy {
        first_delay_ms: 600_000,
        max_delay_ms: 600_000,
        ..fast()
    };
    let (engine, storage) = build(Some(sender), policy);
    queue_send(&storage, None, None).await;
    let first = engine
        .run_commands(&config(), &FakeMail::new())
        .await
        .unwrap();
    assert!(first.next_due.unwrap() > Timestamp::now().plus_ms(500_000));
}

#[tokio::test]
async fn sending_service_failures_land_in_the_status_record() {
    let sender = FakeSender::new();
    sender.script(Err(SendError::Auth("refused".into())));
    let (engine, storage) = build(Some(sender.clone()), fast());
    queue_send(&storage, None, None).await;
    engine
        .run_commands(&config(), &FakeMail::new())
        .await
        .unwrap();
    let status = crate::load_status(&*storage.control, &tenant(), &acc())
        .await
        .unwrap()
        .unwrap();
    let send = status.send.unwrap();
    assert_eq!(send.outcome, skein_core::SyncOutcome::AuthFailed);
    assert!(status.mail.is_none());
}

#[tokio::test]
async fn a_sending_account_that_cannot_send_is_a_config_problem() {
    let sender = FakeSender::new();
    sender.script(Err(SendError::Invalid("the account is paused".into())));
    let (engine, storage) = build(Some(sender.clone()), fast());
    queue_send(&storage, None, None).await;
    engine
        .run_commands(&config(), &FakeMail::new())
        .await
        .unwrap();
    let status = crate::load_status(&*storage.control, &tenant(), &acc())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        status.send.unwrap().outcome,
        skein_core::SyncOutcome::Config
    );
    assert_eq!(sender.calls(), 1, "an invalid send is not tried again");
}

struct Gate {
    sender: Arc<dyn Sender>,
    entered: tokio::sync::Notify,
    go: tokio::sync::Semaphore,
}

#[async_trait]
impl SenderDirectory for Gate {
    async fn sender(
        &self,
        _: &TenantId,
        _: &AccountId,
    ) -> Result<Option<Arc<dyn Sender>>, SendError> {
        self.entered.notify_one();
        let _ = self.go.acquire().await.unwrap();
        Ok(Some(self.sender.clone()))
    }
}

#[tokio::test]
async fn a_run_whose_heartbeats_lapsed_never_reaches_the_provider_after_they_recover() {
    use crate::test_support::{ManualClock, leases_over, profile};
    use std::time::{Duration, Instant};

    let storage = Storage::over(Arc::new(MemoryObjects::new()));
    let state = Arc::new(baton_state_memory::MemoryState::new());
    let clock = ManualClock::new();
    let (leases, liveness) = leases_over(state, 30_000, Some(clock.clock()));
    let nodes = skein_core::coordination::group(&tenant());
    for n in ["n1", "n2"] {
        liveness
            .heartbeat(&nodes, &profile(n), clock.now())
            .await
            .unwrap();
    }
    let sender = FakeSender::new();
    let gate = Arc::new(Gate {
        sender: Arc::new(sender.clone()),
        entered: tokio::sync::Notify::new(),
        go: tokio::sync::Semaphore::new(0),
    });
    let engine = Engine::new(
        storage.clone(),
        leases.clone(),
        crate::test_support::signal(),
        profile("n1"),
    )
    .with_senders(gate.clone())
    .with_send_policy(fast());
    let valid_for = Duration::from_millis(100);
    engine.holding.arm(valid_for);
    engine.holding.beat(Instant::now());
    let id = queue_send(&storage, None, None).await;

    let running = {
        let engine = engine.clone();
        tokio::spawn(async move { engine.run_commands(&config(), &FakeMail::new()).await })
    };
    gate.entered.notified().await;

    tokio::time::sleep(valid_for + Duration::from_millis(30)).await;
    assert!(!engine.holding.held());
    clock.advance(30_001);
    liveness
        .heartbeat(&nodes, &profile("n2"), clock.now())
        .await
        .unwrap();
    let taken = leases
        .acquire(
            &nodes,
            &skein_core::coordination::lease_key(&acc()),
            &profile("n2"),
        )
        .await
        .unwrap()
        .expect("the other node takes the account");
    engine.holding.beat(Instant::now());
    assert!(engine.holding.held(), "heartbeats recovered");

    gate.go.add_permits(1);
    let result = running.await.unwrap();
    assert!(
        matches!(result, Err(crate::EngineError::NotOwner)),
        "{result:?}"
    );
    assert_eq!(sender.calls(), 0, "nothing reached the sending service");
    assert!(
        storage
            .control
            .get(
                &tenant(),
                &crate::state::command_marker(&acc(), id.as_str())
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(taken.fence.0 > 0);
    assert!(matches!(
        engine.run_commands(&config(), &FakeMail::new()).await,
        Err(crate::EngineError::NotOwner)
    ));
}
