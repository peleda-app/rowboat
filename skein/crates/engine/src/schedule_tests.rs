use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use skein_core::{
    AccountId, Command, CommandBody, CommandId, Event, EventBody, Flags, ItemRef, PartStat,
    ScheduleStatus, ScheduleVia, Seq, TenantId, Timestamp,
};
use skein_mail::testing::{FakeMail, ServerControl};
use skein_pim::testing::{CALENDAR, FakePim, PimServerControl};
use skein_send::testing::FakeSender;
use skein_send::{SendError, Sender};
use skein_storage::{Expect, Storage};
use skein_storage_memory::MemoryObjects;

use crate::state::command_marker;
use crate::{AccountConfig, Engine, SenderDirectory};

const MEETING: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Example//EN\r\nBEGIN:VEVENT\r\n\
UID:meet-1@example.com\r\nDTSTAMP:20261101T000000Z\r\nSEQUENCE:0\r\n\
DTSTART:20261130T090000Z\r\nDTEND:20261130T100000Z\r\nSUMMARY:Kickoff\r\n\
ORGANIZER:mailto:ada@example.com\r\n\
ATTENDEE;PARTSTAT=ACCEPTED:mailto:ada@example.com\r\n\
ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:bob@example.org\r\n\
ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:carol@example.org\r\n\
END:VEVENT\r\nEND:VCALENDAR\r\n";

const INVITED: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Example//EN\r\nBEGIN:VEVENT\r\n\
UID:visit-9@example.org\r\nDTSTAMP:20261101T000000Z\r\nSEQUENCE:3\r\n\
DTSTART:20261201T090000Z\r\nSUMMARY:Visit\r\n\
ORGANIZER:mailto:bob@example.org\r\n\
ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:ada@example.com\r\n\
END:VEVENT\r\nEND:VCALENDAR\r\n";

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

fn build(sender: Option<FakeSender>) -> (Engine, Storage) {
    let storage = Storage::over(Arc::new(MemoryObjects::new()));
    let engine = Engine::new(
        storage.clone(),
        crate::test_support::single_leases(),
        crate::test_support::signal(),
        crate::test_support::profile("n1"),
    )
    .with_senders(Arc::new(
        One(sender.map(|s| Arc::new(s) as Arc<dyn Sender>)),
    ));
    (engine, storage)
}

async fn submit(storage: &Storage, body: CommandBody) -> CommandId {
    let command = Command {
        id: CommandId::generate(),
        account: acc(),
        created_at: Timestamp(1_795_262_400_000),
        trace: None,
        body,
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

fn result_of(all: &[Event], id: &CommandId) -> Option<EventBody> {
    all.iter()
        .filter(|e| e.origin.as_ref() == Some(id))
        .find(|e| matches!(e.body, EventBody::ScheduleResult { .. }))
        .map(|e| e.body.clone())
}

fn applied(all: &[Event], id: &CommandId) -> bool {
    all.iter()
        .any(|e| matches!(&e.body, EventBody::WriteApplied { command } if command == id))
}

fn item(name: &str) -> ItemRef {
    ItemRef {
        id: format!("{CALENDAR}{name}"),
        uid: None,
    }
}

async fn put(storage: &Storage, bytes: &str, target: Option<ItemRef>, notify: bool) -> CommandId {
    let blob = storage
        .blobs
        .put(&tenant(), Bytes::from(bytes.to_owned()))
        .await
        .unwrap();
    submit(
        storage,
        CommandBody::PutObject {
            collection: CALENDAR.into(),
            item: target,
            blob,
            if_version: None,
            notify,
        },
    )
    .await
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn calendar_of(mail: &[u8]) -> String {
    let found = skein_itip::imip::find(mail).expect("an iMIP message");
    text(&found.calendar)
}

#[tokio::test]
async fn an_organizer_put_mails_requests_and_cancels_where_the_server_does_not() {
    let sender = FakeSender::new();
    let (engine, storage) = build(Some(sender.clone()));
    let pim = FakePim::standard();
    pim.set_addresses(&["ada@example.com"]);
    let id = put(&storage, MEETING, None, true).await;
    engine.run_pim_commands(&config(), &pim).await.unwrap();
    let all = events(&storage).await;
    assert!(applied(&all, &id));
    let Some(EventBody::ScheduleResult { via, messages, .. }) = result_of(&all, &id) else {
        panic!("a schedule result");
    };
    assert_eq!(via, ScheduleVia::Mail);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].method, "REQUEST");
    assert_eq!(messages[0].status, ScheduleStatus::Sent);
    assert_eq!(messages[0].to, vec!["bob@example.org", "carol@example.org"]);
    let sent = sender.deliveries();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].mail_from, "ada@example.com");
    let ics = calendar_of(&sent[0].bytes);
    assert!(ics.contains("METHOD:REQUEST"));
    assert_eq!(pim.notifies(), vec![false]);

    let created = item(&skein_pim::testing::name_for_key(
        id.as_str(),
        skein_core::CollectionKind::Calendar,
    ));
    let without_carol = MEETING
        .replace(
            "ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:carol@example.org\r\n",
            "",
        )
        .replace("SEQUENCE:0", "SEQUENCE:1");
    let id = put(&storage, &without_carol, Some(created.clone()), true).await;
    engine.run_pim_commands(&config(), &pim).await.unwrap();
    let Some(EventBody::ScheduleResult { messages, .. }) = result_of(&events(&storage).await, &id)
    else {
        panic!("a schedule result");
    };
    let methods: Vec<(&str, &[String])> = messages
        .iter()
        .map(|m| (m.method.as_str(), &m.to[..]))
        .collect();
    assert_eq!(
        methods,
        vec![
            ("REQUEST", &["bob@example.org".to_owned()][..]),
            ("CANCEL", &["carol@example.org".to_owned()][..])
        ]
    );
    let cancel = calendar_of(&sender.deliveries()[2].bytes);
    assert!(cancel.contains("SEQUENCE:1"));
    assert!(cancel.contains("mailto:carol@example.org"));
    assert!(!cancel.contains("bob@"));

    let id = submit(
        &storage,
        CommandBody::DeleteObject {
            collection: CALENDAR.into(),
            item: created,
            if_version: None,
            notify: true,
        },
    )
    .await;
    engine.run_pim_commands(&config(), &pim).await.unwrap();
    let Some(EventBody::ScheduleResult { messages, .. }) = result_of(&events(&storage).await, &id)
    else {
        panic!("a schedule result");
    };
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].method, "CANCEL");
    assert_eq!(messages[0].to, vec!["bob@example.org"]);
    let cancel = calendar_of(&sender.deliveries()[3].bytes);
    assert!(cancel.contains("SEQUENCE:2"));
    assert!(cancel.contains("STATUS:CANCELLED"));
}

#[tokio::test]
async fn a_scheduling_server_is_asked_to_notify_and_nothing_is_mailed() {
    let sender = FakeSender::new();
    let (engine, storage) = build(Some(sender.clone()));
    let pim = FakePim::standard();
    pim.set_server_schedules(true);
    let loud = put(&storage, MEETING, None, true).await;
    let quiet = put(&storage, &MEETING.replace("meet-1", "meet-2"), None, false).await;
    engine.run_pim_commands(&config(), &pim).await.unwrap();
    let all = events(&storage).await;
    assert!(matches!(
        result_of(&all, &loud),
        Some(EventBody::ScheduleResult {
            via: ScheduleVia::Server,
            ..
        })
    ));
    assert_eq!(result_of(&all, &quiet), None);
    let mut notifies = pim.notifies();
    notifies.sort();
    assert_eq!(notifies, vec![false, true]);
    assert!(sender.deliveries().is_empty());
}

#[tokio::test]
async fn nothing_is_mailed_for_events_the_account_does_not_organize() {
    let sender = FakeSender::new();
    let (engine, storage) = build(Some(sender.clone()));
    let pim = FakePim::standard();
    pim.set_addresses(&["dave@example.net"]);
    let id = put(&storage, MEETING, None, true).await;
    let plain = put(
        &storage,
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:solo@example.com\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
        None,
        true,
    )
    .await;
    engine.run_pim_commands(&config(), &pim).await.unwrap();
    let all = events(&storage).await;
    assert_eq!(
        result_of(&all, &id),
        Some(EventBody::ScheduleResult {
            command: id.clone(),
            via: ScheduleVia::None,
            messages: Vec::new(),
            reason: Some("not_organizer".into())
        })
    );
    assert!(matches!(
        result_of(&all, &plain),
        Some(EventBody::ScheduleResult { via: ScheduleVia::None, reason: Some(r), .. }) if r == "not_a_scheduling_object"
    ));
    assert!(sender.deliveries().is_empty());
}

#[tokio::test]
async fn answering_an_invitation_in_a_calendar_mails_a_reply() {
    let sender = FakeSender::new();
    let (engine, storage) = build(Some(sender.clone()));
    let pim = FakePim::standard();
    pim.set_addresses(&["Ada@Example.com"]);
    pim.put(CALENDAR, "visit.ics", INVITED.as_bytes()).await;
    let id = submit(
        &storage,
        CommandBody::RespondObject {
            collection: CALENDAR.into(),
            item: item("visit.ics"),
            answer: PartStat::Declined,
            attendee: None,
            comment: Some("Away that week".into()),
            if_version: None,
            notify: true,
        },
    )
    .await;
    engine.run_pim_commands(&config(), &pim).await.unwrap();
    let all = events(&storage).await;
    assert!(applied(&all, &id));
    assert!(
        all.iter()
            .any(|e| matches!(&e.body, EventBody::ObjectUpserted { .. })
                && e.origin.as_ref() == Some(&id))
    );
    let Some(EventBody::ScheduleResult { via, messages, .. }) = result_of(&all, &id) else {
        panic!("a schedule result");
    };
    assert_eq!(via, ScheduleVia::Mail);
    assert_eq!(messages[0].method, "REPLY");
    assert_eq!(messages[0].to, vec!["bob@example.org"]);
    let sent = sender.deliveries();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].mail_from, "ada@example.com");
    let reply = calendar_of(&sent[0].bytes);
    assert!(reply.contains("METHOD:REPLY"));
    assert!(reply.contains("PARTSTAT=DECLINED"));
    assert!(reply.contains("COMMENT:Away that week"));
    assert!(reply.contains("SEQUENCE:3"));
    let (_, held) = pim.read(CALENDAR, &item("visit.ics")).await.unwrap();
    assert!(text(&held).contains("PARTSTAT=DECLINED:mailto:ada@example.com"));
}

#[tokio::test]
async fn a_quiet_answer_and_a_missing_sender_mail_nothing() {
    let (engine, storage) = build(None);
    let pim = FakePim::standard();
    pim.set_addresses(&["ada@example.com"]);
    pim.put(CALENDAR, "visit.ics", INVITED.as_bytes()).await;
    let respond = |notify| CommandBody::RespondObject {
        collection: CALENDAR.into(),
        item: item("visit.ics"),
        answer: PartStat::Accepted,
        attendee: None,
        comment: None,
        if_version: None,
        notify,
    };
    let quiet = submit(&storage, respond(false)).await;
    let loud = submit(&storage, respond(true)).await;
    engine.run_pim_commands(&config(), &pim).await.unwrap();
    let all = events(&storage).await;
    assert!(applied(&all, &quiet) && applied(&all, &loud));
    assert_eq!(result_of(&all, &quiet), None);
    assert!(matches!(
        result_of(&all, &loud),
        Some(EventBody::ScheduleResult { via: ScheduleVia::None, reason: Some(r), .. }) if r == "no_sender"
    ));
}

#[tokio::test]
async fn a_crash_while_mailing_is_reported_and_never_repeated() {
    let sender = FakeSender::new();
    let (engine, storage) = build(Some(sender.clone()));
    let pim = FakePim::standard();
    let id = put(&storage, MEETING, None, true).await;
    storage
        .control
        .put(
            &tenant(),
            &command_marker(&acc(), id.as_str()),
            Bytes::from_static(b"scheduling"),
            Expect::Absent,
        )
        .await
        .unwrap();
    engine.run_pim_commands(&config(), &pim).await.unwrap();
    let all = events(&storage).await;
    assert!(applied(&all, &id));
    assert!(matches!(
        result_of(&all, &id),
        Some(EventBody::ScheduleResult { via: ScheduleVia::Mail, reason: Some(r), .. }) if r == "interrupted"
    ));
    assert!(sender.deliveries().is_empty());
    assert!(pim.notifies().is_empty());
}

#[tokio::test]
async fn answering_an_invitation_from_mail_sends_one_reply_with_threading() {
    let sender = FakeSender::new();
    let (engine, storage) = build(Some(sender.clone()));
    let fake = FakeMail::new();
    fake.create_mailbox("INBOX").await;
    let message = include_bytes!("../../itip/tests/fixtures/invitation.eml");
    fake.add("INBOX", message, Flags::default()).await;
    engine.sync_account(&config(), &fake).await.unwrap();
    let all = events(&storage).await;
    let (received, at) = all
        .iter()
        .enumerate()
        .find_map(|(n, e)| match &e.body {
            EventBody::ItipReceived { blob, itip, .. } => Some(((*blob, itip.clone()), n)),
            _ => None,
        })
        .expect("itip_received");
    assert!(matches!(all[at - 1].body, EventBody::MessageAdded { .. }));
    assert_eq!(received.1.method, "REQUEST");
    assert_eq!(received.1.uid, "planning-7f3a@example.org");
    let part = storage
        .blobs
        .get(&tenant(), &received.0)
        .await
        .unwrap()
        .unwrap();
    assert!(text(&part).starts_with("BEGIN:VCALENDAR"));

    let whole = all
        .iter()
        .find_map(|e| match &e.body {
            EventBody::MessageAdded { blob, .. } => Some(*blob),
            _ => None,
        })
        .unwrap();
    let ambiguous = submit(
        &storage,
        CommandBody::RespondInvitation {
            invitation: whole,
            answer: PartStat::Accepted,
            attendee: None,
            comment: None,
            save_to_sent: None,
        },
    )
    .await;
    let named = submit(
        &storage,
        CommandBody::RespondInvitation {
            invitation: whole,
            answer: PartStat::Tentative,
            attendee: Some("mailto:ADA@example.com".into()),
            comment: None,
            save_to_sent: Some("INBOX".into()),
        },
    )
    .await;
    engine.run_commands(&config(), &fake).await.unwrap();
    engine.run_commands(&config(), &fake).await.unwrap();
    let all = events(&storage).await;
    assert!(all.iter().any(|e| matches!(&e.body,
        EventBody::WriteFailed { command, reason } if command == &ambiguous && reason == "attendee_required")));
    assert!(applied(&all, &named));
    let sent = sender.deliveries();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].mail_from, "ada@example.com");
    assert_eq!(sent[0].recipients, vec!["bob@example.org"]);
    let mail = text(&sent[0].bytes);
    assert!(mail.contains("In-Reply-To: <inv-1@example.org>"));
    assert!(mail.contains("Subject: Tentative: Planning, weekly"));
    let reply = calendar_of(&sent[0].bytes);
    assert!(reply.contains("PARTSTAT=TENTATIVE"));
    assert_eq!(reply.matches("BEGIN:VEVENT").count(), 2);
    let copies = all
        .iter()
        .filter(|e| matches!(&e.body, EventBody::SendResult { command, sent_copy: Some(skein_core::SentCopy::Saved), .. } if command == &named))
        .count();
    assert_eq!(copies, 1);
}
