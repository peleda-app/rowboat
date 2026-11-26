use std::sync::Arc;

use baton_signal::Signal;
use baton_signal_local::LocalSignal;
use bytes::Bytes;
use futures::StreamExt;
use proptest::prelude::*;
use serde_json::{Value, json};
use skein_core::{AccountId, BlobHash, Command, CommandBody, CommandId, TenantId, Timestamp};
use skein_storage::{Expect, Objects, Storage};
use skein_storage_memory::MemoryObjects;

use super::*;

fn t() -> TenantId {
    TenantId::new("acme").unwrap()
}

fn a() -> AccountId {
    AccountId::new("box").unwrap()
}

fn body(value: Value) -> CommandBody {
    serde_json::from_value(value).unwrap()
}

fn command(id: &CommandId, value: Value) -> Command {
    Command {
        id: id.clone(),
        account: a(),
        created_at: Timestamp(1),
        trace: None,
        body: body(value),
    }
}

fn setup() -> (Storage, Arc<LocalSignal>) {
    let objects: Arc<dyn Objects> = Arc::new(MemoryObjects::new());
    (Storage::over(objects), Arc::new(LocalSignal::new()))
}

fn code(r: Result<(), SubmitError>) -> &'static str {
    match r {
        Err(SubmitError::Invalid { code, .. }) => code,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn commands_are_idempotent_and_hint_the_worker() {
    let (storage, signal) = setup();
    let mut hints = signal
        .subscribe(&skein_core::coordination::group(&t()), "commands/box")
        .await
        .unwrap();
    let id = CommandId::generate();
    let flags = json!({"type": "set_flags", "mailbox": "INBOX", "items": [{"id": "7", "uid": 7}], "add": ["\\Seen"], "remove": []});
    let mut first = command(&id, flags.clone());
    first.trace = Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".into());
    let s = submit_command(&storage, &*signal, &t(), &first)
        .await
        .unwrap();
    assert!(!s.duplicate);
    assert_eq!(hints.next().await.unwrap(), Bytes::from(id.to_string()));

    let again = command(&id, flags.clone());
    let s = submit_command(&storage, &*signal, &t(), &again)
        .await
        .unwrap();
    assert!(
        s.duplicate,
        "a different trace does not make another command"
    );
    let other = command(
        &id,
        json!({"type": "delete", "mailbox": "INBOX", "items": []}),
    );
    assert!(matches!(
        submit_command(&storage, &*signal, &t(), &other).await,
        Err(SubmitError::IdConflict)
    ));
    let pending = storage.commands.pending(&t(), &a(), 10).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].trace, first.trace);

    let missing = command(
        &CommandId::generate(),
        json!({"type": "append", "mailbox": "INBOX", "blob": BlobHash::of(b"missing").to_hex(), "flags": []}),
    );
    assert!(matches!(
        submit_command(&storage, &*signal, &t(), &missing).await,
        Err(SubmitError::BlobMissing)
    ));
    let unknown = command(&CommandId::generate(), json!({"type": "teleport"}));
    assert_eq!(unknown.body, CommandBody::Unknown);
    assert!(matches!(
        submit_command(&storage, &*signal, &t(), &unknown).await,
        Err(SubmitError::Invalid {
            code: "unknown_command",
            ..
        })
    ));
}

#[tokio::test]
async fn send_commands_need_their_blob_and_a_clean_envelope() {
    let (storage, signal) = setup();
    let message = b"From: pat@example.com\r\nTo: sam@example.org\r\n\r\nHi.\r\n".to_vec();
    let hash = BlobHash::of(&message).to_hex();
    let send = |from: &str| {
        command(
            &CommandId::generate(),
            json!({"type": "send", "blob": hash, "envelope": {"from": from, "to": ["sam@example.org"]}}),
        )
    };
    assert!(matches!(
        submit_command(&storage, &*signal, &t(), &send("pat@example.com")).await,
        Err(SubmitError::BlobMissing)
    ));
    storage.blobs.put(&t(), Bytes::from(message)).await.unwrap();
    let r = submit_command(
        &storage,
        &*signal,
        &t(),
        &send("pat@example.com\r\nBcc: x@example.org"),
    )
    .await;
    let text = format!("{r:?}");
    assert_eq!(code(r.map(|_| ())), "invalid_envelope");
    assert!(!text.contains("x@example.org"));
    submit_command(&storage, &*signal, &t(), &send("pat@example.com"))
        .await
        .unwrap();
}

#[tokio::test]
async fn scheduling_commands_are_checked_before_they_queue() {
    let (storage, signal) = setup();
    let invite = b"BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nEND:VCALENDAR\r\n".to_vec();
    let hash = BlobHash::of(&invite).to_hex();
    let invitation = command(
        &CommandId::generate(),
        json!({"type": "respond_invitation", "invitation": hash, "answer": "accepted"}),
    );
    assert!(matches!(
        submit_command(&storage, &*signal, &t(), &invitation).await,
        Err(SubmitError::BlobMissing)
    ));
    storage.blobs.put(&t(), Bytes::from(invite)).await.unwrap();
    submit_command(&storage, &*signal, &t(), &invitation)
        .await
        .unwrap();
    let respond = |extra: Value| {
        let mut b = json!({"type": "respond_object", "collection": "/c/", "item": {"id": "/c/e.ics"}, "answer": "declined"});
        b.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        body(b)
    };
    let r = check_command(&respond(
        json!({"attendee": "ada@example.com\r\nBcc: x@example.org"}),
    ));
    assert!(!format!("{r:?}").contains("x@example.org"));
    assert_eq!(code(r), "invalid_attendee");
    assert_eq!(
        code(check_command(&respond(
            json!({"comment": "x".repeat(5000)})
        ))),
        "comment_too_long"
    );
    check_command(&respond(
        json!({"attendee": "mailto:Ada@example.com", "comment": "Sorry"}),
    ))
    .unwrap();
}

#[test]
fn mailbox_commands_need_clean_paths_and_labels() {
    for (b, expected) in [
        (
            json!({"type": "create_mailbox", "path": ""}),
            "invalid_path",
        ),
        (
            json!({"type": "create_mailbox", "path": "a//b"}),
            "invalid_path",
        ),
        (
            json!({"type": "create_mailbox", "path": "/a"}),
            "invalid_path",
        ),
        (
            json!({"type": "rename_mailbox", "mailbox": "x", "path": "a\nb"}),
            "invalid_path",
        ),
        (
            json!({"type": "set_labels", "mailbox": "INBOX", "items": []}),
            "invalid_labels",
        ),
        (
            json!({"type": "set_labels", "mailbox": "INBOX", "items": [], "add": [""]}),
            "invalid_labels",
        ),
    ] {
        assert_eq!(code(check_command(&body(b.clone()))), expected, "{b}");
    }
    for b in [
        json!({"type": "create_mailbox", "path": "Projects/2026"}),
        json!({"type": "set_labels", "mailbox": "INBOX", "items": [{"id": "1:1"}], "add": ["Work"]}),
        json!({"type": "copy", "from": "INBOX", "to": "Archive", "items": [{"id": "1:1"}]}),
        json!({"type": "delete", "mailbox": "INBOX", "items": [{"id": "1:1"}], "to_trash": true}),
        json!({"type": "delete", "mailbox": "INBOX/Ünïcode", "items": [{"id": "1"}]}),
    ] {
        check_command(&body(b.clone())).unwrap_or_else(|e| panic!("{b}: {e}"));
    }
}

#[test]
fn oversized_or_unprintable_command_fields_are_refused() {
    let items: Vec<Value> = (0..MAX_ITEMS + 1)
        .map(|i| json!({"id": i.to_string()}))
        .collect();
    for (b, expected) in [
        (
            json!({"type": "delete", "mailbox": "INBOX\r\nA1 LOGOUT", "items": []}),
            "invalid_id",
        ),
        (
            json!({"type": "delete", "mailbox": "x".repeat(1025), "items": []}),
            "invalid_id",
        ),
        (
            json!({"type": "move", "from": "INBOX", "to": "Archive", "items": [{"id": "1\n2"}]}),
            "invalid_id",
        ),
        (
            json!({"type": "delete_object", "collection": "c", "item": {"id": "e"}, "if_version": "v\u{0}"}),
            "invalid_id",
        ),
        (
            json!({"type": "delete", "mailbox": "INBOX", "items": items}),
            "too_many_items",
        ),
        (
            json!({"type": "set_flags", "mailbox": "INBOX", "items": [], "add": ["a\r\nb"], "remove": []}),
            "invalid_flags",
        ),
        (
            json!({"type": "set_flags", "mailbox": "INBOX", "items": [], "add": (0..101).map(|i| format!("k{i}")).collect::<Vec<_>>(), "remove": []}),
            "invalid_flags",
        ),
        (
            json!({"type": "set_labels", "mailbox": "INBOX", "items": [], "add": (0..101).map(|i| format!("l{i}")).collect::<Vec<_>>()}),
            "invalid_labels",
        ),
    ] {
        assert_eq!(code(check_command(&body(b))), expected);
    }
}

#[tokio::test]
async fn queued_commands_can_be_cancelled_until_they_start() {
    let (storage, signal) = setup();
    let flags = json!({"type": "set_flags", "mailbox": "INBOX", "items": [], "add": ["\\Seen"], "remove": []});
    let id = CommandId::generate();
    submit_command(&storage, &*signal, &t(), &command(&id, flags.clone()))
        .await
        .unwrap();
    cancel_command(&storage, &t(), &a(), &id).await.unwrap();
    cancel_command(&storage, &t(), &a(), &id)
        .await
        .expect("cancelling again succeeds");
    assert!(
        storage
            .commands
            .pending(&t(), &a(), 10)
            .await
            .unwrap()
            .is_empty()
    );

    let started = CommandId::generate();
    submit_command(&storage, &*signal, &t(), &command(&started, flags))
        .await
        .unwrap();
    storage
        .control
        .put(
            &t(),
            &format!("started/box/{started}"),
            Bytes::from_static(b"started"),
            Expect::Any,
        )
        .await
        .unwrap();
    assert!(matches!(
        cancel_command(&storage, &t(), &a(), &started).await,
        Err(SubmitError::AlreadyStarted)
    ));
    assert_eq!(
        storage
            .commands
            .pending(&t(), &a(), 10)
            .await
            .unwrap()
            .len(),
        1
    );
    let never = CommandId::new("01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap();
    assert!(matches!(
        cancel_command(&storage, &t(), &a(), &never).await,
        Err(SubmitError::NotQueued)
    ));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn mailbox_paths_are_accepted_only_when_clean(path in "(\\PC|[\\r\\n\\t/ ]){0,40}") {
        let r = check_command(&CommandBody::CreateMailbox { path: path.clone() });
        let clean = !path.is_empty()
            && !path.chars().any(char::is_control)
            && path.split('/').all(|l| !l.trim().is_empty());
        prop_assert_eq!(r.is_ok(), clean);
    }

    #[test]
    fn labels_are_accepted_only_when_clean(labels in proptest::collection::vec("(\\PC|[\\r\\n/]){0,12}", 0..4)) {
        let r = check_command(&body(json!({"type": "set_labels", "mailbox": "INBOX", "items": [{"id": "1"}], "add": labels})));
        let clean = !labels.is_empty() && labels.iter().all(|l| {
            !l.is_empty() && !l.chars().any(char::is_control) && l.split('/').all(|p| !p.trim().is_empty())
        });
        prop_assert_eq!(r.is_ok(), clean);
    }

    #[test]
    fn arbitrary_json_commands_never_panic(text in "\\PC{0,400}") {
        if let Ok(b) = serde_json::from_str::<CommandBody>(&text) {
            let _ = check_command(&b);
        }
    }
}

#[test]
fn the_wake_topic_is_the_one_workers_subscribe_to() {
    let account = AccountId::new("box").unwrap();
    assert_eq!(crate::wake_topic(&account), "commands/box");
}
