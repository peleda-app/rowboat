use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use skein_core::{BlobHash, CommandBody, Credentials, Flags, ItemRef, MailboxRole};
use skein_mail::testing::{conformance, write_conformance};
use skein_mail::{Cursor, MailChange, MailError, MailProvider, MailSession, WriteOutcome};

use crate::fake::{FakeGmail, TOKEN};
use crate::*;

fn settings(fake: &FakeGmail) -> GmailSettings {
    GmailSettings {
        api_url: fake.url.clone(),
        user: "me".into(),
    }
}

fn token(t: &str) -> Credentials {
    Credentials::AccessToken { token: t.into() }
}

fn provider(fake: &FakeGmail) -> GmailProvider {
    GmailProvider::new(settings(fake), token(TOKEN))
        .unwrap()
        .with_quota(1_000_000)
        .with_timeout(Duration::from_secs(10))
}

fn msg(n: u32) -> Vec<u8> {
    format!("From: ada@example.com\r\nTo: bob@example.org\r\nSubject: Gmail {n}\r\nMessage-ID: <g{n}@example.com>\r\n\r\nBody {n}\r\n").into_bytes()
}

fn item(id: &str) -> ItemRef {
    ItemRef {
        id: id.into(),
        uid: None,
    }
}

async fn drain(
    s: &mut Box<dyn MailSession>,
    mailbox: &str,
    cursor: Option<Cursor>,
    limit: usize,
) -> (Cursor, Vec<MailChange>) {
    let mut cursor = cursor;
    let mut all = Vec::new();
    loop {
        let batch = s.changes(mailbox, cursor.as_ref(), limit).await.unwrap();
        all.extend(batch.changes);
        cursor = Some(batch.cursor);
        if !batch.more {
            return (cursor.unwrap(), all);
        }
    }
}

fn added_ids(changes: &[MailChange]) -> Vec<String> {
    changes
        .iter()
        .filter_map(|c| match c {
            MailChange::Added { item, .. } => Some(item.id.clone()),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn keeps_the_contract_in_all() {
    let fake = FakeGmail::start().await;
    conformance(Arc::new(provider(&fake)), Arc::new(fake), ALL).await;
}

#[tokio::test]
async fn keeps_the_contract_in_inbox() {
    let fake = FakeGmail::start().await;
    conformance(Arc::new(provider(&fake)), Arc::new(fake), "INBOX").await;
}

#[tokio::test]
async fn keeps_the_contract_in_a_user_label() {
    let fake = FakeGmail::start().await;
    let id = fake.add_label("Projects/2025");
    conformance(Arc::new(provider(&fake)), Arc::new(fake), &id).await;
}

#[tokio::test]
async fn keeps_the_write_contract() {
    let fake = FakeGmail::start().await;
    let archive = fake.add_label("Archive");
    fake.add_label("Projects/2026");
    write_conformance(
        Arc::new(provider(&fake)),
        Arc::new(fake),
        "INBOX",
        &archive,
        Some("Projects/2026"),
    )
    .await;
}

#[tokio::test]
async fn maps_labels_to_mailboxes() {
    let fake = FakeGmail::start().await;
    let receipts = fake.add_label("Receipts");
    let mut s = provider(&fake).connect().await.unwrap();
    let boxes = s.mailboxes().await.unwrap();
    let find = |id: &str| boxes.iter().find(|b| b.id == id).cloned();
    let all = find(ALL).unwrap();
    assert_eq!((all.role, all.label), (Some(MailboxRole::All), false));
    let trash = find("TRASH").unwrap();
    assert_eq!((trash.role, trash.label), (Some(MailboxRole::Trash), false));
    let spam = find("SPAM").unwrap();
    assert_eq!((spam.role, spam.label), (Some(MailboxRole::Junk), false));
    assert_eq!(find("INBOX").unwrap().role, Some(MailboxRole::Inbox));
    assert_eq!(find("SENT").unwrap().role, Some(MailboxRole::Sent));
    assert_eq!(find("DRAFT").unwrap().role, Some(MailboxRole::Drafts));
    assert!(find("IMPORTANT").unwrap().label);
    let user = find(&receipts).unwrap();
    assert_eq!((user.path.as_str(), user.label), ("Receipts", true));
    for skipped in ["UNREAD", "STARRED", "CHAT", "CATEGORY_PERSONAL"] {
        assert!(find(skipped).is_none(), "{skipped} is not a mailbox");
    }
    assert!(matches!(
        s.changes("Label_404", None, 10).await,
        Err(MailError::MailboxNotFound)
    ));
}

#[tokio::test]
async fn labels_carry_names() {
    let fake = FakeGmail::start().await;
    let receipts = fake.add_label("Receipts");
    fake.insert(&msg(1), &["INBOX", "IMPORTANT", "UNREAD", &receipts]);
    let mut s = provider(&fake).connect().await.unwrap();
    let (_, changes) = drain(&mut s, ALL, None, 10).await;
    let MailChange::Added {
        labels,
        flags,
        received_at,
        item,
    } = &changes[0]
    else {
        panic!("{changes:?}");
    };
    assert_eq!(
        labels.as_deref().unwrap(),
        ["Important", "Inbox", "Receipts"]
    );
    assert!(flags.is_empty());
    assert!(received_at.is_some());
    assert_eq!(item.uid, None);
}

#[tokio::test]
async fn trash_leaves_all_and_untrash_brings_it_back() {
    let fake = FakeGmail::start().await;
    let id = fake.insert(&msg(1), &["INBOX"]);
    let p = provider(&fake);
    let mut s = p.connect().await.unwrap();
    let (all, _) = drain(&mut s, ALL, None, 10).await;
    let (trash, changes) = drain(&mut s, "TRASH", None, 10).await;
    assert!(changes.is_empty());

    let moved = s
        .apply(
            &CommandBody::Move {
                from: ALL.into(),
                to: "TRASH".into(),
                items: vec![item(&id)],
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(moved, WriteOutcome::Applied);
    assert!(fake.labels_of(&id).unwrap().contains("TRASH"));
    let (all, changes) = drain(&mut s, ALL, Some(all), 10).await;
    assert_eq!(changes, vec![MailChange::Removed { item: item(&id) }]);
    let (trash, changes) = drain(&mut s, "TRASH", Some(trash), 10).await;
    assert_eq!(added_ids(&changes), vec![id.clone()]);

    s.apply(
        &CommandBody::Move {
            from: "TRASH".into(),
            to: ALL.into(),
            items: vec![item(&id)],
        },
        None,
    )
    .await
    .unwrap();
    assert!(!fake.labels_of(&id).unwrap().contains("TRASH"));
    let (_, changes) = drain(&mut s, ALL, Some(all), 10).await;
    assert_eq!(added_ids(&changes), vec![id.clone()]);
    let (_, changes) = drain(&mut s, "TRASH", Some(trash), 10).await;
    assert_eq!(changes, vec![MailChange::Removed { item: item(&id) }]);
}

#[tokio::test]
async fn label_changes_and_stars_are_told_apart() {
    let fake = FakeGmail::start().await;
    let receipts = fake.add_label("Receipts");
    let id = fake.insert(&msg(1), &["INBOX", "UNREAD"]);
    let mut s = provider(&fake).connect().await.unwrap();
    let (cursor, _) = drain(&mut s, ALL, None, 10).await;

    fake.modify(&id, &[&receipts], &[]);
    let (cursor, changes) = drain(&mut s, ALL, Some(cursor), 10).await;
    assert_eq!(
        changes,
        vec![MailChange::Labels {
            item: item(&id),
            labels: vec!["Inbox".into(), "Receipts".into()],
        }]
    );

    fake.modify(&id, &["STARRED"], &["UNREAD"]);
    let (cursor, changes) = drain(&mut s, ALL, Some(cursor), 10).await;
    assert_eq!(
        changes,
        vec![MailChange::Flags {
            item: item(&id),
            flags: Flags::new(["\\Seen", "\\Flagged"]),
        }]
    );

    fake.modify(&id, &[], &["INBOX"]);
    let (_, changes) = drain(&mut s, ALL, Some(cursor), 10).await;
    assert_eq!(
        changes,
        vec![MailChange::Labels {
            item: item(&id),
            labels: vec!["Receipts".into()],
        }],
        "archiving stays in ALL"
    );
}

#[tokio::test]
async fn several_changes_of_one_message_are_reported_once() {
    let fake = FakeGmail::start().await;
    let a = fake.insert(&msg(1), &["INBOX", "UNREAD"]);
    let mut s = provider(&fake).connect().await.unwrap();
    let (cursor, _) = drain(&mut s, "INBOX", None, 10).await;
    fake.modify(&a, &[], &["UNREAD"]);
    fake.modify(&a, &["STARRED"], &[]);
    let b = fake.insert(&msg(2), &["INBOX"]);
    fake.modify(&b, &["STARRED"], &[]);
    let c = fake.insert(&msg(3), &["INBOX"]);
    fake.modify(&c, &[], &["INBOX"]);
    let (_, changes) = drain(&mut s, "INBOX", Some(cursor), 100).await;
    assert_eq!(changes.len(), 2, "{changes:?}");
    assert!(changes.contains(&MailChange::Flags {
        item: item(&a),
        flags: Flags::new(["\\Seen", "\\Flagged"]),
    }));
    let MailChange::Added { item: i, flags, .. } = &changes[1] else {
        panic!("{changes:?}");
    };
    assert_eq!(
        (i.id.as_str(), flags),
        (b.as_str(), &Flags::new(["\\Seen", "\\Flagged"]))
    );
}

#[tokio::test]
async fn expired_history_resets_and_lists_again() {
    let fake = FakeGmail::start().await;
    for n in 1..=3 {
        fake.insert(&msg(n), &["INBOX"]);
    }
    let mut s = provider(&fake).connect().await.unwrap();
    let (cursor, _) = drain(&mut s, ALL, None, 10).await;
    fake.insert(&msg(4), &["INBOX"]);
    {
        let mut st = fake.state.lock().unwrap();
        st.expired_below = st.history_id + 1;
        st.history_id += 1;
    }
    let (_, changes) = drain(&mut s, ALL, Some(cursor), 10).await;
    assert_eq!(
        changes[0],
        MailChange::Reset {
            reason: "history_expired".into()
        }
    );
    assert_eq!(added_ids(&changes).len(), 4);
}

#[tokio::test]
async fn an_unreadable_cursor_resets() {
    let fake = FakeGmail::start().await;
    fake.insert(&msg(1), &["INBOX"]);
    let mut s = provider(&fake).connect().await.unwrap();
    let garbage = Cursor(Bytes::from_static(b"\x01garbage"));
    let (_, changes) = drain(&mut s, ALL, Some(garbage), 10).await;
    assert_eq!(
        changes[0],
        MailChange::Reset {
            reason: "unreadable_cursor".into()
        }
    );
    assert_eq!(added_ids(&changes).len(), 1);
}

#[tokio::test]
async fn pages_with_small_limits() {
    let fake = FakeGmail::start().await;
    let mut ids = Vec::new();
    for n in 1..=25 {
        ids.push(fake.insert(&msg(n), &["INBOX"]));
    }
    let mut s = provider(&fake).connect().await.unwrap();
    let mut cursor = None;
    let mut seen = HashSet::new();
    let mut calls = 0;
    loop {
        let batch = s.changes(ALL, cursor.as_ref(), 4).await.unwrap();
        calls += 1;
        assert!(batch.changes.len() <= 4);
        for id in added_ids(&batch.changes) {
            assert!(seen.insert(id), "added twice");
        }
        cursor = Some(batch.cursor);
        if !batch.more {
            break;
        }
    }
    assert_eq!(seen.len(), 25);
    assert_eq!(calls, 7);

    for id in &ids[..10] {
        fake.modify(id, &["STARRED"], &[]);
    }
    let mut flagged = HashSet::new();
    loop {
        let batch = s.changes(ALL, cursor.as_ref(), 3).await.unwrap();
        assert!(batch.changes.len() <= 3);
        for c in batch.changes {
            let MailChange::Flags { item, .. } = c else {
                panic!("{c:?}");
            };
            assert!(flagged.insert(item.id));
        }
        cursor = Some(batch.cursor);
        if !batch.more {
            break;
        }
    }
    assert_eq!(flagged.len(), 10);
}

#[tokio::test]
async fn an_expired_listing_page_token_restarts_without_repeats() {
    let fake = FakeGmail::start().await;
    for n in 1..=6 {
        fake.insert(&msg(n), &["INBOX"]);
    }
    let mut s = provider(&fake).connect().await.unwrap();
    let first = s.changes(ALL, None, 3).await.unwrap();
    assert!(first.more);
    let mut state = cursor::CursorState::decode(&first.cursor.0).unwrap();
    state.phase = cursor::Phase::Listing {
        token: Some("expired".into()),
    };
    let forged = Cursor(Bytes::from(state.encode()));
    let (_, rest) = drain(&mut s, ALL, Some(forged), 3).await;
    let mut all = added_ids(&first.changes);
    all.extend(added_ids(&rest));
    let unique: HashSet<_> = all.iter().collect();
    assert_eq!((all.len(), unique.len()), (6, 6));
}

#[tokio::test]
async fn throttling_carries_retry_after() {
    let fake = FakeGmail::start().await;
    let mut s = provider(&fake).connect().await.unwrap();
    fake.state.lock().unwrap().throttle = Some((429, None, Some(7)));
    assert!(matches!(
        s.changes(ALL, None, 10).await,
        Err(MailError::Throttled {
            retry_after: Some(d)
        }) if d == Duration::from_secs(7)
    ));
    fake.state.lock().unwrap().throttle = Some((403, Some("userRateLimitExceeded"), None));
    assert!(matches!(
        s.changes(ALL, None, 10).await,
        Err(MailError::Throttled { retry_after: None })
    ));
    fake.state.lock().unwrap().throttle = Some((403, Some("rateLimitExceeded"), Some(2)));
    assert!(matches!(
        s.apply(
            &CommandBody::SetFlags {
                mailbox: ALL.into(),
                items: vec![item("abc")],
                add: Flags::new(["\\Seen"]),
                remove: Flags::default(),
            },
            None
        )
        .await,
        Err(MailError::Throttled { .. })
    ));
    fake.state.lock().unwrap().fail_status = Some(503);
    let err = s.changes(ALL, None, 10).await.unwrap_err();
    assert!(matches!(err, MailError::Network(_)));
    assert!(!err.to_string().contains("example.com"));
}

#[tokio::test]
async fn the_token_never_goes_to_another_origin() {
    let fake = FakeGmail::start().await;
    let other = FakeGmail::start().await;
    fake.state.lock().unwrap().redirect = Some(format!("{}/gmail/v1/users/me/profile", other.url));
    let err = provider(&fake).connect().await.err().unwrap();
    assert!(matches!(err, MailError::Protocol(_)), "{err:?}");
    assert!(other.requests().is_empty(), "the redirect is not followed");

    let mut s = provider(&fake).connect().await.unwrap();
    s.mailboxes().await.unwrap();
    fake.state.lock().unwrap().redirect = Some(format!("{}/x", other.url));
    assert!(s.changes(ALL, None, 10).await.is_err());
    assert!(other.requests().is_empty());
    assert!(fake.state.lock().unwrap().authorized.iter().all(|a| *a));

    for bad in [
        "http://gmail.example.com",
        "ftp://127.0.0.1",
        "not a url",
        "https://u:p@gmail.example.com",
    ] {
        let s = GmailSettings {
            api_url: bad.into(),
            user: "me".into(),
        };
        assert!(matches!(
            GmailProvider::new(s, token(TOKEN)),
            Err(MailError::Config(_))
        ));
    }
}

#[tokio::test]
async fn caps_message_size() {
    assert_eq!(MAX_MESSAGE, 64 * 1024 * 1024);
    let fake = FakeGmail::start().await;
    let mut small = msg(1);
    small.resize(1000, b'x');
    let mut big = msg(2);
    big.resize(5000, b'x');
    let a = fake.insert(&small, &["INBOX"]);
    let b = fake.insert(&big, &["INBOX"]);
    let p = provider(&fake).with_max_message(2000);
    let mut s = p.connect().await.unwrap();
    let got = s.fetch(ALL, &[item(&a)]).await.unwrap();
    assert_eq!(got[0].bytes.as_ref(), small.as_slice());
    assert!(matches!(
        s.fetch(ALL, &[item(&b)]).await,
        Err(MailError::Protocol(_))
    ));
}

#[tokio::test]
async fn fetch_returns_exact_bytes_and_leaves_out_missing() {
    let fake = FakeGmail::start().await;
    let raw: Vec<u8> = (0..=255u8).cycle().take(3001).collect();
    let id = fake.insert(&raw, &["INBOX"]);
    let mut s = provider(&fake).connect().await.unwrap();
    let got = s
        .fetch(
            ALL,
            &[
                item("ffffffffffffffff"),
                item(&id),
                item("../profile"),
                item(""),
            ],
        )
        .await
        .unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].bytes.as_ref(), raw.as_slice());
    assert!(
        fake.requests()
            .iter()
            .all(|r| !r.contains("profile?") && !r.contains("..")),
        "implausible ids are not requested"
    );
}

#[tokio::test]
async fn a_refused_token_is_auth() {
    let fake = FakeGmail::start().await;
    let p = GmailProvider::new(settings(&fake), token("wrong")).unwrap();
    assert!(matches!(p.connect().await, Err(MailError::Auth)));
}

#[tokio::test]
async fn passwords_are_refused() {
    let err = GmailProvider::new(
        GmailSettings::default(),
        Credentials::Password {
            secret: "hunter2".into(),
        },
    )
    .unwrap_err();
    assert!(matches!(err, MailError::Config(_)));
    assert!(matches!(
        GmailProvider::new(GmailSettings::default(), token(" ")),
        Err(MailError::Config(_))
    ));
}

#[test]
fn debug_hides_the_token_and_user() {
    let settings = GmailSettings {
        api_url: "https://gmail.googleapis.com".into(),
        user: "ada@example.com".into(),
    };
    let p = GmailProvider::new(settings, token("ya29.secret-value")).unwrap();
    let shown = format!("{p:?}");
    assert!(!shown.contains("ya29"), "{shown}");
    assert!(!shown.contains("ada@example.com"), "{shown}");
    assert!(shown.contains("gmail.googleapis.com"));
}

#[test]
fn settings_default_and_parse() {
    let s = GmailSettings::from_json(&serde_json::json!({})).unwrap();
    assert_eq!(s, GmailSettings::default());
    assert_eq!(s.api_url, "https://gmail.googleapis.com");
    assert_eq!(s.user, "me");
    assert!(GmailSettings::from_json(&serde_json::json!({ "user": 5 })).is_err());
}

#[tokio::test]
async fn watch_is_not_offered_yet() {
    let fake = FakeGmail::start().await;
    assert!(
        provider(&fake)
            .watch(&[ALL.into()])
            .await
            .unwrap()
            .is_none()
    );
}

fn set_flags(mailbox: &str, id: &str, add: &[&str], remove: &[&str]) -> CommandBody {
    CommandBody::SetFlags {
        mailbox: mailbox.into(),
        items: vec![item(id)],
        add: Flags::new(add.iter().copied()),
        remove: Flags::new(remove.iter().copied()),
    }
}

#[tokio::test]
async fn applies_flag_changes() {
    let fake = FakeGmail::start().await;
    let id = fake.insert(&msg(1), &["INBOX", "UNREAD"]);
    let mut s = provider(&fake).connect().await.unwrap();
    let r = s
        .apply(&set_flags(ALL, &id, &["\\Seen", "\\Flagged"], &[]), None)
        .await
        .unwrap();
    assert_eq!(r, WriteOutcome::Applied);
    let labels = fake.labels_of(&id).unwrap();
    assert!(labels.contains("STARRED") && !labels.contains("UNREAD"));
    s.apply(&set_flags(ALL, &id, &[], &["\\Seen", "\\Flagged"]), None)
        .await
        .unwrap();
    let labels = fake.labels_of(&id).unwrap();
    assert!(!labels.contains("STARRED") && labels.contains("UNREAD"));
    assert_eq!(
        s.apply(&set_flags(ALL, &id, &["$Important"], &[]), None)
            .await
            .unwrap(),
        WriteOutcome::Failed {
            reason: "unsupported_flag".into()
        }
    );
    assert_eq!(
        s.apply(&set_flags(ALL, "not:an:id", &["\\Seen"], &[]), None)
            .await
            .unwrap(),
        WriteOutcome::Applied
    );
}

#[tokio::test]
async fn applies_moves() {
    let fake = FakeGmail::start().await;
    let receipts = fake.add_label("Receipts");
    let id = fake.insert(&msg(1), &["INBOX"]);
    let mut s = provider(&fake).connect().await.unwrap();
    let mv = |from: &str, to: &str| CommandBody::Move {
        from: from.into(),
        to: to.into(),
        items: vec![item(&id)],
    };
    s.apply(&mv("INBOX", &receipts), None).await.unwrap();
    assert_eq!(
        fake.labels_of(&id).unwrap().into_iter().collect::<Vec<_>>(),
        vec![receipts.clone()]
    );
    s.apply(&mv(ALL, "INBOX"), None).await.unwrap();
    s.apply(&mv(&receipts, "SPAM"), None).await.unwrap();
    assert_eq!(
        fake.labels_of(&id).unwrap().into_iter().collect::<Vec<_>>(),
        vec!["SPAM".to_owned()]
    );
    s.apply(&mv("SPAM", "INBOX"), None).await.unwrap();
    assert_eq!(
        fake.labels_of(&id).unwrap().into_iter().collect::<Vec<_>>(),
        vec!["INBOX".to_owned()]
    );
    assert_eq!(
        s.apply(&mv("INBOX", "Label_404"), None).await.unwrap(),
        WriteOutcome::Failed {
            reason: "no_such_mailbox".into()
        }
    );
    assert!(matches!(
        s.apply(&mv("Label_404", "INBOX"), None).await,
        Err(MailError::MailboxNotFound)
    ));
}

#[tokio::test]
async fn applies_deletes() {
    let fake = FakeGmail::start().await;
    let receipts = fake.add_label("Receipts");
    let id = fake.insert(&msg(1), &["INBOX", &receipts]);
    let mut s = provider(&fake).connect().await.unwrap();
    let delete = |mailbox: &str| CommandBody::Delete {
        mailbox: mailbox.into(),
        items: vec![item(&id)],
        to_trash: false,
    };
    s.apply(&delete(&receipts), None).await.unwrap();
    assert_eq!(
        fake.labels_of(&id).unwrap().into_iter().collect::<Vec<_>>(),
        vec!["INBOX".to_owned()],
        "deleting from a label removes the label"
    );
    fake.state.lock().unwrap().full_scope = false;
    assert_eq!(
        s.apply(&delete(ALL), None).await.unwrap(),
        WriteOutcome::Failed {
            reason: "insufficient_scope".into()
        }
    );
    assert!(fake.labels_of(&id).is_some());
    fake.state.lock().unwrap().full_scope = true;
    assert_eq!(
        s.apply(&delete(ALL), None).await.unwrap(),
        WriteOutcome::Applied
    );
    assert!(fake.labels_of(&id).is_none());
    assert_eq!(
        s.apply(&delete(ALL), None).await.unwrap(),
        WriteOutcome::Applied,
        "deleting again is harmless"
    );
}

#[tokio::test]
async fn applies_appends() {
    let fake = FakeGmail::start().await;
    let mut s = provider(&fake).connect().await.unwrap();
    let (cursor, _) = drain(&mut s, ALL, None, 10).await;
    let raw = Bytes::from(msg(9));
    let append = |mailbox: &str, flags: Flags| CommandBody::Append {
        mailbox: mailbox.into(),
        blob: BlobHash::of(&raw),
        flags,
        received_at: None,
    };
    assert_eq!(
        s.apply(&append("INBOX", Flags::default()), Some(raw.clone()))
            .await
            .unwrap(),
        WriteOutcome::Applied
    );
    assert_eq!(
        s.apply(
            &append(ALL, Flags::new(["\\Seen", "\\Flagged"])),
            Some(raw.clone())
        )
        .await
        .unwrap(),
        WriteOutcome::Applied
    );
    let (_, changes) = drain(&mut s, ALL, Some(cursor), 10).await;
    let ids = added_ids(&changes);
    assert_eq!(ids.len(), 2);
    let first: Vec<String> = fake.labels_of(&ids[0]).unwrap().into_iter().collect();
    assert_eq!(first, vec!["INBOX", "UNREAD"]);
    let second: Vec<String> = fake.labels_of(&ids[1]).unwrap().into_iter().collect();
    assert_eq!(second, vec!["STARRED"]);
    let got = s.fetch(ALL, &[item(&ids[0])]).await.unwrap();
    assert_eq!(got[0].bytes, raw);
    assert!(fake.requests().iter().any(|r| r.contains(
        "/upload/gmail/v1/users/me/messages?uploadType=multipart&internalDateSource=dateHeader"
    )));
    assert_eq!(
        s.apply(&append("INBOX", Flags::default()), None)
            .await
            .unwrap(),
        WriteOutcome::Failed {
            reason: "missing_content".into()
        }
    );
    fake.state.lock().unwrap().fail_status = Some(500);
    assert_eq!(
        s.apply(&append("INBOX", Flags::default()), Some(raw.clone()))
            .await
            .unwrap(),
        WriteOutcome::Uncertain,
        "a failed insert may still have landed"
    );
}

#[tokio::test]
async fn a_lost_answer_is_uncertain() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let silent = format!("http://{}", listener.local_addr().unwrap());
    let p = GmailProvider::new(
        GmailSettings {
            api_url: silent,
            user: "me".into(),
        },
        token(TOKEN),
    )
    .unwrap()
    .with_timeout(Duration::from_millis(300));
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock);
        }
    });
    let http = p.http().unwrap();
    let mut session = GmailSession {
        http,
        labels: Some(Default::default()),
        max_message: MAX_MESSAGE,
    };
    let raw = Bytes::from(msg(1));
    let outcome = session
        .apply(
            &CommandBody::Append {
                mailbox: ALL.into(),
                blob: BlobHash::of(&raw),
                flags: Flags::default(),
                received_at: None,
            },
            Some(raw),
        )
        .await
        .unwrap();
    assert_eq!(outcome, WriteOutcome::Uncertain);
}

fn target(topic: Option<&str>) -> skein_mail::PushTarget {
    skein_mail::PushTarget {
        url: "https://skein.example.com/v1/push/gmail/secret".into(),
        client_state: "unused-by-gmail".into(),
        gmail_topic: topic.map(str::to_owned),
    }
}

#[tokio::test]
async fn watches_renews_and_stops() {
    let fake = FakeGmail::start().await;
    let p = provider(&fake);
    assert!(p.subscribe(&target(None)).await.unwrap().is_none());
    assert!(
        fake.requests().is_empty(),
        "nothing is sent without a topic"
    );

    let topic = "projects/acme-mail/topics/skein-push";
    let sub = p.subscribe(&target(Some(topic))).await.unwrap().unwrap();
    assert_eq!(sub.provider_kind, skein_mail::PUSH_GMAIL);
    assert_eq!(sub.resource, "ada@example.com");
    assert_eq!(sub.id, "1000");
    assert!(sub.expires_at.0 > fake::WATCH_NOW + 6 * 24 * 3600 * 1000);
    {
        let st = fake.state.lock().unwrap();
        assert_eq!(st.watch.as_ref().unwrap().0, topic);
        assert_eq!(st.watches, 1);
    }
    assert!(!format!("{sub:?}").contains("ada@example.com"));

    let renewed = p.renew(&sub, &target(Some(topic))).await.unwrap().unwrap();
    assert!(renewed.expires_at > sub.expires_at);
    assert_eq!(renewed.resource, sub.resource);
    assert_eq!(fake.state.lock().unwrap().watches, 2);

    p.unsubscribe(&renewed).await.unwrap();
    p.unsubscribe(&renewed).await.unwrap();
    let st = fake.state.lock().unwrap();
    assert_eq!(st.stops, 2);
    assert!(st.watch.is_none());
}

#[tokio::test]
async fn refused_watches_and_bad_topics_are_config_errors() {
    let fake = FakeGmail::start().await;
    let p = provider(&fake);
    for bad in [
        "acme-mail/skein-push",
        "projects/acme/topics/",
        "projects/a/b/topics/c",
        "https://evil.example.org/x",
    ] {
        assert!(
            matches!(
                p.subscribe(&target(Some(bad))).await,
                Err(MailError::Config(_))
            ),
            "{bad}"
        );
    }
    assert!(fake.requests().is_empty());
    fake.state.lock().unwrap().publish_denied = true;
    let err = p
        .subscribe(&target(Some("projects/acme/topics/push")))
        .await
        .unwrap_err();
    assert!(matches!(err, MailError::Config(_)), "{err:?}");
    fake.state.lock().unwrap().publish_denied = false;
    fake.state.lock().unwrap().throttle = Some((429, None, Some(3)));
    assert!(matches!(
        p.subscribe(&target(Some("projects/acme/topics/push")))
            .await,
        Err(MailError::Throttled {
            retry_after: Some(_)
        })
    ));
}

#[tokio::test]
async fn other_kinds_are_not_stopped() {
    let fake = FakeGmail::start().await;
    let sub = skein_mail::Subscription {
        id: "x".into(),
        provider_kind: skein_mail::PUSH_GRAPH.into(),
        expires_at: skein_core::Timestamp(0),
        resource: "me/messages".into(),
    };
    provider(&fake).unsubscribe(&sub).await.unwrap();
    assert!(fake.requests().is_empty());
}

fn failed(reason: &str) -> WriteOutcome {
    WriteOutcome::Failed {
        reason: reason.into(),
    }
}

#[tokio::test]
async fn reports_its_capabilities() {
    let fake = FakeGmail::start().await;
    let mut s = provider(&fake).connect().await.unwrap();
    let caps = s.capabilities().await.unwrap();
    assert_eq!(caps.system_flags, vec!["\\Flagged", "\\Seen"]);
    assert!(caps.labels && caps.trash && caps.copy && caps.mailboxes);
    assert!(!caps.keywords && !caps.append_received_at);
}

#[tokio::test]
async fn trashes_and_copies() {
    let fake = FakeGmail::start().await;
    let receipts = fake.add_label("Receipts");
    let id = fake.insert(&msg(1), &["INBOX"]);
    let mut s = provider(&fake).connect().await.unwrap();
    let copy = |from: &str, to: &str| CommandBody::Copy {
        from: from.into(),
        to: to.into(),
        items: vec![item(&id)],
    };
    assert_eq!(
        s.apply(&copy("INBOX", &receipts), None).await.unwrap(),
        WriteOutcome::Applied
    );
    let labels: Vec<String> = fake.labels_of(&id).unwrap().into_iter().collect();
    assert_eq!(labels, vec!["INBOX".to_owned(), receipts.clone()]);
    assert_eq!(
        s.apply(&copy("INBOX", "Label_404"), None).await.unwrap(),
        failed("no_such_mailbox")
    );
    assert!(matches!(
        s.apply(&copy("Label_404", "INBOX"), None).await,
        Err(MailError::MailboxNotFound)
    ));
    assert_eq!(
        s.apply(&copy("INBOX", "TRASH"), None).await.unwrap(),
        failed("unsupported")
    );
    let to_trash = |mailbox: &str| CommandBody::Delete {
        mailbox: mailbox.into(),
        items: vec![item(&id)],
        to_trash: true,
    };
    let before = fake.requests().len();
    assert_eq!(
        s.apply(&to_trash("INBOX"), None).await.unwrap(),
        WriteOutcome::Applied
    );
    assert!(fake.labels_of(&id).unwrap().contains("TRASH"));
    assert!(
        fake.requests()[before..]
            .iter()
            .any(|r| r.ends_with(&format!("/messages/{id}/trash")))
    );
    let before = fake.requests().len();
    assert_eq!(
        s.apply(&to_trash("TRASH"), None).await.unwrap(),
        WriteOutcome::Applied,
        "already in the trash"
    );
    assert!(
        !fake.requests()[before..]
            .iter()
            .any(|r| r.contains("/trash"))
    );
    fake.state.lock().unwrap().throttle = Some((429, None, Some(3)));
    assert!(matches!(
        s.apply(&to_trash("INBOX"), None).await,
        Err(MailError::Throttled {
            retry_after: Some(_)
        })
    ));
}

#[tokio::test]
async fn sets_labels_by_name() {
    let fake = FakeGmail::start().await;
    let receipts = fake.add_label("Receipts");
    let id = fake.insert(&msg(1), &["INBOX"]);
    let mut s = provider(&fake).connect().await.unwrap();
    let set = |add: &[&str], remove: &[&str]| CommandBody::SetLabels {
        mailbox: ALL.into(),
        items: vec![item(&id)],
        add: add.iter().map(|x| (*x).to_owned()).collect(),
        remove: remove.iter().map(|x| (*x).to_owned()).collect(),
    };
    assert_eq!(
        s.apply(&set(&["Receipts", "Important"], &["Inbox"]), None)
            .await
            .unwrap(),
        WriteOutcome::Applied
    );
    let labels: Vec<String> = fake.labels_of(&id).unwrap().into_iter().collect();
    assert_eq!(labels, vec!["IMPORTANT".to_owned(), receipts.clone()]);
    let late = fake.add_label("Later");
    assert_eq!(
        s.apply(&set(&["Later"], &["Later", "Receipts"]), None)
            .await
            .unwrap(),
        WriteOutcome::Applied,
        "a label made after the session started is found; adding wins"
    );
    let labels: Vec<String> = fake.labels_of(&id).unwrap().into_iter().collect();
    assert_eq!(labels, vec!["IMPORTANT".to_owned(), late]);
    assert_eq!(
        s.apply(&set(&["Nowhere"], &[]), None).await.unwrap(),
        failed("no_such_label")
    );
    assert!(matches!(
        s.apply(
            &CommandBody::SetLabels {
                mailbox: "Label_404".into(),
                items: vec![item(&id)],
                add: vec!["Receipts".into()],
                remove: vec![],
            },
            None
        )
        .await,
        Err(MailError::MailboxNotFound)
    ));
}

#[tokio::test]
async fn manages_user_labels() {
    let fake = FakeGmail::start().await;
    let receipts = fake.add_label("Receipts");
    let id = fake.insert(&msg(1), &["INBOX", &receipts]);
    let mut s = provider(&fake).connect().await.unwrap();
    let create = |path: &str| CommandBody::CreateMailbox { path: path.into() };
    assert_eq!(
        s.apply(&create("Projects/2026"), None).await.unwrap(),
        WriteOutcome::Applied
    );
    let boxes = s.mailboxes().await.unwrap();
    let projects = boxes
        .iter()
        .find(|b| b.path == "Projects/2026")
        .expect("listed")
        .id
        .clone();
    assert_eq!(
        s.apply(&create("receipts"), None).await.unwrap(),
        failed("exists")
    );
    assert_eq!(
        s.apply(&create("Inbox"), None).await.unwrap(),
        failed("exists")
    );
    assert_eq!(
        s.apply(&create(" / x"), None).await.unwrap(),
        failed("invalid_path")
    );
    fake.add_label("Raced");
    assert_eq!(
        s.apply(&create("Raced"), None).await.unwrap(),
        failed("exists"),
        "a label made elsewhere is seen before creating"
    );
    assert_eq!(
        s.apply(&create("chat"), None).await.unwrap(),
        failed("exists"),
        "Gmail's 409 is exists"
    );

    let rename = |mailbox: &str, path: &str| CommandBody::RenameMailbox {
        mailbox: mailbox.into(),
        path: path.into(),
    };
    assert_eq!(
        s.apply(&rename(&projects, "Projects/2027"), None)
            .await
            .unwrap(),
        WriteOutcome::Applied
    );
    assert!(
        s.mailboxes()
            .await
            .unwrap()
            .iter()
            .any(|b| b.id == projects && b.path == "Projects/2027")
    );
    assert_eq!(
        s.apply(&rename(&projects, "Receipts"), None).await.unwrap(),
        failed("exists")
    );
    assert_eq!(
        s.apply(&rename(&receipts, "RECEIPTS"), None).await.unwrap(),
        WriteOutcome::Applied,
        "a change of case is a rename"
    );
    for system in ["INBOX", "SENT", ALL, "TRASH"] {
        assert_eq!(
            s.apply(&rename(system, "Elsewhere"), None).await.unwrap(),
            failed("protected"),
            "{system}"
        );
        assert_eq!(
            s.apply(
                &CommandBody::DeleteMailbox {
                    mailbox: system.into()
                },
                None
            )
            .await
            .unwrap(),
            failed("protected"),
            "{system}"
        );
    }
    assert!(matches!(
        s.apply(&rename("Label_404", "X"), None).await,
        Err(MailError::MailboxNotFound)
    ));

    assert_eq!(
        s.apply(
            &CommandBody::DeleteMailbox {
                mailbox: receipts.clone()
            },
            None
        )
        .await
        .unwrap(),
        WriteOutcome::Applied
    );
    assert_eq!(
        fake.labels_of(&id).unwrap().into_iter().collect::<Vec<_>>(),
        vec!["INBOX".to_owned()],
        "messages stay, without the label"
    );
    assert!(matches!(
        s.apply(&CommandBody::DeleteMailbox { mailbox: receipts }, None)
            .await,
        Err(MailError::MailboxNotFound)
    ));
}
