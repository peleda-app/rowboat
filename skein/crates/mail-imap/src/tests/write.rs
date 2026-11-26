use skein_mail::testing::write_conformance;

use super::*;

fn failed(reason: &str) -> WriteOutcome {
    WriteOutcome::Failed {
        reason: reason.into(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn keeps_the_write_contract() {
    let fake = Fake::start(FULL).await;
    write_conformance(
        Arc::new(fake.provider()),
        Arc::new(fake.clone()),
        "INBOX",
        "INBOX/Archive",
        None,
    )
    .await;
    let v = verbs(&fake);
    for verb in ["UID COPY", "UID MOVE", "CREATE", "RENAME", "DELETE"] {
        assert!(v.iter().any(|x| x == verb), "{verb} was used");
    }
    assert!(fake.messages("Bin").is_empty(), "the trash was emptied");
}

#[tokio::test(flavor = "multi_thread")]
async fn keeps_the_write_contract_without_move() {
    let fake = Fake::start(Caps {
        uidplus: true,
        ..BARE
    })
    .await;
    write_conformance(
        Arc::new(fake.provider()),
        Arc::new(fake.clone()),
        "INBOX",
        "INBOX/Archive",
        None,
    )
    .await;
    assert!(!verbs(&fake).iter().any(|v| v == "UID MOVE"));
}

#[tokio::test(flavor = "multi_thread")]
async fn keeps_the_write_contract_on_gmail() {
    let fake = Fake::start(GMAIL).await;
    fake.create_mailbox("Work").await;
    write_conformance(
        Arc::new(fake.provider()),
        Arc::new(fake.clone()),
        "INBOX",
        "Projects/Важное",
        Some("Work"),
    )
    .await;
    assert!(
        fake.commands()
            .iter()
            .any(|c| c.ends_with("+X-GM-LABELS (\"Work\")"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn reports_what_the_server_can_do() {
    let bare = Fake::start(BARE).await;
    let mut session = bare.provider().connect().await.unwrap();
    let caps = session.capabilities().await.unwrap();
    assert_eq!(
        caps.system_flags,
        ["\\Answered", "\\Deleted", "\\Draft", "\\Flagged", "\\Seen"]
    );
    assert!(!caps.keywords && !caps.labels);
    assert!(!caps.trash, "no MOVE and no UIDPLUS");
    assert!(caps.copy && caps.append_received_at && caps.mailboxes);
    assert!(bare.commands().iter().any(|c| c == "SELECT \"INBOX\""));

    let full = Fake::start(FULL).await;
    let caps = full
        .provider()
        .connect()
        .await
        .unwrap()
        .capabilities()
        .await
        .unwrap();
    assert!(caps.keywords && caps.trash && !caps.labels);

    let gmail = Fake::start(GMAIL).await;
    let caps = gmail
        .provider()
        .connect()
        .await
        .unwrap()
        .capabilities()
        .await
        .unwrap();
    assert!(caps.labels && caps.trash);

    full.state
        .lock()
        .unwrap()
        .folders
        .retain(|f| f.path != "Bin");
    let mut session = full.provider().connect().await.unwrap();
    assert!(!session.capabilities().await.unwrap().trash);
    assert_eq!(
        session
            .apply(
                &CommandBody::Delete {
                    mailbox: "INBOX".into(),
                    items: Vec::new(),
                    to_trash: true,
                },
                None
            )
            .await
            .unwrap(),
        failed("no_trash")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn trash_and_labels_follow_their_rules() {
    let fake = Fake::start(FULL).await;
    fake.add("Bin", b"Subject: t\r\n\r\nt\r\n", Flags::default())
        .await;
    let items = listed(&fake, "Bin").await;
    let mut session = fake.provider().connect().await.unwrap();
    let before = fake.commands().len();
    let outcome = session
        .apply(
            &CommandBody::Delete {
                mailbox: "Bin".into(),
                items,
                to_trash: true,
            },
            None,
        )
        .await;
    assert_eq!(outcome.unwrap(), WriteOutcome::Applied);
    assert_eq!(fake.messages("Bin").len(), 1, "already in the trash");
    assert!(
        !fake.commands()[before..]
            .iter()
            .any(|c| c.starts_with("UID")),
        "nothing was sent for it"
    );
    let labels = CommandBody::SetLabels {
        mailbox: "INBOX".into(),
        items: Vec::new(),
        add: vec!["Work".into()],
        remove: Vec::new(),
    };
    assert_eq!(
        session.apply(&labels, None).await.unwrap(),
        failed("unsupported")
    );

    let gmail = Fake::start(GMAIL).await;
    let mut session = gmail.provider().connect().await.unwrap();
    let bad = CommandBody::SetLabels {
        mailbox: "INBOX".into(),
        items: Vec::new(),
        add: vec![String::new()],
        remove: Vec::new(),
    };
    assert_eq!(
        session.apply(&bad, None).await.unwrap(),
        failed("invalid_label")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn manages_mailboxes_with_encoded_names() {
    let fake = Fake::start(FULL).await;
    let mut session = fake.provider().connect().await.unwrap();
    let create = |path: &str| CommandBody::CreateMailbox { path: path.into() };
    assert_eq!(
        session
            .apply(&create("Projects/Счета"), None)
            .await
            .unwrap(),
        WriteOutcome::Applied
    );
    assert!(
        fake.commands()
            .iter()
            .any(|c| c == "CREATE \"Projects.&BCEERwQ1BEIEMA-\"")
    );
    assert!(
        session
            .mailboxes()
            .await
            .unwrap()
            .iter()
            .any(|b| b.id == "Projects/Счета")
    );
    for (path, reason) in [
        ("Projects/Счета", "exists"),
        ("inbox", "exists"),
        ("a.b", "invalid_name"),
        ("a//b", "invalid_name"),
        ("", "invalid_name"),
        ("a*", "invalid_name"),
    ] {
        assert_eq!(
            session.apply(&create(path), None).await.unwrap(),
            failed(reason),
            "{path}"
        );
    }

    let rename = |mailbox: &str, path: &str| CommandBody::RenameMailbox {
        mailbox: mailbox.into(),
        path: path.into(),
    };
    assert_eq!(
        session.apply(&rename("INBOX", "Old"), None).await.unwrap(),
        failed("protected")
    );
    assert_eq!(
        session
            .apply(&rename("Projects/Счета", "Junk"), None)
            .await
            .unwrap(),
        failed("exists")
    );
    assert!(matches!(
        session.apply(&rename("Nowhere", "Else"), None).await,
        Err(MailError::MailboxNotFound)
    ));
    assert_eq!(
        session
            .apply(&rename("Projects/Счета", "Paid"), None)
            .await
            .unwrap(),
        WriteOutcome::Applied
    );
    assert!(
        fake.commands()
            .iter()
            .any(|c| c == "RENAME \"Projects.&BCEERwQ1BEIEMA-\" \"Paid\"")
    );

    let delete = |mailbox: &str| CommandBody::DeleteMailbox {
        mailbox: mailbox.into(),
    };
    assert_eq!(
        session.apply(&delete("INBOX"), None).await.unwrap(),
        failed("protected")
    );
    assert!(matches!(
        session.apply(&delete("Projects/Счета"), None).await,
        Err(MailError::MailboxNotFound)
    ));
    assert_eq!(
        session.apply(&delete("Paid"), None).await.unwrap(),
        WriteOutcome::Applied
    );
    assert!(
        fake.state
            .lock()
            .unwrap()
            .folders
            .iter()
            .all(|f| f.path != "Paid")
    );

    let gmail = Fake::start(GMAIL).await;
    let mut session = gmail.provider().connect().await.unwrap();
    assert_eq!(
        session
            .apply(&delete("[Gmail]/All Mail"), None)
            .await
            .unwrap(),
        failed("protected")
    );
    assert_eq!(
        session.apply(&create("Projects/2026"), None).await.unwrap(),
        WriteOutcome::Applied
    );
    assert!(
        gmail
            .commands()
            .iter()
            .any(|c| c == "CREATE \"Projects/2026\"")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn appends_with_the_received_time_and_copies() {
    let fake = Fake::start(FULL).await;
    fake.add("INBOX", b"Subject: c\r\n\r\nc\r\n", Flags::default())
        .await;
    let items = listed(&fake, "INBOX").await;
    let mut session = fake.provider().connect().await.unwrap();
    let raw = Bytes::from_static(b"Subject: a\r\n\r\na\r\n");
    let append = CommandBody::Append {
        mailbox: "INBOX/Archive".into(),
        blob: BlobHash::of(&raw),
        flags: Flags::new(["\\Seen"]),
        received_at: Some(Timestamp(1_795_000_000_000)),
    };
    assert_eq!(
        session.apply(&append, Some(raw)).await.unwrap(),
        WriteOutcome::Applied
    );
    assert!(
        fake.commands()
            .iter()
            .any(|c| c == "APPEND \"INBOX.Archive\" (\\Seen) \"18-Nov-2026 11:06:40 +0000\" {17}")
    );

    let copy = |to: &str| CommandBody::Copy {
        from: "INBOX".into(),
        to: to.into(),
        items: items.clone(),
    };
    assert_eq!(
        session.apply(&copy("Nowhere"), None).await.unwrap(),
        failed("no_such_mailbox")
    );
    assert!(matches!(
        session
            .apply(
                &CommandBody::Copy {
                    from: "Nowhere".into(),
                    to: "INBOX/Archive".into(),
                    items: items.clone(),
                },
                None
            )
            .await,
        Err(MailError::MailboxNotFound)
    ));
    assert_eq!(
        session.apply(&copy("INBOX/Archive"), None).await.unwrap(),
        WriteOutcome::Applied
    );
    assert_eq!(fake.messages("INBOX").len(), 1);
    assert_eq!(fake.messages("INBOX/Archive").len(), 2);
    assert!(
        !verbs(&fake).iter().any(|v| v == "SELECT"),
        "copying only examines"
    );

    fake.state.lock().unwrap().drop_on = Some("UID COPY");
    assert_eq!(
        session.apply(&copy("INBOX/Archive"), None).await.unwrap(),
        WriteOutcome::Uncertain
    );
}
