use bytes::Bytes;
use proptest::prelude::*;

use super::*;

fn account() -> AccountId {
    AccountId::new(format!("a{}", "b".repeat(26))).unwrap()
}

fn msg(n: u8) -> MessageId {
    MessageId::new(format!("{:02x}", n).repeat(32)).unwrap()
}

fn draft() -> Draft {
    Draft {
        id: None,
        account: account(),
        to: vec![Recipient {
            name: Some("Sam".into()),
            address: EmailAddress::new("sam@example.org").unwrap(),
        }],
        cc: vec![],
        bcc: vec![],
        subject: "Hello".into(),
        text: "Hi".into(),
        reply: None,
        attachments: vec![],
    }
}

#[test]
fn ids_follow_their_rules() {
    assert!(AccountId::new(format!("a{}", "z7".repeat(13))).is_ok());
    for bad in [
        "",
        "a",
        "b234567abcdefghijklmnopqrstu",
        "aBCDEFGHIJKLMNOPQRSTUVWXYZA",
        "a1aaaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        assert!(AccountId::new(bad).is_err(), "{bad}");
    }
    assert!(MessageId::new("a".repeat(64)).is_ok());
    assert!(MessageId::new("A".repeat(64)).is_err());
    assert!(MessageId::new("g".repeat(64)).is_err());
    assert!(MailboxId::new("INBOX/Sub folder").is_ok());
    assert!(MailboxId::new("bad\nname").is_err());
    assert!(MailboxId::new("x".repeat(1025)).is_err());
    assert!(CommandId::new("01ARZ3NDEKTSV4RRFFQ69G5FAV").is_ok());
    assert!(CommandId::new("01arz3ndektsv4rrffq69g5fav").is_err());
    assert!(CommandId::new("81ARZ3NDEKTSV4RRFFQ69G5FAV").is_err());
    assert!(CommandId::new("01ARZ3NDEKTSV4RRFFQ69G5FAU").is_err());
    assert!(ThreadId::new(0).is_err());
    assert!(serde_json::from_str::<ThreadId>("-5").is_err());
    assert!(Tag::new("category.person.direct").is_ok());
    assert!(Tag::new("Spam").is_err());
}

#[test]
fn addresses_refuse_header_and_command_injection() {
    assert!(EmailAddress::new("pat.doe+tag@example.com").is_ok());
    for bad in [
        "pat",
        "@example.com",
        "pat@",
        "pat@exa mple.com",
        "pat@example.com\r\nBcc: x@example.net",
        "pat@example.com>",
        "<pat@example.com",
        "a,b@example.com",
        "a;b@example.com",
        "\"a\"@example.com",
        "a@b@example.com",
        "pat@example.com\0",
    ] {
        assert!(EmailAddress::new(bad).is_err(), "{bad:?}");
    }
    assert!(EmailAddress::new(format!("{}@example.com", "a".repeat(320))).is_err());
    let a = EmailAddress::new("pat@example.com").unwrap();
    assert_eq!((a.local_part(), a.domain()), ("pat", "example.com"));
    assert_eq!(format!("{a:?}"), "EmailAddress(15 bytes)");
}

#[test]
fn drafts_are_checked() {
    assert!(check::sendable(&draft()).is_ok());
    let mut d = draft();
    d.to.clear();
    assert!(check::draft(&d).is_ok());
    assert_eq!(check::sendable(&d), Err(NodeError::InvalidInput));

    let mut d = draft();
    d.subject = "Hi\r\nBcc: victim@example.net".into();
    assert!(check::draft(&d).is_err());
    let mut d = draft();
    d.to[0].name = Some("Sam\nX".into());
    assert!(check::draft(&d).is_err());
    let mut d = draft();
    d.text = "x".repeat(MAX_TEXT_BYTES + 1);
    assert!(check::draft(&d).is_err());
    let mut d = draft();
    d.attachments = vec![DraftAttachment {
        name: "../etc/passwd".into(),
        bytes: Bytes::new(),
    }];
    assert!(check::draft(&d).is_err());
    let mut d = draft();
    d.attachments = vec![DraftAttachment {
        name: "big.bin".into(),
        bytes: Bytes::from(vec![0; MAX_ATTACHMENT_BYTES + 1]),
    }];
    assert!(check::draft(&d).is_err());
    let mut d = draft();
    d.to = (0..=MAX_RECIPIENTS)
        .map(|i| Recipient {
            name: None,
            address: EmailAddress::new(format!("r{i}@example.org")).unwrap(),
        })
        .collect();
    assert!(check::draft(&d).is_err());
    let mut d = draft();
    d.reply = Some(ReplyTo {
        message_id: "abc>@example.com".into(),
        references: vec![],
    });
    assert!(check::draft(&d).is_err());
}

#[test]
fn targets_are_bounded_unique_and_one_account_for_moves() {
    let one = MessageRef {
        account: account(),
        message: msg(1),
    };
    assert!(check::targets(&Targets(vec![])).is_err());
    assert!(check::targets(&Targets(vec![one.clone(), one.clone()])).is_err());
    let many: Vec<MessageRef> = (0..=MAX_TARGETS)
        .map(|i| MessageRef {
            account: account(),
            message: MessageId::new(format!("{i:064x}")).unwrap(),
        })
        .collect();
    assert!(check::targets(&Targets(many[..MAX_TARGETS].to_vec())).is_ok());
    assert!(check::targets(&Targets(many)).is_err());
    let other = MessageRef {
        account: AccountId::new(format!("a{}", "c".repeat(26))).unwrap(),
        message: msg(2),
    };
    assert!(check::targets(&Targets(vec![one.clone(), other.clone()])).is_ok());
    assert!(check::targets_of_one_account(&Targets(vec![one, other])).is_err());
}

#[test]
fn queries_and_prefixes_are_checked() {
    let q = |limit| ListQuery {
        scope: Scope::All { account: None },
        unread_only: false,
        cursor: None,
        limit,
    };
    assert!(check::list(&q(1)).is_ok() && check::list(&q(200)).is_ok());
    assert!(check::list(&q(0)).is_err() && check::list(&q(201)).is_err());
    let s = |text: &str| SearchQuery {
        account: None,
        text: text.into(),
        filter: SearchFilter::default(),
        limit: 10,
    };
    assert!(check::search(&s("garden")).is_ok());
    assert!(check::search(&s("  ")).is_err());
    assert!(check::search(&s(&"x".repeat(257))).is_err());
    let mut mailbox_without_account = s("x");
    mailbox_without_account.filter.mailbox = Some(MailboxId::new("INBOX").unwrap());
    assert!(check::search(&mailbox_without_account).is_err());
    assert!(check::suggest("pa", 5).is_ok());
    assert!(check::suggest("", 5).is_err());
    assert!(check::suggest("pa", 21).is_err());
    assert!(check::suggest("pa", 0).is_err());
    assert!(check::suggest(&"p".repeat(65), 5).is_err());
    assert!(check::password(&Secret::from_text("hunter2")).is_ok());
    for bad in ["", "a\r\nb", "a\0"] {
        assert!(check::password(&Secret::from_text(bad)).is_err());
    }
    assert!(check::password(&Secret::new(vec![0xff, 0xfe])).is_err());
}

#[test]
fn cursors_round_trip_and_refuse_anything_else() {
    let p = cursor::Position {
        sort: -5,
        id: "ab".repeat(32),
        account: Some(account().to_string()),
    };
    assert_eq!(cursor::decode(&cursor::encode(&p)).unwrap(), p);
    for bad in ["c1.", "c2.e30", "c1.!!!", "c1.e30", "x"] {
        let c = Cursor::new(bad).unwrap();
        assert_eq!(cursor::decode(&c), Err(NodeError::InvalidInput), "{bad}");
    }
    assert!(Cursor::new("a b").is_err());
    assert!(Cursor::new("x".repeat(513)).is_err());
}

#[test]
fn requests_round_trip_and_are_checked_on_decode() {
    let r = Request::Send { draft: draft() };
    assert_eq!(r.class().as_str(), "mail-send");
    assert_eq!(decode_request(&encode_request(&r)).unwrap(), r);
    let mut d = draft();
    d.to.clear();
    let bad = encode_request(&Request::Send { draft: d });
    assert_eq!(decode_request(&bad), Err(NodeError::InvalidInput));
    let forged = br#"{"op":"remove_account","account":"../../etc"}"#;
    assert_eq!(decode_request(forged), Err(NodeError::InvalidInput));
    assert_eq!(decode_request(b"\xff"), Err(NodeError::InvalidInput));
    let classes = [
        CommandClass::AccountAdd,
        CommandClass::AccountPassword,
        CommandClass::AccountUpdate,
        CommandClass::AccountRemove,
        CommandClass::Sync,
        CommandClass::Flags,
        CommandClass::Move,
        CommandClass::Delete,
        CommandClass::Draft,
        CommandClass::Send,
        CommandClass::SendCancel,
    ];
    let names: std::collections::BTreeSet<_> = classes.iter().map(|c| c.as_str()).collect();
    assert_eq!(names.len(), classes.len());
    assert!(names.iter().all(|n| n.starts_with("mail-")));
}

#[test]
fn errors_serialize_as_kinds() {
    let e = NodeError::Throttled {
        retry_after_secs: Some(30),
    };
    assert_eq!(
        serde_json::to_string(&e).unwrap(),
        r#"{"kind":"throttled","retry_after_secs":30}"#
    );
    assert_eq!(
        serde_json::to_string(&NodeError::KeysLost).unwrap(),
        r#"{"kind":"keys_lost"}"#
    );
}

proptest! {
    #[test]
    fn decoders_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512), text in "\\PC{0,200}") {
        let _ = decode_request(&bytes);
        if let Ok(c) = Cursor::new(text.clone()) {
            let _ = cursor::decode(&c);
        }
        let _ = Cursor::new(format!("c1.{text}")).map(|c| cursor::decode(&c));
    }

    #[test]
    fn plausible_addresses_never_carry_separators(s in "[ -~]{0,40}") {
        if plausible_address(&s) {
            prop_assert!(!s.contains([' ', '<', '>', ',', ';', '"', '\r', '\n']));
            prop_assert_eq!(s.matches('@').count(), 1);
        }
    }
}
