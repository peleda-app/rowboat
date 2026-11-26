use std::sync::Arc;

use bytes::Bytes;
use proptest::prelude::*;
use rinse_mail::{Content, ContentLimits, RenderOptions, RenderRequest};
use rinse_mail_direct::DirectContent;
use rowboat_api::{AccountId, DraftAttachment, EmailAddress, Recipient, ReplyTo};

use super::*;

fn addr(a: &str) -> EmailAddress {
    EmailAddress::new(a).unwrap()
}

fn draft() -> Draft {
    Draft {
        id: None,
        account: AccountId::new(format!("a{}", "b".repeat(26))).unwrap(),
        to: vec![Recipient {
            name: Some("Sam Example".into()),
            address: addr("sam@example.org"),
        }],
        cc: vec![Recipient {
            name: None,
            address: addr("team@example.org"),
        }],
        bcc: vec![Recipient {
            name: Some("Hidden".into()),
            address: addr("hidden@example.net"),
        }],
        subject: "Garden report".into(),
        text: "The tomatoes did well.\nThe zucchini did not.".into(),
        reply: None,
        attachments: vec![],
    }
}

fn from() -> EmailAddress {
    addr("pat@Example.COM")
}

fn identity(from: &EmailAddress) -> Identity<'_> {
    Identity {
        from,
        from_name: Some("Pat Doe"),
        date_ms: 1_793_610_900_000,
        message_id_local: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        boundary_seed: "abcdef0123456789",
    }
}

fn header_block(bytes: &[u8]) -> String {
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    text.split("\r\n\r\n").next().unwrap().to_owned()
}

fn assert_well_formed(bytes: &[u8]) {
    let text = std::str::from_utf8(bytes).unwrap();
    assert!(text.is_ascii(), "8-bit bytes in the message");
    for (i, w) in bytes.windows(2).enumerate() {
        if w[1] == b'\n' {
            assert_eq!(w[0], b'\r', "bare LF at {i}");
        }
        if w[0] == b'\r' {
            assert_eq!(w[1], b'\n', "bare CR at {i}");
        }
    }
    for line in text.split("\r\n") {
        assert!(line.len() <= 998, "line of {} bytes", line.len());
    }
}

async fn render(bytes: &[u8]) -> rinse_mail::Rendered {
    let content: Arc<dyn Content> = Arc::new(DirectContent::new());
    content
        .render(RenderRequest {
            raw: Bytes::copy_from_slice(bytes),
            options: RenderOptions::default(),
            limits: ContentLimits::default(),
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn a_plain_message_round_trips_through_rinse() {
    let f = from();
    let c = compose(&draft(), &identity(&f)).unwrap();
    assert_well_formed(&c.bytes);
    let headers = header_block(&c.bytes);
    assert!(headers.contains("From: \"Pat Doe\" <pat@Example.COM>"));
    assert!(
        headers.contains("Date: Mon, 02 Nov 2026 09:15:00 +0000"),
        "{headers}"
    );
    assert!(headers.contains("Message-ID: <01ARZ3NDEKTSV4RRFFQ69G5FAV@example.com>"));
    assert!(!String::from_utf8_lossy(&c.bytes).contains("hidden@example.net"));
    assert!(!String::from_utf8_lossy(&c.bytes).contains("Hidden"));
    assert_eq!(
        c.recipients,
        vec!["sam@example.org", "team@example.org", "hidden@example.net"]
    );
    assert_eq!(c.envelope_from, "pat@Example.COM");
    let r = render(&c.bytes).await;
    assert_eq!(r.headers.subject.as_deref(), Some("Garden report"));
    assert!(
        r.headers.from[0]
            .address
            .eq_ignore_ascii_case("pat@example.com")
    );
    assert_eq!(r.headers.to.len(), 1);
    assert!(r.text.contains("zucchini"));
}

#[tokio::test]
async fn unicode_long_and_hostile_headers_are_encoded() {
    let mut d = draft();
    d.subject = "Grüße aus Köln — ".repeat(10);
    d.to[0].name = Some("Jürgen \"JB\" Beispiel".into());
    d.cc[0].name = Some("=?utf-8?B?ZXZpbA==?= <evil@example.net>".into());
    d.text = "Viele Grüße\r\n.\r\nFrom the garden\n".repeat(3) + &"x".repeat(300);
    let f = from();
    let c = compose(&d, &identity(&f)).unwrap();
    assert_well_formed(&c.bytes);
    let headers = header_block(&c.bytes);
    assert!(!headers.contains("evil@example.net>,"));
    let r = render(&c.bytes).await;
    assert_eq!(r.headers.subject.as_deref(), Some(d.subject.trim_end()));
    assert_eq!(
        r.headers.to[0].name.as_deref(),
        Some("Jürgen \"JB\" Beispiel")
    );
    assert_eq!(r.headers.cc.len(), 1);
    assert_eq!(r.headers.cc[0].address, "team@example.org");
    assert!(r.text.contains("Viele Grüße"));
    assert!(r.text.contains(&"x".repeat(300)));
}

#[tokio::test]
async fn attachments_and_replies() {
    let mut d = draft();
    d.reply = Some(ReplyTo {
        message_id: "parent@example.org".into(),
        references: vec!["root@example.org".into()],
    });
    d.attachments = vec![
        DraftAttachment {
            name: "Plan für 2027.PDF".into(),
            bytes: Bytes::from([0u8, 1, 2, 255].repeat(100)),
        },
        DraftAttachment {
            name: "notes".into(),
            bytes: Bytes::from_static(b"--=_rowboat_abcdef0123456789--"),
        },
    ];
    let f = from();
    let c = compose(&d, &identity(&f)).unwrap();
    assert_well_formed(&c.bytes);
    let text = String::from_utf8(c.bytes.clone()).unwrap();
    assert!(text.contains("In-Reply-To: <parent@example.org>"));
    assert!(text.contains("References: <root@example.org>\r\n <parent@example.org>"));
    assert!(
        text.contains("Content-Type: application/pdf;\r\n name*=utf-8''Plan%20f%C3%BCr%202027.PDF")
    );
    assert!(text.contains("Content-Type: application/octet-stream;\r\n name*=utf-8''notes"));
    assert_eq!(
        text.matches("\r\n--=_rowboat_abcdef0123456789\r\n").count(),
        3
    );
    let r = render(&c.bytes).await;
    assert_eq!(r.attachments.len(), 2, "{:?}", r.attachments);
    assert_eq!(
        r.attachments[0].file_name.as_deref(),
        Some("Plan für 2027.PDF")
    );
    assert_eq!(r.attachments[0].size, 400);
    assert_eq!(
        r.facts.thread.in_reply_to.as_deref(),
        Some("parent@example.org")
    );
}

#[tokio::test]
async fn long_names_and_ids_stay_within_the_line_limit() {
    let cyrillic = "Ж".repeat(rowboat_api::MAX_NAME_CHARS - 4) + ".pdf";
    let cjk = "文".repeat(rowboat_api::MAX_NAME_CHARS);
    let longest_id = "i".repeat(rowboat_api::check::MAX_HEADER_ID - 12) + "@example.org";
    let mut d = draft();
    d.reply = Some(ReplyTo {
        message_id: longest_id.clone(),
        references: vec![longest_id.clone()],
    });
    d.attachments = vec![
        DraftAttachment {
            name: cyrillic.clone(),
            bytes: Bytes::from_static(b"one"),
        },
        DraftAttachment {
            name: cjk.clone(),
            bytes: Bytes::from_static(b"two"),
        },
    ];
    let f = from();
    let c = compose(&d, &identity(&f)).unwrap();
    assert_well_formed(&c.bytes);
    let text = String::from_utf8(c.bytes.clone()).unwrap();
    assert!(text.contains("name*0*=utf-8''%D0%96"));
    assert!(text.contains("filename*1*=%D0%96"));
    let r = render(&c.bytes).await;
    let names: Vec<_> = r
        .attachments
        .iter()
        .map(|a| a.file_name.clone().unwrap_or_default())
        .collect();
    assert_eq!(names, vec![cyrillic, cjk]);

    let mut too_long = draft();
    too_long.reply = Some(ReplyTo {
        message_id: "i".repeat(990),
        references: vec![],
    });
    assert_eq!(
        compose(&too_long, &identity(&f)),
        Err(ComposeError::Invalid)
    );
}

#[test]
fn refuses_what_check_refuses_and_bad_identities() {
    let f = from();
    let mut d = draft();
    d.subject = "Hi\r\nBcc: victim@example.net".into();
    assert_eq!(compose(&d, &identity(&f)), Err(ComposeError::Invalid));
    let mut d = draft();
    d.to.clear();
    d.cc.clear();
    d.bcc.clear();
    assert_eq!(compose(&d, &identity(&f)), Err(ComposeError::Invalid));
    let mut id = identity(&f);
    id.message_id_local = "a@b";
    assert_eq!(compose(&draft(), &id), Err(ComposeError::BadIdentity));
    let mut id = identity(&f);
    id.boundary_seed = "short";
    assert_eq!(compose(&draft(), &id), Err(ComposeError::BadIdentity));
    let mut id = identity(&f);
    id.from_name = Some("Pat\r\nBcc: x@example.net");
    assert_eq!(compose(&draft(), &id), Err(ComposeError::Invalid));
}

#[test]
fn recipients_are_deduplicated_case_insensitively() {
    let f = from();
    let mut d = draft();
    d.bcc = vec![Recipient {
        name: None,
        address: addr("SAM@example.org"),
    }];
    let c = compose(&d, &identity(&f)).unwrap();
    assert_eq!(c.recipients, vec!["sam@example.org", "team@example.org"]);
}

#[test]
fn dates() {
    assert_eq!(rfc5322_date(0), "Thu, 01 Jan 1970 00:00:00 +0000");
    assert_eq!(
        rfc5322_date(951_782_400_000),
        "Tue, 29 Feb 2000 00:00:00 +0000"
    );
    assert_eq!(rfc5322_date(-1), "Thu, 01 Jan 1970 00:00:00 +0000");
    assert_eq!(rfc5322_date(i64::MAX), "Fri, 31 Dec 9999 23:59:59 +0000");
    assert_eq!(media_type("A.JPEG"), "image/jpeg");
    assert_eq!(media_type("noext"), "application/octet-stream");
}

proptest! {
    #[test]
    fn any_sendable_draft_gives_a_well_formed_message(
        subject in "\\PC{0,300}",
        name in "\\PC{0,120}",
        text in "(\\PC|\r|\n){0,2000}",
        file in "[^/\\\\\\p{Cc}]{1,200}",
    ) {
        let mut d = draft();
        d.subject = subject;
        d.to[0].name = Some(name);
        d.text = text;
        d.attachments = vec![DraftAttachment { name: file, bytes: Bytes::from_static(b"x") }];
        let f = from();
        if let Ok(c) = compose(&d, &identity(&f)) {
            assert_well_formed(&c.bytes);
            let headers = header_block(&c.bytes);
            for line in headers.split("\r\n") {
                prop_assert!(
                    line.starts_with(' ') || line.contains(": "),
                    "a header line that is neither a field nor a continuation"
                );
            }
            prop_assert!(!String::from_utf8_lossy(&c.bytes).contains("hidden@example.net"));
            prop_assert_eq!(compose(&d, &identity(&f)).unwrap(), c);
        }
    }
}
