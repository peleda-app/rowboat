//! Entry points for the fuzz targets in `fuzz/`. Not part of the public API.

use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::Duration;

use bytes::Bytes;
use serde_json::Value;
use skein_core::TlsRoots;
use skein_mail::Cursor;
use url::Url;

use crate::cursor::JmapCursor;
use crate::http::{Auth, Http};
use crate::{
    JmapSession, MAX_CALLS, MAX_OBJECTS, answers_in_order, expand, flags, in_mailbox, list,
    mailbox_infos, string, strings, time,
};

fn http() -> Http {
    static HTTP: OnceLock<Http> = OnceLock::new();
    HTTP.get_or_init(|| {
        Http::new(
            Auth::Bearer("fuzz".into()),
            Duration::from_secs(1),
            &TlsRoots::default(),
        )
        .expect("a client builds")
    })
    .clone()
}

/// Reads `bytes` as a JMAP session object and, when it is one, fills its download template.
pub fn session(bytes: &[u8]) {
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return;
    };
    let base = Url::parse("https://jmap.example.com/.well-known/jmap").expect("a valid base");
    let Ok(session) = JmapSession::from_session(http(), &base, &value) else {
        return;
    };
    assert!((1..=MAX_OBJECTS).contains(&session.max_objects));
    assert!((1..=MAX_CALLS).contains(&session.max_calls));
    let _ = expand(
        &session.download_url,
        &[("accountId", &session.account), ("blobId", "b1")],
    );
}

/// Reads `bytes` as a JMAP response to three calls and every answer in it as `Mailbox/get`,
/// `Email/get`, `Email/query` and `Email/changes`.
pub fn response(bytes: &[u8]) {
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return;
    };
    let Ok(answers) = answers_in_order(&value, 3) else {
        return;
    };
    let mut cursor = JmapCursor {
        mailbox: "m1".into(),
        account: "a1".into(),
        state: "s1".into(),
        listing: None,
        known: BTreeMap::new(),
    };
    let mut changes = Vec::new();
    for answer in answers.iter().flatten() {
        if let Ok(items) = list(answer) {
            let _ = mailbox_infos(&items);
            for item in &items {
                let _ = JmapSession::see(&mut cursor, item, &mut changes);
                let _ = flags(item);
                let _ = in_mailbox(item, "m1");
                let _ = item
                    .get("receivedAt")
                    .and_then(Value::as_str)
                    .and_then(time::parse_utc);
            }
        }
        for key in ["ids", "created", "updated", "destroyed"] {
            let _ = strings(answer, key);
        }
        let _ = string(answer, "newState");
    }
    let encoded = cursor.encode();
    assert_eq!(JmapCursor::decode(&encoded), Some(cursor));
}

/// Reads `bytes` as a cursor this crate wrote.
pub fn cursor(bytes: &[u8]) {
    if let Some(c) = JmapCursor::decode(&Cursor(Bytes::copy_from_slice(bytes))) {
        assert_eq!(JmapCursor::decode(&c.encode()), Some(c));
    }
}
