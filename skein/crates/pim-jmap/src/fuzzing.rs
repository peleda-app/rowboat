//! Entry points for the fuzz targets in `fuzz/`. Not part of the public API.

use std::sync::OnceLock;
use std::time::Duration;

use bytes::Bytes;
use serde_json::Value;
use skein_core::{PartStat, TlsRoots};
use skein_pim::Cursor;
use url::Url;

use crate::cursor::JmapCursor;
use crate::http::{Auth, Http};
use crate::{
    BOOKS, CALENDARS_KIND, JmapSession, MAX_CALLS, MAX_OBJECTS, answers_in_order, canonical,
    collection_info, list, member_of, state_of, strings, write,
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

/// Reads `bytes` as a JMAP session object.
pub fn session(bytes: &[u8]) {
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return;
    };
    let base = Url::parse("https://jmap.example.com/.well-known/jmap").expect("a valid base");
    if let Ok(session) = JmapSession::from_session(http(), &base, &value) {
        assert!((1..=MAX_OBJECTS).contains(&session.max_objects));
        assert!((1..=MAX_CALLS).contains(&session.max_calls));
        assert_eq!(session.api.origin(), base.origin());
    }
}

/// Reads `bytes` as a JMAP response to three calls and every answer in it as a collection,
/// `/get`, `/query` and `/changes` answer of contact cards and calendar events.
pub fn response(bytes: &[u8]) {
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return;
    };
    let Ok(answers) = answers_in_order(&value, 3) else {
        return;
    };
    for answer in answers.iter().flatten() {
        let _ = state_of(answer);
        for key in ["ids", "created", "updated", "destroyed"] {
            let _ = strings(answer, key);
        }
        let Ok(items) = list(answer) else {
            continue;
        };
        for kind in [&BOOKS, &CALENDARS_KIND] {
            for item in &items {
                let _ = collection_info(kind, item);
                let _ = member_of(item, kind.member, "c1");
                if let Some(raw) = JmapSession::raw(kind, item.clone()) {
                    let back: Value =
                        serde_json::from_slice(&raw.bytes).expect("canonical bytes are JSON");
                    assert_eq!(
                        serde_json::to_vec(&canonical(back)).expect("JSON serializes"),
                        raw.bytes.as_ref(),
                        "canonical bytes are stable"
                    );
                }
            }
        }
    }
}

/// Reads `bytes` as a JSCalendar event and answers it as each participant it names, and as an
/// object to write.
pub fn event(bytes: &[u8]) {
    let _ = write::body(&Bytes::copy_from_slice(bytes), &CALENDARS_KIND);
    let _ = write::body(&Bytes::copy_from_slice(bytes), &BOOKS);
    let Ok(event) = serde_json::from_slice::<Value>(bytes) else {
        return;
    };
    let wanted: Vec<String> = event
        .get("participants")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|m| m.values())
        .flat_map(write::reached_at)
        .take(4)
        .collect();
    if let Some(who) = write::participant(&event, &wanted) {
        let patch = write::answer_patch(
            &event,
            &who,
            &wanted,
            PartStat::Accepted,
            Some("See you there"),
        );
        assert!(!patch.is_empty());
    }
}

/// Reads `bytes` as a cursor this crate wrote.
pub fn cursor(bytes: &[u8]) {
    let raw = Cursor(Bytes::copy_from_slice(bytes));
    if let Some(c) = JmapCursor::decode(&raw, "calendar/c1") {
        assert_eq!(JmapCursor::decode(&c.encode(), "calendar/c1"), Some(c));
    }
}
