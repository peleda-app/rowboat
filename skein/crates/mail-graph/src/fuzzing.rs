//! Entry points for the fuzz targets in `fuzz/`. Not part of the public API.

use std::collections::BTreeMap;

use bytes::Bytes;
use serde_json::Value;
use skein_mail::Cursor;
use url::Url;

use crate::cursor::DeltaCursor;
use crate::{http, page, see, time};

/// Reads `bytes` as a Graph delta page and an error body the way a session reads them.
pub fn page_of(bytes: &[u8]) {
    let _ = http::access_denied(bytes);
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return;
    };
    let Ok(page) = page(&value) else {
        return;
    };
    for link in page.next.iter().chain(&page.delta) {
        if let Ok(url) = Url::parse(link) {
            let _ = http::allowed(&url);
        }
    }
    let mut known = BTreeMap::new();
    let mut changes = Vec::new();
    let _ = see(&mut known, page.items, &mut changes);
    let cursor = DeltaCursor {
        folder: "f1".into(),
        link: page.delta.unwrap_or_default(),
        known,
    };
    assert_eq!(DeltaCursor::decode(&cursor.encode()), Some(cursor));
}

/// Reads `bytes` as an RFC 3339 date, and checks that dates this crate writes read back.
pub fn date(bytes: &[u8]) {
    let _ = time::parse_utc(&String::from_utf8_lossy(bytes));
    if let Some(chunk) = bytes.first_chunk::<8>() {
        let secs = i64::from_le_bytes(*chunk) % 253_402_300_800;
        let secs = secs.abs();
        assert_eq!(
            time::parse_utc(&time::format_utc(secs)).map(|t| t.0),
            Some(secs * 1000)
        );
    }
}

/// Reads `bytes` as a cursor this crate wrote.
pub fn cursor(bytes: &[u8]) {
    if let Some(c) = DeltaCursor::decode(&Cursor(Bytes::copy_from_slice(bytes))) {
        assert_eq!(DeltaCursor::decode(&c.encode()), Some(c));
    }
}
