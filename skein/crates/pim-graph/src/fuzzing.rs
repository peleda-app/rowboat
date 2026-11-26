//! Entry points for the fuzz targets in `fuzz/`. Not part of the public API.

use bytes::Bytes;
use skein_core::ItemRef;
use skein_pim::{Cursor, RawObject};

use crate::cursor::GraphCursor;
use crate::{bare, fold_delta, http, json, page, string, write};

/// Reads `bytes` as a Graph delta or listing page, an object, an error body and a cursor.
pub fn page_of(bytes: &[u8]) {
    let _ = http::error_code(bytes);
    let body = Bytes::copy_from_slice(bytes);
    let _ = write::body(&body);
    let object = RawObject {
        item: ItemRef {
            id: "e1".into(),
            uid: None,
        },
        version: None,
        bytes: body.clone(),
        content_type: "application/json".into(),
    };
    let _ = write::organizes(Some(&object));
    if let Ok(value) = json(bytes) {
        let _ = write::invites(&value, "ada@example.com");
        for key in ["id", "changeKey", "type"] {
            if let Some(v) = string(&value, key) {
                let _ = bare(&v);
                let _ = write::usable(&v);
            }
        }
        if let Ok(page) = page(&value) {
            for initial in [true, false] {
                let (up, gone) = fold_delta(page.items.clone(), initial);
                assert!(up.keys().all(|k| !gone.contains_key(k)));
                assert!(!initial || gone.is_empty());
            }
        }
    }
    let raw = Cursor(body);
    for collection in ["contacts", "calendar/c1"] {
        if let Some(c) = GraphCursor::decode(&raw, collection) {
            assert_eq!(GraphCursor::decode(&c.encode(), collection), Some(c));
        }
    }
}
