//! Entry points for the fuzz targets in `fuzz/`. Not part of the public API.

use std::collections::HashMap;

use base64::Engine as _;

use crate::changes::{HistoryPage, ListPage, fold};
use crate::cursor::CursorState;
use crate::labels::{self, Label, LabelList};
use crate::{ALL, Meta, Raw, base64url, http, parse_number, plausible_id};

/// Reads `bytes` as each Gmail API answer a session reads: `messages.list`, `history.list`,
/// `labels.list`, a message's metadata, a raw message and an error body.
pub fn page(bytes: &[u8]) {
    let _ = http::reasons(bytes);
    if let Ok(page) = serde_json::from_slice::<ListPage>(bytes) {
        let _ = page.messages.iter().filter(|m| plausible_id(&m.id)).count();
    }
    if let Ok(page) = serde_json::from_slice::<HistoryPage>(bytes) {
        let mut order = Vec::new();
        let mut touched = HashMap::new();
        if let Ok(last) = fold(page.history, 10, &mut order, &mut touched) {
            assert!(last >= 10);
            assert_eq!(order.len(), touched.len());
            assert!(order.iter().all(|id| plausible_id(id)));
        }
        if let Some(h) = &page.history_id {
            let _ = parse_number(h);
        }
    }
    let known: HashMap<String, Label> = serde_json::from_slice::<LabelList>(bytes)
        .map(|l| l.labels.into_iter().map(|l| (l.id.clone(), l)).collect())
        .unwrap_or_default();
    let boxes = labels::mailboxes(&known);
    for b in &boxes {
        let _ = labels::id_for(&b.path, &known);
        let _ = labels::path_taken(&b.path, &known);
    }
    if let Ok(meta) = serde_json::from_slice::<Meta>(bytes) {
        let _ = labels::flags(&meta.label_ids);
        let _ = labels::names(&meta.label_ids, &known);
        let _ = labels::member(ALL, &meta.label_ids);
        let _ = meta
            .internal_date
            .as_deref()
            .map(|d| d.trim().parse::<i64>());
    }
    if let Ok(Raw { raw: Some(raw) }) = serde_json::from_slice::<Raw>(bytes) {
        let _ = base64url().decode(raw.trim_end_matches('='));
    }
}

/// Reads `bytes` as a cursor this crate wrote.
pub fn cursor(bytes: &[u8]) {
    if let Ok(c) = CursorState::decode(bytes) {
        assert_eq!(CursorState::decode(&c.encode()), Ok(c));
    }
}
