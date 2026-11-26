//! Entry points for the fuzz targets in `fuzz/`. Not part of the public API.

use async_imap::types::Flag;

use crate::cursor::CursorState;
use crate::session::flag_name;
use crate::{guess_role, labels, quote, uid_set, utf7};

/// Reads `bytes` as a mailbox name, a Gmail label and a flag the way a session reads them from
/// the server, and checks that names written for the server read back as they were.
pub fn names(bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);
    let decoded = utf7::decode(&text);
    let _ = guess_role(&decoded);
    assert_eq!(utf7::decode(&utf7::encode(&text)), text);
    let _ = labels::label_names(text.split(' '));
    let _ = flag_name(Flag::Custom(text.clone()));
    if labels::label_ok(&text) && !text.starts_with('\\') {
        let wire = labels::label_wire(&text);
        let inner = &wire[1..wire.len() - 1];
        let back = labels::label_name(inner);
        let system = [
            "Inbox",
            "Sent",
            "Important",
            "Starred",
            "Drafts",
            "Trash",
            "Spam",
        ];
        if !system.contains(&text.as_ref()) {
            assert_eq!(back, text);
        }
    }
    let _ = quote(&text);
    let mut uids: Vec<u32> = bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_le_bytes(*c))
        .collect();
    uids.sort_unstable();
    uids.dedup();
    let _ = uid_set(&uids);
}

/// Reads `bytes` as a cursor this crate wrote.
pub fn cursor(bytes: &[u8]) {
    if let Ok(c) = CursorState::decode(bytes) {
        assert_eq!(CursorState::decode(&c.encode()), Ok(c));
    }
}
