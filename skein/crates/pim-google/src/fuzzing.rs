//! Entry points for the fuzz targets in `fuzz/`. Not part of the public API.

use bytes::Bytes;
use skein_pim::Cursor;

use crate::cursor::{Feed, Position};
use crate::{calendar, http, people};

/// Reads `bytes` as every Calendar and People API answer a session reads, an error body and a
/// cursor.
pub fn page(bytes: &[u8]) {
    let _ = http::reasons(bytes);
    calendar::fuzz(bytes);
    people::fuzz(bytes);
    let raw = Cursor(Bytes::copy_from_slice(bytes));
    for feed in [Feed::Events, Feed::Contacts] {
        if let Some(pos) = Position::read(&raw, feed) {
            assert_eq!(Position::read(&pos.cursor(), feed), Some(pos));
        }
    }
}
