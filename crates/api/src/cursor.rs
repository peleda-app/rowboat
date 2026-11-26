//! The node's cursor format. Cursors are opaque to the app; this codec is shared so the node and
//! its tests agree, and its decoder has a fuzz target since cursors come back from the app.

use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};

use crate::NodeError;
use crate::types::Cursor;

const PREFIX: &str = "c1.";

/// A position in a list: the sort key and id of the last row, and its account for lists over
/// several accounts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Position {
    /// The row's sort date, milliseconds since the epoch.
    #[serde(rename = "d")]
    pub sort: i64,
    /// The row's id (a message id, or a thread id as text): 1 to 128 printable ASCII bytes.
    #[serde(rename = "i")]
    pub id: String,
    /// The row's account, for lists over several accounts.
    #[serde(rename = "a", default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

fn id_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_graphic())
}

/// The cursor for `position`.
pub fn encode(position: &Position) -> Cursor {
    let json = serde_json::to_vec(position).unwrap_or_default();
    Cursor::new(format!("{PREFIX}{}", BASE64URL_NOPAD.encode(&json)))
        .unwrap_or_else(|_| Cursor::new("c1.e30").expect("constant"))
}

/// The position in `cursor`; [`NodeError::InvalidInput`] for anything this codec did not make.
/// Never panics; linear in the cursor's length (at most 512).
pub fn decode(cursor: &Cursor) -> Result<Position, NodeError> {
    let body = cursor
        .as_str()
        .strip_prefix(PREFIX)
        .ok_or(NodeError::InvalidInput)?;
    let json = BASE64URL_NOPAD
        .decode(body.as_bytes())
        .map_err(|_| NodeError::InvalidInput)?;
    let p: Position = serde_json::from_slice(&json).map_err(|_| NodeError::InvalidInput)?;
    if !id_ok(&p.id)
        || p.account
            .as_deref()
            .is_some_and(|a| !id_ok(a) || a.len() > 64)
    {
        return Err(NodeError::InvalidInput);
    }
    Ok(p)
}
