//! Cursors: which feed they belong to, the sync token reached, and the page token of a listing
//! in progress. Without a sync token a listing in progress is a full one.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use skein_pim::Cursor;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub(crate) enum Feed {
    #[serde(rename = "e")]
    Events,
    #[serde(rename = "c")]
    Contacts,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub(crate) struct Position {
    v: u8,
    f: Feed,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p: Option<String>,
}

impl Position {
    pub(crate) fn start(feed: Feed) -> Self {
        Self {
            v: 1,
            f: feed,
            s: None,
            p: None,
        }
    }

    pub(crate) fn new(feed: Feed, sync: Option<String>, page: Option<String>) -> Self {
        Self {
            v: 1,
            f: feed,
            s: sync,
            p: page,
        }
    }

    /// `None` when the cursor is not one of ours for `feed`.
    pub(crate) fn read(cursor: &Cursor, feed: Feed) -> Option<Self> {
        let pos: Self = serde_json::from_slice(&cursor.0).ok()?;
        (pos.v == 1 && pos.f == feed && (pos.s.is_some() || pos.p.is_some())).then_some(pos)
    }

    pub(crate) fn cursor(&self) -> Cursor {
        Cursor(Bytes::from(
            serde_json::to_vec(self).expect("a cursor serializes"),
        ))
    }

    pub(crate) fn full(&self) -> bool {
        self.s.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursors_round_trip_and_belong_to_one_feed() {
        let pos = Position::new(Feed::Events, Some("tok".into()), Some("page".into()));
        let c = pos.cursor();
        assert_eq!(Position::read(&c, Feed::Events), Some(pos));
        assert_eq!(Position::read(&c, Feed::Contacts), None);
        assert_eq!(
            Position::read(&Cursor(Bytes::from_static(b"\xff junk")), Feed::Events),
            None
        );
        assert_eq!(
            Position::read(&Position::start(Feed::Events).cursor(), Feed::Events),
            None,
            "a cursor with neither token says nothing"
        );
    }
}
