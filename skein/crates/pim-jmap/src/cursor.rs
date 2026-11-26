use bytes::Bytes;
use serde::{Deserialize, Serialize};
use skein_pim::Cursor;

const VERSION: u8 = 1;

/// Where one collection's changes stand: the account's state for the item type, plus changes
/// already read from the server but not handed out yet, so a page never exceeds the caller's
/// limit.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct JmapCursor {
    pub v: u8,
    pub c: String,
    pub state: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub up: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gone: Vec<String>,
    /// The server said `hasMoreChanges` after `state`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub more: bool,
}

impl JmapCursor {
    pub fn fresh(collection: &str) -> Self {
        Self {
            v: VERSION,
            c: collection.to_owned(),
            ..Self::default()
        }
    }

    pub fn encode(&self) -> Cursor {
        Cursor(Bytes::from(
            serde_json::to_vec(self).expect("a plain struct serializes"),
        ))
    }

    /// The cursor in `raw` for `collection`; `None` when it is not one this provider made for it.
    pub fn decode(raw: &Cursor, collection: &str) -> Option<Self> {
        let c: Self = serde_json::from_slice(&raw.0).ok()?;
        (c.v == VERSION && c.c == collection && !c.state.is_empty()).then_some(c)
    }

    pub fn pending(&self) -> bool {
        !self.up.is_empty() || !self.gone.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_refuses_strangers() {
        let mut c = JmapCursor::fresh("calendar/b");
        c.state = "sai".into();
        c.up = vec!["e1".into()];
        assert_eq!(
            JmapCursor::decode(&c.encode(), "calendar/b"),
            Some(c.clone())
        );
        assert_eq!(JmapCursor::decode(&c.encode(), "calendar/c"), None);
        assert_eq!(
            JmapCursor::decode(&JmapCursor::fresh("calendar/b").encode(), "calendar/b"),
            None
        );
        assert_eq!(
            JmapCursor::decode(&Cursor(Bytes::from_static(b"sai")), "calendar/b"),
            None
        );
    }
}
