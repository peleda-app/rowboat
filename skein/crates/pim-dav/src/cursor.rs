use std::collections::BTreeMap;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use skein_pim::Cursor;

const VERSION: u8 = 1;

/// What a cursor holds: where the server's change list stands (a sync token, or the ETag of
/// every known object where `sync-collection` is missing), plus changes already read from the
/// server but not yet handed out, so a page never exceeds the caller's limit.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DavCursor {
    pub v: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etags: Option<BTreeMap<String, Option<String>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ctag: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub up: Vec<(String, Option<String>)>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gone: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

impl DavCursor {
    pub fn fresh() -> Self {
        Self {
            v: VERSION,
            ..Self::default()
        }
    }

    pub fn encode(&self) -> Cursor {
        Cursor(Bytes::from(
            serde_json::to_vec(self).expect("a plain struct serializes"),
        ))
    }

    /// The cursor in `raw`; `None` when it is not one this provider made.
    pub fn decode(raw: &Cursor) -> Option<Self> {
        let c: Self = serde_json::from_slice(&raw.0).ok()?;
        let has_mode = c.token.is_some() != c.etags.is_some();
        (c.v == VERSION && has_mode).then_some(c)
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
        let mut c = DavCursor::fresh();
        c.token = Some("http://example.com/sync/1".into());
        c.up = vec![("/c/a.ics".into(), Some("\"1\"".into()))];
        assert_eq!(DavCursor::decode(&c.encode()), Some(c));
        assert_eq!(DavCursor::decode(&DavCursor::fresh().encode()), None);
        assert_eq!(DavCursor::decode(&Cursor(Bytes::from_static(b"1:2"))), None);
        let mut both = DavCursor::fresh();
        both.token = Some("t".into());
        both.etags = Some(BTreeMap::new());
        assert_eq!(DavCursor::decode(&both.encode()), None);
    }
}
