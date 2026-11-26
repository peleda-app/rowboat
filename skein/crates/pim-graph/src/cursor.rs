use std::collections::BTreeMap;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use skein_pim::Cursor;

const MAGIC: &[u8; 4] = b"SPG1";
const MAX_DECODED: usize = 512 * 1024 * 1024;

/// Where one collection's changes stand, plus changes already read from Graph but not handed
/// out yet, so a page never exceeds the caller's limit.
///
/// A contact folder keeps the delta link to ask next (`link`); a calendar, which Graph v1.0
/// cannot give a delta for without expanding series, keeps every known event with its
/// `changeKey` (`known`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GraphCursor {
    pub c: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub up: Vec<(String, Option<String>)>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gone: Vec<String>,
    /// The link is an `@odata.nextLink`: Graph has more pages of this round.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub next: bool,
    /// The round started without a delta token, so `@removed` entries name nothing reported.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub initial: bool,
}

impl GraphCursor {
    pub fn fresh(collection: &str) -> Self {
        Self {
            c: collection.to_owned(),
            ..Self::default()
        }
    }

    pub fn encode(&self) -> Cursor {
        let plain = serde_json::to_vec(self).expect("a plain struct serializes");
        let mut out = MAGIC.to_vec();
        out.extend(zstd::bulk::compress(&plain, 3).expect("zstd compresses in memory"));
        Cursor(Bytes::from(out))
    }

    /// The cursor in `raw` for `collection`; `None` when it is not one this provider made for it.
    pub fn decode(raw: &Cursor, collection: &str) -> Option<Self> {
        let packed = raw.0.strip_prefix(MAGIC.as_slice())?;
        let plain = zstd::bulk::decompress(packed, MAX_DECODED).ok()?;
        let c: Self = serde_json::from_slice(&plain).ok()?;
        (c.c == collection && c.link.is_some() != c.known.is_some()).then_some(c)
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
        let mut c = GraphCursor::fresh("contacts");
        c.link = Some("https://graph.example.com/v1.0/me/contacts/delta?$deltatoken=1".into());
        c.up = vec![("AAMk1".into(), Some("ck1".into()))];
        assert_eq!(
            GraphCursor::decode(&c.encode(), "contacts"),
            Some(c.clone())
        );
        assert_eq!(GraphCursor::decode(&c.encode(), "contacts/other"), None);
        assert_eq!(
            GraphCursor::decode(&GraphCursor::fresh("contacts").encode(), "contacts"),
            None
        );
        assert_eq!(
            GraphCursor::decode(&Cursor(Bytes::from_static(b"SPG1junk")), "contacts"),
            None
        );
        c.known = Some(BTreeMap::new());
        assert_eq!(GraphCursor::decode(&c.encode(), "contacts"), None);
    }
}
