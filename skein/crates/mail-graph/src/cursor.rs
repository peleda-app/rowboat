use std::collections::BTreeMap;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use skein_core::Flags;
use skein_mail::Cursor;

const MAGIC: &[u8; 4] = b"SKG1";
const MAX_DECODED: usize = 256 * 1024 * 1024;

/// Where a folder's delta round stands, and every message seen in it with a hash of its flags.
///
/// Messages are kept as 64-bit hashes of their ids: Graph names the id in every change, so the
/// hash is enough to tell a new message from a known one and to drop `@removed` entries for
/// messages never reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeltaCursor {
    pub folder: String,
    pub link: String,
    pub known: BTreeMap<u64, u32>,
}

#[derive(Serialize, Deserialize)]
struct Header {
    f: String,
    l: String,
}

pub(crate) fn fnv(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

pub(crate) fn id_key(id: &str) -> u64 {
    fnv(id.as_bytes())
}

pub(crate) fn flags_key(flags: &Flags) -> u32 {
    let joined: Vec<&str> = flags.iter().collect();
    (fnv(joined.join("\n").as_bytes()) & 0xffff_ffff) as u32
}

impl DeltaCursor {
    pub(crate) fn encode(&self) -> Cursor {
        let header = serde_json::to_vec(&Header {
            f: self.folder.clone(),
            l: self.link.clone(),
        })
        .expect("a header serializes");
        let mut plain = Vec::with_capacity(4 + header.len() + self.known.len() * 12);
        plain.extend_from_slice(&(header.len() as u32).to_le_bytes());
        plain.extend_from_slice(&header);
        for (id, flags) in &self.known {
            plain.extend_from_slice(&id.to_le_bytes());
            plain.extend_from_slice(&flags.to_le_bytes());
        }
        let mut out = MAGIC.to_vec();
        out.extend(zstd::bulk::compress(&plain, 3).expect("zstd compresses in memory"));
        Cursor(Bytes::from(out))
    }

    /// `None` for anything this version did not write.
    pub(crate) fn decode(cursor: &Cursor) -> Option<Self> {
        let body = cursor.0.strip_prefix(MAGIC.as_slice())?;
        let plain = zstd::bulk::decompress(body, MAX_DECODED).ok()?;
        let len = u32::from_le_bytes(plain.get(..4)?.try_into().ok()?) as usize;
        let header: Header = serde_json::from_slice(plain.get(4..4 + len)?).ok()?;
        let rest = plain.get(4 + len..)?;
        if rest.len() % 12 != 0 {
            return None;
        }
        let known = rest
            .as_chunks::<12>()
            .0
            .iter()
            .map(|c| {
                let (id, flags) = c.split_at(8);
                (
                    u64::from_le_bytes(id.try_into().unwrap()),
                    u32::from_le_bytes(flags.try_into().unwrap()),
                )
            })
            .collect();
        Some(Self {
            folder: header.f,
            link: header.l,
            known,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_refuses_foreign_bytes() {
        let cursor = DeltaCursor {
            folder: "AAMkFolder".into(),
            link: "https://graph.example.com/v1.0/me/mailFolders/x/messages/delta?$deltatoken=1"
                .into(),
            known: (0..1000u64).map(|i| (i * 7919, i as u32)).collect(),
        };
        assert_eq!(DeltaCursor::decode(&cursor.encode()), Some(cursor));
        assert_eq!(
            DeltaCursor::decode(&Cursor(Bytes::from_static(b"{}"))),
            None
        );
        assert_eq!(
            DeltaCursor::decode(&Cursor(Bytes::from_static(b"SKG1garbage"))),
            None
        );
        assert_ne!(
            flags_key(&Flags::new(["\\Seen"])),
            flags_key(&Flags::default())
        );
    }
}
