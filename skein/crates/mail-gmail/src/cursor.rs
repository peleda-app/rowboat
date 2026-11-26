//! The opaque cursor of one mailbox: where the listing or the history feed stands and which
//! messages the mailbox held after the last `changes` call.
//!
//! Layout: one version byte, then a zstd frame holding the phase (with the `messages.list` page
//! token while listing), the history id, the known message ids that are canonical lowercase hex
//! numbers as ascending LEB128 deltas, and any other ids as length-prefixed strings. Gmail ids
//! grow with time, so neighbouring ids are close and a delta takes five to six bytes.

use std::collections::BTreeSet;

const VERSION: u8 = 1;
const ZSTD_LEVEL: i32 = 3;
/// Largest decompressed cursor accepted, far beyond ten million messages.
const MAX_DECODED: usize = 128 * 1024 * 1024;
const MAX_STRING: usize = 4096;

const LISTING: u8 = 0;
const TRACKING: u8 = 1;

/// What the next `changes` call does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Listing every message; `token` is the next `messages.list` page, `None` for the first.
    Listing { token: Option<String> },
    /// Following `history.list` from `history_id`.
    Tracking,
}

/// A cursor that cannot be read.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Unreadable;

/// The decoded cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CursorState {
    pub phase: Phase,
    /// Every change after this history id is still to be read.
    pub history_id: u64,
    numeric: BTreeSet<u64>,
    other: BTreeSet<String>,
}

/// The id as a number when it is canonical lowercase hex (no leading zero), so that the number
/// stands for exactly one id.
fn numeric(id: &str) -> Option<u64> {
    if id.is_empty() || id.len() > 16 || id.starts_with('0') {
        return None;
    }
    if !id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    u64::from_str_radix(id, 16).ok()
}

impl CursorState {
    pub(crate) fn listing(history_id: u64) -> Self {
        Self {
            phase: Phase::Listing { token: None },
            history_id,
            numeric: BTreeSet::new(),
            other: BTreeSet::new(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.numeric.len() + self.other.len()
    }

    pub(crate) fn contains(&self, id: &str) -> bool {
        match numeric(id) {
            Some(n) => self.numeric.contains(&n),
            None => self.other.contains(id),
        }
    }

    pub(crate) fn insert(&mut self, id: &str) {
        match numeric(id) {
            Some(n) => self.numeric.insert(n),
            None => self.other.insert(id.to_owned()),
        };
    }

    pub(crate) fn remove(&mut self, id: &str) -> bool {
        match numeric(id) {
            Some(n) => self.numeric.remove(&n),
            None => self.other.remove(id),
        }
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + self.numeric.len() * 6);
        match &self.phase {
            Phase::Listing { token } => {
                out.push(LISTING);
                put_str(&mut out, token.as_deref().unwrap_or(""));
            }
            Phase::Tracking => out.push(TRACKING),
        }
        put(&mut out, self.history_id);
        put(&mut out, self.numeric.len() as u64);
        let mut prev = 0u64;
        for &n in &self.numeric {
            put(&mut out, n - prev);
            prev = n;
        }
        put(&mut out, self.other.len() as u64);
        for id in &self.other {
            put_str(&mut out, id);
        }
        let mut framed = vec![VERSION];
        framed.extend(zstd::bulk::compress(&out, ZSTD_LEVEL).expect("zstd compresses in memory"));
        framed
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Unreadable> {
        let (&version, frame) = bytes.split_first().ok_or(Unreadable)?;
        if version != VERSION {
            return Err(Unreadable);
        }
        let data = zstd::bulk::decompress(frame, MAX_DECODED).map_err(|_| Unreadable)?;
        let mut r = Reader { data: &data, at: 0 };
        let phase = match r.byte()? {
            LISTING => {
                let token = r.string()?;
                Phase::Listing {
                    token: (!token.is_empty()).then_some(token),
                }
            }
            TRACKING => Phase::Tracking,
            _ => return Err(Unreadable),
        };
        let history_id = r.num()?;
        let count = r.count()?;
        let mut numeric = BTreeSet::new();
        let mut prev = 0u64;
        for i in 0..count {
            let delta = r.num()?;
            if i > 0 && delta == 0 {
                return Err(Unreadable);
            }
            prev = prev.checked_add(delta).ok_or(Unreadable)?;
            numeric.insert(prev);
        }
        let count = r.count()?;
        let mut other = BTreeSet::new();
        for _ in 0..count {
            other.insert(r.string()?);
        }
        if r.at != data.len() {
            return Err(Unreadable);
        }
        Ok(Self {
            phase,
            history_id,
            numeric,
            other,
        })
    }
}

fn put(out: &mut Vec<u8>, mut n: u64) {
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put(out, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn byte(&mut self) -> Result<u8, Unreadable> {
        let b = *self.data.get(self.at).ok_or(Unreadable)?;
        self.at += 1;
        Ok(b)
    }

    fn num(&mut self) -> Result<u64, Unreadable> {
        let mut n = 0u64;
        for shift in (0..64).step_by(7) {
            let b = self.byte()?;
            n |= u64::from(b & 0x7f).checked_shl(shift).ok_or(Unreadable)?;
            if b & 0x80 == 0 {
                return Ok(n);
            }
        }
        Err(Unreadable)
    }

    /// A count that cannot exceed the bytes left, so a forged count cannot allocate.
    fn count(&mut self) -> Result<usize, Unreadable> {
        let n = usize::try_from(self.num()?).map_err(|_| Unreadable)?;
        if n > self.data.len() - self.at {
            return Err(Unreadable);
        }
        Ok(n)
    }

    fn string(&mut self) -> Result<String, Unreadable> {
        let len = self.count()?;
        if len > MAX_STRING {
            return Err(Unreadable);
        }
        let s = std::str::from_utf8(&self.data[self.at..self.at + len]).map_err(|_| Unreadable)?;
        self.at += len;
        Ok(s.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let mut c = CursorState::listing(4711);
        c.phase = Phase::Listing {
            token: Some("page-2".into()),
        };
        for id in [
            "18c5f2a1b3d4e5f6",
            "18c5f2a1b3d4e5f7",
            "1",
            "0abc",
            "Weird-Id",
        ] {
            c.insert(id);
        }
        assert_eq!(c.len(), 5);
        let back = CursorState::decode(&c.encode()).unwrap();
        assert_eq!(back, c);
        assert!(back.contains("0abc") && back.contains("Weird-Id") && back.contains("1"));
        assert!(!back.contains("abc"));
        c.phase = Phase::Tracking;
        assert!(c.remove("1"));
        assert!(!c.remove("1"));
        assert_eq!(CursorState::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn a_hundred_thousand_ids_stay_small() {
        let mut c = CursorState::listing(1);
        c.phase = Phase::Tracking;
        let mut id: u64 = 0x18c0_0000_0000_0000;
        let mut seed: u64 = 0x2545_f491_4f6c_dd1d;
        for _ in 0..100_000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            // About one message every half hour on average, in Gmail's millisecond-based ids.
            id += ((seed % 3_600_000) << 20) | (seed & 0xfffff);
            c.insert(&format!("{id:x}"));
        }
        let encoded = c.encode();
        eprintln!("100k ids: {} bytes", encoded.len());
        assert!(encoded.len() < 700_000, "{} bytes", encoded.len());
        assert_eq!(CursorState::decode(&encoded).unwrap(), c);
    }

    #[test]
    fn rejects_garbage() {
        assert!(CursorState::decode(b"").is_err());
        assert!(CursorState::decode(b"\x02abc").is_err());
        assert!(CursorState::decode(b"\x01not zstd").is_err());
        let mut forged = vec![TRACKING];
        put(&mut forged, 1);
        put(&mut forged, u64::MAX >> 1);
        let mut framed = vec![VERSION];
        framed.extend(zstd::bulk::compress(&forged, 1).unwrap());
        assert!(CursorState::decode(&framed).is_err(), "counts are bounded");
        let mut trailing = CursorState::listing(1).encode();
        let inner = zstd::bulk::decompress(&trailing[1..], 1024).unwrap();
        let mut longer = inner.clone();
        longer.push(0);
        trailing.truncate(1);
        trailing.extend(zstd::bulk::compress(&longer, 1).unwrap());
        assert!(CursorState::decode(&trailing).is_err());
    }
}
