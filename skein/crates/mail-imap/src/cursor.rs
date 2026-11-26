//! The opaque cursor of one mailbox: what the server looked like after the last `changes` call.
//!
//! Layout: one version byte, then a zstd frame holding the header (`UIDVALIDITY`, `UIDNEXT`,
//! `HIGHESTMODSEQ`, bits), a table of distinct flag and label sets, and three columns over the
//! known UIDs in ascending order: UID deltas, flag-set indexes and, on Gmail, zigzag deltas of
//! `X-GM-MSGID`. Every number is a LEB128 varint. Mailboxes rarely have more than a few dozen
//! distinct flag sets, so a 100k-message folder needs two bytes per message before compression.

use std::collections::{BTreeMap, HashMap};

const VERSION: u8 = 1;
const ZSTD_LEVEL: i32 = 3;
/// Largest decompressed cursor accepted, about ten million messages.
const MAX_DECODED: usize = 128 * 1024 * 1024;

const HAS_MODSEQ: u8 = 1;
const GMAIL: u8 = 2;
const PARTIAL: u8 = 4;

/// The flags and labels of one message, each sorted and without repeats.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub(crate) struct Snapshot {
    pub flags: Vec<String>,
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    msgid: u64,
    state: u32,
}

/// A cursor that cannot be read.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Unreadable;

/// The decoded cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CursorState {
    pub validity: u32,
    pub uidnext: u32,
    pub modseq: Option<u64>,
    pub gmail: bool,
    /// Some messages below `uidnext` may not be known yet (a paged listing, a message that did
    /// not come back from a fetch); the next call has to search the whole mailbox.
    pub partial: bool,
    entries: BTreeMap<u32, Entry>,
    states: Vec<Snapshot>,
    index: HashMap<Snapshot, u32>,
}

impl CursorState {
    pub(crate) fn new(validity: u32, gmail: bool) -> Self {
        Self {
            validity,
            uidnext: 0,
            modseq: None,
            gmail,
            partial: true,
            entries: BTreeMap::new(),
            states: Vec::new(),
            index: HashMap::new(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn contains(&self, uid: u32) -> bool {
        self.entries.contains_key(&uid)
    }

    pub(crate) fn uids(&self) -> impl Iterator<Item = u32> + '_ {
        self.entries.keys().copied()
    }

    /// The `X-GM-MSGID` (0 when unknown) and the flags and labels last seen.
    pub(crate) fn get(&self, uid: u32) -> Option<(u64, &Snapshot)> {
        self.entries
            .get(&uid)
            .map(|e| (e.msgid, &self.states[e.state as usize]))
    }

    pub(crate) fn insert(&mut self, uid: u32, msgid: u64, snapshot: Snapshot) {
        let state = self.intern(snapshot);
        self.entries.insert(uid, Entry { msgid, state });
    }

    pub(crate) fn set(&mut self, uid: u32, snapshot: Snapshot) {
        let state = self.intern(snapshot);
        if let Some(entry) = self.entries.get_mut(&uid) {
            entry.state = state;
        }
    }

    /// Forgets `uid`, returning its `X-GM-MSGID`.
    pub(crate) fn remove(&mut self, uid: u32) -> Option<u64> {
        self.entries.remove(&uid).map(|e| e.msgid)
    }

    fn intern(&mut self, snapshot: Snapshot) -> u32 {
        if let Some(&i) = self.index.get(&snapshot) {
            return i;
        }
        let i = self.states.len() as u32;
        self.states.push(snapshot.clone());
        self.index.insert(snapshot, i);
        i
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut used: Vec<u32> = Vec::new();
        let mut remap: HashMap<u32, u32> = HashMap::new();
        for entry in self.entries.values() {
            remap.entry(entry.state).or_insert_with(|| {
                used.push(entry.state);
                (used.len() - 1) as u32
            });
        }
        let mut out = Vec::with_capacity(16 + self.entries.len() * 3);
        put(&mut out, u64::from(self.validity));
        put(&mut out, u64::from(self.uidnext));
        let mut bits = 0;
        if self.modseq.is_some() {
            bits |= HAS_MODSEQ;
        }
        if self.gmail {
            bits |= GMAIL;
        }
        if self.partial {
            bits |= PARTIAL;
        }
        out.push(bits);
        if let Some(modseq) = self.modseq {
            put(&mut out, modseq);
        }
        put(&mut out, used.len() as u64);
        for &state in &used {
            let snapshot = &self.states[state as usize];
            for list in [&snapshot.flags, &snapshot.labels] {
                put(&mut out, list.len() as u64);
                for item in list {
                    put(&mut out, item.len() as u64);
                    out.extend_from_slice(item.as_bytes());
                }
            }
        }
        put(&mut out, self.entries.len() as u64);
        let mut previous = 0u32;
        for &uid in self.entries.keys() {
            put(&mut out, u64::from(uid - previous));
            previous = uid;
        }
        for entry in self.entries.values() {
            put(&mut out, u64::from(remap[&entry.state]));
        }
        if self.gmail {
            let mut previous = 0u64;
            for entry in self.entries.values() {
                put(&mut out, zigzag(entry.msgid.wrapping_sub(previous) as i64));
                previous = entry.msgid;
            }
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
        let validity = u32::try_from(r.num()?).map_err(|_| Unreadable)?;
        let uidnext = u32::try_from(r.num()?).map_err(|_| Unreadable)?;
        let bits = r.byte()?;
        let modseq = if bits & HAS_MODSEQ != 0 {
            Some(r.num()?)
        } else {
            None
        };
        let mut cursor = Self::new(validity, bits & GMAIL != 0);
        cursor.uidnext = uidnext;
        cursor.modseq = modseq;
        cursor.partial = bits & PARTIAL != 0;
        let states = r.count()?;
        for _ in 0..states {
            let mut lists = [Vec::new(), Vec::new()];
            for list in &mut lists {
                for _ in 0..r.count()? {
                    let len = r.count()?;
                    let text = std::str::from_utf8(r.take(len)?).map_err(|_| Unreadable)?;
                    list.push(text.to_owned());
                }
            }
            let [flags, labels] = lists;
            let snapshot = Snapshot { flags, labels };
            if cursor.index.contains_key(&snapshot) {
                return Err(Unreadable);
            }
            cursor.intern(snapshot);
        }
        let count = r.count()?;
        let mut uids = Vec::with_capacity(count);
        let mut uid = 0u32;
        for _ in 0..count {
            let delta = u32::try_from(r.num()?).map_err(|_| Unreadable)?;
            if delta == 0 {
                return Err(Unreadable);
            }
            uid = uid.checked_add(delta).ok_or(Unreadable)?;
            uids.push(uid);
        }
        let mut indexes = Vec::with_capacity(count);
        for _ in 0..count {
            let state = u32::try_from(r.num()?).map_err(|_| Unreadable)?;
            if state as usize >= cursor.states.len() {
                return Err(Unreadable);
            }
            indexes.push(state);
        }
        let mut msgid = 0u64;
        for (uid, state) in uids.into_iter().zip(indexes) {
            if cursor.gmail {
                msgid = msgid.wrapping_add(unzigzag(r.num()?) as u64);
            }
            cursor.entries.insert(uid, Entry { msgid, state });
        }
        if r.at != data.len() {
            return Err(Unreadable);
        }
        Ok(cursor)
    }
}

fn put(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn zigzag(value: i64) -> u64 {
    ((value << 1) ^ (value >> 63)) as u64
}

fn unzigzag(value: u64) -> i64 {
    ((value >> 1) as i64) ^ -((value & 1) as i64)
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
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let b = self.byte()?;
            value |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(Unreadable)
    }

    /// A length or count, which can never exceed the bytes left.
    fn count(&mut self) -> Result<usize, Unreadable> {
        let n = usize::try_from(self.num()?).map_err(|_| Unreadable)?;
        if n > self.data.len() - self.at {
            return Err(Unreadable);
        }
        Ok(n)
    }

    fn take(&mut self, len: usize) -> Result<&[u8], Unreadable> {
        let end = self.at.checked_add(len).ok_or(Unreadable)?;
        let slice = self.data.get(self.at..end).ok_or(Unreadable)?;
        self.at = end;
        Ok(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(flags: &[&str], labels: &[&str]) -> Snapshot {
        Snapshot {
            flags: flags.iter().map(|s| (*s).to_owned()).collect(),
            labels: labels.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn round_trips() {
        let mut c = CursorState::new(42, true);
        c.uidnext = 900;
        c.modseq = Some(123_456_789);
        c.partial = false;
        c.insert(3, 1_700_000_000_000_000_001, snap(&["\\Seen"], &["Inbox"]));
        c.insert(7, 1_600_000_000_000_000_000, snap(&[], &[]));
        c.insert(
            899,
            1_700_000_000_000_000_002,
            snap(&["\\Seen"], &["Inbox"]),
        );
        c.set(7, snap(&["$Work", "\\Flagged"], &["Работа"]));
        let decoded = CursorState::decode(&c.encode()).unwrap();
        assert_eq!(decoded.validity, 42);
        assert_eq!(decoded.uidnext, 900);
        assert_eq!(decoded.modseq, Some(123_456_789));
        assert!(decoded.gmail && !decoded.partial);
        assert_eq!(decoded.uids().collect::<Vec<_>>(), [3, 7, 899]);
        for uid in [3, 7, 899] {
            assert_eq!(decoded.get(uid), c.get(uid));
        }
        assert_eq!(decoded.states.len(), 2, "unused flag sets are dropped");

        let empty = CursorState::new(1, false);
        let back = CursorState::decode(&empty.encode()).unwrap();
        assert_eq!(back.len(), 0);
        assert!(back.partial && back.modseq.is_none());
    }

    #[test]
    fn stays_small_for_a_hundred_thousand_messages() {
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let sets: [&[&str]; 6] = [
            &["\\Seen"],
            &["\\Answered", "\\Seen"],
            &[],
            &["\\Flagged", "\\Seen"],
            &["$Junk", "\\Seen"],
            &["$Forwarded", "\\Seen"],
        ];
        let labels: [&[&str]; 4] = [&["Inbox"], &[], &["Work"], &["Inbox", "Important"]];
        for gmail in [false, true] {
            let mut c = CursorState::new(7, gmail);
            let mut uid = 0u32;
            let mut msgid = 1_800_000_000_000_000_000u64;
            for _ in 0..100_000 {
                let r = next();
                uid += 1 + (r % 8 == 0) as u32 * (r >> 8) as u32 % 50;
                msgid += 1 + (r >> 16) % 5_000_000_000;
                let flags = sets[(r >> 32) as usize % sets.len()];
                let l = if gmail {
                    labels[(r >> 40) as usize % labels.len()]
                } else {
                    &[]
                };
                c.insert(uid, if gmail { msgid } else { 0 }, snap(flags, l));
            }
            c.uidnext = uid + 1;
            let bytes = c.encode();
            let limit = if gmail { 768 * 1024 } else { 160 * 1024 };
            assert!(bytes.len() < limit, "{} bytes, gmail {gmail}", bytes.len());
            let back = CursorState::decode(&bytes).unwrap();
            assert_eq!(back.len(), 100_000);
            assert_eq!(back.get(uid), c.get(uid));
            assert_eq!(back, CursorState::decode(&back.encode()).unwrap());
        }
    }

    #[test]
    fn refuses_damaged_cursors() {
        let mut c = CursorState::new(5, false);
        c.insert(1, 0, snap(&["\\Seen"], &[]));
        let good = c.encode();
        assert!(CursorState::decode(&[]).is_err());
        assert!(CursorState::decode(&[9]).is_err());
        let mut wrong_version = good.clone();
        wrong_version[0] = 2;
        assert!(CursorState::decode(&wrong_version).is_err());
        assert!(CursorState::decode(&good[..good.len() - 1]).is_err());
        let mut trailing = vec![0u8; 0];
        put(&mut trailing, 5);
        put(&mut trailing, 0);
        trailing.push(0);
        put(&mut trailing, 0);
        put(&mut trailing, 0);
        trailing.push(0xff);
        let mut framed = vec![VERSION];
        framed.extend(zstd::bulk::compress(&trailing, 1).unwrap());
        assert!(CursorState::decode(&framed).is_err());
        let mut huge = vec![0u8; 0];
        put(&mut huge, 5);
        put(&mut huge, 0);
        huge.push(0);
        put(&mut huge, u64::MAX >> 1);
        let mut framed = vec![VERSION];
        framed.extend(zstd::bulk::compress(&huge, 1).unwrap());
        assert!(CursorState::decode(&framed).is_err(), "counts are bounded");
    }
}
