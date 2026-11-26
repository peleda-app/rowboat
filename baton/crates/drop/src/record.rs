//! Byte formats for persistent [`DropStore`](crate::DropStore)s, so every store on disk keeps the
//! same versioned records and decodes them with the same strict checks.
//!
//! - A box record is `[RECORD_VERSION] ‖ postcard(BoxInfo)`, keyed by the 32-byte box id.
//! - A message is keyed by `box id ‖ message id (big endian)`, so keys sort by box, then id; its
//!   value is `stored_at (big endian i64) ‖ bytes`.
//!
//! Decoding refuses unknown versions, trailing bytes, policies outside the limits, inconsistent
//! counters and messages over [`MAX_MESSAGE_CAP`], so a corrupted or planted record is reported as
//! a backend failure instead of being believed.

use baton_core::Timestamp;
use baton_mailbox::BoxId;

use crate::service::MAX_MESSAGE_CAP;
use crate::store::{BoxInfo, StoreError};

/// The version byte of box records.
pub const RECORD_VERSION: u8 = 2;

/// The length of a message key.
pub const MESSAGE_KEY_LEN: usize = 40;

/// The largest box record (a policy with the most writers fits well within it).
pub const MAX_BOX_RECORD: usize = 8 * 1024;

fn corrupt(what: &'static str) -> StoreError {
    StoreError::backend(what)
}

/// Encodes a box record.
pub fn encode_box(info: &BoxInfo) -> Vec<u8> {
    let mut out = vec![RECORD_VERSION];
    out.extend(postcard::to_stdvec(info).expect("box info encodes"));
    out
}

/// Decodes a box record written by [`encode_box`].
pub fn decode_box(raw: &[u8]) -> Result<BoxInfo, StoreError> {
    if raw.len() > MAX_BOX_RECORD {
        return Err(corrupt("box record too large"));
    }
    let Some((&RECORD_VERSION, rest)) = raw.split_first() else {
        return Err(corrupt("unknown box record version"));
    };
    let (info, tail): (BoxInfo, _) =
        postcard::take_from_bytes(rest).map_err(|_| corrupt("malformed box record"))?;
    if !tail.is_empty() {
        return Err(corrupt("trailing bytes in box record"));
    }
    info.policy
        .check()
        .map_err(|_| corrupt("box record policy out of range"))?;
    if info.count > info.policy.max_messages
        || info.bytes > info.policy.max_bytes
        || u64::from(info.count) > info.last_id
    {
        return Err(corrupt("box record counters out of range"));
    }
    Ok(info)
}

/// The key of message `msg` in box `id`.
pub fn message_key(id: &BoxId, msg: u64) -> [u8; MESSAGE_KEY_LEN] {
    let mut k = [0u8; MESSAGE_KEY_LEN];
    k[..32].copy_from_slice(id.as_bytes());
    k[32..].copy_from_slice(&msg.to_be_bytes());
    k
}

/// The box and message id of a message key.
pub fn split_message_key(raw: &[u8]) -> Result<(BoxId, u64), StoreError> {
    let k: &[u8; MESSAGE_KEY_LEN] = raw.try_into().map_err(|_| corrupt("bad message key"))?;
    let mut id = [0u8; 32];
    id.copy_from_slice(&k[..32]);
    let mut n = [0u8; 8];
    n.copy_from_slice(&k[32..]);
    Ok((BoxId(id), u64::from_be_bytes(n)))
}

/// Encodes a message value.
pub fn encode_message(stored_at: Timestamp, bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + bytes.len());
    out.extend_from_slice(&stored_at.0.to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

/// Decodes a message value written by [`encode_message`].
pub fn decode_message(raw: &[u8]) -> Result<(Timestamp, &[u8]), StoreError> {
    if raw.len() < 8 || raw.len() - 8 > MAX_MESSAGE_CAP as usize {
        return Err(corrupt("bad message record"));
    }
    let (at, bytes) = raw.split_at(8);
    let at = i64::from_be_bytes(at.try_into().expect("8 bytes"));
    Ok((Timestamp(at), bytes))
}

#[cfg(test)]
mod tests {
    use baton_mailbox::{BoxKey, BoxPolicy};
    use proptest::prelude::*;

    use super::*;

    fn info() -> BoxInfo {
        let p = BoxPolicy::new(
            BoxKey::generate().public(),
            vec![BoxKey::generate().public()],
        );
        let mut i = BoxInfo::new(
            p,
            crate::store::Admitted::Work,
            Timestamp(1_800_000_000_000),
        );
        i.last_id = 7;
        i.count = 3;
        i.bytes = 100;
        i
    }

    #[test]
    fn box_round_trip_and_refusals() {
        let i = info();
        let raw = encode_box(&i);
        assert_eq!(decode_box(&raw).unwrap(), i);
        let mut v1 = raw.clone();
        v1[0] = 1;
        assert!(
            decode_box(&v1).is_err(),
            "records before the admission class are refused"
        );
        let mut tail = raw.clone();
        tail.push(0);
        assert!(decode_box(&tail).is_err());
        assert!(decode_box(&raw[..raw.len() - 1]).is_err());
        assert!(decode_box(&[]).is_err());
        let mut bad = i.clone();
        bad.count = 8;
        assert!(decode_box(&encode_box(&bad)).is_err());
        let mut bad = i.clone();
        bad.policy.ttl_ms = 1;
        assert!(decode_box(&encode_box(&bad)).is_err());
    }

    #[test]
    fn message_keys_sort_by_box_then_id() {
        let a = BoxId([1; 32]);
        let b = BoxId([2; 32]);
        assert!(message_key(&a, u64::MAX) < message_key(&b, 0));
        assert!(message_key(&a, 255) < message_key(&a, 256));
        assert_eq!(split_message_key(&message_key(&b, 9)).unwrap(), (b, 9));
        assert!(split_message_key(&[0; 39]).is_err());
    }

    #[test]
    fn message_values_are_bounded() {
        let raw = encode_message(Timestamp(-5), b"abc");
        assert_eq!(decode_message(&raw).unwrap(), (Timestamp(-5), &b"abc"[..]));
        assert!(decode_message(&[0; 7]).is_err());
        let big = vec![0u8; 8 + MAX_MESSAGE_CAP as usize + 1];
        assert!(decode_message(&big).is_err());
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(raw in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = decode_box(&raw);
            let _ = decode_message(&raw);
            let _ = split_message_key(&raw);
        }

        #[test]
        fn message_round_trip(at in any::<i64>(), bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let raw = encode_message(Timestamp(at), &bytes);
            prop_assert_eq!(decode_message(&raw).unwrap(), (Timestamp(at), &bytes[..]));
        }
    }
}
