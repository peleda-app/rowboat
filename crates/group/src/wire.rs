//! Frames of the node's link protocols: a 4-byte big-endian length, then a postcard message
//! with exactly one accepted encoding.

use std::time::Duration;

use baton_link::Duplex;
use baton_seal::{Context, Key};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::MembershipError;

/// Reads one frame of at most `max` bytes within `limit`: [`MembershipError::Malformed`] when
/// the length is over `max`, [`MembershipError::TimedOut`] after `limit`,
/// [`MembershipError::Unreachable`] when the stream ends or fails.
pub async fn read_frame(
    stream: &mut dyn Duplex,
    max: usize,
    limit: Duration,
) -> Result<Vec<u8>, MembershipError> {
    let read = async {
        let mut len = [0u8; 4];
        stream
            .read_exact(&mut len)
            .await
            .map_err(|_| MembershipError::Unreachable)?;
        let len = u32::from_be_bytes(len) as usize;
        if len > max {
            return Err(MembershipError::Malformed);
        }
        let mut buf = vec![0u8; len];
        stream
            .read_exact(&mut buf)
            .await
            .map_err(|_| MembershipError::Unreachable)?;
        Ok(buf)
    };
    tokio::time::timeout(limit, read)
        .await
        .map_err(|_| MembershipError::TimedOut)?
}

/// Writes one frame within `limit`.
pub async fn write_frame(
    stream: &mut dyn Duplex,
    bytes: &[u8],
    limit: Duration,
) -> Result<(), MembershipError> {
    let len = u32::try_from(bytes.len()).map_err(|_| MembershipError::Malformed)?;
    let write = async {
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(bytes).await?;
        stream.flush().await
    };
    tokio::time::timeout(limit, write)
        .await
        .map_err(|_| MembershipError::TimedOut)?
        .map_err(|_| MembershipError::Unreachable)
}

/// The postcard encoding of `value`.
pub fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    postcard::to_stdvec(value).expect("wire messages serialize")
}

/// Decodes and re-encodes, so a message has exactly one accepted encoding.
pub fn decode<T: Serialize + DeserializeOwned>(bytes: &[u8]) -> Result<T, MembershipError> {
    let value: T = postcard::from_bytes(bytes).map_err(|_| MembershipError::Malformed)?;
    if encode(&value) != bytes {
        return Err(MembershipError::Malformed);
    }
    Ok(value)
}

const SEAL_PURPOSE: &str = "rowboat-pair-v1";

/// Both directions of a sealed pairing channel: every message is sealed under its direction's
/// key with its sequence number in the context, so a dropped, replayed, reordered or reflected
/// message fails to open.
pub(crate) struct Sealed {
    tx: Key,
    rx: Key,
    sent: u64,
    received: u64,
}

impl Sealed {
    pub(crate) fn new(tx: [u8; 32], rx: [u8; 32]) -> Self {
        Self {
            tx: Key::from_bytes(tx),
            rx: Key::from_bytes(rx),
            sent: 0,
            received: 0,
        }
    }

    pub(crate) fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, MembershipError> {
        let n = self.sent.to_be_bytes();
        self.sent += 1;
        baton_seal::seal(&self.tx, Context::new(SEAL_PURPOSE, &n), plaintext)
            .map_err(|_| MembershipError::Storage)
    }

    pub(crate) fn open(&mut self, sealed: &[u8]) -> Result<Vec<u8>, MembershipError> {
        let n = self.received.to_be_bytes();
        let plain = baton_seal::open(&self.rx, Context::new(SEAL_PURPOSE, &n), sealed)
            .map_err(|_| MembershipError::Malformed)?;
        self.received += 1;
        Ok(plain.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_messages_open_once_and_in_order() {
        let mut a = Sealed::new([1; 32], [2; 32]);
        let mut b = Sealed::new([2; 32], [1; 32]);
        let m0 = a.seal(b"zero").unwrap();
        let m1 = a.seal(b"one").unwrap();
        assert!(b.open(&m1).is_err(), "out of order");
        assert_eq!(b.open(&m0).unwrap(), b"zero");
        assert!(b.open(&m0).is_err(), "replayed");
        assert_eq!(b.open(&m1).unwrap(), b"one");
        let back = b.seal(b"x").unwrap();
        assert!(b.open(&back).is_err(), "reflected");
        let mut flipped = a.seal(b"two").unwrap();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        assert!(b.open(&flipped).is_err(), "bit flipped");
    }

    #[test]
    fn non_canonical_encodings_are_refused() {
        let bytes = encode(&(7u64, true));
        assert_eq!(decode::<(u64, bool)>(&bytes).unwrap(), (7, true));
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(decode::<(u64, bool)>(&longer).is_err());
        assert!(
            decode::<(u64, bool)>(&[0x87, 0x00, 0x01]).is_err(),
            "overlong varint"
        );
    }
}
