//! The frames of link protocol `group`.
//!
//! Every frame on a stream is `u32` big-endian length ‖ body, and every body is
//! `[VERSION] ‖ postcard(value)` with no trailing bytes. A request body is at most
//! [`MAX_REQUEST`] bytes, a reply body at most [`MAX_REPLY`]. Frames are not signed: the link
//! authenticates the peer by its key, and every entry inside carries its own signature, checked
//! by `baton-group`.

use baton_core::GroupId;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The format version of every body.
pub const VERSION: u8 = 1;
/// The largest request body, in bytes: one entry of at most `baton_group::MAX_ENTRY` bytes and
/// its framing.
pub const MAX_REQUEST: usize = baton_group::MAX_ENTRY + 256;
/// The largest reply body, in bytes.
pub const MAX_REPLY: usize = 4 * 1024 * 1024;
/// The most entries one fetch returns.
pub const MAX_FETCH: u32 = 256;

/// The head of a log: its last entry's position and hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Head {
    /// The last entry's `seq`.
    pub seq: u64,
    /// The last entry's hash.
    pub hash: [u8; 32],
}

/// A request from a client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// Asks for the server's limits.
    Hello,
    /// The head of a group's log.
    Head {
        /// The group.
        group: GroupId,
    },
    /// Entries with `seq` above `after` (from genesis when `None`), at most `limit`.
    Fetch {
        /// The group.
        group: GroupId,
        /// The last entry the client has.
        after: Option<u64>,
        /// The most entries wanted.
        limit: u32,
    },
    /// A new signed entry (its encoded form).
    Push {
        /// `baton_group::Entry::encode`.
        entry: Vec<u8>,
    },
}

/// Why the server did not carry a request out. Carries no backend detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Refusal {
    /// The peer may not read or write this group.
    Denied,
    /// The server does not hold this group.
    Unknown,
    /// Bytes that are not an entry (bad encoding, signature or size).
    Malformed,
    /// The entry breaks the group's rules at this point of the log (signer not allowed, stale
    /// or future time, invalid change).
    Invalid,
    /// The entry does not continue the log: its position is past the head. Carries the head.
    Chain(Option<Head>),
    /// Another entry already holds the entry's position.
    Fork,
    /// The log reached the server's limit of entries.
    Full,
    /// The server is at its limit of requests in progress.
    Busy,
    /// The server's store failed.
    Backend,
    /// The answer would exceed the reply limit.
    TooLarge,
    /// The request's format version is unknown.
    Version,
}

/// A reply from the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    /// The server's limits.
    Hello {
        /// The largest request body the server reads.
        max_request: u32,
        /// The largest reply body the server sends.
        max_reply: u32,
        /// The most entries one fetch returns.
        max_fetch: u32,
    },
    /// The head, or `None` while the server holds no entry of the group yet.
    Head(Option<Head>),
    /// Encoded entries, in order.
    Entries(Vec<Vec<u8>>),
    /// The pushed entry is in the log: `new` is false when it already was.
    Accepted {
        /// The head after the push.
        head: Head,
        /// Whether this push added it.
        new: bool,
    },
    /// The request was not carried out.
    Refused(Refusal),
}

/// A frame that cannot be accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// Empty, or longer than the limit.
    #[error("frame has an invalid length")]
    Length,
    /// Unknown format version.
    #[error("unknown frame version")]
    Version,
    /// Not a valid encoding, or trailing bytes.
    #[error("malformed frame")]
    Malformed,
    /// The stream failed or ended inside a frame.
    #[error("stream failed")]
    Io,
}

fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    let mut out = vec![VERSION];
    out.extend(postcard::to_stdvec(value).expect("plain values encode"));
    out
}

fn decode<T: DeserializeOwned>(body: &[u8], max: usize) -> Result<T, FrameError> {
    if body.is_empty() || body.len() > max {
        return Err(FrameError::Length);
    }
    if body[0] != VERSION {
        return Err(FrameError::Version);
    }
    match postcard::take_from_bytes::<T>(&body[1..]) {
        Ok((value, [])) => Ok(value),
        _ => Err(FrameError::Malformed),
    }
}

/// The body of `request`.
pub fn encode_request(request: &Request) -> Vec<u8> {
    encode(request)
}

/// A request body: at most [`MAX_REQUEST`] bytes, version [`VERSION`], every id valid, nothing
/// after the value.
pub fn decode_request(body: &[u8]) -> Result<Request, FrameError> {
    decode(body, MAX_REQUEST)
}

/// The body of `reply`.
pub fn encode_reply(reply: &Reply) -> Vec<u8> {
    encode(reply)
}

/// A reply body: at most `max` (and [`MAX_REPLY`]) bytes, version [`VERSION`], every id valid,
/// nothing after the value.
pub fn decode_reply(body: &[u8], max: usize) -> Result<Reply, FrameError> {
    decode(body, max.min(MAX_REPLY))
}

/// The body length announced by a frame's 4-byte prefix, if it is between 1 and `max`.
pub fn frame_len(prefix: [u8; 4], max: usize) -> Result<usize, FrameError> {
    let len = u32::from_be_bytes(prefix) as usize;
    if len == 0 || len > max {
        Err(FrameError::Length)
    } else {
        Ok(len)
    }
}

/// Writes one frame and flushes.
pub async fn write_frame<W: AsyncWrite + Unpin + ?Sized>(
    w: &mut W,
    body: &[u8],
) -> Result<(), FrameError> {
    let len = u32::try_from(body.len()).map_err(|_| FrameError::Length)?;
    w.write_all(&len.to_be_bytes())
        .await
        .map_err(|_| FrameError::Io)?;
    w.write_all(body).await.map_err(|_| FrameError::Io)?;
    w.flush().await.map_err(|_| FrameError::Io)
}

/// Reads one frame's body of at most `max` bytes. An announced length outside the limit fails
/// before any of the body is read.
pub async fn read_frame<R: AsyncRead + Unpin + ?Sized>(
    r: &mut R,
    max: usize,
) -> Result<Vec<u8>, FrameError> {
    let mut prefix = [0u8; 4];
    r.read_exact(&mut prefix)
        .await
        .map_err(|_| FrameError::Io)?;
    read_body(r, prefix, max).await
}

pub(crate) async fn read_body<R: AsyncRead + Unpin + ?Sized>(
    r: &mut R,
    prefix: [u8; 4],
    max: usize,
) -> Result<Vec<u8>, FrameError> {
    let len = frame_len(prefix, max)?;
    let mut body = Vec::new();
    (&mut *r)
        .take(len as u64)
        .read_to_end(&mut body)
        .await
        .map_err(|_| FrameError::Io)?;
    if body.len() != len {
        return Err(FrameError::Io);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn samples() -> Vec<Request> {
        let g = GroupId::new("g").unwrap();
        vec![
            Request::Hello,
            Request::Head { group: g.clone() },
            Request::Fetch {
                group: g.clone(),
                after: Some(u64::MAX),
                limit: MAX_FETCH,
            },
            Request::Fetch {
                group: g,
                after: None,
                limit: 0,
            },
            Request::Push {
                entry: vec![7; 100],
            },
        ]
    }

    fn replies() -> Vec<Reply> {
        let head = Head {
            seq: 9,
            hash: [3; 32],
        };
        vec![
            Reply::Hello {
                max_request: 1,
                max_reply: 2,
                max_fetch: 3,
            },
            Reply::Head(None),
            Reply::Head(Some(head)),
            Reply::Entries(vec![vec![1, 2], vec![]]),
            Reply::Accepted { head, new: true },
            Reply::Refused(Refusal::Chain(Some(head))),
            Reply::Refused(Refusal::Fork),
        ]
    }

    #[test]
    fn frames_round_trip() {
        for r in samples() {
            assert_eq!(decode_request(&encode_request(&r)).unwrap(), r);
        }
        for r in replies() {
            assert_eq!(decode_reply(&encode_reply(&r), MAX_REPLY).unwrap(), r);
        }
        let biggest = Request::Push {
            entry: vec![0; baton_group::MAX_ENTRY],
        };
        assert!(encode_request(&biggest).len() <= MAX_REQUEST);
    }

    #[test]
    fn bad_bodies_are_refused() {
        let body = encode_request(&Request::Hello);
        assert_eq!(decode_request(&[]), Err(FrameError::Length));
        assert_eq!(decode_request(&[2, 0]), Err(FrameError::Version));
        let mut trailing = body.clone();
        trailing.push(0);
        assert_eq!(decode_request(&trailing), Err(FrameError::Malformed));
        assert_eq!(
            decode_request(&vec![VERSION; MAX_REQUEST + 1]),
            Err(FrameError::Length)
        );
        let mut bad_id = encode_request(&Request::Head {
            group: GroupId::new("g").unwrap(),
        });
        *bad_id.last_mut().unwrap() = b'G';
        assert_eq!(decode_request(&bad_id), Err(FrameError::Malformed));
        assert_eq!(frame_len([0; 4], 10), Err(FrameError::Length));
        assert_eq!(frame_len(11u32.to_be_bytes(), 10), Err(FrameError::Length));
        assert_eq!(frame_len(10u32.to_be_bytes(), 10), Ok(10));
    }

    #[tokio::test]
    async fn frames_cross_a_stream() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let body = encode_request(&Request::Hello);
        let w = tokio::spawn(async move { write_frame(&mut a, &body).await });
        let got = read_frame(&mut b, MAX_REQUEST).await.unwrap();
        w.await.unwrap().unwrap();
        assert_eq!(decode_request(&got).unwrap(), Request::Hello);
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::spawn(async move {
            let _ = a.write_all(&100u32.to_be_bytes()).await;
            let _ = a.write_all(&[1, 2]).await;
        });
        assert_eq!(read_frame(&mut b, 1000).await, Err(FrameError::Io));
    }

    proptest! {
        #[test]
        fn arbitrary_bodies_never_panic(body in proptest::collection::vec(any::<u8>(), 0..300)) {
            if let Ok(r) = decode_request(&body) {
                prop_assert_eq!(decode_request(&encode_request(&r)).unwrap(), r);
            }
            if let Ok(r) = decode_reply(&body, MAX_REPLY) {
                prop_assert_eq!(decode_reply(&encode_reply(&r), MAX_REPLY).unwrap(), r);
            }
        }

        #[test]
        fn flipped_bits_never_change_a_request_silently(i in 0usize..64, bit in 0u8..8) {
            let r = Request::Fetch { group: GroupId::new("grp").unwrap(), after: Some(5), limit: 9 };
            let mut body = encode_request(&r);
            let i = i % body.len();
            body[i] ^= 1 << bit;
            if let Ok(other) = decode_request(&body) {
                prop_assert_ne!(other, r);
            }
        }
    }
}
