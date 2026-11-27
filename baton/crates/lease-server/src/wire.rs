//! The frames of link protocol `lease`.
//!
//! Every frame on a stream is `u32` big-endian length ‖ body, and every body is
//! `[VERSION] ‖ postcard(value)` with no trailing bytes. A request body is at most
//! [`MAX_REQUEST`] bytes, a reply body at most [`MAX_REPLY`]. Frames are not signed: the link
//! authenticates the peer by its key for every stream, and the server checks every request
//! against that peer.

use baton_core::{FencingToken, GroupId, LeaseKey};
use baton_lease::{Lease, NodeProfile, TakeoverOutcome};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The format version of every body.
pub const VERSION: u8 = 1;
/// The largest request body, in bytes.
pub const MAX_REQUEST: usize = 1024;
/// The largest reply body, in bytes.
pub const MAX_REPLY: usize = 1024 * 1024;

/// A request from a client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// Asks for the server's parameters.
    Hello,
    /// `Leases::acquire`.
    Acquire {
        /// The group.
        group: GroupId,
        /// The key.
        key: LeaseKey,
        /// The caller's profile; its node must be the peer's.
        profile: NodeProfile,
    },
    /// `Leases::request_takeover`.
    Takeover {
        /// The group.
        group: GroupId,
        /// The key.
        key: LeaseKey,
        /// The caller's profile; its node must be the peer's.
        profile: NodeProfile,
    },
    /// `Leases::release`.
    Release {
        /// The lease given up; its node must be the peer's.
        lease: Lease,
    },
    /// `Leases::holder`.
    Holder {
        /// The group.
        group: GroupId,
        /// The key.
        key: LeaseKey,
    },
    /// `Liveness::heartbeat`, judged on the server's clock.
    Heartbeat {
        /// The group.
        group: GroupId,
        /// The caller's profile; its node must be the peer's.
        profile: NodeProfile,
    },
    /// `Liveness::alive` on the server's clock.
    Alive {
        /// The group.
        group: GroupId,
    },
    /// `Leases::acquire_above`.
    AcquireAbove {
        /// The group.
        group: GroupId,
        /// The key.
        key: LeaseKey,
        /// The caller's profile; its node must be the peer's.
        profile: NodeProfile,
        /// Every token granted lies above it.
        floor: FencingToken,
    },
    /// Asks the server to endorse the lease the caller holds on `key` with `fence` (see
    /// [`crate::Endorse`]).
    Endorse {
        /// The group.
        group: GroupId,
        /// The key.
        key: LeaseKey,
        /// The token of the caller's lease.
        fence: FencingToken,
    },
}

/// [`TakeoverOutcome`] on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    /// [`TakeoverOutcome::Recorded`].
    Recorded,
    /// [`TakeoverOutcome::AlreadyHolder`].
    AlreadyHolder,
    /// [`TakeoverOutcome::NotNeeded`].
    NotNeeded,
    /// [`TakeoverOutcome::Refused`].
    Refused,
}

impl From<TakeoverOutcome> for Outcome {
    fn from(o: TakeoverOutcome) -> Self {
        match o {
            TakeoverOutcome::Recorded => Self::Recorded,
            TakeoverOutcome::AlreadyHolder => Self::AlreadyHolder,
            TakeoverOutcome::NotNeeded => Self::NotNeeded,
            TakeoverOutcome::Refused => Self::Refused,
        }
    }
}

impl From<Outcome> for TakeoverOutcome {
    fn from(o: Outcome) -> Self {
        match o {
            Outcome::Recorded => Self::Recorded,
            Outcome::AlreadyHolder => Self::AlreadyHolder,
            Outcome::NotNeeded => Self::NotNeeded,
            Outcome::Refused => Self::Refused,
        }
    }
}

/// Why the server did not carry a request out. Carries no detail of the backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Refusal {
    /// The peer may not make this request (unknown peer, acting for another node, not allowed
    /// on the group or key).
    Denied,
    /// Leases cannot be decided now.
    Unavailable,
    /// The stored lease record is corrupted.
    Corrupted,
    /// The server's store failed.
    Backend,
    /// The server is at its limit of requests in progress.
    Busy,
    /// The answer would exceed the reply limit.
    TooLarge,
    /// The request's format version is unknown.
    Version,
}

/// A reply from the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    /// The server's parameters.
    Hello {
        /// The liveness time-to-live, in milliseconds of the server's clock.
        ttl_ms: u64,
        /// The largest request body the server reads.
        max_request: u32,
        /// The largest reply body the server sends.
        max_reply: u32,
    },
    /// The answer to `Acquire` or `Holder`.
    Lease(Option<Lease>),
    /// The answer to `Takeover`.
    Takeover(Outcome),
    /// `Release` done.
    Done,
    /// The answer to `Alive`.
    Alive(Vec<NodeProfile>),
    /// The request was not carried out.
    Refused(Refusal),
    /// `Heartbeat` recorded, with the time-to-live the holder must stop by, counted from when it
    /// sent the heartbeat.
    Beat {
        /// The liveness time-to-live, in milliseconds of the server's clock.
        ttl_ms: u64,
    },
    /// The answer to `Endorse`: the endorsement, or `None` when the caller does not hold that
    /// lease or the server endorses nothing. At most [`MAX_ENDORSEMENT`] bytes.
    Endorsement(Option<Vec<u8>>),
}

/// The largest endorsement a reply carries, in bytes.
pub const MAX_ENDORSEMENT: usize = 512;

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
/// an endorsement of at most [`MAX_ENDORSEMENT`] bytes, nothing after the value.
pub fn decode_reply(body: &[u8], max: usize) -> Result<Reply, FrameError> {
    match decode(body, max.min(MAX_REPLY))? {
        Reply::Endorsement(Some(e)) if e.len() > MAX_ENDORSEMENT => Err(FrameError::Malformed),
        reply => Ok(reply),
    }
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
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    w.write_all(&out).await.map_err(|_| FrameError::Io)?;
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
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await.map_err(|_| FrameError::Io)?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use baton_core::NodeId;
    use baton_lease::{NodeClass, Takeover};
    use proptest::prelude::*;

    use super::*;

    fn profile(name: &str) -> NodeProfile {
        NodeProfile {
            node: NodeId::new(name).unwrap(),
            class: NodeClass::Desktop,
            weight: 3,
            can_run: true,
        }
    }

    fn samples() -> Vec<Request> {
        let g = GroupId::new("g").unwrap();
        let k = LeaseKey::new("k").unwrap();
        vec![
            Request::Hello,
            Request::Acquire {
                group: g.clone(),
                key: k.clone(),
                profile: profile("a"),
            },
            Request::Takeover {
                group: g.clone(),
                key: k.clone(),
                profile: profile("b"),
            },
            Request::Release {
                lease: Lease {
                    group: g.clone(),
                    key: k.clone(),
                    node: NodeId::new("a").unwrap(),
                    class: NodeClass::Phone,
                    fence: FencingToken(u64::MAX),
                    takeover: Some(Takeover {
                        node: NodeId::new("b").unwrap(),
                        class: NodeClass::Server,
                    }),
                },
            },
            Request::Holder {
                group: g.clone(),
                key: k,
            },
            Request::Heartbeat {
                group: g.clone(),
                profile: profile("a"),
            },
            Request::Alive { group: g.clone() },
            Request::AcquireAbove {
                group: g.clone(),
                key: LeaseKey::new("k").unwrap(),
                profile: profile("a"),
                floor: FencingToken(u64::MAX),
            },
            Request::Endorse {
                group: g,
                key: LeaseKey::new("k").unwrap(),
                fence: FencingToken(7),
            },
        ]
    }

    #[test]
    fn requests_round_trip_and_fit() {
        for r in samples() {
            let body = encode_request(&r);
            assert!(body.len() <= MAX_REQUEST);
            assert_eq!(decode_request(&body).unwrap(), r);
        }
        let worst = Request::Release {
            lease: Lease {
                group: GroupId::new("g".repeat(64)).unwrap(),
                key: LeaseKey::new("k".repeat(64)).unwrap(),
                node: NodeId::new("n".repeat(64)).unwrap(),
                class: NodeClass::Blind,
                fence: FencingToken(u64::MAX),
                takeover: Some(Takeover {
                    node: NodeId::new("t".repeat(64)).unwrap(),
                    class: NodeClass::Blind,
                }),
            },
        };
        assert!(encode_request(&worst).len() <= MAX_REQUEST / 2);
    }

    #[test]
    fn refuses_bad_bodies() {
        let good = encode_request(&Request::Hello);
        assert_eq!(decode_request(&[]), Err(FrameError::Length));
        assert_eq!(
            decode_request(&vec![VERSION; MAX_REQUEST + 1]),
            Err(FrameError::Length)
        );
        let mut v2 = good.clone();
        v2[0] = 2;
        assert_eq!(decode_request(&v2), Err(FrameError::Version));
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(decode_request(&trailing), Err(FrameError::Malformed));
        assert_eq!(decode_request(&[VERSION, 99]), Err(FrameError::Malformed));
        let bad_id = {
            let mut b = vec![VERSION, 6, 3];
            b.extend_from_slice(b"../");
            b
        };
        assert_eq!(decode_request(&bad_id), Err(FrameError::Malformed));
        let big = encode_reply(&Reply::Endorsement(Some(vec![1; MAX_ENDORSEMENT + 1])));
        assert_eq!(decode_reply(&big, MAX_REPLY), Err(FrameError::Malformed));
        let fits = Reply::Endorsement(Some(vec![1; MAX_ENDORSEMENT]));
        assert_eq!(decode_reply(&encode_reply(&fits), MAX_REPLY).unwrap(), fits);
        let reply = encode_reply(&Reply::Alive(vec![profile("a"); 100]));
        assert_eq!(decode_reply(&reply, 64), Err(FrameError::Length));
        assert!(decode_reply(&reply, MAX_REPLY).is_ok());
    }

    #[test]
    fn frame_lengths() {
        assert_eq!(frame_len([0, 0, 0, 0], 10), Err(FrameError::Length));
        assert_eq!(frame_len([0, 0, 0, 10], 10), Ok(10));
        assert_eq!(frame_len([0, 0, 0, 11], 10), Err(FrameError::Length));
        assert_eq!(frame_len([255; 4], usize::MAX), Ok(u32::MAX as usize));
    }

    #[tokio::test]
    async fn frames_on_a_stream() {
        let (mut a, mut b) = tokio::io::duplex(64);
        write_frame(&mut a, b"hello").await.unwrap();
        assert_eq!(read_frame(&mut b, 16).await.unwrap(), b"hello");
        write_frame(&mut a, &[1; 17]).await.unwrap();
        assert_eq!(read_frame(&mut b, 16).await, Err(FrameError::Length));
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&[0, 0, 0, 9, 1, 2]).await.unwrap();
        drop(a);
        assert_eq!(read_frame(&mut b, 16).await, Err(FrameError::Io));
    }

    proptest! {
        #[test]
        fn arbitrary_bodies_never_panic(body in proptest::collection::vec(any::<u8>(), 0..2048)) {
            if let Ok(r) = decode_request(&body) {
                prop_assert_eq!(decode_request(&encode_request(&r)).unwrap(), r);
            }
            if let Ok(r) = decode_reply(&body, MAX_REPLY) {
                prop_assert_eq!(decode_reply(&encode_reply(&r), MAX_REPLY).unwrap(), r);
            }
        }

        #[test]
        fn bit_flips_never_panic(i in 0usize..9, bit in 0usize..4096) {
            let body = encode_request(&samples()[i]);
            let mut flipped = body.clone();
            let at = bit % (body.len() * 8);
            flipped[at / 8] ^= 1 << (at % 8);
            let _ = decode_request(&flipped);
            for n in 0..body.len() {
                if let Ok(r) = decode_request(&body[..n]) {
                    prop_assert_ne!(r, samples()[i].clone());
                }
            }
        }
    }
}
