//! The drop wire format.
//!
//! A request is one version byte followed by a postcard envelope: a [`Head`] (operation, box,
//! timestamp, random nonce, signing key, BLAKE3 hash of the body), the body bytes and an Ed25519
//! signature by the stated key over the head, under the context [`CONTEXT`] and the operator's
//! realm. A reply is one version byte followed by a postcard [`Reply`] or error. Every decoder
//! checks the size first, refuses trailing bytes, and [`open`] verifies the signature last among
//! the stateless checks; authorization and replay are the service's.

use baton_core::Timestamp;
use baton_identity::{PublicKey, Signature};
use baton_mailbox::{BoxId, BoxKey, BoxPolicy};
use bytes::Bytes;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::DropError;
use crate::admission::WorkParams;

/// The protocol version.
pub const VERSION: u8 = 1;

/// The signature context of requests.
pub const CONTEXT: &str = "baton/drop/request/1";

/// What a request may carry besides its message: head, signature, policy with every writer.
pub const OVERHEAD: usize = 8 * 1024;

/// The longest operator token on the wire.
pub const MAX_TOKEN: usize = 256;

/// The longest realm name.
pub const MAX_REALM: usize = 128;

/// What a request does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    /// Create a box.
    Create,
    /// Store a message.
    Put,
    /// Read messages.
    Take,
    /// Remove messages up to an id.
    Ack,
    /// Replace the writers.
    SetWriters,
    /// Remove the box.
    Delete,
}

/// The signed head of a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Head {
    /// The operation; must match the body.
    pub op: Op,
    /// The box.
    pub box_id: BoxId,
    /// When the client made the request, on its clock.
    pub at: Timestamp,
    /// 16 random bytes; a nonce is accepted once per key within the freshness window.
    pub nonce: [u8; 16],
    /// The key that signed: the box's reader, or a writer for `Put`.
    pub key: PublicKey,
    /// BLAKE3 of the body bytes.
    pub body_hash: [u8; 32],
}

/// How a creation is admitted, on the wire.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireAdmission {
    /// None.
    None,
    /// An operator token, at most [`MAX_TOKEN`] bytes.
    Token(Vec<u8>),
    /// A proof-of-work nonce for this box.
    Work(u64),
}

impl std::fmt::Debug for WireAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::Token(_) => f.write_str("Token(..)"),
            Self::Work(n) => write!(f, "Work({n})"),
        }
    }
}

impl Drop for WireAdmission {
    fn drop(&mut self) {
        if let Self::Token(t) = self {
            zeroize::Zeroize::zeroize(t);
        }
    }
}

/// The body of a request.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Body {
    /// Create the box with this policy.
    Create {
        /// The policy.
        policy: BoxPolicy,
        /// The admission.
        admission: WireAdmission,
    },
    /// Store these bytes.
    Put {
        /// The sealed message.
        bytes: Bytes,
    },
    /// Read messages after `after`.
    Take {
        /// Messages after this id; all when `None`.
        after: Option<u64>,
        /// At most this many.
        limit: u32,
        /// Wait up to this long for one, in milliseconds.
        wait_ms: u32,
    },
    /// Remove messages up to and including `up_to`.
    Ack {
        /// The last id to remove.
        up_to: u64,
    },
    /// Replace the writers; `version` must be above the stored one.
    SetWriters {
        /// The new writers.
        writers: Vec<PublicKey>,
        /// The change's version.
        version: u64,
    },
    /// Remove the box.
    Delete,
}

impl Body {
    /// The operation of this body.
    pub fn op(&self) -> Op {
        match self {
            Self::Create { .. } => Op::Create,
            Self::Put { .. } => Op::Put,
            Self::Take { .. } => Op::Take,
            Self::Ack { .. } => Op::Ack,
            Self::SetWriters { .. } => Op::SetWriters,
            Self::Delete => Op::Delete,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    head: Head,
    body: Bytes,
    sig: Signature,
}

/// A request whose encoding, freshness and signature were checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    /// The head.
    pub head: Head,
    /// The body.
    pub body: Body,
}

fn signed_bytes(realm: &str, head: &Head) -> Vec<u8> {
    postcard::to_stdvec(&(VERSION, realm, head)).expect("heads encode")
}

/// Encodes a request from its parts, signed by `signer` under `context` (or with an all-zero
/// signature), for tests that forge requests.
#[cfg(test)]
pub(crate) fn seal_parts(
    realm: &str,
    context: &str,
    signer: Option<&BoxKey>,
    head: &Head,
    body: Bytes,
) -> Vec<u8> {
    let sig = signer.map_or(Signature::from_bytes(&[0; 64]), |k| {
        k.sign(context, &signed_bytes(realm, head))
    });
    let mut out = vec![VERSION];
    out.extend(
        postcard::to_stdvec(&Envelope {
            head: head.clone(),
            body,
            sig,
        })
        .expect("envelopes encode"),
    );
    out
}

/// Builds a signed request for `body` on `box_id`, stamped `at` with `nonce`.
pub fn seal(
    realm: &str,
    key: &BoxKey,
    box_id: &BoxId,
    body: &Body,
    at: Timestamp,
    nonce: [u8; 16],
) -> Vec<u8> {
    let op = body.op();
    let body = Bytes::from(postcard::to_stdvec(body).expect("bodies encode"));
    let head = Head {
        op,
        box_id: *box_id,
        at,
        nonce,
        key: key.public(),
        body_hash: *blake3::hash(&body).as_bytes(),
    };
    let sig = key.sign(CONTEXT, &signed_bytes(realm, &head));
    let mut out = vec![VERSION];
    out.extend(postcard::to_stdvec(&Envelope { head, body, sig }).expect("envelopes encode"));
    out
}

fn decode_exact<T: DeserializeOwned>(raw: &[u8]) -> Result<T, DropError> {
    match postcard::take_from_bytes::<T>(raw) {
        Ok((v, [])) => Ok(v),
        _ => Err(DropError::Malformed),
    }
}

/// Checks a raw request: size (at most `max_len`), version, encoding without trailing bytes,
/// body hash, operation, freshness (`at` within `freshness_ms` of `now`, either way) and the
/// signature under `realm`. Never panics on any input.
pub fn open(
    raw: &[u8],
    realm: &str,
    now: Timestamp,
    freshness_ms: i64,
    max_len: usize,
) -> Result<Opened, DropError> {
    if raw.len() > max_len {
        return Err(DropError::TooLarge);
    }
    let (&v, rest) = raw.split_first().ok_or(DropError::Malformed)?;
    if v != VERSION {
        return Err(DropError::Version);
    }
    let env: Envelope = decode_exact(rest)?;
    if *blake3::hash(&env.body).as_bytes() != env.head.body_hash {
        return Err(DropError::Malformed);
    }
    let body: Body = decode_exact(&env.body)?;
    if body.op() != env.head.op {
        return Err(DropError::Malformed);
    }
    if now.0.abs_diff(env.head.at.0) > freshness_ms.unsigned_abs() {
        return Err(DropError::Stale);
    }
    env.head
        .key
        .verify(CONTEXT, &signed_bytes(realm, &env.head), &env.sig)
        .map_err(|_| DropError::BadSignature)?;
    Ok(Opened {
        head: env.head,
        body,
    })
}

/// How long a raw request asks to wait, when it decodes as a take of this version; `None` for
/// anything else. Nothing is verified: it only lets a transport pick the budget a request runs
/// under before the service checks it. Never panics on any input.
pub fn wait_ms(raw: &[u8]) -> Option<u32> {
    let (&VERSION, rest) = raw.split_first()? else {
        return None;
    };
    let env: Envelope = decode_exact(rest).ok()?;
    match decode_exact::<Body>(&env.body).ok()? {
        Body::Take { wait_ms, .. } => Some(wait_ms),
        _ => None,
    }
}

/// A stored message on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireMessage {
    /// Its id.
    pub id: u64,
    /// When it was stored.
    pub at: Timestamp,
    /// The sealed bytes.
    pub bytes: Bytes,
}

/// A successful reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    /// The operation succeeded with nothing to return.
    Done,
    /// The message was stored with this id.
    Stored(u64),
    /// Messages in id order.
    Messages(Vec<WireMessage>),
}

/// Encodes a reply or an error.
pub fn encode_reply(r: &Result<Reply, DropError>) -> Vec<u8> {
    let mut out = vec![VERSION];
    out.extend(postcard::to_stdvec(r).expect("replies encode"));
    out
}

/// Decodes a reply of at most `max_len` bytes. Never panics on any input.
pub fn decode_reply(raw: &[u8], max_len: usize) -> Result<Result<Reply, DropError>, DropError> {
    if raw.len() > max_len {
        return Err(DropError::TooLarge);
    }
    match raw.split_first() {
        Some((&VERSION, rest)) => decode_exact(rest),
        Some(_) => Err(DropError::Version),
        None => Err(DropError::Malformed),
    }
}

/// What a drop service publishes about itself (unsigned; clients check it against their own
/// configuration and caps).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceInfo {
    /// The realm requests must be signed for.
    pub realm: String,
    /// The largest message.
    pub max_message: u32,
    /// The longest wait of a take, in milliseconds.
    pub max_wait_ms: u32,
    /// The most messages one take returns.
    pub max_take: u32,
    /// The most message bytes one take returns.
    pub max_take_bytes: u32,
    /// The freshness window, in milliseconds.
    pub freshness_ms: u32,
    /// Whether creations without admission are accepted.
    pub open: bool,
    /// Whether operator tokens are accepted.
    pub tokens: bool,
    /// The proof-of-work challenge, if work is accepted.
    pub work: Option<WorkParams>,
}

/// The largest encoded [`ServiceInfo`].
pub const MAX_INFO: usize = 1024;

/// Encodes service info.
pub fn encode_info(info: &ServiceInfo) -> Vec<u8> {
    let mut out = vec![VERSION];
    out.extend(postcard::to_stdvec(info).expect("info encodes"));
    out
}

/// Decodes service info. Never panics on any input.
pub fn decode_info(raw: &[u8]) -> Result<ServiceInfo, DropError> {
    if raw.len() > MAX_INFO {
        return Err(DropError::TooLarge);
    }
    match raw.split_first() {
        Some((&VERSION, rest)) => decode_exact(rest),
        Some(_) => Err(DropError::Version),
        None => Err(DropError::Malformed),
    }
}

/// A fresh random nonce.
pub fn nonce() -> [u8; 16] {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("the operating system provides randomness");
    b
}

/// A token wrapped for the wire.
pub fn token(t: &Zeroizing<Vec<u8>>) -> WireAdmission {
    WireAdmission::Token(t.to_vec())
}
