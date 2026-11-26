//! Store-and-forward mailboxes for nodes that are offline.
//!
//! A box holds opaque, already sealed messages for one reader, written by a set of writer keys.
//! Every key is a per-box pseudonymous [`BoxKey`], derived by the node from a seed it keeps in its
//! `SecretStore`, so whoever runs the mailbox cannot link the boxes of one group by key. Delivery
//! is at least once: messages stay until the reader acknowledges them or their time-to-live ends.

#[cfg(feature = "testing")]
pub mod testing;

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use baton_core::Timestamp;
use baton_identity::{Identity, PublicKey, Signature};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The default largest message, in bytes.
pub const DEFAULT_MAX_MESSAGE: usize = 64 * 1024;

/// The default time-to-live of a message: 14 days.
pub const DEFAULT_TTL_MS: u64 = 14 * 24 * 3600 * 1000;

/// The longest time-to-live any box may ask for: 30 days.
pub const MAX_TTL_MS: u64 = 30 * 24 * 3600 * 1000;

/// The shortest time-to-live a box may ask for: one second.
pub const MIN_TTL_MS: u64 = 1000;

/// The most writer keys one box may have.
pub const MAX_WRITERS: usize = 64;

/// The default quota of a box in bytes of stored messages: 16 MiB.
pub const DEFAULT_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// The default quota of a box in stored messages.
pub const DEFAULT_MAX_MESSAGES: u32 = 1024;

/// Errors of the mailbox contract. None of them carries message bytes or key material.
#[derive(Debug, thiserror::Error)]
pub enum MailboxError {
    /// The box does not exist (never created, deleted or expired).
    #[error("unknown box")]
    UnknownBox,
    /// A box with this id already exists.
    #[error("box already exists")]
    Exists,
    /// The key is not allowed to do this on this box (not a writer, not the reader).
    #[error("denied")]
    Denied,
    /// The admission (token or proof of work) was missing or did not verify.
    #[error("admission refused")]
    Admission,
    /// The message is larger than the mailbox accepts; nothing was stored.
    #[error("message too large")]
    TooLarge,
    /// The box is full (messages or bytes); nothing was stored.
    #[error("box quota exceeded")]
    Quota,
    /// A policy outside the limits (time-to-live, writers, quotas).
    #[error("invalid box policy")]
    InvalidPolicy,
    /// A concurrent or out-of-order change of the box won; nothing changed.
    #[error("conflicting change")]
    Conflict,
    /// The request was refused as malformed, stale, replayed or from the wrong context.
    #[error("request refused: {0}")]
    Rejected(&'static str),
    /// The mailbox is busy or rate limits the caller; retry later.
    #[error("mailbox busy")]
    Busy,
    /// The mailbox could not be reached or failed; the call may be retried. A failed `put` may or
    /// may not have been stored.
    #[error("mailbox unavailable: {0}")]
    Unavailable(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl MailboxError {
    /// Wraps any transport or backend error.
    pub fn unavailable(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self::Unavailable(e.into())
    }
}

/// A box: 256 bits bound to its reader key ([`BoxId::of_reader`]), so nobody finds a box they
/// were not told about and nobody but the reader can create it, also after it expired.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BoxId(pub [u8; 32]);

/// The BLAKE3 key-derivation context binding a box id to its reader key.
pub const BOX_ID_CONTEXT: &str = "baton/drop/box/1";

impl BoxId {
    /// The id of the box whose reader key is `reader`: BLAKE3 `derive_key` under
    /// [`BOX_ID_CONTEXT`] over the key's 32 bytes. One reader key has one box; a mailbox refuses
    /// to create any other id for that key.
    pub fn of_reader(reader: &PublicKey) -> Self {
        Self(blake3::derive_key(BOX_ID_CONTEXT, &reader.to_bytes()))
    }

    /// Random bytes, for ids no box can have (tests, unknown boxes).
    pub fn random() -> Self {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).expect("the operating system provides randomness");
        Self(b)
    }

    /// The 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for BoxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            &data_encoding::BASE32_NOPAD
                .encode(&self.0)
                .to_ascii_lowercase(),
        )
    }
}

impl fmt::Debug for BoxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BoxId({self})")
    }
}

/// A message within a box. Ids grow with every `put` and are never reused in that box, also after
/// acknowledgements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MessageId(pub u64);

/// What a key does for a box. Keys of different roles never coincide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BoxRole {
    /// Takes, acknowledges, changes writers, deletes the box.
    Reader,
    /// Puts messages.
    Writer,
}

/// A per-box Ed25519 key. `Debug` shows only the public half.
#[derive(Clone)]
pub struct BoxKey(Identity);

impl BoxKey {
    /// The key a node uses for `box_id` in `role`, derived from a 32-byte seed the node keeps
    /// secret (in its `SecretStore`). The same inputs give the same key; different boxes or roles
    /// give unrelated keys, so keys do not link the boxes of one node or group.
    pub fn derive(seed: &[u8; 32], box_id: &BoxId, role: BoxRole) -> Self {
        let mut input = Zeroizing::new([0u8; 65]);
        input[..32].copy_from_slice(seed);
        input[32..64].copy_from_slice(&box_id.0);
        input[64] = match role {
            BoxRole::Reader => 1,
            BoxRole::Writer => 2,
        };
        let secret = Zeroizing::new(blake3::derive_key(
            "baton-mailbox 2026-11-25 per-box key",
            &input[..],
        ));
        Self(Identity::from_secret_bytes(&secret))
    }

    /// A fresh random key, for tests and one-off boxes.
    pub fn generate() -> Self {
        Self(Identity::generate())
    }

    /// The public half: what a policy names.
    pub fn public(&self) -> PublicKey {
        self.0.public()
    }

    /// Signs `message` under `context` (see [`Identity::sign`]).
    pub fn sign(&self, context: &str, message: &[u8]) -> Signature {
        self.0.sign(context, message)
    }
}

impl fmt::Debug for BoxKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BoxKey({:?})", self.public())
    }
}

/// Who may use a box and how much it may hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoxPolicy {
    /// The only key that may take, acknowledge, change writers and delete.
    pub reader: PublicKey,
    /// The keys that may put, at most [`MAX_WRITERS`], no duplicates.
    pub writers: Vec<PublicKey>,
    /// Stored bytes the box may hold (sum of message sizes).
    pub max_bytes: u64,
    /// Stored messages the box may hold.
    pub max_messages: u32,
    /// How long a message is kept, from when it was stored, between [`MIN_TTL_MS`] and
    /// [`MAX_TTL_MS`]. A box its reader has not used for this long is removed.
    pub ttl_ms: u64,
}

impl BoxPolicy {
    /// A policy with the default quotas and time-to-live.
    pub fn new(reader: PublicKey, writers: Vec<PublicKey>) -> Self {
        Self {
            reader,
            writers,
            max_bytes: DEFAULT_MAX_BYTES,
            max_messages: DEFAULT_MAX_MESSAGES,
            ttl_ms: DEFAULT_TTL_MS,
        }
    }

    /// Whether the policy is within the contract's limits: time-to-live in range, at least one
    /// message and byte of quota, writers within [`MAX_WRITERS`] and without duplicates.
    pub fn check(&self) -> Result<(), MailboxError> {
        check_writers(&self.writers)?;
        if !(MIN_TTL_MS..=MAX_TTL_MS).contains(&self.ttl_ms)
            || self.max_messages == 0
            || self.max_bytes == 0
        {
            return Err(MailboxError::InvalidPolicy);
        }
        Ok(())
    }
}

/// Whether a writer list is within [`MAX_WRITERS`] and has no duplicates.
pub fn check_writers(writers: &[PublicKey]) -> Result<(), MailboxError> {
    if writers.len() > MAX_WRITERS {
        return Err(MailboxError::InvalidPolicy);
    }
    let mut sorted = writers.to_vec();
    sorted.sort();
    if sorted.windows(2).any(|w| w[0] == w[1]) {
        return Err(MailboxError::InvalidPolicy);
    }
    Ok(())
}

/// How a box creation is admitted by whoever runs the mailbox. `Debug` never shows a token.
#[derive(Clone)]
pub enum Admission {
    /// No admission; accepted only by mailboxes that are open.
    None,
    /// A token the operator handed out, compared in constant time.
    Token(Zeroizing<Vec<u8>>),
    /// Solve the mailbox's proof-of-work challenge for this box (the implementation fetches the
    /// challenge and spends the CPU time).
    Work,
}

impl fmt::Debug for Admission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "Admission::None",
            Self::Token(_) => "Admission::Token(..)",
            Self::Work => "Admission::Work",
        })
    }
}

/// A stored message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Its id within the box.
    pub id: MessageId,
    /// The sealed bytes exactly as put.
    pub bytes: Bytes,
    /// When the mailbox stored it, on the mailbox's clock.
    pub stored_at: Timestamp,
}

/// What a mailbox accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxLimits {
    /// The largest message.
    pub max_message: usize,
    /// The longest a `take` waits for a message; longer waits are cut to this.
    pub max_wait: Duration,
    /// The most messages one `take` returns; larger limits are cut to this.
    pub max_take: u32,
}

/// A store-and-forward mailbox.
///
/// Guarantees (checked by [`testing::mailbox`]):
///
/// - Bytes are opaque and returned exactly as put; the mailbox never needs to read them.
/// - `put` stores a message only for a key in the box's writers at that moment, at most
///   [`MailboxLimits::max_message`] bytes and within the box's quotas, and returns an id greater
///   than every earlier id of that box.
/// - `take`, `ack`, `set_writers` and `delete_box` succeed only for the box's reader key.
/// - `take` returns stored messages with ids after `after`, in id order, at most `limit` (cut to
///   [`MailboxLimits::max_take`]). With none to return it waits up to `wait` (cut to
///   [`MailboxLimits::max_wait`]) for one to arrive and then returns what it has, possibly
///   nothing.
/// - At least once: a message stays and is returned by every later `take` until it is
///   acknowledged or its time-to-live ends. `ack(up_to)` removes every message up to that id and
///   frees its quota.
/// - After `set_writers`, a removed writer's `put` is refused; stored messages stay.
/// - `create` refuses an existing id, a policy outside the limits and an admission the mailbox does
///   not accept; the reader key must be the policy's reader and the id must be
///   [`BoxId::of_reader`] of it (refused as [`MailboxError::Denied`]), so a box that expired cannot
///   be taken over by anyone else.
/// - Expired messages are never returned and do not count against quotas.
#[async_trait]
pub trait Mailbox: Send + Sync {
    /// What this mailbox accepts.
    fn limits(&self) -> MailboxLimits;

    /// Creates box `id` (which must be [`BoxId::of_reader`] of `policy.reader`) with `policy`,
    /// signed by `reader` (whose public half must be `policy.reader`), admitted by `admission`.
    async fn create(
        &self,
        id: &BoxId,
        policy: &BoxPolicy,
        reader: &BoxKey,
        admission: &Admission,
    ) -> Result<(), MailboxError>;

    /// Stores `sealed` in box `id` as `writer`.
    async fn put(
        &self,
        id: &BoxId,
        writer: &BoxKey,
        sealed: Bytes,
    ) -> Result<MessageId, MailboxError>;

    /// Messages after `after` (all when `None`), in order, waiting up to `wait` when there are
    /// none.
    async fn take(
        &self,
        id: &BoxId,
        reader: &BoxKey,
        after: Option<MessageId>,
        limit: u32,
        wait: Duration,
    ) -> Result<Vec<Message>, MailboxError>;

    /// Removes every message with an id up to and including `up_to`.
    async fn ack(&self, id: &BoxId, reader: &BoxKey, up_to: MessageId) -> Result<(), MailboxError>;

    /// Replaces the box's writers (for revocation).
    async fn set_writers(
        &self,
        id: &BoxId,
        reader: &BoxKey,
        writers: &[PublicKey],
    ) -> Result<(), MailboxError>;

    /// Removes the box and every message in it.
    async fn delete_box(&self, id: &BoxId, reader: &BoxKey) -> Result<(), MailboxError>;
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn box_keys_depend_on_seed_box_and_role() {
        let seed = [7u8; 32];
        let a = BoxId([1; 32]);
        let b = BoxId([2; 32]);
        let ra = BoxKey::derive(&seed, &a, BoxRole::Reader).public();
        assert_eq!(ra, BoxKey::derive(&seed, &a, BoxRole::Reader).public());
        assert_ne!(ra, BoxKey::derive(&seed, &a, BoxRole::Writer).public());
        assert_ne!(ra, BoxKey::derive(&seed, &b, BoxRole::Reader).public());
        assert_ne!(ra, BoxKey::derive(&[8u8; 32], &a, BoxRole::Reader).public());
    }

    #[test]
    fn debug_never_shows_secrets() {
        let key = BoxKey::generate();
        let shown = format!("{key:?}");
        let secret = format!("{:?}", key.0.secret_bytes());
        assert!(!shown.contains(&secret));
        let token = Admission::Token(Zeroizing::new(b"hunter2-token".to_vec()));
        assert!(!format!("{token:?}").contains("hunter2"));
    }

    #[test]
    fn policies_outside_limits_are_refused() {
        let r = BoxKey::generate().public();
        let w = BoxKey::generate().public();
        assert!(BoxPolicy::new(r, vec![w]).check().is_ok());
        let mut p = BoxPolicy::new(r, vec![w, w]);
        assert!(p.check().is_err(), "duplicate writer");
        p.writers = (0..=MAX_WRITERS)
            .map(|_| BoxKey::generate().public())
            .collect();
        assert!(p.check().is_err(), "too many writers");
        for (ttl, ok) in [
            (MIN_TTL_MS - 1, false),
            (MIN_TTL_MS, true),
            (MAX_TTL_MS, true),
            (MAX_TTL_MS + 1, false),
        ] {
            let mut p = BoxPolicy::new(r, vec![]);
            p.ttl_ms = ttl;
            assert_eq!(p.check().is_ok(), ok, "ttl {ttl}");
        }
        let mut p = BoxPolicy::new(r, vec![]);
        p.max_messages = 0;
        assert!(p.check().is_err());
        let mut p = BoxPolicy::new(r, vec![]);
        p.max_bytes = 0;
        assert!(p.check().is_err());
    }

    proptest! {
        #[test]
        fn box_ids_display_as_52_lowercase_chars(bytes in any::<[u8; 32]>()) {
            let s = BoxId(bytes).to_string();
            prop_assert_eq!(s.len(), 52);
            prop_assert!(s.bytes().all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)));
        }
    }
}
