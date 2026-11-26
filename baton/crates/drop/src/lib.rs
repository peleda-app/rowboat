//! The drop protocol: store-and-forward boxes run by an operator who sees ciphertext only.
//!
//! This crate holds everything the drop server and its clients share, with no file, database or
//! network I/O of its own:
//!
//! - [`wire`]: versioned, context-bound requests signed by a per-box key, and the replies;
//! - [`admission`]: who may create a box (operator token or argon2id proof of work);
//! - [`store`]: [`DropStore`], the service's storage seam, and [`MemoryDropStore`];
//! - [`record`]: the versioned byte formats persistent stores keep;
//! - [`service`]: [`DropService`], the one implementation of the rules (freshness, replay,
//!   authorization, quotas, time-to-live, long polls);
//! - [`client`]: [`DropMailbox`], the one client, a `baton_mailbox::Mailbox` over any
//!   [`Exchange`] (in process, HTTP).

pub mod admission;
pub mod client;
pub mod record;
mod replay;
pub mod service;
pub mod store;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod wire;

use std::sync::Arc;

use baton_core::Timestamp;
use baton_mailbox::MailboxError;
use serde::{Deserialize, Serialize};

pub use admission::{AdmissionConfig, WorkParams};
pub use client::{DropMailbox, Exchange};
pub use service::{BoxLimits, DropConfig, DropService};
pub use store::{Admitted, BoxInfo, DropStore, MemoryDropStore, StoreError};
pub use wire::ServiceInfo;

/// A clock in milliseconds since the Unix epoch, injected so tests never wait on wall time.
pub type Clock = Arc<dyn Fn() -> Timestamp + Send + Sync>;

/// The system clock.
pub fn system_clock() -> Clock {
    Arc::new(Timestamp::now)
}

/// A configuration the service refuses to start with.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid drop configuration: {0}")]
pub struct ConfigError(pub &'static str);

/// Why the drop service refused a request. Travels on the wire as one byte; carries no box id,
/// key or content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum DropError {
    /// Bytes that do not decode as a request or reply of this version.
    #[error("malformed")]
    Malformed,
    /// A protocol version this side does not speak.
    #[error("unsupported version")]
    Version,
    /// A request stamped outside the freshness window.
    #[error("stale or future request")]
    Stale,
    /// A request whose nonce was already seen.
    #[error("replayed request")]
    Replayed,
    /// A signature that does not verify for the stated key, context and realm.
    #[error("bad signature")]
    BadSignature,
    /// The key is not allowed to do this on this box.
    #[error("denied")]
    Denied,
    /// No such box.
    #[error("unknown box")]
    UnknownBox,
    /// The box already exists.
    #[error("box exists")]
    Exists,
    /// Missing or invalid admission.
    #[error("admission refused")]
    Admission,
    /// A request or message over the limits.
    #[error("too large")]
    TooLarge,
    /// The box is full.
    #[error("quota exceeded")]
    Quota,
    /// A policy or writer list outside the limits.
    #[error("invalid policy")]
    InvalidPolicy,
    /// A writer change not newer than the stored one.
    #[error("conflict")]
    Conflict,
    /// Out of capacity (replay cache, waiters); retry later.
    #[error("busy")]
    Busy,
    /// The store failed.
    #[error("unavailable")]
    Unavailable,
}

impl From<DropError> for MailboxError {
    fn from(e: DropError) -> Self {
        match e {
            DropError::Malformed => MailboxError::Rejected("malformed"),
            DropError::Version => MailboxError::Rejected("unsupported version"),
            DropError::Stale => MailboxError::Rejected("stale or future timestamp"),
            DropError::Replayed => MailboxError::Rejected("replayed"),
            DropError::BadSignature => MailboxError::Rejected("bad signature"),
            DropError::Denied => MailboxError::Denied,
            DropError::UnknownBox => MailboxError::UnknownBox,
            DropError::Exists => MailboxError::Exists,
            DropError::Admission => MailboxError::Admission,
            DropError::TooLarge => MailboxError::TooLarge,
            DropError::Quota => MailboxError::Quota,
            DropError::InvalidPolicy => MailboxError::InvalidPolicy,
            DropError::Conflict => MailboxError::Conflict,
            DropError::Busy => MailboxError::Busy,
            DropError::Unavailable => MailboxError::unavailable("drop store unavailable"),
        }
    }
}

#[cfg(test)]
mod tests;
