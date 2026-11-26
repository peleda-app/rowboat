//! Waking a sleeping node.
//!
//! A wake is a hint ("connect now"), never a fact: it carries at most [`MAX_WAKE`] bytes the
//! sender has already sealed for the target, may be lost, delayed or repeated, and the woken node
//! acts on it only by connecting and fetching verified data.

#[cfg(feature = "testing")]
pub mod testing;

use async_trait::async_trait;
use bytes::Bytes;

/// The largest sealed payload of a wake, in bytes.
pub const MAX_WAKE: usize = 256;

/// The largest wake target, in bytes.
pub const MAX_TARGET: usize = 256;

/// Errors of the wake contract. None carries the payload.
#[derive(Debug, thiserror::Error)]
pub enum WakeError {
    /// A payload over [`MAX_WAKE`]; nothing was sent.
    #[error("wake payload too large")]
    TooLarge,
    /// A target this implementation cannot address (wrong format or length).
    #[error("invalid wake target")]
    InvalidTarget,
    /// The channel refused the sender for this target.
    #[error("wake refused")]
    Denied,
    /// The channel failed or could not be reached; a later call may work.
    #[error("wake channel unavailable: {0}")]
    Unavailable(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl WakeError {
    /// Wraps any transport error.
    pub fn unavailable(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self::Unavailable(e.into())
    }
}

/// Where to send a wake: opaque bytes the target node handed out (a box id, a push token), at
/// most [`MAX_TARGET`] bytes.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct WakeTarget(Bytes);

impl WakeTarget {
    /// Wraps `bytes`; `None` when longer than [`MAX_TARGET`].
    pub fn new(bytes: impl Into<Bytes>) -> Option<Self> {
        let bytes = bytes.into();
        (bytes.len() <= MAX_TARGET).then_some(Self(bytes))
    }

    /// The bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for WakeTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WakeTarget({} bytes)", self.0.len())
    }
}

/// A wake that arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Woken {
    /// The sealed payload exactly as sent.
    pub sealed: Bytes,
}

/// A wake channel.
///
/// Guarantees (checked by [`testing::wake`]):
///
/// - `wake` refuses a payload over [`MAX_WAKE`] and a target it cannot address before sending
///   anything.
/// - A wake that is delivered reaches `listen` with its bytes unchanged. Delivery is best effort:
///   wakes may be lost, delayed or repeated.
/// - A wake from a sender the target does not accept never reaches `listen`.
/// - `listen` waits until the next wake for this node arrives.
#[async_trait]
pub trait Wake: Send + Sync {
    /// This node's own target, to hand to the nodes that should be able to wake it.
    fn target(&self) -> WakeTarget;

    /// Sends `sealed` to `target`, best effort.
    async fn wake(&self, target: &WakeTarget, sealed: Bytes) -> Result<(), WakeError>;

    /// The next wake for this node.
    async fn listen(&self) -> Result<Woken, WakeError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_are_capped() {
        let target = WakeTarget::new(vec![1u8; MAX_TARGET]).unwrap();
        assert_eq!(target.as_bytes().len(), MAX_TARGET);
        assert!(WakeTarget::new(vec![1u8; MAX_TARGET + 1]).is_none());
        assert!(WakeTarget::new(Bytes::new()).is_some());
    }

    #[test]
    fn nothing_prints_the_target_bytes() {
        let target = WakeTarget::new(&b"secret-box-id"[..]).unwrap();
        let shown = format!("{target:?}");
        assert_eq!(shown, "WakeTarget(13 bytes)");
        assert!(!shown.contains("secret"));
        let error = WakeError::unavailable("relay down");
        assert_eq!(error.to_string(), "wake channel unavailable: relay down");
        assert!(std::error::Error::source(&error).is_some());
    }
}
