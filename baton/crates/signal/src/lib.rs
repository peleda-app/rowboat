//! Signals: what is cheap to lose. Hints ("resource R has new events"), previews, presence, soft
//! locks, short-lived values such as access tokens, counters.
//!
//! Nothing here may be needed for correctness. If every value and message vanished, applications
//! keep working, only slower, by falling back to durable state. A signal is a hint, never a fact:
//! act on it by fetching verified data. This replaces Skein's `Ephemeral` contract.

#[cfg(feature = "testing")]
pub mod testing;

use std::time::Duration;

use async_trait::async_trait;
use baton_core::GroupId;
use bytes::Bytes;
use futures::stream::BoxStream;

/// The largest payload or value, in bytes.
pub const MAX_PAYLOAD: usize = 64 * 1024;

/// The longest topic or key, in bytes.
pub const MAX_NAME: usize = 200;

/// Errors of the signal contract.
#[derive(Debug, thiserror::Error)]
pub enum SignalError {
    /// A topic or key outside `[a-zA-Z0-9_.:/-]`, empty or longer than [`MAX_NAME`].
    #[error("invalid topic or key")]
    InvalidName,
    /// A payload or value larger than [`MAX_PAYLOAD`]; nothing was sent or stored.
    #[error("payload too large")]
    TooLarge,
    /// The backend holds as many values as it allows; nothing was stored.
    #[error("signal backend is full")]
    Full,
    /// The backend failed.
    #[error("signal backend failed: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Checks a topic or key name.
pub fn check_name(name: &str) -> Result<(), SignalError> {
    let ok = !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'/' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(SignalError::InvalidName)
    }
}

/// Checks a payload or value size.
pub fn check_payload(payload: &[u8]) -> Result<(), SignalError> {
    if payload.len() > MAX_PAYLOAD {
        Err(SignalError::TooLarge)
    } else {
        Ok(())
    }
}

/// Publish–subscribe and values with a time-to-live, scoped to a group.
///
/// Guarantees (checked by [`testing::signal`]):
///
/// - Topics and keys of different groups never mix.
/// - A message published after `subscribe` returned reaches that subscriber at most once, in
///   publish order per publisher, unless the backend drops it; there is no delivery guarantee.
///   A slow subscriber never blocks publishers.
/// - A value is gone after its time-to-live; `get` never returns an expired value.
/// - Counters from `incr`, where the backend has them, are atomic across every process sharing
///   the backend: concurrent adds are never lost.
/// - Names and sizes are checked before anything is sent or stored.
#[async_trait]
pub trait Signal: Send + Sync {
    /// Sends `payload` to current subscribers of `topic`.
    async fn publish(
        &self,
        group: &GroupId,
        topic: &str,
        payload: Bytes,
    ) -> Result<(), SignalError>;

    /// Messages published to `topic` from now on.
    async fn subscribe(
        &self,
        group: &GroupId,
        topic: &str,
    ) -> Result<BoxStream<'static, Bytes>, SignalError>;

    /// Stores a value for at most `ttl`.
    async fn put(
        &self,
        group: &GroupId,
        key: &str,
        value: Bytes,
        ttl: Duration,
    ) -> Result<(), SignalError>;

    /// The value, unless missing or expired.
    async fn get(&self, group: &GroupId, key: &str) -> Result<Option<Bytes>, SignalError>;

    /// Removes a value.
    async fn delete(&self, group: &GroupId, key: &str) -> Result<(), SignalError>;

    /// Atomically adds `by` to the counter at `key` and returns the new value, saturating. A
    /// missing or expired counter starts at 0 and lives for `ttl` from its first add; later adds
    /// do not extend it. Counters are separate from values. `Ok(None)` when the backend has no shared counters (the default).
    async fn incr(
        &self,
        group: &GroupId,
        key: &str,
        by: u64,
        ttl: Duration,
    ) -> Result<Option<u64>, SignalError> {
        let _ = (group, key, by, ttl);
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_short_and_from_a_small_alphabet() {
        for ok in [
            "a",
            "events:R1",
            "presence/node-1",
            "token.v2_x",
            &"n".repeat(MAX_NAME),
        ] {
            assert!(check_name(ok).is_ok(), "{ok}");
        }
        for bad in ["", "a b", "naïve", "a\nb", "x*", &"n".repeat(MAX_NAME + 1)] {
            assert!(
                matches!(check_name(bad), Err(SignalError::InvalidName)),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn payloads_are_capped() {
        assert!(check_payload(&[]).is_ok());
        assert!(check_payload(&vec![0; MAX_PAYLOAD]).is_ok());
        assert!(matches!(
            check_payload(&vec![0; MAX_PAYLOAD + 1]),
            Err(SignalError::TooLarge)
        ));
    }

    struct Silent;

    #[async_trait]
    impl Signal for Silent {
        async fn publish(&self, _: &GroupId, _: &str, _: Bytes) -> Result<(), SignalError> {
            Ok(())
        }
        async fn subscribe(
            &self,
            _: &GroupId,
            _: &str,
        ) -> Result<BoxStream<'static, Bytes>, SignalError> {
            Ok(Box::pin(futures::stream::empty()))
        }
        async fn put(
            &self,
            _: &GroupId,
            _: &str,
            _: Bytes,
            _: Duration,
        ) -> Result<(), SignalError> {
            Ok(())
        }
        async fn get(&self, _: &GroupId, _: &str) -> Result<Option<Bytes>, SignalError> {
            Ok(None)
        }
        async fn delete(&self, _: &GroupId, _: &str) -> Result<(), SignalError> {
            Ok(())
        }
    }

    #[test]
    fn counters_are_optional() {
        let group = GroupId::new("g").unwrap();
        let signal: &dyn Signal = &Silent;
        let counted =
            futures::executor::block_on(signal.incr(&group, "count", 1, Duration::from_secs(1)));
        assert!(matches!(counted, Ok(None)));
    }
}
