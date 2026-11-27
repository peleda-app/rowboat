//! The contract of the factory of link endpoints.
//!
//! The node binds one long-lived endpoint for its own identity (trusting what its group log
//! allows) and a short-lived one with an ephemeral identity for every pairing invite (trusting
//! anyone while the invite is pending). [`Endpoints::bind`] gives a [`baton_link::Link`] and the
//! [`PeerHint`] other nodes dial it with; which transport is behind it is the composition root's
//! choice (`rowboat-endpoint-iroh`, or `rowboat-endpoint-memory` in tests).

#[cfg(feature = "testing")]
pub mod testing;

use std::sync::Arc;

use async_trait::async_trait;
use baton_identity::Identity;
use baton_link::{Link, PeerHint, Trust};

/// Why an endpoint could not be bound. Carries no address or key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EndpointError {
    /// The transport could not bind (no socket, no runtime, a bad configuration). May be retried.
    #[error("the endpoint could not be bound")]
    Unavailable,
    /// The factory was shut down.
    #[error("the endpoint factory is closed")]
    Closed,
}

/// A bound endpoint.
pub struct Endpoint {
    /// The link, keyed by the identity it was bound for.
    pub link: Arc<dyn Link>,
    /// Where peers reach it: given to their [`Link::add_hint`] for this endpoint's key, it lets
    /// every other endpoint of the same factory (and, for real transports, of the same network)
    /// open streams to it.
    pub hint: PeerHint,
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint")
            .field("key", &self.link.local())
            .finish_non_exhaustive()
    }
}

/// Binds endpoints.
///
/// Guarantees (checked by [`testing::endpoints`]):
///
/// - Every bound link's `local()` is the identity's public key, and it keeps the `Link`
///   contract's guarantees (trust asked on every stream, untrusted peers refused both ways).
/// - The returned hint is enough for another endpoint of the same factory to reach this one.
/// - Endpoints are independent: closing one never affects another, and several may exist at once
///   for different identities.
#[async_trait]
pub trait Endpoints: Send + Sync {
    /// Binds a new endpoint for `identity` that trusts what `trust` allows.
    async fn bind(
        &self,
        identity: &Identity,
        trust: Arc<dyn Trust>,
    ) -> Result<Endpoint, EndpointError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_carry_no_content() {
        for e in [EndpointError::Unavailable, EndpointError::Closed] {
            let shown = e.to_string();
            assert!(!shown.contains('/') && !shown.contains(':'), "{shown}");
        }
    }
}
