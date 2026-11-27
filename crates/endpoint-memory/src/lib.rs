//! [`Endpoints`] over one [`MemoryLinkHub`]: every endpoint bound by one factory reaches every
//! other in process. Hints are empty; the hub routes by key.

use std::sync::Arc;

use async_trait::async_trait;
use baton_identity::Identity;
use baton_link::{PeerHint, Trust};
use baton_link_memory::MemoryLinkHub;
use rowboat_endpoint::{Endpoint, EndpointError, Endpoints};

/// Endpoints on one in-process hub. Clones share the hub.
#[derive(Clone, Default)]
pub struct MemoryEndpoints {
    hub: Arc<MemoryLinkHub>,
}

impl MemoryEndpoints {
    /// A factory over a new hub.
    pub fn new() -> Self {
        Self::default()
    }

    /// The hub, for tests that partition and heal it.
    pub fn hub(&self) -> &MemoryLinkHub {
        &self.hub
    }
}

impl std::fmt::Debug for MemoryEndpoints {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemoryEndpoints")
    }
}

#[async_trait]
impl Endpoints for MemoryEndpoints {
    async fn bind(
        &self,
        identity: &Identity,
        trust: Arc<dyn Trust>,
    ) -> Result<Endpoint, EndpointError> {
        Ok(Endpoint {
            link: Arc::new(self.hub.join(identity.public(), trust)),
            hint: PeerHint::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn conformance() {
        rowboat_endpoint::testing::endpoints(&MemoryEndpoints::new()).await;
    }
}
