//! [`Endpoints`] over [`IrohLink`]: every endpoint is a QUIC endpoint whose key is the identity
//! it was bound for, with the ALPN prefix `peleda` unless the configuration says otherwise.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use baton_identity::Identity;
use baton_link::{PeerHint, Trust};
use baton_link_iroh::{AlpnPrefix, IrohConfig, IrohLink};
use rowboat_endpoint::{Endpoint, EndpointError, Endpoints};

/// The ALPN prefix of Peleda's links: `peleda/<protocol>/1`.
pub const ALPN_PREFIX: &str = "peleda";

/// Iroh endpoints with one configuration.
#[derive(Debug, Clone)]
pub struct IrohEndpoints {
    config: IrohConfig,
    advertise: Vec<SocketAddr>,
}

impl IrohEndpoints {
    /// Endpoints with `config`; its ALPN prefix is replaced by [`ALPN_PREFIX`].
    pub fn new(mut config: IrohConfig) -> Self {
        config.alpn_prefix = AlpnPrefix::new(ALPN_PREFIX).expect("a valid prefix");
        Self {
            config,
            advertise: Vec::new(),
        }
    }

    /// Endpoints bound to `127.0.0.1` on random ports with relays and discovery off: what tests
    /// use, nothing leaves the machine.
    pub fn loopback() -> Self {
        Self::new(IrohConfig {
            bind: vec![SocketAddr::from(([127, 0, 0, 1], 0))],
            open_timeout: std::time::Duration::from_secs(5),
            ..IrohConfig::default()
        })
    }

    /// Direct addresses to put in every hint besides the bound ones that name a specific IP (for
    /// example the device's addresses on its local network). Ports of `0` take the endpoint's
    /// own port.
    pub fn advertise(mut self, addrs: Vec<SocketAddr>) -> Self {
        self.advertise = addrs;
        self
    }
}

fn hint(bound: &[SocketAddr], advertise: &[SocketAddr], config: &IrohConfig) -> PeerHint {
    let port = bound.first().map(|a| a.port()).unwrap_or(0);
    let mut direct: Vec<SocketAddr> = bound
        .iter()
        .filter(|a| !a.ip().is_unspecified())
        .copied()
        .collect();
    for a in advertise {
        let a = if a.port() == 0 {
            SocketAddr::new(a.ip(), port)
        } else {
            *a
        };
        if !direct.contains(&a) {
            direct.push(a);
        }
    }
    PeerHint {
        direct,
        relay: config.relays.first().cloned(),
    }
}

#[async_trait]
impl Endpoints for IrohEndpoints {
    async fn bind(
        &self,
        identity: &Identity,
        trust: Arc<dyn Trust>,
    ) -> Result<Endpoint, EndpointError> {
        let link = IrohLink::bind(identity, trust, self.config.clone())
            .await
            .map_err(|_| EndpointError::Unavailable)?;
        let hint = hint(&link.bound_addrs(), &self.advertise, &self.config);
        Ok(Endpoint {
            link: Arc::new(link),
            hint,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use baton_link::RelayUrl;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn conformance_on_loopback() {
        rowboat_endpoint::testing::endpoints(&IrohEndpoints::loopback()).await;
    }

    #[test]
    fn hints_skip_unspecified_addresses_and_fill_ports() {
        let config = IrohConfig {
            relays: vec![RelayUrl::new("https://relay.example.com").unwrap()],
            ..IrohConfig::default()
        };
        let bound = vec![
            "0.0.0.0:4100".parse().unwrap(),
            "127.0.0.1:4101".parse().unwrap(),
        ];
        let h = hint(
            &bound,
            &[
                "192.0.2.7:0".parse().unwrap(),
                "127.0.0.1:4101".parse().unwrap(),
            ],
            &config,
        );
        assert_eq!(
            h.direct,
            vec![
                "127.0.0.1:4101".parse::<SocketAddr>().unwrap(),
                "192.0.2.7:4100".parse().unwrap()
            ]
        );
        assert_eq!(h.relay.unwrap().as_str(), "https://relay.example.com");
    }

    #[test]
    fn the_prefix_is_peleda() {
        let e = IrohEndpoints::new(IrohConfig::default());
        assert_eq!(e.config.alpn_prefix.as_str(), "peleda");
    }
}
