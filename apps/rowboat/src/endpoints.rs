//! Where a tenant's endpoints bind: its link on the port its record keeps (so devices find it at
//! the same address after a restart), pairing endpoints on any other free port of the range.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use baton_identity::Identity;
use baton_link::Trust;
use baton_link_iroh::IrohConfig;
use rowboat_endpoint::{Endpoint, EndpointError, Endpoints};
use rowboat_endpoint_iroh::IrohEndpoints;

use crate::config::Ports;

/// The settings every tenant's endpoints share.
#[derive(Debug, Clone)]
pub struct LinkSettings {
    /// The address to bind.
    pub bind: IpAddr,
    /// The port range; `None` binds random ports.
    pub ports: Option<Ports>,
    /// Addresses put in hints (port `0`: the endpoint's own).
    pub advertise: Vec<SocketAddr>,
    /// Relays.
    pub relays: Vec<baton_link::RelayUrl>,
}

/// One tenant's endpoints.
pub struct TenantEndpoints {
    settings: Arc<LinkSettings>,
    link_port: u16,
    reserved: BTreeSet<u16>,
    node: OnceLock<String>,
}

impl TenantEndpoints {
    /// Endpoints of a tenant whose link keeps `link_port`, staying off `reserved` (every
    /// tenant's link port) for pairing.
    pub fn new(settings: Arc<LinkSettings>, link_port: u16, reserved: BTreeSet<u16>) -> Self {
        Self {
            settings,
            link_port,
            reserved,
            node: OnceLock::new(),
        }
    }

    /// Names the tenant's node, so the endpoint bound for its identity takes the link port.
    /// Until then every endpoint counts as a pairing endpoint.
    pub fn set_node(&self, node: &str) {
        let _ = self.node.set(node.to_owned());
    }

    fn at(&self, port: u16) -> IrohEndpoints {
        IrohEndpoints::new(IrohConfig {
            bind: vec![SocketAddr::new(self.settings.bind, port)],
            relays: self.settings.relays.clone(),
            ..IrohConfig::default()
        })
        .advertise(self.settings.advertise.clone())
    }

    /// The ports a pairing endpoint tries, in order: the range without the reserved link ports.
    pub fn pairing_ports(&self) -> Vec<u16> {
        match self.settings.ports {
            None => vec![0],
            Some(range) => range
                .iter()
                .filter(|p| !self.reserved.contains(p))
                .collect(),
        }
    }
}

#[async_trait]
impl Endpoints for TenantEndpoints {
    async fn bind(
        &self,
        identity: &Identity,
        trust: Arc<dyn Trust>,
    ) -> Result<Endpoint, EndpointError> {
        let is_link = self
            .node
            .get()
            .is_some_and(|n| *n == identity.node_id().to_string());
        if is_link {
            return self.at(self.link_port).bind(identity, trust).await;
        }
        for port in self.pairing_ports() {
            if let Ok(e) = self.at(port).bind(identity, trust.clone()).await {
                return Ok(e);
            }
        }
        Err(EndpointError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(ports: Option<Ports>) -> Arc<LinkSettings> {
        Arc::new(LinkSettings {
            bind: IpAddr::from([127, 0, 0, 1]),
            ports,
            advertise: Vec::new(),
            relays: Vec::new(),
        })
    }

    #[test]
    fn pairing_stays_off_every_link_port() {
        let e = TenantEndpoints::new(
            settings(Some(Ports {
                first: 4400,
                last: 4404,
            })),
            4400,
            [4400, 4402].into(),
        );
        assert_eq!(e.pairing_ports(), vec![4401, 4403, 4404]);
        let any = TenantEndpoints::new(settings(None), 0, BTreeSet::new());
        assert_eq!(any.pairing_ports(), vec![0]);
    }

    struct Open;

    impl Trust for Open {
        fn allows(&self, _: &baton_identity::PublicKey) -> bool {
            true
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_link_keeps_its_port_and_pairing_takes_another() {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let base = probe.local_addr().unwrap().port();
        drop(probe);
        let Some(last) = base.checked_add(3) else {
            return;
        };
        let range = Ports { first: base, last };
        let e = TenantEndpoints::new(settings(Some(range)), base, [base].into());
        let me = Identity::generate();
        e.set_node(&me.node_id().to_string());
        let link = e.bind(&me, Arc::new(Open)).await.unwrap();
        assert_eq!(link.hint.direct[0].port(), base);
        let pairing = e.bind(&Identity::generate(), Arc::new(Open)).await.unwrap();
        let port = pairing.hint.direct[0].port();
        assert_ne!(port, base);
        assert!(range.contains(port));
        link.link.close().await;
        pairing.link.close().await;
    }
}
