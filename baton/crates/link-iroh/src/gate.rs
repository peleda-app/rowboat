use std::fmt;
use std::sync::Arc;

use baton_link::{LinkError, PublicKey, Trust};
use iroh::EndpointAddr;
use iroh::endpoint::{
    AfterHandshakeOutcome, BeforeConnectOutcome, Connection, EndpointHooks, VarInt,
};

use crate::PostQuantum;

pub(crate) const CODE_UNTRUSTED: u32 = 403;
pub(crate) const CODE_PQ: u32 = 426;

pub(crate) fn to_iroh(key: &PublicKey) -> Result<iroh::EndpointId, LinkError> {
    iroh::PublicKey::from_bytes(&key.to_bytes()).map_err(|_| LinkError::Unreachable)
}

pub(crate) fn to_baton(id: &iroh::EndpointId) -> Result<PublicKey, LinkError> {
    PublicKey::from_bytes(id.as_bytes()).map_err(|_| LinkError::Rejected)
}

pub(crate) fn negotiated_hybrid(conn: &Connection) -> bool {
    conn.handshake_data()
        .and_then(|d| d.downcast::<noq::crypto::rustls::HandshakeData>().ok())
        .is_some_and(|d| {
            d.negotiated_key_exchange_group == Some(rustls::NamedGroup::X25519MLKEM768)
        })
}

/// Endpoint hooks that hold every peer connection to the trust and the key exchange policy.
pub(crate) struct Gate {
    trust: Arc<dyn Trust>,
    pq: PostQuantum,
}

impl Gate {
    pub(crate) fn new(trust: Arc<dyn Trust>, pq: PostQuantum) -> Self {
        Self { trust, pq }
    }

    fn allows(&self, id: &iroh::EndpointId) -> bool {
        to_baton(id).is_ok_and(|k| self.trust.reachable(&k))
    }
}

impl fmt::Debug for Gate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gate")
            .field("pq", &self.pq)
            .finish_non_exhaustive()
    }
}

impl EndpointHooks for Gate {
    async fn before_connect<'a>(
        &'a self,
        remote_addr: &'a EndpointAddr,
        _alpn: &'a [u8],
    ) -> BeforeConnectOutcome {
        if self.allows(&remote_addr.id) {
            BeforeConnectOutcome::Accept
        } else {
            BeforeConnectOutcome::Reject
        }
    }

    async fn after_handshake<'a>(&'a self, conn: &'a Connection) -> AfterHandshakeOutcome {
        if !self.allows(&conn.remote_id()) {
            return AfterHandshakeOutcome::Reject {
                error_code: VarInt::from_u32(CODE_UNTRUSTED),
                reason: b"untrusted".to_vec(),
            };
        }
        if self.pq == PostQuantum::Required && !negotiated_hybrid(conn) {
            return AfterHandshakeOutcome::Reject {
                error_code: VarInt::from_u32(CODE_PQ),
                reason: b"hybrid key exchange required".to_vec(),
            };
        }
        AfterHandshakeOutcome::Accept
    }
}
