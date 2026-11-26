use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use baton_core::Timestamp;
use baton_lease::{Leases, Liveness, NodeProfile};
use baton_lease_cas::{CasLeases, CasLiveness, Clock};
use baton_signal::Signal;
use baton_signal_local::LocalSignal;
use baton_state::StateStore;
use baton_state_memory::MemoryState;
use skein_core::NodeId;
use skein_storage::{ControlState, Storage};

use crate::{Engine, OneGroupLiveness, node_profile};

pub(crate) const TTL_MS: u64 = 5_000;

pub(crate) fn profile(node: &str) -> NodeProfile {
    node_profile(NodeId::new(node).unwrap(), 1, true)
}

pub(crate) fn signal() -> Arc<dyn Signal> {
    Arc::new(LocalSignal::new())
}

pub(crate) fn leases_over(
    state: Arc<dyn StateStore>,
    ttl_ms: u64,
    clock: Option<Clock>,
) -> (Arc<dyn Leases>, Arc<dyn Liveness>) {
    let liveness: Arc<dyn Liveness> = Arc::new(OneGroupLiveness::nodes(Arc::new(
        CasLiveness::new(state.clone(), ttl_ms),
    )));
    let leases = CasLeases::new(state, liveness.clone());
    let leases = match clock {
        Some(c) => leases.with_clock(c),
        None => leases,
    };
    (Arc::new(leases), liveness)
}

pub(crate) fn single_leases() -> Arc<dyn Leases> {
    leases_over(Arc::new(MemoryState::new()), TTL_MS, None).0
}

pub(crate) fn control_leases(
    storage: &Storage,
    ttl_ms: u64,
    clock: Option<Clock>,
) -> (Arc<dyn Leases>, Arc<dyn Liveness>) {
    leases_over(
        Arc::new(ControlState::new(storage.control.clone())),
        ttl_ms,
        clock,
    )
}

pub(crate) fn engine_with(storage: Storage, leases: Arc<dyn Leases>, node: &str) -> Engine {
    Engine::new(storage, leases, signal(), profile(node))
}

#[derive(Clone)]
pub(crate) struct ManualClock(Arc<AtomicI64>);

impl ManualClock {
    pub(crate) fn new() -> Self {
        Self(Arc::new(AtomicI64::new(Timestamp::now().0)))
    }

    pub(crate) fn now(&self) -> Timestamp {
        Timestamp(self.0.load(Ordering::SeqCst))
    }

    pub(crate) fn advance(&self, ms: i64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }

    pub(crate) fn clock(&self) -> Clock {
        let c = self.0.clone();
        Arc::new(move || Timestamp(c.load(Ordering::SeqCst)))
    }
}
