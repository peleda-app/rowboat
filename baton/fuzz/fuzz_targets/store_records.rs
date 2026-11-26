#![no_main]

use std::sync::Arc;

use baton_core::{GroupId, LeaseKey, NodeId, Timestamp};
use baton_lease::{Leases, Liveness, NodeClass, NodeProfile};
use baton_lease_cas::{CasLeases, CasLiveness};
use baton_state::RecordName;
use baton_state_memory::MemoryState;
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let split = data
        .first()
        .map_or(0, |b| *b as usize)
        .min(data.len().saturating_sub(1));
    let (heartbeat, lease) = data
        .get(1..)
        .unwrap_or_default()
        .split_at(split.min(data.len().saturating_sub(1)));
    let g = GroupId::new("g").unwrap();
    let state = Arc::new(MemoryState::new());
    state.tamper(
        &g,
        &RecordName::new("nodes/x").unwrap(),
        Bytes::copy_from_slice(heartbeat),
    );
    state.tamper(
        &g,
        &RecordName::new("lease/k").unwrap(),
        Bytes::copy_from_slice(lease),
    );
    let live = Arc::new(CasLiveness::new(state.clone(), 1_000));
    let clock: baton_lease_cas::Clock = Arc::new(|| Timestamp(1_000_000));
    let leases = CasLeases::new(state, live.clone()).with_clock(clock);
    let p = NodeProfile {
        node: NodeId::new("y").unwrap(),
        class: NodeClass::Server,
        weight: 1,
        can_run: true,
    };
    futures::executor::block_on(async {
        let alive = live.alive(&g, Timestamp(i64::MIN)).await.unwrap();
        assert!(alive.len() <= 1);
        let _ = live.alive(&g, Timestamp(i64::MAX)).await.unwrap();
        if let Ok(Some(l)) = leases.acquire(&g, &LeaseKey::new("k").unwrap(), &p).await {
            assert!(l.fence.0 > 0);
        }
        let _ = leases.holder(&g, &LeaseKey::new("k").unwrap()).await;
    });
});
