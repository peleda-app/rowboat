use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use async_trait::async_trait;
use baton_core::{GroupId, Timestamp};
use baton_identity::Identity;
use baton_keys::{KemSecret, RecoveryRoot};
use baton_lease::NodeClass;
use baton_state::StateStore;
use baton_state_memory::MemoryState;

use crate::pairing::{Confirm, PairingCheck};
use crate::{DAY_MS, Membership, NodeKeys, Now};

pub(crate) const T0: i64 = 1_800_000_000_000;

#[derive(Clone)]
pub(crate) struct Clock(pub Arc<AtomicI64>);

impl Clock {
    pub(crate) fn new() -> Self {
        Self(Arc::new(AtomicI64::new(T0)))
    }
    pub(crate) fn now(&self) -> Now {
        let c = self.0.clone();
        Arc::new(move || Timestamp(c.load(Ordering::SeqCst)))
    }
    pub(crate) fn advance(&self, ms: i64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }
}

pub(crate) fn keys(member: Option<&Identity>) -> NodeKeys {
    NodeKeys {
        identity: Identity::generate(),
        kem: KemSecret::generate(),
        member: member.cloned(),
    }
}

pub(crate) fn store() -> Arc<dyn StateStore> {
    Arc::new(MemoryState::new())
}

pub(crate) fn group() -> GroupId {
    GroupId::new("gtestgroup").unwrap()
}

pub(crate) async fn found(clock: &Clock) -> (Arc<Membership>, Identity, Arc<dyn StateStore>) {
    let member = Identity::generate();
    let store = store();
    let m = Membership::found(
        store.clone(),
        group(),
        keys(Some(&member)),
        RecoveryRoot::generate().public(),
        RecoveryRoot::generate().public(),
        NodeClass::Desktop,
        Timestamp(T0 + 400 * DAY_MS),
        clock.now(),
    )
    .await
    .unwrap();
    (Arc::new(m), member, store)
}

pub(crate) struct Answer(pub bool);

#[async_trait]
impl Confirm for Answer {
    async fn confirm(&self, _: &PairingCheck) -> bool {
        self.0
    }
}

pub(crate) struct Recorder(pub std::sync::Mutex<Vec<PairingCheck>>, pub bool);

#[async_trait]
impl Confirm for Recorder {
    async fn confirm(&self, check: &PairingCheck) -> bool {
        self.0.lock().unwrap().push(check.clone());
        self.1
    }
}
