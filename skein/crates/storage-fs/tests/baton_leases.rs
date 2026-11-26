//! Baton's lease and liveness suites with `lease-cas` over [`ControlState`] on files: the
//! arbiter of a Skein server whose control records live on a local disk.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use baton_core::{GroupId, NodeId, Timestamp};
use baton_lease::testing::{self, Harness};
use baton_lease::{Liveness, NodeProfile};
use baton_lease_cas::{CasLeases, CasLiveness};
use baton_state::StateStore;
use skein_storage::{ControlState, ObjectControl};
use skein_storage_fs::FsObjects;

const TTL: u64 = 10_000;

struct Clocked {
    live: Arc<CasLiveness>,
    now: Arc<AtomicI64>,
    registered: Mutex<Vec<NodeProfile>>,
}

impl Clocked {
    fn at(&self) -> Timestamp {
        Timestamp(self.now.load(Ordering::SeqCst))
    }
}

fn group() -> GroupId {
    GroupId::new("conf-lease").unwrap()
}

impl Harness for Clocked {
    async fn alive(&self, p: &NodeProfile) {
        self.registered.lock().unwrap().push(p.clone());
        self.live.heartbeat(&group(), p, self.at()).await.unwrap();
    }

    async fn kill(&self, node: &NodeId) {
        self.live.alive(&group(), self.at()).await.unwrap();
        self.registered.lock().unwrap().retain(|p| &p.node != node);
        self.now.fetch_add(TTL as i64 + 1, Ordering::SeqCst);
        let others = self.registered.lock().unwrap().clone();
        for p in &others {
            self.live.heartbeat(&group(), p, self.at()).await.unwrap();
        }
        self.live.alive(&group(), self.at()).await.unwrap();
    }
}

fn state(dir: &tempfile::TempDir) -> Arc<dyn StateStore> {
    let objects = FsObjects::open(dir.path()).unwrap();
    Arc::new(ControlState::new(Arc::new(ObjectControl::new(Arc::new(
        objects,
    )))))
}

#[tokio::test(flavor = "multi_thread")]
async fn lease_cas_over_control_records() {
    let dir = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let state = state(&dir);
    let live = Arc::new(CasLiveness::new(state.clone(), TTL));
    let now = Arc::new(AtomicI64::new(1_700_000_000_000));
    let clock = now.clone();
    let leases = CasLeases::new(state, live.clone())
        .with_clock(Arc::new(move || Timestamp(clock.load(Ordering::SeqCst))));
    let harness = Arc::new(Clocked {
        live,
        now,
        registered: Mutex::new(Vec::new()),
    });
    testing::leases(Arc::new(leases), harness).await;
    testing::liveness(Arc::new(CasLiveness::new(self::state(&other), TTL))).await;
}
