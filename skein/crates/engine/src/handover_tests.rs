use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use baton_lease::{Lease, NodeClass, NodeProfile};
use baton_state_memory::MemoryState;
use skein_core::{AccountId, NodeId, TenantId, coordination};
use skein_mail::testing::FakeMail;
use skein_storage::Storage;
use skein_storage_memory::MemoryObjects;

use crate::test_support::{leases_over, signal};
use crate::{
    AccountConfig, AccountDirectory, AccountEntry, Eligible, Engine, EngineError, LeaseHooks,
    RunConfig, run,
};

const HANG: Duration = Duration::from_secs(300);

async fn until<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let waited = tokio::time::timeout(HANG, async {
        while !check().await {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(waited.is_ok(), "hung waiting for {what}");
}

fn node(name: &str, class: NodeClass) -> NodeProfile {
    NodeProfile {
        node: NodeId::new(name).unwrap(),
        class,
        weight: 1,
        can_run: true,
    }
}

struct One(AccountEntry);

#[async_trait]
impl AccountDirectory for One {
    async fn accounts(&self) -> Result<Vec<AccountEntry>, EngineError> {
        Ok(vec![self.0.clone()])
    }
}

#[derive(Default)]
struct Hooks {
    acquired: Mutex<Vec<(u64, u64)>>,
    releasing: Mutex<Vec<u64>>,
    fail: AtomicBool,
    storage: Mutex<Option<Storage>>,
}

impl Hooks {
    fn acquired(&self) -> Vec<(u64, u64)> {
        self.acquired.lock().unwrap().clone()
    }

    fn releasing(&self) -> Vec<u64> {
        self.releasing.lock().unwrap().clone()
    }
}

#[async_trait]
impl LeaseHooks for Hooks {
    async fn acquired(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        lease: &Lease,
    ) -> Result<(), EngineError> {
        let storage = self.storage.lock().unwrap().clone().unwrap();
        let head = storage.log.head(tenant, account).await.unwrap().0;
        self.acquired.lock().unwrap().push((lease.fence.0, head));
        if self.fail.load(Ordering::SeqCst) {
            return Err(EngineError::NotOwner);
        }
        Ok(())
    }

    async fn releasing(&self, _: &TenantId, _: &AccountId, lease: &Lease) {
        self.releasing.lock().unwrap().push(lease.fence.0);
    }
}

struct Only(NodeId);

impl Eligible for Only {
    fn may_lead(&self, _: &TenantId, _: &AccountId, node: &NodeId) -> bool {
        node == &self.0
    }
}

fn ids() -> (TenantId, AccountId) {
    (TenantId::new("t").unwrap(), AccountId::new("box").unwrap())
}

fn entry(fake: &FakeMail) -> Arc<One> {
    let (tenant, account) = ids();
    Arc::new(One(AccountEntry {
        config: AccountConfig::new(tenant, account),
        provider: Arc::new(fake.clone()),
        pim: None,
    }))
}

fn fast(liveness: Arc<dyn baton_lease::Liveness>) -> RunConfig {
    let mut config = RunConfig::new(liveness);
    config.heartbeat = Duration::from_millis(20);
    config.interval = Duration::from_millis(30);
    config
}

#[tokio::test]
async fn hooks_run_once_per_taken_lease_before_anything_is_written_and_before_release() {
    let storage = Storage::over(Arc::new(MemoryObjects::new()));
    let (leases, liveness) = leases_over(Arc::new(MemoryState::new()), 60_000, None);
    let hooks = Arc::new(Hooks::default());
    *hooks.storage.lock().unwrap() = Some(storage.clone());
    let engine = Engine::new(
        storage.clone(),
        leases.clone(),
        signal(),
        node("n1", NodeClass::Desktop),
    )
    .with_lease_hooks(hooks.clone());
    let fake = FakeMail::new();
    fake.fill("INBOX", 3, 100);
    let (t, a) = ids();
    let watched = storage.clone();
    let (wt, wa) = (t.clone(), a.clone());
    let probe = engine.clone();
    let seen = hooks.clone();
    run(engine, entry(&fake), fast(liveness), async move {
        until("the first sync", || async {
            watched.log.head(&wt, &wa).await.unwrap().0 >= 3
        })
        .await;
        assert!(probe.holds_lease(&wt, &wa));
        fake.fill("INBOX", 2, 100);
        until("a later sync", || async {
            watched.log.head(&wt, &wa).await.unwrap().0 >= 5
        })
        .await;
        assert_eq!(seen.acquired().len(), 1, "renewals call nothing");
    })
    .await;
    let acquired = hooks.acquired();
    assert_eq!(acquired.len(), 1);
    assert_eq!(acquired[0].1, 0, "the hook ran before the first event");
    assert_eq!(
        hooks.releasing(),
        vec![acquired[0].0],
        "released once, same token"
    );
    let holder = leases
        .holder(&coordination::group(&t), &coordination::lease_key(&a))
        .await
        .unwrap();
    assert!(holder.is_none());
}

#[tokio::test]
async fn a_failing_acquired_hook_gives_the_lease_back_and_nothing_runs() {
    let storage = Storage::over(Arc::new(MemoryObjects::new()));
    let (leases, liveness) = leases_over(Arc::new(MemoryState::new()), 60_000, None);
    let hooks = Arc::new(Hooks::default());
    hooks.fail.store(true, Ordering::SeqCst);
    *hooks.storage.lock().unwrap() = Some(storage.clone());
    let engine = Engine::new(
        storage.clone(),
        leases.clone(),
        signal(),
        node("n1", NodeClass::Desktop),
    )
    .with_lease_hooks(hooks.clone());
    let fake = FakeMail::new();
    fake.fill("INBOX", 3, 100);
    let (t, a) = ids();
    let seen = hooks.clone();
    let probe = engine.clone();
    let (wt, wa) = (t.clone(), a.clone());
    let checked = leases.clone();
    run(engine, entry(&fake), fast(liveness), async move {
        until("two refused takes", || async { seen.acquired().len() >= 2 }).await;
        assert!(!probe.holds_lease(&wt, &wa));
        let holder = checked
            .holder(&coordination::group(&wt), &coordination::lease_key(&wa))
            .await
            .unwrap();
        assert!(holder.is_none_or(|l| l.node.as_str() != "n1" || seen.acquired().len() > 2));
    })
    .await;
    assert_eq!(storage.log.head(&t, &a).await.unwrap().0, 0);
    assert!(hooks.releasing().is_empty(), "nothing was held to release");
}

#[tokio::test]
async fn a_stronger_node_takes_over_at_a_clean_point_and_hands_back_when_it_cannot_run() {
    let storage = Storage::over(Arc::new(MemoryObjects::new()));
    let state = Arc::new(MemoryState::new());
    let (leases, liveness) = leases_over(state.clone(), 60_000, None);
    let desktop_hooks = Arc::new(Hooks::default());
    let server_hooks = Arc::new(Hooks::default());
    *desktop_hooks.storage.lock().unwrap() = Some(storage.clone());
    *server_hooks.storage.lock().unwrap() = Some(storage.clone());
    let desktop = Engine::new(
        storage.clone(),
        leases.clone(),
        signal(),
        node("desk", NodeClass::Desktop),
    )
    .with_lease_hooks(desktop_hooks.clone());
    let server = Engine::new(
        storage.clone(),
        leases.clone(),
        signal(),
        node("srv", NodeClass::Server),
    )
    .with_lease_hooks(server_hooks.clone());
    let fake = FakeMail::new();
    fake.fill("INBOX", 3, 100);
    let (t, a) = ids();
    let (stop_server, server_stopped) = tokio::sync::oneshot::channel::<()>();
    let server_probe = server.clone();
    let directory = entry(&fake);
    let server_run = {
        let liveness = liveness.clone();
        let directory = directory.clone();
        async move {
            run(server, directory, fast(liveness), async move {
                let _ = server_stopped.await;
            })
            .await;
        }
    };
    let watched = storage.clone();
    let (wt, wa) = (t.clone(), a.clone());
    let desktop_probe = desktop.clone();
    let seen_desktop = desktop_hooks.clone();
    let seen_server = server_hooks.clone();
    let checked = leases.clone();
    run(desktop, directory, fast(liveness), async move {
        until("the desktop's first sync", || async {
            watched.log.head(&wt, &wa).await.unwrap().0 >= 3
        })
        .await;
        let server_task = tokio::spawn(server_run);
        until("the server's lease", || async {
            server_probe.holds_lease(&wt, &wa)
        })
        .await;
        assert!(!desktop_probe.holds_lease(&wt, &wa));
        let released = seen_desktop.releasing();
        let taken = seen_server.acquired();
        assert_eq!(released.len(), 1, "the desktop handed over once");
        assert_eq!(taken.len(), 1);
        assert!(
            taken[0].0 > released[0],
            "the new holder has a higher token"
        );
        assert!(taken[0].1 >= 3, "it continues from the desktop's head");
        fake.fill("INBOX", 1, 100);
        until("the server's sync", || async {
            watched.log.head(&wt, &wa).await.unwrap().0 >= 4
        })
        .await;
        let head = watched.log.signed_head(&wt, &wa).await.unwrap();
        assert_eq!(head.head.fence.0, taken[0].0);

        server_probe.set_can_run(false);
        until("the desktop's lease again", || async {
            desktop_probe.holds_lease(&wt, &wa)
        })
        .await;
        until("the server to know it lost the lease", || async {
            !server_probe.holds_lease(&wt, &wa)
        })
        .await;
        assert!(seen_server.releasing().len() <= 1);
        let back = seen_desktop.acquired();
        assert_eq!(back.len(), 2);
        assert!(back[1].0 > taken[0].0);
        let holder = checked
            .holder(&coordination::group(&wt), &coordination::lease_key(&wa))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(holder.node.as_str(), "desk");
        let _ = stop_server.send(());
        let _ = server_task.await;
    })
    .await;
}

#[tokio::test]
async fn a_weaker_live_holder_is_asked_to_hand_over() {
    let storage = Storage::over(Arc::new(MemoryObjects::new()));
    let (leases, liveness) = leases_over(Arc::new(MemoryState::new()), 60_000, None);
    let (t, a) = ids();
    let group = coordination::group(&t);
    let key = coordination::lease_key(&a);
    let phone = node("phone", NodeClass::Phone);
    let now = baton_core::Timestamp::now();
    liveness.heartbeat(&group, &phone, now).await.unwrap();
    let held = leases.acquire(&group, &key, &phone).await.unwrap().unwrap();
    let desktop = Engine::new(
        storage.clone(),
        leases.clone(),
        signal(),
        node("desk", NodeClass::Desktop),
    );
    let desktop_profile = desktop.profile();
    liveness
        .heartbeat(&group, &desktop_profile, now)
        .await
        .unwrap();
    let config = AccountConfig::new(t.clone(), a.clone());
    assert!(matches!(
        desktop.lease(&config).await,
        Err(EngineError::NotOwner)
    ));
    let record = leases.holder(&group, &key).await.unwrap().unwrap();
    assert_eq!(record.node, held.node);
    assert_eq!(
        record.takeover.map(|t| t.node.as_str().to_owned()),
        Some("desk".to_owned())
    );
}

#[tokio::test]
async fn only_eligible_nodes_are_chosen() {
    let storage = Storage::over(Arc::new(MemoryObjects::new()));
    let (leases, liveness) = leases_over(Arc::new(MemoryState::new()), 60_000, None);
    let (t, a) = ids();
    let group = coordination::group(&t);
    let server = node("srv", NodeClass::Server);
    liveness
        .heartbeat(&group, &server, baton_core::Timestamp::now())
        .await
        .unwrap();
    let engine = Engine::new(
        storage.clone(),
        leases,
        signal(),
        node("desk", NodeClass::Desktop),
    );
    let fake = FakeMail::new();
    fake.fill("INBOX", 2, 100);
    let mut config = fast(liveness.clone());
    config.nodes = group.clone();
    config.eligible = Some(Arc::new(Only(NodeId::new("desk").unwrap())));
    let watched = storage.clone();
    let (wt, wa) = (t.clone(), a.clone());
    let beat = liveness.clone();
    run(engine, entry(&fake), config, async move {
        until("the desktop syncs although a server is alive", || async {
            let _ = beat
                .heartbeat(&group, &server, baton_core::Timestamp::now())
                .await;
            watched.log.head(&wt, &wa).await.unwrap().0 >= 2
        })
        .await;
    })
    .await;
}

struct Counting {
    inner: Arc<dyn baton_lease::Liveness>,
    beats: std::sync::atomic::AtomicU64,
}

#[async_trait]
impl baton_lease::Liveness for Counting {
    async fn heartbeat(
        &self,
        group: &baton_core::GroupId,
        profile: &NodeProfile,
        now: baton_core::Timestamp,
    ) -> Result<(), baton_lease::LeaseError> {
        self.beats.fetch_add(1, Ordering::SeqCst);
        self.inner.heartbeat(group, profile, now).await
    }

    async fn alive(
        &self,
        group: &baton_core::GroupId,
        now: baton_core::Timestamp,
    ) -> Result<Vec<NodeProfile>, baton_lease::LeaseError> {
        self.inner.alive(group, now).await
    }

    fn ttl_ms(&self) -> u64 {
        self.inner.ttl_ms()
    }
}

struct Stuck {
    entered: AtomicBool,
    go: tokio::sync::Notify,
}

#[async_trait]
impl LeaseHooks for Stuck {
    async fn acquired(&self, _: &TenantId, _: &AccountId, _: &Lease) -> Result<(), EngineError> {
        Ok(())
    }

    async fn releasing(&self, _: &TenantId, _: &AccountId, _: &Lease) {
        self.entered.store(true, Ordering::SeqCst);
        self.go.notified().await;
    }
}

#[tokio::test]
async fn a_slow_handover_never_holds_heartbeats_up() {
    let storage = Storage::over(Arc::new(MemoryObjects::new()));
    let (leases, liveness) = leases_over(Arc::new(MemoryState::new()), 60_000, None);
    let counting = Arc::new(Counting {
        inner: liveness,
        beats: std::sync::atomic::AtomicU64::new(0),
    });
    let stuck = Arc::new(Stuck {
        entered: AtomicBool::new(false),
        go: tokio::sync::Notify::new(),
    });
    let engine = Engine::new(
        storage.clone(),
        leases,
        signal(),
        node("n1", NodeClass::Desktop),
    )
    .with_lease_hooks(stuck.clone());
    let fake = FakeMail::new();
    fake.fill("INBOX", 2, 100);
    let (t, a) = ids();
    let probe = engine.clone();
    let beats = counting.clone();
    let hook = stuck.clone();
    run(engine, entry(&fake), fast(counting), async move {
        until("the lease", || async { probe.holds_lease(&t, &a) }).await;
        probe.set_can_run(false);
        until("the handover to start", || async {
            hook.entered.load(Ordering::SeqCst)
        })
        .await;
        let before = beats.beats.load(Ordering::SeqCst);
        until("heartbeats while the handover is under way", || async {
            beats.beats.load(Ordering::SeqCst) >= before + 3
        })
        .await;
        hook.go.notify_one();
    })
    .await;
}

/// Regression (security review): a journal claimed with a fence above every token the arbiter
/// grants (a predecessor whose clock ran ahead) made the claim fail while the lease stayed with
/// the node, and every retry renewed the same token: the account was stranded for good. The lease
/// is now given back, so another node or a later, higher grant can proceed.
#[tokio::test]
async fn a_claim_refused_by_a_higher_fence_gives_the_lease_back() {
    let storage = Storage::over(Arc::new(MemoryObjects::new()));
    let (leases, liveness) = leases_over(Arc::new(MemoryState::new()), 60_000, None);
    let (t, a) = ids();
    let group = coordination::group(&t);
    let key = coordination::lease_key(&a);
    let ahead = (baton_core::Timestamp::now().0 as u64 + 600_000) * 1000;
    storage
        .log
        .claim(&t, &a, skein_core::FencingToken(ahead))
        .await
        .unwrap();
    let srv = Engine::new(
        storage.clone(),
        leases.clone(),
        signal(),
        node("srv", NodeClass::Server),
    );
    let now = baton_core::Timestamp::now();
    baton_lease::Liveness::heartbeat(&*liveness, &group, &srv.profile(), now)
        .await
        .unwrap();
    let config = AccountConfig::new(t.clone(), a.clone());
    assert!(matches!(
        srv.lease(&config).await,
        Err(EngineError::NotOwner)
    ));
    assert!(!srv.holds_lease(&t, &a));
    assert_eq!(
        baton_lease::Leases::holder(&*leases, &group, &key)
            .await
            .unwrap(),
        None,
        "the lease is given back"
    );
    let desk = node("desk", NodeClass::Desktop);
    baton_lease::Liveness::heartbeat(&*liveness, &group, &desk, now)
        .await
        .unwrap();
    assert!(
        baton_lease::Leases::acquire(&*leases, &group, &key, &desk)
            .await
            .unwrap()
            .is_some(),
        "another node may take it"
    );
}

struct Flaky {
    inner: Arc<dyn baton_lease::Liveness>,
    fail: AtomicBool,
}

#[async_trait]
impl baton_lease::Liveness for Flaky {
    async fn heartbeat(
        &self,
        group: &baton_core::GroupId,
        profile: &NodeProfile,
        now: baton_core::Timestamp,
    ) -> Result<(), baton_lease::LeaseError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(baton_lease::LeaseError::Unavailable);
        }
        self.inner.heartbeat(group, profile, now).await
    }

    async fn alive(
        &self,
        group: &baton_core::GroupId,
        now: baton_core::Timestamp,
    ) -> Result<Vec<NodeProfile>, baton_lease::LeaseError> {
        self.inner.alive(group, now).await
    }

    fn ttl_ms(&self) -> u64 {
        self.inner.ttl_ms()
    }
}

struct Switch(AtomicBool);

impl Eligible for Switch {
    fn may_lead(&self, _: &TenantId, _: &AccountId, _: &NodeId) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Regression: a worker whose heartbeats lapsed ended on its own and left its lease in the
/// arbiter's record; once the node no longer wanted the account (another node was preferred),
/// nothing released it, and while the node kept heartbeating nobody else could take it.
#[tokio::test]
async fn a_lease_left_by_a_worker_that_lapsed_is_released_once_unwanted() {
    let storage = Storage::over(Arc::new(MemoryObjects::new()));
    let (leases, liveness) = leases_over(Arc::new(MemoryState::new()), 300, None);
    let (t, a) = ids();
    let group = coordination::group(&t);
    let key = coordination::lease_key(&a);
    let flaky = Arc::new(Flaky {
        inner: liveness,
        fail: AtomicBool::new(false),
    });
    let wanted = Arc::new(Switch(AtomicBool::new(true)));
    let engine = Engine::new(
        storage.clone(),
        leases.clone(),
        signal(),
        node("desk", NodeClass::Desktop),
    );
    let fake = FakeMail::new();
    fake.fill("INBOX", 2, 100);
    let mut config = fast(flaky.clone());
    config.nodes = group.clone();
    config.eligible = Some(wanted.clone());
    let watched = engine.clone();
    run(engine, entry(&fake), config, async move {
        until("the desktop to hold the account", || async {
            watched.storage.log.head(&t, &a).await.unwrap().0 >= 2
                && leases.holder(&group, &key).await.unwrap().is_some()
        })
        .await;
        flaky.fail.store(true, Ordering::SeqCst);
        until("the worker to end on the lapse", || async {
            !watched.has_worker(&t, &a)
        })
        .await;
        assert_eq!(
            leases
                .holder(&group, &key)
                .await
                .unwrap()
                .unwrap()
                .node
                .as_str(),
            "desk",
            "the record still names the desktop"
        );
        wanted.0.store(false, Ordering::SeqCst);
        flaky.fail.store(false, Ordering::SeqCst);
        until("the left lease to be released", || async {
            leases.holder(&group, &key).await.unwrap().is_none()
        })
        .await;
    })
    .await;
}
