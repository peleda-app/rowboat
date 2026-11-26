use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use baton_core::GroupId;
use baton_lease::{Liveness, preferred};
use futures::StreamExt;
use skein_core::{AccountId, TenantId, Timestamp, coordination};
use skein_mail::{MailError, MailProvider};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::{AccountConfig, Engine, EngineError};

/// An account the node may sync, with its provider.
#[derive(Clone)]
pub struct AccountEntry {
    /// How to sync it.
    pub config: AccountConfig,
    /// Where its mail is.
    pub provider: Arc<dyn MailProvider>,
    /// Where its calendars and contacts are, when they are synced.
    pub pim: Option<Arc<dyn skein_pim::PimProvider>>,
}

/// Where the engine learns which accounts exist. Implementations open sealed credentials and
/// build providers; the engine never sees credentials.
#[async_trait]
pub trait AccountDirectory: Send + Sync {
    /// Every account to consider. Called again every `RunConfig::rescan`.
    async fn accounts(&self) -> Result<Vec<AccountEntry>, EngineError>;
}

/// Why an [`AccountObserver`] failed: a short text with ids and kinds only, never content,
/// addresses or secrets.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ObserverError(pub String);

/// Work that follows an account's run on the node that owns it, such as delivering webhooks.
///
/// Called by the account's worker after every successful run (commands, then sync, then
/// maintenance), one observer after another, while the node still owns the account. Two calls
/// for the same account never overlap. A failure is logged and never fails or delays the
/// worker beyond the call itself.
#[async_trait]
pub trait AccountObserver: Send + Sync {
    /// The account's worker finished a successful run.
    async fn after_run(&self, tenant: &TenantId, account: &AccountId) -> Result<(), ObserverError>;
}

/// How a node runs.
#[derive(Clone)]
pub struct RunConfig {
    /// Where nodes announce they are alive: the same liveness the engine's leases judge holders
    /// by, answering for every tenant's group what it answers for `nodes` (as
    /// [`crate::OneGroupLiveness`] does), so that the node chosen to own an account can hold it.
    pub liveness: Arc<dyn Liveness>,
    /// The group the node heartbeats in and reads live nodes from, once per heartbeat.
    /// [`crate::NODES_GROUP`] by default.
    pub nodes: GroupId,
    /// Time between heartbeats and lease checks.
    pub heartbeat: Duration,
    /// Time between syncs of an account when its provider cannot push.
    pub interval: Duration,
    /// Longest wait after repeated failures.
    pub max_backoff: Duration,
    /// Snapshots and compaction after successful syncs.
    pub maintenance: crate::Maintenance,
    /// Called after every successful run of an account, in order. Empty by default.
    pub observers: Vec<Arc<dyn AccountObserver>>,
    /// Push subscriptions at providers that call back (Gmail, Graph), when the node has a
    /// public address. Without it, accounts are watched or polled as before.
    pub push: Option<PushConfig>,
}

/// How a node keeps provider push subscriptions alive.
#[derive(Clone)]
pub struct PushConfig {
    /// Subscribes and renews, recording subscriptions in the push registry.
    pub renewer: Arc<skein_push::Renewer>,
    /// The node's public address, such as `https://skein.example.com`.
    pub public_url: String,
    /// The Pub/Sub topic Gmail publishes to, when Gmail push is set up.
    pub gmail_topic: Option<String>,
}

impl RunConfig {
    /// Heartbeats in [`crate::NODES_GROUP`] every 10 s, syncs every 5 min without push, backoff up
    /// to 15 min.
    pub fn new(liveness: Arc<dyn Liveness>) -> Self {
        Self {
            liveness,
            nodes: GroupId::new(crate::NODES_GROUP).expect("constant"),
            heartbeat: Duration::from_secs(10),
            interval: Duration::from_secs(300),
            max_backoff: Duration::from_secs(900),
            maintenance: crate::Maintenance::default(),
            observers: Vec::new(),
            push: None,
        }
    }
}

type Key = (TenantId, AccountId);

struct Worker {
    stop: watch::Sender<bool>,
    handle: JoinHandle<()>,
}

/// Runs the node until `shutdown` completes: heartbeats with the engine's profile, picks the
/// accounts it should own with [`baton_lease::preferred`] over live nodes (the strongest class
/// first, then weighted rendezvous hashing), and keeps one worker per owned account that syncs on
/// push, on command hints and on the interval, with backoff on errors.
///
/// The engine stops acting on its leases once its heartbeats have not succeeded for the liveness
/// time-to-live less a fifth; workers then end and start again after the next successful
/// heartbeat, and a run still working with a lease taken before the lapse never reaches a provider
/// again. An account the node should no longer own is released once its worker has stopped,
/// and on shutdown every lease the node still holds is released.
pub async fn run(
    engine: Engine,
    directory: Arc<dyn AccountDirectory>,
    config: RunConfig,
    shutdown: impl Future<Output = ()>,
) {
    let mut workers: HashMap<Key, Worker> = HashMap::new();
    engine
        .holding
        .arm(crate::lease::valid_for(config.liveness.ttl_ms()));
    let mut tick = tokio::time::interval(config.heartbeat);
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            _ = tick.tick() => {}
        }
        workers.retain(|_, w| !w.handle.is_finished());
        let started = Instant::now();
        if let Err(e) = config
            .liveness
            .heartbeat(
                &config.nodes,
                engine.profile(),
                baton_core::Timestamp::now(),
            )
            .await
        {
            warn!(error = %e, "heartbeat failed");
            continue;
        }
        engine.holding.beat(started);
        let alive = match config
            .liveness
            .alive(&config.nodes, baton_core::Timestamp::now())
            .await
        {
            Ok(a) => a,
            Err(e) => {
                warn!(error = %e, "liveness unavailable");
                continue;
            }
        };
        let entries = match directory.accounts().await {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "account directory unavailable");
                continue;
            }
        };
        let mut wanted = HashMap::new();
        for entry in entries {
            let key = (entry.config.tenant.clone(), entry.config.account.clone());
            let mine = preferred(
                &coordination::group(&key.0),
                &coordination::lease_key(&key.1),
                &alive,
            )
            .is_some_and(|p| &p.node == engine.node());
            if mine {
                wanted.insert(key, entry);
            }
        }
        let leaving: Vec<Key> = workers
            .keys()
            .filter(|k| !wanted.contains_key(*k))
            .cloned()
            .collect();
        for key in leaving {
            if let Some(w) = workers.remove(&key) {
                let _ = w.stop.send(true);
                let engine = engine.clone();
                tokio::spawn(async move {
                    let _ = w.handle.await;
                    engine.release(&key.0, &key.1).await;
                });
            }
        }
        for (key, entry) in wanted {
            if workers.contains_key(&key) {
                continue;
            }
            let (stop, stopped) = watch::channel(false);
            let handle = tokio::spawn(worker(engine.clone(), entry, config.clone(), stopped));
            workers.insert(key, Worker { stop, handle });
        }
    }
    info!(workers = workers.len(), "node stopping");
    for w in workers.values() {
        let _ = w.stop.send(true);
    }
    for (key, w) in workers.drain() {
        let _ = w.handle.await;
        engine.release(&key.0, &key.1).await;
    }
}

async fn worker(
    engine: Engine,
    entry: AccountEntry,
    config: RunConfig,
    mut stop: watch::Receiver<bool>,
) {
    let account = entry.config.account.clone();
    let group = coordination::group(&entry.config.tenant);
    let command_hints = engine
        .signal
        .subscribe(&group, &format!("commands/{account}"))
        .await
        .ok();
    let push_hints = engine
        .signal
        .subscribe(&group, &skein_push::hint_topic(&account))
        .await
        .ok();
    let mut hints = match (command_hints, push_hints) {
        (Some(c), Some(p)) => Some(futures::stream::select(c, p).boxed()),
        (Some(c), None) => Some(c),
        (None, Some(p)) => Some(p),
        (None, None) => None,
    };
    let mut failures: u32 = 0;
    loop {
        if *stop.borrow() {
            return;
        }
        let mut next_due = None;
        let result = async {
            next_due = engine
                .run_commands(&entry.config, &*entry.provider)
                .await?
                .next_due;
            engine.sync_account(&entry.config, &*entry.provider).await
        }
        .await;
        let wait = match result {
            Ok(_) => {
                failures = 0;
                if let Err(e) = engine
                    .maintain(&entry.config.tenant, &account, &config.maintenance)
                    .await
                {
                    warn!(%account, error = %e, "maintenance failed");
                }
                for observer in &config.observers {
                    if let Err(e) = observer.after_run(&entry.config.tenant, &account).await {
                        warn!(%account, error = %e, "account observer failed");
                    }
                }
                if let Some(push) = &config.push {
                    keep_push(push, &entry, &account).await;
                }
                if let Some(pim) = &entry.pim {
                    let mut pim_config = entry.config.clone();
                    pim_config.include = None;
                    pim_config.exclude = Vec::new();
                    if let Err(e) = engine.run_pim_commands(&pim_config, &**pim).await {
                        warn!(%account, error = %e, "calendar and contact commands failed");
                    }
                    if let Err(e) = engine.sync_collections(&pim_config, &**pim).await {
                        warn!(%account, error = %e, "calendar and contact sync failed");
                    }
                }
                None
            }
            Err(EngineError::NotOwner) => {
                debug!(%account, "lost the lease");
                return;
            }
            Err(EngineError::Mail(MailError::Throttled { retry_after })) => {
                failures += 1;
                Some(retry_after.unwrap_or_else(|| backoff(failures, config.max_backoff)))
            }
            Err(e) => {
                failures += 1;
                warn!(%account, error = %e, failures, "account run failed");
                Some(backoff(failures, config.max_backoff))
            }
        };
        if let Some(wait) = wait {
            tokio::select! {
                _ = stop.changed() => return,
                _ = tokio::time::sleep(wait) => continue,
            }
        }
        let mut watch = match entry.provider.watch(&[]).await {
            Ok(w) => w,
            Err(e) => {
                debug!(%account, error = %e, "watch unavailable");
                None
            }
        };
        let pushed = async {
            match watch.as_mut() {
                Some(w) => w.next().await.map(|_| ()).map_err(|_| ()),
                None => std::future::pending().await,
            }
        };
        let hinted = async {
            match hints.as_mut() {
                Some(h) => {
                    h.next().await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        let sleep = match next_due {
            Some(at) => {
                let ms = (at.0 - skein_core::Timestamp::now().0).max(0) as u64;
                config.interval.min(Duration::from_millis(ms))
            }
            None => config.interval,
        };
        tokio::select! {
            _ = stop.changed() => return,
            _ = tokio::time::sleep(sleep) => {}
            _ = pushed => {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            _ = hinted => {}
        }
    }
}

async fn keep_push(push: &PushConfig, entry: &AccountEntry, account: &AccountId) {
    let tenant = &entry.config.tenant;
    let now = Timestamp::now();
    match push
        .renewer
        .registry()
        .due_for_renewal(tenant, account, now)
        .await
    {
        Ok(false) => return,
        Ok(true) => {}
        Err(e) => {
            debug!(%account, error = %e, "push registry unavailable");
            return;
        }
    }
    let client_state = match skein_push::random_client_state() {
        Ok(c) => c,
        Err(e) => {
            warn!(%account, error = %e, "no random bytes for a push subscription");
            return;
        }
    };
    let target = skein_mail::PushTarget {
        url: skein_push::graph_url(&push.public_url),
        client_state,
        gmail_topic: push.gmail_topic.clone(),
    };
    if let Err(e) = push
        .renewer
        .ensure(&*entry.provider, tenant, account, &target, now)
        .await
    {
        debug!(%account, error = %e, "push subscription not kept");
    }
}

fn backoff(failures: u32, max: Duration) -> Duration {
    let secs = 5u64.saturating_mul(1u64 << failures.min(10));
    Duration::from_secs(secs).min(max)
}

#[cfg(test)]
mod observer_tests {
    use std::sync::Mutex;

    use baton_state_memory::MemoryState;
    use skein_core::Seq;
    use skein_mail::testing::FakeMail;
    use skein_storage::Storage;
    use skein_storage_memory::MemoryObjects;

    use super::*;
    use crate::AccountConfig;
    use crate::test_support::{leases_over, profile, signal};

    struct One(AccountEntry);

    #[async_trait]
    impl AccountDirectory for One {
        async fn accounts(&self) -> Result<Vec<AccountEntry>, EngineError> {
            Ok(vec![self.0.clone()])
        }
    }

    #[derive(Default)]
    struct Seen {
        calls: Mutex<Vec<(TenantId, AccountId, Seq)>>,
        storage: Mutex<Option<Storage>>,
    }

    #[async_trait]
    impl AccountObserver for Seen {
        async fn after_run(
            &self,
            tenant: &TenantId,
            account: &AccountId,
        ) -> Result<(), ObserverError> {
            let storage = self.storage.lock().unwrap().clone().unwrap();
            let head = storage.log.head(tenant, account).await.unwrap();
            self.calls
                .lock()
                .unwrap()
                .push((tenant.clone(), account.clone(), head));
            Err(ObserverError("observer failures are only logged".into()))
        }
    }

    #[tokio::test]
    async fn observers_run_after_each_successful_run() {
        let storage = Storage::over(Arc::new(MemoryObjects::new()));
        let (leases, liveness) = leases_over(Arc::new(MemoryState::new()), 5_000, None);
        let engine = Engine::new(storage.clone(), leases, signal(), profile("n1"));
        let fake = FakeMail::new();
        fake.fill("INBOX", 3, 100);
        let tenant = TenantId::new("t").unwrap();
        let account = AccountId::new("box").unwrap();
        let directory = Arc::new(One(AccountEntry {
            config: AccountConfig::new(tenant.clone(), account.clone()),
            provider: Arc::new(fake),
            pim: None,
        }));
        let seen = Arc::new(Seen::default());
        *seen.storage.lock().unwrap() = Some(storage.clone());
        let mut config = RunConfig::new(liveness);
        config.heartbeat = Duration::from_millis(20);
        config.interval = Duration::from_millis(50);
        config.observers.push(seen.clone());
        let watcher = seen.clone();
        run(engine, directory, config, async move {
            for _ in 0..200 {
                if watcher.calls.lock().unwrap().len() >= 2 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        let calls = seen.calls.lock().unwrap().clone();
        assert!(
            calls.len() >= 2,
            "the worker kept running after a failing observer"
        );
        let (t, a, head) = &calls[0];
        assert_eq!((t, a), (&tenant, &account));
        assert!(head.0 >= 3, "observers run after the sync is journaled");
    }

    struct Flaky {
        inner: Arc<dyn Liveness>,
        failing: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl Liveness for Flaky {
        async fn heartbeat(
            &self,
            group: &GroupId,
            profile: &baton_lease::NodeProfile,
            now: baton_core::Timestamp,
        ) -> Result<(), baton_lease::LeaseError> {
            if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(baton_lease::LeaseError::Unavailable);
            }
            self.inner.heartbeat(group, profile, now).await
        }

        async fn alive(
            &self,
            group: &GroupId,
            now: baton_core::Timestamp,
        ) -> Result<Vec<baton_lease::NodeProfile>, baton_lease::LeaseError> {
            self.inner.alive(group, now).await
        }

        fn ttl_ms(&self) -> u64 {
            self.inner.ttl_ms()
        }
    }

    async fn head_reaches(storage: &Storage, t: &TenantId, a: &AccountId, at_least: u64) -> bool {
        for _ in 0..150 {
            if storage.log.head(t, a).await.unwrap().0 >= at_least {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    fn one_account(fake: &FakeMail) -> (Arc<One>, TenantId, AccountId) {
        let tenant = TenantId::new("t").unwrap();
        let account = AccountId::new("box").unwrap();
        let directory = Arc::new(One(AccountEntry {
            config: AccountConfig::new(tenant.clone(), account.clone()),
            provider: Arc::new(fake.clone()),
            pim: None,
        }));
        (directory, tenant, account)
    }

    #[tokio::test]
    async fn every_lease_is_released_on_shutdown() {
        let storage = Storage::over(Arc::new(MemoryObjects::new()));
        let (leases, liveness) = leases_over(Arc::new(MemoryState::new()), 5_000, None);
        let engine = Engine::new(storage.clone(), leases.clone(), signal(), profile("n1"));
        let fake = FakeMail::new();
        fake.fill("INBOX", 3, 100);
        let (directory, tenant, account) = one_account(&fake);
        let mut config = RunConfig::new(liveness);
        config.heartbeat = Duration::from_millis(20);
        config.interval = Duration::from_millis(50);
        let watched = storage.clone();
        let (t, a) = (tenant.clone(), account.clone());
        run(engine, directory, config, async move {
            assert!(head_reaches(&watched, &t, &a, 3).await);
        })
        .await;
        let group = coordination::group(&tenant);
        let key = coordination::lease_key(&account);
        assert!(
            leases.holder(&group, &key).await.unwrap().is_none(),
            "a stopped node holds nothing"
        );
        let next = leases
            .acquire(&group, &key, &profile("n2"))
            .await
            .unwrap()
            .expect("another node takes the account at once");
        assert!(next.fence.0 > 0);
    }

    #[tokio::test]
    async fn a_node_whose_heartbeats_fail_stops_acting_until_they_succeed_again() {
        let storage = Storage::over(Arc::new(MemoryObjects::new()));
        let (leases, liveness) = leases_over(Arc::new(MemoryState::new()), 200, None);
        let flaky = Arc::new(Flaky {
            inner: liveness,
            failing: std::sync::atomic::AtomicBool::new(false),
        });
        let engine = Engine::new(storage.clone(), leases, signal(), profile("n1"));
        let held = engine.holding.clone();
        let fake = FakeMail::new();
        fake.fill("INBOX", 3, 100);
        let (directory, tenant, account) = one_account(&fake);
        let mut config = RunConfig::new(flaky.clone());
        config.heartbeat = Duration::from_millis(20);
        config.interval = Duration::from_millis(30);
        let watched = storage.clone();
        let (t, a) = (tenant.clone(), account.clone());
        let control = flaky.clone();
        run(engine, directory, config, async move {
            assert!(head_reaches(&watched, &t, &a, 3).await);
            control
                .failing
                .store(true, std::sync::atomic::Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(400)).await;
            assert!(!held.held(), "the lease is given up on this node's side");
            let before = watched.log.head(&t, &a).await.unwrap();
            fake.fill("INBOX", 2, 100);
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(
                watched.log.head(&t, &a).await.unwrap(),
                before,
                "nothing is written while heartbeats fail"
            );
            control
                .failing
                .store(false, std::sync::atomic::Ordering::SeqCst);
            assert!(
                head_reaches(&watched, &t, &a, before.0 + 2).await,
                "work resumes after a successful heartbeat"
            );
        })
        .await;
    }
}
