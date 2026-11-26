//! Node-loop scenarios: many accounts on one or more nodes running [`skein_engine::run`] over one
//! shared object store, with optional store latency and node failures, and a check of every
//! account's journal afterwards.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use baton_core::{GroupId, Timestamp};
use baton_lease::{LeaseError, Leases, Liveness, NodeProfile};
use baton_lease_cas::{CasLeases, CasLiveness};
use baton_signal::Signal;
use baton_signal_local::LocalSignal;
use bytes::Bytes;
use skein_core::{AccountId, Event, EventBody, FencingToken, NodeId, Seq, TenantId, coordination};
use skein_engine::{
    AccountConfig, AccountDirectory, AccountEntry, AccountObserver, Engine, EngineError,
    ObserverError, OneGroupLiveness, RunConfig, node_profile,
};
use skein_mail::testing::FakeMail;
use skein_storage::testing::SlowObjects;
use skein_storage::{
    ControlState, CountingObjects, Expect, Log, ObjectCounts, ObjectKey, ObjectLog, Objects,
    SegmentRef, SegmentSource, SignedHead, Snapshot, Storage, StorageError, Version,
};
use tokio::sync::watch;

/// Latency added to every object store call.
#[derive(Debug, Clone, Copy)]
pub struct Latency {
    /// Fixed part of every call.
    pub base: Duration,
    /// Upper bound of the random part added to `base`.
    pub jitter: Duration,
}

/// Nodes that fail once a share of the accounts finished their first sync.
#[derive(Debug, Clone, Copy)]
pub struct Fault {
    /// Share of accounts (0.0–1.0) that must have finished their first sync before the failure.
    pub after: f64,
    /// Nodes that crash: their task is aborted and their store calls fail from then on.
    pub crash: usize,
    /// Nodes whose heartbeats stop while they keep running, until their own lease validity or
    /// fencing stops them.
    pub zombie: usize,
}

/// What to simulate.
#[derive(Debug, Clone)]
pub struct Fleet {
    /// Accounts in the directory every node sees.
    pub accounts: usize,
    /// Messages in each account's `INBOX` before the first sync.
    pub history: usize,
    /// Messages added to each account after the first sync. With a fault they arrive one per
    /// account at a time, spread over the time survivors need to notice the failure, so failed
    /// nodes and survivors write while ownership moves.
    pub extra: usize,
    /// Message size in bytes.
    pub size: usize,
    /// Nodes running the node loop.
    pub nodes: usize,
    /// Store latency, if any.
    pub latency: Option<Latency>,
    /// Node failures, if any.
    pub fault: Option<Fault>,
    /// Heartbeat period of every node.
    pub heartbeat: Duration,
    /// How long a node stays alive after its last heartbeat.
    pub ttl: Duration,
    /// Time between syncs of an idle account; workers otherwise wake on provider pushes and
    /// command hints. Long by default so polling does not blur the request counts.
    pub interval: Duration,
    /// Longest wait for every account to finish; the run reports a violation past it.
    pub timeout: Duration,
}

impl Fleet {
    /// `accounts` accounts with `history` small messages each on one node, no faults.
    pub fn many(accounts: usize, history: usize) -> Self {
        Self {
            accounts,
            history,
            extra: 0,
            size: 1_000,
            nodes: 1,
            latency: None,
            fault: None,
            heartbeat: Duration::from_millis(100),
            ttl: Duration::from_millis(1_500),
            interval: Duration::from_secs(600),
            timeout: Duration::from_secs(120),
        }
    }
}

/// Measurements and findings of a run.
#[derive(Debug, Clone, Default)]
pub struct FleetOutcome {
    /// Requests until every account finished its first sync.
    pub initial: ObjectCounts,
    /// Requests of the whole run, heartbeats included.
    pub total: ObjectCounts,
    /// Messages journaled in the first sync.
    pub initial_messages: u64,
    /// Messages journaled in total.
    pub messages: u64,
    /// Wall time until every account finished its first sync.
    pub initial_time: Duration,
    /// Wall time from the failure until every account held all its messages.
    pub recovery_time: Option<Duration>,
    /// Committed appends per node.
    pub appends: Vec<u64>,
    /// Appends refused with [`StorageError::Fenced`] per node.
    pub fenced: Vec<u64>,
    /// Accounts a failed node wrote to that a survivor then wrote to with a higher token.
    pub taken_over: usize,
    /// Taken-over accounts whose journal refused a write carrying the failed node's last token,
    /// probed after the run; equals `taken_over` when fencing holds.
    pub stale_refused: usize,
    /// Highest fencing token any account reached.
    pub max_fence: u64,
    /// `mailbox_upserted`, `mailbox_deleted` and `first_sync_completed` events journaled twice
    /// under the same key. The engine filters repeats of message events only, so a node that
    /// crashes after journaling one of these but before saving its account state makes the next
    /// owner journal it again. Folding such a repeat changes nothing, so it is counted here rather
    /// than as a violation.
    pub repeated_account_events: usize,
    /// Broken guarantees; empty when the run is correct.
    pub violations: Vec<String>,
}

impl FleetOutcome {
    /// Object store writes per message in the first sync.
    pub fn initial_puts_per_message(&self) -> f64 {
        self.initial.puts as f64 / self.initial_messages.max(1) as f64
    }

    /// Object store writes per account in the first sync beyond one per message: cursors,
    /// journal segments and heads, lease records and heartbeats.
    pub fn initial_overhead_puts_per_account(&self, accounts: usize) -> f64 {
        (self.initial.puts as f64 - self.initial_messages as f64) / accounts.max(1) as f64
    }

    /// Object store reads per message in the first sync.
    pub fn initial_gets_per_message(&self) -> f64 {
        self.initial.gets as f64 / self.initial_messages.max(1) as f64
    }
}

#[derive(Clone)]
struct Append {
    node: usize,
    account: AccountId,
    fence: u64,
    first: u64,
    last: u64,
}

#[derive(Default)]
struct Journal {
    appends: Mutex<Vec<Append>>,
    fenced: Mutex<HashMap<usize, u64>>,
}

struct RecordedLog {
    inner: Arc<dyn Log>,
    node: usize,
    journal: Arc<Journal>,
}

#[async_trait]
impl SegmentSource for RecordedLog {
    async fn segment(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        segment: &SegmentRef,
    ) -> Result<Option<Bytes>, StorageError> {
        self.inner.segment(tenant, account, segment).await
    }
}

#[async_trait]
impl Log for RecordedLog {
    async fn append(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        fence: FencingToken,
        events: Vec<Event>,
    ) -> Result<Vec<Event>, StorageError> {
        let result = self.inner.append(tenant, account, fence, events).await;
        match &result {
            Ok(committed) if !committed.is_empty() => {
                self.journal.appends.lock().unwrap().push(Append {
                    node: self.node,
                    account: account.clone(),
                    fence: fence.0,
                    first: committed[0].seq.0,
                    last: committed[committed.len() - 1].seq.0,
                });
            }
            Err(StorageError::Fenced) => {
                *self
                    .journal
                    .fenced
                    .lock()
                    .unwrap()
                    .entry(self.node)
                    .or_default() += 1;
            }
            _ => {}
        }
        result
    }

    async fn claim(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        fence: FencingToken,
    ) -> Result<(), StorageError> {
        self.inner.claim(tenant, account, fence).await
    }

    async fn head(&self, tenant: &TenantId, account: &AccountId) -> Result<Seq, StorageError> {
        self.inner.head(tenant, account).await
    }

    async fn signed_head(
        &self,
        tenant: &TenantId,
        account: &AccountId,
    ) -> Result<SignedHead, StorageError> {
        self.inner.signed_head(tenant, account).await
    }

    async fn read(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        from: Seq,
        limit: usize,
    ) -> Result<Vec<Event>, StorageError> {
        self.inner.read(tenant, account, from, limit).await
    }

    async fn heads(&self, tenant: &TenantId) -> Result<Vec<(AccountId, Seq)>, StorageError> {
        self.inner.heads(tenant).await
    }

    async fn put_snapshot(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        snapshot: &Snapshot,
    ) -> Result<(), StorageError> {
        self.inner.put_snapshot(tenant, account, snapshot).await
    }

    async fn latest_snapshot(
        &self,
        tenant: &TenantId,
        account: &AccountId,
    ) -> Result<Option<Snapshot>, StorageError> {
        self.inner.latest_snapshot(tenant, account).await
    }

    async fn compact(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        before: Seq,
    ) -> Result<u64, StorageError> {
        self.inner.compact(tenant, account, before).await
    }

    async fn purge(&self, tenant: &TenantId) -> Result<u64, StorageError> {
        self.inner.purge(tenant).await
    }
}

struct Switch {
    inner: Arc<dyn Objects>,
    dead: AtomicBool,
}

impl Switch {
    fn check(&self) -> Result<(), StorageError> {
        if self.dead.load(Ordering::SeqCst) {
            Err(StorageError::Backend("node crashed".into()))
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl Objects for Switch {
    async fn get(&self, key: &ObjectKey) -> Result<Option<(Bytes, Version)>, StorageError> {
        self.check()?;
        self.inner.get(key).await
    }

    async fn put(
        &self,
        key: &ObjectKey,
        value: Bytes,
        expect: Expect,
    ) -> Result<Version, StorageError> {
        self.check()?;
        self.inner.put(key, value, expect).await
    }

    async fn delete(&self, key: &ObjectKey, expect: Expect) -> Result<(), StorageError> {
        self.check()?;
        self.inner.delete(key, expect).await
    }

    async fn list(
        &self,
        prefix: &ObjectKey,
        start_after: Option<&ObjectKey>,
        limit: usize,
    ) -> Result<Vec<ObjectKey>, StorageError> {
        self.check()?;
        self.inner.list(prefix, start_after, limit).await
    }
}

struct Partitioned {
    inner: Arc<dyn Liveness>,
    cut: AtomicBool,
}

#[async_trait]
impl Liveness for Partitioned {
    async fn heartbeat(
        &self,
        group: &GroupId,
        profile: &NodeProfile,
        now: Timestamp,
    ) -> Result<(), LeaseError> {
        if self.cut.load(Ordering::SeqCst) {
            return Err(LeaseError::backend(StorageError::Backend(
                "heartbeats cut".into(),
            )));
        }
        self.inner.heartbeat(group, profile, now).await
    }

    async fn alive(&self, group: &GroupId, now: Timestamp) -> Result<Vec<NodeProfile>, LeaseError> {
        self.inner.alive(group, now).await
    }

    fn ttl_ms(&self) -> u64 {
        self.inner.ttl_ms()
    }
}

struct Directory(Vec<AccountEntry>);

#[async_trait]
impl AccountDirectory for Directory {
    async fn accounts(&self) -> Result<Vec<AccountEntry>, EngineError> {
        Ok(self.0.clone())
    }
}

struct Progress {
    log: Arc<dyn Log>,
    target: AtomicU64,
    seen: HashMap<AccountId, tokio::sync::Mutex<(u64, u64)>>,
    done: Mutex<HashSet<AccountId>>,
}

impl Progress {
    fn done(&self) -> usize {
        self.done.lock().unwrap().len()
    }

    fn reset(&self, target: u64) {
        self.target.store(target, Ordering::SeqCst);
        self.done.lock().unwrap().clear();
    }
}

#[async_trait]
impl AccountObserver for Progress {
    async fn after_run(&self, tenant: &TenantId, account: &AccountId) -> Result<(), ObserverError> {
        let Some(cell) = self.seen.get(account) else {
            return Ok(());
        };
        let mut seen = cell.lock().await;
        loop {
            let page = self
                .log
                .read(tenant, account, Seq(seen.0 + 1), 1_000)
                .await
                .map_err(|e| ObserverError(e.to_string()))?;
            let Some(last) = page.last() else { break };
            seen.0 = last.seq.0;
            seen.1 += page
                .iter()
                .filter(|e| matches!(e.body, EventBody::MessageAdded { .. }))
                .count() as u64;
        }
        if seen.1 >= self.target.load(Ordering::SeqCst) {
            self.done.lock().unwrap().insert(account.clone());
        }
        Ok(())
    }
}

struct Node {
    switch: Arc<Switch>,
    liveness: Arc<Partitioned>,
    stop: watch::Sender<bool>,
    handle: tokio::task::JoinHandle<()>,
}

async fn wait_for(progress: &Progress, want: usize, deadline: Instant) -> bool {
    while progress.done() < want {
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    true
}

fn diff(a: ObjectCounts, b: ObjectCounts) -> ObjectCounts {
    ObjectCounts {
        gets: b.gets - a.gets,
        puts: b.puts - a.puts,
        deletes: b.deletes - a.deletes,
        lists: b.lists - a.lists,
        bytes_written: b.bytes_written - a.bytes_written,
    }
}

/// Runs `fleet` over `objects` and checks every account's journal afterwards: numbers from 1
/// without gaps, no repeated event keys, every message journaled, tokens that only grow along the
/// journal, one node per token, and with a fault, every account owned by a survivor at the end.
pub async fn run_fleet(fleet: &Fleet, objects: Arc<dyn Objects>) -> FleetOutcome {
    let tenant = TenantId::new("load").unwrap();
    let slow: Arc<dyn Objects> = match fleet.latency {
        Some(l) => Arc::new(SlowObjects::new(objects.clone(), l.base, l.jitter, 7)),
        None => objects.clone(),
    };
    let counting = Arc::new(CountingObjects::new(slow));
    let shared: Arc<dyn Objects> = counting.clone();
    let signal: Arc<dyn Signal> = Arc::new(LocalSignal::new());
    let journal = Arc::new(Journal::default());

    let fakes: Vec<(AccountId, FakeMail)> = (0..fleet.accounts)
        .map(|i| {
            let fake = FakeMail::new();
            fake.fill("INBOX", fleet.history, fleet.size);
            (AccountId::new(format!("acc{i}")).unwrap(), fake)
        })
        .collect();
    let directory = Arc::new(Directory(
        fakes
            .iter()
            .map(|(id, fake)| AccountEntry {
                config: AccountConfig::new(tenant.clone(), id.clone()),
                provider: Arc::new(fake.clone()),
                pim: None,
            })
            .collect(),
    ));
    let truth = Storage::over(objects.clone());
    let progress = Arc::new(Progress {
        log: truth.log.clone(),
        target: AtomicU64::new(fleet.history as u64),
        seen: fakes
            .iter()
            .map(|(id, _)| (id.clone(), tokio::sync::Mutex::new((0, 0))))
            .collect(),
        done: Mutex::new(HashSet::new()),
    });

    let profiles: Vec<NodeProfile> = (0..fleet.nodes)
        .map(|i| node_profile(NodeId::new(format!("node{i}")).unwrap(), 1, true))
        .collect();
    let group = coordination::group(&tenant);
    let started = Instant::now();
    let before = counting.counts();
    let mut nodes = Vec::new();
    for (i, profile) in profiles.iter().enumerate() {
        let switch = Arc::new(Switch {
            inner: shared.clone(),
            dead: AtomicBool::new(false),
        });
        let node_objects: Arc<dyn Objects> = switch.clone();
        let mut storage = Storage::over(node_objects.clone());
        storage.log = Arc::new(RecordedLog {
            inner: Arc::new(ObjectLog::new(node_objects)),
            node: i,
            journal: journal.clone(),
        });
        let state = Arc::new(ControlState::new(storage.control.clone()));
        let liveness = Arc::new(Partitioned {
            inner: Arc::new(OneGroupLiveness::nodes(Arc::new(CasLiveness::new(
                state.clone(),
                fleet.ttl.as_millis() as u64,
            )))),
            cut: AtomicBool::new(false),
        });
        liveness
            .heartbeat(&group, profile, Timestamp::now())
            .await
            .expect("first heartbeat");
        let leases = Arc::new(CasLeases::new(state, liveness.clone()));
        let engine = Engine::new(storage, leases, signal.clone(), profile.clone());
        let mut config = RunConfig::new(liveness.clone());
        config.heartbeat = fleet.heartbeat;
        config.interval = fleet.interval;
        config.max_backoff = Duration::from_secs(1);
        config.observers.push(progress.clone());
        let (stop, mut stopped) = watch::channel(false);
        let dir: Arc<dyn AccountDirectory> = directory.clone();
        let handle = tokio::spawn(skein_engine::run(engine, dir, config, async move {
            let _ = stopped.wait_for(|s| *s).await;
        }));
        nodes.push(Node {
            switch,
            liveness,
            stop,
            handle,
        });
    }

    let mut out = FleetOutcome::default();
    let deadline = started + fleet.timeout;
    let mut failed: HashSet<usize> = HashSet::new();
    let mut fault_at = None;
    if let Some(fault) = fleet.fault {
        let want = ((fleet.accounts as f64) * fault.after).ceil() as usize;
        if !wait_for(&progress, want.min(fleet.accounts), deadline).await {
            out.violations.push(format!(
                "only {} accounts synced before the failure",
                progress.done()
            ));
        }
        fault_at = Some(Instant::now());
        for (i, node) in nodes.iter().enumerate().take(fault.crash) {
            node.switch.dead.store(true, Ordering::SeqCst);
            node.handle.abort();
            failed.insert(i);
        }
        for (i, node) in nodes
            .iter()
            .enumerate()
            .skip(fault.crash)
            .take(fault.zombie)
        {
            node.liveness.cut.store(true, Ordering::SeqCst);
            failed.insert(i);
        }
    }
    if !wait_for(&progress, fleet.accounts, deadline).await {
        out.violations.push(format!(
            "{} of {} accounts finished their first sync",
            progress.done(),
            fleet.accounts
        ));
    }
    out.initial_time = started.elapsed();
    out.initial = diff(before, counting.counts());
    out.initial_messages = (fleet.accounts * fleet.history) as u64;

    let mut target = fleet.history as u64;
    if fleet.extra > 0 {
        target += fleet.extra as u64;
        progress.reset(target);
        let (rounds, pause) = match fleet.fault {
            Some(_) => (
                fleet.extra,
                (fleet.ttl + fleet.heartbeat * 3) / fleet.extra as u32,
            ),
            None => (1, Duration::ZERO),
        };
        for round in 0..rounds {
            let count = if rounds == 1 { fleet.extra } else { 1 };
            for (id, fake) in &fakes {
                fake.fill("INBOX", count, fleet.size);
                let _ = signal
                    .publish(
                        &group,
                        &format!("commands/{id}"),
                        Bytes::from_static(b"load"),
                    )
                    .await;
            }
            if round + 1 < rounds {
                tokio::time::sleep(pause).await;
            }
        }
        if !wait_for(&progress, fleet.accounts, deadline).await {
            out.violations.push(format!(
                "{} of {} accounts journaled the mail added after the first sync",
                progress.done(),
                fleet.accounts
            ));
        }
    }
    out.recovery_time = fault_at.map(|t| t.elapsed());
    out.messages = target * fleet.accounts as u64;

    for node in &nodes {
        let _ = node.stop.send(true);
    }
    for node in nodes {
        let _ = tokio::time::timeout(Duration::from_secs(10), node.handle).await;
    }
    out.total = diff(before, counting.counts());

    let appends = journal.appends.lock().unwrap().clone();
    let fenced = journal.fenced.lock().unwrap().clone();
    out.appends = (0..fleet.nodes)
        .map(|i| appends.iter().filter(|a| a.node == i).count() as u64)
        .collect();
    out.fenced = (0..fleet.nodes)
        .map(|i| fenced.get(&i).copied().unwrap_or(0))
        .collect();
    let truth_state = Arc::new(ControlState::new(truth.control.clone()));
    let owners = CasLeases::new(
        truth_state.clone(),
        Arc::new(CasLiveness::new(truth_state, 1)),
    );
    for (id, _) in &fakes {
        check_account(
            &truth, &owners, &tenant, id, target, &appends, &failed, &profiles, &mut out,
        )
        .await;
    }
    out
}

#[allow(clippy::too_many_arguments)]
async fn check_account(
    truth: &Storage,
    owners: &CasLeases,
    tenant: &TenantId,
    account: &AccountId,
    target: u64,
    appends: &[Append],
    failed: &HashSet<usize>,
    profiles: &[NodeProfile],
    out: &mut FleetOutcome,
) {
    let mut events = Vec::new();
    loop {
        match truth
            .log
            .read(tenant, account, Seq(events.len() as u64 + 1), 1_000)
            .await
        {
            Ok(page) if page.is_empty() => break,
            Ok(page) => events.extend(page),
            Err(e) => {
                out.violations
                    .push(format!("{account}: journal unreadable: {e}"));
                return;
            }
        }
    }
    let writer = |seq: u64| {
        appends
            .iter()
            .find(|a| &a.account == account && a.first <= seq && seq <= a.last)
            .map(|a| format!("node{} token {}", a.node, a.fence))
            .unwrap_or_else(|| "unknown writer".into())
    };
    let mut keys: HashMap<&str, u64> = HashMap::new();
    let mut messages = 0;
    for (i, e) in events.iter().enumerate() {
        if e.seq.0 != i as u64 + 1 {
            out.violations
                .push(format!("{account}: event {} has seq {}", i + 1, e.seq.0));
        }
        if let Some(first) = keys.insert(e.key.as_str(), e.seq.0) {
            if matches!(
                e.body,
                EventBody::MailboxUpserted { .. }
                    | EventBody::MailboxDeleted { .. }
                    | EventBody::FirstSyncCompleted
            ) {
                out.repeated_account_events += 1;
                continue;
            }
            let kind = format!("{:?}", e.body);
            let kind = kind.split([' ', '{', '(']).next().unwrap_or_default();
            out.violations.push(format!(
                "{account}: {kind} key at seq {} ({}) repeats seq {first} ({})",
                e.seq.0,
                writer(e.seq.0),
                writer(first)
            ));
        }
        if matches!(e.body, EventBody::MessageAdded { .. }) {
            messages += 1;
        }
    }
    if messages != target {
        let history: Vec<String> = appends
            .iter()
            .filter(|a| &a.account == account)
            .map(|a| format!("node{}@{}:{}-{}", a.node, a.fence, a.first, a.last))
            .collect();
        out.violations.push(format!(
            "{account}: {messages} messages journaled, {target} expected; appends {history:?}"
        ));
    }

    let mut mine: Vec<&Append> = appends.iter().filter(|a| &a.account == account).collect();
    mine.sort_by_key(|a| a.first);
    let mut next = 1;
    let mut fence = 0;
    let mut by_fence: HashMap<u64, usize> = HashMap::new();
    for a in &mine {
        if a.first != next {
            out.violations.push(format!(
                "{account}: append starts at {} after {}",
                a.first,
                next - 1
            ));
        }
        next = a.last + 1;
        if a.fence < fence {
            out.violations.push(format!(
                "{account}: token {} wrote seq {} after token {fence}",
                a.fence, a.first
            ));
        }
        fence = fence.max(a.fence);
        if let Some(other) = by_fence.insert(a.fence, a.node)
            && other != a.node
        {
            out.violations.push(format!(
                "{account}: token {} used by node{other} and node{}",
                a.fence, a.node
            ));
        }
    }
    if next != events.len() as u64 + 1 {
        out.violations.push(format!(
            "{account}: recorded appends end at {}, journal at {}",
            next - 1,
            events.len()
        ));
    }
    out.max_fence = out.max_fence.max(fence);
    if mine.iter().any(|a| failed.contains(&a.node))
        && mine.last().is_some_and(|a| !failed.contains(&a.node))
    {
        out.taken_over += 1;
        let stale = mine
            .iter()
            .filter(|a| failed.contains(&a.node))
            .map(|a| a.fence)
            .max()
            .unwrap_or(0);
        let probe = events.last().cloned().into_iter().collect();
        match truth
            .log
            .append(tenant, account, FencingToken(stale), probe)
            .await
        {
            Err(StorageError::Fenced) => out.stale_refused += 1,
            Ok(_) => out.violations.push(format!(
                "{account}: the journal accepted a write with the failed node's token {stale}"
            )),
            Err(e) => out
                .violations
                .push(format!("{account}: stale write failed oddly: {e}")),
        }
    }
    match owners
        .holder(
            &coordination::group(tenant),
            &coordination::lease_key(account),
        )
        .await
    {
        Ok(Some(lease)) => {
            if lease.fence.0 < fence {
                out.violations.push(format!(
                    "{account}: owner token {} below written token {fence}",
                    lease.fence.0
                ));
            }
            if let Some(i) = profiles.iter().position(|p| p.node == lease.node)
                && failed.contains(&i)
            {
                out.violations
                    .push(format!("{account}: still owned by failed node{i}"));
            }
        }
        Ok(None) => {}
        Err(e) => out
            .violations
            .push(format!("{account}: owner unreadable: {e}")),
    }
}
