//! Who arbitrates the leases of the node's accounts (GROUP.md, "Priority and arbiters").
//!
//! - The group has no server node: the node's own `lease-cas` over its control state, as in
//!   phase 1 (each node leads what it added; question 47).
//! - The group has a server node (the one with the lowest key when several count): that server
//!   runs `baton-lease-server` on its link, authorized from the group log ([`GroupAuthority`]),
//!   and every other node takes and renews leases and heartbeats there (`RemoteLeases`,
//!   `RemoteLiveness`); the server itself uses the same records directly.
//!
//! The arbiter is chosen again on every call, so adopting a server moves every node to it. A new
//! arbiter knows nothing of the leases the old one granted, so a change of arbiter is a lapse:
//! the engine stops acting on every lease it holds ([`NodeLeases::on_change`]), the node offers an
//! account's state only once no worker from before is left, and a server that starts arbitrating
//! grants nothing new for one time-to-live.
//! Tokens never go back for a node: every acquire passes the fence of the node's own head as a
//! floor, and a lease from the local arbiter below a token this node saw from another arbiter is
//! given back and taken again (tokens are at least the wall clock in microseconds, so the new one
//! is higher). Every arbiter but the local one signs its grants ([`rowboat_sync::Grant`]); the
//! holder fetches the grant before acting and its heads carry it.
//!
//! While the server is silent ([`crate::fallback`]) a device arbitrates instead: this node
//! (running the same lease server) or the first device of the fallback order that answers. A
//! node that sees the server yields an account to a fallback holder whose head it followed
//! ([`NodeLeases::yield_account`]); the server tells such heads apart from a device's false claim
//! by how long the device was silent to it ([`NodeLeases::admits`]).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use baton_core::{GroupId, LeaseKey, NodeId, Timestamp};
use baton_group::Capability;
use baton_identity::PublicKey;
use baton_lease::{Lease, LeaseError, Leases, Liveness, NodeClass, NodeProfile, TakeoverOutcome};
use baton_lease_cas::{CasLeases, CasLiveness, Clock};
use baton_lease_server::{
    Authorize, ClientConfig, Endorse, LeaseClient, LeaseServer, RemoteLeases, RemoteLiveness,
    ServerConfig,
};
use baton_link::Protocol;
use baton_state::StateStore;
use rowboat_group::{Membership, account_resource};
use rowboat_sync::{Grant, GrantKind};
use skein_core::{AccountId, FencingToken, TenantId};
use skein_storage::Storage;
use tracing::{debug, info, warn};

use crate::fallback::{
    Change, FallbackTiming, GapWatch, LEAVING_PROTOCOL, Leaving, MAX_LEAVING, ServerView,
    ServerWatch,
};
use crate::group::NodeGroup;

/// What a lease server lets a node of its group ask: only nodes that count speak, a node
/// announces only the class of its certificate, and takes or asks to take over only the lease
/// of an account it holds `lead` on.
pub(crate) struct GroupAuthority {
    pub membership: Arc<Membership>,
    pub group: GroupId,
}

impl Authorize for GroupAuthority {
    fn member(&self, peer: &PublicKey, group: &GroupId) -> bool {
        group == &self.group && self.membership.counts(peer)
    }

    fn profile(&self, peer: &PublicKey, group: &GroupId, profile: &NodeProfile) -> bool {
        self.member(peer, group) && self.membership.class_of(peer) == Some(profile.class)
    }

    fn lease(&self, peer: &PublicKey, group: &GroupId, key: &LeaseKey) -> bool {
        self.member(peer, group)
            && account_resource(key.as_str())
                .is_some_and(|r| self.membership.node_may(peer, &r, &Capability::Lead))
    }
}

/// Which nodes may lead an account: those holding `lead` on its resource in the group log, this
/// node only while it holds state to continue from (its own record and credentials, or an offer),
/// and no other node while this one holds the account's only state (it can lead it alone, nobody
/// wrote the journal after it, and no peer took an offer yet). Without the last rule a stronger
/// node adopted before the first sync of a new account was preferred, could not continue and
/// gave the lease back, while this node deferred to it: nobody synced the account again.
pub(crate) struct LeadEligible(pub std::sync::Weak<crate::boot::Core>);

impl skein_engine::Eligible for LeadEligible {
    fn may_lead(&self, _: &TenantId, account: &AccountId, node: &NodeId) -> bool {
        let Some(core) = self.0.upgrade() else {
            return false;
        };
        let (Ok(m), Some(r), Ok(key)) = (
            core.group.membership(),
            account_resource(account.as_str()),
            PublicKey::from_node_id(node),
        ) else {
            return false;
        };
        if !m.node_may(&key, &r, &Capability::Lead) {
            return false;
        }
        let eligibility = core.eligibility.lock().unwrap_or_else(|e| e.into_inner());
        if key == m.node() {
            !core.arbiter.is_yielded(account.as_str())
                && (eligibility.stateful.contains(account.as_str())
                    || core
                        .led
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .contains(account.as_str()))
        } else {
            !eligibility.sole.contains(account.as_str())
                && !(eligibility.fallback_tail.contains(account.as_str())
                    && !core.arbiter.in_fallback())
        }
    }
}

/// What [`LeadEligible`] reads, refreshed by [`refresh_eligibility`].
#[derive(Default)]
pub(crate) struct Eligibility {
    /// Accounts this node holds state to continue from.
    pub stateful: std::collections::BTreeSet<String>,
    /// Accounts whose only state this node holds.
    pub sole: std::collections::BTreeSet<String>,
    /// Accounts whose state a peer took as an offer since this node started.
    pub handed: std::collections::BTreeSet<String>,
    /// Accounts whose journal this node wrote last under a fallback arbiter's grant: once the
    /// server is back, this node continues them under a grant of the server before anyone else
    /// leads them (everyone else yields to it).
    pub fallback_tail: std::collections::BTreeSet<String>,
}

/// Whether this node wrote the account's journal last: its head is attested by this node, or, with
/// `unattested`, not attested at all (nothing synced yet, or written before attestation).
pub(crate) async fn wrote_last(
    core: &crate::boot::Core,
    account: &AccountId,
    unattested: bool,
) -> bool {
    let me = core.group.membership().map(|m| m.node()).ok();
    match core.local.log.signed_head(&core.tenant, account).await {
        Ok(head) => match head.attestation.as_deref() {
            None => unattested,
            Some(a) => rowboat_sync::attestation_signer(&head.head, a)
                .ok()
                .is_some_and(|s| Some(s) == me),
        },
        Err(_) => false,
    }
}

/// How long [`leader_of`] waits for the arbiter.
const LEADER_ASK: Duration = Duration::from_secs(3);

/// The node id of `account`'s leader as this node sees it: itself while it leads; the arbiter's
/// holder when leases are shared; else the node that signed the newest head this node holds, when
/// it still counts.
pub(crate) async fn leader_of(
    core: &crate::boot::Core,
    account: &str,
    me: &PublicKey,
) -> Option<String> {
    if core.leads(account) {
        return Some(me.node_id().to_string());
    }
    let id = AccountId::new(account).ok()?;
    if core.arbiter.shared() {
        let group = skein_core::coordination::group(&core.tenant);
        let key = skein_core::coordination::lease_key(&id);
        if let Ok(Ok(holder)) =
            tokio::time::timeout(LEADER_ASK, core.arbiter.holder(&group, &key)).await
        {
            return holder.map(|l| l.node.to_string());
        }
    }
    let head = core.local.log.signed_head(&core.tenant, &id).await.ok()?;
    let signer = rowboat_sync::attestation_signer(&head.head, head.attestation.as_deref()?).ok()?;
    let m = core.group.membership().ok()?;
    m.counts(&signer).then(|| signer.node_id().to_string())
}

/// Recomputes [`Eligibility`] from the node's storage: before the engine runs and on every
/// replication tick. Accounts with an offer count even before this node learned anything else
/// about them: without it a node that took the only offer of an account it was never told about
/// stayed ineligible while the offering node deferred to it, and nobody led the account.
pub(crate) async fn refresh_eligibility(core: &crate::boot::Core) {
    core.arbiter.refresh_yields().await;
    let metas = crate::api::all_metas(core).await.unwrap_or_default();
    let staged: std::collections::BTreeSet<String> = match core.replication.get() {
        Some(r) => r
            .staged_accounts()
            .await
            .into_iter()
            .map(|a| a.to_string())
            .collect(),
        None => Default::default(),
    };
    let accounts: std::collections::BTreeSet<String> = metas
        .into_iter()
        .map(|m| m.account.to_string())
        .chain(staged.iter().cloned())
        .collect();
    let mut stateful = std::collections::BTreeSet::new();
    let mut sole = std::collections::BTreeSet::new();
    let handed = core
        .eligibility
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .handed
        .clone();
    let mut fallback_tail = std::collections::BTreeSet::new();
    for name in accounts {
        let Ok(account) = AccountId::new(name.as_str()) else {
            continue;
        };
        if fallback_written(core, &account).await {
            fallback_tail.insert(name.clone());
        }
        if core.arbiter.is_yielded(&name) {
            continue;
        }
        let own = crate::handover::can_lead_alone(core, &account).await;
        let staged = staged.contains(&name);
        if own || staged {
            stateful.insert(name.clone());
        }
        if own && !staged && !handed.contains(&name) && wrote_last(core, &account, true).await {
            sole.insert(name);
        }
    }
    let mut e = core.eligibility.lock().unwrap_or_else(|e| e.into_inner());
    e.stateful = stateful;
    e.sole = sole;
    e.fallback_tail = fallback_tail;
}

/// Whether this node wrote the account's journal last under a fallback arbiter's grant.
async fn fallback_written(core: &crate::boot::Core, account: &AccountId) -> bool {
    let Ok(me) = core.group.membership().map(|m| m.node()) else {
        return false;
    };
    let Ok(head) = core.local.log.signed_head(&core.tenant, account).await else {
        return false;
    };
    let Some(a) = head.attestation.as_deref() else {
        return false;
    };
    rowboat_sync::attestation_signer(&head.head, a).is_ok_and(|s| s == me)
        && rowboat_sync::attestation_grant(&head.head, a).map(|g| g.kind)
            == Some(GrantKind::Fallback)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Arbiter {
    /// The node's own `lease-cas` (no server in the group).
    Local,
    /// This node is the group's server and arbitrates.
    Host,
    /// The group's server arbitrates.
    Remote(PublicKey),
    /// The server is silent; another device arbitrates.
    Fallback(PublicKey),
    /// The server is silent; this device arbitrates.
    FallbackHost,
}

impl Arbiter {
    fn hosted(self) -> bool {
        matches!(self, Self::Host | Self::FallbackHost)
    }

    fn remote_key(self) -> Option<PublicKey> {
        match self {
            Self::Remote(k) | Self::Fallback(k) => Some(k),
            _ => None,
        }
    }

    /// Whether a fallback arbiter decides now.
    pub(crate) fn fallback(self) -> bool {
        matches!(self, Self::Fallback(_) | Self::FallbackHost)
    }
}

struct Remote {
    arbiter: PublicKey,
    client: Arc<LeaseClient>,
    leases: Arc<RemoteLeases>,
    liveness: Arc<RemoteLiveness>,
}

/// Signs grants for the leases this node's lease server gives (see [`rowboat_sync::Grant`]).
struct Endorser {
    identity: baton_identity::Identity,
    kind: GrantKind,
}

impl Endorse for Endorser {
    fn endorse(&self, lease: &Lease) -> Option<Vec<u8>> {
        let node = PublicKey::from_node_id(&lease.node).ok()?;
        Some(Grant::sign(
            &self.identity,
            self.kind,
            lease.group.as_str(),
            lease.key.as_str(),
            node,
            lease.fence.0,
        ))
    }
}

/// The node's [`Leases`] and [`Liveness`], following the group's arbiter, and falling back to a
/// device of the group while the server is silent ([`crate::fallback`]).
pub(crate) struct NodeLeases {
    group: Arc<NodeGroup>,
    state: Arc<dyn StateStore>,
    clock: Clock,
    ttl_ms: u64,
    request_timeout: Duration,
    probe_timeout: Duration,
    stagger: Duration,
    timing: FallbackTiming,
    local: Arc<CasLeases>,
    local_liveness: Arc<CasLiveness>,
    host: tokio::sync::Mutex<Option<LeaseServer>>,
    remote: tokio::sync::Mutex<Option<Remote>>,
    seen: Mutex<HashMap<LeaseKey, u64>>,
    last: Mutex<Option<Arbiter>>,
    changed: std::sync::OnceLock<Box<dyn Fn() + Send + Sync>>,
    started: tokio::time::Instant,
    watch: Mutex<ServerWatch>,
    chosen: Mutex<Option<Arbiter>>,
    grants: Mutex<HashMap<LeaseKey, (u64, Vec<u8>)>>,
    storage: Storage,
    tenant: TenantId,
    leaving: Arc<std::sync::atomic::AtomicBool>,
    wake: Arc<tokio::sync::Notify>,
    listening: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    gaps: Mutex<GapWatch>,
    gaps_loaded: std::sync::atomic::AtomicBool,
    yielded: Mutex<HashMap<String, (u64, tokio::time::Instant)>>,
    presumed: Mutex<std::collections::BTreeSet<String>>,
    stopped: std::sync::atomic::AtomicBool,
    left: std::sync::atomic::AtomicBool,
    #[cfg(feature = "testing")]
    forced: std::sync::atomic::AtomicBool,
}

const LEFT_RECORD: &str = "rowboat/fallback/left";

impl NodeLeases {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        group: Arc<NodeGroup>,
        state: Arc<dyn StateStore>,
        ttl_ms: u64,
        request_timeout: Duration,
        heartbeat: Duration,
        timing: FallbackTiming,
        storage: Storage,
        tenant: TenantId,
    ) -> Self {
        let clock = baton_lease_cas::monotonic_clock();
        let local_liveness = Arc::new(CasLiveness::new(state.clone(), ttl_ms));
        let local = Arc::new(
            CasLeases::new(state.clone(), local_liveness.clone() as Arc<dyn Liveness>)
                .with_clock(clock.clone()),
        );
        Self {
            group,
            state,
            clock,
            ttl_ms,
            request_timeout,
            probe_timeout: (heartbeat * 2).min(Duration::from_secs(5)),
            stagger: heartbeat * 2,
            timing,
            local,
            local_liveness,
            host: tokio::sync::Mutex::new(None),
            remote: tokio::sync::Mutex::new(None),
            seen: Mutex::new(HashMap::new()),
            last: Mutex::new(None),
            changed: std::sync::OnceLock::new(),
            started: tokio::time::Instant::now(),
            watch: Mutex::new(ServerWatch::new(0, timing)),
            chosen: Mutex::new(None),
            grants: Mutex::new(HashMap::new()),
            storage,
            tenant,
            leaving: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            wake: Arc::new(tokio::sync::Notify::new()),
            listening: tokio::sync::Mutex::new(None),
            gaps: Mutex::new(GapWatch::default()),
            gaps_loaded: std::sync::atomic::AtomicBool::new(false),
            yielded: Mutex::new(HashMap::new()),
            presumed: Mutex::new(Default::default()),
            stopped: std::sync::atomic::AtomicBool::new(false),
            left: std::sync::atomic::AtomicBool::new(false),
            #[cfg(feature = "testing")]
            forced: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Runs `f` every time the arbiter this node follows changes, before anything is asked of the
    /// new one. Set once.
    pub(crate) fn on_change(&self, f: impl Fn() + Send + Sync + 'static) {
        let _ = self.changed.set(Box::new(f));
    }

    /// The local arbiter's leases, for forgetting the record of a removed account.
    pub(crate) fn local(&self) -> &Arc<CasLeases> {
        &self.local
    }

    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        m.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The arbiter the group log names, before any fallback.
    fn base(&self) -> Arbiter {
        let Ok(m) = self.group.membership() else {
            return Arbiter::Local;
        };
        let me = m.node();
        let server = m
            .nodes()
            .into_iter()
            .filter(|n| n.counts && n.class == NodeClass::Server)
            .map(|n| n.node)
            .min();
        match server {
            None => Arbiter::Local,
            Some(s) if s == me => Arbiter::Host,
            Some(s) => Arbiter::Remote(s),
        }
    }

    pub(crate) fn arbiter(&self) -> Arbiter {
        let base = self.base();
        let now = match base {
            Arbiter::Remote(_) if Self::lock(&self.watch).in_fallback() => {
                Self::lock(&self.chosen).unwrap_or(base)
            }
            _ => base,
        };
        let before = Self::lock(&self.last).replace(now);
        if before.is_some_and(|b| b != now) {
            info!(
                ?now,
                "the group's lease arbiter changed; leases held under the old one end"
            );
            if let Some(f) = self.changed.get() {
                f();
            }
        }
        now
    }

    /// Whether leases are decided across nodes (the group has a server).
    pub(crate) fn shared(&self) -> bool {
        self.arbiter() != Arbiter::Local
    }

    /// Whether this device arbitrates without the server now, and why.
    pub(crate) fn fallback_reason(&self) -> Option<crate::fallback::Reason> {
        Self::lock(&self.watch).reason()
    }

    /// Whether the server answers again while this device still arbitrates without it.
    pub(crate) fn server_answers(&self) -> bool {
        self.base() != Arbiter::Host && Self::lock(&self.watch).answering()
    }

    /// How long ago the server came back after this device last arbitrated without it.
    pub(crate) fn back_for(&self) -> Option<Duration> {
        Self::lock(&self.watch).back_for(self.now_ms())
    }

    /// The fallback timing.
    pub(crate) fn fallback_timing(&self) -> FallbackTiming {
        self.timing
    }

    /// Treats the server as silent whatever this device observes, or stops doing so (tests of
    /// a device that claims the server is silent).
    #[cfg(feature = "testing")]
    pub(crate) fn force_fallback(&self, on: bool) {
        self.forced.store(on, std::sync::atomic::Ordering::SeqCst);
        if on {
            Self::lock(&self.watch).leaving();
        }
        self.wake.notify_one();
    }

    /// Whether this device considers the server silent now.
    pub(crate) fn in_fallback(&self) -> bool {
        self.base() != Arbiter::Host && Self::lock(&self.watch).in_fallback()
    }

    fn is_stopped(&self) -> bool {
        self.stopped.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn has_left(&self) -> bool {
        self.left.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The lease server this node runs: over its state store on the group's server, over a fresh
    /// in-memory store on a fallback arbiter (records of the node's own arbiter from before the
    /// group had a server would otherwise let it renew at once, inside the grace that keeps it
    /// from granting while holders of the server's leases may still act; tokens still rise, by
    /// the clock and the floor).
    async fn host(&self) -> (Arc<dyn Leases>, Arc<dyn Liveness>) {
        let mut host = self.host.lock().await;
        if host.is_none()
            && !self.is_stopped()
            && !self.has_left()
            && let (Some(link), Ok(m)) = (self.group.link().await, self.group.membership())
        {
            let authority = Arc::new(GroupAuthority {
                membership: m.clone(),
                group: m.group().clone(),
            });
            let kind = if m.class_of(&m.node()) == Some(NodeClass::Server) {
                GrantKind::Server
            } else {
                GrantKind::Fallback
            };
            let state: Arc<dyn StateStore> = match kind {
                GrantKind::Server => self.state.clone(),
                GrantKind::Fallback => Arc::new(baton_state_memory::MemoryState::new()),
            };
            match LeaseServer::start(
                link,
                state,
                authority,
                self.clock.clone(),
                ServerConfig {
                    ttl_ms: self.ttl_ms,
                    grace_ms: self.ttl_ms,
                    endorse: Some(Arc::new(Endorser {
                        identity: m.keys().identity.clone(),
                        kind,
                    })),
                    ..ServerConfig::default()
                },
            )
            .await
            {
                Ok(s) => {
                    info!(?kind, "serving the group's leases");
                    if kind == GrantKind::Server {
                        Self::lock(&self.gaps).serving_since(
                            (self.clock)().0,
                            self.timing.takeover.as_millis() as i64,
                        );
                    }
                    *host = Some(s);
                }
                Err(e) => warn!(error = %e, "the lease server could not start"),
            }
        }
        match host.as_ref() {
            Some(s) => (s.leases(), s.liveness()),
            None => (self.local.clone(), self.local_liveness.clone()),
        }
    }

    /// Whether this node runs a lease server now.
    #[cfg(feature = "testing")]
    pub(crate) async fn serves(&self) -> bool {
        self.host.lock().await.is_some()
    }

    async fn stop_host(&self) {
        if let Some(s) = self.host.lock().await.take() {
            s.stop().await;
            info!("stopped serving the group's leases");
        }
    }

    async fn remote(
        &self,
        arbiter: PublicKey,
    ) -> Result<(Arc<RemoteLeases>, Arc<RemoteLiveness>), LeaseError> {
        let mut remote = self.remote.lock().await;
        if let Some(r) = remote.as_ref()
            && r.arbiter == arbiter
        {
            return Ok((r.leases.clone(), r.liveness.clone()));
        }
        if self.is_stopped() {
            return Err(LeaseError::Unavailable);
        }
        let Some(link) = self.group.link().await else {
            debug!("no link to the lease arbiter");
            return Err(LeaseError::Unavailable);
        };
        let client = LeaseClient::connect(
            link,
            arbiter,
            ClientConfig {
                request_timeout: self.request_timeout,
                ..ClientConfig::default()
            },
        )
        .await
        .inspect_err(|e| debug!(error = %e, "the lease arbiter could not be reached"))?;
        if client.ttl_ms() < self.ttl_ms {
            warn!("the group's lease arbiter judges holders gone sooner than this node stops");
            return Err(LeaseError::Unavailable);
        }
        let r = Remote {
            arbiter,
            leases: Arc::new(RemoteLeases::new(client.clone())),
            liveness: Arc::new(RemoteLiveness::new(client.clone())),
            client,
        };
        let out = (r.leases.clone(), r.liveness.clone());
        *remote = Some(r);
        Ok(out)
    }

    async fn leases(&self) -> Result<(Arbiter, Arc<dyn Leases>), LeaseError> {
        let arbiter = self.arbiter();
        if arbiter == Arbiter::Host && self.has_left() {
            return Err(LeaseError::Unavailable);
        }
        let leases: Arc<dyn Leases> = match arbiter {
            Arbiter::Local => self.local.clone(),
            Arbiter::Host | Arbiter::FallbackHost => self.host().await.0,
            Arbiter::Remote(s) | Arbiter::Fallback(s) => self.remote(s).await?.0,
        };
        Ok((arbiter, leases))
    }

    async fn liveness(&self) -> Result<(Arbiter, Arc<dyn Liveness>), LeaseError> {
        let arbiter = self.arbiter();
        if arbiter == Arbiter::Host && self.has_left() {
            return Err(LeaseError::Unavailable);
        }
        let live: Arc<dyn Liveness> = match arbiter {
            Arbiter::Local => self.local_liveness.clone(),
            Arbiter::Host | Arbiter::FallbackHost => self.host().await.1,
            Arbiter::Remote(s) | Arbiter::Fallback(s) => self.remote(s).await?.1,
        };
        Ok((arbiter, live))
    }

    /// Records that the group's server answered (anything but "unavailable").
    fn note<T>(&self, arbiter: Arbiter, r: Result<T, &LeaseError>) {
        if let Arbiter::Remote(_) = arbiter
            && !matches!(r, Err(LeaseError::Unavailable))
        {
            Self::lock(&self.watch).contact(self.now_ms());
        }
    }

    fn saw(&self, lease: &Lease) -> u64 {
        let mut seen = Self::lock(&self.seen);
        let best = seen.entry(lease.key.clone()).or_insert(0);
        let before = *best;
        *best = (*best).max(lease.fence.0);
        before
    }

    /// The highest token this node's own journal of the account behind `key` carries.
    async fn floor(&self, key: &LeaseKey) -> FencingToken {
        let Ok(account) = AccountId::new(key.as_str()) else {
            return FencingToken(0);
        };
        self.storage
            .log
            .signed_head(&self.tenant, &account)
            .await
            .map_or(FencingToken(0), |h| FencingToken(h.head.fence.0))
    }

    /// Makes sure this node holds the arbiter's signed grant for `lease`.
    async fn ensure_grant(&self, arbiter: Arbiter, lease: &Lease) -> Result<(), LeaseError> {
        if Self::lock(&self.grants)
            .get(&lease.key)
            .is_some_and(|(f, _)| *f == lease.fence.0)
        {
            return Ok(());
        }
        let grant = if arbiter.hosted() {
            match self.host.lock().await.as_ref() {
                Some(s) => s.endorse(lease).await,
                None => None,
            }
        } else {
            let client = self
                .remote
                .lock()
                .await
                .as_ref()
                .filter(|r| Some(r.arbiter) == arbiter.remote_key())
                .map(|r| r.client.clone());
            match client {
                Some(c) => c.endorse(&lease.group, &lease.key, lease.fence).await?,
                None => None,
            }
        };
        let Some(grant) = grant else {
            debug!(key = %lease.key, "the arbiter gave no grant for the lease");
            return Err(LeaseError::Unavailable);
        };
        Self::lock(&self.grants).insert(lease.key.clone(), (lease.fence.0, grant));
        Ok(())
    }

    /// Stops for good: the lease server (if any) and every connection; nothing starts again.
    pub(crate) async fn stop(&self) {
        self.stopped
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.stop_host().await;
        *self.remote.lock().await = None;
        if let Some(t) = self.listening.lock().await.take() {
            t.abort();
        }
    }

    /// Whether `account` is kept from this node because a fallback holder (or a later grant)
    /// holds it: see [`NodeLeases::yield_account`].
    pub(crate) fn is_yielded(&self, account: &str) -> bool {
        Self::lock(&self.yielded).contains_key(account)
    }

    /// Keeps this node from leading `account` until its own journal carries a server's grant to
    /// another node above `fence` (the holder came back to the server and continued), or for
    /// three takeover delays: it neither takes nor asks to take the lease meanwhile, and a node
    /// that leads it gives it up on the engine's next round.
    pub(crate) fn yield_account(&self, account: &str, fence: u64) {
        let mut y = Self::lock(&self.yielded);
        let entry = y
            .entry(account.to_owned())
            .or_insert((fence, tokio::time::Instant::now()));
        if fence > entry.0 {
            *entry = (fence, tokio::time::Instant::now());
        }
        debug!(%account, fence, "yielding the account to its fallback holder");
    }

    /// Ends the yields whose holder continued under a server's grant, or that expired.
    pub(crate) async fn refresh_yields(&self) {
        let entries: Vec<(String, u64, tokio::time::Instant)> = Self::lock(&self.yielded)
            .iter()
            .map(|(a, (f, t))| (a.clone(), *f, *t))
            .collect();
        for (name, fence, since) in entries {
            let expired = since.elapsed() >= self.timing.yield_for();
            let me = self.group.membership().ok().map(|m| m.node());
            let continued = match AccountId::new(name.as_str()) {
                Ok(account) => match self.storage.log.signed_head(&self.tenant, &account).await {
                    Ok(h) => {
                        h.head.fence.0 > fence
                            && rowboat_sync::head_grant(&h)
                                .is_some_and(|g| g.kind == GrantKind::Server && Some(g.node) != me)
                    }
                    Err(_) => false,
                },
                Err(_) => true,
            };
            if expired || continued {
                Self::lock(&self.yielded).remove(&name);
            }
        }
    }

    /// Whether this node should presume the queued commands of `account` started (it takes the
    /// account over from a server that went silent, which may have been running them); true once
    /// per account and fallback period.
    pub(crate) fn presume_once(&self, account: &str) -> bool {
        self.arbiter().fallback()
            && self.fallback_reason() == Some(crate::fallback::Reason::Silence)
            && Self::lock(&self.presumed).insert(account.to_owned())
    }

    /// The watch round, once per heartbeat: on a device, probes the server while it is silent or
    /// said it is leaving, moves in and out of fallback and picks the fallback arbiter; on the
    /// server, samples how long each device was silent to it.
    pub(crate) async fn watch_round(&self) {
        let Ok(m) = self.group.membership() else {
            return;
        };
        self.listen_for_leaving().await;
        match self.base() {
            Arbiter::Host => self.sample_gaps(&m).await,
            Arbiter::Remote(server) => {
                let leaving = self
                    .leaving
                    .swap(false, std::sync::atomic::Ordering::SeqCst);
                let fallback = Self::lock(&self.watch).in_fallback();
                #[cfg(feature = "testing")]
                let forced = self.forced.load(std::sync::atomic::Ordering::SeqCst);
                #[cfg(not(feature = "testing"))]
                let forced = false;
                if forced {
                    Self::lock(&self.watch).leaving();
                } else if leaving || fallback {
                    let up = self.probe(server).await;
                    let mut w = Self::lock(&self.watch);
                    if up {
                        w.contact(self.now_ms());
                    } else {
                        w.failed();
                        if leaving {
                            w.leaving();
                        }
                    }
                }
                let change = Self::lock(&self.watch).tick(self.now_ms());
                match change {
                    Some(Change::Fallback(reason)) => {
                        warn!(?reason, "the group's server is silent; devices arbitrate")
                    }
                    Some(Change::Back) => {
                        info!("the group's server is back");
                        Self::lock(&self.presumed).clear();
                    }
                    None => {}
                }
                if Self::lock(&self.watch).in_fallback() {
                    self.choose(&m).await;
                } else {
                    *Self::lock(&self.chosen) = None;
                }
            }
            Arbiter::Local | Arbiter::Fallback(_) | Arbiter::FallbackHost => {
                *Self::lock(&self.watch) = ServerWatch::new(self.now_ms(), self.timing);
                *Self::lock(&self.chosen) = None;
            }
        }
        let now = self.arbiter();
        let me_server = m.class_of(&m.node()) == Some(NodeClass::Server);
        if now != Arbiter::FallbackHost && !me_server {
            self.stop_host().await;
        }
    }

    /// Wakes the watch round early (a leaving notice arrived).
    pub(crate) fn woken(&self) -> Arc<tokio::sync::Notify> {
        self.wake.clone()
    }

    async fn probe(&self, node: PublicKey) -> bool {
        let Some(link) = self.group.link().await else {
            return false;
        };
        let connect = LeaseClient::connect(
            link,
            node,
            ClientConfig {
                request_timeout: self.probe_timeout,
                streams: 1,
                ..ClientConfig::default()
            },
        );
        matches!(
            tokio::time::timeout(self.probe_timeout, connect).await,
            Ok(Ok(_))
        )
    }

    async fn choose(&self, m: &Membership) {
        let me = m.node();
        let since = Self::lock(&self.watch).since().unwrap_or(0);
        let waited = self.now_ms().saturating_sub(since);
        let mut choice = None;
        for (rank, c) in crate::fallback::candidates(m).into_iter().enumerate() {
            if c == me {
                if waited >= (self.stagger * rank as u32).as_millis() as u64 {
                    choice = Some(Arbiter::FallbackHost);
                }
                break;
            }
            if self.probe(c).await {
                choice = Some(Arbiter::Fallback(c));
                break;
            }
        }
        if choice == Some(Arbiter::FallbackHost) {
            self.host().await;
        }
        *Self::lock(&self.chosen) = choice;
    }

    async fn sample_gaps(&self, m: &Membership) {
        let min_gap = self.timing.min_gap().as_millis() as i64;
        if !self
            .gaps_loaded
            .swap(true, std::sync::atomic::Ordering::SeqCst)
            && let Ok(Some(_)) = self.storage.control.get(&self.tenant, LEFT_RECORD).await
        {
            let until = (self.clock)().0 + 4 * self.timing.takeover.as_millis() as i64;
            Self::lock(&self.gaps).left_gracefully(until);
            let _ = self
                .storage
                .control
                .delete(&self.tenant, LEFT_RECORD, skein_storage::Expect::Any)
                .await;
            info!("back after a graceful leave: devices that took over are believed");
        }
        let host = self.host.lock().await;
        let Some(server) = host.as_ref() else {
            return;
        };
        let devices = crate::fallback::candidates(m);
        let mut seen = Vec::new();
        for d in &devices {
            let Ok(node) = NodeId::new(d.node_id().to_string()) else {
                continue;
            };
            seen.push((*d, server.last_heartbeat(m.group(), &node).await));
        }
        drop(host);
        let mut gaps = Self::lock(&self.gaps);
        gaps.retain(&devices);
        for (d, last) in seen {
            gaps.observe(d, last.map(|t| t.0), min_gap);
        }
    }

    /// Whether this node follows `signed`, verified, given the grants behind its fence and behind
    /// this node's own head ([`crate::fallback::admit`]); a fallback holder's head admitted while
    /// this node sees the server makes it yield the account.
    pub(crate) async fn admits(
        &self,
        signed: &skein_storage::SignedHead,
        remote: Option<&Grant>,
        local: Option<&Grant>,
    ) -> bool {
        let (Ok(m), Some(attestation)) = (self.group.membership(), signed.attestation.as_deref())
        else {
            return false;
        };
        let Ok(signer) = rowboat_sync::attestation_signer(&signed.head, attestation) else {
            return false;
        };
        let in_fallback = self.in_fallback();
        let fallback_grant = remote.is_some_and(|g| g.kind == GrantKind::Fallback);
        let view = if fallback_grant && self.base() == Arbiter::Host {
            Some(self.server_view(&m, signed, remote, &signer).await)
        } else {
            None
        };
        let ok = crate::fallback::admit(
            remote.map(|g| g.kind),
            local.map(|g| g.kind),
            &signer,
            in_fallback,
            view.as_ref(),
            matches!(self.base(), Arbiter::Remote(_)),
        );
        debug!(
            account = %signed.head.account,
            remote = ?remote.map(|g| g.kind),
            local = ?local.map(|g| g.kind),
            in_fallback,
            ok,
            "a head judged by its grant"
        );
        if ok
            && fallback_grant
            && !in_fallback
            && signer != m.node()
            && signed.head.fence
                > self
                    .floor(&skein_core::coordination::lease_key(&signed.head.account))
                    .await
        {
            self.yield_account(signed.head.account.as_str(), signed.head.fence.0);
        }
        ok
    }

    async fn server_view(
        &self,
        m: &Membership,
        signed: &skein_storage::SignedHead,
        remote: Option<&Grant>,
        signer: &PublicKey,
    ) -> ServerView {
        let group = m.group().clone();
        let key = skein_core::coordination::lease_key(&signed.head.account);
        let (leases, live) = self.host().await;
        let alive: Vec<NodeId> = live
            .alive(&group, (self.clock)())
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|p| p.node)
            .collect();
        let held = leases.holder(&group, &key).await.ok().flatten();
        let newer = held.as_ref().is_none_or(|l| signed.head.fence > l.fence);
        let holder = held.and_then(|l| {
            PublicKey::from_node_id(&l.node)
                .ok()
                .map(|k| (k, alive.contains(&l.node)))
        });
        let now = (self.clock)().0;
        let min_gap = self.timing.min_gap().as_millis() as i64;
        let window = 4 * self.timing.takeover.as_millis() as i64;
        let gaps = Self::lock(&self.gaps);
        let silent = |k: &PublicKey| gaps.silent(k, now, min_gap, window);
        ServerView {
            me: m.node(),
            holder,
            gaps: remote.is_some_and(|g| silent(&g.arbiter)) && silent(signer),
            everyone: crate::fallback::candidates(m).iter().all(silent),
            newer,
        }
    }

    async fn listen_for_leaving(&self) {
        let mut listening = self.listening.lock().await;
        if listening.as_ref().is_some_and(|t| !t.is_finished()) {
            return;
        }
        let Some(link) = self.group.link().await else {
            return;
        };
        let protocol = Protocol::new(LEAVING_PROTOCOL).expect("constant");
        let Ok(mut incoming) = link.listen(&protocol).await else {
            return;
        };
        let group = self.group.clone();
        let wake = self.wake.clone();
        let raised = self.leaving.clone();
        let clock = self.clock.clone();
        *listening = Some(tokio::spawn(async move {
            use futures::StreamExt;
            while let Some(inc) = incoming.next().await {
                let (Ok(m), mut stream) = (group.membership(), inc.stream) else {
                    continue;
                };
                let limit = Duration::from_secs(5);
                let Ok(bytes) =
                    rowboat_group::wire::read_frame(&mut *stream, MAX_LEAVING, limit).await
                else {
                    continue;
                };
                if Leaving::verify(&bytes, &inc.peer, &m, (clock)().0).is_some() {
                    info!("the group's server says it is leaving");
                    raised.store(true, std::sync::atomic::Ordering::SeqCst);
                    wake.notify_one();
                }
                let _ = rowboat_group::wire::write_frame(&mut *stream, &[1], limit).await;
            }
        }));
    }

    /// Stops arbitrating for good and tells the group's devices this server is leaving, so they
    /// take over at once; the next start believes devices that took over meanwhile. Only on the
    /// server: false elsewhere.
    pub(crate) async fn announce_leaving(&self) -> bool {
        if self.base() != Arbiter::Host {
            return false;
        }
        let Ok(m) = self.group.membership() else {
            return false;
        };
        self.left.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = self
            .storage
            .control
            .put(
                &self.tenant,
                LEFT_RECORD,
                bytes::Bytes::from_static(b"1"),
                skein_storage::Expect::Any,
            )
            .await;
        let link = self.group.link().await;
        self.stop_host().await;
        let Some(link) = link else {
            return true;
        };
        let notice = Leaving::sign(&m.keys().identity, m.group().as_str(), (self.clock)().0);
        let protocol = Protocol::new(LEAVING_PROTOCOL).expect("constant");
        let limit = Duration::from_secs(2);
        let sends = crate::fallback::candidates(&m).into_iter().map(|peer| {
            let (link, protocol, notice) = (link.clone(), protocol.clone(), notice.clone());
            async move {
                let Ok(Ok(mut s)) = tokio::time::timeout(limit, link.open(&peer, &protocol)).await
                else {
                    return false;
                };
                rowboat_group::wire::write_frame(&mut *s, &notice, limit)
                    .await
                    .is_ok()
                    && rowboat_group::wire::read_frame(&mut *s, 16, limit)
                        .await
                        .is_ok()
            }
        });
        let told = futures::future::join_all(sends)
            .await
            .into_iter()
            .filter(|ok| *ok)
            .count();
        info!(told, "told the group's devices this server is leaving");
        true
    }
}

impl rowboat_sync::Grants for NodeLeases {
    fn grant(&self, account: &AccountId, fence: u64) -> Option<Vec<u8>> {
        let key = skein_core::coordination::lease_key(account);
        Self::lock(&self.grants)
            .get(&key)
            .filter(|(f, _)| *f == fence)
            .map(|(_, g)| g.clone())
    }
}

#[async_trait]
impl Leases for NodeLeases {
    async fn acquire(
        &self,
        group: &GroupId,
        key: &LeaseKey,
        profile: &NodeProfile,
    ) -> Result<Option<Lease>, LeaseError> {
        if self.is_yielded(key.as_str()) {
            let (arbiter, leases) = self.leases().await?;
            let held = leases.holder(group, key).await;
            self.note(arbiter, held.as_ref());
            if let Some(lease) = held?.filter(|l| l.node == profile.node) {
                debug!(%key, "giving a yielded lease back");
                let r = leases.release(&lease).await;
                self.note(arbiter, r.as_ref());
            }
            return Ok(None);
        }
        let (arbiter, leases) = self.leases().await?;
        let floor = self.floor(key).await;
        let got = leases.acquire_above(group, key, profile, floor).await;
        self.note(arbiter, got.as_ref());
        let Some(lease) = got? else {
            debug!(%key, ?arbiter, "the lease is held elsewhere");
            return Ok(None);
        };
        let before = self.saw(&lease);
        if arbiter != Arbiter::Local {
            self.ensure_grant(arbiter, &lease).await?;
            return Ok(Some(lease));
        }
        if lease.fence.0 >= before {
            return Ok(Some(lease));
        }
        leases.release(&lease).await?;
        let again = leases.acquire(group, key, profile).await?;
        if let Some(l) = &again {
            self.saw(l);
            if l.fence.0 < before {
                return Err(LeaseError::Unavailable);
            }
        }
        Ok(again)
    }

    async fn request_takeover(
        &self,
        group: &GroupId,
        key: &LeaseKey,
        profile: &NodeProfile,
    ) -> Result<TakeoverOutcome, LeaseError> {
        if self.is_yielded(key.as_str()) {
            return Ok(TakeoverOutcome::Refused);
        }
        let (arbiter, leases) = self.leases().await?;
        let r = leases.request_takeover(group, key, profile).await;
        self.note(arbiter, r.as_ref());
        r
    }

    async fn release(&self, lease: &Lease) -> Result<(), LeaseError> {
        let (arbiter, leases) = self.leases().await?;
        let r = leases.release(lease).await;
        self.note(arbiter, r.as_ref());
        r
    }

    async fn holder(&self, group: &GroupId, key: &LeaseKey) -> Result<Option<Lease>, LeaseError> {
        let (arbiter, leases) = self.leases().await?;
        let r = leases.holder(group, key).await;
        self.note(arbiter, r.as_ref());
        r
    }
}

#[async_trait]
impl Liveness for NodeLeases {
    async fn heartbeat(
        &self,
        group: &GroupId,
        profile: &NodeProfile,
        now: Timestamp,
    ) -> Result<(), LeaseError> {
        let (arbiter, live) = self.liveness().await?;
        let r = live.heartbeat(group, profile, now).await;
        self.note(arbiter, r.as_ref());
        r
    }

    async fn alive(&self, group: &GroupId, now: Timestamp) -> Result<Vec<NodeProfile>, LeaseError> {
        let (arbiter, live) = self.liveness().await?;
        let r = live.alive(group, now).await;
        self.note(arbiter, r.as_ref());
        r
    }

    fn ttl_ms(&self) -> u64 {
        self.ttl_ms
    }
}

#[cfg(test)]
mod tests;
