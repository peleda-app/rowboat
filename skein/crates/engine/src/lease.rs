use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use baton_core::{GroupId, Timestamp};
use baton_lease::{Lease, LeaseError, Liveness, NodeClass, NodeProfile};
use skein_core::{AccountId, FencingToken, NodeId, TenantId, coordination};

use crate::{AccountConfig, Engine, EngineError};

/// The group every node of a plain Skein deployment heartbeats in, once per interval whatever
/// the number of tenants (see [`OneGroupLiveness`]).
pub const NODES_GROUP: &str = "_nodes";

/// A Skein node's lease profile: an always-on node is [`NodeClass::Server`], any other node
/// [`NodeClass::Desktop`]; both may run work, with `weight` as their relative capacity (zero
/// never holds a lease).
///
/// Leases go to the strongest class alive first, so a node that is not always on gets accounts
/// only while no always-on node is alive. Among nodes of one class the choice is the same
/// weighted rendezvous hash over `(tenant, account, node)` as before.
pub fn node_profile(node: NodeId, weight: u32, always_on: bool) -> NodeProfile {
    NodeProfile {
        node,
        class: if always_on {
            NodeClass::Server
        } else {
            NodeClass::Desktop
        },
        weight,
        can_run: true,
    }
}

/// [`Liveness`] that keeps every group's heartbeats in one group, so a node heartbeats once per
/// interval instead of once per tenant. Every node then counts as a node of every tenant, which is
/// what a plain Skein deployment is: any node may hold any account.
///
/// Guarantees: every call is forwarded to `inner` with the group replaced by `group`; nothing
/// else changes, so `inner`'s guarantees hold for the shared group.
pub struct OneGroupLiveness {
    inner: Arc<dyn Liveness>,
    group: GroupId,
}

impl OneGroupLiveness {
    /// Liveness in `inner`, all of it in `group`.
    pub fn new(inner: Arc<dyn Liveness>, group: GroupId) -> Self {
        Self { inner, group }
    }

    /// Liveness in `inner`, all of it in [`NODES_GROUP`].
    pub fn nodes(inner: Arc<dyn Liveness>) -> Self {
        Self::new(inner, GroupId::new(NODES_GROUP).expect("constant"))
    }

    /// The shared group.
    pub fn group(&self) -> &GroupId {
        &self.group
    }
}

#[async_trait]
impl Liveness for OneGroupLiveness {
    async fn heartbeat(
        &self,
        _group: &GroupId,
        profile: &NodeProfile,
        now: Timestamp,
    ) -> Result<(), LeaseError> {
        self.inner.heartbeat(&self.group, profile, now).await
    }

    async fn alive(
        &self,
        _group: &GroupId,
        now: Timestamp,
    ) -> Result<Vec<NodeProfile>, LeaseError> {
        self.inner.alive(&self.group, now).await
    }

    fn ttl_ms(&self) -> u64 {
        self.inner.ttl_ms()
    }
}

/// When this node may still act on its leases: unbounded until [`Holding::arm`], then for
/// `valid_for` after the start of the last successful heartbeat.
///
/// Every lapse ends an epoch: arming, or a heartbeat that succeeds `valid_for` or more after the
/// start of the one before. A lease taken in an earlier epoch is never acted on again, even once
/// heartbeats succeed, because another node may have taken the account during the lapse.
#[derive(Default)]
pub(crate) struct Holding {
    inner: Mutex<HoldingState>,
}

#[derive(Default)]
struct HoldingState {
    valid_for: Option<Duration>,
    since: Option<Instant>,
    epoch: u64,
    leases: HashMap<(TenantId, AccountId), (FencingToken, u64)>,
}

impl HoldingState {
    fn held(&self) -> bool {
        match self.valid_for {
            None => true,
            Some(d) => self.since.is_some_and(|t| t.elapsed() < d),
        }
    }
}

impl Holding {
    pub(crate) fn arm(&self, valid_for: Duration) {
        let mut s = self.inner.lock().expect("holding lock");
        s.valid_for = Some(valid_for);
        s.epoch += 1;
    }

    pub(crate) fn beat(&self, started: Instant) {
        let mut s = self.inner.lock().expect("holding lock");
        if let (Some(d), Some(prev)) = (s.valid_for, s.since)
            && Instant::now().saturating_duration_since(prev) >= d
        {
            s.epoch += 1;
        }
        if s.since.is_none_or(|t| t < started) {
            s.since = Some(started);
        }
    }

    pub(crate) fn held(&self) -> bool {
        self.inner.lock().expect("holding lock").held()
    }

    fn record(&self, tenant: &TenantId, account: &AccountId, fence: FencingToken) -> bool {
        let mut s = self.inner.lock().expect("holding lock");
        if !s.held() {
            return false;
        }
        let epoch = s.epoch;
        s.leases
            .insert((tenant.clone(), account.clone()), (fence, epoch));
        true
    }

    fn holds(&self, tenant: &TenantId, account: &AccountId, fence: FencingToken) -> bool {
        let s = self.inner.lock().expect("holding lock");
        s.held() && s.leases.get(&(tenant.clone(), account.clone())) == Some(&(fence, s.epoch))
    }

    fn forget(&self, tenant: &TenantId, account: &AccountId) {
        let mut s = self.inner.lock().expect("holding lock");
        s.leases.remove(&(tenant.clone(), account.clone()));
    }
}

/// How long after the start of its last successful heartbeat a node keeps acting on its leases:
/// the liveness time-to-live less a fifth, the margin for clock rate differences.
pub(crate) fn valid_for(ttl_ms: u64) -> Duration {
    Duration::from_millis(ttl_ms.saturating_sub(ttl_ms / 5))
}

impl Engine {
    /// Fails with [`EngineError::NotOwner`] once this node may no longer act on its leases.
    pub(crate) fn check_held(&self) -> Result<(), EngineError> {
        if self.holding.held() {
            Ok(())
        } else {
            Err(EngineError::NotOwner)
        }
    }

    /// Fails with [`EngineError::NotOwner`] unless this node may still act on the account's lease
    /// with `fence`: its heartbeats are current and have not lapsed since the lease was taken or
    /// last renewed by [`Engine::lease`].
    pub(crate) fn check_lease(
        &self,
        config: &AccountConfig,
        fence: FencingToken,
    ) -> Result<(), EngineError> {
        if self.holding.holds(&config.tenant, &config.account, fence) {
            Ok(())
        } else {
            Err(EngineError::NotOwner)
        }
    }

    /// Takes or renews the account's lease and claims the log with its token. A pending takeover
    /// by a stronger node is honoured here, at the start of a run: the lease is released and the
    /// call fails with [`EngineError::NotOwner`].
    pub(crate) async fn lease(&self, config: &AccountConfig) -> Result<Lease, EngineError> {
        self.check_held()?;
        let group = coordination::group(&config.tenant);
        let key = coordination::lease_key(&config.account);
        let lease = self
            .leases
            .acquire(&group, &key, &self.profile)
            .await?
            .ok_or(EngineError::NotOwner)?;
        if lease.takeover.is_some() {
            let _ = self.leases.release(&lease).await;
            return Err(EngineError::NotOwner);
        }
        self.storage
            .log
            .claim(&config.tenant, &config.account, lease.fence)
            .await?;
        if !self
            .holding
            .record(&config.tenant, &config.account, lease.fence)
        {
            return Err(EngineError::NotOwner);
        }
        Ok(lease)
    }

    /// Gives the account's lease up if this node holds it.
    pub(crate) async fn release(&self, tenant: &TenantId, account: &AccountId) {
        self.holding.forget(tenant, account);
        let group = coordination::group(tenant);
        let key = coordination::lease_key(account);
        if let Ok(Some(lease)) = self.leases.holder(&group, &key).await
            && lease.node == self.profile.node
        {
            let _ = self.leases.release(&lease).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_on_nodes_are_servers() {
        let n = NodeId::new("n").unwrap();
        let p = node_profile(n.clone(), 3, true);
        assert_eq!((p.class, p.weight, p.can_run), (NodeClass::Server, 3, true));
        let p = node_profile(n.clone(), 1, false);
        assert_eq!(p.class, NodeClass::Desktop);
        assert!(p.may_lead());
        assert!(!node_profile(n, 0, true).may_lead());
    }

    #[test]
    fn holding_is_unbounded_until_armed_then_follows_heartbeats() {
        let h = Holding::default();
        assert!(h.held());
        h.arm(Duration::from_millis(50));
        assert!(!h.held(), "armed without a heartbeat holds nothing");
        h.beat(Instant::now());
        assert!(h.held());
        std::thread::sleep(Duration::from_millis(60));
        assert!(!h.held(), "a node whose heartbeats stopped stops acting");
        let old = Instant::now() - Duration::from_secs(10);
        h.beat(Instant::now());
        h.beat(old);
        assert!(h.held(), "an older heartbeat never moves the start back");
    }

    #[test]
    fn a_lease_from_before_a_lapse_is_never_held_again() {
        let (t, a) = (TenantId::new("t").unwrap(), AccountId::new("a").unwrap());
        let h = Holding::default();
        assert!(h.record(&t, &a, FencingToken(1)));
        assert!(
            h.holds(&t, &a, FencingToken(1)),
            "unarmed holds what it took"
        );
        h.arm(Duration::from_millis(50));
        h.beat(Instant::now());
        assert!(!h.holds(&t, &a, FencingToken(1)), "arming ends the epoch");
        assert!(h.record(&t, &a, FencingToken(1)));
        h.beat(Instant::now());
        assert!(
            h.holds(&t, &a, FencingToken(1)),
            "timely heartbeats keep it"
        );
        assert!(!h.holds(&t, &a, FencingToken(2)), "only with its own fence");
        let slow = Instant::now();
        std::thread::sleep(Duration::from_millis(60));
        h.beat(slow);
        assert!(
            !h.holds(&t, &a, FencingToken(1)),
            "a heartbeat that started in time but finished after the window still ends the epoch"
        );
        h.beat(Instant::now());
        assert!(h.record(&t, &a, FencingToken(3)));
        std::thread::sleep(Duration::from_millis(60));
        assert!(
            !h.record(&t, &a, FencingToken(3)),
            "nothing is taken while lapsed"
        );
        h.beat(Instant::now());
        assert!(h.held());
        assert!(!h.holds(&t, &a, FencingToken(3)));
        h.forget(&t, &a);
        assert!(!h.holds(&t, &a, FencingToken(3)));
    }

    #[test]
    fn valid_for_keeps_a_margin() {
        assert_eq!(valid_for(30_000), Duration::from_millis(24_000));
        assert_eq!(valid_for(0), Duration::ZERO);
        assert!(valid_for(u64::MAX) < Duration::from_millis(u64::MAX));
    }

    #[test]
    fn same_assignment_as_before_for_one_class() {
        fn old(t: &str, a: &str, nodes: &[(&str, u32)]) -> Option<String> {
            nodes
                .iter()
                .filter(|n| n.1 > 0)
                .map(|n| {
                    let mut h = blake3::Hasher::new();
                    h.update(t.as_bytes());
                    h.update(&[0]);
                    h.update(a.as_bytes());
                    h.update(&[0]);
                    h.update(n.0.as_bytes());
                    let bytes = h.finalize();
                    let x = u64::from_le_bytes(bytes.as_bytes()[..8].try_into().unwrap());
                    let unit = ((x >> 11) as f64 + 0.5) / (1u64 << 53) as f64;
                    (-(n.1 as f64) / unit.ln(), n.0)
                })
                .max_by(|a, b| a.0.total_cmp(&b.0).then_with(|| b.1.cmp(a.1)))
                .map(|(_, n)| n.to_owned())
        }
        let nodes = [("a", 1), ("b", 2), ("c", 1), ("d", 0)];
        let profiles: Vec<_> = nodes
            .iter()
            .map(|(n, w)| node_profile(NodeId::new(*n).unwrap(), *w, true))
            .collect();
        let t = TenantId::new("acme").unwrap();
        for i in 0..2000 {
            let a = AccountId::new(format!("acc{i}")).unwrap();
            let new = baton_lease::preferred(
                &coordination::group(&t),
                &coordination::lease_key(&a),
                &profiles,
            )
            .map(|p| p.node.as_str().to_owned());
            assert_eq!(new, old(t.as_str(), a.as_str(), &nodes), "{a}");
        }
    }
}
