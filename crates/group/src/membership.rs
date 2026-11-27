use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};

use baton_core::{GroupId, ResourceId, Timestamp};
use baton_group::epochs::{self, ResourceKeys};
use baton_group::{
    Capability, Entry, Founding, GroupLog, NodeCert, Op, Principal, Recipient, Role,
};
use baton_identity::{Identity, PublicKey};
use baton_keys::{KemSecret, RecoveryPublic};
use baton_lease::NodeClass;
use baton_link::Trust;
use baton_state::{Expect, RecordName, StateStore};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::invite::WireHint;
use crate::{MembershipError, Now};

/// How far ahead of this node's clock an entry from a peer may be dated, in milliseconds.
pub const MAX_SKEW_MS: i64 = 5 * 60 * 1000;
const MAX_PEERS: usize = 1024;
const MAX_LABEL: usize = 64;
const PEER_VERSION: u8 = 1;

/// The keys a node holds for its group. `Debug` shows only public halves.
pub struct NodeKeys {
    /// The node's signing key: its id and its link key.
    pub identity: Identity,
    /// The node's KEM key, which resource key boxes are sealed to.
    pub kem: KemSecret,
    /// The member key, on desktops and phones; never on servers.
    pub member: Option<Identity>,
}

impl std::fmt::Debug for NodeKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeKeys")
            .field("node", &self.identity.public())
            .field("member", &self.member.as_ref().map(|m| m.public()))
            .finish_non_exhaustive()
    }
}

/// One node of the group as the log has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeView {
    /// The node's key.
    pub node: PublicKey,
    /// Its class.
    pub class: NodeClass,
    /// The member it belongs to.
    pub member: PublicKey,
    /// When its certificate expires.
    pub expires: Timestamp,
    /// Whether it counts now (certified, not revoked, not expired, its member still in).
    pub counts: bool,
    /// Whether it was revoked.
    pub revoked: bool,
    /// The label it gave when it paired with this node; display only, never trusted.
    pub label: Option<String>,
}

/// What this node remembers about a peer: where to reach it, and the label it gave when pairing
/// here. Kept at `peers/{node id}`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerRecord {
    /// Where to reach it.
    pub hint: WireHint,
    /// The label it gave when it paired with this node.
    pub label: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct StoredPeer {
    v: u8,
    record: PeerRecord,
}

/// What a revocation changed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Revocation {
    /// Resources the revoked node could lead: their secrets (account passwords, tokens) must be
    /// changed, since the node may have kept them.
    pub secrets_rotation_required: Vec<ResourceId>,
    /// Resources that got a new key epoch the revoked node cannot open.
    pub rotated: Vec<ResourceId>,
}

/// Something changed in the membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipEvent {
    /// The log moved forward to this head.
    Changed {
        /// The new head's sequence number.
        head: u64,
    },
    /// This node was revoked.
    Revoked,
}

/// The node's view of its group.
///
/// Guarantees:
///
/// - The log only moves forward: entries from peers are applied only when they continue the
///   current head and verify (signatures, chain, authority at their point, entry times at most
///   [`MAX_SKEW_MS`] ahead); an older, shorter or forked log never replaces it. An entry is stored
///   only after it verified, and the in-memory log moves only after the store took it.
/// - Appends are serialized; every append is verified against the state like a peer's entry.
/// - [`Membership::trust`] admits exactly the nodes that count at the moment of the call, so a
///   revocation or an expiry applies to the next stream; a node the log revoked is admitted on
///   the revocation notice protocol ([`crate::notice`]) only.
/// - Capability answers ([`Membership::may`]) are empty for a node that does not count, including
///   this node after its revocation or expiry.
pub struct Membership {
    group: GroupId,
    store: Arc<dyn StateStore>,
    keys: NodeKeys,
    log: RwLock<GroupLog>,
    peers: RwLock<BTreeMap<PublicKey, PeerRecord>>,
    write: tokio::sync::Mutex<()>,
    now: Now,
    events: broadcast::Sender<MembershipEvent>,
}

fn storage<E>(_: E) -> MembershipError {
    MembershipError::Storage
}

fn peer_name(node: &PublicKey) -> RecordName {
    RecordName::new(format!("peers/{}", node.node_id())).expect("node ids are valid names")
}

impl Membership {
    fn new(
        group: GroupId,
        store: Arc<dyn StateStore>,
        keys: NodeKeys,
        log: GroupLog,
        now: Now,
    ) -> Self {
        let (events, _) = broadcast::channel(64);
        Self {
            group,
            store,
            keys,
            log: RwLock::new(log),
            peers: RwLock::new(BTreeMap::new()),
            write: tokio::sync::Mutex::new(()),
            now,
            events,
        }
    }

    /// Founds a new group: genesis with the member key as owner and this node as the founder,
    /// stored before it is returned. Needs a member key.
    #[allow(clippy::too_many_arguments)]
    pub async fn found(
        store: Arc<dyn StateStore>,
        group: GroupId,
        keys: NodeKeys,
        owner_recovery: RecoveryPublic,
        group_recovery: RecoveryPublic,
        class: NodeClass,
        expires: Timestamp,
        now: Now,
    ) -> Result<Self, MembershipError> {
        let member = keys.member.as_ref().ok_or(MembershipError::NotAuthorized)?;
        let log = GroupLog::genesis(
            group.clone(),
            Founding {
                owner: member,
                owner_recovery,
                group_recovery,
                node: &keys.identity,
                node_kem: keys.kem.public(),
                class,
                expires,
            },
            now(),
        )?;
        baton_group::store::save(&store, &log).await?;
        Ok(Self::new(group, store, keys, log, now))
    }

    /// Opens the group stored in `store`, verified from genesis. Fails with
    /// [`MembershipError::NotFound`] when nothing is stored and with
    /// [`MembershipError::Unverified`] when this node was never certified in it.
    pub async fn open(
        store: Arc<dyn StateStore>,
        group: GroupId,
        keys: NodeKeys,
        now: Now,
    ) -> Result<Self, MembershipError> {
        let first = store
            .get(
                &group,
                &RecordName::new(format!("group/{:020}", 0)).expect("constant"),
            )
            .await
            .map_err(storage)?;
        if first.is_none() {
            return Err(MembershipError::NotFound);
        }
        let log = baton_group::store::load(&store, &group).await?;
        if !log.state().was_certified(&keys.identity.public()) {
            return Err(MembershipError::Unverified);
        }
        let m = Self::new(group, store, keys, log, now);
        m.load_peers().await?;
        Ok(m)
    }

    /// Takes a log received when joining: it must already be verified, list this node, and be
    /// the only log of its group in `store` (or a prefix of what is stored).
    pub async fn adopt(
        store: Arc<dyn StateStore>,
        log: GroupLog,
        keys: NodeKeys,
        peers: Vec<(PublicKey, PeerRecord)>,
        now: Now,
    ) -> Result<Self, MembershipError> {
        if log.state().node(&keys.identity.public(), now()).is_none() {
            return Err(MembershipError::Unverified);
        }
        baton_group::store::save(&store, &log).await?;
        let group = log.state().group().clone();
        let m = Self::new(group, store, keys, log, now);
        for (node, record) in peers {
            m.remember_peer(&node, record).await?;
        }
        Ok(m)
    }

    async fn load_peers(&self) -> Result<(), MembershipError> {
        let prefix = RecordName::new("peers").expect("constant");
        let names = self
            .store
            .list(&self.group, &prefix, None, MAX_PEERS)
            .await
            .map_err(storage)?;
        let mut peers = BTreeMap::new();
        for name in names {
            let Some(id) = name.as_str().strip_prefix("peers/") else {
                continue;
            };
            let Ok(node_id) = baton_core::NodeId::new(id) else {
                continue;
            };
            let Ok(node) = PublicKey::from_node_id(&node_id) else {
                continue;
            };
            if let Some((bytes, _)) = self.store.get(&self.group, &name).await.map_err(storage)?
                && let Ok(stored) = postcard::from_bytes::<StoredPeer>(&bytes)
                && stored.v == PEER_VERSION
                && stored.record.hint.check().is_ok()
            {
                peers.insert(node, stored.record);
            }
        }
        *self.peers.write().expect("peers lock") = peers;
        Ok(())
    }

    /// Records where `node` can be reached (and its label, when given). Only nodes the log ever
    /// certified are kept; at most 1,024.
    pub async fn remember_peer(
        &self,
        node: &PublicKey,
        mut record: PeerRecord,
    ) -> Result<(), MembershipError> {
        if !self
            .log
            .read()
            .expect("log lock")
            .state()
            .was_certified(node)
            || node == &self.keys.identity.public()
            || record.hint.check().is_err()
        {
            return Ok(());
        }
        if let Some(l) = &record.label {
            let clean: String = l
                .chars()
                .filter(|c| !c.is_control())
                .take(MAX_LABEL)
                .collect();
            record.label = Some(clean);
        }
        {
            let peers = self.peers.read().expect("peers lock");
            if peers.get(node) == Some(&record) {
                return Ok(());
            }
            if record.label.is_none()
                && let Some(old) = peers.get(node)
            {
                record.label = old.label.clone();
            }
            if !peers.contains_key(node) && peers.len() >= MAX_PEERS {
                return Ok(());
            }
        }
        let bytes = postcard::to_stdvec(&StoredPeer {
            v: PEER_VERSION,
            record: record.clone(),
        })
        .expect("a peer record serializes");
        self.store
            .put(
                &self.group,
                &peer_name(node),
                Bytes::from(bytes),
                Expect::Any,
            )
            .await
            .map_err(storage)?;
        self.peers
            .write()
            .expect("peers lock")
            .insert(*node, record);
        Ok(())
    }

    /// What this node remembers about `node`.
    pub fn peer(&self, node: &PublicKey) -> Option<PeerRecord> {
        self.peers.read().expect("peers lock").get(node).cloned()
    }

    /// Every remembered peer.
    pub fn peers(&self) -> Vec<(PublicKey, PeerRecord)> {
        self.peers
            .read()
            .expect("peers lock")
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    }

    /// The group.
    pub fn group(&self) -> &GroupId {
        &self.group
    }

    /// This node's key.
    pub fn node(&self) -> PublicKey {
        self.keys.identity.public()
    }

    /// This node's keys.
    pub fn keys(&self) -> &NodeKeys {
        &self.keys
    }

    /// The current time.
    pub fn now(&self) -> Timestamp {
        (self.now)()
    }

    /// A copy of the current log.
    pub fn log(&self) -> GroupLog {
        self.log.read().expect("log lock").clone()
    }

    /// The head: sequence number and hash of the last entry.
    pub fn head(&self) -> (u64, [u8; 32]) {
        let log = self.log.read().expect("log lock");
        (log.head_seq(), log.head_hash())
    }

    /// The genesis hash: the group's fingerprint.
    pub fn genesis_hash(&self) -> [u8; 32] {
        self.log.read().expect("log lock").genesis_hash()
    }

    /// Runs `f` on the current log.
    pub fn with_log<T>(&self, f: impl FnOnce(&GroupLog) -> T) -> T {
        f(&self.log.read().expect("log lock"))
    }

    /// Whether `node` counts now.
    pub fn counts(&self, node: &PublicKey) -> bool {
        let now = self.now();
        self.log
            .read()
            .expect("log lock")
            .state()
            .node(node, now)
            .is_some()
    }

    /// Whether this node was revoked.
    pub fn is_revoked(&self) -> bool {
        self.log
            .read()
            .expect("log lock")
            .state()
            .is_revoked(&self.node())
    }

    /// Whether this node holds `capability` on `resource` now.
    pub fn may(&self, resource: &ResourceId, capability: &Capability) -> bool {
        let now = self.now();
        self.log
            .read()
            .expect("log lock")
            .state()
            .may(&self.node(), resource, capability, now)
    }

    /// Every node the log ever certified, sorted by key, with what it says about each.
    pub fn nodes(&self) -> Vec<NodeView> {
        let now = self.now();
        let log = self.log.read().expect("log lock");
        let state = log.state();
        let peers = self.peers.read().expect("peers lock");
        let mut out = Vec::new();
        for e in log.entries() {
            let (Op::CertifyNode { cert } | Op::Genesis { founder: cert, .. }) = e.op() else {
                continue;
            };
            let current = state.node(&cert.node, now);
            let revoked = state.is_revoked(&cert.node);
            let expires = renewed_expiry(&log, &cert.node).unwrap_or(cert.expires);
            out.push(NodeView {
                node: cert.node,
                class: cert.class,
                member: cert.member,
                expires,
                counts: current.is_some(),
                revoked,
                label: peers.get(&cert.node).and_then(|p| p.label.clone()),
            });
        }
        out.sort_by_key(|a| a.node);
        out.dedup_by(|a, b| a.node == b.node);
        out
    }

    /// Every resource the log created, sorted.
    pub fn resources(&self) -> Vec<ResourceId> {
        resource_ids(&self.log.read().expect("log lock"))
    }

    /// Whether `node` holds `capability` on `resource` now.
    pub fn node_may(
        &self,
        node: &PublicKey,
        resource: &ResourceId,
        capability: &Capability,
    ) -> bool {
        let now = self.now();
        self.log
            .read()
            .expect("log lock")
            .state()
            .may(node, resource, capability, now)
    }

    /// The class of `node`'s certificate when it counts now.
    pub fn class_of(&self, node: &PublicKey) -> Option<NodeClass> {
        let now = self.now();
        self.log
            .read()
            .expect("log lock")
            .state()
            .node(node, now)
            .map(|c| c.class)
    }

    /// Whether `node` was revoked in this group.
    pub fn is_revoked_node(&self, node: &PublicKey) -> bool {
        self.log.read().expect("log lock").state().is_revoked(node)
    }

    /// Whether `node` was ever certified in this group (revoked or expired included).
    pub fn was_certified(&self, node: &PublicKey) -> bool {
        self.log
            .read()
            .expect("log lock")
            .state()
            .was_certified(node)
    }

    /// The nodes that count now, other than this one.
    pub fn counting_peers(&self) -> Vec<PublicKey> {
        let now = self.now();
        let me = self.node();
        self.log
            .read()
            .expect("log lock")
            .state()
            .nodes(now)
            .into_iter()
            .map(|c| c.node)
            .filter(|k| k != &me)
            .collect()
    }

    /// A subscription to membership events (at most 64 buffered).
    pub fn subscribe(&self) -> broadcast::Receiver<MembershipEvent> {
        self.events.subscribe()
    }

    /// A trust that admits exactly the nodes counting at the moment of each call.
    pub fn trust(self: &Arc<Self>) -> Arc<dyn Trust> {
        Arc::new(MembershipTrust(Arc::downgrade(self)))
    }

    async fn commit(&self, next: GroupLog, from: u64) -> Result<(), MembershipError> {
        for e in &next.entries()[from as usize..] {
            baton_group::store::append(&self.store, e).await?;
        }
        let head = next.head_seq();
        let was_revoked = self.is_revoked();
        let now_revoked = next.state().is_revoked(&self.node());
        *self.log.write().expect("log lock") = next;
        let _ = self.events.send(MembershipEvent::Changed { head });
        if now_revoked && !was_revoked {
            let _ = self.events.send(MembershipEvent::Revoked);
        }
        Ok(())
    }

    /// Signs `ops` with this node's key as the next entries, verifies each against the state,
    /// stores them and moves the log. Nothing is stored when any of them fails.
    pub async fn append(&self, ops: Vec<Op>) -> Result<Vec<Entry>, MembershipError> {
        let _guard = self.write.lock().await;
        self.append_locked(ops).await
    }

    async fn append_locked(&self, ops: Vec<Op>) -> Result<Vec<Entry>, MembershipError> {
        let mut next = self.log();
        let from = next.head_seq() + 1;
        let now = self.now().max(next.state().last_at());
        let mut out = Vec::new();
        for op in ops {
            out.push(next.append(&self.keys.identity, op, now)?);
        }
        if out.is_empty() {
            return Ok(out);
        }
        self.commit(next, from).await?;
        Ok(out)
    }

    /// Applies entries from a peer or a store: entries this log already has must be identical
    /// (otherwise [`MembershipError::Fork`]); new ones must continue the head and verify. Returns
    /// how many were new. Nothing changes when any entry fails.
    pub async fn apply_remote(&self, entries: Vec<Entry>) -> Result<usize, MembershipError> {
        let _guard = self.write.lock().await;
        let mut next = self.log();
        let from = next.head_seq() + 1;
        let now = self.now();
        let mut added = 0;
        for e in entries {
            if e.group() != &self.group {
                return Err(MembershipError::Fork);
            }
            if e.seq() < from {
                if next.entries()[e.seq() as usize].hash() != e.hash() {
                    return Err(MembershipError::Fork);
                }
                continue;
            }
            next.apply_fresh(e, now, MAX_SKEW_MS)?;
            added += 1;
        }
        if added > 0 {
            self.commit(next, from).await?;
        }
        Ok(added)
    }

    fn member(&self) -> Result<&Identity, MembershipError> {
        let member = self
            .keys
            .member
            .as_ref()
            .ok_or(MembershipError::NotAuthorized)?;
        let log = self.log.read().expect("log lock");
        let cert = log
            .state()
            .node(&self.node(), self.now())
            .ok_or(MembershipError::NotAuthorized)?;
        if cert.member != member.public() {
            return Err(MembershipError::NotAuthorized);
        }
        Ok(member)
    }

    /// The member key, when this node holds one and counts as that member's node.
    pub fn member_key(&self) -> Result<&Identity, MembershipError> {
        self.member()
    }

    /// Whether this node can certify a new node now: it counts and holds its member's key.
    pub fn can_certify(&self) -> bool {
        self.member().is_ok()
    }

    /// Opens this node's keys of `resource` at `epoch`.
    pub fn resource_keys(
        &self,
        resource: &ResourceId,
        epoch: u64,
    ) -> Result<ResourceKeys, MembershipError> {
        let log = self.log.read().expect("log lock");
        epochs::open(
            &log,
            resource,
            epoch,
            &Recipient::Node(self.node()),
            &self.keys.kem,
        )
        .map_err(|_| MembershipError::NotAuthorized)
    }

    /// Certifies a node whose certificate the caller assembled, then shares every epoch of every
    /// resource the node may now read that this node can open. Returns the new entries. A server
    /// may read nothing yet: it gets resources through [`Membership::grant_server`].
    pub async fn certify(&self, cert: NodeCert) -> Result<Vec<Entry>, MembershipError> {
        let _guard = self.write.lock().await;
        self.member()?;
        let mut out = self.append_locked(vec![Op::CertifyNode { cert }]).await?;
        let all = resource_ids(&self.log.read().expect("log lock"));
        out.extend(self.share_locked(&all).await?);
        Ok(out)
    }

    /// Grants the server node `server` read and lead on each of `resources` (the accounts the
    /// person moves to it) and shares their epochs with it. A server holds nothing through its
    /// member: these grants are all it may use. Needs the member key; resources this node's member
    /// did not create are refused.
    pub async fn grant_server(
        &self,
        server: &PublicKey,
        resources: &[ResourceId],
    ) -> Result<Vec<Entry>, MembershipError> {
        let _guard = self.write.lock().await;
        let member = self.member()?.public();
        let ops = {
            let log = self.log.read().expect("log lock");
            let state = log.state();
            let cert = state
                .node(server, self.now())
                .ok_or(MembershipError::NotFound)?;
            if cert.class != NodeClass::Server || cert.member != member {
                return Err(MembershipError::Invalid);
            }
            let mut ops = Vec::new();
            for r in resources {
                let s = state.resource(r).ok_or(MembershipError::NotFound)?;
                if s.creator() != &member {
                    return Err(MembershipError::NotAuthorized);
                }
                let mut caps = s
                    .grants()
                    .get(&Principal::Node(*server))
                    .cloned()
                    .unwrap_or_default();
                if caps.insert(Capability::Read) | caps.insert(Capability::Lead) {
                    ops.push(Op::Grant {
                        resource: r.clone(),
                        principal: Principal::Node(*server),
                        capabilities: caps,
                    });
                }
            }
            ops
        };
        let mut out = self.append_locked(ops).await?;
        out.extend(self.share_locked(resources).await?);
        Ok(out)
    }

    async fn share_locked(&self, resources: &[ResourceId]) -> Result<Vec<Entry>, MembershipError> {
        let mut out = Vec::new();
        let epochs: Vec<(ResourceId, u64)> = {
            let log = self.log.read().expect("log lock");
            let state = log.state();
            resources
                .iter()
                .filter_map(|r| state.resource(r).map(|s| (r.clone(), s.epoch())))
                .collect()
        };
        for (resource, current) in epochs {
            for epoch in 1..=current {
                let Ok(keys) = self.resource_keys(&resource, epoch) else {
                    continue;
                };
                let op = {
                    let log = self.log.read().expect("log lock");
                    epochs::share_epoch(log.state(), &resource, epoch, &keys, self.now())?
                };
                if let Some(op) = op {
                    out.extend(self.append_locked(vec![op]).await?);
                }
            }
        }
        Ok(out)
    }

    /// Makes sure `resource` exists with this node's member granted read, lead, admin and the
    /// command `classes`, and has a key epoch. Does nothing when all of that already holds.
    pub async fn ensure_resource(
        &self,
        resource: &ResourceId,
        classes: &[&str],
    ) -> Result<(), MembershipError> {
        let _guard = self.write.lock().await;
        let member = self.member()?.public();
        let mut wanted: BTreeSet<Capability> =
            [Capability::Read, Capability::Lead, Capability::Admin].into();
        wanted.extend(classes.iter().map(|c| Capability::Command((*c).to_owned())));
        let exists = self
            .log
            .read()
            .expect("log lock")
            .state()
            .resource(resource)
            .is_some();
        if !exists {
            self.append_locked(vec![Op::CreateResource {
                resource: resource.clone(),
            }])
            .await?;
        }
        let (has, creator, epoch) = {
            let log = self.log.read().expect("log lock");
            let state = log.state();
            let r = state.resource(resource).ok_or(MembershipError::Invalid)?;
            let now = self.now();
            let has = state.capabilities(resource, &self.node(), now);
            (has, *r.creator(), r.epoch())
        };
        if creator == member && !wanted.is_subset(&has) {
            self.append_locked(vec![Op::Grant {
                resource: resource.clone(),
                principal: Principal::Member(member),
                capabilities: wanted,
            }])
            .await?;
        }
        if epoch == 0 {
            let op = {
                let log = self.log.read().expect("log lock");
                epochs::new_epoch(log.state(), resource, self.now())?.0
            };
            self.append_locked(vec![op]).await?;
        }
        Ok(())
    }

    /// Revokes `node`: `RevokeNode`, then a new epoch for every resource this node may rotate and
    /// someone revoked still holds keys of. Refuses this node itself and nodes that are not
    /// certified or already revoked.
    pub async fn revoke(&self, node: &PublicKey) -> Result<Revocation, MembershipError> {
        let _guard = self.write.lock().await;
        if node == &self.node() {
            return Err(MembershipError::Invalid);
        }
        let now = self.now();
        let led: Vec<ResourceId> = {
            let log = self.log.read().expect("log lock");
            let state = log.state();
            if !state.was_certified(node) {
                return Err(MembershipError::NotFound);
            }
            if state.is_revoked(node) {
                return Err(MembershipError::Invalid);
            }
            resource_ids(&log)
                .into_iter()
                .filter(|r| state.may(node, r, &Capability::Lead, now))
                .collect()
        };
        self.append_locked(vec![Op::RevokeNode { node: *node }])
            .await?;
        let mut rotated = Vec::new();
        let candidates = resource_ids(&self.log.read().expect("log lock"));
        for r in candidates {
            let op = {
                let log = self.log.read().expect("log lock");
                let state = log.state();
                let may = state.may(&self.node(), &r, &Capability::Admin, now)
                    || state.may(&self.node(), &r, &Capability::Lead, now);
                if !may || !state.needs_rotation(&r, now) {
                    continue;
                }
                epochs::new_epoch(state, &r, now)?.0
            };
            self.append_locked(vec![op]).await?;
            rotated.push(r);
        }
        Ok(Revocation {
            secrets_rotation_required: led,
            rotated,
        })
    }

    /// Renews this node's certificate to `now + term_ms` when it expires within `window_ms`.
    /// Returns whether it renewed; needs the member key.
    pub async fn renew_if_due(
        &self,
        term_ms: i64,
        window_ms: i64,
    ) -> Result<bool, MembershipError> {
        let _guard = self.write.lock().await;
        let now = self.now();
        let cert = {
            let log = self.log.read().expect("log lock");
            log.state().node(&self.node(), now).cloned()
        };
        let Some(cert) = cert else {
            return Err(MembershipError::NotAuthorized);
        };
        if cert.expires.0 - now.0 > window_ms {
            return Ok(false);
        }
        let member = self.member()?;
        let renewed = NodeCert::new(
            member,
            &self.keys.identity,
            self.keys.kem.public(),
            cert.class,
            now.plus_ms(term_ms),
        );
        self.append_locked(vec![Op::RenewNode { cert: renewed }])
            .await?;
        Ok(true)
    }

    /// The role of this node's member.
    pub fn role(&self) -> Option<Role> {
        let log = self.log.read().expect("log lock");
        let state = log.state();
        let cert = state.node(&self.node(), self.now())?;
        state.role(&cert.member)
    }
}

fn renewed_expiry(log: &GroupLog, node: &PublicKey) -> Option<Timestamp> {
    log.entries().iter().rev().find_map(|e| match e.op() {
        Op::RenewNode { cert } if &cert.node == node => Some(cert.expires),
        _ => None,
    })
}

fn resource_ids(log: &GroupLog) -> Vec<ResourceId> {
    let mut ids: Vec<ResourceId> = log
        .entries()
        .iter()
        .filter_map(|e| match e.op() {
            Op::CreateResource { resource } => Some(resource.clone()),
            _ => None,
        })
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

struct MembershipTrust(std::sync::Weak<Membership>);

impl Trust for MembershipTrust {
    fn allows(&self, peer: &PublicKey) -> bool {
        self.0
            .upgrade()
            .is_some_and(|m| peer != &m.node() && m.counts(peer))
    }

    fn allows_on(&self, peer: &PublicKey, protocol: &baton_link::Protocol) -> bool {
        self.allows(peer)
            || (protocol.as_str() == crate::notice::NOTICE_PROTOCOL && self.revoked_peer(peer))
    }

    fn reachable(&self, peer: &PublicKey) -> bool {
        self.allows(peer) || self.revoked_peer(peer)
    }
}

impl MembershipTrust {
    fn revoked_peer(&self, peer: &PublicKey) -> bool {
        self.0.upgrade().is_some_and(|m| {
            peer != &m.node()
                && m.with_log(|l| l.state().was_certified(peer) && l.state().is_revoked(peer))
        })
    }
}

#[cfg(test)]
mod tests;
