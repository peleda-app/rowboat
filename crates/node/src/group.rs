//! The node's group: membership through the Baton group log (`rowboat-group`), pairing, the
//! node's own link with the group log exchange, revocation, and the capability checks of the
//! node's operations.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use baton_group::Capability;
use baton_identity::PublicKey;
use baton_lease::NodeClass;
use baton_link::Link;
use baton_state::StateStore;
use rowboat_api::{
    AccountId, CommandClass, EVENT_BUFFER, GroupEvent, GroupEventStream, NodeError, NodeSummary,
    PairingInvite, PairingResult, Revoked,
};
use rowboat_endpoint::Endpoints;
use rowboat_group::invite::{Invite, InviteKind, PairAddress, PairingCode, ShortCode, WireHint};
use rowboat_group::pairing::{
    self, Candidate, Certifier, Confirm, Inviter, Limits, Outcome, PairingCheck, PairingEndpoint,
    Side,
};
use rowboat_group::{
    DAY_MS, Membership, MembershipError, MembershipEvent, NodeKeys, Now, account_resource, sync,
};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use futures::StreamExt;
use tokio::sync::broadcast;

/// Streams of one pairing endpoint served or waiting for a handshake slot at once; more are
/// dropped unanswered.
const PAIR_STREAMS: usize = 8;

/// The link protocol limits of the group exchange.
const SYNC_LIMIT: Duration = Duration::from_secs(20);
/// How often a node exchanges heads with every peer it can reach.
pub(crate) const SYNC_EVERY: Duration = Duration::from_secs(5 * 60);
/// Renewal: a certificate is renewed in its last 30 days.
const RENEW_WINDOW_MS: i64 = 30 * DAY_MS;

/// Every command class of a mail account, granted to the account's creator.
pub(crate) const ACCOUNT_CLASSES: [CommandClass; 12] = [
    CommandClass::AccountAdd,
    CommandClass::AccountPassword,
    CommandClass::AccountUpdate,
    CommandClass::AccountRemove,
    CommandClass::Sync,
    CommandClass::Flags,
    CommandClass::Move,
    CommandClass::Delete,
    CommandClass::DeleteForever,
    CommandClass::Draft,
    CommandClass::Send,
    CommandClass::SendCancel,
];

pub(crate) fn class_names() -> Vec<&'static str> {
    ACCOUNT_CLASSES.iter().map(|c| c.as_str()).collect()
}

pub(crate) fn err(e: MembershipError) -> NodeError {
    match e {
        MembershipError::Malformed | MembershipError::Invalid => NodeError::InvalidInput,
        MembershipError::WrongCode => NodeError::PairingCodeRejected,
        MembershipError::Refused | MembershipError::Rejected => NodeError::PairingRefused,
        MembershipError::Unreachable | MembershipError::TimedOut => NodeError::PeerUnreachable,
        MembershipError::Busy => NodeError::Busy,
        MembershipError::NotAuthorized => NodeError::Forbidden,
        MembershipError::NotFound => NodeError::NotFound,
        MembershipError::Fork | MembershipError::Unverified => NodeError::ServerRefused,
        MembershipError::Storage => NodeError::Storage,
    }
}

fn class_name(class: NodeClass) -> &'static str {
    match class {
        NodeClass::Server => "server",
        NodeClass::Desktop => "desktop",
        NodeClass::Phone => "phone",
        NodeClass::Blind => "blind",
    }
}

struct Net {
    link: Arc<dyn Link>,
    hint: WireHint,
    serve: JoinHandle<()>,
    notices: JoinHandle<()>,
}

/// A server's first-run invite (GROUP.md, "The server's first run"): what the operator shows the
/// person, and the end of the adoption.
pub struct ServerInvite {
    /// The QR payload (`peleda-pair:...`).
    pub qr: String,
    /// The short code, `XX-XXXX-XXXX`.
    pub short_code: String,
    /// The pairing address a short code is typed with (`peleda-addr:...`).
    pub address: String,
    /// When the invite expires, in milliseconds since the epoch.
    pub expires_at: i64,
    /// Resolves once a member device adopted the server (the node must then be rebuilt), or
    /// with the error that ended the invite (`PairingExpired` when it expired unused).
    pub adopted: oneshot::Receiver<Result<(), NodeError>>,
}

pub(crate) type Adoption = oneshot::Receiver<Result<JoinedGroup, NodeError>>;

/// What the node writes when it joins another group; see [`NodeGroup::accept`].
pub(crate) struct JoinedGroup {
    pub group: String,
    pub member: Option<baton_identity::Identity>,
}

/// The group side of a node.
pub(crate) struct NodeGroup {
    membership: RwLock<Arc<Membership>>,
    pub(crate) replication: std::sync::OnceLock<Arc<rowboat_sync::Replication>>,
    moved: AtomicBool,
    endpoints: Option<Arc<dyn Endpoints>>,
    net: tokio::sync::Mutex<Option<Net>>,
    inviter: Arc<Inviter>,
    confirms: Mutex<BTreeMap<String, oneshot::Sender<bool>>>,
    invites: Mutex<BTreeMap<u64, Arc<PairingEndpoint>>>,
    tasks: crate::tasks::Background,
    catching_up: Mutex<std::collections::BTreeSet<PublicKey>>,
    hub: broadcast::Sender<GroupEvent>,
    store: Arc<dyn StateStore>,
    class: NodeClass,
    limits: Limits,
    now: Now,
    label: String,
    seen: Mutex<BTreeMap<PublicKey, i64>>,
}

/// The record that holds the name this node gave `node` (`rename_node`).
fn name_record(node: &PublicKey) -> baton_state::RecordName {
    baton_state::RecordName::new(format!("rowboat/names/{}", node.node_id()))
        .expect("node ids are valid names")
}

/// `label` cut to one line of at most [`rowboat_api::group::MAX_NODE_LABEL`] characters.
pub(crate) fn clean_label(label: &str) -> String {
    label
        .chars()
        .filter(|c| !c.is_control())
        .take(rowboat_api::group::MAX_NODE_LABEL)
        .collect()
}

struct NodeConfirm {
    group: Arc<NodeGroup>,
    pairing: String,
    ask: bool,
}

#[async_trait]
impl Confirm for NodeConfirm {
    async fn confirm(&self, check: &PairingCheck) -> bool {
        let (tx, rx) = oneshot::channel();
        if self.ask {
            self.group
                .confirms
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(self.pairing.clone(), tx);
        }
        let _ = self.group.hub.send(GroupEvent::PairingCheck {
            pairing: self.pairing.clone(),
            fingerprint: check.fingerprint.clone(),
            node: check.peer.node_id().to_string(),
            class: class_name(check.class).into(),
            confirm: self.ask,
        });
        if !self.ask {
            return true;
        }
        let answer = rx.await.unwrap_or(false);
        self.group
            .confirms
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.pairing);
        answer
    }
}

impl Drop for NodeConfirm {
    fn drop(&mut self) {
        if self.ask {
            self.group
                .confirms
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&self.pairing);
        }
    }
}

fn invite_name(id: u64) -> String {
    format!("{id:016x}")
}

impl NodeGroup {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        membership: Arc<Membership>,
        endpoints: Option<Arc<dyn Endpoints>>,
        store: Arc<dyn StateStore>,
        class: NodeClass,
        limits: Limits,
        now: Now,
        label: String,
    ) -> Arc<Self> {
        let (hub, _) = broadcast::channel(EVENT_BUFFER);
        let group = Arc::new(Self {
            membership: RwLock::new(membership.clone()),
            replication: std::sync::OnceLock::new(),
            moved: AtomicBool::new(false),
            endpoints,
            net: tokio::sync::Mutex::new(None),
            inviter: Arc::new(Inviter::new(limits.clone(), now.clone())),
            confirms: Mutex::new(BTreeMap::new()),
            invites: Mutex::new(BTreeMap::new()),
            tasks: crate::tasks::Background::default(),
            catching_up: Mutex::new(std::collections::BTreeSet::new()),
            hub: hub.clone(),
            store,
            class,
            limits,
            now,
            label: clean_label(&label),
            seen: Mutex::new(BTreeMap::new()),
        });
        let mut events = membership.subscribe();
        tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(MembershipEvent::Changed { .. }) => {
                        let _ = hub.send(GroupEvent::NodesChanged);
                    }
                    Ok(MembershipEvent::Revoked) => {
                        warn!("this node was revoked");
                        let _ = hub.send(GroupEvent::NodeRevoked);
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        let _ = hub.send(GroupEvent::NodesChanged);
                    }
                    Err(_) => break,
                }
            }
        });
        group
    }

    /// Raises `event` to every subscriber of the group's events.
    pub(crate) fn raise(&self, event: GroupEvent) {
        let _ = self.hub.send(event);
    }

    /// Brings the node's link up when the group has other nodes. Returns whether it is up.
    pub(crate) async fn link_up(self: &Arc<Self>) -> bool {
        let Ok(m) = self.membership() else {
            return false;
        };
        if m.counting_peers().is_empty() || self.endpoints.is_none() {
            return false;
        }
        self.ensure_net().await.is_ok()
    }

    /// A new subscription to the group's events.
    pub(crate) fn subscribe(&self) -> GroupEventStream {
        let rx = self.hub.subscribe();
        Box::pin(futures::stream::unfold(rx, |mut rx| async move {
            match rx.recv().await {
                Ok(e) => Some((e, rx)),
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    Some((GroupEvent::Lagged { missed }, rx))
                }
                Err(broadcast::error::RecvError::Closed) => None,
            }
        }))
        .boxed()
    }

    pub(crate) fn membership(&self) -> Result<Arc<Membership>, NodeError> {
        if self.moved.load(Ordering::SeqCst) {
            return Err(NodeError::Busy);
        }
        Ok(self
            .membership
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone())
    }

    /// Whether this node may read `account`, and issue `class` on it when given. Anything the
    /// node may not use looks like an account it does not know.
    pub(crate) fn check(
        &self,
        account: &AccountId,
        class: Option<CommandClass>,
    ) -> Result<(), NodeError> {
        let m = self.membership()?;
        let resource = account_resource(account.as_str()).ok_or(NodeError::NotFound)?;
        if !m.may(&resource, &Capability::Read) {
            return Err(NodeError::NotFound);
        }
        if let Some(c) = class
            && !m.may(&resource, &Capability::Command(c.as_str().to_owned()))
        {
            return Err(NodeError::NotFound);
        }
        Ok(())
    }

    /// Creates the account's resource with every class granted to this node's member.
    pub(crate) async fn add_account(&self, account: &AccountId) -> Result<(), NodeError> {
        let m = self.membership()?;
        let resource = account_resource(account.as_str()).ok_or(NodeError::Internal)?;
        m.ensure_resource(&resource, &class_names())
            .await
            .map_err(err)?;
        self.announce_later();
        Ok(())
    }

    async fn ensure_net(self: &Arc<Self>) -> Result<(Arc<dyn Link>, WireHint), NodeError> {
        let mut net = self.net.lock().await;
        if let Some(n) = net.as_ref() {
            return Ok((n.link.clone(), n.hint.clone()));
        }
        let endpoints = self
            .endpoints
            .as_ref()
            .ok_or(NodeError::ServerUnreachable)?;
        let m = self.membership()?;
        let bound = endpoints
            .bind(&m.keys().identity, m.trust())
            .await
            .map_err(|_| NodeError::ServerUnreachable)?;
        let hint = WireHint::from_peer(&bound.hint);
        let serve = sync::serve(m.clone(), bound.link.clone(), hint.clone(), SYNC_LIMIT)
            .await
            .map_err(err)?;
        let notices = rowboat_group::notice::serve(m.clone(), bound.link.clone(), SYNC_LIMIT)
            .await
            .map_err(err)?;
        if let Some(r) = self.replication.get()
            && let Err(e) = r.attach(bound.link.clone()).await
        {
            warn!(error = %e, "replication could not attach to the link");
        }
        *net = Some(Net {
            link: bound.link.clone(),
            hint: hint.clone(),
            serve,
            notices,
        });
        Ok((bound.link, hint))
    }

    /// Exchanges heads with every peer it can reach; brings the link up first when the group has
    /// other nodes. Returns how many peers answered.
    pub(crate) async fn sync_now(self: &Arc<Self>) -> usize {
        let Ok(m) = self.membership() else {
            return 0;
        };
        if m.counting_peers().is_empty() || self.endpoints.is_none() {
            return 0;
        }
        let Ok((link, hint)) = self.ensure_net().await else {
            return 0;
        };
        let results = sync::announce(&m, &link, &hint, SYNC_LIMIT).await;
        for (peer, r) in &results {
            if r.is_ok() {
                self.saw(*peer);
            }
        }
        let answered = results.iter().filter(|(_, r)| r.is_ok()).count();
        if answered == 0 && !m.is_revoked() {
            self.ask_notices(&m, &link).await;
        }
        answered
    }

    /// Every peer refused this node: asks each, on the revocation notice protocol, whether this
    /// node was revoked, and takes the first notice that verifies.
    async fn ask_notices(&self, m: &Arc<Membership>, link: &Arc<dyn Link>) {
        for peer in m.counting_peers() {
            match rowboat_group::notice::ask(m, link, &peer, SYNC_LIMIT).await {
                Ok(rowboat_group::notice::Noticed::Applied(n)) if n > 0 => {
                    if m.is_revoked() {
                        info!("a peer told this node it was revoked");
                        return;
                    }
                }
                Ok(_) => {}
                Err(e) => info!(error = %e, "a revocation notice was refused"),
            }
        }
    }

    /// The node's link, brought up when the group has other nodes.
    pub(crate) async fn link(self: &Arc<Self>) -> Option<Arc<dyn Link>> {
        if !self.link_up().await {
            return None;
        }
        self.net.lock().await.as_ref().map(|n| n.link.clone())
    }

    pub(crate) fn genesis_hash(&self) -> Result<[u8; 32], NodeError> {
        Ok(self.membership()?.genesis_hash())
    }

    pub(crate) fn is_adopted(&self) -> bool {
        self.class == NodeClass::Server
            && self
                .membership()
                .is_ok_and(|m| m.keys().member.is_none() && !m.is_revoked())
    }

    /// The class of this node's certificate, or the class it pairs as before it has one.
    pub(crate) fn certified_class(&self) -> NodeClass {
        self.membership()
            .ok()
            .and_then(|m| m.class_of(&m.node()))
            .unwrap_or(self.class)
    }

    /// A server's first-run invite: the server asks a member device to adopt it. Only a node
    /// built as a server, alone in its group, may issue one; the adoption moves it to the
    /// device's group and needs a rebuild, like joining. With `ask`, the fingerprint waits for
    /// `confirm_pairing` on this node too (a server console). A server already adopted (it holds
    /// no member key) accepts only terms of its own group, whatever happens to its peers.
    pub(crate) async fn server_invite(
        self: &Arc<Self>,
        ask: bool,
    ) -> Result<
        (
            ServerInvite,
            Adoption,
            oneshot::Sender<Result<(), NodeError>>,
        ),
        NodeError,
    > {
        let m = self.membership()?;
        if self.class != NodeClass::Server || !m.counting_peers().is_empty() {
            return Err(NodeError::Busy);
        }
        let endpoints = self
            .endpoints
            .as_ref()
            .ok_or(NodeError::ServerUnreachable)?;
        let endpoint = Arc::new(PairingEndpoint::open(&**endpoints).await.map_err(err)?);
        let issued = self
            .inviter
            .issue(
                InviteKind::Server,
                None,
                None,
                endpoint.key(),
                endpoint.hint().clone(),
            )
            .map_err(err)?;
        let id = issued.invite.id;
        let (done_tx, done_rx) = oneshot::channel();
        let (tx, rx) = oneshot::channel();
        let me = self.clone();
        let ttl = Duration::from_millis(self.limits.ttl_ms.max(0) as u64);
        let task = tokio::spawn(async move {
            let served =
                tokio::time::timeout(ttl, me.serve_adoption(id, endpoint.clone(), ask)).await;
            me.inviter.cancel(id);
            endpoint.close().await;
            let _ = tx.send(served.unwrap_or(Err(NodeError::PairingExpired)));
        });
        self.tasks.push(task);
        let invite = ServerInvite {
            qr: issued.invite.to_qr(),
            short_code: issued
                .short
                .as_ref()
                .map(|s| s.display())
                .unwrap_or_default(),
            address: issued.address.to_text(),
            expires_at: issued.invite.expires_at.0,
            adopted: done_rx,
        };
        Ok((invite, rx, done_tx))
    }

    async fn serve_adoption(
        self: &Arc<Self>,
        id: u64,
        endpoint: Arc<PairingEndpoint>,
        ask: bool,
    ) -> Result<JoinedGroup, NodeError> {
        let m = self.membership()?;
        let bound = m.keys().member.is_none().then(|| m.genesis_hash());
        let hint = self.ensure_net().await.map(|(_, h)| h).unwrap_or_default();
        while let Some(inc) = endpoint.next().await {
            let keys = m.keys();
            let candidate = Candidate {
                identity: &keys.identity,
                kem: &keys.kem,
                class: NodeClass::Server,
                label: self.own_label().await,
                hint: hint.clone(),
                bound,
                confirm: Arc::new(NodeConfirm {
                    group: self.clone(),
                    pairing: invite_name(id),
                    ask,
                }),
            };
            match self
                .inviter
                .serve(
                    inc.stream,
                    inc.peer,
                    endpoint.key(),
                    Side::Candidate(&candidate),
                )
                .await
            {
                Ok((_, Outcome::Joined(j))) => return self.adopted(*j).await,
                Ok(_) => {}
                Err(e) => info!(error = %e, "an adoption attempt failed"),
            }
            if !self.inviter.is_pending(id) {
                break;
            }
        }
        Err(NodeError::PairingCodeRejected)
    }

    async fn adopted(&self, j: pairing::Joined) -> Result<JoinedGroup, NodeError> {
        let m = self.membership()?;
        let keys = m.keys();
        let group = j.log.state().group().to_string();
        let joined_keys = NodeKeys {
            identity: keys.identity.clone(),
            kem: baton_keys::KemSecret::from_bytes(keys.kem.expose())
                .map_err(|_| NodeError::Internal)?,
            member: None,
        };
        Membership::adopt(
            self.store.clone(),
            j.log,
            joined_keys,
            j.peers,
            self.now.clone(),
        )
        .await
        .map_err(err)?;
        self.moved.store(true, Ordering::SeqCst);
        if let Some(r) = self.replication.get() {
            r.detach().await;
        }
        if let Some(n) = self.net.lock().await.take() {
            n.serve.abort();
            n.notices.abort();
            n.link.close().await;
        }
        info!("adopted by a group; restart required");
        Ok(JoinedGroup {
            group,
            member: None,
        })
    }

    /// Exchanges logs with `peer` in the background, once at a time per peer: it issued a
    /// command under a newer log than this node's.
    pub(crate) fn catch_up_with(self: &Arc<Self>, peer: PublicKey) {
        let Ok(m) = self.membership() else {
            return;
        };
        if !m.counts(&peer)
            || self.endpoints.is_none()
            || !self
                .catching_up
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(peer)
        {
            return;
        }
        let me = self.clone();
        self.tasks.spawn(async move {
            if let Ok((link, hint)) = me.ensure_net().await
                && sync::exchange_with(&m, &link, &peer, &hint, SYNC_LIMIT)
                    .await
                    .is_ok()
            {
                me.saw(peer);
            }
            me.catching_up
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&peer);
        });
    }

    fn announce_later(&self) {
        let Ok(m) = self.membership() else {
            return;
        };
        if m.counting_peers().is_empty() {
            return;
        }
        let net = self
            .net
            .try_lock()
            .ok()
            .and_then(|n| n.as_ref().map(|n| (n.link.clone(), n.hint.clone())));
        if let Some((link, hint)) = net {
            self.tasks.spawn(async move {
                let _ = sync::announce(&m, &link, &hint, SYNC_LIMIT).await;
            });
        }
    }

    /// Renews this node's certificate when it is due. Errors are logged, not returned.
    pub(crate) async fn renew(&self) {
        let Ok(m) = self.membership() else {
            return;
        };
        if m.member_key().is_err() {
            return;
        }
        match m
            .renew_if_due(self.limits.term(self.class), RENEW_WINDOW_MS)
            .await
        {
            Ok(true) => info!("node certificate renewed"),
            Ok(false) => {}
            Err(e) => warn!(error = %e, "node certificate renewal failed"),
        }
    }

    pub(crate) async fn create_invite(self: &Arc<Self>) -> Result<PairingInvite, NodeError> {
        let m = self.membership()?;
        if !m.can_certify() {
            return Err(NodeError::Forbidden);
        }
        let endpoints = self.endpoints.as_ref().ok_or(NodeError::PeerUnreachable)?;
        let endpoint = PairingEndpoint::open(&**endpoints).await.map_err(err)?;
        let issued = self
            .inviter
            .issue(
                InviteKind::Device,
                Some(m.group().clone()),
                Some(m.node()),
                endpoint.key(),
                endpoint.hint().clone(),
            )
            .map_err(err)?;
        let id = issued.invite.id;
        let endpoint = Arc::new(endpoint);
        self.invites
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, endpoint.clone());
        let me = self.clone();
        let ttl = Duration::from_millis(self.limits.ttl_ms.max(0) as u64);
        let task = tokio::spawn(async move {
            let serving = me.serve_invite(id, endpoint.clone());
            let _ = tokio::time::timeout(ttl, serving).await;
            me.inviter.cancel(id);
            me.invites
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&id);
            endpoint.close().await;
        });
        self.tasks.push(task);
        Ok(PairingInvite {
            invite: invite_name(id),
            qr: issued.invite.to_qr(),
            short_code: issued.short.as_ref().map(|s| s.display()),
            address: issued.short.as_ref().map(|_| issued.address.to_text()),
            expires_at: issued.invite.expires_at.0,
        })
    }

    async fn serve_invite(self: &Arc<Self>, id: u64, endpoint: Arc<PairingEndpoint>) {
        let mut streams = tokio::task::JoinSet::new();
        loop {
            let next = tokio::select! {
                inc = endpoint.next() => inc,
                Some(_) = streams.join_next(), if !streams.is_empty() => {
                    if self.inviter.is_pending(id) {
                        continue;
                    }
                    break;
                }
            };
            let Some(inc) = next else {
                break;
            };
            if streams.len() >= PAIR_STREAMS {
                continue;
            }
            let me = self.clone();
            let key = endpoint.key();
            streams.spawn(async move { me.serve_one(id, inc, key).await });
        }
        while streams.join_next().await.is_some() {}
    }

    async fn serve_one(self: &Arc<Self>, id: u64, inc: baton_link::Incoming, key: PublicKey) {
        let Ok(m) = self.membership() else {
            return;
        };
        let hint = self.ensure_net().await.map(|(_, h)| h).unwrap_or_default();
        let certifier = Certifier {
            membership: m,
            confirm: Arc::new(NodeConfirm {
                group: self.clone(),
                pairing: invite_name(id),
                ask: true,
            }),
            hint,
            server_grants: Vec::new(),
        };
        match self
            .inviter
            .serve(inc.stream, inc.peer, key, Side::Certifier(&certifier))
            .await
        {
            Ok((_, Outcome::Certified(c))) => {
                info!(class = class_name(c.class), "a node joined the group");
                self.saw(c.node);
                self.after_certified().await;
            }
            Ok(_) => {}
            Err(e) => info!(error = %e, "a pairing attempt failed"),
        }
    }

    async fn after_certified(self: &Arc<Self>) {
        let _ = self.hub.send(GroupEvent::NodesChanged);
        let me = self.clone();
        self.tasks.spawn(async move {
            me.sync_now().await;
        });
    }

    pub(crate) fn cancel_invite(&self, invite: &str) -> Result<(), NodeError> {
        let id = u64::from_str_radix(invite, 16).map_err(|_| NodeError::InvalidInput)?;
        if !self.inviter.is_pending(id) {
            return Err(NodeError::NotFound);
        }
        self.inviter.cancel(id);
        let endpoint = self
            .invites
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id);
        if let Some(e) = endpoint {
            self.tasks.spawn(async move { e.close().await });
        }
        Ok(())
    }

    pub(crate) fn confirm(&self, pairing: &str, matches: bool) -> Result<(), NodeError> {
        let tx = self
            .confirms
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(pairing)
            .ok_or(NodeError::NotFound)?;
        let _ = tx.send(matches);
        Ok(())
    }

    /// What `code` is, without dialing: its kind and expiry. A QR invite past its expiry is
    /// [`NodeError::PairingExpired`].
    pub(crate) fn inspect(
        &self,
        code: &str,
        address: Option<&str>,
    ) -> Result<rowboat_api::InviteInfo, NodeError> {
        let code = parse_code(code, address)?;
        self.inspected(&code)
    }

    fn inspected(&self, code: &PairingCode) -> Result<rowboat_api::InviteInfo, NodeError> {
        let expires_at = match code {
            PairingCode::Qr(i) => Some(i.expires_at.0),
            PairingCode::Short { .. } => None,
        };
        if expires_at.is_some_and(|e| e < (self.now)().0) {
            return Err(NodeError::PairingExpired);
        }
        Ok(rowboat_api::InviteInfo {
            kind: match code.kind() {
                InviteKind::Device => rowboat_api::InviteKind::Device,
                InviteKind::Server => rowboat_api::InviteKind::Server,
            },
            expires_at,
        })
    }

    /// Pairs with `code`. For a device invite the node must be alone and empty (`may_join`);
    /// the joined log is stored, and the caller rewrites the node record and keys from the
    /// returned [`JoinedGroup`]. For a server invite, `grants` names the accounts the server may
    /// lead (`None`: every account this member created); a device invite with `grants` is
    /// refused before anything is dialed.
    pub(crate) async fn accept(
        self: &Arc<Self>,
        code: &str,
        address: Option<&str>,
        may_join: bool,
        grants: Option<&[AccountId]>,
    ) -> Result<(PairingResult, Option<JoinedGroup>), NodeError> {
        let m = self.membership()?;
        let code = parse_code(code, address)?;
        self.inspected(&code)?;
        if grants.is_some() && code.kind() != InviteKind::Server {
            return Err(NodeError::InvalidInput);
        }
        let endpoints = self.endpoints.clone().ok_or(NodeError::PeerUnreachable)?;
        let pairing = match &code {
            PairingCode::Qr(i) => invite_name(i.id),
            PairingCode::Short { code, .. } => format!("{:016x}", code.id()),
        };
        match code.kind() {
            InviteKind::Server => {
                if !m.can_certify() {
                    return Err(NodeError::Forbidden);
                }
                let server_grants = match grants {
                    None => server_grants(&m),
                    Some(accounts) => chosen_grants(&m, accounts)?,
                };
                let hint = self.ensure_net().await.map(|(_, h)| h).unwrap_or_default();
                let certifier = Certifier {
                    membership: m.clone(),
                    confirm: Arc::new(NodeConfirm {
                        group: self.clone(),
                        pairing,
                        ask: true,
                    }),
                    hint,
                    server_grants,
                };
                let outcome = pairing::join(
                    &*endpoints,
                    &code,
                    Side::Certifier(&certifier),
                    &self.limits,
                )
                .await
                .map_err(err)?;
                let Outcome::Certified(c) = outcome else {
                    return Err(NodeError::Internal);
                };
                self.saw(c.node);
                self.after_certified().await;
                Ok((
                    PairingResult {
                        node_id: c.node.node_id().to_string(),
                        group_id: m.group().to_string(),
                        restart_required: false,
                    },
                    None,
                ))
            }
            InviteKind::Device => {
                if !may_join || !m.counting_peers().is_empty() {
                    return Err(NodeError::Busy);
                }
                let keys = m.keys();
                let candidate = Candidate {
                    identity: &keys.identity,
                    kem: &keys.kem,
                    class: self.class,
                    label: self.own_label().await,
                    hint: WireHint::default(),
                    bound: None,
                    confirm: Arc::new(NodeConfirm {
                        group: self.clone(),
                        pairing,
                        ask: false,
                    }),
                };
                let outcome = pairing::join(
                    &*endpoints,
                    &code,
                    Side::Candidate(&candidate),
                    &self.limits,
                )
                .await
                .map_err(err)?;
                let Outcome::Joined(j) = outcome else {
                    return Err(NodeError::Internal);
                };
                let j = *j;
                let group = j.log.state().group().to_string();
                let joined_keys = NodeKeys {
                    identity: keys.identity.clone(),
                    kem: baton_keys::KemSecret::from_bytes(keys.kem.expose())
                        .map_err(|_| NodeError::Internal)?,
                    member: j.member.clone(),
                };
                Membership::adopt(
                    self.store.clone(),
                    j.log,
                    joined_keys,
                    j.peers,
                    self.now.clone(),
                )
                .await
                .map_err(err)?;
                self.moved.store(true, Ordering::SeqCst);
                if let Some(r) = self.replication.get() {
                    r.detach().await;
                }
                if let Some(n) = self.net.lock().await.take() {
                    n.serve.abort();
                    n.notices.abort();
                    n.link.close().await;
                }
                info!("joined another group; restart required");
                Ok((
                    PairingResult {
                        node_id: j.certifier.node_id().to_string(),
                        group_id: group.clone(),
                        restart_required: true,
                    },
                    Some(JoinedGroup {
                        group,
                        member: j.member,
                    }),
                ))
            }
        }
    }

    /// Grants `server` lead on `accounts` it may not lead yet.
    pub(crate) async fn grant_to_server(
        self: &Arc<Self>,
        server: &str,
        accounts: &[AccountId],
    ) -> Result<(), NodeError> {
        let m = self.membership()?;
        if !m.can_certify() {
            return Err(NodeError::Forbidden);
        }
        let key = node_key(server).ok_or(NodeError::NotFound)?;
        let member = m.member_key().map_err(err)?.public();
        let is_my_server = m.with_log(|log| {
            log.state()
                .node(&key, m.now())
                .is_some_and(|c| c.class == NodeClass::Server && c.member == member)
        });
        if !is_my_server {
            return Err(NodeError::NotFound);
        }
        let wanted: Vec<_> = chosen_grants(&m, accounts)?
            .into_iter()
            .filter(|r| !m.node_may(&key, r, &Capability::Lead))
            .collect();
        if wanted.is_empty() {
            return Ok(());
        }
        m.grant_server(&key, &wanted).await.map_err(|e| match e {
            MembershipError::Invalid => NodeError::NotFound,
            e => err(e),
        })?;
        info!(accounts = wanted.len(), "accounts granted to a server");
        let _ = self.hub.send(GroupEvent::NodesChanged);
        let me = self.clone();
        self.tasks.spawn(async move {
            me.sync_now().await;
        });
        Ok(())
    }

    /// The label this node gives in pairings: the name the person gave it here, else the one
    /// it was built with.
    async fn own_label(&self) -> String {
        match self.membership() {
            Ok(m) => self
                .name_of(&m.node())
                .await
                .unwrap_or_else(|| self.label.clone()),
            Err(_) => self.label.clone(),
        }
    }

    async fn name_of(&self, node: &PublicKey) -> Option<String> {
        let m = self.membership().ok()?;
        let (bytes, _) = self
            .store
            .get(m.group(), &name_record(node))
            .await
            .ok()
            .flatten()?;
        String::from_utf8(bytes.to_vec())
            .ok()
            .map(|l| clean_label(&l))
            .filter(|l| !l.trim().is_empty())
    }

    /// Names `node` on this node, or forgets the name with `None`.
    pub(crate) async fn rename(&self, node_id: &str, label: Option<&str>) -> Result<(), NodeError> {
        let m = self.membership()?;
        let key = node_key(node_id)
            .filter(|k| m.was_certified(k))
            .ok_or(NodeError::NotFound)?;
        let record = name_record(&key);
        match label {
            Some(l) => {
                rowboat_api::group::node_label(l)?;
                self.store
                    .put(
                        m.group(),
                        &record,
                        bytes::Bytes::from(clean_label(l).into_bytes()),
                        baton_state::Expect::Any,
                    )
                    .await
                    .map_err(|_| NodeError::Storage)?;
            }
            None => self
                .store
                .delete(m.group(), &record, baton_state::Expect::Any)
                .await
                .map_err(|_| NodeError::Storage)?,
        }
        let _ = self.hub.send(GroupEvent::NodesChanged);
        Ok(())
    }

    /// Notes that `node` answered this node just now.
    pub(crate) fn saw(&self, node: PublicKey) {
        self.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(node, (self.now)().0);
    }

    pub(crate) async fn list(&self) -> Result<Vec<NodeSummary>, NodeError> {
        let m = self.membership()?;
        let me = m.node();
        let now = (self.now)().0;
        let accounts: Vec<_> = m
            .resources()
            .into_iter()
            .filter_map(|r| {
                let id = AccountId::new(r.as_str().strip_prefix("acct-")?).ok()?;
                Some((r, id))
            })
            .collect();
        let seen = self.seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let mut out = Vec::new();
        for n in m.nodes() {
            let label = match self.name_of(&n.node).await {
                Some(name) => Some(name),
                None if n.node == me => Some(self.label.clone()),
                None => n.label,
            };
            let may_lead = if n.counts {
                accounts
                    .iter()
                    .filter(|(r, _)| m.node_may(&n.node, r, &Capability::Lead))
                    .map(|(_, a)| a.clone())
                    .collect()
            } else {
                Vec::new()
            };
            out.push(NodeSummary {
                node_id: n.node.node_id().to_string(),
                class: class_name(n.class).into(),
                label,
                this_node: n.node == me,
                counts: n.counts,
                revoked: n.revoked,
                expires_at: n.expires.0,
                last_seen: if n.node == me {
                    Some(now)
                } else {
                    seen.get(&n.node).copied()
                },
                may_lead,
            });
        }
        out.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        Ok(out)
    }

    pub(crate) async fn revoke(self: &Arc<Self>, node_id: &str) -> Result<Revoked, NodeError> {
        let m = self.membership()?;
        if node_id == m.node().node_id().as_str() {
            return Err(NodeError::InvalidInput);
        }
        let key = node_key(node_id)
            .filter(|k| m.was_certified(k))
            .ok_or(NodeError::NotFound)?;
        let r = m.revoke(&key).await.map_err(err)?;
        if let Some(n) = self.net.lock().await.as_ref() {
            let _ = n.link.disconnect_untrusted().await;
        }
        let _ = self.hub.send(GroupEvent::NodesChanged);
        let me = self.clone();
        self.tasks.spawn(async move {
            me.sync_now().await;
        });
        let accounts = r
            .secrets_rotation_required
            .iter()
            .filter_map(|res| res.as_str().strip_prefix("acct-"))
            .filter_map(|a| AccountId::new(a).ok())
            .collect();
        info!("node revoked");
        Ok(Revoked {
            secrets_rotation_required: accounts,
        })
    }

    pub(crate) async fn shutdown(&self) {
        self.tasks.stop().await;
        let endpoints: Vec<_> =
            std::mem::take(&mut *self.invites.lock().unwrap_or_else(|e| e.into_inner()))
                .into_values()
                .collect();
        for e in endpoints {
            e.close().await;
        }
        if let Some(r) = self.replication.get() {
            r.detach().await;
        }
        if let Some(n) = self.net.lock().await.take() {
            n.serve.abort();
            n.notices.abort();
            n.link.close().await;
        }
    }
}

fn parse_code(code: &str, address: Option<&str>) -> Result<PairingCode, NodeError> {
    rowboat_api::group::pairing_text(code)?;
    if let Some(a) = address {
        rowboat_api::group::pairing_text(a)?;
    }
    if code.trim().len() > 12 || code.contains(':') {
        let invite = Invite::from_qr(code).map_err(|_| NodeError::InvalidInput)?;
        return Ok(PairingCode::Qr(Box::new(invite)));
    }
    let short = ShortCode::parse(code).map_err(|_| NodeError::InvalidInput)?;
    let address = PairAddress::parse(address.ok_or(NodeError::InvalidInput)?)
        .map_err(|_| NodeError::InvalidInput)?;
    Ok(PairingCode::Short {
        code: short,
        address,
    })
}

fn node_key(node_id: &str) -> Option<PublicKey> {
    baton_core::NodeId::new(node_id)
        .ok()
        .and_then(|id| PublicKey::from_node_id(&id).ok())
}

/// The resources of `accounts`, each created by this node's member, plus the group's storage
/// when this member created it; [`NodeError::NotFound`] for any other account.
fn chosen_grants(
    m: &Membership,
    accounts: &[AccountId],
) -> Result<Vec<baton_core::ResourceId>, NodeError> {
    if accounts.len() > rowboat_api::group::MAX_GRANTS {
        return Err(NodeError::InvalidInput);
    }
    let mine = server_grants(m);
    let mut out: Vec<baton_core::ResourceId> = Vec::new();
    for a in accounts {
        let r = account_resource(a.as_str()).ok_or(NodeError::NotFound)?;
        if !mine.contains(&r) {
            return Err(NodeError::NotFound);
        }
        if !out.contains(&r) {
            out.push(r);
        }
    }
    out.extend(mine.into_iter().filter(|r| r.as_str() == "storage"));
    Ok(out)
}

fn server_grants(m: &Membership) -> Vec<baton_core::ResourceId> {
    let member = m.member_key().map(|k| k.public()).ok();
    m.with_log(|log| {
        let state = log.state();
        m.resources()
            .into_iter()
            .filter(|r| r.as_str().starts_with("acct-") || r.as_str() == "storage")
            .filter(|r| {
                state
                    .resource(r)
                    .is_some_and(|s| Some(*s.creator()) == member)
            })
            .collect()
    })
}
