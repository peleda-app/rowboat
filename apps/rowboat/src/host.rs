//! The tenants of one host: building each tenant's node, adopting a tenant by a server invite,
//! binding it, and running every bound tenant under `serve`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use baton_lease::NodeClass;
use futures::StreamExt;
use rinse_mail::Content;
use rowboat_api::GroupEvent;
use rowboat_endpoint::Endpoints;
use rowboat_keystore::Keystore;
use rowboat_keystore_file::FileKeystore;
use rowboat_node::{BuildError, Node, Profile, Providers, Push};
use serde::{Deserialize, Serialize};
use skein_storage::Objects;
use skein_storage_fs::{FsObjects, OpenError};
use tracing::{info, warn};

use crate::endpoints::{LinkSettings, TenantEndpoints};
use crate::tenant::{Binding, Layout, RECORD_VERSION, TenantError, TenantId, TenantRecord};

/// How tenants reach the network.
#[derive(Clone)]
pub enum Net {
    /// Iroh endpoints per tenant ([`TenantEndpoints`]).
    Iroh(Arc<LinkSettings>),
    /// One factory for every tenant (tests: `rowboat-endpoint-memory`).
    Given(Arc<dyn Endpoints>),
}

/// Opens the object store of a tenant kept outside the data directory (an S3 prefix).
pub type StoreFactory = Arc<dyn Fn(&TenantId) -> Result<Arc<dyn Objects>, String> + Send + Sync>;

/// Everything a tenant's node is composed from besides its directories.
#[derive(Clone)]
pub struct Deps {
    /// The node profile: [`Profile::Server`], or the test profile in tests.
    pub profile: Profile,
    /// Provider factories; IMAP and SMTP when `None`.
    pub providers: Option<Providers>,
    /// The content pipeline.
    pub content: Arc<dyn Content>,
    /// The network.
    pub net: Net,
    /// Tenants' object stores outside the data directory.
    pub store: Option<StoreFactory>,
    /// Extra roots for the mail providers (feature `test-roots`).
    pub roots: Option<skein_core::TlsRoots>,
}

/// What an invite shows the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shown {
    /// The invite: the QR payload, the short code, the pairing address the code is typed with,
    /// the tenant and its node id, and when it expires.
    Invite {
        /// The tenant.
        tenant: TenantId,
        /// The QR payload.
        qr: String,
        /// The short code.
        short_code: String,
        /// The pairing address.
        address: String,
        /// The tenant's node id.
        node: String,
        /// Milliseconds since the epoch.
        expires_at: i64,
    },
    /// A device answered: the fingerprint both screens show.
    Fingerprint {
        /// Six digits.
        fingerprint: String,
        /// The device's node id.
        device: String,
    },
    /// The tenant is bound.
    Bound(Binding),
}

/// How an adoption is confirmed on the server's side.
#[derive(Clone)]
pub enum Confirm {
    /// The person confirms in the app only (`--yes`); the fingerprint is shown.
    App,
    /// The operator confirms too: called with the fingerprint, blocking, `true` to accept.
    Console(Arc<dyn Fn(&str) -> bool + Send + Sync>),
}

/// Shows what an invite produces.
pub type Show = Arc<dyn Fn(Shown) + Send + Sync>;

/// The tenants of a host, as the CLI and `serve` see them.
#[derive(Clone)]
pub struct Tenants {
    /// Where things live.
    pub layout: Layout,
    /// What nodes are composed from.
    pub deps: Deps,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// A tenant's node directory, held so nothing else opens it.
pub struct Hold(#[allow(dead_code)] FsObjects);

impl Tenants {
    /// Takes the tenant's directory lock: `Busy` while a node runs over it. With `stop`, a
    /// running `serve` is asked to stop the tenant (the stop marker) and the lock is waited for
    /// up to `wait`; the marker stays until [`Tenants::release`].
    pub async fn hold(
        &self,
        id: &TenantId,
        stop: bool,
        wait: Duration,
    ) -> Result<Hold, TenantError> {
        let dir = self.layout.node(id).join("objects");
        crate::tenant::private_dir(&dir).map_err(|_| TenantError::Io(id.to_string()))?;
        let deadline = tokio::time::Instant::now() + wait;
        let mut marked = false;
        loop {
            match FsObjects::open(&dir) {
                Ok(f) => return Ok(Hold(f)),
                Err(OpenError::Io(_)) => return Err(TenantError::Io(id.to_string())),
                Err(OpenError::Locked { .. }) => {}
            }
            if !stop || tokio::time::Instant::now() >= deadline {
                return Err(TenantError::Busy(id.to_string()));
            }
            if !marked {
                crate::tenant::write_atomic(&self.layout.stop_marker(id), b"")
                    .map_err(|_| TenantError::Io(id.to_string()))?;
                marked = true;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Removes the stop marker.
    pub fn release(&self, id: &TenantId) {
        let _ = std::fs::remove_file(self.layout.stop_marker(id));
    }

    /// Builds (does not start) the node of `record`: its keys from the secrets directory, its
    /// data directory, its mail database in a cleared cache directory.
    pub async fn open_node(
        &self,
        record: &TenantRecord,
        signal: Option<Arc<dyn baton_signal::Signal>>,
        push: Option<Push>,
    ) -> Result<Node, TenantError> {
        let id = &record.id;
        let io = |_| TenantError::Io(id.to_string());
        let view = self.layout.view(id);
        match std::fs::remove_dir_all(&view) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(io(e)),
            _ => {}
        }
        crate::tenant::private_dir(&view).map_err(io)?;
        let keystore: Arc<dyn Keystore> = Arc::new(
            FileKeystore::open(self.layout.keys(id))
                .map_err(|_| TenantError::Io(id.to_string()))?,
        );
        let (endpoints, tenant_endpoints): (Arc<dyn Endpoints>, Option<Arc<TenantEndpoints>>) =
            match &self.deps.net {
                Net::Given(e) => (e.clone(), None),
                Net::Iroh(settings) => {
                    let e = Arc::new(TenantEndpoints::new(
                        settings.clone(),
                        record.port,
                        self.layout.reserved_ports(),
                    ));
                    (e.clone(), Some(e))
                }
            };
        let mut builder = Node::builder()
            .profile(self.deps.profile)
            .data_dir(self.layout.node(id))
            .view_dir(view)
            .keystore(keystore)
            .content(self.deps.content.clone())
            .class(NodeClass::Server)
            .endpoints(endpoints);
        if let Some(p) = &self.deps.providers {
            builder = builder.providers(p.clone());
        }
        if let Some(s) = signal {
            builder = builder.signal(s);
        }
        if let Some(p) = push {
            builder = builder.push(p);
        }
        if let Some(f) = &self.deps.store {
            builder = builder.store(f(id).map_err(|e| TenantError::Node(id.to_string(), e))?);
        }
        #[cfg(feature = "test-roots")]
        if let Some(r) = &self.deps.roots {
            builder = builder.test_roots(r.clone());
        }
        let node = builder.build().await.map_err(|e| match e {
            BuildError::Locked => TenantError::Busy(id.to_string()),
            BuildError::KeysLost | BuildError::NotEmpty => TenantError::Mismatch(id.to_string()),
            other => TenantError::Node(id.to_string(), other.to_string()),
        })?;
        if let Some(e) = tenant_endpoints {
            e.set_node(node.node_id());
        }
        Ok(node)
    }

    /// Checks `node` against the tenant's binding: a bound tenant's node must be adopted into
    /// exactly the bound group, with the bound genesis and node id. An adopted node without a
    /// binding (a crash after the adoption) gets its binding written now. Returns the binding,
    /// `None` for an unbound tenant.
    pub fn check_binding(
        &self,
        id: &TenantId,
        node: &Node,
    ) -> Result<Option<Binding>, TenantError> {
        let genesis = node
            .genesis_hash()
            .map_err(|e| TenantError::Node(id.to_string(), e.to_string()))?;
        match self.layout.binding(id)? {
            Some(b) => {
                let matches = node.adopted()
                    && b.group == node.group_id()
                    && b.node == node.node_id()
                    && b.genesis_bytes() == Some(genesis);
                if matches {
                    Ok(Some(b))
                } else {
                    Err(TenantError::Mismatch(id.to_string()))
                }
            }
            None if node.adopted() => {
                let b = binding_of(id, node, genesis);
                self.layout.write_binding(&b)?;
                info!(tenant = %id, group = %b.group, "tenant binding restored from its node");
                Ok(Some(b))
            }
            None => Ok(None),
        }
    }

    /// Issues a server invite for a new tenant (`None`) or an unbound one, shows it, waits for a
    /// member device to adopt it (until the invite expires), then binds the tenant to the
    /// device's group. A bound tenant is refused unless `rebind`, which deletes the tenant's data
    /// and keys first (logged as an operator action). Returns the bound node, rebuilt and not
    /// started, with its binding.
    pub async fn adopt(
        &self,
        tenant: Option<TenantId>,
        rebind: bool,
        confirm: Confirm,
        show: Show,
        signal: Option<Arc<dyn baton_signal::Signal>>,
        push: Option<Push>,
    ) -> Result<(Node, Binding), TenantError> {
        let record = match &tenant {
            None => self.layout.create(None, now_ms())?,
            Some(id) => self.layout.record(id)?,
        };
        let id = record.id.clone();
        let result = self
            .adopt_inner(&record, rebind, confirm, show, signal, push)
            .await;
        if rebind {
            self.release(&id);
        }
        result
    }

    async fn adopt_inner(
        &self,
        record: &TenantRecord,
        rebind: bool,
        confirm: Confirm,
        show: Show,
        signal: Option<Arc<dyn baton_signal::Signal>>,
        push: Option<Push>,
    ) -> Result<(Node, Binding), TenantError> {
        let id = &record.id;
        if rebind {
            let hold = self.hold(id, true, Duration::from_secs(120)).await?;
            warn!(tenant = %id, "operator rebind: the tenant's binding is released and its data deleted");
            self.wipe(id, false).await?;
            drop(hold);
        } else if self.layout.binding(id)?.is_some() {
            return Err(TenantError::Bound(id.to_string()));
        }
        let node = self.open_node(record, signal.clone(), push.clone()).await?;
        if self.check_binding(id, &node)?.is_some() {
            node.shutdown().await;
            return Err(TenantError::Bound(id.to_string()));
        }
        node.start().await;
        let asking = matches!(confirm, Confirm::Console(_));
        let invite = if asking {
            node.server_invite_confirmed().await
        } else {
            node.server_invite().await
        };
        let invite = match invite {
            Ok(i) => i,
            Err(e) => {
                node.shutdown().await;
                return Err(TenantError::Node(id.to_string(), e.to_string()));
            }
        };
        show(Shown::Invite {
            tenant: id.clone(),
            qr: invite.qr.clone(),
            short_code: invite.short_code.clone(),
            address: invite.address.clone(),
            node: node.node_id().to_owned(),
            expires_at: invite.expires_at,
        });
        let api = node.api();
        let mut events = api.group_events();
        let watcher = {
            let show = show.clone();
            let api = api.clone();
            tokio::spawn(async move {
                while let Some(e) = events.next().await {
                    let GroupEvent::PairingCheck {
                        pairing,
                        fingerprint,
                        node,
                        confirm: ask,
                        ..
                    } = e
                    else {
                        continue;
                    };
                    show(Shown::Fingerprint {
                        fingerprint: fingerprint.clone(),
                        device: node,
                    });
                    if ask && let Confirm::Console(f) = &confirm {
                        let f = f.clone();
                        let yes = tokio::task::spawn_blocking(move || f(&fingerprint))
                            .await
                            .unwrap_or(false);
                        let _ = api.confirm_pairing(&pairing, yes).await;
                    }
                }
            })
        };
        let adopted = invite.adopted.await;
        watcher.abort();
        node.shutdown().await;
        drop(api);
        drop(node);
        if !matches!(adopted, Ok(Ok(()))) {
            return Err(TenantError::NotAdopted);
        }
        let node = self.open_node(record, signal, push).await?;
        let genesis = match node.genesis_hash() {
            Ok(g) if node.adopted() => g,
            _ => {
                node.shutdown().await;
                return Err(TenantError::NotAdopted);
            }
        };
        let binding = binding_of(id, &node, genesis);
        if let Err(e) = self.layout.write_binding(&binding) {
            node.shutdown().await;
            return Err(e);
        }
        info!(tenant = %id, group = %binding.group, node = %binding.node, "tenant adopted and bound");
        show(Shown::Bound(binding.clone()));
        Ok((node, binding))
    }

    /// Deletes the tenant's objects in its store outside the data directory (an S3 prefix), when
    /// it has one, then its local data and keys ([`Layout::wipe`]). The store goes first: a
    /// failure there leaves the keys, so the tenant still opens.
    async fn wipe(&self, id: &TenantId, all: bool) -> Result<(), TenantError> {
        if let Some(f) = &self.deps.store {
            let objects = f(id).map_err(|e| TenantError::Node(id.to_string(), e))?;
            let failed = |e: skein_storage::StorageError| {
                TenantError::Node(id.to_string(), format!("deleting the stored objects: {e}"))
            };
            for root in ["system", "tenants"] {
                let prefix = skein_storage::ObjectKey::root(root).expect("constant");
                let mut removed = 0u64;
                loop {
                    let page = objects.list(&prefix, None, 1000).await.map_err(failed)?;
                    for key in &page {
                        objects
                            .delete(key, skein_storage::Expect::Any)
                            .await
                            .map_err(failed)?;
                    }
                    removed += page.len() as u64;
                    if page.len() < 1000 {
                        break;
                    }
                }
                info!(tenant = %id, root, removed, "stored objects deleted");
            }
        }
        self.layout.wipe(id, all)
    }

    /// Deletes a tenant and everything of it, stopping it first in a running `serve`.
    pub async fn remove(&self, id: &TenantId, wait: Duration) -> Result<(), TenantError> {
        self.layout.record(id)?;
        let hold = self.hold(id, true, wait).await;
        let hold = match hold {
            Ok(h) => h,
            Err(e) => {
                self.release(id);
                return Err(e);
            }
        };
        warn!(tenant = %id, "operator removed the tenant and its data");
        let r = self.wipe(id, true).await;
        drop(hold);
        r
    }

    /// Every tenant with its binding state, for `rowboat tenants`.
    pub fn list(&self) -> Vec<TenantRow> {
        self.layout
            .ids()
            .into_iter()
            .map(|id| {
                let record = self.layout.record(&id).ok();
                let binding = self.layout.binding(&id);
                TenantRow {
                    state: match (&record, &binding) {
                        (None, _) | (_, Err(_)) => "damaged",
                        (_, Ok(Some(_))) if self.layout.stop_marker(&id).exists() => "stopping",
                        (_, Ok(Some(_))) => "bound",
                        (_, Ok(None)) => "unbound",
                    }
                    .into(),
                    group: binding
                        .as_ref()
                        .ok()
                        .and_then(|b| b.as_ref())
                        .map(|b| b.group.clone()),
                    node: binding.ok().flatten().map(|b| b.node),
                    port: record.map(|r| r.port),
                    id,
                }
            })
            .collect()
    }
}

fn binding_of(id: &TenantId, node: &Node, genesis: [u8; 32]) -> Binding {
    Binding {
        v: RECORD_VERSION,
        tenant: id.clone(),
        group: node.group_id().to_owned(),
        genesis: data_encoding::HEXLOWER.encode(&genesis),
        node: node.node_id().to_owned(),
        bound_ms: now_ms(),
    }
}

/// One line of `rowboat tenants`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantRow {
    /// The tenant.
    pub id: TenantId,
    /// `bound`, `unbound`, `stopping` or `damaged`.
    pub state: String,
    /// The bound group.
    pub group: Option<String>,
    /// The tenant's node id in it.
    pub node: Option<String>,
    /// Its link port.
    pub port: Option<u16>,
}

/// What `serve` writes to the status file every round: ids and counts only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    /// 1.
    pub v: u32,
    /// When it was written, milliseconds since the epoch.
    pub updated_ms: i64,
    /// The serving process.
    pub pid: u32,
    /// Every tenant.
    pub tenants: Vec<TenantStatus>,
}

/// One tenant in [`Status`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantStatus {
    /// The tenant.
    pub id: String,
    /// `running`, `unbound`, `stopped` (stop marker) or `failed`.
    pub state: String,
    /// The group.
    pub group: Option<String>,
    /// The node id.
    pub node: Option<String>,
    /// Accounts the node may read.
    pub accounts: usize,
    /// Accounts it leads now.
    pub leading: usize,
    /// Other nodes of the group that count.
    pub peers: usize,
}

/// Why the host could not run.
#[derive(Debug, thiserror::Error)]
pub enum HostError {
    /// Another `serve` holds the host.
    #[error("another rowboat serve runs over this data directory")]
    Busy,
    /// The host directory could not be used.
    #[error("the host directory is not usable")]
    Io,
}

/// The tenants `serve` runs.
pub struct Host {
    tenants: Tenants,
    signal: Arc<dyn baton_signal::Signal>,
    registry: Arc<FsObjects>,
    push: Option<(String, Option<String>)>,
    handback: Duration,
    running: tokio::sync::Mutex<BTreeMap<TenantId, Arc<Node>>>,
    failed: Mutex<BTreeSet<TenantId>>,
}

impl Host {
    /// Takes the host (`<data_dir>/host`, exclusively): one `serve` per data directory.
    /// `push` is the public address and Gmail topic when provider push is on.
    pub fn open(
        tenants: Tenants,
        push: Option<(String, Option<String>)>,
        handback: Duration,
    ) -> Result<Self, HostError> {
        let dir = tenants.layout.host().join("objects");
        crate::tenant::private_dir(&dir).map_err(|_| HostError::Io)?;
        let registry = Arc::new(FsObjects::open(&dir).map_err(|e| match e {
            OpenError::Locked { .. } => HostError::Busy,
            OpenError::Io(_) => HostError::Io,
        })?);
        Ok(Self {
            tenants,
            signal: Arc::new(baton_signal_local::LocalSignal::new()),
            registry,
            push,
            handback,
            running: tokio::sync::Mutex::new(BTreeMap::new()),
            failed: Mutex::default(),
        })
    }

    /// The tenants.
    pub fn tenants(&self) -> &Tenants {
        &self.tenants
    }

    /// The signal bus every tenant's node shares (the push receivers publish into it).
    pub fn signal(&self) -> Arc<dyn baton_signal::Signal> {
        self.signal.clone()
    }

    /// The push registry the listener's receivers read.
    pub fn push_registry(&self) -> skein_push::PushRegistry {
        let objects: Arc<dyn Objects> = self.registry.clone();
        let control = skein_storage::Storage::over(objects.clone()).control;
        skein_push::PushRegistry::new(objects, control)
    }

    fn push(&self) -> Option<Push> {
        self.push.as_ref().map(|(url, topic)| Push {
            registry: self.registry.clone(),
            public_url: url.clone(),
            gmail_topic: topic.clone(),
        })
    }

    /// The running node of a tenant.
    pub async fn node(&self, id: &TenantId) -> Option<Arc<Node>> {
        self.running.lock().await.get(id).cloned()
    }

    /// The ids of the running tenants.
    pub async fn running(&self) -> Vec<TenantId> {
        self.running.lock().await.keys().cloned().collect()
    }

    /// Creates a tenant and adopts it here, then runs it: the first run of an empty host.
    pub async fn first_run(&self, confirm: Confirm, show: Show) -> Result<TenantId, TenantError> {
        let (node, binding) = self
            .tenants
            .adopt(
                None,
                false,
                confirm,
                show,
                Some(self.signal.clone()),
                self.push(),
            )
            .await?;
        node.start().await;
        self.running
            .lock()
            .await
            .insert(binding.tenant.clone(), Arc::new(node));
        Ok(binding.tenant)
    }

    /// One round: stops tenants asked to stop (or deleted), starts bound tenants that do not
    /// run, and writes the status file. A tenant whose node fails to open (in use by the CLI,
    /// damaged, not matching its binding) is skipped and logged once.
    pub async fn rescan(&self) {
        let layout = &self.tenants.layout;
        let ids: BTreeSet<TenantId> = layout.ids().into_iter().collect();
        let running: Vec<TenantId> = self.running().await;
        for id in running {
            if !ids.contains(&id) || layout.stop_marker(&id).exists() {
                self.stop_tenant(&id).await;
            }
        }
        for id in &ids {
            if layout.stop_marker(id).exists() || self.running.lock().await.contains_key(id) {
                continue;
            }
            if !matches!(layout.binding(id), Ok(Some(_))) {
                continue;
            }
            match self.start_tenant(id).await {
                Ok(()) => {
                    self.failed
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(id);
                }
                Err(e) => {
                    if self
                        .failed
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(id.clone())
                    {
                        warn!(tenant = %id, error = %e, "tenant not started");
                    }
                }
            }
        }
        self.write_status().await;
    }

    async fn start_tenant(&self, id: &TenantId) -> Result<(), TenantError> {
        let record = self.tenants.layout.record(id)?;
        let node = self
            .tenants
            .open_node(&record, Some(self.signal.clone()), self.push())
            .await?;
        match self.tenants.check_binding(id, &node) {
            Ok(Some(b)) => {
                node.start().await;
                info!(tenant = %id, group = %b.group, node = %b.node, "tenant started");
                self.running.lock().await.insert(id.clone(), Arc::new(node));
                Ok(())
            }
            Ok(None) => {
                node.shutdown().await;
                Ok(())
            }
            Err(e) => {
                node.shutdown().await;
                Err(e)
            }
        }
    }

    async fn stop_tenant(&self, id: &TenantId) {
        let Some(node) = self.running.lock().await.remove(id) else {
            return;
        };
        if hand_back(&node, self.handback).await {
            node.announce_leaving().await;
        }
        node.shutdown().await;
        drop(node);
        self.clear_view(id);
        info!(tenant = %id, "tenant stopped");
    }

    /// Deletes a stopped tenant's mail database, which holds mail in the clear.
    fn clear_view(&self, id: &TenantId) {
        let view = self.tenants.layout.view(id);
        if let Err(e) = std::fs::remove_dir_all(&view)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            warn!(tenant = %id, error = %e, "the mail database could not be deleted");
        }
    }

    /// Stops every tenant: each hands its accounts back (see [`hand_back`]), tells its group's
    /// devices it is leaving once every account it led was taken over (they take over under a
    /// fallback arbiter at once instead of after the takeover delay; after an unfinished
    /// hand-back they fall back by silence, presuming what was queued started), shuts down and
    /// has its mail database deleted. Returns the tenants
    /// whose accounts were all taken over by other nodes in time.
    pub async fn shutdown(&self) -> Vec<TenantId> {
        let nodes: Vec<(TenantId, Arc<Node>)> = std::mem::take(&mut *self.running.lock().await)
            .into_iter()
            .collect();
        let handback = self.handback;
        let handed = futures::future::join_all(nodes.iter().map(|(id, node)| async move {
            let handed = hand_back(node, handback).await;
            if handed {
                node.announce_leaving().await;
            }
            node.shutdown().await;
            info!(tenant = %id, "tenant stopped");
            handed.then(|| id.clone())
        }))
        .await;
        drop(nodes);
        for id in self.tenants.layout.ids() {
            self.clear_view(&id);
        }
        self.write_status().await;
        handed.into_iter().flatten().collect()
    }

    async fn write_status(&self) {
        let layout = &self.tenants.layout;
        let running = self.running.lock().await.clone();
        let mut tenants = Vec::new();
        for id in layout.ids() {
            let binding = layout.binding(&id).ok().flatten();
            let mut row = TenantStatus {
                id: id.to_string(),
                state: if running.contains_key(&id) {
                    "running"
                } else if layout.stop_marker(&id).exists() {
                    "stopped"
                } else if binding.is_none() {
                    "unbound"
                } else {
                    "failed"
                }
                .into(),
                group: binding.as_ref().map(|b| b.group.clone()),
                node: binding.as_ref().map(|b| b.node.clone()),
                accounts: 0,
                leading: 0,
                peers: 0,
            };
            if let Some(node) = running.get(&id) {
                let api = node.api();
                let accounts = api.list_accounts().await.unwrap_or_default();
                row.accounts = accounts.len();
                row.leading = accounts.iter().filter(|a| node.leads(&a.id)).count();
                row.peers = api
                    .list_nodes()
                    .await
                    .map(|n| n.iter().filter(|n| !n.this_node && n.counts).count())
                    .unwrap_or(0);
            }
            tenants.push(row);
        }
        let status = Status {
            v: 1,
            updated_ms: now_ms(),
            pid: std::process::id(),
            tenants,
        };
        if let Ok(bytes) = serde_json::to_vec_pretty(&status) {
            let _ = crate::tenant::write_atomic(&layout.status_file(), &bytes);
        }
    }
}

/// Hands a stopping node's accounts back: it stops taking leases and releases what it leads at
/// a clean point with its state offered, then waits up to `limit` for another node to hold each
/// account it led (none may be up; the wait then ends at the limit). Returns whether every
/// account it led is held by another node.
pub async fn hand_back(node: &Node, limit: Duration) -> bool {
    let api = node.api();
    let led: Vec<rowboat_api::AccountId> = api
        .list_accounts()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|a| a.id)
        .filter(|a| node.leads(a))
        .collect();
    node.set_can_run(false);
    if led.is_empty() {
        return true;
    }
    let me = node.node_id().to_owned();
    let handed = async {
        loop {
            let mut done = true;
            for a in &led {
                if node.leads(a) {
                    done = false;
                    break;
                }
                match node.lease_holder(a).await {
                    Some(h) if h != me => {}
                    _ => {
                        done = false;
                        break;
                    }
                }
            }
            if done {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    if tokio::time::timeout(limit, handed).await.is_err() {
        info!(node = %me, "accounts not taken over within the hand-back wait");
        false
    } else {
        info!(node = %me, accounts = led.len(), "accounts handed back");
        true
    }
}
