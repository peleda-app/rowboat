use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use baton_lease::NodeClass;
use baton_state::StateStore;
use bytes::Bytes;
use rinse_mail::Content;
use rowboat_api::NodeApi;
use rowboat_category::Categorizer;
use rowboat_discover::{DiscoverySource, Prober};
use rowboat_endpoint::Endpoints;
use rowboat_keystore::{KeyClass, KeyName, Keystore, KeystoreError, Secret};
use rowboat_spam::SpamFilter;
use skein_accounts::{Accounts, TenantRegistry};
use skein_core::TenantId;
use skein_keyring::Keyring;
use skein_keyring_local::LocalKeyring;
use skein_storage::{ControlState, Expect, ObjectKey, Objects, Storage, StorageError};
use skein_storage_fs::{FsObjects, OpenError};
use skein_storage_sealed::SealedObjects;
use skein_view::Store;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::info;
use zeroize::Zeroizing;

use crate::clock::{Clock, SystemClock};
use crate::events::{Chore, Hub, Sends};
use crate::overlay::Overlay;
use crate::providers::Providers;
use crate::records::{self, NodeRecord};

const IDENTITY: &str = "rowboat.identity";
const MASTER: &str = "rowboat.master";
pub(crate) const NODE_KEM: &str = "rowboat.node-kem";
pub(crate) const MEMBER: &str = "rowboat.member";
pub(crate) const RECOVERY: &str = "rowboat.recovery-pending";

/// The keystore items a node keeps: its identity and master key, its KEM key, the member key
/// (desktops and phones) and the recovery roots until the person wrote them down. Deleting the
/// identity and master key makes every sealed object of its data directory unreadable: an app
/// starting over deletes all of them first.
pub const KEY_NAMES: [&str; 5] = [IDENTITY, MASTER, NODE_KEM, MEMBER, RECOVERY];
const OBJECTS_CONTEXT: &str = "rowboat-node objects v1";
const KEYRING_CONTEXT: &str = "rowboat-node keyring v1";

/// Timing of the test profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TestTiming {
    /// Between engine heartbeats and status reads.
    pub heartbeat: Duration,
    /// Between syncs of an account without push.
    pub interval: Duration,
    /// Between follower rounds.
    pub poll: Duration,
    /// The send undo window in milliseconds.
    pub undo_ms: i64,
    /// How long shutdown waits for the engine's workers before aborting them (the node's other
    /// tasks get twice this).
    pub shutdown: Duration,
    /// A replication round (asking peers for heads) every this many follower polls, the first
    /// poll included; never with 0 (a node that cannot dial its peers).
    pub rounds: u32,
    /// The fallback timing; two lease times-to-live (eight heartbeats each) when `None`.
    pub fallback: Option<crate::FallbackTiming>,
}

/// How the node runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// A desktop: IMAP and SMTP, 10 s heartbeats, syncs every 120 s without push, a 10 s undo
    /// window, at most 2 renders in flight.
    Desktop,
    /// The headless server (`apps/rowboat`, one node per tenant): the desktop's timing, IMAP and
    /// SMTP, discovery from the table only (a server never adds accounts itself).
    Server,
    /// Tests: providers from [`NodeBuilder::providers`] (Skein's fakes), fast timing.
    Test(TestTiming),
}

impl Profile {
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::Server => "server",
            Self::Test(_) => "test",
        }
    }

    pub(crate) fn timing(&self) -> TestTiming {
        match self {
            Self::Desktop | Self::Server => TestTiming {
                heartbeat: Duration::from_secs(10),
                interval: Duration::from_secs(120),
                poll: Duration::from_secs(5),
                undo_ms: 10_000,
                shutdown: Duration::from_secs(30),
                rounds: 150,
                fallback: None,
            },
            Self::Test(t) => *t,
        }
    }

    pub(crate) fn content_workers(&self) -> usize {
        2
    }

    /// The fallback timing by default: a five-minute takeover delay, or two lease times-to-live
    /// (eight heartbeats each) in the test profile.
    pub(crate) fn fallback(&self) -> crate::FallbackTiming {
        match self {
            Self::Desktop | Self::Server => crate::FallbackTiming::after(Duration::from_secs(300)),
            Self::Test(t) => t
                .fallback
                .unwrap_or_else(|| crate::FallbackTiming::after(t.heartbeat * 16)),
        }
    }
}

/// Why the node could not be built. Carries no path, secret or platform text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BuildError {
    /// A required service was not given.
    #[error("missing {0}")]
    Missing(&'static str),
    /// The data directory cannot be created or used.
    #[error("the data directory is not usable")]
    DataDir,
    /// Another process holds the data directory.
    #[error("the data directory is in use by another process")]
    Locked,
    /// The data directory holds something that is not this node's.
    #[error("the data directory is not empty")]
    NotEmpty,
    /// The node record exists but a key is missing or does not open the data. A new key would
    /// orphan every sealed object, so the node never makes one: the app asks the person to
    /// unlock the keychain and retry, or to start over.
    #[error("the node's keys are lost")]
    KeysLost,
    /// The keystore is locked; retry after the device or keychain is unlocked.
    #[error("the keystore is locked")]
    KeystoreLocked,
    /// The keystore failed or refused.
    #[error("the keystore failed")]
    Keystore,
    /// Storage failed.
    #[error("storage failed")]
    Storage,
    /// The mail database failed.
    #[error("the mail database failed")]
    Database,
    /// A hook could not be built (bento's tables).
    #[error("a hook is unavailable")]
    Hook,
}

impl From<StorageError> for BuildError {
    fn from(_: StorageError) -> Self {
        Self::Storage
    }
}

fn default_discovery(profile: Profile) -> Vec<Arc<dyn DiscoverySource>> {
    let mut sources: Vec<Arc<dyn DiscoverySource>> =
        vec![Arc::new(rowboat_discover_table::TableSource)];
    if profile == Profile::Desktop {
        if let Ok(https) = rowboat_discover_net::Https::new() {
            sources.push(Arc::new(
                rowboat_discover_autoconfig::AutoconfigSource::new(Arc::new(https)),
            ));
        }
        if let Ok(resolver) = rowboat_discover_net::UdpResolver::system() {
            sources.push(Arc::new(rowboat_discover_srv::SrvSource::new(Arc::new(
                resolver,
            ))));
        }
    }
    sources
}

/// Builds a [`Node`]. The app hands in everything platform-specific.
pub struct NodeBuilder {
    profile: Profile,
    data_dir: Option<PathBuf>,
    keystore: Option<Arc<dyn Keystore>>,
    content: Option<Arc<dyn Content>>,
    spam: Option<Arc<dyn SpamFilter>>,
    category: Option<Arc<dyn Categorizer>>,
    discovery: Option<Vec<Arc<dyn DiscoverySource>>>,
    prober: Option<Arc<dyn Prober>>,
    providers: Option<Providers>,
    roots: skein_core::TlsRoots,
    clock: Arc<dyn Clock>,
    endpoints: Option<Arc<dyn Endpoints>>,
    class: NodeClass,
    on_revoked: Option<RevokedHook>,
    signal: Option<Arc<dyn baton_signal::Signal>>,
    push: Option<Push>,
    view_dir: Option<PathBuf>,
    store: Option<Arc<dyn Objects>>,
    fallback: Option<crate::FallbackTiming>,
    label: Option<String>,
    advertise: Vec<std::net::SocketAddr>,
}

/// Provider push for the node's accounts: subscriptions are recorded in `registry` (the root
/// object store the host's push receivers read, shared by every node of a host) and providers
/// post to `public_url`. Hints arrive on the node's signal ([`NodeBuilder::signal`]).
#[derive(Clone)]
pub struct Push {
    /// The object store of the host's push registry (`system/push/...`).
    pub registry: Arc<dyn Objects>,
    /// Where providers reach the host's push receivers, such as `https://mail.example.com`.
    pub public_url: String,
    /// The Pub/Sub topic Gmail publishes to, when Gmail push is set up.
    pub gmail_topic: Option<String>,
}

/// Called once when the node learns that its group revoked it (from a peer's revocation notice
/// or the group log). The app wipes from here; the node itself stops leading.
pub type RevokedHook = Arc<dyn Fn() + Send + Sync>;

/// Everything the running node shares between its API and its tasks.
pub(crate) struct Core {
    pub profile: Profile,
    pub node_id: String,
    pub tenant: TenantId,
    pub data_dir: PathBuf,
    pub objects: Arc<dyn Objects>,
    pub storage: Storage,
    pub accounts: Accounts,
    pub tokens: Arc<skein_oauth::TokenManager>,
    pub keyring: Arc<dyn Keyring>,
    pub store: Arc<Store>,
    pub signal: Arc<dyn baton_signal::Signal>,
    pub providers: Providers,
    pub discovery: Vec<Arc<dyn DiscoverySource>>,
    pub prober: Option<Arc<dyn Prober>>,
    pub content: Arc<dyn Content>,
    pub spam: Arc<dyn SpamFilter>,
    pub category: Arc<dyn Categorizer>,
    pub hub: Hub,
    pub overlay: Arc<Overlay>,
    pub sends: Arc<Sends>,
    pub clock: Arc<dyn Clock>,
    pub chores: mpsc::Sender<Chore>,
    pub statuses: Mutex<std::collections::BTreeMap<String, String>>,
    pub removing: Mutex<std::collections::BTreeSet<String>>,
    pub notify_rate: Mutex<bento_notify::RateState>,
    pub synced: Arc<Mutex<std::collections::BTreeSet<String>>>,
    pub arbiter: Arc<crate::leases::NodeLeases>,
    pub can_run: std::sync::atomic::AtomicBool,
    pub on_revoked: Option<RevokedHook>,
    pub push: Option<Push>,
    pub engine: std::sync::OnceLock<skein_engine::Engine>,
    pub background: crate::tasks::Background,
    pub directory: Arc<FsObjects>,
    pub group: Arc<crate::group::NodeGroup>,
    pub keystore: Arc<dyn Keystore>,
    /// The node's own storage, its journal attested with its node key; `storage` reads through
    /// the peers after it.
    pub local: Storage,
    pub replication: std::sync::OnceLock<Arc<rowboat_sync::Replication>>,
    /// The accounts this node leads (it added them); the others it follows.
    pub led: Mutex<std::collections::BTreeSet<String>>,
    /// Which nodes may lead which account, as the engine asks it.
    pub eligibility: Mutex<crate::leases::Eligibility>,
}

impl Core {
    /// Whether this node leads `account` now: with shared leases, whether its engine holds the
    /// account's lease; with the local arbiter, whether this node added it.
    pub(crate) fn leads(&self, account: &str) -> bool {
        if self.arbiter.shared() {
            return match (self.engine.get(), skein_core::AccountId::new(account)) {
                (Some(e), Ok(a)) => e.holds_lease(&self.tenant, &a),
                _ => false,
            };
        }
        self.led
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(account)
    }

    pub(crate) async fn led_accounts(&self) -> Vec<String> {
        if self.arbiter.shared() {
            return crate::api::all_metas(self)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|m| m.account.to_string())
                .filter(|a| self.leads(a))
                .collect();
        }
        self.led
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    pub(crate) fn replication(
        &self,
    ) -> Result<&Arc<rowboat_sync::Replication>, rowboat_api::NodeError> {
        self.replication
            .get()
            .ok_or(rowboat_api::NodeError::Internal)
    }
}

/// A built node: [`Node::api`] answers at once; [`Node::start`] runs the engine and the
/// follower; [`Node::shutdown`] stops them and releases every lease.
pub struct Node {
    pub(crate) core: Arc<Core>,
    pub(crate) stop: watch::Sender<bool>,
    pub(crate) tasks: Mutex<Vec<JoinHandle<()>>>,
    pub(crate) chores: Mutex<Option<mpsc::Receiver<Chore>>>,
}

impl Node {
    /// A builder with the desktop profile.
    pub fn builder() -> NodeBuilder {
        NodeBuilder {
            profile: Profile::Desktop,
            data_dir: None,
            keystore: None,
            content: None,
            spam: None,
            category: None,
            discovery: None,
            prober: None,
            providers: None,
            roots: skein_core::TlsRoots::default(),
            clock: Arc::new(SystemClock),
            endpoints: None,
            class: NodeClass::Desktop,
            on_revoked: None,
            signal: None,
            push: None,
            view_dir: None,
            store: None,
            fallback: None,
            label: None,
            advertise: Vec::new(),
        }
    }

    /// Lets a member device adopt this server node (GROUP.md, "The server's first run"): opens
    /// a pairing endpoint and returns the invite to show. Only a node built with
    /// [`NodeBuilder::class`] `Server`, alone in its group, may call it. When a device adopts it,
    /// the node record moves to the device's group, the member key of the placeholder group is
    /// deleted and [`ServerInvite::adopted`](crate::ServerInvite::adopted) resolves: rebuild the
    /// node then.
    pub async fn server_invite(&self) -> Result<crate::ServerInvite, rowboat_api::NodeError> {
        self.server_invite_asking(false).await
    }

    /// [`Node::server_invite`] where the fingerprint must also be confirmed here: a
    /// `GroupEvent::PairingCheck { confirm: true }` waits for `confirm_pairing` (the server's
    /// console asking the operator) before the adoption completes.
    pub async fn server_invite_confirmed(
        &self,
    ) -> Result<crate::ServerInvite, rowboat_api::NodeError> {
        self.server_invite_asking(true).await
    }

    async fn server_invite_asking(
        &self,
        ask: bool,
    ) -> Result<crate::ServerInvite, rowboat_api::NodeError> {
        let (invite, adoption, done) = self.core.group.server_invite(ask).await?;
        let core = self.core.clone();
        self.core.background.spawn(async move {
            let r = match adoption.await {
                Ok(Ok(joined)) => switch_group(&core, joined).await,
                Ok(Err(e)) => Err(e),
                Err(_) => Err(rowboat_api::NodeError::Internal),
            };
            let _ = done.send(r);
        });
        Ok(invite)
    }

    /// Announces whether this node can lead now: `false` before a phone is suspended or to
    /// move a server's accounts back to the person's devices; it then hands over what it leads
    /// at a clean point and takes nothing until set back to `true`. `true` at start.
    pub fn set_can_run(&self, can_run: bool) {
        self.core
            .can_run
            .store(can_run, std::sync::atomic::Ordering::SeqCst);
        if let Some(e) = self.core.engine.get() {
            e.set_can_run(can_run);
        }
    }

    /// Whether this node leads `account` now.
    pub fn leads(&self, account: &rowboat_api::AccountId) -> bool {
        self.core.leads(account.as_str())
    }

    /// The node id of the holder of `account`'s lease as the group's arbiter records it, `None`
    /// when nobody holds it or the arbiter cannot be asked. On a server that arbitrates, this is
    /// its own record; elsewhere it asks the arbiter.
    pub async fn lease_holder(&self, account: &rowboat_api::AccountId) -> Option<String> {
        use baton_lease::Leases;
        let id = skein_core::AccountId::new(account.as_str()).ok()?;
        let group = skein_core::coordination::group(&self.core.tenant);
        let key = skein_core::coordination::lease_key(&id);
        self.core
            .arbiter
            .holder(&group, &key)
            .await
            .ok()
            .flatten()
            .map(|l| l.node.to_string())
    }

    /// The node's surface for the app.
    pub fn api(&self) -> Arc<dyn NodeApi> {
        Arc::new(crate::api::Api(self.core.clone()))
    }

    /// The node id.
    pub fn node_id(&self) -> &str {
        &self.core.node_id
    }

    /// The group id (Skein's tenant).
    pub fn group_id(&self) -> &str {
        self.core.tenant.as_str()
    }

    /// The hash of the group log's genesis entry, the group's fingerprint: what a server tenant
    /// is bound to once adopted.
    pub fn genesis_hash(&self) -> Result<[u8; 32], rowboat_api::NodeError> {
        self.core.group.genesis_hash()
    }

    /// Whether a member device adopted this server node: it holds no member key of its own, and
    /// its group is the adopting device's.
    pub fn adopted(&self) -> bool {
        self.core.group.is_adopted()
    }
}

impl NodeBuilder {
    /// The profile; [`Profile::Desktop`] by default.
    pub fn profile(mut self, profile: Profile) -> Self {
        self.profile = profile;
        self
    }

    /// How long the group's server must be silent before this device takes over its accounts,
    /// and how long it must answer again before the device goes back to it (GROUP.md, "When the
    /// server is silent"). By default [`Profile`]'s: five minutes and a quarter of that, or 16
    /// heartbeats in the test profile. On a server it sets how long a device must have been
    /// silent before the server believes its fallback grants (half the takeover delay).
    pub fn fallback(mut self, timing: crate::FallbackTiming) -> Self {
        self.fallback = Some(timing);
        self
    }

    /// The directory the node owns: `objects/` and `view/` inside it. Required.
    pub fn data_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.data_dir = Some(dir.into());
        self
    }

    /// The device secret store. Required.
    pub fn keystore(mut self, keystore: Arc<dyn Keystore>) -> Self {
        self.keystore = Some(keystore);
        self
    }

    /// The content pipeline (the app's sandboxed workers). Required.
    pub fn content(mut self, content: Arc<dyn Content>) -> Self {
        self.content = Some(content);
        self
    }

    /// The spam hook; `rowboat-spam-signals` by default.
    pub fn spam(mut self, spam: Arc<dyn SpamFilter>) -> Self {
        self.spam = Some(spam);
        self
    }

    /// The category hook; `rowboat-category-bento` by default.
    pub fn category(mut self, category: Arc<dyn Categorizer>) -> Self {
        self.category = Some(category);
        self
    }

    /// Discovery sources in order. By default the table (`rowboat-discover-table`) for every
    /// profile, and for the desktop also the domain's own autoconfig file
    /// (`rowboat-discover-autoconfig` over HTTPS) and its DNS SRV records
    /// (`rowboat-discover-srv` over the system's name servers). Never a third-party database.
    pub fn discovery(mut self, sources: Vec<Arc<dyn DiscoverySource>>) -> Self {
        self.discovery = Some(sources);
        self
    }

    /// Probes every server not from the table before `discover` returns it. The desktop profile
    /// uses [`ServerProber`](crate::ServerProber) by default; without a prober (the test profile
    /// unless one is given) such candidates are returned unverified.
    pub fn prober(mut self, prober: Arc<dyn Prober>) -> Self {
        self.prober = Some(prober);
        self
    }

    /// The provider factories. IMAP and SMTP by default; required for [`Profile::Test`].
    pub fn providers(mut self, providers: Providers) -> Self {
        self.providers = Some(providers);
        self
    }

    /// Trusts `roots` (a test CA) besides the web roots in the default IMAP and SMTP providers
    /// and the default [`ServerProber`](crate::ServerProber); with [`Profile::Test`] and no
    /// [`providers`](Self::providers), the test profile then runs real IMAP and SMTP. Certificates
    /// are still verified and plain text is still refused.
    #[cfg(feature = "testing")]
    pub fn test_roots(mut self, roots: skein_core::TlsRoots) -> Self {
        self.roots = roots;
        self
    }

    /// Where the node binds its link and its pairing endpoints. The desktop profile binds iroh
    /// endpoints (`rowboat-endpoint-iroh`, no relay, no discovery) by default; the test profile
    /// has no network unless one is given (`rowboat-endpoint-memory` in tests).
    pub fn endpoints(mut self, endpoints: Arc<dyn Endpoints>) -> Self {
        self.endpoints = Some(endpoints);
        self
    }

    /// The name this node gives when it pairs (display only, cut to one line of 64
    /// characters); the profile's name by default. A name the person gave it later
    /// (`rename_node`) takes its place.
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Addresses of this device on its local network to put in invite and link hints of the
    /// default iroh endpoints (question 59); ports of `0` take the endpoint's port. Ignored when
    /// [`NodeBuilder::endpoints`] is given. Relays and discovery stay off.
    pub fn advertise(mut self, addrs: Vec<std::net::SocketAddr>) -> Self {
        self.advertise = addrs;
        self
    }

    /// The class the node pairs as: `Desktop` by default, `Phone` on phones, `Server` for the
    /// headless server, which is adopted by a member device ([`Node::server_invite`]) instead of
    /// joining. Once certified, the certificate's class decides the node's lease priority.
    pub fn class(mut self, class: NodeClass) -> Self {
        self.class = class;
        self
    }

    /// Called once when the node learns that its group revoked it.
    pub fn on_revoked(mut self, hook: RevokedHook) -> Self {
        self.on_revoked = Some(hook);
        self
    }

    /// The signal bus the node's engine, follower and push hints use; a new
    /// `baton-signal-local` bus by default. Topics are scoped to the node's group, so the nodes
    /// of one host may share one bus (the server's push receivers publish into it).
    pub fn signal(mut self, signal: Arc<dyn baton_signal::Signal>) -> Self {
        self.signal = Some(signal);
        self
    }

    /// Keeps provider push subscriptions of the node's accounts alive (see [`Push`]). Off by
    /// default: accounts are synced every interval.
    pub fn push(mut self, push: Push) -> Self {
        self.push = Some(push);
        self
    }

    /// Where the mail database lives, instead of `<data_dir>/view`. The database is rebuilt
    /// from the journal when the directory is empty, so a server may keep it in a cache it
    /// clears on every start.
    pub fn view_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.view_dir = Some(dir.into());
        self
    }

    /// Keeps every object in `store` (an S3 bucket's prefix for this node) instead of
    /// `<data_dir>/objects`, sealed exactly as on disk. The data directory still holds the lock
    /// that keeps a second node of this process or another one out of it; nothing else locks
    /// the store, so one store must serve one node.
    pub fn store(mut self, store: Arc<dyn Objects>) -> Self {
        self.store = Some(store);
        self
    }

    /// The clock for the node's own decisions; the system clock by default.
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Opens or creates the node. On an empty directory: a new identity and master key in the
    /// keystore, a new group, then the node record last. Later: the record and both keys, or
    /// [`BuildError::KeysLost`]. Never creates a new key over existing data.
    pub async fn build(self) -> Result<Node, BuildError> {
        let data_dir = self.data_dir.ok_or(BuildError::Missing("data directory"))?;
        let keystore = self.keystore.ok_or(BuildError::Missing("keystore"))?;
        let content = self.content.ok_or(BuildError::Missing("content"))?;
        let trusting = !self.roots.is_empty();
        let providers = match (self.providers, self.profile) {
            (Some(p), _) => p,
            (None, Profile::Test(_)) if !trusting => return Err(BuildError::Missing("providers")),
            (None, _) => Providers::over(crate::ImapSmtp::with_roots(self.roots.clone())),
        };
        let spam: Arc<dyn SpamFilter> = self
            .spam
            .unwrap_or_else(|| Arc::new(rowboat_spam_signals::SignalsFilter));
        let category: Arc<dyn Categorizer> = match self.category {
            Some(c) => c,
            None => Arc::new(
                rowboat_category_bento::BentoCategorizer::new().map_err(|_| BuildError::Hook)?,
            ),
        };
        let discovery = self
            .discovery
            .unwrap_or_else(|| default_discovery(self.profile));
        let prober = self.prober.or_else(|| match self.profile {
            Profile::Test(_) if !trusting => None,
            _ => Some(Arc::new(crate::ServerProber::trusting(
                self.roots.clone(),
                crate::probe::PROBE_TIMEOUT,
            )) as Arc<dyn Prober>),
        });

        private_dir(&data_dir)?;
        let objects_dir = data_dir.join("objects");
        let view_dir = self.view_dir.unwrap_or_else(|| data_dir.join("view"));
        let fresh_dir = is_empty_dir(&data_dir)?;
        private_dir(&objects_dir)?;
        let directory = Arc::new(FsObjects::open(&objects_dir).map_err(|e| match e {
            OpenError::Locked { .. } => BuildError::Locked,
            OpenError::Io(_) => BuildError::DataDir,
        })?);
        let fs: Arc<dyn Objects> = match self.store {
            Some(store) => store,
            None => directory.clone(),
        };
        let record_key = ObjectKey::parse("system/node").expect("constant");
        let group_key = ObjectKey::parse("system/group").expect("constant");
        let has_record = fs.get(&record_key).await?.is_some();

        let identity_name = KeyName::new(IDENTITY).expect("constant");
        let master_name = KeyName::new(MASTER).expect("constant");
        let keystore_err = |e: KeystoreError| match e {
            KeystoreError::Locked => BuildError::KeystoreLocked,
            _ => BuildError::Keystore,
        };
        let mut identity = keystore.get(&identity_name).await.map_err(keystore_err)?;
        let mut master = keystore.get(&master_name).await.map_err(keystore_err)?;
        if has_record {
            if identity.is_none() || master.is_none() {
                return Err(BuildError::KeysLost);
            }
        } else if identity.is_none() || master.is_none() {
            let other = !fresh_dir || !is_empty_store(&*fs).await?;
            if other {
                return Err(BuildError::NotEmpty);
            }
            let id = Secret::new(random::bytes::<32>().to_vec());
            let key = Secret::new(random::bytes::<32>().to_vec());
            keystore
                .put(&identity_name, &id, KeyClass::Background)
                .await
                .map_err(keystore_err)?;
            keystore
                .put(&master_name, &key, KeyClass::Background)
                .await
                .map_err(keystore_err)?;
            identity = Some(id);
            master = Some(key);
        }
        let identity = key32(identity.as_ref()).ok_or(BuildError::KeysLost)?;
        let master = key32(master.as_ref()).ok_or(BuildError::KeysLost)?;
        let objects_key = Zeroizing::new(blake3::derive_key(OBJECTS_CONTEXT, &master[..]));
        let keyring_key = Zeroizing::new(blake3::derive_key(KEYRING_CONTEXT, &master[..]));
        let objects: Arc<dyn Objects> = Arc::new(SealedObjects::new(fs.clone(), objects_key));
        let me = baton_identity::Identity::from_secret_bytes(&identity);
        let node_id = me.node_id().to_string();

        let mut record = if has_record {
            let (bytes, _) = objects
                .get(&record_key)
                .await
                .map_err(|e| match e {
                    StorageError::Corrupt(_) => BuildError::KeysLost,
                    _ => BuildError::Storage,
                })?
                .ok_or(BuildError::Storage)?;
            let record = records::decode_node_record(&bytes).map_err(|_| BuildError::Storage)?;
            if record.node != node_id {
                return Err(BuildError::KeysLost);
            }
            record
        } else {
            let group = match objects.get(&group_key).await {
                Ok(Some((g, _))) => {
                    String::from_utf8(g.to_vec()).map_err(|_| BuildError::Storage)?
                }
                Ok(None) => {
                    let g = random::base32_id('g');
                    objects
                        .put(&group_key, Bytes::from(g.clone()), Expect::Any)
                        .await?;
                    g
                }
                Err(StorageError::Corrupt(_)) => return Err(BuildError::NotEmpty),
                Err(_) => return Err(BuildError::Storage),
            };
            let tenant = TenantId::new(group.clone()).map_err(|_| BuildError::Storage)?;
            TenantRegistry::new(objects.clone()).add(&tenant).await?;
            NodeRecord {
                v: 0,
                node: node_id.clone(),
                group,
                profile: self.profile.name().into(),
                created_at: self.clock.now_ms(),
            }
        };
        let tenant = TenantId::new(record.group.clone()).map_err(|_| BuildError::Storage)?;
        let storage = Storage::over(objects.clone());
        let state: Arc<dyn StateStore> = Arc::new(ControlState::new(storage.control.clone()));
        let clock = self.clock.clone();
        let now: rowboat_group::Now = Arc::new(move || baton_core::Timestamp(clock.now_ms()));
        let class = self.class;
        let group_id =
            baton_core::GroupId::new(record.group.clone()).map_err(|_| BuildError::Storage)?;
        let fresh_group = record.v < records::NODE_FORMAT;
        let kem = secret_key(&*keystore, NODE_KEM, fresh_group).await?;
        let member = match keystore.get(&KeyName::new(MEMBER).expect("constant")).await {
            Ok(Some(m)) => Some(key32(Some(&m)).ok_or(BuildError::KeysLost)?),
            Ok(None) if fresh_group => Some(secret_key(&*keystore, MEMBER, true).await?),
            Ok(None) => None,
            Err(KeystoreError::Locked) => return Err(BuildError::KeystoreLocked),
            Err(_) => return Err(BuildError::Keystore),
        };
        let keys = rowboat_group::NodeKeys {
            identity: me.clone(),
            kem: baton_keys::KemSecret::from_bytes(&kem).map_err(|_| BuildError::KeysLost)?,
            member: member.map(|m| baton_identity::Identity::from_secret_bytes(&m)),
        };
        let membership = if fresh_group {
            let membership =
                found_or_open(&*keystore, state.clone(), group_id, keys, now.clone()).await?;
            for account in account_ids(&storage, &tenant).await? {
                let Some(resource) = rowboat_group::account_resource(&account) else {
                    continue;
                };
                membership
                    .ensure_resource(&resource, &crate::group::class_names())
                    .await
                    .map_err(|_| BuildError::Storage)?;
            }
            objects
                .delete(
                    &ObjectKey::parse("system/roster").expect("constant"),
                    Expect::Any,
                )
                .await?;
            let created = record.v == 0;
            record.v = records::NODE_FORMAT;
            objects
                .put(
                    &record_key,
                    Bytes::from(records::encode_node_record(&record)),
                    if created { Expect::Absent } else { Expect::Any },
                )
                .await?;
            if created {
                info!(node = %node_id, "node created");
            } else {
                info!(node = %node_id, "node upgraded to the group log");
            }
            membership
        } else {
            rowboat_group::Membership::open(state.clone(), group_id, keys, now.clone())
                .await
                .map_err(|e| match e {
                    rowboat_group::MembershipError::Storage => BuildError::Storage,
                    _ => BuildError::KeysLost,
                })?
        };
        let membership = Arc::new(membership);
        let attestor = Arc::new(rowboat_sync::NodeAttestor::new(membership.clone()));
        let local = Storage::over_attested(objects.clone(), attestor.clone());
        let peers = Arc::new(rowboat_sync::Peers::new(membership.clone()));
        let storage = skein_storage_tiered::Tiered::new(local.clone())
            .with_tier(Arc::new(rowboat_sync::PeerTier::new(peers.clone())))
            .build();
        let hub = Hub::new();
        let endpoints = self.endpoints.or_else(|| match self.profile {
            Profile::Desktop | Profile::Server => Some(Arc::new(
                rowboat_endpoint_iroh::IrohEndpoints::new(baton_link_iroh::IrohConfig::default())
                    .advertise(self.advertise.clone()),
            ) as Arc<dyn Endpoints>),
            Profile::Test(_) => None,
        });
        let group = crate::group::NodeGroup::new(
            membership.clone(),
            endpoints,
            state,
            class,
            match self.profile {
                Profile::Test(_) => rowboat_group::pairing::Limits {
                    step: Duration::from_secs(300),
                    handshake: Duration::from_secs(300),
                    confirm: Duration::from_secs(300),
                    fail_delay: Duration::ZERO,
                    ..rowboat_group::pairing::Limits::default()
                },
                _ => rowboat_group::pairing::Limits::default(),
            },
            now,
            self.label
                .clone()
                .filter(|l| !l.trim().is_empty())
                .unwrap_or_else(|| self.profile.name().into()),
        );
        let timing = self.profile.timing();
        let arbiter = Arc::new(crate::leases::NodeLeases::new(
            group.clone(),
            Arc::new(ControlState::new(storage.control.clone())),
            match self.profile {
                Profile::Test(_) => timing.heartbeat.as_millis() as u64 * 8,
                _ => timing.heartbeat.as_millis() as u64 * 3,
            },
            match self.profile {
                Profile::Test(_) => Duration::from_secs(30),
                _ => Duration::from_secs(5),
            },
            timing.heartbeat,
            self.fallback.unwrap_or_else(|| self.profile.fallback()),
            local.clone(),
            tenant.clone(),
        ));
        attestor.set_grants(arbiter.clone());

        private_dir(&view_dir)?;
        let store =
            Arc::new(Store::open(&view_dir.join("view.sqlite")).map_err(|_| BuildError::Database)?);
        let keyring: Arc<dyn Keyring> = Arc::new(LocalKeyring::from_master(
            *keyring_key,
            storage.control.clone(),
        ));
        let tokens = Arc::new(skein_oauth::TokenManager::new(
            Arc::new(crate::run::NoTokens),
            storage.control.clone(),
            keyring.clone(),
        ));
        let accounts = Accounts::new(storage.control.clone(), keyring.clone());
        let signal: Arc<dyn baton_signal::Signal> = self
            .signal
            .unwrap_or_else(|| Arc::new(baton_signal_local::LocalSignal::new()));
        let (chores_tx, chores_rx) = mpsc::channel(1024);
        let core = Arc::new(Core {
            profile: self.profile,
            node_id,
            tenant,
            data_dir,
            objects,
            storage,
            accounts,
            tokens,
            keyring,
            store,
            signal,
            providers,
            discovery,
            prober,
            content,
            spam,
            category,
            hub,
            group,
            keystore,
            overlay: Arc::new(Overlay::default()),
            sends: Arc::new(Sends::default()),
            clock: self.clock,
            chores: chores_tx,
            statuses: Mutex::default(),
            removing: Mutex::default(),
            notify_rate: Mutex::default(),
            synced: Arc::default(),
            arbiter,
            can_run: std::sync::atomic::AtomicBool::new(true),
            on_revoked: self.on_revoked,
            push: self.push,
            engine: std::sync::OnceLock::new(),
            background: crate::tasks::Background::default(),
            directory,
            local: local.clone(),
            replication: std::sync::OnceLock::new(),
            led: Mutex::default(),
            eligibility: Mutex::default(),
        });
        let led: std::collections::BTreeSet<String> = crate::api::all_metas(&core)
            .await
            .map_err(|_| BuildError::Storage)?
            .into_iter()
            .filter(|m| m.owner.is_none() && !m.removing)
            .map(|m| m.account.to_string())
            .collect();
        *core.led.lock().unwrap_or_else(|e| e.into_inner()) = led;
        let clock = core.clock.clone();
        let replication = Arc::new(rowboat_sync::Replication::new(
            core.tenant.clone(),
            peers,
            local,
            core.storage.clone(),
            core.signal.clone(),
            Arc::new(crate::sync::NodeHost {
                core: Arc::downgrade(&core),
            }),
            Arc::new(move || baton_core::Timestamp(clock.now_ms())),
            rowboat_sync::Config::default(),
        ));
        replication.load().await.map_err(|_| BuildError::Storage)?;
        let _ = core.replication.set(replication.clone());
        let _ = core.group.replication.set(replication);
        let (stop, _) = watch::channel(false);
        Ok(Node {
            core,
            stop,
            tasks: Mutex::new(Vec::new()),
            chores: Mutex::new(Some(chores_rx)),
        })
    }
}

use crate::random;

async fn secret_key(
    keystore: &dyn Keystore,
    name: &str,
    create: bool,
) -> Result<Zeroizing<[u8; 32]>, BuildError> {
    let name = KeyName::new(name).expect("constant");
    match keystore.get(&name).await {
        Ok(Some(s)) => key32(Some(&s)).ok_or(BuildError::KeysLost),
        Ok(None) if create => {
            let key = Secret::new(random::bytes::<32>().to_vec());
            keystore
                .put(&name, &key, KeyClass::Background)
                .await
                .map_err(|e| match e {
                    KeystoreError::Locked => BuildError::KeystoreLocked,
                    _ => BuildError::Keystore,
                })?;
            key32(Some(&key)).ok_or(BuildError::Keystore)
        }
        Ok(None) => Err(BuildError::KeysLost),
        Err(KeystoreError::Locked) => Err(BuildError::KeystoreLocked),
        Err(_) => Err(BuildError::Keystore),
    }
}

/// Opens the group a crashed upgrade or first run already founded, or founds it: the recovery
/// roots are generated and kept in the keystore until the app has shown them.
async fn found_or_open(
    keystore: &dyn Keystore,
    state: Arc<dyn StateStore>,
    group: baton_core::GroupId,
    keys: rowboat_group::NodeKeys,
    now: rowboat_group::Now,
) -> Result<rowboat_group::Membership, BuildError> {
    let first = baton_state::RecordName::new(format!("group/{:020}", 0)).expect("constant");
    if state
        .get(&group, &first)
        .await
        .map_err(|_| BuildError::Storage)?
        .is_some()
    {
        return rowboat_group::Membership::open(state, group, keys, now)
            .await
            .map_err(|_| BuildError::KeysLost);
    }
    let name = KeyName::new(RECOVERY).expect("constant");
    let roots = match keystore
        .get(&name)
        .await
        .map_err(|_| BuildError::Keystore)?
    {
        Some(s) if s.len() == 64 => s,
        _ => {
            let s = Secret::new(random::bytes::<64>().to_vec());
            keystore
                .put(&name, &s, KeyClass::Background)
                .await
                .map_err(|_| BuildError::Keystore)?;
            s
        }
    };
    let owner: [u8; 32] = roots.expose()[..32].try_into().expect("64 bytes");
    let shared: [u8; 32] = roots.expose()[32..].try_into().expect("64 bytes");
    let owner = baton_keys::RecoveryRoot::from_bytes(owner);
    let shared = baton_keys::RecoveryRoot::from_bytes(shared);
    let expires = now().plus_ms(400 * rowboat_group::DAY_MS);
    rowboat_group::Membership::found(
        state,
        group,
        keys,
        owner.public(),
        shared.public(),
        NodeClass::Desktop,
        expires,
        now,
    )
    .await
    .map_err(|e| match e {
        rowboat_group::MembershipError::Storage => BuildError::Storage,
        _ => BuildError::KeysLost,
    })
}

async fn account_ids(storage: &Storage, tenant: &TenantId) -> Result<Vec<String>, BuildError> {
    let mut out = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let page = storage
            .control
            .list(tenant, "rowboat/accounts", after.as_deref(), 1000)
            .await?;
        for path in &page {
            if let Some((bytes, _)) = storage.control.get(tenant, path).await?
                && let Ok(meta) = records::decode_account_meta(&bytes)
                && !meta.removing
            {
                out.push(meta.account.to_string());
            }
        }
        if page.len() < 1000 {
            return Ok(out);
        }
        after = page.last().cloned();
    }
}

fn key32(secret: Option<&Secret>) -> Option<Zeroizing<[u8; 32]>> {
    let bytes = secret?.expose();
    let array: [u8; 32] = bytes.try_into().ok()?;
    Some(Zeroizing::new(array))
}

fn private_dir(dir: &Path) -> Result<(), BuildError> {
    std::fs::create_dir_all(dir).map_err(|_| BuildError::DataDir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| BuildError::DataDir)?;
    }
    Ok(())
}

fn is_empty_dir(dir: &Path) -> Result<bool, BuildError> {
    let mut entries = std::fs::read_dir(dir).map_err(|_| BuildError::DataDir)?;
    Ok(entries.all(|e| {
        e.ok()
            .is_some_and(|e| matches!(e.file_name().to_str(), Some("objects" | "view")))
    }))
}

async fn is_empty_store(objects: &dyn Objects) -> Result<bool, BuildError> {
    for root in ["system", "tenants"] {
        let prefix = ObjectKey::root(root).expect("constant");
        if !objects.list(&prefix, None, 1).await?.is_empty() {
            return Ok(false);
        }
    }
    Ok(true)
}

/// After joining another group: the member key received (or none), the recovery roots of the
/// abandoned group deleted, the new group registered as a tenant, and the node record moved to
/// it, written last. The running node keeps answering for the old group until it is rebuilt.
pub(crate) async fn switch_group(
    core: &Core,
    joined: crate::group::JoinedGroup,
) -> Result<(), rowboat_api::NodeError> {
    use rowboat_api::NodeError;
    let keystore_err = |e: KeystoreError| match e {
        KeystoreError::Locked => NodeError::Busy,
        _ => NodeError::KeysLost,
    };
    let member = KeyName::new(MEMBER).expect("constant");
    match &joined.member {
        Some(m) => core
            .keystore
            .put(
                &member,
                &Secret::new(m.secret_bytes().to_vec()),
                KeyClass::Background,
            )
            .await
            .map_err(keystore_err)?,
        None => {
            core.keystore.delete(&member).await.map_err(keystore_err)?;
        }
    }
    core.keystore
        .delete(&KeyName::new(RECOVERY).expect("constant"))
        .await
        .map_err(keystore_err)?;
    let tenant = TenantId::new(joined.group.clone()).map_err(|_| NodeError::Internal)?;
    TenantRegistry::new(core.objects.clone())
        .add(&tenant)
        .await
        .map_err(|_| NodeError::Storage)?;
    let record_key = ObjectKey::parse("system/node").expect("constant");
    let (bytes, _) = core
        .objects
        .get(&record_key)
        .await
        .map_err(|_| NodeError::Storage)?
        .ok_or(NodeError::Storage)?;
    let mut record = records::decode_node_record(&bytes).map_err(|_| NodeError::Storage)?;
    let old = core.tenant.clone();
    let moved = old.as_str() != joined.group;
    record.group = joined.group;
    record.v = records::NODE_FORMAT;
    core.objects
        .put(
            &record_key,
            Bytes::from(records::encode_node_record(&record)),
            Expect::Any,
        )
        .await
        .map_err(|_| NodeError::Storage)?;
    if moved {
        let removed = forget_tenant(&core.objects, &old)
            .await
            .map_err(|_| NodeError::Storage)?;
        info!(objects = removed, "the old group's local data was deleted");
    }
    info!(node = %core.node_id, "node moved to the group it joined");
    Ok(())
}

/// Deletes everything `tenant` keeps in `objects` and takes it off the tenant registry. Only for
/// a group this node leaves for good: joining runs only on a node with no accounts and no other
/// nodes, so nothing of it lives anywhere else.
pub(crate) async fn forget_tenant(
    objects: &Arc<dyn Objects>,
    tenant: &TenantId,
) -> Result<u64, StorageError> {
    let prefix = ObjectKey::tenant(tenant);
    let mut removed = 0;
    loop {
        let keys = objects.list(&prefix, None, 512).await?;
        if keys.is_empty() {
            break;
        }
        for k in keys {
            objects.delete(&k, Expect::Any).await?;
            removed += 1;
        }
    }
    TenantRegistry::new(objects.clone()).remove(tenant).await?;
    Ok(removed)
}
