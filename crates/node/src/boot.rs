use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use rinse_mail::Content;
use rowboat_api::NodeApi;
use rowboat_category::Categorizer;
use rowboat_discover::{DiscoverySource, Prober};
use rowboat_keystore::{KeyClass, KeyName, Keystore, KeystoreError, Secret};
use rowboat_spam::SpamFilter;
use skein_accounts::{Accounts, TenantRegistry};
use skein_core::TenantId;
use skein_keyring::Keyring;
use skein_keyring_local::LocalKeyring;
use skein_storage::{Expect, ObjectKey, Objects, Storage, StorageError};
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

/// The keystore items a node keeps (its identity and master key). Deleting both makes every
/// sealed object of its data directory unreadable: an app starting over deletes them first.
pub const KEY_NAMES: [&str; 2] = [IDENTITY, MASTER];
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
    /// How long an account removal waits for the engine to let go of the account.
    pub removal_grace: Duration,
}

/// How the node runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// A desktop: IMAP and SMTP, 10 s heartbeats, syncs every 120 s without push, a 10 s undo
    /// window, at most 2 renders in flight.
    Desktop,
    /// Tests: providers from [`NodeBuilder::providers`] (Skein's fakes), fast timing.
    Test(TestTiming),
}

impl Profile {
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::Test(_) => "test",
        }
    }

    pub(crate) fn timing(&self) -> TestTiming {
        match self {
            Self::Desktop => TestTiming {
                heartbeat: Duration::from_secs(10),
                interval: Duration::from_secs(120),
                poll: Duration::from_secs(5),
                undo_ms: 10_000,
                removal_grace: Duration::from_secs(25),
            },
            Self::Test(t) => *t,
        }
    }

    pub(crate) fn content_workers(&self) -> usize {
        2
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
}

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
    pub leases: std::sync::OnceLock<Arc<baton_lease_cas::CasLeases>>,
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
        }
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
}

impl NodeBuilder {
    /// The profile; [`Profile::Desktop`] by default.
    pub fn profile(mut self, profile: Profile) -> Self {
        self.profile = profile;
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
        let view_dir = data_dir.join("view");
        let fresh_dir = is_empty_dir(&data_dir)?;
        private_dir(&objects_dir)?;
        let fs: Arc<dyn Objects> =
            Arc::new(FsObjects::open(&objects_dir).map_err(|e| match e {
                OpenError::Locked { .. } => BuildError::Locked,
                OpenError::Io(_) => BuildError::DataDir,
            })?);
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

        let record = if has_record {
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
            let roster = baton_identity::Roster::genesis(
                &me,
                baton_core::GroupId::new(group.clone()).map_err(|_| BuildError::Storage)?,
            );
            objects
                .put(
                    &ObjectKey::parse("system/roster").expect("constant"),
                    Bytes::from(roster.to_bytes()),
                    Expect::Any,
                )
                .await?;
            let record = NodeRecord {
                v: records::FORMAT,
                node: node_id.clone(),
                group,
                profile: self.profile.name().into(),
                created_at: self.clock.now_ms(),
            };
            objects
                .put(
                    &record_key,
                    Bytes::from(records::encode_node_record(&record)),
                    Expect::Absent,
                )
                .await?;
            info!(node = %node_id, "node created");
            record
        };
        let tenant = TenantId::new(record.group.clone()).map_err(|_| BuildError::Storage)?;

        private_dir(&view_dir)?;
        let store =
            Arc::new(Store::open(&view_dir.join("view.sqlite")).map_err(|_| BuildError::Database)?);
        let storage = Storage::over(objects.clone());
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
        let signal: Arc<dyn baton_signal::Signal> =
            Arc::new(baton_signal_local::LocalSignal::new());
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
            hub: Hub::new(),
            overlay: Arc::new(Overlay::default()),
            sends: Arc::new(Sends::default()),
            clock: self.clock,
            chores: chores_tx,
            statuses: Mutex::default(),
            removing: Mutex::default(),
            notify_rate: Mutex::default(),
            synced: Arc::default(),
            leases: std::sync::OnceLock::new(),
        });
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
