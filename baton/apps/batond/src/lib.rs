//! `batond`: the headless node for a server in the blind role.
//!
//! It holds the logs of the groups it is configured for ([`baton_group_server`], protocol
//! `group`), arbitrates their leases ([`baton_lease_server`], protocol `lease`) with
//! authorization derived from those logs ([`Rules`]), and runs the drop service
//! ([`baton_drop_service`]) in the same process. It holds no resource key and its node has no
//! capability: it never sees plaintext and cannot command anything.
//!
//! [`Core`] is the part that does not depend on the transport or the disk (tests run it over
//! `baton-link-memory`); [`start`] composes it with an iroh link, a redb store in the data
//! directory, the node key file and the drop service.

pub mod config;
pub mod key;
pub mod lease_ttl;
pub mod rules;
pub mod state;

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use baton_core::{GroupId, Timestamp};
use baton_group_server::{GroupLogs, GroupServer, LogLimits};
use baton_identity::PublicKey;
use baton_lease_server::LeaseServer;
use baton_link::{Link, LinkError, RelayUrl, Trust};
use baton_link_iroh::{IrohConfig, IrohLink, PostQuantum};
use baton_state::StateStore;

pub use config::Config;
pub use rules::{Rules, resource_of};
pub use state::RedbState;

/// The state store file inside the data directory.
pub const STATE_FILE: &str = "state.redb";

/// The most entries batond keeps per group log from anyone.
pub const MAX_ENTRIES: u64 = 100_000;

/// The most encoded entry bytes batond keeps per group log from anyone.
pub const MAX_LOG_BYTES: u64 = 256 * 1024 * 1024;

/// Entries batond keeps beyond those limits for revocations by admins, owners and recovery keys.
pub const LOG_RESERVE: u64 = 1_000;

/// Why batond could not start.
#[derive(Debug, thiserror::Error)]
pub enum BatondError {
    /// The configuration is invalid.
    #[error("configuration: {0}")]
    Config(String),
    /// A group log in the store failed to load.
    #[error("group log: {0}")]
    Group(#[from] baton_group::GroupError),
    /// The state store failed.
    #[error("state store: {0}")]
    State(#[from] baton_state::StateError),
    /// The link failed.
    #[error("link: {0}")]
    Link(#[from] LinkError),
    /// The drop service failed to start.
    #[error("drop: {0}")]
    Drop(#[from] baton_drop_service::ServiceError),
    /// A file operation failed.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}

/// A wall clock.
pub type Clock = Arc<dyn Fn() -> Timestamp + Send + Sync>;

/// The clocks batond decides on.
#[derive(Clone)]
pub struct Clocks {
    /// Wall time: certificate expiry, entries from the future.
    pub wall: Clock,
    /// Lease time: never goes back (`baton_lease_cas::monotonic_clock()` in production).
    pub lease: Clock,
}

impl Clocks {
    /// The system's clocks.
    pub fn system() -> Self {
        Self {
            wall: Arc::new(Timestamp::now),
            lease: baton_lease_cas::monotonic_clock(),
        }
    }
}

/// The held group logs and the rules derived from them, before any transport.
pub struct Core {
    logs: Arc<GroupLogs>,
    rules: Arc<Rules>,
    state: Arc<dyn StateStore>,
    clocks: Clocks,
}

impl Core {
    /// Loads the logs of `groups` (each pinned to its genesis hash) from `state` and derives the
    /// rules, with per-group `bootstrap` peers. Fails if the store holds a log that does not
    /// verify or has another genesis.
    pub async fn open(
        state: Arc<dyn StateStore>,
        groups: Vec<(GroupId, [u8; 32])>,
        bootstrap: BTreeMap<GroupId, BTreeSet<PublicKey>>,
        clocks: Clocks,
    ) -> Result<Self, BatondError> {
        let logs = Arc::new(GroupLogs::with_limits(
            groups,
            state.clone(),
            LogLimits {
                max_entries: MAX_ENTRIES,
                max_bytes: MAX_LOG_BYTES,
                reserve: LOG_RESERVE,
            },
        ));
        logs.load().await?;
        let rules = Arc::new(Rules::new(logs.clone(), bootstrap, clocks.wall.clone()));
        Ok(Self {
            logs,
            rules,
            state,
            clocks,
        })
    }

    /// The trust the link must be built with: counting nodes and bootstrap peers of held groups.
    pub fn trust(&self) -> Arc<dyn Trust> {
        self.rules.clone()
    }

    /// The held logs.
    pub fn logs(&self) -> Arc<GroupLogs> {
        self.logs.clone()
    }

    /// The rules.
    pub fn rules(&self) -> Arc<Rules> {
        self.rules.clone()
    }

    /// Serves the logs (protocol `group`) and leases (protocol `lease`) on `link`, which must
    /// have been built with [`Core::trust`].
    pub async fn serve(
        &self,
        link: Arc<dyn Link>,
        lease: baton_lease_server::ServerConfig,
    ) -> Result<Servers, BatondError> {
        let group = GroupServer::start(
            link.clone(),
            self.logs.clone(),
            self.rules.clone(),
            self.clocks.wall.clone(),
            baton_group_server::ServerConfig::default(),
        )
        .await?;
        let lease = LeaseServer::start(
            link,
            self.state.clone(),
            self.rules.clone(),
            self.clocks.lease.clone(),
            lease,
        )
        .await?;
        Ok(Servers { group, lease })
    }
}

/// The servers on one link.
pub struct Servers {
    group: GroupServer,
    lease: LeaseServer,
}

impl Servers {
    /// Stops both and severs their streams.
    pub async fn stop(self) {
        self.group.stop().await;
        self.lease.stop().await;
    }
}

/// A running batond.
pub struct Running {
    /// This node's key (pin it in members' configuration; certify it as a blind node).
    pub node: PublicKey,
    /// The local addresses the iroh endpoint is bound to.
    pub addrs: Vec<SocketAddr>,
    /// The drop service's address, when it runs.
    pub drop_addr: Option<SocketAddr>,
    link: Arc<IrohLink>,
    servers: Servers,
    drop: Option<baton_drop_service::Running>,
}

impl Running {
    /// Stops serving: severs group and lease streams, closes the link, then lets the drop
    /// service finish requests in flight.
    pub async fn stop(self) {
        self.servers.stop().await;
        self.link.close().await;
        if let Some(d) = self.drop {
            d.stop().await;
        }
    }
}

#[cfg(unix)]
fn private_dir(path: &Path) -> Result<(), BatondError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn private_dir(path: &Path) -> Result<(), BatondError> {
    std::fs::create_dir_all(path)?;
    Ok(())
}

#[cfg(unix)]
fn private_file(path: &Path) -> Result<(), BatondError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn private_file(_: &Path) -> Result<(), BatondError> {
    Ok(())
}

/// The iroh configuration `config` describes.
pub fn iroh_config(config: &config::IrohSection) -> Result<IrohConfig, BatondError> {
    Ok(IrohConfig {
        relays: config
            .relays
            .iter()
            .map(|r| RelayUrl::new(r))
            .collect::<Result<_, _>>()?,
        bind: config.bind.clone(),
        post_quantum: if config.allow_classical {
            PostQuantum::Preferred
        } else {
            PostQuantum::Required
        },
        ..IrohConfig::default()
    })
}

/// Starts batond: the data directory (created `0700`) with the node key (`node.key`, `0600`,
/// created on first start) and the state store (`state.redb`, `0600`), the group logs loaded and
/// checked against their pinned genesis, an iroh endpoint trusting exactly the counting nodes
/// and bootstrap peers of held groups, the group and lease servers on it, and the drop service
/// when configured.
pub async fn start(config: &Config, clocks: Clocks) -> Result<Running, BatondError> {
    private_dir(&config.data_dir)?;
    let identity = key::load_or_create(&config.data_dir.join(key::KEY_FILE))?;
    let path = config.data_dir.join(STATE_FILE);
    let state = {
        let path = path.clone();
        tokio::task::spawn_blocking(move || RedbState::open(&path))
            .await
            .map_err(|e| BatondError::Io(std::io::Error::other(e)))??
    };
    private_file(&path)?;
    let state: Arc<dyn StateStore> = Arc::new(state);
    let core = Core::open(
        state,
        config.genesis()?,
        config.bootstrap()?,
        clocks.clone(),
    )
    .await?;
    let previous_ttl_ms = lease_ttl::advance(
        &config.data_dir.join(lease_ttl::TTL_FILE),
        config.lease.ttl_ms,
        (clocks.wall)().0,
    )?;
    let link = Arc::new(IrohLink::bind(&identity, core.trust(), iroh_config(&config.iroh)?).await?);
    let servers = core
        .serve(
            link.clone(),
            baton_lease_server::ServerConfig {
                ttl_ms: config.lease.ttl_ms,
                previous_ttl_ms,
                ..baton_lease_server::ServerConfig::default()
            },
        )
        .await?;
    let drop = match &config.drop {
        Some(d) => Some(baton_drop_service::start(d, clocks.wall.clone()).await?),
        None => None,
    };
    Ok(Running {
        node: identity.public(),
        addrs: link.bound_addrs(),
        drop_addr: drop.as_ref().map(|d| d.addr),
        link,
        servers,
        drop,
    })
}
