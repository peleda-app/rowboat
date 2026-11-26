//! The drop service: `baton-drop`'s rules over a redb store ([`RedbDropStore`]), served over
//! HTTP/1.1 by `baton-drop-http`, with optional TLS, an expiry sweeper and graceful shutdown.
//!
//! [`start`] runs it in the current tokio runtime (the `drop` binary, `batond` and tests use it);
//! [`Config`] is its configuration.

pub mod config;
pub mod store;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use baton_drop::admission::{AdmissionConfig, WorkParams};
use baton_drop::{Clock, DropConfig, DropService, StoreError};
use baton_drop_http::{ClientIp, HttpConfig, RateLimit};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};
use zeroize::Zeroizing;

pub use config::Config;
pub use store::{RedbDropStore, StoreLimits};

/// The file the store lives in, inside the data directory.
pub const STORE_FILE: &str = "drop.redb";

const WORK_SALT: &str = "work_salt";

/// Why the service could not start.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// The configuration is invalid.
    #[error("configuration: {0}")]
    Config(String),
    /// The store failed.
    #[error("store: {0}")]
    Store(#[from] StoreError),
    /// A file or socket operation failed.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    /// The TLS certificate or key is unusable.
    #[error("tls: {0}")]
    Tls(String),
}

fn config_err(e: impl std::fmt::Display) -> ServiceError {
    ServiceError::Config(e.to_string())
}

#[cfg(unix)]
fn private_dir(path: &Path) -> Result<(), ServiceError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn private_dir(path: &Path) -> Result<(), ServiceError> {
    std::fs::create_dir_all(path)?;
    Ok(())
}

#[cfg(unix)]
fn private_file(path: &Path) -> Result<(), ServiceError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn private_file(_: &Path) -> Result<(), ServiceError> {
    Ok(())
}

/// Reads a secret file, refusing one readable by group or others.
pub fn read_secret_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, ServiceError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(ServiceError::Config(format!(
                "{} must not be readable by group or others (chmod 600)",
                path.display()
            )));
        }
    }
    Ok(Zeroizing::new(std::fs::read(path)?))
}

/// The admission `config` describes; a proof-of-work salt is generated once and kept in `store`.
pub fn admission(
    config: &config::AdmissionSection,
    store: &RedbDropStore,
) -> Result<AdmissionConfig, ServiceError> {
    let mut a = if config.open {
        AdmissionConfig::open()
    } else {
        AdmissionConfig::closed()
    };
    let mut any = config.open;
    if let Some(path) = &config.tokens_file {
        let raw = read_secret_file(path)?;
        for line in raw.split(|b| *b == b'\n') {
            let t = line.trim_ascii();
            if t.is_empty() || t.starts_with(b"#") {
                continue;
            }
            a = a.with_token(t).map_err(config_err)?;
            any = true;
        }
    }
    if config.work_difficulty > 0 {
        let salt = match store.setting(WORK_SALT)? {
            Some(s) => s,
            None => {
                let fresh = WorkParams::generate(1, 8, 1).map_err(config_err)?.salt;
                store.set_setting(WORK_SALT, &fresh)?;
                fresh
            }
        };
        let work = WorkParams {
            salt,
            difficulty: config.work_difficulty,
            m_cost_kib: config.work_memory_kib,
            t_cost: config.work_passes,
        };
        a = a.with_work(work).map_err(config_err)?;
        any = true;
    }
    if !any {
        return Err(ServiceError::Config(
            "admission needs open, tokens_file or work_difficulty".into(),
        ));
    }
    Ok(a)
}

/// The service settings `config` describes.
pub fn drop_config(config: &Config, admission: AdmissionConfig) -> DropConfig {
    let l = &config.limits;
    let mut d = DropConfig::new(config.realm.clone(), admission);
    d.max_message = l.max_message;
    d.max_take_bytes = d.max_take_bytes.max(l.max_message);
    d.max_box_bytes = l.max_box_bytes;
    d.max_box_messages = l.max_box_messages;
    d.max_ttl_ms = l.max_ttl_days.saturating_mul(24 * 3600 * 1000);
    d.max_wait = Duration::from_secs(l.max_wait_secs);
    d.max_waiters = l.max_waiters;
    d.untrusted = baton_drop::service::BoxLimits {
        max_box_bytes: l.untrusted_box_bytes.min(d.max_box_bytes),
        max_box_messages: l.untrusted_box_messages.min(d.max_box_messages),
        max_ttl_ms: l
            .untrusted_ttl_days
            .saturating_mul(24 * 3600 * 1000)
            .min(d.max_ttl_ms),
    };
    d
}

/// The HTTP limits `config` describes.
pub fn http_config(config: &Config) -> HttpConfig {
    let h = &config.http;
    HttpConfig {
        header_timeout: Duration::from_secs(h.header_timeout_secs.max(1)),
        body_timeout: Duration::from_secs(h.body_timeout_secs.max(1)),
        max_connections: h.max_connections,
        max_connections_per_client: h.max_connections_per_client.max(1),
        max_in_flight: h.max_in_flight,
        max_polls: h.max_polls,
        write_timeout: Duration::from_secs(h.write_timeout_secs.max(1)),
        rate: (h.rate_per_second > 0).then_some(RateLimit {
            per_second: h.rate_per_second,
            burst: h.rate_burst.max(1),
            in_flight: h.per_client_in_flight.max(1),
            polls: h.per_client_polls.max(1),
            max_tracked: h.max_tracked_clients.max(1),
        }),
        client_ip: if h.behind_proxy {
            ClientIp::ForwardedFor
        } else {
            ClientIp::Peer
        },
        shutdown_grace: Duration::from_secs(config.limits.max_wait_secs + 5),
        ..HttpConfig::default()
    }
}

/// A TLS server configuration from PEM files (HTTP/1.1 only).
pub fn tls_config(tls: &config::TlsSection) -> Result<Arc<rustls::ServerConfig>, ServiceError> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let certs = CertificateDer::pem_file_iter(&tls.cert)
        .map_err(|e| ServiceError::Tls(format!("certificate: {e}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ServiceError::Tls(format!("certificate: {e}")))?;
    if certs.is_empty() {
        return Err(ServiceError::Tls("no certificate in file".into()));
    }
    let key_pem = read_secret_file(&tls.key)?;
    let key = PrivateKeyDer::from_pem_slice(&key_pem)
        .map_err(|e| ServiceError::Tls(format!("key: {e}")))?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut c = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| ServiceError::Tls(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ServiceError::Tls(e.to_string()))?;
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(c))
}

/// A running service.
pub struct Running {
    /// The address it listens on.
    pub addr: SocketAddr,
    /// The service (to share with other parts of the process).
    pub service: Arc<DropService>,
    /// The store under it.
    pub store: Arc<RedbDropStore>,
    stop: watch::Sender<bool>,
    server: JoinHandle<()>,
    sweeper: JoinHandle<()>,
}

impl Running {
    /// Stops accepting, lets requests in flight finish (up to the longest wait plus 5 s) and
    /// returns once the server is down.
    pub async fn stop(self) {
        let _ = self.stop.send(true);
        let _ = self.server.await;
        self.sweeper.abort();
        let _ = self.sweeper.await;
    }
}

/// Opens the store in `config.data_dir` (created `0700`, the file `0600`), checks the
/// configuration, binds `config.listen` and serves until [`Running::stop`]. `clock` judges
/// freshness, time-to-live and rate limits.
pub async fn start(config: &Config, clock: Clock) -> Result<Running, ServiceError> {
    private_dir(&config.data_dir)?;
    let path = config.data_dir.join(STORE_FILE);
    let limits = StoreLimits {
        max_boxes: config.limits.max_boxes,
        max_bytes: config.limits.max_total_bytes,
        max_untrusted_boxes: config.limits.max_untrusted_boxes,
        max_untrusted_bytes: config.limits.max_untrusted_total_bytes,
        ..StoreLimits::default()
    };
    let store = {
        let path = path.clone();
        tokio::task::spawn_blocking(move || RedbDropStore::open(&path, limits))
            .await
            .map_err(|e| ServiceError::Io(std::io::Error::other(e)))??
    };
    private_file(&path)?;
    let admission = admission(&config.admission, &store)?;
    let store = Arc::new(store);
    let service = Arc::new(
        DropService::new(store.clone(), drop_config(config, admission), clock.clone())
            .map_err(config_err)?,
    );
    let tls = config.tls.as_ref().map(tls_config).transpose()?;
    let http = http_config(config);
    let listener = TcpListener::bind(config.listen).await?;
    let addr = listener.local_addr()?;
    let router = baton_drop_http::router(service.clone(), http.clone(), clock);
    let (stop, rx) = watch::channel(false);
    let mut server_rx = rx.clone();
    let server = tokio::spawn(async move {
        baton_drop_http::serve(listener, router, &http, tls, async move {
            let _ = server_rx.wait_for(|s| *s).await;
        })
        .await
    });
    let sweeper = tokio::spawn(sweep(service.clone(), config.sweep_every(), rx));
    Ok(Running {
        addr,
        service,
        store,
        stop,
        server,
        sweeper,
    })
}

async fn sweep(service: Arc<DropService>, every: Duration, mut stop: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            () = tokio::time::sleep(every) => {}
            _ = stop.wait_for(|s| *s) => return,
        }
        match service.sweep().await {
            Ok(n) => info!(removed = n, "swept expired messages and idle boxes"),
            Err(e) => warn!(error = %e, "sweep failed"),
        }
    }
}
