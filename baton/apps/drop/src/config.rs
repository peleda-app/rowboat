//! The service's configuration: a TOML file, with a few settings also taken from flags.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::ServiceError;

/// The whole configuration. Every field but `realm` has a default.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Where to listen (default `127.0.0.1:8470`, for a reverse proxy in front).
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// The data directory: holds `drop.redb` (default `./drop-data`).
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// The realm requests are signed for: the public host name clients configure.
    pub realm: String,
    /// Who may create boxes.
    #[serde(default)]
    pub admission: AdmissionSection,
    /// Service and store limits.
    #[serde(default)]
    pub limits: LimitsSection,
    /// HTTP limits.
    #[serde(default)]
    pub http: HttpSection,
    /// TLS; without it, serve plain HTTP behind a TLS-terminating reverse proxy.
    #[serde(default)]
    pub tls: Option<TlsSection>,
    /// How often expired messages and idle boxes are removed, in seconds (default 300).
    #[serde(default = "default_sweep")]
    pub sweep_secs: u64,
}

/// Who may create boxes; at least one of the three must be set.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionSection {
    /// Admit every creation (only for a private deployment behind other access control).
    #[serde(default)]
    pub open: bool,
    /// A file with one operator token per line (each 16 to 256 bytes); keep it `0600`.
    #[serde(default)]
    pub tokens_file: Option<PathBuf>,
    /// Proof of work: leading zero bits required (1 to 24; 0 turns it off).
    #[serde(default)]
    pub work_difficulty: u8,
    /// Proof of work: argon2id memory in KiB (8 to 4096, default 1024).
    #[serde(default = "default_work_memory")]
    pub work_memory_kib: u32,
    /// Proof of work: argon2id passes (1 to 3, default 1).
    #[serde(default = "default_work_passes")]
    pub work_passes: u32,
}

impl Default for AdmissionSection {
    fn default() -> Self {
        Self {
            open: false,
            tokens_file: None,
            work_difficulty: 0,
            work_memory_kib: default_work_memory(),
            work_passes: default_work_passes(),
        }
    }
}

/// Service and store limits; defaults are those of `DropConfig::new` and `StoreLimits`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsSection {
    /// The largest message in bytes (default 65,536, at most 1 MiB).
    pub max_message: u32,
    /// The largest byte quota a box may ask for (default 64 MiB).
    pub max_box_bytes: u64,
    /// The largest message quota a box may ask for (default 10,000).
    pub max_box_messages: u32,
    /// The longest time-to-live a box may ask for, in days (default and at most 30).
    pub max_ttl_days: u64,
    /// The longest long poll, in seconds (default 30, at most 300).
    pub max_wait_secs: u64,
    /// Long polls waiting at once (default 10,000).
    pub max_waiters: usize,
    /// Boxes kept at once (default 100,000).
    pub max_boxes: u64,
    /// Message bytes kept at once (default 8 GiB).
    pub max_total_bytes: u64,
    /// The largest byte quota a box created by proof of work or on an open service may ask for
    /// (default 1 MiB, at most `max_box_bytes`).
    pub untrusted_box_bytes: u64,
    /// The largest message quota such a box may ask for (default 1,000).
    pub untrusted_box_messages: u32,
    /// The longest time-to-live such a box may ask for, in days (default 7).
    pub untrusted_ttl_days: u64,
    /// Of `max_boxes`, how many such boxes are kept at once (default 50,000).
    pub max_untrusted_boxes: u64,
    /// Of `max_total_bytes`, how many bytes such boxes hold together (default 2 GiB).
    pub max_untrusted_total_bytes: u64,
}

impl Default for LimitsSection {
    fn default() -> Self {
        let store = crate::StoreLimits::default();
        Self {
            max_message: baton_mailbox::DEFAULT_MAX_MESSAGE as u32,
            max_box_bytes: 64 * 1024 * 1024,
            max_box_messages: 10_000,
            max_ttl_days: 30,
            max_wait_secs: 30,
            max_waiters: 10_000,
            max_boxes: store.max_boxes,
            max_total_bytes: store.max_bytes,
            untrusted_box_bytes: 1024 * 1024,
            untrusted_box_messages: 1_000,
            untrusted_ttl_days: 7,
            max_untrusted_boxes: store.max_untrusted_boxes,
            max_untrusted_total_bytes: store.max_untrusted_bytes,
        }
    }
}

/// HTTP limits; defaults are those of `baton_drop_http::HttpConfig`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpSection {
    /// Seconds a client may take to send headers or finish a TLS handshake (default 10).
    pub header_timeout_secs: u64,
    /// Seconds a client may take to send a body (default 10).
    pub body_timeout_secs: u64,
    /// Seconds a connection's reply may make no progress before it is closed (default 30).
    pub write_timeout_secs: u64,
    /// Connections at once (default 4,096).
    pub max_connections: usize,
    /// Connections at once from one client address (IPv4 address or IPv6 /64), unless behind a
    /// proxy (default 64).
    pub max_connections_per_client: usize,
    /// Requests in flight at once, long polls not included (default 2,048).
    pub max_in_flight: usize,
    /// Long polls waiting at once; further takes return at once (default 1,024).
    pub max_polls: usize,
    /// Requests per second per client (IPv4 address or IPv6 /64); 0 turns rate limiting off
    /// (default 20).
    pub rate_per_second: u32,
    /// Burst per client (default 100).
    pub rate_burst: u32,
    /// Requests in flight per client (default 16).
    pub per_client_in_flight: u32,
    /// Long polls waiting per client (default 4).
    pub per_client_polls: u32,
    /// Clients tracked for rate limiting (default 65,536).
    pub max_tracked_clients: usize,
    /// Take the client address from `X-Forwarded-For` (only behind a proxy that sets it).
    pub behind_proxy: bool,
}

impl Default for HttpSection {
    fn default() -> Self {
        let h = baton_drop_http::HttpConfig::default();
        let r = baton_drop_http::RateLimit::default();
        Self {
            header_timeout_secs: h.header_timeout.as_secs(),
            body_timeout_secs: h.body_timeout.as_secs(),
            write_timeout_secs: h.write_timeout.as_secs(),
            max_connections: h.max_connections,
            max_connections_per_client: h.max_connections_per_client,
            max_in_flight: h.max_in_flight,
            max_polls: h.max_polls,
            rate_per_second: r.per_second,
            rate_burst: r.burst,
            per_client_in_flight: r.in_flight,
            per_client_polls: r.polls,
            max_tracked_clients: r.max_tracked,
            behind_proxy: false,
        }
    }
}

/// Certificate chain and private key, PEM files.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSection {
    /// The certificate chain.
    pub cert: PathBuf,
    /// The private key; keep it `0600`.
    pub key: PathBuf,
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8470))
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("drop-data")
}

fn default_sweep() -> u64 {
    300
}

fn default_work_memory() -> u32 {
    1024
}

fn default_work_passes() -> u32 {
    1
}

impl Config {
    /// Parses a TOML configuration.
    pub fn parse(text: &str) -> Result<Self, ServiceError> {
        toml::from_str(text).map_err(|e| ServiceError::Config(e.message().to_owned()))
    }

    /// Reads and parses a TOML file.
    pub fn load(path: &Path) -> Result<Self, ServiceError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ServiceError::Config(format!("cannot read config: {e}")))?;
        Self::parse(&text)
    }

    /// The configuration from command-line arguments (without the program name):
    /// `--config FILE`, `--listen ADDR`, `--data-dir DIR`, `--realm NAME`, `--tokens-file FILE`,
    /// `--open`. Flags override the file.
    pub fn from_args(args: impl IntoIterator<Item = String>) -> Result<Self, ServiceError> {
        let mut file = None;
        let mut over: Vec<(String, String)> = Vec::new();
        let mut open = false;
        let mut it = args.into_iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--open" => open = true,
                "--config" | "--listen" | "--data-dir" | "--realm" | "--tokens-file" => {
                    let v = it
                        .next()
                        .ok_or_else(|| ServiceError::Config(format!("{a} needs a value")))?;
                    if a == "--config" {
                        file = Some(PathBuf::from(v));
                    } else {
                        over.push((a, v));
                    }
                }
                other => return Err(ServiceError::Config(format!("unknown argument {other}"))),
            }
        }
        let mut config = match file {
            Some(f) => Self::load(&f)?,
            None => {
                let realm = over
                    .iter()
                    .find(|(k, _)| k == "--realm")
                    .map(|(_, v)| v.clone())
                    .ok_or_else(|| {
                        ServiceError::Config("--realm or --config is required".into())
                    })?;
                Self::parse(&format!("realm = {}", toml_string(&realm)))?
            }
        };
        for (k, v) in over {
            match k.as_str() {
                "--listen" => {
                    config.listen = v
                        .parse()
                        .map_err(|_| ServiceError::Config("bad --listen address".into()))?
                }
                "--data-dir" => config.data_dir = PathBuf::from(v),
                "--realm" => config.realm = v,
                "--tokens-file" => config.admission.tokens_file = Some(PathBuf::from(v)),
                _ => {}
            }
        }
        config.admission.open |= open;
        Ok(config)
    }

    /// The sweep interval.
    pub fn sweep_every(&self) -> Duration {
        Duration::from_secs(self.sweep_secs.max(1))
    }
}

fn toml_string(s: &str) -> String {
    let escaped: String = s
        .chars()
        .flat_map(|c| match c {
            '"' => vec!['\\', '"'],
            '\\' => vec!['\\', '\\'],
            c if c.is_control() => vec![],
            c => vec![c],
        })
        .collect();
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_and_full_files() {
        let c = Config::parse("realm = \"drop.example.com\"").unwrap();
        assert_eq!(c.listen, default_listen());
        assert_eq!(c.limits.max_message, 65_536);
        assert_eq!(c.http.rate_per_second, 20);
        assert!(c.tls.is_none());
        let c = Config::parse("realm = \"a\"\n[limits]\nmax_boxes = 5\n[http]\nrate_burst = 7")
            .unwrap();
        assert_eq!((c.limits.max_boxes, c.limits.max_message), (5, 65_536));
        assert_eq!((c.http.rate_burst, c.http.rate_per_second), (7, 20));
        let full = r#"
            listen = "0.0.0.0:443"
            data_dir = "/var/lib/baton-drop"
            realm = "drop.example.com"
            sweep_secs = 60
            [admission]
            tokens_file = "/etc/baton-drop/tokens"
            work_difficulty = 12
            [limits]
            max_message = 131072
            max_box_bytes = 1048576
            max_box_messages = 100
            max_ttl_days = 14
            max_wait_secs = 20
            max_waiters = 100
            max_boxes = 10
            max_total_bytes = 1073741824
            [http]
            header_timeout_secs = 5
            body_timeout_secs = 5
            max_connections = 100
            max_in_flight = 50
            rate_per_second = 5
            rate_burst = 10
            per_client_in_flight = 4
            max_tracked_clients = 1000
            behind_proxy = true
            [tls]
            cert = "/etc/baton-drop/cert.pem"
            key = "/etc/baton-drop/key.pem"
        "#;
        let c = Config::parse(full).unwrap();
        assert_eq!(c.admission.work_difficulty, 12);
        assert_eq!(c.admission.work_memory_kib, 1024);
        assert!(c.http.behind_proxy);
        assert_eq!(
            c.tls.unwrap().cert,
            PathBuf::from("/etc/baton-drop/cert.pem")
        );
    }

    #[test]
    fn unknown_or_missing_fields_are_refused() {
        assert!(Config::parse("").is_err());
        assert!(Config::parse("realm = \"a\"\nrelm = \"b\"").is_err());
        assert!(Config::parse("realm = \"a\"\n[limits]\nmax_mesage = 1").is_err());
    }

    #[test]
    fn flags_override_the_file() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let c = Config::from_args(args(&[
            "--realm",
            "drop.example.org",
            "--listen",
            "127.0.0.1:9000",
            "--open",
        ]))
        .unwrap();
        assert_eq!(c.realm, "drop.example.org");
        assert_eq!(c.listen.port(), 9000);
        assert!(c.admission.open);
        assert!(Config::from_args(args(&["--listen", "127.0.0.1:1"])).is_err());
        assert!(Config::from_args(args(&["--realm"])).is_err());
        assert!(Config::from_args(args(&["--bogus"])).is_err());
        let c = Config::from_args(args(&["--realm", "a\"b\\c"])).unwrap();
        assert_eq!(c.realm, "a\"b\\c");
    }
}
