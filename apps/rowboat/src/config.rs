//! The server's configuration file (TOML). Secrets never go into it: S3 keys and the Gmail push
//! secret are read from the environment variables a `*_env` key names.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

/// The default path of the configuration file, overridden by `--config` or `ROWBOAT_CONFIG`.
pub const DEFAULT_PATH: &str = "/etc/rowboat/rowboat.toml";

/// The most ports a range may hold.
pub const MAX_PORTS: u32 = 10_000;

/// Why a configuration was refused. Names the setting, never a secret.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("cannot read the configuration file")]
    Read,
    /// The file does not parse or names an unknown setting.
    #[error("the configuration does not parse: {0}")]
    Parse(String),
    /// A setting is out of its rules.
    #[error("{0}")]
    Invalid(String),
}

fn invalid(text: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(text.into())
}

/// The whole file.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Where tenants' data lives: `tenants/{id}/` (the node's sealed objects, the tenant's
    /// record and binding) and `host/` (the host lock, the push registry and the status file).
    pub data_dir: PathBuf,
    /// Where tenants' node keys live, one directory per tenant, apart from the data so that a
    /// copy of the data alone opens nothing.
    pub secrets_dir: PathBuf,
    /// Where tenants' mail databases live; cleared for a tenant every time its node starts or
    /// stops and rebuilt from the sealed journal. `<data_dir>/cache` by default, where a crash
    /// leaves mail in the clear in the data volume until the next start (`serve` warns); a
    /// memory file system outside the data directory is best.
    #[serde(default)]
    pub cache_dir: Option<PathBuf>,
    /// Whether `rowboat serve` on a host with no tenant creates one and prints its invite.
    #[serde(default = "yes")]
    pub first_run_invite: bool,
    /// The tenants' links.
    #[serde(default)]
    pub link: LinkConfig,
    /// The inbound HTTP listener: provider push and `GET /v1/health`.
    #[serde(default)]
    pub listener: ListenerConfig,
    /// Keeps every tenant's objects in an S3 bucket instead of `data_dir`.
    #[serde(default)]
    pub s3: Option<S3Config>,
    /// Logging.
    #[serde(default)]
    pub logs: LogConfig,
    /// Shutdown.
    #[serde(default)]
    pub shutdown: ShutdownConfig,
    /// Test roots for the container suite's image (feature `test-roots`).
    #[serde(default)]
    pub tls: TlsConfig,
}

fn yes() -> bool {
    true
}

/// Where tenants' links listen and how devices reach them.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LinkConfig {
    /// The address every endpoint binds; `0.0.0.0` by default.
    #[serde(default = "any_ip")]
    pub bind: IpAddr,
    /// UDP ports, `"4400-4499"`: each tenant keeps one for its link, pairing endpoints take free
    /// ones. `"any"` binds random ports (hosts without port mapping; a tenant's address then
    /// changes on every start).
    #[serde(default = "default_ports")]
    pub ports: String,
    /// Addresses devices dial, put in every hint: an IP (the endpoint's own port is added) or
    /// `ip:port`. Without one, only a relay reaches the server.
    #[serde(default)]
    pub advertise: Vec<String>,
    /// Relays the links keep a home connection to (`https://`, or `http://` on loopback).
    #[serde(default)]
    pub relays: Vec<String>,
}

fn any_ip() -> IpAddr {
    IpAddr::from([0, 0, 0, 0])
}

fn default_ports() -> String {
    "4400-4499".into()
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            bind: any_ip(),
            ports: default_ports(),
            advertise: Vec::new(),
            relays: Vec::new(),
        }
    }
}

/// A port range, both ends included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ports {
    /// The first port.
    pub first: u16,
    /// The last port.
    pub last: u16,
}

impl Ports {
    /// Every port of the range in order.
    pub fn iter(&self) -> impl Iterator<Item = u16> {
        self.first..=self.last
    }

    /// Whether `port` is in the range.
    pub fn contains(&self, port: u16) -> bool {
        (self.first..=self.last).contains(&port)
    }
}

impl LinkConfig {
    /// The port range, `None` for `"any"`.
    pub fn port_range(&self) -> Result<Option<Ports>, ConfigError> {
        if self.ports == "any" {
            return Ok(None);
        }
        let bad =
            || invalid("link.ports must be \"any\" or \"first-last\" with 1 <= first <= last");
        let (a, b) = self.ports.split_once('-').ok_or_else(bad)?;
        let first: u16 = a.trim().parse().map_err(|_| bad())?;
        let last: u16 = b.trim().parse().map_err(|_| bad())?;
        if first == 0 || first > last {
            return Err(bad());
        }
        if u32::from(last - first) + 1 > MAX_PORTS {
            return Err(invalid(format!(
                "link.ports holds more than {MAX_PORTS} ports"
            )));
        }
        Ok(Some(Ports { first, last }))
    }

    /// The advertised addresses; a port of `0` stands for the endpoint's own.
    pub fn advertised(&self) -> Result<Vec<SocketAddr>, ConfigError> {
        self.advertise
            .iter()
            .map(|a| {
                if let Ok(ip) = a.parse::<IpAddr>() {
                    return Ok(SocketAddr::new(ip, 0));
                }
                a.parse::<SocketAddr>().map_err(|_| {
                    invalid("link.advertise holds an entry that is not an IP or ip:port")
                })
            })
            .collect()
    }

    /// The relays.
    pub fn relay_urls(&self) -> Result<Vec<baton_link::RelayUrl>, ConfigError> {
        self.relays
            .iter()
            .map(|r| {
                let loopback = ["http://127.0.0.1", "http://[::1]", "http://localhost"]
                    .iter()
                    .any(|p| r.starts_with(p));
                if !r.starts_with("https://") && !loopback {
                    return Err(invalid("link.relays must be https (or http on loopback)"));
                }
                baton_link::RelayUrl::new(r)
                    .map_err(|_| invalid("link.relays holds an address that is not a relay URL"))
            })
            .collect()
    }
}

/// The inbound HTTP listener of `skein-server`.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    /// Whether to listen at all.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Where; `0.0.0.0:8080` by default.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Where providers reach the listener, `https://...`; needed for push.
    #[serde(default)]
    pub public_url: Option<String>,
    /// Push requests accepted per second over the listener.
    #[serde(default = "default_rate")]
    pub push_rate_per_second: u32,
    /// Provider push.
    #[serde(default)]
    pub push: PushConfig,
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 8080))
}

fn default_rate() -> u32 {
    100
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: default_listen(),
            public_url: None,
            push_rate_per_second: default_rate(),
            push: PushConfig::default(),
        }
    }
}

/// Provider push through the listener.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PushConfig {
    /// Subscribes accounts whose provider pushes (needs `listener.public_url`).
    #[serde(default)]
    pub enabled: bool,
    /// The Pub/Sub topic Gmail publishes to.
    #[serde(default)]
    pub gmail_topic: Option<String>,
    /// The environment variable holding the secret of the Gmail push address.
    #[serde(default)]
    pub gmail_token_env: Option<String>,
    /// Also require Pub/Sub's OIDC token for this audience.
    #[serde(default)]
    pub gmail_oidc_audience: Option<String>,
    /// ... signed for this service account.
    #[serde(default)]
    pub gmail_oidc_email: Option<String>,
}

/// An S3-compatible bucket for tenants' objects (`{prefix}/tenants/{id}/...`), sealed as on disk.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct S3Config {
    /// The endpoint for stores other than AWS S3.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// The bucket; it must exist.
    pub bucket: String,
    /// The region.
    #[serde(default = "default_region")]
    pub region: String,
    /// A path inside the bucket.
    #[serde(default)]
    pub prefix: Option<String>,
    /// The environment variable holding the access key id.
    pub access_key_id_env: String,
    /// The environment variable holding the secret access key.
    pub secret_access_key_env: String,
    /// Allows a plain `http://` endpoint on loopback only.
    #[serde(default)]
    pub allow_http: bool,
}

fn default_region() -> String {
    "us-east-1".into()
}

/// Logging.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    /// Filter directives, `info` by default.
    #[serde(default = "default_filter")]
    pub filter: String,
    /// JSON lines instead of text.
    #[serde(default = "yes")]
    pub json: bool,
}

fn default_filter() -> String {
    "info".into()
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            filter: default_filter(),
            json: true,
        }
    }
}

/// Shutdown.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ShutdownConfig {
    /// How long a stopping tenant waits for another node to take over the accounts it hands
    /// back, in seconds; 15 by default, at most 600.
    #[serde(default = "default_handback")]
    pub handback_secs: u64,
}

fn default_handback() -> u64 {
    15
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            handback_secs: default_handback(),
        }
    }
}

impl ShutdownConfig {
    /// The hand-back wait.
    pub fn handback(&self) -> Duration {
        Duration::from_secs(self.handback_secs)
    }
}

/// Extra roots for the mail providers, honoured only by builds with the `test-roots` feature.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// A PEM file with a test CA.
    #[serde(default)]
    pub test_ca: Option<PathBuf>,
}

impl Config {
    /// Parses and validates `text`.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let config: Self =
            toml::from_str(text).map_err(|e| ConfigError::Parse(e.message().into()))?;
        config.validate()?;
        Ok(config)
    }

    /// Reads, parses and validates the file at `path`.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|_| ConfigError::Read)?;
        Self::parse(&text)
    }

    /// Whether the cache lies in the data directory, so that a copy of the data volume taken
    /// after a crash may hold mail in the clear.
    pub fn cache_in_data(&self) -> bool {
        self.cache().starts_with(&self.data_dir)
    }

    /// The cache directory.
    pub fn cache(&self) -> PathBuf {
        self.cache_dir
            .clone()
            .unwrap_or_else(|| self.data_dir.join("cache"))
    }

    /// Checks every rule a running server would otherwise trip over later; returns the first
    /// problem.
    pub fn validate(&self) -> Result<(), ConfigError> {
        for (name, dir) in [
            ("data_dir", &self.data_dir),
            ("secrets_dir", &self.secrets_dir),
        ] {
            if !dir.is_absolute() {
                return Err(invalid(format!("{name} must be an absolute path")));
            }
        }
        let cache = self.cache();
        if !cache.is_absolute() {
            return Err(invalid("cache_dir must be an absolute path"));
        }
        if nested(&self.data_dir, &self.secrets_dir) {
            return Err(invalid(
                "secrets_dir and data_dir must not contain each other: a copy of the data must not carry its keys",
            ));
        }
        if nested(&cache, &self.secrets_dir) {
            return Err(invalid(
                "cache_dir and secrets_dir must not contain each other",
            ));
        }
        if cache == self.data_dir
            || cache.starts_with(self.data_dir.join("tenants"))
            || cache.starts_with(self.data_dir.join("host"))
        {
            return Err(invalid(
                "cache_dir must not be data_dir or lie inside its tenants or host",
            ));
        }
        self.link.port_range()?;
        self.link.advertised()?;
        self.link.relay_urls()?;
        if self.listener.enabled {
            self.server_config_unchecked().validate().map_err(invalid)?;
        }
        if let Some(url) = &self.listener.public_url
            && !url.starts_with("https://")
            && !url.starts_with("http://127.0.0.1")
            && !url.starts_with("http://localhost")
        {
            return Err(invalid(
                "listener.public_url must be https (or http on loopback)",
            ));
        }
        let push = &self.listener.push;
        if push.enabled && self.listener.public_url.is_none() {
            return Err(invalid("listener.push needs listener.public_url"));
        }
        if push.enabled && !self.listener.enabled {
            return Err(invalid("listener.push needs the listener enabled"));
        }
        if push.gmail_oidc_audience.is_some() != push.gmail_oidc_email.is_some() {
            return Err(invalid(
                "listener.push.gmail_oidc_audience and gmail_oidc_email go together",
            ));
        }
        if let Some(s3) = &self.s3 {
            if s3.bucket.is_empty() {
                return Err(invalid("s3.bucket must not be empty"));
            }
            if s3.access_key_id_env.is_empty() || s3.secret_access_key_env.is_empty() {
                return Err(invalid(
                    "s3 needs access_key_id_env and secret_access_key_env",
                ));
            }
        }
        tracing_subscriber_filter_ok(&self.logs.filter)?;
        if self.shutdown.handback_secs > 600 {
            return Err(invalid("shutdown.handback_secs is at most 600"));
        }
        if self.tls.test_ca.is_some() && !cfg!(feature = "test-roots") {
            return Err(invalid(
                "tls.test_ca needs a build with the test-roots feature (the container suite's image)",
            ));
        }
        Ok(())
    }

    fn server_config_unchecked(&self) -> skein_server::ServerConfig {
        let push = &self.listener.push;
        skein_server::ServerConfig {
            gmail_push_token_hash: None,
            gmail_push_oidc: match (&push.gmail_oidc_audience, &push.gmail_oidc_email) {
                (Some(audience), Some(email)) => Some(skein_server::oidc::OidcConfig {
                    jwks_url: skein_server::oidc::GOOGLE_JWKS.into(),
                    audience: audience.clone(),
                    email: email.clone(),
                }),
                _ => None,
            },
            push_rate_per_second: self.listener.push_rate_per_second,
        }
    }

    /// The listener's settings, the Gmail push secret read from its environment variable.
    pub fn server_config(&self) -> Result<skein_server::ServerConfig, ConfigError> {
        let mut config = self.server_config_unchecked();
        if let Some(env) = &self.listener.push.gmail_token_env {
            let token = std::env::var(env)
                .map_err(|_| invalid(format!("the environment variable {env} is not set")))?;
            config.gmail_push_token_hash = Some(skein_server::hash_token(&token));
        }
        config.validate().map_err(invalid)?;
        Ok(config)
    }
}

fn tracing_subscriber_filter_ok(filter: &str) -> Result<(), ConfigError> {
    let ok = !filter.is_empty()
        && filter.split(',').all(|d| {
            !d.is_empty()
                && d.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_=:-.[]{}\"".contains(&b))
        });
    if ok {
        Ok(())
    } else {
        Err(invalid("logs.filter is not a list of filter directives"))
    }
}

fn nested(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = "data_dir = \"/data\"\nsecrets_dir = \"/secrets\"\n";

    fn with(extra: &str) -> Result<Config, ConfigError> {
        Config::parse(&format!("{MINIMAL}{extra}"))
    }

    #[test]
    fn the_minimal_file_takes_the_documented_defaults() {
        let c = Config::parse(MINIMAL).unwrap();
        assert_eq!(c.cache(), PathBuf::from("/data/cache"));
        assert!(c.cache_in_data(), "the default is warned about");
        assert!(c.first_run_invite);
        assert_eq!(
            c.link.port_range().unwrap(),
            Some(Ports {
                first: 4400,
                last: 4499
            })
        );
        assert!(c.listener.enabled);
        assert_eq!(c.listener.listen, "0.0.0.0:8080".parse().unwrap());
        assert!(!c.listener.push.enabled);
        assert!(c.s3.is_none());
        assert!(c.logs.json);
        assert_eq!(c.shutdown.handback(), Duration::from_secs(15));
    }

    #[test]
    fn the_example_file_is_valid() {
        let text = include_str!("../rowboat.example.toml");
        let c = Config::parse(text).unwrap();
        assert!(c.s3.is_none(), "the example keeps S3 commented out");
    }

    #[test]
    fn unknown_settings_and_relative_paths_are_refused() {
        assert!(matches!(with("colour = 1\n"), Err(ConfigError::Parse(_))));
        assert!(matches!(
            Config::parse("data_dir = \"data\"\nsecrets_dir = \"/s\"\n"),
            Err(ConfigError::Invalid(_))
        ));
        assert!(matches!(
            with("cache_dir = \"cache\"\n"),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn keys_never_sit_inside_the_data() {
        for (data, secrets) in [
            ("/srv", "/srv/keys"),
            ("/srv/data", "/srv"),
            ("/srv", "/srv"),
        ] {
            let text = format!("data_dir = \"{data}\"\nsecrets_dir = \"{secrets}\"\n");
            assert!(
                matches!(Config::parse(&text), Err(ConfigError::Invalid(_))),
                "{data} {secrets}"
            );
        }
        assert!(with("cache_dir = \"/secrets/cache\"\n").is_err());
        assert!(with("cache_dir = \"/data/tenants/x\"\n").is_err());
        assert!(with("cache_dir = \"/data\"\n").is_err());
        assert!(with("cache_dir = \"/run/rowboat\"\n").is_ok());
        assert!(
            !with("cache_dir = \"/run/rowboat\"\n")
                .unwrap()
                .cache_in_data()
        );
    }

    #[test]
    fn port_ranges_follow_their_rules() {
        let range = |p: &str| {
            LinkConfig {
                ports: p.into(),
                ..LinkConfig::default()
            }
            .port_range()
        };
        assert_eq!(range("any").unwrap(), None);
        assert_eq!(
            range("4400-4400").unwrap(),
            Some(Ports {
                first: 4400,
                last: 4400
            })
        );
        for bad in ["", "4400", "0-10", "10-9", "a-b", "1-20000", "-", "4400-"] {
            assert!(range(bad).is_err(), "{bad}");
        }
        assert!(with("[link]\nports = \"9-1\"\n").is_err());
    }

    #[test]
    fn advertised_addresses_and_relays_are_checked() {
        let c = with("[link]\nadvertise = [\"192.0.2.7\", \"198.51.100.1:4500\"]\nrelays = [\"https://relay.example.com\"]\n").unwrap();
        assert_eq!(
            c.link.advertised().unwrap(),
            vec![
                "192.0.2.7:0".parse::<SocketAddr>().unwrap(),
                "198.51.100.1:4500".parse().unwrap()
            ]
        );
        assert!(with("[link]\nadvertise = [\"host.example.com\"]\n").is_err());
        assert!(with("[link]\nrelays = [\"http://relay.example.com\"]\n").is_err());
    }

    #[test]
    fn push_needs_a_public_https_address() {
        assert!(with("[listener.push]\nenabled = true\n").is_err());
        assert!(
            with("[listener]\npublic_url = \"http://mail.example.com\"\n").is_err(),
            "plain http off loopback"
        );
        assert!(with(
            "[listener]\npublic_url = \"https://mail.example.com\"\n[listener.push]\nenabled = true\n"
        )
        .is_ok());
        assert!(with(
            "[listener]\nenabled = false\npublic_url = \"https://mail.example.com\"\n[listener.push]\nenabled = true\n"
        )
        .is_err());
        assert!(with("[listener]\npush_rate_per_second = 0\n").is_err());
        assert!(with("[listener.push]\ngmail_oidc_audience = \"a\"\n").is_err());
    }

    #[test]
    fn s3_settings_name_their_secrets_by_variable() {
        assert!(
            with(
                "[s3]\nbucket = \"b\"\naccess_key_id_env = \"A\"\nsecret_access_key_env = \"S\"\n"
            )
            .is_ok()
        );
        assert!(
            with("[s3]\nbucket = \"\"\naccess_key_id_env = \"A\"\nsecret_access_key_env = \"S\"\n")
                .is_err()
        );
        assert!(
            matches!(
                with("[s3]\nbucket = \"b\"\naccess_key_id = \"AKIA\"\n"),
                Err(ConfigError::Parse(_))
            ),
            "a key itself has no setting"
        );
    }

    #[test]
    fn test_roots_need_their_feature() {
        let r = with("[tls]\ntest_ca = \"/certs/ca.crt\"\n");
        assert_eq!(r.is_ok(), cfg!(feature = "test-roots"));
    }

    #[test]
    fn errors_name_settings_not_values() {
        let secret = "sk-live-canary";
        let e = Config::parse(&format!(
            "{MINIMAL}[s3]\nbucket = \"\"\naccess_key_id_env = \"{secret}\"\nsecret_access_key_env = \"S\"\n"
        ))
        .unwrap_err();
        assert!(!e.to_string().contains(secret));
        assert!(with("[logs]\nfilter = \"info;rm\"\n").is_err());
        assert!(with("[shutdown]\nhandback_secs = 601\n").is_err());
    }
}
