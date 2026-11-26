use std::path::PathBuf;

use anyhow::{Context, bail};
use serde::Deserialize;
use skein_oauth::{Access, Client, Provider};

/// The whole config file. Secrets can be given as `*_env`, naming an environment variable, so
/// they never sit in the file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub node: NodeConfig,
    pub storage: StorageConfig,
    pub keyring: KeyringConfig,
    #[serde(default)]
    pub server: ServerSection,
    #[serde(default)]
    pub engine: EngineConfig,
    #[serde(default)]
    pub telemetry: TelemetrySection,
    #[serde(default)]
    pub oauth: OAuthSection,
    #[serde(default)]
    pub metrics: MetricsSection,
    #[serde(default)]
    pub webhooks: WebhooksSection,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsSection {
    /// The loopback address where Prometheus metrics are served without authentication, such as
    /// `127.0.0.1:9464`. Off when missing.
    #[serde(default)]
    pub listen: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub id: String,
    #[serde(default = "one")]
    pub weight: u32,
    #[serde(default = "yes")]
    pub always_on: bool,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StorageConfig {
    Memory,
    Fs {
        path: PathBuf,
    },
    S3 {
        #[serde(default)]
        endpoint: Option<String>,
        bucket: String,
        #[serde(default = "default_region")]
        region: String,
        #[serde(default)]
        prefix: Option<String>,
        #[serde(default)]
        access_key_id: Option<String>,
        #[serde(default)]
        access_key_id_env: Option<String>,
        #[serde(default)]
        secret_access_key_env: Option<String>,
        #[serde(default)]
        allow_http: bool,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyringConfig {
    pub master_key_file: PathBuf,
    #[serde(default = "sixty")]
    pub cache_ttl_secs: u64,
}

/// The inbound listener: provider push and the health check, nothing else.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default = "default_listen")]
    pub listen: String,
    /// The address providers reach the listener at, such as `https://skein.example.com`; push
    /// subscriptions point there.
    #[serde(default)]
    pub public_url: Option<String>,
    /// Push requests accepted per second over the whole listener (default 100).
    #[serde(default = "hundred")]
    pub push_rate_per_second: u32,
    #[serde(default)]
    pub push: PushSection,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushSection {
    /// Subscribes Gmail and Graph accounts to push when `public_url` is set. On by default.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// The Pub/Sub topic Gmail publishes to, `projects/{project}/topics/{topic}`.
    #[serde(default)]
    pub gmail_topic: Option<String>,
    /// Environment variable holding the secret in the Pub/Sub push endpoint
    /// `{public_url}/v1/push/gmail/{secret}`.
    #[serde(default)]
    pub gmail_token_env: Option<String>,
    /// When set with `gmail_oidc_email`, Gmail push requests must also carry a Pub/Sub OIDC
    /// token for this audience (configured on the push subscription).
    #[serde(default)]
    pub gmail_oidc_audience: Option<String>,
    /// The service account the push subscription authenticates as.
    #[serde(default)]
    pub gmail_oidc_email: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhooksSection {
    /// Allows loopback receivers and plain HTTP to them (tests, single-machine setups).
    #[serde(default)]
    pub allow_http_loopback: bool,
    /// Private networks receivers may live in, such as `10.20.0.0/16`.
    #[serde(default)]
    pub allowed_networks: Vec<String>,
    /// Longest wait for one delivery, in seconds (default 10).
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: default_listen(),
            public_url: None,
            push_rate_per_second: 100,
            push: PushSection::default(),
        }
    }
}

impl WebhooksSection {
    /// Where webhook endpoints may point, checked when they are added and on every delivery.
    pub fn policy(&self) -> anyhow::Result<skein_webhooks::WebhookPolicy> {
        let mut policy = skein_webhooks::WebhookPolicy {
            allow_http_loopback: self.allow_http_loopback,
            ..Default::default()
        };
        for net in &self.allowed_networks {
            policy.allowed_networks.push(net.parse().map_err(|_| {
                anyhow::anyhow!("webhooks.allowed_networks: {net} is not a network")
            })?);
        }
        if let Some(secs) = self.timeout_secs {
            policy.timeout = std::time::Duration::from_secs(secs.clamp(1, 60));
        }
        Ok(policy)
    }
}

impl ServerSection {
    /// The listener's settings, checked.
    pub fn server_config(&self) -> anyhow::Result<skein_server::ServerConfig> {
        if let Some(public) = &self.public_url {
            let ok = public.starts_with("https://") || public.starts_with("http://");
            if !ok || public.contains(['?', '#']) {
                bail!("server.public_url must be an http(s) address without query");
            }
        }
        let config = skein_server::ServerConfig {
            gmail_push_oidc: match (&self.push.gmail_oidc_audience, &self.push.gmail_oidc_email) {
                (Some(audience), Some(email)) => Some(skein_server::oidc::OidcConfig {
                    audience: audience.clone(),
                    email: email.clone(),
                    jwks_url: skein_server::oidc::GOOGLE_JWKS.into(),
                }),
                (None, None) => None,
                _ => bail!("server.push needs both gmail_oidc_audience and gmail_oidc_email"),
            },
            gmail_push_token_hash: match &self.push.gmail_token_env {
                Some(env) => Some(skein_server::hash_token(&secret_from_env(env)?)),
                None => None,
            },
            push_rate_per_second: self.push_rate_per_second,
        };
        config
            .validate()
            .map_err(|e| anyhow::anyhow!("server settings: {e}"))?;
        Ok(config)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnershipKind {
    /// One process holds every lease: Baton's compare-and-swap leases over in-memory state.
    Single,
    /// Nodes coordinate through Baton's compare-and-swap leases and heartbeats kept as control
    /// records in the storage.
    Storage,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineConfig {
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default = "default_ownership")]
    pub ownership: OwnershipKind,
    #[serde(default = "ten")]
    pub heartbeat_secs: u64,
    #[serde(default = "three_hundred")]
    pub interval_secs: u64,
    #[serde(default = "five_thousand")]
    pub snapshot_every_events: u64,
    #[serde(default = "seven")]
    pub retain_days: u64,
    #[serde(default)]
    pub send_undo_secs: u64,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ownership: default_ownership(),
            heartbeat_secs: 10,
            interval_secs: 300,
            snapshot_every_events: 5_000,
            retain_days: 7,
            send_undo_secs: 0,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetrySection {
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub json: bool,
    #[serde(default)]
    pub otlp_endpoint: Option<String>,
    /// Exports the counters as OTLP metrics to `otlp_endpoint` too.
    #[serde(default)]
    pub otlp_metrics: bool,
    #[serde(default = "sixty")]
    pub otlp_metrics_interval_secs: u64,
}

impl Default for TelemetrySection {
    fn default() -> Self {
        Self {
            filter: None,
            json: false,
            otlp_endpoint: None,
            otlp_metrics: false,
            otlp_metrics_interval_secs: 60,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthSection {
    #[serde(default)]
    pub clients: Vec<OAuthClientConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthClientConfig {
    pub name: String,
    pub provider: Provider,
    pub client_id: String,
    #[serde(default)]
    pub client_secret_env: Option<String>,
    #[serde(default)]
    pub microsoft_tenant: Option<String>,
    pub access: Access,
    #[serde(default)]
    pub redirect_url: Option<String>,
}

fn one() -> u32 {
    1
}
fn yes() -> bool {
    true
}
fn sixty() -> u64 {
    60
}
fn hundred() -> u32 {
    100
}
fn ten() -> u64 {
    10
}
fn three_hundred() -> u64 {
    300
}
fn five_thousand() -> u64 {
    5_000
}
fn seven() -> u64 {
    7
}
fn default_region() -> String {
    "us-east-1".into()
}
fn default_listen() -> String {
    "127.0.0.1:8080".into()
}
fn default_ownership() -> OwnershipKind {
    OwnershipKind::Single
}

/// The value of the environment variable `name`, refusing an empty one.
pub fn secret_from_env(name: &str) -> anyhow::Result<String> {
    let value =
        std::env::var(name).with_context(|| format!("environment variable {name} is not set"))?;
    if value.is_empty() {
        bail!("environment variable {name} is empty");
    }
    Ok(value)
}

impl Config {
    /// Reads and checks a config file.
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read config file {}", path.display()))?;
        Self::parse(&text)
    }

    /// Parses and checks config text.
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let config: Config = toml::from_str(text).context("the config file is invalid")?;
        skein_core::NodeId::new(&config.node.id).context("node.id is not a valid id")?;
        if config.server.enabled {
            config.server.server_config()?;
        }
        config.webhooks.policy()?;
        if matches!(config.engine.ownership, OwnershipKind::Storage)
            && matches!(config.storage, StorageConfig::Memory)
        {
            bail!("engine.ownership = \"storage\" needs shared storage, not memory");
        }
        if config.engine.send_undo_secs > 3_600 {
            bail!("engine.send_undo_secs must be at most 3600");
        }
        if let Some(listen) = &config.metrics.listen {
            let loopback = listen
                .parse::<std::net::SocketAddr>()
                .is_ok_and(|addr| addr.ip().is_loopback());
            if !loopback {
                bail!(
                    "metrics.listen must be a loopback address such as 127.0.0.1:9464; use telemetry.otlp_metrics to export elsewhere"
                );
            }
        }
        if config.telemetry.otlp_metrics && config.telemetry.otlp_endpoint.is_none() {
            bail!("telemetry.otlp_metrics needs telemetry.otlp_endpoint");
        }
        if config.telemetry.otlp_metrics_interval_secs
            < skein_telemetry::MIN_METRICS_INTERVAL.as_secs()
        {
            bail!(
                "telemetry.otlp_metrics_interval_secs must be at least {}",
                skein_telemetry::MIN_METRICS_INTERVAL.as_secs()
            );
        }
        Ok(config)
    }

    /// The OAuth clients, with secrets from the environment. The node only refreshes tokens it
    /// was handed, so `redirect_url` matters only to whoever ran the sign-in; it may be left out.
    pub fn oauth_clients(&self) -> anyhow::Result<skein_accounts::OAuthClients> {
        self.oauth_clients_with(&secret_from_env)
    }

    /// [`Config::oauth_clients`] with secrets looked up through `env`.
    pub fn oauth_clients_with(
        &self,
        env: &dyn Fn(&str) -> anyhow::Result<String>,
    ) -> anyhow::Result<skein_accounts::OAuthClients> {
        let mut clients = skein_accounts::OAuthClients::new();
        for c in &self.oauth.clients {
            let secret = c.client_secret_env.as_deref().map(env).transpose()?;
            let redirect = c.redirect_url.clone().unwrap_or_default();
            let mut client = Client::new(c.provider, &c.client_id, secret, redirect, &c.access)
                .with_context(|| format!("OAuth client {}", c.name))?;
            if let Some(tenant) = &c.microsoft_tenant {
                client = client
                    .with_microsoft_tenant(tenant)
                    .with_context(|| format!("OAuth client {}", c.name))?;
            }
            clients.insert(c.name.clone(), client);
        }
        Ok(clients)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(extra: &str) -> String {
        format!(
            "[node]\nid = \"n\"\n[storage]\nkind = \"memory\"\n[keyring]\nmaster_key_file = \"k\"\n{extra}"
        )
    }

    #[test]
    fn parses_a_full_config_and_reads_secrets_from_env() {
        let text = r#"
[node]
id = "node-1"

[storage]
kind = "s3"
endpoint = "http://127.0.0.1:9000"
bucket = "skein"
access_key_id = "key"
secret_access_key_env = "SKEIN_TEST_S3_SECRET"
allow_http = true

[keyring]
master_key_file = "/data/master.key"

[server]
listen = "0.0.0.0:8080"
public_url = "https://skein.example.com/"
push_rate_per_second = 20

[server.push]
gmail_topic = "projects/example/topics/skein"

[webhooks]
allowed_networks = ["10.20.0.0/16"]

[engine]
ownership = "storage"

[[oauth.clients]]
name = "google"
provider = "google"
client_id = "id.apps.googleusercontent.com"
client_secret_env = "SKEIN_TEST_GOOGLE_SECRET"
access = { mail = "api", mail_write = true }
"#;
        let config = Config::parse(text).unwrap();
        assert!(matches!(config.engine.ownership, OwnershipKind::Storage));
        assert_eq!(
            config.server.server_config().unwrap().push_rate_per_second,
            20
        );
        assert!(
            config
                .webhooks
                .policy()
                .unwrap()
                .address_allowed("10.20.1.1".parse().unwrap())
        );
        let none = |_: &str| -> anyhow::Result<String> { anyhow::bail!("not set") };
        assert!(
            config.oauth_clients_with(&none).is_err(),
            "a missing secret variable is an error"
        );
        let env = |name: &str| -> anyhow::Result<String> {
            assert_eq!(name, "SKEIN_TEST_GOOGLE_SECRET");
            Ok("s3cret".into())
        };
        let clients = config.oauth_clients_with(&env).unwrap();
        let google = clients.get("google").unwrap();
        assert_eq!(google.client_secret.as_deref(), Some("s3cret"));
    }

    #[test]
    fn the_example_config_parses() {
        Config::parse(include_str!("../skein.example.toml")).unwrap();
    }

    #[test]
    fn needs_no_key_and_no_listener_to_start() {
        let config = Config::parse(&base("")).unwrap();
        assert!(config.server.enabled);
        assert_eq!(config.server.listen, "127.0.0.1:8080");
        assert!(Config::parse(&base("[server]\nenabled = false")).is_ok());
    }

    #[test]
    fn refuses_unusable_configs() {
        let engine = |undo: u64| {
            base(&format!(
                "[engine]\nownership = \"single\"\nsend_undo_secs = {undo}"
            ))
        };
        assert_eq!(
            Config::parse(&engine(30))
                .map(|c| c.engine.send_undo_secs)
                .ok(),
            Some(30)
        );
        assert!(Config::parse(&engine(3_601)).is_err());
        assert!(
            Config::parse(&base("[engine]\nownership = \"storage\"")).is_err(),
            "storage ownership needs shared storage"
        );
        for gone in [
            "[server]\nadmin_key_hashes = []",
            "[server]\ntrusted_proxies = []",
            "[server.cors]\nallowed_origins = [\"*\"]",
            "[server.account_hosts]\nallow_loopback = true",
            "[server.webhooks]\ntimeout_secs = 5",
            "[portal]\nenabled = true",
        ] {
            assert!(Config::parse(&base(gone)).is_err(), "{gone}");
        }
        assert!(Config::parse(&base("[server]\npush_rate_per_second = 0")).is_err());
        assert!(Config::parse(&base("[server]\npublic_url = \"ftp://x.example.com\"")).is_err());
        assert!(
            Config::parse(&base(
                "[server.push]\ngmail_oidc_audience = \"https://skein.example.com\""
            ))
            .is_err(),
            "OIDC needs both audience and email"
        );
        assert!(Config::parse(&base("[webhooks]\nallowed_networks = [\"nope\"]")).is_err());
        let telemetry = |t: &str| base(&format!("[telemetry]\n{t}"));
        let config = Config::parse(&telemetry("")).unwrap();
        assert!(!config.telemetry.otlp_metrics);
        assert_eq!(config.telemetry.otlp_metrics_interval_secs, 60);
        let config = Config::parse(&telemetry(
            "otlp_endpoint = \"http://localhost:4317\"\notlp_metrics = true\notlp_metrics_interval_secs = 10",
        ))
        .unwrap();
        assert!(config.telemetry.otlp_metrics);
        assert!(
            Config::parse(&telemetry("otlp_metrics = true")).is_err(),
            "metrics export needs an endpoint"
        );
        assert!(
            Config::parse(&telemetry(
                "otlp_endpoint = \"http://localhost:4317\"\notlp_metrics = true\notlp_metrics_interval_secs = 9"
            ))
            .is_err(),
            "interval below the minimum"
        );
        let metrics = |listen: &str| base(&format!("[metrics]\nlisten = \"{listen}\""));
        assert!(Config::parse(&metrics("127.0.0.1:9464")).is_ok());
        assert!(Config::parse(&metrics("[::1]:9464")).is_ok());
        for public in [
            "0.0.0.0:9464",
            "[::]:9464",
            "203.0.113.5:9464",
            "metrics.example.com:9464",
        ] {
            assert!(
                Config::parse(&metrics(public)).is_err(),
                "unauthenticated metrics on {public}"
            );
        }
        assert!(Config::parse("[node]\nid = \"../x\"\n[storage]\nkind = \"memory\"\n[keyring]\nmaster_key_file = \"k\"").is_err());
    }
}
