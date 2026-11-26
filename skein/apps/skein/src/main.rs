//! The `skein` binary: the only place that picks implementations. It builds storage, the keyring,
//! leases and liveness, signals and the providers from a config file, then runs a node with its
//! inbound listener (provider push and a health check) until it is stopped. Tenants, accounts,
//! commands and webhooks are managed with its subcommands, which write through the same stores
//! the node reads; there is no management API.

mod admin;
mod config;
mod factory;
mod heartbeat;
mod transfer;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use baton_lease::{Leases, Liveness};
use baton_lease_cas::{CasLeases, CasLiveness};
use baton_signal::Signal;
use baton_signal_local::{Limits, LocalSignal};
use baton_state::StateStore;
use baton_state_memory::MemoryState;
use clap::{Parser, Subcommand};
use skein_accounts::{Accounts, Directory, Senders, TenantRegistry};
use skein_core::NodeId;
use skein_engine::{Engine, OneGroupLiveness, RunConfig, node_profile};
use skein_keyring::Keyring;
use skein_keyring_local::LocalKeyring;
use skein_oauth::{TokenEndpoint, TokenManager};
use skein_oauth_http::HttpTokenEndpoint;
use skein_storage::{ControlState, Objects, Storage};
use skein_webhooks::{HttpTransport, WebhookDelivery, WebhookStore};
use tokio::sync::watch;
use tracing::info;

use crate::config::{Config, OwnershipKind, StorageConfig, secret_from_env};

#[derive(Parser)]
#[command(
    name = "skein",
    version,
    about = "Mail, calendar and contacts sync engine"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Runs a node and its inbound listener (provider push, health).
    Serve {
        /// The config file.
        #[arg(short, long, env = "SKEIN_CONFIG", default_value = "skein.toml")]
        config: PathBuf,
    },
    /// Prints a new random secret for the Gmail Pub/Sub push address; put it into the variable
    /// named by `server.push.gmail_token_env`.
    PushToken,
    /// Registers, lists, unregisters and purges tenants.
    Tenant {
        #[command(flatten)]
        config: admin::ConfigArg,
        #[command(subcommand)]
        command: admin::TenantCommand,
    },
    /// Stores, lists, shows and removes accounts, and seals their credentials.
    Account {
        #[command(flatten)]
        config: admin::ConfigArg,
        #[command(subcommand)]
        command: admin::AccountCommand,
    },
    /// Queues and cancels commands, stores blobs for them, and reads the journal.
    Journal {
        #[command(flatten)]
        config: admin::ConfigArg,
        #[command(subcommand)]
        command: admin::JournalCommand,
    },
    /// Adds, lists, changes and removes outgoing webhook endpoints.
    Webhook {
        #[command(flatten)]
        config: admin::ConfigArg,
        #[command(subcommand)]
        command: admin::WebhookCommand,
    },
    /// Writes every object of a tenant to a zstd NDJSON file (sealed records stay sealed).
    Export {
        /// The config file whose storage is read.
        #[arg(short, long, env = "SKEIN_CONFIG", default_value = "skein.toml")]
        config: PathBuf,
        /// The tenant.
        #[arg(long)]
        tenant: String,
        /// The file to create.
        #[arg(long)]
        out: PathBuf,
    },
    /// Reads an export file into the configured storage, never overwriting existing objects.
    Import {
        /// The config file whose storage is written.
        #[arg(short, long, env = "SKEIN_CONFIG", default_value = "skein.toml")]
        config: PathBuf,
        /// The tenant the file belongs to.
        #[arg(long)]
        tenant: String,
        /// The export file.
        #[arg(long = "in")]
        input: PathBuf,
    },
    /// Copies every object of a tenant from one storage to another, never overwriting.
    Copy {
        /// Config whose storage is read.
        #[arg(long)]
        from: PathBuf,
        /// Config whose storage is written.
        #[arg(long)]
        to: PathBuf,
        /// The tenant.
        #[arg(long)]
        tenant: String,
    },
    /// Checks a config file without starting anything.
    CheckConfig {
        /// The config file.
        #[arg(short, long, env = "SKEIN_CONFIG", default_value = "skein.toml")]
        config: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::PushToken => {
            let mut bytes = [0u8; 32];
            getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("no random bytes"))?;
            let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            println!("{token}");
            eprintln!(
                "Keep it secret: it goes into the Pub/Sub push address and the variable named by server.push.gmail_token_env."
            );
            Ok(())
        }
        Command::Tenant { config, command } => admin::run(&config, |n| admin::tenant(n, command)),
        Command::Account { config, command } => admin::run(&config, |n| admin::account(n, command)),
        Command::Journal { config, command } => admin::run(&config, |n| admin::journal(n, command)),
        Command::Webhook { config, command } => admin::run(&config, |n| admin::webhook(n, command)),
        Command::Export {
            config,
            tenant,
            out,
        } => {
            let config = Config::load(&config)?;
            let tenant = skein_core::TenantId::new(tenant)?;
            let rt = tokio::runtime::Runtime::new()?;
            let n = rt.block_on(transfer::export(objects(&config.storage)?, &tenant, &out))?;
            println!("exported {n} objects of {tenant} to {}", out.display());
            Ok(())
        }
        Command::Import {
            config,
            tenant,
            input,
        } => {
            let config = Config::load(&config)?;
            let tenant = skein_core::TenantId::new(tenant)?;
            let rt = tokio::runtime::Runtime::new()?;
            let c = rt.block_on(transfer::import(objects(&config.storage)?, &tenant, &input))?;
            println!(
                "imported {} objects of {tenant}; {} were already there, {} differed and were left alone",
                c.copied, c.same, c.different
            );
            Ok(())
        }
        Command::Copy { from, to, tenant } => {
            let from = Config::load(&from)?;
            let to = Config::load(&to)?;
            let tenant = skein_core::TenantId::new(tenant)?;
            let rt = tokio::runtime::Runtime::new()?;
            let c = rt.block_on(transfer::copy(
                objects(&from.storage)?,
                objects(&to.storage)?,
                &tenant,
            ))?;
            println!(
                "copied {} objects of {tenant}; {} were already there, {} differed and were left alone",
                c.copied, c.same, c.different
            );
            Ok(())
        }
        Command::CheckConfig { config } => {
            let config = Config::load(&config)?;
            config.oauth_clients()?;
            println!("config is valid (node {})", config.node.id);
            Ok(())
        }
        Command::Serve { config } => {
            let config = Config::load(&config)?;
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(serve(config))
        }
    }
}

pub(crate) fn objects(config: &StorageConfig) -> anyhow::Result<Arc<dyn Objects>> {
    Ok(match config {
        StorageConfig::Memory => Arc::new(skein_storage_memory::MemoryObjects::new()),
        StorageConfig::Fs { path } => Arc::new(
            skein_storage_fs::FsObjects::open(path)
                .with_context(|| format!("cannot open storage at {}", path.display()))?,
        ),
        StorageConfig::S3 {
            endpoint,
            bucket,
            region,
            prefix,
            access_key_id,
            access_key_id_env,
            secret_access_key_env,
            allow_http,
        } => {
            let access_key_id = match (access_key_id, access_key_id_env) {
                (Some(id), _) => id.clone(),
                (None, Some(env)) => secret_from_env(env)?,
                (None, None) => {
                    anyhow::bail!("storage.access_key_id or access_key_id_env is required")
                }
            };
            let secret = secret_from_env(
                secret_access_key_env
                    .as_deref()
                    .context("storage.secret_access_key_env is required")?,
            )?;
            let s3 = skein_storage_s3::S3Config {
                endpoint: endpoint.clone(),
                bucket: bucket.clone(),
                region: region.clone(),
                prefix: prefix.clone(),
                access_key_id,
                secret_access_key: secret,
                allow_http: *allow_http,
            };
            Arc::new(skein_storage_s3::S3Objects::new(&s3).context("S3 storage")?)
        }
    })
}

async fn serve(config: Config) -> anyhow::Result<()> {
    let storage_counts: Arc<std::sync::OnceLock<Arc<skein_storage::CountingObjects>>> =
        Arc::default();
    let otlp_metrics = config.telemetry.otlp_metrics.then(|| {
        let storage_counts = storage_counts.clone();
        skein_telemetry::OtlpMetrics {
            interval: Duration::from_secs(config.telemetry.otlp_metrics_interval_secs),
            source: Arc::new(move || {
                let mut all = skein_metrics::global().samples();
                if let Some(counting) = storage_counts.get() {
                    all.extend(storage_samples(counting));
                }
                all
            }),
        }
    });
    let telemetry = skein_telemetry::init(&skein_telemetry::TelemetryConfig {
        filter: config
            .telemetry
            .filter
            .clone()
            .unwrap_or_else(|| "info".into()),
        json: config.telemetry.json,
        otlp_endpoint: config.telemetry.otlp_endpoint.clone(),
        service_name: "skein".into(),
        otlp_metrics,
    })?;

    let counting = Arc::new(skein_storage::CountingObjects::new(objects(
        &config.storage,
    )?));
    let _ = storage_counts.set(counting.clone());
    let objects: Arc<dyn Objects> = counting.clone();
    let storage = Storage::over(objects.clone());
    let keyring: Arc<dyn Keyring> = Arc::new(
        LocalKeyring::open_or_create(&config.keyring.master_key_file, storage.control.clone())
            .context("master key")?
            .with_cache_ttl(Duration::from_secs(config.keyring.cache_ttl_secs)),
    );
    let signal: Arc<dyn Signal> = Arc::new(LocalSignal::with_limits(Limits {
        max_topics: 1 << 20,
        ..Limits::default()
    }));
    let token_endpoint: Arc<dyn TokenEndpoint> =
        Arc::new(HttpTokenEndpoint::new(Duration::from_secs(30)).context("token endpoint")?);
    let tokens = Arc::new(
        TokenManager::new(
            token_endpoint.clone(),
            storage.control.clone(),
            keyring.clone(),
        )
        .with_signal(signal.clone()),
    );
    let accounts = Accounts::new(storage.control.clone(), keyring.clone());
    let tenants = TenantRegistry::new(objects.clone());
    let push = skein_push::PushRegistry::new(objects.clone(), storage.control.clone());
    let clients = config.oauth_clients()?;
    let node = NodeId::new(&config.node.id)?;

    let heartbeat = Duration::from_secs(config.engine.heartbeat_secs.max(1));
    let ttl_ms = (heartbeat.as_millis() as u64) * 3;
    let state: Arc<dyn StateStore> = match config.engine.ownership {
        OwnershipKind::Single => Arc::new(MemoryState::new()),
        OwnershipKind::Storage => Arc::new(ControlState::new(storage.control.clone())),
    };
    if config.engine.enabled && config.engine.ownership == OwnershipKind::Storage {
        heartbeat::agree(
            state.clone(),
            &baton_core::GroupId::new(skein_engine::NODES_GROUP).expect("constant"),
            &node,
            heartbeat,
        )
        .await?;
    }
    let liveness: Arc<dyn Liveness> = Arc::new(OneGroupLiveness::nodes(Arc::new(
        CasLiveness::new(state.clone(), ttl_ms),
    )));
    let leases: Arc<dyn Leases> = Arc::new(
        CasLeases::new(state, liveness.clone()).reuse_alive_for(heartbeat.as_millis() as u64),
    );

    let (stop_tx, stop_rx) = watch::channel(false);
    let mut tasks = Vec::new();

    if config.engine.enabled {
        let throttles = skein_throttle::Throttles::default();
        let profile = node_profile(node.clone(), config.node.weight, config.node.always_on);
        let engine = Engine::new(storage.clone(), leases, signal.clone(), profile)
            .with_senders(Arc::new(Senders::new(
                accounts.clone(),
                tokens.clone(),
                clients.clone(),
                Arc::new(factory::SenderBuilder::new(throttles.clone())),
            )))
            .with_send_policy(skein_engine::SendPolicy {
                undo_ms: config.engine.send_undo_secs as i64 * 1_000,
                ..skein_engine::SendPolicy::default()
            });
        let directory = Arc::new(
            Directory::new(
                tenants.clone(),
                accounts.clone(),
                tokens.clone(),
                clients.clone(),
                Arc::new(factory::Providers::new(throttles.clone())),
            )
            .with_pim(Arc::new(factory::PimProviders::new(throttles.clone()))),
        );
        let mut run = RunConfig::new(liveness);
        run.heartbeat = heartbeat;
        run.interval = Duration::from_secs(config.engine.interval_secs.max(5));
        run.maintenance = skein_engine::Maintenance {
            snapshot_every: config.engine.snapshot_every_events.max(1),
            retain: Duration::from_secs(config.engine.retain_days * 24 * 3600),
        };
        let webhook_policy = config.webhooks.policy()?;
        if config.server.push.enabled
            && let Some(public_url) = &config.server.public_url
        {
            run.push = Some(skein_engine::PushConfig {
                renewer: Arc::new(skein_push::Renewer::new(push.clone())),
                public_url: public_url.clone(),
                gmail_topic: config.server.push.gmail_topic.clone(),
            });
        }
        run.observers.push(Arc::new(WebhookDelivery::new(
            WebhookStore::new(
                storage.control.clone(),
                storage.log.clone(),
                keyring.clone(),
            ),
            Arc::new(HttpTransport::new(webhook_policy).context("webhook client")?),
        )));
        let mut stop = stop_rx.clone();
        tasks.push(tokio::spawn(async move {
            skein_engine::run(engine, directory, run, async move {
                let _ = stop.wait_for(|s| *s).await;
            })
            .await;
        }));
    }

    if config.server.enabled {
        let server = config.server.server_config()?;
        let listener = tokio::net::TcpListener::bind(&config.server.listen)
            .await
            .with_context(|| format!("cannot listen on {}", config.server.listen))?;
        info!(listen = %listener.local_addr()?, "inbound listener up (push, health)");
        let push_registry = config.server.push.enabled.then(|| push.clone());
        let app = skein_server::router(signal.clone(), push_registry, &server);
        let mut stop = stop_rx.clone();
        tasks.push(tokio::spawn(skein_server::serve(
            listener,
            app,
            async move {
                let _ = stop.wait_for(|s| *s).await;
            },
        )));
    }

    if let Some(listen) = &config.metrics.listen {
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .with_context(|| format!("cannot listen on {listen} for metrics"))?;
        info!(listen = %listener.local_addr()?, "metrics listening");
        let counting = counting.clone();
        let app = axum::Router::new().route(
            "/metrics",
            axum::routing::get(move || {
                let counting = counting.clone();
                async move { metrics_text(&counting) }
            }),
        );
        let mut stop = stop_rx.clone();
        tasks.push(tokio::spawn(skein_server::serve(
            listener,
            app,
            async move {
                let _ = stop.wait_for(|s| *s).await;
            },
        )));
    }

    info!(node = %node, "node started");
    shutdown_signal().await;
    info!("stopping");
    let _ = stop_tx.send(true);
    for task in tasks {
        let _ = tokio::time::timeout(Duration::from_secs(30), task).await;
    }
    let _ = tokio::task::spawn_blocking(move || telemetry.shutdown()).await;
    Ok(())
}

fn metrics_text(counting: &skein_storage::CountingObjects) -> String {
    skein_metrics::global().render(&storage_samples(counting))
}

fn storage_samples(
    counting: &skein_storage::CountingObjects,
) -> Vec<skein_metrics::Extra<'static>> {
    let c = counting.counts();
    let requests = "Object storage requests";
    vec![
        (
            "skein_storage_requests_total",
            requests,
            &[("op", "get")],
            c.gets,
        ),
        (
            "skein_storage_requests_total",
            requests,
            &[("op", "put")],
            c.puts,
        ),
        (
            "skein_storage_requests_total",
            requests,
            &[("op", "list")],
            c.lists,
        ),
        (
            "skein_storage_requests_total",
            requests,
            &[("op", "delete")],
            c.deletes,
        ),
        (
            "skein_storage_bytes_written_total",
            "Bytes written to object storage",
            &[],
            c.bytes_written,
        ),
    ]
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = term => {}
    }
}
