//! The operator's command line: `serve`, `invite`, `tenants`, `status`. There is no management
//! API; the owner administers a tenant from the app through Baton commands.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use tracing::{info, warn};

use crate::config::{Config, DEFAULT_PATH};
use crate::endpoints::LinkSettings;
use crate::host::{Confirm, Deps, Host, Net, Show, Shown, Status, Tenants};
use crate::tenant::{Layout, TenantId};

/// `rowboat`: the headless multi-tenant server.
#[derive(Debug, Parser, PartialEq)]
#[command(
    name = "rowboat",
    version,
    about = "Peleda's headless multi-tenant server"
)]
pub struct Cli {
    /// The configuration file.
    #[arg(long, env = "ROWBOAT_CONFIG", default_value = DEFAULT_PATH, global = true)]
    pub config: PathBuf,
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// The subcommands.
#[derive(Debug, Subcommand, PartialEq)]
pub enum Command {
    /// Runs every bound tenant, the push receivers and the health check until SIGTERM or
    /// SIGINT, then hands every tenant's accounts back and stops. On a host with no tenant it
    /// first creates one and prints its invite (unless `first_run_invite = false`).
    Serve {
        /// Accept the first-run adoption without asking on this console (the fingerprint is
        /// still printed).
        #[arg(long)]
        yes: bool,
    },
    /// Prints a server invite (QR code, short code, pairing address) for a new or unbound
    /// tenant and waits until a device adopts it, then binds the tenant to that device's group.
    Invite {
        /// `new` for a new tenant, or the id of an unbound one.
        #[arg(long, value_parser = parse_tenant_arg)]
        tenant: TenantArg,
        /// Releases a bound tenant: deletes its data and keys, then invites again.
        #[arg(long)]
        rebind: bool,
        /// Do not ask on this console; the person confirms in the app.
        #[arg(long)]
        yes: bool,
    },
    /// Lists tenants, or removes one.
    Tenants {
        /// Without one: list.
        #[command(subcommand)]
        action: Option<TenantsAction>,
        /// JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Shows what a running `serve` last reported: tenants, groups, accounts, leases.
    Status {
        /// JSON instead of text.
        #[arg(long)]
        json: bool,
    },
}

/// `rowboat tenants ...`.
#[derive(Debug, Subcommand, PartialEq)]
pub enum TenantsAction {
    /// Deletes a tenant's data, keys and binding, stopping it in a running `serve` first.
    Remove {
        /// The tenant.
        #[arg(value_parser = parse_tenant_id)]
        tenant: TenantId,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
}

/// The `--tenant` of `invite`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantArg {
    /// A new tenant.
    New,
    /// An existing one.
    Id(TenantId),
}

fn parse_tenant_arg(text: &str) -> Result<TenantArg, String> {
    if text == "new" {
        return Ok(TenantArg::New);
    }
    parse_tenant_id(text).map(TenantArg::Id)
}

fn parse_tenant_id(text: &str) -> Result<TenantId, String> {
    TenantId::parse(text).map_err(|e| e.to_string())
}

/// The production composition of a tenant's node from `config`.
pub fn deps(config: &Config) -> anyhow::Result<Deps> {
    let link = &config.link;
    let settings = Arc::new(LinkSettings {
        bind: link.bind,
        ports: link.port_range()?,
        advertise: link.advertised()?,
        relays: link.relay_urls()?,
    });
    let store: Option<crate::host::StoreFactory> = match &config.s3 {
        None => None,
        Some(s3) => {
            let access_key_id = std::env::var(&s3.access_key_id_env)
                .map_err(|_| anyhow::anyhow!("{} is not set", s3.access_key_id_env))?;
            let secret_access_key = std::env::var(&s3.secret_access_key_env)
                .map_err(|_| anyhow::anyhow!("{} is not set", s3.secret_access_key_env))?;
            let s3 = s3.clone();
            Some(Arc::new(move |id: &TenantId| {
                let prefix = match &s3.prefix {
                    Some(p) => format!("{}/tenants/{id}", p.trim_matches('/')),
                    None => format!("tenants/{id}"),
                };
                let objects = skein_storage_s3::S3Objects::new(&skein_storage_s3::S3Config {
                    endpoint: s3.endpoint.clone(),
                    bucket: s3.bucket.clone(),
                    region: s3.region.clone(),
                    prefix: Some(prefix),
                    access_key_id: access_key_id.clone(),
                    secret_access_key: secret_access_key.clone(),
                    allow_http: s3.allow_http,
                })
                .map_err(|e| e.to_string())?;
                Ok(Arc::new(objects) as Arc<dyn skein_storage::Objects>)
            }))
        }
    };
    let roots = match &config.tls.test_ca {
        None => None,
        Some(path) => Some(
            skein_core::TlsRoots::from_pem(
                &std::fs::read(path).map_err(|_| anyhow::anyhow!("cannot read tls.test_ca"))?,
            )
            .map_err(|_| anyhow::anyhow!("tls.test_ca holds no certificate"))?,
        ),
    };
    Ok(Deps {
        profile: rowboat_node::Profile::Server,
        providers: None,
        content: Arc::new(rinse_mail_direct::DirectContent::new()),
        net: Net::Iroh(settings),
        store,
        roots,
    })
}

/// Prints what an invite shows on stdout (never in the logs: the QR code and short code carry
/// the invite's secret until it is used or expires).
pub fn printer(out: Arc<std::sync::Mutex<dyn Write + Send>>) -> Show {
    Arc::new(move |shown| {
        let mut out = out.lock().unwrap_or_else(|e| e.into_inner());
        let _ = match shown {
            Shown::Invite {
                tenant,
                qr,
                short_code,
                address,
                node,
                expires_at,
            } => {
                let code = crate::qr::render(&qr).unwrap_or_default();
                let minutes = (expires_at - now_ms()).max(0) / 60_000;
                writeln!(
                    out,
                    "\nServer invite for tenant {tenant}\n\n{code}\n  Scan it in Peleda, or enter the short code with the pairing address.\n\n  short code:      {short_code}\n  pairing address: {address}\n  server node:     {}\n  expires in:      {minutes} min\n",
                    short_node(&node)
                )
            }
            Shown::Fingerprint {
                fingerprint,
                device,
            } => writeln!(
                out,
                "  device {} answered; fingerprint {fingerprint} (it must match the app)",
                short_node(&device)
            ),
            Shown::Bound(b) => writeln!(
                out,
                "  tenant {} is bound to group {} as node {}",
                b.tenant,
                b.group,
                short_node(&b.node)
            ),
        };
        let _ = out.flush();
    })
}

fn short_node(node: &str) -> &str {
    &node[..node.len().min(12)]
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn console_confirm() -> Confirm {
    Confirm::Console(Arc::new(|fingerprint: &str| {
        eprint!("Does the app show the fingerprint {fingerprint}? [y/N] ");
        let mut line = String::new();
        if std::io::stdin().lock().read_line(&mut line).is_err() {
            return false;
        }
        matches!(line.trim(), "y" | "Y" | "yes")
    }))
}

fn confirm_mode(yes: bool) -> Confirm {
    use std::io::IsTerminal;
    if yes || !std::io::stdin().is_terminal() {
        Confirm::App
    } else {
        console_confirm()
    }
}

fn stdout_printer() -> Show {
    printer(Arc::new(std::sync::Mutex::new(std::io::stdout())))
}

/// The file `serve` writes the first-run invite to when stdout is not a terminal.
pub fn first_run_file(secrets: &Path) -> PathBuf {
    secrets.join("first-run-invite.txt")
}

/// Where `serve` shows the first-run invite: stdout when it is a terminal; otherwise (a
/// container or a service manager, where stdout is a log others may read) a new file of mode
/// 0600 in the secrets directory ([`first_run_file`]), whose path is returned.
pub fn first_run_sink(terminal: bool, secrets: &Path) -> std::io::Result<(Show, Option<PathBuf>)> {
    if terminal {
        return Ok((stdout_printer(), None));
    }
    let path = first_run_file(secrets);
    match std::fs::remove_file(&path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(&path)?;
    Ok((printer(Arc::new(std::sync::Mutex::new(file))), Some(path)))
}

/// Runs the parsed command line.
pub async fn run(cli: Cli) -> anyhow::Result<()> {
    let config =
        Config::load(&cli.config).map_err(|e| anyhow::anyhow!("{}: {e}", cli.config.display()))?;
    let _logs = skein_telemetry::init(&skein_telemetry::TelemetryConfig {
        filter: config.logs.filter.clone(),
        json: config.logs.json,
        service_name: "rowboat".into(),
        ..Default::default()
    })?;
    let tenants = Tenants {
        layout: Layout::of(&config),
        deps: deps(&config)?,
    };
    match cli.command {
        Command::Serve { yes } => serve(config, tenants, yes).await,
        Command::Invite {
            tenant,
            rebind,
            yes,
        } => {
            let id = match tenant {
                TenantArg::New => None,
                TenantArg::Id(id) => Some(id),
            };
            if rebind && id.is_none() {
                anyhow::bail!("--rebind needs an existing tenant");
            }
            tenants
                .adopt(id, rebind, confirm_mode(yes), stdout_printer(), None, None)
                .await
                .map(drop_node)?
                .await;
            Ok(())
        }
        Command::Tenants { action: None, json } => {
            let rows = tenants.list();
            if json {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                println!(
                    "{:<34} {:<9} {:<28} {:<14} PORT",
                    "TENANT", "STATE", "GROUP", "NODE"
                );
                for r in rows {
                    println!(
                        "{:<34} {:<9} {:<28} {:<14} {}",
                        r.id,
                        r.state,
                        r.group.unwrap_or_else(|| "-".into()),
                        r.node.as_deref().map(short_node).unwrap_or("-"),
                        r.port.map(|p| p.to_string()).unwrap_or_else(|| "-".into())
                    );
                }
            }
            Ok(())
        }
        Command::Tenants {
            action: Some(TenantsAction::Remove { tenant, yes }),
            ..
        } => {
            if !yes {
                eprint!(
                    "Delete tenant {tenant} with all its data and keys? Type the tenant id to confirm: "
                );
                let mut line = String::new();
                std::io::stdin().lock().read_line(&mut line)?;
                if line.trim() != tenant.as_str() {
                    anyhow::bail!("not confirmed; nothing was deleted");
                }
            }
            tenants.remove(&tenant, Duration::from_secs(120)).await?;
            println!("tenant {tenant} removed");
            Ok(())
        }
        Command::Status { json } => status(&tenants.layout, json),
    }
}

async fn drop_node((node, _): (rowboat_node::Node, crate::tenant::Binding)) {
    node.shutdown().await;
}

fn status(layout: &Layout, json: bool) -> anyhow::Result<()> {
    let serving = matches!(
        skein_storage_fs::FsObjects::open(layout.host().join("objects")),
        Err(skein_storage_fs::OpenError::Locked { .. })
    );
    let status: Option<Status> = std::fs::read(layout.status_file())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({ "serving": serving, "status": status })
            )?
        );
        return Ok(());
    }
    println!("serve: {}", if serving { "running" } else { "not running" });
    let Some(status) = status else {
        println!("no status reported yet");
        return Ok(());
    };
    let age = (now_ms() - status.updated_ms).max(0) / 1000;
    println!("reported {age} s ago by process {}", status.pid);
    println!(
        "{:<34} {:<8} {:<28} {:>8} {:>8} {:>6}",
        "TENANT", "STATE", "GROUP", "ACCOUNTS", "LEADING", "PEERS"
    );
    for t in status.tenants {
        println!(
            "{:<34} {:<8} {:<28} {:>8} {:>8} {:>6}",
            t.id,
            t.state,
            t.group.unwrap_or_else(|| "-".into()),
            t.accounts,
            t.leading,
            t.peers
        );
    }
    Ok(())
}

async fn serve(config: Config, tenants: Tenants, yes: bool) -> anyhow::Result<()> {
    let push = config.listener.push.enabled.then(|| {
        (
            config.listener.public_url.clone().unwrap_or_default(),
            config.listener.push.gmail_topic.clone(),
        )
    });
    if config.cache_in_data() {
        warn!(
            cache = %config.cache().display(),
            "cache_dir lies in data_dir: after a crash the data volume holds mail in the clear until the next start; set cache_dir to a memory file system"
        );
    }
    let empty = tenants.layout.ids().is_empty();
    let host = Arc::new(Host::open(tenants, push, config.shutdown.handback())?);
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let listener = if config.listener.enabled {
        let server = config.server_config()?;
        let registry = config.listener.push.enabled.then(|| host.push_registry());
        let router = skein_server::router(host.signal(), registry, &server);
        let socket = tokio::net::TcpListener::bind(config.listener.listen).await?;
        info!(
            port = config.listener.listen.port(),
            "listening for push and health checks"
        );
        let mut stop = stop_rx.clone();
        Some(tokio::spawn(skein_server::serve(
            socket,
            router,
            async move {
                let _ = stop.wait_for(|s| *s).await;
            },
        )))
    } else {
        None
    };
    host.rescan().await;
    let invite_file = first_run_file(&config.secrets_dir);
    let first = (empty && config.first_run_invite).then(|| {
        let host = host.clone();
        let secrets = config.secrets_dir.clone();
        tokio::spawn(async move {
            use std::io::IsTerminal;
            let (show, file) = match first_run_sink(std::io::stdout().is_terminal(), &secrets) {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "the first-run invite could not be written; run `rowboat invite --tenant new`");
                    return;
                }
            };
            if let Some(path) = &file {
                info!(path = %path.display(), "stdout is not a terminal: the first-run invite is in this file only");
            }
            let r = host.first_run(confirm_mode(yes), show).await;
            if let Some(path) = file {
                let _ = std::fs::remove_file(path);
            }
            match r {
                Ok(id) => info!(tenant = %id, "first tenant running"),
                Err(e) => warn!(error = %e, "the first-run invite ended without a tenant; run `rowboat invite --tenant new`"),
            }
        })
    });
    let supervisor = {
        let host = host.clone();
        let mut stop = stop_rx.clone();
        tokio::spawn(async move {
            loop {
                let stopped = tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(5)) => false,
                    r = stop.wait_for(|s| *s) => r.is_ok(),
                };
                if stopped {
                    break;
                }
                host.rescan().await;
            }
        })
    };
    wait_for_signal().await;
    info!("stopping: handing accounts back");
    let _ = stop_tx.send(true);
    if let Some(f) = first {
        f.abort();
        let _ = std::fs::remove_file(&invite_file);
    }
    let _ = supervisor.await;
    host.shutdown().await;
    if let Some(l) = listener {
        let _ = l.await;
    }
    info!("stopped");
    Ok(())
}

async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("a signal handler");
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("rowboat").chain(args.iter().copied()))
    }

    #[test]
    fn subcommands_parse() {
        let c = parse(&["--config", "/x.toml", "serve"]).unwrap();
        assert_eq!(c.config, PathBuf::from("/x.toml"));
        assert_eq!(c.command, Command::Serve { yes: false });
        assert_eq!(
            parse(&["invite", "--tenant", "new"]).unwrap().command,
            Command::Invite {
                tenant: TenantArg::New,
                rebind: false,
                yes: false
            }
        );
        assert_eq!(
            parse(&["invite", "--tenant", "acme", "--rebind", "--yes"])
                .unwrap()
                .command,
            Command::Invite {
                tenant: TenantArg::Id(TenantId::parse("acme").unwrap()),
                rebind: true,
                yes: true
            }
        );
        assert_eq!(
            parse(&["tenants"]).unwrap().command,
            Command::Tenants {
                action: None,
                json: false
            }
        );
        assert_eq!(
            parse(&["tenants", "remove", "acme", "--yes"])
                .unwrap()
                .command,
            Command::Tenants {
                action: Some(TenantsAction::Remove {
                    tenant: TenantId::parse("acme").unwrap(),
                    yes: true
                }),
                json: false
            }
        );
        assert_eq!(
            parse(&["status", "--json"]).unwrap().command,
            Command::Status { json: true }
        );
    }

    #[test]
    fn hostile_tenant_ids_never_parse() {
        for bad in ["../other", "a/b", "", "NEW", "x".repeat(40).as_str()] {
            assert!(parse(&["invite", "--tenant", bad]).is_err(), "{bad}");
            assert!(parse(&["tenants", "remove", bad]).is_err(), "{bad}");
        }
        assert!(parse(&["tenants", "remove", "new"]).is_err());
        assert!(parse(&["invite"]).is_err(), "--tenant is required");
        assert!(
            parse(&["serve", "--http-api"]).is_err(),
            "no management API to turn on"
        );
        assert!(parse(&[]).is_err());
    }

    /// Regression (security review): in a container stdout is the container log, which others
    /// may read; anyone holding the first-run invite could adopt the fresh tenant.
    #[test]
    fn without_a_terminal_the_first_run_invite_goes_to_a_private_file() {
        let dir = tempfile::tempdir().unwrap();
        let (_, none) = first_run_sink(true, dir.path()).unwrap();
        assert_eq!(none, None, "a terminal shows it");
        std::fs::write(first_run_file(dir.path()), "stale").unwrap();
        let (show, path) = first_run_sink(false, dir.path()).unwrap();
        let path = path.unwrap();
        assert!(path.starts_with(dir.path()));
        show(Shown::Invite {
            tenant: TenantId::parse("acme").unwrap(),
            qr: "peleda-pair:ABCDEF".into(),
            short_code: "AB-CDEF-GHJK".into(),
            address: "peleda-addr:XYZ".into(),
            node: "0123456789abcdef".into(),
            expires_at: now_ms() + 600_000,
        });
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("AB-CDEF-GHJK") && !text.contains("stale"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn the_printer_shows_the_invite_and_never_the_logs() {
        let buffer = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        struct Sink(Arc<std::sync::Mutex<Vec<u8>>>);
        impl Write for Sink {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let show = printer(Arc::new(std::sync::Mutex::new(Sink(buffer.clone()))));
        show(Shown::Invite {
            tenant: TenantId::parse("acme").unwrap(),
            qr: "peleda-pair:ABCDEF".into(),
            short_code: "AB-CDEF-GHJK".into(),
            address: "peleda-addr:XYZ".into(),
            node: "0123456789abcdef".into(),
            expires_at: now_ms() + 600_000,
        });
        show(Shown::Fingerprint {
            fingerprint: "123 456".into(),
            device: "fedcba9876543210".into(),
        });
        let text = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
        assert!(text.contains("AB-CDEF-GHJK") && text.contains("peleda-addr:XYZ"));
        assert!(text.contains('\u{2588}'), "the QR code is drawn");
        assert!(text.contains("123 456") && text.contains("0123456789ab"));
        assert!(
            text.contains("expires in:      9 min") || text.contains("expires in:      10 min")
        );
    }
}
