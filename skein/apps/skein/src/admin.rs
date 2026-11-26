use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use baton_signal_local::LocalSignal;
use bytes::Bytes;
use clap::{Args, Subcommand};
use serde_json::json;
use skein_accounts::admin::{self as checks, AdminError};
use skein_accounts::{AccountRecord, Accounts, OAuthClients, TenantRegistry};
use skein_core::{AccountId, BlobHash, Command, CommandBody, CommandId, Seq, TenantId, Timestamp};
use skein_keyring::Keyring;
use skein_keyring_local::LocalKeyring;
use skein_oauth::{Grant, TokenManager};
use skein_oauth_http::HttpTokenEndpoint;
use skein_storage::Storage;
use skein_webhooks::{EndpointPatch, NewEndpoint, WebhookPolicy, WebhookStore};

use crate::config::{Config, StorageConfig};

/// Largest blob `journal put-blob` stores, the same as the engine's largest message.
const MAX_BLOB: u64 = 128 * 1024 * 1024;
/// Largest record or command file read.
const MAX_FILE: u64 = 1024 * 1024;

#[derive(Args)]
pub struct ConfigArg {
    /// The config file whose storage and keyring are used.
    #[arg(
        short,
        long,
        env = "SKEIN_CONFIG",
        default_value = "skein.toml",
        global = true
    )]
    config: PathBuf,
}

#[derive(Subcommand)]
pub enum TenantCommand {
    /// Registers a tenant so nodes sync it; registering again changes nothing.
    Add { tenant: String },
    /// Lists registered tenants, one per line.
    List,
    /// Unregisters a tenant: nodes stop syncing it, its data stays.
    Remove {
        tenant: String,
        /// Also deletes every account, credential, journal, blob and command of the tenant and
        /// destroys its key. Irreversible; needs `--confirm` with the tenant id again.
        #[arg(long)]
        purge: bool,
        /// The tenant id again, required with `--purge`.
        #[arg(long)]
        confirm: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum AccountCommand {
    /// Stores an account record read as JSON from a file (`-` for stdin): `provider`,
    /// `settings`, `auth`, and optionally `include`, `exclude`, `paused`, `send`, `pim`. Never
    /// put secrets in it.
    Put {
        #[arg(long)]
        tenant: String,
        account: String,
        #[arg(long)]
        file: PathBuf,
    },
    /// Lists a tenant's accounts with their health, one JSON object per line.
    List {
        #[arg(long)]
        tenant: String,
    },
    /// Prints one account with its health as JSON.
    Show {
        #[arg(long)]
        tenant: String,
        account: String,
    },
    /// Deletes an account record, its sealed credentials and its OAuth grant; the journal stays.
    Remove {
        #[arg(long)]
        tenant: String,
        account: String,
    },
    /// Seals the account's password, read from the first line of stdin.
    Password {
        #[arg(long)]
        tenant: String,
        account: String,
        /// The password for calendars and contacts (`pim.auth = "password"`) instead.
        #[arg(long)]
        pim: bool,
    },
    /// Seals an access key for the account's sending service (`send.kind = "ses"`): the secret
    /// on the first line of stdin, an optional session token on the second.
    SendKey {
        #[arg(long)]
        tenant: String,
        account: String,
        #[arg(long)]
        access_key_id: String,
    },
    /// Stores OAuth tokens obtained elsewhere, replacing any grant: the access token on the
    /// first line of stdin, an optional refresh token on the second.
    Grant {
        #[arg(long)]
        tenant: String,
        account: String,
        /// When the access token expires, in milliseconds since the Unix epoch.
        #[arg(long)]
        expires_at: Option<i64>,
    },
}

#[derive(Subcommand)]
pub enum JournalCommand {
    /// Stores the bytes of a file as a blob and prints its hash, for `append` and `send`.
    PutBlob {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        file: PathBuf,
    },
    /// Writes a stored blob to a file.
    GetBlob {
        #[arg(long)]
        tenant: String,
        hash: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Queues a command read as JSON from a file (`-` for stdin): `{"id"?, "body"}`. Prints its
    /// id and whether it was a duplicate. The owner picks it up on its next round.
    Submit {
        #[arg(long)]
        tenant: String,
        account: String,
        #[arg(long)]
        file: PathBuf,
    },
    /// Cancels a queued command that has not started.
    Cancel {
        #[arg(long)]
        tenant: String,
        account: String,
        id: String,
    },
    /// Prints events of an account's journal from `--from`, one JSON object per line.
    Events {
        #[arg(long)]
        tenant: String,
        account: String,
        #[arg(long, default_value_t = 1)]
        from: u64,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
}

#[derive(Subcommand)]
pub enum WebhookCommand {
    /// Adds an endpoint and prints it with its signing secret, shown only now.
    Add {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        url: String,
        /// Only these event types.
        #[arg(long, value_delimiter = ',')]
        events: Option<Vec<String>>,
        /// Only these accounts.
        #[arg(long, value_delimiter = ',')]
        accounts: Option<Vec<String>>,
    },
    /// Lists a tenant's endpoints, one JSON object per line, never their secrets.
    List {
        #[arg(long)]
        tenant: String,
    },
    /// Pauses an endpoint.
    Pause {
        #[arg(long)]
        tenant: String,
        id: String,
    },
    /// Resumes an endpoint and clears its backoff.
    Resume {
        #[arg(long)]
        tenant: String,
        id: String,
    },
    /// Replaces an endpoint's signing secret and prints the new one.
    Rotate {
        #[arg(long)]
        tenant: String,
        id: String,
    },
    /// Removes an endpoint and its delivery state.
    Remove {
        #[arg(long)]
        tenant: String,
        id: String,
    },
}

pub struct Node {
    storage: Storage,
    keyring: Arc<dyn Keyring>,
    accounts: Accounts,
    tenants: TenantRegistry,
    tokens: TokenManager,
    clients: OAuthClients,
    webhooks: WebhookPolicy,
}

pub fn run<F, Fut>(arg: &ConfigArg, f: F) -> anyhow::Result<()>
where
    F: FnOnce(Node) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    let config = Config::load(&arg.config)?;
    if matches!(config.storage, StorageConfig::Memory) {
        bail!("storage.kind = \"memory\" lives only inside `skein serve`; nothing to manage");
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let objects = crate::objects(&config.storage, crate::Access::Shared)?;
        let storage = Storage::over(objects.clone());
        let keyring: Arc<dyn Keyring> = Arc::new(
            LocalKeyring::open_or_create(&config.keyring.master_key_file, storage.control.clone())
                .context("master key")?,
        );
        let endpoint =
            Arc::new(HttpTokenEndpoint::new(Duration::from_secs(30)).context("token endpoint")?);
        let node = Node {
            accounts: Accounts::new(storage.control.clone(), keyring.clone()),
            tenants: TenantRegistry::new(objects),
            tokens: TokenManager::new(endpoint, storage.control.clone(), keyring.clone()),
            clients: config.oauth_clients()?,
            webhooks: config.webhooks.policy()?,
            storage,
            keyring,
        };
        f(node).await
    })
}

fn tenant_id(raw: &str) -> anyhow::Result<TenantId> {
    TenantId::new(raw).context("not a tenant id")
}

fn account_id(raw: &str) -> anyhow::Result<AccountId> {
    AccountId::new(raw).context("not an account id")
}

fn admin(e: AdminError) -> anyhow::Error {
    anyhow::anyhow!("{e}")
}

fn read_capped(path: &Path, max: u64) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    if path == Path::new("-") {
        std::io::stdin().take(max + 1).read_to_end(&mut bytes)?;
    } else {
        std::fs::File::open(path)
            .with_context(|| format!("cannot read {}", path.display()))?
            .take(max + 1)
            .read_to_end(&mut bytes)?;
    }
    if bytes.len() as u64 > max {
        bail!("{} is larger than {max} bytes", path.display());
    }
    Ok(bytes)
}

fn secrets_from(terminal: bool) -> anyhow::Result<()> {
    if terminal {
        bail!(
            "secrets are read from a pipe or a file, not typed into a terminal that shows them: `skein ... < secret.txt`"
        );
    }
    Ok(())
}

fn stdin_lines(max: usize) -> anyhow::Result<Vec<String>> {
    secrets_from(std::io::IsTerminal::is_terminal(&std::io::stdin()))?;
    let mut text = String::new();
    std::io::stdin()
        .take(64 * 1024)
        .read_to_string(&mut text)
        .context("stdin is not text")?;
    Ok(text
        .lines()
        .map(|l| l.trim_end_matches('\r').to_owned())
        .filter(|l| !l.is_empty())
        .take(max)
        .collect())
}

async fn ensure_tenant(n: &Node, t: &TenantId) -> anyhow::Result<()> {
    if !n.tenants.contains(t).await? {
        bail!("no such tenant; add it with `skein tenant add`");
    }
    Ok(())
}

async fn existing(n: &Node, t: &TenantId, a: &AccountId) -> anyhow::Result<AccountRecord> {
    ensure_tenant(n, t).await?;
    n.accounts
        .get(t, a)
        .await?
        .context("no such account; store it with `skein account put`")
}

pub async fn tenant(n: Node, command: TenantCommand) -> anyhow::Result<()> {
    match command {
        TenantCommand::Add { tenant } => {
            let t = tenant_id(&tenant)?;
            checks::register_tenant(&n.tenants, &*n.keyring, &t)
                .await
                .map_err(admin)?;
            println!("tenant {t} registered");
        }
        TenantCommand::List => {
            for t in n.tenants.list().await? {
                println!("{t}");
            }
        }
        TenantCommand::Remove {
            tenant,
            purge: false,
            ..
        } => {
            let t = tenant_id(&tenant)?;
            checks::unregister_tenant(&n.tenants, &t)
                .await
                .map_err(admin)?;
            println!("tenant {t} unregistered; its data stays");
        }
        TenantCommand::Remove {
            tenant,
            purge: true,
            confirm,
        } => {
            let t = tenant_id(&tenant)?;
            if confirm.as_deref() != Some(t.as_str()) {
                bail!("purging is irreversible; repeat the tenant id with --confirm");
            }
            ensure_tenant(&n, &t).await?;
            let purged = checks::purge_tenant(
                &n.storage,
                &n.accounts,
                &n.tokens,
                &n.tenants,
                &*n.keyring,
                &t,
            )
            .await
            .map_err(admin)?;
            println!(
                "tenant {t} purged: {} accounts, {} objects; its key is destroyed",
                purged.accounts, purged.objects
            );
        }
    }
    Ok(())
}

async fn view(n: &Node, t: &TenantId, record: AccountRecord) -> anyhow::Result<serde_json::Value> {
    let status = skein_engine::load_status(&*n.storage.control, t, &record.account).await?;
    let head = n.storage.log.head(t, &record.account).await?;
    let status = status.unwrap_or_default();
    Ok(json!({
        "record": record,
        "health": {
            "state": status.health(),
            "head": head,
            "mail": status.mail,
            "pim": status.pim,
            "send": status.send,
        },
    }))
}

pub async fn account(n: Node, command: AccountCommand) -> anyhow::Result<()> {
    match command {
        AccountCommand::Put {
            tenant,
            account,
            file,
        } => {
            let (t, a) = (tenant_id(&tenant)?, account_id(&account)?);
            ensure_tenant(&n, &t).await?;
            let mut value: serde_json::Value =
                serde_json::from_slice(&read_capped(&file, MAX_FILE)?)
                    .context("the record is not JSON")?;
            let object = value
                .as_object_mut()
                .context("the record is a JSON object")?;
            match object.get("account") {
                None => {
                    object.insert("account".into(), json!(a));
                }
                Some(given) if given == &json!(a) => {}
                Some(_) => bail!("the record names another account"),
            }
            let record: AccountRecord =
                serde_json::from_value(value).context("the record does not fit the schema")?;
            checks::check_record(&record, &n.clients).map_err(admin)?;
            n.accounts.put(&t, &record).await?;
            println!("account {a} of {t} stored");
        }
        AccountCommand::List { tenant } => {
            let t = tenant_id(&tenant)?;
            ensure_tenant(&n, &t).await?;
            for record in n.accounts.list(&t).await? {
                println!("{}", view(&n, &t, record).await?);
            }
        }
        AccountCommand::Show { tenant, account } => {
            let (t, a) = (tenant_id(&tenant)?, account_id(&account)?);
            let record = existing(&n, &t, &a).await?;
            println!("{:#}", view(&n, &t, record).await?);
        }
        AccountCommand::Remove { tenant, account } => {
            let (t, a) = (tenant_id(&tenant)?, account_id(&account)?);
            ensure_tenant(&n, &t).await?;
            checks::delete_account(&n.accounts, &n.tokens, &t, &a)
                .await
                .map_err(admin)?;
            println!("account {a} of {t} deleted; its journal stays");
        }
        AccountCommand::Password {
            tenant,
            account,
            pim,
        } => {
            let (t, a) = (tenant_id(&tenant)?, account_id(&account)?);
            let password = stdin_lines(1)?.into_iter().next().unwrap_or_default();
            checks::check_password(&password).map_err(admin)?;
            existing(&n, &t, &a).await?;
            if pim {
                n.accounts.set_pim_password(&t, &a, &password).await?;
            } else {
                n.accounts.set_password(&t, &a, &password).await?;
            }
            println!("password of {a} sealed");
        }
        AccountCommand::SendKey {
            tenant,
            account,
            access_key_id,
        } => {
            let (t, a) = (tenant_id(&tenant)?, account_id(&account)?);
            let lines = stdin_lines(2)?;
            let secret = lines.first().map(String::as_str).unwrap_or_default();
            let token = lines.get(1).map(String::as_str);
            let id = access_key_id.trim();
            checks::check_send_key(id, secret, token).map_err(admin)?;
            existing(&n, &t, &a).await?;
            n.accounts.set_send_key(&t, &a, id, secret, token).await?;
            println!("send key of {a} sealed");
        }
        AccountCommand::Grant {
            tenant,
            account,
            expires_at,
        } => {
            let (t, a) = (tenant_id(&tenant)?, account_id(&account)?);
            let mut lines = stdin_lines(2)?.into_iter();
            let access = lines.next().unwrap_or_default();
            let refresh = lines.next();
            checks::check_token(&access).map_err(admin)?;
            if let Some(r) = &refresh {
                checks::check_token(r).map_err(admin)?;
            }
            existing(&n, &t, &a).await?;
            let grant = Grant::external(access, expires_at.map(Timestamp), refresh);
            n.tokens
                .store(&t, &a, &grant)
                .await
                .map_err(|_| anyhow::anyhow!("storing the grant failed"))?;
            println!("OAuth grant of {a} stored");
        }
    }
    Ok(())
}

pub async fn journal(n: Node, command: JournalCommand) -> anyhow::Result<()> {
    match command {
        JournalCommand::PutBlob { tenant, file } => {
            let t = tenant_id(&tenant)?;
            ensure_tenant(&n, &t).await?;
            let bytes = read_capped(&file, MAX_BLOB)?;
            if bytes.is_empty() {
                bail!("the blob is empty");
            }
            println!("{}", n.storage.blobs.put(&t, Bytes::from(bytes)).await?);
        }
        JournalCommand::GetBlob { tenant, hash, out } => {
            let t = tenant_id(&tenant)?;
            let hash = BlobHash::parse(&hash).map_err(|_| anyhow::anyhow!("not a blob hash"))?;
            let bytes = n
                .storage
                .blobs
                .get(&t, &hash)
                .await?
                .context("no such blob")?;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            options
                .open(&out)
                .and_then(|mut file| std::io::Write::write_all(&mut file, &bytes))
                .with_context(|| format!("cannot create {}; it must not exist", out.display()))?;
        }
        JournalCommand::Submit {
            tenant,
            account,
            file,
        } => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Submit {
                #[serde(default)]
                id: Option<CommandId>,
                body: CommandBody,
            }
            let (t, a) = (tenant_id(&tenant)?, account_id(&account)?);
            let submit: Submit = serde_json::from_slice(&read_capped(&file, MAX_FILE)?)
                .context("the command does not fit the schema")?;
            existing(&n, &t, &a).await?;
            let id = submit.id.unwrap_or_else(CommandId::generate);
            let created_at = ulid_time(&id)?;
            let command = Command {
                id: id.clone(),
                account: a,
                created_at,
                trace: None,
                body: submit.body,
            };
            let signal = LocalSignal::new();
            let done = skein_engine::submit_command(&n.storage, &signal, &t, &command)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("{}", json!({"id": id, "duplicate": done.duplicate}));
        }
        JournalCommand::Cancel {
            tenant,
            account,
            id,
        } => {
            let (t, a) = (tenant_id(&tenant)?, account_id(&account)?);
            let id = CommandId::new(id).map_err(|_| anyhow::anyhow!("not a command id"))?;
            ensure_tenant(&n, &t).await?;
            skein_engine::cancel_command(&n.storage, &t, &a, &id)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("command {id} cancelled");
        }
        JournalCommand::Events {
            tenant,
            account,
            from,
            limit,
        } => {
            let (t, a) = (tenant_id(&tenant)?, account_id(&account)?);
            ensure_tenant(&n, &t).await?;
            let events = n
                .storage
                .log
                .read(&t, &a, Seq(from.max(1)), limit.clamp(1, 1000))
                .await?;
            for e in events {
                println!("{}", serde_json::to_string(&e)?);
            }
        }
    }
    Ok(())
}

fn ulid_time(id: &CommandId) -> anyhow::Result<Timestamp> {
    let ulid = ulid::Ulid::from_string(id.as_str())
        .map_err(|_| anyhow::anyhow!("the id is not a ULID"))?;
    Ok(Timestamp(ulid.timestamp_ms() as i64))
}

fn store(n: &Node) -> WebhookStore {
    WebhookStore::new(
        n.storage.control.clone(),
        n.storage.log.clone(),
        n.keyring.clone(),
    )
}

fn shown(e: &skein_webhooks::Endpoint) -> serde_json::Value {
    json!({
        "id": e.id,
        "url": e.url,
        "events": e.events,
        "accounts": e.accounts,
        "created_at": e.created_at,
        "paused": e.paused,
        "paused_reason": e.paused_reason,
    })
}

pub async fn webhook(n: Node, command: WebhookCommand) -> anyhow::Result<()> {
    let webhook_error = |e: skein_webhooks::WebhookError| anyhow::anyhow!("{e}");
    match command {
        WebhookCommand::Add {
            tenant,
            url,
            events,
            accounts,
        } => {
            let t = tenant_id(&tenant)?;
            ensure_tenant(&n, &t).await?;
            let accounts = accounts
                .map(|list| list.iter().map(|a| account_id(a)).collect())
                .transpose()?;
            let (endpoint, secret) = store(&n)
                .create(
                    &t,
                    NewEndpoint {
                        url,
                        events,
                        accounts,
                    },
                    &n.webhooks,
                )
                .await
                .map_err(webhook_error)?;
            let mut out = shown(&endpoint);
            out["secret"] = json!(secret);
            println!("{out:#}");
            eprintln!("Store the secret now; it is never shown again.");
        }
        WebhookCommand::List { tenant } => {
            let t = tenant_id(&tenant)?;
            ensure_tenant(&n, &t).await?;
            for e in store(&n).list(&t).await.map_err(webhook_error)? {
                println!("{}", shown(&e));
            }
        }
        WebhookCommand::Pause { tenant, id } => set_paused(&n, &tenant, &id, true).await?,
        WebhookCommand::Resume { tenant, id } => set_paused(&n, &tenant, &id, false).await?,
        WebhookCommand::Rotate { tenant, id } => {
            let t = tenant_id(&tenant)?;
            let secret = store(&n).rotate(&t, &id).await.map_err(webhook_error)?;
            println!("{secret}");
            eprintln!("Store the secret now; it is never shown again.");
        }
        WebhookCommand::Remove { tenant, id } => {
            let t = tenant_id(&tenant)?;
            if !store(&n).delete(&t, &id).await.map_err(webhook_error)? {
                bail!("no such webhook");
            }
            println!("webhook {id} removed");
        }
    }
    Ok(())
}

async fn set_paused(n: &Node, tenant: &str, id: &str, paused: bool) -> anyhow::Result<()> {
    let t = tenant_id(tenant)?;
    let endpoint = store(n)
        .update(
            &t,
            id,
            EndpointPatch {
                paused: Some(paused),
                ..Default::default()
            },
            &n.webhooks,
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("{}", shown(&endpoint));
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn secrets_are_never_typed_into_a_terminal() {
        assert!(super::secrets_from(true).is_err());
        assert!(super::secrets_from(false).is_ok());
    }
}
