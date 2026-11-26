//! Account records, sealed credentials, and the account directory the engine runs from.
//!
//! An account record says which provider an account uses, its settings and how it signs in;
//! it never holds a secret. Passwords are sealed by the keyring; OAuth grants are kept by
//! [`skein_oauth::TokenManager`]. Credentials are resolved when a provider connects, which only
//! happens on the account's owner, so tokens are refreshed in one place.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use skein_core::{AccountId, Credentials, TenantId};
use skein_engine::{AccountConfig, AccountDirectory, AccountEntry, EngineError, SenderDirectory};
use skein_keyring::{KeyScope, Keyring, open_account};
use skein_mail::{MailError, MailProvider, MailSession, MailWatch};
use skein_oauth::{Client, OAuthError, TokenManager};
use skein_pim::{PimError, PimProvider};
use skein_send::{SendError, Sender};
use skein_storage::{
    ControlStore, Expect, Migrate, ObjectKey, Objects, StorageError, decode_record, encode_record,
};
use tracing::warn;

pub mod admin;

/// Which provider implementation an account uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    /// IMAP.
    Imap,
    /// JMAP.
    Jmap,
    /// The Gmail API.
    Gmail,
    /// Microsoft Graph.
    Graph,
}

/// How an account signs in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Auth {
    /// A password or app password, sealed at `credentials/{account}/password`.
    Password,
    /// OAuth with the named client from the [`OAuthClients`] registry; the grant is kept by the
    /// token manager.
    OAuth {
        /// The client's name in the registry.
        client: String,
    },
}

/// An account as stored at control path `accounts/{account}`. Holds no secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRecord {
    /// The account.
    pub account: AccountId,
    /// Its provider.
    pub provider: ProviderKind,
    /// Provider settings (host, port, API address, user name), as the provider crate reads them.
    pub settings: serde_json::Value,
    /// How it signs in.
    pub auth: Auth,
    /// Only these mailbox ids, when set.
    #[serde(default)]
    pub include: Option<Vec<String>>,
    /// Mailbox ids never synced.
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Paused accounts are not synced.
    #[serde(default)]
    pub paused: bool,
    /// How the account sends mail, when not the provider's own API (needed for IMAP).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send: Option<SendSettings>,
    /// Where the account's calendars and contacts are, when they are synced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pim: Option<PimSettings>,
}

/// Which calendars and contacts service an account uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PimKind {
    /// CalDAV and CardDAV.
    Dav,
    /// Google Calendar and People.
    Google,
    /// Microsoft Graph calendars and contacts.
    Graph,
    /// JMAP for Calendars and Contacts.
    Jmap,
}

/// Where an account's calendars and contacts are. Holds no secret: the account's credentials
/// are used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PimSettings {
    /// The service.
    pub kind: PimKind,
    /// Its settings, as the provider crate reads them (for DAV: `calendars`, `contacts`, optional
    /// `username`; for Google, Graph and JMAP: the provider's own settings, `{}` for defaults;
    /// for JMAP and an empty object, the account's mail settings).
    #[serde(default)]
    pub settings: serde_json::Value,
    /// How the service signs in, when not with the account's own credentials: `password` uses
    /// the password stored with [`Accounts::set_pim_password`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<PimAuth>,
}

/// Credentials of an account's calendars and contacts that differ from its mail credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PimAuth {
    /// A password of its own, sealed at `credentials/{account}/pim-password`.
    Password,
}

impl AccountRecord {
    /// The sending service and its settings: [`AccountRecord::send`] when set, else the
    /// provider's own API for Gmail, Graph and JMAP, with the account's settings; `None` for an
    /// IMAP account without `send`. Settings that are `null` are the account's settings, and SMTP
    /// settings without a `username` key take the account's user name.
    pub fn sender(&self) -> Option<(SenderKind, serde_json::Value)> {
        let (kind, settings) = match &self.send {
            Some(send) => (send.kind, send.settings.clone()),
            None => match self.provider {
                ProviderKind::Imap => return None,
                ProviderKind::Jmap => (SenderKind::Jmap, serde_json::Value::Null),
                ProviderKind::Gmail => (SenderKind::Gmail, serde_json::Value::Null),
                ProviderKind::Graph => (SenderKind::Graph, serde_json::Value::Null),
            },
        };
        let mut settings = if settings.is_null() {
            self.settings.clone()
        } else {
            settings
        };
        if kind == SenderKind::Smtp
            && let Some(object) = settings.as_object_mut()
            && !object.contains_key("username")
            && let Some(user) = self.settings.get("username")
        {
            object.insert("username".into(), user.clone());
        }
        Some((kind, settings))
    }
}

impl Migrate for AccountRecord {
    const VERSION: u16 = 3;

    fn migrate(v: u16, data: serde_json::Value) -> Result<Self, String> {
        match v {
            1 | 2 => serde_json::from_value(data).map_err(|e| e.to_string()),
            _ => Err(format!("no migration from version {v}")),
        }
    }
}

/// Which sending service an account uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SenderKind {
    /// SMTP submission.
    Smtp,
    /// The Gmail API.
    Gmail,
    /// Microsoft Graph.
    Graph,
    /// JMAP submission.
    Jmap,
    /// Amazon SES, signing with the access key stored with [`Accounts::set_send_key`] instead
    /// of the account's credentials.
    Ses,
}

/// How an account sends mail. Holds no secret: the account's credentials are used, or for
/// [`SenderKind::Ses`] the sealed send key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendSettings {
    /// The sending service.
    pub kind: SenderKind,
    /// Its settings (for SMTP: `host`, `port`, `security`, `username`; for SES: `region`,
    /// optional `endpoint`, `configuration_set`, `from_identity_arn`, `message_id_domain`), as the
    /// sender crate reads them; `null` for the account's own settings.
    #[serde(default)]
    pub settings: serde_json::Value,
}

/// Errors of the account store.
#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    /// Storage failed.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// Sealing or opening failed.
    #[error(transparent)]
    Keyring(#[from] skein_keyring::KeyringError),
    /// The record was changed by someone else meanwhile.
    #[error("the account changed meanwhile")]
    Conflict,
}

/// Account records and passwords of all tenants in one control store.
#[derive(Clone)]
pub struct Accounts {
    control: Arc<dyn ControlStore>,
    keyring: Arc<dyn Keyring>,
}

fn record_path(account: &AccountId) -> String {
    format!("accounts/{account}")
}

fn password_path(account: &AccountId) -> String {
    format!("credentials/{account}/password")
}

fn pim_password_path(account: &AccountId) -> String {
    format!("credentials/{account}/pim-password")
}

fn send_key_path(account: &AccountId) -> String {
    format!("credentials/{account}/send-key")
}

#[derive(Serialize, Deserialize)]
struct SealedKey {
    id: String,
    secret: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session_token: Option<String>,
}

impl Accounts {
    /// Records in `control`, secrets sealed by `keyring`.
    pub fn new(control: Arc<dyn ControlStore>, keyring: Arc<dyn Keyring>) -> Self {
        Self { control, keyring }
    }

    /// Creates or replaces an account record.
    pub async fn put(&self, tenant: &TenantId, record: &AccountRecord) -> Result<(), AccountError> {
        self.control
            .put(
                tenant,
                &record_path(&record.account),
                encode_record(record)?,
                Expect::Any,
            )
            .await?;
        Ok(())
    }

    /// The account, `None` when missing.
    pub async fn get(
        &self,
        tenant: &TenantId,
        account: &AccountId,
    ) -> Result<Option<AccountRecord>, AccountError> {
        match self.control.get(tenant, &record_path(account)).await? {
            None => Ok(None),
            Some((bytes, _)) => Ok(Some(decode_record(&bytes)?)),
        }
    }

    /// Every account of the tenant, by id.
    pub async fn list(&self, tenant: &TenantId) -> Result<Vec<AccountRecord>, AccountError> {
        let mut out = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let page = self
                .control
                .list(tenant, "accounts", after.as_deref(), 1000)
                .await?;
            for path in &page {
                if let Some((bytes, _)) = self.control.get(tenant, path).await? {
                    out.push(decode_record::<AccountRecord>(&bytes)?);
                }
            }
            if page.len() < 1000 {
                return Ok(out);
            }
            after = page.last().cloned();
        }
    }

    /// Removes the account, its passwords and its send key. OAuth grants are removed through the
    /// token manager.
    pub async fn delete(&self, tenant: &TenantId, account: &AccountId) -> Result<(), AccountError> {
        for path in [
            password_path(account),
            pim_password_path(account),
            send_key_path(account),
        ] {
            self.control.delete(tenant, &path, Expect::Any).await?;
        }
        self.control
            .delete(tenant, &record_path(account), Expect::Any)
            .await?;
        Ok(())
    }

    async fn store_secret(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        path: &str,
        plain: &[u8],
    ) -> Result<(), AccountError> {
        let sealed = self
            .keyring
            .seal(&KeyScope::account_of(tenant, account), path, plain)
            .await?;
        self.control
            .put(tenant, path, Bytes::from(sealed), Expect::Any)
            .await?;
        Ok(())
    }

    async fn secret(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        path: &str,
    ) -> Result<Option<Vec<u8>>, AccountError> {
        let Some((sealed, version)) = self.control.get(tenant, path).await? else {
            return Ok(None);
        };
        let opened = open_account(&*self.keyring, tenant, account, path, &sealed).await?;
        if !opened.is_legacy() {
            return Ok(Some(opened.into_plaintext()));
        }
        let plain = opened.into_plaintext();
        let resealed = self
            .keyring
            .seal(&KeyScope::account_of(tenant, account), path, &plain)
            .await?;
        match self
            .control
            .put(
                tenant,
                path,
                Bytes::from(resealed),
                Expect::Version(version),
            )
            .await
        {
            Ok(_) | Err(StorageError::Conflict) => {}
            Err(e) => {
                warn!(tenant = %tenant, account = %account, error = %e, "re-sealing a secret under the account's key failed")
            }
        }
        Ok(Some(plain))
    }

    /// Seals and stores the account's password under the account's key.
    pub async fn set_password(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        password: &str,
    ) -> Result<(), AccountError> {
        self.store_secret(
            tenant,
            account,
            &password_path(account),
            password.as_bytes(),
        )
        .await
    }

    /// Seals and stores the password of the account's calendars and contacts, used when its
    /// [`PimSettings::auth`] is `password`.
    pub async fn set_pim_password(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        password: &str,
    ) -> Result<(), AccountError> {
        self.store_secret(
            tenant,
            account,
            &pim_password_path(account),
            password.as_bytes(),
        )
        .await
    }

    /// Seals and stores the access key the account's sending service signs with, used when its
    /// [`SendSettings::kind`] is [`SenderKind::Ses`]. Replaces any earlier key; never returned.
    pub async fn set_send_key(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        id: &str,
        secret: &str,
        session_token: Option<&str>,
    ) -> Result<(), AccountError> {
        let plain = serde_json::to_vec(&SealedKey {
            id: id.to_owned(),
            secret: secret.to_owned(),
            session_token: session_token.map(str::to_owned),
        })
        .expect("plain struct");
        self.store_secret(tenant, account, &send_key_path(account), &plain)
            .await
    }

    async fn send_key(
        &self,
        tenant: &TenantId,
        account: &AccountId,
    ) -> Result<Option<Credentials>, AccountError> {
        let Some(plain) = self
            .secret(tenant, account, &send_key_path(account))
            .await?
        else {
            return Ok(None);
        };
        Ok(serde_json::from_slice::<SealedKey>(&plain)
            .ok()
            .map(|key| Credentials::AccessKey {
                id: key.id,
                secret: key.secret,
                session_token: key.session_token,
            }))
    }

    async fn pim_password(
        &self,
        tenant: &TenantId,
        account: &AccountId,
    ) -> Result<Option<String>, AccountError> {
        Ok(self
            .secret(tenant, account, &pim_password_path(account))
            .await?
            .map(|plain| String::from_utf8_lossy(&plain).into_owned()))
    }

    async fn password(
        &self,
        tenant: &TenantId,
        account: &AccountId,
    ) -> Result<Option<String>, AccountError> {
        Ok(self
            .secret(tenant, account, &password_path(account))
            .await?
            .map(|plain| String::from_utf8_lossy(&plain).into_owned()))
    }
}

/// Named OAuth clients, as configured by the operator.
#[derive(Clone, Default)]
pub struct OAuthClients(HashMap<String, Client>);

impl OAuthClients {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds or replaces a client.
    pub fn insert(&mut self, name: impl Into<String>, client: Client) {
        self.0.insert(name.into(), client);
    }

    /// The client named `name`.
    pub fn get(&self, name: &str) -> Option<&Client> {
        self.0.get(name)
    }
}

/// Builds a provider from an account record and resolved credentials. Implemented by the
/// composition root, which is the only place that knows provider crates.
pub trait ProviderFactory: Send + Sync {
    /// A provider for `record` signing in with `credentials`. `MailError::Config` for settings
    /// the provider cannot use.
    fn build(
        &self,
        record: &AccountRecord,
        credentials: Credentials,
    ) -> Result<Arc<dyn MailProvider>, MailError>;

    /// The same as [`ProviderFactory::build`] for an account of `tenant`; the directory always
    /// calls this one, so a factory can share per-account state such as a request throttle
    /// between the providers and senders of one account. By default ignores `tenant`.
    fn build_in(
        &self,
        tenant: &TenantId,
        record: &AccountRecord,
        credentials: Credentials,
    ) -> Result<Arc<dyn MailProvider>, MailError> {
        let _ = tenant;
        self.build(record, credentials)
    }
}

/// Builds a calendars and contacts provider from an account record and resolved credentials.
/// Implemented by the composition root.
pub trait PimFactory: Send + Sync {
    /// A provider for `record`'s [`PimSettings`] signing in with `credentials`.
    fn build(
        &self,
        record: &AccountRecord,
        settings: &PimSettings,
        credentials: Credentials,
    ) -> Result<Arc<dyn PimProvider>, PimError>;

    /// The same as [`PimFactory::build`] for an account of `tenant`; the directory always calls
    /// this one. By default ignores `tenant`.
    fn build_in(
        &self,
        tenant: &TenantId,
        record: &AccountRecord,
        settings: &PimSettings,
        credentials: Credentials,
    ) -> Result<Arc<dyn PimProvider>, PimError> {
        let _ = tenant;
        self.build(record, settings, credentials)
    }
}

/// Builds a sender from an account record and resolved credentials. Implemented by the
/// composition root, which is the only place that knows sender crates.
pub trait SenderFactory: Send + Sync {
    /// A sender of `kind` with `settings` (from [`AccountRecord::sender`]) signing in with
    /// `credentials`. `SendError::Invalid` for settings the sender cannot use.
    fn build(
        &self,
        record: &AccountRecord,
        kind: SenderKind,
        settings: &serde_json::Value,
        credentials: Credentials,
    ) -> Result<Arc<dyn Sender>, SendError>;

    /// The same as [`SenderFactory::build`] for an account of `tenant`; [`Senders`] always calls
    /// this one. By default ignores `tenant`.
    fn build_in(
        &self,
        tenant: &TenantId,
        record: &AccountRecord,
        kind: SenderKind,
        settings: &serde_json::Value,
        credentials: Credentials,
    ) -> Result<Arc<dyn Sender>, SendError> {
        let _ = tenant;
        self.build(record, kind, settings, credentials)
    }
}

/// The engine's [`SenderDirectory`] over [`Accounts`]: reads the account record and resolves
/// its credentials each time a sender is asked for, which happens only when the owner sends.
pub struct Senders {
    accounts: Accounts,
    tokens: Arc<TokenManager>,
    clients: OAuthClients,
    factory: Arc<dyn SenderFactory>,
}

impl Senders {
    /// Senders for the accounts in `accounts`, built by `factory`.
    pub fn new(
        accounts: Accounts,
        tokens: Arc<TokenManager>,
        clients: OAuthClients,
        factory: Arc<dyn SenderFactory>,
    ) -> Self {
        Self {
            accounts,
            tokens,
            clients,
            factory,
        }
    }
}

#[async_trait]
impl SenderDirectory for Senders {
    async fn sender(
        &self,
        tenant: &TenantId,
        account: &AccountId,
    ) -> Result<Option<Arc<dyn Sender>>, SendError> {
        let record = match self.accounts.get(tenant, account).await {
            Ok(Some(record)) => record,
            Ok(None) => return Ok(None),
            Err(e) => return Err(SendError::Unavailable(e.to_string())),
        };
        let Some((kind, settings)) = record.sender() else {
            return Ok(None);
        };
        if kind == SenderKind::Ses {
            let key = self
                .accounts
                .send_key(tenant, account)
                .await
                .map_err(|e| SendError::Unavailable(e.to_string()))?
                .ok_or_else(|| SendError::Auth("the account has no send key".into()))?;
            return self
                .factory
                .build_in(tenant, &record, kind, &settings, key)
                .map(Some);
        }
        let credentials = credentials(&self.accounts, &self.tokens, &self.clients, tenant, &record)
            .await
            .map_err(|e| match e {
                Unresolved::Auth => SendError::Auth("the account cannot sign in".into()),
                Unresolved::Config(text) => SendError::Invalid(text),
                Unresolved::Unavailable(text) => SendError::Unavailable(text),
            })?;
        self.factory
            .build_in(tenant, &record, kind, &settings, credentials)
            .map(Some)
    }
}

enum Unresolved {
    Auth,
    Config(String),
    Unavailable(String),
}

async fn credentials(
    accounts: &Accounts,
    tokens: &TokenManager,
    clients: &OAuthClients,
    tenant: &TenantId,
    record: &AccountRecord,
) -> Result<Credentials, Unresolved> {
    match &record.auth {
        Auth::Password => {
            let secret = accounts
                .password(tenant, &record.account)
                .await
                .map_err(|e| Unresolved::Unavailable(e.to_string()))?
                .ok_or(Unresolved::Auth)?;
            Ok(Credentials::Password { secret })
        }
        Auth::OAuth { client } => {
            let client = clients.get(client).ok_or_else(|| {
                Unresolved::Config("the account's OAuth client is not configured".into())
            })?;
            let token = tokens
                .access_token(tenant, &record.account, client)
                .await
                .map_err(|e| {
                    warn!(account = %record.account, transient = e.is_transient(), "no access token");
                    match e {
                        OAuthError::Revoked(_) | OAuthError::NoGrant | OAuthError::Denied(_) => {
                            Unresolved::Auth
                        }
                        OAuthError::Rejected(reason) => Unresolved::Config(reason),
                        other => Unresolved::Unavailable(other.to_string()),
                    }
                })?;
            Ok(Credentials::AccessToken { token })
        }
    }
}

/// The tenants that exist, kept as empty objects under `system/tenants/` in an object store, so
/// the node loop and the server agree on them without listing every tenant's data.
#[derive(Clone)]
pub struct TenantRegistry {
    objects: Arc<dyn Objects>,
}

impl TenantRegistry {
    /// A registry in `objects`.
    pub fn new(objects: Arc<dyn Objects>) -> Self {
        Self { objects }
    }

    fn prefix() -> ObjectKey {
        ObjectKey::root("system")
            .and_then(|k| k.join("tenants"))
            .expect("constant")
    }

    /// Registers a tenant; registering twice changes nothing.
    pub async fn add(&self, tenant: &TenantId) -> Result<(), StorageError> {
        let key = Self::prefix().join(tenant.as_str())?;
        match self.objects.put(&key, Bytes::new(), Expect::Absent).await {
            Ok(_) | Err(StorageError::Conflict) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Unregisters a tenant. Its data is not touched.
    pub async fn remove(&self, tenant: &TenantId) -> Result<(), StorageError> {
        self.objects
            .delete(&Self::prefix().join(tenant.as_str())?, Expect::Any)
            .await
    }

    /// Whether a tenant is registered.
    pub async fn contains(&self, tenant: &TenantId) -> Result<bool, StorageError> {
        Ok(self
            .objects
            .get(&Self::prefix().join(tenant.as_str())?)
            .await?
            .is_some())
    }

    /// Every registered tenant, by id.
    pub async fn list(&self) -> Result<Vec<TenantId>, StorageError> {
        let mut out = Vec::new();
        let mut after = None;
        loop {
            let page = self
                .objects
                .list(&Self::prefix(), after.as_ref(), 1000)
                .await?;
            out.extend(page.iter().filter_map(|k| TenantId::new(k.last()).ok()));
            if page.len() < 1000 {
                return Ok(out);
            }
            after = page.last().cloned();
        }
    }
}

/// The engine's [`AccountDirectory`] over [`Accounts`] for every registered tenant.
pub struct Directory {
    tenants: TenantRegistry,
    accounts: Accounts,
    tokens: Arc<TokenManager>,
    clients: OAuthClients,
    factory: Arc<dyn ProviderFactory>,
    pim: Option<Arc<dyn PimFactory>>,
}

impl Directory {
    /// Accounts of the tenants in `tenants`, with providers from `factory`.
    pub fn new(
        tenants: TenantRegistry,
        accounts: Accounts,
        tokens: Arc<TokenManager>,
        clients: OAuthClients,
        factory: Arc<dyn ProviderFactory>,
    ) -> Self {
        Self {
            tenants,
            accounts,
            tokens,
            clients,
            factory,
            pim: None,
        }
    }

    /// Also builds calendars and contacts providers for accounts with [`PimSettings`].
    pub fn with_pim(mut self, factory: Arc<dyn PimFactory>) -> Self {
        self.pim = Some(factory);
        self
    }
}

#[async_trait]
impl AccountDirectory for Directory {
    async fn accounts(&self) -> Result<Vec<AccountEntry>, EngineError> {
        let mut out = Vec::new();
        for tenant in &self.tenants.list().await? {
            let records = self.accounts.list(tenant).await.map_err(|e| match e {
                AccountError::Storage(s) => EngineError::from(s),
                other => EngineError::Mail(MailError::Config(other.to_string())),
            })?;
            for record in records.into_iter().filter(|r| !r.paused) {
                let mut config = AccountConfig::new(tenant.clone(), record.account.clone());
                config.include = record.include.clone();
                config.exclude = record.exclude.clone();
                let pim: Option<Arc<dyn PimProvider>> = match (&self.pim, &record.pim) {
                    (Some(factory), Some(_)) => Some(Arc::new(LazyPim {
                        tenant: tenant.clone(),
                        record: record.clone(),
                        accounts: self.accounts.clone(),
                        tokens: self.tokens.clone(),
                        clients: self.clients.clone(),
                        factory: factory.clone(),
                    })),
                    _ => None,
                };
                let provider: Arc<dyn MailProvider> = Arc::new(LazyProvider {
                    tenant: tenant.clone(),
                    record,
                    accounts: self.accounts.clone(),
                    tokens: self.tokens.clone(),
                    clients: self.clients.clone(),
                    factory: self.factory.clone(),
                });
                out.push(AccountEntry {
                    config,
                    provider,
                    pim,
                });
            }
        }
        Ok(out)
    }
}

/// A provider that resolves credentials each time it connects or watches.
struct LazyProvider {
    tenant: TenantId,
    record: AccountRecord,
    accounts: Accounts,
    tokens: Arc<TokenManager>,
    clients: OAuthClients,
    factory: Arc<dyn ProviderFactory>,
}

impl LazyProvider {
    async fn credentials(&self) -> Result<Credentials, MailError> {
        credentials(
            &self.accounts,
            &self.tokens,
            &self.clients,
            &self.tenant,
            &self.record,
        )
        .await
        .map_err(|e| match e {
            Unresolved::Auth => MailError::Auth,
            Unresolved::Config(text) => MailError::Config(text),
            Unresolved::Unavailable(text) => MailError::Network(text),
        })
    }

    async fn inner(&self) -> Result<Arc<dyn MailProvider>, MailError> {
        let credentials = self.credentials().await?;
        self.factory
            .build_in(&self.tenant, &self.record, credentials)
    }
}

#[async_trait]
impl MailProvider for LazyProvider {
    async fn connect(&self) -> Result<Box<dyn MailSession>, MailError> {
        self.inner().await?.connect().await
    }

    async fn watch(&self, mailboxes: &[String]) -> Result<Option<Box<dyn MailWatch>>, MailError> {
        self.inner().await?.watch(mailboxes).await
    }

    async fn subscribe(
        &self,
        target: &skein_mail::PushTarget,
    ) -> Result<Option<skein_mail::Subscription>, MailError> {
        self.inner().await?.subscribe(target).await
    }

    async fn renew(
        &self,
        subscription: &skein_mail::Subscription,
        target: &skein_mail::PushTarget,
    ) -> Result<Option<skein_mail::Subscription>, MailError> {
        self.inner().await?.renew(subscription, target).await
    }

    async fn unsubscribe(&self, subscription: &skein_mail::Subscription) -> Result<(), MailError> {
        self.inner().await?.unsubscribe(subscription).await
    }
}

/// A calendars and contacts provider that resolves credentials each time it connects.
struct LazyPim {
    tenant: TenantId,
    record: AccountRecord,
    accounts: Accounts,
    tokens: Arc<TokenManager>,
    clients: OAuthClients,
    factory: Arc<dyn PimFactory>,
}

#[async_trait]
impl PimProvider for LazyPim {
    async fn connect(&self) -> Result<Box<dyn skein_pim::PimSession>, PimError> {
        if let Some(PimSettings {
            auth: Some(PimAuth::Password),
            ..
        }) = &self.record.pim
        {
            let secret = self
                .accounts
                .pim_password(&self.tenant, &self.record.account)
                .await
                .map_err(|e| PimError::Network(e.to_string()))?
                .ok_or(PimError::Auth)?;
            let settings = self.record.pim.as_ref().expect("matched above");
            return self
                .factory
                .build_in(
                    &self.tenant,
                    &self.record,
                    settings,
                    Credentials::Password { secret },
                )?
                .connect()
                .await;
        }
        let credentials = credentials(
            &self.accounts,
            &self.tokens,
            &self.clients,
            &self.tenant,
            &self.record,
        )
        .await
        .map_err(|e| match e {
            Unresolved::Auth => PimError::Auth,
            Unresolved::Config(text) => PimError::Config(text),
            Unresolved::Unavailable(text) => PimError::Network(text),
        })?;
        let settings =
            self.record.pim.as_ref().ok_or_else(|| {
                PimError::Config("the account has no calendars or contacts".into())
            })?;
        self.factory
            .build_in(&self.tenant, &self.record, settings, credentials)?
            .connect()
            .await
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod send_tests;
