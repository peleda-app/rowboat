//! What managing a node changes: checks on account records and the secrets handed in for them,
//! and registering, unregistering and purging tenants. The `skein` binary's subcommands call
//! these, and the node's Baton commands will.

use skein_core::{AccountId, TenantId};
use skein_keyring::{KeyScope, Keyring, KeyringError};
use skein_oauth::TokenManager;
use skein_storage::{Storage, StorageError};

use crate::{AccountRecord, Accounts, Auth, OAuthClients, SenderKind, TenantRegistry};

/// Largest settings object of a record (`settings`, `send.settings`, `pim.settings`), in bytes of
/// JSON.
pub const MAX_SETTINGS: usize = 64 * 1024;
/// Longest password, in bytes.
pub const MAX_PASSWORD: usize = 4096;
/// Longest OAuth token, in bytes.
pub const MAX_TOKEN: usize = 16 * 1024;

/// Why a record, a secret or a tenant change was refused. `Display` never carries the value.
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    /// The input breaks a rule; `code` is stable, `reason` says which rule.
    #[error("{code}: {reason}")]
    Invalid {
        /// A stable code, such as `invalid_settings`.
        code: &'static str,
        /// The rule that was broken.
        reason: &'static str,
    },
    /// No such tenant or account.
    #[error("not found")]
    NotFound,
    /// The tenant was purged; its key is destroyed, so its id cannot be used again.
    #[error("this tenant was purged; use another tenant id")]
    Purged,
    /// Storage failed.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// The keyring failed.
    #[error(transparent)]
    Keyring(#[from] KeyringError),
    /// Removing an OAuth grant failed.
    #[error("the OAuth grant could not be removed")]
    Grant,
}

impl From<crate::AccountError> for AdminError {
    fn from(e: crate::AccountError) -> Self {
        match e {
            crate::AccountError::Storage(s) => Self::Storage(s),
            crate::AccountError::Keyring(k) => Self::Keyring(k),
            crate::AccountError::Conflict => Self::Storage(StorageError::Conflict),
        }
    }
}

fn invalid(code: &'static str, reason: &'static str) -> AdminError {
    AdminError::Invalid { code, reason }
}

fn small_object_or_null(value: &serde_json::Value) -> bool {
    (value.is_object() || value.is_null()) && value.to_string().len() <= MAX_SETTINGS
}

/// Checks a record before it is stored: `settings` is a JSON object, and `send.settings` and
/// `pim.settings` objects or `null`, each at most [`MAX_SETTINGS`]; SES settings name a region,
/// optionally a `message_id_domain` that is a hostname and an `endpoint` that is an `https`
/// origin (plain `http` only to loopback); an OAuth record names a configured client.
pub fn check_record(record: &AccountRecord, clients: &OAuthClients) -> Result<(), AdminError> {
    if !record.settings.is_object() || record.settings.to_string().len() > MAX_SETTINGS {
        return Err(invalid(
            "invalid_settings",
            "settings is a JSON object of at most 64 KiB",
        ));
    }
    if let Some(send) = &record.send {
        if !small_object_or_null(&send.settings) {
            return Err(invalid(
                "invalid_settings",
                "send.settings is a JSON object of at most 64 KiB, or null",
            ));
        }
        if send.kind == SenderKind::Ses {
            check_ses(&send.settings)?;
        }
    }
    if let Some(pim) = &record.pim
        && !small_object_or_null(&pim.settings)
    {
        return Err(invalid(
            "invalid_settings",
            "pim.settings is a JSON object of at most 64 KiB, or null",
        ));
    }
    if let Auth::OAuth { client } = &record.auth
        && clients.get(client).is_none()
    {
        return Err(invalid(
            "unknown_client",
            "no OAuth client with that name is configured",
        ));
    }
    Ok(())
}

/// Checks a password or app password: 1 to [`MAX_PASSWORD`] bytes.
pub fn check_password(password: &str) -> Result<(), AdminError> {
    if password.is_empty() || password.len() > MAX_PASSWORD {
        return Err(invalid("invalid_password", "a password is 1 to 4096 bytes"));
    }
    Ok(())
}

/// Checks an OAuth token handed in: 1 to [`MAX_TOKEN`] bytes without control characters.
pub fn check_token(token: &str) -> Result<(), AdminError> {
    if token.is_empty() || token.len() > MAX_TOKEN || token.chars().any(char::is_control) {
        return Err(invalid(
            "invalid_token",
            "tokens are 1 to 16384 printable characters",
        ));
    }
    Ok(())
}

/// Checks an access key for a sending service: the id is 1 to 128 letters and digits, the
/// secret 1 to 1024 and the session token 1 to 8192 printable ASCII characters.
pub fn check_send_key(
    id: &str,
    secret: &str,
    session_token: Option<&str>,
) -> Result<(), AdminError> {
    if id.is_empty() || id.len() > 128 || !id.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(invalid(
            "invalid_key",
            "access_key_id is 1 to 128 letters and digits",
        ));
    }
    let printable = |v: &str, max: usize| {
        !v.is_empty() && v.len() <= max && v.bytes().all(|b| b.is_ascii_graphic())
    };
    if !printable(secret, 1024) {
        return Err(invalid(
            "invalid_key",
            "secret_access_key is 1 to 1024 printable ASCII characters",
        ));
    }
    if session_token.is_some_and(|t| !printable(t, 8192)) {
        return Err(invalid(
            "invalid_key",
            "session_token is 1 to 8192 printable ASCII characters",
        ));
    }
    Ok(())
}

fn region_name(region: &str) -> bool {
    (1..=32).contains(&region.len())
        && region.starts_with(|c: char| c.is_ascii_lowercase())
        && region.ends_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && region
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn hostname(name: &str) -> bool {
    (1..=253).contains(&name.len())
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn origin_ok(endpoint: &str) -> bool {
    let Ok(url) = url::Url::parse(endpoint) else {
        return false;
    };
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        None => false,
    };
    let scheme_ok = match url.scheme() {
        "https" => true,
        "http" => loopback,
        _ => false,
    };
    scheme_ok
        && url.host().is_some()
        && url.path() == "/"
        && url.query().is_none()
        && url.username().is_empty()
        && url.password().is_none()
}

fn check_ses(settings: &serde_json::Value) -> Result<(), AdminError> {
    let bad = |reason: &'static str| invalid("invalid_settings", reason);
    let region = settings.get("region").and_then(serde_json::Value::as_str);
    if !region.is_some_and(region_name) {
        return Err(bad(
            "send.settings.region is an AWS region name, such as eu-west-1",
        ));
    }
    match settings.get("message_id_domain") {
        None | Some(serde_json::Value::Null) => {}
        Some(serde_json::Value::String(domain)) if hostname(domain.trim()) => {}
        Some(_) => {
            return Err(bad(
                "send.settings.message_id_domain is a hostname, such as eu-west-1.amazonses.com",
            ));
        }
    }
    match settings.get("endpoint") {
        None | Some(serde_json::Value::Null) => Ok(()),
        Some(serde_json::Value::String(endpoint)) if origin_ok(endpoint.trim()) => Ok(()),
        Some(_) => Err(bad(
            "send.settings.endpoint is an https origin (plain http only to loopback)",
        )),
    }
}

/// Registers `tenant` so nodes sync it; registering again changes nothing. A tenant whose key
/// was destroyed by [`purge_tenant`] is [`AdminError::Purged`].
pub async fn register_tenant(
    tenants: &TenantRegistry,
    keyring: &dyn Keyring,
    tenant: &TenantId,
) -> Result<(), AdminError> {
    match keyring
        .seal(&KeyScope::tenant_of(tenant), "tenant-check", b"")
        .await
    {
        Err(KeyringError::Destroyed) => return Err(AdminError::Purged),
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    tenants.add(tenant).await?;
    Ok(())
}

/// Unregisters `tenant`: nodes stop syncing it; its data stays. An unknown tenant is
/// [`AdminError::NotFound`].
pub async fn unregister_tenant(
    tenants: &TenantRegistry,
    tenant: &TenantId,
) -> Result<(), AdminError> {
    if !tenants.contains(tenant).await? {
        return Err(AdminError::NotFound);
    }
    tenants.remove(tenant).await?;
    Ok(())
}

/// What [`purge_tenant`] removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Purged {
    /// Account records deleted.
    pub accounts: usize,
    /// Objects deleted from storage.
    pub objects: u64,
}

/// Deletes every account record, password, send key and OAuth grant of `tenant`, destroys its
/// keyring key (crypto-shredding, so everything sealed for it is unreadable for good), deletes
/// its journal, blobs, commands and control records, and unregisters it. Irreversible; the id
/// cannot be registered again.
pub async fn purge_tenant(
    storage: &Storage,
    accounts: &Accounts,
    tokens: &TokenManager,
    tenants: &TenantRegistry,
    keyring: &dyn Keyring,
    tenant: &TenantId,
) -> Result<Purged, AdminError> {
    let records = accounts.list(tenant).await?;
    for record in &records {
        tokens
            .forget(tenant, &record.account)
            .await
            .map_err(|_| AdminError::Grant)?;
        accounts.delete(tenant, &record.account).await?;
    }
    keyring.destroy(&KeyScope::tenant_of(tenant)).await?;
    let objects = storage.purge_tenant(tenant).await?;
    tenants.remove(tenant).await?;
    Ok(Purged {
        accounts: records.len(),
        objects,
    })
}

/// Deletes an account's record, its sealed passwords and send key, and its OAuth grant. The
/// journal is kept. An unknown account is [`AdminError::NotFound`].
pub async fn delete_account(
    accounts: &Accounts,
    tokens: &TokenManager,
    tenant: &TenantId,
    account: &AccountId,
) -> Result<(), AdminError> {
    if accounts.get(tenant, account).await?.is_none() {
        return Err(AdminError::NotFound);
    }
    tokens
        .forget(tenant, account)
        .await
        .map_err(|_| AdminError::Grant)?;
    accounts.delete(tenant, account).await?;
    Ok(())
}

#[cfg(test)]
#[path = "admin_tests.rs"]
mod tests;
