//! Sealing secrets (credentials, tokens) and content with a key per tenant or per account.
//!
//! Every tenant has its own key, and every account of a tenant can have its own key under it
//! ([`KeyScope`]). Destroying a key makes everything sealed under it unreadable for good, even
//! copies left in backups or in object storage that were not deleted; destroying a tenant's key
//! destroys the keys of all its accounts too.

#[cfg(feature = "testing")]
pub mod testing;

use async_trait::async_trait;
use skein_core::{AccountId, TenantId};

/// Errors of the keyring contract.
#[derive(Debug, thiserror::Error)]
pub enum KeyringError {
    /// The sealed bytes are damaged, were sealed under another scope or context, or with another
    /// key. Nothing about the plaintext is revealed.
    #[error("sealed data cannot be opened")]
    Invalid,
    /// The scope's key, or the key of the tenant above it, was destroyed.
    #[error("the key was destroyed")]
    Destroyed,
    /// The key store failed; the call may be retried.
    #[error("keyring backend failed: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl KeyringError {
    /// Wraps any backend error.
    pub fn backend(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self::Backend(e.into())
    }
}

/// Whose key seals the bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeyScope {
    /// The tenant's key, for secrets that belong to no single account (webhook secrets, sign-ins
    /// in progress).
    Tenant(TenantId),
    /// One account's key (its credentials, grants and content). It belongs to the tenant: it is
    /// destroyed when the tenant's key is.
    Account(TenantId, AccountId),
}

impl KeyScope {
    /// The tenant scope.
    pub fn tenant_of(tenant: &TenantId) -> Self {
        Self::Tenant(tenant.clone())
    }

    /// The scope of one account.
    pub fn account_of(tenant: &TenantId, account: &AccountId) -> Self {
        Self::Account(tenant.clone(), account.clone())
    }

    /// The tenant the scope belongs to.
    pub fn tenant(&self) -> &TenantId {
        match self {
            Self::Tenant(t) | Self::Account(t, _) => t,
        }
    }

    /// The account, `None` for a tenant scope.
    pub fn account(&self) -> Option<&AccountId> {
        match self {
            Self::Tenant(_) => None,
            Self::Account(_, a) => Some(a),
        }
    }
}

/// Seals and opens bytes with the key of a [`KeyScope`].
///
/// Guarantees (checked by [`testing::keyring`]):
///
/// - `open` returns the plaintext only for the same scope and the same `context` it was sealed
///   with; anything else, including a single changed byte, another account of the same tenant, the
///   tenant scope for bytes sealed under an account and the other way round, is
///   [`KeyringError::Invalid`].
/// - Sealing the same plaintext twice gives different bytes (random nonces).
/// - After `destroy` of a scope, sealing and opening under it fail with
///   [`KeyringError::Destroyed`]. Destroying a tenant scope also destroys every account scope of
///   that tenant; destroying an account scope affects no other scope. Other instances that cache
///   keys follow within their documented cache lifetime. A scope used again after `destroy` stays
///   destroyed.
/// - Concurrent first use of a scope from several nodes ends with one key.
#[async_trait]
pub trait Keyring: Send + Sync {
    /// Seals `plaintext`, bound to `scope` and `context` (for example `credentials/{account}`).
    async fn seal(
        &self,
        scope: &KeyScope,
        context: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, KeyringError>;

    /// Opens bytes sealed with the same scope and context.
    async fn open(
        &self,
        scope: &KeyScope,
        context: &str,
        sealed: &[u8],
    ) -> Result<Vec<u8>, KeyringError>;

    /// Destroys the scope's key for good; for a tenant scope, the keys of all its accounts too.
    async fn destroy(&self, scope: &KeyScope) -> Result<(), KeyringError>;
}

/// What [`open_account`] opened.
#[derive(Debug, PartialEq, Eq)]
pub enum Opened {
    /// Bytes sealed under the account's key.
    Account(Vec<u8>),
    /// Bytes sealed under the tenant's key with the same context, as every account secret was
    /// before account scopes existed. The caller should seal the plaintext again under the
    /// account's scope and store it in place of the old bytes.
    Legacy(Vec<u8>),
}

impl Opened {
    /// The plaintext, whichever key opened it.
    pub fn into_plaintext(self) -> Vec<u8> {
        match self {
            Self::Account(p) | Self::Legacy(p) => p,
        }
    }

    /// Whether the tenant's key opened it.
    pub fn is_legacy(&self) -> bool {
        matches!(self, Self::Legacy(_))
    }
}

/// Opens an account's secret, accepting bytes sealed under the tenant scope with the same context
/// when the account scope refuses them as [`KeyringError::Invalid`]. Only `Invalid` falls back: a
/// destroyed account key stays [`KeyringError::Destroyed`], so a destroyed account never opens
/// through its tenant. The fallback exists to read secrets written before account scopes and will
/// be removed in a later release; see `docs/MIGRATION.md`.
pub async fn open_account(
    ring: &dyn Keyring,
    tenant: &TenantId,
    account: &AccountId,
    context: &str,
    sealed: &[u8],
) -> Result<Opened, KeyringError> {
    match ring
        .open(&KeyScope::account_of(tenant, account), context, sealed)
        .await
    {
        Ok(plain) => Ok(Opened::Account(plain)),
        Err(KeyringError::Invalid) => ring
            .open(&KeyScope::tenant_of(tenant), context, sealed)
            .await
            .map(Opened::Legacy),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    fn tenant() -> TenantId {
        TenantId::new("t1").unwrap()
    }

    fn account() -> AccountId {
        AccountId::new("a1").unwrap()
    }

    #[test]
    fn scopes_name_their_tenant_and_account() {
        let t = KeyScope::tenant_of(&tenant());
        let a = KeyScope::account_of(&tenant(), &account());
        assert_eq!(t.tenant(), &tenant());
        assert_eq!(t.account(), None);
        assert_eq!(a.tenant(), &tenant());
        assert_eq!(a.account(), Some(&account()));
        assert_ne!(t, a);
    }

    struct Scripted {
        account: Result<Vec<u8>, KeyringError>,
        tenant: Mutex<Option<Result<Vec<u8>, KeyringError>>>,
    }

    fn copy(r: &Result<Vec<u8>, KeyringError>) -> Result<Vec<u8>, KeyringError> {
        match r {
            Ok(p) => Ok(p.clone()),
            Err(KeyringError::Invalid) => Err(KeyringError::Invalid),
            Err(KeyringError::Destroyed) => Err(KeyringError::Destroyed),
            Err(KeyringError::Backend(e)) => Err(KeyringError::backend(e.to_string())),
        }
    }

    #[async_trait]
    impl Keyring for Scripted {
        async fn seal(&self, _: &KeyScope, _: &str, _: &[u8]) -> Result<Vec<u8>, KeyringError> {
            Err(KeyringError::backend("not scripted"))
        }
        async fn open(&self, scope: &KeyScope, _: &str, _: &[u8]) -> Result<Vec<u8>, KeyringError> {
            match scope.account() {
                Some(_) => copy(&self.account),
                None => self
                    .tenant
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap_or_else(|| Err(KeyringError::backend("opened twice"))),
            }
        }
        async fn destroy(&self, _: &KeyScope) -> Result<(), KeyringError> {
            Ok(())
        }
    }

    fn ring(
        account: Result<Vec<u8>, KeyringError>,
        tenant: Result<Vec<u8>, KeyringError>,
    ) -> Scripted {
        Scripted {
            account,
            tenant: Mutex::new(Some(tenant)),
        }
    }

    #[tokio::test]
    async fn account_keys_win_and_tenant_keys_open_legacy_data() {
        let opened = open_account(
            &ring(Ok(b"new".to_vec()), Ok(b"old".to_vec())),
            &tenant(),
            &account(),
            "c",
            b"x",
        )
        .await
        .unwrap();
        assert_eq!(opened, Opened::Account(b"new".to_vec()));
        assert!(!opened.is_legacy());

        let opened = open_account(
            &ring(Err(KeyringError::Invalid), Ok(b"old".to_vec())),
            &tenant(),
            &account(),
            "c",
            b"x",
        )
        .await
        .unwrap();
        assert!(opened.is_legacy());
        assert_eq!(opened.into_plaintext(), b"old".to_vec());
    }

    #[tokio::test]
    async fn only_unreadable_data_falls_back_to_the_tenant_key() {
        let destroyed = open_account(
            &ring(Err(KeyringError::Destroyed), Ok(b"old".to_vec())),
            &tenant(),
            &account(),
            "c",
            b"x",
        )
        .await;
        assert!(matches!(destroyed, Err(KeyringError::Destroyed)));
        let failed = open_account(
            &ring(Err(KeyringError::backend("down")), Ok(b"old".to_vec())),
            &tenant(),
            &account(),
            "c",
            b"x",
        )
        .await;
        assert!(matches!(failed, Err(KeyringError::Backend(_))));
        let neither = open_account(
            &ring(Err(KeyringError::Invalid), Err(KeyringError::Invalid)),
            &tenant(),
            &account(),
            "c",
            b"x",
        )
        .await;
        assert!(matches!(neither, Err(KeyringError::Invalid)));
    }
}
