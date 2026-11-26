use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use baton_signal::Signal;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use skein_core::{AccountId, TenantId, Timestamp, coordination};
use skein_keyring::{KeyScope, Keyring, KeyringError, open_account};
use skein_storage::{ControlStore, Expect, StorageError};
use tracing::{debug, warn};

use crate::{Client, OAuthError, TokenEndpoint, Tokens};

/// What is kept for an account: a refresh token, the current access token, or both. Stored sealed
/// with the account's key; `Debug` never shows a token.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Grant {
    /// Gets new access tokens; `None` for an access token handed in without one.
    pub refresh_token: Option<String>,
    /// The current access token.
    pub access_token: Option<String>,
    /// When the access token expires.
    pub expires_at: Option<Timestamp>,
    /// The scopes granted, when known.
    pub scope: Option<String>,
}

impl std::fmt::Debug for Grant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Grant")
            .field("refresh_token", &self.refresh_token.is_some())
            .field("access_token", &self.access_token.is_some())
            .field("expires_at", &self.expires_at)
            .field("scope", &self.scope)
            .finish()
    }
}

impl Grant {
    /// The grant tokens from a sign-in give, at `now`.
    pub fn from_tokens(tokens: &Tokens, now: Timestamp) -> Self {
        Self {
            refresh_token: tokens.refresh_token.clone(),
            access_token: Some(tokens.access_token.clone()),
            expires_at: Some(now.plus_ms(tokens.expires_in.as_millis() as i64)),
            scope: tokens.scope.clone(),
        }
    }

    /// A grant an integrator hands in: an access token with its expiry and, if they have one, a
    /// refresh token Skein may use with the matching client.
    pub fn external(
        access_token: impl Into<String>,
        expires_at: Option<Timestamp>,
        refresh_token: Option<String>,
    ) -> Self {
        Self {
            refresh_token,
            access_token: Some(access_token.into()),
            expires_at,
            scope: None,
        }
    }

    fn usable(&self, now: Timestamp, margin: Duration) -> Option<&str> {
        let token = self.access_token.as_deref()?;
        match self.expires_at {
            Some(at) if at.0 - margin.as_millis() as i64 > now.0 => Some(token),
            Some(_) => None,
            None => Some(token),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Cached {
    token: String,
    expires_at: Timestamp,
}

/// Keeps OAuth grants sealed in control records (`credentials/{account}/oauth`) and hands out
/// access tokens, refreshing them when they are about to expire.
///
/// - Call `access_token` only on the account's owner: refreshing in one place matters because
///   Microsoft rotates refresh tokens, and two nodes refreshing at once would invalidate each
///   other. Within a process, concurrent calls for one account refresh once.
/// - A rotated refresh token is stored back with compare-and-swap before the new access token is
///   handed out, so it is never lost.
/// - With a signal backend, access tokens are cached there as expiring values in the tenant's
///   group, sealed with the account's key, so a restart or another node does not refresh
///   needlessly.
/// - A refresh token the provider no longer accepts is [`OAuthError::Revoked`]; so is an expired
///   access token handed in without a refresh token.
pub struct TokenManager {
    endpoint: Arc<dyn TokenEndpoint>,
    control: Arc<dyn ControlStore>,
    keyring: Arc<dyn Keyring>,
    signal: Option<Arc<dyn Signal>>,
    margin: Duration,
    locks: Mutex<RefreshLocks>,
}

type RefreshLocks = HashMap<(TenantId, AccountId), Arc<tokio::sync::Mutex<()>>>;

fn path(account: &AccountId) -> String {
    format!("credentials/{account}/oauth")
}

fn storage(e: StorageError) -> OAuthError {
    OAuthError::Storage(e.to_string())
}

fn keyring(e: KeyringError) -> OAuthError {
    OAuthError::Storage(e.to_string())
}

impl TokenManager {
    /// Grants in `control`, sealed by `keyring`, refreshed through `endpoint`.
    pub fn new(
        endpoint: Arc<dyn TokenEndpoint>,
        control: Arc<dyn ControlStore>,
        keyring: Arc<dyn Keyring>,
    ) -> Self {
        Self {
            endpoint,
            control,
            keyring,
            signal: None,
            margin: Duration::from_secs(120),
            locks: Mutex::new(HashMap::new()),
        }
    }

    /// Also caches access tokens in `signal`, sealed, as values that expire with the token.
    pub fn with_signal(mut self, signal: Arc<dyn Signal>) -> Self {
        self.signal = Some(signal);
        self
    }

    /// Refreshes when less than `margin` of an access token's life is left (two minutes by
    /// default).
    pub fn with_margin(mut self, margin: Duration) -> Self {
        self.margin = margin;
        self
    }

    /// Stores (or replaces) the account's grant.
    pub async fn store(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        grant: &Grant,
    ) -> Result<(), OAuthError> {
        let sealed = self.seal(tenant, account, grant).await?;
        self.control
            .put(tenant, &path(account), sealed, Expect::Any)
            .await
            .map_err(storage)?;
        self.drop_cache(tenant, account).await;
        Ok(())
    }

    /// Removes the account's grant.
    pub async fn forget(&self, tenant: &TenantId, account: &AccountId) -> Result<(), OAuthError> {
        self.control
            .delete(tenant, &path(account), Expect::Any)
            .await
            .map_err(storage)?;
        self.drop_cache(tenant, account).await;
        Ok(())
    }

    /// A valid access token for the account, refreshing with `client` when needed.
    pub async fn access_token(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        client: &Client,
    ) -> Result<String, OAuthError> {
        if let Some(token) = self.cached(tenant, account).await {
            return Ok(token);
        }
        let lock = self
            .locks
            .lock()
            .expect("lock")
            .entry((tenant.clone(), account.clone()))
            .or_default()
            .clone();
        let _guard = lock.lock().await;
        if let Some(token) = self.cached(tenant, account).await {
            return Ok(token);
        }
        for _ in 0..3 {
            let (grant, version) = self.load(tenant, account).await?;
            let now = Timestamp::now();
            if let Some(token) = grant.usable(now, self.margin) {
                let token = token.to_owned();
                self.cache(tenant, account, &token, grant.expires_at).await;
                return Ok(token);
            }
            let Some(refresh) = grant.refresh_token.clone() else {
                return Err(OAuthError::Revoked(
                    "the access token expired and there is no refresh token".into(),
                ));
            };
            let tokens = client.refresh(&*self.endpoint, &refresh).await?;
            let mut next = Grant::from_tokens(&tokens, now);
            if next.refresh_token.is_none() {
                next.refresh_token = Some(refresh);
            }
            if next.scope.is_none() {
                next.scope = grant.scope.clone();
            }
            let sealed = self.seal(tenant, account, &next).await?;
            match self
                .control
                .put(tenant, &path(account), sealed, Expect::Version(version))
                .await
            {
                Ok(_) => {
                    debug!(%account, rotated = tokens.refresh_token.is_some(), "access token refreshed");
                    let token = tokens.access_token;
                    self.cache(tenant, account, &token, next.expires_at).await;
                    return Ok(token);
                }
                Err(StorageError::Conflict) => {
                    warn!(%account, "the grant changed while refreshing; reading it again");
                    continue;
                }
                Err(e) => return Err(storage(e)),
            }
        }
        Err(OAuthError::Storage(
            "the grant kept changing while refreshing".into(),
        ))
    }

    async fn load(
        &self,
        tenant: &TenantId,
        account: &AccountId,
    ) -> Result<(Grant, skein_storage::Version), OAuthError> {
        let Some((sealed, version)) = self
            .control
            .get(tenant, &path(account))
            .await
            .map_err(storage)?
        else {
            return Err(OAuthError::NoGrant);
        };
        let opened = open_account(&*self.keyring, tenant, account, &path(account), &sealed)
            .await
            .map_err(keyring)?;
        let legacy = opened.is_legacy();
        let plain = opened.into_plaintext();
        let grant: Grant = serde_json::from_slice(&plain)
            .map_err(|e| OAuthError::Storage(format!("the stored grant does not decode: {e}")))?;
        if !legacy {
            return Ok((grant, version));
        }
        let resealed = self.seal(tenant, account, &grant).await?;
        match self
            .control
            .put(
                tenant,
                &path(account),
                resealed,
                Expect::Version(version.clone()),
            )
            .await
        {
            Ok(next) => Ok((grant, next)),
            Err(StorageError::Conflict) => Ok((grant, version)),
            Err(e) => {
                warn!(%account, error = %e, "re-sealing the grant under the account's key failed");
                Ok((grant, version))
            }
        }
    }

    async fn seal(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        grant: &Grant,
    ) -> Result<Bytes, OAuthError> {
        let plain = serde_json::to_vec(grant).expect("plain struct");
        Ok(Bytes::from(
            self.keyring
                .seal(
                    &KeyScope::account_of(tenant, account),
                    &path(account),
                    &plain,
                )
                .await
                .map_err(keyring)?,
        ))
    }

    fn cache_key(account: &AccountId) -> String {
        format!("oauth/{account}")
    }

    async fn cached(&self, tenant: &TenantId, account: &AccountId) -> Option<String> {
        let signal = self.signal.as_ref()?;
        let sealed = signal
            .get(&coordination::group(tenant), &Self::cache_key(account))
            .await
            .ok()??;
        let plain = self
            .keyring
            .open(
                &KeyScope::account_of(tenant, account),
                &Self::cache_key(account),
                &sealed,
            )
            .await
            .ok()?;
        let cached: Cached = serde_json::from_slice(&plain).ok()?;
        (cached.expires_at.0 - self.margin.as_millis() as i64 > Timestamp::now().0)
            .then_some(cached.token)
    }

    async fn cache(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        token: &str,
        expires_at: Option<Timestamp>,
    ) {
        let (Some(signal), Some(expires_at)) = (&self.signal, expires_at) else {
            return;
        };
        let left = expires_at.0 - Timestamp::now().0;
        if left <= 0 {
            return;
        }
        let plain = serde_json::to_vec(&Cached {
            token: token.to_owned(),
            expires_at,
        })
        .expect("plain struct");
        let Ok(sealed) = self
            .keyring
            .seal(
                &KeyScope::account_of(tenant, account),
                &Self::cache_key(account),
                &plain,
            )
            .await
        else {
            return;
        };
        let _ = signal
            .put(
                &coordination::group(tenant),
                &Self::cache_key(account),
                Bytes::from(sealed),
                Duration::from_millis(left as u64),
            )
            .await;
    }

    async fn drop_cache(&self, tenant: &TenantId, account: &AccountId) {
        if let Some(signal) = &self.signal {
            let _ = signal
                .delete(&coordination::group(tenant), &Self::cache_key(account))
                .await;
        }
    }
}
