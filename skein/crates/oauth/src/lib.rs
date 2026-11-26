//! OAuth 2.0 for Google and Microsoft accounts: which scopes a set of domains needs, the
//! authorization code flow with PKCE, exchanging and refreshing tokens, and keeping grants sealed.
//!
//! Talking to a token endpoint goes through the [`TokenEndpoint`] contract (an HTTPS
//! implementation is `skein-oauth-http`), so everything here is tested without a network.
//! Integrators register their own OAuth clients; Skein ships no client ids.

mod redirect;
mod scopes;
mod tokens;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub use redirect::{Redirect, read_redirect};
pub use scopes::{Access, MailAccess, Rw};
pub use tokens::{Grant, TokenManager};

/// When a token response says nothing about its lifetime.
const DEFAULT_LIFETIME: Duration = Duration::from_secs(3600);

/// A provider that signs in with OAuth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    /// Gmail, Google Workspace, Google Calendar and Contacts.
    Google,
    /// Outlook.com, Hotmail and Microsoft 365.
    Microsoft,
}

impl Provider {
    /// The provider of a well-known address domain, such as `gmail.com` or `outlook.com`.
    /// Custom domains hosted by either provider return `None`.
    pub fn for_address(address: &str) -> Option<Self> {
        let domain = address.rsplit_once('@')?.1.trim().to_ascii_lowercase();
        match domain.as_str() {
            "gmail.com" | "googlemail.com" => Some(Self::Google),
            "outlook.com" | "hotmail.com" | "live.com" | "msn.com" => Some(Self::Microsoft),
            _ => None,
        }
    }

    /// The IMAP server host and its TLS port.
    pub fn imap(self) -> (&'static str, u16) {
        match self {
            Self::Google => ("imap.gmail.com", 993),
            Self::Microsoft => ("outlook.office365.com", 993),
        }
    }

    fn authorize_endpoint(self, tenant: &str) -> String {
        match self {
            Self::Google => "https://accounts.google.com/o/oauth2/v2/auth".into(),
            Self::Microsoft => {
                format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize")
            }
        }
    }

    fn token_endpoint(self, tenant: &str) -> String {
        match self {
            Self::Google => "https://oauth2.googleapis.com/token".into(),
            Self::Microsoft => {
                format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token")
            }
        }
    }
}

/// An OAuth client registered with a provider, the scopes it asks for and its endpoints.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Client {
    /// The provider.
    pub provider: Provider,
    /// The registered client id.
    pub client_id: String,
    /// The client secret; public clients have none.
    pub client_secret: Option<String>,
    /// Where people sign in.
    pub authorize_url: String,
    /// Where codes and refresh tokens are exchanged.
    pub token_url: String,
    /// Space-separated scopes.
    pub scope: String,
    /// Where the provider sends the browser after sign-in; must match the registration.
    pub redirect_url: String,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("provider", &self.provider)
            .field("client_id", &self.client_id)
            .field("scope", &self.scope)
            .field("redirect_url", &self.redirect_url)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A client registered with `provider` that asks for the scopes `access` needs. Microsoft
    /// clients use the `common` authority (any work, school or personal account); see
    /// [`Client::with_microsoft_tenant`].
    pub fn new(
        provider: Provider,
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_url: impl Into<String>,
        access: &Access,
    ) -> Result<Self, OAuthError> {
        Ok(Self {
            provider,
            client_id: client_id.into(),
            client_secret,
            authorize_url: provider.authorize_endpoint("common"),
            token_url: provider.token_endpoint("common"),
            scope: access.scopes(provider)?,
            redirect_url: redirect_url.into(),
        })
    }

    /// Restricts a Microsoft client to one Entra ID tenant (a directory id or domain, or
    /// `organizations` / `consumers`). Ignored for Google.
    pub fn with_microsoft_tenant(mut self, tenant: &str) -> Result<Self, OAuthError> {
        if self.provider != Provider::Microsoft {
            return Ok(self);
        }
        let ok = !tenant.is_empty()
            && tenant.len() <= 128
            && tenant
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'));
        if !ok {
            return Err(OAuthError::Rejected(
                "not a Microsoft tenant id or domain".into(),
            ));
        }
        self.authorize_url = self.provider.authorize_endpoint(tenant);
        self.token_url = self.provider.token_endpoint(tenant);
        Ok(self)
    }

    /// Starts a sign-in: a fresh `state` and PKCE verifier, and the address to open. With
    /// `login_hint` the provider suggests that account. Google is asked for offline access with
    /// a consent prompt, so it always returns a refresh token.
    pub fn authorize(&self, login_hint: Option<&str>) -> Result<Authorization, OAuthError> {
        let state = random_token()?;
        let verifier = random_token()?;
        let url = self.authorize_url_for(&state, &verifier, login_hint);
        Ok(Authorization {
            url,
            state,
            verifier,
        })
    }

    fn authorize_url_for(&self, state: &str, verifier: &str, login_hint: Option<&str>) -> String {
        let mut url = url::Url::parse(&self.authorize_url).expect("a valid authorize endpoint");
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("response_type", "code")
                .append_pair("client_id", &self.client_id)
                .append_pair("redirect_uri", &self.redirect_url)
                .append_pair("scope", &self.scope)
                .append_pair("state", state)
                .append_pair("code_challenge", &challenge(verifier))
                .append_pair("code_challenge_method", "S256");
            if let Some(hint) = login_hint.map(str::trim).filter(|h| !h.is_empty()) {
                query.append_pair("login_hint", hint);
            }
            if self.provider == Provider::Google {
                query
                    .append_pair("access_type", "offline")
                    .append_pair("prompt", "consent")
                    .append_pair("include_granted_scopes", "true");
            }
        }
        url.into()
    }

    /// Checks that `redirect` answers `authorization` (its `state` matches, compared in constant
    /// time) and exchanges its code for tokens. [`OAuthError::Redirect`] for a foreign state,
    /// [`OAuthError::Revoked`] when the code is used, expired or does not match the verifier.
    pub async fn complete(
        &self,
        endpoint: &dyn TokenEndpoint,
        authorization: &Authorization,
        redirect: &Redirect,
    ) -> Result<Tokens, OAuthError> {
        let same: bool = authorization
            .state
            .as_bytes()
            .ct_eq(redirect.state.as_bytes())
            .into();
        if !same {
            return Err(OAuthError::Redirect(
                "the answer belongs to another sign-in".into(),
            ));
        }
        self.exchange(endpoint, &redirect.code, &authorization.verifier)
            .await
    }

    /// Exchanges an authorization `code`, with the verifier of the same sign-in, for tokens.
    pub async fn exchange(
        &self,
        endpoint: &dyn TokenEndpoint,
        code: &str,
        verifier: &str,
    ) -> Result<Tokens, OAuthError> {
        let mut form = vec![
            pair("grant_type", "authorization_code"),
            pair("code", code),
            pair("redirect_uri", &self.redirect_url),
            pair("code_verifier", verifier),
        ];
        self.add_client(&mut form);
        self.request(endpoint, form).await
    }

    /// A fresh access token for `refresh_token`. The answer may carry a new refresh token that
    /// replaces the old one (Microsoft rotates them). [`OAuthError::Revoked`] when the provider
    /// no longer accepts it.
    pub async fn refresh(
        &self,
        endpoint: &dyn TokenEndpoint,
        refresh_token: &str,
    ) -> Result<Tokens, OAuthError> {
        let mut form = vec![
            pair("grant_type", "refresh_token"),
            pair("refresh_token", refresh_token),
        ];
        if self.provider == Provider::Microsoft {
            form.push(pair("scope", &self.scope));
        }
        self.add_client(&mut form);
        self.request(endpoint, form).await
    }

    fn add_client(&self, form: &mut Vec<(String, String)>) {
        form.push(pair("client_id", &self.client_id));
        if let Some(secret) = &self.client_secret {
            form.push(pair("client_secret", secret));
        }
    }

    async fn request(
        &self,
        endpoint: &dyn TokenEndpoint,
        form: Vec<(String, String)>,
    ) -> Result<Tokens, OAuthError> {
        let answer = endpoint.post_form(&self.token_url, &form).await?;
        read_token_answer(&answer)
    }
}

fn pair(key: &str, value: &str) -> (String, String) {
    (key.to_owned(), value.to_owned())
}

/// A sign-in that was started: open `url`, keep `state` and `verifier` until the answer comes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authorization {
    /// The provider's sign-in page with every parameter.
    pub url: String,
    /// The random value the answer must carry back.
    pub state: String,
    /// The PKCE verifier; secret until the code is exchanged.
    pub verifier: String,
}

impl std::fmt::Debug for Authorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authorization").finish_non_exhaustive()
    }
}

/// The PKCE S256 challenge of `verifier`: unpadded base64url of its SHA-256 (RFC 7636).
pub fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn random_token() -> Result<String, OAuthError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| OAuthError::Random)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Tokens from the provider. `Debug` never shows them.
#[derive(Clone, PartialEq, Eq)]
pub struct Tokens {
    /// Signs requests until it expires.
    pub access_token: String,
    /// Gets new access tokens; `None` when the provider did not send one.
    pub refresh_token: Option<String>,
    /// How long the access token lives; one hour when the provider does not say.
    pub expires_in: Duration,
    /// The scopes the provider actually granted, when it says (people can untick some).
    pub scope: Option<String>,
}

impl std::fmt::Debug for Tokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tokens")
            .field("refresh_token", &self.refresh_token.is_some())
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

/// What a token endpoint answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenAnswer {
    /// The HTTP status.
    pub status: u16,
    /// The body as sent.
    pub body: Vec<u8>,
}

/// Posts forms to a provider's token endpoint.
#[async_trait]
pub trait TokenEndpoint: Send + Sync {
    /// Posts `form` as `application/x-www-form-urlencoded` to `url` and returns the status and
    /// body, whatever the status. Only `https` URLs are contacted, except loopback addresses for
    /// tests. [`OAuthError::Connection`] when no answer came; nothing in the error repeats the
    /// form, which holds codes, secrets and tokens.
    async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
    ) -> Result<TokenAnswer, OAuthError>;
}

#[derive(Deserialize)]
struct TokenBody {
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<serde_json::Value>,
    scope: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

fn read_token_answer(answer: &TokenAnswer) -> Result<Tokens, OAuthError> {
    let body: Option<TokenBody> = serde_json::from_slice(&answer.body).ok();
    if let Some(body) = &body
        && let Some(error) = &body.error
    {
        let reason = body
            .error_description
            .as_deref()
            .map(|d| {
                d.lines()
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .chars()
                    .take(200)
                    .collect::<String>()
            })
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| error.clone());
        return Err(match error.as_str() {
            "invalid_grant" => OAuthError::Revoked(reason),
            "temporarily_unavailable" | "server_error" => OAuthError::Protocol(reason),
            _ => OAuthError::Rejected(reason),
        });
    }
    if !(200..300).contains(&answer.status) {
        return Err(OAuthError::Protocol(format!(
            "the token endpoint answered {}",
            answer.status
        )));
    }
    let Some(TokenBody {
        access_token: Some(access_token),
        refresh_token,
        expires_in,
        scope,
        ..
    }) = body
    else {
        return Err(OAuthError::Protocol(
            "the token endpoint sent no access token".into(),
        ));
    };
    let seconds = match expires_in {
        Some(serde_json::Value::Number(n)) => n.as_u64(),
        Some(serde_json::Value::String(s)) => s.parse().ok(),
        _ => None,
    };
    Ok(Tokens {
        access_token,
        refresh_token: refresh_token.filter(|t| !t.is_empty()),
        expires_in: seconds.map_or(DEFAULT_LIFETIME, Duration::from_secs),
        scope,
    })
}

/// Why OAuth failed. Messages never hold tokens, codes or secrets.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OAuthError {
    /// The redirect is not an answer to this sign-in.
    #[error("not a sign-in answer: {0}")]
    Redirect(String),
    /// The person or the provider refused at the sign-in page.
    #[error("access was not granted: {0}")]
    Denied(String),
    /// The code or refresh token is no longer accepted (`invalid_grant`): revoked, expired, the
    /// password changed. Only signing in again helps.
    #[error("the sign-in is no longer valid: {0}")]
    Revoked(String),
    /// The provider refused the request for another reason, or the request cannot be made
    /// (unknown client, unsupported combination of scopes).
    #[error("refused: {0}")]
    Rejected(String),
    /// The token endpoint could not be reached. Retrying later may help.
    #[error("the provider could not be reached: {0}")]
    Connection(String),
    /// The token endpoint answered something unexpected. Retrying later may help.
    #[error("unexpected answer from the provider: {0}")]
    Protocol(String),
    /// No grant is stored for the account.
    #[error("the account has no OAuth grant")]
    NoGrant,
    /// Storage or the keyring failed.
    #[error("grant storage failed: {0}")]
    Storage(String),
    /// The system could not provide random bytes.
    #[error("no random bytes available")]
    Random,
}

impl OAuthError {
    /// Whether retrying the same request later can succeed.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::Connection(_) | Self::Protocol(_) | Self::Storage(_)
        )
    }
}

#[cfg(test)]
mod tests;
