//! Checking the OIDC token Pub/Sub sends with push requests: an RS256 JWT signed by Google,
//! whose audience and service account the operator configured.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use tracing::{debug, warn};

/// Where Google publishes the keys it signs OIDC tokens with.
pub const GOOGLE_JWKS: &str = "https://www.googleapis.com/oauth2/v3/certs";

/// What a Pub/Sub push token must say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcConfig {
    /// The audience set on the push subscription (often the push endpoint URL).
    pub audience: String,
    /// The service account the push subscription authenticates as.
    pub email: String,
    /// Where the signing keys are; [`GOOGLE_JWKS`] in production.
    pub jwks_url: String,
}

#[derive(Deserialize)]
struct Claims {
    email: Option<String>,
    email_verified: Option<bool>,
}

const MAX_KEYS_BYTES: u64 = 256 * 1024;
const KEYS_FRESH: Duration = Duration::from_secs(3600);
const REFRESH_AT_MOST_EVERY: Duration = Duration::from_secs(60);

/// Verifies push tokens against cached signing keys. Keys are fetched when missing, older than
/// an hour, or when a token names an unknown key id, but at most once a minute.
pub(crate) struct OidcVerifier {
    config: OidcConfig,
    http: reqwest::Client,
    keys: Mutex<Option<(JwkSet, Instant)>>,
    last_fetch: Mutex<Option<Instant>>,
}

impl OidcVerifier {
    pub(crate) fn new(config: OidcConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("an HTTP client"),
            keys: Mutex::new(None),
            last_fetch: Mutex::new(None),
        }
    }

    async fn fetch(&self) -> Option<JwkSet> {
        {
            let mut last = self.last_fetch.lock().expect("lock");
            if last.is_some_and(|t| t.elapsed() < REFRESH_AT_MOST_EVERY) {
                return None;
            }
            *last = Some(Instant::now());
        }
        let response = match self.http.get(&self.config.jwks_url).send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                warn!(status = r.status().as_u16(), "signing keys not fetched");
                return None;
            }
            Err(_) => {
                warn!("signing keys not fetched");
                return None;
            }
        };
        let mut response = response;
        if response
            .content_length()
            .is_some_and(|n| n > MAX_KEYS_BYTES)
        {
            return None;
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.ok()? {
            if bytes.len() + chunk.len() > MAX_KEYS_BYTES as usize {
                warn!("signing key set is too large");
                return None;
            }
            bytes.extend_from_slice(&chunk);
        }
        let set: JwkSet = serde_json::from_slice(&bytes).ok()?;
        *self.keys.lock().expect("lock") = Some((set.clone(), Instant::now()));
        Some(set)
    }

    async fn key(&self, kid: &str) -> Option<DecodingKey> {
        let cached = self.keys.lock().expect("lock").clone();
        let set = match cached {
            Some((set, at)) if at.elapsed() < KEYS_FRESH && set.find(kid).is_some() => set,
            Some((set, _)) => self.fetch().await.unwrap_or(set),
            None => self.fetch().await?,
        };
        DecodingKey::from_jwk(set.find(kid)?).ok()
    }

    /// Whether `authorization` (the request's header value) carries a valid token for this
    /// configuration.
    pub(crate) async fn verify(&self, authorization: Option<&str>) -> bool {
        let Some(token) = authorization.and_then(|h| h.strip_prefix("Bearer ")) else {
            return false;
        };
        let Ok(header) = decode_header(token) else {
            return false;
        };
        if header.alg != Algorithm::RS256 {
            return false;
        }
        let Some(kid) = header.kid else {
            return false;
        };
        let Some(key) = self.key(&kid).await else {
            debug!("push token signed with an unknown key");
            return false;
        };
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.config.audience]);
        validation.set_issuer(&["https://accounts.google.com", "accounts.google.com"]);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        match decode::<Claims>(token, &key, &validation) {
            Ok(data) => {
                data.claims.email_verified == Some(true)
                    && data.claims.email.as_deref() == Some(self.config.email.as_str())
            }
            Err(_) => false,
        }
    }
}
