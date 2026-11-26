//! The node's only inbound HTTP: the Gmail Pub/Sub and Microsoft Graph change notification
//! receivers and a health check. There is no management API; the node is managed through Baton
//! commands.
//!
//! The receivers need no API key: each checks the provider's own proof (Graph's `clientState`,
//! the Gmail push secret and optionally Pub/Sub's OIDC token), never calls a provider, and only
//! publishes hints on the Baton signal topic `push/{account}` in the group of the account's
//! tenant. See `docs/README.md` for the routes, limits and security notes.

mod limit;
mod listen;
pub mod oidc;
mod push;
mod rate;

use std::sync::Arc;

use axum::Router;
use axum::http::header;
use axum::http::{HeaderValue, StatusCode};
use axum::routing::get;
use baton_signal::Signal;
use skein_push::PushRegistry;

pub use listen::{HEADER_READ_TIMEOUT, MAX_CONNECTIONS, serve};

/// Settings of the inbound listener. `Default` gives the documented defaults with Gmail push off.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// BLAKE3 hash (hex, from [`hash_token`]) of the secret in the Gmail Pub/Sub push address
    /// `{public_url}/v1/push/gmail/{secret}`. Without it Gmail push answers 404.
    pub gmail_push_token_hash: Option<String>,
    /// When set, Gmail push requests must also carry a valid Pub/Sub OIDC token for this
    /// audience and service account, besides the secret in the path.
    pub gmail_push_oidc: Option<oidc::OidcConfig>,
    /// Push requests accepted per second over the whole listener, with bursts of as many;
    /// further ones are answered 429 with `Retry-After`, which both providers retry. Default 100.
    pub push_rate_per_second: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            gmail_push_token_hash: None,
            gmail_push_oidc: None,
            push_rate_per_second: 100,
        }
    }
}

impl ServerConfig {
    /// Checks the settings a router would otherwise misread: the push token hash is 64
    /// lowercase hex digits, the OIDC settings name an `https` key address (or loopback), an
    /// audience and an email, and the rate is not zero. Returns the first problem.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(oidc) = &self.gmail_push_oidc {
            let ok = oidc.jwks_url.starts_with("https://")
                || oidc.jwks_url.starts_with("http://127.0.0.1")
                || oidc.jwks_url.starts_with("http://localhost");
            if !ok || oidc.audience.is_empty() || oidc.email.is_empty() {
                return Err(
                    "gmail push OIDC needs an https key address, an audience and an email".into(),
                );
            }
        }
        if let Some(hash) = &self.gmail_push_token_hash
            && (hash.len() != 64 || !hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        {
            return Err("the push token hash is not 64 lowercase hex digits".into());
        }
        if self.push_rate_per_second == 0 {
            return Err("push_rate_per_second must not be zero".into());
        }
        Ok(())
    }
}

/// The BLAKE3 hash of a secret, as hex; what the config holds instead of the Gmail push secret.
pub fn hash_token(token: &str) -> String {
    blake3::hash(token.as_bytes()).to_hex().to_string()
}

/// `GET /v1/health`, plus, when `push` is given, `GET`/`POST /v1/push/graph` and
/// `POST /v1/push/gmail/{secret}` routed through it. Every other path is 404. Every answer
/// carries `nosniff`, `no-store`, a deny-all CSP and `DENY` framing; a request body that pauses
/// for 30 seconds is given up.
pub fn router(
    signal: Arc<dyn Signal>,
    push: Option<PushRegistry>,
    config: &ServerConfig,
) -> Router {
    let routes = Router::new().route("/v1/health", get(health));
    let routes = match push {
        Some(registry) => routes.merge(push::routes(config, signal, registry)),
        None => routes,
    };
    routes
        .fallback(fallback)
        .layer(axum::middleware::map_request(limit::idle_body))
        .layer(axum::middleware::map_response(security_headers))
}

async fn health() -> &'static str {
    "ok"
}

async fn fallback() -> StatusCode {
    StatusCode::NOT_FOUND
}

async fn security_headers(mut response: axum::response::Response) -> axum::response::Response {
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers
        .entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    headers
        .entry(header::CONTENT_SECURITY_POLICY)
        .or_insert(HeaderValue::from_static(
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        ));
    headers
        .entry(header::X_FRAME_OPTIONS)
        .or_insert(HeaderValue::from_static("DENY"));
    response
}

#[cfg(test)]
mod push_tests;
#[cfg(test)]
mod tests;
