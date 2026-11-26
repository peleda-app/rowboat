use std::collections::HashMap;

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use baton_signal::Signal;
use skein_push::PushRegistry;
use subtle::ConstantTimeEq;
use tracing::{debug, warn};

use crate::ServerConfig;

/// Largest notification body; providers send far less.
pub(crate) const BODY_LIMIT: usize = 64 * 1024;

#[derive(Clone)]
pub(crate) struct PushApp {
    registry: PushRegistry,
    signal: Arc<dyn Signal>,
    gmail_token_hash: Option<String>,
    oidc: Option<Arc<crate::oidc::OidcVerifier>>,
    gmail_rate: Arc<crate::rate::Bucket>,
    graph_rate: Arc<crate::rate::Bucket>,
}

pub(crate) fn routes(
    config: &ServerConfig,
    signal: Arc<dyn Signal>,
    registry: PushRegistry,
) -> Router {
    let app = PushApp {
        registry,
        signal,
        gmail_token_hash: config.gmail_push_token_hash.clone(),
        oidc: config
            .gmail_push_oidc
            .clone()
            .map(|c| Arc::new(crate::oidc::OidcVerifier::new(c))),
        gmail_rate: crate::rate::Bucket::new(config.push_rate_per_second),
        graph_rate: crate::rate::Bucket::new(config.push_rate_per_second),
    };
    Router::new()
        .route("/v1/push/graph", get(graph_validate).post(graph_notify))
        .route("/v1/push/gmail/{token}", post(gmail_notify))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .with_state(app)
}

fn validation(query: &HashMap<String, String>) -> Option<Response> {
    let raw = query.get("validationToken")?;
    Some(match skein_push::validation_token(raw) {
        Some(token) => (
            StatusCode::OK,
            [(CONTENT_TYPE, "text/plain; charset=utf-8")],
            token.to_owned(),
        )
            .into_response(),
        None => StatusCode::BAD_REQUEST.into_response(),
    })
}

/// Graph's check that the address is ours: the `validationToken` comes back as plain text.
pub(crate) async fn graph_validate(Query(query): Query<HashMap<String, String>>) -> Response {
    validation(&query).unwrap_or_else(|| StatusCode::BAD_REQUEST.into_response())
}

/// Microsoft Graph change and lifecycle notifications. With `validationToken` it is Graph's
/// address check and the token is echoed. Otherwise every item whose subscription id and
/// `clientState` match a registered subscription wakes its account; the answer is 202 whatever
/// matched, so it tells nothing about which subscriptions exist.
pub(crate) async fn graph_notify(
    State(app): State<PushApp>,
    Query(query): Query<HashMap<String, String>>,
    body: Bytes,
) -> Response {
    if let Some(answer) = validation(&query) {
        return answer;
    }
    if !app.graph_rate.take() {
        return crate::rate::refused();
    }
    match app.registry.accept_graph(&body, &*app.signal).await {
        Ok(_) => StatusCode::ACCEPTED.into_response(),
        Err(skein_push::PushError::Invalid) => StatusCode::BAD_REQUEST.into_response(),
        Err(e) => {
            warn!(error = %e, "graph notifications failed");
            StatusCode::ACCEPTED.into_response()
        }
    }
}

fn token_matches(expected_hash: &str, presented: &str) -> bool {
    let presented = crate::hash_token(presented);
    expected_hash.len() == presented.len()
        && bool::from(expected_hash.as_bytes().ct_eq(presented.as_bytes()))
}

/// Gmail notifications through a Cloud Pub/Sub push subscription. `token` is the operator's
/// secret from the push endpoint address; anything else is 404. The envelope's address wakes the
/// account registered for it. Every envelope is acknowledged with 204, unknown or malformed ones
/// too, so Pub/Sub does not deliver them again.
pub(crate) async fn gmail_notify(
    State(app): State<PushApp>,
    axum::extract::Path(token): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    let Some(expected) = &app.gmail_token_hash else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !token_matches(expected, &token) {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !app.gmail_rate.take() {
        return crate::rate::refused();
    }
    if let Some(oidc) = &app.oidc {
        let authorization = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        if !oidc.verify(authorization).await {
            debug!("gmail push without a valid OIDC token");
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }
    match app.registry.accept_gmail(&body, &*app.signal).await {
        Ok(_) => {}
        Err(skein_push::PushError::Invalid) => debug!("ignoring a malformed gmail envelope"),
        Err(e) => warn!(error = %e, "gmail notification failed"),
    }
    StatusCode::NO_CONTENT.into_response()
}
