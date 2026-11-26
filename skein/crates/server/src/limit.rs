use std::time::Duration;

use axum::body::Body;
use axum::extract::Request;
use tower_http::timeout::TimeoutBody;

/// Longest pause between two parts of a request body before reading it fails.
pub(crate) const BODY_IDLE: Duration = Duration::from_secs(30);

pub(crate) async fn idle_body(request: Request) -> Request {
    request.map(|body| Body::new(TimeoutBody::new(BODY_IDLE, body)))
}
