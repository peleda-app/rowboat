use std::sync::{Arc, Mutex};

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use tokio::time::Instant;
use tracing::debug;

pub(crate) struct Bucket {
    rate: f64,
    state: Mutex<(f64, Instant)>,
}

impl Bucket {
    pub(crate) fn new(per_second: u32) -> Arc<Self> {
        let rate = f64::from(per_second.max(1));
        Arc::new(Self {
            rate,
            state: Mutex::new((rate, Instant::now())),
        })
    }

    pub(crate) fn take(&self) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let (tokens, at) = *state;
        let tokens = (tokens + now.duration_since(at).as_secs_f64() * self.rate).min(self.rate);
        if tokens >= 1.0 {
            *state = (tokens - 1.0, now);
            true
        } else {
            *state = (tokens, now);
            false
        }
    }
}

pub(crate) fn refused() -> Response {
    debug!("push request over the rate limit");
    let mut response = StatusCode::TOO_MANY_REQUESTS.into_response();
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    response
}
