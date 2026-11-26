//! The drop service over HTTP/1.1.
//!
//! Two routes, both carrying raw drop bytes (`baton_drop::wire`), so HTTP adds no format of its
//! own:
//!
//! - `GET /v1/info` returns the encoded [`ServiceInfo`](baton_drop::ServiceInfo);
//! - `POST /v1/request` takes one encoded request and returns `200` with the encoded reply,
//!   refusals included.
//!
//! HTTP statuses other than `200` and `504` mean the request never reached the service: `413`
//! (body over the service's request limit), `408` (body not received within
//! [`HttpConfig::body_timeout`]), `429` (the client's rate or concurrency limit), `503` (the
//! server's in-flight cap). `504` means the service did not answer within its deadline: the
//! request may or may not have been executed. Long polls wait under their own budget
//! ([`HttpConfig::max_polls`], [`RateLimit::polls`] per client, and the service's per-box cap), so
//! they never take the in-flight capacity short requests need; a take beyond that budget returns
//! at once. [`router`] builds the routes; [`serve`] runs them with a header timeout, a write
//! timeout, connection caps in all and per client, optional TLS and graceful shutdown. Nothing
//! here logs box ids, keys, content or client addresses.

mod limit;
mod serve;

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use baton_drop::{Clock, DropService, wire};
use bytes::Bytes;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub use limit::RateLimit;
pub use serve::serve;

/// The path of the service info.
pub const INFO_PATH: &str = "/v1/info";

/// The path requests are posted to.
pub const REQUEST_PATH: &str = "/v1/request";

/// The content type of every body.
pub const CONTENT_TYPE: &str = "application/octet-stream";

/// Where the client address used for rate limiting comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientIp {
    /// The TCP peer (a server facing the internet directly).
    Peer,
    /// The last address of the last `X-Forwarded-For` header, falling back to the peer: only
    /// behind a reverse proxy that sets it, since clients can write anything there.
    ForwardedFor,
}

/// Limits of the HTTP server.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// How long a client may take to send a request's headers, on a new connection or between
    /// requests on a kept-alive one; also the TLS handshake limit (default 10 s).
    pub header_timeout: Duration,
    /// How long a client may take to send a request body (default 10 s).
    pub body_timeout: Duration,
    /// How long the service may take beyond its longest wait before the request fails with `503`
    /// (default 10 s).
    pub reply_margin: Duration,
    /// How long writing a reply may make no progress (the client does not read) before the
    /// connection is closed (default 30 s).
    pub write_timeout: Duration,
    /// Connections served at once; further ones wait in the listen backlog (default 4,096).
    pub max_connections: usize,
    /// Connections served at once from one client (IPv4 address or IPv6 /64); further ones are
    /// closed at once. Applies with [`ClientIp::Peer`] only, since behind a proxy every
    /// connection comes from the proxy (default 64).
    pub max_connections_per_client: usize,
    /// Requests in flight at once, long polls waiting under [`HttpConfig::max_polls`] not
    /// included; beyond this `503` at once (default 2,048).
    pub max_in_flight: usize,
    /// Long polls waiting at once; a take beyond this returns at once (default 1,024).
    pub max_polls: usize,
    /// Per-client limits, or none (only for tests and private deployments).
    pub rate: Option<RateLimit>,
    /// Where the client address comes from.
    pub client_ip: ClientIp,
    /// How long shutdown waits for requests in flight (default 35 s, above the longest wait).
    pub shutdown_grace: Duration,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            header_timeout: Duration::from_secs(10),
            body_timeout: Duration::from_secs(10),
            reply_margin: Duration::from_secs(10),
            write_timeout: Duration::from_secs(30),
            max_connections: 4096,
            max_connections_per_client: 64,
            max_in_flight: 2048,
            max_polls: 1024,
            rate: Some(RateLimit::default()),
            client_ip: ClientIp::Peer,
            shutdown_grace: Duration::from_secs(35),
        }
    }
}

struct Shared {
    service: Arc<DropService>,
    config: HttpConfig,
    info: Bytes,
    in_flight: Arc<Semaphore>,
    polls: Arc<Semaphore>,
    limiter: Option<Mutex<limit::Limiter>>,
    clock: Clock,
    handle_timeout: Duration,
}

struct Admitted {
    shared: Arc<Shared>,
    slot: Option<limit::Slot>,
    permit: Option<OwnedSemaphorePermit>,
    poll: Option<OwnedSemaphorePermit>,
}

impl Admitted {
    /// Moves this request from the in-flight budget to the long-poll budget, if the server and
    /// the client have room for one more waiting poll; otherwise it stays a short request.
    fn start_poll(&mut self) -> bool {
        let Ok(permit) = self.shared.polls.clone().try_acquire_owned() else {
            return false;
        };
        if let (Some(slot), Some(l)) = (self.slot, &self.shared.limiter)
            && !l.lock().expect("limiter lock").start_poll(slot)
        {
            return false;
        }
        self.poll = Some(permit);
        self.permit = None;
        true
    }
}

impl Drop for Admitted {
    fn drop(&mut self) {
        if let (Some(slot), Some(l)) = (self.slot, &self.shared.limiter) {
            let mut l = l.lock().expect("limiter lock");
            if self.poll.is_some() {
                l.end_poll(slot);
            }
            l.release(slot);
        }
    }
}

impl Shared {
    fn client(&self, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
        match self.config.client_ip {
            ClientIp::Peer => peer.ip(),
            ClientIp::ForwardedFor => forwarded_for(headers).unwrap_or(peer.ip()),
        }
    }

    fn admit(
        self: &Arc<Self>,
        peer: SocketAddr,
        headers: &HeaderMap,
    ) -> Result<Admitted, StatusCode> {
        let slot = match &self.limiter {
            None => None,
            Some(l) => {
                let key = limit::client_key(self.client(peer, headers));
                let now = (self.clock)().0;
                match l.lock().expect("limiter lock").acquire(key, now) {
                    Ok(s) => Some(s),
                    Err(_) => return Err(StatusCode::TOO_MANY_REQUESTS),
                }
            }
        };
        match self.in_flight.clone().try_acquire_owned() {
            Ok(permit) => Ok(Admitted {
                shared: self.clone(),
                slot,
                permit: Some(permit),
                poll: None,
            }),
            Err(_) => {
                if let (Some(s), Some(l)) = (slot, &self.limiter) {
                    l.lock().expect("limiter lock").release(s);
                }
                Err(StatusCode::SERVICE_UNAVAILABLE)
            }
        }
    }
}

/// The last address in the last `X-Forwarded-For` header (the one the nearest proxy appended).
pub fn forwarded_for(headers: &HeaderMap) -> Option<IpAddr> {
    let last = headers.get_all("x-forwarded-for").iter().next_back()?;
    let value = last.to_str().ok()?;
    value.rsplit(',').next()?.trim().parse().ok()
}

/// The routes of `service`, rate limited by `clock` (milliseconds).
pub fn router(service: Arc<DropService>, config: HttpConfig, clock: Clock) -> Router {
    let shared = Arc::new(Shared {
        info: Bytes::from(wire::encode_info(&service.info())),
        in_flight: Arc::new(Semaphore::new(config.max_in_flight.max(1))),
        polls: Arc::new(Semaphore::new(config.max_polls)),
        limiter: config.rate.map(|r| Mutex::new(limit::Limiter::new(r))),
        handle_timeout: service.config().max_wait + config.reply_margin,
        service,
        config,
        clock,
    });
    Router::new()
        .route(INFO_PATH, get(info))
        .route(REQUEST_PATH, post(request))
        .fallback(|| async { status(StatusCode::NOT_FOUND) })
        .with_state(shared)
}

fn status(code: StatusCode) -> Response {
    code.into_response()
}

fn octets(body: impl Into<Body>) -> Response {
    let mut r = Response::new(body.into());
    r.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(CONTENT_TYPE));
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

async fn info(
    State(s): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let _admitted = match s.admit(peer, &headers) {
        Ok(a) => a,
        Err(code) => return status(code),
    };
    octets(s.info.clone())
}

async fn request(
    State(s): State<Arc<Shared>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let mut admitted = match s.admit(peer, &headers) {
        Ok(a) => a,
        Err(code) => return status(code),
    };
    let max = s.service.max_request();
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > max as u64) {
        return status(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let raw =
        match tokio::time::timeout(s.config.body_timeout, axum::body::to_bytes(body, max)).await {
            Err(_) => return status(StatusCode::REQUEST_TIMEOUT),
            Ok(Err(_)) => return status(StatusCode::PAYLOAD_TOO_LARGE),
            Ok(Ok(b)) => b,
        };
    let may_wait = wire::wait_ms(&raw).is_some_and(|w| w > 0) && admitted.start_poll();
    match tokio::time::timeout(s.handle_timeout, s.service.handle_with(&raw, may_wait)).await {
        Ok(reply) => octets(reply),
        Err(_) => status(StatusCode::GATEWAY_TIMEOUT),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarded_for_takes_the_nearest_proxys_entry() {
        let mut h = HeaderMap::new();
        assert_eq!(forwarded_for(&h), None);
        h.append(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.9, 198.51.100.7"),
        );
        assert_eq!(forwarded_for(&h), Some("198.51.100.7".parse().unwrap()));
        h.append("x-forwarded-for", HeaderValue::from_static(" 2001:db8::1 "));
        assert_eq!(forwarded_for(&h), Some("2001:db8::1".parse().unwrap()));
        h.append("x-forwarded-for", HeaderValue::from_static("garbage"));
        assert_eq!(forwarded_for(&h), None);
    }
}
