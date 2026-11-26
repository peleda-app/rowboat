use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use baton_core::{GroupId, LeaseKey, Timestamp};
use baton_lease::{Lease, LeaseError, Leases, Liveness, NodeProfile, TakeoverOutcome};
use baton_link::{Duplex, Link, Protocol, PublicKey};
use tokio::sync::Semaphore;
use tokio::time::{Instant, timeout};

use crate::PROTOCOL;
use crate::wire::{self, FrameError, Refusal, Reply, Request};

/// Why the server refused a call or answered wrongly; travels inside
/// [`LeaseError::Backend`]. Calls that fail because the server cannot be reached, is busy or
/// cannot decide fail with [`LeaseError::Unavailable`] instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RemoteError {
    /// The server refused: this node may not make that request.
    #[error("the lease server refused the request")]
    Denied,
    /// The server's store failed.
    #[error("the lease server's store failed")]
    Server,
    /// The answer would exceed the server's reply limit.
    #[error("the answer is too large")]
    TooLarge,
    /// The server answered something that does not fit the request, or does not speak this
    /// version.
    #[error("the lease server answered out of protocol")]
    Protocol,
}

/// Limits and timings of a [`LeaseClient`].
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// How long one call may take, opening a stream included.
    pub request_timeout: Duration,
    /// How many streams the client keeps to the server; also how many calls run at once. Keep
    /// it at or below the server's per-peer limit.
    pub streams: usize,
    /// The largest reply body accepted.
    pub max_reply: usize,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(5),
            streams: 4,
            max_reply: wire::MAX_REPLY,
        }
    }
}

enum Failure {
    Io,
    Protocol,
}

/// A connection to a [`LeaseServer`](crate::LeaseServer) for one node: the node of this link's
/// key.
///
/// Guarantees: every call ends within [`ClientConfig::request_timeout`]; at most
/// [`ClientConfig::streams`] streams are open; a stream that failed or carried a malformed reply
/// is dropped; a call on a reused stream that breaks is retried once on a new stream (every
/// request is safe to repeat); replies larger than [`ClientConfig::max_reply`] are refused
/// before they are read.
pub struct LeaseClient {
    link: Arc<dyn Link>,
    server: PublicKey,
    protocol: Protocol,
    config: ClientConfig,
    ttl_ms: AtomicU64,
    idle: Mutex<Vec<Box<dyn Duplex>>>,
    slots: Semaphore,
}

impl LeaseClient {
    /// Connects to the server with key `server` over `link` and reads its parameters. Fails
    /// with [`LeaseError::Unavailable`] when it cannot be reached and with
    /// [`RemoteError::Denied`] when it refuses this node.
    pub async fn connect(
        link: Arc<dyn Link>,
        server: PublicKey,
        config: ClientConfig,
    ) -> Result<Arc<Self>, LeaseError> {
        let client = Self {
            link,
            server,
            protocol: Protocol::new(PROTOCOL).expect("valid protocol name"),
            slots: Semaphore::new(config.streams.max(1)),
            config,
            ttl_ms: AtomicU64::new(0),
            idle: Mutex::new(Vec::new()),
        };
        match client.call(&Request::Hello).await? {
            Reply::Hello { ttl_ms, .. } if ttl_ms > 0 => {
                client.ttl_ms.store(ttl_ms, Ordering::SeqCst);
            }
            _ => return Err(LeaseError::backend(RemoteError::Protocol)),
        }
        Ok(Arc::new(client))
    }

    /// The server's liveness time-to-live, in milliseconds, as its last `Hello` or heartbeat
    /// reply stated it (a restarted server may state another).
    pub fn ttl_ms(&self) -> u64 {
        self.ttl_ms.load(Ordering::SeqCst)
    }

    /// The server's key.
    pub fn server(&self) -> PublicKey {
        self.server
    }

    async fn exchange(
        &self,
        mut s: Box<dyn Duplex>,
        body: &[u8],
    ) -> Result<(Box<dyn Duplex>, Reply), Failure> {
        let raw = async {
            wire::write_frame(&mut s, body).await?;
            wire::read_frame(&mut s, self.config.max_reply.min(wire::MAX_REPLY)).await
        };
        let raw = match timeout(self.config.request_timeout, raw).await {
            Ok(Ok(raw)) => raw,
            Ok(Err(FrameError::Length)) => return Err(Failure::Protocol),
            _ => return Err(Failure::Io),
        };
        match wire::decode_reply(&raw, self.config.max_reply) {
            Ok(reply) => Ok((s, reply)),
            Err(_) => Err(Failure::Protocol),
        }
    }

    async fn call(&self, request: &Request) -> Result<Reply, LeaseError> {
        let started = Instant::now();
        let _slot = self
            .slots
            .acquire()
            .await
            .map_err(|_| LeaseError::Unavailable)?;
        let body = wire::encode_request(request);
        let reused = self.idle.lock().expect("idle lock").pop();
        let mut done = None;
        if let Some(s) = reused {
            match self.exchange(s, &body).await {
                Ok(ok) => done = Some(ok),
                Err(Failure::Protocol) => return Err(LeaseError::backend(RemoteError::Protocol)),
                Err(Failure::Io) => {}
            }
        }
        let (s, reply) = match done {
            Some(ok) => ok,
            None => {
                let left = self
                    .config
                    .request_timeout
                    .saturating_sub(started.elapsed());
                let s = match timeout(left, self.link.open(&self.server, &self.protocol)).await {
                    Ok(Ok(s)) => s,
                    _ => return Err(LeaseError::Unavailable),
                };
                match self.exchange(s, &body).await {
                    Ok(ok) => ok,
                    Err(Failure::Protocol) => {
                        return Err(LeaseError::backend(RemoteError::Protocol));
                    }
                    Err(Failure::Io) => return Err(LeaseError::Unavailable),
                }
            }
        };
        if !matches!(reply, Reply::Refused(Refusal::Version)) {
            self.idle.lock().expect("idle lock").push(s);
        }
        match reply {
            Reply::Refused(r) => Err(match r {
                Refusal::Denied => LeaseError::backend(RemoteError::Denied),
                Refusal::Unavailable | Refusal::Busy => LeaseError::Unavailable,
                Refusal::Corrupted => LeaseError::Corrupted,
                Refusal::Backend => LeaseError::backend(RemoteError::Server),
                Refusal::TooLarge => LeaseError::backend(RemoteError::TooLarge),
                Refusal::Version => LeaseError::backend(RemoteError::Protocol),
            }),
            reply => Ok(reply),
        }
    }
}

fn out_of_protocol<T>() -> Result<T, LeaseError> {
    Err(LeaseError::backend(RemoteError::Protocol))
}

/// [`Leases`] decided by a [`LeaseServer`](crate::LeaseServer).
///
/// Guarantees beyond the contract: a lease returned by `acquire` is for the group, key and node
/// asked; `holder` returns only a lease for the group and key asked; anything else from the
/// server fails with [`RemoteError::Protocol`].
pub struct RemoteLeases {
    client: Arc<LeaseClient>,
}

impl RemoteLeases {
    /// Leases through `client`.
    pub fn new(client: Arc<LeaseClient>) -> Self {
        Self { client }
    }
}

fn matches(lease: &Option<Lease>, group: &GroupId, key: &LeaseKey) -> bool {
    lease
        .as_ref()
        .is_none_or(|l| &l.group == group && &l.key == key)
}

#[async_trait]
impl Leases for RemoteLeases {
    async fn acquire(
        &self,
        group: &GroupId,
        key: &LeaseKey,
        profile: &NodeProfile,
    ) -> Result<Option<Lease>, LeaseError> {
        let request = Request::Acquire {
            group: group.clone(),
            key: key.clone(),
            profile: profile.clone(),
        };
        match self.client.call(&request).await? {
            Reply::Lease(l)
                if matches(&l, group, key) && l.as_ref().is_none_or(|l| l.node == profile.node) =>
            {
                Ok(l)
            }
            _ => out_of_protocol(),
        }
    }

    async fn request_takeover(
        &self,
        group: &GroupId,
        key: &LeaseKey,
        profile: &NodeProfile,
    ) -> Result<TakeoverOutcome, LeaseError> {
        let request = Request::Takeover {
            group: group.clone(),
            key: key.clone(),
            profile: profile.clone(),
        };
        match self.client.call(&request).await? {
            Reply::Takeover(o) => Ok(o.into()),
            _ => out_of_protocol(),
        }
    }

    async fn release(&self, lease: &Lease) -> Result<(), LeaseError> {
        let request = Request::Release {
            lease: lease.clone(),
        };
        match self.client.call(&request).await? {
            Reply::Done => Ok(()),
            _ => out_of_protocol(),
        }
    }

    async fn holder(&self, group: &GroupId, key: &LeaseKey) -> Result<Option<Lease>, LeaseError> {
        let request = Request::Holder {
            group: group.clone(),
            key: key.clone(),
        };
        match self.client.call(&request).await? {
            Reply::Lease(l) if matches(&l, group, key) => Ok(l),
            _ => out_of_protocol(),
        }
    }
}

/// [`Liveness`] observed by a [`LeaseServer`](crate::LeaseServer) on its own clock.
///
/// Guarantees beyond the contract:
///
/// - The `now` passed to `heartbeat` and `alive` is ignored: the server is the observer and
///   uses its clock, so no client clock decides anything.
/// - `heartbeat` returns `Ok` only once the server recorded it.
/// - [`RemoteLiveness::valid_until`] is the holder's self-expiry: the start of the last
///   heartbeat the server confirmed, plus the time-to-live the server stated in that
///   confirmation, minus a margin. A holder must stop acting on its leases of that group once it
///   passes, which is how a holder stops while the server is down or unreachable. A server
///   restarted with a shorter time-to-live shortens it at the next confirmed heartbeat.
pub struct RemoteLiveness {
    client: Arc<LeaseClient>,
    confirmed: Mutex<HashMap<GroupId, (Instant, u64)>>,
}

impl RemoteLiveness {
    /// Liveness through `client`.
    pub fn new(client: Arc<LeaseClient>) -> Self {
        Self {
            client,
            confirmed: Mutex::new(HashMap::new()),
        }
    }

    /// Until when this node may act on its leases in `group`: the start of its last confirmed
    /// heartbeat there plus the time-to-live that confirmation stated, minus `margin`; `None`
    /// before the first one.
    pub fn valid_until(&self, group: &GroupId, margin: Duration) -> Option<Instant> {
        let (start, ttl) = *self.confirmed.lock().expect("confirmed lock").get(group)?;
        Some(start + Duration::from_millis(ttl).saturating_sub(margin))
    }

    /// Whether this node may still act on its leases in `group` now (see
    /// [`RemoteLiveness::valid_until`]).
    pub fn holding(&self, group: &GroupId, margin: Duration) -> bool {
        self.valid_until(group, margin)
            .is_some_and(|t| Instant::now() < t)
    }
}

#[async_trait]
impl Liveness for RemoteLiveness {
    async fn heartbeat(
        &self,
        group: &GroupId,
        profile: &NodeProfile,
        _now: Timestamp,
    ) -> Result<(), LeaseError> {
        let started = Instant::now();
        let request = Request::Heartbeat {
            group: group.clone(),
            profile: profile.clone(),
        };
        match self.client.call(&request).await? {
            Reply::Beat { ttl_ms } if ttl_ms > 0 => {
                self.client.ttl_ms.store(ttl_ms, Ordering::SeqCst);
                let mut confirmed = self.confirmed.lock().expect("confirmed lock");
                let entry = confirmed.entry(group.clone()).or_insert((started, ttl_ms));
                if started >= entry.0 {
                    *entry = (started, ttl_ms);
                } else {
                    entry.1 = entry.1.min(ttl_ms);
                }
                Ok(())
            }
            _ => out_of_protocol(),
        }
    }

    async fn alive(
        &self,
        group: &GroupId,
        _now: Timestamp,
    ) -> Result<Vec<NodeProfile>, LeaseError> {
        let request = Request::Alive {
            group: group.clone(),
        };
        match self.client.call(&request).await? {
            Reply::Alive(v) => Ok(v),
            _ => out_of_protocol(),
        }
    }

    fn ttl_ms(&self) -> u64 {
        self.client.ttl_ms()
    }
}
