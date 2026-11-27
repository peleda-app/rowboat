use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use baton_core::{FencingToken, GroupId, LeaseKey, NodeId, Timestamp};
use baton_lease::{Lease, LeaseError, Leases, Liveness, NodeProfile, TakeoverOutcome};
use baton_lease_cas::{CasLeases, CasLiveness, Clock};
use baton_link::{Duplex, Link, LinkError, Protocol, PublicKey};
use baton_state::StateStore;
use futures::StreamExt;
use tokio::io::AsyncReadExt;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;

use crate::wire::{self, FrameError, Refusal, Reply, Request};
use crate::{Authorize, PROTOCOL, ServerConfig};

/// The arbiter: [`CasLeases`] and [`CasLiveness`] over the server's own store, served on a link.
///
/// Guarantees:
///
/// - Every request is decided by the rules of `baton_lease::record` (through [`CasLeases`]), so
///   tokens of a key only grow, across restarts over the same store too.
/// - A request that names a node (acquire, takeover, release, heartbeat) is refused with
///   [`Refusal::Denied`] unless that node is the one [`Authorize::node`] gives for the
///   link-authenticated peer; [`Authorize`] is asked for every request, so a revocation applies
///   to the next request on a stream that is already open. Releasing needs nothing more: it
///   never grants anything, so a holder that lost the right to lead can still give its lease up.
/// - Liveness is judged on the server's clock only: the time a client sends is ignored. The
///   server is the one observer for all its clients. Every heartbeat reply states the
///   time-to-live, and holders are judged gone only after
///   `max(`[`ServerConfig::ttl_ms`]`, `[`ServerConfig::previous_ttl_ms`]`)`.
/// - For [`ServerConfig::grace_ms`] after start, an acquire is granted only to the node the
///   key's record already names, on the server's link and to [`LeaseServer::leases`] alike.
/// - What a peer can make the server spend is bounded: [`ServerConfig::max_streams`] streams in
///   all, [`ServerConfig::max_per_peer`] per peer (more are closed at once), a request body of
///   at most [`wire::MAX_REQUEST`] bytes that must arrive within
///   [`ServerConfig::header_timeout`] of its first byte, a stream idle for
///   [`ServerConfig::idle_timeout`] is closed, replies must be read within
///   [`ServerConfig::write_timeout`], [`ServerConfig::max_busy`] requests are decided at once,
///   each within [`ServerConfig::request_timeout`]. A malformed or oversized frame closes its
///   stream.
/// - Dropping the server (or [`LeaseServer::stop`]) stops accepting and severs every stream.
pub struct LeaseServer {
    leases: Arc<Graced>,
    liveness: Arc<CasLiveness>,
    endorse: Option<Arc<dyn crate::Endorse>>,
    task: Option<JoinHandle<()>>,
}

impl Drop for LeaseServer {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

struct Ctx {
    leases: Arc<Graced>,
    liveness: Arc<CasLiveness>,
    authorize: Arc<dyn Authorize>,
    clock: Clock,
    config: ServerConfig,
    busy: Semaphore,
}

struct PeerSlot {
    peer: PublicKey,
    open: Arc<Mutex<HashMap<PublicKey, usize>>>,
    _stream: OwnedSemaphorePermit,
}

impl Drop for PeerSlot {
    fn drop(&mut self) {
        let mut open = self.open.lock().expect("per-peer lock");
        if let Some(n) = open.get_mut(&self.peer) {
            *n -= 1;
            if *n == 0 {
                open.remove(&self.peer);
            }
        }
    }
}

impl LeaseServer {
    /// Starts serving on `link`, which must have no other listener for [`PROTOCOL`]. Leases and
    /// heartbeats live in `state`; `clock` is the server's own time for liveness and tokens
    /// (`baton_lease_cas::monotonic_clock()` in production). Needs a Tokio runtime.
    pub async fn start(
        link: Arc<dyn Link>,
        state: Arc<dyn StateStore>,
        authorize: Arc<dyn Authorize>,
        clock: Clock,
        config: ServerConfig,
    ) -> Result<Self, LinkError> {
        let protocol = Protocol::new(PROTOCOL).expect("valid protocol name");
        let mut incoming = link.listen(&protocol).await?;
        let liveness = Arc::new(CasLiveness::new(
            state.clone(),
            config.ttl_ms.max(config.previous_ttl_ms),
        ));
        let until = (clock)().plus_ms(config.grace_ms.min(i64::MAX as u64) as i64);
        let leases = Arc::new(Graced {
            inner: CasLeases::new(state, liveness.clone() as Arc<dyn Liveness>)
                .with_clock(clock.clone()),
            clock: clock.clone(),
            until,
        });
        let endorse = config.endorse.clone();
        let ctx = Arc::new(Ctx {
            leases: leases.clone(),
            liveness: liveness.clone(),
            authorize,
            clock,
            busy: Semaphore::new(config.max_busy.max(1)),
            config,
        });
        let streams = Arc::new(Semaphore::new(ctx.config.max_streams.max(1)));
        let open: Arc<Mutex<HashMap<PublicKey, usize>>> = Arc::default();
        let task = tokio::spawn(async move {
            let mut sessions = JoinSet::new();
            loop {
                tokio::select! {
                    inc = incoming.next() => {
                        let Some(inc) = inc else { break };
                        let Ok(permit) = streams.clone().try_acquire_owned() else {
                            continue;
                        };
                        {
                            let mut open = open.lock().expect("per-peer lock");
                            let n = open.entry(inc.peer).or_insert(0);
                            if *n >= ctx.config.max_per_peer.max(1) {
                                continue;
                            }
                            *n += 1;
                        }
                        let slot = PeerSlot {
                            peer: inc.peer,
                            open: open.clone(),
                            _stream: permit,
                        };
                        sessions.spawn(session(ctx.clone(), slot, inc.stream));
                    }
                    Some(_) = sessions.join_next(), if !sessions.is_empty() => {}
                }
            }
        });
        Ok(Self {
            leases,
            liveness,
            endorse,
            task: Some(task),
        })
    }

    /// The endorsement of `lease` for the server's own process: given only when the server's
    /// record names `lease.node` as holder with `lease.fence` (see [`crate::Endorse`]).
    pub async fn endorse(&self, lease: &Lease) -> Option<Vec<u8>> {
        endorsement(
            &self.leases,
            self.endorse.as_deref(),
            &lease.group,
            &lease.key,
            &lease.node,
            lease.fence,
        )
        .await
    }

    /// The server's clock time of `node`'s latest heartbeat in `group`, kept across restarts
    /// over the same store, or `None` when it has none. For judging how long a node was silent.
    pub async fn last_heartbeat(&self, group: &GroupId, node: &NodeId) -> Option<Timestamp> {
        self.liveness
            .last_heartbeat(group, node)
            .await
            .ok()
            .flatten()
    }

    /// The server's own leases, for work the server process does itself.
    pub fn leases(&self) -> Arc<dyn Leases> {
        self.leases.clone()
    }

    /// The server's own liveness (the one observer of its clients' heartbeats).
    pub fn liveness(&self) -> Arc<dyn Liveness> {
        self.liveness.clone()
    }

    /// Stops accepting and severs every stream; when it returns, the link has no listener for
    /// [`PROTOCOL`] any more, so a new server can start on it.
    pub async fn stop(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

/// [`CasLeases`] that grants only renewals until `until`.
struct Graced {
    inner: CasLeases,
    clock: Clock,
    until: Timestamp,
}

#[async_trait]
impl Leases for Graced {
    async fn acquire(
        &self,
        group: &GroupId,
        key: &LeaseKey,
        profile: &NodeProfile,
    ) -> Result<Option<Lease>, LeaseError> {
        self.acquire_above(group, key, profile, FencingToken(0))
            .await
    }

    async fn acquire_above(
        &self,
        group: &GroupId,
        key: &LeaseKey,
        profile: &NodeProfile,
        floor: FencingToken,
    ) -> Result<Option<Lease>, LeaseError> {
        if (self.clock)() < self.until {
            let holder = self.inner.holder(group, key).await?;
            if holder.is_none_or(|l| l.node != profile.node) {
                return Ok(None);
            }
        }
        self.inner.acquire_above(group, key, profile, floor).await
    }

    async fn request_takeover(
        &self,
        group: &GroupId,
        key: &LeaseKey,
        profile: &NodeProfile,
    ) -> Result<TakeoverOutcome, LeaseError> {
        self.inner.request_takeover(group, key, profile).await
    }

    async fn release(&self, lease: &Lease) -> Result<(), LeaseError> {
        self.inner.release(lease).await
    }

    async fn holder(&self, group: &GroupId, key: &LeaseKey) -> Result<Option<Lease>, LeaseError> {
        self.inner.holder(group, key).await
    }
}

async fn endorsement(
    leases: &Graced,
    endorse: Option<&dyn crate::Endorse>,
    group: &GroupId,
    key: &LeaseKey,
    node: &NodeId,
    fence: FencingToken,
) -> Option<Vec<u8>> {
    let endorse = endorse?;
    let held = leases.inner.holder(group, key).await.ok()??;
    if &held.node != node || held.fence != fence {
        return None;
    }
    endorse
        .endorse(&held)
        .filter(|e| e.len() <= wire::MAX_ENDORSEMENT)
}

async fn session(ctx: Arc<Ctx>, slot: PeerSlot, mut s: Box<dyn Duplex>) {
    let peer = slot.peer;
    loop {
        let Ok(Ok(first)) = timeout(ctx.config.idle_timeout, s.read_u8()).await else {
            return;
        };
        let body = timeout(ctx.config.header_timeout, async {
            let mut rest = [0u8; 3];
            s.read_exact(&mut rest).await.map_err(|_| FrameError::Io)?;
            wire::read_body(
                &mut s,
                [first, rest[0], rest[1], rest[2]],
                wire::MAX_REQUEST,
            )
            .await
        })
        .await;
        let Ok(Ok(body)) = body else { return };
        let (reply, keep) = match wire::decode_request(&body) {
            Ok(request) => (ctx.handle(&peer, request).await, true),
            Err(FrameError::Version) => (Reply::Refused(Refusal::Version), false),
            Err(_) => return,
        };
        let mut out = wire::encode_reply(&reply);
        if out.len() > ctx.config.max_reply.min(wire::MAX_REPLY) {
            out = wire::encode_reply(&Reply::Refused(Refusal::TooLarge));
        }
        let written = timeout(ctx.config.write_timeout, wire::write_frame(&mut s, &out)).await;
        if !matches!(written, Ok(Ok(()))) || !keep {
            return;
        }
    }
}

fn refusal(e: LeaseError) -> Reply {
    Reply::Refused(match e {
        LeaseError::Unavailable => Refusal::Unavailable,
        LeaseError::Corrupted => Refusal::Corrupted,
        LeaseError::Backend(_) => Refusal::Backend,
    })
}

impl Ctx {
    fn allowed(&self, peer: &PublicKey, node: &NodeId, request: &Request) -> bool {
        let a = &*self.authorize;
        match request {
            Request::Hello => true,
            Request::Acquire {
                group,
                key,
                profile,
            }
            | Request::AcquireAbove {
                group,
                key,
                profile,
                ..
            }
            | Request::Takeover {
                group,
                key,
                profile,
            } => {
                &profile.node == node
                    && a.profile(peer, group, profile)
                    && a.lease(peer, group, key)
            }
            Request::Endorse { group, key, .. } => {
                a.member(peer, group) && a.lease(peer, group, key)
            }
            Request::Release { lease } => &lease.node == node,
            Request::Holder { group, .. } | Request::Alive { group } => a.member(peer, group),
            Request::Heartbeat { group, profile } => {
                &profile.node == node && a.profile(peer, group, profile)
            }
        }
    }

    async fn handle(&self, peer: &PublicKey, request: Request) -> Reply {
        let Some(node) = self.authorize.node(peer) else {
            return Reply::Refused(Refusal::Denied);
        };
        if !self.allowed(peer, &node, &request) {
            return Reply::Refused(Refusal::Denied);
        }
        let Ok(Ok(_slot)) = timeout(self.config.busy_wait, self.busy.acquire()).await else {
            return Reply::Refused(Refusal::Busy);
        };
        timeout(self.config.request_timeout, self.execute(&node, request))
            .await
            .unwrap_or(Reply::Refused(Refusal::Unavailable))
    }

    async fn execute(&self, node: &NodeId, request: Request) -> Reply {
        let result = match request {
            Request::AcquireAbove {
                group,
                key,
                profile,
                floor,
            } => self
                .leases
                .acquire_above(&group, &key, &profile, floor)
                .await
                .map(Reply::Lease),
            Request::Endorse { group, key, fence } => Ok(Reply::Endorsement(
                endorsement(
                    &self.leases,
                    self.config.endorse.as_deref(),
                    &group,
                    &key,
                    node,
                    fence,
                )
                .await,
            )),
            Request::Hello => Ok(Reply::Hello {
                ttl_ms: self.config.ttl_ms.max(1),
                max_request: wire::MAX_REQUEST as u32,
                max_reply: self.config.max_reply.min(wire::MAX_REPLY) as u32,
            }),
            Request::Acquire {
                group,
                key,
                profile,
            } => self
                .leases
                .acquire(&group, &key, &profile)
                .await
                .map(Reply::Lease),
            Request::Takeover {
                group,
                key,
                profile,
            } => self
                .leases
                .request_takeover(&group, &key, &profile)
                .await
                .map(|o| Reply::Takeover(o.into())),
            Request::Release { lease } => self.leases.release(&lease).await.map(|()| Reply::Done),
            Request::Holder { group, key } => {
                self.leases.holder(&group, &key).await.map(Reply::Lease)
            }
            Request::Heartbeat { group, profile } => self
                .liveness
                .heartbeat(&group, &profile, (self.clock)())
                .await
                .map(|()| Reply::Beat {
                    ttl_ms: self.config.ttl_ms.max(1),
                }),
            Request::Alive { group } => self
                .liveness
                .alive(&group, (self.clock)())
                .await
                .map(Reply::Alive),
        };
        result.unwrap_or_else(refusal)
    }
}
