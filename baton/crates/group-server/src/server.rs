use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use baton_group::Entry;
use baton_link::{Duplex, Link, LinkError, Protocol, PublicKey};
use futures::StreamExt;
use tokio::io::AsyncReadExt;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;

use crate::logs::GroupLogs;
use crate::wire::{self, FrameError, Refusal, Reply, Request};
use crate::{Admit, Clock, PROTOCOL, ServerConfig};

/// Serves [`GroupLogs`] on a link.
///
/// Guarantees:
///
/// - A peer reads (`Head`, `Fetch`) or pushes a group only while it is a node that counts in
///   that group on the server's clock, or while `bootstrap` admits it to that group (the founding node
///   before genesis, a recovering device); asked for every request, so a revocation applies to the
///   next request on an open stream. After an accepted entry that can take trust away, the link
///   is asked to sever peers it no longer trusts.
/// - Every pushed entry is checked by `baton-group` at the head before it is stored (see
///   [`GroupLogs::push`]): forged, replayed into another place, forked, stale, future and
///   unauthorized entries are refused, and an exact repeat of a held entry changes nothing.
/// - What a peer can make the server spend is bounded: [`ServerConfig::max_streams`] streams in
///   all, [`ServerConfig::max_per_peer`] per peer (more are closed at once), requests of at most
///   [`wire::MAX_REQUEST`] bytes that must arrive within [`ServerConfig::header_timeout`] of
///   their first byte, idle streams closed after [`ServerConfig::idle_timeout`], replies read
///   within [`ServerConfig::write_timeout`], [`ServerConfig::max_busy`] requests at once, fetches
///   of at most [`ServerConfig::max_fetch`] entries and about [`ServerConfig::max_reply`] bytes,
///   and per peer [`ServerConfig::push_per_second`] pushes (burst [`ServerConfig::push_burst`])
///   on the server's clock, refused as busy beyond. A malformed or oversized frame closes its
///   stream.
pub struct GroupServer {
    task: Option<JoinHandle<()>>,
}

impl Drop for GroupServer {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

struct Ctx {
    logs: Arc<GroupLogs>,
    bootstrap: Arc<dyn Admit>,
    link: Arc<dyn Link>,
    clock: Clock,
    config: ServerConfig,
    busy: Semaphore,
    pushes: Mutex<HashMap<PublicKey, (u64, i64)>>,
}

const MAX_RATE_TRACKED: usize = 4096;

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

impl GroupServer {
    /// Starts serving `logs` on `link`, which must have no other listener for [`PROTOCOL`].
    /// `bootstrap` admits peers to groups they do not count in yet; `clock` is the server's wall
    /// clock (certificate expiry, entries from the future). Needs a Tokio runtime.
    pub async fn start(
        link: Arc<dyn Link>,
        logs: Arc<GroupLogs>,
        bootstrap: Arc<dyn Admit>,
        clock: Clock,
        config: ServerConfig,
    ) -> Result<Self, LinkError> {
        let protocol = Protocol::new(PROTOCOL).expect("valid protocol name");
        let mut incoming = link.listen(&protocol).await?;
        let ctx = Arc::new(Ctx {
            logs,
            bootstrap,
            link,
            clock,
            busy: Semaphore::new(config.max_busy.max(1)),
            pushes: Mutex::new(HashMap::new()),
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
        Ok(Self { task: Some(task) })
    }

    /// Stops accepting and severs every stream; when it returns, the link has no listener for
    /// [`PROTOCOL`] any more.
    pub async fn stop(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
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

impl Ctx {
    fn may(&self, peer: &PublicKey, group: &baton_core::GroupId) -> Result<(), Refusal> {
        if !self.logs.holds(group) {
            return Err(Refusal::Unknown);
        }
        if self.logs.counts(group, peer, (self.clock)()) || self.bootstrap.admits(peer, group) {
            Ok(())
        } else {
            Err(Refusal::Denied)
        }
    }

    async fn handle(&self, peer: &PublicKey, request: Request) -> Reply {
        let Ok(Ok(_slot)) = timeout(self.config.busy_wait, self.busy.acquire()).await else {
            return Reply::Refused(Refusal::Busy);
        };
        timeout(self.config.request_timeout, self.execute(peer, request))
            .await
            .unwrap_or(Reply::Refused(Refusal::Busy))
    }

    async fn execute(&self, peer: &PublicKey, request: Request) -> Reply {
        let result = match request {
            Request::Hello => Ok(Reply::Hello {
                max_request: wire::MAX_REQUEST as u32,
                max_reply: self.config.max_reply.min(wire::MAX_REPLY) as u32,
                max_fetch: self.config.max_fetch.min(wire::MAX_FETCH),
            }),
            Request::Head { group } => self
                .may(peer, &group)
                .map(|()| Reply::Head(self.logs.head(&group))),
            Request::Fetch {
                group,
                after,
                limit,
            } => self.may(peer, &group).map(|()| {
                let limit = limit.min(self.config.max_fetch).min(wire::MAX_FETCH) as usize;
                let budget = self
                    .config
                    .max_reply
                    .min(wire::MAX_REPLY)
                    .saturating_sub(64);
                Reply::Entries(
                    self.logs
                        .fetch(&group, after, limit, budget)
                        .unwrap_or_default(),
                )
            }),
            Request::Push { entry } => self.push(peer, &entry).await,
        };
        result.unwrap_or_else(Reply::Refused)
    }

    /// Takes one push from `peer`'s token bucket (milli-pushes, refilled on the server's clock,
    /// never minted by a clock going back).
    fn may_push(&self, peer: &PublicKey) -> bool {
        let cap = u64::from(self.config.push_burst.max(1)) * 1000;
        let rate = u64::from(self.config.push_per_second);
        let now = (self.clock)().0;
        let refill = |(milli, at): (u64, i64)| {
            let elapsed = now.saturating_sub(at).max(0) as u64;
            milli.saturating_add(elapsed.saturating_mul(rate)).min(cap)
        };
        let mut pushes = self.pushes.lock().expect("push rate lock");
        if pushes.len() >= MAX_RATE_TRACKED && !pushes.contains_key(peer) {
            pushes.retain(|_, b| refill(*b) < cap);
        }
        let (milli, at) = pushes.get(peer).copied().unwrap_or((cap, now));
        let milli = refill((milli, at));
        let at = at.max(now);
        if milli < 1000 {
            pushes.insert(*peer, (milli, at));
            return false;
        }
        pushes.insert(*peer, (milli - 1000, at));
        true
    }

    async fn push(&self, peer: &PublicKey, bytes: &[u8]) -> Result<Reply, Refusal> {
        let entry = Entry::decode(bytes).map_err(|_| Refusal::Malformed)?;
        self.may(peer, entry.group())?;
        if !self.may_push(peer) {
            return Err(Refusal::Busy);
        }
        let pushed = self
            .logs
            .push(entry, (self.clock)(), self.config.max_skew_ms)
            .await?;
        if pushed.revokes {
            let _ = self.link.disconnect_untrusted().await;
        }
        Ok(Reply::Accepted {
            head: pushed.head,
            new: pushed.new,
        })
    }
}
