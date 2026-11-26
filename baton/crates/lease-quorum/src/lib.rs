//! [`QuorumLeases`]: `baton-lease`'s [`Leases`] decided by a majority of a group's members, for
//! groups without a shared store.
//!
//! Each lease key has a register (its `LeaseRecord`) replicated on every roster member, changed
//! only by single-decree Paxos per change (CASPaxos, Rystsov 2018): every call reads the register
//! from a majority, applies the rules of `baton_lease::record`, and writes the result back to a
//! majority. A node that cannot reach a majority can neither acquire, release nor read a lease.
//! Acceptors write every promise and acceptance to a [`StateStore`] before answering.

mod paxos;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use baton_core::{GroupId, LeaseKey, NodeId, Timestamp};
use baton_identity::RosterHandle;
use baton_lease::record::{self, LeaseRecord, Reply as Answer, Step, View};
use baton_lease::{Lease, LeaseError, Leases, Liveness, NodeProfile, TakeoverOutcome};
use baton_mesh::{MAX_PAYLOAD, Transport};
use baton_state::StateStore;
use bytes::Bytes;
use futures::StreamExt;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use paxos::{Acceptor, Ballot, Register, Reply};

/// The transport channel rounds travel on.
pub const CHANNEL: &str = "baton/lease/1";

/// How many prepare and accept messages one member may send in [`RATE_WINDOW`] before the rest
/// are dropped, so a member cannot flood acceptors with new keys.
pub const RATE_LIMIT: u32 = 5_000;

/// The window of [`RATE_LIMIT`].
pub const RATE_WINDOW: Duration = Duration::from_secs(10);

/// How far above the wall clock in microseconds a token in a register may be; a register beyond
/// it is refused, so a member cannot push a key's token to the top of the range.
pub const MAX_FENCE_AHEAD_US: u64 = 86_400 * 1_000_000;

const MAX_TIMEOUTS: u32 = 3;

/// A source of this node's own time.
pub type Clock = Arc<dyn Fn() -> Timestamp + Send + Sync>;

/// Why a call could not finish. Wrapped in [`LeaseError::Backend`]; [`LeaseError::Unavailable`]
/// is used when no majority is reachable or a majority vetoed a change; every case may be
/// retried.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QuorumError {
    /// This node is not a member of the roster it trusts, so it takes no part in decisions.
    #[error("this node is not a roster member")]
    NotMember,
    /// Other proposers kept winning for every attempt, or the ballot space ran out.
    #[error("contention: gave up after repeated conflicts")]
    Contention,
    /// A call named another group than the one this instance serves.
    #[error("this instance serves another group")]
    OtherGroup,
}

/// Tuning for [`QuorumLeases`].
#[derive(Debug, Clone)]
pub struct QuorumConfig {
    /// How long to wait for a majority in one phase of a round, and for one send.
    pub phase_timeout: Duration,
    /// How many rounds to try before giving up. A call also gives up after three phases that
    /// time out without a majority.
    pub max_attempts: u32,
}

impl Default for QuorumConfig {
    fn default() -> Self {
        Self {
            phase_timeout: Duration::from_millis(500),
            max_attempts: 16,
        }
    }
}

#[derive(Serialize, Deserialize)]
enum Msg {
    Prepare {
        id: u64,
        group: GroupId,
        key: LeaseKey,
        ballot: Ballot,
    },
    Accept {
        id: u64,
        group: GroupId,
        key: LeaseKey,
        ballot: Ballot,
        base: Register,
        value: Register,
    },
    Reply {
        id: u64,
        reply: Reply,
    },
}

fn encode(msg: &Msg) -> Bytes {
    Bytes::from(postcard::to_stdvec(msg).expect("a message always serializes"))
}

type Pending = Mutex<HashMap<u64, mpsc::UnboundedSender<(NodeId, Reply)>>>;

#[derive(Default)]
struct Observed {
    seen: Mutex<HashMap<LeaseKey, ([u8; 32], i64)>>,
}

impl Observed {
    fn unchanged_for(&self, key: &LeaseKey, value: &Register, now: Timestamp) -> u64 {
        let digest =
            *blake3::hash(&postcard::to_stdvec(value).expect("a register serializes")).as_bytes();
        let mut seen = self.seen.lock().expect("observed lock");
        if seen.len() > 100_000 && !seen.contains_key(key) {
            seen.clear();
        }
        let entry = seen.entry(key.clone()).or_insert((digest, now.0));
        if entry.0 != digest {
            *entry = (digest, now.0);
        }
        now.0.saturating_sub(entry.1).max(0) as u64
    }
}

#[derive(Default)]
struct Rate {
    seen: Mutex<HashMap<NodeId, (Instant, u32)>>,
}

impl Rate {
    fn allow(&self, from: &NodeId) -> bool {
        let mut seen = self.seen.lock().expect("rate lock");
        let now = Instant::now();
        if seen.len() > 4096 {
            seen.retain(|_, (start, _)| now.duration_since(*start) < RATE_WINDOW);
        }
        let entry = seen.entry(from.clone()).or_insert((now, 0));
        if now.duration_since(entry.0) >= RATE_WINDOW {
            *entry = (now, 0);
        }
        entry.1 = entry.1.saturating_add(1);
        entry.1 <= RATE_LIMIT
    }
}

struct Inner {
    group: GroupId,
    transport: Arc<dyn Transport>,
    roster: RosterHandle,
    liveness: Arc<dyn Liveness>,
    clock: Clock,
    config: QuorumConfig,
    acceptor: Acceptor,
    pending: Pending,
    next_id: AtomicU64,
    next_round: AtomicU64,
    last_fence: Mutex<u64>,
    observed: Observed,
    rate: Rate,
    key_locks: Mutex<HashMap<LeaseKey, Arc<tokio::sync::Mutex<()>>>>,
}

enum Gathered {
    Quorum(Vec<Reply>),
    Nack(Ballot),
    Veto,
    Timeout,
}

struct PendingGuard<'a>(&'a Pending, u64);

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.0.lock().expect("pending lock").remove(&self.1);
    }
}

/// [`Leases`] decided by a majority of one group's roster members.
///
/// Every member runs one, as proposer for its own calls and acceptor for everyone's.
///
/// Guarantees beyond the contract:
///
/// - Calls are linearizable per key across the group, as long as acceptors keep their state
///   (they write it to the [`StateStore`] before answering) and roster changes follow the rule
///   in the crate docs.
/// - A node that cannot reach a majority gets [`LeaseError::Unavailable`] from every call, so a
///   minority partition can neither acquire nor confirm a lease.
/// - **Acceptors veto takeovers they cannot confirm.** An acceptor refuses a change that moves a
///   key away from a holder (unless the holder itself proposes it) while its own view still shows
///   that holder alive or its record changed within the time-to-live. With `baton-liveness-mesh`,
///   a holder's heartbeat succeeds only when a majority acknowledged it, and any majority that
///   could grant a takeover shares a member with it, so no takeover is granted within the
///   time-to-live of a holder's last successful heartbeat.
/// - Tokens never go backwards, across partitions, healing and restarts: a new token is above
///   every token any promise in the round reported and follows `baton_lease::record::next_token`;
///   registers whose token runs more than a day ahead of the wall clock are refused.
/// - Ballots cannot jump far ahead of the binding promise, promises to proposers that left the
///   roster stop binding, and each member's prepare and accept messages are rate limited.
pub struct QuorumLeases {
    inner: Arc<Inner>,
    task: JoinHandle<()>,
}

impl QuorumLeases {
    /// Starts this node's proposer and acceptor for `group` on `transport`. `roster` decides who
    /// votes and what a majority is; `liveness` and `clock` decide whether a holder is gone;
    /// `state` keeps the acceptor's promises across restarts. Needs a Tokio runtime.
    pub async fn start(
        group: GroupId,
        transport: Arc<dyn Transport>,
        roster: RosterHandle,
        liveness: Arc<dyn Liveness>,
        state: Arc<dyn StateStore>,
        clock: Clock,
        config: QuorumConfig,
    ) -> Result<Self, LeaseError> {
        let mut incoming = transport
            .subscribe(CHANNEL)
            .await
            .map_err(LeaseError::backend)?;
        let inner = Arc::new(Inner {
            acceptor: Acceptor::new(group.clone(), state, roster.clone()),
            group,
            transport,
            roster,
            liveness,
            clock,
            config,
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(OsRng.next_u64() >> 1),
            next_round: AtomicU64::new(0),
            last_fence: Mutex::new(0),
            observed: Observed::default(),
            rate: Rate::default(),
            key_locks: Mutex::new(HashMap::new()),
        });
        let weak: Weak<Inner> = Arc::downgrade(&inner);
        let task = tokio::spawn(async move {
            while let Some(env) = incoming.next().await {
                let Some(inner) = weak.upgrade() else { break };
                if env.payload.len() > MAX_PAYLOAD {
                    continue;
                }
                let Ok(msg) = postcard::from_bytes::<Msg>(&env.payload) else {
                    continue;
                };
                let answer = match msg {
                    Msg::Prepare {
                        id,
                        group,
                        key,
                        ballot,
                    } if ballot.proposer == env.from
                        && group == inner.group
                        && inner.rate.allow(&env.from) =>
                    {
                        inner.acceptor.prepare(&key, &ballot).await.map(|r| (id, r))
                    }
                    Msg::Accept {
                        id,
                        group,
                        key,
                        ballot,
                        base,
                        value,
                    } if ballot.proposer == env.from
                        && group == inner.group
                        && inner.rate.allow(&env.from) =>
                    {
                        let now = (inner.clock)();
                        if !valid(&value, now) || !valid(&base, now) {
                            continue;
                        }
                        let Ok(alive) = inner.alive(now).await else {
                            continue;
                        };
                        let allow = |_: &Register, next: &Register| {
                            inner.allows(&key, &env.from, &alive, now, &base, next)
                        };
                        let reply = inner
                            .acceptor
                            .accept(&key, &ballot, value.clone(), &allow)
                            .await;
                        if matches!(reply, Some(Reply::Accepted)) {
                            inner.observed.unchanged_for(&key, &value, now);
                        }
                        reply.map(|r| (id, r))
                    }
                    Msg::Reply { id, reply } => {
                        let tx = inner
                            .pending
                            .lock()
                            .expect("pending lock")
                            .get(&id)
                            .cloned();
                        if let Some(tx) = tx {
                            let _ = tx.send((env.from.clone(), reply));
                        }
                        None
                    }
                    _ => None,
                };
                if let Some((id, reply)) = answer {
                    let t = inner.transport.clone();
                    let wait = inner.config.phase_timeout;
                    tokio::spawn(async move {
                        let _ = tokio::time::timeout(
                            wait,
                            t.send(&env.from, CHANNEL, encode(&Msg::Reply { id, reply })),
                        )
                        .await;
                    });
                }
            }
        });
        Ok(Self { inner, task })
    }
}

impl Drop for QuorumLeases {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn valid(value: &Register, now: Timestamp) -> bool {
    let ceiling = (now.0.max(0) as u64)
        .saturating_mul(1000)
        .saturating_add(MAX_FENCE_AHEAD_US);
    value
        .as_ref()
        .is_none_or(|r| r.fence <= ceiling && LeaseRecord::decode(&r.encode()).is_ok())
}

impl Inner {
    fn key_lock(&self, key: &LeaseKey) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.key_locks.lock().expect("key locks");
        if locks.len() > 10_000 && !locks.contains_key(key) {
            locks.retain(|_, l| Arc::strong_count(l) > 1);
        }
        locks.entry(key.clone()).or_default().clone()
    }

    async fn alive(&self, now: Timestamp) -> Result<Vec<NodeId>, LeaseError> {
        Ok(self
            .liveness
            .alive(&self.group, now)
            .await?
            .into_iter()
            .filter(NodeProfile::may_lead)
            .map(|p| p.node)
            .collect())
    }

    /// Whether this node, as acceptor, lets the proposer move a key from `base` (the register the
    /// proposer read from its majority) to `next`: never to another holder while this node still
    /// sees the base holder alive or its record freshly written, unless the holder itself
    /// proposes it. Keeping the holder and releasing (same token, no holder) always pass, so a
    /// decided value spreads to acceptors that fell behind.
    fn allows(
        &self,
        key: &LeaseKey,
        proposer: &NodeId,
        alive: &[NodeId],
        now: Timestamp,
        base: &Register,
        next: &Register,
    ) -> bool {
        let Some(base_record) = base.as_ref() else {
            return true;
        };
        let Some(h) = base_record.holder.as_ref() else {
            return true;
        };
        let keeps = next
            .as_ref()
            .and_then(|r| r.holder.as_ref())
            .is_some_and(|n| n.node == h.node);
        let releases = next
            .as_ref()
            .is_some_and(|r| r.holder.is_none() && r.fence == base_record.fence);
        if keeps || releases || proposer == &h.node {
            return true;
        }
        let quiet = self.observed.unchanged_for(key, base, now);
        !(alive.contains(&h.node) || quiet <= self.liveness.ttl_ms())
    }

    async fn gather(
        &self,
        members: &[NodeId],
        reachable: &[NodeId],
        quorum: usize,
        local: Option<Reply>,
        make: impl Fn(u64) -> Msg,
    ) -> Gathered {
        let mut replies = Vec::new();
        match local {
            Some(Reply::Nack(b)) => return Gathered::Nack(b),
            Some(Reply::Veto) => return Gathered::Veto,
            Some(r) => replies.push(r),
            None => {}
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, mut rx) = mpsc::unbounded_channel();
        self.pending.lock().expect("pending lock").insert(id, tx);
        let _guard = PendingGuard(&self.pending, id);
        let bytes = encode(&make(id));
        let wait = self.config.phase_timeout;
        futures::future::join_all(reachable.iter().map(|peer| {
            let b = bytes.clone();
            async move {
                let _ = tokio::time::timeout(wait, self.transport.send(peer, CHANNEL, b)).await;
            }
        }))
        .await;
        let mut seen: HashSet<NodeId> = HashSet::from([self.transport.local()]);
        let deadline = tokio::time::Instant::now() + wait;
        while replies.len() < quorum {
            let Ok(Some((from, reply))) = tokio::time::timeout_at(deadline, rx.recv()).await else {
                return Gathered::Timeout;
            };
            if !members.contains(&from) || !seen.insert(from) {
                continue;
            }
            match reply {
                Reply::Nack(b) => return Gathered::Nack(b),
                Reply::Veto => return Gathered::Veto,
                r => replies.push(r),
            }
        }
        Gathered::Quorum(replies)
    }

    fn next_ballot(&self, local: &NodeId) -> Result<Ballot, LeaseError> {
        let round = self
            .next_round
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |r| r.checked_add(1))
            .map_err(|_| LeaseError::backend(QuorumError::Contention))?
            + 1;
        Ok(Ballot {
            round,
            proposer: local.clone(),
        })
    }

    async fn round<F>(&self, key: &LeaseKey, step: F) -> Result<(Answer, Register), LeaseError>
    where
        F: Fn(
            Option<&LeaseRecord>,
            &View<'_>,
            &dyn Fn(u64) -> Option<u64>,
        ) -> Result<Step, LeaseError>,
    {
        let lock = self.key_lock(key);
        let _held = lock.lock().await;
        let local = self.transport.local();
        let mut contention = false;
        let mut timeouts = 0;
        for attempt in 0..self.config.max_attempts {
            if attempt > 0 {
                let cap = 5 * u64::from(attempt.min(20));
                tokio::time::sleep(Duration::from_millis(1 + u64::from(OsRng.next_u32()) % cap))
                    .await;
            }
            let roster = self.roster.current();
            if !roster.contains_node(&local) {
                return Err(LeaseError::backend(QuorumError::NotMember));
            }
            let members = roster.member_ids();
            let quorum = roster.quorum();
            let reachable: Vec<NodeId> = self
                .transport
                .peers()
                .await
                .map_err(LeaseError::backend)?
                .into_iter()
                .filter(|p| members.contains(p))
                .collect();
            if reachable.len() + 1 < quorum {
                return Err(LeaseError::Unavailable);
            }
            let ballot = self.next_ballot(&local)?;
            let promises = match self
                .gather(
                    &members,
                    &reachable,
                    quorum,
                    self.acceptor.prepare(key, &ballot).await,
                    |id| Msg::Prepare {
                        id,
                        group: self.group.clone(),
                        key: key.clone(),
                        ballot: ballot.clone(),
                    },
                )
                .await
            {
                Gathered::Quorum(r) => r,
                Gathered::Nack(seen) => {
                    self.next_round.fetch_max(seen.round, Ordering::Relaxed);
                    contention = true;
                    continue;
                }
                Gathered::Veto => return Err(LeaseError::Unavailable),
                Gathered::Timeout => {
                    timeouts += 1;
                    if timeouts >= MAX_TIMEOUTS {
                        return Err(LeaseError::Unavailable);
                    }
                    continue;
                }
            };
            let now = (self.clock)();
            let accepted: Vec<(Ballot, Register)> = promises
                .into_iter()
                .filter_map(|r| match r {
                    Reply::Promise(a) => a,
                    _ => None,
                })
                .filter(|(_, v)| valid(v, now))
                .collect();
            let floor = accepted
                .iter()
                .filter_map(|(_, v)| v.as_ref().map(|r| r.fence))
                .max()
                .unwrap_or(0);
            let current: Register = accepted
                .into_iter()
                .max_by(|a, b| a.0.cmp(&b.0))
                .and_then(|(_, v)| v);
            let alive = self.alive(now).await?;
            let quiet = self.observed.unchanged_for(key, &current, now);
            let ttl = self.liveness.ttl_ms();
            let wall = now.0;
            let next_fence = |previous: u64| {
                let mut last = self.last_fence.lock().expect("fence lock");
                let f = record::next_token(previous.max(floor), *last, wall)?;
                *last = f;
                Some(f)
            };
            let (next, answer) = {
                let is_alive = |n: &NodeId| alive.contains(n);
                let view = View {
                    alive: &is_alive,
                    quiet_ms: quiet,
                    ttl_ms: ttl,
                };
                match step(current.as_ref(), &view, &next_fence)? {
                    Step::Write(r, a) => (Some(r), a),
                    Step::Reply(a) => (current.clone(), a),
                }
            };
            let allow =
                |_: &Register, n: &Register| self.allows(key, &local, &alive, now, &current, n);
            let local_reply = self
                .acceptor
                .accept(key, &ballot, next.clone(), &allow)
                .await;
            match self
                .gather(&members, &reachable, quorum, local_reply, |id| {
                    Msg::Accept {
                        id,
                        group: self.group.clone(),
                        key: key.clone(),
                        ballot: ballot.clone(),
                        base: current.clone(),
                        value: next.clone(),
                    }
                })
                .await
            {
                Gathered::Quorum(_) => {
                    self.observed.unchanged_for(key, &next, now);
                    return Ok((answer, next));
                }
                Gathered::Nack(seen) => {
                    self.next_round.fetch_max(seen.round, Ordering::Relaxed);
                    contention = true;
                }
                Gathered::Veto => return Err(LeaseError::Unavailable),
                Gathered::Timeout => {
                    timeouts += 1;
                    if timeouts >= MAX_TIMEOUTS {
                        return Err(LeaseError::Unavailable);
                    }
                }
            }
        }
        if contention {
            Err(LeaseError::backend(QuorumError::Contention))
        } else {
            Err(LeaseError::Unavailable)
        }
    }

    fn check_group(&self, group: &GroupId) -> Result<(), LeaseError> {
        if group == &self.group {
            Ok(())
        } else {
            Err(LeaseError::backend(QuorumError::OtherGroup))
        }
    }
}

#[async_trait]
impl Leases for QuorumLeases {
    async fn acquire(
        &self,
        group: &GroupId,
        key: &LeaseKey,
        profile: &NodeProfile,
    ) -> Result<Option<Lease>, LeaseError> {
        self.inner.check_group(group)?;
        match self
            .inner
            .round(key, |cur, view, next| {
                record::acquire(cur, group, key, profile, view, next)
            })
            .await?
            .0
        {
            Answer::Lease(l) => Ok(l),
            _ => unreachable!("acquire answers with a lease"),
        }
    }

    async fn request_takeover(
        &self,
        group: &GroupId,
        key: &LeaseKey,
        profile: &NodeProfile,
    ) -> Result<TakeoverOutcome, LeaseError> {
        self.inner.check_group(group)?;
        match self
            .inner
            .round(key, |cur, view, _| {
                record::request_takeover(cur, profile, view)
            })
            .await?
            .0
        {
            Answer::Takeover(o) => Ok(o),
            _ => unreachable!("request_takeover answers with an outcome"),
        }
    }

    async fn release(&self, lease: &Lease) -> Result<(), LeaseError> {
        if lease.group != self.inner.group {
            return Ok(());
        }
        self.inner
            .round(&lease.key, |cur, _, _| Ok(record::release(cur, lease)))
            .await
            .map(|_| ())
    }

    async fn holder(&self, group: &GroupId, key: &LeaseKey) -> Result<Option<Lease>, LeaseError> {
        self.inner.check_group(group)?;
        let (_, current) = self
            .inner
            .round(key, |_, _, _| Ok(Step::Reply(Answer::Released)))
            .await?;
        Ok(current.and_then(|r| r.lease(group, key)))
    }
}

#[cfg(test)]
mod tests;
