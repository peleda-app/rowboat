//! [`CasLeases`]: leases as records `lease/{key}` in a [`StateStore`], decided by compare-and-swap
//! with the rules of [`baton_lease::record`]. [`CasLiveness`]: one heartbeat record per node under
//! `nodes/`, so heartbeats cost the same whatever the number of leases.
//!
//! Over a durable store (Skein's control store on S3, a local disk) this is the arbiter for a
//! group whose nodes share that store. Over `baton-state-memory` it serves a single process.
//!
//! No decision compares one node's clock with another's: liveness and staleness are judged on
//! the observer's own clock by watching record versions change.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use baton_core::{GroupId, LeaseKey, NodeId, Timestamp};
use baton_lease::record::{self, LeaseRecord, Reply, Step, View};
use baton_lease::{Lease, LeaseError, Leases, Liveness, NodeProfile, TakeoverOutcome};
use baton_state::{Expect, RecordName, StateError, StateStore, Version};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

const ATTEMPTS: usize = 64;
const MAX_CACHED_GROUPS: usize = 1024;

/// A source of the caller's own time, injectable for tests.
pub type Clock = Arc<dyn Fn() -> Timestamp + Send + Sync>;

/// A clock that never goes back: the wall clock when it is created, advanced by a monotonic
/// timer. Liveness and staleness are judged on it, so a wall-clock jump on this node does not make
/// live peers look dead.
pub fn monotonic_clock() -> Clock {
    let start_wall = Timestamp::now();
    let start = Instant::now();
    Arc::new(move || start_wall.plus_ms(start.elapsed().as_millis() as i64))
}

/// Remembers, on the observer's own clock, when it first saw each version of a record.
#[derive(Default)]
struct Observed {
    seen: Mutex<HashMap<(GroupId, String), (Version, i64)>>,
}

impl Observed {
    /// How long, in milliseconds of the observer's clock, the record has stayed at `version`
    /// since this observer first saw that version; zero the first time.
    fn unchanged_for(&self, group: &GroupId, name: &str, version: &Version, now: Timestamp) -> i64 {
        let mut seen = self.seen.lock().expect("observed lock");
        let entry = seen
            .entry((group.clone(), name.to_owned()))
            .or_insert_with(|| (version.clone(), now.0));
        if &entry.0 != version {
            *entry = (version.clone(), now.0);
        }
        now.0.saturating_sub(entry.1).max(0)
    }
}

/// Leases in a [`StateStore`].
pub struct CasLeases {
    state: Arc<dyn StateStore>,
    liveness: Arc<dyn Liveness>,
    clock: Clock,
    wall: Clock,
    last: Mutex<u64>,
    observed: Observed,
    reuse_alive_ms: u64,
    alive_seen: Mutex<HashMap<GroupId, (i64, Vec<NodeId>)>>,
}

impl CasLeases {
    /// Leases in `state`; a holder counts as gone once `liveness` no longer lists it as alive and
    /// able to lead.
    pub fn new(state: Arc<dyn StateStore>, liveness: Arc<dyn Liveness>) -> Self {
        Self {
            state,
            liveness,
            clock: monotonic_clock(),
            wall: Arc::new(Timestamp::now),
            last: Mutex::new(0),
            observed: Observed::default(),
            reuse_alive_ms: 0,
            alive_seen: Mutex::new(HashMap::new()),
        }
    }

    /// Reuses one answer of `liveness.alive` per group for up to `ms` of this node's time
    /// (clamped to a quarter of the time-to-live) instead of asking on every call, so a node
    /// holding many leases over a liveness that reads a store asks once per interval. An answer
    /// is reused only while it lists the caller and every node the record names (holder,
    /// requester, reservation) as alive; a node that would count as gone is always asked about
    /// again, so reuse can only delay a takeover, never cause one. 0 (the default) asks every
    /// time.
    pub fn reuse_alive_for(mut self, ms: u64) -> Self {
        self.reuse_alive_ms = ms.min(self.liveness.ttl_ms() / 4);
        self
    }

    async fn alive_now(
        &self,
        group: &GroupId,
        now: Timestamp,
        named: &[&NodeId],
    ) -> Result<Vec<NodeId>, LeaseError> {
        if self.reuse_alive_ms > 0 {
            let seen = self.alive_seen.lock().expect("alive cache lock");
            if let Some((at, nodes)) = seen.get(group) {
                let age = now.0.saturating_sub(*at);
                let all_alive = named.iter().all(|n| nodes.contains(n));
                if all_alive && (0..self.reuse_alive_ms as i64).contains(&age) {
                    return Ok(nodes.clone());
                }
            }
        }
        let nodes: Vec<NodeId> = self
            .liveness
            .alive(group, now)
            .await?
            .into_iter()
            .filter(|p| p.may_lead())
            .map(|p| p.node)
            .collect();
        if self.reuse_alive_ms > 0 {
            let mut seen = self.alive_seen.lock().expect("alive cache lock");
            if seen.len() >= MAX_CACHED_GROUPS && !seen.contains_key(group) {
                seen.clear();
            }
            seen.insert(group.clone(), (now.0, nodes.clone()));
        }
        Ok(nodes)
    }

    /// Uses `clock` as this node's own time for liveness and staleness, and as the wall clock for
    /// tokens (tests pass a manual clock).
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.wall = clock.clone();
        self.clock = clock;
        self
    }

    fn name(key: &LeaseKey) -> RecordName {
        RecordName::new(format!("lease/{key}")).expect("a lease key is a valid segment")
    }

    /// The shared token rule, `baton_lease::record::next_token`.
    fn next_fence(&self, previous: u64) -> Option<u64> {
        let mut last = self.last.lock().expect("fence lock");
        let f = record::next_token(previous, *last, (self.wall)().0)?;
        *last = f;
        Some(f)
    }

    async fn read(
        &self,
        group: &GroupId,
        key: &LeaseKey,
    ) -> Result<Option<(LeaseRecord, Version)>, LeaseError> {
        match self
            .state
            .get(group, &Self::name(key))
            .await
            .map_err(LeaseError::backend)?
        {
            None => Ok(None),
            Some((bytes, version)) => Ok(Some((LeaseRecord::decode(&bytes)?, version))),
        }
    }

    async fn run<F>(
        &self,
        group: &GroupId,
        key: &LeaseKey,
        caller: Option<&NodeId>,
        step: F,
    ) -> Result<Reply, LeaseError>
    where
        F: Fn(Option<&LeaseRecord>, &View<'_>) -> Result<Step, LeaseError>,
    {
        let ttl = self.liveness.ttl_ms();
        for attempt in 0..ATTEMPTS {
            let current = self.read(group, key).await?;
            let now = (self.clock)();
            let record = current.as_ref().map(|(r, _)| r);
            let named: Vec<&NodeId> = caller
                .into_iter()
                .chain(record.and_then(|r| r.holder.as_ref()).map(|h| &h.node))
                .chain(record.and_then(|r| r.takeover.as_ref()).map(|t| &t.node))
                .chain(record.and_then(|r| r.reserved.as_ref()).map(|t| &t.node))
                .collect();
            let alive = self.alive_now(group, now, &named).await?;
            let quiet = current.as_ref().map_or(0, |(_, v)| {
                self.observed
                    .unchanged_for(group, Self::name(key).as_str(), v, now) as u64
            });
            let decided = {
                let is_alive = |n: &NodeId| alive.contains(n);
                let view = View {
                    alive: &is_alive,
                    quiet_ms: quiet,
                    ttl_ms: ttl,
                };
                step(current.as_ref().map(|(r, _)| r), &view)?
            };
            match decided {
                Step::Reply(reply) => return Ok(reply),
                Step::Write(next, reply) => {
                    let expect = match &current {
                        None => Expect::Absent,
                        Some((_, v)) => Expect::Version(v.clone()),
                    };
                    match self
                        .state
                        .put(group, &Self::name(key), Bytes::from(next.encode()), expect)
                        .await
                    {
                        Ok(version) => {
                            self.observed.unchanged_for(
                                group,
                                Self::name(key).as_str(),
                                &version,
                                now,
                            );
                            return Ok(reply);
                        }
                        Err(StateError::Conflict) => {
                            if attempt > 4 {
                                tokio::time::sleep(Duration::from_millis(attempt as u64)).await;
                            } else {
                                tokio::task::yield_now().await;
                            }
                        }
                        Err(e) => return Err(LeaseError::backend(e)),
                    }
                }
            }
        }
        Err(LeaseError::Unavailable)
    }
}

#[async_trait]
impl Leases for CasLeases {
    async fn acquire(
        &self,
        group: &GroupId,
        key: &LeaseKey,
        profile: &NodeProfile,
    ) -> Result<Option<Lease>, LeaseError> {
        let next = |f| self.next_fence(f);
        match self
            .run(group, key, Some(&profile.node), |cur, view| {
                record::acquire(cur, group, key, profile, view, &next)
            })
            .await?
        {
            Reply::Lease(l) => Ok(l),
            _ => unreachable!("acquire answers with a lease"),
        }
    }

    async fn request_takeover(
        &self,
        group: &GroupId,
        key: &LeaseKey,
        profile: &NodeProfile,
    ) -> Result<TakeoverOutcome, LeaseError> {
        match self
            .run(group, key, Some(&profile.node), |cur, view| {
                record::request_takeover(cur, profile, view)
            })
            .await?
        {
            Reply::Takeover(o) => Ok(o),
            _ => unreachable!("request_takeover answers with an outcome"),
        }
    }

    async fn release(&self, lease: &Lease) -> Result<(), LeaseError> {
        self.run(&lease.group, &lease.key, None, |cur, _| {
            Ok(record::release(cur, lease))
        })
        .await
        .map(|_| ())
    }

    async fn holder(&self, group: &GroupId, key: &LeaseKey) -> Result<Option<Lease>, LeaseError> {
        Ok(self
            .read(group, key)
            .await?
            .and_then(|(r, _)| r.lease(group, key)))
    }
}

const MAX_HEARTBEAT: usize = 4096;
const PAGE: usize = 1000;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Heartbeat {
    v: u8,
    profile: NodeProfile,
    at: Timestamp,
}

/// Liveness through one record per node, `nodes/{node}`, in a [`StateStore`]. Every heartbeat is
/// a new write, so a new version; an observer counts a node alive while the version it sees has
/// changed within the time-to-live of the observer's own clock. The timestamp in a heartbeat is
/// kept for display only.
///
/// What it has observed is part of each instance, so every node runs its own `CasLiveness` with
/// its own clock; an instance is never shared between nodes.
pub struct CasLiveness {
    state: Arc<dyn StateStore>,
    ttl_ms: u64,
    observed: Observed,
}

impl CasLiveness {
    /// Heartbeats in `state`; nodes stay alive for `ttl_ms` (at least 1) of the observer's time
    /// after it last saw a new heartbeat.
    pub fn new(state: Arc<dyn StateStore>, ttl_ms: u64) -> Self {
        Self {
            state,
            ttl_ms: ttl_ms.max(1),
            observed: Observed::default(),
        }
    }

    fn prefix() -> RecordName {
        RecordName::new("nodes").expect("constant")
    }
}

#[async_trait]
impl Liveness for CasLiveness {
    async fn heartbeat(
        &self,
        group: &GroupId,
        profile: &NodeProfile,
        now: Timestamp,
    ) -> Result<(), LeaseError> {
        let name =
            RecordName::new(format!("nodes/{}", profile.node)).expect("a node id is a segment");
        let beat = Heartbeat {
            v: 1,
            profile: profile.clone(),
            at: now,
        };
        let bytes = Bytes::from(serde_json::to_vec(&beat).expect("plain record"));
        self.state
            .put(group, &name, bytes, Expect::Any)
            .await
            .map_err(LeaseError::backend)?;
        Ok(())
    }

    async fn alive(&self, group: &GroupId, now: Timestamp) -> Result<Vec<NodeProfile>, LeaseError> {
        let mut out = Vec::new();
        let mut after: Option<RecordName> = None;
        loop {
            let page = self
                .state
                .list(group, &Self::prefix(), after.as_ref(), PAGE)
                .await
                .map_err(LeaseError::backend)?;
            let Some(last) = page.last().cloned() else {
                break;
            };
            for name in &page {
                let Some((bytes, version)) = self
                    .state
                    .get(group, name)
                    .await
                    .map_err(LeaseError::backend)?
                else {
                    continue;
                };
                if bytes.len() > MAX_HEARTBEAT {
                    continue;
                }
                let Ok(beat) = serde_json::from_slice::<Heartbeat>(&bytes) else {
                    continue;
                };
                let own_record = name.as_str() == format!("nodes/{}", beat.profile.node);
                if beat.v != 1 || !own_record {
                    continue;
                }
                let quiet = self
                    .observed
                    .unchanged_for(group, name.as_str(), &version, now);
                if quiet <= self.ttl_ms as i64 {
                    out.push(beat.profile);
                }
            }
            after = Some(last);
        }
        Ok(out)
    }

    fn ttl_ms(&self) -> u64 {
        self.ttl_ms
    }
}

#[cfg(test)]
mod tests;
