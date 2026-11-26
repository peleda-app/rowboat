//! [`MeshLiveness`]: `baton-lease`'s [`Liveness`] by heartbeat gossip between the members of one
//! group. An observer counts a node alive while it has seen a new heartbeat from it within the
//! time-to-live of its own clock; a new heartbeat is stamped with the observer's time at its next
//! `alive` call, so the only clock involved is the one the caller passes to `alive`. A node's own
//! heartbeat succeeds only when a majority of the roster acknowledged it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use async_trait::async_trait;
use baton_core::{GroupId, NodeId, Timestamp};
use baton_identity::RosterHandle;
use baton_lease::{LeaseError, Liveness, NodeProfile};
use baton_mesh::Transport;
use bytes::Bytes;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// The transport channel heartbeats travel on.
pub const CHANNEL: &str = "baton/liveness/1";

/// The largest heartbeat accepted, in bytes.
pub const MAX_HEARTBEAT: usize = 4096;

const FORGET_AFTER_MS: i64 = 3_600_000;

#[derive(Serialize, Deserialize)]
enum Msg {
    Beat {
        group: GroupId,
        profile: NodeProfile,
        epoch: u64,
        counter: u64,
    },
    Ack {
        epoch: u64,
        counter: u64,
    },
}

struct Entry {
    profile: NodeProfile,
    epoch: u64,
    counter: u64,
    seen_at: Option<i64>,
}

type Seen = Mutex<HashMap<NodeId, Entry>>;
type Waiting = Mutex<HashMap<u64, mpsc::UnboundedSender<NodeId>>>;

fn record(seen: &Seen, profile: NodeProfile, epoch: u64, counter: u64) {
    let mut seen = seen.lock().expect("liveness lock");
    if seen.len() > 4096 {
        let newest = seen.values().filter_map(|e| e.seen_at).max().unwrap_or(0);
        seen.retain(|_, e| {
            e.seen_at
                .is_none_or(|at| newest.saturating_sub(at) < FORGET_AFTER_MS)
        });
    }
    match seen.get_mut(&profile.node) {
        Some(e) if e.epoch == epoch && e.counter >= counter => {}
        _ => {
            seen.insert(
                profile.node.clone(),
                Entry {
                    profile,
                    epoch,
                    counter,
                    seen_at: None,
                },
            );
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("this liveness serves another group")]
struct OtherGroup;

/// [`Liveness`] by gossip for one node of one group.
///
/// Guarantees beyond the contract:
///
/// - A heartbeat for this node is recorded and sent to every member reachable now, and returns
///   `Ok` only once a majority of the roster (this node included) acknowledged it within the ack
///   timeout; otherwise [`LeaseError::Unavailable`]. A holder that cannot get its heartbeats
///   acknowledged must stop, which is what makes "stop `ttl` after the start of the last
///   successful heartbeat" sound across partitions, including one-sided ones.
/// - A heartbeat for another node is recorded locally only, so no member speaks for another.
/// - An incoming heartbeat counts only from a roster member (checked by the transport), only for
///   the sending node itself, only for this group, only up to [`MAX_HEARTBEAT`] bytes, and only if
///   it is newer than the last one from that node: a higher counter in the same boot epoch, or a
///   new epoch (a restart, whatever the restarted node's clock says). Old heartbeats cannot be
///   replayed at all, because the transport refuses replayed frames.
pub struct MeshLiveness {
    group: GroupId,
    seen: Arc<Seen>,
    waiting: Arc<Waiting>,
    transport: Arc<dyn Transport>,
    roster: RosterHandle,
    ttl_ms: u64,
    ack_timeout: Duration,
    epoch: u64,
    counter: AtomicU64,
    task: JoinHandle<()>,
}

impl MeshLiveness {
    /// Starts for `group` on `transport`, with `roster` deciding what a majority is, a time-to-live
    /// of `ttl_ms` (at least 1) and `ack_timeout` to wait for acknowledgements. Needs a Tokio
    /// runtime.
    pub async fn start(
        transport: Arc<dyn Transport>,
        group: GroupId,
        roster: RosterHandle,
        ttl_ms: u64,
        ack_timeout: Duration,
    ) -> Result<Self, LeaseError> {
        let ttl_ms = ttl_ms.max(1);
        let mut incoming = transport
            .subscribe(CHANNEL)
            .await
            .map_err(LeaseError::backend)?;
        let seen: Arc<Seen> = Arc::default();
        let waiting: Arc<Waiting> = Arc::default();
        let epoch = random_u64();
        let weak_seen: Weak<Seen> = Arc::downgrade(&seen);
        let weak_waiting: Weak<Waiting> = Arc::downgrade(&waiting);
        let own_group = group.clone();
        let reply_transport = transport.clone();
        let task = tokio::spawn(async move {
            while let Some(env) = incoming.next().await {
                let (Some(seen), Some(waiting)) = (weak_seen.upgrade(), weak_waiting.upgrade())
                else {
                    break;
                };
                if env.payload.len() > MAX_HEARTBEAT {
                    continue;
                }
                match postcard::from_bytes::<Msg>(&env.payload) {
                    Ok(Msg::Beat {
                        group,
                        profile,
                        epoch,
                        counter,
                    }) if profile.node == env.from && group == own_group => {
                        record(&seen, profile, epoch, counter);
                        let t = reply_transport.clone();
                        let ack = encode(&Msg::Ack { epoch, counter });
                        tokio::spawn(async move {
                            let _ = tokio::time::timeout(
                                Duration::from_secs(2),
                                t.send(&env.from, CHANNEL, ack),
                            )
                            .await;
                        });
                    }
                    Ok(Msg::Ack { epoch: e, counter }) if e == epoch => {
                        let tx = waiting.lock().expect("waiting lock").get(&counter).cloned();
                        if let Some(tx) = tx {
                            let _ = tx.send(env.from.clone());
                        }
                    }
                    _ => {}
                }
            }
        });
        let start = (Timestamp::now().0.max(0) as u64).saturating_mul(1000);
        Ok(Self {
            group,
            seen,
            waiting,
            transport,
            roster,
            ttl_ms,
            ack_timeout,
            epoch,
            counter: AtomicU64::new(start),
            task,
        })
    }
}

fn random_u64() -> u64 {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).expect("the operating system provides randomness");
    u64::from_le_bytes(b)
}

fn encode(msg: &Msg) -> Bytes {
    Bytes::from(postcard::to_stdvec(msg).expect("a message always serializes"))
}

impl Drop for MeshLiveness {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[async_trait]
impl Liveness for MeshLiveness {
    async fn heartbeat(
        &self,
        group: &GroupId,
        profile: &NodeProfile,
        now: Timestamp,
    ) -> Result<(), LeaseError> {
        let _ = now;
        if group != &self.group {
            return Err(LeaseError::backend(OtherGroup));
        }
        let counter = self.counter.fetch_add(1, Ordering::Relaxed) + 1;
        if profile.node != self.transport.local() {
            let mut seen = self.seen.lock().expect("liveness lock");
            let next = seen
                .get(&profile.node)
                .map_or(1, |e| e.counter.saturating_add(1));
            let epoch = seen.get(&profile.node).map_or(0, |e| e.epoch);
            seen.insert(
                profile.node.clone(),
                Entry {
                    profile: profile.clone(),
                    epoch,
                    counter: next,
                    seen_at: None,
                },
            );
            return Ok(());
        }
        record(&self.seen, profile.clone(), self.epoch, counter);
        let roster = self.roster.current();
        let members = roster.member_ids();
        let quorum = roster.quorum();
        let (tx, mut rx) = mpsc::unbounded_channel();
        self.waiting
            .lock()
            .expect("waiting lock")
            .insert(counter, tx);
        let bytes = encode(&Msg::Beat {
            group: group.clone(),
            profile: profile.clone(),
            epoch: self.epoch,
            counter,
        });
        let peers = self.transport.peers().await.map_err(LeaseError::backend)?;
        let sends = peers.iter().map(|p| {
            let t = self.transport.clone();
            let b = bytes.clone();
            let p = p.clone();
            async move {
                let _ = tokio::time::timeout(self.ack_timeout, t.send(&p, CHANNEL, b)).await;
            }
        });
        futures::future::join_all(sends).await;
        let mut acked: std::collections::HashSet<NodeId> =
            std::collections::HashSet::from([self.transport.local()]);
        let deadline = tokio::time::Instant::now() + self.ack_timeout;
        let ok = loop {
            if acked.len() >= quorum {
                break true;
            }
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(from)) if members.contains(&from) => {
                    acked.insert(from);
                }
                Ok(Some(_)) => {}
                _ => break false,
            }
        };
        self.waiting.lock().expect("waiting lock").remove(&counter);
        if ok {
            Ok(())
        } else {
            Err(LeaseError::Unavailable)
        }
    }

    async fn alive(&self, group: &GroupId, now: Timestamp) -> Result<Vec<NodeProfile>, LeaseError> {
        if group != &self.group {
            return Ok(Vec::new());
        }
        let mut seen = self.seen.lock().expect("liveness lock");
        Ok(seen
            .values_mut()
            .filter_map(|e| {
                let at = *e.seen_at.get_or_insert(now.0);
                (now.0.saturating_sub(at) <= self.ttl_ms as i64).then(|| e.profile.clone())
            })
            .collect())
    }

    fn ttl_ms(&self) -> u64 {
        self.ttl_ms
    }
}

#[cfg(test)]
mod tests;
