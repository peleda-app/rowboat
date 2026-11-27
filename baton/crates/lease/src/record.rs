//! The lease rules as a pure state machine over a stored [`LeaseRecord`].
//!
//! An implementation reads the record, calls [`acquire`], [`request_takeover`] or [`release`],
//! writes the returned record with compare-and-swap if the step says so, and retries from the
//! read on a conflict. Liveness and token generation come in as closures, so the same rules run
//! over a compare-and-swap store, in one process or in a quorum.

use baton_core::{FencingToken, GroupId, LeaseKey, NodeId};
use serde::{Deserialize, Serialize};

use crate::{Lease, LeaseError, NodeClass, NodeProfile, Takeover, TakeoverOutcome};

/// The record format version this crate writes and reads.
pub const RECORD_VERSION: u8 = 1;

/// The largest encoded record accepted from storage, in bytes.
pub const MAX_RECORD: usize = 4096;

/// The current holder of a lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Holder {
    /// The node.
    pub node: NodeId,
    /// Its class.
    pub class: NodeClass,
}

/// What is stored per lease key. Never deleted: a released record keeps its token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRecord {
    /// Format version, [`RECORD_VERSION`].
    pub v: u8,
    /// The holder, if any.
    pub holder: Option<Holder>,
    /// The last token granted.
    pub fence: u64,
    /// A stronger node waiting while a holder is in place.
    pub takeover: Option<Takeover>,
    /// After a handover, the node the released lease is reserved for.
    pub reserved: Option<Takeover>,
    /// How many times this record was written; every write raises it, so implementations that
    /// version records by content still see every write as a change.
    pub seq: u64,
}

impl LeaseRecord {
    /// Parses a stored record and checks its invariants; anything else is
    /// [`LeaseError::Corrupted`].
    pub fn decode(bytes: &[u8]) -> Result<Self, LeaseError> {
        if bytes.len() > MAX_RECORD {
            return Err(LeaseError::Corrupted);
        }
        let r: LeaseRecord = serde_json::from_slice(bytes).map_err(|_| LeaseError::Corrupted)?;
        let ok = r.v == RECORD_VERSION
            && r.holder.as_ref().is_none_or(|h| h.class.may_lead())
            && (r.holder.is_some() || r.takeover.is_none())
            && (r.holder.is_none() || r.reserved.is_none())
            && r.takeover.as_ref().is_none_or(|t| {
                t.class.may_lead() && r.holder.as_ref().is_some_and(|h| t.class.outranks(h.class))
            })
            && r.reserved.as_ref().is_none_or(|t| t.class.may_lead())
            && (r.holder.is_none() || r.fence > 0);
        if ok {
            Ok(r)
        } else {
            Err(LeaseError::Corrupted)
        }
    }

    /// The stored form.
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("plain record")
    }

    /// The lease this record describes, if it has a holder.
    pub fn lease(&self, group: &GroupId, key: &LeaseKey) -> Option<Lease> {
        self.holder.as_ref().map(|h| Lease {
            group: group.clone(),
            key: key.clone(),
            node: h.node.clone(),
            class: h.class,
            fence: FencingToken(self.fence),
            takeover: self.takeover.clone(),
        })
    }

    fn held_by(profile: &NodeProfile, fence: u64) -> Self {
        Self {
            v: RECORD_VERSION,
            holder: Some(Holder {
                node: profile.node.clone(),
                class: profile.class,
            }),
            fence,
            takeover: None,
            reserved: None,
            seq: 0,
        }
    }

    fn after(mut self, previous: Option<&LeaseRecord>) -> Self {
        self.seq = previous.map_or(1, |p| p.seq.saturating_add(1));
        self
    }
}

/// The answer an operation gives once its record (if any) is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// For `acquire`.
    Lease(Option<Lease>),
    /// For `request_takeover`.
    Takeover(TakeoverOutcome),
    /// For `release`.
    Released,
}

/// What to do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Write this record with compare-and-swap against what was read, then answer; on a conflict,
    /// read again and redo the step.
    Write(LeaseRecord, Reply),
    /// Answer without writing.
    Reply(Reply),
}

/// What the caller observed about the world when it read the record.
pub struct View<'a> {
    /// Whether a node is alive and may lead now, according to the caller's liveness view.
    pub alive: &'a dyn Fn(&NodeId) -> bool,
    /// How long, in milliseconds of the caller's own clock, the stored record has stayed
    /// unchanged since the caller first saw it as it is now (zero for a record seen for the first
    /// time).
    pub quiet_ms: u64,
    /// The liveness time-to-live in milliseconds.
    pub ttl_ms: u64,
}

impl View<'_> {
    /// A holder is gone when the liveness view says so and its record has not changed for a
    /// whole time-to-live, which covers a view that has not yet heard of a new holder.
    fn holder_gone(&self, node: &NodeId) -> bool {
        !(self.alive)(node) && self.quiet_ms > self.ttl_ms
    }

    /// A waiting requester (a pending takeover or a reservation) holds others back while it is
    /// alive and may lead, and the record has changed within two time-to-lives: one for a holder
    /// to be declared gone, one for the requester to take over. A requester that never comes
    /// cannot block the key for longer.
    fn waiter_blocks(&self, waiter: Option<&Takeover>, caller: &NodeId) -> bool {
        waiter.is_some_and(|t| {
            &t.node != caller
                && (self.alive)(&t.node)
                && self.quiet_ms <= self.ttl_ms.saturating_mul(2)
        })
    }
}

fn bump(next_fence: &dyn Fn(u64) -> Option<u64>, previous: u64) -> Result<u64, LeaseError> {
    match next_fence(previous) {
        Some(f) if f > previous => Ok(f),
        _ => Err(LeaseError::Corrupted),
    }
}

/// The `acquire` rule. `next_fence` returns a token higher than the one it is given, or `None`
/// when none exists (the step then fails instead of wrapping around).
pub fn acquire(
    current: Option<&LeaseRecord>,
    group: &GroupId,
    key: &LeaseKey,
    profile: &NodeProfile,
    view: &View<'_>,
    next_fence: &dyn Fn(u64) -> Option<u64>,
) -> Result<Step, LeaseError> {
    acquire_above(current, group, key, profile, view, 0, next_fence)
}

/// The `acquire` rule with a floor: a new grant carries a token above `floor`, and a renewal by
/// the holder whose token is below `floor` is granted again with a new token above it (same
/// holder, same takeover state), so a holder whose storage already saw a higher token from
/// another arbiter can write again. A renewal at the floor keeps its token (the holder's own
/// storage carries it). Callers bound `floor` themselves (see
/// `Leases::acquire_above`).
pub fn acquire_above(
    current: Option<&LeaseRecord>,
    group: &GroupId,
    key: &LeaseKey,
    profile: &NodeProfile,
    view: &View<'_>,
    floor: u64,
    next_fence: &dyn Fn(u64) -> Option<u64>,
) -> Result<Step, LeaseError> {
    if !profile.may_lead() {
        return Ok(Step::Reply(Reply::Lease(None)));
    }
    let grant = |fence: u64| {
        let r = LeaseRecord::held_by(profile, fence).after(current);
        let lease = r.lease(group, key);
        Step::Write(r, Reply::Lease(lease))
    };
    let Some(r) = current else {
        return Ok(grant(bump(next_fence, floor)?));
    };
    match &r.holder {
        Some(h) if h.node == profile.node => {
            if h.class == profile.class && r.fence >= floor {
                return Ok(Step::Reply(Reply::Lease(r.lease(group, key))));
            }
            let mut next = r.clone();
            if r.fence < floor {
                next.fence = bump(next_fence, floor)?;
            }
            next.holder = Some(Holder {
                node: profile.node.clone(),
                class: profile.class,
            });
            if next
                .takeover
                .as_ref()
                .is_some_and(|t| !t.class.outranks(profile.class))
            {
                next.takeover = None;
            }
            let next = next.after(Some(r));
            let lease = next.lease(group, key);
            Ok(Step::Write(next, Reply::Lease(lease)))
        }
        Some(h) if !view.holder_gone(&h.node) => Ok(Step::Reply(Reply::Lease(None))),
        Some(_) if view.waiter_blocks(r.takeover.as_ref(), &profile.node) => {
            Ok(Step::Reply(Reply::Lease(None)))
        }
        None if view.waiter_blocks(r.reserved.as_ref(), &profile.node) => {
            Ok(Step::Reply(Reply::Lease(None)))
        }
        _ => Ok(grant(bump(next_fence, r.fence.max(floor))?)),
    }
}

/// The `request_takeover` rule. A requester that asks again while its request is stale rewrites
/// it, which refreshes it.
pub fn request_takeover(
    current: Option<&LeaseRecord>,
    profile: &NodeProfile,
    view: &View<'_>,
) -> Result<Step, LeaseError> {
    use TakeoverOutcome::*;
    let reply = |o| Ok(Step::Reply(Reply::Takeover(o)));
    if !profile.may_lead() {
        return reply(Refused);
    }
    let me = Takeover {
        node: profile.node.clone(),
        class: profile.class,
    };
    let Some(r) = current else {
        return reply(NotNeeded);
    };
    let Some(h) = &r.holder else {
        return match &r.reserved {
            Some(t) if view.waiter_blocks(Some(t), &profile.node) => {
                if profile.class.outranks(t.class) {
                    let mut next = r.clone();
                    next.reserved = Some(me);
                    Ok(Step::Write(next.after(Some(r)), Reply::Takeover(Recorded)))
                } else {
                    reply(Refused)
                }
            }
            _ => reply(NotNeeded),
        };
    };
    if h.node == profile.node {
        return reply(AlreadyHolder);
    }
    if view.holder_gone(&h.node) {
        return reply(NotNeeded);
    }
    if !profile.class.outranks(h.class) {
        return reply(Refused);
    }
    match &r.takeover {
        Some(t) if t == &me && view.quiet_ms <= view.ttl_ms => reply(Recorded),
        Some(t)
            if view.waiter_blocks(Some(t), &profile.node) && !profile.class.outranks(t.class) =>
        {
            reply(Refused)
        }
        _ => {
            let mut next = r.clone();
            next.takeover = Some(me);
            Ok(Step::Write(next.after(Some(r)), Reply::Takeover(Recorded)))
        }
    }
}

/// The `release` rule: only the holder with the matching token releases; the token is kept and
/// a pending takeover becomes a reservation.
pub fn release(current: Option<&LeaseRecord>, lease: &Lease) -> Step {
    match current {
        Some(r)
            if r.fence == lease.fence.0
                && r.holder.as_ref().is_some_and(|h| h.node == lease.node) =>
        {
            let mut next = r.clone();
            next.holder = None;
            next.reserved = next.takeover.take();
            Step::Write(next.after(Some(r)), Reply::Released)
        }
        _ => Step::Reply(Reply::Released),
    }
}

/// The next token: above `previous` (the stored token), above `last` (the last one this node
/// granted) and at least `wall_ms` in microseconds, so a lost or rolled-back record or a restart
/// over a store that forgets never lowers tokens (unless the wall clock went back by more than the
/// time in between). `None` when no higher token exists.
pub fn next_token(previous: u64, last: u64, wall_ms: i64) -> Option<u64> {
    let wall = (wall_ms.max(0) as u64).saturating_mul(1000);
    Some(previous.checked_add(1)?.max(wall).max(last.checked_add(1)?))
}

#[cfg(test)]
mod tests;
