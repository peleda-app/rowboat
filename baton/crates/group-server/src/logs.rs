use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use baton_core::{GroupId, Timestamp};
use baton_group::{Entry, GroupError, GroupLog, Op, Role, store};
use baton_link::PublicKey;
use baton_state::{RecordName, StateStore};

use crate::wire::{Head, Refusal};

struct Slot {
    genesis: [u8; 32],
    log: RwLock<Option<GroupLog>>,
    bytes: AtomicU64,
    write: tokio::sync::Mutex<()>,
}

/// How large a log a server keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogLimits {
    /// Entries per log any node may fill.
    pub max_entries: u64,
    /// Encoded entry bytes per log any node may fill.
    pub max_bytes: u64,
    /// Entries kept beyond either limit (and 4 KiB of bytes each) for entries that take trust
    /// away (`RevokeNode`, `RemoveMember`, `RekeyMember`) signed by an admin's or owner's node or
    /// by a recovery key, so a full log never blocks a revocation.
    pub reserve: u64,
}

impl LogLimits {
    /// At most `max_entries` entries, no byte limit, and a reserve of a sixteenth of that
    /// (at least 16).
    pub fn entries(max_entries: u64) -> Self {
        Self {
            max_entries: max_entries.max(1),
            max_bytes: u64::MAX,
            reserve: (max_entries / 16).max(16),
        }
    }
}

/// Bytes the reserve allows per reserved entry beyond [`LogLimits::max_bytes`]; entries that take
/// trust away are a few hundred bytes.
const RESERVE_ENTRY_BYTES: u64 = 4096;

fn encoded_len(e: &Entry) -> u64 {
    e.encode().len() as u64
}

fn takes_trust(op: &Op) -> bool {
    matches!(
        op,
        Op::RevokeNode { .. } | Op::RemoveMember { .. } | Op::RekeyMember { .. }
    )
}

/// Whether `entry` may be stored in the reserve: it takes trust away and its signer is not a
/// plain member's node (an admin's or owner's node, or a recovery key that `baton-group` checks).
fn reserve_allows(log: &GroupLog, entry: &Entry) -> bool {
    if !takes_trust(entry.op()) {
        return false;
    }
    let state = log.state();
    match state.node(entry.signer(), entry.at()) {
        None => true,
        Some(cert) => state.role(&cert.member).is_some_and(|r| r >= Role::Admin),
    }
}

/// What a push did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pushed {
    /// The head after the push.
    pub head: Head,
    /// False when the log already held exactly this entry.
    pub new: bool,
    /// Whether the entry can take trust away (revokes a node, removes or rekeys a member), so
    /// open streams must be checked again.
    pub revokes: bool,
}

/// The group logs a server holds, verified and in memory, backed by a [`StateStore`].
///
/// Guarantees:
///
/// - Only the groups given to [`GroupLogs::new`] are held, each pinned to its genesis hash: a
///   genesis with another hash is never accepted, and a store holding another genesis fails
///   [`GroupLogs::load`].
/// - An entry enters a log only after `baton-group` accepted it at the head
///   ([`GroupLog::apply_fresh`]), and is written to the store with `put_if_absent` before the push
///   is reported done; if writing fails, the group is reloaded from the store (and held empty, so
///   nobody counts, if that fails too) and the push fails.
/// - Pushes to one group are serialized; reads never wait for the store. A push runs to its end
///   (stored and in memory, or reloaded from the store) even when its caller stops waiting.
/// - A log holds at most [`LogLimits::max_entries`] entries and [`LogLimits::max_bytes`] bytes
///   from anyone; beyond that only entries that take trust away, signed by an admin's or owner's
///   node or a recovery key, are stored, up to [`LogLimits::reserve`] more. So a member that
///   fills the log cannot stop its own revocation.
pub struct GroupLogs {
    slots: BTreeMap<GroupId, Slot>,
    store: Arc<dyn StateStore>,
    limits: LogLimits,
}

impl GroupLogs {
    /// Logs for `groups` (each with the hash of its genesis entry) kept in `store`, with the
    /// limits of [`LogLimits::entries`]`(max_entries)`. Empty until [`GroupLogs::load`].
    pub fn new(
        groups: impl IntoIterator<Item = (GroupId, [u8; 32])>,
        store: Arc<dyn StateStore>,
        max_entries: u64,
    ) -> Self {
        Self::with_limits(groups, store, LogLimits::entries(max_entries))
    }

    /// Logs for `groups` kept in `store` within `limits`. Empty until [`GroupLogs::load`].
    pub fn with_limits(
        groups: impl IntoIterator<Item = (GroupId, [u8; 32])>,
        store: Arc<dyn StateStore>,
        limits: LogLimits,
    ) -> Self {
        Self {
            slots: groups
                .into_iter()
                .map(|(g, genesis)| {
                    (
                        g,
                        Slot {
                            genesis,
                            log: RwLock::new(None),
                            bytes: AtomicU64::new(0),
                            write: tokio::sync::Mutex::new(()),
                        },
                    )
                })
                .collect(),
            store,
            limits: LogLimits {
                max_entries: limits.max_entries.max(1),
                ..limits
            },
        }
    }

    fn set(slot: &Slot, log: Option<GroupLog>) {
        let bytes = log
            .as_ref()
            .map_or(0, |l| l.entries().iter().map(encoded_len).sum());
        *slot.log.write().expect("log lock") = log;
        slot.bytes.store(bytes, Ordering::SeqCst);
    }

    /// Reads and verifies every held group from the store, refusing a log whose genesis is not
    /// the pinned one. A group with no entry in the store stays empty.
    pub async fn load(&self) -> Result<(), GroupError> {
        for (group, slot) in &self.slots {
            let _w = slot.write.lock().await;
            let log = self.read(group, slot.genesis).await?;
            Self::set(slot, log);
        }
        Ok(())
    }

    async fn read(
        &self,
        group: &GroupId,
        genesis: [u8; 32],
    ) -> Result<Option<GroupLog>, GroupError> {
        let first = RecordName::new(format!("group/{:020}", 0)).expect("a valid name");
        let present = self
            .store
            .get(group, &first)
            .await
            .map_err(|e| GroupError::Backend(e.to_string()))?
            .is_some();
        if !present {
            return Ok(None);
        }
        store::load_expecting(&self.store, group, genesis)
            .await
            .map(Some)
    }

    /// The groups held.
    pub fn groups(&self) -> impl Iterator<Item = &GroupId> {
        self.slots.keys()
    }

    /// Whether `group` is held.
    pub fn holds(&self, group: &GroupId) -> bool {
        self.slots.contains_key(group)
    }

    /// Runs `f` on the current log of `group`; `None` when the group is not held or has no
    /// entry yet. `f` must not block.
    pub fn with<R>(&self, group: &GroupId, f: impl FnOnce(&GroupLog) -> R) -> Option<R> {
        let slot = self.slots.get(group)?;
        let log = slot.log.read().expect("log lock");
        log.as_ref().map(f)
    }

    /// The head of `group`'s log.
    pub fn head(&self, group: &GroupId) -> Option<Head> {
        self.with(group, |l| Head {
            seq: l.head_seq(),
            hash: l.head_hash(),
        })
    }

    /// Whether `node` is a node that counts at `at` (certified, not revoked, member still in the
    /// group, not expired) in `group`.
    pub fn counts(&self, group: &GroupId, node: &PublicKey, at: Timestamp) -> bool {
        self.with(group, |l| l.state().node(node, at).is_some())
            .unwrap_or(false)
    }

    /// Whether `node` counts at `at` in any held group.
    pub fn counts_anywhere(&self, node: &PublicKey, at: Timestamp) -> bool {
        self.slots.keys().any(|g| self.counts(g, node, at))
    }

    /// The encoded entries of `group` after `after`, at most `limit` and about `max_bytes`
    /// (always at least one when there is one).
    pub fn fetch(
        &self,
        group: &GroupId,
        after: Option<u64>,
        limit: usize,
        max_bytes: usize,
    ) -> Option<Vec<Vec<u8>>> {
        let slot = self.slots.get(group)?;
        let log = slot.log.read().expect("log lock");
        let Some(log) = log.as_ref() else {
            return Some(Vec::new());
        };
        let start = match after {
            None => 0,
            Some(a) => match usize::try_from(a).ok().and_then(|a| a.checked_add(1)) {
                Some(s) => s,
                None => return Some(Vec::new()),
            },
        };
        let mut out = Vec::new();
        let mut bytes = 0usize;
        for e in log.entries().iter().skip(start).take(limit) {
            let enc = e.encode();
            bytes += enc.len() + 8;
            if !out.is_empty() && bytes > max_bytes {
                break;
            }
            out.push(enc);
        }
        Some(out)
    }

    /// Adds `entry` to its group's log if `baton-group` accepts it at the head at time `now`
    /// (entry times at most `max_skew_ms` ahead), then stores it. Pushing an entry the log
    /// already holds changes nothing and succeeds with `new: false`. The push runs on its own
    /// task, so dropping the returned future never leaves memory and store apart.
    pub async fn push(
        self: &Arc<Self>,
        entry: Entry,
        now: Timestamp,
        max_skew_ms: i64,
    ) -> Result<Pushed, Refusal> {
        let this = self.clone();
        tokio::spawn(async move { this.push_now(entry, now, max_skew_ms).await })
            .await
            .unwrap_or(Err(Refusal::Backend))
    }

    async fn push_now(
        &self,
        entry: Entry,
        now: Timestamp,
        max_skew_ms: i64,
    ) -> Result<Pushed, Refusal> {
        let group = entry.group().clone();
        let slot = self.slots.get(&group).ok_or(Refusal::Unknown)?;
        let _w = slot.write.lock().await;
        let revokes = takes_trust(entry.op());
        let seq = entry.seq();
        let len = encoded_len(&entry);
        let current = {
            let log = slot.log.read().expect("log lock");
            match log.as_ref() {
                None => None,
                Some(l) => {
                    let head = Head {
                        seq: l.head_seq(),
                        hash: l.head_hash(),
                    };
                    if seq <= head.seq {
                        return if l.entries()[seq as usize] == entry {
                            Ok(Pushed {
                                head,
                                new: false,
                                revokes: false,
                            })
                        } else {
                            Err(Refusal::Fork)
                        };
                    }
                    if seq != head.seq + 1 {
                        return Err(Refusal::Chain(Some(head)));
                    }
                    let over = seq >= self.limits.max_entries
                        || slot.bytes.load(Ordering::SeqCst).saturating_add(len)
                            > self.limits.max_bytes;
                    let beyond = seq >= self.limits.max_entries.saturating_add(self.limits.reserve)
                        || slot.bytes.load(Ordering::SeqCst).saturating_add(len)
                            > self.limits.max_bytes.saturating_add(
                                self.limits.reserve.saturating_mul(RESERVE_ENTRY_BYTES),
                            );
                    if over && (beyond || !reserve_allows(l, &entry)) {
                        return Err(Refusal::Full);
                    }
                    Some(head)
                }
            }
        };
        if current.is_none() {
            if seq != 0 {
                return Err(Refusal::Chain(None));
            }
            if entry.hash() != slot.genesis {
                return Err(Refusal::Fork);
            }
            if entry.at() > now.plus_ms(max_skew_ms) {
                return Err(Refusal::Invalid);
            }
            let log = GroupLog::verify(vec![entry.clone()]).map_err(|_| Refusal::Invalid)?;
            store::append(&self.store, &entry)
                .await
                .map_err(|e| match e {
                    GroupError::Fork => Refusal::Fork,
                    _ => Refusal::Backend,
                })?;
            let head = Head {
                seq: 0,
                hash: log.head_hash(),
            };
            Self::set(slot, Some(log));
            return Ok(Pushed {
                head,
                new: true,
                revokes: false,
            });
        }
        let head = {
            let mut log = slot.log.write().expect("log lock");
            let l = log.as_mut().expect("checked above");
            l.apply_fresh(entry.clone(), now, max_skew_ms)
                .map_err(|_| Refusal::Invalid)?;
            Head {
                seq: l.head_seq(),
                hash: l.head_hash(),
            }
        };
        if let Err(e) = store::append(&self.store, &entry).await {
            let reloaded = self.read(&group, slot.genesis).await.ok().flatten();
            Self::set(slot, reloaded);
            return Err(match e {
                GroupError::Fork => Refusal::Fork,
                _ => Refusal::Backend,
            });
        }
        slot.bytes.fetch_add(len, Ordering::SeqCst);
        Ok(Pushed {
            head,
            new: true,
            revokes,
        })
    }

    /// Every peer key that counts at `at` in some held group, plus nothing else.
    pub fn counting_nodes(&self, at: Timestamp) -> BTreeSet<PublicKey> {
        let mut out = BTreeSet::new();
        for g in self.slots.keys() {
            self.with(g, |l| {
                out.extend(l.state().nodes(at).into_iter().map(|c| c.node));
            });
        }
        out
    }
}
