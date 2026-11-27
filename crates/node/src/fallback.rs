//! When the group's server is silent (GROUP.md, "When the server is silent"; question 70).
//!
//! - [`ServerWatch`] decides, from this device's own contact with the server, when the server is
//!   silent (no successful call for the takeover delay, or a verified leaving notice followed by
//!   a failed probe) and when it is back (it answered without a break for the return delay, which
//!   doubles for a server that keeps coming and going).
//! - While the server is silent the devices pick a fallback arbiter among themselves:
//!   [`candidates`] in a fixed order (desktops before phones, then by key), the first one that
//!   answers, a node taking the role itself only after a delay that grows with its rank.
//! - [`Leaving`] is the server's signed notice on a graceful shutdown.
//! - [`GapWatch`] is the server's memory of how long each device was silent to it, and [`admit`]
//!   the rule by which a node follows a head whose fence a fallback arbiter granted.

use std::collections::HashMap;
use std::time::Duration;

use baton_identity::{Identity, PublicKey, Signature};
use baton_lease::NodeClass;
use rowboat_group::Membership;
use rowboat_sync::GrantKind;
use serde::{Deserialize, Serialize};

/// The link protocol of leaving notices.
pub(crate) const LEAVING_PROTOCOL: &str = "leaving";
/// The signing context of a leaving notice.
pub(crate) const LEAVING_CONTEXT: &str = "rowboat-leaving-v1";
/// The largest leaving notice, in bytes.
pub(crate) const MAX_LEAVING: usize = 512;
/// How far a leaving notice's time may lie from the receiver's clock, in milliseconds.
pub(crate) const LEAVING_SKEW_MS: i64 = 5 * 60_000;
const LEAVING_VERSION: u8 = 1;
const MAX_FLAPS: u32 = 3;

/// The timing of fallback arbitration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FallbackTiming {
    /// How long the server must be silent before devices take over (5 minutes by default).
    pub takeover: Duration,
    /// How long the server must answer without a break before devices go back to it (a quarter
    /// of `takeover` by default), doubled for each time it came back and went silent again
    /// within four takeover delays, up to eight times.
    pub return_after: Duration,
}

impl FallbackTiming {
    /// `takeover`, with the default return delay.
    pub fn after(takeover: Duration) -> Self {
        Self {
            takeover,
            return_after: takeover / 4,
        }
    }

    /// How long another node is kept from leading an account a fallback holder still holds.
    pub(crate) fn yield_for(&self) -> Duration {
        self.takeover * 3
    }

    /// How long a gap in a device's heartbeats must be for the server to count it as silent.
    pub(crate) fn min_gap(&self) -> Duration {
        self.takeover / 2
    }
}

/// Why this device arbitrates without the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reason {
    /// The server did not answer for the takeover delay: it may still be running, cut off.
    Silence,
    /// The server said it was leaving and then stopped answering: it released what it held.
    Leaving,
}

/// What [`ServerWatch::tick`] changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Change {
    Fallback(Reason),
    Back,
}

/// This device's view of the server, on its own monotonic clock in milliseconds.
#[derive(Debug, Clone)]
pub(crate) struct ServerWatch {
    timing: FallbackTiming,
    fallback: Option<(u64, Reason)>,
    last_ok: u64,
    up_since: Option<u64>,
    leaving: bool,
    returned_at: Option<u64>,
    flaps: u32,
}

impl ServerWatch {
    pub(crate) fn new(now: u64, timing: FallbackTiming) -> Self {
        Self {
            timing,
            fallback: None,
            last_ok: now,
            up_since: None,
            leaving: false,
            returned_at: None,
            flaps: 0,
        }
    }

    /// The server answered a call or a probe.
    pub(crate) fn contact(&mut self, now: u64) {
        if self.fallback.is_some() {
            self.up_since.get_or_insert(now);
        } else {
            self.last_ok = self.last_ok.max(now);
            self.leaving = false;
        }
    }

    /// A probe of the server failed (only a break while in fallback matters).
    pub(crate) fn failed(&mut self) {
        self.up_since = None;
    }

    /// The server sent a verified leaving notice and a probe right after it failed.
    pub(crate) fn leaving(&mut self) {
        self.leaving = true;
        self.up_since = None;
    }

    pub(crate) fn in_fallback(&self) -> bool {
        self.fallback.is_some()
    }

    /// Whether the server answers again while this device is still in fallback.
    pub(crate) fn answering(&self) -> bool {
        self.fallback.is_some() && self.up_since.is_some()
    }

    pub(crate) fn reason(&self) -> Option<Reason> {
        self.fallback.map(|(_, r)| r)
    }

    /// How long ago the server came back, while this device is not in fallback.
    pub(crate) fn back_for(&self, now: u64) -> Option<Duration> {
        if self.fallback.is_some() {
            return None;
        }
        self.returned_at
            .map(|r| Duration::from_millis(now.saturating_sub(r)))
    }

    /// Since when this device has been in fallback.
    pub(crate) fn since(&self) -> Option<u64> {
        self.fallback.map(|(t, _)| t)
    }

    /// How long the server must answer without a break now before devices go back to it.
    pub(crate) fn return_after(&self) -> Duration {
        self.timing.return_after * 2u32.pow(self.flaps)
    }

    pub(crate) fn tick(&mut self, now: u64) -> Option<Change> {
        match self.fallback {
            None => {
                let silent =
                    now.saturating_sub(self.last_ok) >= self.timing.takeover.as_millis() as u64;
                if !silent && !self.leaving {
                    return None;
                }
                let reason = if self.leaving {
                    Reason::Leaving
                } else {
                    Reason::Silence
                };
                let recent = self.returned_at.is_some_and(|r| {
                    now.saturating_sub(r) <= 4 * self.timing.takeover.as_millis() as u64
                });
                self.flaps = if recent {
                    (self.flaps + 1).min(MAX_FLAPS)
                } else {
                    0
                };
                self.fallback = Some((now, reason));
                self.up_since = None;
                Some(Change::Fallback(reason))
            }
            Some(_) => {
                let back = self.up_since.is_some_and(|t| {
                    now.saturating_sub(t) >= self.return_after().as_millis() as u64
                });
                if !back {
                    return None;
                }
                self.fallback = None;
                self.leaving = false;
                self.up_since = None;
                self.last_ok = now;
                self.returned_at = Some(now);
                Some(Change::Back)
            }
        }
    }
}

/// The devices that may act as fallback arbiter, in the order they are tried: counting desktops,
/// then counting phones, each by key. Servers, blind nodes and nodes that do not count (revoked,
/// expired) are never candidates.
pub(crate) fn candidates(membership: &Membership) -> Vec<PublicKey> {
    let mut nodes: Vec<(NodeClass, PublicKey)> = membership
        .nodes()
        .into_iter()
        .filter(|n| n.counts && matches!(n.class, NodeClass::Desktop | NodeClass::Phone))
        .map(|n| (n.class, n.node))
        .collect();
    nodes.sort();
    nodes.into_iter().map(|(_, k)| k).collect()
}

#[derive(Serialize)]
struct LeavingSigned<'a> {
    v: u8,
    group: &'a str,
    server: &'a PublicKey,
    at_ms: i64,
}

/// A server's signed notice that it is shutting down gracefully, sent to the devices of its
/// group after it stopped arbitrating, so they take over at once instead of after the delay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Leaving {
    v: u8,
    pub group: String,
    pub server: PublicKey,
    pub at_ms: i64,
    signature: Signature,
}

impl Leaving {
    fn message(&self) -> Vec<u8> {
        rowboat_group::wire::encode(&LeavingSigned {
            v: self.v,
            group: &self.group,
            server: &self.server,
            at_ms: self.at_ms,
        })
    }

    pub(crate) fn sign(server: &Identity, group: &str, at_ms: i64) -> Vec<u8> {
        let mut n = Self {
            v: LEAVING_VERSION,
            group: group.to_owned(),
            server: server.public(),
            at_ms,
            signature: server.sign(LEAVING_CONTEXT, b""),
        };
        n.signature = server.sign(LEAVING_CONTEXT, &n.message());
        rowboat_group::wire::encode(&n)
    }

    /// Decodes and verifies a notice from `sender` (the link-authenticated peer): well formed,
    /// signed by `sender` itself, for `membership`'s group, from a node that counts there as a
    /// server, and dated within [`LEAVING_SKEW_MS`] of `now_ms`. Whether the server really left
    /// is the receiver's own probe; the notice only lets it skip the delay.
    pub(crate) fn verify(
        bytes: &[u8],
        sender: &PublicKey,
        membership: &Membership,
        now_ms: i64,
    ) -> Option<Self> {
        if bytes.len() > MAX_LEAVING {
            return None;
        }
        let n: Self = rowboat_group::wire::decode(bytes).ok()?;
        let fresh = (n.at_ms - now_ms).abs() <= LEAVING_SKEW_MS;
        let ok = n.v == LEAVING_VERSION
            && &n.server == sender
            && n.group == membership.group().as_str()
            && fresh
            && membership.counts(&n.server)
            && membership.class_of(&n.server) == Some(NodeClass::Server)
            && n.server
                .verify(LEAVING_CONTEXT, &n.message(), &n.signature)
                .is_ok();
        ok.then_some(n)
    }
}

/// Runs the leaving notice decoder over `bytes`, for the fuzz target. Never panics.
pub fn fuzz_leaving(bytes: &[u8]) {
    let _ = rowboat_group::wire::decode::<Leaving>(bytes);
}

/// The server's memory of each device's heartbeats, on the server's clock in milliseconds: a
/// device is silent while its last heartbeat is at least the minimum gap old, or when a gap that
/// long ended within the window. A gap that began before the server started serving overlaps
/// the server's own downtime, which every device saw, so it counts only once it is the full
/// takeover delay long (only then did the devices fall back). Bounded by the group's nodes.
#[derive(Debug, Default)]
pub(crate) struct GapWatch {
    seen: HashMap<PublicKey, (Option<i64>, Option<i64>)>,
    graceful_until: Option<i64>,
    serving: Option<(i64, i64)>,
}

impl GapWatch {
    /// The server started serving at `at`; gaps that began before count from `takeover` on.
    pub(crate) fn serving_since(&mut self, at: i64, takeover: i64) {
        self.serving.get_or_insert((at, takeover));
    }

    fn need(&self, from: i64, min_gap: i64) -> i64 {
        match self.serving {
            Some((at, takeover)) if from < at => takeover.max(min_gap),
            _ => min_gap,
        }
    }

    /// The server came back from a graceful leave at `now`: every device counts as silent until
    /// `until`, since devices took over at once on its notice.
    pub(crate) fn left_gracefully(&mut self, until: i64) {
        self.graceful_until = Some(until);
    }

    /// The latest heartbeat the server holds from `node` (`None`: never).
    pub(crate) fn observe(&mut self, node: PublicKey, last: Option<i64>, min_gap: i64) {
        let before = self.seen.get(&node).map_or(last, |e| e.0);
        let need = before.map(|b| self.need(b, min_gap));
        let entry = self.seen.entry(node).or_insert((last, None));
        if let (Some(before), Some(now), Some(need)) = (before, last, need)
            && now - before >= need
        {
            entry.1 = Some(now);
        }
        entry.0 = last;
    }

    /// Keeps only `nodes`.
    pub(crate) fn retain(&mut self, nodes: &[PublicKey]) {
        self.seen.retain(|k, _| nodes.contains(k));
    }

    pub(crate) fn silent(&self, node: &PublicKey, now: i64, min_gap: i64, window: i64) -> bool {
        if self.graceful_until.is_some_and(|t| now < t) {
            return true;
        }
        match self.seen.get(node) {
            None | Some((None, _)) => true,
            Some((Some(last), ended)) => {
                now - last >= self.need(*last, min_gap) || ended.is_some_and(|e| now - e <= window)
            }
        }
    }
}

/// What the server knows when it judges a head granted by a fallback arbiter.
#[derive(Debug, Clone)]
pub(crate) struct ServerView {
    /// This server.
    pub me: PublicKey,
    /// The holder its own lease record names for the account, and whether it is alive to it.
    pub holder: Option<(PublicKey, bool)>,
    /// The fallback arbiter and the holder of the head were both silent to it.
    pub gaps: bool,
    /// Every device of the group was silent to it.
    pub everyone: bool,
    /// The head's fence lies above the token of the lease the server's record names: a grant
    /// from before the server's latest grant is stale.
    pub newer: bool,
}

/// Whether a node follows a verified head whose fence `remote` (the grant's kind, if any)
/// stands behind, signed by `signer`, over its own head granted as `local`:
///
/// - a server's grant always;
/// - a head without a grant only over a head without one (groups without a server, or journals
///   from before grants);
/// - a fallback arbiter's grant by a node that is itself in fallback; on the server, when the
///   arbiter and the holder were silent to the server, the head's fence lies above the lease the
///   server's record names (a grant from before the server's latest one is stale), and that
///   record names no other live holder (and, when it names the server itself, every device was
///   silent: a server cut off from all of them); on a device that sees a live server (`server`
///   without a view), never, whatever its own head (none yet, or one a fallback arbiter
///   granted); and in a group without a server only over a head no server granted. Anything
///   else would let a device that claims the server is silent replace a live server's journal.
pub(crate) fn admit(
    remote: Option<GrantKind>,
    local: Option<GrantKind>,
    signer: &PublicKey,
    in_fallback: bool,
    server: Option<&ServerView>,
    server_live: bool,
) -> bool {
    match remote {
        Some(GrantKind::Server) => true,
        None => local.is_none(),
        Some(GrantKind::Fallback) => {
            if in_fallback {
                return true;
            }
            let Some(v) = server else {
                return !server_live && local != Some(GrantKind::Server);
            };
            if !v.gaps || !v.newer {
                return false;
            }
            match v.holder {
                Some((h, _)) if h == v.me => v.everyone,
                Some((h, alive)) if h != *signer => !alive,
                _ => true,
            }
        }
    }
}

#[cfg(test)]
mod tests;
