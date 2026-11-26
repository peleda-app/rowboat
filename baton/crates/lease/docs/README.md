# baton-lease

Who does the work of a resource or a job now. Contract crate: the `Leases` and `Liveness` traits, their types, `LeaseError`, the `preferred` placement function and, in `record`, the one implementation of the lease rules as a pure state machine. No I/O.

This replaces Skein's `skein-ownership` (`Ownership`, `Liveness`, `NodeProfile`, `preferred_owner`); Skein's guarantees are kept and extended with node classes and handover.

## API

| Item | Guarantees |
| --- | --- |
| `NodeClass` | `Server` outranks `Desktop` outranks `Phone`; `Blind` never leads |
| `NodeProfile { node, class, weight, can_run }` | `may_lead()` is false for blind nodes, nodes that cannot run now, and weight zero |
| `Leases::acquire(group, key, profile)` | grants a free key, renews for the holder (same token, reports a pending takeover), takes over from a dead holder (higher token); a dead holder's key with a pending takeover, or a released key reserved for one, goes only to the requester unless it is gone, may not lead, or has not renewed its request within the time-to-live; a live holder is never replaced; nodes that may not lead get nothing, and a holder that announces it may not lead counts as gone |
| `Leases::request_takeover(group, key, profile)` | `Recorded` only when the caller strictly outranks a live holder and no equally strong or stronger live node is already waiting; `AlreadyHolder`, `NotNeeded` (no live holder), `Refused` otherwise |
| `Leases::release(lease)` | only the holder with the matching token releases; the token is kept; a pending takeover becomes a reservation |
| `Leases::holder(group, key)` | the current holder, alive or not |
| tokens | per key only grow, never shared by two grants, the recorded holder has the highest; at `u64::MAX` the key refuses new grants instead of wrapping |
| `LeaseError::Corrupted` | a stored record that fails to parse or breaks an invariant grants nothing |
| `Liveness::heartbeat(group, profile, now)`, `alive(group, now)`, `ttl_ms()` | judged on the observer's own clock: a node is alive while the observer has seen a new heartbeat from it within `ttl_ms`; a heartbeat's own timestamp never decides; groups never mix; the latest profile is reported. A holder stops acting `ttl_ms` minus a safety margin after the start of its last successful heartbeat, which is what keeps unfenceable side effects single |
| `preferred(group, key, nodes)` | strongest class that may lead, then weighted rendezvous hashing within it; deterministic; only the keys of a node that leaves move |
| `record::{acquire, request_takeover, release}`, `record::next_token` | the rules as pure steps over a `LeaseRecord` and a `View` (who is alive and may lead, how long the record stayed unchanged on the caller's clock, the time-to-live); a holder is gone only when the view says so *and* its record has not changed for a whole time-to-live; a waiting requester blocks others while alive and within two time-to-lives of the last change; every write raises the record's `seq`; `next_token` is the one token rule; `LeaseRecord::decode` caps size (4 KiB), rejects unknown fields and versions and every invariant violation |

## Handover

1. A stronger node that has been alive for its stabilization period calls `request_takeover`.
2. The holder sees `takeover` on its next `acquire` (renewal), reaches a safe point, releases.
3. The lease is reserved for the requester, which acquires it with a higher token.
4. If the holder never releases, the requester waits until the holder is no longer alive; nothing is ever stolen. If the holder dies first, the key still goes to the requester.
5. A request or reservation that nobody completes within two time-to-lives of the last change stops blocking; the requester asks again to refresh it.

## What an implementation must do

Read the record, apply the `record` step, write the result with compare-and-swap, retry from the read on conflict; build the `View` from a `Liveness` (alive and `may_lead`) and from how long the record has stayed unchanged on the implementation's own clock; produce tokens that only grow, also across a lost record and a restart. Run both suites.

## Conformance suites

Feature `testing`:

- `testing::leases(leases, harness)` (a `Harness` that makes nodes alive and kills them): basics (grant, renew, live holder kept, dead holder replaced with a higher token, the replaced holder cannot renew, stale release ignored, release keeps the token); priorities (no stealing, takeover recorded and displaced only by a stronger requester, the holder sees it, the reservation, a weaker node cannot ask a server, a dead reservation does not block); forged releases (wrong token either way, wrong node, wrong key, wrong group); nodes that may never lead; 64 concurrent live acquirers on one key (exactly one wins); 4 nodes racing over 100 keys (one holder each).
- `testing::liveness(live)`: groups isolated, alive up to the time-to-live inclusive and gone right after, latest profile reported, a heartbeat stamped far in the future does not keep a node alive, one stamped in the distant past still counts when new to the observer.

The pure rules also have a property test (2,048 cases of up to 120 operations: kill, revive, change of class, staleness on and off, acquire, takeover, release, releases forged by token and by node) checking that written records stay valid, tokens never go back, a token is granted once, only nodes that may lead get leases, a live holder is never replaced, a live and fresh waiter is never skipped, forged releases never write, and a lease returned without a write is only the holder's renewal.

Implementations: `baton-lease-cas` (any `StateStore`; over `baton-state-memory` it serves one process), `baton-lease-quorum` (a majority of members, no shared store). Liveness: `CasLiveness` in `baton-lease-cas`, `baton-liveness-mesh`.
