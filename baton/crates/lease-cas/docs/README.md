# baton-lease-cas

`CasLeases` and `CasLiveness`: `baton-lease`'s contracts over any `baton-state` `StateStore`. They replace Skein's `ownership-control` and `ownership-single`.

## How it decides

- **Leases** live in `lease/{key}`. Every call reads the record, applies the pure rules of `baton_lease::record`, and writes with compare-and-swap (`Absent` for a new record, the read version otherwise), retrying from the read on a conflict (up to 64 times with a short backoff, then `Unavailable`). Records are never deleted.
- **Liveness** lives in `nodes/{node}`, one record per node, so heartbeats cost the same whatever the number of leases. Every heartbeat is a new write and so a new version. An observer counts a node alive while the version it sees has changed within the time-to-live **of its own clock**; the timestamp inside a heartbeat is for display only. A heartbeat counts only in the record named after its own node, only up to 4 KiB, only in format version 1 with no unknown fields. Paging continues until an empty page, so a store that returns short pages hides nobody.
- **Who counts as alive for leases**: alive and able to lead (`may_lead`), so a holder that announces it cannot run (a phone going to the background) is replaced, and a reservation for a drained node does not block.
- **Freshness**: `CasLeases` remembers, on its own clock, when it first saw each version of each lease record (including the ones it wrote). A holder whose record changed within the time-to-live counts as alive even if the liveness view does not list it yet; a pending takeover or reservation blocks others for at most two time-to-lives after the last change, so a requester that never comes cannot block a key. Asking again refreshes a request.
- **Tokens** follow `baton_lease::record::next_token`: `max(stored + 1, last granted here + 1, wall clock in microseconds)`. A store that loses or rolls back a record, or a restarted process over a store that forgets, still produces higher tokens than before, unless the wall clock went back by more than the time in between. At `u64::MAX` grants stop instead of wrapping.

Nothing compares one node's clock with another's. A fresh observer counts every heartbeat it sees for the first time as new, so a restart only delays takeovers by up to one time-to-live.

## Configuration

| Item | Default | Meaning |
| --- | --- | --- |
| `CasLiveness::new(state, ttl_ms)` | | heartbeats in `state`; `ttl_ms` at least 1 |
| `CasLeases::new(state, liveness)` | | leases in `state`; the observer's clock is `monotonic_clock()` (wall clock at start plus a monotonic timer) |
| `with_clock(clock)` | | a manual clock, used as both the observer clock and the wall clock for tokens (tests) |
| `reuse_alive_for(ms)` | 0 | reuse one liveness answer per group for up to `ms` (at most a quarter of the time-to-live), but only while it lists the caller and every node the record names; a node that would count as gone is always asked about again, so reuse only delays takeovers. With `CasLiveness` over object storage this turns one listing and one read per node for every lease into one per interval |

Every node runs its own `CasLiveness` and `CasLeases`: what an instance has observed is its own, and sharing one between nodes with different clocks would mix observations.

## Topologies

- **Leases in a shared store, heartbeats between nodes** (Peleda): one `CasLeases` per node over the store, with `baton-liveness-mesh` as its liveness. No heartbeat ever reaches the store; a holder renewing its lease reads the lease record once per call and writes nothing; the store is written only when a lease changes hands. `crates/liveness-mesh/tests/with_lease_cas.rs` runs the lease suite on this combination and counts store calls.
- **Heartbeats in the store** (plain Skein servers that share only a bucket): one `CasLeases` and `CasLiveness` per node over that store, preferably with `reuse_alive_for` set to the heartbeat interval. Each heartbeat is a write and each liveness answer a listing plus one read per node, which object storage bills per request. The store must really honor conditional writes; see TRANSPORTS.md.
- One process: `CasLeases::new(Arc::new(MemoryState::new()), Arc::new(CasLiveness::new(state, ttl)))`; the wall-clock floor keeps tokens above earlier runs.

## Limits

- Lease and heartbeat records are not signed yet: anyone who can write the store can write them. Signed records and the check that a holder has `lead` on the resource come with `baton-group` (phase 4).
- `alive` reads every heartbeat record of the group on each call; fine for groups of tens of nodes (about 11,000 contended acquires per second over `state-memory` with 32 nodes, see `tests/load`).

## Tests

`cargo test -p baton-lease-cas`: both conformance suites over `MemoryState` with a manual clock, and regression tests for every finding of the first review: an observer with a clock far ahead cannot steal a live lease and a holder with a clock far behind stays alive while it heartbeats; hostile heartbeat timestamps (`i64::MIN`, `i64::MAX`) and observer time going back never panic; a reservation for a drained node, or one nobody takes within the time-to-live, does not block; a dead holder goes to the waiting stronger node; tokens stay higher after a restart 500 ms later with 1,000 grants in between and after a lost record; short pages hide no node (also running the state suite on such a store); liveness of one group never counts for another; corrupted, unknown-version and invariant-breaking records refused without writing; a token at `u64::MAX` refused; heartbeats in another node's record, oversized, malformed, with unknown fields or another version ignored; a failing store grants nothing.
