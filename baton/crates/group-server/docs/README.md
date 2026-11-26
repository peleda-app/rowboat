# baton-group-server

Group logs held by a server node and served over link protocol `group`. Members fetch entries after a position and push new signed entries; `baton-group` checks each entry at the head before it is stored. The member side (`GroupClient`) trusts nothing the server says and verifies every entry against its own log, so a server (such as the blind `batond`) can withhold entries or hand out a stale head, which `sync` detects, but cannot forge, reorder or fork a log.

It has no storage of its own: logs are kept through `baton_group::store` in a `StateStore` the caller passes (batond's redb store, `state-memory` in tests).

## API

| Item | Guarantees |
| --- | --- |
| `GroupLogs::new(groups, store, max_entries)` | holds exactly the listed groups, each pinned to its genesis hash; the limits of `LogLimits::entries(max_entries)` (no byte limit, a reserve of a sixteenth, at least 16) |
| `GroupLogs::with_limits(groups, store, LogLimits { max_entries, max_bytes, reserve })` | at most `max_entries` entries and `max_bytes` encoded bytes per log from anyone; beyond either, only entries that take trust away (`RevokeNode`, `RemoveMember`, `RekeyMember`) signed by an admin's or owner's node or a recovery key are stored, up to `reserve` more entries and `reserve × 4 KiB` more bytes; everything else is `Full`. A member that fills the log therefore cannot block its own revocation |
| `GroupLogs::load()` | reads and verifies each held group from genesis (`load_expecting`); a store holding another genesis fails; a group with no entry stays empty |
| `GroupLogs::push(entry, now, max_skew_ms)` | serialized per group. Before genesis only an entry at position 0 whose hash is the pinned one (and not from the future); after it, an exact repeat of a held entry is `new: false` and changes nothing, another entry at a held position is `Fork`, a position past the head is `Chain(head)`, the next position goes through `GroupLog::apply_fresh` (signature, signer's rights, entry times never going back, not from the future) and only then `store::append` (`put_if_absent`). If the write fails, the group is reloaded from the store (held empty if that fails too, so nobody counts) and the push fails. The push runs on its own task (`push` takes `self: &Arc<Self>`), so a caller that stops waiting (the server's request timeout, `stop`) never leaves memory ahead of the store |
| `GroupLogs::with`, `head`, `counts`, `counts_anywhere`, `counting_nodes`, `fetch` | answers from memory, never waiting for the store: `counts` is "a node that counts at that time" (certified, not revoked, member in the group, not expired) |
| `GroupServer::start(link, logs, bootstrap, clock, config)` | serves `logs` on `group`. A peer reads or pushes a group only while it counts in it on the server's clock or `bootstrap` (`Admit`) admits it to that group; decided for every request, so a revocation applies to the next request on an open stream. After an accepted entry that can take trust away (`RevokeNode`, `RemoveMember`, `RekeyMember`) it calls `Link::disconnect_untrusted` |
| `Admit` (trait) | admits a peer to a group's log before it counts there (the founding node before genesis, a recovering device); `PinnedKeys` admits its keys to every group |
| `GroupClient::connect(link, server, config)` | one stream, calls one at a time, each within `request_timeout`; a broken reused stream is retried once (every request is safe to repeat); replies over `max_reply` are refused before they are read |
| `GroupClient::head`, `fetch`, `push` | `fetch` returns only entries whose signature checks, of the group asked, numbered from `after + 1` without a gap, at most `limit`; `push` returns the server's head (never below the entry) and whether the push added it |
| `GroupClient::sync(group, genesis, log, now)` | brings a copy up to the server's head, verifying each entry with `apply_fresh` (a new copy must start from the pinned genesis), then compares heads: `Rollback` when the server is behind the caller's log, `Fork` when they disagree at a shared position. The caller's log is never changed |
| `RemoteError` | `Unavailable` (unreachable, busy, timed out), `Refused(Refusal)`, `Protocol`, `Invalid(GroupError)`, `Rollback`, `Fork`; no entry content |
| `wire` | the frame codec |

## Wire

Every frame is `u32` big-endian length ‖ body; every body is `[1] ‖ postcard(value)` with no trailing bytes and every id checked while decoding. Requests: `Hello`, `Head { group }`, `Fetch { group, after, limit }`, `Push { entry }`. Replies: `Hello { max_request, max_reply, max_fetch }`, `Head(Option<Head>)`, `Entries(Vec<bytes>)`, `Accepted { head, new }`, `Refused(Denied | Unknown | Malformed | Invalid | Chain(head) | Fork | Full | Busy | Backend | TooLarge | Version)`. Frames are not signed: the link authenticates the peer, and every entry carries its own context-bound signature (`baton-group-entry-v1`).

## Limits

| `ServerConfig` | Default | Meaning |
| --- | --- | --- |
| `idle_timeout` | 60 s | a stream with no request for this long is closed |
| `header_timeout` | 10 s | the rest of a request after its first byte (a push can be 1 MiB) |
| `write_timeout` | 10 s | the peer must read the reply within this |
| `request_timeout` | 10 s | one decision |
| `max_streams` | 256 | open streams across all peers; more are closed at once |
| `max_per_peer` | 4 | open streams per peer; more are closed at once |
| `max_busy` | 64 | requests decided at once, then `Refused(Busy)` after `busy_wait` (1 s) |
| `max_fetch` | 256 | entries per fetch (`wire::MAX_FETCH`) |
| `max_reply` | 4 MiB | a fetch stops before it (always one entry, which is at most 1 MiB) |
| `max_skew_ms` | 5 min | how far ahead of the server's clock an entry's time may be |
| `push_per_second`, `push_burst` | 20, 100 | pushes per peer, a token bucket on the server's clock (never refilled by a clock going back); beyond it `Refused(Busy)`, which the client reports as `Unavailable` |

Request bodies are at most `baton_group::MAX_ENTRY` (1 MiB) plus 256 bytes; the announced length is checked before any body byte is read, and the body is read as it arrives (never allocated up front). A malformed, empty or oversized frame closes its stream; an unknown version gets `Refused(Version)`, then the stream closes.

## Tests

`cargo test -p baton-group-server`: push, fetch (paged by count and bytes) and sync; the genesis pinned (another genesis of the same id, an entry before genesis, strangers, unknown groups); forged signatures, non-canonical bytes, replays (no change), entries on a stale head (fork), gaps, future entries and the edge of the skew, a signer that is no node, backdated entries, another log of the same id, another group; a revoked node refused on its open stream and an expired certificate; oversized, empty, garbage, trailing-byte and wrong-version frames and 200 junk streams; slow, dripped and idle streams (paused clock); per-peer and total stream caps; restart from the store and a store holding another genesis; the entry cap; a member filling the log while the owner's revocation is still stored and the member cannot spend the reserve; byte and entry budgets with a bounded reserve; the per-peer push rate; a revoked node's entry built on the current head refused as `Invalid` (not by position); a push cancelled while its write is pending still reloading the log when the write fails; a failing store leaving the log as stored; a server behind or forked detected by `sync`; a lying server (gaps, wrong positions, too many entries, garbage, wrong push head, an oversized reply). Wire unit and property tests. Fuzz target `group_frame`; load scenario `group_server`.
