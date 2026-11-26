# baton-lease-server

The lease arbiter for a group that has a server node but no shared store. The server runs `CasLeases` and `CasLiveness` (from `baton-lease-cas`, so the rules of `baton_lease::record` apply unchanged) over its own `StateStore` and serves them over link protocol `lease`. Clients use `RemoteLeases` (a `baton_lease::Leases`) and `RemoteLiveness` (a `baton_lease::Liveness`). While the server is down, every call fails with `LeaseError::Unavailable`: nothing new starts, and holders stop on their own.

## API

| Item | Guarantees |
| --- | --- |
| `LeaseServer::start(link, state, authorize, clock, config)` | listens on `lease`. Leases live in `lease/{key}`, heartbeats in `nodes/{node}` of `state`. `clock` is the server's own time for liveness and tokens (`baton_lease_cas::monotonic_clock()` in production). Tokens of a key only grow, across restarts over the same store too |
| `LeaseServer::leases()`, `liveness()` | the server's own instances, for work the server process does itself |
| `LeaseServer::stop()` | stops accepting and severs every stream; afterwards a new server can listen on the same link. Dropping the server does the same without waiting |
| `Authorize` (trait) | asked for **every request**: `node(peer)` is the node a link-authenticated peer speaks as (default `PublicKey::node_id`; `None` refuses everything); `member(peer, group)` allows reading liveness and holders; `profile(peer, group, profile)` allows announcing a profile (default `member`; batond caps the class at the certified one); `lease(peer, group, key)` allows acquire and takeover; a release needs only that the lease's node is the peer's, so a holder that lost its right can still give the key up. It must answer from current state and never block |
| `LeaseClient::connect(link, server, config)` | one node's connection (the node of the link's key): reads the server's time-to-live with `Hello`, keeps up to `streams` streams, every call ends within `request_timeout`, a broken reused stream is retried once on a new stream (every request is safe to repeat), replies over `max_reply` are refused before they are read |
| `RemoteLeases::new(client)` | `Leases` through the server. A lease from `acquire` must be for the group, key and node asked, one from `holder` for the group and key asked; anything else is `RemoteError::Protocol` |
| `RemoteLiveness::new(client)` | `Liveness` observed by the server. The `now` arguments are ignored: the server's clock decides. `heartbeat` is `Ok` only once the server recorded it |
| `RemoteLiveness::valid_until(group, margin)`, `holding(group, margin)` | the holder's self-expiry: start of the last confirmed heartbeat in the group plus the time-to-live the server stated in that confirmation (`Beat`) minus `margin`, so a server restarted with a shorter time-to-live shortens it at the next heartbeat; `LeaseClient::ttl_ms` follows the latest stated one. A holder stops acting on that group's leases once it passes; failed heartbeats extend nothing |
| `RemoteError` | inside `LeaseError::Backend`: `Denied` (refused by the server), `Server` (its store failed), `TooLarge`, `Protocol` (a reply that does not fit the request). Unreachable, busy and undecided all map to `LeaseError::Unavailable`, a corrupted record to `LeaseError::Corrupted` |
| `wire` | the frame codec: `encode_request`/`decode_request`, `encode_reply`/`decode_reply`, `frame_len`, `read_frame`/`write_frame` |

## The server is the one observer

`CasLiveness` remembers what it has observed per instance, so one instance belongs to one observing node. Here the server is that node for all its clients: each heartbeat a client sends is written by the server into its own store, and "alive" is decided by the server's instance on the server's clock. No client clock is ever compared with another. A server restart forgets observations, so every heartbeat counts as new to the restarted server, which only delays takeovers by up to one time-to-live (the lease records and their tokens survive in the store).

What a holder relies on: the server first observes a heartbeat no earlier than the client sent it, and treats the node as alive for at least the time-to-live after that on its monotonic clock. A holder that stops `ttl - margin` after the start of its last confirmed heartbeat is therefore never still acting when the server hands the lease to someone else, with `margin` covering clock rate differences.

## Wire

Every frame is `u32` big-endian length ‖ body; every body is `[1] ‖ postcard(value)` with no trailing bytes and every id checked while decoding. Requests: `Hello`, `Acquire`, `Takeover`, `Release`, `Holder`, `Heartbeat`, `Alive`. Replies: `Hello { ttl_ms, max_request, max_reply }`, `Lease`, `Takeover`, `Done` (release), `Alive`, `Refused(Denied | Unavailable | Corrupted | Backend | Busy | TooLarge | Version)`, `Beat { ttl_ms }` (heartbeat, stating the time-to-live the holder must stop by). Refusals carry no backend detail. Frames are not signed: the link authenticates the peer by its key on every stream (QUIC with TLS keyed by node identities in `link-iroh`), and the server checks every request against that peer, as `baton-fetch` does.

A request that names a node (`Acquire`, `Takeover`, `Heartbeat` by the profile, `Release` by the lease) is refused unless that node is `Authorize::node(peer)`.

## Limits

| `ServerConfig` | Default | Meaning |
| --- | --- | --- |
| `ttl_ms` | 15,000 | liveness time-to-live on the server's clock, stated in `Hello` and every `Beat` |
| `previous_ttl_ms` | 0 | the largest time-to-live an earlier run stated that a holder may still believe; holders are judged gone only after `max(ttl_ms, previous_ttl_ms)` (batond keeps it in `lease.ttl`) |
| `idle_timeout` | 60 s | a stream with no request for this long is closed |
| `header_timeout` | 2 s | the rest of a request after its first byte |
| `write_timeout` | 5 s | the peer must read the reply within this |
| `request_timeout` | 10 s | one decision; then `Refused(Unavailable)` |
| `max_streams` | 1,024 | open streams across all peers; more are closed at once |
| `max_per_peer` | 8 | open streams per peer; more are closed at once |
| `max_busy` | 256 | requests decided at once |
| `busy_wait` | 1 s | wait for a slot, then `Refused(Busy)` |
| `max_reply` | 1 MiB | an `Alive` list over this is `Refused(TooLarge)` |

Request bodies are at most 1 KiB (`wire::MAX_REQUEST`; the largest real request is under half of that). A malformed, empty or oversized frame closes its stream without a reply; an unknown version gets `Refused(Version)`, then the stream closes. Lengths are checked before any body byte is read.

| `ClientConfig` | Default |
| --- | --- |
| `request_timeout` | 5 s |
| `streams` | 4 (keep at or below the server's `max_per_peer`) |
| `max_reply` | 1 MiB |

## Limits of the design

- The arbiter decides ordering and is trusted for it: a compromised server can grant one lease to two nodes or withhold leases (SECURITY.md). Lease records are not yet signed by their holders.
- `alive` reads every heartbeat record of the group on each call, and `acquire` calls it; fine for groups of tens to a few hundred nodes.
- There is no per-peer request rate limit beyond the stream caps: a peer has at most `max_per_peer` requests in progress, each a bounded amount of work.

## Tests

`cargo test -p baton-lease-server`:

- both `baton-lease` conformance suites through `RemoteLeases` and `RemoteLiveness` over `baton-link-memory`, every suite node with its own link identity and client (the liveness suite drives the server's clock, since the server is the observer);
- impersonation (acquire, takeover, heartbeat and release as another node, an unknown peer refused at `Hello`);
- unauthorized key, group and inflated class;
- revocation applied to the next request on an already open stream, with the revoked holder lapsing;
- oversized, empty, garbage, trailing-byte and wrong-version frames, plus 200 random frames, after which the server still serves;
- slowloris (a stalled frame and a dripped frame closed after `header_timeout`, an idle stream after `idle_timeout`, the slot freed), on Tokio's paused clock;
- per-peer and total stream caps against one greedy peer and 40 peers, recovering after the idle timeout;
- a restart over the same store with the server's clock an hour back (state kept, tokens higher, the takeover only delayed);
- the server down (every call `Unavailable`, the holder's `valid_until` not extended and passing, resumption after restart);
- a restart with a shorter time-to-live: the arbiter does not hand the key to another node before the old time-to-live of silence, and the holder's next heartbeat learns the shorter one;
- a holder that lost the right to a key still releasing it;
- a reply over the limit; a lying server (wrong key, wrong node, wrong reply kind, oversized and garbage replies);
- wire round trips, bounds, proptests over arbitrary bodies, bit flips and truncations.

Fuzz target `lease_frame`. Load scenario `lease_server` in `tests/load` (32 clients × 2,000 keys over the in-memory link).
