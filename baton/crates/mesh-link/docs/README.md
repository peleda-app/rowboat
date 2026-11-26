# baton-mesh-link

`baton-mesh`'s `Transport` over any `baton-link` `Link`, so `signal-mesh`, `lease-quorum` and `liveness-mesh` run over a real link (`baton-link-iroh`) or the in-process one (`baton-link-memory`). Moved from the app's `transport-link`.

## API

- `LinkTransport::start(link, identity, roster, config)`: the link must belong to `identity` (`WrongIdentity` otherwise) and should trust `roster` (build it with the `RosterHandle` as its `Trust`). Listens on the link protocol `mesh`. Needs a Tokio runtime.
- `LinkTransport` implements `Transport`.
- `LinkTransport::dropped()`: incoming frames dropped because they failed a check or were malformed.
- `LinkTransportConfig`: `send_timeout` (5 s), `probe_timeout` (1 s), `retry_after` (2 s).

## Guarantees beyond the contract

- Every message is a frame sealed with `mesh_transport::frame::seal` and checked with `frame::Opener`: addressed to this node, signed by a member of the roster held at that moment, sequence number higher than any accepted before from that sender. The stream's authenticated peer is passed to `Opener::open` as the expected sender, so a member cannot relay another member's frames, and because the opener moves a counter only after every check, one opener serves all streams.
- Frames from one sender to one receiver travel over one stream at a time, in order; after a stream breaks the next send opens a new one, and a late frame from the old stream is dropped by the sequence check rather than delivered out of order.
- `send` returns `Unreachable` if no stream can be opened or written within `send_timeout`; on a write failure it reopens once. Success means the link took the frame, not that it arrived. A stream whose write was cut short (by the timeout or because the `send` future was dropped) is dropped and never written to again, so a half-written frame cannot misalign later ones; the next send opens a new stream.
- `peers` tries to open a stream to every roster member it has none to (for at most `probe_timeout`, skipping members that failed within `retry_after`) and lists those it has a stream to.
- Revocation: the link refuses new streams from and to a revoked member at once (roster trust); frames still arriving on a stream opened before the revocation are dropped by the roster check. `Link::disconnect_untrusted` severs those streams.

## Wire layout

On each `mesh` stream the opener writes frames as a 4-byte big-endian length followed by the sealed frame. A length above `MAX_FRAME` (64 KiB payload plus 4 KiB) drops the stream, and so does a frame that is malformed, has a bad signature or names another sender: on an authenticated, length-prefixed stream these mean framing is broken, and dropping the stream lets the opener see end-of-stream and reopen. Frames failing only the destination, roster or sequence check are dropped one by one and the stream stays. The acceptor never writes; the opener watches its read side to learn when the stream is gone.

## Limits

- Delivery is best effort, as the contract says: nothing is queued or retried beyond one reopen.
- `peers` on a mesh with unreachable members costs up to `probe_timeout` per call, at most once per `retry_after` per member.
- One outgoing stream per peer; a slow receiver slows every channel to it.

## Tests

`cargo test -p baton-mesh-link`: the `baton-mesh` conformance suite over `baton-link-memory` and over `baton-link-iroh` on loopback; wrong identity refused; in-order delivery per channel with a full payload; partitions cut and heal; outsiders refused by the link, a relayed frame dropped together with its stream, an oversized length dropped, a revoked member's frames dropped on an open stream and refused on a new one; the `baton-lease` suite on one node of a 3-node link mesh with `lease-quorum` and `liveness-mesh`; majority decisions across a 3/2 split of 5 nodes; signals published on one node reaching another; leases over iroh on loopback; a `send` cut short mid-frame by its timeout followed by frames that all arrive in order.
