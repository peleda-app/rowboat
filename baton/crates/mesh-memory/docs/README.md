# baton-mesh-memory

`MemoryHub` and `MemoryTransport`: an in-process network implementing `baton-mesh`'s `Transport`, for tests. Frames are sealed and opened for real, so signature, membership, sender and replay checks run as on a network; the sender passed to `Opener::open` is the joined identity that called `send`.

- `MemoryHub::join(identity, roster)` connects a node; joining again replaces the connection.
- `partition(groups)` splits nodes into groups that cannot reach each other (`send` fails with `Unreachable`); `heal()` joins them.
- `inject(to, bytes)` delivers raw bytes with no known sender, for tests of what is dropped.
- `MemoryTransport::dropped()` counts frames that failed a check.

Tests: `cargo test -p baton-mesh-memory` runs the `baton-mesh` conformance suite, order and channel isolation, partitions, and unsigned, outsider and revoked traffic.
