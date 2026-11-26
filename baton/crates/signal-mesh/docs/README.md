# baton-signal-mesh

`MeshSignal`: `baton-signal`'s `Signal` spread over the mesh channel `baton/signal/1`. Moved from the app's `ephemeral-mesh` and changed to wrap a local backend instead of keeping its own maps, so there is one implementation of bounded local signals (`baton-signal-local`) and this crate only adds fan-out.

## API

`MeshSignal::start(transport, group, local)` serves one group: `local` (normally `LocalSignal`) holds values and subscribers.

- Local effects are immediate; publish, put and delete are then sent once, concurrently, to every member reachable now, each send abandoned after `SEND_TIMEOUT` (1 s) so a stuck peer does not delay the others. Nothing is retried or caught up.
- A remote value expires after its time-to-live from arrival, capped at `MAX_REMOTE_TTL` (24 h), so clock differences do not matter.
- Concurrent writes to one key from different nodes have no order.
- Incoming messages count only from members (transport check), only for this group, only within the names and sizes of the contract; they land in the local backend, whose limits (`Limits` of `LocalSignal`) bound what remote members can make this node hold.
- Calls for another group fail; counters are not shared across the mesh (`incr` returns `None`).

## Tests

`cargo test -p baton-signal-mesh`: the `baton-signal` suite on one node and across nodes of in-memory meshes (one per group); values replicating, expiring and deleted across nodes; partitions; another group refused locally and ignored from members; hostile members sending a `u64::MAX` time-to-live (clamped), invalid names, oversized values, a flood of 500 keys against a 50-value limit, and garbage bytes; counters not shared.
