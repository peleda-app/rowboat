# baton-liveness-mesh

`MeshLiveness`: `baton-lease`'s `Liveness` by heartbeat gossip on the mesh channel `baton/liveness/1`, for groups whose nodes talk directly (no shared store). Moved from the app's `ownership-mesh` (`MeshLiveness`) and changed to judge liveness on the observer's clock and to confirm heartbeats with a majority.

## API

`MeshLiveness::start(transport, group, roster, ttl_ms, ack_timeout)` serves one group; `roster` decides what a majority is.

- **A node's own heartbeat succeeds only when a majority of the roster acknowledged it** within `ack_timeout`, otherwise `LeaseError::Unavailable`. A holder whose heartbeat fails must stop acting `ttl` after the start of its last *successful* heartbeat. Because any majority that could grant a takeover in `lease-quorum` shares a member with the majority that acknowledged that heartbeat, and acceptors veto takeovers of holders they still see alive, the rule holds across full and one-sided partitions.
- A heartbeat for another node is recorded locally only.
- Heartbeats carry the group, the profile, a random boot epoch and a counter (starting at the sender's wall clock in microseconds), never a time. A received heartbeat counts only from a member (transport check), only for the sender itself, only for this group, only up to 4 KiB, and only if newer: a higher counter in the same epoch, or a new epoch (a restart, whatever the restarted node's clock says). Replays are impossible anyway: the transport refuses replayed frames.
- A new heartbeat, local or received, is stamped with the `now` of the next `alive` call, so the only clock involved is the observer's own.
- `alive(group, now)`: nodes whose last new heartbeat was stamped within `ttl_ms` of `now`; another group gives nothing; `heartbeat` for another group fails.
- Acknowledgements and fan-out run concurrently with per-send timeouts, so one stuck peer does not delay the rest. Entries not stamped within an hour of the newest are forgotten once more than 4,096 nodes were seen.

## Tests

`cargo test -p baton-liveness-mesh`: the `baton-lease` liveness suite; spreading and expiry over a 3-node in-memory mesh; heartbeats for another node, for another group, oversized, replayed or with an older counter ignored; an isolated node's heartbeat failing while the majority side's succeeds; a restarted node with a new epoch and a lower counter heard again.
