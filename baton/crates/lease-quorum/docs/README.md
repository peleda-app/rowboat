# baton-lease-quorum

`QuorumLeases`: `baton-lease`'s `Leases` decided by a majority of a group's roster members, for groups without a shared store (devices only). Moved from the app's `ownership-mesh` and changed to apply `baton_lease::record` (priority, handover, reservations, the shared token rule), to judge liveness and freshness on the observer's own clock, and to keep acceptor state durable.

## API

`QuorumLeases::start(group, transport, roster, liveness, state, clock, config)` on mesh channel `baton/lease/1`. Every member runs one; each is proposer for its own calls and acceptor for everyone's.

- Calls are linearizable per key across the group. Every call is one CASPaxos round (Rystsov 2018): prepare to a majority, take the register accepted under the highest ballot, apply the record step, accept to a majority.
- A node that cannot reach a majority gets `LeaseError::Unavailable` from every call; a minority partition can neither acquire, confirm nor read.
- **Acceptors are durable**: every promise and acceptance is written to the `StateStore` (`quorum/{key}`) and only answered once the store returned; an acceptor whose store fails does not answer. A restarted node keeps its promises, so a token is never reused (the limit of the app's in-memory acceptors).
- **Acceptors veto takeovers they cannot confirm.** An `Accept` carries the register the proposer read (`base`) and the new one; an acceptor refuses (`Veto`, surfaced as `LeaseError::Unavailable`) a change to another holder while its own view still shows the base holder alive or its record changed within the time-to-live, unless the holder itself proposes it. Keeping the holder and releasing always pass, so a decided value still spreads to acceptors that fell behind. With `baton-liveness-mesh` (heartbeats confirmed by a majority) no takeover is granted within the time-to-live of a holder's last successful heartbeat.
- Tokens follow `record::next_token` and are above every token reported in the round's promises; registers whose token runs more than a day ahead of the wall clock are refused.
- A ballot may not jump more than 2^20 rounds above the binding promise; a promise to a proposer that left the roster stops binding; rounds never overflow; each member may send 5,000 prepare and accept messages per 10 s; the acceptor cache drops idle keys beyond 10,000; replies and fan-out are sent concurrently with timeouts.
- Views (alive and able to lead, how long the register stayed unchanged) are built on this node's clock; the register's "version" is the BLAKE3 hash of its content, and every record write raises `seq`, so every write counts as a change.
- `QuorumConfig`: `phase_timeout` (500 ms), `max_attempts` (16). Errors: `Unavailable` (no majority), `Backend(QuorumError::{NotMember, Contention, OtherGroup})`, `Corrupted` (an invalid register).

## Limits

- **Not Byzantine-tolerant.** A compromised member that votes can still forge a register within the bounds above (a holder, a token within a day of the clock) or release a lease whose token it read. Signed lease records (phase 4, with `baton-group`) close this.
- **Roster changes one at a time.** Majorities of two rosters that differ by one member overlap; after each roster change every key needs one round (`holder` is enough) before the next change.
- No leader, no batching: every call costs two round trips to a majority, fine for a handful of nodes and a few lease changes per minute.

## Tests

`cargo test -p baton-lease-quorum`: the `baton-lease` suite on a single node and on one node of a 3-node in-memory mesh; a 5-node split into 3 and 2 (the minority can neither acquire nor read, the majority takes over after the holder is gone, tokens grow, healed nodes see the majority's holder); five concurrent acquirers with exactly one winner; a restarted acceptor with the same store keeping its promise so the next token is higher; a revoked member losing its vote; another group refused; an isolated holder whose heartbeat fails while the majority cannot take the key within the time-to-live of its last successful heartbeat, and can afterwards; a member's maximal ballot and maximal token not poisoning another node's acceptor; acceptor unit tests (promises survive a restart, ballots cannot jump, promises to departed proposers do not bind, vetoes, a store that cannot persist means no answer, corrupted state means no answer).
