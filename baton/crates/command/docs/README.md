# baton-command

Signed, sealed commands to a resource's leaseholder, and their results.

## API

| Item | Guarantees |
| --- | --- |
| `Command::issue(identity, log, Request { resource, epoch, data_key, class, idempotency_key, payload }, now, ttl_ms)` | a random 16-byte id; the idempotency key and payload sealed together with `baton-seal` under the epoch's data key, **bound to the whole command body** (id, group, resource, epoch, class, issuer, head, times), so carriers never see the key and a payload never opens as another command; the group log head (seq and hash) it was made against; signed by the issuing node (`baton-command-v1`); class 1–32 bytes of `[a-z0-9_-]`, idempotency key 1–128 bytes, valid for 1 ms to one day (`MAX_TTL_MS`), at most 64 KiB encoded |
| `Command::decode` | size-limited (64 KiB), canonical bytes only, known version, valid signature |
| `Command::check(log, resource, data_key, now)` | what the leaseholder of `resource` runs before its worker sees anything: signature; same group and the expected resource; a valid class; a time window of at most a day, not stamped more than 5 minutes ahead (`MAX_SKEW_MS`), not expired; the named head is in `log` (`CatchUp` if `log` is behind, `Fork` if it differs there); an epoch the resource has; the issuer counts and holds `Command(class)` on the resource in `log`'s **current** state (so a revocation the leaseholder knows of applies at once); the payload opens for exactly this body and carries a valid idempotency key; returns `Checked` (id, resource, class, idempotency key, issuer, epoch, payload wiped on drop) |
| `CommandResult::sign(identity, checked, data_key, outcome, at)` | `Outcome` (`Applied`, `Failed { reason }`, `Conflict { state }`, `Uncertain`) sealed under the same key, bound to the whole result body (command id, group, resource, epoch, signer, time), signed (`baton-command-result-v1`) |
| `CommandResult::check(command, log, data_key, now)` | the issuer's check at its own time: the result answers this command (id, resource, epoch), is not stamped in the future, comes from a node holding `Lead` on the resource in `log` with its certificate judged at the latest of `now`, the log and the stamp, opens, and decodes canonically. Any `Lead` holder may sign; which one ran the command is the application's knowledge (the lease fence) |
| `bus::{send_command, send_result, commands, results}` | mesh channels `baton/command/1` and `baton/result/1`; incoming values are decoded and signature-checked, anything else dropped; authorization stays with `check` |

Delivery is at least once. Deduplication by `(issuer, resource, idempotency_key)` (never the key alone, so one member cannot shadow another's command), the claim-before-execute record and the decision what `Uncertain` means belong to the worker's durable queue (Skein's `CommandQueue`). Mailbox delivery for an unreachable leaseholder comes with the drop service (phase 8).

## Tests

`cargo test -p baton-command`: issue, decode, check and result round trips; commands outside the issuer's classes, from outsiders and for other resources refused; expiry, wrong keys, tampered class and swapped issuer refused; a revoked node's command refused once the revocation is in the log; a log behind the command (`CatchUp`), a command against a newer head accepted, a forked head refused; results from a reader (no lead), for another command, or with the wrong key refused; argument bounds and non-canonical bytes; the bus over an in-memory mesh dropping garbage; a property test that arbitrary bytes never decode. Fuzz target `command`.
