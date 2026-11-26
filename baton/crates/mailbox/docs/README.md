# baton-mailbox

Store-and-forward boxes for nodes that are offline. Contract crate: the `Mailbox` trait, its types, `MailboxError` and, behind the `testing` feature, the conformance suite. No I/O.

## API

| Item | Guarantees |
| --- | --- |
| `BoxId` | 256 bits bound to the box's reader key: `BoxId::of_reader(reader)` is BLAKE3 `derive_key("baton/drop/box/1", reader)`, so nobody finds a box they were not told about and nobody but the reader can create it, also after it expired; `BoxId::random` only for ids no box has |
| `MessageId` | grows with every `put` in a box and is never reused, also after acknowledgements |
| `BoxKey::derive(seed, box, role)` | the per-box Ed25519 key of a node: BLAKE3 `derive_key` over a 32-byte seed the node keeps in its `SecretStore`, the box id and the role (`Reader`, `Writer`). Same inputs, same key; another box or role gives an unrelated key, so the operator cannot link a node's or a group's boxes by key. `Debug` shows only the public half |
| `BoxPolicy { reader, writers, max_bytes, max_messages, ttl_ms }` | `check()` refuses a time-to-live outside 1 s to 30 days (`MIN_TTL_MS`, `MAX_TTL_MS`; default 14 days), zero quotas, more than 64 writers (`MAX_WRITERS`) or a duplicate writer. A box its reader has not used for its time-to-live is removed |
| `Admission` | `None`, `Token(bytes)` (zeroized, never shown by `Debug`), `Work` (the implementation solves the mailbox's proof-of-work challenge for this box) |
| `Mailbox::create(id, policy, reader, admission)` | refuses an existing id, a policy outside the limits (or the operator's caps), a reader key that is not `policy.reader`, an id that is not `BoxId::of_reader(policy.reader)` (`Denied`), and an admission the mailbox does not accept; a refused creation creates nothing |
| `Mailbox::put(id, writer, sealed)` | stores only for a current writer, at most `limits().max_message` bytes (default 64 KiB), within the quotas; returns a growing id |
| `Mailbox::take(id, reader, after, limit, wait)` | reader only; messages after `after` in id order, at most `limit` (cut to `max_take`); with none, waits up to `wait` (cut to `max_wait`) |
| `Mailbox::ack(id, reader, up_to)` | reader only; removes every message up to `up_to` and frees its quota |
| `Mailbox::set_writers(id, reader, writers)` | reader only; a removed writer's next `put` is refused; stored messages stay |
| `Mailbox::delete_box(id, reader)` | reader only; the box and its messages are gone |
| delivery | at least once: a message is returned by every `take` until acknowledged or expired; bytes are opaque and returned unchanged; expired messages are never returned and do not count against quotas |

`MailboxError`: `UnknownBox`, `Exists`, `Denied`, `Admission`, `TooLarge`, `Quota`, `InvalidPolicy`, `Conflict`, `Rejected(reason)` (malformed, stale, replayed, wrong context), `Busy`, `Unavailable(source)`. None carries bytes or keys.

## What an implementation must do

Enforce every rule above itself (never trust the client), treat message bytes as opaque, judge time-to-lives on its own clock, and run the suite.

## Conformance suite

Feature `testing`: `testing::mailbox(mailbox, harness)`, where the `Harness` gives an admission the mailbox accepts and moves the clock the mailbox (and the client stamping requests) uses. The mailbox under test must refuse `Admission::None` and unknown tokens. It checks: admission refused without or with a wrong token and nothing created, only the policy's reader creates, an id bound to another reader key or not derived from the reader key refused, invalid policies, duplicate ids; round trip, order, `after` and `limit`, at least once without ack, ack removes up to its id, ids never reused; non-writers (including the reader) cannot put, non-readers (including writers) cannot take, ack, change writers or delete, and refused calls change nothing; a removed writer is refused after `set_writers` while stored messages stay; oversized refused and exactly the maximum accepted; message and byte quotas, freed by ack; time-to-live to the millisecond and expired messages freeing quota; unknown and deleted boxes; a waiting take returns when a message arrives and a short wait ends empty; four concurrent writers get distinct ids, taken in order.

Implementations: `baton-mailbox-memory` (in process, over the drop service); `baton-mailbox-drop` (HTTP, planned in this phase).
