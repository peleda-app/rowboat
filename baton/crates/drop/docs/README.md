# baton-drop

The drop protocol and the one implementation of its rules, shared by the drop server (`apps/drop`, `drop-http`) and every client (`mailbox-memory`, `mailbox-drop`). A library with no file, database or network I/O: storage is the `DropStore` seam, transport is the `Exchange` seam, time is an injected `Clock`.

## Modules

| Module | What it holds |
| --- | --- |
| `wire` | request and reply encoding: `seal`, `open`, `encode_reply`/`decode_reply`, `ServiceInfo` with `encode_info`/`decode_info`, and `wait_ms` (an unverified peek at a take's wait, so a transport can choose the budget a request runs under) |
| `admission` | `AdmissionConfig` (open, operator tokens, proof of work) and `WorkParams` (argon2id hashcash) |
| `store` | `DropStore` (the service's storage seam), `BoxInfo`, `Admitted` (how a box was admitted: `Token`, `Work`, `Open`), `StoreError`, `MemoryDropStore` |
| `record` | the versioned byte formats persistent stores keep (box records, message keys and values) with strict decoders |
| `service` | `DropService` and `DropConfig` |
| `client` | `DropMailbox` (a `baton_mailbox::Mailbox`) over any `Exchange` |
| `testing` | `testing::store(store)`: the `DropStore` conformance suite (feature `testing`) |

## Requests

`[version = 1] ‖ postcard { head, body, signature }`:

- `head`: operation, box id, timestamp (client clock, ms), 16-byte random nonce, the signing key, BLAKE3 of the body bytes;
- `body`: `Create { policy, admission }`, `Put { bytes }`, `Take { after, limit, wait_ms }`, `Ack { up_to }`, `SetWriters { writers, version }`, `Delete`;
- signature: Ed25519 by the stated key under context `baton/drop/request/1` over `postcard(version, realm, head)`. The realm is the operator's name for the service (normally its host name) and comes from the client's own configuration, never from the service, so a request made for one service never verifies at another.

`wire::open` checks, in order: size (`max_message + 8 KiB`), version, encoding with no trailing bytes, body hash, that the body's operation matches the head's, freshness (timestamp within `freshness_ms` of the service's clock, either way, default 5 minutes, inclusive), and the signature. Replies are `[1] ‖ postcard(Result<Reply, DropError>)`; every decoder refuses oversized input and trailing bytes and never panics (fuzz target `drop_request`).

## Service rules (`DropService::execute`)

1. `wire::open` as above.
2. The box and the key's role: `Put` needs a current writer, every other operation on a box the reader; `Create` needs the signing key to be the policy's reader, the box id to be `BoxId::of_reader` of that key (so nobody else can create a box, also after it went idle; `Denied` otherwise), a policy within the contract's and the operator's caps, and no live box with that id.
3. Admission for `Create`: a configured token (hashes compared in constant time over every token), or an open service, or a valid proof of work. Proof-of-work checks run on blocking threads, at most `max_work_checks` (4) at once; beyond that `Busy`. A box admitted by work or an open service may ask for at most the `untrusted` quotas (default 1 MiB, 1,000 messages, 7 days), and the store keeps how it was admitted (`Admitted`), so a persistent store can cap the share such boxes take.
4. The nonce is recorded (key and nonce hashed) in a bounded replay cache until the request's freshness ends. **Check, then commit**: requests refused by any earlier step never enter it, so strangers cannot fill it. When full of fresh nonces it refuses with `Busy` instead of forgetting one. Each box may hold at most `replay_per_box` nonces, so the requests of one box (or of the few boxes one client can get) make only that box busy, never the service.
5. The store executes atomically (`append` re-checks the writer and the quotas).

Takes return at most `max_take` messages and `max_take_bytes` bytes (always at least one message); an empty take waits for a put to the box (or its deletion) up to `min(wait, max_wait)`, with at most `max_waiters` takes waiting at once and `max_waiters_per_box` on one box (beyond either it returns at once). `handle_with(raw, false)` / `execute_with(raw, false)` make a take return at once whatever it asked, for a transport whose long-poll budget is spent. Writer changes carry a version that must be above the stored one, so a replayed older writer list (for example after a restart emptied the replay cache) never restores a removed writer. `sweep()` removes idle boxes and expired messages. The service logs nothing.

## Proof of work

`argon2id(password = "baton/drop/work/1" ‖ box id ‖ nonce (u64 LE), salt = operator salt)`, 32 bytes, at least `difficulty` leading zero bits. Bound to the box and the operator. Caps both sides enforce: difficulty ≤ 24, memory 8 KiB to 4 MiB, 1 to 3 passes, salt 16 to 64 bytes, so a verification costs one evaluation (about 1–5 ms with 1–4 MiB on current hardware) and a client never accepts a challenge that would cost more than `2^24` evaluations. `WorkParams::generate(difficulty, m_cost_kib, t_cost)` makes a challenge with a fresh salt.

## Limits (`DropConfig::new`)

| Setting | Default |
| --- | --- |
| `freshness_ms` | 300,000 (±5 min) |
| `replay_capacity` | 262,144 nonces (about 20 MiB) |
| `replay_per_box` | 4,096 nonces (about 7 requests/s for ten minutes) |
| `max_message` | 64 KiB (at most 1 MiB) |
| `max_box_bytes`, `max_box_messages` | 64 MiB, 10,000 (token boxes) |
| `max_ttl_ms` | 30 days (token boxes) |
| `untrusted` | 1 MiB, 1,000 messages, 7 days (work or open boxes; cut to the token limits) |
| `max_wait`, `max_waiters`, `max_waiters_per_box` | 30 s, 10,000, 4 |
| `max_take`, `max_take_bytes` | 256, 4 MiB |
| `max_work_checks` | 4 |

## Stores

`DropStore` guarantees (checked by `testing::store`): `create` keeps how the box was admitted; a box idle for its time-to-live (reader not using it) is absent for every method and may be replaced; `append` checks the writer and the quotas (not counting expired messages) and assigns `last_id + 1` atomically; `read` returns unexpired messages after a cursor in order and marks the box used; `ack` removes up to an id; `set_writers` needs a higher version; `delete` removes everything; `sweep` removes idle boxes and expired messages. `MemoryDropStore` keeps everything in a mutex-protected map (not durable); the persistent store lives in `apps/drop` (redb, `RedbDropStore`, which runs `testing::store`), since library crates never open files. Persistent stores keep `record`'s formats: a box record is `[2] ‖ postcard(BoxInfo)` (version 2 added `admitted`; version 1 records are refused), a message key `box id ‖ id (big endian)` so keys sort by box then id, a message value `stored_at ‖ bytes`; the decoders refuse unknown versions, trailing bytes, out-of-range policies, inconsistent counters and oversized messages (fuzz target `drop_record`).

## Client

`DropMailbox::connect(exchange, realm, clock)` fetches and checks `ServiceInfo` (realm equal to the configured one, limits and proof-of-work parameters within the client's caps). Every request gets a fresh nonce and the client's clock; replies are size-checked against the service's limits and validated (kind, order, ids after the cursor, sizes) before they are believed. `Admission::Work` solves the challenge on a blocking thread. Writer versions are the client's clock in microseconds, kept increasing per client.

## Known limits

- The replay cache is in memory: after a service restart a request seen in the last five minutes could be replayed once. A replayed put duplicates a message (allowed by at-least-once), a replayed ack or delete repeats an idempotent effect, a replayed writer change is refused by its version, and a replayed creation needs a deleted box id and recreates an empty box for the same reader (only that reader's key can create that id).
- The operator sees which box receives how many messages of which size and when; boxes are unlinkable by key, not by timing or network address.
- No global cap on the number of boxes in the library: admission is the control; disk quotas belong to `apps/drop`.

Tests: `cargo test -p baton-drop` (store suite on the memory store; forged, unsigned, bit-flipped, truncated, replayed, stale and future, wrong realm and context, mismatched operation and hash; non-writer, non-reader, removed writer also after a restart; quotas, oversized; proof of work with the wrong salt, box or difficulty; token mismatch; replay cache exhaustion, and one box's requests never making other boxes busy; an idle box's id not creatable by another key, nor any id not derived from the reader key; proof of work buying only the untrusted quotas; waiters bound in all and per box, and long polls ended by deletion; `wait_ms` peeking takes only; client against lying services).
