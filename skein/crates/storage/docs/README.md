# skein-storage

The storage contracts. Backends implement one small trait, `Objects` (key–value with compare-and-swap); `Storage::over` builds the four typed stores the engine uses on top of it. Other implementations (replicated, database-backed) can implement the typed traits directly.

## Contracts

| Trait | Guarantees |
| --- | --- |
| `Objects` | read-after-write; `put` with `Expect::Absent`/`Version` is compare-and-swap and of concurrent writes with the same expectation at most one wins; `list` returns keys strictly under a prefix in ascending byte order; case-sensitive keys; values byte for byte. A version changes whenever the value changes |
| `ControlStore` | the same, scoped to `tenants/{t}/control/`; paths checked segment by segment |
| `Log` | per account: consecutive numbers from 1, all-or-nothing appends, fencing (`Fenced` for a lower token, forever), reads of committed events only; snapshots (`put_snapshot`, `latest_snapshot`, the last two kept); `compact(before)` removes events a snapshot covers, after which reads that start earlier fail with `Compacted { first }`; a hash chain: `signed_head` returns the head with its tip (the segment ending at the head) and attestation, and `segment` (from the supertrait `SegmentSource`) returns any segment's stored bytes by reference |
| `HeadAttestor` | `verify(head, attest(head))` succeeds; when `attest` returns bytes, `verify` refuses them for any other head, refuses any other bytes and refuses none, with `Integrity(Attestation)`; `NoAttestor` (the default) attests nothing and accepts everything |
| `SegmentSource` | hands out stored segment bytes by `SegmentRef`, `None` when it does not have one; untrusted, callers verify |
| `ReadTier` | an untrusted, read-only source of segments (by `SegmentRef`) and blobs (by `BlobHash`), each asked for with an expected hash and a `max_len`: the exact bytes it holds under that name or `None`, never more than `max_len` bytes, never a write; callers verify everything it returns |
| `BlobStore` | content by BLAKE3, idempotent put, `get` never returns bytes that do not match the hash, blobs isolated per tenant |
| `CommandQueue` | id is the idempotency key (`Duplicate` for the same command, `Conflict` for another under a used id); pending in id (= time) order |

## Tamper-evident journal

Every segment `ObjectLog` writes starts with a header line, `{"skein_segment":1,"tenant":…,"account":…,"start":…,"end":…,"fence":…,"prev":…}`, where `prev` is a `SegmentRef` (`start`, `end`, `fence`, and `hash`: BLAKE3 of the previous segment's stored bytes, 64 hex digits) or `null` for the first chained segment. The head (`tenants/{t}/heads/{account}`, JSON) holds `seq`, `fence`, `tip` (the `SegmentRef` of the segment ending at `seq`) and `attestation` (base64, when the attestor returned one). A head therefore pins every chained event before it.

| API | Guarantee |
| --- | --- |
| `SegmentHash::of(bytes)`, `SegmentRef::name()` | the hash of stored bytes; the object name `{start}-{end}-{fence}` of a reference |
| `JournalHead` | tenant, account, `seq`, `fence`, `tip`; `digest()` is a domain-separated BLAKE3 digest of every field (what attestors sign); `check()` refuses a tip that does not end at `seq`, carries a higher token than the head, or holds more than `MAX_SEGMENT_EVENTS` events |
| `JournalHead::check_successor(newer)` | same tenant and account (`Scope`), neither `seq` nor `fence` lower (`Rollback`: the source is behind or withholds events), the same tip at the same `seq` and a tip whenever the older head has one (`Fork`); reads nothing |
| `verify_segment(tenant, account, ref, bytes)` | the bytes hash to `ref.hash` (`HashMismatch`), the header names this tenant, account, range and token (`Mismatch`), `prev` ends right before `start` with no higher token (`Link`), the events are this account's and numbered `start..=end`; unchained (pre-chain) segments are refused; reads nothing |
| `Chain::new(source, head)`, `next()` | walks back from the tip, newest first, fetching each segment from any `SegmentSource` and verifying it against the reference the segment after it holds; ends after the first chained segment; a segment the source lacks is `Missing` (withheld or compacted) |
| `locate(source, head, seq)` | the verified segment holding `seq`; `Unchained` when `seq` is beyond the head or before the first chained segment |
| `verify_extends(source, trusted, newer)` | `check_successor`, then a walk from `newer` that must reach exactly `trusted`'s tip (`Fork` otherwise); a trusted head without a tip pins only `seq` and `fence` |
| `verify_head(attestor, signed)` | `check()` and the attestor's `verify` |

`ObjectLog::with_attestor(objects, attestor)` (and `Storage::over_attested`) attests every head it writes, each append and each claim, and verifies every head it reads whose head or attestation differs from the last one it verified. A missing head object reads as an empty journal and is not verified; only a trusted head held elsewhere detects its deletion. It also remembers the newest head it has read or written per account (forgotten on `purge`) and refuses a head read afterwards that is behind it or disagrees with it (`Rollback`, `Fork`), so a rolled-back head never makes it write over committed segments; concurrent reads racing a write are not compared. `read` checks that every two consecutive segments it reads link by hash and that the segment ending at the head matches the tip, so a retouched tip is caught by any read and a retouched middle segment by any read that also reads the segment after it; complete assurance comes from `Chain` from a trusted head. All of these fail with `StorageError::Integrity(IntegrityError)`.

Cost: one BLAKE3 pass over each segment's compressed bytes when it is written and when it is read (BLAKE3 hashes gigabytes per second, a fraction of the zstd work on the same bytes), a header line per segment, about 200 bytes more per head, one `attest` per head write and at most one `verify` per head change seen; no extra storage requests. A chain walk costs one `get` per segment walked.

**Data written before chaining.** Unchained segments (no header) and heads without a tip still read. The chain starts at the first segment written after the upgrade, whose `prev` is `null`; earlier events are not covered (`locate` says `Unchained`) and are not rehashed, so nothing is rewritten. Once a head has a tip, an unchained segment after a chained one, a second chain root, or a head without a tip is refused. Moving a journal to another tenant or account id breaks verification, since headers name both; `skein export`/`import` keep the ids and the bytes.

## Read tiers

`ReadTier` is how segments and blobs reach a node from somewhere other than its own storage: a mirror, a backup bucket, another store that keeps copies. A tier is not trusted. Every request pins what it wants by hash, the `SegmentRef` (from a verified chain or a trusted head) or the `BlobHash` (the content address), and passes `max_len` so an implementation that fetches over a network stops early. `skein-storage-tiered` reads local storage first and then each tier in order, verifies every byte and never writes to a tier; `StorageTier` there serves another `Storage` as a tier.

`testing::read_tier(tier, origin, counts)` checks an implementation: given a tier that serves `origin` (built over the `CountingObjects` `counts`), it must hand out a stored blob exactly, `None` for an unknown hash or another tenant, nothing over `max_len`; segments it hands out must verify along the whole chain from `origin`'s head and match `read`; an unknown range, another account or another tenant gives `None`; and no request writes anything.

## Baton state over control records

`ControlState::new(control)` implements `baton_state::StateStore` (from Baton, the coordination library Skein uses for leases, liveness and signals) over any `ControlStore`, so `baton-lease-cas` can run its leases and heartbeats in the same store as the tenant's other control records: memory for a single process, files for one server, S3 for many.

| Baton | Skein |
| --- | --- |
| group `g` | tenant `g` (every group id is a valid tenant id) |
| record `name` (`RecordName`: lowercase segments) | a control path under `baton/` (`STATE_AREA`), with `-` written `--`, `.` written `-.` and `/` written `-/` (`lease/res-1` is `baton/lease-/res--1`): the byte order of names is kept, so listing and paging follow Baton's contract, and no path is ever a prefix of another (`list` next to `list/a` is `list` next to `list-/a`), which S3 gateways backed by a file system cannot store; state never collides with Skein's own control records, and `purge` removes it with the tenant. A name with a non-final segment of 64 bytes made only of `-` and `.` does not fit a key segment and is refused with `InvalidName` |
| stored value | a format byte (`1`), 16 random bytes, then the value: every write changes the stored bytes, so the backend's version changes too, even where versions are content hashes (S3 ETags), and a version is never reused after an A-B-A sequence or a delete and recreate |
| `Expect`, `Version` | mapped one to one onto the store's `Expect` and `Version` |
| errors | `Conflict` to `Conflict`, a refused key to `InvalidName`, everything else (including `Fenced`, `Corrupt`) to `Backend`; a value over `MAX_VALUE` is `TooLarge` before anything is written |
| `list(prefix, after, limit)` | the store's listing under `baton/{prefix}`, ascending, after `after`; objects whose names are not valid record names (written by something else) are skipped and the listing keeps going so they never end it early |

Durability is the store's: `storage-fs` and `storage-s3` make a write durable before `Ok`, `storage-memory` keeps nothing across a restart. On stores without conditional deletes (S3), a delete with `Expect::Version` checks the version first and then deletes, the short race `Objects::delete` allows; Baton's arbiter never deletes lease records, so leases are unaffected. A stored object that is not a state record (foreign, truncated, unknown format) is never read as a value: `get` fails with `Backend`. Values are not encrypted or authenticated here: whoever can write the control area can change state, exactly as with Skein's own control records.

Keys (`ObjectKey`) refuse empty segments, `.`/`..`, leading dots and separators inside a segment, so no key can leave its prefix on a file system or reach another tenant.

## Object layout

`tenants/{t}/control/...`, `tenants/{t}/heads/{account}` (committed head, highest token, tip and attestation), `tenants/{t}/log/{account}/{start}-{end}-{fence}` (zstd NDJSON segments with a header line, at most `MAX_SEGMENT_EVENTS` events), `tenants/{t}/blobs/{hash}`, `tenants/{t}/commands/{account}/{ulid}`. A segment that decompresses to more than 256 MiB is refused as corrupt. A segment counts only once the head covers it; of segments starting at the same position the higher token wins.

Control records can use `encode_record`/`decode_record`: an envelope with a schema version, upgraded on read through `Migrate`, and newer versions refused.

`CountingObjects` wraps any store and counts requests and bytes, for metrics and the load tests. `testing::SlowObjects` (feature `testing`) wraps any store and sleeps a fixed base plus deterministic pseudo-random jitter before every call, to simulate S3 latency in load tests.

## Conformance

Enable the `testing` feature and call `testing::all_over_objects(store)` for an `Objects` backend, or `testing::{control, control_state, log, blobs, commands}` for a direct implementation of a typed trait. `testing::control_state(control)` runs Baton's `StateStore` suite (`baton_state::testing::state`) over `ControlState` and then the adapter's own checks: state never lands on Skein's control paths and Skein's records are not visible as state, writing the same bytes again yields a new version and a version from before an A-B-A sequence is stale, no stored path is a prefix of another, forged objects (empty, truncated, unknown format byte, plain JSON) are refused by `get`, foreign names are skipped without ending a paged listing, `limit` 0 lists nothing, and purging the tenant removes its state. `all_over_objects` includes it, so every backend (memory, files, S3, and a real S3 endpoint under `SKEIN_IT=1`) runs it. `storage-memory` and `storage-fs` also run Baton's lease and liveness suites with `lease-cas` over `ControlState` (`tests/baton_leases.rs`).

`testing::log` also checks the hash chain of any `Log`: an empty account's signed head is `JournalHead::empty`, a tip after appends, the chain from the head covering exactly what `read` returns (also after a race between two tokens), `locate` across segments, a claim keeping the tip, and `verify_extends` across appends and claims (and refusing the reverse). `testing::head_attestor(attestor)` checks a `HeadAttestor`; `testing::KeyedAttestor` (a BLAKE3 keyed hash, for tests only) is a signing attestor to run it and the attacks with. `all_over_objects` also runs `head_attestor` for `NoAttestor` and `KeyedAttestor` and attacks `ObjectLog` through the raw objects: retouched and bit-flipped segments (middle and tip), swapped, removed and renamed segments, segments and heads copied to another account or tenant, rolled-back, lowered, forked and tip-stripped heads, forged, stripped, borrowed and foreign-key attestations, and journals written before chaining, including a downgrade back to unchained segments.

## Snapshots

`Snapshot` is the state of an account at a log position: mailboxes by id, calendars and address books by id (`collections`, each with its objects, blob and version), each with its messages (item, blob, size, flags, labels, received time). `Snapshot::apply` folds the next event in; events out of order are ignored, so applying a page twice is harmless, and a `resync_required` clears that mailbox until its messages are listed again. `ObjectLog` stores snapshots as zstd JSON at `tenants/{t}/snapshots/{account}/{seq}`.

## Purging a tenant or an account

Every typed store has `purge(tenant)`, and `Storage::purge_tenant` calls all four. Everything of the tenant goes (logs, heads, snapshots, blobs, queued commands, control records) except control records under `keys/`, where the keyring keeps the tombstone of a destroyed key (and, for `keyring-local`, the account keys wrapped under it) so the tenant id cannot get a fresh key.

`purge_account(objects, tenant, account)` removes one account from storage laid out by `Storage::over`: its head, log segments, snapshots and queued commands, and the control records Skein keeps per account (`accounts/`, `status/`, `state/`, `pim-state/`, `push/`, `oauth/` records and the `cursors/`, `started/`, `sending/`, `credentials/`, `pim-cursors/` subtrees). Blobs are shared by content address and stay; `keys/` and other accounts are never touched. It is idempotent and part of `testing::all_over_objects`. A log handle that read the account before keeps its watermark and refuses the purged head as a rollback; read it again through a new handle.
