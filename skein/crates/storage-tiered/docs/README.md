# skein-storage-tiered

Storage that reads journal segments and blobs from local storage first, then from untrusted read-only tiers (`skein_storage::ReadTier`) in order, and hands out only bytes that match the hash they were asked for.

```rust
let storage = Tiered::new(local)
    .with_tier(Arc::new(StorageTier::new(mirror)))
    .with_timeout(Duration::from_secs(5))
    .build();
let mut chain = Chain::new(&*storage.log, &trusted_head);
```

| Item | Guarantees |
| --- | --- |
| `Tiered::new(local).build()` | a `Storage`: control records, commands and every write go to `local` only; tiers are never written to |
| `with_tier(tier)` | tiers are asked after local storage, in the order added, and only until one returns bytes that verify |
| `with_timeout(d)` | one tier gets `d` (default 10 s) per request; a slower tier counts as failed and the next one is asked |
| `with_limits(segment, blob)` | the largest segment (default 256 MiB, the journal's own limit) and blob (default 128 MiB) accepted from a tier, also passed to it as `max_len`; larger bytes are refused even when they hash right |
| `without_fill()` | by default a verified blob that local storage lacked is stored locally, so the next read is local; this turns that off |
| `TieredLog::segment` (`SegmentSource`) | the local bytes when they hash to `segment.hash`, else the first tier's bytes that do and fit the limit; when none do: `Integrity(HashMismatch)` if any source returned wrong bytes (local included), the last error if any source failed or timed out, `None` otherwise |
| other `Log` methods | the local log's; `read` does not ask tiers, so verified reads from tiers go through `Chain` and `locate` from a trusted head |
| `TieredBlobs::get` | the local blob when it matches, else the first tier's that matches and fits; damaged local copies (`Corrupt`) fall back too; when none match: `Corrupt` if any source returned wrong bytes, the last error if any failed, `None` otherwise |
| `TieredBlobs::{put, contains, purge}` | the local store's; `contains` does not ask tiers |
| `StorageTier::new(storage)` | a `ReadTier` over another `Storage`: its log's segments and its blobs, read only; bytes over `max_len` are reported missing after being read, so it suits stores whose objects are already bounded |

The hash a segment is checked against is the one its `SegmentRef` carries; that reference must come from a verified source (a trusted head, or the segment after it in a verified chain). `Chain`, `locate` and `verify_extends` from `skein-storage` do this and also verify headers, links and event numbering.

## Tests

`StorageTier` runs `skein_storage::testing::read_tier`. The wrapper runs the `control`, `blobs`, `commands`, `log`, `snapshots` and `purge` suites with no tiers and with an empty tier, and attack tests where a hostile tier returns wrong bytes, truncated, extended, bit-flipped or oversized bytes, another account's valid segment, fails, withholds, or never answers: every attack falls back to the next tier, and alone it is refused with the errors above. Further tests cover damaged local copies, tier order (a later tier is never asked once one answers), filling, limits on bytes that hash right, a slow tier costing at most the timeout, and 512 concurrent reads through a slow tier waiting on the timeout concurrently (all on a paused clock).
