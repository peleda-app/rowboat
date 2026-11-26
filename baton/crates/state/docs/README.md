# baton-state

The contract for the durable state Baton hands to the application. Baton has no storage of its own: lease records, heartbeats for nodes that cannot reach each other, and later the group log and key boxes go through a `StateStore` the application implements. Contract crate: the trait, its types and `StateError`; no I/O.

## API

| Item | Guarantees |
| --- | --- |
| `StateStore::get(group, name)` | value and version of the last successful write, or `None` |
| `StateStore::put(group, name, value, expect)` | writes only if `expect` holds (`Any`, `Absent`, `Version(v)`), else `Conflict` and nothing changes; of concurrent writes expecting the same state at most one succeeds; `Ok` means durable (survives a crash and power loss) |
| `StateStore::delete(group, name, expect)` | same expectation rules; deleting a missing record with `Any` is fine |
| `StateStore::list(group, prefix, after, limit)` | names under `prefix` (whole segments: `lease` covers `lease/a`, not `leases/a`) in ascending byte order, after `after` (which need not exist), at most `limit`; a short page is not the end, callers page until an empty one |
| `RecordName` | `/`-joined segments of 1–64 bytes of `[a-z0-9_.-]`, none empty, none starting or ending with `.`, no Windows device names (`con`, `nul`, `com1`, `lpt9.log`, ...), at most 256 bytes: cannot escape its group or alias another name in any key scheme or file system |
| `Version` | opaque; every write yields a version different from every earlier version of that record, also after delete and recreate |
| `MAX_VALUE` | 1 MiB; larger values are `TooLarge` before anything is written (`check_value`) |
| groups | records of different groups never mix |

| `SecretStore::put/get/delete(name)` | named secrets on this device (node keys, opened resource keys), at most 16 KiB each, wiped on drop, never in errors or logs |

## What an implementation must do

Map `(group, name)` to a key without ambiguity, enforce `Expect` atomically, make `Ok` durable (fsync on a local disk; conditional writes on object storage that really honor `If-Match`/`If-None-Match`, which some S3 implementations silently ignore), keep versions unique across delete and recreate, and run the suite.

## Conformance suite

Feature `testing`: `baton_state::testing::state(Arc::new(MyStore::new())).await` from a multi-threaded Tokio test. It checks create-only, version compare-and-swap, stale versions refused, group isolation, the size limit writing nothing, delete expectations, versions never reused after recreate, listing order, prefix boundaries, pagination, paging from a name that does not exist, 32 concurrent creates with exactly one winner, and 32 concurrent compare-and-swap increments with no lost update.

Secrets: `baton_state::testing::secrets(store)` checks put, replace, the size limit storing nothing, delete.

Implementations: `baton-state-memory` (`MemoryState`, `MemorySecrets`; tests). Peleda implements `StateStore` over Skein's `ControlStore` and `SecretStore` over its platform vaults.
