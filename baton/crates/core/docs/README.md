# baton-core

The small value types every Baton crate and every consumer shares. No I/O, no traits.

| Item | Guarantees |
| --- | --- |
| `GroupId`, `NodeId`, `LeaseKey` | 1–64 bytes of `[a-z0-9_-]`, not starting with `-`, never a Windows device name (`reserved_name`: `con`, `nul`, `aux`, `prn`, `com0`–`com9`, `lpt0`–`lpt9`, ...); safe as one path segment in any storage key or file system, so every id forms a valid `RecordName` segment; deserializing checks the same rules, so an id from untrusted bytes is valid or refused |
| `InvalidId` | the only error of id construction |
| `Timestamp` | milliseconds since the Unix epoch, UTC; `plus_ms` saturates |
| `FencingToken` | grows on every change of lease holder; storage written by a leaseholder refuses a lower token than it has seen for the key |

The id rules are the same as Skein's, so Skein's `NodeId` and `FencingToken` can become re-exports of these.

Tests: `cargo test -p baton-core` (path-escape attempts, deserialization of invalid ids, saturation, a property test over arbitrary strings).
