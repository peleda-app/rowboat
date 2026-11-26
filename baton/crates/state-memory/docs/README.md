# baton-state-memory

`MemoryState`: a `StateStore` in a map behind a mutex, for tests and examples. **Not durable**: it keeps nothing across a restart and must never back a real node.

- Versions come from one counter, so they are never reused, also after delete and recreate.
- `tamper(group, name, value)` overwrites a record with no check, as a hostile or broken backend would, so tests can check what readers do with corrupted state.
- Listing walks the map in key order, so it costs O(records); fine for tests.

Tests: `cargo test -p baton-state-memory` runs the `baton-state` conformance suite.
