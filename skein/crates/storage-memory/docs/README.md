# skein-storage-memory

`MemoryObjects`: an `Objects` store in memory, for tests, load tests and library mode where the journal feeds a consumer in the same process. Nothing survives the process. Versions are a counter. Passes the full storage conformance suite, including Baton's `StateStore` suite over `ControlState`, and `tests/baton_leases.rs` runs Baton's lease and liveness suites with `lease-cas` over `ControlState` on it: the single-process arbiter for library mode and tests.
