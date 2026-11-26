# baton-mailbox-memory

`MemoryMailbox`: a `Mailbox` in the same process, for tests and single-process setups. It is the drop client (`baton_drop::DropMailbox`) talking to a `DropService` over an in-process exchange, so every rule (signed requests, freshness, replay cache, admission, quotas, time-to-live, long polls) is the drop service's own and there is one implementation of them. Over `MemoryDropStore` it keeps nothing across a restart.

- `MemoryMailbox::new(admission, clock)` makes a service with the default `DropConfig` limits, realm `memory.invalid` and a memory store; `MemoryMailbox::over(service, clock)` uses an existing service (to share one service between several clients, or to sweep it with `service()`).
- `clock` stamps requests and, for `new`, is the service's clock; tests inject a manual clock.
- Limits: those of `DropConfig::new` (64 KiB messages, takes of 256 messages or 4 MiB, waits of 30 s, 5-minute freshness window).

Tests: `cargo test -p baton-mailbox-memory` runs the `baton-mailbox` suite twice, with an operator token and with proof of work.
