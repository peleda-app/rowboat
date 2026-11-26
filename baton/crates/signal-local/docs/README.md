# baton-signal-local

`LocalSignal`: `baton-signal` within one process. Replaces Skein's `ephemeral-local`.

- Broadcast channel per topic with capacity 16; a subscriber that falls further behind loses the oldest messages (the contract allows it), and publishers never wait for subscribers.
- Bounded by `Limits` (defaults): 1,024 topics with live subscribers, 100,000 values, 64 MiB of value bytes, 100,000 counters. When a bound is reached, expired entries and topics without subscribers are dropped first; then the call fails with `SignalError::Full`. Updating an existing value or counter always works within the byte budget.
- Worst-case payload memory is `max_topics × 16 × 64 KiB + max_value_bytes`, about 1 GiB with the defaults; `with_limits` lowers it.
- A `Duration::MAX` time-to-live is capped at a year instead of overflowing.

Tests: `cargo test -p baton-signal-local` runs the conformance suite, the byte budget (refusal at the limit, accounting through update, delete and expiry), the count bounds for values, counters and topics (a topic without subscribers frees its slot), and huge time-to-live values.
