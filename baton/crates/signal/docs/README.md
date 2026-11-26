# baton-signal

Signals between nodes: hints, previews, presence, soft locks, short-lived values, counters. Everything here is cheap to lose and is a hint, never a fact. Contract crate; replaces Skein's `Ephemeral`.

## API

| Item | Guarantees |
| --- | --- |
| `Signal::publish(group, topic, payload)` / `subscribe(group, topic)` | groups isolated; at most once, publish order per publisher, no delivery guarantee; a slow subscriber never blocks publishers |
| `Signal::put/get/delete(group, key, ...)` | values expire after their time-to-live; `get` never returns an expired value |
| `Signal::incr(group, key, by, ttl)` | atomic across processes sharing the backend, saturating, separate from values, lives for `ttl` from its first add (later adds do not extend it); `Ok(None)` when the backend has no shared counters |
| `check_name` | topics and keys are 1–200 bytes of `[a-zA-Z0-9_.:/-]` |
| `check_payload`, `MAX_PAYLOAD` | 64 KiB; larger payloads and values are `TooLarge` before anything is sent or stored |
| `SignalError::Full` | a backend at its value limit refuses instead of growing without bound |

## Conformance suite

Feature `testing`: `baton_signal::testing::signal(Arc::new(MySignal::new()), Duration::from_millis(100)).await`. It checks order and group isolation, 2,000 publishes (more than any backend buffers) with a subscriber that never reads finishing within 20 s, generous enough for signing backends in debug builds, values and expiry, delete, 20 concurrent counter adds, saturation and expiry of counters, later adds not extending a counter's time-to-live, invalid names refused on every method (empty, spaces, newline, NUL, non-ASCII, too long), oversized payloads refused and neither stored nor delivered.

Implementations: `baton-signal-local` (one process); later `signal-mesh` (between nodes, moved from the app's `ephemeral-mesh`), `signal-nats`, `signal-redis`.
