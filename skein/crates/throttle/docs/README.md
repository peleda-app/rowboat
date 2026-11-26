# skein-throttle

An in-process gate for one remote key, such as one mailbox at a provider: at most N requests at a time, and a pause that every holder respects once the server asks to wait. Providers that talk to the same mailbox through separate clients (Graph mail, calendars and contacts, and sending) share one gate, so one of them cannot keep sending while another was told to back off. No I/O besides `tokio` time and sync; the gate only works within one process, which is enough because all of an account's provider work runs on the node that owns the account.

## Public API

| Item | Guarantees |
| --- | --- |
| `Throttle::new(limit)`, `Throttle::default()` | a gate with `limit` slots (at least one; `DEFAULT_LIMIT` = 4, Graph's limit per app and mailbox) and pauses capped at `MAX_PAUSE` (10 minutes); `with_max_pause(limit, cap)` sets another cap. Cloning is cheap and clones share slots and pause |
| `Throttle::acquire().await -> Permit` | waits until no pause is in effect and a slot is free, then holds the slot until the `Permit` drops. A pause recorded while waiting for a slot is respected too. Never fails or times out on its own; waiters are not ordered |
| `Throttle::pause(d)`, `pause_until(instant)` | records a server's `Retry-After` for every holder. Pauses only extend (a shorter one changes nothing), are capped at the maximum pause, and one in the past does nothing. Requests already holding a slot are not interrupted |
| `Throttle::paused_until()` | when the pause in effect ends, `None` when there is none |
| `Throttle::available()`, `same(&other)` | free slots now; whether two values are clones of one gate |
| `Throttles::new(limit)`, `default()`, `with_max_pause` | a registry; clones share it |
| `Throttles::get(key) -> Throttle` | the same key gives clones of the same gate for as long as anyone holds one or its pause is in effect; a gate nobody holds and that is not paused is dropped once the registry grows past twice its live size (at least 64 keys), so memory follows the keys in use |

Times use `tokio::time::Instant`, so tests can run with paused time.

## Use in Skein

The binary keeps one `Throttles` for the process and keys it `{tenant}/{account}`. `skein-mail-graph`, `skein-pim-graph` and `skein-send-graph` take a `Throttle` through `with_throttle`, hold a permit for each request to Graph (until its body is read), and pause the gate on `429`, or `503` with `Retry-After` (`504` too for calendars and contacts). Each crate's own error mapping and retries stay as they were.

## Tests

`src/tests.rs` with paused time: the concurrency cap, the default limit, a pause shared by clones, a pause set while waiting for a slot, pauses that only extend and their cap, registry identity, and dropping idle keys while keeping held and paused ones.
