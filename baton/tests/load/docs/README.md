# baton-load

Load scenarios for Baton. `mise run load-baton` runs them full size in release mode and prints operations, time and rate; `mise run load-baton -- <scenario>` runs one. A small version of every scenario runs in `cargo test -p baton-load`.

| Scenario | Full size | Fails when |
| --- | --- | --- |
| `contention` | 32 nodes race for 2,000 keys over `lease-cas` and `state-memory` | two holders for a key, a key without holder, under 2,000 acquires/s |
| `handover` | 2,000 keys held by 8 phones handed over to one server (request, renew, release, acquire) | any takeover not recorded or not seen, a token not above the previous one, over 30 s |
| `fanout` | one publisher, 100 subscribers, 100,000 signals through `signal-local` | a subscriber never sees the last message, under 20,000 publishes/s |
| `churn` | 6 nodes going offline in turns for longer than the time-to-live while 20 keys are acquired, 5,000 rounds | a token held by two nodes, a token going back, a holder replaced before it was silent for the whole time-to-live, no lease ever moving |
| `drop_memory` | 1,000 boxes with their own reader and writer, 100 messages of 64 bytes each put concurrently through `mailbox-memory` (signed requests, replay cache, memory store), then drained with takes and acks | a message lost, repeated or out of order, under 50,000 messages/s (puts plus taken messages) |
| `lease_server` | 32 clients, each with its own link identity, race for 2,000 keys through a `lease-server` over the in-memory link (`state-memory` on the server) | two holders or a repeated token, a key without holder, the server disagreeing on a holder, under 2,000 remote acquires/s |
| `group_server` | one member pushes 2,000 node certifications to a `group-server` over the in-memory link (`state-memory`), then 16 members sync the whole log at once, each verifying every entry from genesis | a member ending at another head, under 5,000 entries verified/s across members |
| `drop_http` | 200 boxes, 100 messages of 64 bytes each, through `mailbox-drop` over HTTP/1.1 to a `drop-http` server on 127.0.0.1 (memory store, no rate limit), 32 boxes at a time, then drained with takes and acks | a message lost, repeated or out of order, under 20,000 messages/s |

The small versions in `cargo test` check invariants only (no rate thresholds, so slow CI does not flake). Full-size numbers on the maintainer's laptop (Apple silicon, release, 2026-11-25): contention 11,500 acquires/s, handover 2,000 keys in 0.26 s, fan-out 143,000 publishes/s with the slowest of 100 subscribers seeing 24% (capacity 16 drops the rest, as allowed), churn 5,547 handovers after silence and no violation; drop_memory 302,000 messages/s (200,000 in 0.66 s); drop_http 119,000 to 148,000 messages/s (40,000 in 0.27 to 0.34 s); lease_server 11,000 remote acquires/s (64,000 in 5.8 s); group_server 30,000 to 37,000 entries verified/s (16 × 2,001 in 0.87 to 1.05 s), pushes about 2,200/s.
