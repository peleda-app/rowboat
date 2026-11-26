# skein-load

Load scenarios through the real engine over fake providers (`FakeMail`), with every storage request counted.

```bash
mise run load-skein -- --accounts 10 --history 2000 --rounds 20         # history (default)
mise run load-skein -- --scenario many --accounts 5000 --history 20
mise run load-skein -- --scenario failover --nodes 3 --crash 1 --zombie 1 --accounts 300
mise run load-skein -- --scenario slow --latency-ms 20 --jitter-ms 10
```

## Scenarios

- **history** (`run`, `Scenario`): accounts with a mail history synced by `Engine::sync_account`, then rounds of new mail and flag changes.
- **many** (`run_fleet`, `Fleet::many`): many accounts with small mailboxes on one node running the real node loop (`skein_engine::run`) with Baton's `CasLeases` and `CasLiveness` over `ControlState` in one object store, as the binary's `storage` mode. Reports PUT and GET per message and the PUT per account beyond one per message (cursors, journal segments and heads, lease records, heartbeats).
- **failover** (`Fleet::fault`): several nodes over one shared store. Once a share of the accounts (`--after`) finished the first sync, `--crash` nodes are aborted and their store calls fail from then on, and `--zombie` nodes stop heartbeating but keep running until their own lease validity (four fifths of the time-to-live after the last successful heartbeat) or fencing stops them. During the liveness window (`--ttl-ms`) every account gets `--extra` new messages one at a time, so failed nodes and survivors write while leases move. Idle accounts are polled every `--interval-secs` (default 3); a command hint that never arrives, or new mail that lands between a sync and the provider watch that follows it, shows up as a recovery time of about one interval rather than a hang.
- **slow**: the many-accounts run over `skein_storage::testing::SlowObjects`, which sleeps `--latency-ms` plus up to `--jitter-ms` before every store call (`--latency-ms` also applies to failover).

After every node-loop run each account's journal is read back and checked: numbers from 1 without gaps, no repeated event keys, every message journaled once, fencing tokens that never go down along the journal, one node per token, recorded appends that cover the journal exactly, and with a fault, every account owned by a survivor whose token is at least the highest written. For every account a failed node wrote to and a survivor took over, a write carrying the failed node's last token is tried and must be refused with `Fenced`. Broken guarantees are listed in `FleetOutcome::violations` and make the CLI exit with status 1.

The failover run once found that a node crashing after journaling `mailbox_upserted`, `mailbox_deleted` or `first_sync_completed` but before saving its account state made the next owner journal that event again; the engine now checks those against the log since its last saved state, and the tests require `repeated_account_events` to be 0. It also found a race in the former `LocalEphemeral::subscribe` that could leave a subscriber on a dropped channel; Baton's `LocalSignal`, used now, joins an existing channel before it prunes any.

## In CI

`tests/budget.rs` keeps the history budget: under 1.1 PUT per message for the first sync and under 3 PUT per new message incrementally. `tests/fleet.rs` runs many (200 accounts × 10 messages, under 12 PUT per account beyond one per message, under 2.4 GET per message: every run renews the account's lease, which reads the lease record and the heartbeats of the live nodes), failover (3 nodes, 60 accounts × 20 messages plus 8 during the outage, one crash and one zombie, 2–6 ms store latency, 3 s polling) and slow (100 accounts, 5–20 ms per call), each in a few seconds in a debug build, plus the `Objects` conformance suite over `SlowObjects`.

## Measured

On a laptop, release build, in memory:

- history: 20,000 messages first sync in about 0.5 s (1.01 PUT per message), about 1,400 messages per second on the file store with fsync, 1.1–1.6 PUT per new message incrementally.
- many: 1,000 accounts × 20 messages in about 0.12 s before the move to Baton's leases; now 1.55 PUT and 1.0 GET per message and 11 PUT per account beyond one per message (each lease renewal also reads the live nodes' heartbeats), about 0.47 s in a debug build.
- slow: the same at 5–20 ms per call in about 0.9 s, at 20–30 ms in about 1.6 s; request counts unchanged.
- failover: 300 accounts on 3 nodes, one crashed and one zombie: about 200 accounts taken over, every one refusing the failed node's token, recovery in 3–5 s (most of it the liveness window and the 2 s pause after a provider push); 6.5 s in a debug build on Baton's leases. With two nodes and a zombie at 10 ms latency the zombie had about 20 appends refused with `Fenced` mid-sync.
