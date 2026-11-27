# rowboat-load

Node load tests over the test profile: Skein's `FakeMail` filled with generated messages, the engine, the follower, `rinse-mail-direct` rendering every message and the `skein-view` database, as the desktop profile runs them (fast engine timing, no network).

`mise run load-node` (release build) runs the default scenario: 100,000 messages in 10 mailboxes, then 40 `list_threads` calls of 50 rows, 40 searches, and 200 mark-reads. Flags: `--messages`, `--mailboxes`, `--marks` (at most one page, 200), `--size`.

Targets on an Apple silicon laptop, to calibrate on the first run and then hold:

| Measure | Target |
| --- | --- |
| first sync | at least 200 messages a second (2 content workers) |
| `list_threads` p95 | under 50 ms over 100,000 messages |
| `search` p95 | under 100 ms over 100,000 messages |
| mark-reads | 1,000 settled within 30 s |

The replication scenario (`--replicate`, 20,000 messages by default, 0 skips it) syncs that many messages on an owner, pairs a second node over in-process links, restarts it into the group and measures until it lists every message (journal and blobs replicated), then sends `--marks` mark-reads from the second node that the owner runs and that come back through the replicated journal. Targets to calibrate: at least 100 messages a second replicated (measured 2026-11-26: 117 a second for 20,000 messages, bound by the second node parsing every message through its content workers and by blob fetches four at a time), 200 mark-reads from the second node settled within 30 s.

The handover scenario (`--handover`, 100 accounts of 20 messages by default, 0 skips it) has a desktop lead that many accounts, adopts a server node into its group and measures from the server's restart until it leads every account (each handed over at a clean point with its state) and lists every message. Target to calibrate: 100 accounts within 60 s.

`cargo test` runs a small version (300 messages, 60 mark-reads) that checks invariants only: every message listed, every mark-read settled in the database; a small replication (200 messages, 40 mark-reads from the second node); and a small handover (6 accounts).
