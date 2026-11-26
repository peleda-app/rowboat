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

`cargo test` runs a small version (300 messages, 60 mark-reads) that checks invariants only: every message listed, every mark-read settled in the database.
