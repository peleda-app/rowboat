# rowboat-keystore-memory

`rowboat-keystore` in memory, for tests and the node's test profile. Clones share their items, so a clone stands in for a second instance over the same backing store (the suite's persistence check).

Faults for tests: `set_locked(true)` makes reads of existing items fail with `Locked` (missing items still read as `None`); `fail_next_put()` makes the next `put` fail with `Backend` and change nothing; `tamper(name, secret)` replaces an item's bytes behind the node's back; `class_of(name)` tells which class an item was stored with. Secrets above `MAX_SECRET` are `Unsupported`.

Runs `rowboat_keystore::testing::keystore` and `failed_put_keeps_the_old_item`.
