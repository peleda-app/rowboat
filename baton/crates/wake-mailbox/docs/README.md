# baton-wake-mailbox

`MailboxWake`: `Wake` over any `Arc<dyn Mailbox>`. The plan called it `wake-drop`; it needs nothing from drop, so it is named after its contract.

- Every node has a **wake box**; its `WakeTarget` is the box's 32-byte id (`MailboxWake::target_of`), which is `BoxId::of_reader` of the box's reader key, so nobody else can create the box, also after it went idle for a day.
- `MailboxWake::new(mailbox, seed, slot)` derives the node's reader key from `seed` (32 secret bytes from the node's `SecretStore`) and `slot` (32 bytes the node keeps, not secret), its box id from that key, and its writer keys for other nodes' boxes from `seed` and their box ids, all with `BoxKey::derive`, so the operator cannot link a node's wake keys across targets. A node whose box was lost calls `create_own` again (same slot, same target), or takes a fresh slot for a fresh target.
- `writer_key(target)` is the key this node wakes `target` with; the target lists the keys of the nodes allowed to wake it in `create_own(writers, admission)` and changes them with `set_wakers` (revocation). The group log records which node owns which key.
- `wake` is a `put` of the sealed payload (at most 256 bytes); a target with no box or a sender not among its writers gets `Denied`.
- `listen` long-polls its box (up to the mailbox's `max_wait`), takes up to 16 wakes from the front of the box (no cursor: acknowledged wakes are gone, and a re-created box numbers its messages from 1 again), acknowledges them at once and returns them one by one. A wake lost to a crash between ack and return costs only a later connection, which is acceptable for a hint.
- Wake boxes hold at most 64 wakes (`WAKE_BOX_MESSAGES`, 16 KiB) for one day (`WAKE_TTL_MS`).

Tests: `cargo test -p baton-wake-mailbox` runs the `baton-wake` suite over `baton-mailbox-memory`, plus revocation and unknown targets, wakes still arriving after the wake box was deleted and re-created on the same instance, and a lost wake box that another key cannot create.
