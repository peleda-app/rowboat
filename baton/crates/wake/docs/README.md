# baton-wake

Waking a sleeping node. Contract crate: the `Wake` trait, `WakeTarget`, `Woken`, `WakeError` and, behind `testing`, the conformance suite. No I/O.

A wake is a hint ("connect now"), never a fact: at most `MAX_WAKE` (256) bytes the sender already sealed for the target, best effort (may be lost, delayed or repeated). The woken node acts only by connecting and fetching verified data.

## API

| Item | Guarantees |
| --- | --- |
| `WakeTarget::new(bytes)` | opaque, at most 256 bytes (a box id, a push token); `Debug` shows only the length |
| `Wake::target()` | this node's own target, to hand to the nodes that may wake it |
| `Wake::wake(target, sealed)` | refuses a payload over `MAX_WAKE` (`TooLarge`) and a target it cannot address (`InvalidTarget`) before sending; `Denied` when the channel refuses the sender |
| `Wake::listen()` | the next wake for this node, bytes unchanged; a wake from a sender the target does not accept never arrives |

## Conformance suite

Feature `testing`: `testing::wake(sender, receiver, stranger, invalid_target)`. The receiver must accept wakes from `sender` and not from `stranger`. Checks oversized and invalid targets, a full-size wake arriving unchanged, a stranger's wake never arriving, and a listener that is already waiting being woken.

Implementations: `baton-wake-mailbox` (over any `Mailbox`); applications supply platform push (Peleda: `push` in rowboat's node layer); later `wake-nostr`.
