# baton-mesh

Small signed messages between the nodes of one group: the `Transport` contract, the signed wire form (`frame`) every implementation shares, and the conformance suite. Moved from the app's `mesh-transport`, with the sender check fixed and a suite added.

## API

- `Transport` (`Send + Sync`, object safe, `async_trait`): `local()`, `send(to, channel, payload)` (best effort; `Unreachable` when known unreachable), `subscribe(channel)`, `peers()`.
  - Guarantees: messages are never altered, duplicated or delivered on another channel; per sender and receiver they arrive in send order; subscribers see only messages from members of the roster trusted when the message arrives; a node never receives its own messages.
- `Envelope { from, channel, payload }`: a message that passed every check.
- `check_channel`: 1–64 bytes of `[a-z0-9/_.-]`. `MAX_PAYLOAD` is 72 KiB (room for a full 64 KiB signal and its envelope).
- `frame::seal(identity, to, channel, seq, payload)` and `frame::Opener::open(raw, sender)`: a frame carries the sender key, destination, channel, sequence number and payload, signed under the context `baton-frame-v1`. `open` accepts a frame only if it is at most `MAX_FRAME` (`MAX_PAYLOAD` + 4 KiB) bytes, has a valid channel and payload size, is addressed to this node, comes from `sender` when the caller knows who delivered it, is signed by a member of the roster held right now, and has a sequence number above the last accepted from that signer. `reset(sender)` forgets a sender's counter when a new channel authenticated as that sender begins (a new stream on an identity-keyed link): nobody else can write there, and a sender that restarted with its clock behind is heard again at once. **The counter moves only after every other check passed**, so a frame relayed by another member, or failing any check, never burns its signer's counter (the flaw in the app's copy, which recorded the counter before its caller compared senders).

## Limits

- Replay counters live in memory. After a restart a receiver accepts any newer-looking frame again; that is safe on carriers that authenticate the sender per connection (`mesh-link` passes the stream's peer as `sender` and resets on each new stream) and must be revisited before frames travel through store-and-forward carriers (phase 8).
- `SUBSCRIBER_BUFFER` (1,024): a subscriber that stops reading loses newer messages instead of growing memory.
- Payloads are not encrypted by the frame; confidentiality comes from the link (QUIC with TLS keyed by node identities) and, for application data, from resource keys.

## Conformance suite

Feature `testing`: implement `testing::Harness` (`join(identity, roster) -> Arc<dyn Transport>`) and call `baton_mesh::testing::transport(&harness)` from a multi-threaded Tokio test. It needs a lossless environment and checks: peers listed (and never oneself), 20 messages in order on the right channel with the authenticated sender, channel isolation, no echo to oneself, a full-size payload and `TooLarge` above it, invalid channels on `send` and `subscribe`, sending to oneself fails, an outsider (with its own view of the roster) never delivers and is never a peer, 3 concurrent senders × 50 messages all arriving in per-sender order, and revocation (the revoked member keeps its old roster and still tries to send; its messages are dropped by the receiver's own check, members are still delivered, the revoked member is not a peer). It drives transports only through the trait, so replays, frames for another node and relayed frames are each implementation's own tests (both here have them).

Implementations: `baton-mesh-memory` (tests), `baton-mesh-link` (over any `baton-link`).

## Tests

`cargo test -p baton-mesh`: valid and invalid frames, a relayed frame refused as `WrongSender` without moving the signer's counter, failed signature checks not moving the counter, oversized frames, oversized payloads and bad channels as malformed, property tests (arbitrary bytes never open, any flipped bit is refused). Fuzz target `frame`.
