# baton-link

The contract of the channel between a person's nodes: the app and its cloud node, or any two members of a mesh. A `Link` opens byte streams to a peer named by its Ed25519 key and accepts streams from peers, one listener per protocol. Who may talk at all is decided by a `Trust`. Contract crate: traits, the types in their signatures and `LinkError`; no I/O.

Implementations: `baton-link-memory` (in-process, for tests), `baton-link-iroh` (QUIC over iroh). `mesh-link` (phase 5) will run the mesh `Transport` on top of any `Link`.

## API

| Item | Guarantees |
| --- | --- |
| `Link::local()` | this node's key (`baton_identity::PublicKey`) |
| `Link::open(peer, protocol)` | `Untrusted` without sending anything if this node does not trust `peer`; `Rejected` if the peer does not trust this node or nothing listens for `protocol` there; `Unreachable` if there is no path. `Ok` only once the peer's listener has the stream |
| `Link::listen(protocol)` | a stream of `Incoming { peer, stream }`, each from a peer trusted when the stream arrived; one listener per protocol (`AlreadyListening`); dropping it stops accepting at once; it ends when the link closes |
| `Link::add_hint(peer, PeerHint)` | records direct socket addresses and a relay; later hints add addresses and replace the relay. Hints never change who the peer is |
| `Link::disconnect_untrusted()` | severs every open stream and connection to peers the trust no longer allows; returns how many peers were cut off |
| `Link::close()` | idempotent; afterwards `open`/`listen` return `Closed`, listeners end, open streams are severed, peers cannot reach this node |
| `Duplex` | `AsyncRead + AsyncWrite + Send + Unpin`; in-order, unchanged, exactly once, or the stream fails; `shutdown` gives the other side end-of-stream; a dead peer ends or fails the stream instead of hanging |
| `Protocol` | 1–32 bytes of `[a-z0-9._-]`, starting with a letter or digit: ASCII, no `/`, fits an ALPN |
| `RelayUrl` | `https://` or `http://`, a host part, at most 2048 printable ASCII bytes |
| `Trust` | `allows(peer)` reflects the trust state at the moment of the call and never blocks on I/O |
| `Trust for RosterHandle` | exactly the members of the roster the handle holds now |
| `PinnedKeys` | a set of pinned keys (the node key pinned in the app at pairing); changes are visible to every holder at once |

### Trust and revocation

- An implementation refuses an untrusted peer in both directions before any application byte is read or written.
- The trust is asked again for every new stream (not only every new connection), so a revocation applies to the next stream immediately, even over a connection that is already up.
- Streams already open when a peer is revoked keep working until either side closes them, the link closes, or `disconnect_untrusted` is called. The composition root calls `disconnect_untrusted` right after moving the roster or unpinning a key.

## Dependencies

The contract depends on Tokio with no features (only the `AsyncRead`/`AsyncWrite` traits in `Duplex`), through the workspace entry `tokio-io`; the `testing` feature turns on `io-util`, `macros`, `rt` and `time` for the suite.

## What an implementation must do

- Authenticate the peer by its key only; Web PKI plays no part.
- Keep every guarantee above, including `open` returning only accepted streams (an in-band accept/refuse step is the usual way).
- Keep no third-party type in the public API or in errors.
- Run the conformance suite.

## Conformance suite

Feature `testing`. Implement `testing::Harness` (`link(identity, trust) -> Arc<dyn Link>`, with links built by one harness able to reach each other) and call `baton_link::testing::link(&harness).await` from a multi-threaded Tokio test. It checks: protocol name rules, data both ways with the acceptor learning the opener's key, untrusted peers refused on open (`Untrusted`) and on accept (`Rejected`, nothing reaches the listener), protocol isolation and `Rejected` without a listener, one listener per protocol, 64 concurrent streams, an 8 MiB transfer echoed back, revocation (new streams refused both ways at once, `disconnect_untrusted` severs the open stream, trust restored works again), and close semantics.
