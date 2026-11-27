# rowboat-endpoint-iroh

`rowboat-endpoint` over `baton-link-iroh`. Every endpoint is an iroh QUIC endpoint keyed by the identity it was bound for, with Baton's TLS policy (X25519MLKEM768 required by default) and the ALPN prefix `peleda` (`peleda/<protocol>/1`), whatever the configuration's prefix says.

## Configuration

- `IrohEndpoints::new(IrohConfig)`: relays, discovery, bind addresses and timeouts as in `baton-link-iroh` (relays and discovery off by default).
- `IrohEndpoints::loopback()`: `127.0.0.1`, random ports, no relay, no discovery; what tests use.
- `advertise(addrs)`: direct addresses added to every hint (a port of `0` takes the endpoint's own port).

## Hints

The hint holds the bound addresses that name a specific IP (an endpoint bound to `0.0.0.0` contributes only what `advertise` adds) and the first configured relay. Finding the device's own local-network addresses is the composition root's job; see `docs/QUESTIONS.md`.

Runs `rowboat_endpoint::testing::endpoints` on loopback.
