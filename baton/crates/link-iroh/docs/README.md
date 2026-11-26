# baton-link-iroh

`baton-link` over [iroh](https://github.com/n0-computer/iroh) 1.5 (MIT OR Apache-2.0): QUIC (iroh's `noq` fork of quinn) with TLS 1.3 using raw public keys, so each side is authenticated by its pinned Ed25519 node key; direct paths with hole punching, relays as fallback. No iroh type crosses the public API.

## API

- `IrohLink::bind(identity, trust, config)`: binds an endpoint whose secret key is the node's identity. The 32 secret bytes go from `Identity::secret_bytes()` (zeroized on drop) straight into iroh's `SecretKey` (an `ed25519_dalek::SigningKey`, built with the `zeroize` feature in this workspace); the endpoint id equals the node's public key.
- `IrohLink::bound_addrs()`: local socket addresses, to hand to peers as hints (an unspecified IP means every interface).
- `IrohLink` implements `Link`.
- `alpn(prefix, protocol)` = `<prefix>/<protocol>/1`; `generic_alpn(prefix)` = `<prefix>/link/1`; the prefix comes from `IrohConfig::alpn_prefix` (`AlpnPrefix`, 1–16 bytes of `[a-z0-9-]`, `baton` by default), so different applications on Baton never land on each other's protocols.

## Configuration (`IrohConfig`)

| Field | Default | Meaning |
| --- | --- | --- |
| `relays` | empty: relays disabled | relay URLs (the application's, the person's own, or the node itself). No public relay is used unless listed. Plain `http` relays (here and in hints) are refused unless the host is loopback (`127.0.0.0/8`, `::1`, `localhost`): over plain HTTP the relay protocol shows on-path observers the endpoint id and each packet's destination id |
| `discovery` | `Discovery::Disabled` | `Disabled` uses only `add_hint`; `Pkarr { relay, dns_origin }` publishes signed address records to that pkarr relay and resolves through it (and DNS under `dns_origin`). The relay operator learns which keys exist and their addresses. Plain `http` is refused unless the host is loopback |
| `bind` | empty: all interfaces, IPv4 and IPv6, random ports | explicit socket addresses, for example `127.0.0.1:0` in tests |
| `post_quantum` | `PostQuantum::Required` | `Required`: a peer connection that did not negotiate X25519MLKEM768 is closed before any stream; `Preferred`: hybrid first, classical accepted |
| `alpn_prefix` | `baton` | the first part of every ALPN offered and accepted; Peleda sets `peleda` |
| `open_timeout` | 10 s | total time one `open` may take: waiting for the pooled connection, connecting and the peer accepting the stream, under one deadline |

## Wire layout

- One QUIC connection per peer and protocol, reused by later `open` calls. Concurrent opens on a live pooled connection run in parallel; only replacing a dead connection is serialized. The dialer offers `<prefix>/<protocol>/1` and `<prefix>/link/1`; the acceptor serves the ALPN of every protocol it listens for plus `<prefix>/link/1`, so a connection lands on the protocol's own ALPN when someone listens for it and on the generic one otherwise. (Without the fallback, a TLS `no_application_protocol` alert never reached the dialer in iroh 1.5 and `open` hung until its timeout.)
- Every stream starts with a header from the opener: `0x50`, a length byte and the protocol name. The acceptor answers one byte, `1` (accepted) or `0` (refused), before any application byte; the opener writes nothing else until it has the answer. On a protocol-specific connection the header must name that protocol, otherwise the stream is reset.
- Close codes: 403 untrusted, 426 hybrid key exchange required, 401 revoked by `disconnect_untrusted`, 0 link closed.

## Trust

Checked four times: before dialing (`open` returns `Untrusted`), in an endpoint hook before an outgoing connection starts, in an endpoint hook right after every TLS handshake in both directions (the connection is closed with 403 before any stream is accepted), and for every stream on the accepting side (refused with `0`). So a revocation applies to the next stream even on a pooled connection. `disconnect_untrusted` closes every live connection to peers the trust no longer allows.

## Post-quantum key exchange

Findings for iroh 1.5.0 with rustls 0.23.46:

- iroh's QUIC handshake is rustls TLS 1.3, and iroh lets the application pass its own rustls `CryptoProvider` (`Builder::crypto_provider`). It does not choose a key exchange group itself.
- rustls' `ring` provider has no ML-KEM. Its `aws-lc-rs` provider has `X25519MLKEM768` (the hybrid of X25519 and ML-KEM-768 standardized for TLS); it is offered first only with rustls' `prefer-post-quantum` feature.
- This crate therefore builds iroh with `tls-aws-lc-rs` only (no `ring` backend, no default features) and installs an aws-lc-rs provider whose groups are `X25519MLKEM768, X25519, secp256r1`, in that order. Between two Peleda nodes the hybrid group is always negotiated; the tests check `negotiated_key_exchange_group` on live connections for both policies.
- Classical groups stay in the provider because iroh uses the same provider for TLS to relays and discovery servers, which may not support ML-KEM. That outer TLS carries only already end-to-end encrypted QUIC packets. Peer connections are held to the policy by the after-handshake hook: with `Required`, a peer that negotiated anything else is closed (code 426) before any stream; a test dials with an X25519-only peer and is refused, and the same peer is served under `Preferred`.
- A man in the middle cannot downgrade the group selection without breaking the handshake, which is signed by the Ed25519 keys; `Required` makes that a hard rule rather than a property of the peers' configuration.
- What stays classical: authentication (Ed25519 raw public keys in TLS, Ed25519 frame signatures in `baton-mesh`). A future quantum computer could not decrypt recorded traffic, but an attacker who has one at connection time could impersonate a node. That needs post-quantum signatures in TLS and in the roster, which neither iroh nor rustls offer today.
- 0-RTT is not used, so no data travels under keys from a resumed classical session.

Fallback plan, if a target platform cannot build aws-lc (so only `ring` would be available): run an extra hybrid KEM handshake (X25519 + ML-KEM-768) as the first message of every connection, bind it to the TLS session with exported keying material, and encrypt the streams' content under the derived key. It is not implemented because the native TLS path works on every target we build today.

## Dependencies and licenses

iroh, iroh-base, noq (MIT OR Apache-2.0); rustls (Apache-2.0 OR ISC OR MIT); aws-lc-rs (ISC AND (Apache-2.0 OR ISC)); aws-lc-sys (ISC, Apache-2.0, MIT, BSD-3-Clause combinations); url (MIT OR Apache-2.0). The rest of the tree is MIT, Apache-2.0, BSD, ISC, Zlib, Unicode-3.0 and CDLA-Permissive-2.0 (webpki roots), with a few Unlicense crates used only on wasm. aws-lc-sys compiles C code with the `cc` crate at build time (no CMake needed on macOS).

## Limits and platform notes

- Default features of iroh are off: no port mapping (UPnP/NAT-PMP/PCP), no metrics, no fast Apple datapath. Hole punching through relays still works when relays are configured.
- With relays disabled and no discovery, a peer is reachable only on the direct addresses given as hints.
- Connections are pooled per peer and protocol and kept until they idle out or fail; a failed pooled connection is redialed once per `open`.
- A stream accepted right as its listener is dropped can be reset after the accept byte was sent.
- Not yet checked: behavior in the iOS and Android background, binary size per platform.

## Tests

`cargo test -p baton-link-iroh` runs on loopback only, with relays and discovery disabled: the conformance suite, endpoint id equals the identity key, hybrid group negotiated under both policies, a classical-only peer refused under `Required` and served under `Preferred` in both directions (dialing it and being dialed by it), hint merging and relay URL checks, discovery URL checks, plain `http` relay and pkarr URLs allowed only to loopback.
