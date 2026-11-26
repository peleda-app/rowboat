# Transports

Baton separates four transport roles. Every role is a contract with a conformance suite, and every implementation carries only bytes that Baton has already sealed and signed: no transport is trusted for confidentiality, integrity or ordering of application data.

| Role | Contract | What it does |
| --- | --- | --- |
| Link | `baton-link` | live, mutually authenticated byte streams between two nodes that are both up |
| Mailbox | `baton-mailbox` | store-and-forward of sealed messages for a node that is offline |
| Wake | `baton-wake` | a tiny signal that makes a sleeping node connect |
| Key agreement | `baton-keys` | getting resource epoch keys to exactly the authorized nodes |

Summary of the decisions below:

| Candidate | Role | Decision | License |
| --- | --- | --- | --- |
| iroh 1.x | link | **built in, phase 0** (already in the app) | MIT OR Apache-2.0 |
| drop (our own) | mailbox, wake | **built in, phase 8** | ours |
| S3 and compatibles | application side: storage, arbiter, mailbox | **not in Baton**; notes below for applications | n/a (protocol) |
| HPKE key boxes | key agreement | **built in, phase 4** | RustCrypto / aws-lc-rs |
| OpenMLS | key agreement | evaluate, phase 9 | MIT |
| Nostr relays | wake | optional, phase 9 | rust-nostr MIT |
| Matrix | mailbox | optional, only on demand | matrix-rust-sdk Apache-2.0 |
| WebDAV, cloud app folders | application side: storage | not in Baton; notes below | n/a |
| SimpleX SMP | mailbox | research only; not built in now | AGPL-3.0 |


Facts below were checked on 2026-11-24; the notes behind them, with every source and what could not be verified, are kept outside the repository by the planning session. Re-check versions before building.

## Link: iroh

**What it is.** QUIC between endpoints addressed by Ed25519 public keys, hole punching first and relays as fallback, address lookup through DNS/Pkarr. iroh 1.0 was released on 2026-06-15 with a stability promise for the wire protocol and the API ("any v1 endpoint talks to any v1 endpoint"); 1.5.0 is current (2026-11-19). The QUIC layer is n0's `noq`, which began as a Quinn fork and has been standalone since 0.97; it adds QUIC multipath, NAT traversal and address discovery. License MIT OR Apache-2.0 for iroh, iroh-relay, iroh-base and noq. Bindings exist for Python, Node.js, Swift and Kotlin.
Sources: <https://iroh.computer/blog/v1>, <https://github.com/n0-computer/iroh>, <https://github.com/n0-computer/noq>.

**Post-quantum.** X25519MLKEM768 (the hybrid group of RFC 10024) is available with iroh's `tls-aws-lc-rs` feature and rustls' `prefer-post-quantum`; upstream it is *preferred*, falling back to X25519 with peers that lack it, and authentication stays Ed25519. The app's `link-iroh` already turns preference into a rule (`PostQuantum::Required` closes any peer connection that negotiated something else), and that crate moves here with only its ALPN prefix made the application's choice.
Source: <https://iroh.computer/blog/iroh-post-quantum-handshakes>.

**Relays.** n0's public relays are free, shared, rate-limited and described as suitable for development and testing; production means n0's paid relays or self-hosting the open-source `iroh-relay` binary (the same code n0 runs). Baton's default is no public relay at all (as `link-iroh` does today): the group's server embeds a relay, Peleda can run relays for its users, anyone can run their own.
Source: <https://docs.iroh.computer/concepts/relays>.

**Companion crates.** `iroh-blobs` (0.105, its README says it is not yet production quality), `iroh-gossip` (0.103) and `iroh-docs` (0.101, no release since 2026-06-15) are all MIT OR Apache-2.0 and all still 0.x, outside the 1.0 promise. Baton does not depend on them: blob transfer is our own verified fetch (objects are ciphertext with known hashes), groups are small enough for direct fan-out, and `iroh-docs`' data model (namespaces with author keys and set reconciliation) is a different design from single-writer journals. Revisit `iroh-gossip` if groups grow.

**Pros:** already integrated and tested in the app with mandatory hybrid key exchange; keys instead of addresses; good NAT traversal; stable 1.x; permissive license; mobile bindings.
**Cons:** UDP may be blocked on some networks (relays fall back to HTTPS, so it still works but slower); mobile background behavior is the platform's, not iroh's: an iOS app cannot keep connections open in the background, which is why mailbox and wake roles exist; authentication is classical until PQ signatures arrive.

## Mailbox and wake: drop (our own)

A small store-and-forward service written for Baton, in this repository: the protocol and the one implementation of its rules in `baton-drop` (built), `mailbox-memory` and `wake-mailbox` over any mailbox (built), the HTTP server `drop-http`, the client `mailbox-drop` and the service `apps/drop` (built; `batond` embeds the same service through its optional `[drop]` section). It exists because offline nodes need somewhere to receive commands and key boxes, and because the alternatives either carry licensing baggage (SimpleX), need accounts and a heavy server (Matrix) or keep nothing reliably (Nostr).

**Model.**

- A **box** is a 256-bit id bound to its read key (`BoxId::of_reader`: BLAKE3 `derive_key("baton/drop/box/1", read key)`, so only the holder of the read key can create it, also after it expired) with a policy: a set of write keys, one read key, quota (bytes and messages), TTL per message (default 14 days, at most 30).
- **Creating a box** needs a proof of work (Argon2id hashcash bound to the box id and the operator's salt, difficulty set by the operator, parameters capped so a verification stays a few milliseconds and at most 4 MiB) or an operator token (compared in constant time), so nobody can fill the service with boxes cheaply. Boxes made by proof of work (or on an open service) may ask for small quotas only (default 1 MiB, 1,000 messages, 7 days) and share a bounded part of the store (default 50,000 boxes and 2 GiB of 8 GiB), so token holders are never locked out. Binding the proof to a time epoch or rotating the salt (against stockpiled proofs) is not built. A box whose reader has not used it for its time-to-live is removed.
- **Writes** are signed by one of the box's write keys. Write keys are *per-box pseudonymous keys* derived by each node for that box, not node identity keys, so the operator cannot link boxes of one group by key. The group log records which node owns which drop write key, so members can check who wrote.
- **Reads** are signed by the read key; messages are taken in order and acknowledged, then deleted. Long polling for the wake role (a WebSocket is not planned).
- **Requests** are versioned and signed by the box key under a context and the operator's realm, stamped with the client's clock (accepted within ±5 minutes) and a random nonce kept in a bounded replay cache with a share per box (so one box's requests make only that box busy); writer changes carry a version so a replay cannot restore a removed writer.
- **Ciphertext only.** Payloads are already sealed by Baton to the recipient node; the service enforces a size limit (64 KiB per message by default) and refuses anything unsigned.
- **No logs** of ids or IPs beyond rate limiting kept in memory; that is policy the operator states, not something clients can verify.
- **HTTP (built).** `drop-http` serves two routes over HTTP/1.1, `GET /v1/info` and `POST /v1/request`, whose bodies are raw drop bytes, so HTTP adds no format and no rule. Limits: body size (`max_message + 8 KiB`, declared or counted), header and TLS-handshake timeout (10 s, also between kept-alive requests), body timeout (10 s), write timeout (30 s without progress, for clients that never read), connection caps (4,096, and 64 per client), server-wide in-flight cap (2,048, refused at once with `503`, waiting long polls not counted), per-client token bucket (20/s, burst 100), in-flight cap (16) and poll cap (4) for IPv4 addresses and IPv6 /64s with a bounded table, long polls waiting under their own budget (1,024 at once, 4 per box, 30 s; beyond it a take returns at once). A handler deadline answers `504` (outcome unknown). HTTP/2 is not served (no per-request header timeout there, and nothing to gain for one request per long poll).
- **Client (built).** `mailbox-drop` is the drop client over reqwest: HTTPS required except to loopback, no redirects or proxy, timeouts above each long poll, replies read in chunks and capped by the service's limits, statuses mapped to `MailboxError`.
- **Deployment (built).** `drop` (package `baton-drop-service`, `apps/drop`): one Rust binary with an embedded redb store, TOML configuration, admission by operator tokens (a `0600` file) or proof of work (salt kept in the store), store-wide caps on boxes and bytes, an expiry sweeper, graceful shutdown, and TLS itself or behind a reverse proxy (`X-Forwarded-For` for rate limits). Runnable by the group's own server, by Peleda for its users, or by anyone. `batond` runs it in the same process as its blind role (built); an embedded `iroh-relay` is not built yet (run the relay binary beside it).

**Pros:** exactly the semantics Baton needs; small; ours to license; no accounts; abuse controls built in.
**Cons:** another service to run and secure; a public instance needs abuse handling and costs money; metadata (which box gets messages when) is visible to the operator, unlike SimpleX's design that also hides senders' IPs through proxy routing.

## Notes for applications: S3 as storage and arbiter

Baton has no storage and no S3 client. Applications that keep their data and Baton's exported state in object storage, and that want the store as a lease arbiter through Baton's `lease-cas` over a `StateStore` they implement (Peleda does, with Skein's `ControlStore`), should know the following.


**Conditional writes** are what make object storage an arbiter. AWS S3 supports `If-None-Match: *` on `PutObject` since 2024-08-20 and `If-Match: <ETag>` since 2024-11-25, with bucket policies that can require them; a lost race returns 412 (409 or 404 when racing a delete).
Sources: <https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html>, <https://aws.amazon.com/about-aws/whats-new/2024/11/amazon-s3-functionality-conditional-writes>.

| Store | Conditional writes | Note |
| --- | --- | --- |
| AWS S3 | yes | |
| Cloudflare R2 | yes | <https://developers.cloudflare.com/r2/api/s3/conditional-operations/> |
| MinIO | yes in AIStor | the open-source `minio/minio` repository is archived and AGPL; the maintained product is proprietary AIStor |
| RustFS, Versity, SeaweedFS | pass Skein's `storage-s3` conformance suite (November 2026) | |
| Backblaze B2 | reportedly errors on `If-None-Match` (third-party report only) | treat as unsupported |
| Garage | **no**: the header is silently ignored and the write overwrites | <https://git.deuxfleurs.fr/Deuxfleurs/garage/issues/1052> |

Because some stores *ignore* the header instead of refusing it, an S3 arbiter must probe at setup time (create a probe key twice with `If-None-Match: *` and expect 412; update with a stale `If-Match` and expect 412) and refuse to arbitrate if the probe fails. Such a store can still hold data; leases then come from the server or the quorum. `baton-state`'s conformance suite (run by Skein's `ControlStore` over each backend, under `lease-cas`) includes a lost-race test that catches a store ignoring the headers.

An application can also implement Baton's `Mailbox` over a prefix in its bucket, with listing by prefix, for commands to nodes that are offline.

**Pros:** durable, cheap, everywhere, CAS where supported, presigned URLs let the server hand phones one-object access without credentials.
**Cons:** a compromised or dishonest store can delete, roll back or fork compare-and-swap (SECURITY.md); every operation costs a request; listings are eventually consistent on some compatibles.

## Key agreement: HPKE boxes, and MLS through OpenMLS

**HPKE key boxes** (phase 4): RFC 9180 with a hybrid KEM (X25519 + ML-KEM-768). The HPKE post-quantum KEMs are being standardized in `draft-ietf-hpke-pq`; until the code points are final, Baton pins its own versioned suite identifier and uses aws-lc-rs's ML-KEM (already in the tree through rustls) or RustCrypto's `ml-kem`. Simple, stateless, works with any ordering, gives new devices access to past epochs by boxing old keys to them, and gives recovery by boxing every epoch to the recovery public keys.

**MLS** (RFC 9420; architecture in RFC 9750). OpenMLS is MIT-licensed, at 0.9.2 stable with 0.10.0 announced on 2026-11-23, was audited by SRLabs (funded by the Sovereign Tech Agency; 8 findings, one high, fixed in 0.8.1 and 0.7.3), and has post-quantum suites: an experimental X-Wing suite since 0.6, ML-DSA and ML-KEM-1024 suites since 0.9, and in 0.10 suites that follow `draft-ietf-hpke-pq` and `draft-ietf-mls-pq-ciphersuites` (not interoperable with 0.9's PQ groups).
Sources: <https://github.com/openmls/openmls>, <https://blog.openmls.tech/>, <https://www.rfc-editor.org/rfc/rfc9420>, <https://www.rfc-editor.org/info/rfc9750>, <https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites/>.

How MLS would fit: one MLS group per resource; Baton's arbiter is the strongly consistent delivery service RFC 9750 describes (one compare-and-swap per epoch on `res/{r}/mls/{epoch}`), the group log is the authentication service; the resource data key of an epoch is an MLS exporter secret.

**Pros of MLS:** standard, audited, logarithmic cost for large groups, forward secrecy and post-compromise security with regular updates, PQ suites arriving.
**Cons for Baton:** groups are small, so the cost advantage is small; MLS deletes past secrets by design, while a new phone of a member must read the history of a shared mailbox, so key boxes (or exported epoch keys) are still needed; every device keeps MLS state that must survive crashes and restores consistently; the PQ suites are not stable across versions yet. Decision: `keys-boxes` first behind the `baton-keys` contract; `keys-mls` as an evaluated alternative in phase 9. The group log stays the source of truth either way.

Related work worth reading, not adopting: Ink & Switch's **Keyhive** (Apache-2.0) with convergent capabilities and the BeeKEM group key agreement; it is explicitly pre-alpha and unaudited (<https://www.inkandswitch.com/keyhive/notebook/>). **Willow**'s Meadowcap capabilities (`willow25` crate, MIT OR Apache-2.0; <https://willowprotocol.org/>).

## Mailbox (research only): SimpleX

**Protocol.** The SimpleX Messaging Protocol (SMP, spec version 23) uses unidirectional queues on SMP servers; each queue has separate random recipient and sender ids and keys, and a two-way connection is two queues, possibly on different servers, with no user identifiers anywhere. TLS with the server's certificate fingerprint pinned in its address, fixed 16 KB blocks, re-encryption between sender and recipient sides so the two ciphertexts differ, and optional private message routing through a forwarding server so the destination server does not see the sender's IP. The agent layer adds duplex connections, redundancy and queue rotation; end-to-end encryption is a double ratchet with encrypted headers and a hybrid post-quantum step with sntrup761 (ML-KEM was considered and not chosen). Files go through separate XFTP servers.
Sources: <https://github.com/simplex-chat/simplexmq/blob/stable/protocol/simplex-messaging.md>, <https://github.com/simplex-chat/simplexmq/blob/stable/protocol/pqdr.md>.

**Licensing.** `simplexmq` (servers, agent, client library) and `simplex-chat` are AGPL-3.0, in Haskell; the name and logo are under separate terms. No separate license was found for the protocol documents, which live in the AGPL repository.
Sources: <https://github.com/simplex-chat/simplexmq>, <https://github.com/simplex-chat/simplex-chat>.

**Preset servers.** The conditions of use let third-party apps use SimpleX Chat Ltd's preset servers only if they are user-to-user messaging (or clearly labeled bots), compatible with specs at most a year old, open source (AGPL if they use SimpleX code), do not charge for that infrastructure and do not use the brand. Messages are deleted after delivery or 21 days. A device-sync mailbox for Baton is very likely outside "user-to-user messaging", so preset servers are out; self-hosted SMP servers are allowed.
Source: <https://github.com/simplex-chat/simplex-chat/blob/stable/PRIVACY.md>.

**From Rust.** No native Rust implementation of SMP exists. The options:

1. **Clean-room Rust SMP client** from the published specs, talking to self-hosted SMP servers. Copyright in the spec text does not normally cover an independent implementation, but this needs a legal opinion, and contributors must not read the Haskell source. Large (queues, agent protocol, ratchet, PQ, rotation, proxy routing) and chasing a protocol that moves fast. For a *mailbox* Baton needs only the queue layer (SMP commands `NEW`, `SUB`, `ACK`, `SEND`, `KEY`, `DEL`), since end-to-end encryption is Baton's own; that subset is much smaller.
2. **The SimpleX CLI as a sidecar** over its local WebSocket API (`simplex-chat -p 5225`, JSON commands, no authentication, localhost only). The AGPL then covers the shipped CLI binary, not Baton, but it is a Haskell binary per platform, cannot run as a helper on iOS, and turns a mailbox into a chat account. `simploxide-client` (MIT OR Apache-2.0) is a Rust client for that API; its `ffi` feature links SimpleX code and would bring the AGPL in.
3. **Linking** the SimpleX library: makes the combined work AGPL. Ruled out.

**Decision:** not built in now. SimpleX's strength is metadata protection (no identifiers, unlinkable queues, sender IP hidden), which drop does not match. If that becomes a requirement, option 1 limited to the queue layer is the research item (QUESTIONS 15).

## Wake (optional): Nostr relays

Nostr events are signed with BIP-340 Schnorr over secp256k1 (NIP-01); kinds 20000–29999 are ephemeral and not stored; NIP-44 v2 encryption (audited by Cure53) has no forward secrecy and no post-quantum protection; NIP-59 gift wraps hide the sender behind a one-time key, and kind 21059 is an ephemeral gift wrap that relays must not store. rust-nostr (`nostr` 0.45, `nostr-sdk` 0.45) is MIT and pre-1.0.
Sources: <https://github.com/nostr-protocol/nips> (01, 44, 59, 40), <https://github.com/nostrdevkit/nostr>.

Use in Baton: a `wake-nostr` implementation that sends an ephemeral gift-wrapped event, whose content is a Baton-sealed "connect now" of a few dozen bytes, to a per-node pseudonymous Nostr key, published to several relays. Nostr's own encryption is irrelevant (Baton seals first); it is used as a free, account-less, many-operator pager.
**Pros:** no account, many relays, cheap, censorship-resistant. **Cons:** no delivery guarantee; relays see that a pubkey was pinged (rotate keys per node); secp256k1 keys are one more key type per node; useless on iOS in the background (the app cannot listen), so it serves desktops and servers, where a live iroh connection usually exists anyway. Optional, phase 9.

## Mailbox (optional): Matrix

To-device messages (`PUT /_matrix/client/v3/sendToDevice/{eventType}/{txnId}`) are stored by the homeserver until the device syncs, delivered once through `/sync`, and federate between servers; they never enter a room's history. That is a usable mailbox keyed by user and device. matrix-rust-sdk is Apache-2.0 (`matrix-sdk` 0.19). Synapse moved to AGPL-3.0 (or Element's commercial license) in late 2023; the Rust homeservers Conduit, Tuwunel (successor to the archived conduwuit) and Continuwuity are Apache-2.0.
Sources: <https://spec.matrix.org/v1.19/client-server-api/#send-to-device-messaging>, <https://github.com/matrix-org/matrix-rust-sdk>, <https://element.io/blog/element-to-adopt-agplv3/>, <https://github.com/matrix-construct/tuwunel>.

**Pros:** federated, many existing servers, people who already run a homeserver could use it. **Cons:** needs a Matrix account per node, a large SDK, homeserver operators see the account graph; nothing Baton needs that drop does not do with less. Decision: only if users ask; the `baton-mailbox` contract keeps the door open.

## Notes for applications: other stores

Again outside Baton; relevant to applications choosing where to keep their data and Baton's exported state.


- **WebDAV** (RFC 4918, conditional `PUT` with `If-Match`/`If-None-Match` from RFC 9110): Nextcloud and other self-hosted servers. Behavior of conditional writes varies by server, so the same setup probe as for S3 decides whether it may back an arbiter. Good for people who already run Nextcloud.
- **Apple CloudKit private database**: free storage in the user's iCloud, reachable on non-Apple platforms only through CloudKit Web Services with an API token and an Apple ID web sign-in (server-to-server keys reach only the public database). `CKSyncEngine` is Apple-only. Object store only; no usable arbiter.
- **Google Drive `appDataFolder`** (`drive.appdata` scope, hidden from the user, deleted when the app is removed from Drive): object store only, no compare-and-swap on content.
Sources: <https://developer.apple.com/library/archive/documentation/DataManagement/Conceptual/CloudKitWebServicesReference/SettingUpWebServices.html>, <https://developers.google.com/workspace/drive/api/guides/appdata>.

## Considered and not planned

| Candidate | Why not (now) | License |
| --- | --- | --- |
| Tailscale / Headscale | a WireGuard network, not a mailbox; would duplicate iroh and add a control server | BSD-3-Clause |
| Veilid | a whole private routing network; heavy, different goals | MPL-2.0 |
| Syncthing BEP | file sync with version vectors and multi-writer folders, not single-writer journals | MPL-2.0 |
| Willow / Earthstar | multi-writer data model with capabilities; interesting for Meadowcap, not for leases and commands | `willow25` MIT OR Apache-2.0; Earthstar LGPL-3.0 |
| Signal servers, libsignal | already ruled out in the app (terms, no API; AGPL) | AGPL-3.0 |
| iroh-docs | multi-writer KV with set reconciliation, stalled since June 2026 | MIT OR Apache-2.0 |

## References for coordination

- Kubernetes Lease objects (`holderIdentity`, `leaseDurationSeconds`, `renewTime`, optimistic concurrency by `resourceVersion`): <https://kubernetes.io/docs/concepts/architecture/leases/>.
- client-go leader election, which states it does not guarantee a single acting leader ("fencing") and tolerates clock offset but not clock rate differences: <https://pkg.go.dev/k8s.io/client-go/tools/leaderelection>. Baton adds fencing tokens for exactly this reason.
- CASPaxos, Rystsov 2018: <https://arxiv.org/abs/1802.07000>.
