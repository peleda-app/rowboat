# Plan

Baton is a Rust library for the nodes of one **group** (a person, a family or a small team: phones, desktops and always-on servers) to talk to each other and coordinate. It decides who belongs to the group and who may do what, which node does which piece of work, carries commands and signals between nodes, fetches objects from peers, and keeps every resource readable only by those allowed to read it.

It is a library first, embedded in an application's node, and a small headless daemon second (`batond`, for a server in the blind role: arbiter, relay, drop and wake-up without any resource key).

## The boundary

Baton is the nervous system between a group's nodes. It is not their hands (talking to the outside world) or their memory (storing data).

| Through Baton | Outside Baton (the application) |
| --- | --- |
| membership, pairing, revocation, roles, capabilities | talking to external services (for Peleda: IMAP, SMTP, Gmail, Graph through Skein) |
| key epochs per resource: sealing them to the right nodes, opening them, rotation mechanics | application data: journals, messages, files, databases |
| leases: who does the work of a resource or job now, with priority and fencing | object storage, file systems, backups |
| commands to the current leaseholder, checked against capabilities, delivered at least once, answered with a result | deduplication by idempotency key, the claim-before-execute record and the "uncertain" outcome for commands that must not repeat (they need a durable journal; Skein has one) |
| signals, previews, presence, hints between nodes | push through APNs, FCM, UnifiedPush (Baton's wake contract can use the application's push) |
| objects by hash from peers, then from a source the application plugs in | the source itself (for Peleda: S3, directly or through presigned URLs) |
| its own durable state, handed to the application through contracts | where that state is stored (for Peleda: the same bucket as Skein's journal) |

Examples for Peleda:

- **New mail.** The server holding the lease for an account receives the message over IMAP IDLE and writes it to Skein's journal in S3 (no Baton). Through Baton it tells the person's devices that the account has new events, with a preview. A sleeping phone is woken through the application's push.
- **Sending from a phone.** The phone sends a signed `send` command through Baton to the leaseholder; if the leaseholder is unreachable the command waits in a drop mailbox. The leaseholder checks the capability, submits over SMTP (no Baton) and returns the result through Baton.
- **Opening an old message.** Local first; then through Baton from peers (server, then desktop); if no peer has it, Baton calls the application's source, which reads S3 directly or through a presigned URL from the server.
- **Journal replication.** A device learns through Baton that an account's journal moved on, and fetches the new segments from a peer through Baton or from S3 through Skein's storage, whichever is available.

## Goals

1. **Groups with members and nodes.** Member keys that certify device keys; a signed, hash-chained group log with roles, per-resource capabilities and key epochs; pairing with a PAKE; revocation that takes effect on every node that hears of it.
2. **Shared and private resources side by side.** Capabilities per resource (read, command classes, lead, admin) for members or single nodes. Keys per resource and epoch: a member of a shared resource cannot read a private one, a reader never receives the resource's secrets, a revoked member cannot read anything sealed after revocation. Baton does the cryptography and the checks; the application decides the policy.
3. **Leases with priority.** One holder per resource or job, fencing tokens that only grow, priority by node class (server, then desktop, then phone), cooperative handover to a stronger node, expiry otherwise. Safety never depends on clocks; arbiters are pluggable.
4. **Commands that are checked and delivered.** Signed by the issuing node, checked by the leaseholder against the group log, delivered at least once over whatever path works now, answered with a result. Deduplication by idempotency key belongs to the worker's durable queue (Skein's `CommandQueue`), so it exists once.
5. **Peers before external storage.** Objects by content hash from reachable peers in priority order, verified, then from the application's source.
6. **No storage of its own.** Every byte of durable state goes through `StateStore` and `SecretStore` implemented by the application, with "durable before return" semantics where safety needs it.
7. **Recovery from scratch.** With every node and server lost, a person with the recovery root and the application's stored state can restore the group on a fresh install: the group log verifies, key boxes sealed to the recovery key open, a new node is certified, old ones revoked.
8. **Contained compromise.** A stolen phone, a compromised server, a hostile relay or mailbox, or a dishonest store behind `StateStore` can each do only what SECURITY.md says, and that list is tested.
9. **Pluggable transports.** Live links (iroh first), store-and-forward mailboxes (our drop service first) and wake-up channels as separate contracts with conformance suites.
10. **Generic.** Applications define resource kinds, command classes, job kinds, workers and storage. Baton never parses application data.

## Non-goals

- **Not storage, not a database, not a CRDT.** Baton keeps no application data and orders nothing but its own group log and leases.
- **Not a client for external services.** Mail providers, object storage and push services are the application's.
- **Not a public network.** Groups are small (tens of nodes, hundreds of resources). No global discovery.
- **Not a messenger.** Human-to-human messaging is an application on top.
- **Not anonymity.** Transports may hide metadata from each other; Baton does not promise unlinkability against an operator who sees traffic.

## Vocabulary

| Term | Meaning |
| --- | --- |
| **Group** | the trust domain: a person or a team (generalizes the app's *tenant*) |
| **Member** | a person in the group, with a member key that certifies their nodes and a recovery root |
| **Node** | one device or server with its own signing and encryption keys, certified by its member; class `server`, `desktop`, `phone` or `blind` |
| **Resource** | a unit of data and work with its own capabilities and keys (for Peleda: one mail account, one shared mailbox); its data lives with the application |
| **Job** | a unit of work without keys of its own (a periodic export); leased like a resource |
| **Lease** | the right to do the work of one resource or job now, with a fencing token |
| **Command** | a signed request from a node to the leaseholder of a resource |
| **Group log** | the signed, hash-chained history of members, nodes, roles, capabilities, key epochs and recovery keys |
| **Recovery root** | a 32-byte secret kept offline, from which a member's (or the group's) recovery keys are derived |

## One implementation of each thing

Baton, Skein and the Peleda app overlap today: Skein has its own ownership, liveness and ephemeral contracts with implementations, the app has mesh implementations of those Skein contracts, and Baton adds leases, liveness and signals. The rule from here on: **every function has exactly one implementation, in the one place that owns it**, and the others use it.

| Function | The one implementation | Used by | Replaces |
| --- | --- | --- | --- |
| ids, fencing token, time | `baton-core` (types only) | Baton, Skein, app | `NodeId`, `FencingToken` in `skein-core` |
| leases, liveness, node profiles, priority, `preferred_owner` | `baton-lease` contract | Skein's engine, app | `skein-ownership` (contract), Skein's `NodeProfile` and `preferred_owner` |
| lease arbiter over any compare-and-swap record store | `lease-cas` in Baton (over `baton-state`'s `StateStore`, which Skein's `ControlStore` implements) | Skein servers and Peleda | `skein-ownership-control` |
| single-process leases | `lease-cas` over `baton-state-memory` (no separate crate) | Skein library mode, tests | `skein-ownership-single` |
| leases among nodes without a store | `lease-quorum` | Peleda devices-only groups | the app's `ownership-mesh` |
| heartbeats into a store when nodes cannot reach each other | `CasLiveness` in `lease-cas`, over the same `StateStore` | plain Skein servers only (never Peleda, which uses `liveness-mesh` or `lease-server`) | `ObjectLiveness` in `ownership-control` |
| signals, previews, expiring values | `baton-signal` contract; `signal-local`, `signal-mesh`; later `signal-nats`, `signal-redis` | Skein's engine, app | `skein-ephemeral`, `skein-ephemeral-local`, the app's `ephemeral-mesh`, the planned `ephemeral-nats`/`-redis` |
| node identity, membership, capabilities, resource keys | `baton-identity`, `baton-group`, `baton-keys` | app | the app's `mesh-identity` |
| sealing at rest | `baton-seal` | Baton, the Peleda repositories | the app's `seal` (Skein keeps its own envelope code, so it depends only on Baton's contract crates) |
| node-to-node links and frames | `baton-link`, `baton-mesh` | app | the app's `link*`, `mesh-transport`, `transport-link` |
| journal, segments, blobs, snapshots, cursors | Skein storage (`storage-s3`, `-fs`, `-memory`, `-tiered`) | Skein, and Baton's state in Peleda (below) | nothing; Baton never stores |
| durable command queue, idempotency, claim and `WriteUncertain` | Skein's `CommandQueue` and engine | Skein | Baton's own persisted deduplication (dropped: Baton delivers at least once, the worker deduplicates by idempotency key) |
| capability checks and delivery of commands between nodes | Baton commands | app | nothing in Skein (its HTTP management API was removed on 2026-11-25; the node is managed through Baton commands) |
| keys for sealing an account's data | Skein's `Keyring` contract, given an account scope; implemented in Peleda by Baton resource keys, in plain Skein servers by `keyring-local` | Skein | the single tenant-wide key for Peleda |
| fetching segments and blobs from peers | a peer tier in `storage-tiered`, implemented in rowboat's node layer over Baton fetch | Skein on devices | nothing |
| push payload format | `push`, moved from the app to rowboat's node layer (the server seals, the phone opens) | rowboat's headless server, app | nothing |
| push delivery to APNs, FCM, UnifiedPush | rowboat's headless server | Baton's `Wake` in rowboat's node layer | nothing |

### What changes in Skein

Skein stays generic and keeps everything that is about mail, calendars, contacts and journals. It starts depending on Baton's **contract crates only** (`baton-core`, `baton-state`, `baton-lease`, `baton-signal`: traits and types, no I/O), never on Baton's runtime, groups or transports.

1. **Coordination contracts move to Baton.** The engine takes `Arc<dyn baton_lease::Leases>` and `Arc<dyn baton_signal::Signal>` instead of Skein's `Ownership`, `Liveness` and `Ephemeral`. The crates `skein-ownership`, `skein-ownership-control`, `skein-ownership-single`, `skein-ephemeral` and `skein-ephemeral-local` are deleted; their conformance suites move into Baton's lease and signal suites, so no guarantee is lost. Skein's `ControlStore` gains a `baton-state` `StateStore` implementation so a plain Skein server keeps working exactly as today with `lease-cas` over S3.
2. **Account-scoped keys.** `Keyring::seal(tenant, context, ...)` becomes `seal(scope, context, ...)` where the scope is a tenant or an account, so each account's blobs, segments and credentials can be sealed under that account's own key. `keyring-local` keeps a key per scope; Peleda implements the contract with Baton resource keys (data key for content, secret key for credentials).
3. **Tamper-evident journal.** Each segment records the hash of the previous one, and `head` records the hash of the last segment. A pluggable `HeadAttestor` (no-op by default) lets an application sign each head; Peleda signs with the leaseholder's node key and fence. Then a segment from any source (S3, a peer) can be verified from a trusted head, and comparing heads detects rollback and withheld events.
4. **Peer tier.** `storage-tiered` accepts a read-only tier that fetches segments and blobs by name with an expected hash; Peleda supplies it over Baton fetch.
5. **Docs and rules.** Skein's docs describe Baton as the coordination library it uses. (Since 2026-11-25 both live in rowboat, so the local rule against describing the mesh is gone.) These are pre-1.0 breaking changes, released as a minor version.

What does not change in Skein: providers, events, commands and their results, the storage contracts and implementations, the server and its API keys (they authorize HTTP integrators, a different job from Baton capabilities between nodes), `skein-view`.

### What rowboat's node layer does

The node layer of rowboat (`crates/`, `apps/`, packages `rowboat-*`) is the only place where Skein and Baton meet. The app (desktop, phone) and rowboat's headless server both run it, so there is no second implementation for servers and no copy of the app on the server. It:

- builds a Baton node with `lease-server` on the group's server (`batond` or rowboat's headless server) where there is one, otherwise `lease-cas` over Skein's `ControlStore` in the account's bucket with `liveness-mesh` as its liveness, or `lease-quorum` when a group has no bucket. **It never uses `CasLiveness`**: heartbeats travel only between nodes, never into object storage, so the bucket sees a lease write only when a lease changes hands and one read of a lease record per holder per interval;
- implements Baton's `StateStore` with Skein's storage (`storage-fs` locally, `storage-s3` for state that must survive losing every device), so there is no extra storage code;
- runs Skein's engine as the worker for each account resource, passing the fence through to Skein's storage;
- turns incoming Baton commands into entries in Skein's `CommandQueue` after Baton's checks, and Skein's results into Baton results;
- implements Skein's `Keyring` with Baton resource keys, the peer tier with Baton fetch, `HeadAttestor` with the node key, Baton's `Source` with Skein's `BlobStore`, Baton's `Wake` with `push`; it takes a `SecretStore` from its caller (the app passes its platform vault, the headless server its file secret store).

## What moves here from `app`

The app repository is private; these crates are generic and move here (with history, by `git filter-repo`, once the maintainer decides). The app then depends on Baton.

| From `app/crates` | Becomes | Changes on the way |
| --- | --- | --- |
| `mesh-identity` | `baton-identity` (keys, contexts, pairing) and `baton-group` (the roster grows into the group log) | own ids from `baton-core`; member keys separate from node keys; recovery keys; PAKE (CPace or SPAKE2) before short codes; fork detection |
| `mesh-transport` | `baton-mesh` (signed frames, `Transport` contract) | `Opener::open` takes the expected sender and records the sequence number only after every check (today it records it before the caller checks that the frame's sender is the stream's peer, which forces per-peer openers in `transport-link`); sequence state through `StateStore`; a conformance suite; memory hub moves to `mesh-memory` |
| `link`, `link-memory`, `link-iroh` | `baton-link`, `link-memory`, `link-iroh` | the ALPN prefix becomes the application's choice |
| `transport-link` | `mesh-link` | follows the `Opener` fix |
| `ephemeral-mesh` | `signal-mesh` | implements `baton-signal` instead of Skein's `Ephemeral` |
| `ownership-mesh` | `lease-quorum`, plus `liveness-mesh` from its `MeshLiveness` | implements `baton-lease`; acceptor state written through `StateStore` before each answer; priority-aware takeover |
| `seal` | `baton-seal` | add HPKE (RFC 9180) with a hybrid post-quantum KEM for key boxes |

Other crates leave `app` for the private repositories below, not for Baton. What stays in `app`: the shells, the UI, platform vaults, `snapshot*`, widgets and extensions.

## Repositories around Baton

Agreed with the maintainer on 2026-11-25; split by who runs the code. Nothing here is created or moved yet; moves out of `app` are coordinated with the work going on there.

The repository map is maintained in dojo's `registry.toml` (tiers and status) and the workspace's `reorg-plan.md`. Since 2026-11-25 Baton is the `baton/` layer of `rowboat`, next to Skein (`skein/`) and the node (`crates/`, `apps/`, formerly Smereka; see `../docs/PLAN.md`); untrusted content is handled by `rinse` (formerly `washer` and `peleda-content`) and the UI lives in `tinginys`.

Baton itself depends on none of them.

## Phases

Across Baton, Skein, rowboat's node layer and `app`, in order; each phase ends with every conformance suite green in all of them.

0. **Foundation.** Baton workspace, CI, `cargo deny`, conformance harness. Move `seal`, `mesh-identity` (as is; split into `baton-identity` and `baton-group` in phase 4) and `link*` here; the app switches to path dependencies. Fix `Opener::open`. License: originally `MIT OR Apache-2.0`; since 2026-11-25 PolyForm Noncommercial 1.0.0 as part of rowboat.
1. **Coordination contracts.** `baton-core`, `baton-state`, `baton-lease` (leases, liveness, profiles, priority, preemption, `preferred_owner` moved from Skein), `baton-signal`; `lease-cas` (with `CasLiveness`), `state-memory`, `signal-local`; Skein's ownership and ephemeral suites ported into Baton's.
2. **Skein on Baton contracts.** Skein's engine, server, `skein-view` and binary switch to `baton-lease` and `baton-signal`; the five Skein crates are deleted; `ControlStore` implements `StateStore`. A plain Skein server behaves as before (integration suite unchanged). Skein minor release.
3. **Skein integrity and scoping.** Hash-chained segments, `HeadAttestor`, account-scoped `Keyring`, the read-only peer tier in `storage-tiered`.
4. **State, groups and keys.** `baton-state`; `baton-group` with member and node certificates, recovery keys, capabilities, fork and rollback detection, pairing with a PAKE; `keys-boxes`; export and restore with a recovery drill test.
5. **Links, mesh, quorum.** Move `mesh-transport`, `transport-link`, `ephemeral-mesh`, `ownership-mesh` as `baton-mesh`, `mesh-link`, `signal-mesh`, `lease-quorum`, `liveness-mesh`.
6. **Commands and peer fetch.** Signed commands, checks, at-least-once delivery, results; fetch from peers with a have-index and the application's `Source`.
7. **rowboat's node layer.** The single meeting point of Skein and Baton, used by the app and by rowboat's headless server; every Peleda node runs on it.
8. **Drop and wake.** `baton-mailbox`, `baton-wake`, `baton-drop` (protocol and service rules), `mailbox-memory`, `wake-mailbox` (planned as `wake-drop`; it works over any mailbox) are built, and so are `drop-http`, `mailbox-drop` and `apps/drop` (the `drop` binary with its redb store); `lease-server` (the arbiter over a link, with `RemoteLeases` and `RemoteLiveness`) is built; `group-server` (group logs held by a server and served over link protocol `group`) and `apps/batond` (the blind server: group logs, lease arbiter with rights from the logs, drop service, iroh, redb `StateStore`) are built. Deferred: an embedded iroh relay and wake sending from `batond`.
9. **More transports and keys.** OpenMLS, Nostr wake, Matrix mailbox, SimpleX if the licensing question resolves.
10. **External audit** of groups, keys, recovery, leases, commands and Skein's journal integrity before anything is called stable.

## Open questions

See [QUESTIONS.md](QUESTIONS.md).
