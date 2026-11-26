# Architecture

How Baton is built: its contracts and implementations, the group log, leases and priority, commands, signals, peer fetch, the state contracts, recovery, and how an application plugs in. Security reasoning is in [SECURITY.md](SECURITY.md); transports in detail in [TRANSPORTS.md](TRANSPORTS.md). What is inside and outside Baton is in [PLAN.md](PLAN.md#the-boundary).

## Layers

```
 application (Peleda: Skein, S3, push, UI)
   │  resource kinds, command classes, workers, Source, StateStore, SecretStore
   ▼
 baton-node ─────────── the runtime embedded in every node (in-memory state only)
   │
   ├── baton-group     who is in the group, what each may do, which keys exist    (pure)
   ├── baton-keys      sealing and opening resource epoch keys                     (contract)
   ├── baton-lease     who does which work now (priority, fencing)                 (contract)
   ├── baton-command   signed commands, checks, delivery, results                  (pure + runtime)
   ├── baton-signal    signals, previews, presence, expiring values                (contract)
   ├── baton-fetch     objects by hash: peers, then the application's Source       (planner)
   ├── baton-state     StateStore, SecretStore: durable state kept by the app      (contract)
   │
   ├── baton-link      live byte streams to a node by key                          (contract)
   ├── baton-mesh      signed small frames over links                              (contract + frame format)
   ├── baton-mailbox   store-and-forward for nodes that are offline                (contract)
   ├── baton-wake      wake a sleeping node                                        (contract)
   └── baton-seal, baton-identity                                                  (pure crypto)
```

### Contracts and implementations

| Contract | Guarantees (summary) | Implementations planned |
| --- | --- | --- |
| `baton-core` | ids (`NodeId`, `GroupId`, `ResourceId`), `FencingToken`, time types; no traits with I/O | used by every crate here and by Skein |
| `baton-state::StateStore` | small named records with compare-and-swap by version; a write that returns `Ok` is durable (survives a crash and a power cut on that node); listing by prefix | **application** (Peleda: Skein's `ControlStore`); here `state-memory` (tests, one process) and `RedbState` inside `apps/batond` (the blind server's own store) |
| `baton-state::SecretStore` | named secrets with a protection class, never exported in clear | **application** (Peleda: its `vault`); here `secret-memory` |
| `baton-link::Link` | byte streams to a peer named by its Ed25519 key, mutual authentication by key only, trust checked per stream (moved from the app; only the ALPN prefix becomes the application's choice) | `link-iroh`, `link-memory` |
| `baton-mesh::Transport` | small signed frames on named channels, per-pair order, membership check, replay protection | `mesh-link` (over any `Link`), `mesh-memory` |
| `baton-mailbox::Mailbox` | `create(box, policy, reader key, admission)`, `put(box, writer key, sealed)`, `take(box, reader key, after, limit, wait)`, `ack`, `set_writers`, `delete_box`; per-box pseudonymous keys (`BoxKey::derive`), box ids bound to the reader key (`BoxId::of_reader`), at-least-once, opaque bytes, TTL (default 14 days, at most 30), quotas; the operator sees ciphertext only | `mailbox-memory` (built: the drop client over an in-process `DropService`), `mailbox-drop` (built: the drop client over HTTP(S) to `drop-http`, served by `apps/drop`); the rules live once, in the `baton-drop` library; applications may add their own (Peleda could use a prefix in its bucket); later `mailbox-matrix`, `mailbox-simplex` |
| `baton-wake::Wake` | best-effort "connect now" carrying at most 256 sealed bytes; `listen` for the next one | `wake-mailbox` (built; over any `Mailbox`, a per-node wake box); applications supply platform push; later `wake-nostr` |
| `baton-lease::Leases`, `Liveness` | linearizable compare-and-swap per lease key, tokens only grow; liveness and node profiles with priority (moved from Skein's `skein-ownership`, including `preferred_owner`) | `lease-cas` with `CasLeases` and `CasLiveness` (over `baton-state`'s `StateStore`, which the consumer implements: Skein's `ControlStore` does, over S3, files or memory; over `baton-state-memory` with a wall-clock fence floor it serves one process), `lease-quorum` (CASPaxos among nodes), `liveness-mesh` (heartbeats over `baton-mesh`), `lease-server` (built: a server node runs `CasLeases` and `CasLiveness` over its own store and serves them over link protocol `lease` to `RemoteLeases` and `RemoteLiveness`; it is the one liveness observer for its clients) |
| `baton-keys::KeyAgreement` | hands every authorized node, and the recovery keys, the resource key of each epoch, and nobody else | `keys-boxes` (HPKE key boxes in the group log), later `keys-mls` (OpenMLS) |
| `baton-signal::Signal` | publish/subscribe and expiring values within a group, no delivery guarantee (replaces Skein's `Ephemeral`) | `signal-local`, `signal-mesh`; later `signal-nats`, `signal-redis` for server deployments |
| `baton-fetch::Source` | fetch an object by content id from somewhere outside the group's nodes | **application** (Peleda: S3 directly or through presigned URLs) |

Every contract has a conformance suite behind its `testing` feature, including the hostile cases: a frame from a non-member, a replayed frame, a stale group head, a lease from a node without `lead`, a command from a revoked node, a `StateStore` that loses a write it acknowledged.

## State without storage

Baton holds state in memory and persists through `StateStore`. What it persists, and why:

| State | Key in `StateStore` | Why it must survive a restart |
| --- | --- | --- |
| group log entries and the highest verified head | `group/{seq}`, `group/head` | membership and rights; rollback detection |
| key boxes addressed to this node, and the node's view of epochs | `keys/{resource}/{epoch}` | opening resource keys |
| replay state: highest frame sequence accepted per sender | `mesh/seq/{node}` | refusing replays after a restart (with the clock-based starting counter the app already uses as a second line) |
| CASPaxos acceptor promises and accepted registers | `quorum/{key}` | two leaders could exist if a voter forgets a promise; written **before** each answer |
| pending outgoing commands | `cmd/out/{id}` | a command issued while offline is not lost |

Secrets (node keys, opened resource keys, member key where present) go through `SecretStore`, never `StateStore`.

Everything Baton writes to `StateStore` that another node or a fresh install might need is self-authenticating: group entries are signed, key boxes are HPKE ciphertexts addressed to known keys. The application can therefore keep it anywhere (a local database, its bucket, both) without trusting that place for anything but availability.

**Export and restore.** `node.export()` streams every durable, shareable piece of group state (the group log from genesis or a signed checkpoint, all key boxes including those sealed to recovery keys); `Builder::restore(stream)` accepts it. The application stores exports where it keeps its own data (Peleda: next to Skein's journal), and `StateStore` change events let it store new pieces as they appear.

## Group log

A hash-chained sequence of entries, each signed by a node whose member holds the right role at that point:

- `Genesis { group, founder member key, founder node cert, group recovery public keys }`
- `MemberAdded { member key, recovery public keys, roles }`, `MemberRemoved`
- `NodeCertified { node signing key, node encryption key, class, member, expires }`, `NodeRevoked`
- `ResourceCreated { resource id, kind, command classes, admins }`, `ResourceDeleted`
- `Granted { resource, principal (member or node), capabilities }`, `RevokedGrant`
- `KeyEpoch { resource, epoch, boxes }` (with `keys-boxes`; with `keys-mls`, the MLS epoch it maps to)
- `RecoveryRotated { member or group, new recovery public keys }`
- `Checkpoint { seq, hash }` signed by a recovery key, optionally, to anchor restores

Ordering: entries are appended through the group's arbiter (the same compare-and-swap as leases, key `group/head`), so two admins cannot append conflicting entries. Every node verifies every entry from genesis (or from a recovery-signed checkpoint) and never moves backwards; two different entries at the same sequence are a fork (SECURITY.md). The app's current roster is the special case of one member with only `NodeCertified` and `NodeRevoked` entries.

The policy (who to add, what to grant, when to rotate) is the application's: it calls `node.group().grant(...)`, `.revoke_node(...)`, `.rotate(resource)`. Baton builds, signs, checks and distributes the entries and the key boxes.

## Leases

A lease is the right to do the work of one key now: a resource (`res/{id}`) or a job (`job/{id}`). The model follows Kubernetes `coordination.k8s.io/v1` Lease objects (holder identity, lease duration, acquire and renew times, transitions) with three additions: a **fencing token** that grows on every change of holder, a **priority class**, and **preemption**. Fencing is the addition that matters most: client-go's own leader election says it does not guarantee that only one client acts as leader ([client-go leaderelection](https://pkg.go.dev/k8s.io/client-go/tools/leaderelection), [Kubernetes Leases](https://kubernetes.io/docs/concepts/architecture/leases/)).

### The lease record

```
LeaseRecord {
  v: 1, holder: Option<{ node, class }>, fence: u64,
  takeover: Option<{ node, class }>,   // a stronger node waiting while a holder is in place
  reserved: Option<{ node, class }>,   // after a handover, who the released lease is for
}
```

Implemented in `baton_lease::record` as a pure state machine that every implementation applies. Leases carry no duration of their own: whether a holder is gone is decided by node liveness (heartbeats), one time-to-live for the whole group. Records will be signed by their holder once `baton-group` exists (phase 4).

### Who should hold it

`preferred(group, key, nodes)` is computed identically on every node from the liveness view:

1. Only nodes that may hold it: `lead` on the resource (or the job's kind, phase 4), not revoked, and able to run work now (`can_run`; a phone in the background cannot), weight above zero.
2. Lowest class wins: `server` < `desktop` < `phone`. A `blind` node never leads.
3. Within a class, weighted rendezvous hashing over the node profile's weight (Skein's `preferred_owner`, kept), so resources spread over several servers or desktops and few move when one joins or leaves.

### Acquire, renew, release

- **Acquire.** A node that sees no live holder takes the key with a higher token. A node that sees a live holder of a lower class requests a takeover. A node never takes a lease from a live holder, whatever its class.
- **Liveness is judged on the observer's own clock.** Every heartbeat is a new write of the node's record; an observer counts the node alive while the record's version has changed within the time-to-live of the observer's clock (a monotonic timer). The timestamp inside a heartbeat is for display only, so no node ever compares its clock with another's. An observer that starts fresh counts every heartbeat it sees for the first time as new, which only delays takeovers. A node that announces it cannot run counts as gone for leases.
- **Renew** is a heartbeat (and an `acquire` that returns the lease with any pending takeover). A holder stops all work for a key `ttl` minus a safety margin after the *start* of its last successful heartbeat: no observer can have seen that heartbeat before it started, so none treats the holder as gone before then. That is what keeps side effects storage cannot fence (SMTP) single.
- **Release** on shutdown or handover after finishing or abandoning in-flight work; the token is kept.
- **Tokens** are at least the wall clock in microseconds and above the stored token and anything this node granted, so a lost or rolled-back record, or a restart over a store that forgets, never lowers them.

### Priority and preemption

1. A higher-priority node must be continuously alive for a **stabilization period** (default 30 s for servers, 60 s for desktops; a runtime setting, phase 6) before asking, so a flapping server does not move work back and forth.
2. It writes `takeover = { node, class }` into the record by compare-and-swap; a stronger requester displaces a weaker one, an equal one is refused.
3. The holder sees it on its next renewal, reaches a safe point (the worker says when: Skein, for example, between commands), tells the worker to stop, and releases; the pending takeover becomes a reservation, so no weaker node grabs the key in the gap.
4. The requester acquires with a higher token; its worker continues from the application's own state (Skein from its cursor and journal head).
5. If the holder never releases, the requester waits until the holder is gone, and then the key still goes to the requester rather than to whoever calls first. It never steals a live lease.
6. A request or reservation that is not renewed or taken within one time-to-live (as each observer sees the record unchanged) stops blocking; a requester that is still interested asks again, which refreshes it.

Phones release when background time ends (and announce `can_run = false`); desktops release on sleep notifications; the group's time-to-live is a deployment setting (default 15 s).

### Arbiters by topology

| Topology | Arbiter |
| --- | --- |
| a store with compare-and-swap (Peleda and plain Skein servers with S3) | `lease-cas` over the consumer's `StateStore` (Skein's `ControlStore`); servers and devices use the same records, so there is one sequence of versions whoever is reachable; see TRANSPORTS.md for which S3 implementations really support conditional writes. Peleda pairs it with `liveness-mesh`, so heartbeats never reach the store and it is written only when a lease changes hands; plain Skein servers that share nothing but a bucket use `CasLiveness`, which bills a write per heartbeat and a listing per liveness answer |
| a server but no store | `lease-server`: the server node decides on its own clock, every request checked against the link-authenticated peer and the group's rights; while it is down, calls fail, holders stop `ttl` minus a margin after their last confirmed heartbeat and nothing new starts |
| devices only | `lease-quorum`: CASPaxos ([Rystsov 2018](https://arxiv.org/abs/1802.07000)) among nodes with `lead` on the key; a minority partition cannot lead |
| one device | `lease-cas` over `baton-state-memory` (the wall-clock token floor keeps tokens above earlier runs) |

The arbiter decides only ordering; every lease record is also signed by its holder and checked by readers, so an arbiter cannot invent a holder.

### Fencing is the application's to enforce

Baton hands the worker a `LeaseGuard` with the fence and a `lost()` future. Writes the worker makes to the application's storage must carry the fence, and that storage must refuse a fence lower than the highest it has seen (Skein's storage already does, with compare-and-swap on its heads, and with Baton's `FencingToken` type once Skein uses `baton-core`). Baton cannot fence storage it does not own; `LeaseGuard`'s documentation says so in its first paragraph, and rowboat's node layer passes the fence to Skein's storage. Side effects at external services (SMTP) are not fenceable at all; the holder's self-expiry narrows the window, and the application's claim-before-execute record (Skein's `WriteUncertain`) handles the rest.

## Commands

```
Command {
  id: ULID, resource, class, idempotency_key, issued_by: NodeId, group_head: (seq, hash),
  expires_at, payload (sealed under the resource epoch key), signature by issuing node
}
```

1. **Issue.** `node.command(resource, class, payload, idempotency_key)`. Baton seals, signs, persists it as pending and delivers it by the best path: live link to the leaseholder; otherwise the leaseholder's mailbox (or any `lead`-capable node's, since the next leaseholder will drain it); otherwise it waits.
2. **Check** on the receiving leaseholder: signature, issuer certified and not revoked, issuer (or its member) holds `command:{class}` on the resource at the leaseholder's group head, which must be at least the command's `group_head` (if not, the leaseholder catches up first). Refused commands get a signed refusal.
3. **Hand over at least once.** A command may reach the worker twice (two paths, a restart). Baton does not keep its own deduplication store: the worker's durable queue does it by idempotency key (Skein's `CommandQueue` already does), so it exists in one place.
4. **Hand to the worker** with the issuer's identity and the class. Whether the class may be repeated (`once` or `repeatable`, declared per resource kind in `ResourceCreated`) is passed along; recording a claim before executing a `once` command and reporting an uncertain outcome after a crash are the worker's job in the application's durable journal.
5. **Result.** The worker returns `Applied | Failed { reason } | Conflict { state } | Uncertain`; Baton signs it and delivers it to the issuer by the same paths. The issuer's handle resolves.

## Signals

Signals carry what is cheap to lose: "resource R has new events up to N", previews, presence ("open on the desktop, do not push to the phone"), soft locks, access tokens. Publish/subscribe and expiring values per group, sealed under the resource key when scoped to a resource or under the group's signal key otherwise; best-effort fan-out to reachable members (the app's `ephemeral-mesh`, moved). A signal is a hint, never a fact: applications act on it by fetching verified data, never by trusting its content (SECURITY.md, "A lying peer").

## Peer fetch

`node.fetch(resource, content_id)` returns bytes whose BLAKE3 hash is `content_id`, from the first source that has them:

1. local cache, if the application registered one;
2. reachable peers with `read` on the resource, in this order: the leaseholder, servers, desktops, connected phones (nobody is woken); at most two in parallel with a short timeout (default 1.5 s);
3. the application's `Source` (Peleda: S3 directly for nodes with credentials, through a presigned URL from the server otherwise, finally a `refetch` command to the leaseholder).

Peers serve only to nodes with `read` on the resource, over links (already encrypted end to end). Every answer is checked against `content_id` before it is returned; a peer that serves wrong bytes is skipped for that resource and reported. A small have-index (per resource, a Bloom filter of content ids a node holds) travels in heartbeats so the planner skips peers that certainly lack the object.

## Liveness and node profiles

Heartbeats over `baton-mesh` every few seconds to every reachable node, signed, accepted only for the sender itself, carrying the node profile: class, weight, whether it can run work now (foreground, on power, metered, battery saver), the have-index digest, and the node's highest group head (for fork detection). Liveness affects only who tries to lead; safety comes from the arbiter and fencing.

## Transports in the runtime

| Need | First choice | Then |
| --- | --- | --- |
| frames to a node that is up | `baton-mesh` over a live link | |
| command or result to a node that is down | drop mailbox | other mailboxes the application configured |
| get a sleeping node to connect | the application's platform push | drop long poll, Nostr (optional) |
| objects | peers over links | the application's `Source` |

Everything that crosses a transport is already sealed and signed; transports are never trusted for confidentiality or integrity.

## How an application plugs in

```rust
let node = baton_node::Builder::new(state_store, secret_store)
    .link(Arc::new(link_iroh))
    .arbiter(Arc::new(LeaseCas::new(skein_control_store.clone())))
    .mailbox(Arc::new(mailbox_drop))
    .wake(Arc::new(peleda_push))
    .source(Arc::new(SkeinBlobSource::new(skein_blob_store)))
    .resource_kind(ResourceKind {
        name: "peleda.mail-account",
        commands: &[("flag", Repeatable), ("move", Repeatable), ("delete", Once), ("send", Once)],
    })
    .worker("peleda.mail-account", Arc::new(SkeinWorker::new(engine_builder)))
    .build()
    .await?;
```

- **`Worker::run(lease: LeaseGuard, ctx)`** runs while this node holds the lease and returns promptly when `lease.lost()` fires. `ctx` gives the fence, the resource's data and secret keys (if this node has `lead`), the checked command stream, signals, and peer fetch.
- **Readers** (any node with `read`) get the resource's data key for sealing and opening their own application data, and the signal and fetch APIs.
- **Group administration** (`node.group()`): create resources, grant and revoke, pair and revoke nodes, rotate keys, export and restore.

In Peleda all of this is rowboat's node layer (`rowboat-*`), used by the app and by rowboat's headless server alike (PLAN.md, "One implementation of each thing"): Skein's `ControlStore` as `StateStore`, Skein's storage as `StateStore`, Skein's `BlobStore` as `Source`, `push` as `Wake`, a `SecretStore` passed in by the caller (the app's platform vault, the headless server's file store), Skein's engine as the worker.

## Restore from scratch

1. Fresh install. The person enters the recovery root (or combines shares) and the application's storage location.
2. The application reads Baton's exported state from its storage and calls `Builder::restore`.
3. Baton derives the recovery keys from the root, checks that their public parts are the ones in the group log, verifies the log from genesis (or from the newest recovery-signed checkpoint), and opens the key boxes sealed to the recovery keys.
4. The recovery signing key certifies the new node; the application asks whether to revoke every old node (default yes after a loss); every resource gets a new epoch.
5. The application's workers continue from their own state (Skein reads its journal and secrets from S3 with the restored resource keys).

## What `batond` is

The headless node for a server in the **blind role** (`apps/batond`, built). Its node is certified in each group as a `Blind` node; it holds no resource key and has no capability on any resource, so it never sees plaintext and cannot command anything. A server that does real work (Peleda's node fetching mail) is the application's binary built on `baton-node`, not `batond`. In one process it runs:

- **The group logs** of the groups it is configured for, each pinned to its genesis hash (`baton-group-server`, link protocol `group`): counting nodes (and per-group bootstrap peers while the log has never certified their key: the founding node before genesis, recovering devices) fetch entries after a position and push new signed entries, which `baton-group` checks at the head (`apply_fresh`) before they are stored with `put_if_absent`; forks, gaps, future and unauthorized entries are refused; a log is capped in entries and bytes with a reserve only revocations by admins, owners and recovery keys may use. Members verify everything they fetch and detect a stale or forked head with `GroupClient::sync`.
- **The lease arbiter** (`lease-server`) over its own store, authorized from the logs: a peer speaks only as its own node while it counts; it leases a key only with `Lead` on the key's resource and never as a blind node, and releases its own leases whatever its rights; its profile is capped at its certificate's class. A lease key is held on the resource it names, or on the part before the first `--` (`vault-1--sync` on `vault-1`) when that reading is unambiguous. A lowered lease time-to-live is honored at its old value until no holder can still believe it (`lease.ttl`).
- **The drop service** (`apps/drop`: `drop-http` over a redb store) for mailboxes and wake boxes.
- **iroh** (`link-iroh`) trusting exactly the counting nodes and bootstrap peers of its groups; the node key is a `0600` file in the data directory.
- **A redb `StateStore`** (`state.redb`) for group entries, lease records and heartbeats.

Deferred: an embedded iroh relay (run `iroh-relay` beside it) and sending wake-ups itself (members wake each other through `wake-mailbox` over its drop service).

## Open questions

See [QUESTIONS.md](QUESTIONS.md).
