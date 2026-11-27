# Security

Baton carries commands into resources that hold someone's mail, documents or files, for groups where some resources are shared (a team inbox, a family calendar) and others are private (each person's own mailbox). This document says what Baton protects, from whom, how, and what it cannot protect.

## Assets

1. **Authority**: issuing commands (send as someone, delete), leading a resource, changing the group (adding a node, granting a capability).
2. **Resource keys**: the data key that opens a resource's content (stored by the application) and the secret key that opens what the leaseholder needs to work (for Peleda: IMAP passwords, OAuth refresh tokens). Leaking a secret key is worse than leaking content: it reaches the external service, including the future.
3. **Traffic between nodes**: commands, results, signals, previews, fetched objects.
4. **Metadata**: which nodes exist, which resources exist, who talks to whom and when.
5. **Availability**: that work runs, and that a group can be restored after losing every device.

## Actors and trust

| Actor | Trusted for | Not trusted for |
| --- | --- | --- |
| A member's own node, uncompromised | everything its capabilities allow | anything beyond them |
| Another member's node | what that member was granted | private resources of others |
| A server doing real work (Peleda's node) | what grants naming its node allow, usually `lead` and `read` on the resources it fetches; its member's grants and role never reach it | resources it has no grant for; changing members, certificates or other nodes (it revokes only itself); granting unless a grant naming it gives `admin` |
| A server in the blind role (`batond`) | ordering (arbiter), relaying, holding mailboxes, waking | content, keys, authority: it holds no resource key and has no capability |
| The application's store behind `StateStore` (local disk, a bucket) | keeping what it was given | confidentiality, integrity, freshness (Baton's state is signed and sealed; rollback is detected where possible) |
| Relays, drop service, mailboxes, wake channels, push providers | delivering bytes eventually | everything else |
| The network | nothing | |

## Identities

- **Node keys.** Every node has an Ed25519 signing key and a hybrid encryption key (X25519 plus ML-KEM-768, used through HPKE), created on the node and kept in `SecretStore` (hardware-wrapped where the platform allows, as the app's `vault` does). The node id is the signing key, as in `mesh-identity` today, and equals its iroh endpoint id.
- **Member keys.** Every member has an Ed25519 member key that signs their node certificates. It lives on the member's desktops and phones with hardware-backed storage, never on servers. Separating member keys from node keys lets a team grant a capability to a person (all their devices, present and future) and lets a person revoke one stolen phone without involving anyone else.
- **Recovery keys** (see "Recovery from scratch"): derived from a recovery root kept offline; their public parts are in the group log.
- **Node certificates** (`NodeCertified`): signing key, encryption key, class (`server`, `desktop`, `phone`, `blind`), member, expiry. Servers and blind nodes get short expiries (90 days, renewed automatically by a member device), so a forgotten server drops out by itself.
- **Signatures are context-bound** (the existing `sign(context, message)`), so a signature for a frame never verifies as a lease, a command or a group entry.
- **Post-quantum status.** Key exchange on links and key boxes are hybrid post-quantum (X25519MLKEM768 in iroh's TLS, a hybrid KEM in HPKE), so recorded traffic and stored key boxes stay private against a future quantum computer. Signatures stay Ed25519: an attacker with a quantum computer *at the time* could forge certificates and commands. ML-DSA as a second signature on group log entries, node certificates and recovery checkpoints is planned once a vetted Rust implementation is in the dependency tree (QUESTIONS).

## Capabilities

Authority is recorded in the group log, not in bearer tokens. A leaseholder checks every command against its own verified view of the group log, so revocation does not wait for a token to expire. The application decides the policy (what to grant to whom); Baton records, verifies and enforces it.

### Group roles

| Role | May |
| --- | --- |
| `owner` | everything, including adding and removing admins and rotating the group recovery root |
| `admin` | add and remove members, certify nodes for any member (needed for servers), create resources, grant on resources they administer |
| `member` | certify and revoke their own nodes, create private resources, use what they were granted |

### Resource capabilities

| Capability | Grants | Key material received |
| --- | --- | --- |
| `read` | open the resource's data, receive its signals, fetch its objects from peers | the data key of each epoch since the grant (earlier epochs if the grant says so) |
| `command:{class}` | issue commands of that class (`command:flag`, `command:send`); requires `read` | nothing extra |
| `lead` | hold the lease, receive commands, use the resource's secrets | the data key and the separate **secret key** |
| `admin` | grant and revoke on this resource, rotate its keys, delete it | nothing extra (an admin who is not a reader cannot read) |

Grants name a **principal**: a member (all their certified desktops and phones, never their servers; a further class filter, "Alice's desktops, not her phones", is still open) or a single node (the team server, which holds only grants naming it). A private resource is one where only its creator holds anything. Defaults for Peleda: the creator of an account gets everything; a shared team mailbox gives `read` and the everyday command classes to each team member, `command:send` to those who may send as the box, `lead` to the team's server and, as a fallback, to its admins' desktops.

Splitting the **data key** from the **secret key** matters: a family member who reads the shared family inbox on their phone never receives its IMAP password or OAuth refresh token, because the phone has `read` but not `lead`.

### Sensitive operations need a second device

Operations whose abuse cannot be undone can require approval from a second node of the same member (or a second admin), configured per group: adding a node, granting `admin` or `lead`, rotating a recovery root, and application-declared command classes (Peleda: "delete more than N messages", "change forwarding"). The request is a group log proposal or a command marked `needs_approval`; it takes effect only when a second signature from an eligible node arrives. A single compromised device then cannot quietly add itself a friend or wipe a mailbox.

### Checks

- **Commands**: signature, node certified and not revoked, capability held at a group head at least as new as the one the command names, approval present where required.
- **Leases**: a lease record signed by a node without `lead` on that resource is ignored by every node, and its fence is never handed to a worker.
- **Group log entries**: checked by every node against the roles in force at the previous entry; an entry its signer could not make invalidates the log from that point for every honest node.
- **Peers serving data** check that the requester has `read` on the resource.

## Keys

| Key | Scope | Held by | Used for |
| --- | --- | --- | --- |
| node signing key | node | the node | link authentication, frames, leases, commands, results, group entries |
| node encryption key | node | the node | receiving key boxes and sealed mailbox messages |
| member key | member | the member's devices (not servers) | node certificates, member-level group entries |
| resource data key `D(r, e)` | resource, epoch | nodes with `read` or `lead`; recovery keys | the application seals its data for the resource with it (subkeys by purpose through HKDF, as `baton-seal` does); Baton seals command payloads and resource signals with it |
| resource secret key `S(r, e)` | resource, epoch | nodes with `lead`; recovery keys | the application seals the resource's secrets with it |
| group signal key | group, epoch | every certified node | sealing signals not scoped to a resource (presence, liveness extras); rotated on every node revocation |
| recovery keys | member or group | offline only (the recovery root) | opening boxes after losing every device, certifying a new node, signing checkpoints |

### Distribution

`keys-boxes` (phase 4): when an epoch starts, the admin or leaseholder starting it seals `D(r, e)` (and `S(r, e)` for `lead` holders) to each authorized node's encryption key, **and to the recovery public keys** of the members who may read the resource and of the group, with HPKE (RFC 9180) using a hybrid post-quantum KEM, and appends the boxes in a `KeyEpoch` entry. A newly certified node of an authorized member gets boxes from any node of that member, or any admin, that holds the key. One box is about 1.2 KB with ML-KEM-768; 30 nodes × 200 resources × 2 keys is about 14 MB in total, written incrementally.

`keys-mls` (phase 9): one MLS group (RFC 9420, OpenMLS) per resource, the epoch data key exported from the MLS key schedule. Logarithmic update cost, forward secrecy and post-compromise security; but MLS deletes old secrets by design, so history for new devices and recovery still needs boxes of past keys. See TRANSPORTS.md.

### Bring your own keys

An application may hand Baton a resource key per epoch itself and keep its own distribution. Baton then only uses it to seal command payloads and signals. In that mode Baton guarantees authentication of nodes and capability checks on commands, but not that only authorized nodes can read the resource: that becomes the application's responsibility, stated in its documentation.

### Rotation

A new epoch starts when a principal loses `read` or `lead`, when a node holding the keys is reported lost, when an admin asks, or by policy (default: never for data keys, yearly for secret keys). New sealing uses the new epoch at once. Old data is not re-sealed by default (a revoked node may already have copied it); the application may re-seal on an admin's request.

## Recovery from scratch

Goal: every device and server is lost; the person installs the application on a new device and gets everything back from what the application stored, with one secret.

- **Recovery root.** 32 random bytes per member (for their private resources) and one per group (for shared resources, held by the owners). When a group is created from an existing setup, today's single tenant master key in Skein's `keyring-local` is replaced by a recovery root: a fresh root is recommended, with the old key kept only until re-sealing finishes; reusing the old key as the root is the alternative (QUESTIONS 7). Either way it stops being a working key and leaves the server.
- **Derivation.** From the root, by HKDF with fixed labels: an X25519 key pair, an ML-KEM-768 key pair (deterministic key generation from a 64-byte seed), and an Ed25519 recovery signing key. The public parts go into the group log (`MemberAdded`, `Genesis`); the root never touches a working node except during recovery.
- **Every epoch is boxed to the recovery keys**, so nodes can seal new epochs for recovery without holding the root. This is why the recovery key must be asymmetric: a symmetric master key would have to sit on every node that starts an epoch, and any stolen phone would then hold the key to everything, including the future.
- **Keeping the root.** Printed recovery sheet, password manager, or Shamir shares (for example 2 of 3 among family members). The sheet can also carry the application's storage location and the sequence number and hash of the latest recovery checkpoint.
- **Restore** (ARCHITECTURE.md, "Restore from scratch"): verify the group log, open the recovery boxes, certify a new node with the recovery signing key, revoke the old nodes, start new epochs.
- **Rotating a root**: a new root, `RecoveryRotated`, and current epochs re-boxed to the new public keys. Old boxes stay openable by the old root until the application deletes them from its storage.

Limits:

- **The root is a key to everything its scope covers.** For one person that is the point. In a team, a group root held by the owner can open every shared resource but no member's private resource; members' private resources are covered only by their own roots. A family that wants one person able to recover everything boxes private resources to that person's root as well, by explicit choice.
- **A restore trusts the stored state for freshness.** A fresh device has no memory of the newest group head it saw, so a dishonest store could present an old group log (for example from before a revocation). Recovery checkpoints signed by the recovery key, the checkpoint number on the recovery sheet, revoking all old nodes and starting new epochs on restore narrow this; they do not remove it.
- **Losing the root and every device loses the data.** By design: nobody else can open it.

## Revocation, end to end

1. A member (for their own node) or an admin appends `NodeRevoked` or `MemberRemoved` (with a second approval where configured).
2. Every honest node that sees it refuses the revoked node on links (per-stream trust check plus `disconnect_untrusted`), drops its frames, ignores its leases and refuses its commands.
3. Every resource the revoked principal could read gets a new epoch.
4. If it held `lead` anywhere, its lease is ignored at once, the next preferred node takes over, and **the resource's secrets are considered leaked**: Baton marks the resource `secrets_rotation_required`, and the application asks the person to change the password or revoke the OAuth grant at the provider. Baton cannot do that part.
5. Credentials the application gave that node (storage access, for Peleda) are the application's to rotate; Baton reports which nodes were revoked.

A revocation takes effect on a node once it has seen the entry. Nodes fetch the group head from the arbiter and peers on every reconnect and before handing a `once` command to a worker.

## Forks and rollback

- **Rollback**: every node keeps the highest verified group head in `StateStore` and refuses older ones.
- **Forks**: two different signed entries at the same group sequence, or two lease records with the same fence and different holders, prove a fork. Nodes carry their highest group head in heartbeats, so a fork shown to two nodes is detected as soon as they talk; both then stop handing `once` commands to workers and alert the person.
- A group whose nodes never talk to each other directly and share only an arbiter cannot detect a forking arbiter. This is the residual risk for setups that arbitrate through a store alone (Peleda with S3 and no server).

## A lying peer: wrong answers and malicious payloads

A compromised node of the group is a member that lies. What it can send, and what stops it:

| It sends | Protection |
| --- | --- |
| a wrong object for a content id | every fetched object is checked against its BLAKE3 content id before Baton returns it; the peer is skipped and reported |
| a forged command, result, lease or group entry in someone else's name | signatures by the claimed node; link authentication; frames bound to sender, receiver and sequence |
| a replay of an old valid message | per-sender sequence numbers (persisted), destination binding, and the worker's idempotency keys for commands (Skein's `CommandQueue`) |
| a command beyond its rights | the leaseholder checks the class against the group log; second-device approval for sensitive classes |
| a false signal ("account is at N", a fake preview, fake presence) | signals are hints: applications must only act on them by fetching verified data. A fake preview can be *shown*; Peleda shows previews but records nothing until the journal entry arrives |
| malformed bytes meant to crash or exploit a parser | Baton parses only its own small formats, with size limits checked before signatures and fuzz targets for each; application payloads are opaque to Baton |
| content that is itself an attack (a hostile message body, a crafted attachment) | Baton cannot judge content. A peer is as untrusted as any sender on the internet: applications must treat every payload from a peer exactly like data from outside. For Peleda: peers exchange only original bytes verified by hash against the journal, and every node parses them through `rinse-mail` behind `rinse`'s sandbox walls (PLAN.md, "Repositories around Baton"); a node never accepts a peer's *derived* results (parsed documents, spam verdicts, thumbnails) as trusted |
| code | nothing in Baton transfers or runs code. Application updates come only from signed releases built in CI, never from peers |
| a flood | per-node rate limits and quotas on frames, commands and mailboxes; a node that floods is revoked |

What cannot be prevented: a compromised node with `lead` writes the resource's data. It can omit events, write false ones into the application's journal, and execute any command at the provider with the resource's secrets. Its entries are signed with its key, so they are attributable after the fact, and leaving `lead` to as few nodes as possible (the server, perhaps one desktop) keeps this small. A phone that reads but does not lead cannot do this.

## What a compromised party can and cannot do

### A compromised node (stolen unlocked phone, malware on a laptop, a hacked server that does real work)

Can: read every resource it holds `read` on (current and past epochs it received) until revoked; issue commands within its classes until revoked (sensitive ones only with a second approval); with `lead`, write the resource's data and use its secrets; try to take leases (only with `lead`, only when preferred or the holder is gone, with a fresh fence that is visible); lie as in the section above.

Cannot: read resources it has no grant on; command outside its classes; grant itself anything; certify nodes (member keys are not on servers; on a member's own device, a second approval is required where configured); read anything sealed after its revocation; impersonate another node; open recovery boxes.

### A server in the blind role

Can: stop arbitrating (leases expire, nothing new starts unless another arbiter is configured), as `lease-server` arbiter grant one lease to two nodes or withhold it (lease records are not yet signed by their holders, so ordering is trusted to the arbiter; storage fencing still refuses the lower of two tokens), delay or drop mailbox messages and relayed traffic, show stale or forked group heads to nodes that cannot compare notes, learn metadata (which nodes exist, when they connect, resource ids, sizes and timing of messages).

Cannot: read content or keys, issue commands, take leases itself (it is blind and has no `lead`), change the group.

`lease-server` refuses, with an attack test for each: a request naming another node than the link-authenticated peer (acquire, takeover, release, heartbeat; a release needs nothing more, so a holder that lost `Lead` can still give its lease up), a peer the authorization callback does not know or no longer allows (checked on every request, so a revocation applies to the next request on an open stream), a key or group the peer may not use, a profile with a stronger class than allowed, oversized, empty, malformed and wrong-version frames; it bounds slow and idle streams by timeouts and streams per peer and in total. Liveness is judged on the server's clock alone; every heartbeat reply states the time-to-live the holder stops by, and after a restart with a shorter one the server judges with the longer one a holder may still believe (batond keeps it in `lease.ttl`), so two nodes never act at once (tested).

`batond` authorizes from the group logs it holds, with an attack test for each: a revoked node is refused on every protocol at its next request and its lease lapses; blind nodes get no heartbeat and no lease whatever profile they claim; a node without `Lead` on a key's resource is refused until a grant, and a key maps to at most one resource, never ambiguously (`vault---sync` maps to none); a bootstrap peer is admitted only while the log has never certified its key, so a revoked founder is refused on `group` and by the link; a profile stronger than the certificate's class is refused; strangers cannot open a stream. Its group server refuses forged signatures, non-canonical bytes, entries at a held position (fork, stale head), gaps, entries from the future, signers without the right, another genesis of the same group id, pushes and reads by peers that neither count in the group nor are its bootstrap peers, entries of a revoked node built on the current head also when a member relays them, and oversized, malformed and slow frames; a replayed entry changes nothing; a failed write leaves the log as stored, also when the push was cancelled while writing. A log is capped in entries and bytes, with a reserve only revocations by admins, owners and recovery keys may use, so a member filling the log cannot block its own revocation; pushes are rate limited per peer. batond's node gets no key box and no capability (tested), and it keeps no secret besides its own node key.

### A server doing real work

Everything a compromised node can do, for the resources it leads; for Peleda in connected mode, every account it fetches, with their credentials. This is inherent: a server that fetches mail must see it, and Peleda states this trust level plainly.

### The application's store behind `StateStore`

Can: lose or delete Baton's state (availability; recovery then depends on another copy), present an old copy (detected by nodes that saw newer; not by a fresh restore, see Recovery limits), learn group size, resource ids and key-epoch activity from Baton's records.

Cannot: read keys (boxes are sealed to node and recovery keys), forge entries, grant anything.

### Relays, drop, mailboxes, Nostr relays, push providers

Can: drop, delay or reorder; learn who talks to whom and when.

Cannot: read or alter anything; replay.

The drop service itself refuses unsigned and forged requests, requests stamped more than five minutes from its clock, repeated nonces, writes by keys not among a box's writers (also right after a writer is removed), reads by anyone but the box's reader, creations without a valid token or proof of work, and creations of a box id not derived from the creator's reader key (so an expired wake box cannot be squatted). One box holds at most a share of the replay cache, so one box's requests never make others busy, and boxes made by proof of work or on an open service get small quotas and a bounded share of the store. Its replay cache lives in memory, so after a restart a request from the last five minutes could be accepted once more; that is harmless by construction (a duplicate message within at-least-once delivery, an idempotent ack or delete, and writer changes are versioned). Box keys are derived per box, so the operator cannot link a group's boxes by key, but it sees each box's traffic pattern and the clients' addresses. Over HTTP (`drop-http`) the service bounds what one connection or client can hold: body size, header, handshake and body timeouts, a write timeout for clients that never read, connection caps in all and per client, an in-flight cap long polls do not count against, a per-client rate, in-flight and poll limit with a bounded table, and long polls capped in number (in all, per client, per box) and time; a handler deadline answers `504` (outcome unknown), never a status that claims the request was not executed; it logs no box ids, keys or addresses (a test captures every log event to check). The `drop` service refuses to start with a token file or TLS key readable by group or others and keeps its store `0600` in a `0700` directory.

### A malicious member of a shared resource

Can: read the shared resource, issue the commands they were granted, copy data before being removed.

Cannot: read other members' private resources, escalate, lead without `lead`, read new data after removal.

## Metadata

Baton hides application names (pseudonymous resource ids) and content. It does not hide from relays and the blind server which nodes connect when, or from the application's store how many resources and epochs exist. Transports with stronger metadata protection (SimpleX-style queues) can carry mailbox traffic where a group wants it.

## Implementation rules that follow

- Check, then commit: sequence numbers, fences and heads are recorded only after every check passes, including the caller's expected sender (the known flaw in `mesh-transport`'s `Opener::open` is fixed when it moves here).
- Every signed structure has a version byte, a context string, size limits checked before signature verification, and a fuzz target.
- Conformance suites contain the attacks in this document as tests.
- No secret in logs, metrics or errors; resource and group names never in logs.
- Dependencies vetted with `cargo deny` and pinned; cryptography from RustCrypto, aws-lc-rs (through rustls) and, for MLS, OpenMLS.
- An external audit (phase 10) before anything is called stable.

## Open questions

See [QUESTIONS.md](QUESTIONS.md).
