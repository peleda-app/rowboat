# rowboat group, phases 2 and 3

The implementation spec of the node layer for [PLAN.md](PLAN.md) phases 2 (group and handover) and 3 (server): a person's nodes (desktops, phones and servers) form one Baton group, pair by QR code or short code, replicate each account's journal, send commands to whichever node owns an account, hand ownership to the strongest node that is up, and a headless multi-tenant server joins a group as its server node. Phase 1, the node on one device, is [NODE.md](NODE.md); this document builds on it and changes nothing it promises to the app.

Baton already implements groups, keys, pairing, leases, commands, peer fetch, signals, mailboxes and wake (`baton/docs/PLAN.md`, `ARCHITECTURE.md`, `SECURITY.md`, `TRANSPORTS.md`). This document does not restate those rules: it says which Baton pieces the node uses, what it puts into them, which gaps Baton must close first (generic changes, listed as **B1** to **B8**), which Skein changes are needed (**S1** to **S4**), and what is rowboat's own (the crates `rowboat-group` and `rowboat-sync`, the server `apps/rowboat`). The app side (screens, the platform vault, the QR scanner, the "Lost or stolen" flow) is `../app/docs/LINK.md` and `../app/docs/PLAN.md`; the app is not touched in wave 1.

Status: specified 2026-11-26. Wave 1, part 1 is built: B1 (CPace in `baton-identity`, the HMAC invite removed), `RenewNode` and two-part certificates in `baton-group`, the `rowboat-endpoint` contract with `-memory` and `-iroh`, `rowboat-group` (membership, invites, pairing by QR for devices and by QR or short code for servers, revocation with rotation, the group log exchange) and the node wired to it (`create_invite`, `accept_invite`, `confirm_pairing`, `cancel_invite`, `list_nodes`, `revoke_node`, the upgrade from phase 1, capability checks). Wave 1, part 2 is built: S1 (`Log::stage` and `Log::install`), S2 (`rowboat-sync`'s `PeerTier` over `baton-fetch`, with B5, a locator in fetch requests), `rowboat-sync` (head attestation, the head protocol, replication with blobs fetched before the head, the remote command bridge with its outbox and `cmdkey` records) and the node wired to it, so a second desktop reads and acts on mail the first node owns. Wave 2, part 1 is built: leases across nodes with the group's server as the one arbiter (`baton-lease-server` authorized from the group log), priority by class among the nodes holding `lead`, cooperative handover through Skein's new lease hooks, expiry and takeover, the holder's state of an account (record, credentials, cursors, queue) sealed to the account's secret key and moved with the lease (S3 and S4 as built), deposed writers dropping their tail, the server as an adopted node class, and B4 (revocation notices over a per-protocol trust in `baton-link`). Wave 2, part 2 is built: `apps/rowboat` (one node per tenant, binding to the adopting group's genesis, keys in `rowboat-keystore-file`, optional S3, the CLI, hand-back on shutdown, the container image; DECISIONS.md "wave 2, part 2 built", questions 74 to 78). The app's pairing surface (wave 3, 2026-11-27) is built: typed pairing errors, `inspect_invite`, `adopt_server` with the chosen accounts, `grant_to_server`, `rename_node`, `group_status`, LAN addresses in hints and the old group's data deleted after joining (DECISIONS.md, "the app's side of pairing"). Not built: B2 beyond the node's own link, B3 (the outbox is `rowboat-sync`'s, link only), `lease-cas` over a bucket and `lease-quorum`, the `GroupKeyring`, OAuth refresh and token revocation across nodes (the node offers no OAuth yet), the activity signal, wipe and self-lock, the server's admin through `node-settings` commands, `rowboat license` (L5b), the blob cache limits (question 5). Wave 2's defaults are in DECISIONS.md ("wave 2, part 1 built"), open items in QUESTIONS.md (69 to 73). Defaults taken without the maintainer are in [DECISIONS.md](DECISIONS.md) (2026-11-26, "group, pairing, replication and commands", "wave 1, part 1 built" and "wave 1, part 2 built"), open items in [QUESTIONS.md](QUESTIONS.md) (45 to 64).

## The pieces at a glance

| Concern | Baton (the one implementation) | What rowboat adds |
| --- | --- | --- |
| node identity, member key, recovery | `baton-identity`, `baton-keys`, `baton-group` | where the keys live (the app's keystore, the server's file secret store), first run, the upgrade from phase 1 |
| the group: members, node certificates, roles, capabilities, key epochs | `baton-group` (the signed group log), `group-server` | resource kinds and command classes for mail, the default grants, the policy for rotation |
| pairing | `baton-identity` invites, **B1** (PAKE) | the invite's carrier (QR, short code), the pairing endpoint, fingerprint confirmation, the server's first-run invite |
| links and frames | `baton-link-iroh`, `baton-mesh`, `mesh-link`, **B2** (trust from the group log) | relay and address configuration per profile, the `peleda` ALPN prefix |
| journal replication | `baton-fetch`, `baton-signal` | `rowboat-sync`: head announcements, the replica writer, the peer tier for Skein (**S1**, **S2**) |
| blobs | `baton-fetch` with a `Source` | the source chain: peers, then S3, then `refetch` to the leaseholder |
| commands | `baton-command` (issue, check, bus), **B3** (outbox and mailbox delivery) | `NodeApi` operations as command classes, the bridge into Skein's `CommandQueue`, results back to the app |
| leases | `baton-lease`, `lease-cas`, `lease-quorum`, `lease-server`, `liveness-mesh` | which arbiter for which topology, the fence into Skein's storage, credentials moving with the lease |
| offline delivery and wake | `baton-mailbox`, `baton-drop`, `mailbox-drop`, `baton-wake`, `wake-mailbox` | which drop service, push as `Wake` (phase 4) |
| sealing at rest | `baton-seal`, resource keys | Skein's `Keyring` over resource keys (**S3**), per-tenant sealing on the server |

## Node identity and the person's group

### Keys and where they live

Every node keeps, in its `SecretStore` (on devices the app's keystore through `rowboat-keystore`, class `Background`; on the server a file secret store with `0600` files):

- the node's Ed25519 signing key (`rowboat.identity`, as in phase 1; the node id is its public key and its iroh endpoint id);
- the node's X-Wing encryption key (`rowboat.node-kem`, new), which receives the key boxes of resource epochs;
- on desktops and phones only, the **member key** (`rowboat.member`), which signs node certificates. It never reaches a server (Baton SECURITY.md, "Identities"); every desktop and phone of the member holds a copy (question 48);
- the objects key, derived from the master key as in phase 1, for the node's own local storage.

The **recovery roots** (the owner's and the group's) are generated by the founding device and kept in its keystore only until the app has shown them to the person and the person confirmed writing them down (`rowboat.recovery-pending`); then they are deleted from the device. Until that confirmation the group has no offline recovery, and `node_info` says so (question 55). The app's screen for it is wave 2.

### The group log replaces the roster of one

Phase 1 writes a `baton-identity` genesis roster of one to `system/roster`. Phase 2 uses `baton-group`'s log instead, stored through the node's `StateStore` at `group/{seq}`:

- **New node, new group.** First run on a device that is not joining anything: `Genesis` with the owner member key, the founding node's certificate (its class from the profile), and both recovery public keys. The group id stays what phase 1 chose (`g` and 26 base32 characters), and it stays Skein's tenant id.
- **Upgrade from phase 1.** On the first start of a phase 2 build over a phase 1 directory, the node creates the member key and recovery roots, writes `Genesis` for the existing group id with its existing identity, moves every account's sealed password under the account's resource keys (see "Credentials") and deletes `system/roster`. The node record gets format 2. The upgrade is resumable: every step is idempotent and the record is written last.
- **Fork and rollback.** The node keeps the highest verified head in its `StateStore` and refuses older ones (`GroupLog::check_head`); a fork stops `once` commands and is reported to the app as `GroupForked` (an event with no content).

### Classes and certificates

| Class | Who | Certificate expiry | Renewed by |
| --- | --- | --- | --- |
| `server` | `apps/rowboat` for one tenant, a person's own server | 90 days (Baton's default for servers) | any member device online in the last 30 days of the term, automatically |
| `desktop` | the desktop app | 400 days | the node itself, with the member key, in its last 30 days |
| `phone` | iOS and Android | 400 days | the node itself, as above |
| `blind` | `batond` | 90 days | any member device |

Device terms are question 52. A certificate is `CertifyNode`, signed by the member key and by the node key (Baton). An expired node stops counting everywhere; a server that nobody renewed drops out by itself.

### Resources, capabilities and command classes

| Resource | Id | Kind | Grants by default |
| --- | --- | --- | --- |
| one per mail account | `acct-{account id}` | `peleda.mail-account` | the creator's member: `read`, `lead`, `admin` and every class below. Member principals cover all their desktops and phones, present and future; a server holds only what names it (`Principal::Node`): `read` and `lead` on the accounts moved to it |
| one per node | `node-{node id}` | `peleda.node` | the owner member: `read`, `admin`, classes `wipe`, `node-settings`, `license-*` (question 28's proposal); leased only by that node |
| one per group with object storage | `storage` | `peleda.storage` | the owner member: `read`, `lead` (the secret key holds the S3 credentials) |

Command classes of `peleda.mail-account` are the reserved classes of NODE.md ("Commands"), with Baton's repeat flag: `mail-account-add`, `mail-account-remove`, `mail-account-password`, `mail-send` and `mail-delete-forever` are `once`; flags, moves, archive, delete to trash, drafts (`mail-draft`), `mail-sync`, `mail-refetch` (not built) and `mail-account-update` are `repeatable`; `delete(.., permanent: true)` needs `mail-delete-forever`, delete to the trash `mail-delete` (built names, DECISIONS.md "review of wave 1"). Member grants never reach servers (Baton, `baton-group`): a server cannot act as its member, so it adds, removes, certifies and grants nothing and revokes only itself; the person's own setup grants everything to their member and read and lead on the moved accounts to the server.

Every resource has a key epoch with a data key and a secret key (Baton). For mail accounts the data key seals the journal, blobs and drafts in shared storage; the secret key seals credentials. Phones and desktops receive the secret key because they may lead.

## Pairing

### What Baton builds first

**B1. PAKE pairing.** `baton-identity`'s invite proves knowledge of the secret with an HMAC, which an eavesdropper can attack offline: fine for a 128-bit secret in a QR code, broken at once for a typed code. Baton gets a `pair` module: **CPace** (the CFRG's balanced PAKE, `draft-irtf-cfrg-cpace`) over ristretto255 with SHA-512, implemented in `baton-identity` on `curve25519-dalek` (already in the tree through `ed25519-dalek`) and checked against the draft's test vectors (question 45), followed by explicit key confirmation in both directions. The PAKE's session id binds the group (or none, for a server's first run), the invite id and both parties' ephemeral pairing keys. The existing HMAC invite stays only until B1 lands and is then removed. A failed confirmation burns one attempt of the invite (below); nothing about why it failed is told to the peer.

### The invite

An invite is made on the side that is already trusted (a member device inviting a new device, or a server inviting the app that will adopt it) and lives in memory until it is used up or expires (10 minutes). It carries:

| Field | QR code | Short code |
| --- | --- | --- |
| version, kind (`device` joins a group; `server` asks to be adopted) | yes | implied by where it is typed |
| group id (absent for a server's first run) | yes | no |
| invite id | 64 bits | the first 2 characters (which pending invite at the inviter) |
| secret | 128 bits | 8 characters, 40 bits |
| the pairing endpoint's public key and address hints (direct addresses, relay URLs) | yes | no: the joiner must know where to dial (the server's address, see below) |
| expiry | yes | the inviter's |

The QR code holds `peleda-pair:` followed by the encoded invite in base32 (no host, so a camera app that opens it sends nothing anywhere). The short code is 10 characters of Crockford base32 shown as `XX-XXXX-XXXX`, case-insensitive, `0/O` and `1/I/L` folded. An invite allows **three failed attempts in total**, then dies, so a typed code gives an online attacker at most three guesses of 2⁻⁴⁰; a QR invite dies on its first failure (a person scans a fresh one).

Short codes reach the inviter only where the joiner knows its address: the server's first run (the person enters the server's address, or Peleda's hosting gives it) and devices that see each other's address on the same network. Typing a code between two devices elsewhere needs a rendezvous through a drop mailbox (question 46); wave 1 builds QR codes everywhere and short codes for servers.

### The pairing endpoint

Pairing runs on a separate, short-lived iroh endpoint with an ephemeral key, ALPN `peleda/pair/1`, that accepts any peer while an invite is pending and closes when the invite is used up or expires. The node's own link never accepts a peer the group log does not list, so pairing opens no hole in it. The pairing endpoint caps attempts per invite (above; only a valid PAKE message followed by a failed key confirmation counts), concurrent handshakes (2, a stream waits at most 10 s for a slot), each unauthenticated handshake message (10 s), the size of every message (8 KiB) and the time of each step after the key confirmation (60 s); a failed handshake holds its slot one second longer, and streams are served concurrently. The candidate verifies the welcome log entry by entry and takes at most 100,000 entries and 64 MiB.

### The flow (a member device adds a device)

1. The inviting device shows the QR code. The new device scans it and dials the pairing endpoint.
2. CPace over the invite secret, then key confirmation; from here everything travels sealed under the PAKE's key.
3. The new device sends its node signing key, its encryption key, its class (`desktop` or `phone`), a display label (display only: it never raises anything, SEC-8), and its signature over the transcript and the `baton-node-cert-proof-v1` proof.
4. Both screens show the same **fingerprint**: six digits in two groups, derived from the transcript (both node keys, the group id and the PAKE session). The person confirms on the inviting device that it matches the device in their hand. Confirmation is required for every pairing, also by QR: it is what stops someone who photographed the QR code from joining in the person's place (question 51).
5. The inviting device appends `CertifyNode` (signed by the member key and carrying the new node's proof), boxes the member key to the new node's encryption key (HPKE, associated data bound to the group, the node and the purpose) and appends `ShareEpoch` for every resource the member may read or lead.
6. It sends the new device the group log (or, for a long log, the newest recovery-signed checkpoint and the entries after it). The new device verifies it from genesis, checks that the inviter named in the invite counts in it and that its own certificate is there, pins the genesis hash, opens its member key box and starts its link with trust from the log (B2).

### The server's first run (the app adopts a server)

A server has no member key and cannot certify anyone, so the direction is reversed: the server asks to be adopted.

1. `rowboat invite --tenant new` creates the tenant's directory and a `server` invite, and prints the QR code as text, the short code, the server's address and the server's node id fingerprint. The first start of an empty server prints the same once.
2. The app scans or types it, dials, runs CPace and key confirmation.
3. The server sends its node keys and its proof; both sides show the fingerprint; the person confirms in the app, and on the server console when the CLI runs interactively (`--yes` skips it for scripted installs, and the CLI then prints the fingerprint only).
4. The app (a member device, or the founding device creating the group right there if the person has none yet) appends `CertifyNode` for the server (class `server`, 90 days) and the grants the person chose (`read` and `lead` on the accounts to move, `lead` on `storage`, all to `Principal::Node(server)`; built: `Membership::grant_server`, the node passes every account its member created until the app's picker), shares only those epochs, and sends the log.
5. The server verifies the log, binds the tenant to the group's genesis hash and from then on serves that tenant to that group only. A tenant is bound to the first group that completes its invite; another invite for a bound tenant is refused, so a stolen invite cannot move a tenant to another group. Only the operator on the server's console can release the binding (`rowboat invite --tenant {id} --rebind`, for a person who lost every device and their recovery root), which question 56 leaves open.

`../app/docs/LINK.md` still describes the older direction (the app's key entering the server's roster); the app's document follows this one in wave 2.

### Revoking a device

From any member device: `RevokeNode` (Baton), then a new epoch for every resource the node could read (`needs_rotation`), then the resources it could lead are marked `secrets_rotation_required` and the app is told which accounts need their passwords changed or OAuth grants revoked (see "Lost device"). Links refuse the node on the next stream (B2), frames and commands from it are dropped, its lease records are ignored.

### Attack tests (pairing and membership)

Each is a test in the crate that owns the check (TEST-5):

- a wrong secret, a wrong short code and a replayed PAKE transcript fail; the third failed attempt kills the invite; a QR invite dies on the first; an expired invite and a used invite are refused; attempts against an invite id that does not exist look the same as wrong secrets;
- an eavesdropper who records a whole pairing cannot test guesses offline (the test runs a dictionary of every 4-digit code against a recorded transcript and finds no distinguisher);
- a relay or network attacker swapping the joiner's key, the inviter's log or the fingerprint inputs breaks confirmation;
- a joiner that claims class `server` from a member device's invite, or `desktop` from a server's invite, is refused; a joiner whose proof signature does not match its key is refused;
- a log from the inviter that does not contain the inviter, does not certify the joiner, belongs to another group or has a forged genesis is refused by the joiner;
- a server invite for a bound tenant is refused; a second group completing a server invite after the first does nothing;
- a revoked node is refused on every link protocol but `peleda/revoked/1`, its frames, commands, results, heartbeats and lease records are dropped, and it cannot open anything sealed under an epoch after its revocation;
- a node of another group with a valid certificate in its own group is refused on links, in commands and in fetch;
- oversized, truncated and non-canonical pairing messages are refused without panics (a fuzz target per decoder: invite, short code, pairing messages).

## Transports

| Need | First | Then |
| --- | --- | --- |
| node to node | iroh direct (hole punching), `X25519MLKEM768` required (`baton-link-iroh`) | through a relay: the person's own server's relay when the group has one, otherwise Peleda's iroh relay |
| commands and results to a node that is down | drop mailbox (B3) | wait in the issuer's outbox |
| waking a sleeping phone | platform push through `push` (phase 4) | `wake-mailbox` over the drop service |
| objects | peers over links | S3, then `refetch` |

**B2. Trust from the group log.** `baton-mesh`, `mesh-link`, `lease-quorum` and the link's `Trust` take a `RosterHandle` from `baton-identity`; the node's authority is the group log. Baton gets a membership view of a `GroupLog` (counting nodes now, their classes and encryption keys) that implements `Trust` and is what the mesh opener, the quorum and the liveness check against, moving only forward as the log does. `RosterHandle` stays as the one-member special case for tests.

**B4. Revocation notices.** A node that refuses a peer because the log revoked it answers on one link protocol only, `revoked` (ALPN `peleda/revoked/1` with Peleda's prefix), with the log suffix from the peer's last known head to the `RevokeNode` entry, plus any `wipe` command for that node. Only keys the log ever certified and then revoked may use it, and the answer is the same signed entries anyone could verify; no new authority is created.

Address hints travel in signed heartbeats (`liveness-mesh`); no DNS-based discovery is used by default (`baton-link-iroh`'s `Discovery::Disabled`). Relays are configured per group: the server's relay URL is part of its node record in the group (an application value in the server's heartbeats), Peleda's relay is the fallback the app ships. Tests run iroh with relays disabled or against a local relay on loopback.

## Journal replication

Every node with `read` on an account keeps a replica of its journal: events, previews, cursors, the input of `skein-view`. Only the leaseholder appends.

### Heads and attestation

Skein's journal is a hash chain: each segment names the BLAKE3 of the previous one, and the head names the segment ending at it (`JournalHead`: tenant, account, `seq`, `fence`, `tip`). rowboat implements Skein's `HeadAttestor` (`rowboat-sync`'s `NodeAttestor`): the leaseholder signs the head's `digest()` with its node key under the context `rowboat-head-v1`. A head verifies when:

1. the signature is by a node that counts in the verifier's group log and holds `lead` on `acct-{account}` there;
2. its fence is at least the highest fence the verifier has accepted for the account, and its `seq` is at least the highest `seq` under that fence;
3. its tip and chain verify (Skein).

A node that takes the lease re-attests the head it continues from with its own key and higher fence before appending, so heads of a revoked former owner do not have to stay verifiable. Two verified heads with the same `seq` and fence and different tips are a fork of the journal: the node stops following that account, keeps both heads as evidence and reports `JournalForked` (ids only).

### Who serves, how a replica moves on

1. (Built over the link protocol `head` until the mesh exists: an owner pushes `Announce`, readers `Ask`.) After every head write the leaseholder publishes the signed head as a signal on topic `head` scoped to the account resource (sealed under its data key, `baton-signal-mesh`). A signed head is about 300 bytes and verifies on its own; the signal stays a hint, so nothing is trusted that does not verify.
2. A replica that sees a newer verified head walks back from its tip to its own head and fetches the missing segments by hash through `baton-fetch`: content id = the BLAKE3 of the segment's bytes as `ObjectLog` hashes them (compressed, before the node's own at-rest sealing), which is the hash in `SegmentRef`. Peers are asked in Baton's order (leaseholder, servers, desktops, connected phones; nobody woken), then S3.
3. Every segment is checked by its hash on arrival (Baton) and against the chain (Skein) before it is written. The replica installs segments and the head verbatim (**S1**), so its storage is byte-for-byte the leaseholder's journal and it can continue the chain if it becomes leaseholder.
4. On reconnect, and every 5 minutes while linked, a replica asks the peers it can reach for their newest head (`peleda/head/1`, request and signed answer) to catch announcements it missed.

Peers serve journal segments only to nodes with `read` on that account (`baton-fetch`'s `authorize`, from the group log), and `LocalObjects` returns nothing for a segment of another account. `skein-view` follows the local replica exactly as it follows a local journal today.

**S1. Replica writes in Skein's storage.** Built as two calls (DECISIONS.md, "wave 1, part 2 built"): `Log::stage` stores each verified segment ahead of the head, `Log::install(signed_head)` commits them. The original form, `Log::install(signed_head, segments)`, writes segments a verifier already checked and moves the head, refusing anything that does not continue the local chain, a fence below the local head's, or a head that does not verify with the configured attestor. The engine never appends to an account through `install`, and `install` never runs while the node holds the account's lease.

**S2. Peer tier for segments.** `skein-storage-tiered` already reads blobs and segments by hash from untrusted `ReadTier`s; `rowboat-sync` supplies a `ReadTier` over `baton-fetch`. Snapshots stay local and are rebuilt from segments; a replica behind a compacted journal fetches the newest snapshot only once question 19 (snapshots bound to the chain) is answered, and until then refuses to follow past a compaction it has not seen and asks the leaseholder to keep segments for replicas (compaction waits for the slowest replica that confirmed within 14 days; question 54).

### Blobs

Blobs (bodies, attachments) are content-addressed by BLAKE3 already. A node that needs a blob it does not hold:

1. its local storage;
2. peers with `read`, in Baton's order, over `baton-fetch` (the peer opens its sealed copy and serves the blob over the link, the receiver checks the hash and seals it under its own key);
3. S3 through `skein-storage-tiered` (nodes with the `storage` secret key directly, others through a presigned URL from a node that has it);
4. a `mail-refetch` command to the leaseholder, which asks the provider again (Skein's `Refetch`), stores the blob and answers; then the node fetches it from the leaseholder as in step 2.

A peer that served wrong bytes is skipped for that resource (Baton's liar list) and the event is counted.

### Attack tests (replication)

- a peer serving a segment with one flipped byte, a segment of another account, a segment of the right account at the wrong position, a truncated segment, an oversized answer, or nothing at all: each is refused or times out and the next source is tried;
- a head signed by a node without `lead`, by a revoked node, by a node of another group, with a lower fence, with a lower `seq` under the same fence, or with a valid signature over another head: refused;
- two valid heads at one position (a deposed leaseholder still writing): `JournalForked`, nothing installed;
- a peer withholding the newest head while another serves it: the replica follows the newest verified one;
- a node without `read` on an account asks for its segments and gets "not here", the same answer as a miss;
- a replayed head signal from an hour ago changes nothing;
- `install` with a gap, with a segment whose `prev` hash does not match, or while holding the lease: refused.

## Commands from any node

The app calls `NodeApi` on its own node only. A mutating operation on an account this node does not lead becomes a Baton command; on the leaseholder it is handled in process as in phase 1.

1. **Issue.** (Built with a Skein command as payload and a derived queue id, DECISIONS.md "wave 1, part 2 built".) `rowboat-sync` encodes the request (the same encoding `rowboat-api` already has for the reserved classes; a fuzz target exists), picks an idempotency key (the overlay's command id, so a retry of one operation in the app never makes two), and calls `Command::issue` for `acct-{account}` with the current epoch's data key and a time-to-live of 24 hours (an hour for `mail-sync-now`, 10 minutes for `mail-draft-save`).
2. **Deliver.** The command goes into the node's durable outbox (**B3**) and over `baton/command/1` to the current leaseholder; while that fails, into the leaseholder's drop mailbox; it stays in the outbox until a valid result arrives or it expires. The overlay shows the expected state at once, as in phase 1.
3. **Check** on the leaseholder: `Command::check` against its group log (catching up first on `CatchUp`), plus the node's own rules: the class is one of the resource kind's, the decoded request validates exactly as a local call does (`rowboat_api::check`).
4. **Enqueue once.** (Built keyed by the derived queue id, `rowboat/cmdkeys/{account}/{queue id}`.) Baton delivers at least once; deduplication is Skein's `CommandQueue`. The key Baton requires, `(issuer, resource, idempotency key)`, maps to one queue id through a record `cmdkey/{BLAKE3(issuer, resource, key)}` written with put-if-absent in the account's control state; a second delivery finds the record and answers with the stored outcome, or waits for it. Records live two days, longer than any command's validity plus skew, so an expired replay can never re-run.
5. **Result.** Skein's outcome maps to Baton's `Applied`, `Failed { reason }` (reason as an error kind, never content), `Conflict { state }` or `Uncertain` (Skein's `WriteUncertain` for a `once` command interrupted after its claim). The leaseholder signs it (`CommandResult::sign`) and sends it over `baton/result/1`, or into the issuer's mailbox. The issuer checks it (`CommandResult::check`), drops its outbox entry and raises `CommandSettled` or `SendSettled` to the app exactly as phase 1 does.

A lease that moves while a command is pending is fine: the command goes to the new leaseholder (any `lead` node's mailbox reaches the next holder), and the `cmdkey` record travels with the journal's control state, so a command that the old owner already ran is answered, not run again.

**B3. Command outbox and mailbox delivery.** `baton-command` delivers over the mesh only. Baton adds a durable outbox (pending commands and awaited results in the `StateStore`), retries on reconnect, delivery into a `baton-mailbox` box of the leaseholder or of any `lead` node, and results back through the issuer's box. Commands and results are self-contained signed values, so a mailbox needs no replay counter of its own: expiry and the worker's deduplication cover replays.

### Attack tests (commands)

- a command from a node of another group, from a revoked node (also one revoked after it issued the command), from a reader without the class, for another resource, with a swapped class or issuer, expired, stamped more than 5 minutes ahead, against a forked head: refused with a signed refusal, never enqueued;
- the same command delivered twice, over the mesh and the mailbox, before and after a restart of the leaseholder, and after a handover: executed once, the same result each time;
- the same idempotency key from two different issuers: two commands (no shadowing);
- a request that passes Baton's check but fails `rowboat_api::check` (header injection in a draft, 1,001 targets, another account's message id): refused as in phase 1;
- a result signed by a reader, for another command, with another key, or replayed for a newer command: refused by the issuer; the outbox keeps waiting;
- a drop mailbox that reorders, duplicates or withholds: no command runs twice, and a withheld one expires visibly (`Failed { reason: expired }` raised locally).

## Leases, handover and credentials (wave 2)

### Priority and arbiters

One lease per account resource (`acct-{account}`) and one for each node's own resource. Priority is Baton's: server, then desktop, then phone; within a class, weighted rendezvous. Stabilization periods, takeover requests, reservations and expiry are Baton's (`ARCHITECTURE.md`, "Leases"); the worker's safe point is Skein's engine between commands.

| The group has | Arbiter |
| --- | --- |
| a server node | `lease-server` on the server, one per tenant over the tenant's `StateStore`; while it is silent, a fallback arbiter among the devices (below) |
| no server, an S3 bucket with conditional writes | `lease-cas` over Skein's `ControlStore` in the bucket, liveness through `liveness-mesh` (never `CasLiveness`) |
| no server, no bucket, three or more nodes that may lead | `lease-quorum` |
| no server, no bucket, two nodes | question 47 |
| one node | `lease-cas` over the local `StateStore`, as in phase 1 |

The fence goes into Skein's storage with every write (phase 1 already does this under its local lease). The holder stops all work `ttl` minus a margin after the start of its last successful heartbeat (Baton), which keeps SMTP sends single across a handover; Skein's claim-before-execute record covers the rest.

The phone leads only while the platform lets it run (foreground, or a background task it was granted); it announces `can_run = false` before it is suspended and releases. Question 7 (iOS background) stays open.

### When the server is silent (question 70, decided 2026-11-27)

A server's maintenance, crash or network trouble must not stop the person's mail on every device. When the group's server has been silent for the **takeover delay** (5 minutes by default, per profile, `NodeBuilder::fallback`), the devices take over the accounts it led, by the usual priority (desktop before phone) among the live nodes that hold `lead` and state; when it returns it first catches up, then takes them back through the normal cooperative handover.

- **Silence is each device's own observation.** A device counts the server silent when none of its lease calls got an answer for the takeover delay, or at once when it received the server's signed **leaving notice** and a probe right after it fails. While silent it probes the server every heartbeat; the server is back once it answered without a break for the **return delay** (a quarter of the takeover delay). A server that keeps coming and going (it went silent again within four takeover delays of coming back) doubles the return delay each time, up to eight times, so it cannot bounce leases (hysteresis).
- **The fallback arbiter** is the first device of a fixed order (counting desktops, then counting phones, each by key; never a server, a blind node or a node that does not count, so never a revoked one) that answers on the lease protocol; a device takes the role itself, running `baton-lease-server` on its link, only after waiting two heartbeats for each device ranked before it. It serves only while it considers the server silent; a device that sees the server never arbitrates. Its server starts with the grace of one time-to-live, so nothing granted under the server is still acting when it grants.
- **Fences never go back across arbiters** (question 79). Every acquire passes the node's own head fence as a floor (`Leases::acquire_above`: a new grant comes above it, a renewal below it is granted again above it), so a fallback token is above the server's last one and the returning server's next token above the fallback's. Every arbiter signs each grant (`rowboat-grant-v1`: kind `Server` or `Fallback`, arbiter, group, account, holder, fence) through Baton's generic `Endorse` hook of `lease-server`, and the holder carries it in every head it writes under that token (attestation version 2, the grant under the head signer's signature). A grant counts only from an arbiter that counts now and is of its kind's class; a grant fixes the head's fence, so a replayed grant can only make a head as old as the grant.
- **Which heads a node follows.** A head under a server's grant always (by fence, as before); a head without a grant only over one without (groups without a server, journals from before grants); a head under a fallback grant over a head no server granted, by a node that is itself in fallback, or on the server only when the fallback arbiter and the holder were both silent to it (gaps of at least half the takeover delay in their heartbeats, from the times its lease server records, across restarts; a gap that began before the server's lease server started overlaps the server's own downtime, which every device saw, so it counts only once it is a full takeover delay long, when the devices did fall back), the head's fence lies above its own record's lease, and its record names no other live holder; when it names the server itself, every device must have been silent (a server cut off from all of them). The server applies this rule whatever its own head (one it granted, one a fallback arbiter granted, or none yet), and a device that sees a live server never follows a fallback grant, even with no journal of the account yet. A device that claims the server is silent while the server and the other devices still talk therefore writes a journal nobody follows, and a live server's journal is never replaced by it.
- **No split brain on a journal.** A node that follows a fallback holder's head while it sees the server **yields** the account: it neither takes nor asks to take the lease and gives up what it holds, until the holder continues the journal under a grant of the server (or for three takeover delays, for a holder that never returns). The fallback holder announces its fallback heads to the server every tick from the moment the server answers its probes again, while it still arbitrates without it, so the server learns of them and yields before its own lease server grants again (one time-to-live after it started) rather than leading beside the holder; offers of the holder's state reach it as well, and taking a lease imports the newer offer. The fallback holder, once the server is back, is the only node it considers eligible until it continued its journal under a server grant (it takes the lease from the server with its head fence as floor); the server then takes the account over cooperatively, with the holder's offer. A leader that sees an admitted head above its own fence stops leading at once.
- **A cut-off server that kept writing** wrote a journal nobody followed: its tail is a fork in time, not in the journal. When it learns of the device's head it yields, drops its tail (the deposed-writer rule of wave 2) and follows the device's journal. What it fetched is the provider's state, which the device fetched too or fetches with its next sync. What can be lost or repeated:
  - **Lost from the journal, not from the provider:** the server's events after the device's takeover (new mail, flag changes it observed, results of commands it ran). The provider keeps the mail and the flags; the device's next sync records them. The outcome of a command the server ran in that window reaches its issuer only as what the provider shows (a sent message in Sent, a flag), not as a command result: the issuer's overlay expires as for a command that never settled.
  - **Not repeated: sends and other commands that cannot be repeated** (with the one window below). A device that takes over from a server that went silent (not one that announced leaving) presumes every queued command of the account that cannot be repeated (send, move, delete, append) started, through Skein's `presume_started`: each is reported `Uncertain` instead of being run, because the server may have run it after its last offer. Flag and label changes may run on both, which is harmless. A command a device delivered to the server without getting an answer (the server may have run it and gone silent) waits in that device's outbox; if that device itself takes the account over from the silent server, it settles the command `Uncertain` instead of running it (`Host::previous_owner_silent`; the record of delivery attempts is kept in memory, so a device restarted in between runs it, guarded only by the `cmdkey` records that travelled in offers). Delivered instead to another device that took over, it is run there unless that device holds its `cmdkey` record: the one window in which a command that cannot be repeated may run twice (a send issued from a third device to the server, run by the server, its answer lost in the cut, then redelivered to the device that took over; question 81).
  - **Uncertain:** those presumed sends; the person is told and may send again.
- **Graceful shutdown.** The server hands its accounts back (`set_can_run(false)`), stops arbitrating for good (nothing restarts its lease server, not even its own engine's calls while it shuts down), sends the leaving notice to every device (`Node::announce_leaving`) and stops. The notice says the server released everything, so devices then repeat even what cannot be repeated; it goes out only once the hand-back finished (`apps/rowboat` sends it only when every account it led is held by another node, and `announce_leaving` refuses while the node still leads an account or a worker of one runs), otherwise the devices fall back by silence and presume the queue started. Devices take over at once; the server, back, believes the devices that took over for four takeover delays after start (it left on its own, so their silence toward it proves nothing).
- **Attack tests** (`crates/node/tests/fallback.rs`, `crates/node/src/fallback/tests.rs`, `crates/sync`): a forged leaving notice (another key, a device's key, another group, moved, replayed after its five-minute window, bit-flipped, oversized, a revoked server's) and a genuine one replayed while the server answers change nothing; a device that claims the server is silent cannot take over under a live server's fence, nor after a server outage shorter than the takeover delay, nor through a device that just joined; a server that announced its leave never serves leases again; a send that was still running when an unfinished hand-back asked to announce the leave is never repeated; a fallback grant replayed after the server took the account back is refused and makes nothing yield; a revoked device's grants are refused (even those signed before) and it is never a candidate; grants swapped or stripped under a head's signature, for another fence, account, group or holder, a desktop's grant claiming to be a server's, all refused.

### Credentials move with the lease

- Account credentials (passwords, OAuth refresh tokens) are sealed with the account's **secret key** (Skein's `Keyring` over Baton resource keys, **S3**) and kept in the account's control state, which replicates like the journal's control records. Every node with `lead` can open them; readers cannot.
- Only the leaseholder refreshes an OAuth token. A rotated refresh token is sealed and written (fenced) **before** it is used for the first time, so the next leaseholder always finds the newest token; question 2 (a leaseholder that refreshed and died before writing) stays open.
- When a node loses `lead` (revocation, a grant removed), the account gets a new epoch, the credentials are re-sealed under it, and `secrets_rotation_required` is raised: the node may have kept them.

**S3. Account-scoped keyring over resource keys.** Skein's `Keyring` already takes an account scope; rowboat's `GroupKeyring` implements it with the account resource's epochs (data key for content, secret key for credentials), opening older epochs for older objects. The phase 1 master-key keyring stays for the objects key only.

**S4. Fenced control records.** The records that travel with a lease (credentials, cursors, `cmdkey`) are written with the lease's fence, and a write under a lower fence is refused, like journal appends.

## The headless server, `apps/rowboat` (wave 2)

One process per host serves many tenants. Each tenant is one group, and the server is that group's `server` node.

- **Identity.** One node identity per host, certified separately in each group it serves (as `batond` does); question 49. Built: one per tenant (DECISIONS.md, "wave 2, part 2 built").
- **Storage per tenant.** Skein's layout already separates tenants (`tenants/{group}/...`); every tenant's Baton state (`group/`, `lease/`, `nodes/`, outbox) lives under its own prefix of the same store. Files by default (`skein-storage-fs`), S3 when configured (`skein-storage-s3`, from the `storage` resource's sealed credentials, configured from the app).
- **Sealing.** Blobs and journal segments are sealed with the account's data key, credentials with its secret key (S3 above). The host keeps its node keys in a file secret store, separate from the data directory, so a copy of the data alone reveals nothing.
- **Inbound.** The existing `skein-server` listener only: push receivers and `GET /v1/health`. Everything else is iroh.
- **No management API.** The owner administers the server through Baton commands on the server's node resource (`node-settings`: storage, relay URL, leaving the group; `license-*` for L5b). Locally there is only a CLI for the operator: `rowboat invite` (first-run invites), `rowboat tenant list` and `rowboat tenant remove` (deletes a tenant's data; asks for confirmation), `rowboat license` (L5b), and `rowboat serve`. Built as `rowboat serve`, `invite`, `tenants`, `tenants remove` and `status` (`apps/rowboat/docs/README.md`).
- **Blob cache.** Without S3 the server keeps blobs as a cache with a size and age limit (question 5); an expired blob is fetched again with Skein's `refetch`.
- **Lease arbiter.** `lease-server` per tenant, authorized from that tenant's group log (`group-server`'s rules: a peer speaks only as a counting node of that group, leases only with `lead`).
- **Group log.** The server holds each tenant's log (`group-server`), so devices that are never online together still see one log.

## Hooks for "Continue on another device"

The app's mechanism is in `../app/docs/PLAN.md`; the node provides:

- **The `activity` signal**, `baton-signal` topic `activity` scoped to the group (sealed under the group's signal key, `baton-signal-mesh`), payload: account, mailbox, message or draft id, search id, scroll anchor, device node id, a time-to-live of at most 5 minutes. Ids only; never logged (SEC-3). `NodeApi` gets `publish_activity` and an `Activity` event.
- **Checks on receipt.** The sender counts in the group log; the signal is not expired by the receiver's clock (a time-to-live it never extends); every id exists in the receiver's own journal for an account the receiver reads; otherwise the signal is dropped silently. Publishing is off per device on request.
- **Drafts through the owner.** `mail-draft-save` (`repeatable`, idempotency key = draft id and revision) every few seconds while typing, so the other device opens the newest text from its replica.
- **Tests:** a revoked device's signal is dropped; an expired one never raises an event; a signal naming another group's or another account's ids is dropped; a replayed signal after its expiry is dropped; a draft round trip through the owner keeps text and cursor.

## Hooks for a lost or stolen device

The app's flow is in `../app/docs/PLAN.md` ("Lost or stolen device"); the node's side:

- **Revocation with key rotation.** `revoke_node(node)` on `NodeApi`: `RevokeNode`, new epochs for every resource the node could read, credentials re-sealed, and the list of accounts it led returned to the app (`secrets_rotation_required`). The member key is not rotated (a stolen copy alone cannot add a node: `CertifyNode` must also be signed by a node that counts); rekeying the member through the recovery root is question 50.
- **Signed `wipe`.** A `wipe` command on the target's node resource (`node-{id}`), issued by an owner or admin member's node, with a mode (`keys` or `keys-and-data`). The target checks it with `Command::check` against **its own** log, extended by the revocation notice it received (the entries must chain from its own head and verify), and only then calls the app's `on_wipe` hook. A device never wipes on anything that does not verify; nobody else (push gateway, relay, drop, Peleda) can make one.
- **Many paths.** The device learns of its revocation from the group log on any contact: a link refused with a revocation notice (B4), its drop mailbox (the wipe is placed there), a group log fetch from the server, and later the sealed wipe push (phase 4), which is never the only path.
- **OAuth revocation.** The next leaseholder of each account the revoked device led calls the provider's revocation endpoint for the refresh tokens it may have held, then re-authorizes if needed (wave 2, with OAuth accounts). For password accounts the app tells the person to change the password.
- **Membership confirmation and self-lock.** A node records the time (its own monotonic clock, persisted as elapsed time across restarts) of its last verified contact with the group: a log head newer than or equal to its own, fetched from another counting node or the server. `NodeApi` exposes `membership_status` (`confirmed`, days since, `locked`); after the configured silence (default 14 days, `0` turns it off; question 53) the node refuses reads and commands with `MembershipLocked` until it confirms again, and a node that confirms and finds itself revoked runs the wipe path.
- **Tests:** a `wipe` signed by a revoked node, by a node of another group, by a member without `admin` on the target's node resource, for another node, expired, or replayed after the target was re-paired: refused, `on_wipe` never called; a revocation notice whose entries do not chain from the device's head: ignored; the self-lock after the configured silence on a manual clock, lifted by a valid head, kept by a forged one.

## Crates

```
crates/
  group/   rowboat-group: the node's group log, first run and upgrade, pairing flows over B1
           (device and server invites, pairing endpoint, fingerprints), revocation and wipe hooks,
           membership confirmation; resource kinds and default grants
  sync/    rowboat-sync: NodeAttestor, head announcements and the head protocol, the replica writer
           over S1, the peer tier over baton-fetch, the blob source chain, commands to the leaseholder
           and results, the cmdkey bridge into Skein's CommandQueue, the activity signal
apps/
  rowboat/ the headless multi-tenant server (wave 2)
```

`rowboat-node` composes them: the desktop and test profiles get a link (`baton-link-iroh`, or `baton-link-memory` in tests), the mesh, signals over the mesh instead of `signal-local`, the group's keyring, and the sync tasks. `rowboat-api` gains the operations named above (pairing, devices, revocation, membership status, activity), each with its validation and its conformance case.

## Waves

**Wave 1 (rowboat only, the app untouched):**

1. Baton B1 (CPace pairing), B2 (trust from the group log), B3 (outbox and mailbox delivery), B4 (revocation notices), each with its suite and attack tests.
2. Skein S1 (replica install) and S2 (the peer tier wired for segments).
3. `rowboat-group`: group log, upgrade from phase 1, device pairing by QR, the server invite protocol (the server side as a library, so it is tested before the binary exists), revocation with rotation, `wipe` checking, membership confirmation.
4. `rowboat-sync`: attestation, replication, blob fetch from peers, commands and results with the `cmdkey` bridge, the activity signal.
5. `rowboat-node` and `rowboat-api` wired; end-to-end tests with two and three nodes over `baton-link-memory` and over iroh on loopback without relays: pair, replicate, command from the reader to the owner, revoke.

In wave 1 the owner of an account is still fixed: the node that added it holds its lease (phase 1's local `lease-cas`), and other nodes read and command. Nothing moves ownership.

**Wave 2:**

1. Leases across nodes with priority and cooperative handover (the arbiters above), credentials moving with the lease (S3, S4), phones as leaders within platform limits, OAuth refresh only by the leaseholder and token revocation for a lost device.
2. `apps/rowboat`: multi-tenant server, per-tenant storage and sealing, optional S3, the CLI, admin through the owner's commands, `lease-server` and `group-server` per tenant.
3. The app side in `../app`: pairing screens (QR shown and scanned, short code for servers, fingerprint confirmation), devices and "Lost or stolen", recovery root sheet, continue chips, `LINK.md` updated to this document.

## Tests across the wave

Besides the attack lists above: conformance suites of every Baton contract still pass with the new implementations; a load test (`tests/load`) with 3 nodes replicating 100,000 events and 1,000 commands from readers settling within 30 s (targets to calibrate on the first run); fuzz targets for every new decoder (invite, short code, pairing messages, head protocol, revocation notice, `cmdkey` record, activity payload); no wall-clock assertions (manual clocks and paused tokio time, as in `docs/DECISIONS.md` "no wall-clock thresholds in tests"); no test reaches beyond loopback.
