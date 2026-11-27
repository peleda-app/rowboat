# rowboat-group

The node's group (GROUP.md, phases 2 and 3; wave 1, part 1): membership through Baton's group log, pairing by invite over CPace with fingerprint confirmation, revocation with key rotation, and the group log exchange between nodes. A library: storage arrives as a `baton_state::StateStore` (the node's control records), transports as `rowboat_endpoint::Endpoints` and `baton_link::Link`, the person's answer as `pairing::Confirm`, the time as a `Now`.

## Membership

`Membership` is the node's verified copy of the `baton_group::GroupLog`, stored entry by entry at `group/{seq}` (`baton_group::store`) with what the node remembers about peers at `peers/{node id}` (their link hint and the label they gave when pairing here).

- `found` (genesis with this node as founder, needs a member key), `open` (verify the stored log from genesis; `NotFound` when there is none, `Unverified` when this node was never certified in it), `adopt` (store a log received when joining).
- The log only moves forward. `apply_remote` takes entries from peers: entries already held must be identical (else `Fork`), new ones must continue the head and verify, with entry times at most 5 minutes ahead (`MAX_SKEW_MS`). Every append and every remote batch is applied to a copy, stored, and only then swapped in; nothing changes when any entry fails. Appends are serialized.
- `may(resource, capability)`, `counts(node)`, `nodes()`, `counting_peers()`: answers from the log at the current time, empty for a node that does not count (revoked, expired, its member removed).
- `trust()`: a `baton_link::Trust` that admits exactly the nodes counting at each call (never this node itself), so a revocation or an expiry applies to the next stream.
- `certify(cert)`: `CertifyNode` plus `ShareEpoch` of every epoch of every resource the new node may read that this node can open. `ensure_resource(resource, classes)`: `CreateResource`, a `Grant` of read, lead, admin and the command classes to this node's member, and the first `KeyEpoch`, each only when missing. `revoke(node)`: `RevokeNode`, then a new epoch for every resource this node may rotate that needs one; returns the resources whose secrets must change (the revoked node could lead them). `renew_if_due(term, window)`: `RenewNode` with the member key in the certificate's last `window`.
- `subscribe()`: `Changed { head }` after every move, `Revoked` once when the log revokes this node (the hook for the app's "lost or stolen" path).

## Invites (`invite`)

- `Invite`: the QR payload, `peleda-pair:` and unpadded base32 of a postcard body (version, kind, group and inviting node for device invites, 64-bit id, 128-bit secret, the pairing endpoint's key and hint, expiry). No host, so a camera app opening it sends nothing anywhere.
- `ShortCode`: 10 Crockford base32 characters shown `XX-XXXX-XXXX`; the first two pick the pending invite (10 bits), the other eight are the 40-bit secret. Parsing is case-insensitive, ignores `-` and spaces and folds `O` to `0`, `I` and `L` to `1`.
- `PairAddress`: `peleda-addr:` and base32 of the pairing endpoint's key and hint, which a server prints beside its short code.
- `WireHint`: at most 8 direct addresses and a relay URL that passes `RelayUrl::new`.

Every decoder caps its input (2,048 characters), never panics and has a fuzz target (`fuzz/` `group_codes`).

## Pairing (`pairing`)

A joiner dials the inviter's `PairingEndpoint` (an ephemeral identity that accepts anyone on the `pair` protocol, `peleda/pair/1` on iroh).

1. `Hello` (version, which invite, CPace message) → `Reply` (CPace message, the responder's confirmation tag) → `Confirmation` (the initiator's tag). The CPace channel identifier holds both endpoint keys, the session id the invite reference and the group, so a relay swapping endpoints or a QR edited to another group fails the key confirmation.
2. Everything after is sealed (`baton-seal`, one key per direction derived from the PAKE session, the message's sequence number in the context): replayed, reordered, reflected or flipped messages do not open.
3. The candidate sends its node key, KEM key, class, label and hint; the certifier answers with the terms (group, genesis hash, its node, the member key, the expiry: 400 days for desktops and phones, 90 for servers); the candidate signs them (`NodeCert::node_proof`).
4. Both sides compute the fingerprint, six digits in two groups from a keyed hash (key from the PAKE session) of both node keys and the group, and ask their `Confirm`. The certifier must ask the person; a refusal or no answer within 2 minutes adds nobody.
5. The certifier appends `CertifyNode` and the shared epochs, sends a desktop or phone its member key boxed to its KEM key (HPKE, bound to the group and the node), and sends the whole log. The candidate verifies it from genesis and checks the group, the genesis hash, that the certifier and itself count as nodes of the member named in the terms, its own KEM key and class, and that the member key opens to that member.

Who certifies follows the invite: a device invite is made by the certifier and joined by the candidate; a server invite is made by the server (the candidate, which may refuse terms of any group but the one its tenant is bound to) and answered by the member device that adopts it. A joiner claiming a class the invite does not allow, a key the group ever certified (a revoked node trying again), or a malformed message is refused.

`Inviter` guarantees: an invite is used at most once (a passed key confirmation consumes it); a QR attempt that fails the key confirmation kills the invite, a short code allows three failures in total; an attempt against an expired, used, cancelled or unknown invite runs a decoy PAKE and looks to the joiner exactly like a wrong code, costing the real invite nothing; only a valid PAKE message followed by a failed key confirmation counts as a failure (an invalid point leaves the invite untouched); at most two handshakes at once (a stream waits at most 10 s for a slot, then is dropped unanswered) and eight pending invites; every message before the key confirmation is at most 8 KiB and has 10 seconds; a failed handshake keeps its slot one second longer; each step after the key confirmation has 60 seconds; a candidate verifies the log entry by entry and takes at most 100,000 entries and 64 MiB. A server is certified with no member authority (Baton): `Certifier::server_grants` and `Membership::grant_server` give it read and lead on the chosen resources and share only their epochs. Pending invites live in memory only.

## Exchange (`sync`)

`serve` answers and `exchange_with` / `announce` open the `group` protocol (`peleda/group/1`) on the node's link: both sides offer their head, genesis and hint; the side ahead sends the missing entries (at most 4,096 per exchange) and the receiver acknowledges once it stored them. Different groups or genesis hashes, or different entries at a position both hold, are `Synced::Forked` and change nothing. Only nodes the log counts reach this protocol at all (the link's trust), so a revoked node or a node of another group is refused before a byte is read.

## Wire (`wire`)

The frames every link protocol of the node shares (also `rowboat-sync`'s): a 4-byte big-endian length capped by the caller, a time limit per frame, and a postcard message with exactly one accepted encoding (`decode` re-encodes and compares). `Membership` also answers `resources()` (every resource of the log), `node_may(node, resource, capability)` (another node's capability now) and `was_certified(node)` (ever certified, revoked included).

## Revocation notices (`notice`)

`serve` answers and `ask` opens the `revoked` protocol (`peleda/revoked/1`). `Membership::trust` admits a node the log revoked on this protocol only (`Trust::allows_on`); counting nodes reach it too and are told `NotRevoked`. The asker offers its head; the answer is the log entries from that head up to and including the `RevokeNode` entry naming it (at most one batch), `Unknown` when the head is not in the answering log, or nothing more when the asker already holds its revocation. The asker stages every entry against a working copy of its log and applies them through `apply_remote` only if all verify and chain; `Membership` then raises `Revoked`. A notice never carries entries after the revocation. Wipe commands are not carried yet. `Membership::class_of` gives a counting node's certificate class and `is_revoked_node` whether the log revoked a node.

## Not yet

Trust for the mesh, quorum and liveness from the log (B2), the server's tenant binding store and CLI (wave 2), short codes between devices without a known address (question 46).

## Tests

Membership (founding, reopening, resources, certification with shared epochs, revocation with rotation and the `Revoked` hook, forged entries, a shorter, forked or future-dated log, expiry and renewal, peers), pairing over `rowboat-endpoint-memory` and over iroh on loopback (a device by QR, a third node invited by the second, a server adopted by short code; attacks: a wrong secret kills a QR invite, three wrong short codes kill a server invite, expired, used and unknown invites look alike, a rejected fingerprint on either side, a wrong class either way, a bound server refusing another group, a revoked node pairing again, a QR edited to another group, the caps), and the exchange (three nodes following and spreading a revocation in memory and over iroh, a revoked node and a node of another group refused on the link, a fork changing nothing, hostile peers sending flipped, garbage, truncated, missing and replayed entries, each with its exact error on a paused clock, entries that do not continue the log dropped at the first, a batch over 16 MiB dropped, a long log sent in batches under the cap), an adopted server holding only its grants and refused every member-level entry, invalid PAKE points never burning an invite, the fail delay, and a candidate refusing a log over its byte cap. Revocation notices: a revoked node learns once (a repeat takes nothing, nothing after the revocation is carried, every other protocol still refuses it), a stranger cannot ask, and flipped, unchained or foreign entries change nothing.
