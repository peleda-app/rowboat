# baton-identity

Who belongs to a person's mesh. Every node has an Ed25519 identity, and its `NodeId` is derived from the public key. The group's members are listed in a signed roster whose epoch only grows; pairing a device or revoking one produces the next roster, signed by a current member. Pairing runs over CPace, a PAKE that lets two devices agree on a key from a short secret without exposing it to offline guessing.

## API

- `Identity`: a key pair. `generate()`, `from_secret_bytes`/`secret_bytes` (zeroized) for the keyring, `public()`, `node_id()`, `sign(context, message)`. `Debug` shows only the node id.
- `PublicKey`: `node_id()` is the key in lowercase unpadded base32, 52 characters of `[a-z2-7]`, which fits the id rules of `baton-core` without truncation and maps back to exactly one key (`from_node_id`). `verify(context, message, signature)` uses strict Ed25519 verification. Every signature is bound to a context string, so a signature made for one protocol (rosters, frames, join requests) never verifies in another.
- `Roster`: group, epoch, sorted members, every key ever revoked, the signer and the signature.
  - `genesis(founder, group)`: epoch 1 with the founder alone.
  - `with_member(signer, key)` and `without_member(signer, key)`: the next roster, epoch + 1, signed by a member. A revoked key can never be added again; a member cannot revoke itself.
  - `verify()`: structure (members sorted, unique, non-empty, none revoked, signer a member) and signature.
  - `verify_successor(next)`: `next` verifies, has the same group, a higher epoch, is signed by a member of this roster that is not revoked, and keeps every revoked key revoked. Epochs may be skipped, so a node that was offline catches up in one step.
  - `quorum()`: the smallest majority of members.
- `RosterHandle`: the roster a node trusts, shared by its transport and its ownership. It only moves to a valid successor, so its epoch only grows; receiving the same roster again is a no-op.
- `Pake`, `PakeRole`, `PakeSession`: CPace for pairing, below.

## Pairing: CPace

`Pake` is CPace (`draft-irtf-cfrg-cpace`) over ristretto255 with SHA-512 (`curve25519-dalek`), in initiator-responder order:

1. Each side calls `Pake::start(role, password, channel, sid, ad)`: the generator is derived from `lv_cat(DSI, password, zero padding, channel, sid)` hashed to the group, the scalar comes from the operating system (`start_seeded` takes 64 bytes for test vectors), and `message()` is the 32-byte point to send.
2. `finish(peer_message, peer_ad)` refuses a non-canonical encoding, the identity and a shared point at the identity (`InvalidKey`), and derives the intermediate session key `ISK = SHA-512(lv_cat(DSI_ISK, sid, K) || lv_cat(Ya, ADa) || lv_cat(Yb, ADb))`.
3. Key confirmation, which CPace leaves to the application: each side sends `confirmation()` (HMAC-SHA512 of the ISK under `baton-pake-confirm-v1` and its role) and checks the peer's with `check_confirmation`, in constant time (`BadProof` on any mismatch). Only then is `derive(label)` used for further keys.

The application binds the channel (both endpoint keys) and the session (the invite) into `channel` and `sid`; rowboat's pairing protocol (`crates/group`) is the consumer. The HMAC invite that preceded it was removed when CPace landed (GROUP.md, B1).

## Threat model and limits

- **One guess per run.** An eavesdropper who records a whole run cannot test guesses offline; an active attacker learns whether one guess was right per run. Limiting runs (attempts per invite) is the application's job.
- **Not yet checked against the draft's test vectors.** The construction follows the draft; adding its published vectors is open (rowboat `docs/QUESTIONS.md`, 45).
- **Trust starts out of band.** The genesis roster is trusted because it was made on the person's own device; a joining device trusts what the PAKE-authenticated peer sends only after the person confirmed the fingerprint.
- **Revocation needs the new roster to spread.** A revoked device stays a member for every node that has not yet seen the roster that revoked it, and it can sign successors of the older roster for those nodes (a fork). Nodes should fetch the latest roster from several peers on reconnect; detecting forks (two different rosters with one epoch) is future work.
- **Revocation does not rotate the group key here.** Rotating the group key on revocation, as SECURITY.md requires, belongs to `baton-keys` (phase 4).
- Nothing in this crate logs, and `Debug` of `Identity`, `Pake` and `PakeSession` hides the secrets; the scalar and the ISK are zeroized on drop.
