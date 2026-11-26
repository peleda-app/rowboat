# baton-identity

Who belongs to a person's mesh. Every node has an Ed25519 identity, and its `NodeId` is derived from the public key. The group's members are listed in a signed roster whose epoch only grows; pairing a device or revoking one produces the next roster, signed by a current member. New devices join with a one-time invite.

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
- `Inviter`, `Invite`, `JoinRequest`: pairing, below.

## Pairing

1. A member calls `Inviter::invite`, which draws a random 128-bit secret and a public invite id and keeps them in memory until the expiry (minutes). The `Invite` (group, inviter key, id, secret, expiry) is shown as a QR code.
2. The new device creates its identity and answers with `JoinRequest::new(invite, identity)`: its public key, an HMAC-SHA256 keyed by the secret over the group, the inviter key, the invite id and the device key, and the device's signature over all of it.
3. The member calls `Inviter::accept`: the invite must be pending and unexpired (any attempt naming it uses it up), the HMAC and the signature must verify, and the device must not be revoked. It returns the next roster with the device added, signed by the member.
4. The device checks that roster with `Invite::verify_roster` (signed by the inviter named in the invite, same group, lists the device) and trusts it as its first roster.

## Threat model and limits

- **The invite is a bearer secret.** Anyone who reads it before it expires and before the real device uses it can join instead. It must travel over a channel the person trusts: a QR code scanned in person, never a message through a server. A device that joins by mistake is removed by revocation.
- **No PAKE yet.** Because the proof is an HMAC, an eavesdropper who sees a join request can test guesses of the secret offline. With a 128-bit secret that is hopeless; a short code that a person types (6–8 digits) would be broken at once. Short codes need a PAKE (SPAKE2 or CPace) first.
- **The join channel needs no secrecy.** A network attacker without the secret cannot forge a request, cannot swap the device key in a request (the HMAC covers it) and cannot forge the roster reply (it is signed by the inviter whose key the device read from the QR code).
- **Trust starts out of band.** The genesis roster is trusted because it was made on the person's own device; a joining device trusts the inviter named in the QR code.
- **Revocation needs the new roster to spread.** A revoked device stays a member for every node that has not yet seen the roster that revoked it, and it can sign successors of the older roster for those nodes (a fork). Nodes should fetch the latest roster from several peers on reconnect; detecting forks (two different rosters with one epoch) is future work.
- **Revocation does not rotate the group key here.** Rotating the group key on revocation, as SECURITY.md requires, belongs to `baton-keys` (phase 4).
- Pending invites live in memory; restarting the member cancels them.
- Nothing in this crate logs, and `Debug` of `Identity` and `Invite` hides the secrets.
