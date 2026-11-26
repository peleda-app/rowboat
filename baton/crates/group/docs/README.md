# baton-group

The signed group log: members, nodes, roles, per-resource capabilities, key epochs and recovery. The rules are those of `docs/SECURITY.md`; this crate is where they are enforced.

## The log

A hash-chained sequence of `Entry`s (`v`, group, `seq`, `prev` = BLAKE3 of the previous entry, signer time `at`, signer, `Op`), each signed under the context `baton-group-entry-v1`. `GroupLog::verify` checks every entry from genesis against the state the previous entries produced; `GroupLog::append` signs, checks and appends; `GroupLog::apply` takes an entry made elsewhere. Nothing that fails a check changes the state.

| Op | Signed by | Rules |
| --- | --- | --- |
| `Genesis` | the founding node | certified by the owner; owner key, founding node key, owner and group recovery keys all distinct; both recovery keys self-signed |
| `AddMember` | a node of an admin (plain members) or an owner (admins and owners) | member key and recovery keys never used before in any role; recovery key self-signed |
| `RemoveMember` | the member's own node or recovery key, an owner, an admin (for plain members), the group recovery key | the last owner stays; a removed key never returns |
| `RekeyMember` | the member's recovery key only | the new key was never used; role, recovery key, grants and resource creation move to it; the old key and its nodes stop counting |
| `CertifyNode` | a node of the same member, an owner's node, an admin's node (for plain members), the member's or the group's recovery key | signed by the member key (`baton-node-cert-v1`) **and by the node key** (`baton-node-cert-proof-v1`), not expired, node key never used before in any role |
| `RevokeNode` | a node of the same member, an owner's node, an admin's node (for plain members' nodes), the member's or the group's recovery key | for good |
| `CreateResource` | any non-blind node | its member is the creator and gets read, lead and admin |
| `Grant` | a node with admin on the resource | principal exists; changing one's own member's grants needs to be the creator (so owners cannot grant themselves into private resources and resource admins cannot grant themselves read); no grants to blind nodes; command classes are 1–32 bytes of `[a-z0-9_-]` and need read; an empty set revokes |
| `KeyEpoch` | a node with admin or lead | epoch = last + 1; carries `Commitments` to its keys; boxes go to **exactly** `required_recipients`, once each, the secret key exactly to those who may lead |
| `ShareEpoch` | a node with read (secret keys only from nodes with lead or admin) | boxes of an existing epoch for recipients authorized now; a recipient may be boxed again, and `open` takes the first box whose keys match the commitments |
| `Checkpoint` | the group recovery key | anchors restores |
| `RotateRecovery` | the current recovery key it replaces (member's or group's) only | the new key is self-signed and never used before |

Entry times never go back (`at` ≥ the previous entry's), so an expired server cannot backdate; `GroupLog::apply_fresh(entry, now, skew)` also refuses entries from the future when they arrive. `Entry::decode` refuses non-canonical bytes. Applying an entry checks everything before changing anything, in place, so verifying a log is linear.

Node certificates count only while not revoked, not expired at the entry's time, and their member is in the group; `GroupState::was_certified` says whether a key was ever certified (revoked or not), so a server can stop admitting a bootstrap key once the log has taken it over. A node's capabilities on a resource are the grants to its member and to itself.

## Keys and epochs (`epochs`)

`required_recipients(resource)`: every counting, non-blind node with read or lead (secret key only with lead); the recovery key of every member involved (secret key only if that member or one of its nodes may lead); and, for a shared resource (more than one member involved), the group recovery key with both keys. A member's private resource is never boxed to the group recovery key. `new_epoch` seals fresh `baton-seal` keys to exactly those; `share_epoch` boxes an epoch for newly authorized devices; `open` finds and opens one's box. Each box's associated data binds group, resource, epoch, recipient and which key it holds. Each box's keys are checked against the epoch's `Commitments` on `open`, so forged or wrong boxes are skipped. `needs_rotation(resource)` is true when someone holding the current epoch is no longer allowed to, or holds its secret key without lead.

## Store (`store`)

Entry `seq` lives at `group/{seq:020}` in a `StateStore`, written with `put_if_absent`: two writers never both append at one position (`GroupError::Fork` for the loser, who reloads). `load` pages to the end, refuses gaps, verifies from genesis and checks the log is the requested group's; `load_expecting(store, group, genesis_hash)` also refuses a forged genesis (keep `GroupLog::genesis_hash()` on the recovery sheet). `GroupLog::check_head(seq, hash)` tells `Same`, `Behind` (stale copy or rollback), `Ahead` or `Fork`.

## Recovery from scratch

With every device lost: load the log from the store (with the genesis fingerprint), derive the recovery keys from the root, check they match the log, open the recovery boxes, revoke the old nodes with the recovery key, `RekeyMember` to a new member key, certify a new device (signed by the new member key and the device), start a new epoch from it, and rotate the recovery key with the old one. The test `recovery_drill_restores_a_group_from_scratch` does exactly this.

## Limits

- No PAKE pairing yet (the copied `baton-identity` invites remain); no ML-DSA signatures yet (QUESTIONS).
- Entry times are the signer's clock; they matter only for certificate expiry.
- A fresh restore trusts the store for freshness; checkpoints and revoking all old nodes narrow that (SECURITY.md).

## Tests

`cargo test -p baton-group`: genesis checks; roles for members and nodes; forged, expired and reused certificates; revoked nodes signing nothing; the last owner; shared and private resources keeping keys apart (a member of the shared box cannot open the private one; readers never get the secret key; nobody grants themselves more; bad command grants); exact epoch recipients (missing, extra, duplicate, out of order, wrong secret distribution); revocation forcing a new epoch the revoked node cannot open; sharing with a new device and refusing outsiders; chain rewrites, drops, tampering and forks detected; checkpoints and recovery rotation; the store ordering writers and refusing gaps and tampering; the full recovery drill; a property test that arbitrary bytes never decode; and `review_tests`, one regression test per finding of the first adversarial review (takeover through recovery rotation, group recovery key on private resources, readers' recovery keys and the secret key, blind nodes, backdated and future entries, poisoned and forged shares, lead loss without rotation, paired, squatted and reused recovery keys, admin overreach and self-grants, another group or a forged genesis from the store, non-canonical bytes, a 3,000-entry log verified in linear time). Fuzz target `group_entries`; load scenario `group`.
