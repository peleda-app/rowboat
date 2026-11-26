# batond

The headless node for a server in the **blind role**. It holds the logs of the groups it is configured for, arbitrates their leases, and runs the drop service in the same process. Its node is certified in each group as a `Blind` node: it holds no resource key and has no capability, so it never sees plaintext and cannot command anything. A server that does real work is the application's own binary built on `baton-node`, not `batond`.

## What runs

| Part | Crate | Link protocol / port |
| --- | --- | --- |
| group logs: members fetch entries and push new signed ones | `baton-group-server` | `group` |
| lease arbiter with authorization from the logs | `baton-lease-server` + `Rules` | `lease` |
| drop service (mailboxes and wake boxes) | `baton-drop-service` (`apps/drop`) | HTTP/1.1, `[drop] listen` |
| transport | `baton-link-iroh` | QUIC, `[iroh] bind` |

## Who may do what (`Rules`)

All decided from the held logs on batond's wall clock, at the moment of each call:

- **Link trust**: a counting node (certified, not revoked, member still in the group, certificate not expired) of a held group, or a bootstrap peer of a held group whose log has never certified that key. Anyone else is refused before an application byte crosses.
- **Group logs**: counting nodes of that group read and push; bootstrap peers of that group too, but only while the log has no genesis or has never certified their key. Once the log certified a bootstrap key (the founder at genesis), the log alone decides, so a revoked, removed or rekeyed founder is refused on `group` and by the link like any other node, whatever the configuration still lists. Every pushed entry is checked by `baton-group` at the head (see `baton-group-server`).
- **Leases**: a peer speaks only as its own node and only while it counts in some held group; it reads liveness and holders of a group it counts in; it announces only a profile no stronger than its certificate's class and never as a blind node; it acquires or takes over a key only if it is not blind and has `Lead` on the key's resource; it releases its own leases whatever its rights are now (releasing grants nothing, so a holder that lost `Lead` can still give the key up).

**Lease keys map to resources** (`resource_of`): the key itself, or the part before the first `--` when a non-empty suffix follows (`vault-1--sync` is held on resource `vault-1`). Every key maps to at most one resource, and only when the reading is unambiguous: a key whose resource part ends with `-` or whose suffix starts with `-` (`vault---sync`, readable as `vault` + `-sync` or `vault-` + `sync`) maps to none. So a resource id containing `--` cannot be leased through batond, one ending with `-` only whole, and `vault-1--` maps to none.

**Log limits**: at most 100,000 entries (`MAX_ENTRIES`) and 256 MiB (`MAX_LOG_BYTES`) per log from anyone, plus a reserve of 1,000 entries (`LOG_RESERVE`) only for entries that take trust away signed by an admin's or owner's node or a recovery key, so a member device that fills the log cannot block its own revocation; pushes are rate limited per peer (`baton-group-server` defaults: 20/s, burst 100).

## Configuration

`batond --config FILE`, TOML with unknown keys refused:

```toml
data_dir = "/var/lib/batond"          # default ./batond-data

[[group]]                             # at least one, at most 1,024
id = "family"
genesis = "<64 hex digits>"           # the group's fingerprint (GroupLog::genesis_hash)
bootstrap = ["<node id>"]             # optional: the founding node until genesis is pushed,
                                      # a recovering device; remove once certified

[iroh]
bind = ["0.0.0.0:7843"]               # default: every interface, random ports
relays = []                           # default: none (direct paths only)
allow_classical = false               # default: X25519MLKEM768 required

[lease]
ttl_ms = 15000                        # liveness time-to-live, at least 1,000; lowering it
                                      # takes effect for holders at once and for the arbiter
                                      # once no holder can still believe the old one

[drop]                                # optional: the whole apps/drop configuration
realm = "drop.example.com"
listen = "127.0.0.1:8470"
data_dir = "/var/lib/batond/drop"
[drop.admission]
work_difficulty = 12
```

## Files and keys

- The data directory is created `0700`.
- `node.key`: the node's Ed25519 secret, 32 raw bytes, created on first start with mode `0600` (`create_new`, so an existing file is never overwritten). A key file readable by group or others, of the wrong length, or not a regular file (a symlink) is refused. Its public half is what members pin for the link and what the group certifies as a `Blind` node. batond has no other secret: no member key, no KEM secret, no resource key.
- `state.redb` (`0600`): `RedbState`, batond's `StateStore` (group log entries under `group/…`, lease records under `lease/…`, heartbeats under `nodes/…`). Records are `group ‖ 0x00 ‖ name` → `version ‖ value`, versions from one store-wide counter; each call is one flushed transaction on a blocking thread. It passes `baton_state::testing::state`.
- `lease.ttl` (`0600`): the lease time-to-live the last run advertised and the larger one it still honored, with until when (wall clock). At start batond computes the largest time-to-live a holder may still believe and passes it as `previous_ttl_ms`, so the arbiter judges holders gone only after `max(ttl_ms, previous)` while holders already stop by the new, shorter one. A malformed file is refused.
- The drop service keeps its own `drop.redb` in `[drop] data_dir`.

## Starting and stopping

`start(config, clocks)` creates the data directory, loads or creates the node key, opens the store, loads every held log (refusing one that does not verify or has another genesis), binds iroh trusting exactly the counting nodes and bootstrap peers, starts the group and lease servers on it and the drop service. `Running::stop` severs group and lease streams, closes the link, then lets the drop service finish requests in flight; the binary does this on SIGINT or SIGTERM.

`Core` is the part without transport or disk: `Core::open(state, groups, bootstrap, clocks)`, `trust()` for building the link, `serve(link, lease_config)`. Tests run it over `baton-link-memory`.

## Not built (deferred)

- An embedded iroh relay: run `iroh-relay` next to batond and list it in members' and batond's `[iroh] relays`.
- Sending wake-ups: members wake each other through `wake-mailbox` over the drop service batond runs; batond itself sends none.
- Adding a group without a restart, and holder-signed lease records (SECURITY.md).

## Tests

- `src/state.rs`: the `StateStore` suite on redb, versions never repeating across a delete and a reopen, prefixes and groups not leaking, a corrupted record.
- `src/rules.rs`: the key-to-resource mapping, with a property test that every mapping is unambiguous (`vault---sync` maps to none).
- `src/lease_ttl.rs`: a lowered time-to-live honoring the old one until no holder can believe it, across quick restarts too; damaged records refused; a property test.
- `src/key.rs`, `src/config.rs`: key file creation, mode, length and type checks; configuration parsing and refusals.
- `tests/e2e.rs` (in-memory links, redb store): a member gets leases on its resource and on `resource--suffix` keys, not on unknown resources or a key mapping to none, nor with a stronger profile than its certificate; a second member's node is refused until a grant gives its member `Lead`, then allowed on the next request; a revoked node is refused on every protocol and its lease lapses to another member; blind nodes are refused heartbeats and leases whatever they claim; batond's node gets no key box and no capability and cannot open the epoch even with a KEM key; a stranger cannot connect; logs and leases survive a restart; forged, replayed and stale-head entries are refused, and a revoked node's entry built on the current head is refused as `Invalid` by the log rules, also when relayed by a member; a store holding another genesis is refused; a founder configured as bootstrap peer and then revoked is refused on `group` and by the link, while a bootstrap key the log never certified is still admitted; a holder that loses `Lead` can still release, and nobody can release another node's lease.
- `tests/start.rs` (127.0.0.1 only): the whole binary's `start` with iroh and the drop service, a member pushing genesis and syncing over iroh, a lease request, a mailbox round trip over HTTP, the node key kept across a restart, directory and file modes, a stranger refused, a group-readable key refused.
