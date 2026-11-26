# Migration

Breaking changes between minor releases, with what an integrator has to do. Skein is pre-1.0: a minor release may break the API, configuration, storage format or behavior, and every such break is listed here.

## Unreleased: no management API

The web portal, the HTTP management API, `openapi.json`, `@peleda-app/skein-client` and the `skein-view` binary are gone (decided by the maintainer on 2026-11-25).

- **Managing a node.** Use the binary's subcommands instead of the routes: `skein tenant add|list|remove [--purge --confirm]`, `skein account put|list|show|remove|password|send-key|grant`, `skein journal put-blob|get-blob|submit|cancel|events`, `skein webhook add|list|pause|resume|rotate|remove`. They open the node's storage and master key file and work while it runs. A command queued from the command line is picked up on the owner's next round (at most `engine.interval_secs`). OAuth sign-in through the server is gone: obtain tokens elsewhere and hand them in with `skein account grant`.
- **Config.** Remove `server.admin_key_hashes`, `server.trusted_proxies`, `[server.cors]`, `[server.account_hosts]` and `[portal]`; they are refused now. Move `[server.webhooks]` to `[webhooks]`. `[server]` configures only the inbound listener (push and health); `push_rate_per_second` is new. OAuth clients no longer need `redirect_url`. `skein admin-key` is gone; `skein push-token` makes the Gmail push secret.
- **Inbound HTTP.** Only `GET /v1/health`, `/v1/push/graph` and `/v1/push/gmail/{secret}` answer; the push addresses are unchanged. In code, `skein_server::router(signal, push, &config)` replaces `router(state)` and `router_with_push`, `hash_token` replaces `hash_key`, and `ServerState`, `Scope`, `Cidr`, `CorsConfig` and `openapi_json` are gone.
- **Reading the journal.** Read the storage contracts directly, or embed `skein-view` (`skein/crates/view`), which follows a tenant's journals from storage with hash-chain verification. Its `Store` keeps the same SQLite schema (migrated to version 3 on open) and offers the queries its API used to serve.
- **Checks in libraries.** `skein_engine::{check_command, submit_command, cancel_command}` and `skein_accounts::admin::{check_record, check_password, check_send_key, check_token, register_tenant, unregister_tenant, purge_tenant, delete_account}` hold the checks the routes ran.
- **Features.** The `openapi` features of `skein-core`, `skein-storage` and `skein-accounts` and the `portal` feature of the binary are gone.
- **Images.** Only `ghcr.io/peleda-app/rowboat` is built; `-headless` and `rowboat-view` are gone.

## Unreleased: Skein on Baton contracts

Skein starts using Baton, the coordination library, for leases, liveness and signals. Skein's libraries depend only on Baton's contract crates (`baton-core`, `baton-state`, `baton-lease`, `baton-signal`); the binary and the tests also use `baton-lease-cas` (the built-in lease arbiter over any compare-and-swap store), `baton-state-memory` (in-memory state for single-process mode) and `baton-signal-local` (in-process signals).

### Where Baton comes from

Baton is not published. Since 2026-11-25 Skein and Baton are layers of one repository, rowboat (`skein/` and `baton/`), under PolyForm Noncommercial 1.0.0 with every crate `publish = false`. Both layers are members of the root Cargo workspace, which refers to Baton's crates by path (`baton/crates/...`): CI and the fuzz workflow need no second checkout, and the Docker images build with the repository root as context (`docker build -f skein/Dockerfile .`).

### Ids and fencing tokens come from `baton-core`

`skein_core::NodeId`, `skein_core::FencingToken` and `skein_core::InvalidId` are now re-exports of the `baton-core` types of the same names. Imports through `skein_core` keep working.

- **Serialized forms are unchanged.** A `NodeId` is the same JSON string and a `FencingToken` the same JSON number as before, so every stored fence (account status records, owner records, journal heads and segment names, which store the plain number) stays readable.
- **`NodeId`, `TenantId` and `AccountId` refuse Windows device names** (`con`, `prn`, `aux`, `nul`, `conin$`, `conout$`, `com0`–`com9`, `lpt0`–`lpt9`), on construction and when deserializing; all other ids that were valid stay valid. Tenants and accounts follow Baton's id rules so that every tenant is a group and every account a lease key (`skein_core::coordination`). What to do: if a node is configured with such an id (`node.id`), give it another one before upgrading; the binary refuses to start otherwise. A tenant or account with such an id can no longer be created or read through the API, synced or leased: export its data with the old version, purge it and recreate it under another id before upgrading.
- **No `utoipa::ToSchema` on `NodeId` and `FencingToken`** under the `openapi` feature (they are foreign types now; Skein's own API does not expose them; the feature itself is gone since, see above). What to do: if your OpenAPI schemas embed them, annotate the field with `#[schema(value_type = String)]` or `#[schema(value_type = u64)]`.
- `InvalidId` (also used by `TenantId::new` and `AccountId::new`) keeps its message.
- `skein_core` also re-exports `GroupId` and `LeaseKey`, and the new module `skein_core::coordination` is the one mapping between them and tenants and accounts: `group(tenant)`, `tenant(group)`, `lease_key(account)`, `account(key)`, each the same id.

### Baton state in control records

`skein_storage::ControlState` (new) implements Baton's `StateStore` over any `ControlStore`, so `baton-lease-cas` can keep leases and heartbeats in the same store as the tenant's other control records. It writes under the control path `baton/` of each tenant (the group id is the tenant id).

- **The control path `baton/` is reserved.** What to do: if your own code stores control records under `baton/`, move them. `ControlStore::purge` removes `baton/` records with the tenant's other records.
- **Every `Objects` backend now also runs Baton's `StateStore` suite.** `skein_storage::testing::all_over_objects` calls the new `testing::control_state`, and the `testing` feature of `skein-storage` now enables `baton-state/testing`. What to do: a custom `Objects` or `ControlStore` implementation must pass it; it needs nothing beyond the existing contract (compare-and-swap, ordered listing, keys never nested).

### Coordination moves to Baton; five crates are removed

`skein-ownership`, `skein-ownership-control`, `skein-ownership-single`, `skein-ephemeral` and `skein-ephemeral-local` are deleted. Their guarantees live on in Baton's lease, liveness and signal conformance suites. What to do: replace them as follows.

| Removed | Use instead |
| --- | --- |
| `skein_ownership::{Ownership, Lease, OwnershipError}` | `baton_lease::{Leases, Lease, LeaseError}`; `acquire` takes a `NodeProfile`, keys are `(GroupId, LeaseKey)` from `skein_core::coordination` |
| `skein_ownership::{Liveness, NodeProfile}` | `baton_lease::{Liveness, NodeProfile}`; build Skein profiles with `skein_engine::node_profile(node, weight, always_on)` |
| `skein_ownership::preferred_owner` | `baton_lease::preferred` |
| `skein_ownership_control::{ControlOwnership, ObjectLiveness}` | `baton_lease_cas::{CasLeases, CasLiveness}` over `skein_storage::ControlState`, with `skein_engine::OneGroupLiveness` |
| `skein_ownership_single::{SingleOwnership, SingleLiveness}` | `CasLeases` and `CasLiveness` over `baton_state_memory::MemoryState` |
| `skein_ephemeral::{Ephemeral, EphemeralError}` | `baton_signal::{Signal, SignalError}`; calls take `skein_core::coordination::group(tenant)` |
| `skein_ephemeral_local::LocalEphemeral` | `baton_signal_local::LocalSignal` |

API changes that follow:

- `Engine::new(storage, leases, signal, profile)` takes `Arc<dyn baton_lease::Leases>`, `Arc<dyn baton_signal::Signal>` and a `baton_lease::NodeProfile` instead of ownership, the ephemeral layer and a `NodeId`. `Engine::profile()` is new.
- `RunConfig::new(liveness)` drops the profile argument (the engine's profile is used) and gains `RunConfig::nodes`, the group heartbeats go to (`skein_engine::NODES_GROUP` by default). The liveness must answer for every tenant's group what it answers for `nodes`: wrap it in `OneGroupLiveness`, and give the same instance to the leases.
- `EngineError::Ownership(OwnershipError)` becomes `EngineError::Lease(LeaseError)`; `CollectionsError` converts from `LeaseError`.
- `skein_server::ServerState::ephemeral` is renamed `signal` (`Arc<dyn baton_signal::Signal>`).
- `skein_oauth::TokenManager::with_ephemeral` is renamed `with_signal`.
- `skein_push::PushRegistry::{accept_graph, accept_gmail}` take `&dyn baton_signal::Signal`; `PushError::Ephemeral` is renamed `PushError::Signal`.

### Behavior

- **Configuration is unchanged.** `engine.ownership = "single"` is now Baton's compare-and-swap leases over in-memory state, and `"storage"` the same leases and heartbeats kept as control records through `ControlState`.
- **Storage layout of coordination records.** Lease records move from `owners/{account}` in each tenant's control records to `baton/lease-/{account}` (Baton's record `lease/{account}`), and heartbeats from the root objects `nodes/{node}` to the control records of the tenant `_nodes` (`baton/nodes-/{node}`). Old records are no longer read; they can be deleted after every node runs the new version. Upgrading needs no data migration: fencing tokens are now microseconds of wall-clock time, far above the tokens stored before, so the first lease on each account outranks every earlier owner and the journal accepts it. What to do: stop all nodes of the old version before starting the new one (an old and a new node never see each other's leases).
- **Assignment of accounts.** Nodes of one class choose with the same weighted rendezvous hash as before, so accounts stay where they were on upgrade unless nodes differ in `always_on`. Nodes with `always_on = false` now get accounts only while no always-on node is alive; before, `always_on` was informational. What to do: set `always_on = true` on every node that should share accounts as before. Accounts may move once when such a mixed fleet is upgraded.
- **Takeover timing.** A node takes over an account only after its holder has dropped out of liveness and the lease record has not changed for a whole liveness time-to-live, judged on the taking node's own clock; a node that just started therefore waits one time-to-live before taking over a crashed node's accounts. A node that shuts down cleanly now releases its leases, so its accounts move at once.
- **Holder self-expiry.** A node running `skein_engine::run` stops acting on its accounts once its heartbeats have failed for four fifths of the time-to-live (three heartbeat intervals in the binary), and resumes after the next successful heartbeat with new runs that take the lease again: a run working with a lease taken before the lapse ends with `NotOwner` before its next provider write, send or iTIP mailing, even once heartbeats succeed again; before, it kept running until a write was fenced.
- **Tenant ids starting with `_` are reserved.** `TenantId::new`, parsing and deserializing refuse them; the API answers 400 for every route naming one (`PUT`/`DELETE /v1/tenants/_x`, purge included), and the CLI refuses them. They are kept for Skein's own groups: node heartbeats live in the group `_nodes`, which before could be registered, purged (resetting every node's liveness, so other nodes took accounts from live holders) or exported as a tenant. `skein_core::coordination::tenant` still maps every group to a tenant (a group starting with `_` to a reserved one, see `TenantId::is_reserved`). What to do: a tenant whose id starts with `_` can no longer be created or read: export its data with the old version, purge it and recreate it under another id before upgrading.
- **`engine.heartbeat_secs` must match on every node.** Each node judges the others with its own interval, so nodes with different values took accounts from live holders. With `engine.ownership = "storage"`, a node now records the agreed interval in shared storage (Baton record `skein/heartbeat` in the group `_nodes`) and refuses to start while a node running with another interval is heartbeating; when none is, it watches heartbeats for three of the longer interval, then makes its own value the agreed one. What to do: give every node the same `heartbeat_secs`; to change it, stop every node and start them with the new value (a node started alone after a change waits up to three old intervals once).
- **Signals are bounded.** `LocalSignal` keeps at most 16 undelivered messages per subscriber (it was 1024) and refuses payloads and values over 64 KiB and names over 200 bytes; previews, head hints and push hints are far smaller, and a subscriber that falls behind only misses hints, as before. The binary raises the topic limit so every account's subscriptions fit.

### Tamper-evident journal

The journal becomes a hash chain: every segment names the previous one by BLAKE3 hash, and each account's head names the last segment, optionally attested by a `HeadAttestor`. See the [storage README](../crates/storage/docs/README.md#tamper-evident-journal).

- **Storage format of segments.** Every segment written from now on starts with a header line (`{"skein_segment":1,"tenant":…,"account":…,"start":…,"end":…,"fence":…,"prev":…}`) before the events. Segments without it keep reading. Older versions cannot read the new segments (they fail as corrupt). What to do: stop every node of the old version before starting the new one (already required for the lease records), and never run an older version against the store afterwards; take an export first if you may need to roll back.
- **Storage format of heads.** Heads gain `tip` (the last segment's start, end, token and hash) and `attestation` (base64), both left out when absent. Heads without them keep reading. An older version would read such a head but write it back without them, after which the new version refuses the account's head (`Integrity(Fork)`): the same rule, no old versions after the upgrade.
- **No data migration, no rehash.** The chain starts at the first segment each account writes after the upgrade; its `prev` is `null`. Events before it stay readable but are not covered by the chain: `locate` reports them `Unchained`, and a head without a tip pins only its `seq` and `fence`. Nothing is rewritten.
- **`Log` gains methods.** `Log` now has the supertrait `SegmentSource` (`segment(tenant, account, &SegmentRef)`, the stored bytes of a segment) and the method `signed_head(tenant, account)` (the head with its tip and attestation). What to do: a custom `Log` must implement both; one that wraps another can delegate. `testing::log` now checks the chain, so the custom `Log` must also write chained segments that `verify_segment` accepts and keep the tip on claims.
- **`StorageError::Integrity(IntegrityError)` is new.** Reads now fail with it for tampered, reordered, removed-and-relinked or mixed-up segments, a head behind or disagreeing with one the log has already seen, and a refused attestation. Segments whose length or event numbering does not match their name, which used to fail as `Corrupt`, now fail as `Integrity(Mismatch)`. What to do: add the variant to exhaustive matches; treat it like `Corrupt` (stop and investigate, do not retry). The server answers it with 500, as before for `Corrupt`.
- **`ObjectLog` refuses rolled-back heads.** An `ObjectLog` remembers the newest head it has read or written for each account and refuses an older one read later. If something else purges a tenant's journal while a process keeps using its own `ObjectLog` for that tenant, its next access fails with `Integrity(Rollback)`; purge through the same `Storage` (`Storage::purge_tenant`) or restart the process.
- **Attesting heads (optional).** `ObjectLog::with_attestor` and `Storage::over_attested` take an `Arc<dyn HeadAttestor>`; `ObjectLog::new` and `Storage::over` keep using `NoAttestor`, so nothing changes unless you opt in. To adopt an attestor on existing data, its `verify` has to accept unattested heads until each account has written once; the binary does not configure one.
- **Moving a journal between ids.** Segment headers name the tenant and account, so a journal copied under another tenant or account id no longer verifies there. `skein export`/`import` keep ids and bytes and are unaffected.
- **New public API** in `skein-storage`: `SegmentHash`, `SegmentRef`, `JournalHead`, `SignedHead`, `IntegrityError`, `HeadAttestor`, `NoAttestor`, `SegmentSource`, `VerifiedSegment`, `Chain`, `verify_segment`, `locate`, `verify_extends`, `verify_head`, `Storage::over_attested`, `ObjectLog::with_attestor`; behind `testing`: `head_attestor`, `KeyedAttestor`.

### Account-scoped keys

The keyring seals under a `KeyScope`: a tenant, or one account of a tenant with its own key. See the [keyring README](../crates/keyring/docs/README.md).

- **`Keyring` signatures change.** `seal(tenant, context, plaintext)`, `open(tenant, context, sealed)` and `destroy(tenant)` become `seal(&KeyScope, context, plaintext)`, `open(&KeyScope, context, sealed)` and `destroy(&KeyScope)`. What to do: callers pass `KeyScope::tenant_of(&tenant)` to keep the old meaning, or `KeyScope::account_of(&tenant, &account)` for an account's secrets. A custom `Keyring` must keep a key per scope, make account keys unusable once their tenant's key is destroyed (also on instances that never saw the account), and pass the extended `testing::keyring` suite, which now attacks scope isolation, destruction per scope and through the tenant, and the `open_account` fallback.
- **Which scope Skein uses.** Account passwords, calendar and contact passwords, send keys (`skein-accounts`) and OAuth grants and their cached access tokens (`skein-oauth`) are sealed under the account's scope. Pending sign-ins, webhook secrets and the tenant registration check stay on the tenant scope. Blobs and segments are not sealed by Skein.
- **Existing sealed data stays readable; no migration step.** Secrets sealed by an earlier version are tenant-scoped. `skein_keyring::open_account` opens an account secret under the account scope and, only when that is `Invalid`, under the tenant scope with the same context (contexts already name the account). `skein-accounts` and `skein-oauth` then seal the secret again under the account's key and store it with a compare-and-swap on first read, so data moves over as it is used. Cached access tokens sealed by an earlier version are simply missed and fetched again. What to do: nothing; to finish moving a tenant early, read every account's credentials once (for example by letting every account sync). The fallback will be removed in a later release, after which tenant-scoped account secrets must have been re-sealed.
- **`keyring-local` storage format.** Account keys are stored as control records `keys/accounts/{account}`, wrapped by a key derived from the tenant's data key; account-scoped sealed bytes start with version byte `2` (tenant-scoped ones keep `1` and their format, so tenant data written before opens unchanged). Older versions cannot open account-scoped bytes (`Invalid`): do not run an older version against the store after the upgrade (already required by the journal changes). `Storage::purge_tenant` keeps `keys/` as before, so account key records survive a purge next to the tenant's tombstone; they are unreadable once the tenant key is destroyed.
- **Destroying per account.** `destroy(&KeyScope::Account(..))` destroys one account's key for good; that account id then stays destroyed in that tenant, and its legacy tenant-scoped copies are not reachable through `open_account` (it returns `Destroyed`), though they are only shredded with the tenant key. Destroying a tenant destroys every account key under it. The server does not destroy account keys when an account is deleted, so an account id can be used again.
- **Cache lifetime.** `[keyring] cache_ttl_secs` now also bounds how long an account key, and a key whose tenant was destroyed on another node, keeps working on this node. An account key is cached no longer than the tenant key it was unwrapped with, so a tenant destroyed on another node stops every account key here within one cache lifetime (before this fix, up to two).
- **New public API** in `skein-keyring`: `KeyScope`, `Opened`, `open_account`.

### Read-only tiers

Storage can read segments and blobs from untrusted read-only tiers after local storage. See the [storage README](../crates/storage/docs/README.md#read-tiers) and [skein-storage-tiered](../crates/storage-tiered/docs/README.md).

- **New contract `skein_storage::ReadTier`** (`segment(tenant, account, &SegmentRef, max_len)`, `blob(tenant, &BlobHash, max_len)`) with the suite `testing::read_tier`. Additive; nothing existing changes.
- **New crate `skein-storage-tiered`**: `Tiered::new(local).with_tier(..).build()` gives a `Storage` whose log and blobs fall back to tiers, verifying every byte against the expected hash, refusing oversized bytes, giving each tier a timeout and never writing to a tier; `StorageTier` serves another `Storage` as a tier. The binary does not configure tiers; nothing changes for existing deployments.
