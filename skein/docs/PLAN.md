# Plan

Skein connects to mail, calendar and contacts providers and keeps nothing but a journal. It turns every change on IMAP, JMAP, Gmail API, Microsoft Graph, CalDAV, CardDAV, Google Calendar and Google People into an append-only log in object storage, and carries out write commands that consumers put next to that log. Consumers build their own databases from the log: archives, search, thread views, mail servers. Skein itself stays dumb and, as far as possible, stateless.

Skein is the `skein/` layer of rowboat, source-available under the PolyForm Noncommercial License 1.0.0 (see the root `LICENSE.md` and `docs/DECISIONS.md`); no crate is published.

## Principles

- **The journal is the truth.** Every change Skein sees becomes an event in a per-account log; every piece of content (RFC 5322 message, iCalendar, vCard, provider JSON) is stored once as a blob addressed by its BLAKE3 hash. Any database a consumer builds can be rebuilt from the log and the blobs.
- **Dumb core.** Skein does not parse content for features, index, thread, merge edits or decide policy. It reports what happened and does what it is told, and says honestly when a write failed, conflicted or has an unknown outcome.
- **Stateless instances.** No local disk and no database are required on a server. The little durable state Skein needs (accounts, sealed credentials, provider cursors, ownership) lives in object storage with compare-and-swap. Any instance can be killed at any time.
- **Distribution by contract.** Who owns an account, how nodes see each other, what a node is capable of and where the journal lives are contracts. This repository ships implementations for servers; other applications can plug in their own (see [Extension points](#extension-points)) without forking.
- **Losing memory is harmless.** Data kept only in memory (liveness, hints, previews, caches, access tokens) may vanish at any moment; every reader has a durable fallback.
- **Consumers own their projections.** Each consumer reads the log at its own pace with its own checkpoint.
- **Original representation is kept.** Normalized fields are convenience; the provider's original bytes are always stored, so unknown properties survive a read–edit–write round trip.

## Domains

Mail, calendars and contacts share one account, one OAuth connection and one engine. Each domain is a cargo feature and a config switch; a deployment can run mail only.

| Domain | Providers |
| --- | --- |
| Mail | IMAP, JMAP, Gmail API, Microsoft Graph |
| Calendars | CalDAV, JMAP Calendars, Google Calendar, Microsoft Graph |
| Contacts | CardDAV, JMAP Contacts, Google People, Microsoft Graph |
| Sending | SMTP submission, JMAP `EmailSubmission`, Gmail send, Graph `sendMail` |

## Architecture

```
  providers (IMAP, JMAP, Gmail, Graph, CalDAV, CardDAV, Google Calendar and People)
                         ▲            │
             commands    │            │  changes
                         │            ▼
              ┌───────────────────────────────┐
              │  Skein nodes                   │  leases (Baton)
              └───────────────────────────────┘
                         ▲            │
                         │            ▼
  ┌────────────────────────────────────────────────────────────┐
  │ object storage                                              │
  │  control/    accounts, sealed credentials, cursors, leases  │
  │  log/        per-account event log (append-only)            │
  │  blobs/      messages, iCalendar, vCard, provider JSON       │
  │  snapshots/  current account state at a log position        │
  │  commands/   write requests; results land in log/           │
  └────────────────────────────────────────────────────────────┘
                         ▲            │
             commands    │            │  read the log, each with its own checkpoint
                         │            ▼
        consumers: archive · search · insights · own IMAP/JMAP/DAV server · skein-view
```

### Ways to use it

1. **Rust library.** Depend on `skein-engine` and the providers you need, implement the storage contracts or use the in-memory ones; the log can feed straight into your own `Sink`.
2. **Headless node.** Run the `skein` binary or container and manage it with its subcommands; consumers read object storage directly (`skein-view` does, as a library). There is no web panel and no management API (removed on 2026-11-25); Peleda's node will be managed through Baton commands from the app.
3. **Extended.** An application composes Skein's crates with its own implementations of the extension contracts and builds its own binary.

## Change feed

Each provider maps its own change mechanism onto one model: a cursor per collection, a batch of changes, and an explicit `ResyncRequired` when the provider stops accepting the cursor.

| Provider | Cursor | Push |
| --- | --- | --- |
| IMAP | `UIDVALIDITY` + `UIDNEXT` + `HIGHESTMODSEQ` (`CONDSTORE`, `QRESYNC`); UID snapshots where `QRESYNC` is missing | `IDLE`, `NOTIFY` |
| JMAP | `*/changes` states | EventSource |
| Gmail API | `historyId` | Pub/Sub `watch`, polling otherwise |
| Microsoft Graph | delta links | subscriptions, polling delta otherwise |
| CalDAV, CardDAV | `sync-collection` tokens, ctag/ETag otherwise | WebDAV-Push where offered |
| Google Calendar, People | `syncToken` | channels (`watch`), polling otherwise |

Cursors are opaque and never hold credentials. An expired Gmail `historyId`, a Graph `410`, a new `UIDVALIDITY` or an invalid sync token becomes `ResyncRequired`, followed by a full listing.

Initial sync is bounded: newest first, then history, within the account's optional date window (fixed start date or sliding window), and within provider quotas. A minimal mode lists only identity and flags for mail.

## Journal

### Layout

```
tenants/{t}/
├── control/
│   ├── accounts/{a}.json            account config (record version, CAS)
│   ├── credentials/{a}.sealed       tokens and passwords, sealed with the account key
│   ├── cursors/{a}/{collection}     provider cursors
│   ├── imap-uids/{a}/{folder}       UID sets (roaring bitmap + zstd)
│   └── owners/{a}                   owning node, fencing token
├── log/{a}/
│   ├── head                          last event number (CAS)
│   └── 00000000000001200000-00000000000001200417.ndjson.zst
├── snapshots/{a}/00000000000001200000.json.zst
├── blobs/{blake3}
└── commands/{a}/{ulid}.json
```

- One sequence per account. Only the account's owner writes, so the order is strict. Segments are flushed every 10 seconds or 500 events (see Delivery); zero-padded keys make `ListObjects` return segments in order.
- Events are thin and point at blobs: `MessageAdded { ref, blob, mailboxes, flags, labels, received_at }`, `MessageRemoved`, `FlagsChanged`, `LabelsChanged`, `MailboxCreated`, `MailboxRenamed`, `MailboxDeleted`, `EventChanged { ref, blob, version }`, `EventRemoved`, `ContactChanged`, `ContactRemoved`, `CollectionChanged`, `AccountHealthChanged`, `FirstSyncCompleted`, `ResyncRequired`, and the command results below. Every event carries a schema version.
- Snapshots record the full current state of an account (every object with its blob, flags or version) at log position N. A new consumer loads the latest snapshot and reads the log after it. Segments older than the retention policy may be deleted once a snapshot covers them.
- Blobs are deduplicated within a tenant only, so one tenant cannot learn what another holds and a tenant can be deleted whole.
- A blob is written before any event or preview that points at it.
- Besides each account's `head`, a tenant-wide `log/heads` index lists every account's head, so a consumer polls one object instead of one per account.

### Retention

Skein is a buffer, not an archive. Long-term storage is a consumer's job.

| Prefix | Default |
| --- | --- |
| `blobs/` | expire after 30 days (an object storage lifecycle rule) |
| `log/` | segments older than the retention window and covered by a snapshot are deleted |
| `snapshots/` | the last two are kept |
| `commands/` | deleted some days after their final result |
| `control/` | small, does not grow |

A consumer that needs a blob that has expired asks for it with a `refetch` command; Skein downloads it from the provider again while the provider still has it.

Consumers that keep content addressed by BLAKE3 too (Holtmail's archive) adopt a blob with a server-side copy instead of downloading and uploading it, or share one blob store with Skein, in which case the consumer owns the blobs and their lifetime.

### Delivery

- **Durable:** events in the log with their number. Only these move a consumer's checkpoint and become facts in its database.
- **Preview:** the same change published as a signal as soon as it is seen, without a number, carrying refs and the change id. A consumer may show it at once (a new message in the UI, a push to a phone) but waits for the durable event before recording it. A node that crashes before flushing loses only previews; the change comes back from the provider because the cursor had not moved.
- **Hints:** "account A is at N" as a signal, signed webhooks or object storage event notifications. Consumers fall back to polling `log/heads` every 30–60 seconds. A missed hint only delays a consumer.

Because live delivery goes through previews, segments can be flushed rarely (every 10 seconds or 500 events) without making anything feel slow.

## Writes through commands

1. A consumer writes `commands/{a}/{ulid}.json` (through `skein_engine::submit_command`, which checks it first, or `skein journal submit`): set or clear flags, move, copy, delete, append, create or edit a mailbox, send a message, create, edit or delete an event or contact, send an iTIP message. Every command carries an idempotency key, and edits carry the version they were made against.
2. The account's owner runs it against the provider and writes the result to the log: `WriteApplied`, `Conflict { server_version_blob }`, `WriteFailed { reason }` or `WriteUncertain` (the request left, no answer came back).
3. When the change comes back from the provider, its event carries `origin: command_id`, so a consumer never mistakes its own write for someone else's.

Version preconditions per provider: ETag (CalDAV, CardDAV), `changeKey` (Graph), `etag` and `sequence` (Google), `ifInState` (JMAP). IMAP flags have no versions and are sent as `+FLAGS` and `-FLAGS`, which commute.

Skein never merges. Resolving a conflict (rebase a patch, ask the user, give up) is the consumer's decision. Three-way diffs and field patches ship as a library, `skein-merge`, for consumers that want them; the service does not use it.

Commands are retried with backoff and kept until they reach a final result. Sending has its own queue semantics: scheduled send (per message and per recipient), undo window, retry policy, save to Sent, DSN parameters, dry run.

## Scheduling

- `put_object` and `delete_object` with `notify`, and `respond_object`, tell the other side. When the server schedules itself (Graph, Google Calendar, JMAP, CalDAV with `calendar-auto-schedule`), Skein asks it to and lets it. Otherwise Skein mails what RFC 6638 asks of a scheduling agent through the account's sender: `REQUEST` and `CANCEL` for an organizer, `REPLY` for an attendee. `schedule_result` says who told whom. A message is never sent twice for one change.
- `respond_invitation` answers an invitation that came by mail with an iMIP `REPLY`, under the rules of `send`.
- Incoming invitations stay mail in the log, followed by `itip_received` with the calendar part and its facts. Deciding whether to trust a reply and applying it to the organizer's copy is consumer policy; applying is an ordinary calendar command. `COUNTER`, `REFRESH` and other methods can be built with `skein-itip` and sent with `send`.
- A CalDAV scheduling inbox can be listed as a collection with `role: schedule_inbox`.

## Accounts and authorization

- An account is credentials plus whose data they reach, not one user per token: a user's own token, a Microsoft app-only token with tenant admin consent (`/users/{id}`, shared mailboxes, rooms), or a Google service account with domain-wide delegation.
- Built-in OAuth with PKCE for Google and Microsoft: OAuth client configs through the API, authorize URLs, token refresh. Integrators can also hand Skein their own tokens, with or without a refresh token.
- Scopes come from the enabled domains; consent can be incremental (mail first, calendar later) and partial (no contacts), and the account's capabilities say what it can do per domain.
- Health per account: `healthy`, `reauth_required`, `throttled`, `degraded`, with events on every change.
- Discovery: settings for an address from Mozilla autoconfig, the ISPDB, SRV records and MX hints, including the OAuth provider.
- Network: SOCKS5 and HTTP proxies per account for IMAP, SMTP, DAV and OAuth.
- Rate limits are shared per account across domains, since Graph and Google quotas are per mailbox or user.

## Storage contracts

| Contract | Holds | Needs |
| --- | --- | --- |
| `ControlStore` | accounts, sealed credentials, cursors, IMAP UID sets, owners | compare-and-swap, listing by prefix |
| `Log` | per-account events, `head`, snapshots | append by the owner only, ordered reads from a position |
| `BlobStore` | content by BLAKE3 hash | idempotent put, ranged get |
| `CommandQueue` | write requests | ordered by ULID, claimed by the owner |

Implementations: `storage-s3` (ETags and conditional requests: AWS S3, Cloudflare R2, RustFS, Versity S3 Gateway and SeaweedFS pass the conformance suite; Garage and s3s-fs failed it in November 2026), `storage-fs` and `storage-memory`. `storage-tiered` reads segments and blobs from local storage first and then from untrusted read-only tiers (`ReadTier`), verifying every byte against the hash it was asked for, so a mirror or backup can fill in what local storage lacks. A Postgres implementation can come later. Each contract ships a conformance suite behind its `testing` feature.

### Records and migrations

- Control records and events are stored in envelopes with a schema version. Migrations are Rust functions in the typed layer, written once for every backend; records are upgraded when read and rewritten on their next write.
- `skein migrate` rewrites every control record to the current version. Log segments are immutable; readers understand every past event version.
- `skein export` and `skein import` copy a tenant between backends.

### Ownership

Exactly one node owns an account at a time: it holds the provider connections, writes the account's log and runs its commands. Ownership is a lease from Baton, the coordination library Skein uses for leases, liveness and signals (`baton-lease`); `skein_core::coordination` maps a tenant to a Baton group and an account to a lease key.

- Liveness is per node, not per account: nodes heartbeat once per interval in one shared group (`OneGroupLiveness`), and accounts go to live nodes by `baton_lease::preferred`: the strongest node class first (always-on nodes are servers), then consistent hashing weighted by each node's profile.
- The built-in arbiter is Baton's `lease-cas` over Skein's `ControlState` (Baton's `StateStore` over `ControlStore`): taking an account over writes one lease record with a new fencing token by compare-and-swap; that happens only when the holder changes. Over in-memory state it serves one process.
- Every write of a cursor, segment or `head` checks the fencing token, so a node that lost an account cannot write. A node whose heartbeats stop succeeding also stops acting on its leases after most of the time-to-live, which keeps side effects that storage cannot fence (sending, provider writes) single.
- Long-lived connections (IDLE, JMAP push, Graph subscriptions, Google channels) live with the owner; when a node disappears another takes its accounts over, and a node that shuts down releases its leases.
- OAuth refresh happens only on the owner (Microsoft rotates refresh tokens, so two nodes refreshing at once would invalidate each other); access tokens are shared as signals.
- A local cache only speeds things up; correctness never depends on local disk on a server.

## Signals

Everything that is cheap to lose goes through Baton's `Signal` contract (`baton-signal`), scoped to the tenant's group:

- hints and previews;
- OAuth access tokens (refresh tokens stay sealed in durable storage), discovery results, server capabilities;
- shared counters for rate limits;
- a channel for consumers, scoped to a tenant: `publish(topic, payload)` and `subscribe(topic)` without delivery guarantees, and `put(key, value, ttl)`, `get` for values that expire. Presence, soft locks ("this draft is open on another device"), UI sync between devices, counters, consumer-to-consumer signals. Skein does not interpret it; it only applies tenant scopes.

If every signal is lost, everything keeps working, only slower, through object storage polling.

| Implementation | For |
| --- | --- |
| `baton-signal-local` | one node, library mode |
| a NATS or Redis implementation in Baton (planned) | server deployments with several nodes |

Consumers in the same process reach it directly; across nodes it travels over Baton's transports.

## Extension points

Skein is built so that an application can run it in places this repository does not cover (many nodes without object storage, nodes on user devices, a custom transport between nodes) by supplying its own implementations:

| Contract | Built in | What another implementation can do |
| --- | --- | --- |
| `baton_lease::{Leases, Liveness}` | Baton's `lease-cas` over `ControlState` or in-memory state | decide leases among nodes without object storage, with its own rules for commands that cannot be repeated safely |
| `baton_lease::NodeProfile` | `skein_engine::node_profile` from config | report class, capacity and whether the node can run now, so leases go to capable nodes |
| `baton_signal::Signal` | `baton-signal-local` | carry hints and previews over its own transport |
| `ControlStore`, `Log`, `BlobStore`, `CommandQueue` | `s3`, `fs`, `memory`, `tiered` | keep replicas elsewhere, fetch segments and blobs from other nodes, verified by sequence and hash |
| HTTP routes | `skein_server::router(state)` | merge its own routes next to Skein's |

Rules that keep this working:

- The engine receives every one of these as `Arc<dyn Trait>` through a builder and never checks which implementation it got.
- Every contract ships a conformance suite behind its `testing` feature; an implementation outside this repository proves it keeps the contract by passing it.
- Contract changes follow semver, since implementations outside this repository cannot be fixed in the same change.
- The engine treats the absence of object storage as a normal configuration: the journal can live in any `Log` and `BlobStore`.

## Load estimate

Ten people, each receiving and sending 150 messages a day (3,000 messages, about 100 KB each with attachments, and two or three metadata changes per message), with a shared signal backend:

| | Per day | Per month |
| --- | --- | --- |
| Blobs | 300–450 MB, 3,000–4,500 PUT | 9–14 GB |
| Log segments | about 0.5 MB after zstd, 2,000–3,000 PUT with `head` and `log/heads` | about 15 MB |
| Cursors, ownership, commands | about 2,000 PUT | small |
| Reads by consumers | about 10,000 GET | |
| Initial import | | 50–100 GB once (mailbox history) |

That is about 8,000–10,000 PUT a day, mostly blobs, and a buffer that stays at 10–15 GB with 30-day blob retention. Costs follow mail volume, not the number of accounts. Without a shared signal backend, heartbeats and head polling add a few thousand requests a day per deployment; per-account heartbeats or per-account head polling would add hundreds of thousands, which is why neither is used.

## Security and tenants

- Every account belongs to a tenant, an id from the integrator's side. Tenants and accounts are managed by the operator through the binary's subcommands (and, in Peleda, through Baton commands with Baton's capabilities); there are no API keys.
- Credentials and blobs are sealed with a per-tenant data key through a `Keyring` contract (local key first, AWS KMS and Vault later). Deleting a tenant's key makes its data unreadable; deleting a tenant also removes its objects.
- Webhooks and hints are signed with HMAC and carry a timestamp against replay.
- Every command is audited in the log with its origin.
- Logs, metrics and traces carry ids, counts and timings, never message content, subjects, addresses or secrets.

## Observability

OpenTelemetry from the first phase, through `tracing`, `tracing-opentelemetry` and the OTLP exporter, behind an `otel` feature and off unless configured.

- **Traces:** spans per account sync run, provider request, batch, segment flush and command. A command carries a W3C `traceparent`, and the events it causes carry it too, so one trace runs from the consumer's request through Skein and the provider back to the consumer that reads the result.
- **Metrics:** OTel metrics (sync lag per account, log head age, provider latency and errors, throttling, ownership changes, command outcomes), also exposed for Prometheus scraping.
- **Logs:** structured `tracing` events correlated with the trace id.
- Span attributes follow the logging rule: ids and counts only.

## Inbound HTTP and management

- `skein-server` is the only inbound HTTP: the Gmail Pub/Sub and Microsoft Graph push receivers with their authenticity checks, and a health check. The web portal, the HTTP management API, `openapi.json` and the TypeScript client were removed on 2026-11-25 (see `../docs/DECISIONS.md`).
- The binary manages tenants, accounts, credentials, commands and webhooks through subcommands that write through the same stores; the checks live in the libraries (`skein_accounts::admin`, `skein_engine::check_command`), so Baton commands can reuse them.
- Image: `ghcr.io/peleda-app/rowboat`.

## skein-view

A library that keeps an envelope index, threads (JWZ), search, parsed content, calendars and contacts in SQLite, following a tenant's journal straight from the storage contracts and verifying it through the hash chain. The Peleda app will embed it. It is a separate module on top of the journal, so the core stays dumb.

## Out of scope

- Bulk and marketing sending: templates, campaigns, open and click tracking, bounce and complaint processing, IP warm-up. That is a separate product that can use Skein accounts.
- Parsing for features, indexing, threading, merging edits and trust decisions in the core.

How each of these can be built on top of Skein is described on the documentation site page "Out of scope, and how to build it" (`apps/docs/src/content/docs/start/out-of-scope.md`).

## Repository

```
skein/
├── crates/
│   ├── core/              accounts, tenants, capabilities, change model, events, commands
│   ├── storage/           ControlStore, Log, BlobStore, CommandQueue; envelopes, migrations, conformance
│   ├── storage-s3/  storage-fs/  storage-memory/  storage-tiered/
│   ├── keyring/  keyring-local/
│   ├── oauth/             PKCE, Google and Microsoft presets, refresh, external tokens
│   ├── discover/          autoconfig, ISPDB, SRV, MX hints
│   ├── engine/            leases (Baton), workers, scheduling, backoff, shared rate limits, push and polling, snapshots
│   ├── mail/              mail contract; mail-imap, mail-jmap, mail-gmail, mail-graph
│   ├── send/              sending contract and queue; send-smtp, send-jmap, send-gmail, send-graph
│   ├── calendar/          calendar contract; calendar-caldav, calendar-jmap, calendar-google, calendar-graph
│   ├── contacts/          contacts contract; contacts-carddav, contacts-jmap, contacts-google, contacts-graph
│   ├── itip/              building iTIP and iMIP, choosing server scheduling or iMIP
│   ├── merge/             skein-merge: three-way diffs and field patches for consumers
│   ├── telemetry/         OpenTelemetry setup
│   ├── server/            skein-server: push receivers and health
│   └── view/              skein-view: the mail database over the journal
├── apps/
│   ├── skein/             the binary: config, management subcommands, serve
│   └── docs/              documentation site (Astro Starlight)
├── tests/integration/     GreenMail, Dovecot, Stalwart, Radicale, RustFS and Versity S3 Gateway in containers; Gmail, Graph and Google fakes
├── Cargo.toml  mise.toml   (at the rowboat root)
└── docs/PLAN.md
```

Crates are named `skein-<dir>` and are not published.

Rules: contract crates hold no I/O; implementations depend only on their contract and `skein-core`; only `apps/skein` picks implementations; traits are object-safe `Send + Sync` with `#[async_trait]`; one `thiserror` enum per contract; no provider or driver types cross a boundary; tests run against in-process fakes and never touch the network outside `tests/integration`; fixtures are invented data on `example.com`.

## Moving code from Holtmail

Holtmail's provider layer moves here and is rewritten onto the journal; its archive, search, insights, rules, aliases, serving (IMAP, JMAP, DAV, submission) and web app do not:

| Skein | From Holtmail |
| --- | --- |
| `mail-*` | `source`, `source-imap`, `source-jmap`, `source-graph`, the cursor part of `sync`, `mail-writeback` |
| `send-*` | `submit`, `submit-smtp`, `submit-jmap`, `submit-graph`, `outbox`, `compose` |
| `calendar-*`, `contacts-*` | `collection`, `collection-dav`, `collection-graph`, `collection-jmap`, `collection-merge`, `pim-writeback`, the vCard and iCalendar model of `pim`, `recur` |
| `itip` | `schedule`, `schedule-itip` |
| `merge` | the diff and patch parts of `pim-edit` |
| `oauth`, `keyring`, `engine` | `oauth`, `oauth-http`, `secret`, `secret-local`, push from Holtmail's `PUSH.md`, `sse`, `json-http` |
| `server` hints | `hooks`, `webhook`, `webhook-http` |

Holtmail's integration suites for these providers move to `tests/integration`.

## Documentation

`apps/docs` uses the Holtkeeper setup: Astro Starlight with `starlight-sidebar-topics`, `astro-mermaid` and Geist. It covers the ways to use Skein, the extension points, the journal format and how to write a consumer, every provider (including registering Google and Microsoft OAuth clients and app-only access), storage backends and stateless deployment, observability, and the REST reference rendered from `openapi.json`. It deploys to GitHub Pages; the Rust API docs are built locally with `cargo doc`, since no crate is published.

## Releases

Images on GHCR and binaries for Linux, macOS and Windows; no crate or npm package is published. The pipeline is described in [RELEASING.md](RELEASING.md).

## Work plan

Status as of November 2026: ✅ done, 🚧 in progress, ⬜ not started. Every step ends with its tests (unit tests next to the code, the contract's conformance suite, integration tests against containers where a real server exists, a live test where only the real service will do), its `docs/README.md`, and `mise run check` green. Security notes per step are part of its definition of done, not a later pass.

### Phase 1: foundation ✅

- ✅ `skein-core`: path-safe ids, BLAKE3 hashes, events and commands with schema versions, redacted credentials, TLS roots.
- ✅ `skein-storage`: `Objects` with compare-and-swap, typed `ControlStore`, `Log` (fenced, segment-based), `BlobStore` (hash-checked), `CommandQueue` (idempotent); record envelopes with migrations; `CountingObjects`; conformance suites.
- ✅ `storage-memory`, `storage-fs`, `storage-s3` (conditional writes; plain HTTP only to loopback).
- ✅ `skein-keyring` + `keyring-local`: per-tenant data keys wrapped by a master key, per-account keys wrapped under them (`KeyScope`), crypto-shredding per tenant or account.
- ✅ Coordination: leases, liveness and signals from Baton's contracts (`baton-lease`, `baton-signal`), with `lease-cas` over `skein_storage::ControlState` as the built-in arbiter; the former `skein-ownership*` and `skein-ephemeral*` crates are removed and their conformance suites live in Baton's.
- ✅ `skein-telemetry` with optional OTLP.
- ✅ [Storage requirements](REQUIREMENTS.md) checked against RustFS and Versity in CI.

### Phase 2: mail providers ✅

1. ✅ `mail` contract, `FakeMail`, conformance suite.
2. ✅ `mail-imap`, ported from Holtmail: TLS/STARTTLS, XOAUTH2, Gmail labels, CONDSTORE, IDLE/NOTIFY, compact cursors, writes.
3. ✅ `skein-oauth` and `skein-oauth-http` (from Holtmail `oauth`, `oauth-http`, `json-http`):
   - authorization code with PKCE (S256), `state` checked in constant time, presets for Google and Microsoft with scopes per domain (mail, calendar, contacts) and per access (IMAP, API);
   - token refresh through a `TokenEndpoint` contract with an HTTP implementation; Microsoft's rotated refresh tokens are stored back; refresh happens on the account's owner only;
   - access tokens cached as signals, refresh tokens sealed by the keyring;
   - external tokens handed in by integrators, with or without a refresh token;
   - `invalid_grant` becomes `reauth_required`;
   - tests: PKCE vectors, redirect parsing (wrong state, error responses, missing code), refresh against an in-process fake token endpoint, rotation, no secret in `Debug` or logs.
4. ✅ `mail-gmail`: the Gmail API with
   - mailboxes from labels (system labels mapped to roles, user labels as `label: true` mailboxes; one journal of messages in `All` with labels, like IMAP on Gmail);
   - first listing with `messages.list` (paged, newest first), changes with `history.list` from `historyId` (`messageAdded`, `messageDeleted`, `labelsAdded`, `labelsRemoved`); an expired `historyId` (404) becomes `Reset`;
   - raw bytes with `format=raw` (base64url), metadata with `format=minimal`;
   - writes: labels and `UNREAD`/`STARRED` for flags, move as label change, delete as `TRASH` or `messages.delete`, append as `messages.insert`;
   - quota: per-user rate limiting (250 units/s), `429`/`403 rateLimitExceeded` to `Throttled` with `Retry-After`, batched `get` requests;
   - push: `users.watch` with Pub/Sub where configured, polling otherwise;
   - tests: an in-process fake Gmail API implementing `ServerControl`, the mail conformance suite against it, history expiry, throttling, label mapping, and the live suite with `SKEIN_LIVE_GMAIL_*`.
5. ✅ `mail-graph`, ported from Holtmail `source-graph`: delta links per folder, `$value` for raw bytes, flags from `isRead`/`flag`, writes, `410` to `Reset`, throttling with `Retry-After`; fake Graph server; Dev Proxy for throttling and error injection in CI once the provider exists; live suite with `SKEIN_LIVE_GRAPH_*`.
6. ✅ `mail-jmap`, ported from Holtmail `source-jmap`: `Email/changes`, `Mailbox/changes`, blob download, EventSource push, writes; Stalwart in the integration stack.
7. ✅ Integration stack: Dovecot (real CONDSTORE, QRESYNC, NOTIFY, MOVE, UIDPLUS) and Stalwart next to GreenMail.

### Phase 3: engine 🚧

1. ✅ Sync with the write order blobs → previews → events → cursor; replay protection by event keys; fencing; health events; Gmail label mailboxes skipped next to `All`.
2. ✅ Commands once, with markers against repeats after a crash.
3. ✅ Node loop: heartbeats, rendezvous assignment, workers with push, hints, interval and backoff.
4. ✅ `skein-accounts`: account records without secrets, sealed passwords, OAuth grants through `TokenManager`, and a `Directory` that resolves credentials only when the owner connects.
5. ✅ Snapshots: `Snapshot` folded from the journal, stored by the `Log` contract (last two kept), taken after syncs every 5,000 events, served at `GET .../snapshot`.
6. 🚧 Retention: ✅ compaction of events covered by a snapshot older than the retention window, with `Compacted` / HTTP 410 for readers that fell behind; ✅ completed commands are already removed; ✅ the `refetch` command; blob expiry is left to object storage lifecycle rules.
7. 🚧 ✅ `storage-tiered` (read-only tiers after local storage, every byte verified by hash; writable tiers and replication not yet); ⬜ a shared signal backend for several nodes (in Baton); ✅ a per-account rate limiter shared across domains, for Microsoft Graph (`skein-throttle`: the mail, calendars and contacts providers and the sender of one account share four slots and every `Retry-After` pause); other providers have none yet.
8. ✅ Load tests through the node loop: 1,000+ accounts per node with request budgets, failover with crashed and heartbeat-less nodes checked for whole journals and refused stale tokens, and S3 latency with jitter via `SlowObjects`.
9. ✅ Tamper-evident journal: segments chained by BLAKE3 hash, the head naming the last segment, a pluggable `HeadAttestor` (none by default), verification of segments from any `SegmentSource` against a trusted head (`Chain`, `locate`, `verify_extends`), rollback and fork detection; journals written before chaining keep reading and are chained from the next segment.

### Phase 4: sending ✅

- ✅ Done: `skein-send` contract with a conformance suite ("not sent" versus "maybe sent"), `send-smtp`, `send-gmail`, `send-graph`, `send-jmap`; `CommandBody::Send` with scheduled send, retries with backoff only when nothing was sent, uncertain outcomes never resent, save to Sent when the provider does not, per-recipient refusals in `send_result`; workers wake for the next scheduled send; GreenMail and Stalwart integration tests.
- ✅ Also done: an undo window (`SendPolicy::undo_ms`, `[engine] send_undo_secs` in the binary: a send stays queued until `created_at` plus the window, so cancelling stops it), dry run (`dry_run` on `send`: every check, nothing handed over, `send_result` with `dry_run`), `retry_after` from servers (`SendError::Throttled` from HTTP `429`/`503` with `Retry-After`; the next try waits for it, at most an hour), paging past the first 100 queued commands (a run pages through up to 2,000). Scheduled send per recipient is by separate commands: one `send` per send time.
- ✅ `send-ses`: Amazon SES v2 `SendEmail` with the raw message, in-crate SigV4, a sealed per-account access key (`PUT .../send-key`), an endpoint override for SES-compatible services; the engine saves the sent copy. ✅ SES replaces the `Message-ID`: `SendReport` carries the delivered `Message-ID` and the provider id, and the engine saves the sent copy with the delivered id (original in `X-Skein-Original-Message-ID`) so replies thread.
- Original scope: `skein-send` contract and queue semantics (scheduled send per message and per recipient, undo window, retries, uncertain outcomes, save to Sent, DSN, dry run), from Holtmail `outbox`, `compose`, `submit*`.
- `send-smtp` (TLS, STARTTLS, XOAUTH2), `send-gmail`, `send-graph`, `send-jmap`.
- Tests: GreenMail SMTP in the stack, fakes for the APIs, live suites sending to the test account itself.

### Phase 5: server and binary 🚧

- 2026-11-25, by the maintainer's decision: the HTTP management API, its key auth, scopes, rate limits, CORS and account host policy, `openapi.json`, the TypeScript client, OAuth sign-in through the server and the SSE stream were removed. What stays of this phase: `skein-server` as the push receivers and health check (with a push rate limit per receiver), the binary with management subcommands (`tenant`, `account`, `journal`, `webhook`, `push-token`) writing through the same stores, the command checks in `skein-engine` and the record checks and purge in `skein-accounts`, export/import/copy, metrics, webhooks (managed from the command line), cancelling, account health (shown by `skein account show`), the release pipeline with one image. The items below are kept as history.
- ✅ `skein-server`: tenants, API keys (hashed, scoped, rate-limited, IP allowlists with trusted proxies), accounts and credentials, OAuth sign-in with a public callback, journal and blob reads, blob uploads and idempotent commands with `traceparent`, SSE hints, purge with crypto-shredding (a purged id cannot be registered again), `openapi.json` with a drift test.
- ✅ `apps/skein`: TOML config with secrets from the environment only, the composition of every implementation, node and API in one process with graceful shutdown, `admin-key`, `check-config`; Dockerfile; end-to-end test of the binary in the integration stack.
- ✅ `skein export` / `import` (zstd NDJSON, sealed records stay sealed, never overwrites, a file cannot be imported into another tenant) and `skein copy` between storages.
- ✅ Metrics: `skein-metrics` counters with fixed labels (sync runs by result, events, commands by outcome, snapshots, compaction, storage requests), served in the Prometheus text format on an internal `[metrics] listen` address.
- ✅ Signed webhooks (`skein-webhooks`): HMAC-SHA256 over timestamp and body, at-least-once delivery in log order per endpoint and account with backoff up to an hour and a pause after three days of failures, compaction notices, SSRF protection with checked DNS resolution, routes to manage, rotate and test endpoints, `[server.webhooks]` config.
- ✅ TypeScript client `@peleda-app/skein-client` generated from `openapi.json` with a drift check, typed helpers, 410 handling and an SSE iterator; part of `mise run check`.
- ✅ Cancelling queued commands: `DELETE .../commands/{id}`, decided by compare-and-swap on the command's marker so a command either never runs or is reported by the engine.
- ✅ Key lookups cached for 30 seconds (negative answers too), dropped at once on the revoking node; at most 8 live streams per tenant key; purge deletes the tenant's journal, blobs and commands through `Storage::purge_tenant`.
- ✅ OTel metrics export: the same counters over OTLP, opt-in with `[telemetry] otlp_metrics`.
- ✅ Account health in the accounts API (`health`: worst state, per-domain outcome, last success and failure, resync flag, log head) from a status record the owner writes; opt-in CORS (`[server.cors]`).
- ✅ A shared rate limit across nodes: a sliding one-minute window over `Signal::incr` counters, falling back to per-node buckets where the backend has no counters.
- ✅ Hardening: an OWASP API Top 10 review ([SECURITY-REVIEW.md](SECURITY-REVIEW.md)) with a cross-tenant test over every route in `openapi.json`, header and body read timeouts and a connection cap on every listener, field length limits on commands, an optional allowlist for account hosts against SSRF, security headers and `no-store` on secrets, a bounded key cache, capped decompression in import and journal segments; property tests of request parsing; cargo-fuzz targets for every parser of provider and file input ([fuzz/README.md](../fuzz/README.md)) with a weekly workflow, which found and fixed five parser bugs.
- ✅ Release pipeline, switched off ([RELEASING.md](RELEASING.md)): signed multi-arch images (`rowboat`, `rowboat-view`) with SBOM and provenance, `skein` and `skein-view` binaries for Linux (musl), macOS and Windows with checksums and attestations.
- Original scope: `skein-server`: REST over accounts, OAuth flows, journal reads, snapshots, commands and health; API keys scoped to tenants with access scopes, IP allowlists and rate limits; signed webhooks and SSE hints; `utoipa` → `openapi.json` with a CI drift check; `@peleda-app/skein-client`.
- `apps/skein`: config file and environment, storage and keyring selection, `migrate`, `export`, `import`; Docker images `skein` and `skein:headless`.
- Security: OWASP API Top 10 review, request size limits, constant-time key comparison, no secrets in responses or logs, fuzzing of request parsing.
- Tests: HTTP tests per route, end-to-end tests with the binary in the integration stack.

### Phase 6: calendars and contacts 🚧

- ✅ `skein-pim` contract (collections with kind, name, color, access; a change feed per collection with `Reset`/`Upserted`/`Removed`; exact bytes; conditional writes with idempotent creates), `FakePim`, conformance suite; core events `collection_upserted`, `collection_deleted`, `object_upserted`, `object_removed` and commands `put_object`, `delete_object`, folded into snapshots.
- ✅ `skein-pim-dav`: discovery, `sync-collection` with an ETag-listing fallback, multiget, `If-Match`/`If-None-Match` writes, same-origin credentials, size limits, no XML entities; conformance against an in-process fake in four server modes.
- ✅ Engine: `sync_collections` and `run_pim_commands` with mail's guarantees (fencing, blobs → events → cursor, replay protection, started markers); Radicale round trip in the integration stack.
- ✅ Routing PIM commands and syncs in the node loop and the binary, server checks for `put_object` blobs, Google Calendar and People, Graph, JMAP.
- ✅ `skein-itip`: reading and building iTIP and iMIP; `itip_received`; `respond_object`, `respond_invitation`, `notify` on object commands, `schedule_result`; `PimSession::scheduling` and `addresses`; RFC 6638 in `pim-dav` (`calendar-auto-schedule`, `calendar-user-address-set`, `Schedule-Reply`, the scheduling inbox).
- ✅ Stalwart CalDAV in the stack (real `calendar-auto-schedule`, `calendar-user-address-set`, scheduling inbox, an answer through the server); answers reach JMAP `recurrenceOverrides`.
- ⬜ Left: `skein-merge`, WebDAV-Push, Baïkal in the stack, recurrence and time zone cases beyond iTIP (one-instance invitations, floating times and exceptions are covered there), free-busy through the scheduling outbox, live tests of answering on Google and Graph.
- Contracts and providers: CalDAV/CardDAV (from Holtmail `collection-dav`), Google Calendar and People, Graph, JMAP; original iCalendar, vCard or provider JSON as blobs; writes with version preconditions; `skein-itip` (from `schedule`, `schedule-itip`); `skein-merge` (from `pim-edit`).
- Tests: Radicale, Baïkal and Stalwart in the stack; fakes for Google and Graph; recurrence and time zone cases.

### Phase 7: portal, documentation site, skein-view 🚧

- 2026-11-25, by the maintainer's decision: the portal is removed, the documentation site lost its API reference, and `skein-view` became a library (`crates/view`) that follows a journal straight from the storage contracts with hash-chain verification; its binary, REST API, SSE follower and image are gone. The items below are kept as history.
- Portal (React, bun) on the generated client only; documentation site on Astro Starlight; `skein-view` with envelopes, JWZ threads and search over the journal.
- ✅ `skein-view` (`apps/view`): follows a tenant through the public API with a `read` key (heads polling, pages applied with the checkpoint in one SQLite transaction, 410 → snapshot rebuild), parses with `mail-parser` (ids, decoded subject and addresses, dates, text, unsanitized HTML, attachments, snippet), one message per blob with memberships per mailbox, JWZ grouping by ids with merges and late parents, FTS5 search with quoted user terms, a bearer-token REST API (accounts, mailboxes, messages with cursor paging, raw bytes, threads, search); end-to-end test against an in-process `skein-server`. ✅ Also: SSE hints per account (up to `follow.streams`, polling for the rest and a safety pass every five minutes), calendars and contacts (collections, objects with parsed iCalendar, vCard and provider JSON fields, a time range filter without recurrence expansion, contact search), the JWZ container tree, versioned schema migrations, opt-in CORS. ⬜ Left: a tenant-wide hint stream on the server so one consumer needs one stream; exact time zones (only the standard offset of an embedded `VTIMEZONE` is used).
- ✅ Portal, first version (`apps/portal`): sign-in with an admin or tenant key kept in session storage; tenants, keys (shown once) and typed purge confirmation; accounts with health and log head, record editor, passwords, OAuth start; journal browser with type filters, live SSE updates and the snapshot after a 410; commands with templates and generated idempotency ids, cancel; webhooks. Account health comes from the API's `health` field (a per-account status record written by the engine, fresh within a minute). Embedded with `rust-embed` behind the `portal` feature, served at `/` without shadowing `/v1`, `[portal] enabled`; the default image ships it, `skein:headless` does not.
- ✅ Documentation site (`apps/docs`, a standalone bun project): Starlight with sidebar topics (getting started, concepts, providers with OAuth client registration and app-only access, scheduling, deployment and storage, consumers, extending), Mermaid diagrams, Geist, the REST reference rendered from `openapi.json` by `starlight-openapi`, a link checker that fails the build, and `.github/workflows/docs.yml` building on pull requests and deploying to GitHub Pages from `main`. ⬜ Left: pages for the portal and `skein-view` once they ship.

### Order right now

1. ✅ The rest of phase 5 (webhooks, export/import, metrics); the TypeScript client was removed with the API.
2. The sending leftovers (undo, cancel, queue paging).
3. ✅ Push for Gmail (Pub/Sub, secret in the push URL) and Graph (subscriptions with clientState), renewed by the account's owner after runs and waking its worker through `push/{account}` hints; ✅ Pub/Sub OIDC token verification (opt-in); ⬜ Dev Proxy in CI for Graph throttling.
4. 🚧 Calendars and contacts: ✅ DAV wired into accounts (`pim` settings), the binary and the node loop, with a Radicale end-to-end test through the binary; ✅ separate credentials for calendars and contacts (`pim.auth`, `PUT .../pim-password`); ✅ `domain` on `resync_required`; ✅ Google Calendar and People (`pim-google`), Graph (`pim-graph`) and JMAP (`pim-jmap`, tested against Stalwart), all selectable through `pim.kind`; objects are the provider's JSON where it has no iCalendar or vCard; ✅ iTIP and RFC 6638 (`skein-itip`, answers, organizer notifications, iMIP where the server does not schedule, `itip_received`, the CalDAV scheduling inbox); ⬜ a shared conformance suite for JSON providers (each crate carries its own today).

✅ Follow-ups for the `skein-mail` contract: labels without moving (`set_labels`), delete to the trash or for good (`to_trash`), `copy`, mailbox create, rename and delete, which flags a provider can set (`capabilities`, journaled as `account_capabilities`), `received_at` for `append`, "nothing changed" errors that run again instead of turning uncertain, and a write conformance suite run by every provider. ⬜ Still open: push delivered from outside (webhooks) instead of a held connection for IMAP.

## Open questions

- Do consumers read Skein's bucket directly (read-only on `log/`, `blobs/`, `snapshots/`, write on `commands/`), or does Skein replicate to their storage?
- Segment format: NDJSON + zstd first; Parquet if analytics straight on object storage (DuckDB, Athena) becomes a goal.
- Google OAuth: Gmail scopes are restricted, so a public OAuth client needs Google's CASA assessment; Calendar and Contacts scopes are sensitive. Self-hosted users bring their own client, and the docs must say so from the start.
