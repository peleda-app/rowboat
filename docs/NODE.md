# rowboat-node, phases 0 and 1

The implementation spec of the node layer for [PLAN.md](PLAN.md) phases 0 (foundation) and 1 (node on one device): the first node that reads and sends mail on a desktop, with IMAP and SMTP accounts signed in by password or app password. The app side of the same step is `../app/docs/DESKTOP.md` (the app's phase 2). OAuth for Gmail and Outlook, the group, handover, servers, push and aliases come in later phases and are only kept possible here. The group, pairing, replication, commands, handover and the server (phases 2 and 3) are specified in [GROUP.md](GROUP.md).

Status: built on 2026-11-26, including (later the same day) Skein change 9 (the `probe` functions and the node's `ServerProber`), discovery from the domain's autoconfig file and DNS SRV records, typed causes in Skein's `MailError` and `SendError`, and re-parsing in the background on a parser version change. Not built: re-parsing on read (only the background rounds), the live suite (it needs the maintainer's accounts), and the moved `push` crate. The integration suite (`tests/integration`) was built later the same day. Where this document and the code disagree, the crates' `docs/README.md` win; the departures are listed in `docs/DECISIONS.md` (2026-11-26, node phases 0 and 1 built).

## What phase 1 delivers

- A Peleda desktop app (macOS first, Linux compiling) embeds `rowboat-node` with the desktop profile. The node is the only owner of every account on that device (a group of one node).
- Accounts: IMAP for reading, SMTP submission for sending, one password or app password per account, TLS or STARTTLS only.
- Sync through Skein's engine under a local lease, into a journal and blobs on local disk (`skein-storage-fs` under a directory the app gives), followed into `skein-view` as the mail database.
- Commands: add and remove an account, sync now, list mailboxes, list threads and messages, open a message, mark read, flag, move, archive, delete, send with an undo window, search, local drafts.
- An event stream the app subscribes to; ids, counts and kinds only.
- Hooks for spam and categories, minimal: spam from the provider's Junk placement and rinse's authentication facts, categories from bento. Pellet joins later inside the sandbox (question 41).

Not in phase 1: OAuth providers (Gmail and Graph APIs, XOAUTH2), JMAP accounts (the provider exists in Skein, its setup flow does not), calendars and contacts, a second node, Baton commands over the link, push, S3, aliases, remote content, the Original view, IMAP drafts sync.

## Crates

New crates of the node layer for phases 0 and 1. The planned crates in PLAN.md "Layout of the node layer" (`sync`, `push*`, `aliases*`, `rules`, `license*`) keep their phases; `push` still moves from `../app` in phase 0.

| Crate | Package | Kind | Job |
| --- | --- | --- | --- |
| `crates/api` | `rowboat-api` | contract | `NodeApi`, the node's whole surface for an app: requests, responses, events, `NodeError`, the validation every caller and the node run, the conformance suite |
| `crates/keystore` | `rowboat-keystore` | contract | the device secret store the node keeps its identity and master key in; the app implements it over its vault |
| `crates/keystore-memory` | `rowboat-keystore-memory` | implementation | in memory, for tests and the test profile |
| `crates/discover` | `rowboat-discover` | contract | `DiscoverySource`: candidate IMAP and SMTP servers for an address domain; `Candidate`, ranking and merge rules (pure) |
| `crates/discover-table` | `rowboat-discover-table` | implementation | the embedded table of well-known providers plus the conventional host guesses |
| `crates/discover-autoconfig` | `rowboat-discover-autoconfig` | implementation | the domain's own autoconfig file over an `HttpsFetcher`, with the bounded `clientConfig` decoder |
| `crates/discover-srv` | `rowboat-discover-srv` | implementation | the domain's DNS SRV records (RFC 6186, RFC 8314) over an `SrvResolver` |
| `crates/discover-net` | `rowboat-discover-net` | implementation | `Https` (the `HttpsFetcher` over `reqwest`) and `UdpResolver` (the `SrvResolver` over UDP to the system's name servers, with the bounded DNS answer reader) |
| `crates/spam` | `rowboat-spam` | contract | `SpamFilter`: a verdict for one rendered message |
| `crates/spam-signals` | `rowboat-spam-signals` | implementation | verdict from the provider's Junk placement and rinse's authentication facts |
| `crates/category` | `rowboat-category` | contract | `Categorizer`: a category for one rendered message |
| `crates/category-bento` | `rowboat-category-bento` | implementation | bento's analyzer over rinse's document model |
| `crates/compose` | `rowboat-compose` | library | a draft to RFC 5322 bytes and a send envelope; pure, deterministic |
| `crates/node` | `rowboat-node` | library (node builder) | the builder and profiles, the runtime around Skein's engine and `skein-view`, `NodeApi` in process, drafts, the pending overlay, the event stream |
| `tests/load` | `rowboat-load` | test | node load tests (see "Tests") |

`rowboat-node` is a node builder in the sense of RULES.md MOD-4: it picks Skein and Baton implementations for each profile and receives everything platform-specific (keystore, content, data directory) from the app. dojo has no kind for a composition library, so it declares `library` and `docs/DECISIONS.md` records why, as the app does for `peleda-core`.

Dependencies: `rowboat-node` depends on `rinse-mail` (open, the content contract) and on bento's crates (open) by path, as LIC-5 allows. It never depends on `../app` or `../tinginys` (private).

### Changes this needs in `skein/`

Each lands in Skein with its own tests and README changes; none names Peleda or rowboat.

1. **`skein-view` takes its parser as a hook.** A `MessageParser` trait (`async fn parse(&self, raw: &Bytes) -> Result<ParsedMessage, ParseError>`, `fn version(&self) -> &str`) and `ParsedMessage` (message id, in-reply-to, references, subject, from, to, cc, reply-to, date, attachments list with part index, name, type and size, text body capped at 1 MiB, invitation summary, and `tags`). `Follower::with_parser(Arc<dyn MessageParser>)`; the current `mail-parser` code becomes the default `MailParser` the `skein` binary and Skein's own tests keep. The stored HTML body goes away for parsed content from a hook (it has no consumer in Peleda; the Original view comes through rinse, phase 7). This answers question 16 for the node: nothing in the node process parses message bytes. A message the parser refuses is stored as unavailable, as a missing blob is today. The database records the parser's version per message; a version change re-parses lazily on read and in the background, bounded per round.
2. **`skein-view` tags.** `tags` from the parser (at most 8, each 1 to 64 characters of `[a-z0-9._-]`) stored per message, filterable in `messages`, `threads` and `search`.
3. **`skein-view` scopes.** `account: Option<&str>` on the list and search reads (every account of the tenant when `None`), a mailbox filter by role (`inbox`, `sent`, `drafts`, `archive`, `junk`, `trash`) besides by id, and a `flagged` filter; paging stays `(sort_date, id)`.
4. **`skein-view` addresses.** An `addresses` table filled at parse time (address, name, account, last seen, count as sender and as recipient), with `suggest_addresses(prefix, limit)`, and `knows_address(account, address)`, which is true only for a `To` or `Cc` of a message in a `sent` mailbox, so an inbound message naming an address never makes it known.
5. **`skein-view` observer and forgetting.** `Follower::with_observer(Arc<dyn ViewObserver>)`, called after each committed page with the account, the new checkpoint, the mailboxes whose memberships changed (capped at 64, else "many"), whether mailboxes themselves changed, and the command outcomes in the page (`origin`, kind, reason word); `Store::forget_account`.
6. **`skein-storage-sealed`** (new implementation of `skein-storage`'s `Objects`): wraps any `Arc<dyn Objects>` and seals every value with XChaCha20-Poly1305 under a 256-bit key given by the caller, the object key and a format version as associated data, so a value moved to another key does not open. Keys stay readable (they hold tenant, account and mailbox ids and blob hashes). Versions and compare-and-swap pass through. Runs `all_over_objects` and its own attacks (moved, truncated, bit-flipped, replayed-from-another-key values). The hosted server (phase 3) reuses it.
7. **`skein-keyring-local`** gains `LocalKeyring::with_master_key(MasterKey, control)`, the master key handed in as zeroized bytes instead of read from a file; the file variant stays for the `skein` binary.
8. **`skein-storage`** gains `purge_account(tenant, account)` on the typed stores (log, heads, snapshots, commands, the account's control records); blobs are shared by content address and are swept separately (see "Removing an account").
9. **`skein-mail-imap` and `skein-send-smtp`** gain `probe(host, port, security, roots, timeout)`: connect, verify TLS (or STARTTLS), read the greeting and the capabilities before sign-in, send nothing else and no credentials; with a timeout and the existing reply caps. Used by discovery to check guessed hosts.
10. **`skein-engine`** exports `wake_topic(account)`, the `commands/{account}` topic its workers wake on, so the node does not spell Skein's topic names.

## Profiles and the builder

```rust
let node = rowboat_node::Node::builder()
    .profile(Profile::Desktop)
    .data_dir(app_data_dir.join("node"))
    .keystore(keystore)            // Arc<dyn rowboat_keystore::Keystore>, the app's vault adapter
    .content(content)              // Arc<dyn rinse_mail::Content>, the app's sandboxed workers
    .spam(spam)                    // optional, default spam-signals
    .category(category)            // optional, default category-bento
    .discovery(vec![table])        // optional, default discover-table only
    .build()
    .await?;
let api: Arc<dyn NodeApi> = node.api();
node.start().await?;               // engine and follower tasks
// ...
node.shutdown().await;             // stops workers, releases every lease
```

| | Desktop (phase 1) | Test (phase 1) | Phone (app phase 3) | Server (phase 3) |
| --- | --- | --- | --- | --- |
| node class | `Desktop` (`node_profile(id, 1, false)`) | `Desktop` | `Phone` | `Server` |
| objects | `skein-storage-sealed` over `skein-storage-fs` at `<data_dir>/objects` | `skein-storage-memory` | as desktop | `skein-storage-s3` or files |
| leases and liveness | `baton-lease-cas` over `ControlState`, heartbeat 10 s, time-to-live 30 s | same, manual clock | same | as configured |
| signals | `baton-signal-local` | same | same | as configured |
| keyring | `skein-keyring-local` with the master key from the keystore | same over `keystore-memory` | same | sealed to the group |
| providers | `skein-mail-imap`, `skein-send-smtp` | `skein_mail::testing::FakeMail`, `skein_send::testing::FakeSender` | as desktop | all |
| engine interval | 120 s, IDLE watches on, undo window 10 s | 50 ms, undo window configurable | per platform | 300 s |
| follower | `<data_dir>/view/view.sqlite`, poll 5 s, woken by `heads/{account}` | in a temporary directory | as desktop | none |
| content workers | at most 2 renders in flight | `rinse-mail-direct` | 1 | `rinse-mail-process` |

`build` fails with a typed `BuildError` (missing service, data directory not usable, `Locked` when another process holds it, `KeysLost`, see below) and never creates a half-initialized directory: the first run writes the node record last.

## Identity, group and the data directory

On the first `build` over an empty directory the node:

1. creates the Ed25519 identity (`baton-identity`) and stores its secret in the keystore as `rowboat.identity` (class `Background`); the node id is the public key's id (52 characters);
2. creates a random 256-bit master key and stores it as `rowboat.master` (class `Background`);
3. derives the objects sealing key from the master key (BLAKE3 `derive_key`, context `rowboat-node objects v1`) and opens the sealed objects;
4. picks a group id (`g` and 26 random lowercase base32 characters; a valid `TenantId`), registers it as Skein's tenant (`TenantRegistry::add`) and writes the genesis roster of one member (Baton phase 2 builds on it);
5. writes the node record `system/node` (format version, node id, group id, profile, creation time) as the last step.

Later starts read `system/node`, load both keystore items and refuse to start with `KeysLost` when the record exists but either item is missing or does not open the objects: a new key would orphan every sealed object, so the app asks the person (retry when the keychain is locked, or start over, which deletes the directory). A directory without `system/node` but with other content is `NotEmpty`, never reused.

```
<data_dir>/
  objects/        skein-storage-fs root: sealed control records, journal segments, blobs, commands, drafts
  view/view.sqlite, view.sqlite-wal, view.sqlite-shm
```

`skein-storage-fs` holds an exclusive lock on `objects/`, so a second process over the same directory fails with `Locked`. The database is written by this process only. Directories are `0700` and files `0600`. The database is not encrypted in phase 1 (question 40); everything under `objects/` is.

## Keystore contract

`rowboat-keystore` is the only way the node reaches device secrets. It is deliberately smaller than the app's `peleda-vault`, which it maps onto one to one.

| Item | Guarantees |
| --- | --- |
| `KeyName` | 1 to 64 characters of `[a-z0-9.-]`, not starting with `.`; the node uses `rowboat.identity` and `rowboat.master` only |
| `KeyClass` | `Foreground` (readable while the device is unlocked) or `Background` (from the first unlock until shutdown, for background work); never shared with app extensions, never synced or backed up |
| `Keystore::get(name)` | the secret, or `None` when the item does not exist; `Locked` when it exists but cannot be read now; never returns another item's bytes |
| `Keystore::put(name, secret, class)` | atomic: a failed put leaves the old item readable; `Unsupported` when the class cannot be honoured |
| `Keystore::delete(name)` | `true` when an item was removed |
| `Secret` | zeroized on drop, `Debug` shows only the length |
| `KeystoreError` | `InvalidName`, `Locked`, `Denied`, `Unsupported`, `Backend` (no secret, path or platform text) |

Conformance (`testing::keystore(factory)`): round trip, missing items, delete, replace, persistence across two instances from the factory, a failed put keeping the old item (when the factory can inject it), invalid names refused, `Debug` of secrets.

The app's adapter is `peleda-keystore-vault` (in `../app`) over `Arc<dyn peleda_vault::Vault>`: `Foreground` is `Protection::APP_ONLY`, `Background` is `AfterFirstUnlock` without sharing.

## Credentials

Account passwords are sealed by Skein's keyring under the account's scope (`skein-accounts`, `credentials/{account}/password`), in the sealed objects. The keyring's master key and the objects key both exist only in the keystore, so no password or key that opens one is ever on disk in the clear, and nothing outside the keystore can open them (question 39 records the alternative of one keychain item per password). Passwords enter the node only through `add_account` and `update_password`, as a `Secret`, and leave it only to the provider being connected. They are never returned, logged or put into events or errors.

## Running Skein's engine

`node.start()` spawns two tasks.

- **Engine.** `skein_engine::run(engine, directory, run_config, stop)` with `skein_accounts::Directory` over the tenant, the node's `ProviderFactory` and `SenderFactory` (IMAP and SMTP only in phase 1; any other kind is `MailError::Config`), `Senders` for sending, `SendPolicy { undo_ms: 10_000, .. }`. The engine takes the lease of every account (a group of one node always wins it), heartbeats, keeps one worker per account that syncs on IDLE, on `wake_topic(account)` hints and on the interval, and releases every lease on shutdown. A new account is picked up on the next heartbeat; `add_account` also publishes a wake hint.
- **Follower.** `skein_view::Follower` over the same storage and tenant, with the parser adapter (below), the head attestor the log uses (`NoAttestor` in phase 1), the signal for `heads/{account}` hints and the node's `ViewObserver`.

`sync_now(account)` publishes on `wake_topic(account)` for one or every account; the worker runs pending commands, then a sync. Calls are coalesced: at most one pending wake per account.

The account status (`skein_core::AccountStatus`, one control record per account) is read once per heartbeat per account and on every observer call; a change becomes an `AccountStatus` event.

## The content contract and the parser adapter

The node never parses message bytes. The engine it runs is built with `without_message_inspection`, so sync does no iMIP detection (no `itip_received`, no calendar part stored) and `respond_invitation` fails with `unsupported`; the end-to-end test `a_calendar_part_is_never_parsed_in_the_node_process` holds this. It receives `Arc<dyn rinse_mail::Content>`, which the app implements with rinse's sandboxed workers (`rinse-mail-process` and the shell's `rinse-worker` sidecar on macOS and Linux) and tests with `rinse-mail-direct`.

The node implements `skein_view::MessageParser` over it:

1. `render` the raw bytes with display-only options: no original HTML, no remote images, images re-encoded at the smallest size (`max_image_px` 1: the engine never goes below 1 px, so 0 failed verification for every message with an inline image), the profile's limits;
2. `rinse_mail::verify_rendered` on the result, whatever implementation produced it; a failure is `ParseError::Refused` and the message is listed as unavailable;
3. map `Rendered` to `ParsedMessage`: headers and thread facts from `headers` and `facts.thread`, the text body from `text`, attachments from `attachments`, the invitation from `facts.invitation`;
4. run the spam and category hooks on the same `Rendered` and put their results into `tags` (`spam.junk`, `spam.suspicious`, `category.<class id>`).

The parser's version is the node's adapter version joined with the content implementation's, the spam filter's and the categorizer's versions, so a new rinse, bento or rule table re-parses messages lazily.

Throughput is bounded by the workers: renders run at most `content_workers` at a time, the follower parses at most one page (200 events) ahead, and a first sync of a large mailbox shows messages as their envelopes are parsed (see "Events").

## Spam and categories

Both hooks are synchronous, CPU-bound contracts (MOD-5) over `rinse_mail::Rendered` and a small context (account id, the mailbox roles the message sits in). They never see raw bytes and never reach the network.

- **`rowboat-spam`**: `SpamFilter::verdict(&SpamInput) -> SpamVerdict { Clean, Suspicious, Junk, NotChecked }` and `version()`. `spam-signals` says `Junk` for a message in a mailbox with the `junk` role, `Suspicious` when rinse's authentication facts show a failed DMARC or a `From` domain the authenticated domains do not align with, `Clean` otherwise, and `NotChecked` instead of `Clean` when the topmost `Authentication-Results` field is not from one of the account's receivers (`receivers_for` over its IMAP host and address, which the parser adapter reads once per account). Pellet's verdicts (content rules, classifier, reputation) need Pellet inside the content sandbox, since Pellet parses raw messages itself (question 41).
- **`rowboat-category`**: `Categorizer::category(&CategoryInput) -> Option<ClassId>` and `version()`. `category-bento` builds bento's `MessageInput` from `Rendered` with bento's own adapter, runs `bento::standard()` and returns the top class at `Likely` or better; personal mail returns `person.direct`. Nothing else of bento (codes, insights) is used in phase 1.

### Notifications

The observer hands the node every message a committed page added once the account's first sync finished before that page (pages of a rebuild never count), unread arrivals only. The node reads each one's envelope, mailbox role and tags from the database and asks `bento_notify::decide_in_place` for a desktop decision with stored values only: the folder from the role, freshness (unread, with a receive time from the server, and received at most 24 hours before the node's clock and never after it, so a message moved into the inbox or listed late does not notify and no sender-written `Date` makes mail fresh), `spam.junk` as a tagged spam action and `spam.suspicious` as a suspicious score (a message the content pipeline refused, stored unavailable, counts as suspicious too, so it is at most silent), the kind from the category's taxonomy hint (`notification` when there is none), trust `unknown` (nothing is escalated until authentication facts are stored), no presence (desktops never defer). The settings are bento's defaults (`Important`) with the account `Off` when its `notify` switch is off and its skipped mailboxes excluded; the rate state lives in memory per node. Alerts the policy coalesced (rate limits, bursts) become `silent`; `none` and `digest` are dropped. One `NewMail` event per batch carries ids and the decision only; the app reads sender and subject itself.

The app shows tags as filters and badges only; a tag never moves, deletes or hides a message in phase 1.

## The mail database

`skein-view` answers every read. Ids crossing `NodeApi`:

| Id | Form |
| --- | --- |
| account | `AccountId`, generated by the node: `a` and 26 lowercase base32 characters |
| mailbox | the provider's mailbox id (IMAP: the decoded path), 1 to 1024 bytes, no control characters |
| message | the blob hash, 64 lowercase hex characters: the BLAKE3 of the original bytes, the same id the app's message library uses |
| thread | `skein-view`'s thread id within an account; may disappear when threads merge, so a read of a vanished thread is `NotFound` and the app reloads the list |

Lists are newest first with an opaque cursor (`(sort_date, id)` and, for scopes over several accounts, the account), at most 200 rows per page through the API (the database caps at 1000).

**Pending overlay.** A command changes the database only after the provider applied it and the next sync journaled the change. So that a mark-read shows at once, the node keeps an overlay of the expected flags and memberships per `(account, message)` for each queued command and applies it to every read. An entry is dropped when its command's outcome appears (`ViewObserver`) and the checkpoint has passed it, or after 10 minutes. At most 10,000 entries; when full, the oldest entries go first and the reads show the database as it is.

## Commands

`NodeApi` is object-safe and async (`#[async_trait]`). Each mutating operation also has a reserved Baton command class (`mail-…`), so phase 2 can carry the same request to another node as a signed Baton command (`baton-command`) without changing the app; in phase 1 every call is in process.

| Operation | Does | Class |
| --- | --- | --- |
| `node_info()` | node id, group id, profile, version, data directory usage (objects bytes, database bytes) | |
| `discover(address)` | candidate servers for the address (see "Discovery"); no credentials, no sign-in | |
| `add_account(setup, secret)` | validates the setup (`skein_accounts::admin::check_record`, `check_password`), signs in to IMAP (capabilities) and to SMTP (`Sender::check`) with the secret, then stores the record and the sealed password and wakes the account. Nothing is stored when either sign-in fails | `mail-account-add` |
| `update_password(account, secret)` | signs in with the new secret first, then replaces the sealed password; clears `reauth_required` on the next run | `mail-account-password` |
| `update_account(account, patch)` | display name, paused, mailboxes to skip, the archive mailbox | `mail-account-update` |
| `remove_account(account)` | see below | `mail-account-remove` |
| `list_accounts()` | id, address, display name, provider kind, health and the latest outcome per domain, first sync completed, messages and unread counts | |
| `sync_now(account?)` | wake hint for one or every account | `mail-sync` |
| `list_mailboxes(account)` | id, path, role, selectable, total, unread | |
| `list_threads(query)` | thread rows (count, unread, latest envelope) for a scope: a mailbox, a role across one or all accounts, flagged, a tag | |
| `get_thread(account, thread)` | the thread's envelopes and reply tree | |
| `list_messages(query)` | envelopes for a scope | |
| `get_message(account, message)` | envelope, memberships, attachments list, references, tags | |
| `message_raw(account, message)` | the original bytes from the blob store (checked against the hash), for the app to render through rinse; `Unavailable` when the blob is missing | |
| `set_read(targets, read)`, `set_flagged(targets, flagged)` | `set_flags` per mailbox the targets sit in | `mail-flags` |
| `move_to(targets, mailbox)` | `move` per source mailbox; refuses a mailbox of another account | `mail-move` |
| `archive(targets)` | a move to the account's archive mailbox (the `archive` role, else the one set with `update_account`; `NoArchive` otherwise); on Gmail, a move out of the inbox to All Mail | `mail-move` |
| `delete(targets, permanent)` | `delete` with `to_trash` when the provider has a trash and `permanent` is false; `permanent` true deletes for good (the app asks first) | `mail-delete`; `mail-delete-forever` when `permanent` |
| `save_draft(draft)`, `list_drafts()`, `get_draft(id)`, `delete_draft(id)` | local drafts in the sealed objects (`drafts/{id}`, at most 200 drafts of at most 25 MiB each); not synced to the provider in phase 1 | `mail-draft` |
| `send(draft)` | see "Sending" | `mail-send` |
| `cancel_send(account, command)` | `skein_engine::cancel_command`; `AlreadyStarted` once the message may have left | `mail-send-cancel` |
| `outbox()` | queued and waiting sends with their due time and try count | |
| `search(query)` | `skein-view` FTS over one or all accounts with filters (mailbox, role, unread, flagged, has attachments, tag), merged by rank within an account and by date across accounts, at most 200 results | |
| `suggest_addresses(prefix, limit)` | from the `addresses` table, at most 20 | |
| `events()` | the event stream | |

Targets are `MessageRef { account, message }`, at most 1,000 per call, all of one account for moves; the node resolves each to its memberships (mailbox and item) and queues one command per mailbox. A target the database does not know is skipped and reported in the result (`skipped`), never an error for the whole call. Every result that queued commands returns their ids, so the app can match `CommandSettled` events.

`NodeError` (serializable, kinds only, no provider text, address, subject or path): `InvalidInput`, `NotFound`, `AccountExists`, `AuthFailed`, `ServerUnreachable`, `TlsFailed`, `InsecureRefused`, `ServerRefused`, `Throttled { retry_after_secs }`, `NoSender`, `NoArchive`, `NoTrash`, `QuotaFull`, `Unavailable`, `AlreadyStarted`, `Storage`, `KeysLost`, `Busy`, `PairingCodeRejected`, `PairingExpired`, `PairingRefused`, `Forbidden`, `PeerUnreachable` (the group calls, GROUP.md), `Internal`. Mapping from Skein, by the typed cause (`MailError::cause()`, `SendError::cause()`), never by text: `Auth` is `AuthFailed`; `Tls` is `TlsFailed`; `Insecure` (plain text to a remote host, no STARTTLS) is `InsecureRefused`; `Network`, `Timeout`, `Unavailable` and `Temporary` are `ServerUnreachable`; `Quota` and `TooLarge` are `QuotaFull`; `Refused`, `Protocol`, `MailboxNotFound`, `RecipientsRefused` and `Uncertain` are `ServerRefused`; `Config` and `Invalid` are `InvalidInput`; `Throttled` keeps its wait.

### Removing an account

1. pause it (`AccountRecord::paused`), so the engine stops its worker and releases its lease;
2. `skein_accounts::admin::delete_account` (record, sealed password);
3. destroy the account's keyring scope (shreds everything sealed under it);
4. `Storage::purge_account` (journal, head, snapshots, commands, control records) and `Store::forget_account`;
5. sweep blobs: list `tenants/{group}/blobs/` and delete those no remaining account's database rows or queued commands name, in pages of 1,000, resumable after a crash (the sweep cursor is a control record).

A crash between steps leaves a paused account that the next start finishes removing.

### Sending

`send(draft)`:

1. `rowboat-compose` builds the message: `From` the account's address and display name, `To`, `Cc`, `Subject`, `Date` and `Message-ID` (`<ulid@domain-of-from>`) from the node's clock and randomness passed in, `In-Reply-To` and `References` for replies, a `text/plain; charset=utf-8` body (format=flowed off, quoted-printable when needed), attachments as `multipart/mixed` parts with a type from the file extension and RFC 2231 names. Bcc recipients go only to the envelope. Header values are encoded (RFC 2047) and never carry CR or LF; addresses must pass `SendEnvelope::check`. Limits: 500 recipients, 25 MiB of attachments, 1 MiB of text.
2. The bytes go to the blob store; `submit_command` queues `send { blob, envelope, save_to_sent: the account's sent mailbox, send_at }`. The engine waits out the undo window (10 s), sends at most once, retries only while nothing can have been sent, saves the copy to Sent (SMTP does not keep one), and journals `write_applied` and `send_result`.
3. The draft is deleted once the command is queued; `cancel_send` within the window brings it back as a draft.

HTML composition and IMAP drafts are later; the reply quote is plain text built from the rendered text the app already has.

## Discovery

`rowboat-discover` defines `DiscoverySource::lookup(&Domain) -> Vec<Candidate>` (async, bounded to 16 candidates), `Candidate { imap: Endpoint, smtp: Endpoint, username: UsernameForm (full address or local part), auth_hint: Password | AppPassword | OAuthOnly, help: Option<HelpTopic>, source }` and the pure merge: sources in configured order, duplicates dropped, `OAuthOnly` kept so the app can say "coming later".

- `discover-table` (phase 1): an embedded, reviewed table of well-known providers (the large free mail services, their alias domains, the hosts and ports they publish, whether they need an app password, a help topic id the app maps to a page) and, for any other domain, guesses `imap.<domain>` and `mail.<domain>` on 993 (TLS) and 143 (STARTTLS), `smtp.<domain>` and `mail.<domain>` on 465 (TLS) and 587 (STARTTLS).
- `discover-autoconfig` (desktop, default since 2026-11-26, question 42): the domain's own autoconfig file, `https://autoconfig.<domain>/mail/config-v1.1.xml`, then `https://<domain>/.well-known/autoconfig/mail/config-v1.1.xml`, through `HttpsFetcher` (verified certificate, no redirects, no query string, 64 KiB). The file is decoded by a bounded, fuzzed parser.
- `discover-srv` (desktop, default since 2026-11-26): `_imaps._tcp`, `_imap._tcp`, `_submissions._tcp` and `_submission._tcp` of the domain through `SrvResolver` (`UdpResolver` over the system's name servers; the answer reader is bounded and fuzzed).
- The ISP database is not built and stays off: it would tell a third party which domain is being set up.
- The table is asked first; when it knows the provider nothing reaches the network. Otherwise autoconfig and SRV are asked at once, and answers are ranked table, autoconfig, SRV, guesses. Candidates from the network with an IP literal, or STARTTLS on a port other than 143 and 587, are dropped.
- The node probes every candidate that is not from the table with the `probe` functions (TLS verified with the web roots, greeting and capabilities, no credentials) through `ServerProber`, each distinct server once, at most 8 at a time, and returns only candidates whose IMAP and SMTP both answered, marked `verified`; servers that take no password but offer OAuth make the hint `OAuthOnly`, servers that take neither drop the candidate. Table entries are not probed; `add_account` signs in anyway.
- A candidate with a server outside the address's domain and outside the table's providers gets `needs_confirmation`: the app shows it as "suggested by" its source (autoconfig, DNS) and asks the person to confirm it. The rule is one function, `rowboat_discover_table::needs_confirmation(host, domain)`, so an app can run it again on the servers it is about to send a password to (the Peleda app does, in `add_account`).

When nothing is found, the app asks for host, port and security by hand; `add_account` treats both paths alike.

## Events

`events()` returns a bounded stream (256 events per subscriber). A slow subscriber never holds the node up: when its buffer is full it gets one `Lagged { missed }` and the app reloads what it shows. Events carry ids, counts and kinds only.

| Event | When |
| --- | --- |
| `AccountsChanged` | an account was added, removed or changed |
| `AccountStatus { account, health, mail, send }` | the status record changed (`healthy`, `reauth_required`, `throttled`, `degraded`; outcome kinds per domain) |
| `SyncProgress { account, first_sync_completed, messages, behind }` | after each committed page while the database is behind the journal or the first sync is running; `behind` is the journal head less the checkpoint. Skein reports no totals before a mailbox is listed, so the app shows a count, not a percentage, until `first_sync_completed` |
| `MailboxesChanged { account }` | mailboxes were added, removed or renamed |
| `MessagesChanged { account, mailboxes }` | memberships, flags or messages changed in these mailboxes (`mailboxes` empty means many) |
| `CommandSettled { account, command, outcome }` | `applied`, `failed { reason }`, `conflict`, `uncertain`, `cancelled` |
| `SendSettled { account, command, outcome }` | `sent { refused }`, `failed { reason }`, `uncertain`, `waiting { due_at }` |
| `NewMail { account, items }` | bento's notification policy wants arrivals shown: each item is a message, its thread and mailbox, `alert` or `silent`, and whether the sender's name and the subject may be shown; at most 64 per event (see "Notifications") |
| `Lagged { missed }` | the subscriber fell behind |

Sources: the `ViewObserver` (messages, mailboxes, outcomes, progress), the status reads (health), the node itself (accounts, waiting sends).

## Baton in phase 1

The node runs Baton's lease, liveness, signal and state contracts in process, with its own identity and a roster of one (since phase 2, wave 1, a Baton group log of its own; GROUP.md). No link, mesh or command bus runs. What phase 2 adds (pairing, replication, commands from other nodes) plugs in behind the same `NodeApi` and the reserved command classes; nothing in phase 1 may assume it is the only node beyond the lease it holds. Phase 2 is specified in [GROUP.md](GROUP.md), including what devices do while the group's server is silent ("When the server is silent": a fallback arbiter among the devices after the takeover delay, `NodeBuilder::fallback`).

## Logging and privacy

Logs and metrics carry account ids, mailbox ids only as counts, blob hashes, command ids, counts, timings and error kinds (SEC-3). No address, subject, name, mailbox path, host name entered by the person, password or token appears in a log, event, error or panic message. The view database holds content in the clear (question 40); the objects directory holds only sealed values.

## Tests

Every crate ships its tests (TEST-1); the break-in points and their attack tests are listed with the crate that owns them.

- **Conformance suites.** `rowboat-keystore` (above), `rowboat-discover` (bounded output, no I/O in the merge, `OAuthOnly` kept, duplicates dropped), `rowboat-spam` and `rowboat-category` (deterministic, never panic on a hostile `Rendered` from rinse's corpus, version changes when output may change), `rowboat-api` (run against the test profile: every operation's validation, paging stability, overlay, events, cancellation, errors carry no content).
- **Node end to end** (test profile, FakeMail and FakeSender, `rinse-mail-direct`, manual clock): first run creates identity, master key and group; add an account, first sync, threads and search; mark read shows at once through the overlay and settles with `CommandSettled`; move, archive, delete to trash and for good; send with the undo window, cancel inside it, send after it, the Sent copy appears; remove an account and its blobs are swept; restart over the same directory keeps everything.
- **Attacks.** `KeysLost` instead of a new key when an item is missing or wrong; a second process over the same directory is `Locked`; a sealed object moved to another key or bit-flipped does not open; a worker that returns output failing `verify_rendered` leaves the message unavailable, never parsed in the node; header injection through draft fields (CR, LF, NUL, overlong lines, addresses with `<>,;"`) refused or encoded; targets of another account, unknown ids, 1,001 targets, mailbox ids with control characters; a lagging event subscriber does not block sync; a provider that answers `Auth` on sign-in stores nothing; a password never appears in logs, events, errors or `Debug` (a test scans captured output for a canary secret).
- **Fuzz targets** (a `fuzz/` workspace for the node layer, beside `baton/fuzz` and `skein/fuzz`): the drafts record decoder, the node record decoder, the cursor decoder, `rowboat-api` request decoding (the future Baton payloads), the autoconfig decoder (`discover_autoconfig`) and the DNS answer reader (`discover_dns`), and the IMAP probe reader in Skein (`skein/fuzz` `imap_probe`; the SMTP probe reads replies through the reader `smtp_replies` already covers).
- **Load** (`tests/load`, `mise run load-node`): FakeMail with 100,000 messages in 10 mailboxes through engine, follower and `rinse-mail-direct`: first sync at least 200 messages a second on an Apple silicon laptop with 2 workers, memory under 500 MiB; `list_threads` p95 under 50 ms and `search` p95 under 100 ms over 100,000 messages; 1,000 mark-read commands settle within 30 s. The numbers are targets to calibrate on the first run and then hold.
- **Integration** (`mise run it`, `tests/integration`): the node against Dovecot, Stalwart and GreenMail, the containers Skein's integration suite already uses, over TLS with a test CA handed in through `NodeBuilder::test_roots`; see `tests/integration/docs/README.md`.
- **Live** (`mise run live`, ignored, real test accounts of the maintainer): add, sync, send to self, remove.

## Order of work

1. Phase 0: `rowboat-api`, `rowboat-keystore` with `keystore-memory`, `rowboat-discover`, `rowboat-spam`, `rowboat-category` with their suites; `push` moved from `../app`.
2. Skein changes 1 to 10, each with its tests.
3. `rowboat-compose`, `discover-table`, `spam-signals`, `category-bento`.
4. `rowboat-node`: builder and test profile, then the desktop profile; end to end and attack tests; load tests.
5. The app switches its desktop shell to it (`../app/docs/DESKTOP.md`).
