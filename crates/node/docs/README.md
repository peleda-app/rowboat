# rowboat-node

Peleda's node builder (RULES.md MOD-4): it picks Skein's and Baton's implementations for a profile, receives everything platform-specific from the app (keystore, content pipeline, data directory) and answers `rowboat_api::NodeApi` in process. The spec is `docs/NODE.md`; where they differ, this file describes the code.

```rust
let node = Node::builder()
    .profile(Profile::Desktop)
    .data_dir(app_data_dir.join("node"))
    .keystore(keystore)            // Arc<dyn rowboat_keystore::Keystore>
    .content(content)              // Arc<dyn rinse_mail::Content>, the app's sandboxed workers
    .build()
    .await?;
let api: Arc<dyn NodeApi> = node.api();
node.start().await;                // engine, follower, housekeeping
node.shutdown().await;             // stops them, releases every lease
```

Optional: `spam` (default `rowboat-spam-signals`), `category` (default `rowboat-category-bento`), `discovery` (default: the table for every profile; on the desktop also `rowboat-discover-autoconfig` over `rowboat-discover-net::Https` and `rowboat-discover-srv` over `rowboat-discover-net::UdpResolver::system()`, each left out when it cannot be built), `prober` (default `ServerProber` on the desktop, none on the test profile), `providers` (default IMAP and SMTP; required for the test profile unless `test_roots` is set), `clock` (system clock). With the `testing` feature, `test_roots(roots)` (and `ServerProber::with_test_roots`) makes the default IMAP and SMTP providers and the default `ServerProber` also trust a test CA (certificates are still verified, plain text is still refused) and gives the test profile real IMAP and SMTP; the integration suite (`tests/integration`) runs the node that way against containers.

## Profiles

| | `Desktop` | `Test(TestTiming)` |
| --- | --- | --- |
| objects | `skein-storage-sealed` over `skein-storage-fs` at `<data_dir>/objects` | the same, in the test's directory |
| leases and liveness | `baton-lease-cas` over `ControlState`, heartbeat 10 s, time-to-live 30 s | heartbeat as given |
| signals | `baton-signal-local` | the same |
| keyring | `skein-keyring-local` with a key derived from the master key | the same |
| providers | `skein-mail-imap`, `skein-send-smtp` | `testing::FakeProviders` (Skein's `FakeMail` and `FakeSender`) |
| engine | sync every 120 s without push, undo window 10 s | as given (50 ms in `testing::fast`) |
| follower | `<data_dir>/view/view.sqlite`, polled every 5 s, woken by `heads/{account}` | as given |
| content | at most 2 renders in flight | the same |

## Data directory, identity and keys

```
<data_dir>/
  objects/   skein-storage-fs root (exclusive lock): every value sealed (XChaCha20-Poly1305)
  view/      view.sqlite (+ -wal, -shm): the mail database, in the clear (question 40)
```

Directories are `0700`; the database file `0600`.

- **First run** over an empty directory: an Ed25519 identity (`baton-identity`) and a random 256-bit master key go into the keystore as `rowboat.identity` and `rowboat.master` (class `Background`); the objects key and the keyring key are derived from the master key with BLAKE3 (`rowboat-node objects v1`, `rowboat-node keyring v1`); a group id (`g` and 26 base32 characters) is registered as Skein's tenant, the genesis roster written to `system/roster`, and the node record `system/node` (format, node id, group, profile, creation time) last. A crash before the record leaves the keys in the keystore; the next start reuses them and finishes.
- **Later starts** read both keys and the record. A missing key, a key of the wrong length, a key that does not open the record, or a record for another node id is `BuildError::KeysLost`: the node never makes a new key over existing data. A locked keystore is `KeystoreLocked`.
- A directory with anything else in it is `NotEmpty`; a directory another process holds is `Locked`. The lock is released when the node and every API handle are dropped.

## Accounts and credentials

`add_account` checks the setup (`rowboat_api::check`, `skein_accounts::admin::check_record`), signs in to IMAP (a session and a mailbox listing) and to SMTP (`Sender::check`) with the password, and only then stores the sealed password (Skein's keyring), the node's account record (`rowboat/accounts/{id}`: address, display name, archive mailbox) and Skein's account record, and wakes the account. Nothing is stored when a sign-in fails. A password enters only through `add_account` and `update_password` and leaves only to the provider being connected; a test scans logs, events, errors, `Debug` output and the objects directory for a canary password.

Removing an account marks it removing and paused at once (it disappears from every read), then after a grace period (25 s on the desktop, so the engine lets go of it) deletes Skein's record and password, destroys the account's keyring scope, purges its journal, commands and control records (`skein_storage::purge_account`), deletes its released lease record (`CasLeases::forget`; a lease still held stays and is logged), forgets it in the database and deletes the blobs only it named. A removal interrupted by a crash is finished on the next start. What stays is the keyring's tombstone for the destroyed scope (`keys/accounts/{account}`), which keeps a destroyed key destroyed. Blobs the account's journal named but the database never held are not swept.

## The content pipeline and hooks

The node never parses message bytes. `skein-view`'s parser hook is the node's adapter over `Arc<dyn rinse_mail::Content>`: render with display-only options (no original HTML, no remote images, images re-encoded at 1 px, since `max_image_px` 0 made every message with an inline image fail verification), `rinse_mail::verify_rendered` on the result whatever produced it (a failure stores the message as unavailable, with none of the output), map headers, thread facts, text and attachments, then run the spam and category hooks on the same render and store their tags (`spam.junk`, `spam.suspicious`, `category.<id>`). A pipeline that is `Unavailable` leaves the page for the next round. The adapter's version joins its own with the hooks' versions and is stored per message; re-parsing on a version change is not built yet.

## Reads, commands and the overlay

Reads come from `skein-view`: lists newest first with a cursor over `(sort date, account, id)`, so scopes over every account page stably; at most 200 rows. Mutations resolve each target to its memberships and queue one Skein command per account, mailbox and 10,000 items; unknown targets are `skipped`. A pending overlay (at most 10,000 entries, 10 minutes) shows each change at once; an entry is dropped when its commands failed, conflicted or were cancelled, or when they were applied and the database shows the expected state.

`send` composes with `rowboat-compose` (the account's address and name, the node's clock, a ULID `Message-ID`, a random boundary), puts the bytes in the blob store and queues `send` with the account's Sent mailbox (when the database knows one) for the engine, which waits out the undo window. The draft is hidden while the send waits, comes back on `cancel_send` or a failure and is deleted once sent.

## Events

`events()` is a `tokio::sync::broadcast` subscription of 256 events; a subscriber that falls behind gets one `Lagged { missed }` and never holds the node up. Sources: `skein-view`'s observer after each committed page (sync progress, mailboxes, messages, command and send outcomes, and the arrivals `notify.rs` hands to bento's notification policy for `NewMail`, see NODE.md "Notifications"), the status records read every heartbeat (account health), and the node itself (accounts, waiting sends, cancellations).

## Discovery

1. The first source (the table) is asked alone; when it knows the provider, its answer is returned and nothing reaches the network.
2. Otherwise the other sources are asked at once. Candidates from autoconfig and SRV with an IP literal, or STARTTLS on a port other than 143 and 587, are dropped (`Candidate::fit_from_network`).
3. Answers are joined by source rank (table, autoconfig, SRV, guesses) with `rowboat_discover::merge`, so a guess equal to an autoconfig candidate is dropped.
4. With a `Prober`, every candidate not from the table is returned only when both of its servers answered, each distinct server probed once, at most 8 probes in flight; it is marked `verified`. When the servers take no password but offer OAuth the hint becomes `OAuthOnly`; when they take neither, the candidate is dropped. Without a prober (the test profile) such candidates are returned unverified and `add_account` signs in anyway.
5. A candidate not from the table with a server outside the address's domain and outside the table's providers (`TableSource::known_host`) gets `needs_confirmation`, so the app shows it as "suggested by" its source and asks the person.

`ServerProber::new(timeout)` trusts only the web roots; extra roots exist only behind `testing`. Cargo unifies features across the packages of one build, and `rowboat-integration` and `rowboat-load` turn `testing` on, so a release binary is built with `-p <binary>`, never with `--workspace`. `ServerProber` probes with `skein_mail_imap::probe` and `skein_send_smtp::probe` (TLS verified against the web roots, greeting and capabilities, no credential), 10 s per probe, and maps their typed causes to `DiscoverError` kinds (`TlsFailed`, `Insecure`, `Timeout`, `Unreachable`, `NotMail`). Provider errors reach `NodeError` through `MailError::cause()` and `SendError::cause()`, never through their texts.

## Records

`records` holds the node's stored records with versioned decoders (node record, account records, drafts), each fuzzed in `fuzz/`.

## Tests

- `cargo test` (the e2e tests need the `testing` feature, which `rowboat-load` turns on in workspace builds): the API conformance suites on the test profile; first run, sync, threads, search, suggestions and a restart over the same directory; mark-read through the overlay settling with `CommandSettled`; move, archive, delete to the trash and for good; send with the undo window, cancel inside it, send after it, the Sent copy; removing an account and sweeping its blobs and records (only the keyring tombstone stays); a lagging subscriber; attacks: a second process (`Locked`), lost, wrong, short and locked keys (`KeysLost`, `KeystoreLocked`, never a new key), a foreign directory (`NotEmpty`), a refused sign-in storing nothing, targets across accounts, worker output failing `verify_rendered`, and the canary password scan.
- Load: `tests/load` (`mise run load-node`).
