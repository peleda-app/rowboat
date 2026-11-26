# skein-mail-graph

The mail contract (`skein-mail`) on Microsoft 365 (work and school), Outlook.com and Hotmail mailboxes through Microsoft Graph. `GraphProvider` lists mail folders, turns each folder's message delta query into a change feed behind an opaque cursor, downloads each message's original MIME bytes from its `$value`, and carries out writes. Graph's JSON rendering of a message is never used. Reading only sends `GET` requests, so it never marks anything read. Useful where a tenant turned IMAP off.

## Public API

- `GraphProvider::new(settings, credentials) -> Result<GraphProvider, MailError>` takes only `Credentials::AccessToken`: an OAuth access token with `Mail.Read`, or `Mail.ReadWrite` for writes (folder management included). A password, an empty token, an API address that is not `https` (plain `http` only to `localhost`, `127.0.0.0/8` or `::1`), an address with credentials in it, or an extra root that is not a certificate is `Config`, before anything is sent. Refreshing the token is not this crate's job (see `skein-oauth`); a token that expired is `Auth`.
- `GraphProvider::with_timeout(d)`: every request gets `d` (default five minutes).
- `GraphProvider::with_max_download(bytes)`: message downloads above `bytes` (default 256 MiB) are `Protocol`.
- `GraphProvider::with_throttle(throttle)`: every request waits for a slot of the `skein-throttle` gate and for any pause in effect, holding the slot until its answer is read; a `429`, or `503` with `Retry-After`, pauses the gate for every holder (the account's calendar, contacts and sending providers too). Without one, requests go out at once.
- `MailProvider::connect` is cheap: sessions share one HTTP client and keep no state between calls. `MailProvider::watch` is `Ok(None)`: Graph pushes only through webhooks.
- `MailProvider::subscribe(target)` sends `POST /subscriptions` with `changeType: created,updated,deleted`, `resource: me/messages`, `target.url` as both `notificationUrl` and `lifecycleNotificationUrl`, `clientState = target.client_state`, and an expiry 4200 minutes ahead (the limit for messages is 4230). The URL must be `https` (plain `http` only to loopback), and the client state must be 1 to 128 printable characters; otherwise it is `Config` before anything is sent. Graph checks the address first with a validation request, so the server must already be reachable. A refused subscription is `Protocol`, `401`/`403` is `Auth`, and a lost answer is `Network` (a duplicate subscription only expires). `renew` sends `PATCH /subscriptions/{id}` with a new expiry; one Graph no longer knows is replaced by a new subscription. `unsubscribe` sends `DELETE /subscriptions/{id}`, and an unknown one counts as removed. Routing and renewal live in `skein-push`.
- `GraphSettings { api_url, roots }`, `GRAPH_URL`.

## Settings

| Field | Default | Meaning |
| --- | --- | --- |
| `api_url` | `https://graph.microsoft.com/v1.0` | The Graph endpoint with its version; national clouds need their own |
| `roots` | none | `TlsRoots` trusted besides the built-in roots; not serialized |

## Security

The token goes only to the origin (scheme, host, port) of `api_url`. Next-page and delta links in answers that point anywhere else are `Protocol`; a cursor whose stored link points anywhere else is treated as unreadable (`Reset`) and nothing is sent to that host. Redirects are never followed. Logs carry counts and status codes only; error texts name the host, never ids, folder names, addresses or the token. `GraphProvider`'s `Debug` hides the token.

## Ids and cursors

- Every request sends `Prefer: IdType="ImmutableId"`, so a message keeps its id when it moves between folders. Mailbox ids are folder ids; message ids are immutable message ids; `uid` is always `None`.
- Folders: `GET /me/mailFolders?includeHiddenFolders=true`, then `childFolders` of every folder with children, every page followed. Paths join display names with `/`. Search folders are left out (their messages live in other folders). Roles come from the well-known names `inbox`, `sentitems`, `drafts`, `deleteditems`, `junkemail` and `archive` (one request each per `mailboxes` call). Every folder is selectable, none is a label. At most 10,000 folders.
- Changes: `GET /me/mailFolders/{id}/messages/delta?$select=id,receivedDateTime,isRead,flag,isDraft` with `Prefer: odata.maxpagesize=<limit>` (1 to 1000). One page per call; `more` is set while Graph gives a next link, and the round ends with a delta link. The cursor holds that link and, for every message seen in the folder, a 64-bit hash of its id with a 32-bit hash of its flags (12 bytes per message, zstd-compressed). The hashes tell a new message (`Added`) from a known one whose flags changed (`Flags`) or that only changed otherwise (nothing reported), and keep `@removed` entries of messages never reported out of the feed. A moved message is `Removed` in one folder and `Added` in the other with the same id.
- `Reset`: a delta link Graph answers with `404`, `410` or `400` (expired or unknown sync state), a cursor that does not decode, or one for another folder or host, starts a fresh delta query, reported as `Reset { reason: "delta_expired" | "cursor" }` followed by a full listing. A fresh query answered with `404` is `MailboxNotFound`.
- Flags: `isRead` is `\Seen`, `flag.flagStatus == "flagged"` is `\Flagged`, `isDraft` is `\Draft`. `received_at` is `receivedDateTime`.
- `fetch`: `GET /me/messages/{id}/$value`, four at a time, in the order asked. A `404` (deleted since) is left out. The message is found by id wherever it is now.

## Writes

Every message is changed by its own request, one after another, so a command that stops part way may have changed some messages; each request is idempotent except the upload, copies and folder creation.

Every command that names a source folder (`SetFlags`, `Move`, `Copy`, `Delete`) checks it first with `GET /me/mailFolders/{id}`; one that does not exist is `MailboxNotFound`, before anything changes.

- `SetFlags`: one `PATCH /me/messages/{id}` with `isRead` and/or `flag.flagStatus`. Only `\Seen` and `\Flagged` can be written; any other flag is `Failed { reason: "unsupported_flag" }` before any request. A flag in both lists ends up set. Messages already gone (`404`) are skipped.
- `Move`: the target is checked first (`Failed { reason: "no_such_mailbox" }`), then `POST /me/messages/{id}/move` per message. The id stays the same. A move to the same folder changes nothing.
- `Copy`: the target is checked first (`Failed { reason: "no_such_mailbox" }`), then `POST /me/messages/{id}/copy` with `destinationId` per message. Each copy gets a new id; the originals stay. Copying is not idempotent, so a `5xx` is `Uncertain`, not retried.
- `Delete`: `POST /me/messages/{id}/permanentDelete`, gone for good.
- `Delete` with `to_trash`: `POST /me/messages/{id}/move` into the folder with the well-known name `deleteditems` (looked up per command); the id stays the same. Messages already in Deleted Items stay there (`Applied` without a request); an account without Deleted Items is `Failed { reason: "no_trash" }`.
- `Append`: the bytes in base64 as a `text/plain` body of `POST /me/mailFolders/{id}/messages`, then one `PATCH` when the created message's `isRead` or `flag` differ from the wanted flags; other flags are not written. If that `PATCH` fails, the upload is removed with `permanentDelete` and the outcome is `Failed { reason: "flags_not_set" }`, or `Uncertain` if the removal fails too. Above 3 MiB (Graph takes 4 MiB of base64) the outcome is `Failed { reason: "too_large" }`; an unknown folder is `MailboxNotFound`. Graph sets `receivedDateTime` to the upload time and may mark an upload as a draft.
- `CreateMailbox`: the folder tree is listed, the path is split at `/`, and missing levels are created one by one with `POST /me/mailFolders` (top level) or `POST /me/mailFolders/{parent}/childFolders` and `displayName`. A path that is already there (names compare without case, as Exchange does) or a `409` (`ErrorFolderExists`) is `Failed { reason: "exists" }`; an empty level is `Failed { reason: "invalid_path" }`. Creating is not idempotent, so a `5xx` is `Uncertain`.
- `RenameMailbox`: the folder tree is listed. A new parent path moves the folder with `POST /me/mailFolders/{id}/move` (`destinationId` is the parent, created level by level when missing, or `msgfolderroot` for the top level); a new last level renames it with `PATCH /me/mailFolders/{id}` and `displayName`. Subfolders come along. A path that another folder has, or a `409`, is `Failed { reason: "exists" }`; a path inside the folder itself is `Failed { reason: "invalid_path" }`; renaming to the same path is `Applied` without a request. A move followed by a refused rename leaves the folder moved under its old name.
- `DeleteMailbox`: `DELETE /me/mailFolders/{id}`. Graph does not delete for good: the folder and its messages go to Deleted Items (it then lists as `Deleted Items/<name>`), where they can be recovered or purged. A folder already gone at that point counts as deleted.
- `RenameMailbox` and `DeleteMailbox` of a folder with a role (`inbox`, `sentitems`, `drafts`, `deleteditems`, `junkemail`, `archive`), by id or by well-known name, or of `msgfolderroot`, are `Failed { reason: "protected" }` before any write; an unknown folder is `MailboxNotFound`. Other distinguished folders Graph protects (Outbox, Conversation History) are refused by Graph itself.
- `SetLabels` is `Failed { reason: "unsupported" }`: categories are not reported as labels.
- Outcomes: a request that went out without an answer (timeout, broken connection, unreadable body), or a `5xx` other than throttling, is `Uncertain`; `401` is `Auth`, and so is a `403` whose error code says the sign-in lacks access (`ErrorAccessDenied`, `Authorization_RequestDenied`, `ErrorInsufficientPermission`, or no readable code); any other `403` (such as deleting a well-known folder) is `Failed { reason: "http_403" }`; other refusals are `Failed { reason: "http_<status>" }`. `Refetch` and unknown commands are `Failed { reason: "unsupported" }`.

## Capabilities

`capabilities()` reports `system_flags: [\Flagged, \Seen]` (`isDraft` cannot be written and Graph has no answered property), `trash`, `copy` and `mailboxes`. `labels` is off (categories are not labels here), `keywords` is off, and `append_received_at` is off: an upload always gets the upload time.

## Throttling and errors

`429`, and `503` with `Retry-After`, are `Throttled { retry_after }` (an upload answered `503` is `Uncertain` instead, since it may have been carried out); nothing is retried inside the provider. With a throttle, the `Retry-After` also pauses the shared gate (at most 10 minutes), and later requests from any holder wait for it. `401` is `Auth`, as is `403` on the mailbox as a whole; `403` on one message is `Protocol`. Other `5xx`, timeouts and broken connections are `Network`; other refusals and malformed answers are `Protocol`. JSON answers above 64 MiB are `Protocol`.

## Limits and not done

- Push needs a public `https` address (see `skein-push`). Without one, the engine polls delta.
- `$batch` is not used; writes and the six well-known lookups are separate requests.
- A folder name containing `/` reads as a deeper path.
- Tested against the in-process fake Graph server in `src/tests.rs` (the mail conformance suite and the write conformance suite, folders with hidden, child and search folders, paged delta rounds, moves, expired links, foreign links and redirects, cursors for another folder, throttling, a shared throttle (waiting out another holder's pause, a `429` pausing it), a wrong token, size limits, every write, trash and copy, folder create (with missing levels), rename, move, protected folders and conflicts, lost answers, subscriptions made, renewed, replaced and removed, and no secrets or content in logs, errors or `Debug`). The live suite (`SKEIN_LIVE_GRAPH_ACCESS_TOKEN`, see [LIVE.md](../../../docs/LIVE.md)) runs the engine round trip against a real mailbox; it has not run yet. Throttling and error injection with Dev Proxy are still to come.
