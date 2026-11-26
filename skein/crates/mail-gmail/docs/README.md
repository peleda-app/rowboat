# skein-mail-gmail

The mail contract (`skein-mail`) on Gmail through the Gmail API. `GmailProvider` signs in with an OAuth access token, shows labels as mailboxes next to a synthetic `ALL` mailbox, lists messages with `messages.list`, follows changes with `history.list` behind an opaque cursor, returns the exact RFC 5322 bytes from `messages.get?format=raw`, and carries out writes as label changes, trash, delete, insert and user label management. Reading never changes the server.

## Public API

- `GmailProvider::new(settings, credentials) -> Result<GmailProvider, MailError>` checks everything before a request leaves: `Config` for a password (the API takes only OAuth access tokens), an empty token, an `api_url` that is not `https` (plain `http` only to `localhost`, `127.0.0.0/8` or `::1`) or carries credentials, or a `user` that is empty or not a plain path segment.
- `GmailProvider::with_timeout(d)`: every request gets `d` (default two minutes). No answer in time is `Network`, or `Uncertain` for a write that already left.
- `GmailProvider::with_quota(units)`: keep under `units` quota units per second instead of `DEFAULT_UNITS_PER_SECOND` (250).
- `MailProvider::connect` reads `users.getProfile` to check the token (`Auth` when refused). Sessions are cheap; clones of a provider share one quota limiter.
- `MailProvider::watch` returns `Ok(None)`: Gmail holds no push connection.
- `MailProvider::subscribe(target)` calls `users.watch` with `topicName = target.gmail_topic` and no label filter, so every label is watched. It returns `Ok(None)` without a topic. The `Subscription` has `provider_kind: "gmail"`, `resource` set to the mailbox address (from `users.getProfile`, which Gmail names in every notification), `id` set to the history id at watch time, and `expires_at` set to Gmail's `expiration` (about seven days). A topic that is not `projects/{p}/topics/{t}` is `Config` before anything is sent. A watch Gmail refuses (`400`, `403` or `404`, typically a missing publish grant for `gmail-api-push@system.gserviceaccount.com`) is also `Config`. `renew` is the default: watching again replaces the previous watch. `unsubscribe` calls `users.stop`, and stopping twice succeeds. Routing and renewal live in `skein-push`.
- Constants: `ALL` (`"ALL"`), `MAX_MESSAGE` (64 MiB), `CONCURRENCY` (8), `DEFAULT_UNITS_PER_SECOND` (250).
- `GmailSettings`; its `Debug` hides `user` unless it is `me`. The provider's `Debug` never shows the token.

## Settings

| Field | Default | Meaning |
| --- | --- | --- |
| `api_url` | `https://gmail.googleapis.com` | API origin, optionally with a path prefix (a proxy). Requests go to `{api_url}/gmail/v1/users/{user}/...` and `{api_url}/upload/gmail/v1/users/{user}/...` |
| `user` | `me` | The user id in paths: `me` for the token's owner, or an address with domain-wide delegation |

The token is sent only to the origin of `api_url`. Every address is built from that origin with percent-encoded path segments, so no id, page token or user name can change the host or climb out of the path; each request is checked against the origin once more before the token is attached. Redirects are never followed (a `3xx` is `Protocol`). Gmail pages with opaque `pageToken` values, never with links, so there is no server-supplied address to follow.

## Scopes

| Operation | Least scope |
| --- | --- |
| `mailboxes`, `changes`, `fetch` | `gmail.readonly` |
| `SetFlags`, `SetLabels`, `Move`, `Copy`, `Delete` in a label mailbox or with `to_trash`, `Append` | `gmail.modify` (`Append` also works with `gmail.insert`) |
| `CreateMailbox`, `RenameMailbox`, `DeleteMailbox` | `gmail.labels` (or `gmail.modify`) |
| `Delete` in `ALL`, `TRASH` or `SPAM` (`messages.batchDelete`) | `https://mail.google.com/` |

A write refused for scope is `Failed { reason: "insufficient_scope" }`; a read refused for scope is `Auth`.

## Mailboxes and ids

| Mailbox id | Path | Role | `label` | Members |
| --- | --- | --- | --- | --- |
| `ALL` | All Mail | `All` | no | every message not in Spam or Trash; not a Gmail label |
| `INBOX` | Inbox | `Inbox` | yes | label `INBOX`, not in Spam or Trash |
| `SENT` | Sent | `Sent` | yes | |
| `DRAFT` | Drafts | `Drafts` | yes | |
| `IMPORTANT` | Important | none | yes | listed when the account has the label |
| `TRASH` | Trash | `Trash` | no | label `TRASH` |
| `SPAM` | Spam | `Junk` | no | label `SPAM` |
| user label id (`Label_12`) | the label name (`Projects/2025`) | none | yes | that label, not in Spam or Trash |

`UNREAD` and `STARRED` are flags, not mailboxes; `CHAT` and `CATEGORY_*` are not shown (categories may become mailboxes later). The engine skips `label: true` mailboxes when `ALL` is synced, so each message arrives once, from `ALL`, with its labels.

- Message ids are Gmail message ids; `uid` is `None`. `received_at` is `internalDate`.
- Flags come from labels: no `UNREAD` is `\Seen`, `STARRED` is `\Flagged`, `DRAFT` is `\Draft`.
- `labels` names every label but `UNREAD` and `STARRED`, sorted: system labels as Gmail's IMAP names them (`Inbox`, `Sent`, `Drafts`, `Important`, `Trash`, `Spam`, `Chat`), user labels by name, anything else (categories, unknown ids) by id. The label list is read once per session and again when a message carries a `Label_*` id it does not know.

## How `changes` works

The cursor is one version byte and a zstd frame with the phase (and the `messages.list` page token while listing), the history id, and the known message ids of the mailbox: ids that are canonical lowercase hex fit in a `u64` and are stored as ascending LEB128 deltas; any other id is stored as a string. Gmail ids grow with time, so 100,000 messages take about 600 KB (six bytes each). A cursor that does not decode yields `Reset { reason: "unreadable_cursor" }`.

1. Without a cursor, `users.getProfile` gives the history id the feed will continue from, then the listing starts.
2. Listing: one `messages.list` page per call (`maxResults` = `limit`, at most 500; `labelIds` for label mailboxes, `includeSpamTrash=true` only for `TRASH` and `SPAM`), and `messages.get?format=minimal&fields=id,labelIds,internalDate` for every id not yet known, eight at a time. Each message still in the mailbox is `Added`. `more` is set while pages remain. A page token Gmail no longer accepts restarts the listing; known ids are skipped, so nothing is reported twice.
3. Tracking: one `history.list` page per call from the stored history id (all history types, `maxResults` = `limit`). For every message a page touches, membership before comes from the known ids and membership after from its current labels (`format=minimal`; permanently deleted or `404` means gone):
   - entering the mailbox is `Added`, leaving it or being deleted while known is `Removed`;
   - staying with a change to `UNREAD`, `STARRED` or `DRAFT` is `Flags` with the full set; staying with a change to any other label is `Labels` with the full set (both can come for one message);
   - a message touched several times in one page is reported once, with its current state.
   The cursor moves to the last record read, or to the response's `historyId` once the feed is drained.
4. A `404` (or `400`) on `history.list`, Gmail's answer to a history id it no longer keeps (usually after about a week), yields `Reset { reason: "history_expired" }` and a new listing in the same call.

`fetch` asks `messages.get?format=raw&fields=raw` eight at a time and decodes the base64url body to the exact bytes, in the order given. Ids that cannot be Gmail ids and messages that answer `404` are left out. A message over 64 MiB, or an answer over its base64 size, is `Protocol`.

## Writes

| Command | Gmail API |
| --- | --- |
| `SetFlags` | `messages.batchModify` (1,000 ids per call): `\Seen` removes `UNREAD`, `\Flagged` adds `STARRED`, and the reverse for removal; adding wins. Any other flag is `Failed { "unsupported_flag" }` before any request |
| `Move` to `TRASH` | `messages/{id}/trash` per message |
| `Move` from `TRASH` | `messages/{id}/untrash` per message, then the target label as below |
| `Move` otherwise | `batchModify`: remove the source label (none for `ALL`), add the target label (none for `ALL`); into `SPAM` also removes `INBOX`. A missing target is `Failed { "no_such_mailbox" }`; a missing source is `MailboxNotFound` |
| `Delete` in `ALL`, `TRASH`, `SPAM` | `messages.batchDelete`, permanent; needs `https://mail.google.com/`, else `Failed { "insufficient_scope" }` |
| `Delete` in a label mailbox | `batchModify` removing that label |
| `Delete` with `to_trash` | `messages/{id}/trash` per message; in `TRASH` already, `Applied` without a request |
| `Copy` | `batchModify` adding the target's label; the originals keep theirs and the id stays the same. Into `ALL` or the source itself changes nothing; into `TRASH` or `SPAM` is `Failed { "unsupported" }` (use `Delete` with `to_trash` or `Move`). A missing target is `Failed { "no_such_mailbox" }`; a missing source is `MailboxNotFound` |
| `SetLabels` | `batchModify` with `addLabelIds`/`removeLabelIds`. Labels are named as `labels` reports them: `Inbox`, `Sent`, `Drafts`, `Important`, `Trash`, `Spam`, `Chat` for system labels, user labels by name (exact), anything else by id (`CATEGORY_SOCIAL`). The label list is read again once when a name is unknown; a name still unknown is `Failed { "no_such_label" }` before any change. A label in both lists ends up added. Gmail itself refuses labels it does not let messages take (`Sent`, `Drafts`, `Chat`): `Failed { "refused" }` |
| `CreateMailbox` | `labels.create` with the path as the name (Gmail nests labels at `/`), shown in the label list and message list. A path a user label already has (Gmail compares names without case), a system mailbox path (`Inbox`, `All Mail`, ...) or a `409` is `Failed { "exists" }`; an empty level is `Failed { "invalid_path" }`. Not idempotent, so a `5xx` is `Uncertain` |
| `RenameMailbox` | `labels.patch` with the new name. Only user labels: `ALL`, `TRASH`, `SPAM` and every system label are `Failed { "protected" }`, an unknown id is `MailboxNotFound`. A name another label has, or a `409`, is `Failed { "exists" }`; a change of case alone is a rename. Sub-labels (`Old/child`) keep their names, unlike in Gmail's web interface |
| `DeleteMailbox` | `labels.delete`. Only user labels, as for rename. Messages are not deleted; they lose the label |
| `Append` | `messages.insert` as a `multipart/related` upload with `internalDateSource=dateHeader`; `labelIds` = the mailbox (none for `ALL`) plus `UNREAD` without `\Seen` and `STARRED` with `\Flagged`; other flags are `Failed { "unsupported_flag" }`, no content is `Failed { "missing_content" }` |
| `Refetch`, `Unknown` | `Failed { "unsupported" }` |

Writes with labels map names or ids to the label list read once per session; label management reads it again before checking and drops it afterwards, so a later command sees the change.

Ids that cannot be Gmail ids are skipped; messages that are already gone count as done. A write whose request left but whose answer was lost (timeout, broken connection, unreadable answer) is `Uncertain`; so is a `5xx` on an insert. A `5xx` on a label change or delete is `Network`, since repeating them is harmless. A refused write is `Failed { "exists" }` (`409`), `Failed { "refused" }` (other `4xx`) or `Failed { "forbidden" }` (a `403` that is neither scope nor rate).

## Capabilities

`capabilities()` reports `system_flags: [\Flagged, \Seen]`, `labels`, `trash`, `copy` and `mailboxes`. `\Draft` and `\Answered` are not listed: Gmail does not let `messages.modify` add or remove `DRAFT`, and has no answered label. `keywords` is off (Gmail has no keywords; custom labels go through `SetLabels`), and `append_received_at` is off: `messages.insert` takes the received time from the `Date` header or the upload time, never an arbitrary one.

## Quota

Gmail allows 250 quota units per user per second (moving average). Every request waits in a token bucket shared by the provider's sessions, with a one-second burst. Costs, from the Gmail API "Usage limits" page:

| Method | Units |
| --- | --- |
| `getProfile`, `labels.list` | 1 |
| `history.list` | 2 |
| `messages.list`, `messages.get`, `trash`, `untrash`, `labels.create`, `labels.patch`, `labels.delete` | 5 |
| `messages.insert` | 25 |
| `messages.batchModify`, `messages.batchDelete`, `stop` | 50 |
| `watch` | 100 |

A first listing therefore runs at about 50 messages per second (each needs one `messages.get`). Requests are not grouped in HTTP batches yet.

## Errors

- `401`: `Auth`. A read refused with `403` (scope, policy): `Auth`.
- `429`, and `403` with reason `rateLimitExceeded`, `userRateLimitExceeded` or `RATE_LIMIT_EXCEEDED`: `Throttled { retry_after }` from a `Retry-After` in seconds (an HTTP date is ignored).
- `5xx`, timeouts and broken connections: `Network`.
- Anything else: `Protocol`, with the status code only. Error bodies are read for their machine-readable reasons only; their messages, which can echo addresses or subjects, never reach errors or logs.
- Answers are capped: 16 MiB for JSON, and the base64 size of `MAX_MESSAGE` for raw messages. Logs carry counts, statuses and timings, never tokens, message bytes, subjects, addresses or label names.

## Limits and what is left out

- Push needs a Cloud Pub/Sub topic and a push subscription set up by the operator (see `skein-push`). Without one, the engine polls.
- Cursors grow with the mailbox, about six bytes per message.
- No HTTP batch requests (`/batch/gmail/v1`); metadata and raw messages are fetched eight requests at a time.
- Categories are not mailboxes; they can be added and removed by id through `SetLabels`.
- Renaming a label does not rename its sub-labels.
- Messages larger than 64 MiB cannot be fetched.

## Tests

`cargo test -p skein-mail-gmail` runs `skein_mail::testing::conformance` and `write_conformance` (with `INBOX`, a user label as the other mailbox and a nested user label to add and remove) against an in-process fake of the Gmail API (axum on loopback) in `ALL`, `INBOX` and a user label. The fake keeps raw messages, labels, a growing history log and an expiry threshold, and implements `ServerControl`: `add` puts a message in `INBOX` (or the named label) with `UNREAD`/`STARRED`/`DRAFT` from its flags, `remove` deletes permanently, label create, patch and delete answer `409` on a name taken without regard to case, `set_flags` changes `UNREAD` and `STARRED`, `invalidate` expires the history. Focused tests cover the label mapping, trash and untrash in `ALL` and `TRASH`, `Labels` against `Flags`, repeated changes reported once, history expiry, unreadable cursors, paging with small limits, an expired listing page token, the cursor encoding and its size for 100,000 ids, throttling with `Retry-After`, refused redirects to another origin, the message size cap, `401`, every write including `Delete` without the full scope, trash and copy, labels set by name (including one made after the session started), label create, rename and delete with `exists`, `protected` and `invalid_path`, lost answers, the quota bucket, `Debug` redaction, and `watch`/`stop` (without a topic, renewal, refused watches, bad topics, throttling). The live suite is `gmail_api` in `tests/integration/tests/live.rs`, see `docs/LIVE.md`.
