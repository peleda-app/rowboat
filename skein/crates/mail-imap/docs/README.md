# skein-mail-imap

The mail contract (`skein-mail`) on IMAP servers. `ImapProvider` signs in over TLS or STARTTLS with `LOGIN` or `AUTHENTICATE XOAUTH2`, turns each mailbox into a change feed behind an opaque cursor, returns the exact RFC 5322 bytes of messages, carries out writes and watches mailboxes with `IDLE` (one connection for many mailboxes when the server has `NOTIFY`). Reading opens mailboxes with `EXAMINE` and fetches with `BODY.PEEK[]`, so it never sets `\Seen` or changes anything else.

## Public API

- `ImapProvider::new(settings, credentials) -> Result<ImapProvider, MailError>` checks the settings before anything is sent: `Config` for an empty host, plain text to a host that is not loopback (unless `allow_insecure_plain`), or an extra root that is not a usable CA certificate. A password signs in with `LOGIN`, an access token with `AUTHENTICATE XOAUTH2`.
- `ImapProvider::with_timeout(d)`: every command, the connection and the sign-in get `d` (default two minutes); a server that does not answer in time is `Network`.
- `ImapProvider::with_idle_renew(d)`: a watch ends and restarts its `IDLE` after `d` (default ten minutes).
- `MailProvider::connect` opens one connection per session. `MailProvider::watch` is described below.
- `ImapSettings`, `Security`, `MAX_WATCH_CONNECTIONS` (3).

## Settings

| Field | Default | Meaning |
| --- | --- | --- |
| `host` | required | Host name or IP address |
| `port` | 993 for `tls`, else 143 | |
| `security` | `tls` | `tls`, `starttls` or `plain` |
| `username` | required | Often the address; never logged and hidden from `Debug` |
| `roots` | none | `TlsRoots` trusted besides the built-in web roots; not serialized |
| `allow_insecure_plain` | `false` | Allows `plain` to a host that is not `localhost`, `127.0.0.0/8` or `::1` |

TLS uses rustls with the `webpki-roots` set plus `roots`; verification can never be turned off. STARTTLS that the server refuses is a `Config` error, never a fallback to plain text. Credentials are sent in plain text only to loopback hosts or with `allow_insecure_plain`; the check runs again on the live connection right before sign-in.

## Ids and cursors

- Mailbox ids are the decoded path with `/` between levels (modified UTF-7 names are decoded, other delimiters replaced). `\Noselect` and `\NonExistent` mailboxes are listed with `selectable: false`. Roles come from RFC 6154 attributes, `INBOX`, or common English names.
- Message ids are `{UIDVALIDITY}:{UID}` with `uid` set. On Gmail (`X-GM-EXT-1`) the id is the decimal `X-GM-MSGID`, `uid` is still set, and `labels` are filled from `X-GM-LABELS` (system labels read `Inbox`, `Sent`, `Important`, ...). Every selectable mailbox but All Mail, Trash and Spam is marked `label: true`, because its messages also sit in All Mail.
- The cursor is one version byte and a zstd frame with `UIDVALIDITY`, `UIDNEXT`, `HIGHESTMODSEQ`, a table of distinct flag and label sets, and columns over the known UIDs: UID deltas, flag-set indexes and, on Gmail, zigzag deltas of `X-GM-MSGID` (varints throughout). With random flags and gaps, 100,000 messages take about 65 KB, or about 550 KB on Gmail where the message ids dominate. A cursor that does not decode, or decodes to more than 128 MiB, yields `Reset { reason: "unreadable_cursor" }`.

## How `changes` works

1. `EXAMINE` the mailbox. A different `UIDVALIDITY` yields `Reset { reason: "uidvalidity" }` and a full listing.
2. New and removed messages: when the previous listing was complete and `UIDNEXT` and `EXISTS` show that nothing came or went, nothing more is asked. Otherwise `UID SEARCH UID <uidnext>:*` finds new UIDs and, if `EXISTS` adds up, nothing was removed; if not, `UID SEARCH ALL` is diffed against the cursor.
3. Flag and label changes of known messages: with `CONDSTORE` (enabled with `ENABLE CONDSTORE`) and an unchanged `HIGHESTMODSEQ`, nothing is fetched; a changed one fetches `(CHANGEDSINCE <previous>)`. Without mod-sequences (or after `NOMODSEQ`) the flags of every known message are fetched in ranges of 5,000 UIDs and compared with the cursor. A change is reported only when the set differs from the cursor, so nothing is reported twice.
4. Up to `limit` new messages are listed in UID order with flags, labels and `INTERNALDATE`, fetched 500 at a time; `more` is set while others wait. A paged or interrupted listing marks the cursor partial, which makes the next call search the whole mailbox.

`fetch` checks each item against the current `UIDVALIDITY` (and on Gmail against `X-GM-MSGID`), asks for `RFC822.SIZE` 500 at a time and then the bodies in batches of up to 32 MiB, and returns the bytes in the order the items were given, leaving out messages that are gone.

## Capabilities

`capabilities()` lists the mailboxes (one `LIST`) and, unless a write already opened a mailbox with `SELECT`, opens the inbox with `SELECT`, because `EXAMINE` reports no `PERMANENTFLAGS`.

| Field | Source |
| --- | --- |
| `system_flags` | `\Seen`, `\Answered`, `\Flagged`, `\Deleted`, `\Draft` as far as `PERMANENTFLAGS` (or `FLAGS` when the server sent none) lists them; the basic four when it lists none |
| `keywords` | `\*` in `PERMANENTFLAGS` |
| `labels` | Gmail (`X-GM-EXT-1`) only |
| `trash` | a selectable mailbox with the trash role (RFC 6154 `\Trash`, else a name such as `Trash`, `Deleted Items`, `Bin`) and `MOVE` or `UIDPLUS` |
| `copy`, `append_received_at`, `mailboxes` | always (`COPY`, `APPEND` date-time, `CREATE`/`RENAME`/`DELETE` are base IMAP) |

## Writes

`apply` opens the mailbox with `SELECT` (`EXAMINE` for `Copy`), resolves the items as `fetch` does (ids of another `UIDVALIDITY` or another Gmail message are skipped, and a write with nothing left is `Applied`), and sends at most 1,000 UIDs per command.

| Command | IMAP |
| --- | --- |
| `SetFlags` | `UID STORE -FLAGS.SILENT`, then `+FLAGS.SILENT` (adding wins). Flags must be `\Seen`, `\Answered`, `\Flagged`, `\Deleted`, `\Draft` or keyword atoms, else `Failed { "invalid_flag" }` |
| `Move` | `UID MOVE` with `MOVE`; else `UID COPY`, `+FLAGS.SILENT (\Deleted)`, `UID EXPUNGE` with `UIDPLUS`; else `Failed { "no_uidplus" }`. A missing target is `Failed { "no_such_mailbox" }` |
| `Copy` | `UID COPY`; a missing target is `Failed { "no_such_mailbox" }`. On Gmail, copying into a label's mailbox adds the label |
| `Delete` | `+FLAGS.SILENT (\Deleted)` and `UID EXPUNGE` of exactly those UIDs; without `UIDPLUS`, `Failed { "no_uidplus" }` before any command, so other messages marked `\Deleted` are never expunged |
| `Delete` with `to_trash` | a `Move` to the first selectable trash mailbox in `LIST` order; none is `Failed { "no_trash" }`. Messages already in the trash stay and the result is `Applied` with nothing sent |
| `SetLabels` | Gmail only (else `Failed { "unsupported" }`): `UID STORE -X-GM-LABELS`, then `+X-GM-LABELS` (adding wins). Labels are named as `labels` reports them: `Inbox`, `Sent`, `Important`, `Starred`, `Drafts`, `Trash`, `Spam` are sent as Gmail's system labels, others in modified UTF-7, all as quoted strings. An empty name or control characters is `Failed { "invalid_label" }` |
| `CreateMailbox` | `CREATE` with each `/`-level encoded in modified UTF-7 and joined by the server's delimiter (from `LIST "" ""`). An empty level, `*`, `%`, control characters, the server's delimiter inside a level, or levels on a flat server are `Failed { "invalid_name" }`; a listed mailbox (or `INBOX` in any case) is `Failed { "exists" }` before anything is sent, and so is `[ALREADYEXISTS]` |
| `RenameMailbox` | `RENAME`, with the new path encoded as for `CreateMailbox`. `INBOX`, and on Gmail the system mailboxes (All Mail, Sent, Drafts, Trash, Spam, Starred), are `Failed { "protected" }`; an unlisted mailbox or `[NONEXISTENT]` is `MailboxNotFound`; a taken path is `Failed { "exists" }`; renaming to the same path is `Applied` with nothing sent |
| `DeleteMailbox` | `DELETE`, with the same `protected` and `MailboxNotFound` rules. What happens to the messages and child mailboxes is the server's choice |
| `Append` | `APPEND` with the flags, `received_at` as a UTC date-time (whole seconds; left out outside years 1–9999) and a synchronizing literal; no content is `Failed { "missing_content" }`, `TRYCREATE` or `NONEXISTENT` is `MailboxNotFound` |
| `Refetch`, `Unknown` | `Failed { "unsupported" }` |

A connection lost or timed out after a write command left is `Uncertain`, and so is a failure after `UID COPY` succeeded. Errors before any write command (`SELECT`, `LIST`, sign-in) keep their meaning: `MailboxNotFound` and `Throttled` mean nothing changed, `Network` means the outcome is unknown. A tagged `NO` or `BAD` is `Failed { "refused" }`, `Failed { "exists" }` with `[ALREADYEXISTS]`, `MailboxNotFound` with `[NONEXISTENT]`, `Failed { "no_such_mailbox" }` with `[TRYCREATE]`, or `Throttled` when it carries a limit hint. When a batch of more than 1,000 UIDs is refused after an earlier batch went through, the result is still `Failed`, although the earlier batch is applied. After `Uncertain` or a network error the session refuses further calls with `Network`; connect again.

## Watches

`watch(mailboxes)` returns `None` when the server lacks `IDLE`. With `NOTIFY` and several mailboxes it uses one connection (`NOTIFY SET` for `MessageNew MessageExpunge FlagChange`); otherwise one connection per mailbox for the first three. Unknown or unselectable mailboxes are left out; with none left, `INBOX` is watched. `IDLE` is renewed every ten minutes; a dead connection ends the watch with `Network`. `next` returns the ids of the mailboxes that changed. Dropping the watch stops its connections.

## Errors

- Refused sign-in: `Auth`; a refusal that carries `LIMIT`, `UNAVAILABLE`, `INUSE`, `THROTTLED` or "Too many simultaneous connections" is `Throttled` (without a delay, IMAP gives none).
- Timeouts, I/O and lost connections: `Network`.
- A mailbox that does not exist or cannot be selected: `MailboxNotFound`.
- Errors never carry server text, which can echo mailbox names. Logs carry counts and timings only.

## Limits and what is left out

- async-imap buffers one response up to 512 MiB and offers no lower cap. Body fetches are batched by `RFC822.SIZE` (32 MiB per batch) so only a single huge message can grow the buffer that far. Lines before STARTTLS are capped at 8 KiB.
- `QRESYNC` and `VANISHED` are not used; removals come from the UID diff, which `EXISTS`/`UIDNEXT` usually let it skip.
- Conditional stores (`UNCHANGEDSINCE`) have no command in the contract yet.
- `NAMESPACE` is not read: `CreateMailbox` creates at the top level of the hierarchy, which servers that keep every mailbox under `INBOX.` refuse (`Failed { "refused" }`); pass the full path, such as `INBOX/Projects`, there.
- `UNSELECT` is not used: renaming or deleting the mailbox the session has selected forgets the selection on the client only.

## Server notes

The write suite runs against GreenMail, Dovecot and Stalwart (see Tests). All three report `\*` in `PERMANENTFLAGS`, so every system flag and keywords are claimed. GreenMail starts with nothing but `INBOX` and has no special-use mailboxes, so `trash` is `false` there until a mailbox named like a trash (`Trash`) exists. Dovecot and Stalwart list a `\Trash` mailbox.

## Tests

`cargo test -p skein-mail-imap` runs the `skein_mail::testing::conformance` suite against an in-process fake IMAP server without `CONDSTORE`, with `CONDSTORE`, as Gmail, over TLS and over STARTTLS (with a throwaway CA from `skein_core::tls::testing::TestCa`), and `skein_mail::testing::write_conformance` against the fake with `MOVE`, with `UIDPLUS` but no `MOVE`, and as Gmail (with `X-GM-LABELS` stores), plus focused tests for the cursor encoding, Gmail ids and labels, writes, capabilities, mailbox names, `APPEND` dates, STARTTLS refusal, plain-text refusal, XOAUTH2 and IDLE/NOTIFY watches. Nothing leaves loopback.

`tests/integration/tests/imap_write.rs` runs `write_conformance` against GreenMail, Dovecot and Stalwart in containers with `SKEIN_IT=1` (`cargo test -p skein-integration --test imap_write -- --test-threads=1`). It creates `skein-other` (and on GreenMail `Trash`) when missing, and adds its messages through the provider itself.
