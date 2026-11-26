# skein-mail

The mail provider contract: per mailbox, an opaque `Cursor` and the `MailChange`s since it (`Reset`, `Added`, `Removed`, `Flags`, `Labels`), raw message bytes, and writes.

| Item | Guarantees |
| --- | --- |
| `MailSession::changes` | without a cursor: everything as `Added`, paged with `more`; with the previous cursor: exactly what changed since, never repeating earlier changes, never losing later ones; an unaccepted or unreadable cursor gives `Reset` and a full listing |
| `fetch` | exact bytes, vanished messages left out |
| reading | never changes the server |
| `apply` | `Applied`, `Conflict`, `Failed { reason }` or `Uncertain`; a command beyond the provider's capabilities is `Failed { reason: "unsupported" }`. Errors: `Network` means the outcome is unknown; `Auth`, `Config`, `Throttled` and `MailboxNotFound` mean nothing changed, so the engine runs the command again later instead of reporting it uncertain; `Protocol` may follow a partial change |
| `capabilities` | `MailCapabilities`: settable system flags, keywords, labels, trash, copy, `received_at` on append, mailbox management; the default (`basic_capabilities`) is `\Answered`, `\Draft`, `\Flagged` and `\Seen` only |
| `MailWatch::next` | wakes when something may have changed; dropping the watch closes it |
| `MailError` | `Auth`, `Config`, `Throttled { retry_after }`, `MailboxNotFound`, `Protocol`, `Network` |

## For implementations

Run `testing::conformance(provider, control, mailbox)` against a server your tests can change through `ServerControl` (an in-process fake of your protocol, or a container), and `testing::write_conformance(provider, control, mailbox, other, label)` for writes: flags (and keywords), move, copy, labels, delete for good and to the trash, append with flags and `received_at`, creating, renaming and deleting mailboxes, a missing mailbox, each checked only as far as `capabilities` claims and read back through the provider's own listing. Its messages carry unique subjects and are removed again, so it can run against a shared test account. `testing::FakeMail` is an in-memory server and provider used by engine and load tests; it has everything but labels.

## Push from the provider

`MailProvider::subscribe(&PushTarget)` asks a provider to call a public URL when the account changes and returns a `Subscription` with its expiry; `renew` extends it (by default it subscribes again) and `unsubscribe` ends it. The defaults do nothing (`Ok(None)`), so providers without push need no code. Gmail subscribes with `users.watch` to the operator's Pub/Sub topic, Graph with `/subscriptions` and a `clientState`. Notifications are hints: a missed one only delays the next sync. `skein-push` keeps the registry and renews; `skein-engine` renews after successful runs when `RunConfig::push` is set.
