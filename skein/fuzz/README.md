# Fuzzing

Coverage-guided fuzz targets ([cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz), libFuzzer)
for everything that reads untrusted provider answers or files. Every target must never panic and
never allocate without bound; where it is cheap, it also checks a round trip (what Skein writes
reads back as the same thing).

The crate lives outside the root workspace (`mise run check` formats it and compiles its targets on stable) and fuzzes on the nightly pinned in
[`rust-toolchain.toml`](rust-toolchain.toml). Crates expose what the targets call in a
`#[doc(hidden)] pub mod fuzzing`, which is not part of their public API. The two apps are read
through their own source files (`#[path]`), so they need no library target.

## Targets

| Target | What it reads |
| --- | --- |
| `itip` | iCalendar objects: `summary`, `facts`, `plan` on two objects; `request`, `cancel`, `reply` and `set_partstat` must give objects that read back, and building again from a built `REQUEST` or answered copy gives the same bytes |
| `imip` | raw messages through `imip::find` and `imip::read`; a message from `imip::compose` must carry its calendar back out |
| `dav_xml` | WebDAV `multistatus`, `sync-collection` and principal answers (quick-xml): responses, statuses, ETags, privileges, component sets, `calendar-user-address-set`; no entity is ever expanded (decoded text never outgrows the input); paths survive encoding |
| `mail_jmap` | JMAP sessions, method responses read as `Mailbox/get`, `Email/get`, `Email/query`, `Email/changes`; cursors |
| `pim_jmap` | JMAP sessions, responses read as `AddressBook/get`, `Calendar/get`, `ContactCard/get`, `CalendarEvent/get`, `/changes`; canonical object bytes are stable; JSCalendar answer patches; objects to write; cursors |
| `mail_imap` | mailbox names (modified UTF-7, both ways), Gmail labels (both ways), flags, UID sets, cursors |
| `mail_gmail` | `messages.list`, `history.list`, `labels.list`, message metadata, raw messages (base64url), error bodies, cursors |
| `mail_graph` | delta pages, error bodies, RFC 3339 dates (both ways), cursors |
| `pim_google` | calendar lists, events pages, events, an event being answered, connections pages, batch gets, people, error bodies, cursors |
| `pim_graph` | delta and listing pages, objects to write, attendee and organizer checks, error bodies, cursors |
| `journal` | `Event`, `Command` and `Snapshot` JSON (each round-trips), journal segments as stored (zstd) and as the NDJSON inside them, folded into a snapshot |
| `journal_chain` | stored journal heads (with tip and attestation; each round-trips) and chained segments: verification against the segment's own header never panics, accepts only matching bytes, refuses any other hash, and a chain walk from a head naming the segment ends |
| `control_state` | stored Baton state records (`ControlState`): the header check and round trip; control paths under `baton/` decode to a record name only if that name encodes back to the same path; the input planted as a control object is read back as a record and listed, and a foreign or malformed object or path is never returned as a record value or name |
| `keyring_local` | `LocalKeyring` with a planted tenant or account key record (any bytes, including forged JSON, bad base64, short or tombstone records): opening arbitrary sealed bytes under the tenant or an account scope is always `Invalid` or `Destroyed` and never panics, the `open_account` fallback never opens them, and whatever seals round-trips |
| `export_import` | `skein import` files (zstd NDJSON) into memory storage; the first byte `0` means the rest is the file as is, otherwise the input is compressed first so the lines get parsed |
| `sse` | Server-Sent Events streams (`skein-sse`) fed whole and cut into up to 15 chunks at fuzzer-chosen points: the same events or the same `TooLarge` either way; no event data over the limit |
| `push_notify` | Microsoft Graph notification posts, Gmail Pub/Sub envelopes and Graph validation tokens (`skein-push`, what the push receivers read from the internet): at most `MAX_GRAPH_ITEMS` notifications with plausible ids, Gmail addresses trimmed and bounded, echoed tokens printable and bounded |
| `oauth_redirect` | pasted redirect addresses (`skein_oauth::read_redirect`): whatever is accepted has a non-empty, trimmed code and state |
| `smtp_replies` | everything an SMTP server sends (`skein-send-smtp`): multi-line replies until the bytes end or one is malformed, each also read as an EHLO answer; codes stay three digits, replies stay within the line cap |
| `view_parse` | `skein-view` message parsing (caps on text, HTML and snippet, clean message ids) and JWZ thread assignment of up to four messages split at `NUL` |

Seeds are hand-written files in [`corpus/<target>/`](corpus) (and copies of the small fixtures
in `crates/itip/tests/fixtures` and `crates/view/tests/fixtures`). Runs write what they find to
`work/<target>/` and crashes to `artifacts/<target>/`; both are ignored by git.

## Running

Install cargo-fuzz once (`cargo install cargo-fuzz`); the script picks the pinned nightly itself.

```sh
mise run fuzz-skein -- itip 300     # one target for 300 seconds (60 by default)
mise run fuzz-skein -- all 120      # every Skein target, 120 seconds each
mise run fuzz-skein -- build        # build every Skein target
mise run fuzz-all -- 120            # every target of both layers
bash skein/fuzz/run.sh list         # the targets
```

Extra arguments after the seconds go to libFuzzer, for example
`mise run fuzz-skein -- itip 60 -jobs=4`. To replay a crash:
`bash skein/fuzz/run.sh replay itip artifacts/itip/crash-…` (paths inside `skein/fuzz/`).

CI ([`.github/workflows/fuzz.yml`](../../.github/workflows/fuzz.yml)) builds every target and runs
each for 30 seconds on pull requests that touch a parser crate, and for 300 seconds every week
(or as many as asked when started by hand). Crash files are uploaded as the `fuzz-crashes`
artifact.

## Adding a regression

1. Minimize the crash: in `fuzz/`, `RUSTUP_TOOLCHAIN=<the pinned nightly> cargo fuzz tmin -s none
   <target> artifacts/<target>/crash-…`.
2. Turn the minimized input into a test next to the code that failed: inline bytes, or a
   hand-written fixture in that crate's `tests/fixtures/`, with no real data (invented
   addresses on `example.com` or `example.org`).
3. Fix the code, check that the test fails without the fix, and run the target again.

Never commit crash files: they may hold whatever the fuzzer happened to put together.

## Adding a target

Give the crate a function in its `fuzzing` module (or use its public API), add
`fuzz_targets/<name>.rs` and a `[[bin]]` entry in [`Cargo.toml`](Cargo.toml), add seeds in
`corpus/<name>/`, a row above, and the crate's path to the pull request filter in the workflow.
