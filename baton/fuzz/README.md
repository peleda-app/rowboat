# baton-fuzz

Fuzz targets for every decoder of untrusted bytes, on the pinned nightly in `rust-toolchain.toml`. `mise run fuzz-baton -- <target> [secs]` or `bash baton/fuzz/run.sh all [secs]`. The crate is its own workspace outside the root one; `mise run check` formats it and compiles its targets on stable.

| Target | What it attacks |
| --- | --- |
| `lease_record` | `LeaseRecord::decode` (records read from a store): never panics; whatever decodes re-encodes to an equal valid record; a held record has a token above zero |
| `roster` | `Roster::from_bytes`: only verified rosters come back (non-empty, signer is a member, no revoked member) |
| `pairing` | CPace peer messages and key confirmation tags (`Pake::finish`, `PakeSession::check_confirmation`): never panic, invalid points refused |
| `seal_open` | `baton_seal::open` on arbitrary bytes never succeeds and never panics |
| `store_records` | arbitrary bytes as a heartbeat record and a lease record in the store, then `CasLiveness::alive` at extreme observer times and `CasLeases::acquire`/`holder`: never panics; a granted token is above zero |
| `frame` | `baton_mesh::frame::Opener::open` on arbitrary bytes, with and without an expected sender: never panics; only a member's genuine frame could open |
| `group_entries` | `baton_group::Entry::decode` and `GroupLog::verify` over arbitrary byte chunks: never panic; decoded entries re-encode identically |
| `drop_request` | `baton_drop::wire::open`, `wait_ms`, `decode_reply`, `decode_info` and `DropService::handle` over a memory store with one box: never panic; whatever opens has a matching operation and a fresh timestamp, and `wait_ms` agrees with the opened take; every reply decodes |
| `drop_record` | `baton_drop::record::decode_box`, `decode_message`, `split_message_key` (what a persistent drop store such as `apps/drop` reads back): never panic; whatever decodes re-encodes to the same record |
| `lease_frame` | `baton_lease_server::wire::decode_request`, `decode_reply` and `frame_len` (what a lease server reads from any peer and a client reads from the server): never panic; whatever decodes re-encodes to an equal value; an accepted length is within the limit |
| `group_frame` | `baton_group_server::wire::decode_request`, `decode_reply` and `frame_len` (what a group server such as `batond` reads from any trusted peer and a member reads from the server), and every pushed entry that decodes through `GroupLogs::push` on a log with a genesis: never panic; whatever decodes re-encodes to an equal value; the head never goes back |
| `command` | `Command::decode` and `CommandResult::decode`: never panic; decoded values re-encode identically |
| `keys_box` | `KemPublic::from_bytes` and `open_box` on boxes cut from arbitrary bytes: never panic; forged boxes never open; short plaintexts sealed to a key open back only with the same associated data |
| `fetch_request` | `baton_fetch::fuzz_decoders`: a serving node's request header (length, then the versioned request with its locator) and a fetching node's reply header: never panic; an accepted reply length is within `max_object` |
| `names` | `RecordName` and `NodeId` construction and deserialization: no path traversal ever passes |

Every crash becomes a regression test next to the code and a corpus entry here before it is fixed.
