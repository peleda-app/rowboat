# Fuzzing the node layer

Coverage-guided fuzz targets (cargo-fuzz, libFuzzer) for every decoder of the node layer (`crates/`), beside `baton/fuzz` and `skein/fuzz`. Each target must never panic and never allocate without bound, and checks a round trip where one exists.

The crate is its own workspace outside the root one, on the nightly pinned in `rust-toolchain.toml`; `mise run check` formats it and compiles its targets on stable. Run with `mise run fuzz-node -- <target> [secs]`, `-- all [secs]`, `-- build`, `-- list`.

| Target | What it reads |
| --- | --- |
| `api_cursor` | list cursors as the app hands them back (`rowboat_api::cursor::decode`); an accepted cursor re-encodes to the same position |
| `api_request` | mutating calls as JSON payloads (`rowboat_api::decode_request`, the future Baton command payloads); an accepted request passes its checks and round-trips |
| `node_records` | the node's stored records (`rowboat_node::records`): the node record, local drafts and account records; each accepted one round-trips |
| `discover_autoconfig` | a domain's autoconfig file (`rowboat_discover_autoconfig::parse`); every candidate is valid, at most 16, and the same bytes give the same answer |
| `discover_dns` | DNS answers to an SRV question (`rowboat_discover_net::dns::parse_answer`); the id and question are taken from the input so the reader gets past the header; at most 32 records |

Seeds are hand-written files in `corpus/<target>/`. Runs write to `work/<target>/` and crashes to `artifacts/<target>/`; both are ignored by git.
