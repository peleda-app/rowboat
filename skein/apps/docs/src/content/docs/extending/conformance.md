---
title: Conformance suites
description: How an implementation proves it keeps a contract.
sidebar:
  order: 2
---

Every contract crate has a `testing` feature with a conformance suite and, where useful, an in-memory fake. Enable the feature in your `dev-dependencies` and call the suite from a test.

| Contract | Suite | What it checks |
| --- | --- | --- |
| `Objects` | `skein_storage::testing::all_over_objects(store)` | compare-and-swap (at most one of concurrent writers wins), read-after-write, byte-ordered listing, case-sensitive keys, exact values, and every typed store on top |
| `ControlStore`, `Log`, `BlobStore`, `CommandQueue` | `skein_storage::testing::{control, log, blobs, commands}` | the same for a direct implementation of a typed store: fencing, consecutive numbers, all-or-nothing appends, compaction, hash checks, idempotent ids |
| `Log` hash chain | part of `skein_storage::testing::log`; `all_over_objects` adds attacks on the stored objects | signed head and tip after appends and claims, the chain from the head covers every committed event, `locate`, `verify_extends` across appends and claims; tampered, reordered, removed and mixed-up segments, rolled-back, forked and stripped heads, forged attestations, journals written before chaining |
| `HeadAttestor` | `skein_storage::testing::head_attestor(attestor)` | an attestation verifies for its head and, when the attestor attests at all, for no other head, no other bytes and not when missing |
| `ControlStore` as Baton's `StateStore` | `skein_storage::testing::control_state(control)` | Baton's `StateStore` suite over `ControlState` (create-only, compare-and-swap, unique versions, group isolation, size limit, ordered and paged listing, concurrent writers), plus no collision with Skein's control records, forged objects refused, foreign names skipped; included in `all_over_objects` |
| `Leases`, `Liveness` (Baton) | `baton_lease::testing::{leases, liveness}` | grants, tokens that only grow and are never shared, exactly one winner of a race, takeover of dead holders, priority and takeover requests, corrupted records, time-to-live on the observer's clock |
| `Signal` (Baton) | `baton_signal::testing::signal(sig, ttl)` | group scopes, expiry, counters that are never lost and not extended by later adds, size and name limits |
| `Keyring` | `skein_keyring::testing::keyring(a, b)` | sealing bound to the scope (tenant or account) and context, account isolation from other accounts and the tenant, destroy per scope and through the tenant, one key under concurrent first use, the fallback for tenant-sealed account secrets |
| `ReadTier` | `skein_storage::testing::read_tier(tier, origin, counts)` | exact bytes or `None` by name, nothing over `max_len`, segments that verify along the chain, never a write |
| `MailProvider` | `skein_mail::testing::{conformance, write_conformance}` | listing, exact bytes, incremental changes, reset on a bad cursor, every write as far as `capabilities` claims |
| `PimProvider` | `skein_pim::testing::conformance` | paged listing, exact bytes and versions, upserts and removals, resets, idempotent creates by key, `if_version` conflicts |
| `Sender` | `skein_send::testing::conformance(&receiver)` | "not sent" versus "maybe sent", per-recipient refusals, size limits |
| `TokenEndpoint` | `skein_oauth::testing::conformance` | the token endpoint contract against a fake |

## Example: a storage backend

```rust
#[tokio::test]
async fn keeps_the_storage_contract() {
    let store = MyObjects::connect_to_test_instance().await;
    skein_storage::testing::all_over_objects(store).await;
}
```

## Example: a mail provider

Provider suites need a way to change the server behind your provider's back, so they take a `ServerControl` implementation: an in-process fake of your protocol, or a container.

```rust
#[tokio::test]
async fn keeps_the_mail_contract() {
    let (provider, control) = start_fake_server().await;
    skein_mail::testing::conformance(provider, control, "INBOX").await;
}
```

Run storage suites more than once against a real backend: an atomicity bug often shows only in some runs. Each contract's README describes what an implementation must do: [storage](https://github.com/peleda-app/rowboat/blob/main/skein/crates/storage/docs/README.md), [keyring](https://github.com/peleda-app/rowboat/blob/main/skein/crates/keyring/docs/README.md), [mail](https://github.com/peleda-app/rowboat/blob/main/skein/crates/mail/docs/README.md), [pim](https://github.com/peleda-app/rowboat/blob/main/skein/crates/pim/docs/README.md), [send](https://github.com/peleda-app/rowboat/blob/main/skein/crates/send/docs/README.md). Leases, liveness and signals are Baton's contracts; their suites and what an implementation must do are documented in Baton's `baton-lease` and `baton-signal` crates.
