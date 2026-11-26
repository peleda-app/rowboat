# Open questions for the maintainer

Decisions the plan cannot make alone. Each has a recommendation; nothing is built on it until it is answered.

## Decided

- **License:** PolyForm Noncommercial 1.0.0 as part of rowboat (maintainer, 2026-11-25). See `../docs/DECISIONS.md`; every crate inherits `license` and `publish = false` from the workspace.
- **Name:** *Baton*, the relay baton (work is held by one node at a time and handed to a stronger one; the fencing token counts the hand-overs), and in Russian also a loaf of bread. Crates `baton-*` where free on crates.io, otherwise `peleda-baton-*`; binary `batond`. Baton is not published; it lives in the `baton/` layer of `peleda-app/rowboat`.
- **No storage in Baton.** Baton is a communication and coordination library; durable state goes through `StateStore` and `SecretStore` implemented by the application; S3, journals and external services stay with the application (PLAN.md, "The boundary").
- **Key mechanics in Baton, key policy in the application.** Baton seals, opens, checks and rotates; the application decides who gets what and when. A "bring your own keys" mode exists with weaker guarantees (SECURITY.md).
- **Recovery from scratch** through recovery roots whose public keys are in the group log and to which every epoch is boxed; today's tenant master key is replaced by a recovery root (a fresh root is recommended, see 7) and leaves the server.
- **One implementation of each thing.** Coordination contracts (leases, liveness, profiles, signals, ids, fencing) move from Skein to Baton's contract crates; Skein depends on those and deletes its own ownership and ephemeral crates. Skein keeps journals, storage, commands and providers, and gains account-scoped keys, a hash-chained journal with head attestation and a peer tier. The only meeting point of Skein and Baton is rowboat's node layer (`rowboat-*`), used by the app and by rowboat's headless server (PLAN.md).

## Project

1. **License.** Decided: PolyForm Noncommercial 1.0.0 as part of rowboat (see Decided).
2. **Moving crates out of `app`.** Move `seal`, `mesh-identity`, `mesh-transport`, `link`, `link-memory`, `link-iroh`, `transport-link`, `ephemeral-mesh`, `ownership-mesh` here with history (`git filter-repo`), then make `app` depend on Baton? Needs coordination with the session working in `app`. Recommendation: with history, after that session's current work lands.


## Skein

3. ~~**Skein's local rule.**~~ Resolved 2026-11-25: Baton and Skein merged into rowboat (PolyForm Noncommercial 1.0.0), and the paragraph of `skein/AGENTS.local.md` that forbade describing the mesh, nodes, pairing, relays and the hosted node was removed; the rest of that note still applies.
4. **Server deployments of Skein without Peleda.** After phase 2 a plain Skein server uses `lease-cas` (`CasLeases`, `CasLiveness`) from Baton over its S3 control store and `signal-local` (later `signal-nats`). Fine to make integrators pull three small Baton crates, or keep a thin re-export in Skein so its public API does not mention Baton? Recommendation: re-export from `skein-core`, so integrators see one crate.

## Design

5. **Members versus nodes.** The app's roster lists node keys only. The plan adds member keys that certify nodes (needed for teams, for "grant to a person" and for recovery). Recommendation: from the first version of `baton-group` (phase 4); retrofitting later changes every signed structure.
6. **Recovery roots in a family or team.** One root per member plus one group root held by the owners (members' private resources are not covered by the group root), or one root that covers everything (simpler; its holder can read everyone's private mail)? Recommendation: per member plus group; "one root for everything" only as an explicit family setting.
7. **Migrating today's master key.** When an existing Peleda setup becomes a Baton group, turn Skein's `keyring-local` master key into the owner's recovery root (no new secret to write down, but it has lived on a server) or generate a fresh root and re-seal (cleaner, one more step for the person)? Recommendation: fresh root, with the old master key kept only until re-sealing finishes.
8. **Second-device approval.** Which operations require it by default: adding a node, granting `admin`/`lead`, rotating a recovery root, and which Peleda command classes (mass delete, forwarding rules)? And what about people with a single device? Recommendation: on by default for group changes when the member has two or more devices; command classes chosen by the app.
9. **Group log ordering.** Sequenced through the arbiter (simple; changing the group needs the server, the app's store arbiter or a quorum) or a DAG merging concurrent admin entries (works fully offline, harder to audit)? Recommendation: sequenced.
10. **Re-sealing on revocation.** Default off (new epoch for new data only) or on? Recommendation: off; a button for admins.
11. **Phones as leaders.** Allow a phone to lead when a desktop exists but sleeps, and allow it to run `once` commands (sending)? Recommendation: yes for both, only in the foreground, with 30-second leases.
12. **MLS.** Ship `keys-boxes` first and evaluate OpenMLS later, or start with OpenMLS? Recommendation: boxes first; the group log stays the authority even if MLS is adopted.
13. **Post-quantum signatures.** Add ML-DSA as a second signature on group log entries, node certificates and recovery checkpoints as soon as a vetted Rust implementation exists? Recommendation: yes, those first, since they live longest.
14. **`vault`.** Platform vaults stay in `app` and implement Baton's `SecretStore`; the file vault goes to rowboat's headless server. Move it here later so other applications get hardware-backed secrets out of the box? Recommendation: only when a second application needs it.

## Transports

15. **SimpleX.** AGPL-3.0, Haskell, no Rust implementation, and its preset servers are for user-to-user messaging only. Options: skip; a clean-room Rust client of the SMP queue layer only, against self-hosted SMP servers (needs a legal opinion on the spec); the SimpleX CLI as a sidecar (AGPL binary per platform, no iOS). Recommendation: skip for now, keep the clean-room queue client as a research item. See TRANSPORTS.md.
16. **Drop service operation.** Peleda runs a public drop instance (cost, abuse handling, terms) or only the person's own server runs it? Recommendation: own server first; a public instance with proof of work and quotas when the hosted offering comes.
17. **Matrix and Nostr.** Build them in at all? Recommendation: Nostr as an optional wake channel; Matrix only if users ask.
