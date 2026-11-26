# Licensing

How people may use rowboat, which additional licenses Peleda grants, and how a license key works: the certificate format, the keys that sign it, the verifier in the node, what the app shows, the tests, the phases and the risks. Decided by the maintainer on 2026-11-26 (see [DECISIONS.md](DECISIONS.md)); open points are in [QUESTIONS.md](QUESTIONS.md) (24 to 38).

Status: designed, nothing built. The issuer side lives in hallway ([hallway/docs/LICENSING.md](../../hallway/docs/LICENSING.md)), the pages on peleda.app in tinginys ([tinginys/docs/PLAN.md](../../tinginys/docs/PLAN.md)), the license screen in the app ([app/docs/PLAN.md](../../app/docs/PLAN.md)).

## The program

rowboat stays public under the PolyForm Noncommercial License 1.0.0. On top of it, the licensor grants three additional licenses itself, automatically where possible.

| Way to use rowboat | Who | Cost | How | Key |
| --- | --- | --- | --- | --- |
| **Noncommercial** (the base license) | personal use, hobby, study, research; charities, schools, public research, public safety or health, environmental organizations and government institutions, as PolyForm Noncommercial lists them | free | nothing to do | none, ever |
| **Small Team License** | anyone, for any purpose including commercial, up to 5 users counted together with affiliates; not for providing the node as a service to third parties | free | issued automatically: confirmed email address, accepted terms, key | yes |
| **Organization License** | human-rights organizations, press freedom and investigative journalism, legal aid, digital rights, refugee aid (education and independent research pending, question 27); not governments | free | by application, partly automated checks, the maintainer decides; one year, renewable, revocable on stated grounds | yes |
| **Commercial License** | companies above 5 users, and hosting providers (service to third parties) | paid | checkout through the merchants of record hallway already plans | yes |

What the Organization License is for, given the base license. PolyForm Noncommercial already permits use by "any charitable organization, educational institution, public research organization, public safety or health organization, environmental protection organization, or government institution", whatever their funding. The plan reads this to mean that a registered charity needs no key and that governments are not so much excluded from the Organization License as already covered by the base license (which, as the plan understands it, cannot be narrowed for copies already distributed); this reading is to be confirmed by the lawyer (question 24) and no page states it as settled before then. The Organization License matters for organizations whose noncommercial status is doubtful (independent newsrooms run as companies, legal-aid practices and cooperatives, fiscally sponsored or unregistered collectives, digital-rights consultancies) and for one right neither the base license nor Small Team gives: **running the node for beneficiaries and partner organizations** without a fee. For a charity it is also a document that gives certainty to boards, donors and auditors. The page sends charities to "no key needed" first. Whether this is the intended scope is question 24.

### What a key is, and what it is not

- **A signed certificate, not a lock.** It records a grant; it is evidence, not the grant itself. A forged or altered certificate grants nothing. Enforcement is by copyright and contract, with an audit on request in which the licensor checks the serial against its own issuance ledger.
- **Checked offline.** The node verifies it against public keys compiled into rowboat. It never phones home, never fetches anything about licensing, sends Peleda no telemetry and stores no user count beyond what the app shows (and local monthly peaks, see "Counting users").
- **Never blocks.** No feature, limit, rate, schedule or exit code depends on the license status. Noncommercial use needs no key and the app shows one neutral line for it.
- **Honest notices.** Owners and admins may see a dismissible notice when users exceed an installed license, when it ended, or when a server with an installed license that does not allow service serves several unrelated groups. Nothing else, never to ordinary members, and never anything when no certificate is installed.
- **Revocation without network.** Certificates run one year at most (400 days for Commercial with grace), and the latest end any certificate can carry is bounded by its issuing key's window (see "LicenseCert body"); a signed revocation list ships with rowboat and app updates and can be installed by hand. Nothing is fetched behind the user's back.
- **Screened and minimal.** Licensees are screened against sanctions lists with the sanctions engine running on Peleda's control machine; licensee data never goes to sanctions.page or anyone else. The certificate carries no email address, no account id and no unchecked name: Small Team certificates carry no name at all, Organization names are reviewed, Commercial names are checked at first issuance.

## Where the parts live

| Part | Repository | Crates and documents |
| --- | --- | --- |
| Format, verifier, trust anchors, shared test vectors | rowboat | `crates/license` (`rowboat-license`, pure library); this document |
| Node side: installed certificates, user counting, status, Baton commands, CLI | rowboat | `crates/licensing` (`rowboat-licensing`, service crate), wired by `rowboat-node` and `apps/rowboat` |
| Issuer: accounts, requests, applications, screening, signing, ledger, revocation list export, offline root tool | hallway | `hallway-license`, `hallway-license-key`, `hallway-screening`, `screening-sanctions`, `hallway-registry`, `apps/license-root`; [hallway/docs/LICENSING.md](../../hallway/docs/LICENSING.md) |
| Pages on peleda.app and the account pages on my.peleda.app | tinginys | `sites/peleda.app` (new), the portal patterns; [tinginys/docs/PLAN.md](../../tinginys/docs/PLAN.md) |
| License screen (status, install, request, renew) | app and tinginys app kit | `settings/license` pattern; [app/docs/PLAN.md](../../app/docs/PLAN.md) |
| Sanctions data and matching | sanctions (open) | `sanctions-engine`, `sanctions-snapshot`, used by hallway by path |

Dependency direction follows LIC-5: hallway (private) depends on `rowboat-license` (noncommercial) by path, so the issuer signs exactly the bytes the verifier checks and both run the same vectors. `rowboat-license` depends on no Baton crate, so hallway keeps its decision "No dependency on Baton yet". rowboat never depends on hallway. If a third party should verify keys under an open license, `rowboat-license` moves to its own open repository (question 33).

## Certificate format

One binary format, version 1, in the same shape as hallway's signed statements (postcard `{ body, signature }`, a versioned body, a context string per kind) and Baton's rules for signed structures (version byte, context string, size limits checked before the signature, a fuzz target).

### Signed objects and contexts

| Object | Signed by | Context |
| --- | --- | --- |
| `LicenseCert` | an issuing key with the role for its kind | `peleda-license/cert/v1` |
| `IssuerCert` (delegation of an issuing or revocation key) | a root | `peleda-license/issuer/v1` |
| `RevocationList` | a revocation key | `peleda-license/revocations/v1` |
| `LicenseRequest` (issuance or renewal request from the app) | the holder's key (proof of possession) | `peleda-license/request/v1` |
| `HolderProof` (links a holder key to a member on one node) | the holder key | `peleda-license/holder-bind/v1` |
| key id (hashed, never signed) | none | `peleda-license/key-id/v1` |

The signed message is `context || 0x00 || body`, byte-identical to `baton_identity`'s framing and to hallway's `CONTEXT` constants. Verification uses `ed25519-dalek`'s `verify_strict` (refuses malleable signatures and small-order keys). No license key signs under any other context, and no hallway or Baton key signs under these; a test asserts that a signature under each context fails under every other existing context (`hallway-attest/v1`, `hallway-command/v1`, `hallway-reqsig/v1`, every `baton-*` context) and the reverse.

### Envelope and canonical encoding

`Wire = postcard { version: u8, body: Vec<u8>, signature: [u8; 64] }`, version 1.

- `body` is the postcard encoding of the object; its first byte is the body version, which must equal the wire version.
- Decoding refuses trailing bytes in the wire, the body and any nested structure.
- **Canonical rule**: after decoding, the verifier re-encodes and compares byte for byte; anything that does not round-trip (overlong varints, a second spelling of an option or enum) is refused as `NonCanonical`. The signed bytes and the meaning are the same thing.
- Sizes are checked before decoding and before any signature work.
- Version 2 (post-quantum, see "Versioning") adds a second signature field; a v1 verifier refuses it as `UnknownVersion`.

### LicenseCert body, version 1

Every field is present (an `Option` encodes its absence). Enums are closed and append-only; an unknown tag is `Malformed`. There is no extensions field: a new field is a new version.

| Field | Type | Rule |
| --- | --- | --- |
| `version` | `u8` | `1` |
| `serial` | `[u8; 16]` | random, unique in the issuer's ledger; the handle for revocation, audit and support |
| `kind` | enum | `SmallTeam = 0`, `Organization = 1`, `Commercial = 2`. There is no kind for noncommercial use |
| `licensee_id` | `[u8; 16]` | random and opaque per licensee (not the hallway account id, not derived from the email); links renewals |
| `display_name` | `Option<String>` | 1 to 96 bytes, NFC, no code point of the Unicode general categories Cc, Cf, Co, Cn, Zl or Zp (which covers every control, format, bidi mark, override and isolate, LRM, RLM, ALM, soft hyphen, zero-width and tag character, private-use and unassigned code points, as of the Unicode version pinned by the crate's tables), no space other than U+0020, no leading or trailing space. Absent for Small Team (never printed, since nobody checks it); required for Commercial (checked against the payment record at first issuance, see hallway); for Organization the name the organization chooses to show, reviewed by the maintainer, which may be a pseudonym for safety |
| `country` | `Option<[u8; 2]>` | ISO 3166-1 alpha-2, upper case; absent if the licensee prefers (Organization) |
| `holders` | `Vec<[u8; 32]>` | 0 to 8 Ed25519 public keys, sorted, unique, none small-order: **license holder keys** the app creates for licensing only (one per owner or admin who binds, or one for a server operator), never a Baton member key. Present only when the person chose "bind this license to my group" in the app (which proves possession); empty for keys requested on the web or without binding. Which member a holder key belongs to is recorded only on the node (see "Binding") |
| `max_users` | `Option<u32>` | Small Team exactly `Some(5)`; Organization `None` or `Some(1..=1_000_000)`; Commercial `Some(1..=1_000_000)` or `None` for an unlimited agreement |
| `scope` | `u32` bitset | bit 0 `OWN_USE` (always set); bit 1 `SERVICE_TO_THIRD_PARTIES` (Commercial only); bit 2 `SERVICE_TO_BENEFICIARIES` (Organization only). Any other bit makes the certificate invalid, so a future scope is never read as a narrower one |
| `terms_id` | `String` | 1 to 32 printable ASCII bytes, for example `small-team/1.0` |
| `terms_digest` | `[u8; 32]` | SHA-256 of the exact terms text accepted, published at `peleda.app/license/terms/<id>` |
| `issued_at`, `not_before`, `not_after` | `u64` Unix seconds | `issued_at <= not_before + 1 day`; `not_before <= issued_at + 31 days`; `not_after > not_before`; `not_after - not_before` at most the cap of its kind (365 days for Small Team and Organization, 400 for Commercial) and at most the issuer's `max_license_days`; `not_after <= issuer.not_after + issuer.max_license_days`. So a leaked issuing key, current or retired, cannot mint a certificate that starts more than 31 days after a time inside its window or ends later than its window's end plus `max_license_days` |
| `supersedes` | `Option<[u8; 16]>` | the serial this one renews or replaces (renewal, reissue after a key rotation, a changed name) |
| `issuer_key_id` | `[u8; 16]` | must equal the key id of the `IssuerCert` in the same bundle |

Validity by kind: Small Team and Organization 365 days; Commercial the paid period plus 30 days of grace, capped at 400 days. **Renewal window**, the same in every document: a renewal can be requested from 60 days before the old certificate ends; the new one has `not_before = max(issued_at, old not_after − 30 days)` and `not_after = not_before + 365 days` (Commercial: the renewed paid period plus grace). A renewal made more than 30 days before the end is therefore `NotYetValid` for a while; `evaluate` keeps showing the old certificate as the best one until the new one starts.

### IssuerCert body, version 1

| Field | Type | Rule |
| --- | --- | --- |
| `version` | `u8` | `1` |
| `serial` | `[u8; 16]` | random |
| `key_id` | `[u8; 16]` | key id of `public_key` |
| `public_key` | `[u8; 32]` | Ed25519, not small-order |
| `roles` | `u8` bitset | `SMALL_TEAM`, `ORGANIZATION`, `COMMERCIAL`, `REVOCATIONS`. `REVOCATIONS` is exclusive: a key with it has no other role. Unknown bits are invalid |
| `min_version` | `u8` | the lowest wire version this key's objects may use; at least the version of this `IssuerCert` and at least the anchor's minimum |
| `not_before`, `not_after` | `u64` | the window: at most 15 months for keys with an issuing role, at most 25 months for a `REVOCATIONS` key |
| `max_license_days` | `u16` | at most 400; `0` for a `REVOCATIONS` key |
| `root_key_id` | `[u8; 16]` | the root that signed it |

A license is valid only when its `issued_at` falls inside the issuer's window, its dates obey the bounds above and the issuer holds the role for its kind, so a Small Team key can never produce an Organization or Commercial certificate. A certificate issued while its delegation was valid stays valid after the delegation ends: rotating issuing keys never touches licensees. A revocation list is accepted only when its `issued_at` falls inside its revocation key's window (see "Revocation list").

**Versions down the chain.** The wire version of every object must be at least the `min_version` of the `IssuerCert` that vouches for it, and an `IssuerCert`'s `min_version` at least its anchor's minimum. So under a hybrid (version 2) delegation a version 1 license or list is refused, and stripping the post-quantum signature at the issuer-to-license or revocation-key-to-list level fails as it does at the root.

### License bundle

What the licensee downloads and installs: `LicenseBundle = postcard { version: u8 = 1, issuer: Wire<IssuerCert>, license: Wire<LicenseCert> }`, at most 4 KiB (version 1 bundles are about 600 bytes; version 2 raises the limit to 16 KiB for ML-DSA). The delegation travels inside, so the node needs only the embedded roots.

### Revocation list

`RevocationBundle = postcard { version: u8 = 1, issuer: Wire<IssuerCert>, list: Wire<RevocationList> }`, at most `MAX_REVOCATIONS` (48 KiB), checked before decoding. The cap keeps the bundle, inside a `license-revocations` command, under Baton's 64 KiB `MAX_ENCODED` for commands with room for the command envelope; a test pushes a list at the cap through a real `Command::encode` and `Command::decode`.

| Field | Type | Rule |
| --- | --- | --- |
| `version` | `u8` | `1` |
| `number` | `u64` | greater than the stored list's number and at most the stored number plus 2^20 (see "Revocation distribution" for the one exception) |
| `issued_at` | `u64` | inside the signing revocation key's `IssuerCert` window |
| `serials` | `Vec<([u8; 16], Reason)>` | sorted, unique, at most 2 500 entries |
| `issuers` | `Vec<([u8; 16], u64)>` | sorted by key id, unique, at most 64 entries; key id and `since`: certificates of that key with `issued_at >= since` are revoked; `since = 0` revokes all (a leaked key can backdate, so compromise always uses 0). A revocation key listed here is revoked too: lists it signs are refused from then on |
| `roots` | `Vec<[u8; 16]>` | sorted, unique, at most 8 entries; withdrawn roots; an entry counts only when the list's revocation key was delegated by a different root. If the roots withdraw each other, both count as withdrawn and every certificate shows `Unverified` until an update brings new anchors |

`Reason`: `Superseded`, `TermsBreach`, `Sanctions`, `KeyCompromise`, `Fraud`, `PaymentReversed`, `NoLongerEligible`, `WithdrawnByLicensee`. Codes only, never text or names. The issuer omits serials whose certificate ended more than 30 days before, which keeps the list bounded: revocations of single certificates are rare (a leaked issuing key is revoked by one `issuers` entry, renewals are never listed), so 2 500 live serials is far above the expected need. The export refuses to produce a list over the caps; if the live list ever approaches them, signed delta lists or carrying lists over peer fetch are the way out (question 38).

A list is refused when its signer's key id is not pinned by the running release (see "Revocation distribution"), when the signer is revoked by the stored list, by a sticky entry or by the list itself, when the signer's `IssuerCert` was signed by a withdrawn root, or when its `issued_at` lies outside the signer's window.

### Key ids

`key_id = BLAKE3("peleda-license/key-id/v1" || 0x00 || public_key)[..16]`. Used for lookup only: the verifier always compares the full public key, so a key id collision cannot substitute a key.

### Text form and short id

```
-----BEGIN PELEDA LICENSE-----
base64 of the LicenseBundle (standard alphabet, padded, lines of 64 characters)
-----END PELEDA LICENSE-----
```

- Exactly one block; LF or CRLF; no headers inside; no character outside the alphabet; exact padding; the decoded bytes go through the canonical decoder. License text above `MAX_TEXT` (16 KiB) is refused before parsing.
- Text outside the block is ignored and never shown. The issuer writes a human summary above it ("Small Team License, up to 5 users, valid until 2027-11-26"); everything the app shows comes from the verified body, so an edited summary misleads only someone who never verifies.
- File extension `.peleda-license`, media type `application/vnd.peleda.license`. A bundle fits a QR code (binary mode, error correction M).
- Revocation lists use the same armor with `PELEDA LICENSE REVOCATIONS`, parsed by `parse_revocations_text` with its own limit `MAX_REVOCATIONS_TEXT` (72 KiB, enough for a 48 KiB list in base64 with line breaks), but normally ship as binary files inside releases. `rowboat license revocations install <file>` accepts either form; the fuzz target `license_text` covers both parsers.
- **Short id**, shown everywhere and used for support and audit: `PL-ST-`, `PL-OR-` or `PL-CO-` followed by the first 10 characters of the serial in RFC 4648 base32, in two groups of five (`PL-ST-7KQ2M-XD4PA`).

### Versioning and post-quantum

Version 1 is Ed25519 only: it matches Baton's member and node keys and hallway's attestations, its signatures are deterministic (so issuer and verifier vectors compare byte for byte) and small enough for QR codes and mail. A forged license gains nothing functional, so licensing migrates after Baton's group log, not before. When a vetted ML-DSA implementation passes `cargo deny` (the trigger in Baton's question 13):

- New hybrid roots (Ed25519 plus ML-DSA-65) ship in a release; each anchor states the minimum wire version it accepts.
- Wire version 2 carries both signatures over the same framed body; the body version is 2, so stripping the ML-DSA signature and relabelling the wire as version 1 fails, and a hybrid anchor refuses version 1 outright. Hybrid delegations carry `min_version = 2`, so the same holds for licenses and lists under them ("Versions down the chain").
- Version 1 bundles under the old anchors keep verifying until they end (at most 400 days); the release after that drops the classical-only anchors. Until then, and on nodes that never update, post-quantum signatures add nothing against a forger who can break Ed25519 (risk 16).

JSON (JWT, JWS) and X.509 were rejected: algorithm confusion, duplicate keys, a large parser surface and non-canonical forms.

### Verification order

1. Length limit. 2. Canonical decoding of bundle, wires and bodies. 3. Versions and anchor policy. 4. The root's signature on the `IssuerCert` (full key comparison against an embedded anchor). 5. The issuer's signature on the license. 6. Semantic rules: versions down the chain, roles, windows and date bounds, sorted and unique lists with their caps, scope bits by kind, `max_users` by kind, `display_name` characters; for lists, the pinned signer, its window and that it is not revoked. 7. Revocation. 8. Time (in `evaluate`, never in `verify`).

`verify` does not read a clock and does not refuse a certificate because of the node's time: a wrong clock changes the status shown, never whether the certificate is accepted for storage.

## Keys

### Hierarchy

| Key | Roles | Custody | Window |
| --- | --- | --- | --- |
| **Root R1** (active) and **R2** (standby) | sign `IssuerCert`s and, in an emergency, withdraw the other root | generated offline in a recorded ceremony; each held on a YubiKey 5 (firmware 5.7 or later, Ed25519 in PIV, PIN and touch "always"), with a backup seed split 2-of-3 with Shamir on paper or metal in separate places. Both public keys are compiled into rowboat (`crates/license/anchors/`) and published with fingerprints on `peleda.app/license/keys` | no expiry; rotated only by release |
| **Small Team issuer** | `SMALL_TEAM` | fully automatic, so the most exposed: a seed in hallway's control zone, loaded like the attestation key (systemd credential, zeroized, `Debug` shows only the public key), moving to the separate signer process or a YubiHSM in hallway's phase 2 | 12 months, overlap 1 month, `max_license_days` 365 |
| **Commercial issuer** | `COMMERCIAL` | same zone, separate seed; signs only after the reconciler re-read the entitlement from its source | 12 months, `max_license_days` 400 |
| **Organization issuer** | `ORGANIZATION` (and `COMMERCIAL` for hand-made deals) | on its own hardware token (token O), never on a server and never on a token that holds a revocation key; each signature needs a touch | 12 months, `max_license_days` 400 (Organization certificates stay at 365 days by the kind cap; hand-made Commercial ones get their 30 days of grace) |
| **Revocation keys A and B** | `REVOCATIONS` only | two distinct keys, each generated on its own token (token A with the maintainer, token B in a separate place), each with its own `IssuerCert` and its own PIN; both key ids are pinned by every release. A signs the list before each release; B is the standby that revokes A if A is lost, and A revokes B | 25 months |
| **Holder keys** | sign requests | license holder keys the app creates for licensing (per owner or admin who binds, or for a server operator) and keeps in the device's keychain; never a Baton member key; Peleda never sees the secret half | |

Separate roles keep a leak contained: the online keys can only mint the kind they are for, and none of them can sign revocations, so a compromised control machine can neither revoke licensees nor hide its own forgeries from the list.

### Ceremony and rotation

- The ceremony runs the offline tool `apps/license-root` (hallway) on an air-gapped machine booted from a fresh live image: `init` (roots), `certify-issuer <request>` (an issuing key's public key and wanted window, generated where it will live and carried on removable media), `sign-revocations <body>`, `sign-license <body>` (Organization, with the token). Every operation appends to a signed ceremony log kept with the seed shares; its hash is recorded in rowboat's anchors file history.
- Issuing keys roll yearly: a new key is certified before the old window ends, hallway switches, and the old seed is destroyed 30 days after the switch (recorded in the audit log; the one rule in every document). Existing certificates keep verifying because their delegation is inside them.
- Roots roll only by release: release N embeds the new root next to the old ones, the old one stays accepted for 400 days. At least two roots are embedded at all times.
- **Test keys** exist only behind the `testing` feature of `rowboat-license` (deterministic seeds labelled TEST). `TrustAnchors::release()` never contains them; a unit test asserts the tables do not overlap; a CI step scans release binaries for the test public keys and fails if it finds them; hallway's `check-config` refuses an issuer certificate that does not chain to a production root in a production configuration.

### Compromise

- **An online issuing key leaks.** The issuance ledger in hallway (an audit record per signature: serial, licensee id, kind, key id, body hash, with off-site heads) says which serials are legitimate. The maintainer signs a list with `issuers: [(key_id, 0)]`, a new key is certified, `hallway-reconciler license reissue --issuer <key_id>` re-signs every legitimate unexpired certificate under a new serial with `supersedes` set ("reissue" always means a new serial; downloading the same certificate again is "download"), licensees get a mail and a fresh download, and the list ships in the next rowboat and app release (a hotfix release if needed). Until a node updates, forgeries show as valid on the forger's own node, which changes nothing functional; an audit checks the ledger.
- **Token O (the Organization issuer) is lost or stolen** (physical theft plus PIN). Revocation key A signs a list with `issuers: [(O's key id, 0)]`, a new Organization key is certified from a root, legitimate Organization certificates are reissued as above.
- **Token A (revocation key A) is lost or stolen.** Revocation key B signs a list with `issuers: [(A's key id, 0)]`. That list replaces any list A signed whatever its number (see "Revocation distribution"), sticky entries that came only from A's lists are dropped, and lists signed by A are refused from then on. A new revocation key C is certified from a root and pinned by the next release next to B. Token B lost: the same with A revoking B. Both lost, or A and B revoking each other: both count as revoked, the node keeps the lists it had from neither, and the next release pins a new pair.
- **A root is compromised or lost.** R2 signs a revocation key whose list withdraws R1, every issuer is re-delegated under R2, legitimate certificates are reissued, and the next release adds R3 as the new standby. Both roots lost: a release with new roots and mass reissue from the ledger. Survivable because verification is advisory.

## Revocation distribution

The node never fetches a list. A list reaches it in three ways, all started by a person:

1. **Embedded in every release** of rowboat and the app (`crates/license/data/revocations.bin`, `include_bytes!`, verified at start like any input).
2. **From the app**: after an app update the app hands its newer embedded list to its nodes with the `license-revocations` command; the person can also do it from Settings → Node → License.
3. **By hand**: `peleda.app/license/revocations` offers the current signed file; `rowboat license revocations install <file>`.

The node keeps one list plus **sticky revocations**: once an installed certificate, its issuer or its root has been seen revoked, it stays revoked on that node even if a later list omits it. So a leaked revocation key can revoke more but never revive, and the issuer may drop long-expired serials without anything coming back. Rules for replacing the stored list:

- **Pinned signers.** Every release pins the revocation key ids it accepts (`crates/license/anchors/revocation-keys`, today A and B). A list from any other key is refused, and the trust in a revocation key never outlives the releases that pin it.
- **Numbers.** A list replaces the stored one when its number is greater and at most the stored number plus 2^20; otherwise it is refused as `Stale` or `NumberJump` (harmless). The cap stops a single list from setting the number to `u64::MAX`.
- **A revoked signer loses.** A list whose `issuers` names the signer of the stored list replaces it whatever its number. At start, if the stored list's signer is no longer pinned by the running release, or is revoked by the embedded list or a sticky entry, the stored list is dropped and the embedded list takes its place. So a stolen revocation key cannot freeze revocation: the other key's list or the next release resets it.
- **Sticky entries remember their signer.** Each sticky entry records which revocation key's list produced it; when that key is revoked or unpinned, the entries only it produced are dropped (an attacker's revocations do not outlive the attacker's key).
- **Time.** A list's `issued_at` feeds the clock floor only while that list is the stored one and only when it lies inside its signer's window (see "Time without the network").

## Verifier and node

### `rowboat-license` (pure library)

No I/O, no clock, no randomness (MOD-3); `#![forbid(unsafe_code)]`; compiles to WebAssembly for the verify page. Dependencies: `ed25519-dalek`, `postcard`, `serde`, `blake3`, `sha2`, `data-encoding`, `thiserror`, `unicode-normalization` (new, for the NFC check).

```rust
pub const MAX_TEXT: usize = 16 * 1024;
pub const MAX_BUNDLE: usize = 4 * 1024;
pub const MAX_REVOCATIONS: usize = 48 * 1024;
pub const MAX_REVOCATIONS_TEXT: usize = 72 * 1024;

pub struct TrustAnchors;      // release(); testing() behind the `testing` feature; roots and pinned revocation keys
pub fn parse_text(text: &str) -> Result<Vec<u8>, LicenseError>;
pub fn parse_revocations_text(text: &str) -> Result<Vec<u8>, LicenseError>;
pub fn verify_bundle(bytes: &[u8], anchors: &TrustAnchors) -> Result<VerifiedLicense, LicenseError>;
pub fn verify_revocations(bytes: &[u8], anchors: &TrustAnchors) -> Result<RevocationList, LicenseError>;
pub struct RevocationSet;     // merge(list) -> Result<(), LicenseError>; reset_from(embedded); mark_sticky(&[VerifiedLicense])
pub fn clock_floor(build_time: u64, revs: &RevocationSet, installed: &[VerifiedLicense], observed: Option<u64>) -> u64;
pub fn trusted_time(clock: u64, floor: u64) -> TrustedTime;
pub fn evaluate(installed: &[VerifiedLicense], revs: &RevocationSet, usage: &Usage, now: TrustedTime) -> LicenseStatus;
pub fn verify_request(bytes: &[u8]) -> Result<LicenseRequest, LicenseError>;
// feature `issue`: encode_body, signed_message, envelope, bundle, request encoding (used by hallway and the app)
```

- `LicenseError` (one `thiserror` enum, `Display` carries no input bytes and no names): `TooLarge`, `Malformed`, `NonCanonical`, `UnknownVersion`, `UntrustedRoot`, `BadKey`, `BadSignature`, `WrongRole`, `OutsideIssuerWindow`, `BadWindow`, `BadField(&'static str)`, `UnpinnedSigner`, `RevokedSigner`, `Stale`, `NumberJump`.
- `encode_body` refuses what `verify_bundle` would refuse, so the issuer cannot produce a certificate the node rejects.
- `evaluate` picks the best certificate: not revoked, then inside its window, then latest `not_after`, then serial; it is order-independent (property test).
- `LicenseStatus { state, best: Option<Summary>, users_seen, accounts_connected, clock_behind, revocations_number, notices }` with `state` one of `None`, `Valid`, `ExpiringSoon { days }`, `Expired { on }`, `NotYetValid`, `Revoked { reason }`, `Unverified { reason }`. `Summary` holds kind, short id, display name, country, `max_users`, scope, `not_after`, bound.
- `LicenseRequest { version, kind, holders, nonce: [u8; 16], created_at, audience, renews: Option<serial> }`, signed by every holder key under the request context; `audience` is the fixed string `peleda.app/license`; hallway checks it, the app creates it. How it reaches the page is in "What the app shows".

### Time without the network

`TrustedTime = max(system clock, floor)`. The floor is recomputed on every evaluation (never a stored maximum that only rises) as the largest of:

- the build time embedded at compile time (`SOURCE_DATE_EPOCH`);
- the `issued_at` of the stored revocation list, which is inside its signer's window by the acceptance rules, and drops out when that list is replaced or its signer revoked;
- the largest `issued_at` among installed certificates that are not revoked, each inside its issuer's window by the verification rules, and dropping out when the certificate is removed;
- the observed clock: the system clock recorded at a status evaluation (persisted at most once a day in `license/floor`), capped at the largest of the signed values above plus 35 days, so one wrong forward clock moves the floor at most 35 days past what Peleda has signed.

Setting the clock back therefore cannot revive a license past times the node has already seen (within the cap). The observed clock is cleared by the owner-only command `license-reset-clock-floor` (and `rowboat license reset-clock-floor`), and automatically when no certificate is installed; the signed values cannot be reset, since they are bounded by key windows. When the clock is more than a day below the floor the status says "the clock on this device appears to be behind". `not_before` tolerates 24 hours of skew. No NTP, `Date` header or other network time is ever queried for licensing.

### `rowboat-licensing` (service crate)

Takes `Arc<dyn baton_state::StateStore>` and the `baton_group::GroupState`s the node serves; depends on `rowboat-license`, `baton-state`, `baton-group`, `baton-core` only. It has no link, mesh, HTTP or DNS dependency, and a manifest walk test keeps it that way, so "never phones home" holds by construction. It can be built and tested before `rowboat-node` exists.

- `LicenseBook::open(store, anchors, embedded_revocations)`; `install(text_or_bytes)`: verify, then store; at most 8 certificates; idempotent for a serial already held; an expired or over-limit certificate is accepted (a renewal can be installed early, and a person can see why it is shown as ended); a chain error is refused with its reason. `remove(short_id)`. `install_revocations(bytes)`. `bind_holder(holder_proof, member)`. `reset_clock_floor()`. `status(groups, profile, caller, now)`. `record_usage(groups, now)` (daily tick). `dismiss(notice)`.
- State keys: `license/cert/<serial>` (bundle bytes, re-verified on read, so an edited record is found invalid), `license/revocations` (the stored list plus sticky entries with their signer), `license/floor` (the observed clock only), `license/holder/<holder_key>` (the member key it belongs to, see "Binding"), `license/usage/<yyyy-mm>` (a `u32` peak), `license/dismissed/<notice>`. Writes use Baton's compare-and-swap.
- Certificates are stored per node. The app installs a key on every node of the group it can reach and the license screen lists which nodes hold it; replicating it through a group resource instead is question 29.

### Counting users

`count_users(groups, now)` is pure and property-tested:

> users seen = the number of distinct member public keys that appear in `GroupState::members()` of any group this node serves and hold at least one node certificate in `nodes(now)` that is not revoked, not expired and not of class `Blind`.

- Owners, admins and members count alike; one person with several devices is one member key, one user. Members without a live device, blind nodes and the recovery identity do not count. Member keys are deduplicated across groups; the same person in two groups under two member keys counts twice, so the app says "about".
- A phone or desktop counts its own group. A self-hosted server counts across every group it serves. Peleda's hosted multi-tenant servers are Peleda's own deployment and show nothing.
- Mail accounts connected are reported separately as `accounts_connected`, for information: the contract's definition of a user also covers people whose mail is processed, which the node cannot tell.
- Affiliates are invisible to a node: the app says "this node sees about N people; your license counts everyone in your organization and its affiliates".
- The count is never sent anywhere. The node keeps monthly peaks (counts only, 24 months, local) so a licensee can answer an audit request by self-certification if they choose.

### Binding

Binding is opt-in: "Request a key" in the app offers "bind this license to my group" with a plain explanation (a copied certificate then shows as not bound; the certificate carries a licensing key that only your nodes can link to you). Holder keys are license holder keys the app creates for licensing, never Baton member keys, so a certificate shared in a bug report or on the verify page links to no identity that Baton peers, group servers or relays see.

The link between a holder key and a member exists only on the node: `license-install` may carry a `holder_proof` (the holder key's signature, under the context `peleda-license/holder-bind/v1`, over the node's group id and the calling member's key), and the node records `license/holder/<holder_key> → member key` after checking it. A certificate with `holders` is **bound** when any holder key is recorded on this node for a member who is still an owner or admin of a group this node serves (or, on a server, for the configured operator key). A bound certificate is shown as such; one whose holders match nobody gets the `NotBound` notice ("This license was issued to someone else's group"), which makes a copied certificate visible to the people running the node, with no network check: a copier has the certificate but not the holder secret, so cannot produce the proof. A certificate without holders is shown without either.

### Baton commands

The app manages the node only through Baton commands. Command classes on the node's admin resource (`node/<node_id>`, a per-node resource whose definition is question 28):

| Class | Who | Payload | Result |
| --- | --- | --- | --- |
| `license-status` | phone and desktop: any member of the group; server: see below | none | `LicenseStatusView`: the status, every installed summary, which notices apply to the caller's role, the revocation list number, monthly peaks (owners and admins, or the operator) |
| `license-install` | owners and admins (server: the operator) | bundle bytes or text, at most 16 KiB, and an optional `holder_proof` | `InstallOutcome { short_id, status }` |
| `license-remove` | owners and admins (server: the operator) | short id | |
| `license-revocations` | owners and admins, and the app after an update (server: the operator) | list bytes, at most `MAX_REVOCATIONS` (48 KiB), so the command stays under Baton's 64 KiB `MAX_ENCODED` | the stored list number |
| `license-dismiss` | owners and admins (server: the operator) | notice | |
| `license-reset-clock-floor` | owners (server: the operator) | none | the new floor |

Baton's `Command::check` enforces capability, signature, expiry and head. A replayed install is idempotent.

**On the server profile** the license belongs to the server's operator, not to the hosted groups. The operator is the configured operator key (`operator_key` in the server's configuration), or the owners of a designated operator group (`operator_group`). Only the operator may install, remove, dismiss, push revocations or reset the floor, and only the operator gets the counts, peaks, summaries and notices. A member or owner of any other hosted group gets a view that says only "this server's license is managed by its operator", with no kind, name, country or counts. Attack tests: a tenant owner tries to install, remove, dismiss or reset; a tenant member reads the status and gets no other tenant's counts and no operator details.

### Headless CLI

`rowboat license status | install <file> | remove <short-id> | verify <file> | revocations install <file> | reset-clock-floor`. `verify` works standalone (no node, no state) for licensees and auditors and prints what the certificate says and whether it chains to the embedded roots. Exit codes report only parse and verify errors of these subcommands; the license never changes the behaviour or exit code of `rowboat run`. A server may also name a file in configuration (`license_file`), installed at start.

The node logs one line at start and on change: kind, state, short id, counts and dates (`license: small_team valid until 2027-11-26, users 3/5, PL-ST-7KQ2M-XD4PA`). Never the display name, holder keys or country.

### What the app shows

Settings → Node → License (the `settings/license` pattern in tinginys' app kit):

- **No certificate**: "Noncommercial use · no license key needed" with a quiet link "Using Peleda for work?". No badge, no banner, no count, no dialog, no notification, on any device.
- **Valid**: "Small Team License · up to 5 users · valid until 26 Nov 2027 · PL-ST-7KQ2M-XD4PA · this node sees about 3 people" (no name: Small Team certificates carry none); "Organization License · <name> · may serve beneficiaries and partners · until …"; "Commercial License · <name> · hosting for third parties allowed · until …".
- **Renewed, not yet valid**: the current certificate as above plus "Renewal installed · starts on …".
- **Expiring, ended, revoked, unverified**: plain wording, the date or the reason code, and "Renew" or "Get a key", which opens peleda.app in the browser on the person's click.
- Actions: Add (paste, file, QR), Remove, Request a key, Renew, Update revocation list, Reset clock check (owners, shown only with `ClockBehind`), Usage history (owners and admins).
- **Request a key**: the person picks the kind and whether to bind it to the group (opt-in, explained). With binding, the app creates license holder keys in the keychain of the owners' devices that take part, never using a member key, and signs a `LicenseRequest`. The request reaches the page only in the URL fragment (`peleda.app/license/small-team#request=<base64url>`, which browsers never send to a server and which the page reads and clears from the address bar at once), or as a file or clipboard text the person drops in; never in a query string. A request is single-use: hallway refuses a second presentation. If someone else's account presented it first (a leaked request), the app's "start again" makes new holder keys and a new request, so a stolen request locks nobody out; the stolen certificate stays `NotBound` on every node, since the thief cannot produce the holder proof.

### Notices

A closed set computed in `evaluate`, shown only to owners and admins, only in Settings → Node as a non-modal banner, dismissible for 90 days, back earlier only if the numbers change. No operating-system notifications: renewal reminders come by mail from the issuer.

| Notice | When | Text (draft) |
| --- | --- | --- |
| `OverLimit { seen, allowed }` | a valid certificate with `max_users` and more users seen | "This node serves about 7 people; your Small Team License covers up to 5, together with affiliates. Nothing stops working. An Organization or Commercial License covers more." |
| `ExpiringSoon { days }` | 30 days or fewer left | "Your license ends on …. Renew at peleda.app/license." |
| `Ended { on }`, `Revoked { reason }` | an installed certificate ended or was revoked | "Your license ended on …. Nothing stops working." |
| `NotBound` | holders present and none matches | see "Binding" |
| `ServiceWithoutLicense` | server profile only, a valid certificate is installed and none of the installed ones has `SERVICE_TO_THIRD_PARTIES` or `SERVICE_TO_BENEFICIARIES`, and the server serves two or more groups whose owners share no member key. The installed certificate is the commercial signal the node can see; with no certificate installed this notice never appears (a person hosting their own family and a friend's is noncommercial) | "This server serves several unrelated groups, and your license does not cover service to others. If you provide this as a service, you need a Commercial License (or an Organization License to serve beneficiaries)." Shown to the server's operator only, never to the hosted groups |
| `ClockBehind` | clock more than a day below the floor | "The clock on this device appears to be behind." with "Reset clock check" for owners |

No notice of any kind appears when no certificate is installed, whatever the group size or the number of groups (a family of eight is noncommercial). The node never guesses commercial use from mail content.

### Guarantees and how they are enforced

- **No blocking.** `rowboat-licensing` exposes no function returning a permission. Only `rowboat-node`'s admin handler, `apps/rowboat`'s CLI and the app's bridge may depend on `rowboat-license` or `rowboat-licensing` (a dependency check in `mise run check`, `no_licensing_gate`). An integration test runs the node's functional scenario with no certificate, a valid, an expired, a revoked, a forged, an over-limit and a garbage one installed and asserts identical behaviour.
- **No phone-home.** The manifest walk above, plus a test that captures sockets during install, status and revocation install and finds none.
- **No secrets or personal data in logs** (SEC-3). A log capture test over every verify and install path finds no display name, holder key, country or serial bytes beyond the short id.

## Issuance (summary)

The issuer is part of hallway's control plane; details, contracts and abuse controls are in [hallway/docs/LICENSING.md](../../hallway/docs/LICENSING.md). The edge (portal-api) only writes intents; control re-checks, screens, signs, records in the audit log and projects the bundle back for download. No signing key is ever at the edge.

- **Small Team** (automatic, about two minutes): a portal account with a confirmed address, the form (licensee name, kept in the account and never printed on the certificate; country; three statements: at most 5 users with affiliates, no service to third parties, authority to accept), the terms with their digest, optionally the holder request from the app. Control checks limits and screens; clear → signed with the Small Team issuer, ledger record, a mail with a link to the download. A hit → held for review, the person is told only that a manual check is needed.
- **Organization** (application): mission, independence and eligibility criteria published; automated hints (register lookups from published bulk files, domain checks, screening, not a government body); the maintainer decides in the review queue (operator CLI until hallway's admin panel exists) with a closed list of reasons; signed on the maintainer's token; one year; renewal by a two-question form, pre-approved when nothing changed.
- **Commercial**: checkout at a merchant of record, the entitlement re-read from its source, the display name checked against the payment record at first issuance (a mismatch goes to the review queue), signed with the Commercial issuer for the paid period plus 30 days; renewed with each renewed entitlement; a lapse issues nothing new and revokes nothing (the certificate simply ends); a refund or chargeback for fraud revokes.
- **Renewal**: possible from 60 days before the end (the app offers it from then; reminder mails follow hallway's schedule); a new certificate under a new serial with `supersedes` and the dates of "Renewal window", screened again, terms accepted again if their digest changed. Never automatic from the node.
- **Revocation grounds** (closed, published): false statements; users or scope exceeded and not cured within 30 days of notice; sanctions listing of the licensee or its controlling owners; the key published or shared outside the licensee; service to third parties without that scope; loss of eligibility (Organization); payment fraud or a chargeback (Commercial); the licensee's own request. Notice with the ground, 30 days to respond or cure (none for sanctions, fraud or a published key), then the serial goes into the next list; the licensee is told which release carries it. One appeal by mail.

## Privacy

- **In the certificate**: kind, limits, scope, terms, dates, an opaque licensee id, a display name for Organization (which may be a pseudonym) and Commercial only, optionally a country, optionally holder public keys. Holder keys are licensing-only keys, but they are stable for the life of the license and its renewals: anyone holding the certificate can recognise the same holder keys on another certificate, and the nodes that recorded the binding can link them to the owners' member keys. No email, no account id, no address, no IP.
- **On the node**: certificates, the revocation list, the observed clock, the holder-key bindings, monthly peak counts, dismissals. Nothing is transmitted. Certificates may end up in bug reports, which is fine for unbound ones; the app says that a bound certificate carries the group's licensing keys.
- **At the issuer** (control store; the edge holds only what "Shape" in hallway's document allows): the account's email (already there), licensee name and country, terms acceptance (id, digest, time), serials and dates, holder public keys of bound licenses (for renewals and the one-active-Small-Team rule), request nonces (kept two hours), screening outcomes (outcome, list ids, entry ids, snapshot version; never copies of list entries), application fields for Organization (sealed in the browser to a control-only key, sealed at rest under the tenant secrets key, since they reveal affiliations; deleted 90 days after a refusal or withdrawal). The audit log carries ids and codes only, never names or holder keys, because the hash chain cannot be edited.
- **Retention** (proposal for the lawyer, question 36): while a license is valid plus one year for the email, name and holder keys; request nonces two hours; serial, kind, dates and acceptance record three years; then only serial, kind and dates.
- **Screening** runs on the control machine against a signed local snapshot; register checks use bulk files downloaded weekly; no query to a third party reveals who applied.
- **Rights**: export and erasure through the account page; erasure of an active licensee first supersedes the certificate (a name already handed out cannot be recalled). The merchant of record is an independent controller for payment data; hallway keeps only entitlements.
- **Lawful bases** (to be confirmed by the lawyer): contract for issuing and renewing; legal obligation or legitimate interest for sanctions screening; legitimate interest for abuse limits.

## For the lawyer

### Documents

1. **Small Team License**: an additional permission on top of PolyForm Noncommercial, any purpose, at most 5 Users counted with Affiliates, no Service to Third Parties, one year, renewable, one per Licensee with its Affiliates, termination for breach after a 30-day cure, no warranty or liability (as PolyForm), audit on request, sanctions and export clause; ending it ends only the additional permission, PolyForm rights remain.
2. **Organization License**: eligibility as stated at issuance; own use plus service to Beneficiaries and Partner Organizations without fee; the users cap if any; one year; a duty to report a change in eligibility; revocation grounds and procedure; truthful application.
3. **Commercial License agreement and order form**, with a **Hosting addendum** (service to third parties, branding and trademark, no sublicensing of the software beyond use of the service, yearly self-certification of hosted users), fitted to the merchant of record's reseller terms (the merchant is the seller of record, the licensor licenses). B2B only, or consumer withdrawal language (question 35).
4. **Eligibility policy and review procedure** for Organization licenses, with the appeal.
5. **Revocation policy** (the grounds above).
6. **Licensing privacy notice** (GDPR Art. 13).
7. **Audit clause**: written self-certification on request, at most once a year, 30 days' notice; an independent auditor only on documented reasonable suspicion, at the licensor's cost unless a material shortfall is found; never access to mail content.
8. **Terms acceptance record**: terms digest, time, confirmed account, holder signature when present.
9. **License key notice**: the certificate is evidence of a grant, not the grant; a forged or altered certificate grants nothing; its absence never restricts noncommercial use.
10. **CLA placeholders** (question 11) filled, since the additional licenses rest on the CLA; and the licensor's name and seat (question 10).
11. **Templates**: request for information, refusal reasons, revocation notice, the friendly first letter to a hosting provider found offering rowboat.
12. **Trademark note** for the name Peleda (separate from the copyright licenses).

### Definitions to settle

- **Software**: rowboat and any Peleda build that contains it.
- **Licensee**: the single legal person, or natural person acting in a business capacity, the license is issued to.
- **Affiliate**: any entity that controls, is controlled by, or is under common control with the Licensee; control means more than 50 % of the voting interests or the power to direct management and policies by contract or otherwise.
- **User**: a natural person who (a) has an identity in a group served by a node used by the Licensee or its Affiliates, or (b) whose mail, calendars or contacts the Software processes for the Licensee or its Affiliates; counted once across all their nodes; employees, contractors and volunteers count; automated mailboxes with no person behind them do not; shared mailboxes count the people who use them; people whose messages are merely received do not. The node's count is an approximation; the contract governs.
- **Service to Third Parties**: making the Software's functionality available, paid or free, to anyone who is not a User of the Licensee or its Affiliates (hosting, managed services, white-label, embedding in a product offered to others). Running nodes for the Licensee's own Users on someone else's infrastructure is not.
- **Beneficiary and Partner Organization** (Organization License): a natural person the organization serves within its mission, or a nonprofit organization in an eligible field with documented cooperation, served without fee.
- **Eligible Organization**: primary purpose in an eligible field; independent (not a government body, not state-owned or controlled, not a party or campaign); not profit-distributing, or a for-profit newsroom or legal-aid practice whose main activity that is (revenue threshold, question 26); not listed on sanctions or caution lists.
- **Commercial Purpose** and **noncommercial organization**: as PolyForm Noncommercial words them.
- **Certificate** or **License Key**; **Term**, **Renewal**, **Revocation**, **Cure Period**.

## Tests

### Shared conformance vectors

`crates/license/vectors/v1.json`, generated by `mise run regen-license-vectors` from deterministic TEST roots and issuers and checked in; a golden test pins the context strings and the byte layout. Each vector: name, seeds, body fields, the expected bundle bytes (hex) and text, and expected results (`Ok(state)` or an error variant) for evaluation cases (`usage`, `now`, revocation set). Consumers: `rowboat-license`'s tests (verify and evaluate every vector), hallway's `hallway-license` conformance suite (signs every positive body and must produce the identical bytes; refuses every negative body before signing), the app's bridge (the text vectors), the verify page (the text vectors through WebAssembly). Hallway's CI checks out rowboat and runs them, so format drift fails both.

- **Positive**: each kind; maximal and minimal fields; 8 holders; a non-ASCII NFC display name; scopes by kind; a renewal pair; a renewal made 60 days ahead (renewed, not yet valid, old still valid and shown as best); a hand-made Commercial certificate of 395 days under the Organization issuer; a bundle at exactly `MAX_BUNDLE`; issued one second before the issuer's window ends and evaluated after it ended; `not_before = issued_at + 31 days`; `not_after = issuer.not_after + max_license_days`.
- **Negative, one mutation each**: every single bit flip of body and signature (exhaustive); trailing bytes in wire, bundle and body; overlong varint and non-canonical option or enum; unknown wire and body version and mismatched versions; unknown kind; a key id that matches but a different full key, and a crafted key id collision with test keys; small-order and non-canonical public keys; a malleated signature (`S` not reduced); a Small Team issuer signing an Organization or Commercial certificate; a `REVOCATIONS` key signing a license; a key with `REVOCATIONS` plus another role; `issued_at` outside the issuer window; a far-future `not_before` (`issued_at + 31 days + 1`); `not_after` one second beyond `issuer.not_after + max_license_days`; validity above `max_license_days` or the cap of its kind (an Organization certificate of 366 days under the 400-day Organization issuer); `not_after <= not_before`; a revocation key whose window exceeds 25 months, an issuing key whose window exceeds 15 months; Small Team with `max_users != 5`, a service scope or any display name; unknown scope bits; holders unsorted, duplicated or 9; display name empty, 97 bytes, with RLO, ZWJ, LRM, RLM, ALM, a soft hyphen, a tag character, a private-use or unassigned code point, U+2028, a control character, a newline, a leading space or not NFC; a version 1 license or list under an `IssuerCert` with `min_version = 2`, and an `IssuerCert` whose `min_version` is below its anchor's (strip and relabel at the issuer-to-license and revocation-key-to-list levels); lower-case or unknown country; context swaps (a license signature presented as an `IssuerCert`, a revocation list, a request or a holder proof, and each reverse; a request signature presented as a holder proof); a hallway attestation fed as a license and the reverse; an untrusted root; a test root against release anchors.
- **Revocation vectors**: revoked serial; revoked issuer with `since` before and after `issued_at`; withdrawn root by the other root; a root withdrawing itself (ignored); both roots withdrawn (`Unverified`); a lower or equal number (`Stale`); a number above the stored one plus 2^20 (`NumberJump`), including `u64::MAX`; a list signed by an issuing key; a list signed by an unpinned revocation key; a list whose `issued_at` is outside its key's window, including far in the future; a list signed by a key under a withdrawn root; key B revokes key A with a lower number than A's stored list (B's list replaces it, later lists by A are refused, sticky entries only A produced are dropped); A and B revoking each other; a release whose embedded list revokes the stored list's signer (reset at start); unsorted or duplicated serials, issuers or roots; 2 501 serials, 65 issuers, 9 roots; a list at exactly `MAX_REVOCATIONS` through `Command::encode` and `decode`; an armored list at `MAX_REVOCATIONS_TEXT` and one byte over; sticky revocation surviving a later list that omits the serial.
- **Time vectors**: not yet valid inside and beyond 24 hours of skew; expired; the clock behind the floor; the floor from build time, from a list and from a certificate; a list's `issued_at` leaving the floor when the list is replaced; one evaluation at a clock years ahead, then a correct clock: the observed value is capped at the largest signed value plus 35 days, and after `reset_clock_floor` the status is `Valid` with no `ClockBehind`; the observed clock cleared when the last certificate is removed.

### Attack tests (named after the attack)

- `rowboat-license`: substitution of a signature from another certificate; edited text outside the armor never shown; 16 KiB plus one; size checked before any signature work (counted); revival by a leaked revocation key (sticky); revocation frozen by a leaked revocation key (number at `u64::MAX`, far-future `issued_at`) and unfrozen by the other key's list and by a release; forged certificates of every kind but Small Team under a leaked Small Team issuer refused, and after `issuers` all shown `Revoked`; a retired Small Team key minting a certificate that starts years later, refused; clock rollback past the floor keeps `Expired`.
- `rowboat-licensing`: install from a member without the capability; a replayed install; an oversized payload; garbage input yields a typed error and no panic; a record edited in the state store is found invalid on read; an older list never replaces a newer one, also after restart and reinstall; a copied certificate shows `NotBound`; a copied certificate with a forged `holder_proof` is refused; a holder whose member was removed from the group shows `NotBound`; on the server profile, a tenant owner's install, remove, dismiss, revocations and reset are refused and a tenant member's status reveals no counts, kind, name or country; `ServiceWithoutLicense` never on phone or desktop profiles and never shown to hosted groups; two unrelated personal groups on a server with no key show no notice; no notice without a certificate on a personal group of any size; `no_licensing_gate` (identical behaviour across states); the socket capture; the log capture.
- Hallway's attack tests (request forgery, replay, splitting, edge compromise, screening fail-closed) are listed in [hallway/docs/LICENSING.md](../../hallway/docs/LICENSING.md).

### Fuzz targets

In a new `fuzz/` workspace for the node layer at the root, beside `baton/fuzz` and `skein/fuzz` (one target per decoder, as the rules require): `license_text` (armor parser), `license_bundle` (bytes to `verify_bundle` with test anchors), `license_revocations`, `license_request`, `license_structured` (arbitrary bodies signed with the test issuer, to reach the semantic checks past the signature, asserting that `verify` accepts exactly when a plain reference model of this specification accepts), and `license_command` (the six command payload decoders and the `holder_proof`). Properties: no panic, allocation bounded by a small multiple of the input, every accepted input round-trips, no quadratic checks on sorted lists.

### Property tests

Encode, decode and verify round-trip for every body; best-certificate selection is order-independent; `count_users` is invariant under group order and duplicated members, never counts blind, revoked or expired nodes, and never decreases when a member with a live device is added; more users never improves a status; a revocation lookup by binary search equals a linear scan.

### Load tests

Verify 10 000 bundles (recorded, expected well above 20 000 a second in release); start-up verification of an embedded list at the cap (2 500 serials, 48 KiB) under 5 ms on a Raspberry Pi 4 class device and under 1 MiB of memory; `count_users` and `evaluate` for a server serving 10 000 groups with 50 000 members under 100 ms. Small in `cargo test`, full size in `mise run load`.

## Phases

The phases are named L0 to L9 so they do not collide with rowboat's, hallway's or the app's numbering. Where they fall among rowboat's phases is in [PLAN.md](PLAN.md#license-keys).

| Phase | Where | Work | Done when |
| --- | --- | --- | --- |
| **L0 Decisions and legal groundwork** | rowboat, hallway, lawyer | This document and hallway's, the DECISIONS entries, the questions; the lawyer starts the Small Team terms and the privacy notice; licensor entity and CLA placeholders | the maintainer signed off the format, roles and invariants; the Small Team terms and privacy notice are final with a published digest |
| **L1 Format and verifier** | rowboat `crates/license` | types, envelope, canonical rule, bundle, revocations, requests, armor, short id, `verify`, `evaluate`, `trusted_time`, test anchors, vectors and the golden test, attack, property and load tests, the fuzz targets, `docs/README.md` | `mise run check` green, every vector passes, each fuzz target ran 30 minutes clean, `dojo check` passes |
| **L2 Keys** | offline, hallway `apps/license-root`, rowboat | the offline tool (`init`, `certify-issuer`, `sign-revocations`, `sign-license`, ceremony log), the ceremony runbook (`hallway/docs/LICENSE-KEYS.md`), a dry run with test roots, then the real ceremony: R1, R2, the five delegations (Small Team, Commercial, Organization on token O, revocation keys A and B on tokens A and B), an empty revocation list number 1 signed by A, the pinned revocation key ids; anchors committed; the release-binary scan for test keys | the dry run's issuer certificate verifies in rowboat; the production anchors and fingerprints are published; the ceremony log is stored off-site |
| **L3 Issuer core** | hallway | `hallway-license` (contract, pure rules, suite over the shared vectors), `hallway-license-key`, `hallway-screening` with memory and sanctions implementations, store and audit extensions, the operator commands (`lookup`, `revoke`, `export-revocations`, `reissue`), forbidden-crate walks for the edge | the suites are green; an integration test issues, verifies with `rowboat-license`, revokes and re-verifies |
| **L4 Small Team end to end** | hallway, tinginys | intents, portal routes, limits, screening, issuance, projection and download, notices and mails, renewal; the pages `/license`, `/license/small-team`, terms, privacy, FAQ, keys and revocations, and `my.peleda.app/licenses` | the integration scenario "sign up, confirm, request, receive bundle, verify on a test node" passes on memory implementations; the attack and load tests pass; the site builds with types, lint and tests green; the lawyer reviewed the copy |
| **L5a Node on a device and app** | rowboat `crates/licensing`, `rowboat-node`, `apps/rowboat` (`license verify` only), app, tinginys app kit | `LicenseBook`, `count_users` for one group, holder binding, notices, the commands on the device profile, the log line, the standalone `rowboat license verify`; the license screen with every state, the request generator (holder keys, fragment hand-off) and the revocation hand-off after updates | every state from the vectors renders in a story and a test; `no_licensing_gate`, socket and log capture pass; the node on one device (rowboat phase 1) takes the commands |
| **L5b Server** | rowboat `apps/rowboat`, `crates/licensing` | the `rowboat license` subcommands, `license_file`, the operator rule on the server profile, counting across the groups a multi-tenant server serves, `ServiceWithoutLicense` | the server attack tests (tenant owner, tenant member, two unrelated groups without a key) pass on rowboat phase 3 |
| **L6 Organization** | hallway, tinginys | applications (sealed fields), `hallway-registry` with the first bulk-file registers, the review queue (CLI, later the admin panel), signing on the maintainer's token, request for information, refusal reasons, appeal, renewal pre-approval, retention pruning; the application page | apply → hints → approve → install → renew → revoke with a stated ground lands in the next list, end to end on memory implementations |
| **L7 Commercial** | hallway, tinginys | license plans in the catalog, issuance on a re-read entitlement, renewal, lapse, refund and fraud revocation, the hosting plan; the commercial and hosting pages | "checkout (memory merchant), entitlement, certificate, renewal, lapse, end" passes; going live waits on the first real merchant of record (hallway question 2) |
| **L8 Revocation pipeline and drill** | rowboat and app CI, hallway | CI embeds the latest signed list and checks its signature, its pinned signer, its size cap and that its number did not go down; the hotfix release procedure; the compromise drills with test keys (a leaked Small Team issuer: revoke, reissue all, ship, nodes show `Revoked` then `Valid`; a stolen revocation key A freezing the number: B revokes A, nodes take B's list) | the drills pass and are documented |
| **L9 Hardening and review** | hallway, rowboat | the online issuers move into the separate signer process or YubiHSM (hallway phase 2); hybrid anchors once Baton adopts ML-DSA; external review of format, verifier and signer together with Baton's audit | hybrid vectors and strip tests pass; review findings closed |

**Go-live gate** for the first public key: the real ceremony done, production anchors in a signed rowboat and app release, the Small Team terms and privacy notice final, the screening snapshot loaded, L1 to L4 and L5a done. L5b (the server) follows with rowboat phase 3 and is not needed for the first key; the Small Team pages go live with this gate, not with L4 alone.

## Risks

1. **The verifier is public and can be patched out.** Accepted by design: the certificate is evidence, not a lock, and the page says so. Enforcement is copyright, contract and audit against the issuance ledger.
2. **Leak of the online Small Team key.** Contained by roles (Small Team only), yearly windows, the date bounds (no certificate ends later than the key's window end plus 365 days), destruction 30 days after the switch, the ledger, reissue and revocation in the next release. Residual: forgeries look valid on forgers' own nodes until they update, with no functional effect.
3. **Root compromise or loss.** Two roots, cross-withdrawal, Shamir backups, rotation by release. Residual: old binaries trust a compromised root until updated.
4. **Revocation latency.** Lists travel only with updates or a person's action, so a revoked certificate can look valid for months on an unupdated node; expiry bounds it (a certificate's own end, and for forgeries the issuing key's window end plus `max_license_days`). The price of never phoning home.
5. **Clock manipulation.** The floor bounds rollback to times already seen; a fresh install with a clock in the past shows an expired certificate as valid. Harmless. In the other direction, a wrong forward clock moves the floor at most 35 days past signed values and owners can reset it.
6. **Approximate counts.** Double counting across groups, invisible affiliates and mailboxes. "About", "this node sees", dismissible notices; the contract definition governs.
7. **Notice creep.** Pressure to add "just one" blocking check would break the promise that makes the program trustworthy. `no_licensing_gate` and the identical-behaviour test are merge gates.
8. **Free-tier splitting** (a company taking several Small Team keys). No technical gain; the domain review trigger, one license per licensee with affiliates, and audit. No locks.
9. **Sanctions in exactly the audience served.** Refugee aid and human rights in repressive countries: refusing can harm the people the product is for, issuing can breach rules. No automatic refusal by name, the lawyer's answer on humanitarian exemptions and general licenses before L6, country rules as data (question 30).
10. **Seizure or leak of records of human-rights licensees.** Pseudonymous display names, optional country, sealed application fields, short retention, no names in logs or the audit chain.
11. **Overlap with the base license.** Charities and governments are already covered, which may confuse people and pile up applications nobody needs. The decision tree sends them to "no key needed" first (question 24).
12. **Support load for one operator.** Small Team fully automatic; Organization reviewed in a weekly batch with a checklist card and canned reasons; renewals pre-approved; stated response times (5 working days for questions, 10 for decisions). If load grows past a few hours a week, require a register entry or pause new applications with an honest banner.
13. **Coupling between repositories.** Hallway depends on a crate in noncommercial rowboat; a format change needs both. Version bytes, shared vectors in both CIs, no Baton dependency in the format crate; an open `peleda-license` repository is the alternative (question 33).
14. **The node layer does not exist yet.** `rowboat-licensing` is built against `StateStore` and `GroupState` directly; the per-node admin resource needs a Baton decision (question 28).
15. **Hardware tokens as single points.** Three tokens with distinct keys: token O (Organization issuer), token A (revocation key A), token B (revocation key B, kept elsewhere), each with its own PIN and its own delegation from the roots; one theft plus one PIN breaks one role only.
16. **PQ timing** depends on Baton's ML-DSA choice; until then a quantum-capable forger can mint certificates, with no functional effect.
17. **A stolen revocation key.** It can revoke (until revoked itself) but not revive, and cannot freeze revocation: number jumps are capped, its lists lose to the other key's list naming it, releases pin the accepted keys and reset a list from an unpinned or revoked signer, and its `issued_at` is bounded by its window.
