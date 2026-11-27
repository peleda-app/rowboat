# Plan

rowboat is Peleda's node: one repository with three layers that together make a working mail, calendar and contacts node, and the headless server that runs it. The same code runs inside the desktop and mobile apps (`../app`) and on Peleda's servers. It continues the plan of Smereka, which merged here on 2026-11-25 together with Skein and Baton.

## Layers

| Layer | Packages | Job |
| --- | --- | --- |
| `baton/` | `baton-*`, `batond` | coordination: groups, capabilities, keys, leases with priority and fencing, commands, signals, peer fetch, transports; generic, knows nothing about mail ([baton/docs/PLAN.md](../baton/docs/PLAN.md)) |
| `skein/` | `skein-*` | the mail engine: providers, the journal and its storage, commands, keyring, push receivers, `skein-view` ([skein/docs/PLAN.md](../skein/docs/PLAN.md)) |
| `crates/`, `apps/` | `rowboat-*` | the node: composes Baton, Skein, Pellet, `rinse`, bento and the alias providers; the headless multi-tenant server (this plan) |

`baton/` and `skein/` are members of one Cargo workspace with one `Cargo.lock` at the root, on one version of `hmac` and `sha2` and on `aws-lc-rs` as the only rustls crypto provider (Baton needs it for the post-quantum `X25519MLKEM768` group); see `docs/DECISIONS.md`. The map of all repositories is kept in the workspace's `reorg-plan.md` and dojo's `registry.toml`.

## No web interface, no HTTP management API

Decided by the maintainer on 2026-11-25: the web portal (`skein/apps/portal`, the `portal` feature, `rust-embed`, the Docker stage, bun in the checks), the HTTP management API of `skein-server` (tenants, keys, accounts, OAuth, journal reads, blobs, commands, webhooks, SSE), `openapi.json`, the TypeScript client `@peleda-app/skein-client`, and the HTTP server and HTTP follower of `skein-view` go away. The node is managed only through Baton commands from the app. What stays is a minimal inbound endpoint: the Gmail Pub/Sub and Microsoft Graph change notification receivers (`skein-push`, with their authenticity checks: the Gmail token and OIDC verification, the Graph client state) and a health check. Done the same day: the portal, `openapi.json`, the client and the management routes are deleted; `skein-server` serves only `GET /v1/health` and the push routes (now with a rate limit per receiver); the `skein` binary is managed through subcommands (`tenant`, `account`, `journal`, `webhook`) that write through the same stores until the node takes Baton commands; `skein-view` is a library that follows a journal straight from storage with hash-chain verification, for the app to embed.

## One node in every shell

There is no separate standalone or connected mode. Every installation of the app, and every server, is a node in the person's group (Baton's roster). For each account exactly one node owns the work at a time (a Baton lease): it fetches, sends, writes the journal, classifies and decides what to notify. Priority follows the node class: **server, then desktop, then phone**.

| What the person has | Who owns the accounts | How the phone gets mail |
| --- | --- | --- |
| a Peleda server (ours, or their own) | the server, around the clock | journal and commands over the link, push for new mail |
| no server, desktop running | the desktop | over the link straight to the desktop (iroh, direct or through a relay) |
| no server, desktop asleep | the phone itself, while the app is open or the OS gives it background time | from the providers directly |
| one device only | that device | a group of one node |

A stronger node that comes back takes the lease over cooperatively and continues from the same journal position, so nothing is fetched twice. Ownership changes never depend on clocks (Baton's fencing tokens).

## What the first version does

1. **Mail, calendars and contacts** through Skein's providers (IMAP, JMAP, Gmail, Graph, CalDAV, CardDAV), synchronized between the person's devices over Baton. No teams or shared mailboxes yet.
2. **Classification and notifications** on the owner node: Pellet's spam verdict, bento's categories, extracted codes and decision whether to notify (bento absorbed `peleda-insight` on 2026-11-26), plus the person's own rules (never notify for a sender, a category, an alias, a mailbox).
3. **Push** from whichever node owns the account: sealed payloads through APNs, FCM or UnifiedPush. A server sends them itself; a desktop sends them through Peleda's push gateway (the APNs and FCM keys cannot ship inside an app). The gateway sees a device token and ciphertext only.
4. **Email aliases** from external services: SimpleLogin, addy.io, Firefox Relay, DuckDuckGo Email Protection. Create, list, enable, disable and delete aliases from the app; mark incoming mail with the alias it came through; reply from the alias where the service supports it; notification rules per alias.
5. **Optional S3 backup** (see "Storage").
6. **Original view and Rinse** are the app's and `rinse`'s; the node routes the requests: the owner node fetches remote content for the device and hands attachments to Rinse.
7. **Hosted servers on Peleda's machines**: one multi-tenant `rowboat` process per host serving many groups, each as the server node of that group.

Not in the first version: teams and shared resources, the blind node, the own mail server for the person's domains (later), disposable inboxes (see "Wishlist"), one VM per customer (`../hallway`).

## Storage

The journal (events, previews, cursors) is small and lives with every node: the owner writes it, the others replicate it.

- **Without S3.** Message bodies and attachments (blobs) are kept by the owner node as a cache with a size and age limit; devices keep what they opened. A blob nobody has is fetched again from the provider through Skein's `refetch` command to the owner. The price, stated plainly in the product: a message deleted on the provider is gone once its cached copy expires.
- **With S3** (the person's own bucket, or one Peleda provides). The owner writes blobs and journal segments to it through `skein-storage-s3`, kept as long as the person wants. Devices read from it as an untrusted tier through `skein-storage-tiered` (every byte checked against its hash), so the bucket also serves as a meeting point when no node is online. Credentials are sealed to the group and never reach the UI.

## Hosted server and what it sees

A Peleda server that owns an account sees plaintext while it works: it holds the credentials, classifies and builds notifications with sender and subject. The link guarantees that nobody between the server and the devices does (`../app/docs/LINK.md`); at rest the server seals blobs and credentials with the group key. A person who does not want that runs without a server (desktop and phone only) or, later, with a blind node.

## Peleda's own infrastructure

Even without a hosted server, three small blind services run on Peleda's machines:

| Service | Does | Sees |
| --- | --- | --- |
| push gateway (`apps/push-gateway`) | forwards sealed payloads from desktops and servers to APNs, FCM and UnifiedPush | device tokens, sizes, timing |
| iroh relay | forwards encrypted QUIC packets when a direct connection fails | node ids, sizes, timing |
| Rinse (`../rinse`) | washes attachments in disposable microVMs | the attachments sent to it, by design |

Baton's `batond` (group logs, lease arbiter, drop mailbox) can run next to them for groups without a server.

## Layout of the node layer (planned)

```
crates/
  node/              the composition library: builder over profile (server, desktop, phone),
                     storage, keystore and providers; runs the account workers under leases
  sync/              Skein meets Baton: journal replication, commands to the leaseholder,
                     blob fetch from peers then S3 then refetch
  push/              the sealed push payload format (moves here from ../app/crates/push)
  push-send/         contract: deliver a sealed payload to a device
  push-send-apns/, push-send-fcm/, push-send-unifiedpush/, push-send-gateway/
  aliases/           contract: alias services
  aliases-simplelogin/, aliases-addy/, aliases-firefox/, aliases-duck/
  rules/             the person's notification rules (pure)
  license/           license certificate format and offline verifier (pure; LICENSING.md)
  licensing/         installed certificates, user counting, status, the license commands
apps/
  rowboat/           the headless multi-tenant server binary and container image
  push-gateway/      the blind push gateway
docs/
```

Contracts, crates, errors, tests and docs follow [RULES.md](RULES.md). The app links `rowboat-node` and picks the desktop or phone profile, its platform keystore and its content sandbox.

## Phases

0. **Foundation.** (Stage 4 of the reorganization formed the repository; the node layer starts here.) Workspace, CI, the contracts above with memory implementations and conformance suites; `push` moved from `../app`. The contracts phase 1 needs (`rowboat-api`, `rowboat-keystore`, `rowboat-discover`, `rowboat-spam`, `rowboat-category`) are specified in [NODE.md](NODE.md) and built with their memory or table implementations and conformance suites (2026-11-26); moving `push` from `../app` is still open.
1. **Node on one device.** `rowboat-node` with Skein's engine, local storage, the content worker, Pellet, bento and insight; the app's desktop shell switches to it. Implementation spec: [NODE.md](NODE.md) (IMAP and SMTP accounts by password or app password, spam and categories minimal; the app side is `../app/docs/DESKTOP.md`). Built 2026-11-26 except discovery probes, lazy re-parsing, the integration and live suites; the app's switch to it is next.
2. **Group and handover.** Pairing, journal replication, commands, peer fetch, priority leases and cooperative handover between desktop and phone; the phone talking to the desktop over iroh; the `activity` signal (ids only, short time-to-live, sealed to the group) that lets the app continue reading or writing on another device (`../app/docs/PLAN.md`, "Continue on another device"), and drafts saved through the owner node every few seconds while typing; losing a device (`../app/docs/PLAN.md`, "Lost or stolen device"): revocation with key rotation, a signed `wipe` command class checked against the roster, OAuth refresh-token revocation for every account the revoked device owned, the revocation seen by the device on any contact with the group, and periodic membership confirmation with a self-lock after a configurable silence. Implementation spec for phases 2 and 3: [GROUP.md](GROUP.md). Built so far: pairing, replication and commands (wave 1); leases across nodes with the server as arbiter, cooperative handover and takeover with the account's state, and revocation notices (wave 2, part 1).
3. **Server.** `apps/rowboat` multi-tenant, sealed credentials and blobs, S3 optional, refetch for expired blobs. Specified in [GROUP.md](GROUP.md) ("The headless server"). Built so far (wave 2, part 2): the binary with its CLI, tenants bound to their group, keys apart from the sealed data, optional S3, the push receivers and health check, hand-back on shutdown, the container image; not yet: admin through `node-settings` commands, `rowboat license`, the blob cache.
4. **Push.** The senders, the gateway, deduplication across handovers, the person's rules, and the sealed wipe push as the fastest (never the only) way a revoked device learns of its revocation.
5. **Aliases.** The four services, alias recognition on incoming mail, replies from aliases, rules per alias.
6. **Calendars and contacts** through Skein's PIM providers on the same leases.
7. **Original view and Rinse** routing.

## License keys

rowboat stays public under PolyForm Noncommercial; Peleda also grants a free Small Team License, a free Organization License and a paid Commercial License, each as a signed certificate the node checks offline and that never blocks anything (decided 2026-11-26). The program, the certificate format, the keys, the verifier, the tests and the phases L0 to L9 are in [LICENSING.md](LICENSING.md); the issuer is in hallway, the pages in tinginys, the license screen in the app. Where the license phases fall among rowboat's:

| rowboat phase | License work in rowboat |
| --- | --- |
| now, beside phase 0 | L0 decisions; **L1** `crates/license` (`rowboat-license`): format, verifier, test anchors, shared vectors, fuzz targets. Pure and independent of the node, so it can start before the node layer exists |
| beside phase 0 or 1 | **L2** production anchors from the key ceremony committed to `crates/license/anchors/`, the first signed revocation list in `crates/license/data/`, the release-binary scan for test keys |
| 1 (node on one device) | **L5a** `crates/licensing` (`rowboat-licensing`) built and tested against `StateStore` and `GroupState`; holder binding; wired into `rowboat-node` with the `license-*` Baton commands once the node and its admin resource exist; the standalone `rowboat license verify`; the app's license screen |
| 3 (server) | **L5b** the `rowboat license` subcommands in `apps/rowboat`, the operator rule on the server profile, counting across the groups a multi-tenant server serves, the `ServiceWithoutLicense` notice |
| every release from L2 on | **L8** CI embeds the latest signed revocation list and checks that its number never goes down |
| with Baton's PQ work and external audit | **L9** hybrid anchors and review |

Hallway's L3, L4, L6 and L7 (issuer, Small Team, Organization, Commercial) run on their own schedule; the first public key needs L1 to L4, L5a and the go-live gate in LICENSING.md; L5b follows with the server and is not needed for it.

## Wishlist

- **Disposable inboxes** (mail.tm and similar): a short-lived mailbox as a Skein provider reading through the service's API, removed with its messages when it expires.
- Teams and shared mailboxes on Baton's shared resources.
- The blind node.
- The own mail server.

## Open questions

See [QUESTIONS.md](QUESTIONS.md).
