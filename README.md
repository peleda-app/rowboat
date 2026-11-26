# rowboat

Peleda's node. It runs mail, calendars and contacts for a person's or a team's devices and servers: one node owns each account at a time, the others follow its journal, and the work moves to a stronger node when one appears. The Peleda app embeds it on desktops and phones; the same code runs as a headless server.

| Layer | What |
| --- | --- |
| [`baton/`](baton/README.md) | coordination between the nodes of a group: membership, capabilities and keys, leases with priority and fencing, commands, signals, transports |
| [`skein/`](skein/README.md) | the mail engine: providers (IMAP, JMAP, Gmail, Microsoft Graph, CalDAV, CardDAV, Google Calendar and People), the append-only journal with the original bytes, write commands, storage |
| `crates/`, `apps/` | the node and the headless server built on both (planned) |

There is no web interface and no HTTP management API: the app manages the node through Baton commands. The only inbound HTTP endpoints receive Gmail and Microsoft Graph change notifications and answer a health check.

Status: early development. See [docs/PLAN.md](docs/PLAN.md); agents start with [AGENTS.md](AGENTS.md).

## License

rowboat is source-available under the [PolyForm Noncommercial License 1.0.0](LICENSE.md). In plain words, and without replacing the license text:

- **You may** use, copy, change and share it for a noncommercial purpose: personal study, research, experiment, testing, a hobby or private entertainment with no commercial application; or in a charity, school, public research organization, public safety or health organization, environmental protection organization or government institution.
- **You may not** use it for a commercial purpose (in a product or service you sell, inside a company's business, or to provide services to paying customers) without one of the additional licenses below (the free Small Team License or the paid Commercial License).
- **Commercial use, and some other uses,** are covered by one of three additional licenses Peleda grants on top of PolyForm Noncommercial, all from <https://peleda.app/license> (the page is not online yet):
  - **Small Team License**: free, for any purpose including commercial, up to 5 users counted together with affiliates; not for providing the node as a service to others. Issued automatically after you confirm an email address and accept the terms.
  - **Organization License**: free for human-rights organizations, press freedom and investigative journalism, legal aid, digital rights and refugee aid. By application, for one year, renewable.
  - **Commercial License**: paid, for companies with more than 5 users and for hosting providers who run rowboat for others.
- **A license key is a signed certificate, not a lock.** Your node checks it offline against keys built into rowboat and shows its status in the app. rowboat never phones home about licenses, sends Peleda no telemetry and never disables or limits anything, with or without a key; noncommercial use needs no key at all. How keys work: [docs/LICENSING.md](docs/LICENSING.md).
- **A work mailbox on your own node**: whether connecting the mailbox your employer gave you to a node you run yourself counts as personal use is an open question for the maintainer ([docs/QUESTIONS.md](docs/QUESTIONS.md)).

Contributions are welcome under the [Contributor License Agreement](CLA.md), which lets the maintainer offer the project under both licenses.
