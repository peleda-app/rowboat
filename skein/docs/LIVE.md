# Live tests

`tests/integration/tests/live.rs` runs against real provider accounts. It never runs in normal CI:
only the [Live providers](../../.github/workflows/live.yml) workflow (manual or daily) and
`mise run live` locally start it, and every suite skips itself when its secrets are missing.

## Rules

- Use dedicated test accounts, never a personal or production mailbox. The suites append, flag,
  move and delete messages in the mailbox you name.
- Store the values as secrets of the GitHub environment `live` (Settings → Environments → live →
  Environment secrets) and protect the environment so only `main` can use it.
- Tests log ids and counts only; message content, addresses and secrets never reach the job log.
- Each run tags its messages with a unique `Message-ID` on `example.com` and removes them at the end.

## Secrets

| Suite | Secrets | Notes |
| --- | --- | --- |
| IMAP | `SKEIN_LIVE_IMAP_HOST`, `SKEIN_LIVE_IMAP_PORT` (default 993), `SKEIN_LIVE_IMAP_USER`, `SKEIN_LIVE_IMAP_PASSWORD`, `SKEIN_LIVE_IMAP_MAILBOX` (default `INBOX`) | For Gmail: `imap.gmail.com`, the address as user, an app password (needs 2-step verification). For Outlook.com and Microsoft 365, IMAP needs OAuth; use the Graph suite instead. |
| Gmail API | `SKEIN_LIVE_GMAIL_ACCESS_TOKEN` works now; `SKEIN_LIVE_GMAIL_CLIENT_ID`, `SKEIN_LIVE_GMAIL_CLIENT_SECRET`, `SKEIN_LIVE_GMAIL_REFRESH_TOKEN` are reserved until refresh comes with `skein-oauth` | Runs the round trip in `ALL`. The token needs scope `https://mail.google.com/`: the round trip deletes its message for good, which `gmail.modify` does not allow. A Google Cloud OAuth client of type "Desktop", test user = the test account; an access token from the OAuth Playground also works for one hour. |
| Microsoft Graph | `SKEIN_LIVE_GRAPH_ACCESS_TOKEN`, optional `SKEIN_LIVE_GRAPH_MAILBOX` (a folder id; the Inbox by default) and `SKEIN_LIVE_GRAPH_API_URL`; later `SKEIN_LIVE_GRAPH_TENANT`, `SKEIN_LIVE_GRAPH_CLIENT_ID`, `SKEIN_LIVE_GRAPH_CLIENT_SECRET`, `SKEIN_LIVE_GRAPH_REFRESH_TOKEN` | Runs the mail round trip with an access token, which lasts about an hour; signing in with the refresh token comes with `skein-oauth`. Delegated permissions `Mail.ReadWrite`, `Calendars.ReadWrite`, `Contacts.ReadWrite`, `offline_access`. |
| CalDAV/CardDAV | `SKEIN_LIVE_CALDAV_URL`, `SKEIN_LIVE_CALDAV_USER`, `SKEIN_LIVE_CALDAV_PASSWORD` | Reserved until the calendar providers land. |

## Push

The live suites do not cover push. Gmail and Graph push need a public `https` address that the provider can reach, which a CI runner does not have. To try push by hand against a test account:

- **Graph:** expose the server through a public HTTPS address (a tunnel with a public CA certificate), set `public_url`, and let the renewer subscribe. The validation request must reach `/v1/push/graph` within 10 seconds. Logs then show `graph notifications` with counts for each change.
- **Gmail:** create a Pub/Sub topic in the test project and grant `gmail-api-push@system.gserviceaccount.com` publish rights on it. Add a push subscription to `{public_url}/v1/push/gmail/{secret}` and set the secret's hash in the server config.
- Use only test mailboxes, as for the other suites. Never paste the push secret or client states into issues or logs.

## Running locally

```bash
SKEIN_LIVE_IMAP_HOST=imap.gmail.com SKEIN_LIVE_IMAP_USER=test@example.com SKEIN_LIVE_IMAP_PASSWORD=... mise run live
```
