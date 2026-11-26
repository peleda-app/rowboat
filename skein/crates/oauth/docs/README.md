# skein-oauth

OAuth 2.0 for Google and Microsoft accounts. Integrators register their own OAuth clients; Skein ships no client ids.

## Public API

| Item | Guarantees |
| --- | --- |
| `Access { mail: None/Imap/Api, mail_write, send, calendar, contacts }` | `scopes(provider)` gives the least set of scopes that covers it, always with a refresh token; Microsoft cannot mix IMAP with calendars or contacts in one token, which is refused |
| `Client::new(provider, id, secret, redirect, &access)` | endpoints for the provider; `with_microsoft_tenant` restricts to one Entra ID tenant (checked id or domain) |
| `Client::authorize(login_hint)` | fresh random `state` and PKCE verifier (S256); Google is asked for offline access with consent |
| `Client::complete(endpoint, &authorization, &redirect)` | checks `state` in constant time before exchanging; nothing is sent for a foreign answer |
| `Client::refresh` | Microsoft refreshes with the same scope; `invalid_grant` → `Revoked`, `temporarily_unavailable`/5xx → transient `Protocol` |
| `read_redirect(pasted)` | code and state from an address or query; provider errors → `Denied` |
| `Grant` | refresh token, access token, expiry, scope; `Debug` shows no token; `Grant::external` for tokens an integrator hands in |
| `TokenManager` | grants sealed by the keyring under the account's scope at control path `credentials/{account}/oauth` (grants sealed under the tenant scope by an earlier version are read and sealed again under the account's on first load); `access_token` refreshes when less than the margin (2 min) is left, once per account in a process, stores rotated refresh tokens with compare-and-swap before handing out the access token, and caches access tokens sealed under the account's scope as expiring values in a Baton `Signal` given with `with_signal`, in the tenant's group; call it on the account's owner only |
| `TokenEndpoint` | the contract for posting to a token endpoint; `testing::FakeTokenEndpoint` and `testing::conformance` behind `testing` |
| `OAuthError` | `Redirect`, `Denied`, `Revoked`, `Rejected`, `Connection`, `Protocol`, `NoGrant`, `Storage`, `Random`; messages never hold tokens, codes or secrets |

## Scopes

| Access | Google | Microsoft |
| --- | --- | --- |
| mail over IMAP | `https://mail.google.com/` | `IMAP.AccessAsUser.All` (+ `SMTP.Send`) |
| mail over the API, read | `gmail.readonly` | `Mail.Read` |
| mail over the API, write | `gmail.modify` | `Mail.ReadWrite` |
| send | `gmail.send` | `Mail.Send` |
| calendars | `calendar.readonly` / `calendar` | `Calendars.Read` / `Calendars.ReadWrite` |
| contacts | `contacts.readonly` / `contacts` | `Contacts.Read` / `Contacts.ReadWrite` |

Microsoft scopes always add `offline_access`, and `User.Read` with Graph. Permanently deleting Gmail messages needs the full `https://mail.google.com/` scope; `gmail.modify` can only move them to Trash. Gmail scopes are restricted: a public Google OAuth client needs Google's verification and a CASA assessment, so self-hosted installations use their own client in "testing" or internal mode.
