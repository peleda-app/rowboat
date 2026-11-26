---
title: OAuth clients and sign-in
description: Registering OAuth clients in Skein, scopes per access, and the sign-in flow.
sidebar:
  order: 1
---

Skein ships no OAuth client ids. Operators register their own clients at Google and Microsoft and name them in the config; accounts then refer to a client by name with `"auth": {"type": "o_auth", "client": "google"}`.

## Configuring a client

```toml
[[oauth.clients]]
name = "google"
provider = "google"
client_id = "1234.apps.googleusercontent.com"
client_secret_env = "SKEIN_GOOGLE_CLIENT_SECRET"
access = { mail = "api", mail_write = true, send = true, calendar = "write", contacts = "read" }

[[oauth.clients]]
name = "microsoft"
provider = "microsoft"
client_id = "00000000-0000-0000-0000-000000000000"
client_secret_env = "SKEIN_MICROSOFT_CLIENT_SECRET"
microsoft_tenant = "organizations"
access = { mail = "api", mail_write = true, calendar = "read", contacts = "read" }
```

- `access.mail`: `none`, `imap` (XOAUTH2 over IMAP and SMTP) or `api` (Gmail API or Graph); `mail_write` and `send` are booleans; `calendar` and `contacts` are `read` or `write`.
- `microsoft_tenant` restricts sign-in to one Entra ID tenant (id or domain), or `organizations`, `consumers`, `common`.
- `redirect_url` is the address registered at the provider for whoever runs the sign-in (in Peleda, the app). The node never runs a sign-in itself, so it may be left out.
- Secrets come only from environment variables named by `*_env`.

## Scopes

Skein asks for the least set of scopes that covers the access, always with a refresh token.

| Access | Google | Microsoft |
| --- | --- | --- |
| mail over IMAP | `https://mail.google.com/` | `IMAP.AccessAsUser.All` (+ `SMTP.Send`) |
| mail over the API, read | `gmail.readonly` | `Mail.Read` |
| mail over the API, write | `gmail.modify` | `Mail.ReadWrite` |
| send | `gmail.send` | `Mail.Send` |
| calendars | `calendar.readonly` / `calendar` | `Calendars.Read` / `Calendars.ReadWrite` |
| contacts | `contacts.readonly` / `contacts` | `Contacts.Read` / `Contacts.ReadWrite` |

Microsoft scopes always add `offline_access`, and `User.Read` with Graph. Microsoft cannot mix IMAP with calendars or contacts in one token, so such a combination is refused: use the API for mail too. Consent can grow later: sign in again with a wider access.

## Signing in

The node runs no sign-in flow and has no callback: the HTTP management API that did was removed. Whoever signs the person in (in Peleda, the app, with PKCE through `skein_oauth::Client`) hands the tokens to the node:

```bash
printf '%s\n%s\n' "$ACCESS_TOKEN" "$REFRESH_TOKEN" | skein account grant --tenant acme box --expires-at 1732150800000
```

The access token is the first line of stdin, the optional refresh token the second. The grant is sealed with the account's key and never shown again. The refresh token must come from the same OAuth client the account's record names, so the node can refresh it.

## Refresh

Access tokens are refreshed on the account's owner only, when less than two minutes are left; Microsoft's rotated refresh tokens are stored back with compare-and-swap. `invalid_grant` turns the account `reauth_required`.

Provider-specific steps: [Google](/rowboat/providers/auth/google/), [Microsoft](/rowboat/providers/auth/microsoft/), [app-only access](/rowboat/providers/auth/app-only/).
