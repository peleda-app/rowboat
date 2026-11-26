---
title: Registering a Microsoft client
description: Creating a Microsoft Entra ID app registration for Graph or IMAP, and Graph push.
sidebar:
  order: 3
---

The steps happen in the Microsoft Entra admin center (or the Azure portal) under **App registrations**. Names below are examples.

## 1. Register the app

Create a new registration:

- **Supported account types:** work and school accounts only (`organizations`), personal accounts too (`common`), or your tenant only. Set `microsoft_tenant` in the config to match.
- **Redirect URI:** the address of the program that runs the sign-in and hands the tokens to the node with `skein account grant` (the node itself has no callback).

## 2. Add a secret

In **Certificates & secrets**, create a client secret and put it in the environment variable named by `client_secret_env`. Note when it expires.

## 3. API permissions

Add **delegated** Microsoft Graph permissions for the access you configure:

| Access | Permissions |
| --- | --- |
| mail over Graph | `Mail.Read` or `Mail.ReadWrite`, `User.Read` |
| sending over Graph | `Mail.Send` |
| calendars, contacts | `Calendars.Read` / `Calendars.ReadWrite`, `Contacts.Read` / `Contacts.ReadWrite` |
| mail over IMAP | `IMAP.AccessAsUser.All`, `SMTP.Send` |
| always | `offline_access` |

IMAP cannot be combined with calendars or contacts in one token, so use `mail = "api"` when an account also syncs calendars or contacts.

```toml
[[oauth.clients]]
name = "microsoft"
provider = "microsoft"
client_id = "00000000-0000-0000-0000-000000000000"
client_secret_env = "SKEIN_MICROSOFT_CLIENT_SECRET"
microsoft_tenant = "organizations"
access = { mail = "api", mail_write = true, send = true, calendar = "write", contacts = "read" }
```

Microsoft rotates refresh tokens; Skein stores the rotated token back before handing out the access token, and refreshes on the account's owner only.

## Graph push

Nothing to configure at Microsoft. Serve `https://skein.example.com/v1/push/graph` over HTTPS with a certificate from a public CA (Graph refuses plain HTTP and self-signed certificates) and set `server.public_url` and `server.push.enabled = true`. When a subscription is made, Graph first calls the address with a `validationToken` and expects it back within 10 seconds, so the API must already be serving.
