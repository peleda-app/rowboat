---
title: App-only access
description: Microsoft app-only tokens with admin consent, Google service accounts, and handing tokens to Skein.
sidebar:
  order: 4
---

An account is credentials plus whose data they reach, not one user per token. Besides a user's own sign-in, an integrator can reach mailboxes with organization-wide credentials:

- a **Microsoft app-only token** with tenant admin consent (`/users/{id}`, shared mailboxes, rooms);
- a **Google service account** with domain-wide delegation.

## How Skein takes such tokens

The node takes tokens it is handed and refreshes them; it runs no sign-in flow. App-only tokens are obtained by the integrator (Microsoft client credentials flow, or a signed service-account assertion at Google) and handed in per account:

```bash
printf '%s\n' "$ACCESS_TOKEN" | skein account grant --tenant acme room-1 --expires-at 1732150800000
```

Without a refresh token, Skein cannot renew the token itself: hand in a fresh one before it expires, or the account turns `reauth_required`.

## Pointing providers at another user

| Provider | Setting |
| --- | --- |
| Gmail mail | `user`: the address to act as, with domain-wide delegation |
| Graph calendars and contacts (`pim`) | `user`: a user id or user principal name, read as `/users/{id}` |
| Graph sending (`send`) | `user`: a user id or UPN, sending through `/users/{id}/sendMail` |

The Graph mail provider reads the token's own mailbox (`/me`). For calendars and contacts with app-only Graph tokens, the account addresses also need `User.Read.All`.

## Microsoft: application permissions

In the app registration, add **application** permissions (not delegated) such as `Mail.Read`, `Mail.Send`, `Calendars.ReadWrite`, `Contacts.Read`, `User.Read.All`, then **Grant admin consent**. Exchange Online application access policies can limit which mailboxes the app reaches.

## Google: domain-wide delegation

In the Google Workspace admin console, under **Security → API controls → Domain-wide delegation**, add the service account's client id with the scopes it needs. The integrator signs a token request for each user it impersonates.

Background: [accounts and authorization in the plan](https://github.com/peleda-app/rowboat/blob/main/skein/docs/PLAN.md#accounts-and-authorization).
