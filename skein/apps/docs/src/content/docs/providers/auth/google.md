---
title: Registering a Google client
description: Creating a Google OAuth client for Gmail, Calendar and People, and Pub/Sub push.
sidebar:
  order: 2
---

The steps happen in the Google Cloud console of a project you control. Names below are examples.

## 1. Enable the APIs

In **APIs & Services → Library**, enable the APIs for the domains you need: Gmail API, Google Calendar API, People API. Enable Cloud Pub/Sub too if you want push for Gmail.

## 2. Configure the consent screen

In **Google Auth Platform** (the OAuth consent screen), set the app name and support address, and add the scopes from the [scope table](/rowboat/providers/auth/oauth-clients/#scopes) you plan to use.

Gmail scopes are restricted: a public client needs Google's verification and a security assessment. Self-hosted installations use their own client in **testing** mode (add the test users) or **internal** mode (Google Workspace, users of your organization only).

## 3. Create the client

In **Clients**, create an OAuth client for the program that runs the sign-in and add its redirect URI; the node has no callback and takes the tokens through `skein account grant`. Copy the client id into the config and the secret into the environment variable named by `client_secret_env`.

```toml
[[oauth.clients]]
name = "google"
provider = "google"
client_id = "1234.apps.googleusercontent.com"
client_secret_env = "SKEIN_GOOGLE_CLIENT_SECRET"
access = { mail = "api", mail_write = true, send = true, calendar = "write", contacts = "write" }
```

Skein asks Google for offline access with consent, so the grant includes a refresh token. Permanently deleting Gmail messages needs the full `https://mail.google.com/` scope; with `gmail.modify` deletes can only move to Trash.

## Push through Pub/Sub

1. Create a Pub/Sub topic in the same project, for example `projects/example-project/topics/skein-gmail`.
2. Grant `gmail-api-push@system.gserviceaccount.com` the role **Pub/Sub Publisher** on that topic. Without it, `users.watch` fails.
3. Pick a long random secret (`skein push-token` prints one) and create a **push** subscription on the topic with the endpoint `https://skein.example.com/v1/push/gmail/{secret}`.
4. Configure the node:

```toml
[server.push]
enabled = true
gmail_topic = "projects/example-project/topics/skein-gmail"
gmail_token_env = "SKEIN_GMAIL_PUSH_TOKEN"   # holds the secret
# Optional: also require Pub/Sub's signed OIDC token
# gmail_oidc_audience = "https://skein.example.com/v1/push/gmail"
# gmail_oidc_email = "push@example-project.iam.gserviceaccount.com"
```

Notifications only wake the account's worker; the change is always read through the history feed, and polling continues on the interval.

## Domain-wide delegation

The Gmail provider takes `user` (an address) for tokens obtained with a Google Workspace service account and domain-wide delegation. Skein does not mint such tokens itself; see [app-only access](/rowboat/providers/auth/app-only/).
