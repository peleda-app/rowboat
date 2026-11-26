# skein-push

Push from outside. Gmail (through Cloud Pub/Sub) and Microsoft Graph (through change notifications) call Skein's public endpoint instead of Skein holding a connection. This crate routes those notifications to accounts, turns them into hints, and keeps each account's subscription alive. It never calls a provider while handling a notification, so a flood of posts cannot become a flood of provider requests. Only `Renewer` talks to providers, and it runs from the account's worker.

Notifications are hints. Each one only says that something may have changed, and the change is always read through `MailSession::changes`. If a notification is lost or late, the sync waits until the next notification or poll; no change is lost.

## Public API

- `PushRegistry::new(objects, control)` takes the root object store (as `TenantRegistry` does) and the control store.
  - `register(sub, tenant, account, client_state)` routes `sub` to the account. For Graph only the BLAKE3 hash of `client_state` is stored. Registering again overwrites. Kinds other than Gmail and Graph are `Unsupported`.
  - `lookup_graph(subscription_id, client_state)` returns `Some((tenant, account))` only when the id is registered and the client state hashes to the stored hash. The hashes are compared in constant time. An unknown id, a wrong state and an id that cannot be a key all give `None`.
  - `lookup_gmail(email)` looks up by address, ignoring case and surrounding spaces.
  - `remove(sub, tenant, account)` deletes the entry only if it still points at this account. Removing a missing entry succeeds.
  - `state(tenant, account)` returns the account's `PushState`. `due_for_renewal(tenant, account, now)` is true when the account has no record or its renewal time has come.
  - `forget(tenant, account)` drops the entry and the record without asking the provider. Use it for a deleted account or one whose credentials are gone; the provider's subscription runs out on its own.
  - `accept_graph(body, signal)` and `accept_gmail(body, signal)` (any Baton `Signal`) turn a provider post into hints and return `Accepted { received, hinted }`. They return `Invalid` only when the body does not parse.
- `Renewer::new(registry)`:
  - `ensure(provider, tenant, account, target, now) -> Ensured` subscribes when the account has none. It renews through `MailProvider::renew` once less than a third of the lifetime is left, or when a lifecycle notification asked for it. It unsubscribes and subscribes again when the target's address or topic changed. The result is one of `Unsupported` (nothing stored), `Subscribed`, `Renewed` or `Current`. If it fails, the previous subscription and record stay as they were.
  - `next_check(tenant, account)` gives the time of the next renewal, or `None` when there is no subscription.
  - `stop(provider, tenant, account)` unsubscribes (best effort) and forgets the account.
- `hint_topic(account)` is `push/{account}`, the signal topic (in the tenant's group, see `skein_core::coordination`) that receives `{"provider":"graph"}` or `{"provider":"gmail"}`.
- `random_client_state()` gives 32 random bytes as base64url (43 characters).
- `graph_url(public_url)` gives `{public_url}/v1/push/graph`.
- `parse_graph`, `parse_gmail` and `validation_token` are the parsers. `MAX_GRAPH_ITEMS` is 1000 and `MAX_VALIDATION_TOKEN` is 1024.
- Re-exported from `skein-mail`: `PushTarget`, `Subscription`, `PUSH_GMAIL`, `PUSH_GRAPH`.
- `PushError` has the variants `Storage`, `Mail`, `Signal`, `Unsupported`, `Invalid` and `Random`.

`target.client_state` is used only when a subscription is made. Renewals keep the state Graph already holds, so a fresh `random_client_state()` on every call is fine.

## Storage

| Key | Value |
| --- | --- |
| `system/push/graph/{subscription_id}` | tenant, account, BLAKE3 of `clientState`, expiry |
| `system/push/gmail/{blake3(lowercased address)}` | tenant, account, expiry |
| `tenants/{t}/control/push/{account}` | `PushState`: the subscription, `renewed_at`, a hash of the target's address and topic, `renew_now` |

Registry entries sit at the object store root because notifications name no tenant. Neither the address nor the client state is ever stored there in clear. If two accounts register the same Gmail address, the one registered last receives the notifications. Only the account's owner writes these records.

## Renewal timing

The renewal time is `renewed_at + 2/3 × (expires_at − renewed_at)`.

- Graph message subscriptions last 4200 minutes (Graph allows at most 4230), so they are renewed after about 1.9 days with `PATCH /subscriptions/{id}`. If Graph no longer knows the subscription (it expired or was removed), it is replaced by a new one, which gets a new id and a new registry entry.
- Gmail watches last about seven days and are renewed after about 4.7 days by calling `users.watch` again.

A lifecycle notification `reauthorizationRequired` or `subscriptionRemoved` sets `renew_now`, so the next `ensure` renews at once. `missed` only hints, since the sync it triggers catches up anyway.

## Handling notifications

- **Graph:** the body is `{"value": [...]}`. At most 1000 items are read. Items whose subscription id and `clientState` match an entry wake their accounts, at most one hint per account per post. Lookups run 16 at a time. Unknown ids and wrong states are dropped silently. A storage error on one item is logged and that item is skipped.
- **Gmail:** the body is a Pub/Sub envelope whose `message.data` is base64 (standard or URL-safe) of `{"emailAddress", "historyId"}`. A registered address wakes its account; an unknown address is dropped.

Logs carry counts only, never addresses, client states or tokens.

## Operator setup

Both providers need the server reachable at a public `https` address, set as `public_url`.

### Microsoft Graph

1. Serve `{public_url}/v1/push/graph` over HTTPS with a certificate from a public CA. Graph refuses plain HTTP and self-signed certificates.
2. Nothing to configure at Microsoft. When a subscription is made, Graph first calls `{public_url}/v1/push/graph?validationToken=...` and expects the token back within 10 seconds. The server answers this without a key, so the router must already be serving when the renewer runs.
3. Accounts need `Mail.Read`. Subscriptions use the account's own token.

### Gmail

1. In the Google Cloud project of the OAuth client, create a Pub/Sub topic, for example `projects/acme-mail/topics/skein-push`.
2. Grant `gmail-api-push@system.gserviceaccount.com` the role **Pub/Sub Publisher** on that topic. Without it, `users.watch` fails and the provider reports `Config`.
3. Pick a long random secret (`skein push-token` prints one). Create a **push** subscription on the topic with endpoint `{public_url}/v1/push/gmail/{secret}`.
4. Put the secret into the variable named by `[server.push] gmail_token_env` (the server keeps only `hash_token(secret)`) and set `gmail_topic` for the renewer.
5. Optional: let the push subscription attach an OIDC token and set `gmail_oidc_audience` and `gmail_oidc_email`; the server then also verifies the token against Google's key set (see [skein-server](../../server/docs/README.md)).

## Integration (engine and binary)

1. In the binary, build `let push = PushRegistry::new(objects.clone(), storage.control.clone())`. Serve `skein_server::router(signal, Some(push.clone()), &config)`, with `ServerConfig::gmail_push_token_hash` set from the secret in the environment.
2. Give the engine a `Renewer::new(push)`, the public URL and an optional Gmail topic. In each account worker:
   - also subscribe to `hint_topic(&account)` (next to `commands/{account}`) and treat a message like a command hint: run the account again;
   - after each successful run, when `registry.due_for_renewal(tenant, account, Timestamp::now())` is true, call `renewer.ensure(&*provider, tenant, account, &target, Timestamp::now())` with `target = PushTarget { url: graph_url(public_url) for Graph or the Gmail endpoint, client_state: random_client_state()?, gmail_topic }`. Log failures with ids only; never fail the run because of them;
   - keep polling on the interval as before. Push only shortens the wait; it is not a reason to stop polling. With push active, the interval may be raised (for example to 15 minutes).
3. When an account is paused or deleted, call `renewer.stop(provider, ...)` if the provider can still be built, otherwise `registry.forget(...)`.
4. Without a public URL, do not call `ensure`; accounts poll as before.
