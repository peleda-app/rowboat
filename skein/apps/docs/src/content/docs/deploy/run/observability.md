---
title: Metrics and OpenTelemetry
description: Prometheus counters, OTLP traces and metrics, and structured logs.
sidebar:
  order: 5
---

## Prometheus

`[metrics] listen = "127.0.0.1:9464"` serves `/metrics` in the Prometheus text format, without authentication: keep it on an internal address.

| Metric | Labels |
| --- | --- |
| `skein_sync_runs_total` | `result`: ok, auth, throttled, network, not_owner, other |
| `skein_sync_milliseconds_total` | |
| `skein_events_appended_total`, `skein_messages_added_total`, `skein_events_replayed_total` | |
| `skein_commands_total` | `outcome`: applied, failed, uncertain |
| `skein_snapshots_total`, `skein_events_compacted_total` | |
| `skein_storage_requests_total` | `op`: get, put, list, delete |
| `skein_storage_bytes_written_total` | |

The set is fixed and labels take fixed values: nothing derived from mail, accounts or tenants becomes a label, so metrics leak no data and their cardinality never grows. Average sync time is `rate(skein_sync_milliseconds_total) / rate(skein_sync_runs_total{result="ok"})`.

## OpenTelemetry

In a build with the `otel` feature:

```toml
[telemetry]
otlp_endpoint = "http://otel-collector:4317"
otlp_metrics = true
otlp_metrics_interval_secs = 60
```

- **Traces:** spans per account sync run, provider request, batch and command, exported over OTLP gRPC. A command carries a W3C `traceparent` (its `trace` field, set by whoever queued it), and the events it causes carry it too, so one trace runs from the consumer's request through Skein and the provider back to the consumer that reads the result.
- **Metrics:** the same counters as Prometheus, as monotonic counters named `skein.sync.runs`, `skein.storage.bytes.written` and so on. On shutdown they are exported once more.
- **Logs:** `tracing` events on stderr, as text or JSON lines (`json = true`), filtered with `filter`.

Span attributes and logs follow one rule: ids, counts and timings only, never content, subjects, addresses or secrets.

## Health

`GET /v1/health` on the inbound listener answers `ok`. It says the process serves requests, nothing about accounts.

## Account health

`skein account list` and `skein account show` print `health` next to each record:

```json
{
  "record": { "account": "box", "provider": "imap", "…": "…" },
  "health": {
    "head": 812,
    "state": "degraded",
    "mail": { "outcome": "network", "last_ok_at": 1763700000000, "last_error_at": 1763703600000, "error": "network", "resync_required": false, "updated_at": 1763703600000 },
    "send": { "outcome": "ok", "last_ok_at": 1763703000000, "resync_required": false, "updated_at": 1763703000000 }
  }
}
```

- `head` is the journal head when the command ran.
- `state` is the worst over the domains present: `healthy`, `throttled`, `degraded`, `reauth_required`. It is absent until the engine first tried the account.
- `mail`, `pim` (calendars and contacts) and `send` each appear once tried. `outcome` is `ok` or an error kind: `auth_failed` (gives `reauth_required`), `throttled`, or `config`, `network`, `protocol`, `storage`, `other` (all `degraded`). `error` is the latest failure's kind and stays after recovery. `resync_required` is true while a cursor reset has not been followed by a successful run.
- Only kinds and times are returned, never provider messages or secrets.

The owning node keeps one small status record per account, apart from the journal. A change of outcome is written as soon as the run that saw it ends; an unchanged one is rewritten at most once a minute, so `last_ok_at` and `last_error_at` may lag by up to a minute. When the status record is missing or unreadable, `health` holds only `head`.

Changes of the overall state are also journaled as `account_health_changed`, so consumers and [webhooks](/rowboat/consumers/webhooks/) can react to them.
