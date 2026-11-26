# skein-metrics

Process-wide counters (`global()`), rendered in the Prometheus text format by `Metrics::render`. The set is fixed and its labels take fixed values (`result`, `outcome`, `op`): nothing derived from mail, accounts or tenants becomes a label, so metrics leak no data and their cardinality never grows.

| Metric | Labels |
| --- | --- |
| `skein_sync_runs_total` | `result`: ok, auth, throttled, network, not_owner, other |
| `skein_sync_milliseconds_total` | |
| `skein_events_appended_total`, `skein_messages_added_total`, `skein_events_replayed_total` | |
| `skein_commands_total` | `outcome`: applied, failed, uncertain |
| `skein_snapshots_total`, `skein_events_compacted_total` | |
| `skein_storage_requests_total` (from the binary) | `op`: get, put, list, delete |
| `skein_storage_bytes_written_total` (from the binary) | |

`Metrics::samples` returns every counter as `(name, help, labels, value)` in a fixed order; `render` and the OTLP export in `skein-telemetry` both read it, so the two never disagree. Over OTLP each name is a monotonic cumulative counter named by `otel_name`: `_total` dropped and `_` turned into `.` (`skein_sync_runs_total` becomes `skein.sync.runs`, `skein_storage_bytes_written_total` becomes `skein.storage.bytes.written`), with the same labels as attributes. A collector that writes OTLP to Prometheus restores the original names.

Average sync time is `rate(skein_sync_milliseconds_total) / rate(skein_sync_runs_total{result="ok"})`.
