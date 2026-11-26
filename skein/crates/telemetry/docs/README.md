# skein-telemetry

`init(&TelemetryConfig)` installs the `tracing` subscriber: text or JSON lines on stderr with `RUST_LOG`-style filters, and with the `otel` feature an OTLP gRPC exporter for spans and, on request, metrics. Without an endpoint nothing is exported; asking for one in a build without `otel` is an error rather than a silent no-op. `valid_traceparent` checks W3C `traceparent` values before they are carried into commands and events.

## Metrics export

`TelemetryConfig::otlp_metrics` (`OtlpMetrics { interval, source }`) also exports counters over OTLP gRPC to the same endpoint. `source` is a `MetricSource` returning samples in the shape of `skein_metrics::Metrics::samples`; every name becomes a monotonic cumulative `u64` counter named by `skein_metrics::otel_name`, its labels the attributes, its help the description. A periodic reader collects every `interval` (at least `MIN_METRICS_INTERVAL`, 10 s). Asking for metrics without an endpoint, or with a shorter interval, is an error; the names and labels come only from the source, so nothing outside its fixed set is exported.

`TelemetryGuard::shutdown` (or dropping the guard) exports the counters a last time, flushes pending spans and stops both providers. It blocks until the collector answers or times out, so async code calls it through `spawn_blocking`.

The bridge test needs the feature: `cargo test -p skein-telemetry --features otel`, which `mise run check` runs.
