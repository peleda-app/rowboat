//! Logging and tracing setup for Skein binaries.
//!
//! Every module logs through `tracing` with ids, counts and timings only. This crate installs the
//! subscriber: human-readable or JSON lines on stderr, filtered by `RUST_LOG`-style directives,
//! and with the `otel` feature an OTLP exporter that sends spans, and on request the
//! `skein-metrics` counters, to an OpenTelemetry collector. Without an endpoint nothing is
//! exported.

use std::sync::Arc;
use std::time::Duration;

use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// How to log and trace.
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    /// Filter directives such as `info,skein_engine=debug`.
    pub filter: String,
    /// JSON lines instead of human-readable text.
    pub json: bool,
    /// OTLP gRPC endpoint (for example `http://localhost:4317`); spans are exported only when
    /// set and the `otel` feature is on.
    pub otlp_endpoint: Option<String>,
    /// `service.name` reported to the collector.
    pub service_name: String,
    /// Exports counters as OTLP metrics to `otlp_endpoint` as well; needs the endpoint.
    pub otlp_metrics: Option<OtlpMetrics>,
}

/// Returns every counter with its current value, in the shape of
/// [`skein_metrics::Metrics::samples`]. Called on every export, so it must be cheap; every call
/// must yield the same names with the same help text, and label values must be fixed strings.
pub type MetricSource = Arc<dyn Fn() -> Vec<skein_metrics::Extra<'static>> + Send + Sync>;

/// The shortest interval between two metric exports.
pub const MIN_METRICS_INTERVAL: Duration = Duration::from_secs(10);

/// OTLP export of counters.
#[derive(Clone)]
pub struct OtlpMetrics {
    /// Time between exports; at least [`MIN_METRICS_INTERVAL`].
    pub interval: Duration,
    /// Where the counters come from. Every name becomes a monotonic cumulative counter named by
    /// [`skein_metrics::otel_name`], with the labels as attributes.
    pub source: MetricSource,
}

impl std::fmt::Debug for OtlpMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtlpMetrics")
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            filter: "info".into(),
            json: false,
            otlp_endpoint: None,
            service_name: "skein".into(),
            otlp_metrics: None,
        }
    }
}

/// Telemetry could not be set up.
#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    /// The filter directives do not parse.
    #[error("bad log filter: {0}")]
    Filter(String),
    /// An OTLP endpoint was given but this build has no `otel` feature.
    #[error("this build cannot export OpenTelemetry; rebuild with the `otel` feature")]
    NoOtel,
    /// Metrics export was asked for without an OTLP endpoint.
    #[error("OTLP metrics export needs an OTLP endpoint")]
    MetricsWithoutEndpoint,
    /// The metrics interval is shorter than [`MIN_METRICS_INTERVAL`].
    #[error("the OTLP metrics interval must be at least {}s", MIN_METRICS_INTERVAL.as_secs())]
    MetricsInterval,
    /// The exporter or subscriber could not be installed.
    #[error("telemetry setup failed: {0}")]
    Setup(String),
}

/// Keeps exporters running. [`TelemetryGuard::shutdown`] or dropping it flushes pending spans,
/// exports the counters one last time and stops the exporters.
pub struct TelemetryGuard {
    #[cfg(feature = "otel")]
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
    #[cfg(feature = "otel")]
    meters: Option<opentelemetry_sdk::metrics::SdkMeterProvider>,
}

impl TelemetryGuard {
    /// Flushes and stops the exporters. Blocks until the collector answered or its timeout
    /// passed, so call it from a blocking context in async code.
    pub fn shutdown(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        #[cfg(feature = "otel")]
        {
            if let Some(meters) = self.meters.take() {
                let _ = meters.shutdown();
            }
            if let Some(provider) = self.provider.take() {
                let _ = provider.shutdown();
            }
        }
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Installs the global subscriber. Call once at startup and keep the guard alive.
pub fn init(config: &TelemetryConfig) -> Result<TelemetryGuard, TelemetryError> {
    if let Some(metrics) = &config.otlp_metrics {
        if config.otlp_endpoint.is_none() {
            return Err(TelemetryError::MetricsWithoutEndpoint);
        }
        if metrics.interval < MIN_METRICS_INTERVAL {
            return Err(TelemetryError::MetricsInterval);
        }
    }
    let filter =
        EnvFilter::try_new(&config.filter).map_err(|e| TelemetryError::Filter(e.to_string()))?;
    let fmt = if config.json {
        tracing_subscriber::fmt::layer()
            .json()
            .with_writer(std::io::stderr)
            .boxed()
    } else {
        tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .boxed()
    };
    let registry = tracing_subscriber::registry().with(filter).with(fmt);

    #[cfg(feature = "otel")]
    {
        use opentelemetry::trace::TracerProvider as _;
        use opentelemetry_otlp::WithExportConfig;
        if let Some(endpoint) = &config.otlp_endpoint {
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint)
                .build()
                .map_err(|e| TelemetryError::Setup(e.to_string()))?;
            let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
                .with_batch_exporter(exporter)
                .with_resource(provider_resource(&config.service_name))
                .build();
            let meters = match &config.otlp_metrics {
                Some(metrics) => {
                    let exporter = opentelemetry_otlp::MetricExporter::builder()
                        .with_tonic()
                        .with_endpoint(endpoint)
                        .build()
                        .map_err(|e| TelemetryError::Setup(e.to_string()))?;
                    Some(otel::meter_provider(
                        exporter,
                        metrics,
                        provider_resource(&config.service_name),
                    ))
                }
                None => None,
            };
            let tracer = provider.tracer("skein");
            registry
                .with(tracing_opentelemetry::layer().with_tracer(tracer))
                .try_init()
                .map_err(|e| TelemetryError::Setup(e.to_string()))?;
            return Ok(TelemetryGuard {
                provider: Some(provider),
                meters,
            });
        }
        registry
            .try_init()
            .map_err(|e| TelemetryError::Setup(e.to_string()))?;
        Ok(TelemetryGuard {
            provider: None,
            meters: None,
        })
    }

    #[cfg(not(feature = "otel"))]
    {
        if config.otlp_endpoint.is_some() {
            return Err(TelemetryError::NoOtel);
        }
        registry
            .try_init()
            .map_err(|e| TelemetryError::Setup(e.to_string()))?;
        Ok(TelemetryGuard {})
    }
}

use tracing_subscriber::Layer as _;

#[cfg(feature = "otel")]
fn provider_resource(service_name: &str) -> opentelemetry_sdk::Resource {
    opentelemetry_sdk::Resource::builder()
        .with_service_name(service_name.to_owned())
        .build()
}

#[cfg(feature = "otel")]
mod otel {
    use opentelemetry::KeyValue;
    use opentelemetry::metrics::MeterProvider as _;
    use opentelemetry_sdk::metrics::exporter::PushMetricExporter;
    use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};

    use super::{MetricSource, OtlpMetrics};

    pub(crate) fn meter_provider<E: PushMetricExporter>(
        exporter: E,
        metrics: &OtlpMetrics,
        resource: opentelemetry_sdk::Resource,
    ) -> SdkMeterProvider {
        let reader = PeriodicReader::builder(exporter)
            .with_interval(metrics.interval)
            .build();
        let provider = SdkMeterProvider::builder()
            .with_reader(reader)
            .with_resource(resource)
            .build();
        register(&provider, &metrics.source);
        provider
    }

    fn register(provider: &SdkMeterProvider, source: &MetricSource) {
        let meter = provider.meter("skein");
        let mut seen: Vec<&'static str> = Vec::new();
        for (name, help, _, _) in source() {
            if seen.contains(&name) {
                continue;
            }
            seen.push(name);
            let source = source.clone();
            meter
                .u64_observable_counter(skein_metrics::otel_name(name))
                .with_description(help)
                .with_callback(move |observer| {
                    for (n, _, labels, value) in source() {
                        if n == name {
                            let attributes: Vec<KeyValue> =
                                labels.iter().map(|(k, v)| KeyValue::new(*k, *v)).collect();
                            observer.observe(value, &attributes);
                        }
                    }
                })
                .build();
        }
    }

    #[cfg(test)]
    mod tests {
        use std::collections::BTreeMap;
        use std::sync::Arc;
        use std::time::Duration;

        use opentelemetry_sdk::metrics::InMemoryMetricExporter;
        use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};

        use super::*;

        #[test]
        fn exports_every_counter_with_its_labels() {
            let metrics = Arc::new(skein_metrics::Metrics::default());
            metrics.sync_ok.add(3);
            metrics.sync_failed(skein_metrics::SyncFailure::NotOwner);
            metrics.commands_uncertain.add(2);
            metrics.events_appended.add(42);
            let counted = metrics.clone();
            let source: MetricSource = Arc::new(move || {
                let mut all = counted.samples();
                all.push((
                    "skein_storage_requests_total",
                    "Object storage requests",
                    &[("op", "put")],
                    7,
                ));
                all
            });
            let exporter = InMemoryMetricExporter::default();
            let provider = meter_provider(
                exporter.clone(),
                &OtlpMetrics {
                    interval: Duration::from_secs(3600),
                    source: source.clone(),
                },
                opentelemetry_sdk::Resource::builder_empty().build(),
            );
            provider.force_flush().unwrap();

            let mut exported = BTreeMap::new();
            let finished = exporter.get_finished_metrics().unwrap();
            for resource in &finished {
                for scope in resource.scope_metrics() {
                    for metric in scope.metrics() {
                        let AggregatedMetrics::U64(MetricData::Sum(sum)) = metric.data() else {
                            panic!("{} is not a u64 sum", metric.name());
                        };
                        assert!(sum.is_monotonic(), "{}", metric.name());
                        for point in sum.data_points() {
                            let labels: Vec<(String, String)> = point
                                .attributes()
                                .map(|kv| (kv.key.to_string(), kv.value.to_string()))
                                .collect();
                            exported.insert((metric.name().to_owned(), labels), point.value());
                        }
                    }
                }
            }

            let expected: BTreeMap<_, _> = source()
                .into_iter()
                .map(|(name, _, labels, value)| {
                    let labels: Vec<(String, String)> = labels
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect();
                    ((skein_metrics::otel_name(name), labels), value)
                })
                .collect();
            assert_eq!(exported, expected);
            assert_eq!(
                exported[&(
                    "skein.sync.runs".to_owned(),
                    vec![("result".to_owned(), "not_owner".to_owned())]
                )],
                1
            );
            assert_eq!(exported.len(), 16);
            provider.shutdown().unwrap();
        }
    }
}

/// Checks a W3C `traceparent` header value (`00-<32 hex>-<16 hex>-<2 hex>`, ids not all zero), so
/// only well-formed values from outside are carried into events and commands.
pub fn valid_traceparent(value: &str) -> bool {
    let parts: Vec<&str> = value.split('-').collect();
    let hex = |s: &str, n: usize| {
        s.len() == n && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    };
    parts.len() == 4
        && hex(parts[0], 2)
        && parts[0] != "ff"
        && hex(parts[1], 32)
        && parts[1].bytes().any(|b| b != b'0')
        && hex(parts[2], 16)
        && parts[2].bytes().any(|b| b != b'0')
        && hex(parts[3], 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_traceparent() {
        assert!(valid_traceparent(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        ));
        for bad in [
            "",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\nX-Injected: 1",
        ] {
            assert!(!valid_traceparent(bad), "{bad:?}");
        }
    }
}
