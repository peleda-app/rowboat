//! Process-wide counters, rendered in the Prometheus text format.
//!
//! A fixed set of counters with fixed label values: nothing derived from mail, accounts or
//! tenants ever becomes a label, so metrics cannot leak data or explode in cardinality.

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};

/// A monotonically increasing counter.
#[derive(Debug, Default)]
pub struct Counter(AtomicU64);

impl Counter {
    /// A counter at zero.
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    /// Adds `n`.
    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    /// Adds one.
    pub fn inc(&self) {
        self.add(1);
    }

    /// The current value.
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Why a sync run failed, as a fixed label.
#[derive(Debug, Clone, Copy)]
pub enum SyncFailure {
    /// The provider refused the credentials.
    Auth,
    /// The provider throttled.
    Throttled,
    /// Network or timeout.
    Network,
    /// Another node owns the account.
    NotOwner,
    /// Anything else.
    Other,
}

/// A counter kept outside this crate: name, help text, labels and value.
pub type Extra<'a> = (&'a str, &'a str, &'a [(&'a str, &'a str)], u64);

/// Every counter Skein keeps.
#[derive(Debug, Default)]
pub struct Metrics {
    /// Sync runs that finished.
    pub sync_ok: Counter,
    /// Sync runs that failed on credentials.
    pub sync_auth: Counter,
    /// Sync runs that were throttled.
    pub sync_throttled: Counter,
    /// Sync runs that failed on the network.
    pub sync_network: Counter,
    /// Sync runs stopped because another node owns the account.
    pub sync_not_owner: Counter,
    /// Sync runs that failed otherwise.
    pub sync_other: Counter,
    /// Total time of finished sync runs, in milliseconds.
    pub sync_millis: Counter,
    /// Events appended to journals.
    pub events_appended: Counter,
    /// Messages journaled as added.
    pub messages_added: Counter,
    /// Events dropped as replays after a crash.
    pub events_replayed: Counter,
    /// Commands applied.
    pub commands_applied: Counter,
    /// Commands that failed or conflicted.
    pub commands_failed: Counter,
    /// Commands with an unknown outcome.
    pub commands_uncertain: Counter,
    /// Snapshots stored.
    pub snapshots: Counter,
    /// Events removed by compaction.
    pub events_compacted: Counter,
}

impl Metrics {
    /// Counts a failed sync run.
    pub fn sync_failed(&self, why: SyncFailure) {
        match why {
            SyncFailure::Auth => self.sync_auth.inc(),
            SyncFailure::Throttled => self.sync_throttled.inc(),
            SyncFailure::Network => self.sync_network.inc(),
            SyncFailure::NotOwner => self.sync_not_owner.inc(),
            SyncFailure::Other => self.sync_other.inc(),
        }
    }

    /// Every counter with its current value, in a fixed order: each name appears with the same
    /// help text and label keys every time, and label values are fixed strings.
    pub fn samples(&self) -> Vec<Extra<'static>> {
        let syncs = "Sync runs by result";
        let cmds = "Commands by outcome";
        vec![
            (
                "skein_sync_runs_total",
                syncs,
                &[("result", "ok")],
                self.sync_ok.get(),
            ),
            (
                "skein_sync_runs_total",
                syncs,
                &[("result", "auth")],
                self.sync_auth.get(),
            ),
            (
                "skein_sync_runs_total",
                syncs,
                &[("result", "throttled")],
                self.sync_throttled.get(),
            ),
            (
                "skein_sync_runs_total",
                syncs,
                &[("result", "network")],
                self.sync_network.get(),
            ),
            (
                "skein_sync_runs_total",
                syncs,
                &[("result", "not_owner")],
                self.sync_not_owner.get(),
            ),
            (
                "skein_sync_runs_total",
                syncs,
                &[("result", "other")],
                self.sync_other.get(),
            ),
            (
                "skein_sync_milliseconds_total",
                "Total time of finished sync runs",
                &[],
                self.sync_millis.get(),
            ),
            (
                "skein_events_appended_total",
                "Events appended to journals",
                &[],
                self.events_appended.get(),
            ),
            (
                "skein_messages_added_total",
                "Messages journaled as added",
                &[],
                self.messages_added.get(),
            ),
            (
                "skein_events_replayed_total",
                "Events dropped as replays after a crash",
                &[],
                self.events_replayed.get(),
            ),
            (
                "skein_commands_total",
                cmds,
                &[("outcome", "applied")],
                self.commands_applied.get(),
            ),
            (
                "skein_commands_total",
                cmds,
                &[("outcome", "failed")],
                self.commands_failed.get(),
            ),
            (
                "skein_commands_total",
                cmds,
                &[("outcome", "uncertain")],
                self.commands_uncertain.get(),
            ),
            (
                "skein_snapshots_total",
                "Snapshots stored",
                &[],
                self.snapshots.get(),
            ),
            (
                "skein_events_compacted_total",
                "Events removed by compaction",
                &[],
                self.events_compacted.get(),
            ),
        ]
    }

    /// Renders every counter in the Prometheus text format, followed by `extra` lines (for
    /// example storage request counts the binary keeps).
    pub fn render(&self, extra: &[Extra<'_>]) -> String {
        let mut out = String::new();
        for (name, help, labels, value) in self.samples().iter().chain(extra) {
            if !out.contains(&format!("# TYPE {name} ")) {
                let _ = writeln!(out, "# HELP {name} {help}");
                let _ = writeln!(out, "# TYPE {name} counter");
            }
            if labels.is_empty() {
                let _ = writeln!(out, "{name} {value}");
            } else {
                let joined: Vec<String> =
                    labels.iter().map(|(k, v)| format!("{k}=\"{v}\"")).collect();
                let _ = writeln!(out, "{name}{{{}}} {value}", joined.join(","));
            }
        }
        out
    }
}

/// The OpenTelemetry name of a Prometheus counter name: the `_total` suffix dropped and every
/// `_` turned into `.`, so `skein_sync_runs_total` becomes `skein.sync.runs`. A collector that
/// writes OTLP counters to Prometheus turns the name back into the original one.
pub fn otel_name(prometheus: &str) -> String {
    prometheus
        .strip_suffix("_total")
        .unwrap_or(prometheus)
        .replace('_', ".")
}

/// The process's counters.
pub fn global() -> &'static Metrics {
    static METRICS: std::sync::OnceLock<Metrics> = std::sync::OnceLock::new();
    METRICS.get_or_init(Metrics::default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_prometheus_text_with_fixed_labels() {
        let m = Metrics::default();
        m.sync_ok.add(3);
        m.sync_failed(SyncFailure::Auth);
        m.events_appended.add(42);
        let text = m.render(&[(
            "skein_storage_requests_total",
            "Storage requests",
            &[("op", "put")],
            7,
        )]);
        assert!(text.contains("# TYPE skein_sync_runs_total counter"));
        assert!(text.contains("skein_sync_runs_total{result=\"ok\"} 3"));
        assert!(text.contains("skein_sync_runs_total{result=\"auth\"} 1"));
        assert!(text.contains("skein_events_appended_total 42"));
        assert!(text.contains("skein_storage_requests_total{op=\"put\"} 7"));
        assert_eq!(
            text.matches("# TYPE skein_sync_runs_total").count(),
            1,
            "one header per metric"
        );
        assert!(global().sync_ok.get() == global().sync_ok.get());
    }

    #[test]
    fn maps_names_to_opentelemetry() {
        assert_eq!(otel_name("skein_sync_runs_total"), "skein.sync.runs");
        assert_eq!(
            otel_name("skein_storage_bytes_written_total"),
            "skein.storage.bytes.written"
        );
        assert_eq!(otel_name("skein_x"), "skein.x");
    }
}
