//! Gmail's per-user quota as a token bucket shared by every session of one provider.
//!
//! Costs are the quota units Google publishes for each method ("Usage limits" in the Gmail API
//! reference); the per-user limit is 250 units per second as a moving average.

use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

/// The published per-user limit in quota units per second.
pub const DEFAULT_UNITS_PER_SECOND: u32 = 250;

pub(crate) const PROFILE: u32 = 1;
pub(crate) const LABELS_LIST: u32 = 1;
pub(crate) const LABELS_WRITE: u32 = 5;
pub(crate) const MESSAGES_LIST: u32 = 5;
pub(crate) const MESSAGES_GET: u32 = 5;
pub(crate) const HISTORY_LIST: u32 = 2;
pub(crate) const BATCH_MODIFY: u32 = 50;
pub(crate) const BATCH_DELETE: u32 = 50;
pub(crate) const TRASH: u32 = 5;
pub(crate) const UNTRASH: u32 = 5;
pub(crate) const INSERT: u32 = 25;
pub(crate) const WATCH: u32 = 100;
pub(crate) const STOP: u32 = 50;

pub(crate) struct Quota {
    rate: f64,
    state: Mutex<(f64, Instant)>,
}

impl Quota {
    pub(crate) fn new(units_per_second: u32) -> Self {
        let rate = f64::from(units_per_second.max(1));
        Self {
            rate,
            state: Mutex::new((rate, Instant::now())),
        }
    }

    /// Waits until `units` fit under the limit and takes them. Bursts up to one second's worth.
    pub(crate) async fn take(&self, units: u32) {
        let units = f64::from(units).min(self.rate);
        loop {
            let wait = {
                let mut state = self.state.lock().unwrap();
                let now = Instant::now();
                let (tokens, at) = &mut *state;
                *tokens =
                    (*tokens + now.duration_since(*at).as_secs_f64() * self.rate).min(self.rate);
                *at = now;
                if *tokens >= units {
                    *tokens -= units;
                    return;
                }
                Duration::from_secs_f64((units - *tokens) / self.rate)
            };
            tokio::time::sleep(wait).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn keeps_under_the_rate() {
        let quota = Quota::new(250);
        let start = Instant::now();
        for _ in 0..100 {
            quota.take(MESSAGES_GET).await;
        }
        // 500 units: 250 from the initial burst, 250 more over one second.
        let spent = start.elapsed();
        assert!(spent >= Duration::from_millis(990), "{spent:?}");
        assert!(spent <= Duration::from_millis(1100), "{spent:?}");
    }
}
