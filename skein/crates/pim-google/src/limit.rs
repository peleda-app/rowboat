//! A per-user request limiter: a token bucket shared by every session of one provider.

use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

pub(crate) struct Limiter {
    per_second: f64,
    burst: f64,
    state: Mutex<(f64, Instant)>,
}

impl Limiter {
    /// `per_minute` requests on average, bursts of up to `burst`.
    pub(crate) fn new(per_minute: u32, burst: u32) -> Self {
        let per_second = f64::from(per_minute.max(1)) / 60.0;
        let burst = f64::from(burst.max(1));
        Self {
            per_second,
            burst,
            state: Mutex::new((burst, Instant::now())),
        }
    }

    /// Waits until one more request fits and takes it.
    pub(crate) async fn take(&self) {
        loop {
            let wait = {
                let mut state = self.state.lock().unwrap();
                let now = Instant::now();
                let (tokens, at) = &mut *state;
                *tokens = (*tokens + now.duration_since(*at).as_secs_f64() * self.per_second)
                    .min(self.burst);
                *at = now;
                if *tokens >= 1.0 {
                    *tokens -= 1.0;
                    return;
                }
                Duration::from_secs_f64((1.0 - *tokens) / self.per_second)
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
        let limiter = Limiter::new(600, 10);
        let start = Instant::now();
        for _ in 0..30 {
            limiter.take().await;
        }
        assert_eq!(start.elapsed(), Duration::from_secs(2));
    }
}
