//! [`LocalSignal`]: signals within one process. A broadcast channel per topic (a subscriber more
//! than [`CAPACITY`] messages behind loses the oldest, which the contract allows), expiring values
//! and counters. Everything is bounded by [`Limits`], so no caller can make it hold more than
//! `max_topics × CAPACITY × MAX_PAYLOAD + max_value_bytes` of payloads plus `max_counters` small
//! counters (about 1 GiB worst case with the defaults, far less in practice).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use baton_core::GroupId;
use baton_signal::{Signal, SignalError, check_name, check_payload};
use bytes::Bytes;
use futures::stream::{self, BoxStream, StreamExt};
use tokio::sync::broadcast;

/// Messages a subscriber may fall behind before it loses the oldest.
pub const CAPACITY: usize = 16;

/// What `LocalSignal` holds at most.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Topics with at least one live subscriber.
    pub max_topics: usize,
    /// Live values.
    pub max_values: usize,
    /// Total bytes of live values.
    pub max_value_bytes: usize,
    /// Live counters.
    pub max_counters: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_topics: 1024,
            max_values: 100_000,
            max_value_bytes: 64 * 1024 * 1024,
            max_counters: 100_000,
        }
    }
}

type Key = (GroupId, String);

#[derive(Default)]
struct Values {
    map: HashMap<Key, (Bytes, Instant)>,
    bytes: usize,
}

impl Values {
    fn prune(&mut self, now: Instant) {
        let mut freed = 0;
        self.map.retain(|_, (v, until)| {
            let keep = *until > now;
            if !keep {
                freed += v.len();
            }
            keep
        });
        self.bytes -= freed;
    }
}

/// Signals in memory.
pub struct LocalSignal {
    topics: Mutex<HashMap<Key, broadcast::Sender<Bytes>>>,
    values: Mutex<Values>,
    counters: Mutex<HashMap<Key, (u64, Instant)>>,
    limits: Limits,
}

impl Default for LocalSignal {
    fn default() -> Self {
        Self::with_limits(Limits::default())
    }
}

fn until(ttl: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(ttl)
        .unwrap_or(now + Duration::from_secs(86_400 * 365))
}

impl LocalSignal {
    /// Empty, with the default limits.
    pub fn new() -> Self {
        Self::default()
    }

    /// Empty, with `limits`.
    pub fn with_limits(limits: Limits) -> Self {
        Self {
            topics: Mutex::new(HashMap::new()),
            values: Mutex::new(Values::default()),
            counters: Mutex::new(HashMap::new()),
            limits,
        }
    }

    fn receiver(
        &self,
        group: &GroupId,
        topic: &str,
    ) -> Result<broadcast::Receiver<Bytes>, SignalError> {
        let mut topics = self.topics.lock().expect("lock");
        let key = (group.clone(), topic.to_owned());
        if let Some(sender) = topics.get(&key) {
            return Ok(sender.subscribe());
        }
        if topics.len() >= self.limits.max_topics {
            topics.retain(|_, s| s.receiver_count() > 0);
            if topics.len() >= self.limits.max_topics {
                return Err(SignalError::Full);
            }
        }
        let (tx, rx) = broadcast::channel(CAPACITY);
        topics.insert(key, tx);
        Ok(rx)
    }
}

#[async_trait]
impl Signal for LocalSignal {
    async fn publish(
        &self,
        group: &GroupId,
        topic: &str,
        payload: Bytes,
    ) -> Result<(), SignalError> {
        check_name(topic)?;
        check_payload(&payload)?;
        let sender = self
            .topics
            .lock()
            .expect("lock")
            .get(&(group.clone(), topic.to_owned()))
            .cloned();
        if let Some(sender) = sender {
            let _ = sender.send(payload);
        }
        Ok(())
    }

    async fn subscribe(
        &self,
        group: &GroupId,
        topic: &str,
    ) -> Result<BoxStream<'static, Bytes>, SignalError> {
        check_name(topic)?;
        let rx = self.receiver(group, topic)?;
        Ok(stream::unfold(rx, |mut rx| async move {
            loop {
                match rx.recv().await {
                    Ok(b) => return Some((b, rx)),
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        })
        .boxed())
    }

    async fn put(
        &self,
        group: &GroupId,
        key: &str,
        value: Bytes,
        ttl: Duration,
    ) -> Result<(), SignalError> {
        check_name(key)?;
        check_payload(&value)?;
        let mut values = self.values.lock().expect("lock");
        let k = (group.clone(), key.to_owned());
        let fits = |vs: &Values| {
            let old = vs.map.get(&k).map_or(0, |(v, _)| v.len());
            (vs.map.contains_key(&k) || vs.map.len() < self.limits.max_values)
                && vs.bytes - old + value.len() <= self.limits.max_value_bytes
        };
        if !fits(&values) {
            values.prune(Instant::now());
            if !fits(&values) {
                return Err(SignalError::Full);
            }
        }
        let len = value.len();
        if let Some((prev, _)) = values.map.insert(k, (value, until(ttl))) {
            values.bytes -= prev.len();
        }
        values.bytes += len;
        Ok(())
    }

    async fn get(&self, group: &GroupId, key: &str) -> Result<Option<Bytes>, SignalError> {
        check_name(key)?;
        let values = self.values.lock().expect("lock");
        Ok(values
            .map
            .get(&(group.clone(), key.to_owned()))
            .filter(|(_, until)| *until > Instant::now())
            .map(|(v, _)| v.clone()))
    }

    async fn delete(&self, group: &GroupId, key: &str) -> Result<(), SignalError> {
        check_name(key)?;
        let mut values = self.values.lock().expect("lock");
        if let Some((v, _)) = values.map.remove(&(group.clone(), key.to_owned())) {
            values.bytes -= v.len();
        }
        Ok(())
    }

    async fn incr(
        &self,
        group: &GroupId,
        key: &str,
        by: u64,
        ttl: Duration,
    ) -> Result<Option<u64>, SignalError> {
        check_name(key)?;
        let mut counters = self.counters.lock().expect("lock");
        let k = (group.clone(), key.to_owned());
        let now = Instant::now();
        if !counters.contains_key(&k) && counters.len() >= self.limits.max_counters {
            counters.retain(|_, (_, until)| *until > now);
            if counters.len() >= self.limits.max_counters {
                return Err(SignalError::Full);
            }
        }
        let entry = counters.entry(k).or_insert((0, until(ttl)));
        if entry.1 <= now {
            *entry = (0, until(ttl));
        }
        entry.0 = entry.0.saturating_add(by);
        Ok(Some(entry.0))
    }
}

impl LocalSignal {
    /// Bytes of live and expired-but-not-yet-pruned values held now.
    pub fn value_bytes(&self) -> usize {
        self.values.lock().expect("lock").bytes
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use baton_signal::MAX_PAYLOAD;

    use super::*;

    fn g() -> GroupId {
        GroupId::new("g").unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn conformance() {
        baton_signal::testing::signal(Arc::new(LocalSignal::new()), Duration::from_millis(100))
            .await;
    }

    #[tokio::test]
    async fn value_bytes_stay_within_the_budget() {
        let limits = Limits {
            max_value_bytes: 4 * MAX_PAYLOAD,
            ..Limits::default()
        };
        let sig = LocalSignal::with_limits(limits);
        let big = Bytes::from(vec![0u8; MAX_PAYLOAD]);
        for i in 0..4 {
            sig.put(&g(), &format!("k{i}"), big.clone(), Duration::from_secs(60))
                .await
                .unwrap();
        }
        assert!(matches!(
            sig.put(&g(), "k4", big.clone(), Duration::from_secs(60))
                .await,
            Err(SignalError::Full)
        ));
        assert!(sig.value_bytes() <= limits.max_value_bytes);
        sig.put(
            &g(),
            "k1",
            Bytes::from_static(b"small"),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
        sig.put(
            &g(),
            "k4",
            Bytes::from(vec![0u8; 1000]),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
        sig.delete(&g(), "k0").await.unwrap();
        assert_eq!(sig.value_bytes(), 2 * MAX_PAYLOAD + 5 + 1000);
        sig.put(&g(), "k5", big.clone(), Duration::from_millis(1))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        sig.put(&g(), "k6", big.clone(), Duration::from_secs(60))
            .await
            .unwrap();
        assert!(
            sig.value_bytes() <= limits.max_value_bytes,
            "expired values free their bytes"
        );
    }

    #[tokio::test]
    async fn counts_of_values_counters_and_topics_are_bounded() {
        let limits = Limits {
            max_topics: 4,
            max_values: 100,
            max_counters: 100,
            ..Limits::default()
        };
        let sig = LocalSignal::with_limits(limits);
        for i in 0..100 {
            sig.put(
                &g(),
                &format!("k{i}"),
                Bytes::new(),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
            sig.incr(&g(), &format!("c{i}"), 1, Duration::from_secs(60))
                .await
                .unwrap();
        }
        assert!(matches!(
            sig.put(&g(), "more", Bytes::new(), Duration::from_secs(60))
                .await,
            Err(SignalError::Full)
        ));
        assert!(matches!(
            sig.incr(&g(), "more", 1, Duration::from_secs(60)).await,
            Err(SignalError::Full)
        ));
        sig.put(
            &g(),
            "k5",
            Bytes::from_static(b"update"),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
        let mut subs = Vec::new();
        for i in 0..4 {
            subs.push(sig.subscribe(&g(), &format!("t{i}")).await.unwrap());
        }
        assert!(matches!(
            sig.subscribe(&g(), "t4").await,
            Err(SignalError::Full)
        ));
        assert!(
            sig.subscribe(&g(), "t1").await.is_ok(),
            "an existing topic takes more subscribers"
        );
        drop(subs.pop());
        assert!(
            sig.subscribe(&g(), "t4").await.is_ok(),
            "a topic without subscribers frees its slot"
        );
    }

    #[tokio::test]
    async fn a_huge_ttl_does_not_panic() {
        let sig = LocalSignal::new();
        sig.put(&g(), "k", Bytes::new(), Duration::MAX)
            .await
            .unwrap();
        assert!(sig.get(&g(), "k").await.unwrap().is_some());
        sig.incr(&g(), "c", 1, Duration::MAX).await.unwrap();
    }
}
