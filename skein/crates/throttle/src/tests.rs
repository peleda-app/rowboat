use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::time::{Instant, sleep};

use super::*;

#[tokio::test(start_paused = true)]
async fn holds_at_most_limit_slots() {
    let throttle = Throttle::new(2);
    let running = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for _ in 0..6 {
        let (throttle, running, peak) = (throttle.clone(), running.clone(), peak.clone());
        tasks.push(tokio::spawn(async move {
            let _permit = throttle.acquire().await;
            let now = running.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            sleep(Duration::from_secs(1)).await;
            running.fetch_sub(1, Ordering::SeqCst);
        }));
    }
    let start = Instant::now();
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(peak.load(Ordering::SeqCst), 2);
    assert_eq!(start.elapsed(), Duration::from_secs(3));
    assert_eq!(throttle.available(), 2);
}

#[tokio::test(start_paused = true)]
async fn default_limit_is_four() {
    let throttle = Throttle::default();
    let permits: Vec<_> = acquire_all(&throttle, 4).await;
    assert_eq!(throttle.available(), 0);
    drop(permits);
    assert_eq!(throttle.available(), 4);
    assert_eq!(Throttle::new(0).available(), 1);
}

async fn acquire_all(throttle: &Throttle, n: usize) -> Vec<Permit> {
    let mut out = Vec::new();
    for _ in 0..n {
        out.push(throttle.acquire().await);
    }
    out
}

#[tokio::test(start_paused = true)]
async fn a_pause_holds_every_clone() {
    let throttle = Throttle::default();
    let other = throttle.clone();
    let start = Instant::now();
    throttle.pause(Duration::from_secs(30));
    let _permit = other.acquire().await;
    assert_eq!(start.elapsed(), Duration::from_secs(30));
    assert!(other.paused_until().is_none());
}

#[tokio::test(start_paused = true)]
async fn a_pause_set_while_waiting_for_a_slot_is_respected() {
    let throttle = Throttle::new(1);
    let held = throttle.acquire().await;
    let waiter = {
        let throttle = throttle.clone();
        tokio::spawn(async move {
            let _p = throttle.acquire().await;
            Instant::now()
        })
    };
    let start = Instant::now();
    sleep(Duration::from_secs(1)).await;
    throttle.pause(Duration::from_secs(10));
    drop(held);
    let got = waiter.await.unwrap();
    assert_eq!(got - start, Duration::from_secs(11));
}

#[tokio::test(start_paused = true)]
async fn pauses_only_extend_and_are_capped() {
    let throttle = Throttle::with_max_pause(4, Duration::from_secs(60));
    let start = Instant::now();
    throttle.pause(Duration::from_secs(20));
    throttle.pause(Duration::from_secs(5));
    assert_eq!(
        throttle.paused_until(),
        Some(start + Duration::from_secs(20))
    );
    throttle.pause(Duration::from_secs(3600));
    assert_eq!(
        throttle.paused_until(),
        Some(start + Duration::from_secs(60))
    );
    throttle.pause_until(start + Duration::from_secs(7200));
    assert_eq!(
        throttle.paused_until(),
        Some(start + Duration::from_secs(60))
    );
    throttle.pause_until(start);
    throttle.pause(Duration::ZERO);
    assert_eq!(
        throttle.paused_until(),
        Some(start + Duration::from_secs(60))
    );
    let _p = throttle.acquire().await;
    assert_eq!(start.elapsed(), Duration::from_secs(60));
}

#[tokio::test(start_paused = true)]
async fn the_default_cap_is_ten_minutes() {
    let throttle = Throttle::default();
    let start = Instant::now();
    throttle.pause(Duration::from_secs(86_400));
    assert_eq!(throttle.paused_until(), Some(start + MAX_PAUSE));
}

#[tokio::test(start_paused = true)]
async fn the_registry_gives_one_throttle_per_key() {
    let throttles = Throttles::default();
    let a = throttles.get("tenant/a");
    let again = throttles.clone().get("tenant/a");
    let b = throttles.get("tenant/b");
    assert!(a.same(&again));
    assert!(!a.same(&b));
    a.pause(Duration::from_secs(5));
    assert!(again.paused_until().is_some());
    assert!(b.paused_until().is_none());
}

#[tokio::test(start_paused = true)]
async fn the_registry_drops_idle_keys_but_keeps_held_and_paused_ones() {
    let throttles = Throttles::new(2);
    let held = throttles.get("held");
    throttles.get("paused").pause(Duration::from_secs(60));
    for i in 0..200 {
        throttles.get(&format!("idle-{i}"));
    }
    assert!(throttles.len() < 100, "kept {}", throttles.len());
    assert!(throttles.get("held").same(&held));
    assert!(throttles.get("paused").paused_until().is_some());
    sleep(Duration::from_secs(61)).await;
    drop(held);
    for i in 0..200 {
        throttles.get(&format!("more-{i}"));
    }
    assert!(throttles.len() < 100);
    assert_eq!(throttles.get("held").available(), 2);
}
