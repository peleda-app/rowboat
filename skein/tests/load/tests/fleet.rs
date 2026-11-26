//! Node-loop scenarios in CI: many accounts on one node, failover between nodes, and a slow
//! object store. Each keeps to a small budget of storage requests and finishes in seconds.

use std::sync::Arc;
use std::time::Duration;

use skein_load::{Fault, Fleet, FleetOutcome, Latency, run_fleet};
use skein_storage::testing::SlowObjects;
use skein_storage_memory::MemoryObjects;

fn report(name: &str, o: &FleetOutcome) {
    println!(
        "{name}: {} messages, first sync {:.2?}, {:.3} PUT and {:.3} GET per message, recovery {:?}, appends {:?}, fenced {:?}, taken over {}, max token {}, stale refused {}, account event repeats {}, total {:?}",
        o.messages,
        o.initial_time,
        o.initial_puts_per_message(),
        o.initial_gets_per_message(),
        o.recovery_time,
        o.appends,
        o.fenced,
        o.taken_over,
        o.max_fence,
        o.stale_refused,
        o.repeated_account_events,
        o.total
    );
    assert!(o.violations.is_empty(), "{name}: {:#?}", o.violations);
    assert_eq!(o.repeated_account_events, 0, "{name}: no event key repeats");
}

#[tokio::test(flavor = "multi_thread")]
async fn many_accounts_on_one_node() {
    let fleet = Fleet::many(200, 10);
    let o = run_fleet(&fleet, Arc::new(MemoryObjects::new())).await;
    report("many", &o);
    assert_eq!(o.initial_messages, 2_000);
    let overhead = o.initial_overhead_puts_per_account(200);
    println!("many: {overhead:.1} PUT per account beyond one per message");
    assert!(
        overhead < 12.0,
        "{overhead:.1} PUT per account beyond one per message"
    );
    assert!(
        o.initial_gets_per_message() < 2.4,
        "{:.2} GET per message",
        o.initial_gets_per_message()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn failover_keeps_every_journal_whole() {
    let fleet = Fleet {
        nodes: 3,
        extra: 8,
        latency: Some(Latency {
            base: Duration::from_millis(2),
            jitter: Duration::from_millis(4),
        }),
        fault: Some(Fault {
            after: 0.3,
            crash: 1,
            zombie: 1,
        }),
        ttl: Duration::from_millis(800),
        interval: Duration::from_secs(3),
        timeout: Duration::from_secs(30),
        ..Fleet::many(60, 20)
    };
    let o = run_fleet(&fleet, Arc::new(MemoryObjects::new())).await;
    report("failover", &o);
    assert!(o.taken_over > 0, "no account moved to a survivor");
    assert_eq!(o.stale_refused, o.taken_over);
}

#[tokio::test(flavor = "multi_thread")]
async fn slow_store_still_completes() {
    let fleet = Fleet {
        latency: Some(Latency {
            base: Duration::from_millis(5),
            jitter: Duration::from_millis(15),
        }),
        ..Fleet::many(100, 10)
    };
    let o = run_fleet(&fleet, Arc::new(MemoryObjects::new())).await;
    report("slow", &o);
    let overhead = o.initial_overhead_puts_per_account(100);
    assert!(
        overhead < 12.0,
        "{overhead:.1} PUT per account beyond one per message"
    );
}

#[tokio::test]
async fn slow_objects_keep_the_objects_contract() {
    skein_storage::testing::objects(Arc::new(SlowObjects::new(
        Arc::new(MemoryObjects::new()),
        Duration::ZERO,
        Duration::from_micros(200),
        1,
    )))
    .await;
}
