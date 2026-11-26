//! Keeps storage request counts within the budget the plan promises, so a change that multiplies
//! requests fails CI instead of the bill.

use std::sync::Arc;

use skein_load::{Scenario, run};
use skein_storage_memory::MemoryObjects;

#[tokio::test(flavor = "multi_thread")]
async fn requests_stay_within_budget() {
    let scenario = Scenario {
        accounts: 4,
        history: 600,
        per_round: 5,
        rounds: 6,
        flag_changes: 2,
        size: 2_000,
        concurrency: 4,
    };
    let o = run(&scenario, Arc::new(MemoryObjects::new())).await;
    assert_eq!(o.initial_messages, 2_400);
    let initial = o.initial.puts as f64 / o.initial_messages as f64;
    println!("initial {initial:.3} PUT/message {:?}", o.initial);
    println!(
        "incremental {:.3} PUT/message {:?}",
        o.puts_per_message(),
        o.incremental
    );
    assert!(initial < 1.1, "initial sync: {initial:.2} PUT per message");
    assert!(
        o.puts_per_message() < 3.0,
        "incremental: {:.2} PUT per new message",
        o.puts_per_message()
    );
}
