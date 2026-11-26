//! `mise run load -- [scenario]`: runs the full-size load scenarios and prints their numbers.

use std::time::Duration;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let which = std::env::args().nth(1).unwrap_or_else(|| "all".to_owned());
    if which == "list" {
        println!(
            "contention handover fanout churn group fetch drop_memory drop_http lease_server group_server all"
        );
        return;
    }
    let mut failed = false;
    let run = |name: &str| which == "all" || which == name;
    let mut results = Vec::new();
    if run("contention") {
        results.push(baton_load::contention(32, 2_000, 2_000.0).await);
    }
    if run("handover") {
        results.push(baton_load::handover(2_000, Duration::from_secs(30)).await);
    }
    if run("fanout") {
        results.push(baton_load::fanout(100, 100_000, 20_000.0).await);
    }
    if run("churn") {
        results.push(baton_load::churn(5_000).await);
    }
    if run("fetch") {
        results.push(baton_load::fetch(1_000, 256 * 1024, 50.0).await);
    }
    if run("group") {
        results.push(baton_load::group_log(50, 200, Duration::from_secs(60)).await);
    }
    if run("drop_memory") {
        results.push(baton_load::drop_memory(1_000, 100, 50_000.0).await);
    }
    if run("drop_http") {
        results.push(baton_load::drop_http(200, 100, 20_000.0).await);
    }
    if run("lease_server") {
        results.push(baton_load::lease_server(32, 2_000, 2_000.0).await);
    }
    if run("group_server") {
        results.push(baton_load::group_server(2_000, 16, 5_000.0).await);
    }
    for r in results {
        match r {
            Ok(r) => println!(
                "{:<11} {:>9} ops in {:>9.3?}  {:>12.0} ops/s  {}",
                r.name,
                r.ops,
                r.elapsed,
                r.rate(),
                r.notes
            ),
            Err(e) => {
                failed = true;
                eprintln!("FAILED: {e}");
            }
        }
    }
    if failed {
        std::process::exit(1);
    }
}
