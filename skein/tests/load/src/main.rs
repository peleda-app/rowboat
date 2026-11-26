//! `skein-load`: run a load scenario and print request counts and throughput.

use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use skein_load::{Fault, Fleet, Latency, Scenario, run, run_fleet};
use skein_storage::Objects;

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Kind {
    /// Accounts with a mail history, then rounds of new mail and flag changes.
    History,
    /// Many accounts with small mailboxes on one node running the node loop.
    Many,
    /// Several nodes; some crash or stop heartbeating while accounts sync.
    Failover,
    /// Many accounts on one node over a store with added latency.
    Slow,
}

#[derive(Parser)]
#[command(about = "Load test of the Skein engine against fake mail servers")]
struct Args {
    /// Which scenario to run.
    #[arg(long, value_enum, default_value_t = Kind::History)]
    scenario: Kind,
    /// Accounts (people). Default: 10 for history, 1000 for many and slow, 300 for failover.
    #[arg(long)]
    accounts: Option<usize>,
    /// Messages per account before the first sync. Default: 2000 for history, 20 otherwise.
    #[arg(long)]
    history: Option<usize>,
    /// New messages per account per round (history).
    #[arg(long, default_value_t = 20)]
    per_round: usize,
    /// Rounds of incremental sync (history).
    #[arg(long, default_value_t = 15)]
    rounds: usize,
    /// Flag changes per account per round (history).
    #[arg(long, default_value_t = 10)]
    flag_changes: usize,
    /// Message size in bytes. Default: 20000 for history, 1000 otherwise.
    #[arg(long)]
    size: Option<usize>,
    /// Accounts synced at once (history).
    #[arg(long, default_value_t = 10)]
    concurrency: usize,
    /// Nodes (failover).
    #[arg(long, default_value_t = 3)]
    nodes: usize,
    /// Nodes that crash (failover).
    #[arg(long, default_value_t = 1)]
    crash: usize,
    /// Nodes whose heartbeats stop while they keep writing (failover).
    #[arg(long, default_value_t = 1)]
    zombie: usize,
    /// Share of accounts done with their first sync when nodes fail (failover).
    #[arg(long, default_value_t = 0.3)]
    after: f64,
    /// Messages per account added after the first sync (failover: during the outage).
    #[arg(long, default_value_t = 5)]
    extra: usize,
    /// Node liveness window in milliseconds (failover).
    #[arg(long, default_value_t = 1500)]
    ttl_ms: u64,
    /// Seconds between syncs of an idle account (failover), the fallback when a hint is lost.
    #[arg(long, default_value_t = 3)]
    interval_secs: u64,
    /// Fixed latency per store call in milliseconds (slow; failover when set).
    #[arg(long)]
    latency_ms: Option<u64>,
    /// Extra random latency per store call, up to this many milliseconds.
    #[arg(long, default_value_t = 15)]
    jitter_ms: u64,
    /// Store objects in this directory instead of memory.
    #[arg(long)]
    fs: Option<std::path::PathBuf>,
}

fn rate(n: u64, d: Duration) -> f64 {
    n as f64 / d.as_secs_f64().max(1e-9)
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let objects: Arc<dyn Objects> = match &args.fs {
        Some(dir) => Arc::new(skein_storage_fs::FsObjects::open(dir).expect("open directory")),
        None => Arc::new(skein_storage_memory::MemoryObjects::new()),
    };
    if args.scenario == Kind::History {
        history(&args, objects).await;
    } else {
        fleet(&args, objects).await;
    }
}

async fn history(args: &Args, objects: Arc<dyn Objects>) {
    let scenario = Scenario {
        accounts: args.accounts.unwrap_or(10),
        history: args.history.unwrap_or(2000),
        per_round: args.per_round,
        rounds: args.rounds,
        flag_changes: args.flag_changes,
        size: args.size.unwrap_or(20_000),
        concurrency: args.concurrency,
    };
    let o = run(&scenario, objects).await;
    println!("scenario: {scenario:?}");
    println!(
        "initial:     {} messages in {:.2?} ({:.0}/s); PUT {} GET {} LIST {} DELETE {}; {:.1} MiB written",
        o.initial_messages,
        o.initial_time,
        rate(o.initial_messages, o.initial_time),
        o.initial.puts,
        o.initial.gets,
        o.initial.lists,
        o.initial.deletes,
        o.initial.bytes_written as f64 / 1048576.0
    );
    println!(
        "incremental: {} messages in {:.2?} ({:.0}/s); PUT {} GET {} LIST {} DELETE {}; {:.2} PUT per new message",
        o.incremental_messages,
        o.incremental_time,
        rate(o.incremental_messages, o.incremental_time),
        o.incremental.puts,
        o.incremental.gets,
        o.incremental.lists,
        o.incremental.deletes,
        o.puts_per_message()
    );
}

async fn fleet(args: &Args, objects: Arc<dyn Objects>) {
    let failover = args.scenario == Kind::Failover;
    let default_accounts = if failover { 300 } else { 1000 };
    let mut fleet = Fleet::many(
        args.accounts.unwrap_or(default_accounts),
        args.history.unwrap_or(20),
    );
    fleet.size = args.size.unwrap_or(1_000);
    fleet.timeout = Duration::from_secs(600);
    let latency_ms = match args.scenario {
        Kind::Slow => Some(args.latency_ms.unwrap_or(5)),
        _ => args.latency_ms,
    };
    fleet.latency = latency_ms.map(|ms| Latency {
        base: Duration::from_millis(ms),
        jitter: Duration::from_millis(args.jitter_ms),
    });
    if failover {
        fleet.nodes = args.nodes;
        fleet.extra = args.extra;
        fleet.ttl = Duration::from_millis(args.ttl_ms);
        fleet.interval = Duration::from_secs(args.interval_secs);
        fleet.fault = Some(Fault {
            after: args.after,
            crash: args.crash,
            zombie: args.zombie,
        });
    }
    let accounts = fleet.accounts;
    let o = run_fleet(&fleet, objects).await;
    println!("scenario: {fleet:?}");
    println!(
        "first sync: {} messages of {accounts} accounts in {:.2?} ({:.0}/s); PUT {} GET {} LIST {}; {:.2} PUT and {:.2} GET per message, {:.1} PUT per account beyond one per message",
        o.initial_messages,
        o.initial_time,
        rate(o.initial_messages, o.initial_time),
        o.initial.puts,
        o.initial.gets,
        o.initial.lists,
        o.initial_puts_per_message(),
        o.initial_gets_per_message(),
        o.initial_overhead_puts_per_account(accounts),
    );
    println!(
        "whole run: {} messages; PUT {} GET {} LIST {} DELETE {}",
        o.messages, o.total.puts, o.total.gets, o.total.lists, o.total.deletes
    );
    if let Some(recovery) = o.recovery_time {
        println!(
            "failover: recovered in {recovery:.2?}; appends per node {:?}; fenced appends per node {:?}; {} accounts taken over, {} refused the failed node's token; highest token {}; {} account events journaled twice",
            o.appends,
            o.fenced,
            o.taken_over,
            o.stale_refused,
            o.max_fence,
            o.repeated_account_events
        );
    }
    if o.violations.is_empty() {
        println!("every journal checked: no gaps, no repeated keys, every message present");
    } else {
        for v in &o.violations {
            println!("violation: {v}");
        }
        std::process::exit(1);
    }
}
