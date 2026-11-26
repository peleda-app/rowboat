//! `rowboat-load`: node load tests. Targets on an Apple silicon laptop (calibrate on the first
//! run, then hold): first sync at least 200 messages a second, `list_threads` p95 under 50 ms,
//! `search` p95 under 100 ms over 100,000 messages, 1,000 mark-reads settled within 30 s.

use clap::Parser;

#[derive(Parser)]
#[command(name = "rowboat-load")]
struct Args {
    /// Messages in all.
    #[arg(long, default_value_t = 100_000)]
    messages: usize,
    /// Mailboxes they are spread over.
    #[arg(long, default_value_t = 10)]
    mailboxes: usize,
    /// Mark-reads issued after the first sync (at most 200, one page).
    #[arg(long, default_value_t = 200)]
    marks: usize,
    /// Approximate bytes per message.
    #[arg(long, default_value_t = 2_000)]
    size: usize,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), rowboat_load::LoadError> {
    let args = Args::parse();
    let r = rowboat_load::run(args.messages, args.mailboxes, args.marks, args.size).await?;
    println!(
        "messages {}  first sync {:.1?} ({:.0}/s, target >= 200/s)  list_threads p95 {:.1?} (target < 50ms)  search p95 {:.1?} (target < 100ms)  {} mark-reads settled in {:.1?} (target < 30s for 1000)",
        r.messages, r.first_sync, r.rate, r.threads_p95, r.search_p95, r.marked, r.mark_read
    );
    Ok(())
}
