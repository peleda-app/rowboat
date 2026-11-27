//! `rowboat-load`: node load tests. Targets on an Apple silicon laptop (calibrate on the first
//! run, then hold): first sync at least 200 messages a second, `list_threads` p95 under 50 ms,
//! `search` p95 under 100 ms over 100,000 messages, 1,000 mark-reads settled within 30 s;
//! replication to a second node at least 100 messages a second, 200 mark-reads from it settled
//! within 30 s; 100 accounts handed over from a desktop to a newly adopted server within 60 s.

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
    /// Messages the replication scenario syncs on the owner and replicates to a second node
    /// (0 skips it).
    #[arg(long, default_value_t = 20_000)]
    replicate: usize,
    /// Accounts a desktop hands over to a newly adopted server at once (0 skips it).
    #[arg(long, default_value_t = 100)]
    handover: usize,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), rowboat_load::LoadError> {
    let args = Args::parse();
    let r = rowboat_load::run(args.messages, args.mailboxes, args.marks, args.size).await?;
    println!(
        "messages {}  first sync {:.1?} ({:.0}/s, target >= 200/s)  list_threads p95 {:.1?} (target < 50ms)  search p95 {:.1?} (target < 100ms)  {} mark-reads settled in {:.1?} (target < 30s for 1000)",
        r.messages, r.first_sync, r.rate, r.threads_p95, r.search_p95, r.marked, r.mark_read
    );
    if args.replicate > 0 {
        let r =
            rowboat_load::replicate(args.replicate, args.mailboxes, args.marks, args.size).await?;
        println!(
            "replicated {} messages in {:.1?} ({:.0}/s, target >= 100/s)  {} mark-reads from the second node settled in {:.1?} (target < 30s for 200)",
            r.messages, r.took, r.rate, r.marked, r.mark_read
        );
    }
    if args.handover > 0 {
        let r = rowboat_load::handover(args.handover, 20).await?;
        println!(
            "handed {} accounts over to the server in {:.1?} ({:.1}/s, target: 100 within 60s), {} messages listed there",
            r.accounts, r.took, r.rate, r.messages
        );
    }
    Ok(())
}
