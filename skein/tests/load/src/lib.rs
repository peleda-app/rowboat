//! Load scenarios for the engine: accounts with a mail history, then days of new mail and flag
//! changes, with every storage request counted; and node-loop scenarios with many accounts per
//! node, node failover and store latency ([`Fleet`]).

mod fleet;

pub use fleet::{Fault, Fleet, FleetOutcome, Latency, run_fleet};

use std::sync::Arc;
use std::time::{Duration, Instant};

use baton_lease_cas::{CasLeases, CasLiveness};
use baton_signal_local::LocalSignal;
use baton_state_memory::MemoryState;
use futures::future::join_all;
use skein_core::{AccountId, Flags, NodeId, TenantId};
use skein_engine::{AccountConfig, Engine, node_profile};
use skein_mail::testing::{FakeMail, ServerControl};
use skein_storage::{CountingObjects, ObjectCounts, Objects, Storage};

/// What to simulate.
#[derive(Debug, Clone)]
pub struct Scenario {
    /// Accounts (people).
    pub accounts: usize,
    /// Messages already in each mailbox before the first sync.
    pub history: usize,
    /// New messages per account per round (a round is one sync after new mail arrived).
    pub per_round: usize,
    /// Rounds of incremental sync.
    pub rounds: usize,
    /// Messages whose flags change per account per round.
    pub flag_changes: usize,
    /// Average message size in bytes.
    pub size: usize,
    /// Accounts synced at once.
    pub concurrency: usize,
}

/// Measurements of a run.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// Requests during the first sync.
    pub initial: ObjectCounts,
    /// Requests during the incremental rounds.
    pub incremental: ObjectCounts,
    /// Messages journaled in the first sync.
    pub initial_messages: u64,
    /// Messages journaled in the rounds.
    pub incremental_messages: u64,
    /// Wall time of the first sync.
    pub initial_time: Duration,
    /// Wall time of the rounds.
    pub incremental_time: Duration,
}

impl Outcome {
    /// Object store writes per new message during the rounds.
    pub fn puts_per_message(&self) -> f64 {
        self.incremental.puts as f64 / self.incremental_messages.max(1) as f64
    }
}

fn diff(a: ObjectCounts, b: ObjectCounts) -> ObjectCounts {
    ObjectCounts {
        gets: b.gets - a.gets,
        puts: b.puts - a.puts,
        deletes: b.deletes - a.deletes,
        lists: b.lists - a.lists,
        bytes_written: b.bytes_written - a.bytes_written,
    }
}

/// Runs `scenario` against `objects`.
pub async fn run(scenario: &Scenario, objects: Arc<dyn Objects>) -> Outcome {
    let counting = Arc::new(CountingObjects::new(objects));
    let storage = Storage::over(counting.clone());
    let state = Arc::new(MemoryState::new());
    let liveness = Arc::new(CasLiveness::new(state.clone(), 30_000));
    let engine = Engine::new(
        storage,
        Arc::new(CasLeases::new(state, liveness)),
        Arc::new(LocalSignal::new()),
        node_profile(NodeId::new("load").unwrap(), 1, true),
    );
    let tenant = TenantId::new("load").unwrap();
    let accounts: Vec<(AccountConfig, FakeMail)> = (0..scenario.accounts)
        .map(|i| {
            let fake = FakeMail::new();
            fake.fill("INBOX", scenario.history, scenario.size);
            let config =
                AccountConfig::new(tenant.clone(), AccountId::new(format!("acc{i}")).unwrap());
            (config, fake)
        })
        .collect();

    let sync_all = |accounts: &Vec<(AccountConfig, FakeMail)>| {
        let engine = engine.clone();
        let chunks: Vec<Vec<(AccountConfig, FakeMail)>> = accounts
            .chunks(scenario.concurrency.max(1))
            .map(|c| c.to_vec())
            .collect();
        async move {
            let mut total = 0u64;
            for chunk in chunks {
                let results = join_all(chunk.iter().map(|(c, f)| engine.sync_account(c, f))).await;
                for r in results {
                    let r = r.expect("sync succeeds");
                    total += r.mailboxes.iter().map(|m| m.added).sum::<u64>();
                }
            }
            total
        }
    };

    let before = counting.counts();
    let started = Instant::now();
    let initial_messages = sync_all(&accounts).await;
    let initial_time = started.elapsed();
    let after_initial = counting.counts();

    let started = Instant::now();
    let mut incremental_messages = 0;
    for round in 0..scenario.rounds {
        for (_, fake) in &accounts {
            fake.fill("INBOX", scenario.per_round, scenario.size);
        }
        for (_, fake) in &accounts {
            for k in 0..scenario.flag_changes {
                let bytes = format!("flag-target-{round}-{k}");
                fake.add("INBOX", bytes.as_bytes(), Flags::default()).await;
                fake.set_flags("INBOX", bytes.as_bytes(), Flags::new(["\\Seen"]))
                    .await;
            }
        }
        incremental_messages += sync_all(&accounts).await;
    }
    let incremental_time = started.elapsed();
    let after = counting.counts();
    Outcome {
        initial: diff(before, after_initial),
        incremental: diff(after_initial, after),
        initial_messages,
        incremental_messages,
        initial_time,
        incremental_time,
    }
}
