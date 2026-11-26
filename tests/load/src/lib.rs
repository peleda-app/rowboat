//! Node load scenarios over the test profile: Skein's FakeMail, the engine, the follower,
//! `rinse-mail-direct` and the mail database, as the desktop runs them.

use std::time::{Duration, Instant};

use rowboat_api::{
    AccountSetup, EmailAddress, Endpoint, ListQuery, MessageRef, NodeApi, Scope, SearchFilter,
    SearchQuery, Secret, Security, Targets,
};
use rowboat_node::testing::test_node;

/// Why a run failed: the stage that failed, never content.
#[derive(Debug, thiserror::Error)]
#[error("load run failed: {0}")]
pub struct LoadError(pub &'static str);

impl From<rowboat_api::NodeError> for LoadError {
    fn from(_: rowboat_api::NodeError) -> Self {
        Self("a node call failed")
    }
}

/// What one run measured.
#[derive(Debug, Clone)]
pub struct Report {
    /// Messages placed in mailboxes and synced.
    pub messages: usize,
    /// Time from adding the account until every message was listed.
    pub first_sync: Duration,
    /// Messages per second of the first sync.
    pub rate: f64,
    /// 95th percentile of `list_threads` (50 rows).
    pub threads_p95: Duration,
    /// 95th percentile of `search`.
    pub search_p95: Duration,
    /// Time until every mark-read settled in the database.
    pub mark_read: Duration,
    /// Mark-reads issued.
    pub marked: usize,
}

fn p95(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    samples
        .get(samples.len() * 95 / 100)
        .copied()
        .unwrap_or_default()
}

async fn wait<F, Fut>(limit: Duration, mut f: F) -> Result<(), LoadError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if f().await {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Err(LoadError("timed out"))
}

async fn placed(api: &dyn NodeApi) -> u64 {
    let Ok(accounts) = api.list_accounts().await else {
        return 0;
    };
    let mut total = 0;
    for a in accounts {
        if let Ok(boxes) = api.list_mailboxes(&a.id).await {
            total += boxes.iter().map(|b| b.total).sum::<u64>();
        }
    }
    total
}

/// Fills `mailboxes` mailboxes with `messages` messages in all (FakeMail generates the same
/// messages in every mailbox, so they are one message placed in several mailboxes), adds the account, waits for the
/// first sync, then measures lists, search and `marks` mark-reads.
pub async fn run(
    messages: usize,
    mailboxes: usize,
    marks: usize,
    size: usize,
) -> Result<Report, LoadError> {
    let t = test_node(0)
        .await
        .map_err(|_| LoadError("the node did not build"))?;
    let api = t.node.api();
    let server = t.fakes.server("load");
    let per = messages / mailboxes.max(1);
    for m in 0..mailboxes.max(1) {
        let name = if m == 0 {
            "INBOX".to_owned()
        } else {
            format!("Box{m}")
        };
        server.fill(&name, per, size);
    }
    let total = per * mailboxes.max(1);
    let started = Instant::now();
    let account = api
        .add_account(
            AccountSetup {
                address: EmailAddress::new("load@example.com")?,
                display_name: None,
                username: "load".into(),
                imap: Endpoint::new("imap.example.com", 993, Security::Tls)
                    .map_err(|_| LoadError("bad endpoint"))?,
                smtp: Endpoint::new("smtp.example.com", 465, Security::Tls)
                    .map_err(|_| LoadError("bad endpoint"))?,
            },
            Secret::from_text("load-test-password"),
        )
        .await?;
    wait(Duration::from_secs(3600), || async {
        placed(&*api).await >= total as u64
    })
    .await?;
    let first_sync = started.elapsed();

    let mut threads = Vec::new();
    for _ in 0..40 {
        let s = Instant::now();
        api.list_threads(ListQuery {
            scope: Scope::All {
                account: Some(account.clone()),
            },
            unread_only: false,
            cursor: None,
            limit: 50,
        })
        .await?;
        threads.push(s.elapsed());
    }
    let mut search = Vec::new();
    for word in ["lorem", "message", "ipsum", "sender1", "nothing-here"] {
        for _ in 0..8 {
            let s = Instant::now();
            api.search(SearchQuery {
                account: None,
                text: word.into(),
                filter: SearchFilter::default(),
                limit: 50,
            })
            .await?;
            search.push(s.elapsed());
        }
    }

    let page = api
        .list_messages(ListQuery {
            scope: Scope::All {
                account: Some(account.clone()),
            },
            unread_only: false,
            cursor: None,
            limit: 200,
        })
        .await?;
    let mut targets: Vec<MessageRef> = page
        .items
        .iter()
        .map(|e| MessageRef {
            account: account.clone(),
            message: e.id.clone(),
        })
        .collect();
    targets.truncate(marks);
    let marked = targets.len();
    let s = Instant::now();
    for chunk in targets.chunks(50) {
        api.set_read(Targets(chunk.to_vec()), true).await?;
    }
    wait(Duration::from_secs(600), || async {
        let mut all_read = true;
        for t in &targets {
            match api.get_message(&t.account, &t.message).await {
                Ok(d) => {
                    all_read &= d
                        .memberships
                        .iter()
                        .all(|m| m.flags.iter().any(|f| f == "\\Seen"))
                }
                Err(_) => return false,
            }
        }
        all_read
    })
    .await?;
    let mark_read = s.elapsed();
    t.node.shutdown().await;
    Ok(Report {
        messages: total,
        first_sync,
        rate: total as f64 / first_sync.as_secs_f64().max(0.001),
        threads_p95: p95(threads),
        search_p95: p95(search),
        mark_read,
        marked,
    })
}
