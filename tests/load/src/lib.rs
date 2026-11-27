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

/// What one replication run measured.
#[derive(Debug, Clone)]
pub struct Replicated {
    /// Messages the owner synced and the second node replicated.
    pub messages: usize,
    /// Time from the second node's restart into the group until it listed every message.
    pub took: Duration,
    /// Messages per second replicated.
    pub rate: f64,
    /// Mark-reads the second node issued to the owner.
    pub marked: usize,
    /// Time until every mark-read settled in the second node's database.
    pub mark_read: Duration,
}

/// Two nodes over in-process links: the owner syncs `messages` messages in `mailboxes`
/// mailboxes, a second node pairs, restarts into the group and replicates the journal and every
/// blob; then the second node sends `marks` mark-reads that the owner runs and that come back
/// through the replicated journal.
pub async fn replicate(
    messages: usize,
    mailboxes: usize,
    marks: usize,
    size: usize,
) -> Result<Replicated, LoadError> {
    use futures::StreamExt;
    use std::sync::Arc;

    let endpoints: Arc<dyn rowboat_endpoint::Endpoints> =
        Arc::new(rowboat_endpoint_memory::MemoryEndpoints::new());
    let clock: Arc<dyn rowboat_node::Clock> = Arc::new(rowboat_node::SystemClock);
    let a = rowboat_node::testing::test_node_on(clock.clone(), endpoints.clone())
        .await
        .map_err(|_| LoadError("the owner did not build"))?;
    let owner = a.node.api();
    let server = a.fakes.server("load");
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
    owner
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
        placed(&*owner).await >= total as u64
    })
    .await?;

    let mut b = rowboat_node::testing::test_node_on(clock.clone(), endpoints.clone())
        .await
        .map_err(|_| LoadError("the second node did not build"))?;
    let confirmer = owner.clone();
    let mut events = owner.group_events();
    let answer = tokio::spawn(async move {
        while let Some(e) = events.next().await {
            if let rowboat_api::GroupEvent::PairingCheck {
                pairing,
                confirm: true,
                ..
            } = e
            {
                let _ = confirmer.confirm_pairing(&pairing, true).await;
                break;
            }
        }
    });
    let invite = owner.create_invite().await?;
    b.node.api().accept_invite(&invite.qr, None).await?;
    let _ = tokio::time::timeout(Duration::from_secs(10), answer).await;
    b.node.shutdown().await;
    let placeholder = rowboat_node::testing::test_node(0)
        .await
        .map_err(|_| LoadError("the placeholder did not build"))?;
    drop(std::mem::replace(&mut b.node, placeholder.node));
    let started = Instant::now();
    let reopened =
        rowboat_node::testing::reopen_on(&b.dir, &b.fakes, &b.keystore, 0, clock, Some(endpoints))
            .await
            .map_err(|_| LoadError("the second node did not reopen"))?;
    let old = std::mem::replace(&mut b.node, reopened);
    drop(old);
    let reader = b.node.api();
    wait(Duration::from_secs(3600), || async {
        placed(&*reader).await >= total as u64
    })
    .await?;
    let took = started.elapsed();

    let account = reader
        .list_accounts()
        .await?
        .first()
        .map(|a| a.id.clone())
        .ok_or(LoadError("no account replicated"))?;
    let page = reader
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
    let s = Instant::now();
    for chunk in targets.chunks(50) {
        reader.set_read(Targets(chunk.to_vec()), true).await?;
    }
    wait(Duration::from_secs(600), || async {
        for t in &targets {
            match reader.get_message(&t.account, &t.message).await {
                Ok(d)
                    if d.memberships
                        .iter()
                        .all(|m| m.flags.iter().any(|f| f == "\\Seen")) => {}
                _ => return false,
            }
        }
        true
    })
    .await?;
    let mark_read = s.elapsed();
    a.node.shutdown().await;
    b.node.shutdown().await;
    Ok(Replicated {
        messages: total,
        took,
        rate: total as f64 / took.as_secs_f64().max(0.001),
        marked: targets.len(),
        mark_read,
    })
}

/// What one handover run measured.
#[derive(Debug, Clone)]
pub struct HandedOver {
    /// Accounts the desktop led and the server took over.
    pub accounts: usize,
    /// Time from the server's restart into the group until it led every account.
    pub took: Duration,
    /// Accounts per second handed over.
    pub rate: f64,
    /// Messages the server listed afterwards, over every account.
    pub messages: u64,
}

/// A desktop leads `accounts` accounts of `per_account` messages each; a server node is adopted
/// into its group and takes every account over at once (the desktop hands each over at a clean
/// point with its state); measures until the server leads them all and lists every message.
pub async fn handover(accounts: usize, per_account: usize) -> Result<HandedOver, LoadError> {
    use futures::StreamExt;
    use rowboat_node::testing::{FakeProviders, Spec, group_timing, reopen_as, test_node_as};
    use std::sync::Arc;

    let endpoints: Arc<dyn rowboat_endpoint::Endpoints> =
        Arc::new(rowboat_endpoint_memory::MemoryEndpoints::new());
    let fakes = FakeProviders::new();
    let spec = |class| Spec {
        class,
        fakes: fakes.clone(),
        endpoints: endpoints.clone(),
        timing: group_timing(),
        on_revoked: None,
    };
    let desktop = test_node_as(&spec(baton_lease::NodeClass::Desktop))
        .await
        .map_err(|_| LoadError("the desktop did not build"))?;
    let api = desktop.node.api();
    let mut ids = Vec::new();
    for i in 0..accounts {
        let user = format!("load{i}");
        fakes.server(&user).fill("INBOX", per_account, 400);
        ids.push(
            api.add_account(
                AccountSetup {
                    address: EmailAddress::new(format!("{user}@example.com"))?,
                    display_name: None,
                    username: user,
                    imap: Endpoint::new("imap.example.com", 993, Security::Tls)
                        .map_err(|_| LoadError("bad endpoint"))?,
                    smtp: Endpoint::new("smtp.example.com", 465, Security::Tls)
                        .map_err(|_| LoadError("bad endpoint"))?,
                },
                Secret::from_text("load-test-password"),
            )
            .await?,
        );
    }
    let total = (accounts * per_account) as u64;
    wait(Duration::from_secs(3600), || async {
        placed(&*api).await >= total
    })
    .await?;

    let server_spec = spec(baton_lease::NodeClass::Server);
    let mut server = test_node_as(&server_spec)
        .await
        .map_err(|_| LoadError("the server did not build"))?;
    let confirmer = api.clone();
    let mut events = api.group_events();
    let answer = tokio::spawn(async move {
        while let Some(e) = events.next().await {
            if let rowboat_api::GroupEvent::PairingCheck {
                pairing,
                confirm: true,
                ..
            } = e
            {
                let _ = confirmer.confirm_pairing(&pairing, true).await;
                break;
            }
        }
    });
    let invite = server
        .node
        .server_invite()
        .await
        .map_err(|_| LoadError("no server invite"))?;
    api.accept_invite(&invite.qr, None).await?;
    let _ = tokio::time::timeout(Duration::from_secs(60), answer).await;
    match tokio::time::timeout(Duration::from_secs(60), invite.adopted).await {
        Ok(Ok(Ok(()))) => {}
        _ => return Err(LoadError("the server was not adopted")),
    }
    server.node.shutdown().await;
    let started = Instant::now();
    let reopened = reopen_as(&server.dir, &server.keystore, &server_spec)
        .await
        .map_err(|_| LoadError("the server did not reopen"))?;
    drop(std::mem::replace(&mut server.node, reopened));
    wait(Duration::from_secs(3600), || async {
        ids.iter().all(|a| server.node.leads(a))
    })
    .await?;
    let took = started.elapsed();
    let reader = server.node.api();
    wait(Duration::from_secs(3600), || async {
        placed(&*reader).await >= total
    })
    .await?;
    let messages = placed(&*reader).await;
    desktop.node.shutdown().await;
    server.node.shutdown().await;
    Ok(HandedOver {
        accounts,
        took,
        rate: accounts as f64 / took.as_secs_f64().max(0.001),
        messages,
    })
}
