//! Leases across nodes (GROUP.md, wave 2): a server adopted by a desktop takes the desktop's
//! accounts over cooperatively and hands them back, a holder that dies is replaced, a holder cut
//! off by a partition can no longer write anywhere that counts, a revoked node loses its lease and
//! learns of its revocation, and many accounts move at once.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use baton_lease::NodeClass;
use futures::StreamExt;
use rowboat_api::*;
use rowboat_endpoint::Endpoints;
use rowboat_endpoint_memory::MemoryEndpoints;
use rowboat_node::testing::{FakeProviders, Spec, TestNode, group_timing, reopen_as, test_node_as};
use skein_mail::testing::ServerControl;

use common::{add, message, seed, until, within};

fn log() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}

fn spec(class: NodeClass, fakes: &FakeProviders, endpoints: &Arc<dyn Endpoints>) -> Spec {
    Spec {
        class,
        fakes: fakes.clone(),
        endpoints: endpoints.clone(),
        timing: group_timing(),
        on_revoked: None,
    }
}

fn confirm_next(on: &TestNode) -> tokio::task::JoinHandle<()> {
    let api = on.node.api();
    let mut events = api.group_events();
    tokio::spawn(async move {
        while let Some(e) = events.next().await {
            if let GroupEvent::PairingCheck {
                pairing,
                confirm: true,
                ..
            } = e
            {
                let _ = api.confirm_pairing(&pairing, true).await;
                break;
            }
        }
    })
}

async fn rebuild(t: &mut TestNode, spec: &Spec) {
    t.node.shutdown().await;
    let node = reopen_as(&t.dir, &t.keystore, spec).await.unwrap();
    let old = std::mem::replace(&mut t.node, node);
    drop(old);
}

/// `desktop` adopts `server` by the server's first-run invite; the server is rebuilt.
async fn adopt(desktop: &TestNode, server: &mut TestNode, spec: &Spec) {
    let answer = confirm_next(desktop);
    let invite = server.node.server_invite().await.unwrap();
    let r = desktop
        .node
        .api()
        .accept_invite(&invite.qr, None)
        .await
        .unwrap();
    assert!(!r.restart_required);
    answer.await.unwrap();
    within("the adoption", invite.adopted)
        .await
        .unwrap()
        .unwrap();
    rebuild(server, spec).await;
}

/// `joiner` joins `inviter`'s group as a device and is rebuilt.
async fn join(inviter: &TestNode, joiner: &mut TestNode, spec: &Spec) {
    let answer = confirm_next(inviter);
    let invite = inviter.node.api().create_invite().await.unwrap();
    let r = joiner
        .node
        .api()
        .accept_invite(&invite.qr, None)
        .await
        .unwrap();
    assert!(r.restart_required);
    answer.await.unwrap();
    rebuild(joiner, spec).await;
}

async fn count(api: &dyn NodeApi, account: &AccountId) -> usize {
    api.list_messages(ListQuery {
        scope: Scope::All {
            account: Some(account.clone()),
        },
        unread_only: false,
        cursor: None,
        limit: 200,
    })
    .await
    .map(|p| p.items.len())
    .unwrap_or(0)
}

async fn shows(t: &TestNode, account: &AccountId, n: usize) {
    let api = t.node.api();
    let what = format!("{n} messages to show on {}", t.node.node_id());
    until(&what, || async { count(&*api, account).await >= n }).await;
}

async fn leads(t: &TestNode, account: &AccountId) {
    until("the lease", || async { t.node.leads(account) }).await;
}

async fn add_mail(fakes: &FakeProviders, user: &str, from: usize, n: usize) {
    let server = fakes.server(user);
    for i in from..from + n {
        server
            .add(
                "INBOX",
                &message(i, &format!("Note {i}")),
                Default::default(),
            )
            .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_account_moves_to_the_server_and_back() {
    log();
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let fakes = FakeProviders::new();
    let desktop_spec = spec(NodeClass::Desktop, &fakes, &endpoints);
    let server_spec = spec(NodeClass::Server, &fakes, &endpoints);
    let desktop = test_node_as(&desktop_spec).await.unwrap();
    seed(&desktop, "ada", "INBOX", 3).await;
    let account = add(&desktop, "ada").await;
    shows(&desktop, &account, 3).await;
    assert!(desktop.node.leads(&account));
    let (_, before, _) = desktop.node.head_for_tests(&account).await;

    let mut server = test_node_as(&server_spec).await.unwrap();
    adopt(&desktop, &mut server, &server_spec).await;
    leads(&server, &account).await;
    until("the desktop to let go", || async {
        !desktop.node.leads(&account)
    })
    .await;
    shows(&server, &account, 3).await;
    add_mail(&fakes, "ada", 3, 2).await;
    shows(&server, &account, 5).await;
    shows(&desktop, &account, 5).await;
    let (seq, fence, digest) = server.node.head_for_tests(&account).await;
    assert!(fence > before, "the server continues under a higher token");
    until("the desktop's replica", || async {
        desktop.node.head_for_tests(&account).await == (seq, fence, digest)
    })
    .await;

    let api = desktop.node.api();
    let mut events = api.events();
    let first = api
        .list_messages(ListQuery {
            scope: Scope::All {
                account: Some(account.clone()),
            },
            unread_only: false,
            cursor: None,
            limit: 1,
        })
        .await
        .unwrap()
        .items[0]
        .clone();
    let queued = api
        .set_read(
            Targets(vec![MessageRef {
                account: account.clone(),
                message: first.id.clone(),
            }]),
            true,
        )
        .await
        .unwrap();
    let command = queued.commands[0].clone();
    let outcome = within("the command from the desktop", async {
        while let Some(e) = events.next().await {
            if let NodeEvent::CommandSettled {
                command: c,
                outcome,
                ..
            } = e
                && c == command
            {
                return outcome;
            }
        }
        panic!("events ended")
    })
    .await;
    assert_eq!(outcome, CommandOutcome::Applied, "the server ran it");

    server.node.set_can_run(false);
    leads(&desktop, &account).await;
    until("the server to let go", || async {
        !server.node.leads(&account)
    })
    .await;
    add_mail(&fakes, "ada", 5, 1).await;
    shows(&desktop, &account, 6).await;
    shows(&server, &account, 6).await;
    let (_, back, _) = desktop.node.head_for_tests(&account).await;
    assert!(back > fence);
    for t in [&desktop, &server] {
        assert_eq!(
            count(&*t.node.api(), &account).await,
            6,
            "nothing was lost or doubled across the handovers"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_account_the_server_may_not_lead_stays_on_the_desktop() {
    log();
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let fakes = FakeProviders::new();
    let desktop_spec = spec(NodeClass::Desktop, &fakes, &endpoints);
    let server_spec = spec(NodeClass::Server, &fakes, &endpoints);
    let desktop = test_node_as(&desktop_spec).await.unwrap();
    let mut server = test_node_as(&server_spec).await.unwrap();
    adopt(&desktop, &mut server, &server_spec).await;
    seed(&desktop, "bea", "INBOX", 2).await;
    let account = add(&desktop, "bea").await;
    leads(&desktop, &account).await;
    shows(&desktop, &account, 2).await;
    add_mail(&fakes, "bea", 2, 1).await;
    shows(&desktop, &account, 3).await;
    assert!(
        !server.node.leads(&account),
        "a stronger node without lead on the account never takes it"
    );
}

struct Trio {
    fakes: FakeProviders,
    memory: MemoryEndpoints,
    server: TestNode,
    first: TestNode,
    second: TestNode,
    account: AccountId,
}

/// A server that does not lead (the arbiter only) and two desktops: `first` is the one the
/// lease went to (the weighted choice among equals), `second` follows it.
async fn trio(revoked: Option<rowboat_node::RevokedHook>) -> Trio {
    let memory = MemoryEndpoints::new();
    let endpoints: Arc<dyn Endpoints> = Arc::new(memory.clone());
    let fakes = FakeProviders::new();
    let mut desktop_spec = spec(NodeClass::Desktop, &fakes, &endpoints);
    desktop_spec.on_revoked = revoked;
    let server_spec = spec(NodeClass::Server, &fakes, &endpoints);
    let first = test_node_as(&desktop_spec).await.unwrap();
    seed(&first, "cai", "INBOX", 3).await;
    let account = add(&first, "cai").await;
    shows(&first, &account, 3).await;
    let mut server = test_node_as(&server_spec).await.unwrap();
    adopt(&first, &mut server, &server_spec).await;
    server.node.set_can_run(false);
    let mut second = test_node_as(&desktop_spec).await.unwrap();
    join(&first, &mut second, &desktop_spec).await;
    shows(&second, &account, 3).await;
    until("one desktop to lead", || async {
        first.node.leads(&account) || second.node.leads(&account)
    })
    .await;
    let (first, second) = if first.node.leads(&account) {
        (first, second)
    } else {
        (second, first)
    };
    until("the follower to hold the holder's journal", || async {
        second.node.head_for_tests(&account).await == first.node.head_for_tests(&account).await
    })
    .await;
    until("the follower to hold the holder's state", || async {
        second.node.holds_offer_for_tests(&account).await
    })
    .await;
    Trio {
        fakes,
        memory,
        server,
        first,
        second,
        account,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_holder_killed_mid_sync_is_replaced_after_its_lease_expires() {
    log();
    let t = trio(None).await;
    let (_, old, _) = t.first.node.head_for_tests(&t.account).await;
    let fake = t.fakes.server("cai");
    let hold = fake.hold();
    add_mail(&t.fakes, "cai", 3, 2).await;
    let api = t.first.node.api();
    until("the holder inside a session", || async {
        let _ = api.sync_now(Some(&t.account)).await;
        fake.waiting() > 0
    })
    .await;
    t.first.node.kill_for_tests().await;
    drop(hold);
    leads(&t.second, &t.account).await;
    shows(&t.second, &t.account, 5).await;
    shows(&t.server, &t.account, 5).await;
    let (_, fence, _) = t.second.node.head_for_tests(&t.account).await;
    assert!(fence > old);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_partitioned_holder_that_still_writes_is_refused_everywhere() {
    log();
    let t = trio(None).await;
    let (_, stale_fence, _) = t.first.node.head_for_tests(&t.account).await;
    let ids = [
        t.first.node.node_id(),
        t.second.node.node_id(),
        t.server.node.node_id(),
    ];
    let key = |id: &str| {
        baton_identity::PublicKey::from_node_id(&baton_core::NodeId::new(id).unwrap()).unwrap()
    };
    let hub = t.memory.hub();
    hub.partition(&[&[key(ids[0])], &[key(ids[1]), key(ids[2])]]);

    t.first
        .node
        .write_for_tests(&t.account, 2, Some(stale_fence))
        .await
        .expect("cut off, the old holder still writes its own journal");
    leads(&t.second, &t.account).await;
    add_mail(&t.fakes, "cai", 3, 2).await;
    shows(&t.second, &t.account, 5).await;
    let (seq, fence, digest) = t.second.node.head_for_tests(&t.account).await;
    assert!(fence > stale_fence);
    until("the server's replica of the new holder", || async {
        t.server.node.head_for_tests(&t.account).await == (seq, fence, digest)
    })
    .await;

    hub.heal();
    until("the old holder to follow the new one", || async {
        let (_, f, _) = t.first.node.head_for_tests(&t.account).await;
        f >= fence
    })
    .await;
    assert!(!t.first.node.leads(&t.account));
    shows(&t.first, &t.account, 5).await;
    let now = t.second.node.head_for_tests(&t.account).await;
    until(
        "the old holder's journal equals the new holder's",
        || async {
            t.first.node.head_for_tests(&t.account).await
                == t.second.node.head_for_tests(&t.account).await
        },
    )
    .await;
    assert!(now.1 > stale_fence);
    assert!(
        t.first
            .node
            .write_for_tests(&t.account, 1, Some(stale_fence))
            .await
            .is_err(),
        "once it saw the higher token its own storage refuses the old one"
    );
    let server_head = t.server.node.head_for_tests(&t.account).await;
    assert!(
        server_head.1 >= fence,
        "the stale writes never reached the server"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_holder_loses_its_lease_and_learns_why() {
    log();
    let fired = Arc::new(AtomicUsize::new(0));
    let hook = {
        let fired = fired.clone();
        Arc::new(move || {
            fired.fetch_add(1, Ordering::SeqCst);
        }) as rowboat_node::RevokedHook
    };
    let t = trio(Some(hook)).await;
    t.second
        .node
        .api()
        .revoke_node(t.first.node.node_id())
        .await
        .unwrap();
    leads(&t.second, &t.account).await;
    add_mail(&t.fakes, "cai", 3, 1).await;
    shows(&t.second, &t.account, 4).await;
    until("the revocation notice", || async {
        fired.load(Ordering::SeqCst) > 0
    })
    .await;
    until("the revoked node to stop leading", || async {
        !t.first.node.leads(&t.account)
    })
    .await;
    assert_eq!(fired.load(Ordering::SeqCst), 1, "the hook runs once");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_accounts_move_to_the_server_at_once() {
    log();
    const ACCOUNTS: usize = 12;
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let fakes = FakeProviders::new();
    let desktop_spec = spec(NodeClass::Desktop, &fakes, &endpoints);
    let server_spec = spec(NodeClass::Server, &fakes, &endpoints);
    let desktop = test_node_as(&desktop_spec).await.unwrap();
    let mut accounts = Vec::new();
    for i in 0..ACCOUNTS {
        let user = format!("user{i}");
        seed(&desktop, &user, "INBOX", 2).await;
        accounts.push((user.clone(), add(&desktop, &user).await));
    }
    for (_, a) in &accounts {
        shows(&desktop, a, 2).await;
    }
    let mut server = test_node_as(&server_spec).await.unwrap();
    adopt(&desktop, &mut server, &server_spec).await;
    for (_, a) in &accounts {
        leads(&server, a).await;
    }
    for (user, a) in &accounts {
        add_mail(&fakes, user, 2, 1).await;
        shows(&server, a, 3).await;
        shows(&desktop, a, 3).await;
    }
    for (_, a) in &accounts {
        assert!(!desktop.node.leads(a));
    }
}

/// Regression: a server adopted before the desktop's first sync of a new account never took it,
/// and nobody synced it again. The desktop had no attested head to offer, so the server could
/// not continue, gave each lease back, and the desktop kept deferring to the stronger server.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_server_adopted_before_the_first_sync_still_takes_the_account() {
    log();
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let fakes = FakeProviders::new();
    let desktop_spec = spec(NodeClass::Desktop, &fakes, &endpoints);
    let server_spec = spec(NodeClass::Server, &fakes, &endpoints);
    let desktop = test_node_as(&desktop_spec).await.unwrap();
    seed(&desktop, "eve", "INBOX", 2).await;
    let account = add(&desktop, "eve").await;
    let mut server = test_node_as(&server_spec).await.unwrap();
    adopt(&desktop, &mut server, &server_spec).await;
    leads(&server, &account).await;
    shows(&server, &account, 2).await;
    shows(&desktop, &account, 2).await;
}

/// Waits for `done` while checking that `a` and `b` never lead `account` at once.
async fn never_both<F, Fut>(
    what: &str,
    a: &TestNode,
    b: &TestNode,
    account: &AccountId,
    mut done: F,
) where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    within(what, async {
        loop {
            assert!(
                !(a.node.leads(account) && b.node.leads(account)),
                "{} and {} led the account at once",
                a.node.node_id(),
                b.node.node_id()
            );
            if done().await {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
}

/// Regression (security review): the arbiter is chosen from each node's view of the group log,
/// and a new arbiter knew nothing of the leases the old one granted. A desktop adopting a server
/// while its worker was inside a provider session kept acting under its local lease while the
/// server took the account from its own, empty lease table.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adopting_a_server_while_the_desktop_is_inside_a_run_never_splits_the_lease() {
    log();
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let fakes = FakeProviders::new();
    let desktop_spec = spec(NodeClass::Desktop, &fakes, &endpoints);
    let server_spec = spec(NodeClass::Server, &fakes, &endpoints);
    let desktop = test_node_as(&desktop_spec).await.unwrap();
    seed(&desktop, "ada", "INBOX", 3).await;
    let account = add(&desktop, "ada").await;
    shows(&desktop, &account, 3).await;
    assert!(desktop.node.leads(&account));
    let fake = fakes.server("ada");
    let hold = fake.hold();
    let dapi = desktop.node.api();
    until("the desktop inside a session", || async {
        let _ = dapi.sync_now(Some(&account)).await;
        fake.waiting() >= 1
    })
    .await;

    let mut server = test_node_as(&server_spec).await.unwrap();
    adopt(&desktop, &mut server, &server_spec).await;
    never_both(
        "the desktop to stop acting or the server to lead",
        &desktop,
        &server,
        &account,
        || async { !desktop.node.leads(&account) || server.node.leads(&account) },
    )
    .await;
    drop(hold);
    never_both(
        "the server to lead",
        &desktop,
        &server,
        &account,
        || async { server.node.leads(&account) },
    )
    .await;
    add_mail(&fakes, "ada", 3, 1).await;
    let dapi = desktop.node.api();
    never_both(
        "the new mail on the desktop",
        &desktop,
        &server,
        &account,
        || async { count(&*dapi, &account).await >= 4 },
    )
    .await;
}

/// The same with a second server whose key is lower than the first's: every node moves to the
/// new arbiter, which knew nothing of the first one's leases.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_server_becoming_the_arbiter_never_splits_the_lease() {
    log();
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let fakes = FakeProviders::new();
    let desktop_spec = spec(NodeClass::Desktop, &fakes, &endpoints);
    let server_spec = spec(NodeClass::Server, &fakes, &endpoints);
    let desktop = test_node_as(&desktop_spec).await.unwrap();
    seed(&desktop, "bea", "INBOX", 2).await;
    let account = add(&desktop, "bea").await;
    shows(&desktop, &account, 2).await;
    let key = |t: &TestNode| {
        baton_identity::PublicKey::from_node_id(&baton_core::NodeId::new(t.node.node_id()).unwrap())
            .unwrap()
    };
    let mut one = test_node_as(&server_spec).await.unwrap();
    let mut two = test_node_as(&server_spec).await.unwrap();
    if key(&two) > key(&one) {
        std::mem::swap(&mut one, &mut two);
    }
    adopt(&desktop, &mut one, &server_spec).await;
    leads(&one, &account).await;
    let fake = fakes.server("bea");
    let hold = fake.hold();
    let oapi = one.node.api();
    until("the first server inside a session", || async {
        let _ = oapi.sync_now(Some(&account)).await;
        fake.waiting() >= 1
    })
    .await;

    adopt(&desktop, &mut two, &server_spec).await;
    never_both(
        "the first server to stop acting or the second to lead",
        &one,
        &two,
        &account,
        || async { !one.node.leads(&account) || two.node.leads(&account) },
    )
    .await;
    drop(hold);
    never_both("one server to lead", &one, &two, &account, || async {
        one.node.leads(&account) || two.node.leads(&account)
    })
    .await;
    add_mail(&fakes, "bea", 2, 1).await;
    let dapi = desktop.node.api();
    never_both(
        "the new mail on the desktop",
        &one,
        &two,
        &account,
        || async { count(&*dapi, &account).await >= 3 },
    )
    .await;
}

/// Regression (review): a node that held only an offer of an account it had never been told
/// about (the offering node did not lead it, so described nothing) was not eligible for it, while
/// the offering node deferred to it: nobody led the account again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_server_holding_only_an_offer_still_takes_the_account() {
    log();
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let fakes = FakeProviders::new();
    let desktop_spec = spec(NodeClass::Desktop, &fakes, &endpoints);
    let server_spec = spec(NodeClass::Server, &fakes, &endpoints);
    let desktop = test_node_as(&desktop_spec).await.unwrap();
    seed(&desktop, "fay", "INBOX", 2).await;
    let account = add(&desktop, "fay").await;
    shows(&desktop, &account, 2).await;
    desktop.node.set_can_run(false);
    let mut server = test_node_as(&server_spec).await.unwrap();
    adopt(&desktop, &mut server, &server_spec).await;
    leads(&server, &account).await;
    assert!(!desktop.node.leads(&account));
    add_mail(&fakes, "fay", 2, 1).await;
    shows(&server, &account, 3).await;
    shows(&desktop, &account, 3).await;
}
