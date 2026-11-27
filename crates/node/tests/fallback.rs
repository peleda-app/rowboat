//! When the group's server is silent (GROUP.md, "When the server is silent"; question 70): the
//! devices take its accounts over after the takeover delay (at once on its signed leaving
//! notice) under a fallback arbiter, the server catches up and takes them back when it returns,
//! a server that was only cut off loses the journal it kept writing, a flapping server does not
//! bounce leases, and a device cannot use any of this to take an account from a live server.

mod common;

use std::sync::Arc;

use baton_lease::NodeClass;
use futures::StreamExt;
use rowboat_api::*;
use rowboat_endpoint::Endpoints;
use rowboat_endpoint_memory::MemoryEndpoints;
use rowboat_node::testing::{FakeProviders, Spec, TestNode, group_timing, reopen_as, test_node_as};
use rowboat_sync::GrantKind;
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
    reopen(t, spec).await;
}

async fn reopen(t: &mut TestNode, spec: &Spec) {
    let node = reopen_as(&t.dir, &t.keystore, spec).await.unwrap();
    let old = std::mem::replace(&mut t.node, node);
    drop(old);
}

async fn adopt(device: &TestNode, server: &mut TestNode, spec: &Spec) {
    let answer = confirm_next(device);
    let invite = server.node.server_invite().await.unwrap();
    device
        .node
        .api()
        .accept_invite(&invite.qr, None)
        .await
        .unwrap();
    answer.await.unwrap();
    within("the adoption", invite.adopted)
        .await
        .unwrap()
        .unwrap();
    rebuild(server, spec).await;
}

async fn join(inviter: &TestNode, joiner: &mut TestNode, spec: &Spec) {
    let answer = confirm_next(inviter);
    let invite = inviter.node.api().create_invite().await.unwrap();
    joiner
        .node
        .api()
        .accept_invite(&invite.qr, None)
        .await
        .unwrap();
    answer.await.unwrap();
    rebuild(joiner, spec).await;
}

async fn count(api: &dyn NodeApi, account: &AccountId) -> usize {
    list(api, account).await.len()
}

async fn list(api: &dyn NodeApi, account: &AccountId) -> Vec<Envelope> {
    api.list_messages(ListQuery {
        scope: Scope::All {
            account: Some(account.clone()),
        },
        unread_only: false,
        cursor: None,
        limit: 200,
    })
    .await
    .map(|p| p.items)
    .unwrap_or_default()
}

async fn shows(t: &TestNode, account: &AccountId, n: usize) {
    let api = t.node.api();
    let what = format!("{n} messages to show on {}", t.node.node_id());
    until(&what, || async { count(&*api, account).await >= n }).await;
}

async fn leads(t: &TestNode, account: &AccountId) {
    let what = format!("{} to lead", t.node.node_id());
    until(&what, || async { t.node.leads(account) }).await;
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

fn key(t: &TestNode) -> baton_identity::PublicKey {
    baton_identity::PublicKey::from_node_id(&baton_core::NodeId::new(t.node.node_id()).unwrap())
        .unwrap()
}

/// A device of `class` that adds an account and adopts a server, which then leads the account.
struct Pair {
    memory: MemoryEndpoints,
    fakes: FakeProviders,
    device: TestNode,
    server: TestNode,
    device_spec: Spec,
    server_spec: Spec,
    account: AccountId,
}

async fn pair(class: NodeClass) -> Pair {
    pair_timed(class, group_timing()).await
}

async fn pair_timed(class: NodeClass, timing: rowboat_node::TestTiming) -> Pair {
    let memory = MemoryEndpoints::new();
    let endpoints: Arc<dyn Endpoints> = Arc::new(memory.clone());
    let fakes = FakeProviders::new();
    let device_spec = Spec {
        timing,
        ..spec(class, &fakes, &endpoints)
    };
    let server_spec = Spec {
        timing,
        ..spec(NodeClass::Server, &fakes, &endpoints)
    };
    let device = test_node_as(&device_spec).await.unwrap();
    seed(&device, "ada", "INBOX", 3).await;
    let account = add(&device, "ada").await;
    shows(&device, &account, 3).await;
    let mut server = test_node_as(&server_spec).await.unwrap();
    adopt(&device, &mut server, &server_spec).await;
    leads(&server, &account).await;
    until("the device to let go", || async {
        !device.node.leads(&account)
    })
    .await;
    until("the device to hold the server's state", || async {
        device.node.holds_offer_for_tests(&account).await
    })
    .await;
    assert_eq!(
        server.node.grant_for_tests(&account).await,
        Some(GrantKind::Server),
        "the server's head carries its own grant"
    );
    Pair {
        memory,
        fakes,
        device,
        server,
        device_spec,
        server_spec,
        account,
    }
}

/// The server leads again, its journal continuing the device's, and the device follows it.
async fn server_takes_back(p: &Pair, fallback_fence: u64) {
    leads(&p.server, &p.account).await;
    until("the device to let go", || async {
        !p.device.node.leads(&p.account)
    })
    .await;
    until("the server to write under its own grant", || async {
        p.server.node.grant_for_tests(&p.account).await == Some(GrantKind::Server)
            && p.server.node.head_for_tests(&p.account).await.1 > fallback_fence
    })
    .await;
    until("the device to follow the server", || async {
        p.device.node.head_for_tests(&p.account).await
            == p.server.node.head_for_tests(&p.account).await
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stopped_server_hands_its_accounts_to_the_desktop_and_takes_them_back() {
    log();
    let mut p = pair(NodeClass::Desktop).await;
    let (_, server_fence, _) = p.server.node.head_for_tests(&p.account).await;
    p.server.node.kill_for_tests().await;

    leads(&p.device, &p.account).await;
    assert_eq!(p.device.node.fallback_for_tests(), Some("silence"));
    assert!(p.device.node.under_fallback_arbiter_for_tests());
    add_mail(&p.fakes, "ada", 3, 2).await;
    shows(&p.device, &p.account, 5).await;
    until("the desktop to write under its fallback grant", || async {
        p.device.node.grant_for_tests(&p.account).await == Some(GrantKind::Fallback)
    })
    .await;
    let (_, fallback_fence, _) = p.device.node.head_for_tests(&p.account).await;
    assert!(
        fallback_fence > server_fence,
        "fences continue across arbiters"
    );

    let spec = p.server_spec.clone();
    reopen(&mut p.server, &spec).await;
    server_takes_back(&p, fallback_fence).await;
    shows(&p.server, &p.account, 5).await;
    add_mail(&p.fakes, "ada", 5, 1).await;
    shows(&p.device, &p.account, 6).await;
    assert_eq!(p.device.node.fallback_for_tests(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_graceful_shutdown_hands_over_at_once() {
    log();
    let mut p = pair(NodeClass::Desktop).await;
    p.server.node.set_can_run(false);
    leads(&p.device, &p.account).await;
    p.server.node.announce_leaving().await;
    p.server.node.shutdown().await;

    until("the desktop to take over on the notice", || async {
        p.device.node.fallback_for_tests().is_some()
    })
    .await;
    assert_eq!(
        p.device.node.fallback_for_tests(),
        Some("leaving"),
        "the notice, not the takeover delay, started the fallback"
    );
    leads(&p.device, &p.account).await;
    add_mail(&p.fakes, "ada", 3, 2).await;
    shows(&p.device, &p.account, 5).await;
    until("the desktop to write under its fallback grant", || async {
        p.device.node.grant_for_tests(&p.account).await == Some(GrantKind::Fallback)
    })
    .await;
    let (_, fallback_fence, _) = p.device.node.head_for_tests(&p.account).await;

    let spec = p.server_spec.clone();
    reopen(&mut p.server, &spec).await;
    server_takes_back(&p, fallback_fence).await;
    shows(&p.server, &p.account, 5).await;
}

/// The server is cut off from every device but keeps running and leading: it keeps fetching
/// (new mail, a flag changed at the provider) into a journal nobody else sees, while the desktop
/// takes over, sends a message and fetches too. Once the partition heals the desktop's journal
/// wins, the server drops its own tail and follows it, the message went out once, and what the
/// server had journaled is in the desktop's journal too, observed again at the provider.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cut_off_server_that_kept_fetching_loses_its_tail_and_nothing_is_sent_twice() {
    log();
    let p = pair(NodeClass::Desktop).await;
    let hub = p.memory.hub();
    hub.partition(&[&[key(&p.server)], &[key(&p.device)]]);

    let server_api = p.server.node.api();
    let first = list(&*server_api, &p.account)
        .await
        .into_iter()
        .find(|m| m.subject.as_deref() == Some("Note 0 for ada"))
        .unwrap();
    assert!(first.unread);
    p.fakes
        .server("ada")
        .set_flags(
            "INBOX",
            &message(0, "Note 0 for ada"),
            skein_core::Flags::new(["\\Seen"]),
        )
        .await;
    until("the cut-off server to fetch the flag change", || async {
        list(&*server_api, &p.account)
            .await
            .iter()
            .any(|m| m.id == first.id && !m.unread)
    })
    .await;
    add_mail(&p.fakes, "ada", 3, 1).await;
    shows(&p.server, &p.account, 4).await;
    let (_, server_fence, _) = p.server.node.head_for_tests(&p.account).await;
    assert!(
        p.server.node.leads(&p.account),
        "cut off, the server still leads"
    );

    leads(&p.device, &p.account).await;
    assert_eq!(p.device.node.fallback_for_tests(), Some("silence"));
    shows(&p.device, &p.account, 4).await;
    let device_api = p.device.node.api();
    until("the Sent mailbox", || async {
        device_api
            .list_mailboxes(&p.account)
            .await
            .unwrap_or_default()
            .iter()
            .any(|m| m.role == Some(MailboxRole::Sent))
    })
    .await;
    let mut events = device_api.events();
    let sent = device_api
        .send(Draft {
            id: None,
            account: p.account.clone(),
            to: vec![Recipient {
                name: None,
                address: EmailAddress::new("sam@example.org").unwrap(),
            }],
            cc: vec![],
            bcc: vec![],
            subject: "While the server was away".into(),
            text: "Sent once.".into(),
            reply: None,
            attachments: vec![],
        })
        .await
        .unwrap();
    let outcome = within("the send to settle", async {
        while let Some(e) = events.next().await {
            if let NodeEvent::SendSettled {
                command, outcome, ..
            } = e
                && command == sent.command
                && !matches!(outcome, SendOutcome::Waiting { .. })
            {
                return outcome;
            }
        }
        panic!("events ended");
    })
    .await;
    assert_eq!(outcome, SendOutcome::Sent { refused: 0 });
    until("the desktop to write under its fallback grant", || async {
        p.device.node.grant_for_tests(&p.account).await == Some(GrantKind::Fallback)
    })
    .await;
    let (_, fallback_fence, _) = p.device.node.head_for_tests(&p.account).await;
    assert!(fallback_fence > server_fence);

    hub.heal();
    server_takes_back(&p, fallback_fence).await;
    assert_eq!(
        p.fakes.sender().deliveries().len(),
        1,
        "the message went out once, though both nodes held the account"
    );
    shows(&p.device, &p.account, 4).await;
    until(
        "the server's flag change to converge on the desktop",
        || async {
            list(&*device_api, &p.account)
                .await
                .iter()
                .any(|m| m.id == first.id && !m.unread)
        },
    )
    .await;
    add_mail(&p.fakes, "ada", 4, 1).await;
    shows(&p.device, &p.account, 5).await;
    assert_eq!(p.fakes.sender().deliveries().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_flapping_server_does_not_bounce_leases() {
    log();
    let p = pair(NodeClass::Desktop).await;
    let hub = p.memory.hub();
    let cut = || hub.partition(&[&[key(&p.server)], &[key(&p.device)]]);
    cut();
    leads(&p.device, &p.account).await;
    until("the desktop to write under its fallback grant", || async {
        p.device.node.grant_for_tests(&p.account).await == Some(GrantKind::Fallback)
    })
    .await;
    let held = p.device.node.head_for_tests(&p.account).await.1;
    for _ in 0..4 {
        hub.heal();
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        cut();
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        assert!(
            p.device.node.fallback_for_tests().is_some(),
            "a server that answers for less than the return delay is not trusted"
        );
        assert!(p.device.node.leads(&p.account));
        assert_eq!(
            p.device.node.head_for_tests(&p.account).await.1,
            held,
            "the lease never moved"
        );
    }
    hub.heal();
    server_takes_back(&p, held).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_phone_alone_with_a_server_takes_over_and_gives_back() {
    log();
    let mut p = pair(NodeClass::Phone).await;
    p.server.node.kill_for_tests().await;
    leads(&p.device, &p.account).await;
    add_mail(&p.fakes, "ada", 3, 1).await;
    shows(&p.device, &p.account, 4).await;
    until("the phone to write under its fallback grant", || async {
        p.device.node.grant_for_tests(&p.account).await == Some(GrantKind::Fallback)
    })
    .await;
    let (_, fallback_fence, _) = p.device.node.head_for_tests(&p.account).await;
    let spec = p.server_spec.clone();
    reopen(&mut p.server, &spec).await;
    server_takes_back(&p, fallback_fence).await;
}

/// Attack: a leaving notice that is forged, or genuine but replayed while the server still
/// answers, never moves an account.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forged_or_replayed_leaving_notice_changes_nothing() {
    log();
    let p = pair(NodeClass::Desktop).await;
    let to = p.device.node.node_id().to_owned();
    let stranger = baton_identity::Identity::generate();
    let forged = p.server.node.leaving_notice_for_tests(Some(&stranger));
    p.server.node.send_leaving_for_tests(&to, &forged).await;
    let by_device = p.device.node.leaving_notice_for_tests(None);
    p.server.node.send_leaving_for_tests(&to, &by_device).await;
    let genuine = p.server.node.leaving_notice_for_tests(None);
    assert!(
        p.server.node.send_leaving_for_tests(&to, &genuine).await,
        "the device reads the notice"
    );
    for _ in 0..4 {
        tokio::time::sleep(group_timing().heartbeat).await;
        assert_eq!(
            p.device.node.fallback_for_tests(),
            None,
            "the server still answers: the notice is not believed"
        );
        assert!(!p.device.node.leads(&p.account));
        assert!(!p.device.node.under_fallback_arbiter_for_tests());
    }
    leads(&p.server, &p.account).await;
    assert_eq!(
        p.server.node.grant_for_tests(&p.account).await,
        Some(GrantKind::Server)
    );
}

/// Attack: a desktop that claims the server is silent while the server and the other desktop
/// still reach it arbitrates for itself and writes under its own fallback grant, but neither the
/// server nor the other desktop follows it, the server keeps the account, and once the desktop
/// stops claiming, it drops its journal and follows the server's again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_claiming_the_server_is_silent_cannot_take_over() {
    log();
    let p = pair(NodeClass::Desktop).await;
    let mut liar = test_node_as(&p.device_spec).await.unwrap();
    join(&p.device, &mut liar, &p.device_spec).await;
    until("the liar to hold the server's state", || async {
        liar.node.holds_offer_for_tests(&p.account).await
    })
    .await;
    let honest_head = p.server.node.head_for_tests(&p.account).await;

    liar.node.force_fallback_for_tests(true);
    leads(&liar, &p.account).await;
    until("the liar to write under its own fallback grant", || async {
        liar.node.grant_for_tests(&p.account).await == Some(GrantKind::Fallback)
    })
    .await;
    let lie = liar.node.head_for_tests(&p.account).await;
    assert!(
        lie.1 > honest_head.1,
        "its fence is higher than the server's"
    );
    let wire = liar.node.wire_head_for_tests(&p.account).await;
    p.server
        .node
        .hear_for_tests(liar.node.node_id(), wire.clone())
        .await;
    p.device
        .node
        .hear_for_tests(liar.node.node_id(), wire)
        .await;
    add_mail(&p.fakes, "ada", 3, 1).await;
    shows(&p.server, &p.account, 4).await;
    shows(&p.device, &p.account, 4).await;
    assert!(
        p.server.node.leads(&p.account),
        "the live server keeps its lease"
    );
    assert!(!p.server.node.yields_for_tests(&p.account));
    assert!(!p.device.node.yields_for_tests(&p.account));
    assert_ne!(
        p.server.node.head_for_tests(&p.account).await,
        lie,
        "the server never followed the liar's journal"
    );
    assert_eq!(
        p.server.node.grant_for_tests(&p.account).await,
        Some(GrantKind::Server)
    );
    until("the other desktop to follow the server only", || async {
        p.device.node.head_for_tests(&p.account).await
            == p.server.node.head_for_tests(&p.account).await
    })
    .await;

    liar.node.force_fallback_for_tests(false);
    until(
        "the liar to give its journal up and follow the server",
        || async {
            liar.node.head_for_tests(&p.account).await
                == p.server.node.head_for_tests(&p.account).await
        },
    )
    .await;
    assert!(p.server.node.leads(&p.account));
}

/// Attack: after the server took the account back, the desktop's fallback head (with its grant)
/// replayed to the server or followed again is refused: its grant pins it to the old fence.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replayed_fallback_grant_is_refused() {
    log();
    let mut p = pair(NodeClass::Desktop).await;
    p.server.node.kill_for_tests().await;
    leads(&p.device, &p.account).await;
    until("the desktop to write under its fallback grant", || async {
        p.device.node.grant_for_tests(&p.account).await == Some(GrantKind::Fallback)
    })
    .await;
    let old = p.device.node.wire_head_for_tests(&p.account).await;
    let (_, fallback_fence, _) = p.device.node.head_for_tests(&p.account).await;
    let spec = p.server_spec.clone();
    reopen(&mut p.server, &spec).await;
    server_takes_back(&p, fallback_fence).await;

    let before = p.server.node.head_for_tests(&p.account).await;
    p.server
        .node
        .hear_for_tests(p.device.node.node_id(), old.clone())
        .await;
    p.device
        .node
        .hear_for_tests(p.server.node.node_id(), old)
        .await;
    assert!(p.server.node.leads(&p.account));
    assert!(!p.server.node.yields_for_tests(&p.account));
    let after = p.server.node.head_for_tests(&p.account).await;
    assert!(
        after.1 >= before.1 && after.0 >= before.0,
        "nothing went back"
    );
    assert_eq!(
        p.server.node.grant_for_tests(&p.account).await,
        Some(GrantKind::Server)
    );
}

/// A send the server queued (and tried once, refused for now) when it went silent: the desktop
/// that takes over cannot know whether the server, perhaps only cut off, sent it since, so it is
/// reported uncertain and never sent by the desktop.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_send_queued_on_a_silent_server_is_uncertain_never_repeated() {
    queued_send_is_never_repeated(false).await;
}

/// Regression: a server whose hand-back did not finish (a worker still runs a send) asks to
/// announce its leave anyway; no notice goes out, the devices fall back by silence and the send
/// stays uncertain instead of being repeated under the leaving reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_send_started_before_an_unfinished_hand_back_is_not_repeated() {
    queued_send_is_never_repeated(true).await;
}

async fn queued_send_is_never_repeated(announce: bool) {
    log();
    let p = pair(NodeClass::Desktop).await;
    let device_api = p.device.node.api();
    until("the Sent mailbox", || async {
        device_api
            .list_mailboxes(&p.account)
            .await
            .unwrap_or_default()
            .iter()
            .any(|m| m.role == Some(MailboxRole::Sent))
    })
    .await;
    p.fakes
        .sender()
        .script(Err(skein_send::SendError::Throttled {
            retry_after: Some(std::time::Duration::from_secs(40)),
        }));
    let mut events = device_api.events();
    let sent = device_api
        .send(Draft {
            id: None,
            account: p.account.clone(),
            to: vec![Recipient {
                name: None,
                address: EmailAddress::new("sam@example.org").unwrap(),
            }],
            cc: vec![],
            bcc: vec![],
            subject: "Queued on the server".into(),
            text: "Never twice.".into(),
            reply: None,
            attachments: vec![],
        })
        .await
        .unwrap();
    until("the server to try it once", || async {
        p.fakes.sender().calls() == 1
    })
    .await;
    add_mail(&p.fakes, "ada", 3, 1).await;
    shows(&p.server, &p.account, 4).await;
    until("the desktop to hold the server's newest state", || async {
        let (seq, fence, _) = p.server.node.head_for_tests(&p.account).await;
        p.device.node.offer_head_for_tests(&p.account).await == Some((seq, fence))
    })
    .await;
    if announce {
        assert!(
            !p.server.node.announce_leaving().await,
            "a server that still leads sends no leaving notice"
        );
    }
    p.server.node.kill_for_tests().await;

    leads(&p.device, &p.account).await;
    if announce {
        assert_eq!(p.device.node.fallback_for_tests(), Some("silence"));
    }
    let outcome = within("the send to settle", async {
        while let Some(e) = events.next().await {
            if let NodeEvent::SendSettled {
                command, outcome, ..
            } = e
                && command == sent.command
                && !matches!(outcome, SendOutcome::Waiting { .. })
            {
                return outcome;
            }
        }
        panic!("events ended");
    })
    .await;
    assert_eq!(outcome, SendOutcome::Uncertain);
    assert!(
        p.fakes.sender().deliveries().is_empty(),
        "the desktop never sent what the silent server may have sent"
    );
    assert_eq!(p.fakes.sender().calls(), 1);
}

/// Regression: a server that announced its leave never serves leases again, even when its own
/// engine asks for them while it shuts down; the devices stay with their fallback arbiter.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_server_that_announced_leaving_never_serves_leases_again() {
    log();
    let p = pair(NodeClass::Desktop).await;
    p.server.node.set_can_run(false);
    leads(&p.device, &p.account).await;
    assert!(p.server.node.announce_leaving().await);
    until("the desktop to take over on the notice", || async {
        p.device.node.fallback_for_tests() == Some("leaving")
    })
    .await;
    let _ = p.server.node.lease_holder(&p.account).await;
    assert!(
        !p.server.node.serves_leases_for_tests().await,
        "the lease server stays stopped"
    );
    assert_eq!(p.device.node.fallback_for_tests(), Some("leaving"));
}

/// Regression, attack: the server was down for less than the takeover delay, so no device fell
/// back; a device that then claims the server is silent cannot use the gap the outage left in
/// every device's heartbeats to make the server follow its journal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_a_short_server_outage_a_device_claiming_silence_cannot_take_over() {
    log();
    let mut p = pair(NodeClass::Desktop).await;
    let mut liar = test_node_as(&p.device_spec).await.unwrap();
    join(&p.device, &mut liar, &p.device_spec).await;
    until("the liar to hold the server's state", || async {
        liar.node.holds_offer_for_tests(&p.account).await
    })
    .await;
    p.server.node.kill_for_tests().await;
    tokio::time::sleep(std::time::Duration::from_secs(11)).await;
    assert_eq!(p.device.node.fallback_for_tests(), None);
    assert_eq!(liar.node.fallback_for_tests(), None);
    let spec = p.server_spec.clone();
    reopen(&mut p.server, &spec).await;
    leads(&p.server, &p.account).await;
    let honest_head = p.server.node.head_for_tests(&p.account).await;

    liar.node.force_fallback_for_tests(true);
    leads(&liar, &p.account).await;
    until("the liar to write under its own fallback grant", || async {
        liar.node.grant_for_tests(&p.account).await == Some(GrantKind::Fallback)
    })
    .await;
    let lie = liar.node.head_for_tests(&p.account).await;
    assert!(lie.1 > honest_head.1);
    let wire = liar.node.wire_head_for_tests(&p.account).await;
    p.server
        .node
        .hear_for_tests(liar.node.node_id(), wire)
        .await;
    assert!(
        !p.server.node.yields_for_tests(&p.account),
        "a live server never yields to a device that claimed it was silent"
    );
    assert!(p.server.node.leads(&p.account));
    assert_ne!(p.server.node.head_for_tests(&p.account).await, lie);
}

/// Attack: a device that just joined holds no journal of the account yet, and the server sees
/// it; a head another device wrote under its own fallback grant while claiming the server is
/// silent is not followed, and the new device follows the server.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_device_never_follows_a_false_fallback_head_while_the_server_answers() {
    log();
    let p = pair(NodeClass::Desktop).await;
    let mut liar = test_node_as(&p.device_spec).await.unwrap();
    join(&p.device, &mut liar, &p.device_spec).await;
    until("the liar to hold the server's state", || async {
        liar.node.holds_offer_for_tests(&p.account).await
    })
    .await;
    liar.node.force_fallback_for_tests(true);
    leads(&liar, &p.account).await;
    until("the liar to write under its own fallback grant", || async {
        liar.node.grant_for_tests(&p.account).await == Some(GrantKind::Fallback)
    })
    .await;
    let lie = liar.node.head_for_tests(&p.account).await;
    let wire = liar.node.wire_head_for_tests(&p.account).await;

    let mut fresh = test_node_as(&p.device_spec).await.unwrap();
    join(&p.device, &mut fresh, &p.device_spec).await;
    fresh.node.hear_for_tests(liar.node.node_id(), wire).await;
    assert!(!fresh.node.yields_for_tests(&p.account));
    add_mail(&p.fakes, "ada", 3, 1).await;
    shows(&p.server, &p.account, 4).await;
    until("the new device to follow the server", || async {
        fresh.node.has_head_for_tests(&p.account).await
            && fresh.node.head_for_tests(&p.account).await
                == p.server.node.head_for_tests(&p.account).await
    })
    .await;
    assert_ne!(fresh.node.head_for_tests(&p.account).await, lie);
}

/// Production's ratios: the devices go back to the server only well after its lease server
/// grants again (the return delay is longer than a time-to-live), and no node asks its peers
/// for heads on its rounds (production does so every five minutes, and only when it can dial
/// them). The desktop tells the server of its fallback journal as soon as the server answers,
/// so the server yields instead of leading beside the desktop until the desktop is back, then
/// takes the account back continuing the desktop's journal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_production_timing_a_returning_server_continues_the_fallback_journal() {
    log();
    let takeover = std::time::Duration::from_secs(16);
    let timing = rowboat_node::TestTiming {
        rounds: 0,
        fallback: Some(rowboat_node::FallbackTiming {
            takeover,
            return_after: std::time::Duration::from_secs(24),
        }),
        ..group_timing()
    };
    let mut p = pair_timed(NodeClass::Desktop, timing).await;
    p.server.node.kill_for_tests().await;
    leads(&p.device, &p.account).await;
    add_mail(&p.fakes, "ada", 3, 2).await;
    shows(&p.device, &p.account, 5).await;
    until("the desktop to write under its fallback grant", || async {
        p.device.node.grant_for_tests(&p.account).await == Some(GrantKind::Fallback)
    })
    .await;
    let (fallback_seq, fallback_fence, _) = p.device.node.head_for_tests(&p.account).await;
    let written = p
        .device
        .node
        .event_for_tests(&p.account, fallback_seq)
        .await
        .unwrap();

    let spec = p.server_spec.clone();
    reopen(&mut p.server, &spec).await;
    until("the desktop to go back to the server", || async {
        assert!(
            !(p.server.node.leads(&p.account) && p.device.node.leads(&p.account)),
            "the server never leads while the desktop still holds the account in fallback"
        );
        p.device.node.fallback_for_tests().is_none()
    })
    .await;
    server_takes_back(&p, fallback_fence).await;
    assert_eq!(
        p.server
            .node
            .event_for_tests(&p.account, fallback_seq)
            .await,
        Some(written),
        "the server's journal continues the desktop's"
    );
    shows(&p.server, &p.account, 5).await;
}
