//! Nodes forming a group through the node's own surface: pairing by QR, joining with a restart,
//! revocation, and the attacks on pairing a person can meet through the app.

mod common;

use std::sync::Arc;

use futures::StreamExt;
use rowboat_api::{GroupEvent, NodeApi, NodeError};
use rowboat_endpoint::Endpoints;
use rowboat_endpoint_iroh::IrohEndpoints;
use rowboat_endpoint_memory::MemoryEndpoints;
use rowboat_group::invite::Invite;
use rowboat_node::testing::{TestNode, reopen_on, test_node_on};
use rowboat_node::{Clock, ManualClock, SystemClock};

use common::{add, seed, until};

fn system() -> Arc<dyn Clock> {
    Arc::new(SystemClock)
}

/// Answers the first fingerprint check `api` raises that asks for confirmation with `answer`,
/// recording every fingerprint shown until then.
fn answer_checks(api: Arc<dyn NodeApi>, answer: bool) -> Arc<std::sync::Mutex<Vec<String>>> {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let out = seen.clone();
    let mut events = api.group_events();
    tokio::spawn(async move {
        let api = api;
        while let Some(e) = events.next().await {
            if let GroupEvent::PairingCheck {
                pairing,
                fingerprint,
                confirm,
                ..
            } = e
            {
                seen.lock().unwrap().push(fingerprint);
                if confirm {
                    let _ = api.confirm_pairing(&pairing, answer).await;
                    break;
                }
            }
        }
    });
    out
}

/// Records the fingerprints shown, holding only the event stream (never the node).
fn record_checks(mut events: rowboat_api::GroupEventStream) -> Arc<std::sync::Mutex<Vec<String>>> {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let out = seen.clone();
    tokio::spawn(async move {
        while let Some(e) = events.next().await {
            if let GroupEvent::PairingCheck { fingerprint, .. } = e {
                seen.lock().unwrap().push(fingerprint);
                break;
            }
        }
    });
    out
}

async fn restart(t: &mut TestNode, endpoints: &Arc<dyn Endpoints>, clock: Arc<dyn Clock>) {
    t.node.shutdown().await;
    let placeholder = rowboat_node::testing::test_node(0).await.unwrap();
    let old = std::mem::replace(&mut t.node, placeholder.node);
    drop(old);
    t.node = reopen_on(
        &t.dir,
        &t.fakes,
        &t.keystore,
        0,
        clock,
        Some(endpoints.clone()),
    )
    .await
    .unwrap();
}

async fn reopen_plain(t: &mut TestNode) {
    t.node.shutdown().await;
    let placeholder = rowboat_node::testing::test_node(0).await.unwrap();
    let old = std::mem::replace(&mut t.node, placeholder.node);
    drop(old);
    t.node = rowboat_node::testing::reopen(&t.dir, &t.fakes, &t.keystore, 0)
        .await
        .unwrap();
}

async fn pair(
    a: &TestNode,
    b: &mut TestNode,
    endpoints: &Arc<dyn Endpoints>,
) -> (Vec<String>, Vec<String>) {
    let a_seen = answer_checks(a.node.api(), true);
    let b_seen = record_checks(b.node.api().group_events());
    let invite = a.node.api().create_invite().await.unwrap();
    assert!(invite.qr.starts_with("peleda-pair:"));
    let result = b.node.api().accept_invite(&invite.qr, None).await.unwrap();
    let a_info = a.node.api().node_info().await.unwrap();
    assert_eq!(result.group_id, a_info.group_id);
    assert_eq!(result.node_id, a_info.node_id);
    assert!(result.restart_required);
    assert_eq!(
        b.node.api().list_nodes().await.unwrap_err(),
        NodeError::Busy,
        "the old instance answers nothing about groups until it is rebuilt"
    );
    restart(b, endpoints, system()).await;
    let b_info = b.node.api().node_info().await.unwrap();
    assert_eq!(b_info.group_id, a_info.group_id);
    let a_fp = a_seen.lock().unwrap().clone();
    let b_fp = b_seen.lock().unwrap().clone();
    (a_fp, b_fp)
}

async fn two_nodes(endpoints: Arc<dyn Endpoints>) {
    let a = test_node_on(system(), endpoints.clone()).await.unwrap();
    let mut b = test_node_on(system(), endpoints.clone()).await.unwrap();
    let (a_fp, b_fp) = pair(&a, &mut b, &endpoints).await;
    assert_eq!(a_fp.len(), 1);
    assert_eq!(a_fp, b_fp, "both screens showed the same fingerprint");
    for t in [&a, &b] {
        let nodes = t.node.api().list_nodes().await.unwrap();
        assert_eq!(nodes.len(), 2);
        assert!(nodes.iter().all(|n| n.counts && n.class == "desktop"));
    }
    let b_id = b.node.api().node_info().await.unwrap().node_id;
    let a_nodes = a.node.api().list_nodes().await.unwrap();
    let b_row = a_nodes.iter().find(|n| n.node_id == b_id).unwrap();
    assert_eq!(b_row.label.as_deref(), Some("test"));
    a.node.shutdown().await;
    b.node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_nodes_pair_in_memory() {
    two_nodes(Arc::new(MemoryEndpoints::new())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_nodes_pair_over_iroh_on_loopback() {
    two_nodes(Arc::new(IrohEndpoints::loopback())).await;
}

async fn three_nodes(endpoints: Arc<dyn Endpoints>) {
    let a = test_node_on(system(), endpoints.clone()).await.unwrap();
    seed(&a, "ada", "INBOX", 1).await;
    let account = add(&a, "ada").await;
    let mut b = test_node_on(system(), endpoints.clone()).await.unwrap();
    let mut c = test_node_on(system(), endpoints.clone()).await.unwrap();
    pair(&a, &mut b, &endpoints).await;
    pair(&a, &mut c, &endpoints).await;
    let c_id = c.node.api().node_info().await.unwrap().node_id;

    until("the second node to hear of the third", || async {
        b.node
            .api()
            .list_nodes()
            .await
            .unwrap()
            .iter()
            .any(|n| n.node_id == c_id && n.counts)
    })
    .await;

    let revoked = a.node.api().revoke_node(&c_id).await.unwrap();
    assert_eq!(revoked.secrets_rotation_required, vec![account.clone()]);
    until("the second node to hear of the revocation", || async {
        b.node
            .api()
            .list_nodes()
            .await
            .unwrap()
            .iter()
            .any(|n| n.node_id == c_id && n.revoked)
    })
    .await;
    assert_eq!(
        a.node.api().revoke_node(&c_id).await.unwrap_err(),
        NodeError::InvalidInput,
        "revoked twice"
    );

    let invite = a.node.api().create_invite().await.unwrap();
    let again = c.node.api().accept_invite(&invite.qr, None).await;
    assert_eq!(
        again.unwrap_err(),
        NodeError::Busy,
        "a node that is part of a group with other nodes does not join another"
    );
    a.node.api().cancel_invite(&invite.invite).await.unwrap();
    assert!(
        a.node.api().list_accounts().await.unwrap().len() == 1,
        "the owner keeps working"
    );
    for t in [&a, &b, &c] {
        t.node.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_nodes_in_memory() {
    three_nodes(Arc::new(MemoryEndpoints::new())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_nodes_over_iroh_on_loopback() {
    three_nodes(Arc::new(IrohEndpoints::loopback())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tampered_or_expired_invite_is_refused() {
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let clock = ManualClock::at(1_800_000_000_000);
    let a = test_node_on(Arc::new(clock.clone()), endpoints.clone())
        .await
        .unwrap();
    let b = test_node_on(Arc::new(clock.clone()), endpoints.clone())
        .await
        .unwrap();
    answer_checks(a.node.api(), true);

    let invite = a.node.api().create_invite().await.unwrap();
    let real = Invite::from_qr(&invite.qr).unwrap();
    let guessed = Invite::new(
        real.kind,
        real.group.clone(),
        real.inviter,
        real.id,
        [0x5a; 16],
        real.endpoint,
        real.hint.clone(),
        real.expires_at,
    );
    assert_eq!(
        b.node
            .api()
            .accept_invite(&guessed.to_qr(), None)
            .await
            .unwrap_err(),
        NodeError::PairingCodeRejected,
        "a wrong secret"
    );
    assert!(
        matches!(
            b.node.api().accept_invite(&invite.qr, None).await,
            Err(NodeError::PairingCodeRejected | NodeError::PeerUnreachable)
        ),
        "the failed attempt killed the QR invite and closed its endpoint"
    );

    let invite = a.node.api().create_invite().await.unwrap();
    clock.advance(10 * 60 * 1000 + 1);
    assert_eq!(
        b.node
            .api()
            .accept_invite(&invite.qr, None)
            .await
            .unwrap_err(),
        NodeError::PairingExpired,
        "an expired invite"
    );
    assert_eq!(a.node.api().list_nodes().await.unwrap().len(), 1);
    assert_eq!(b.node.api().list_nodes().await.unwrap().len(), 1);
    a.node.shutdown().await;
    b.node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rejected_fingerprint_and_a_replayed_invite_add_nobody() {
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let a = test_node_on(system(), endpoints.clone()).await.unwrap();
    let mut b = test_node_on(system(), endpoints.clone()).await.unwrap();
    let c = test_node_on(system(), endpoints.clone()).await.unwrap();

    let saying_no = answer_checks(a.node.api(), false);
    let invite = a.node.api().create_invite().await.unwrap();
    assert_eq!(
        b.node
            .api()
            .accept_invite(&invite.qr, None)
            .await
            .unwrap_err(),
        NodeError::PairingRefused
    );
    assert_eq!(saying_no.lock().unwrap().len(), 1);
    assert_eq!(a.node.api().list_nodes().await.unwrap().len(), 1);
    assert_eq!(
        b.node.api().node_info().await.unwrap().group_id,
        b.node.group_id()
    );

    let (_, _) = pair_with_answer(&a, &mut b, &endpoints).await;
    let invite = a.node.api().create_invite().await.unwrap();
    let qr = invite.qr.clone();
    let d = test_node_on(system(), endpoints.clone()).await.unwrap();
    answer_checks(a.node.api(), true);
    d.node.api().accept_invite(&qr, None).await.unwrap();
    assert!(
        matches!(
            c.node.api().accept_invite(&qr, None).await,
            Err(NodeError::PairingCodeRejected | NodeError::PeerUnreachable)
        ),
        "an invite is used once"
    );
    for t in [&a, &b, &c, &d] {
        t.node.shutdown().await;
    }
}

async fn pair_with_answer(
    a: &TestNode,
    b: &mut TestNode,
    endpoints: &Arc<dyn Endpoints>,
) -> (Vec<String>, Vec<String>) {
    let a2 = a.node.api();
    let mut events = a2.group_events();
    let api = a.node.api();
    let task = tokio::spawn(async move {
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
    });
    let invite = a.node.api().create_invite().await.unwrap();
    b.node.api().accept_invite(&invite.qr, None).await.unwrap();
    task.await.unwrap();
    restart(b, endpoints, system()).await;
    (Vec::new(), Vec::new())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_with_accounts_does_not_join_another_group() {
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let a = test_node_on(system(), endpoints.clone()).await.unwrap();
    let b = test_node_on(system(), endpoints.clone()).await.unwrap();
    seed(&b, "bob", "INBOX", 1).await;
    add(&b, "bob").await;
    answer_checks(a.node.api(), true);
    let invite = a.node.api().create_invite().await.unwrap();
    assert_eq!(
        b.node
            .api()
            .accept_invite(&invite.qr, None)
            .await
            .unwrap_err(),
        NodeError::Busy
    );
    a.node.shutdown().await;
    b.node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_a_network_pairing_is_unavailable() {
    let t = rowboat_node::testing::test_node(0).await.unwrap();
    assert_eq!(
        t.node.api().create_invite().await.unwrap_err(),
        NodeError::PeerUnreachable
    );
    rowboat_api::testing::validation(&*t.node.api()).await;
    t.node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_phase_one_directory_is_upgraded_to_the_group_log() {
    let mut t = rowboat_node::testing::test_node(0).await.unwrap();
    seed(&t, "ada", "INBOX", 2).await;
    let account = add(&t, "ada").await;
    let before = t.node.api().node_info().await.unwrap();
    t.node.regress_to_phase1_for_tests(&t.keystore).await;
    reopen_plain(&mut t).await;
    let after = t.node.api().node_info().await.unwrap();
    assert_eq!(after.node_id, before.node_id);
    assert_eq!(after.group_id, before.group_id);
    let nodes = t.node.api().list_nodes().await.unwrap();
    assert_eq!(nodes.len(), 1);
    assert!(nodes[0].this_node && nodes[0].counts);
    t.node.api().list_mailboxes(&account).await.unwrap();
    t.node.api().sync_now(Some(&account)).await.unwrap();
    reopen_plain(&mut t).await;
    assert_eq!(
        t.node.api().list_nodes().await.unwrap().len(),
        1,
        "upgraded once"
    );
    t.node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_silent_peer_on_the_pairing_endpoint_does_not_hold_up_the_joiner() {
    use baton_link::{PinnedKeys, Protocol};
    use futures::FutureExt;
    use tokio::io::AsyncReadExt;

    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let a = test_node_on(system(), endpoints.clone()).await.unwrap();
    let mut b = test_node_on(system(), endpoints.clone()).await.unwrap();
    answer_checks(a.node.api(), true);
    let invite = a.node.api().create_invite().await.unwrap();
    let real = Invite::from_qr(&invite.qr).unwrap();
    let silent = baton_identity::Identity::generate();
    let bound = endpoints
        .bind(&silent, Arc::new(PinnedKeys::new([real.endpoint])))
        .await
        .unwrap();
    bound
        .link
        .add_hint(&real.endpoint, real.hint.to_peer().unwrap())
        .unwrap();
    let mut stalled = bound
        .link
        .open(&real.endpoint, &Protocol::new("pair").unwrap())
        .await
        .unwrap();

    b.node.api().accept_invite(&invite.qr, None).await.unwrap();
    let mut byte = [0u8; 1];
    assert!(
        stalled.read(&mut byte).now_or_never().is_none(),
        "the joiner paired while the silent stream was still waiting"
    );
    restart(&mut b, &endpoints, system()).await;
    assert_eq!(a.node.api().list_nodes().await.unwrap().len(), 2);
    bound.link.close().await;
    a.node.shutdown().await;
    b.node.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn an_expired_invite_is_refused_before_anything_is_dialed() {
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let clock = ManualClock::at(1_800_000_000_000);
    let a = test_node_on(Arc::new(clock.clone()), endpoints.clone())
        .await
        .unwrap();
    let b = test_node_on(Arc::new(clock.clone()), endpoints.clone())
        .await
        .unwrap();
    let invite = a.node.api().create_invite().await.unwrap();
    clock.advance(10 * 60 * 1000 + 1);
    assert_eq!(
        b.node
            .api()
            .accept_invite(&invite.qr, None)
            .await
            .unwrap_err(),
        NodeError::PairingExpired,
        "the joiner reads the expiry from the QR code"
    );
    assert_eq!(
        b.node.api().inspect_invite(&invite.qr, None).await,
        Err(NodeError::PairingExpired)
    );
    a.node.shutdown().await;
    b.node.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_shut_down_node_leaves_nothing_holding_its_directory() {
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let a = test_node_on(system(), endpoints.clone()).await.unwrap();
    a.node.api().create_invite().await.unwrap();
    a.node.api().sync_now(None).await.unwrap();
    a.node.shutdown().await;
    let TestNode {
        node,
        fakes,
        keystore,
        dir,
    } = a;
    drop(node);
    let again = reopen_on(&dir, &fakes, &keystore, 0, system(), Some(endpoints))
        .await
        .unwrap();
    again.shutdown().await;
}
