//! The device and server management surface the app's Devices screens use: adopting a server
//! with a chosen set of accounts, granting it more later, names given on this node, when a peer
//! was last heard from, who leads each account, inspecting a code before dialing, and the old
//! group's data going away when a device joins another group.

mod common;

use std::path::Path;
use std::sync::Arc;

use baton_lease::NodeClass;
use futures::StreamExt;
use rowboat_api::*;
use rowboat_endpoint::Endpoints;
use rowboat_endpoint_memory::MemoryEndpoints;
use rowboat_node::testing::{FakeProviders, Spec, TestNode, group_timing, reopen_as, test_node_as};

use common::{add, seed, until, within};

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

fn mentions(dir: &Path, needle: &str) -> bool {
    walkdir(dir)
        .iter()
        .any(|p| p.to_string_lossy().contains(needle))
}

fn walkdir(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p.clone());
            }
            out.push(p);
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_server_leads_only_the_accounts_it_was_given_until_more_are_granted() {
    let fakes = FakeProviders::new();
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let desktop_spec = spec(NodeClass::Desktop, &fakes, &endpoints);
    let server_spec = spec(NodeClass::Server, &fakes, &endpoints);
    let desktop = test_node_as(&desktop_spec).await.unwrap();
    let mut server = test_node_as(&server_spec).await.unwrap();
    seed(&desktop, "ada", "INBOX", 1).await;
    seed(&desktop, "bob", "INBOX", 1).await;
    let ada = add(&desktop, "ada").await;
    let bob = add(&desktop, "bob").await;
    let api = desktop.node.api();
    assert_eq!(api.group_status().await.unwrap().server, ServerState::None);

    let invite = server.node.server_invite().await.unwrap();
    let info = api
        .inspect_invite(&invite.short_code, Some(&invite.address))
        .await
        .unwrap();
    assert_eq!(info.kind, InviteKind::Server);
    assert_eq!(info.expires_at, None, "a short code does not say");
    let info = api.inspect_invite(&invite.qr, None).await.unwrap();
    assert_eq!(info.kind, InviteKind::Server);
    assert_eq!(info.expires_at, Some(invite.expires_at));

    let stranger = AccountId::new("aaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    assert_eq!(
        api.adopt_server(&invite.qr, None, std::slice::from_ref(&stranger))
            .await,
        Err(NodeError::NotFound),
        "an account this member never created is refused before dialing"
    );

    let answer = confirm_next(&desktop);
    let r = api
        .adopt_server(
            &invite.short_code,
            Some(&invite.address),
            std::slice::from_ref(&ada),
        )
        .await
        .unwrap();
    assert!(!r.restart_required);
    answer.await.unwrap();
    within("the adoption", invite.adopted)
        .await
        .unwrap()
        .unwrap();
    rebuild(&mut server, &server_spec).await;
    let server_id = server.node.node_id().to_string();

    let row = |nodes: Vec<NodeSummary>| nodes.into_iter().find(|n| n.node_id == server_id);
    let s = row(api.list_nodes().await.unwrap()).unwrap();
    assert_eq!(s.class, "server");
    assert_eq!(s.may_lead, vec![ada.clone()], "only the chosen account");
    let me = api
        .list_nodes()
        .await
        .unwrap()
        .into_iter()
        .find(|n| n.this_node)
        .unwrap();
    assert!(me.last_seen.is_some());
    assert_eq!(
        me.may_lead.len(),
        2,
        "the member's devices may lead everything"
    );

    api.grant_to_server(&server_id, std::slice::from_ref(&bob))
        .await
        .unwrap();
    api.grant_to_server(&server_id, std::slice::from_ref(&bob))
        .await
        .unwrap();
    let s = row(api.list_nodes().await.unwrap()).unwrap();
    let mut granted = s.may_lead.clone();
    granted.sort();
    let mut both = vec![ada.clone(), bob.clone()];
    both.sort();
    assert_eq!(granted, both);
    assert_eq!(
        api.grant_to_server(&me.node_id, std::slice::from_ref(&bob))
            .await,
        Err(NodeError::NotFound),
        "only a server takes grants"
    );
    assert_eq!(
        api.grant_to_server(&server_id, std::slice::from_ref(&stranger))
            .await,
        Err(NodeError::NotFound)
    );

    until("the server to answer and be seen", || async {
        api.sync_now(None).await.ok();
        let seen = row(api.list_nodes().await.unwrap()).and_then(|s| s.last_seen);
        seen.is_some()
            && api.group_status().await.map(|g| g.server).ok() == Some(ServerState::Answering)
    })
    .await;
    let status = api.group_status().await.unwrap();
    let mut accounts: Vec<_> = status.leaders.iter().map(|l| l.account.clone()).collect();
    accounts.sort();
    assert_eq!(accounts, both, "every account this node reads is listed");
    until("the server to lead what it was given", || async {
        api.group_status()
            .await
            .unwrap()
            .leaders
            .iter()
            .any(|l| l.account == ada && l.node.as_deref() == Some(server_id.as_str()))
    })
    .await;

    desktop.node.shutdown().await;
    server.node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_invite_is_not_a_server_and_names_stay_on_this_node() {
    let fakes = FakeProviders::new();
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let s = spec(NodeClass::Desktop, &fakes, &endpoints);
    let a = test_node_as(&s).await.unwrap();
    let mut b = test_node_as(&s).await.unwrap();
    let a_api = a.node.api();

    let invite = a_api.create_invite().await.unwrap();
    assert_eq!(
        invite.short_code, None,
        "device invites have no short code yet"
    );
    assert_eq!(invite.address, None);
    let info = b.node.api().inspect_invite(&invite.qr, None).await.unwrap();
    assert_eq!(info.kind, InviteKind::Device);
    assert_eq!(info.expires_at, Some(invite.expires_at));
    assert_eq!(
        b.node.api().adopt_server(&invite.qr, None, &[]).await,
        Err(NodeError::InvalidInput),
        "a device invite is not a server's"
    );

    b.node
        .api()
        .rename_node(b.node.node_id(), Some("Ada's laptop"))
        .await
        .unwrap();
    let old_group = b.node.group_id().to_string();
    let answer = confirm_next(&a);
    let r = b.node.api().accept_invite(&invite.qr, None).await.unwrap();
    assert!(r.restart_required);
    answer.await.unwrap();
    rebuild(&mut b, &s).await;
    assert_ne!(b.node.group_id(), old_group);
    assert!(
        !mentions(b.dir.path(), &old_group),
        "the old group's local data is gone"
    );

    let b_id = b.node.node_id().to_string();
    let label_of = |nodes: Vec<NodeSummary>, id: &str| {
        nodes
            .into_iter()
            .find(|n| n.node_id == id)
            .and_then(|n| n.label)
    };
    assert_eq!(
        label_of(a_api.list_nodes().await.unwrap(), &b_id).as_deref(),
        Some("Ada's laptop"),
        "the joiner's name travels with its pairing"
    );
    a_api.rename_node(&b_id, Some("Office")).await.unwrap();
    assert_eq!(
        label_of(a_api.list_nodes().await.unwrap(), &b_id).as_deref(),
        Some("Office")
    );
    assert_ne!(
        label_of(b.node.api().list_nodes().await.unwrap(), &b_id).as_deref(),
        Some("Office"),
        "a name is this node's own"
    );
    a_api.rename_node(&b_id, None).await.unwrap();
    assert_eq!(
        label_of(a_api.list_nodes().await.unwrap(), &b_id).as_deref(),
        Some("Ada's laptop")
    );
    for bad in [
        "",
        "  ",
        "two\nlines",
        &"x".repeat(group::MAX_NODE_LABEL + 1),
    ] {
        assert_eq!(
            a_api.rename_node(&b_id, Some(bad)).await,
            Err(NodeError::InvalidInput)
        );
    }
    assert_eq!(
        a_api.rename_node(&"a".repeat(52), Some("ghost")).await,
        Err(NodeError::NotFound)
    );
    a.node.shutdown().await;
    b.node.shutdown().await;
}
