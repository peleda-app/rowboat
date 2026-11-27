//! The headless server (`apps/rowboat`) in its container: an in-process desktop on the host adds
//! an account on a container mail server, adopts a new tenant of the server by its short code
//! over loopback, and the server takes the account's lease and syncs it. Skips unless
//! `ROWBOAT_IT=1` (`mise run it`, which builds the image with the stack).

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::Arc;

use futures::StreamExt;
use rowboat_api::{GroupEvent, ListQuery, NodeApi, Scope, Secret};
use rowboat_integration::*;
use rowboat_keystore_memory::MemoryKeystore;
use rowboat_node::{Node, Profile};

fn compose() -> Command {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut c = Command::new("docker");
    c.current_dir(&root).args([
        "compose",
        "-f",
        "skein/tests/integration/compose.yaml",
        "-f",
        "tests/integration/compose.yaml",
    ]);
    c
}

async fn desktop(dir: &std::path::Path, keystore: &MemoryKeystore) -> Node {
    let node = Node::builder()
        .profile(Profile::Test(timing()))
        .data_dir(dir.join("node"))
        .keystore(Arc::new(keystore.clone()))
        .content(Arc::new(rinse_mail_direct::DirectContent::new()))
        .endpoints(Arc::new(rowboat_endpoint_iroh::IrohEndpoints::loopback()))
        .test_roots(ca())
        .build()
        .await
        .expect("the desktop builds");
    node.start().await;
    node
}

async fn count(api: &dyn NodeApi, account: &rowboat_api::AccountId) -> usize {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_server_container_is_adopted_and_takes_the_account_over() {
    if !enabled() {
        return;
    }
    until("the server's health check", 120, async || {
        reqwest::get("http://127.0.0.1:49480/v1/health")
            .await
            .is_ok_and(|r| r.status().is_success())
    })
    .await;

    let mail = Server::of(Kind::GreenMailShared);
    let user = mail.user("srv").await;
    let mut imap = mail.imap(&user).await;
    for n in 0..3 {
        imap.append("INBOX", &message("srv", n, &user.address), false)
            .await;
    }
    let dir = tempfile::tempdir().unwrap();
    let keystore = MemoryKeystore::new();
    let node = desktop(dir.path(), &keystore).await;
    let api = node.api();
    let account = api
        .add_account(mail.setup(&user), Secret::from_text(&user.password))
        .await
        .expect("the account signs in");
    until("the desktop's first sync", 120, async || {
        count(&*api, &account).await >= 3
    })
    .await;

    let mut invite = compose()
        .args([
            "exec", "-T", "rowboat", "rowboat", "invite", "--tenant", "new", "--yes",
        ])
        .stdout(Stdio::piped())
        .spawn()
        .expect("docker compose exec");
    let mut lines = BufReader::new(invite.stdout.take().unwrap()).lines();
    let (mut code, mut address, mut server) = (None, None, None);
    for line in lines.by_ref() {
        let line = line.expect("the invite's output");
        let field = |name: &str| line.trim().strip_prefix(name).map(|v| v.trim().to_owned());
        if let Some(v) = field("short code:") {
            code = Some(v);
        } else if let Some(v) = field("pairing address:") {
            address = Some(v);
        } else if let Some(v) = field("server node:") {
            server = Some(v);
        }
        if code.is_some() && address.is_some() && server.is_some() {
            break;
        }
    }
    let (code, address, server) = (code.unwrap(), address.unwrap(), server.unwrap());

    let confirming = {
        let api = api.clone();
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
    };
    let joined = api
        .accept_invite(&code, Some(&address))
        .await
        .expect("the desktop adopts the server");
    assert!(!joined.restart_required);
    confirming.await.unwrap();
    let rest: Vec<String> = lines.map_while(Result::ok).collect();
    let status = tokio::task::spawn_blocking(move || invite.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(status.success(), "rowboat invite ended with {status}");
    assert!(rest.iter().any(|l| l.contains("is bound to group")));

    until("the server to hold the lease", 180, async || {
        !node.leads(&account)
            && node
                .lease_holder(&account)
                .await
                .is_some_and(|h| h.starts_with(&server))
    })
    .await;
    drop(imap);
    let mut imap = mail.imap(&user).await;
    imap.append("INBOX", &message("srv", 3, &user.address), false)
        .await;
    api.sync_now(Some(&account))
        .await
        .expect("asks the server to sync");
    until("the server's sync to reach the desktop", 180, async || {
        count(&*api, &account).await >= 4
    })
    .await;
    assert!(!node.leads(&account), "the desktop only follows");

    let tenants = compose()
        .args(["exec", "-T", "rowboat", "rowboat", "tenants", "--json"])
        .output()
        .expect("rowboat tenants");
    let rows: serde_json::Value = serde_json::from_slice(&tenants.stdout).unwrap();
    assert!(
        rows.as_array()
            .unwrap()
            .iter()
            .any(|r| r["group"] == node.group_id() && r["state"] == "bound")
    );
    imap.logout().await;
    node.shutdown().await;
}
