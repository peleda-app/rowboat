//! A password never appears in logs, events, errors or `Debug` output.

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use futures::StreamExt;
use rowboat_api::*;
use rowboat_node::testing::test_node;

use common::*;

const CANARY: &str = "canary-pw-5e1f0a";

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_canary_password_never_leaks() {
    let capture = Capture::default();
    let writer = capture.clone();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .init();

    let t = test_node(0).await.unwrap();
    let api = t.node.api();
    let mut events = api.events();
    t.fakes.require_password(CANARY);
    seed(&t, "ada", "INBOX", 3).await;

    let refused = api
        .add_account(setup("ada"), Secret::from_text("wrong-canary-pw-5e1f0b"))
        .await
        .unwrap_err();
    let account = api
        .add_account(setup("ada"), Secret::from_text(CANARY))
        .await
        .unwrap();
    wait_messages(&*api, &account, 3).await;
    let err = api
        .update_password(&account, Secret::from_text("canary-pw-5e1f0a-but-wrong"))
        .await
        .unwrap_err();
    let secret_debug = format!("{:?}", Secret::from_text(CANARY));
    let accounts = format!("{:?}", api.list_accounts().await.unwrap());
    t.node.shutdown().await;

    let mut seen = Vec::new();
    while let Ok(Some(e)) =
        tokio::time::timeout(std::time::Duration::from_millis(50), events.next()).await
    {
        seen.push(serde_json::to_string(&e).unwrap());
    }
    assert!(!seen.is_empty());

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(!logs.is_empty(), "the capture works");
    for (what, text) in [
        ("logs", logs),
        ("events", seen.join("\n")),
        ("errors", format!("{refused} {refused:?} {err} {err:?}")),
        ("debug", secret_debug),
        ("accounts", accounts),
    ] {
        assert!(!text.contains("canary-pw"), "{what} carry the password");
    }
    let objects = t.dir.path().join("node/objects");
    assert!(
        !grep(&objects, CANARY.as_bytes()),
        "the objects directory holds the password in the clear"
    );
}

fn grep(dir: &std::path::Path, needle: &[u8]) -> bool {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .any(|e| {
            let p = e.path();
            if p.is_dir() {
                grep(&p, needle)
            } else {
                std::fs::read(&p)
                    .map(|b| b.windows(needle.len()).any(|w| w == needle))
                    .unwrap_or(false)
            }
        })
}
