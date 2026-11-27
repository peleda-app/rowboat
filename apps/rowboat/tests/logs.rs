//! SEC-3: everything the server and its tenants' nodes log at debug level while a device adopts a
//! tenant and the tenant syncs and serves its mail (with provider push on) carries no content and no secret: no subject,
//! address, password, invite payload or short code.

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use rowboat::host::Shown;
use rowboat_endpoint::Endpoints;
use rowboat_endpoint_memory::MemoryEndpoints;
use rowboat_node::testing::FakeProviders;

use common::*;

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn logs_carry_no_content_or_secrets() {
    let captured = Captured::default();
    let sink = captured.clone();
    tracing_subscriber::fmt()
        .with_env_filter("debug,iroh=info")
        .json()
        .with_writer(move || sink.clone())
        .init();

    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let fakes = FakeProviders::new();
    fakes.require_password(PASSWORD);
    seed(&fakes, "eve", 0, 3, "Quarterly orchard invoice").await;
    let desktop = desktop(&fakes, &endpoints).await;
    let account = add(&desktop, "eve").await;

    let test_host = TestHost::new(&endpoints, &fakes);
    let host = Arc::new(
        rowboat::host::Host::open(
            test_host.tenants.clone(),
            Some(("https://push.example.com".into(), None)),
            std::time::Duration::from_secs(60),
        )
        .unwrap(),
    );
    let (show, mut qr, seen) = recorder();
    let running = {
        let host = host.clone();
        tokio::spawn(async move { host.first_run(rowboat::host::Confirm::App, show).await })
    };
    scan(&desktop, &mut qr).await;
    let tenant = within("the adoption", running).await.unwrap().unwrap();
    leads(&host, &tenant, &account).await;
    let server = host.node(&tenant).await.unwrap();
    shows(&*server.api(), &account, 3).await;
    seed(&fakes, "eve", 3, 1, "Quarterly orchard invoice").await;
    shows(&*desktop.node.api(), &account, 4).await;
    host.rescan().await;
    drop(server);
    host.shutdown().await;

    let (payload, code) = seen
        .lock()
        .unwrap()
        .iter()
        .find_map(|s| match s {
            Shown::Invite { qr, short_code, .. } => Some((qr.clone(), short_code.clone())),
            _ => None,
        })
        .unwrap();
    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("tenant adopted and bound"),
        "the capture works"
    );
    for (what, needle) in [
        ("a subject", "Quarterly orchard"),
        ("an address", "eve@example.com"),
        ("a sender", "sender1@example.org"),
        ("the password", PASSWORD),
        ("the invite", payload.as_str()),
        ("the invite's encoding", &payload["peleda-pair:".len()..]),
        ("the short code", code.as_str()),
        ("a body", "about gardens"),
    ] {
        assert!(!logs.contains(needle), "the logs carry {what}");
    }
}
