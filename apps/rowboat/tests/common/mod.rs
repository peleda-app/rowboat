#![allow(dead_code)]

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use baton_lease::NodeClass;
use futures::StreamExt;
use rowboat::host::{Confirm, Deps, Host, Net, Show, Shown, Tenants};
use rowboat::tenant::{Layout, TenantError, TenantId};
use rowboat_api::*;
use rowboat_endpoint::Endpoints;
use rowboat_node::testing::{FakeProviders, Spec, TestNode, group_timing, test_node_as};
use skein_mail::testing::ServerControl;

pub fn log() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}

pub const PASSWORD: &str = "correct-horse-battery-1";
pub const HANG: Duration = Duration::from_secs(300);

pub async fn within<T>(what: &str, f: impl Future<Output = T>) -> T {
    match tokio::time::timeout(HANG, f).await {
        Ok(v) => v,
        Err(_) => panic!("hung waiting for {what}"),
    }
}

pub async fn until<F, Fut>(what: &str, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    within(what, async {
        while !f().await {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
}

pub fn message(n: usize, subject: &str) -> Vec<u8> {
    format!(
        "From: Sender {n} <sender{n}@example.org>\r\nTo: ada@example.com\r\nSubject: {subject}\r\nMessage-ID: <m{n}@example.org>\r\nDate: Mon, 2 Nov 2026 09:{:02}:00 +0000\r\n\r\nBody of message {n} about gardens.\r\n",
        n % 60
    )
    .into_bytes()
}

pub async fn seed(fakes: &FakeProviders, user: &str, from: usize, count: usize, subject: &str) {
    let server = fakes.server(user);
    for n in from..from + count {
        server
            .add(
                "INBOX",
                &message(n, &format!("{subject} {n}")),
                Default::default(),
            )
            .await;
    }
}

pub fn setup(user: &str) -> AccountSetup {
    AccountSetup {
        address: EmailAddress::new(format!("{user}@example.com")).unwrap(),
        display_name: Some("Ada Example".into()),
        username: user.into(),
        imap: Endpoint::new("imap.example.com", 993, Security::Tls).unwrap(),
        smtp: Endpoint::new("smtp.example.com", 465, Security::Tls).unwrap(),
    }
}

pub async fn add(t: &TestNode, user: &str) -> AccountId {
    t.node
        .api()
        .add_account(setup(user), Secret::from_text(PASSWORD))
        .await
        .unwrap()
}

pub async fn count(api: &dyn NodeApi, account: &AccountId) -> usize {
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

pub async fn shows(api: &dyn NodeApi, account: &AccountId, n: usize) {
    until(&format!("{n} messages to show"), || async {
        count(api, account).await >= n
    })
    .await;
}

/// A host over its own temporary directories: data, secrets and cache apart.
pub struct TestHost {
    pub dir: Arc<tempfile::TempDir>,
    pub tenants: Tenants,
}

impl TestHost {
    pub fn new(endpoints: &Arc<dyn Endpoints>, fakes: &FakeProviders) -> Self {
        let dir = Arc::new(tempfile::tempdir().unwrap());
        Self::over(dir, endpoints, fakes)
    }

    pub fn over(
        dir: Arc<tempfile::TempDir>,
        endpoints: &Arc<dyn Endpoints>,
        fakes: &FakeProviders,
    ) -> Self {
        let layout = Layout {
            data: dir.path().join("data"),
            secrets: dir.path().join("secrets"),
            cache: dir.path().join("cache"),
            ports: None,
        };
        let deps = Deps {
            profile: rowboat_node::Profile::Test(group_timing()),
            providers: Some(fakes.providers()),
            content: Arc::new(rinse_mail_direct::DirectContent::new()),
            net: Net::Given(endpoints.clone()),
            store: None,
            roots: None,
        };
        Self {
            dir,
            tenants: Tenants { layout, deps },
        }
    }

    pub fn open(&self) -> Arc<Host> {
        Arc::new(Host::open(self.tenants.clone(), None, Duration::from_secs(60)).unwrap())
    }
}

pub fn spec(fakes: &FakeProviders, endpoints: &Arc<dyn Endpoints>) -> Spec {
    Spec {
        class: NodeClass::Desktop,
        fakes: fakes.clone(),
        endpoints: endpoints.clone(),
        timing: group_timing(),
        on_revoked: None,
    }
}

pub async fn desktop(fakes: &FakeProviders, endpoints: &Arc<dyn Endpoints>) -> TestNode {
    test_node_as(&spec(fakes, endpoints)).await.unwrap()
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

/// A show that records everything and hands the invite's QR payload over.
pub fn recorder() -> (
    Show,
    tokio::sync::mpsc::UnboundedReceiver<String>,
    Arc<std::sync::Mutex<Vec<Shown>>>,
) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let kept = seen.clone();
    let show: Show = Arc::new(move |s: Shown| {
        if let Shown::Invite { qr, .. } = &s {
            let _ = tx.send(qr.clone());
        }
        kept.lock().unwrap().push(s);
    });
    (show, rx, seen)
}

/// `desktop` scans the QR payload that arrives on `qr` and confirms the fingerprint.
pub async fn scan(desktop: &TestNode, qr: &mut tokio::sync::mpsc::UnboundedReceiver<String>) {
    let payload = within("the invite", qr.recv()).await.unwrap();
    accept(desktop, &payload).await;
}

/// `desktop` accepts the invite `payload` and confirms the fingerprint.
pub async fn accept(desktop: &TestNode, payload: &str) {
    let answer = confirm_next(desktop);
    desktop
        .node
        .api()
        .accept_invite(payload, None)
        .await
        .unwrap();
    within("the desktop's confirmation", answer).await.unwrap();
}

/// The host's first run, adopted by `desktop`.
pub async fn first_run(host: &Arc<Host>, desktop: &TestNode) -> TenantId {
    let (show, mut qr, _) = recorder();
    let running = {
        let host = host.clone();
        tokio::spawn(async move { host.first_run(Confirm::App, show).await })
    };
    scan(desktop, &mut qr).await;
    within("the adoption", running).await.unwrap().unwrap()
}

/// `rowboat invite` for `tenant` (or a new one), adopted by `desktop`. An invite refused before
/// it is shown returns its error.
pub async fn invite(
    tenants: &Tenants,
    tenant: Option<TenantId>,
    rebind: bool,
    desktop: &TestNode,
) -> Result<rowboat::tenant::Binding, TenantError> {
    let (show, mut qr, _) = recorder();
    let mut running = {
        let tenants = tenants.clone();
        tokio::spawn(async move {
            tenants
                .adopt(tenant, rebind, Confirm::App, show, None, None)
                .await
        })
    };
    let payload = within("the invite", async {
        tokio::select! {
            biased;
            p = qr.recv() => match p {
                Some(p) => Ok(p),
                None => Err((&mut running).await.unwrap().err().expect("an invite ends only by an adoption")),
            },
            r = &mut running => Err(r.unwrap().err().expect("an invite ends only by an adoption")),
        }
    })
    .await?;
    accept(desktop, &payload).await;
    let (node, binding) = within("the adoption", running).await.unwrap()?;
    node.shutdown().await;
    Ok(binding)
}

pub async fn leads(host: &Host, tenant: &TenantId, account: &AccountId) {
    until(&format!("tenant {tenant} to lead"), || async {
        match host.node(tenant).await {
            Some(n) => n.leads(account),
            None => false,
        }
    })
    .await;
}
