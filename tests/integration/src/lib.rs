//! Helpers for the node's integration suite: the servers of the container stack, fresh users on
//! them, an independent IMAP client to seed and inspect mailboxes, a byte-counting TCP relay and
//! nodes built on the test profile with real IMAP and SMTP trusting the stack's test CA.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use futures::StreamExt;
use rowboat_api::{AccountSetup, EmailAddress, Endpoint, NodeApi, NodeEvent, Security};
use rowboat_keystore_memory::MemoryKeystore;
use rowboat_node::{BuildError, Node, Profile, TestTiming};
use skein_core::TlsRoots;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls;

/// The host name every server certificate of the stack carries; it resolves to loopback.
pub const HOST: &str = "mail.localhost";

/// Whether the stack is up (`ROWBOAT_IT=1`, set by `mise run it`).
pub fn enabled() -> bool {
    std::env::var("ROWBOAT_IT").as_deref() == Ok("1")
}

/// The test CA the stack's certificates chain to.
pub fn ca() -> TlsRoots {
    let path = std::env::var("ROWBOAT_IT_CA").expect("ROWBOAT_IT_CA is not set");
    TlsRoots::from_pem(&std::fs::read(path).expect("the test CA")).expect("a PEM certificate")
}

/// A server of the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Dovecot 2.4: IMAP, submission relaying to GreenMail (no local delivery).
    Dovecot,
    /// Stalwart: IMAP and SMTP with local delivery.
    Stalwart,
    /// GreenMail: IMAP and SMTP with local delivery.
    GreenMail,
}

/// How the node reaches a server and how the suite inspects it.
#[derive(Debug, Clone)]
pub struct Server {
    /// Which server.
    pub kind: Kind,
    /// The IMAP endpoint accounts use.
    pub imap: Endpoint,
    /// The SMTP endpoint accounts use.
    pub smtp: Endpoint,
    /// The implicit-TLS IMAP port the suite's own client uses.
    pub imaps_port: u16,
    /// The implicit-TLS submission port.
    pub smtps_port: u16,
    /// Whether mail to another user of the server lands in that user's INBOX.
    pub delivers_locally: bool,
}

fn endpoint(port: u16, security: Security) -> Endpoint {
    Endpoint::new(HOST, port, security).expect("endpoint")
}

impl Server {
    /// The server of `kind`: Dovecot over IMAPS and submissions, Stalwart over STARTTLS on both,
    /// GreenMail over IMAPS and SMTPS.
    pub fn of(kind: Kind) -> Self {
        match kind {
            Kind::Dovecot => Self {
                kind,
                imap: endpoint(49293, Security::Tls),
                smtp: endpoint(49265, Security::Tls),
                imaps_port: 49293,
                smtps_port: 49265,
                delivers_locally: false,
            },
            Kind::Stalwart => Self {
                kind,
                imap: endpoint(49244, Security::StartTls),
                smtp: endpoint(49387, Security::StartTls),
                imaps_port: 49393,
                smtps_port: 49365,
                delivers_locally: true,
            },
            Kind::GreenMail => Self {
                kind,
                imap: endpoint(49193, Security::Tls),
                smtp: endpoint(49165, Security::Tls),
                imaps_port: 49193,
                smtps_port: 49165,
                delivers_locally: true,
            },
        }
    }

    /// A new user on the server with an invented address on `example.com`, unique per run.
    pub async fn user(&self, name: &str) -> User {
        let id = ulid::Ulid::generate().to_string().to_lowercase();
        let local = format!("{name}{}", &id[16..]);
        let user = User {
            address: format!("{local}@example.com"),
            password: match self.kind {
                Kind::Dovecot => "it-password".into(),
                _ => format!("it-{id}"),
            },
        };
        match self.kind {
            Kind::Dovecot => {}
            Kind::GreenMail => {
                let answer = reqwest::Client::new()
                    .post("http://127.0.0.1:49180/api/user")
                    .json(&serde_json::json!({
                        "email": user.address,
                        "login": user.address,
                        "password": user.password,
                    }))
                    .send()
                    .await
                    .expect("GreenMail API");
                assert!(answer.status().is_success(), "GreenMail refused the user");
            }
            Kind::Stalwart => stalwart_user(&local, &user.password).await,
        }
        user
    }

    /// The setup the node gets for `user`: the address as the user name on both servers.
    pub fn setup(&self, user: &User) -> AccountSetup {
        AccountSetup {
            address: EmailAddress::new(&user.address).expect("address"),
            display_name: Some("Integration Example".into()),
            username: user.address.clone(),
            imap: self.imap.clone(),
            smtp: self.smtp.clone(),
        }
    }

    /// The suite's own IMAP session for `user`, over implicit TLS verified with the test CA.
    pub async fn imap(&self, user: &User) -> Imap {
        Imap::connect(self.imaps_port, user).await
    }
}

async fn stalwart_user(local: &str, password: &str) {
    let client = reqwest::Client::new();
    let call = |body: serde_json::Value| {
        let client = client.clone();
        async move {
            client
                .post("http://127.0.0.1:49280/jmap/")
                .basic_auth("admin", Some("it-stalwart-admin-password"))
                .json(&body)
                .send()
                .await
                .expect("Stalwart API")
                .json::<serde_json::Value>()
                .await
                .expect("Stalwart answer")
        }
    };
    let using = serde_json::json!(["urn:ietf:params:jmap:core", "urn:stalwart:jmap"]);
    let domains = call(serde_json::json!({
        "using": using,
        "methodCalls": [["x:Domain/get", {}, "d"]],
    }))
    .await;
    let domain = domains["methodResponses"][0][1]["list"]
        .as_array()
        .and_then(|l| l.iter().find(|d| d["name"] == "example.com"))
        .and_then(|d| d["id"].as_str())
        .expect("the example.com domain")
        .to_owned();
    let created = call(serde_json::json!({
        "using": using,
        "methodCalls": [["x:Account/set", {"create": {"user": {
            "@type": "User", "name": local, "domainId": domain,
            "credentials": {"0": {"@type": "Password", "secret": password}},
            "roles": {"@type": "User"}, "permissions": {"@type": "Inherit"},
            "encryptionAtRest": {"@type": "Disabled"}
        }}}, "u"]],
    }))
    .await;
    assert!(
        created["methodResponses"][0][1]["created"]["user"].is_object(),
        "Stalwart refused the user"
    );
}

/// A user of one server. The password is a throwaway value of this run.
#[derive(Debug, Clone)]
pub struct User {
    /// The address, also the user name.
    pub address: String,
    /// The password.
    pub password: String,
}

/// An invented message to `to` with a unique `Message-ID` built from `tag` and `n` and the word
/// [`marker`]`(n)` in its body only.
pub fn message(tag: &str, n: usize, to: &str) -> Vec<u8> {
    format!(
        "From: Sender {n} <sender{n}@example.org>\r\nTo: {to}\r\nSubject: Garden note {n} {tag}\r\nMessage-ID: <{tag}-{n}@example.org>\r\nDate: Mon, 2 Nov 2026 09:{:02}:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nBody {n} about tulips and {tag}.\r\nBed {}.\r\n",
        n % 60,
        marker(n)
    )
    .into_bytes()
}

/// A word of letters only that is in the body of message `n` and of no other (`n` < 17576).
pub fn marker(n: usize) -> String {
    let letter = |d: usize| char::from(b'a' + (d % 26) as u8);
    format!("kw{}{}{}", letter(n / 676), letter(n / 26), letter(n))
}

/// The node's id of a message: the BLAKE3 of its bytes in lowercase hex.
pub fn message_id(bytes: &[u8]) -> rowboat_api::MessageId {
    rowboat_api::MessageId::new(blake3::hash(bytes).to_hex().to_string()).expect("message id")
}

/// An IMAP session independent of the node's providers.
pub struct Imap {
    session: async_imap::Session<TlsStream<TcpStream>>,
}

fn tls() -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    for der in ca().iter() {
        roots.add(der.to_vec().into()).expect("CA certificate");
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("TLS versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

impl Imap {
    async fn connect(port: u16, user: &User) -> Self {
        let tcp = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("IMAP port");
        let name = rustls::pki_types::ServerName::try_from(HOST).expect("name");
        let stream = tls().connect(name, tcp).await.expect("TLS");
        let mut client = async_imap::Client::new(stream);
        client.read_response().await.expect("greeting");
        let session = client
            .login(&user.address, &user.password)
            .await
            .map_err(|(e, _)| e)
            .expect("IMAP login");
        Self { session }
    }

    /// Every mailbox path with its attributes in lowercase (`\sent`, `\trash`).
    pub async fn mailboxes(&mut self) -> Vec<(String, Vec<String>)> {
        let names: Vec<_> = self
            .session
            .list(Some(""), Some("*"))
            .await
            .expect("LIST")
            .collect()
            .await;
        names
            .into_iter()
            .map(|n| n.expect("LIST entry"))
            .map(|n| {
                (
                    n.name().to_owned(),
                    n.attributes()
                        .iter()
                        .map(|a| format!("{a:?}").to_lowercase())
                        .collect(),
                )
            })
            .collect()
    }

    /// Creates `mailbox` unless it exists.
    pub async fn ensure(&mut self, mailbox: &str) {
        if !self.mailboxes().await.iter().any(|(n, _)| n == mailbox) {
            self.session.create(mailbox).await.expect("CREATE");
        }
    }

    /// Appends `bytes` to `mailbox`, `\Seen` when `seen`; the server's time is the arrival time.
    pub async fn append(&mut self, mailbox: &str, bytes: &[u8], seen: bool) {
        self.session
            .append(mailbox, seen.then_some("(\\Seen)"), None, bytes)
            .await
            .expect("APPEND");
    }

    /// Messages in `mailbox`.
    pub async fn count(&mut self, mailbox: &str) -> u32 {
        self.session
            .status(mailbox, "(MESSAGES)")
            .await
            .expect("STATUS")
            .exists
    }

    /// The flags (lowercase) of the message with `message_id` in `mailbox`, `None` when it is
    /// not there. Reads every message's `Message-ID` field: Stalwart's `SEARCH HEADER` does not
    /// match it.
    pub async fn flags(&mut self, mailbox: &str, message_id: &str) -> Option<Vec<String>> {
        self.scan(mailbox, &format!("<{message_id}>")).await
    }

    /// The flags of a message in `mailbox` whose header contains `text` (a unique subject),
    /// `None` when none.
    pub async fn flags_by_subject(&mut self, mailbox: &str, text: &str) -> Option<Vec<String>> {
        self.scan(mailbox, text).await
    }

    async fn scan(&mut self, mailbox: &str, text: &str) -> Option<Vec<String>> {
        let found = self.session.examine(mailbox).await.expect("EXAMINE");
        if found.exists == 0 {
            return None;
        }
        let fetched: Vec<_> = self
            .session
            .uid_fetch("1:*", "(UID FLAGS BODY.PEEK[HEADER])")
            .await
            .expect("FETCH")
            .collect()
            .await;
        fetched
            .into_iter()
            .map(|f| f.expect("FETCH entry"))
            .find_map(|f| {
                let header = String::from_utf8_lossy(f.header()?).into_owned();
                header
                    .contains(text)
                    .then(|| f.flags().map(|x| format!("{x:?}").to_lowercase()).collect())
            })
    }

    /// Signs out.
    pub async fn logout(mut self) {
        let _ = self.session.logout().await;
    }
}

/// Polls `f` every 200 ms until it is true; panics with `what` after `secs` seconds.
pub async fn until(what: &str, secs: u64, mut f: impl AsyncFnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        if f().await {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Waits up to `secs` seconds for an event `pick` accepts, skipping the others.
pub async fn event<T>(
    events: &mut rowboat_api::EventStream,
    secs: u64,
    what: &str,
    mut pick: impl FnMut(&NodeEvent) -> Option<T>,
) -> T {
    let wait = async {
        while let Some(e) = events.next().await {
            if let Some(t) = pick(&e) {
                return t;
            }
        }
        panic!("the event stream ended before {what}");
    };
    tokio::time::timeout(Duration::from_secs(secs), wait)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
}

/// The suite's timing: 250 ms heartbeats, a sync every second, 100 ms follower rounds, a 300 ms
/// undo window.
pub fn timing() -> TestTiming {
    TestTiming {
        heartbeat: Duration::from_millis(250),
        interval: Duration::from_secs(1),
        poll: Duration::from_millis(100),
        undo_ms: 300,
        removal_grace: Duration::from_secs(3),
    }
}

/// Builds and starts a node over `dir` with real IMAP and SMTP; `roots` are the CAs it trusts
/// besides the web roots (the test CA, or none to see verification fail).
pub async fn node(dir: &Path, keystore: &MemoryKeystore, roots: TlsRoots) -> Node {
    node_timed(dir, keystore, roots, timing()).await
}

/// [`node`] with its own timing.
pub async fn node_timed(
    dir: &Path,
    keystore: &MemoryKeystore,
    roots: TlsRoots,
    timing: TestTiming,
) -> Node {
    try_node(dir, keystore, roots, timing, None)
        .await
        .expect("the node builds")
}

/// [`node_timed`] with discovery sources, returning the build error.
pub async fn try_node(
    dir: &Path,
    keystore: &MemoryKeystore,
    roots: TlsRoots,
    timing: TestTiming,
    discovery: Option<Vec<Arc<dyn rowboat_discover::DiscoverySource>>>,
) -> Result<Node, BuildError> {
    let mut builder = Node::builder()
        .profile(Profile::Test(timing))
        .data_dir(dir.join("node"))
        .keystore(Arc::new(keystore.clone()))
        .content(Arc::new(rinse_mail_direct::DirectContent::new()))
        .test_roots(if roots.is_empty() { untrusted() } else { roots });
    if let Some(sources) = discovery {
        builder = builder.discovery(sources);
    }
    let node = builder.build().await?;
    node.start().await;
    Ok(node)
}

fn untrusted() -> TlsRoots {
    skein_core::tls::testing::TestCa::new(&[HOST]).roots()
}

/// The first account's state as lists show it.
pub async fn account(api: &dyn NodeApi) -> Option<rowboat_api::AccountInfo> {
    api.list_accounts().await.ok()?.into_iter().next()
}

/// A loopback TCP relay to `127.0.0.1:target` that counts the bytes the server sends back.
pub struct Relay {
    /// The relay's port.
    pub port: u16,
    received: Arc<AtomicU64>,
}

impl Relay {
    /// Starts relaying until the runtime stops.
    pub async fn start(target: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("address").port();
        let received = Arc::new(AtomicU64::new(0));
        let counter = received.clone();
        tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                let counter = counter.clone();
                tokio::spawn(async move {
                    let Ok(mut server) = TcpStream::connect(("127.0.0.1", target)).await else {
                        return;
                    };
                    let (mut cr, mut cw) = client.split();
                    let (mut sr, mut sw) = server.split();
                    let up = tokio::io::copy(&mut cr, &mut sw);
                    let down = async {
                        let mut buf = vec![0u8; 16 * 1024];
                        loop {
                            use tokio::io::{AsyncReadExt, AsyncWriteExt};
                            let n = match sr.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => n,
                            };
                            counter.fetch_add(n as u64, Ordering::Relaxed);
                            if cw.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        let _ = tokio::io::AsyncWriteExt::shutdown(&mut cw).await;
                    };
                    tokio::select! {
                        _ = up => {}
                        _ = down => {}
                    }
                });
            }
        });
        Self { port, received }
    }

    /// Bytes the server sent through the relay so far.
    pub fn received(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
    }
}

/// Every file path under `dir`.
pub fn files(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p.to_string_lossy().into_owned());
            }
        }
    }
    out.sort();
    out
}
