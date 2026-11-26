//! The test profile's pieces: Skein's fake providers behind the node's factories, and a whole
//! test node over a temporary directory, the in-memory keystore and `rinse-mail-direct`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use rinse_mail::Content;
use rowboat_keystore::Keystore;
use rowboat_keystore_memory::MemoryKeystore;
use skein_accounts::{AccountRecord, ProviderFactory, SenderFactory, SenderKind};
use skein_core::Credentials;
use skein_mail::testing::FakeMail;
use skein_mail::{MailError, MailProvider, MailSession};
use skein_send::testing::FakeSender;
use skein_send::{SendError, Sender};

use crate::{BuildError, Node, Profile, Providers, TestTiming};

/// One [`FakeMail`] per account (created on first use, with an `INBOX`, `Sent`, `Trash` and
/// `Archive`) and one shared [`FakeSender`]. Sign-in succeeds only with the password set by
/// [`FakeProviders::require_password`] (any password when none is set).
#[derive(Clone, Default)]
pub struct FakeProviders {
    by_user: Arc<Mutex<BTreeMap<String, FakeMail>>>,
    password: Arc<Mutex<Option<String>>>,
    sender: FakeSender,
}

impl FakeProviders {
    /// No servers yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Only `password` signs in from now on.
    pub fn require_password(&self, password: &str) {
        *self.password.lock().unwrap() = Some(password.to_owned());
    }

    /// The fake server for the user name `username` (accounts are matched by the user name of
    /// their setup), created with the standard mailboxes on first use.
    pub fn server(&self, username: &str) -> FakeMail {
        self.by_user
            .lock()
            .unwrap()
            .entry(username.to_owned())
            .or_insert_with(|| {
                let fake = FakeMail::new();
                for m in ["Sent", "Trash", "Archive"] {
                    fake.fill(m, 0, 0);
                }
                fake
            })
            .clone()
    }

    /// The shared sender, to read what was sent.
    pub fn sender(&self) -> FakeSender {
        self.sender.clone()
    }

    /// The factories for [`crate::NodeBuilder::providers`].
    pub fn providers(&self) -> Providers {
        Providers {
            mail: Arc::new(self.clone()),
            send: Arc::new(self.clone()),
        }
    }

    fn admits(&self, credentials: &Credentials) -> bool {
        match (&*self.password.lock().unwrap(), credentials) {
            (None, _) => true,
            (Some(want), Credentials::Password { secret }) => want == secret,
            _ => false,
        }
    }

    fn username(record: &AccountRecord) -> String {
        record
            .settings
            .get("username")
            .and_then(|u| u.as_str())
            .unwrap_or_default()
            .to_owned()
    }
}

struct Refusing;

#[async_trait]
impl MailProvider for Refusing {
    async fn connect(&self) -> Result<Box<dyn MailSession>, MailError> {
        Err(MailError::Auth)
    }
}

#[async_trait]
impl Sender for Refusing {
    async fn check(&self) -> Result<skein_send::Limits, SendError> {
        Err(SendError::Auth("refused by the fake".into()))
    }

    async fn send(
        &self,
        _: &skein_send::Envelope,
        _: &[u8],
    ) -> Result<skein_send::SendReport, SendError> {
        Err(SendError::Auth("refused by the fake".into()))
    }

    fn saves_to_sent(&self) -> bool {
        false
    }
}

impl ProviderFactory for FakeProviders {
    fn build(
        &self,
        record: &AccountRecord,
        credentials: Credentials,
    ) -> Result<Arc<dyn MailProvider>, MailError> {
        if !self.admits(&credentials) {
            return Ok(Arc::new(Refusing));
        }
        Ok(Arc::new(self.server(&Self::username(record))))
    }
}

impl SenderFactory for FakeProviders {
    fn build(
        &self,
        _: &AccountRecord,
        _: SenderKind,
        _: &serde_json::Value,
        credentials: Credentials,
    ) -> Result<Arc<dyn Sender>, SendError> {
        if !self.admits(&credentials) {
            return Ok(Arc::new(Refusing));
        }
        Ok(Arc::new(self.sender.clone()))
    }
}

/// A test node with its pieces, removed with its temporary directory when dropped.
pub struct TestNode {
    /// The node.
    pub node: Node,
    /// The fake servers and sender.
    pub fakes: FakeProviders,
    /// The keystore.
    pub keystore: MemoryKeystore,
    /// The data directory.
    pub dir: Arc<tempfile::TempDir>,
}

/// Fast timing for tests: 50 ms engine interval and heartbeat, 50 ms follower poll, the given
/// undo window.
pub fn fast(undo_ms: i64) -> TestTiming {
    TestTiming {
        heartbeat: Duration::from_millis(50),
        interval: Duration::from_millis(50),
        poll: Duration::from_millis(50),
        undo_ms,
        removal_grace: Duration::from_millis(150),
    }
}

/// Builds and starts a test node in a new temporary directory.
pub async fn test_node(undo_ms: i64) -> Result<TestNode, BuildError> {
    test_node_with_clock(undo_ms, Arc::new(crate::SystemClock)).await
}

/// [`test_node`] with the node's clock given, for decisions that depend on the time (the
/// freshness of arrivals: the fake servers date messages near the epoch).
pub async fn test_node_with_clock(
    undo_ms: i64,
    clock: Arc<dyn crate::Clock>,
) -> Result<TestNode, BuildError> {
    let dir = Arc::new(tempfile::tempdir().map_err(|_| BuildError::DataDir)?);
    let fakes = FakeProviders::new();
    let keystore = MemoryKeystore::new();
    let node = reopen_with_clock(&dir, &fakes, &keystore, undo_ms, clock).await?;
    Ok(TestNode {
        node,
        fakes,
        keystore,
        dir,
    })
}

/// Builds and starts a test node over an existing directory, fakes and keystore.
pub async fn reopen(
    dir: &tempfile::TempDir,
    fakes: &FakeProviders,
    keystore: &MemoryKeystore,
    undo_ms: i64,
) -> Result<Node, BuildError> {
    reopen_with_clock(dir, fakes, keystore, undo_ms, Arc::new(crate::SystemClock)).await
}

/// [`reopen`] with the node's clock given.
pub async fn reopen_with_clock(
    dir: &tempfile::TempDir,
    fakes: &FakeProviders,
    keystore: &MemoryKeystore,
    undo_ms: i64,
    clock: Arc<dyn crate::Clock>,
) -> Result<Node, BuildError> {
    let content: Arc<dyn Content> = Arc::new(rinse_mail_direct::DirectContent::new());
    let keystore: Arc<dyn Keystore> = Arc::new(keystore.clone());
    let node = Node::builder()
        .profile(Profile::Test(fast(undo_ms)))
        .data_dir(dir.path().join("node"))
        .keystore(keystore)
        .content(content)
        .providers(fakes.providers())
        .clock(clock)
        .build()
        .await?;
    node.start().await;
    Ok(node)
}
