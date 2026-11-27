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
        shutdown: Duration::from_secs(30),
        rounds: 1,
        fallback: None,
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
    reopen_on(dir, fakes, keystore, undo_ms, clock, None).await
}

/// [`reopen_with_clock`] with the endpoints the node binds its link and pairing endpoints on
/// (`rowboat-endpoint-memory` or loopback iroh in tests; none means no network).
pub async fn reopen_on(
    dir: &tempfile::TempDir,
    fakes: &FakeProviders,
    keystore: &MemoryKeystore,
    undo_ms: i64,
    clock: Arc<dyn crate::Clock>,
    endpoints: Option<Arc<dyn rowboat_endpoint::Endpoints>>,
) -> Result<Node, BuildError> {
    reopen_timed(dir, fakes, keystore, fast(undo_ms), clock, endpoints).await
}

/// A started test node with the given timing in a new temporary directory, without network.
pub async fn test_node_timed(timing: TestTiming) -> Result<TestNode, BuildError> {
    let dir = Arc::new(tempfile::tempdir().map_err(|_| BuildError::DataDir)?);
    let fakes = FakeProviders::new();
    let keystore = MemoryKeystore::new();
    let node = reopen_timed(
        &dir,
        &fakes,
        &keystore,
        timing,
        Arc::new(crate::SystemClock),
        None,
    )
    .await?;
    Ok(TestNode {
        node,
        fakes,
        keystore,
        dir,
    })
}

/// How a node of a multi-node test is built: its class, the fakes it shares with the other nodes
/// (one fake server per user name for all of them), its network and its revocation hook.
#[derive(Clone)]
pub struct Spec {
    /// The class it pairs as.
    pub class: baton_lease::NodeClass,
    /// The fake servers, shared between the nodes.
    pub fakes: FakeProviders,
    /// The network.
    pub endpoints: Arc<dyn rowboat_endpoint::Endpoints>,
    /// Timing.
    pub timing: TestTiming,
    /// Called when the node learns it was revoked.
    pub on_revoked: Option<crate::RevokedHook>,
}

/// Timing for multi-node tests: 1 s heartbeats (the test profile's leases live eight heartbeats,
/// so a loaded machine does not make holders lapse), syncs every 100 ms, 100 ms follower polls and
/// replication rounds.
pub fn group_timing() -> TestTiming {
    TestTiming {
        heartbeat: Duration::from_secs(1),
        interval: Duration::from_millis(100),
        poll: Duration::from_millis(100),
        undo_ms: 0,
        shutdown: Duration::from_secs(30),
        rounds: 1,
        fallback: None,
    }
}

/// A started node built from `spec` in a new temporary directory.
pub async fn test_node_as(spec: &Spec) -> Result<TestNode, BuildError> {
    let dir = Arc::new(tempfile::tempdir().map_err(|_| BuildError::DataDir)?);
    let keystore = MemoryKeystore::new();
    let node = reopen_as(&dir, &keystore, spec).await?;
    Ok(TestNode {
        node,
        fakes: spec.fakes.clone(),
        keystore,
        dir,
    })
}

/// Builds and starts the node of `dir` and `keystore` from `spec`.
pub async fn reopen_as(
    dir: &tempfile::TempDir,
    keystore: &MemoryKeystore,
    spec: &Spec,
) -> Result<Node, BuildError> {
    let content: Arc<dyn Content> = Arc::new(rinse_mail_direct::DirectContent::new());
    let ks: Arc<dyn Keystore> = Arc::new(keystore.clone());
    let mut builder = Node::builder()
        .profile(Profile::Test(spec.timing))
        .data_dir(dir.path().join("node"))
        .keystore(ks)
        .content(content)
        .providers(spec.fakes.providers())
        .endpoints(spec.endpoints.clone())
        .class(spec.class);
    if let Some(h) = &spec.on_revoked {
        builder = builder.on_revoked(h.clone());
    }
    let node = builder.build().await?;
    node.start().await;
    Ok(node)
}

async fn reopen_timed(
    dir: &tempfile::TempDir,
    fakes: &FakeProviders,
    keystore: &MemoryKeystore,
    timing: TestTiming,
    clock: Arc<dyn crate::Clock>,
    endpoints: Option<Arc<dyn rowboat_endpoint::Endpoints>>,
) -> Result<Node, BuildError> {
    let content: Arc<dyn Content> = Arc::new(rinse_mail_direct::DirectContent::new());
    let keystore: Arc<dyn Keystore> = Arc::new(keystore.clone());
    let mut builder = Node::builder()
        .profile(Profile::Test(timing))
        .data_dir(dir.path().join("node"))
        .keystore(keystore)
        .content(content)
        .providers(fakes.providers())
        .clock(clock);
    if let Some(e) = endpoints {
        builder = builder.endpoints(e);
    }
    let node = builder.build().await?;
    node.start().await;
    Ok(node)
}

/// A started test node in a new temporary directory, on `endpoints`.
pub async fn test_node_on(
    clock: Arc<dyn crate::Clock>,
    endpoints: Arc<dyn rowboat_endpoint::Endpoints>,
) -> Result<TestNode, BuildError> {
    let dir = Arc::new(tempfile::tempdir().map_err(|_| BuildError::DataDir)?);
    let fakes = FakeProviders::new();
    let keystore = MemoryKeystore::new();
    let node = reopen_on(&dir, &fakes, &keystore, 0, clock, Some(endpoints)).await?;
    Ok(TestNode {
        node,
        fakes,
        keystore,
        dir,
    })
}

impl Node {
    /// Appends `count` invented events to this node's own journal of `account` under `fence`
    /// (the fence of its local head when `None`), as a holder that still believes it leads
    /// would. Returns the fence used, or the storage's refusal.
    pub async fn write_for_tests(
        &self,
        account: &rowboat_api::AccountId,
        count: u64,
        fence: Option<u64>,
    ) -> Result<u64, skein_storage::StorageError> {
        let core = &self.core;
        let id = skein_core::AccountId::new(account.as_str()).unwrap();
        let head = core.local.log.signed_head(&core.tenant, &id).await?;
        let fence = fence.unwrap_or(head.head.fence.0);
        let events = (0..count)
            .map(|n| skein_core::Event {
                v: skein_core::SCHEMA_VERSION,
                seq: skein_core::Seq(0),
                at: skein_core::Timestamp(n as i64),
                account: id.clone(),
                key: format!("stale-{}-{n}", head.head.seq.0),
                origin: None,
                trace: None,
                body: skein_core::EventBody::ResyncRequired {
                    collection: "INBOX".into(),
                    reason: "test".into(),
                    domain: None,
                },
            })
            .collect();
        core.local
            .log
            .append(&core.tenant, &id, skein_core::FencingToken(fence), events)
            .await?;
        Ok(fence)
    }

    /// Makes this device treat the group's server as silent whatever it observes (`true`), or
    /// go back to judging by its own contact (`false`): a device that claims the server is
    /// silent while it is not.
    pub fn force_fallback_for_tests(&self, on: bool) {
        self.core.arbiter.force_fallback(on);
    }

    /// Why this device arbitrates without the server now: `Some("silence")`,
    /// `Some("leaving")`, or `None` while it follows the server (or is the server).
    pub fn fallback_for_tests(&self) -> Option<&'static str> {
        if !self.core.arbiter.in_fallback() {
            return None;
        }
        self.core.arbiter.fallback_reason().map(|r| match r {
            crate::fallback::Reason::Silence => "silence",
            crate::fallback::Reason::Leaving => "leaving",
        })
    }

    /// Whether this device's fallback arbiter decides its leases now (itself or another device).
    pub fn under_fallback_arbiter_for_tests(&self) -> bool {
        self.core.arbiter.arbiter().fallback()
    }

    /// The kind of grant behind this node's own head of `account`, if it carries one.
    pub async fn grant_for_tests(
        &self,
        account: &rowboat_api::AccountId,
    ) -> Option<rowboat_sync::GrantKind> {
        let id = skein_core::AccountId::new(account.as_str()).unwrap();
        let h = self
            .core
            .local
            .log
            .signed_head(&self.core.tenant, &id)
            .await
            .ok()?;
        rowboat_sync::head_grant(&h).map(|g| g.kind)
    }

    /// Whether this node keeps away from `account` for a fallback holder or a later grant.
    pub fn yields_for_tests(&self, account: &rowboat_api::AccountId) -> bool {
        self.core.arbiter.is_yielded(account.as_str())
    }

    /// This node's own head of `account` as it travels on the head protocol.
    pub async fn wire_head_for_tests(
        &self,
        account: &rowboat_api::AccountId,
    ) -> rowboat_sync::heads::WireHead {
        let id = skein_core::AccountId::new(account.as_str()).unwrap();
        let h = self
            .core
            .local
            .log
            .signed_head(&self.core.tenant, &id)
            .await
            .unwrap();
        rowboat_sync::heads::WireHead::new(&h, None)
    }

    /// Considers `head` as if the node `from` had announced it (verified, admitted, followed).
    pub async fn hear_for_tests(&self, from: &str, head: rowboat_sync::heads::WireHead) {
        let peer = baton_identity::PublicKey::from_node_id(&baton_core::NodeId::new(from).unwrap())
            .unwrap();
        if let Some(r) = self.core.replication.get() {
            r.hear(peer, vec![head]).await;
        }
    }

    /// A leaving notice for this node's group, signed by `signer` (this node's key when `None`)
    /// and dated now.
    pub fn leaving_notice_for_tests(&self, signer: Option<&baton_identity::Identity>) -> Vec<u8> {
        let m = self.core.group.membership().unwrap();
        let id = signer.unwrap_or(&m.keys().identity);
        crate::fallback::Leaving::sign(id, m.group().as_str(), self.core.clock.now_ms())
    }

    /// Sends `notice` to the node `to` on the leaving protocol; true when it was acknowledged.
    pub async fn send_leaving_for_tests(&self, to: &str, notice: &[u8]) -> bool {
        let Some(link) = self.core.group.link().await else {
            return false;
        };
        let peer =
            baton_identity::PublicKey::from_node_id(&baton_core::NodeId::new(to).unwrap()).unwrap();
        let protocol = baton_link::Protocol::new(crate::fallback::LEAVING_PROTOCOL).unwrap();
        let limit = Duration::from_secs(5);
        let Ok(mut s) = link.open(&peer, &protocol).await else {
            return false;
        };
        rowboat_group::wire::write_frame(&mut *s, notice, limit)
            .await
            .is_ok()
            && rowboat_group::wire::read_frame(&mut *s, 16, limit)
                .await
                .is_ok()
    }

    /// The head `(seq, fence)` of the offer of `account`'s state this node holds, if any.
    pub async fn offer_head_for_tests(
        &self,
        account: &rowboat_api::AccountId,
    ) -> Option<(u64, u64)> {
        let id = skein_core::AccountId::new(account.as_str()).unwrap();
        let offer = self.core.replication.get()?.staged(&id).await?;
        let h = offer.signed(&self.core.tenant).ok()?;
        Some((h.head.seq.0, h.head.fence.0))
    }

    /// Whether this node holds an offer of `account`'s state from the node that leads it.
    pub async fn holds_offer_for_tests(&self, account: &rowboat_api::AccountId) -> bool {
        let id = skein_core::AccountId::new(account.as_str()).unwrap();
        match self.core.replication.get() {
            Some(r) => r.staged(&id).await.is_some(),
            None => false,
        }
    }

    /// Whether this node runs a lease server now.
    pub async fn serves_leases_for_tests(&self) -> bool {
        self.core.arbiter.serves().await
    }

    /// Whether this node holds a journal of `account` (a head past the empty one).
    pub async fn has_head_for_tests(&self, account: &rowboat_api::AccountId) -> bool {
        let id = skein_core::AccountId::new(account.as_str()).unwrap();
        self.core
            .local
            .log
            .signed_head(&self.core.tenant, &id)
            .await
            .is_ok_and(|h| h.head.seq.0 > 0)
    }

    /// The event at `seq` of this node's journal of `account`, as text.
    pub async fn event_for_tests(
        &self,
        account: &rowboat_api::AccountId,
        seq: u64,
    ) -> Option<String> {
        let id = skein_core::AccountId::new(account.as_str()).unwrap();
        let events = self
            .core
            .local
            .log
            .read(&self.core.tenant, &id, skein_core::Seq(seq), 1)
            .await
            .ok()?;
        events.first().map(|e| format!("{e:?}"))
    }

    /// This node's own signed head of `account`: `(seq, fence, digest)`.
    pub async fn head_for_tests(&self, account: &rowboat_api::AccountId) -> (u64, u64, [u8; 32]) {
        let id = skein_core::AccountId::new(account.as_str()).unwrap();
        let h = self
            .core
            .local
            .log
            .signed_head(&self.core.tenant, &id)
            .await
            .unwrap();
        (h.head.seq.0, h.head.fence.0, h.head.digest())
    }

    /// Replaces the command classes this node's member holds on `account` with `classes` (read,
    /// lead and admin stay). For the capability tests.
    pub async fn set_member_classes_for_tests(
        &self,
        account: &rowboat_api::AccountId,
        classes: &[&str],
    ) {
        use baton_group::{Capability, Op, Principal};
        let m = self.core.group.membership().unwrap();
        let member = m.member_key().unwrap().public();
        let mut caps: std::collections::BTreeSet<Capability> =
            [Capability::Read, Capability::Lead, Capability::Admin].into();
        caps.extend(classes.iter().map(|c| Capability::Command((*c).to_owned())));
        m.append(vec![Op::Grant {
            resource: rowboat_group::account_resource(account.as_str()).unwrap(),
            principal: Principal::Member(member),
            capabilities: caps,
        }])
        .await
        .unwrap();
    }

    /// Turns the node's directory back into what a phase 1 build left: a format 1 record, a
    /// roster of one at `system/roster`, no group log and none of the group's keys. For the
    /// upgrade tests; it shuts the node down itself, then reopen.
    pub async fn regress_to_phase1_for_tests(&self, keystore: &MemoryKeystore) {
        self.stop_tasks().await;
        use rowboat_keystore::KeyName;
        use skein_storage::{Expect, ObjectKey};
        let core = &self.core;
        let key = ObjectKey::parse("system/node").unwrap();
        let (bytes, _) = core.objects.get(&key).await.unwrap().unwrap();
        let mut record = crate::records::decode_node_record(&bytes).unwrap();
        record.v = 1;
        core.objects
            .put(
                &key,
                bytes::Bytes::from(crate::records::encode_node_record(&record)),
                Expect::Any,
            )
            .await
            .unwrap();
        let state = skein_storage::ControlState::new(core.storage.control.clone());
        let group = baton_core::GroupId::new(record.group.clone()).unwrap();
        let prefix = baton_state::RecordName::new("group").unwrap();
        use baton_state::StateStore;
        for name in state.list(&group, &prefix, None, 10_000).await.unwrap() {
            state
                .delete(&group, &name, baton_state::Expect::Any)
                .await
                .unwrap();
        }
        let me = baton_identity::Identity::from_secret_bytes(
            &keystore
                .get(&KeyName::new("rowboat.identity").unwrap())
                .await
                .unwrap()
                .unwrap()
                .expose()
                .try_into()
                .unwrap(),
        );
        let roster = baton_identity::Roster::genesis(&me, group);
        core.objects
            .put(
                &ObjectKey::parse("system/roster").unwrap(),
                bytes::Bytes::from(roster.to_bytes()),
                Expect::Any,
            )
            .await
            .unwrap();
        for name in [
            crate::boot::NODE_KEM,
            crate::boot::MEMBER,
            crate::boot::RECOVERY,
        ] {
            keystore.delete(&KeyName::new(name).unwrap()).await.unwrap();
        }
        core.directory.close().await;
    }
}
