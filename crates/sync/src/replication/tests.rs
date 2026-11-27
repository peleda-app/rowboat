use std::collections::BTreeSet;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use async_trait::async_trait;
use baton_core::{GroupId, ResourceId, Timestamp};
use baton_group::{Capability, NodeCert, Op, Principal, epochs};
use baton_identity::{Identity, PublicKey};
use baton_keys::{KemSecret, RecoveryRoot};
use baton_lease::NodeClass;
use baton_link::Link;
use baton_link_memory::MemoryLinkHub;
use baton_signal_local::LocalSignal;
use baton_state_memory::MemoryState;
use bytes::Bytes;
use rowboat_group::{DAY_MS, Membership, NodeKeys, Now, account_resource};
use skein_core::{
    AccountId, BlobHash, CommandBody, Event, EventBody, FencingToken, Flags, ItemRef,
    SCHEMA_VERSION, SendEnvelope, Seq, TenantId,
};
use skein_storage::{JournalHead, Log, ObjectLog, Objects, SignedHead, Storage};
use skein_storage_memory::MemoryObjects;
use skein_storage_tiered::Tiered;

use super::*;
use crate::{About, Caught, NodeAttestor, PeerTier, Peers, Settled, SyncError, attest};

const T0: i64 = 1_800_000_000_000;
const CLASSES: &[&str] = &[
    "mail-flags",
    "mail-move",
    "mail-delete",
    "mail-send",
    "mail-send-cancel",
    "mail-sync",
];

#[derive(Clone)]
struct Clock(Arc<AtomicI64>);

impl Clock {
    fn new() -> Self {
        Self(Arc::new(AtomicI64::new(T0)))
    }
    fn now(&self) -> Now {
        let c = self.0.clone();
        Arc::new(move || Timestamp(c.load(Ordering::SeqCst)))
    }
    fn advance(&self, ms: i64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }
}

#[derive(Default)]
struct FakeHost {
    leads: Mutex<BTreeSet<AccountId>>,
    about: Mutex<Option<About>>,
    described: Mutex<Vec<(AccountId, PublicKey)>>,
    installed: Mutex<Vec<(AccountId, u64)>>,
    forked: Mutex<Vec<AccountId>>,
    settled: Mutex<Vec<(String, Settled)>>,
    view: Mutex<BTreeSet<BlobHash>>,
    behind: Mutex<Vec<PublicKey>>,
    reset: Mutex<Vec<AccountId>>,
    replication: OnceLock<Weak<Replication>>,
    silent_owner: std::sync::atomic::AtomicBool,
}

#[async_trait]
impl Host for FakeHost {
    fn leads(&self, account: &AccountId) -> bool {
        self.leads.lock().unwrap().contains(account)
    }
    async fn about(&self, account: &AccountId) -> Option<About> {
        if self.leads(account) {
            self.about.lock().unwrap().clone()
        } else {
            None
        }
    }
    async fn holds_blob(&self, account: &AccountId, blob: &BlobHash) -> bool {
        self.view.lock().unwrap().contains(blob)
            || self
                .replication
                .get()
                .and_then(Weak::upgrade)
                .is_some_and(|r| r.outbox_holds(account, blob))
    }
    async fn described(&self, account: &AccountId, owner: &PublicKey, _: &About) {
        self.described
            .lock()
            .unwrap()
            .push((account.clone(), *owner));
    }
    fn installed(&self, account: &AccountId, seq: u64) {
        self.installed.lock().unwrap().push((account.clone(), seq));
    }
    fn forked(&self, account: &AccountId) {
        self.forked.lock().unwrap().push(account.clone());
    }
    fn settled(&self, _: &AccountId, command: &str, outcome: Settled) {
        self.settled
            .lock()
            .unwrap()
            .push((command.to_owned(), outcome));
    }

    fn group_behind(&self, peer: &PublicKey) {
        self.behind.lock().unwrap().push(*peer);
    }

    async fn reset(&self, account: &AccountId) {
        self.reset.lock().unwrap().push(account.clone());
    }

    fn previous_owner_silent(&self, _: &AccountId) -> bool {
        self.silent_owner.load(Ordering::SeqCst)
    }
}

struct Node {
    m: Arc<Membership>,
    local: Storage,
    host: Arc<FakeHost>,
    r: Arc<Replication>,
    link: Arc<dyn Link>,
}

fn tenant() -> TenantId {
    TenantId::new("gtestgroup").unwrap()
}

fn group() -> GroupId {
    GroupId::new("gtestgroup").unwrap()
}

fn acct(name: &str) -> AccountId {
    AccountId::new(name).unwrap()
}

fn res(a: &AccountId) -> ResourceId {
    account_resource(a.as_str()).unwrap()
}

fn keys(member: Option<&Identity>) -> NodeKeys {
    NodeKeys {
        identity: Identity::generate(),
        kem: KemSecret::generate(),
        member: member.cloned(),
    }
}

/// Long enough that no step of a correct run ever reaches it, however loaded the machine.
const HANG: Duration = Duration::from_secs(300);

fn config() -> Config {
    Config {
        limit: HANG,
        fetch: baton_fetch::FetchConfig {
            peer_timeout: HANG,
            ..baton_fetch::FetchConfig::default()
        },
    }
}

async fn eventually<F: Future<Output = bool>>(what: &str, mut f: impl FnMut() -> F) {
    let wait = async {
        while !f().await {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    if tokio::time::timeout(HANG, wait).await.is_err() {
        panic!("hung waiting for {what}");
    }
}

async fn node(hub: &MemoryLinkHub, m: Arc<Membership>, clock: &Clock) -> Node {
    let objects: Arc<dyn Objects> = Arc::new(MemoryObjects::new());
    let local = Storage::over_attested(objects.clone(), Arc::new(NodeAttestor::new(m.clone())));
    let peers = Arc::new(Peers::new(m.clone()));
    let through = Tiered::new(local.clone())
        .with_tier(Arc::new(PeerTier::new(peers.clone())))
        .build();
    let host = Arc::new(FakeHost::default());
    let r = Arc::new(Replication::new(
        tenant(),
        peers,
        local.clone(),
        through,
        Arc::new(LocalSignal::new()),
        host.clone(),
        clock.now(),
        config(),
    ));
    let _ = host.replication.set(Arc::downgrade(&r));
    r.load().await.unwrap();
    let link: Arc<dyn Link> = Arc::new(hub.join(m.node(), m.trust()));
    r.attach(link.clone()).await.unwrap();
    Node {
        m,
        local,
        host,
        r,
        link,
    }
}

async fn certify(
    a: &Membership,
    member: &Identity,
    clock: &Clock,
) -> (NodeKeys, Vec<baton_group::Entry>) {
    let k = keys(Some(member));
    let cert = NodeCert::new(
        member,
        &k.identity,
        k.kem.public(),
        NodeClass::Desktop,
        Timestamp(clock.now()().0 + 400 * DAY_MS),
    );
    let entries = a.certify(cert).await.unwrap();
    (k, entries)
}

struct World {
    clock: Clock,
    hub: MemoryLinkHub,
    member: Identity,
    a: Node,
    b: Node,
    account: AccountId,
}

async fn world() -> World {
    let clock = Clock::new();
    let hub = MemoryLinkHub::new();
    let member = Identity::generate();
    let ma = Membership::found(
        Arc::new(MemoryState::new()),
        group(),
        keys(Some(&member)),
        RecoveryRoot::generate().public(),
        RecoveryRoot::generate().public(),
        NodeClass::Desktop,
        Timestamp(T0 + 400 * DAY_MS),
        clock.now(),
    )
    .await
    .unwrap();
    let ma = Arc::new(ma);
    let account = acct("ax");
    ma.ensure_resource(&res(&account), CLASSES).await.unwrap();
    let (kb, _) = certify(&ma, &member, &clock).await;
    let mb = Arc::new(
        Membership::adopt(
            Arc::new(MemoryState::new()),
            ma.log(),
            kb,
            Vec::new(),
            clock.now(),
        )
        .await
        .unwrap(),
    );
    let a = node(&hub, ma, &clock).await;
    let b = node(&hub, mb, &clock).await;
    a.host.leads.lock().unwrap().insert(account.clone());
    *a.host.about.lock().unwrap() = Some(About {
        address: "ada@example.com".into(),
        display_name: Some("Ada".into()),
        archive: None,
    });
    World {
        clock,
        hub,
        member,
        a,
        b,
        account,
    }
}

fn message(account: &AccountId, n: u64, blob: BlobHash) -> Event {
    Event {
        v: SCHEMA_VERSION,
        seq: Seq(0),
        at: skein_core::Timestamp(n as i64),
        account: account.clone(),
        key: format!("m{n}"),
        origin: None,
        trace: None,
        body: EventBody::MessageAdded {
            mailbox: "INBOX".into(),
            item: ItemRef {
                id: format!("1:{n}"),
                uid: Some(n as u32),
            },
            blob,
            size: 10,
            flags: Flags::default(),
            labels: None,
            received_at: None,
        },
    }
}

/// The owner syncs `n` messages in batches of `batch` under `fence`, storing their blobs.
async fn write(owner: &Node, account: &AccountId, from: u64, n: u64, batch: u64, fence: u64) {
    let mut i = from;
    while i < from + n {
        let mut events = Vec::new();
        for k in i..(i + batch).min(from + n) {
            let body = Bytes::from(format!("From: s{k}@example.org\r\n\r\nbody {k}\r\n"));
            let blob = owner.local.blobs.put(&tenant(), body).await.unwrap();
            owner.host.view.lock().unwrap().insert(blob);
            events.push(message(account, k, blob));
        }
        owner
            .local
            .log
            .append(&tenant(), account, FencingToken(fence), events)
            .await
            .unwrap();
        i += batch;
    }
}

async fn head(n: &Node, account: &AccountId) -> SignedHead {
    n.local.log.signed_head(&tenant(), account).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_follows_the_owner_byte_for_byte_with_blobs() {
    let w = world().await;
    write(&w.a, &w.account, 1, 25, 4, 1).await;
    let results = w.b.r.round().await;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].1, Ok(Caught::Installed { seq: 25 }));
    assert_eq!(head(&w.b, &w.account).await, head(&w.a, &w.account).await);
    assert_eq!(
        w.b.local
            .log
            .read(&tenant(), &w.account, Seq(1), 100)
            .await
            .unwrap(),
        w.a.local
            .log
            .read(&tenant(), &w.account, Seq(1), 100)
            .await
            .unwrap()
    );
    let blobs: Vec<BlobHash> = w.a.host.view.lock().unwrap().iter().copied().collect();
    for blob in &blobs {
        assert!(w.b.local.blobs.contains(&tenant(), blob).await.unwrap());
    }
    assert_eq!(w.b.r.peers().owner(&w.account), Some(w.a.m.node()));
    assert_eq!(
        w.b.host.described.lock().unwrap().as_slice(),
        &[(w.account.clone(), w.a.m.node())]
    );
    assert_eq!(w.b.r.round().await[0].1, Ok(Caught::Current));

    write(&w.a, &w.account, 26, 3, 3, 2).await;
    assert_eq!(w.a.r.announce(&w.account).await, 1);
    eventually("the announced head", || async {
        head(&w.b, &w.account).await.head.seq == Seq(28)
    })
    .await;
    assert_eq!(head(&w.b, &w.account).await.head.seq, Seq(28));
    assert_eq!(
        w.b.host.installed.lock().unwrap().last(),
        Some(&(w.account.clone(), 28))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn old_lower_and_unsigned_heads_change_nothing() {
    let w = world().await;
    write(&w.a, &w.account, 1, 4, 2, 1).await;
    let old = head(&w.a, &w.account).await;
    write(&w.a, &w.account, 5, 2, 2, 2).await;
    w.b.r.round().await;
    let now = head(&w.b, &w.account).await;
    assert_eq!(now.head.seq, Seq(6));
    assert_eq!(
        w.b.r.follow(&old).await,
        Ok(Caught::Stale),
        "a replayed head with a lower seq and fence"
    );

    let stripped = SignedHead {
        attestation: None,
        ..now.clone()
    };
    assert_eq!(
        verify_remote(&w.b.m, &stripped, w.clock.now()()),
        Err(SyncError::Unverified)
    );
    let swapped = SignedHead {
        attestation: old.attestation.clone(),
        ..now.clone()
    };
    assert_eq!(
        verify_remote(&w.b.m, &swapped, w.clock.now()()),
        Err(SyncError::Unverified),
        "a valid signature over another head"
    );
    let stranger = Identity::generate();
    let foreign = SignedHead {
        attestation: Some(attest(&stranger, &now.head)),
        ..now.clone()
    };
    assert_eq!(
        verify_remote(&w.b.m, &foreign, w.clock.now()()),
        Err(SyncError::NotAuthorized)
    );
    assert_eq!(head(&w.b, &w.account).await, now);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn heads_of_nodes_without_lead_or_revoked_are_refused() {
    let w = world().await;
    let (kc, entries) = certify(&w.a.m, &w.member, &w.clock).await;
    w.b.m.apply_remote(entries).await.unwrap();
    let c = kc.identity.public();
    let y = acct("ay");
    let ops = vec![
        Op::CreateResource { resource: res(&y) },
        Op::Grant {
            resource: res(&y),
            principal: Principal::Node(w.a.m.node()),
            capabilities: [Capability::Read, Capability::Lead, Capability::Admin].into(),
        },
        Op::Grant {
            resource: res(&y),
            principal: Principal::Member(w.member.public()),
            capabilities: BTreeSet::new(),
        },
        Op::Grant {
            resource: res(&y),
            principal: Principal::Node(c),
            capabilities: [Capability::Read].into(),
        },
    ];
    let mut entries = w.a.m.append(ops).await.unwrap();
    let epoch = w.a.m.with_log(|l| {
        epochs::new_epoch(l.state(), &res(&y), w.clock.now()())
            .unwrap()
            .0
    });
    entries.extend(w.a.m.append(vec![epoch]).await.unwrap());
    w.b.m.apply_remote(entries).await.unwrap();

    let h = JournalHead::empty(tenant(), y.clone());
    let reader = SignedHead {
        attestation: Some(attest(&kc.identity, &h)),
        head: h,
    };
    assert_eq!(
        verify_remote(&w.b.m, &reader, w.clock.now()()),
        Err(SyncError::NotAuthorized)
    );

    let hx = JournalHead::empty(tenant(), w.account.clone());
    let by_c = SignedHead {
        attestation: Some(attest(&kc.identity, &hx)),
        head: hx,
    };
    assert_eq!(
        verify_remote(&w.b.m, &by_c, w.clock.now()()).map(|_| ()),
        Ok(())
    );
    let entries = {
        let before = w.a.m.head().0;
        w.a.m.revoke(&c).await.unwrap();
        w.a.m
            .with_log(|l| l.entries()[(before + 1) as usize..].to_vec())
    };
    w.b.m.apply_remote(entries).await.unwrap();
    assert_eq!(
        verify_remote(&w.b.m, &by_c, w.clock.now()()),
        Err(SyncError::NotAuthorized)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fork_stops_following_and_keeps_evidence() {
    let w = world().await;
    write(&w.a, &w.account, 1, 4, 2, 1).await;
    w.b.r.round().await;
    let deposed: Arc<dyn Objects> = Arc::new(MemoryObjects::new());
    let other = ObjectLog::with_attestor(deposed, Arc::new(NodeAttestor::new(w.a.m.clone())));
    for (from, n) in [(1u64, 2u64), (103, 2)] {
        let events = (from..from + n)
            .map(|k| message(&w.account, k, BlobHash::of(b"x")))
            .collect();
        other
            .append(&tenant(), &w.account, FencingToken(1), events)
            .await
            .unwrap();
    }
    let forked = other.signed_head(&tenant(), &w.account).await.unwrap();
    assert_eq!(forked.head.seq, head(&w.b, &w.account).await.head.seq);
    assert_eq!(w.b.r.follow(&forked).await, Ok(Caught::Forked));
    assert!(w.b.r.is_forked(&w.account));
    assert_eq!(
        w.b.host.forked.lock().unwrap().as_slice(),
        std::slice::from_ref(&w.account)
    );
    assert!(
        w.b.local
            .control
            .get(&tenant(), &fork_path(&w.account))
            .await
            .unwrap()
            .is_some()
    );
    write(&w.a, &w.account, 5, 2, 2, 1).await;
    assert!(
        w.b.r.round().await.is_empty(),
        "a forked account is not followed"
    );
    assert_eq!(head(&w.b, &w.account).await.head.seq, Seq(4));
    w.b.r.clear_fork(&w.account).await.unwrap();
    assert_eq!(w.b.r.round().await[0].1, Ok(Caught::Installed { seq: 6 }));
}

type Attack = Box<dyn Fn(&Bytes, usize) -> Bytes>;

/// A peer that serves whatever it was given under a segment's name.
struct Hostile(Mutex<std::collections::BTreeMap<Vec<u8>, Bytes>>);

#[async_trait]
impl baton_fetch::LocalObjects for Hostile {
    async fn get(
        &self,
        _: &ResourceId,
        _: &baton_fetch::ContentId,
        locator: &[u8],
    ) -> Option<Bytes> {
        self.0.lock().unwrap().get(locator).cloned()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hostile_peers_serving_wrong_segments_are_skipped() {
    let w = world().await;
    let (kc, entries) = certify(&w.a.m, &w.member, &w.clock).await;
    w.b.m.apply_remote(entries).await.unwrap();
    let mc = Arc::new(
        Membership::adopt(
            Arc::new(MemoryState::new()),
            w.a.m.log(),
            kc,
            Vec::new(),
            w.clock.now(),
        )
        .await
        .unwrap(),
    );
    let c_key = mc.node();
    let c_link: Arc<dyn Link> = Arc::new(w.hub.join(c_key, mc.trust()));
    let served = Arc::new(Hostile(Mutex::new(std::collections::BTreeMap::new())));
    let _serving = baton_fetch::serve(
        c_link.clone(),
        served.clone(),
        Arc::new(|_, _| true),
        baton_fetch::FetchConfig::default(),
    )
    .await
    .unwrap();
    write(&w.a, &w.account, 1, 6, 2, 1).await;
    let other = acct("aother");
    write(&w.a, &other, 1, 2, 2, 1).await;
    let wanted = head(&w.a, &w.account).await;
    let segments: Vec<(String, Bytes)> = {
        let mut out = Vec::new();
        let mut chain = skein_storage::Chain::new(&*w.a.local.log, &wanted.head);
        while let Some(s) = chain.next().await.unwrap() {
            let b =
                w.a.local
                    .log
                    .segment(&tenant(), &w.account, &s.segment)
                    .await
                    .unwrap()
                    .unwrap();
            out.push((s.segment.name(), b));
        }
        out
    };
    let foreign = head(&w.a, &other).await;
    let foreign_bytes =
        w.a.local
            .log
            .segment(&tenant(), &other, foreign.head.tip.as_ref().unwrap())
            .await
            .unwrap()
            .unwrap();

    w.hub.partition(&[&[w.b.m.node(), c_key], &[w.a.m.node()]]);
    let attacks: Vec<(&str, Attack)> = vec![
        (
            "oversized",
            Box::new(|b: &Bytes, _| {
                let mut v = b.to_vec();
                v.resize(70 * 1024 * 1024, 0);
                Bytes::from(v)
            }),
        ),
        (
            "flipped",
            Box::new(|b: &Bytes, _| {
                let mut v = b.to_vec();
                let i = v.len() / 2;
                v[i] ^= 1;
                Bytes::from(v)
            }),
        ),
        ("truncated", Box::new(|b: &Bytes, _| b.slice(..b.len() - 3))),
        ("reordered", {
            let s = segments.clone();
            Box::new(move |_: &Bytes, i| s[(i + 1) % s.len()].1.clone())
        }),
        ("another account", {
            let f = foreign_bytes.clone();
            Box::new(move |_: &Bytes, _| f.clone())
        }),
    ];
    for (what, attack) in attacks {
        for (i, (name, bytes)) in segments.iter().enumerate() {
            served
                .0
                .lock()
                .unwrap()
                .insert(name.as_bytes().to_vec(), attack(bytes, i));
        }
        w.b.r.attach(w.b.link.clone()).await.unwrap();
        let r = w.b.r.follow(&wanted).await;
        assert_eq!(r, Err(SyncError::Unreachable), "{what}");
        assert_eq!(head(&w.b, &w.account).await.head.seq, Seq(0), "{what}");
    }
    let fetcher = w.b.r.peers().fetcher().unwrap();
    assert!(fetcher.liars(&res(&w.account)).contains(&c_key));

    w.hub.heal();
    w.b.r.attach(w.b.link.clone()).await.unwrap();
    w.b.r.peers().set_owner(&w.account, w.a.m.node());
    assert_eq!(
        w.b.r.follow(&wanted).await,
        Ok(Caught::Installed { seq: 6 })
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_without_read_gets_nothing() {
    let w = world().await;
    let (kc, entries) = certify(&w.a.m, &w.member, &w.clock).await;
    w.b.m.apply_remote(entries).await.unwrap();
    let z = acct("az");
    let mut entries =
        w.a.m
            .append(vec![
                Op::CreateResource { resource: res(&z) },
                Op::Grant {
                    resource: res(&z),
                    principal: Principal::Node(w.a.m.node()),
                    capabilities: [Capability::Read, Capability::Lead, Capability::Admin].into(),
                },
                Op::Grant {
                    resource: res(&z),
                    principal: Principal::Member(w.member.public()),
                    capabilities: BTreeSet::new(),
                },
            ])
            .await
            .unwrap();
    let epoch = w.a.m.with_log(|l| {
        epochs::new_epoch(l.state(), &res(&z), w.clock.now()())
            .unwrap()
            .0
    });
    entries.extend(w.a.m.append(vec![epoch]).await.unwrap());
    w.a.host.leads.lock().unwrap().insert(z.clone());
    let mc = Arc::new(
        Membership::adopt(
            Arc::new(MemoryState::new()),
            w.a.m.log(),
            kc,
            Vec::new(),
            w.clock.now(),
        )
        .await
        .unwrap(),
    );
    let c = node(&w.hub, mc, &w.clock).await;
    write(&w.a, &z, 1, 2, 2, 1).await;
    let h = head(&w.a, &z).await;
    let tip = h.head.tip.clone().unwrap();
    let fetcher = c.r.peers().fetcher().unwrap();
    let got = fetcher
        .fetch_located(
            &res(&z),
            &baton_fetch::ContentId(tip.hash.0),
            tip.name().as_bytes(),
            &[w.a.m.node()],
        )
        .await;
    assert!(matches!(got, Err(baton_fetch::FetchError::NotFound)));
    let blob = *w.a.host.view.lock().unwrap().iter().next().unwrap();
    assert!(matches!(
        fetcher
            .fetch(
                &res(&z),
                &baton_fetch::ContentId(*blob.as_bytes()),
                &[w.a.m.node()]
            )
            .await,
        Err(baton_fetch::FetchError::NotFound)
    ));
    let answer =
        c.r.ask(&c.link, &w.a.m.node(), std::slice::from_ref(&z))
            .await
            .unwrap();
    assert!(answer.is_empty(), "no head for an account it may not read");
    assert!(!c.r.followed().contains(&z));
}

fn flags(account: &AccountId) -> CommandBody {
    let _ = account;
    CommandBody::SetFlags {
        mailbox: "INBOX".into(),
        items: vec![ItemRef {
            id: "1:1".into(),
            uid: Some(1),
        }],
        add: Flags::new(["\\Seen"]),
        remove: Flags::default(),
    }
}

/// Issues `body` from `n` into its outbox without delivering it, and returns the encoded Baton
/// command.
async fn parked(n: &Node, account: &AccountId, body: CommandBody) -> (CommandId, Vec<u8>) {
    n.r.detach().await;
    let id = n.r.submit(account, body).await.unwrap();
    let bytes = n.r.outbox.lock().unwrap()[id.as_str()].command.clone();
    (id, bytes)
}

fn applied(reply: &CmdMsg) -> bool {
    matches!(reply, CmdMsg::Result { .. })
}

async fn pending(n: &Node, account: &AccountId) -> Vec<skein_core::Command> {
    n.local
        .commands
        .pending(&tenant(), account, 100)
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn commands_reach_the_owner_queue_once() {
    let w = world().await;
    write(&w.a, &w.account, 1, 2, 2, 1).await;
    w.b.r.round().await;
    let id = w.b.r.submit(&w.account, flags(&w.account)).await.unwrap();
    eventually("the outbox to drain", || async {
        w.b.r.flush().await;
        w.b.r.outbox_len() == 0
    })
    .await;
    assert_eq!(w.b.r.outbox_len(), 0);
    let queued = pending(&w.a, &w.account).await;
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].id, id, "the owner queued it under the derived id");

    let (id2, bytes) = parked(&w.b, &w.account, flags(&w.account)).await;
    for _ in 0..3 {
        assert!(applied(&w.a.r.handle(&bytes).await), "redelivered");
    }
    let queued = pending(&w.a, &w.account).await;
    assert_eq!(queued.len(), 2);
    assert!(queued.iter().any(|c| c.id == id2));
    w.a.local
        .commands
        .complete(&tenant(), &w.account, &id2)
        .await
        .unwrap();
    assert!(applied(&w.a.r.handle(&bytes).await));
    assert_eq!(
        pending(&w.a, &w.account).await.len(),
        1,
        "a finished command never runs again"
    );

    let mut forged = bytes.clone();
    let i = forged.len() - 70;
    forged[i] ^= 1;
    assert!(matches!(
        w.a.r.handle(&forged).await,
        CmdMsg::Refused { .. }
    ));
    w.clock.advance(COMMAND_TTL_MS + 1);
    let (_, late) = parked(&w.b, &w.account, flags(&w.account)).await;
    w.clock.advance(COMMAND_TTL_MS + 1);
    assert_eq!(
        w.a.r.handle(&late).await,
        CmdMsg::Refused {
            reason: "expired".into()
        }
    );
    assert!(
        matches!(w.b.r.handle(&bytes).await, CmdMsg::NotHere),
        "only the owner runs it"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_same_key_from_two_issuers_makes_two_commands() {
    let w = world().await;
    let (kc, entries) = certify(&w.a.m, &w.member, &w.clock).await;
    w.b.m.apply_remote(entries).await.unwrap();
    let mc = Arc::new(
        Membership::adopt(
            Arc::new(MemoryState::new()),
            w.a.m.log(),
            kc,
            Vec::new(),
            w.clock.now(),
        )
        .await
        .unwrap(),
    );
    let c = node(&w.hub, mc, &w.clock).await;
    let key = CommandId::generate();
    let mut ids = Vec::new();
    for n in [&w.b, &c] {
        let q = derive_queue_id(
            &n.m.node().to_bytes(),
            res(&w.account).as_str(),
            key.as_str(),
        )
        .unwrap();
        let request = RemoteRequest::Submit {
            command: Box::new(skein_core::Command {
                id: q.clone(),
                account: w.account.clone(),
                created_at: skein_core::Timestamp(0),
                trace: None,
                body: flags(&w.account),
            }),
        };
        let bytes =
            n.r.issue(&w.account, &request, key.as_str(), COMMAND_TTL_MS)
                .unwrap();
        assert!(applied(&w.a.r.handle(&bytes).await));
        ids.push(q);
    }
    assert_ne!(ids[0], ids[1]);
    assert_eq!(pending(&w.a, &w.account).await.len(), 2);

    let wrong = RemoteRequest::Submit {
        command: Box::new(skein_core::Command {
            id: ids[0].clone(),
            account: w.account.clone(),
            created_at: skein_core::Timestamp(0),
            trace: None,
            body: flags(&w.account),
        }),
    };
    let bytes =
        c.r.issue(&w.account, &wrong, key.as_str(), COMMAND_TTL_MS)
            .unwrap();
    assert!(applied(&w.a.r.handle(&bytes).await));
    let r = baton_command::Command::decode(&bytes).unwrap();
    let CmdMsg::Result { bytes: result } = w.a.r.handle(&bytes).await else {
        panic!("a signed answer");
    };
    let result = baton_command::CommandResult::decode(&result).unwrap();
    let keys = c.m.resource_keys(r.resource(), r.epoch()).unwrap();
    assert_eq!(
        result.check(&r, &c.m.log(), &keys.data, w.clock.now()()),
        Ok(Outcome::Failed {
            reason: "wrong_id".into()
        }),
        "another issuer's queue id is refused"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn commands_without_the_class_or_from_another_group_are_refused() {
    let w = world().await;
    let (kc, entries) = certify(&w.a.m, &w.member, &w.clock).await;
    w.b.m.apply_remote(entries).await.unwrap();
    let c_key = kc.identity.public();
    let y = acct("ay");
    let mut entries =
        w.a.m
            .append(vec![
                Op::CreateResource { resource: res(&y) },
                Op::Grant {
                    resource: res(&y),
                    principal: Principal::Node(w.a.m.node()),
                    capabilities: [Capability::Read, Capability::Lead, Capability::Admin].into(),
                },
                Op::Grant {
                    resource: res(&y),
                    principal: Principal::Member(w.member.public()),
                    capabilities: BTreeSet::new(),
                },
                Op::Grant {
                    resource: res(&y),
                    principal: Principal::Node(c_key),
                    capabilities: [Capability::Read].into(),
                },
            ])
            .await
            .unwrap();
    let epoch = w.a.m.with_log(|l| {
        epochs::new_epoch(l.state(), &res(&y), w.clock.now()())
            .unwrap()
            .0
    });
    entries.extend(w.a.m.append(vec![epoch]).await.unwrap());
    w.a.host.leads.lock().unwrap().insert(y.clone());
    let mc = Arc::new(
        Membership::adopt(
            Arc::new(MemoryState::new()),
            w.a.m.log(),
            kc,
            Vec::new(),
            w.clock.now(),
        )
        .await
        .unwrap(),
    );
    let c = node(&w.hub, mc, &w.clock).await;
    let (_, bytes) = parked(&c, &y, flags(&y)).await;
    assert_eq!(
        w.a.r.handle(&bytes).await,
        CmdMsg::Refused {
            reason: "not_authorized".into()
        }
    );

    let other = World::stranger(&w.clock).await;
    other
        .ensure_resource(&res(&w.account), CLASSES)
        .await
        .unwrap();
    let hub = MemoryLinkHub::new();
    let stranger = node(&hub, Arc::new(other), &w.clock).await;
    let (_, bytes) = parked(&stranger, &w.account, flags(&w.account)).await;
    assert!(matches!(w.a.r.handle(&bytes).await, CmdMsg::Refused { .. }));
    assert!(pending(&w.a, &w.account).await.is_empty());
    assert!(pending(&w.a, &y).await.is_empty());
}

impl World {
    async fn stranger(clock: &Clock) -> Membership {
        let member = Identity::generate();
        Membership::found(
            Arc::new(MemoryState::new()),
            group(),
            keys(Some(&member)),
            RecoveryRoot::generate().public(),
            RecoveryRoot::generate().public(),
            NodeClass::Desktop,
            Timestamp(T0 + 400 * DAY_MS),
            clock.now(),
        )
        .await
        .unwrap()
    }
}

fn send_body(blob: BlobHash, from: &str) -> CommandBody {
    CommandBody::Send {
        blob,
        envelope: SendEnvelope {
            from: from.into(),
            to: vec!["bob@example.org".into()],
            dsn: None,
        },
        save_to_sent: None,
        send_at: None,
        dry_run: false,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_send_carries_its_blob_and_must_come_from_the_account() {
    let w = world().await;
    write(&w.a, &w.account, 1, 2, 2, 1).await;
    w.b.r.round().await;
    let message = Bytes::from_static(b"From: ada@example.com\r\nTo: bob@example.org\r\n\r\nhi\r\n");
    let blob =
        w.b.local
            .blobs
            .put(&tenant(), message.clone())
            .await
            .unwrap();
    assert!(!w.a.local.blobs.contains(&tenant(), &blob).await.unwrap());

    let wrong =
        w.b.r
            .submit(&w.account, send_body(blob, "eve@example.net"))
            .await
            .unwrap();
    let id =
        w.b.r
            .submit(&w.account, send_body(blob, "ADA@example.com"))
            .await
            .unwrap();
    eventually("the outbox to drain", || async {
        w.b.r.flush().await;
        w.b.r.outbox_len() == 0
    })
    .await;
    let queued = pending(&w.a, &w.account).await;
    assert_eq!(
        queued.iter().map(|c| c.id.clone()).collect::<Vec<_>>(),
        vec![id]
    );
    assert_eq!(
        w.a.local.blobs.get(&tenant(), &blob).await.unwrap(),
        Some(message),
        "the owner fetched the message from the issuer"
    );
    assert_eq!(
        w.b.host.settled.lock().unwrap().as_slice(),
        &[(
            wrong.to_string(),
            Settled::Failed {
                reason: "wrong_sender".into()
            }
        )]
    );
    assert!(!w.b.r.outbox_holds(&w.account, &blob));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_expired_outbox_entry_settles_failed() {
    let w = world().await;
    let (id, _) = parked(&w.b, &w.account, flags(&w.account)).await;
    w.clock.advance(COMMAND_TTL_MS + 1);
    w.b.r.flush().await;
    assert_eq!(w.b.r.outbox_len(), 0);
    assert_eq!(
        w.b.host.settled.lock().unwrap().as_slice(),
        &[(
            id.to_string(),
            Settled::Failed {
                reason: "expired".into()
            }
        )]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_outbox_survives_a_restart_and_old_cmdkeys_are_pruned() {
    let w = world().await;
    write(&w.a, &w.account, 1, 2, 2, 1).await;
    w.b.r.round().await;
    let owner = w.b.r.peers().owner(&w.account).unwrap();
    let (id, _) = parked(&w.b, &w.account, flags(&w.account)).await;
    let peers = Arc::new(Peers::new(w.b.m.clone()));
    peers.set_owner(&w.account, owner);
    let through = Tiered::new(w.b.local.clone())
        .with_tier(Arc::new(PeerTier::new(peers.clone())))
        .build();
    let again = Arc::new(Replication::new(
        tenant(),
        peers,
        w.b.local.clone(),
        through,
        Arc::new(LocalSignal::new()),
        w.b.host.clone(),
        w.clock.now(),
        config(),
    ));
    again.load().await.unwrap();
    assert_eq!(again.outbox_len(), 1);
    again.attach(w.b.link.clone()).await.unwrap();
    again.flush().await;
    assert_eq!(again.outbox_len(), 0);
    assert!(pending(&w.a, &w.account).await.iter().any(|c| c.id == id));
    assert_eq!(w.a.r.prune().await, 0);
    w.clock.advance(CMDKEY_TTL_MS + 1);
    assert_eq!(w.a.r.prune().await, 1);
}

async fn third(w: &World) -> Node {
    let (kc, entries) = certify(&w.a.m, &w.member, &w.clock).await;
    w.b.m.apply_remote(entries).await.unwrap();
    let mc = Arc::new(
        Membership::adopt(
            Arc::new(MemoryState::new()),
            w.a.m.log(),
            kc,
            Vec::new(),
            w.clock.now(),
        )
        .await
        .unwrap(),
    );
    node(&w.hub, mc, &w.clock).await
}

async fn outcome_of(issuer: &Node, owner: &Node, bytes: &[u8]) -> Outcome {
    let CmdMsg::Result { bytes: result } = owner.r.handle(bytes).await else {
        panic!("a signed answer");
    };
    let c = baton_command::Command::decode(bytes).unwrap();
    let result = baton_command::CommandResult::decode(&result).unwrap();
    let keys = issuer.m.resource_keys(c.resource(), c.epoch()).unwrap();
    result
        .check(&c, &issuer.m.log(), &keys.data, issuer.m.now())
        .unwrap()
}

fn cancel_bytes(n: &Node, account: &AccountId, command: &CommandId) -> Vec<u8> {
    let key = CommandId::generate();
    n.r.issue(
        account,
        &RemoteRequest::Cancel {
            command: command.clone(),
        },
        key.as_str(),
        COMMAND_TTL_MS,
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_cancels_only_its_own_queued_sends() {
    let w = world().await;
    let c = third(&w).await;
    let message = Bytes::from_static(b"From: ada@example.com\r\nTo: bob@example.org\r\n\r\nhi\r\n");
    let blob = w.a.local.blobs.put(&tenant(), message).await.unwrap();
    let delayed = |blob| CommandBody::Send {
        blob,
        envelope: SendEnvelope {
            from: "ada@example.com".into(),
            to: vec!["bob@example.org".into()],
            dsn: None,
        },
        save_to_sent: None,
        send_at: Some(skein_core::Timestamp(T0 + 3_600_000)),
        dry_run: false,
    };
    let (b_send, bytes) = parked(&w.b, &w.account, delayed(blob)).await;
    assert!(applied(&w.a.r.handle(&bytes).await));
    let (b_flags, bytes) = parked(&w.b, &w.account, flags(&w.account)).await;
    assert!(applied(&w.a.r.handle(&bytes).await));
    let own = skein_core::Command {
        id: CommandId::generate(),
        account: w.account.clone(),
        created_at: skein_core::Timestamp(T0),
        trace: None,
        body: delayed(blob),
    };
    skein_engine::submit_command(&w.a.local, &LocalSignal::new(), &tenant(), &own)
        .await
        .unwrap();
    assert_eq!(pending(&w.a, &w.account).await.len(), 3);

    for target in [&b_send, &own.id, &b_flags] {
        let bytes = cancel_bytes(&c, &w.account, target);
        assert_eq!(
            outcome_of(&c, &w.a, &bytes).await,
            Outcome::Failed {
                reason: "not_queued".into()
            },
            "another node's command"
        );
    }
    let bytes = cancel_bytes(&w.b, &w.account, &b_flags);
    assert_eq!(
        outcome_of(&w.b, &w.a, &bytes).await,
        Outcome::Failed {
            reason: "not_queued".into()
        },
        "only sends are cancelled"
    );
    assert_eq!(pending(&w.a, &w.account).await.len(), 3);

    let bytes = cancel_bytes(&w.b, &w.account, &b_send);
    assert_eq!(outcome_of(&w.b, &w.a, &bytes).await, Outcome::Applied);
    assert!(
        !pending(&w.a, &w.account)
            .await
            .iter()
            .any(|q| q.id == b_send)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_permanent_delete_needs_its_own_class() {
    let w = world().await;
    let delete = |to_trash| RemoteRequest::Submit {
        command: Box::new(skein_core::Command {
            id: CommandId::generate(),
            account: w.account.clone(),
            created_at: skein_core::Timestamp(T0),
            trace: None,
            body: CommandBody::Delete {
                mailbox: "INBOX".into(),
                items: vec![ItemRef {
                    id: "1:1".into(),
                    uid: Some(1),
                }],
                to_trash,
            },
        }),
    };
    assert_eq!(delete(true).class(), Some("mail-delete"));
    assert_eq!(delete(false).class(), Some("mail-delete-forever"));

    let key = CommandId::generate();
    let queue = derive_queue_id(
        &w.b.m.node().to_bytes(),
        res(&w.account).as_str(),
        key.as_str(),
    )
    .unwrap();
    let RemoteRequest::Submit { mut command } = delete(false) else {
        unreachable!()
    };
    command.id = queue;
    let payload = RemoteRequest::Submit { command }.encode();
    let log = w.b.m.log();
    let keys = w.b.m.resource_keys(&res(&w.account), 1).unwrap();
    let forged = baton_command::Command::issue(
        &w.b.m.keys().identity,
        &log,
        Request {
            resource: &res(&w.account),
            epoch: 1,
            data_key: &keys.data,
            class: "mail-delete",
            idempotency_key: key.as_str(),
            payload: &payload,
        },
        w.clock.now()(),
        COMMAND_TTL_MS,
    )
    .unwrap()
    .encode();
    assert_eq!(
        outcome_of(&w.b, &w.a, &forged).await,
        Outcome::Failed {
            reason: "wrong_class".into()
        },
        "a permanent delete under the trash class"
    );
    assert!(pending(&w.a, &w.account).await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_send_blob_is_fetched_after_the_answer_and_a_slow_fetch_is_not_fatal() {
    let w = world().await;
    write(&w.a, &w.account, 1, 2, 2, 1).await;
    w.b.r.round().await;
    let message = Bytes::from_static(b"From: ada@example.com\r\nTo: bob@example.org\r\n\r\nhi\r\n");
    let blob =
        w.b.local
            .blobs
            .put(&tenant(), message.clone())
            .await
            .unwrap();
    let (id, bytes) = parked(&w.b, &w.account, send_body(blob, "ada@example.com")).await;
    let protocol = baton_link::Protocol::new(baton_fetch::PROTOCOL).unwrap();
    let mut stalls = w.b.link.listen(&protocol).await.unwrap();

    assert_eq!(w.a.r.handle(&bytes).await, CmdMsg::Later);
    assert_eq!(
        w.a.r.fetching(),
        1,
        "the answer did not wait for the blob, whose fetch can only end through the stall"
    );
    let stalled = futures::StreamExt::next(&mut stalls).await.unwrap();
    assert_eq!(
        w.a.r.handle(&bytes).await,
        CmdMsg::Later,
        "a redelivery while the first run is under way waits instead of settling uncertain"
    );
    drop(stalled);
    drop(stalls);
    eventually("the stalled fetch to end", || async {
        w.a.r.fetching() == 0
    })
    .await;
    assert!(pending(&w.a, &w.account).await.is_empty());

    w.b.r.attach(w.b.link.clone()).await.unwrap();
    eventually("the fetch to succeed", || async {
        let answer = w.a.r.handle(&bytes).await;
        if !applied(&answer) {
            assert_eq!(answer, CmdMsg::Later, "a failed fetch is transient");
            return false;
        }
        true
    })
    .await;
    let queued = pending(&w.a, &w.account).await;
    assert_eq!(queued.iter().filter(|c| c.id == id).count(), 1);
    assert_eq!(
        w.a.local.blobs.get(&tenant(), &blob).await.unwrap(),
        Some(message)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_owner_behind_on_the_group_log_answers_later_not_refused() {
    let w = world().await;
    let c = third(&w).await;
    let revocation = {
        w.b.m.revoke(&c.m.node()).await.unwrap();
        let log = w.b.m.log();
        let from = w.a.m.head().0 as usize + 1;
        log.entries()[from..].to_vec()
    };
    let epoch =
        w.b.m
            .with_log(|l| l.state().resource(&res(&w.account)).unwrap().epoch());
    assert_eq!(epoch, 2, "the revocation rotated the account");
    let (_, bytes) = parked(&w.b, &w.account, flags(&w.account)).await;
    assert_eq!(w.a.r.handle(&bytes).await, CmdMsg::Later);
    assert_eq!(
        w.a.host.behind.lock().unwrap().as_slice(),
        &[w.b.m.node()],
        "the owner asks the issuer for the log"
    );
    w.a.m.apply_remote(revocation).await.unwrap();
    assert!(applied(&w.a.r.handle(&bytes).await));
}

use skein_keyring::Keyring as _;

fn keyring(n: &Node, seed: u8) -> skein_keyring_local::LocalKeyring {
    skein_keyring_local::LocalKeyring::from_master([seed; 32], n.local.control.clone())
}

async fn put(n: &Node, path: &str, value: &[u8]) {
    n.local
        .control
        .put(
            &tenant(),
            path,
            Bytes::from(value.to_vec()),
            skein_storage::Expect::Any,
        )
        .await
        .unwrap();
}

async fn get(n: &Node, path: &str) -> Option<Vec<u8>> {
    n.local
        .control
        .get(&tenant(), path)
        .await
        .unwrap()
        .map(|(b, _)| b.to_vec())
}

async fn holder_state(w: &World, ring: &dyn skein_keyring::Keyring) {
    let a = &w.account;
    put(&w.a, &format!("accounts/{a}"), b"{\"record\":1}").await;
    put(&w.a, &format!("cursors/{a}/inbox"), b"cursor-1").await;
    put(&w.a, &format!("state/{a}"), b"state-1").await;
    put(&w.a, &format!("rowboat/cmdkeys/{a}/k1"), b"key-1").await;
    let path = format!("credentials/{a}/password");
    let sealed = ring
        .seal(
            &skein_keyring::KeyScope::account_of(&tenant(), a),
            &path,
            b"hunter2-test",
        )
        .await
        .unwrap();
    put(&w.a, &path, &sealed).await;
    w.a.local
        .commands
        .submit(
            &tenant(),
            &skein_core::Command {
                id: skein_core::CommandId::generate(),
                account: a.clone(),
                created_at: skein_core::Timestamp(T0),
                trace: None,
                body: flags(a),
            },
        )
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_offer_moves_the_state_sealed_until_the_next_holder_opens_it() {
    let w = world().await;
    let ring_a = keyring(&w.a, 1);
    let ring_b = keyring(&w.b, 2);
    holder_state(&w, &ring_a).await;
    write(&w.a, &w.account, 1, 6, 3, 1).await;
    let offer = crate::handover::export(&tenant(), &w.a.local, &ring_a, &w.a.m, &w.account)
        .await
        .unwrap();
    assert!(
        !offer.sealed.windows(12).any(|x| x == b"hunter2-test"),
        "credentials travel sealed"
    );
    assert_eq!(w.a.r.hand_over(&offer).await, 1);
    assert_eq!(head(&w.b, &w.account).await, head(&w.a, &w.account).await);
    assert_eq!(w.b.r.staged(&w.account).await, Some(offer.clone()));
    let a = &w.account;
    assert!(get(&w.b, &format!("accounts/{a}")).await.is_some());
    assert!(
        get(&w.b, &format!("credentials/{a}/password"))
            .await
            .is_none(),
        "nothing is opened before the lease"
    );
    put(&w.b, &format!("cursors/{a}/stale"), b"old").await;

    crate::handover::import(&tenant(), &w.b.local, &ring_b, &w.b.m, &offer)
        .await
        .unwrap();
    assert_eq!(
        get(&w.b, &format!("cursors/{a}/inbox")).await.unwrap(),
        b"cursor-1"
    );
    assert!(get(&w.b, &format!("cursors/{a}/stale")).await.is_none());
    assert_eq!(
        get(&w.b, &format!("rowboat/cmdkeys/{a}/k1")).await.unwrap(),
        b"key-1"
    );
    let path = format!("credentials/{a}/password");
    let sealed = get(&w.b, &path).await.unwrap();
    let opened = ring_b
        .open(
            &skein_keyring::KeyScope::account_of(&tenant(), a),
            &path,
            &sealed,
        )
        .await
        .unwrap();
    assert_eq!(opened, b"hunter2-test");
    assert!(
        ring_a
            .open(
                &skein_keyring::KeyScope::account_of(&tenant(), a),
                &path,
                &sealed
            )
            .await
            .is_err(),
        "at rest it is sealed under the new holder's own keyring"
    );
    assert_eq!(pending(&w.b, a).await, pending(&w.a, a).await);
    crate::handover::import(&tenant(), &w.b.local, &ring_b, &w.b.m, &offer)
        .await
        .unwrap();
    assert_eq!(
        pending(&w.b, a).await.len(),
        1,
        "importing again changes nothing"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forged_stale_and_unauthorized_offers_are_refused() {
    let w = world().await;
    let ring_a = keyring(&w.a, 1);
    let ring_b = keyring(&w.b, 2);
    holder_state(&w, &ring_a).await;
    write(&w.a, &w.account, 1, 4, 2, 1).await;
    let old = crate::handover::export(&tenant(), &w.a.local, &ring_a, &w.a.m, &w.account)
        .await
        .unwrap();
    write(&w.a, &w.account, 5, 2, 2, 2).await;
    let newer = crate::handover::export(&tenant(), &w.a.local, &ring_a, &w.a.m, &w.account)
        .await
        .unwrap();
    let c = third(&w).await;
    assert_eq!(
        w.b.r.receive_offer(&c.m.node(), newer.clone()).await,
        Err(SyncError::NotAuthorized),
        "an offer relayed by a node that did not write the head"
    );
    w.b.r
        .receive_offer(&w.a.m.node(), newer.clone())
        .await
        .unwrap();
    w.b.r
        .receive_offer(&w.a.m.node(), newer.clone())
        .await
        .unwrap();
    assert!(
        w.b.r
            .receive_offer(&w.a.m.node(), old.clone())
            .await
            .is_err(),
        "a replayed offer under a lower head"
    );
    assert_eq!(w.b.r.staged(&w.account).await, Some(newer.clone()));

    let mut swapped = newer.clone();
    swapped.head = old.head.clone();
    assert!(
        w.b.r
            .receive_offer(&w.a.m.node(), swapped.clone())
            .await
            .is_err()
    );
    assert_eq!(
        crate::handover::import(&tenant(), &w.b.local, &ring_b, &w.b.m, &swapped).await,
        Err(SyncError::Unverified),
        "a state moved under another head does not open"
    );
    let mut flipped = newer.clone();
    let mid = flipped.sealed.len() / 2;
    flipped.sealed[mid] ^= 1;
    assert_eq!(
        crate::handover::import(&tenant(), &w.b.local, &ring_b, &w.b.m, &flipped).await,
        Err(SyncError::Unverified)
    );
    assert!(
        get(&w.b, &format!("cursors/{}/inbox", w.account))
            .await
            .is_none()
    );

    w.b.host.leads.lock().unwrap().insert(w.account.clone());
    assert_eq!(
        w.b.r.receive_offer(&w.a.m.node(), newer.clone()).await,
        Err(SyncError::NotHere),
        "the holder takes no offer for what it leads"
    );
    w.b.host.leads.lock().unwrap().clear();

    let ring_c = keyring(&c, 3);
    write(&c, &w.account, 1, 6, 6, 9).await;
    let path = format!("credentials/{}/password", w.account);
    let sealed = ring_c
        .seal(
            &skein_keyring::KeyScope::account_of(&tenant(), &w.account),
            &path,
            b"other-test",
        )
        .await
        .unwrap();
    put(&c, &path, &sealed).await;
    let from_c = crate::handover::export(&tenant(), &c.local, &ring_c, &c.m, &w.account)
        .await
        .unwrap();
    w.a.m.revoke(&c.m.node()).await.unwrap();
    let entries = w.a.m.with_log(|l| l.entries().to_vec());
    w.b.m.apply_remote(entries).await.unwrap();
    assert_eq!(
        w.b.r.receive_offer(&c.m.node(), from_c).await,
        Err(SyncError::NotAuthorized),
        "a revoked node cannot hand anything over"
    );
    assert_eq!(
        crate::handover::export(&tenant(), &w.b.local, &ring_b, &w.b.m, &w.account).await,
        Err(SyncError::NotHere),
        "a node without credentials has nothing to hand over"
    );
    for x in ["oops", "", "\u{0}"] {
        assert!(crate::handover::Offer::decode(x.as_bytes()).is_err());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deposed_writer_drops_its_tail_and_its_heads_are_refused() {
    let w = world().await;
    write(&w.a, &w.account, 1, 4, 2, 1).await;
    w.b.r.round().await;
    let common = head(&w.b, &w.account).await;
    assert_eq!(common.head.seq, Seq(4));
    write(&w.a, &w.account, 5, 2, 2, 1).await;
    let stale = head(&w.a, &w.account).await;

    w.a.host.leads.lock().unwrap().clear();
    w.b.host.leads.lock().unwrap().insert(w.account.clone());
    write(&w.b, &w.account, 5, 1, 1, 7).await;
    let newer = head(&w.b, &w.account).await;
    assert_eq!(newer.head.seq, Seq(5));

    w.b.host.leads.lock().unwrap().clear();
    assert_eq!(
        w.b.r.follow(&stale).await,
        Ok(Caught::Stale),
        "a head under the deposed fence changes nothing"
    );
    assert_eq!(head(&w.b, &w.account).await, newer);
    w.b.host.leads.lock().unwrap().insert(w.account.clone());

    put(&w.a, &format!("rowboat/handover/{}", w.account), b"x").await;
    assert_eq!(w.a.r.follow(&newer).await, Ok(Caught::Deposed));
    assert_eq!(
        w.a.host.reset.lock().unwrap().as_slice(),
        std::slice::from_ref(&w.account)
    );
    assert!(w.a.host.forked.lock().unwrap().is_empty(), "not a fork");
    assert!(!w.a.r.is_forked(&w.account));
    assert!(
        get(&w.a, &format!("rowboat/handover/{}", w.account))
            .await
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_head_fenced_far_ahead_of_the_clock_is_refused() {
    let w = world().await;
    write(&w.a, &w.account, 1, 4, 2, 1).await;
    let now = head(&w.a, &w.account).await;
    let clock = w.clock.now()();
    let limit = (clock.0 as u64 + crate::MAX_FENCE_AHEAD_MS) * 1000;
    let signed = |fence: u64| {
        let h = JournalHead {
            fence: skein_core::FencingToken(fence),
            ..now.head.clone()
        };
        SignedHead {
            attestation: Some(attest(&w.a.m.keys().identity, &h)),
            head: h,
        }
    };
    assert_eq!(
        verify_remote(&w.b.m, &signed(limit), clock),
        Ok(w.a.m.node()),
        "a clock somewhat ahead is accepted"
    );
    assert_eq!(
        verify_remote(&w.b.m, &signed(limit + 1), clock),
        Err(SyncError::Unverified)
    );
    assert_eq!(
        verify_remote(&w.b.m, &signed(u64::MAX), clock),
        Err(SyncError::Unverified),
        "a fence no arbiter's token could pass"
    );
}

/// A command delivered to an owner that never answered (it went silent, perhaps after running
/// it) is not run again by the issuer when the issuer takes the account over from that silent
/// owner: it settles uncertain. Taken over normally, the issuer runs it, guarded by its own
/// `cmdkey` record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_command_a_silent_owner_may_have_run_is_uncertain_not_repeated() {
    for silent in [true, false] {
        let w = world().await;
        write(&w.a, &w.account, 1, 2, 2, 1).await;
        w.b.r.round().await;
        w.a.r.detach().await;
        let protocol = baton_link::Protocol::new(COMMAND_PROTOCOL).unwrap();
        let mut deaf = w.a.link.listen(&protocol).await.unwrap();
        let swallow = tokio::spawn(async move {
            while let Some(mut inc) = futures::StreamExt::next(&mut deaf).await {
                let _ = rowboat_group::wire::read_frame(
                    &mut *inc.stream,
                    MAX_FRAME,
                    std::time::Duration::from_secs(5),
                )
                .await;
            }
        });
        let id = w.b.r.submit(&w.account, flags(&w.account)).await.unwrap();
        w.b.r.flush().await;
        assert_eq!(w.b.r.outbox_len(), 1, "no answer: it stays in the outbox");

        w.b.host.leads.lock().unwrap().insert(w.account.clone());
        w.b.host.silent_owner.store(silent, Ordering::SeqCst);
        w.b.r.flush().await;
        assert_eq!(w.b.r.outbox_len(), 0);
        let queued = pending(&w.b, &w.account).await;
        if silent {
            assert!(queued.is_empty(), "never run a second time here");
            assert!(
                w.b.host
                    .settled
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(c, o)| c == id.as_str() && *o == Settled::Uncertain)
            );
        } else {
            assert_eq!(queued.iter().filter(|c| c.id == id).count(), 1);
        }
        swallow.abort();
    }
}
