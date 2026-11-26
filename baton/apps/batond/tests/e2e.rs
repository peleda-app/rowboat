//! batond end to end over in-memory links: group logs, leases from the logs, no keys.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use baton_core::{GroupId, LeaseKey, ResourceId, Timestamp};
use baton_group::{
    Capability, Entry, Founding, GroupLog, NodeCert, Op, Principal, Recipient, Role, epochs,
};
use baton_group_server::wire::{self, Refusal, Reply, Request};
use baton_group_server::{ClientConfig, GroupClient, RemoteError};
use baton_identity::Identity;
use baton_keys::{KemSecret, RecoveryRoot};
use baton_lease::{LeaseError, Leases, Liveness, NodeClass, NodeProfile};
use baton_lease_server::{LeaseClient, RemoteLeases, RemoteLiveness};
use baton_link::{Link, PinnedKeys, Protocol, PublicKey};
use baton_link_memory::MemoryLinkHub;
use baton_state::StateStore;
use batond::{Clocks, Core, RedbState, Servers};

const T0: i64 = 1_700_000_000_000;
const LATER: Timestamp = Timestamp(1_800_000_000_000);

struct Device {
    id: Identity,
    kem: KemSecret,
}

impl Device {
    fn new() -> Self {
        Self {
            id: Identity::generate(),
            kem: KemSecret::generate(),
        }
    }

    fn cert(&self, member: &Identity, class: NodeClass) -> NodeCert {
        NodeCert::new(member, &self.id, self.kem.public(), class, LATER)
    }

    fn profile(&self, class: NodeClass) -> NodeProfile {
        NodeProfile {
            node: self.id.node_id(),
            class,
            weight: 1,
            can_run: true,
        }
    }
}

fn group() -> GroupId {
    GroupId::new("family").unwrap()
}

fn key(k: &str) -> LeaseKey {
    LeaseKey::new(k).unwrap()
}

fn r1() -> ResourceId {
    ResourceId::new("vault-1").unwrap()
}

struct Member {
    dev: Device,
    link: Arc<dyn Link>,
    groups: GroupClient,
    leases: RemoteLeases,
    live: RemoteLiveness,
}

impl Member {
    async fn beat(&self, class: NodeClass) -> Result<(), LeaseError> {
        self.live
            .heartbeat(&group(), &self.dev.profile(class), Timestamp(0))
            .await
    }

    async fn take(&self, k: &str, class: NodeClass) -> Result<bool, LeaseError> {
        self.leases
            .acquire(&group(), &key(k), &self.dev.profile(class))
            .await
            .map(|l| l.is_some())
    }
}

struct World {
    hub: MemoryLinkHub,
    now: Arc<AtomicI64>,
    server: Identity,
    server_kem: KemSecret,
    owner: Identity,
    log: GroupLog,
    _dir: tempfile::TempDir,
    state: Arc<dyn StateStore>,
    core: Option<Core>,
    servers: Option<Servers>,
}

impl World {
    fn new(laptop: &Device) -> Self {
        let owner = Identity::generate();
        let log = GroupLog::genesis(
            group(),
            Founding {
                owner: &owner,
                owner_recovery: RecoveryRoot::generate().public(),
                group_recovery: RecoveryRoot::generate().public(),
                node: &laptop.id,
                node_kem: laptop.kem.public(),
                class: NodeClass::Desktop,
                expires: LATER,
            },
            Timestamp(T0),
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        Self {
            hub: MemoryLinkHub::new(),
            now: Arc::new(AtomicI64::new(T0)),
            server: Identity::generate(),
            server_kem: KemSecret::generate(),
            owner,
            log,
            state: Arc::new(RedbState::open(&dir.path().join("state.redb")).unwrap()),
            _dir: dir,
            core: None,
            servers: None,
        }
    }

    fn clocks(&self) -> Clocks {
        let now = self.now.clone();
        let clock: batond::Clock = Arc::new(move || Timestamp(now.load(Ordering::SeqCst)));
        Clocks {
            wall: clock.clone(),
            lease: clock,
        }
    }

    async fn start(&mut self, bootstrap: &[PublicKey]) {
        let core = Core::open(
            self.state.clone(),
            vec![(group(), self.log.genesis_hash())],
            BTreeMap::from([(group(), bootstrap.iter().copied().collect::<BTreeSet<_>>())]),
            self.clocks(),
        )
        .await
        .unwrap();
        let link: Arc<dyn Link> = Arc::new(self.hub.join(self.server.public(), core.trust()));
        let servers = core
            .serve(
                link,
                baton_lease_server::ServerConfig {
                    ttl_ms: 10_000,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        self.core = Some(core);
        self.servers = Some(servers);
    }

    async fn stop(&mut self) {
        if let Some(s) = self.servers.take() {
            s.stop().await;
        }
        self.core = None;
        self.hub
            .join(self.server.public(), Arc::new(PinnedKeys::default()));
    }

    fn link(&self, dev: &Device) -> Arc<dyn Link> {
        Arc::new(self.hub.join(
            dev.id.public(),
            Arc::new(PinnedKeys::new([self.server.public()])),
        ))
    }

    async fn member(&self, dev: Device) -> Member {
        self.member_after(dev, None).await
    }

    async fn founder(&self, dev: Device) -> Member {
        self.member_after(dev, Some(&self.log.entries()[0])).await
    }

    async fn member_after(&self, dev: Device, genesis: Option<&Entry>) -> Member {
        let link = self.link(&dev);
        let groups =
            GroupClient::connect(link.clone(), self.server.public(), ClientConfig::default())
                .await
                .unwrap();
        if let Some(g) = genesis {
            groups.push(g).await.unwrap();
        }
        let client = LeaseClient::connect(link.clone(), self.server.public(), Default::default())
            .await
            .unwrap();
        Member {
            dev,
            link,
            groups,
            leases: RemoteLeases::new(client.clone()),
            live: RemoteLiveness::new(client),
        }
    }

    async fn append(&mut self, by: &Member, op: Op) -> Entry {
        let e = self
            .log
            .append(&by.dev.id, op, Timestamp(self.now.load(Ordering::SeqCst)))
            .unwrap();
        let (head, new) = by.groups.push(&e).await.unwrap();
        assert!(new);
        assert_eq!(head.seq, e.seq());
        e
    }
}

fn denied<T: std::fmt::Debug>(r: Result<T, LeaseError>) -> bool {
    match r {
        Err(LeaseError::Unavailable) => true,
        Err(LeaseError::Backend(b)) => {
            b.downcast_ref::<baton_lease_server::RemoteError>()
                == Some(&baton_lease_server::RemoteError::Denied)
        }
        _ => false,
    }
}

fn strictly_denied<T: std::fmt::Debug>(r: Result<T, LeaseError>) -> bool {
    match r {
        Err(LeaseError::Backend(b)) => {
            b.downcast_ref::<baton_lease_server::RemoteError>()
                == Some(&baton_lease_server::RemoteError::Denied)
        }
        _ => false,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn members_lease_revoked_and_blind_nodes_are_refused_and_batond_holds_no_key() {
    let laptop = Device::new();
    let mut w = World::new(&laptop);
    w.start(&[laptop.id.public()]).await;
    let laptop = w.founder(laptop).await;

    let desk = Device::new();
    let blind = Device::new();
    let alice = Identity::generate();
    let alice_node = Device::new();
    let ops = vec![
        Op::CertifyNode {
            cert: desk.cert(&w.owner, NodeClass::Desktop),
        },
        Op::CertifyNode {
            cert: NodeCert::new(
                &w.owner,
                &w.server,
                w.server_kem.public(),
                NodeClass::Blind,
                LATER,
            ),
        },
        Op::CertifyNode {
            cert: blind.cert(&w.owner, NodeClass::Blind),
        },
        Op::AddMember {
            member: alice.public(),
            recovery: RecoveryRoot::generate().public(),
            role: Role::Member,
        },
        Op::CertifyNode {
            cert: alice_node.cert(&alice, NodeClass::Server),
        },
        Op::CreateResource { resource: r1() },
    ];
    for op in ops {
        w.append(&laptop, op).await;
    }
    let (epoch, _keys) = epochs::new_epoch(w.log.state(), &r1(), Timestamp(T0)).expect("an epoch");
    let epoch_entry = w.append(&laptop, epoch).await;

    let Op::KeyEpoch { boxes, .. } = epoch_entry.op() else {
        panic!("a key epoch");
    };
    assert!(
        boxes
            .iter()
            .all(|b| b.recipient != Recipient::Node(w.server.public())),
        "batond's node gets no key box"
    );
    assert!(
        w.log
            .state()
            .capabilities(&r1(), &w.server.public(), Timestamp(T0))
            .is_empty(),
        "batond's node has no capability"
    );
    assert!(
        epochs::open(
            &w.log,
            &r1(),
            1,
            &Recipient::Node(w.server.public()),
            &w.server_kem
        )
        .is_err(),
        "even with its KEM key batond opens nothing"
    );

    laptop.beat(NodeClass::Desktop).await.unwrap();
    assert!(laptop.take("vault-1", NodeClass::Desktop).await.unwrap());
    assert!(
        laptop
            .take("vault-1--sync", NodeClass::Desktop)
            .await
            .unwrap()
    );
    assert!(
        strictly_denied(laptop.take("vault-2", NodeClass::Desktop).await),
        "no such resource"
    );
    assert!(
        strictly_denied(laptop.take("vault-1--", NodeClass::Desktop).await),
        "a key that maps to no resource"
    );
    assert!(
        strictly_denied(laptop.beat(NodeClass::Server).await),
        "a profile stronger than the certificate"
    );

    let desk = w.member(desk).await;
    desk.beat(NodeClass::Desktop).await.unwrap();
    assert!(
        desk.take("vault-1--index", NodeClass::Desktop)
            .await
            .unwrap()
    );
    let synced = desk
        .groups
        .sync(&group(), w.log.genesis_hash(), None, Timestamp(T0))
        .await
        .unwrap();
    assert_eq!(synced.head_hash(), w.log.head_hash());

    let blind = w.member(blind).await;
    assert!(strictly_denied(blind.beat(NodeClass::Blind).await));
    assert!(strictly_denied(blind.beat(NodeClass::Desktop).await));
    assert!(
        strictly_denied(blind.take("vault-1--x", NodeClass::Desktop).await),
        "a blind node never leads, whatever it claims"
    );
    assert!(
        blind.live.alive(&group(), Timestamp(0)).await.is_ok(),
        "a blind node is still a member that may read liveness"
    );

    let alice_m = w.member(alice_node).await;
    alice_m.beat(NodeClass::Server).await.unwrap();
    assert!(
        strictly_denied(alice_m.take("vault-1--alice", NodeClass::Server).await),
        "a member without lead on the resource"
    );
    w.append(
        &laptop,
        Op::Grant {
            resource: r1(),
            principal: Principal::Member(alice.public()),
            capabilities: [Capability::Read, Capability::Lead].into_iter().collect(),
        },
    )
    .await;
    assert!(
        alice_m
            .take("vault-1--alice", NodeClass::Server)
            .await
            .unwrap(),
        "a grant applies to the next request"
    );

    w.append(
        &laptop,
        Op::RevokeNode {
            node: desk.dev.id.public(),
        },
    )
    .await;
    assert!(denied(desk.beat(NodeClass::Desktop).await));
    assert!(denied(
        desk.take("vault-1--index", NodeClass::Desktop).await
    ));
    assert!(denied(
        desk.leases.holder(&group(), &key("vault-1--index")).await
    ));
    assert!(matches!(
        desk.groups.head(&group()).await,
        Err(RemoteError::Unavailable | RemoteError::Refused(Refusal::Denied))
    ));

    w.now.fetch_add(10_001, Ordering::SeqCst);
    laptop.beat(NodeClass::Desktop).await.unwrap();
    assert!(
        laptop
            .take("vault-1--index", NodeClass::Desktop)
            .await
            .unwrap(),
        "the revoked holder's lease lapses and another member takes it"
    );

    let stranger = Device::new();
    let link = w.link(&stranger);
    assert!(matches!(
        GroupClient::connect(link.clone(), w.server.public(), ClientConfig::default()).await,
        Err(RemoteError::Unavailable)
    ));
    assert!(denied(
        LeaseClient::connect(link, w.server.public(), Default::default())
            .await
            .map(|_| ())
    ));

    let head = w.log.head_hash();
    w.stop().await;
    w.start(&[]).await;
    let core = w.core.as_ref().unwrap();
    assert_eq!(core.logs().head(&group()).unwrap().hash, head);
    let laptop = w
        .member(Device {
            id: Identity::from_secret_bytes(&laptop.dev.id.secret_bytes()),
            kem: KemSecret::generate(),
        })
        .await;
    laptop.beat(NodeClass::Desktop).await.unwrap();
    let held = laptop
        .leases
        .holder(&group(), &key("vault-1"))
        .await
        .unwrap()
        .expect("leases survive a restart");
    assert_eq!(held.node, laptop.dev.id.node_id());
}

#[tokio::test(flavor = "multi_thread")]
async fn forged_replayed_forked_and_revoked_entries_are_refused() {
    let laptop = Device::new();
    let mut w = World::new(&laptop);
    w.start(&[laptop.id.public()]).await;
    let laptop = w.founder(laptop).await;
    let desk = Device::new();
    let cert = w
        .append(
            &laptop,
            Op::CertifyNode {
                cert: desk.cert(&w.owner, NodeClass::Desktop),
            },
        )
        .await;
    let desk = w.member(desk).await;

    let mut raw = laptop
        .link
        .open(
            &w.server.public(),
            &Protocol::new(baton_group_server::PROTOCOL).unwrap(),
        )
        .await
        .unwrap();
    let mut forged = cert.encode();
    let mid = forged.len() / 2;
    forged[mid] ^= 0x10;
    wire::write_frame(
        &mut raw,
        &wire::encode_request(&Request::Push { entry: forged }),
    )
    .await
    .unwrap();
    let reply = wire::read_frame(&mut raw, wire::MAX_REPLY).await.unwrap();
    assert!(matches!(
        wire::decode_reply(&reply, wire::MAX_REPLY).unwrap(),
        Reply::Refused(Refusal::Malformed | Refusal::Invalid | Refusal::Fork)
    ));

    let (_, new) = laptop.groups.push(&cert).await.unwrap();
    assert!(!new, "a replayed entry changes nothing");

    let mut stale = GroupLog::verify(vec![w.log.entries()[0].clone()]).unwrap();
    let on_old_head = stale
        .append(
            &laptop.dev.id,
            Op::CertifyNode {
                cert: Device::new().cert(&w.owner, NodeClass::Desktop),
            },
            Timestamp(T0),
        )
        .unwrap();
    assert_eq!(
        laptop.groups.push(&on_old_head).await.unwrap_err(),
        RemoteError::Refused(Refusal::Fork)
    );

    w.append(
        &laptop,
        Op::RevokeNode {
            node: desk.dev.id.public(),
        },
    )
    .await;
    let by_revoked = craft(
        &desk.dev.id,
        w.log.head_seq() + 1,
        w.log.head_hash(),
        Timestamp(T0),
        Op::CreateResource {
            resource: ResourceId::new("sneaky").unwrap(),
        },
    );
    assert!(desk.groups.push(&by_revoked).await.is_err());
    assert_eq!(
        laptop.groups.push(&by_revoked).await.unwrap_err(),
        RemoteError::Refused(Refusal::Invalid),
        "relayed by a member onto the current head, the revoked node's entry is refused by the log rules"
    );
    let core = w.core.as_ref().unwrap();
    assert_eq!(core.logs().head(&group()).unwrap().seq, w.log.head_seq());
    assert_eq!(core.logs().head(&group()).unwrap().hash, w.log.head_hash());
    assert!(
        core.logs()
            .with(&group(), |l| l
                .state()
                .resource(&ResourceId::new("sneaky").unwrap())
                .is_none())
            .unwrap()
    );
}

fn craft(signer: &Identity, seq: u64, prev: [u8; 32], at: Timestamp, op: Op) -> Entry {
    #[derive(serde::Serialize)]
    struct Body<'a> {
        v: u8,
        group: &'a GroupId,
        seq: u64,
        prev: [u8; 32],
        at: Timestamp,
        signer: PublicKey,
        op: &'a Op,
    }
    #[derive(serde::Serialize)]
    struct Signed<'a> {
        body: Body<'a>,
        signature: baton_identity::Signature,
    }
    let group = group();
    let body = Body {
        v: baton_group::ENTRY_VERSION,
        group: &group,
        seq,
        prev,
        at,
        signer: signer.public(),
        op: &op,
    };
    let signature = signer.sign("baton-group-entry-v1", &postcard::to_stdvec(&body).unwrap());
    Entry::decode(&postcard::to_stdvec(&Signed { body, signature }).unwrap()).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_bootstrap_founder_is_refused_on_group_and_by_the_link() {
    let laptop = Device::new();
    let mut w = World::new(&laptop);
    let founder_key = laptop.id.public();
    w.start(&[founder_key]).await;
    let laptop = w.founder(laptop).await;
    let desk = Device::new();
    w.append(
        &laptop,
        Op::CertifyNode {
            cert: desk.cert(&w.owner, NodeClass::Desktop),
        },
    )
    .await;
    let desk = w.member(desk).await;
    w.append(&desk, Op::RevokeNode { node: founder_key }).await;
    let rules = w.core.as_ref().unwrap().rules();
    assert!(
        !baton_link::Trust::allows(&*rules, &founder_key),
        "the link no longer trusts the revoked founder"
    );
    assert!(
        !baton_group_server::Admit::admits(&*rules, &founder_key, &group()),
        "bootstrap no longer admits a key the log certified"
    );
    assert!(matches!(
        laptop.groups.head(&group()).await,
        Err(RemoteError::Unavailable | RemoteError::Refused(Refusal::Denied))
    ));
    assert!(matches!(
        GroupClient::connect(
            w.link(&laptop.dev),
            w.server.public(),
            ClientConfig::default()
        )
        .await,
        Err(RemoteError::Unavailable)
    ));
    let stranger = Identity::generate().public();
    assert!(
        !baton_link::Trust::allows(&*rules, &stranger),
        "keys outside bootstrap and the log stay refused"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bootstrap_peer_is_admitted_before_genesis_and_while_uncertified() {
    let laptop = Device::new();
    let mut w = World::new(&laptop);
    let recovering = Identity::generate().public();
    w.start(&[laptop.id.public(), recovering]).await;
    let rules = w.core.as_ref().unwrap().rules();
    assert!(baton_group_server::Admit::admits(
        &*rules,
        &laptop.id.public(),
        &group()
    ));
    let laptop = w.founder(laptop).await;
    assert!(baton_link::Trust::allows(&*rules, &laptop.dev.id.public()));
    assert!(
        baton_group_server::Admit::admits(&*rules, &recovering, &group()),
        "a recovering device the log never certified is still admitted"
    );
    assert!(baton_link::Trust::allows(&*rules, &recovering));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_holder_that_loses_lead_can_still_release() {
    let laptop = Device::new();
    let mut w = World::new(&laptop);
    w.start(&[laptop.id.public()]).await;
    let laptop = w.founder(laptop).await;
    let alice = Identity::generate();
    let alice_node = Device::new();
    for op in [
        Op::AddMember {
            member: alice.public(),
            recovery: RecoveryRoot::generate().public(),
            role: Role::Member,
        },
        Op::CertifyNode {
            cert: alice_node.cert(&alice, NodeClass::Server),
        },
        Op::CreateResource { resource: r1() },
        Op::Grant {
            resource: r1(),
            principal: Principal::Member(alice.public()),
            capabilities: [Capability::Read, Capability::Lead].into_iter().collect(),
        },
    ] {
        w.append(&laptop, op).await;
    }
    let alice_m = w.member(alice_node).await;
    alice_m.beat(NodeClass::Server).await.unwrap();
    let lease = alice_m
        .leases
        .acquire(
            &group(),
            &key("vault-1"),
            &alice_m.dev.profile(NodeClass::Server),
        )
        .await
        .unwrap()
        .expect("alice holds vault-1");
    w.append(
        &laptop,
        Op::Grant {
            resource: r1(),
            principal: Principal::Member(alice.public()),
            capabilities: [Capability::Read].into_iter().collect(),
        },
    )
    .await;
    assert!(
        strictly_denied(alice_m.take("vault-1--next", NodeClass::Server).await),
        "without lead nothing new is acquired"
    );
    alice_m
        .leases
        .release(&lease)
        .await
        .expect("releasing one's own lease needs no lead");
    laptop.beat(NodeClass::Desktop).await.unwrap();
    assert!(
        laptop.take("vault-1", NodeClass::Desktop).await.unwrap(),
        "the released key is free at once"
    );
    let other = Device::new();
    let forged = baton_lease::Lease {
        node: other.id.node_id(),
        ..lease
    };
    assert!(
        strictly_denied(alice_m.leases.release(&forged).await),
        "a lease of another node is never released"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_store_with_another_genesis_is_refused_at_start() {
    let laptop = Device::new();
    let mut w = World::new(&laptop);
    w.start(&[laptop.id.public()]).await;
    let _laptop = w.founder(laptop).await;
    w.stop().await;
    let state = w.state.clone();
    let other = World::new(&Device::new());
    assert!(
        Core::open(
            state,
            vec![(group(), other.log.genesis_hash())],
            BTreeMap::new(),
            w.clocks()
        )
        .await
        .is_err()
    );
}
