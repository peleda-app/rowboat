//! Regression tests for the findings of the first adversarial review of this crate; each test is
//! named after what it prevents.

use std::collections::BTreeSet;
use std::sync::Arc;

use baton_keys::{KemSecret, RecoveryPublic, RecoveryRoot};
use baton_state::StateStore;
use baton_state_memory::MemoryState;

use super::*;
use crate::epochs;

const T: Timestamp = Timestamp(1_700_000_000_000);
const LATER: Timestamp = Timestamp(1_800_000_000_000);

struct Dev {
    id: Identity,
    kem: KemSecret,
}

impl Dev {
    fn new() -> Self {
        Self {
            id: Identity::generate(),
            kem: KemSecret::generate(),
        }
    }
    fn cert(&self, member: &Identity, class: NodeClass, expires: Timestamp) -> NodeCert {
        NodeCert::new(member, &self.id, self.kem.public(), class, expires)
    }
    fn r(&self) -> Recipient {
        Recipient::Node(self.id.public())
    }
}

struct W {
    owner: Identity,
    _owner_root: RecoveryRoot,
    group_root: RecoveryRoot,
    laptop: Dev,
    alice: Identity,
    alice_root: RecoveryRoot,
    alice_phone: Dev,
    log: GroupLog,
}

fn res(n: &str) -> ResourceId {
    ResourceId::new(n).unwrap()
}

fn caps(c: &[Capability]) -> BTreeSet<Capability> {
    c.iter().cloned().collect()
}

fn w() -> W {
    let owner = Identity::generate();
    let owner_root = RecoveryRoot::generate();
    let group_root = RecoveryRoot::generate();
    let laptop = Dev::new();
    let mut log = GroupLog::genesis(
        GroupId::new("g").unwrap(),
        Founding {
            owner: &owner,
            owner_recovery: owner_root.public(),
            group_recovery: group_root.public(),
            node: &laptop.id,
            node_kem: laptop.kem.public(),
            class: NodeClass::Desktop,
            expires: LATER,
        },
        T,
    )
    .unwrap();
    let alice = Identity::generate();
    let alice_root = RecoveryRoot::generate();
    log.append(
        &laptop.id,
        Op::AddMember {
            member: alice.public(),
            recovery: alice_root.public(),
            role: Role::Member,
        },
        T,
    )
    .unwrap();
    let alice_phone = Dev::new();
    log.append(
        &laptop.id,
        Op::CertifyNode {
            cert: alice_phone.cert(&alice, NodeClass::Phone, LATER),
        },
        T,
    )
    .unwrap();
    W {
        owner,
        _owner_root: owner_root,
        group_root,
        laptop,
        alice,
        alice_root,
        alice_phone,
        log,
    }
}

#[test]
fn a_node_alone_cannot_take_over_its_member_through_recovery_rotation() {
    let mut w = w();
    let evil = RecoveryRoot::generate();
    for member in [Some(w.alice.public()), None] {
        let r = w.log.append(
            &w.alice_phone.id,
            Op::RotateRecovery {
                member,
                recovery: evil.public(),
            },
            T,
        );
        assert!(matches!(r, Err(GroupError::NotAuthorized(_))));
    }
    let r = w.log.append(
        &w.laptop.id,
        Op::RotateRecovery {
            member: None,
            recovery: evil.public(),
        },
        T,
    );
    assert!(
        matches!(r, Err(GroupError::NotAuthorized(_))),
        "not even an owner's node takes the group recovery key"
    );
    let r = w.log.append(
        &w.alice_phone.id,
        Op::RekeyMember {
            member: w.alice.public(),
            new_key: Identity::generate().public(),
        },
        T,
    );
    assert!(matches!(r, Err(GroupError::NotAuthorized(_))));
}

#[test]
fn the_group_recovery_key_gets_shared_resources_only_and_readers_recovery_no_secret() {
    let mut w = w();
    w.log
        .append(
            &w.alice_phone.id,
            Op::CreateResource {
                resource: res("alice-mail"),
            },
            T,
        )
        .unwrap();
    let (op, _) = epochs::new_epoch(w.log.state(), &res("alice-mail"), T).unwrap();
    w.log.append(&w.alice_phone.id, op, T).unwrap();
    let g = w.group_root.keys();
    assert!(
        epochs::open(
            &w.log,
            &res("alice-mail"),
            1,
            &Recipient::Recovery(g.sign.public()),
            &g.kem
        )
        .is_err()
    );
    let a = w.alice_root.keys();
    assert!(
        epochs::open(
            &w.log,
            &res("alice-mail"),
            1,
            &Recipient::Recovery(a.sign.public()),
            &a.kem
        )
        .unwrap()
        .secret
        .is_some()
    );

    w.log
        .append(
            &w.laptop.id,
            Op::CreateResource {
                resource: res("inbox"),
            },
            T,
        )
        .unwrap();
    w.log
        .append(
            &w.laptop.id,
            Op::Grant {
                resource: res("inbox"),
                principal: Principal::Member(w.alice.public()),
                capabilities: caps(&[Capability::Read]),
            },
            T,
        )
        .unwrap();
    let (op, _) = epochs::new_epoch(w.log.state(), &res("inbox"), T).unwrap();
    w.log.append(&w.laptop.id, op, T).unwrap();
    let reader = epochs::open(
        &w.log,
        &res("inbox"),
        1,
        &Recipient::Recovery(a.sign.public()),
        &a.kem,
    )
    .unwrap();
    assert!(
        reader.secret.is_none(),
        "a reader's recovery root never opens the secret key"
    );
    assert!(
        epochs::open(
            &w.log,
            &res("inbox"),
            1,
            &Recipient::Recovery(g.sign.public()),
            &g.kem
        )
        .unwrap()
        .secret
        .is_some()
    );
}

#[test]
fn blind_nodes_hold_nothing() {
    let mut w = w();
    let blind = Dev::new();
    w.log
        .append(
            &w.laptop.id,
            Op::CertifyNode {
                cert: blind.cert(&w.owner, NodeClass::Blind, LATER),
            },
            T,
        )
        .unwrap();
    w.log
        .append(&w.laptop.id, Op::CreateResource { resource: res("r") }, T)
        .unwrap();
    assert!(
        w.log
            .state()
            .capabilities(&res("r"), &blind.id.public(), T)
            .is_empty()
    );
    assert!(
        !w.log
            .state()
            .required_recipients(&res("r"), T)
            .contains_key(&blind.r())
    );
    let r = w.log.append(
        &w.laptop.id,
        Op::Grant {
            resource: res("r"),
            principal: Principal::Node(blind.id.public()),
            capabilities: caps(&[Capability::Read]),
        },
        T,
    );
    assert!(r.is_err());
    assert!(
        w.log
            .append(&blind.id, Op::CreateResource { resource: res("x") }, T)
            .is_err()
    );
}

#[test]
fn entry_times_never_go_back_and_expired_servers_cannot_backdate() {
    let mut w = w();
    let server = Dev::new();
    let expires = Timestamp(T.0 + 1_000);
    w.log
        .append(
            &w.laptop.id,
            Op::CertifyNode {
                cert: server.cert(&w.owner, NodeClass::Server, expires),
            },
            T,
        )
        .unwrap();
    w.log
        .append(
            &w.laptop.id,
            Op::CreateResource {
                resource: res("later"),
            },
            Timestamp(T.0 + 5_000),
        )
        .unwrap();
    let r = w
        .log
        .append(&server.id, Op::CreateResource { resource: res("x") }, T);
    assert!(
        matches!(r, Err(GroupError::Invalid(_))),
        "a backdated entry is refused"
    );
    let r = w.log.append(
        &server.id,
        Op::CreateResource { resource: res("x") },
        Timestamp(T.0 + 6_000),
    );
    assert!(
        matches!(r, Err(GroupError::NotAuthorized(_))),
        "an expired certificate signs nothing"
    );
    let ahead = Entry::sign(
        &w.laptop.id,
        w.log.state().group(),
        w.log.entries().len() as u64,
        w.log.head_hash(),
        Timestamp(T.0 + 10_000_000),
        Op::CreateResource { resource: res("y") },
    );
    assert!(matches!(
        w.log.apply_fresh(ahead, Timestamp(T.0 + 6_000), 300_000),
        Err(GroupError::Invalid(_))
    ));
}

#[test]
fn a_reader_cannot_poison_an_epoch_and_forged_boxes_do_not_shadow_genuine_ones() {
    let mut w = w();
    w.log
        .append(
            &w.laptop.id,
            Op::CreateResource {
                resource: res("inbox"),
            },
            T,
        )
        .unwrap();
    w.log
        .append(
            &w.laptop.id,
            Op::Grant {
                resource: res("inbox"),
                principal: Principal::Member(w.alice.public()),
                capabilities: caps(&[Capability::Read]),
            },
            T,
        )
        .unwrap();
    let (op, keys) = epochs::new_epoch(w.log.state(), &res("inbox"), T).unwrap();
    w.log.append(&w.laptop.id, op, T).unwrap();
    let phone = Dev::new();
    w.log
        .append(
            &w.laptop.id,
            Op::CertifyNode {
                cert: phone.cert(&w.owner, NodeClass::Phone, LATER),
            },
            T,
        )
        .unwrap();

    let fake = baton_seal::Key::generate().unwrap();
    let forged = epochs::ResourceKeys {
        data: fake,
        secret: Some(baton_seal::Key::generate().unwrap()),
    };
    assert!(
        epochs::share_epoch(w.log.state(), &res("inbox"), 1, &forged, T).is_err(),
        "wrong keys are not shared"
    );
    let bad_box = KeyBox {
        recipient: phone.r(),
        data: baton_keys::seal_box(&phone.kem.public(), b"whatever", &[1; 32]).unwrap(),
        secret: Some(baton_keys::seal_box(&phone.kem.public(), b"whatever", &[2; 32]).unwrap()),
    };
    let r = w.log.append(
        &w.alice_phone.id,
        Op::ShareEpoch {
            resource: res("inbox"),
            epoch: 1,
            boxes: vec![bad_box.clone()],
        },
        T,
    );
    assert!(
        matches!(r, Err(GroupError::NotAuthorized(_))),
        "a reader cannot share the secret key"
    );
    w.log
        .append(
            &w.laptop.id,
            Op::ShareEpoch {
                resource: res("inbox"),
                epoch: 1,
                boxes: vec![bad_box],
            },
            T,
        )
        .unwrap();
    let genuine = epochs::share_epoch(w.log.state(), &res("inbox"), 1, &keys, T).unwrap();
    assert!(genuine.is_none(), "the phone already counts as a recipient");
    let op = Op::ShareEpoch {
        resource: res("inbox"),
        epoch: 1,
        boxes: vec![KeyBox {
            recipient: phone.r(),
            data: baton_keys::seal_box(
                &phone.kem.public(),
                &epoch_aad(&w.log, "inbox", 1, &phone.r(), "data"),
                keys.data.expose(),
            )
            .unwrap(),
            secret: Some(
                baton_keys::seal_box(
                    &phone.kem.public(),
                    &epoch_aad(&w.log, "inbox", 1, &phone.r(), "secret"),
                    keys.secret.as_ref().unwrap().expose(),
                )
                .unwrap(),
            ),
        }],
    };
    w.log.append(&w.laptop.id, op, T).unwrap();
    let opened = epochs::open(&w.log, &res("inbox"), 1, &phone.r(), &phone.kem).unwrap();
    assert_eq!(
        opened.data.expose(),
        keys.data.expose(),
        "the genuine box wins over the forged one"
    );
}

fn epoch_aad(log: &GroupLog, resource: &str, epoch: u64, r: &Recipient, which: &str) -> Vec<u8> {
    let mut out = b"baton-epoch/v1\0".to_vec();
    out.extend(log.state().group().as_str().as_bytes());
    out.push(0);
    out.extend(resource.as_bytes());
    out.push(0);
    out.extend(epoch.to_be_bytes());
    out.extend(postcard::to_stdvec(r).unwrap());
    out.extend(which.as_bytes());
    out
}

#[test]
fn losing_lead_forces_a_new_epoch() {
    let mut w = w();
    w.log
        .append(
            &w.laptop.id,
            Op::CreateResource {
                resource: res("inbox"),
            },
            T,
        )
        .unwrap();
    w.log
        .append(
            &w.laptop.id,
            Op::Grant {
                resource: res("inbox"),
                principal: Principal::Member(w.alice.public()),
                capabilities: caps(&[Capability::Read, Capability::Lead]),
            },
            T,
        )
        .unwrap();
    let (op, _) = epochs::new_epoch(w.log.state(), &res("inbox"), T).unwrap();
    w.log.append(&w.laptop.id, op, T).unwrap();
    assert!(!w.log.state().needs_rotation(&res("inbox"), T));
    w.log
        .append(
            &w.laptop.id,
            Op::Grant {
                resource: res("inbox"),
                principal: Principal::Member(w.alice.public()),
                capabilities: caps(&[Capability::Read]),
            },
            T,
        )
        .unwrap();
    assert!(
        w.log.state().needs_rotation(&res("inbox"), T),
        "alice still holds the secret key she may no longer use"
    );
}

#[test]
fn recovery_keys_cannot_be_paired_squatted_or_reused() {
    let mut w = w();
    let attacker = RecoveryRoot::generate();
    let paired = RecoveryPublic {
        kem: attacker.public().kem,
        ..RecoveryRoot::generate().public()
    };
    let r = w.log.append(
        &w.laptop.id,
        Op::AddMember {
            member: Identity::generate().public(),
            recovery: paired,
            role: Role::Member,
        },
        T,
    );
    assert_eq!(
        r,
        Err(GroupError::BadSignature),
        "an admin cannot pair a member's recovery key with its own KEM key"
    );
    let r = w.log.append(
        &w.laptop.id,
        Op::AddMember {
            member: Identity::generate().public(),
            recovery: w.alice_root.public(),
            role: Role::Member,
        },
        T,
    );
    assert!(matches!(r, Err(GroupError::Invalid(_))));

    let group_keys = w.group_root.keys();
    let squat = NodeCert::new(
        &w.alice,
        &group_keys.sign,
        KemSecret::generate().public(),
        NodeClass::Phone,
        LATER,
    );
    let r = w
        .log
        .append(&w.alice_phone.id, Op::CertifyNode { cert: squat }, T);
    assert!(
        matches!(r, Err(GroupError::Invalid(_))),
        "a recovery key cannot be registered as a node"
    );
    let unproven = NodeCert {
        node: Identity::generate().public(),
        ..w.alice_phone.cert(&w.alice, NodeClass::Phone, LATER)
    };
    assert_eq!(
        w.log
            .append(&w.alice_phone.id, Op::CertifyNode { cert: unproven }, T),
        Err(GroupError::BadSignature)
    );

    let next = RecoveryRoot::generate();
    w.log
        .append(
            &group_keys.sign,
            Op::RotateRecovery {
                member: None,
                recovery: next.public(),
            },
            T,
        )
        .unwrap();
    let back = w.log.append(
        &next.keys().sign,
        Op::RotateRecovery {
            member: None,
            recovery: w.group_root.public(),
        },
        T,
    );
    assert!(
        matches!(back, Err(GroupError::Invalid(_))),
        "an old recovery key never comes back"
    );
}

#[test]
fn admins_cannot_add_admins_revoke_owner_nodes_or_grant_into_private_resources() {
    let mut w = w();
    let admin = Identity::generate();
    w.log
        .append(
            &w.laptop.id,
            Op::AddMember {
                member: admin.public(),
                recovery: RecoveryRoot::generate().public(),
                role: Role::Admin,
            },
            T,
        )
        .unwrap();
    let admin_dev = Dev::new();
    w.log
        .append(
            &w.laptop.id,
            Op::CertifyNode {
                cert: admin_dev.cert(&admin, NodeClass::Desktop, LATER),
            },
            T,
        )
        .unwrap();
    let r = w.log.append(
        &admin_dev.id,
        Op::AddMember {
            member: Identity::generate().public(),
            recovery: RecoveryRoot::generate().public(),
            role: Role::Admin,
        },
        T,
    );
    assert!(matches!(r, Err(GroupError::NotAuthorized(_))));
    let r = w.log.append(
        &admin_dev.id,
        Op::RevokeNode {
            node: w.laptop.id.public(),
        },
        T,
    );
    assert!(
        matches!(r, Err(GroupError::NotAuthorized(_))),
        "an admin cannot revoke an owner's node"
    );
    w.log
        .append(
            &admin_dev.id,
            Op::RevokeNode {
                node: w.alice_phone.id.public(),
            },
            T,
        )
        .unwrap();

    let mut w = self::w();
    w.log
        .append(
            &w.alice_phone.id,
            Op::CreateResource {
                resource: res("alice-mail"),
            },
            T,
        )
        .unwrap();
    let r = w.log.append(
        &w.laptop.id,
        Op::Grant {
            resource: res("alice-mail"),
            principal: Principal::Member(w.owner.public()),
            capabilities: caps(&[Capability::Read]),
        },
        T,
    );
    assert!(
        matches!(r, Err(GroupError::NotAuthorized(_))),
        "an owner cannot grant itself into a member's private resource"
    );

    w.log
        .append(
            &w.laptop.id,
            Op::CreateResource {
                resource: res("shared"),
            },
            T,
        )
        .unwrap();
    w.log
        .append(
            &w.laptop.id,
            Op::Grant {
                resource: res("shared"),
                principal: Principal::Member(w.alice.public()),
                capabilities: caps(&[Capability::Admin]),
            },
            T,
        )
        .unwrap();
    let r = w.log.append(
        &w.alice_phone.id,
        Op::Grant {
            resource: res("shared"),
            principal: Principal::Member(w.alice.public()),
            capabilities: caps(&[Capability::Admin, Capability::Read, Capability::Lead]),
        },
        T,
    );
    assert!(
        matches!(r, Err(GroupError::NotAuthorized(_))),
        "a resource admin cannot grant itself read"
    );
}

#[tokio::test]
async fn a_store_cannot_pass_off_another_group_or_a_forged_genesis() {
    let a = w();
    let b = w();
    let store: Arc<dyn StateStore> = Arc::new(MemoryState::new());
    store::save(&store, &b.log).await.unwrap();
    let wrong = GroupId::new("other").unwrap();
    let mem = Arc::new(MemoryState::new());
    for e in b.log.entries() {
        mem.tamper(
            &wrong,
            &baton_state::RecordName::new(format!("group/{:020}", e.seq())).unwrap(),
            bytes::Bytes::from(e.encode()),
        );
    }
    let dyn_mem: Arc<dyn StateStore> = mem;
    assert_eq!(
        store::load(&dyn_mem, &wrong).await.unwrap_err(),
        GroupError::Chain
    );
    let g = GroupId::new("g").unwrap();
    assert_eq!(
        store::load_expecting(&store, &g, a.log.genesis_hash())
            .await
            .unwrap_err(),
        GroupError::Fork
    );
    assert!(
        store::load_expecting(&store, &g, b.log.genesis_hash())
            .await
            .is_ok()
    );
}

#[test]
fn non_canonical_bytes_do_not_decode() {
    let w = w();
    let e = &w.log.entries()[1];
    let mut bytes = e.encode();
    bytes.push(0);
    assert!(Entry::decode(&bytes).is_err());
    assert!(Entry::decode(&e.encode()).is_ok());
}

#[test]
fn verifying_a_long_log_stays_linear() {
    let mut w = w();
    for i in 0..3_000 {
        w.log
            .append(
                &w.laptop.id,
                Op::CreateResource {
                    resource: res(&format!("r{i}")),
                },
                T,
            )
            .unwrap();
    }
    let entries = w.log.entries().to_vec();
    let started = std::time::Instant::now();
    GroupLog::verify(entries).unwrap();
    assert!(
        started.elapsed() < std::time::Duration::from_secs(20),
        "{:?}",
        started.elapsed()
    );
}
