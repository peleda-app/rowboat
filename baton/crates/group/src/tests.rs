use std::collections::BTreeSet;
use std::sync::Arc;

use baton_keys::{KemSecret, RecoveryRoot};
use baton_state::StateStore;
use baton_state_memory::MemoryState;

use super::*;
use crate::epochs;

const T: Timestamp = Timestamp(1_700_000_000_000);
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
    fn cert(&self, member: &Identity) -> NodeCert {
        NodeCert::new(
            member,
            &self.id,
            self.kem.public(),
            NodeClass::Desktop,
            LATER,
        )
    }
    fn recipient(&self) -> Recipient {
        Recipient::Node(self.id.public())
    }
}

struct World {
    owner: Identity,
    owner_root: RecoveryRoot,
    group_root: RecoveryRoot,
    laptop: Device,
    log: GroupLog,
}

fn group() -> GroupId {
    GroupId::new("family").unwrap()
}

fn res(name: &str) -> ResourceId {
    ResourceId::new(name).unwrap()
}

fn world() -> World {
    let owner = Identity::generate();
    let owner_root = RecoveryRoot::generate();
    let group_root = RecoveryRoot::generate();
    let laptop = Device::new();
    let log = GroupLog::genesis(
        group(),
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
    World {
        owner,
        owner_root,
        group_root,
        laptop,
        log,
    }
}

fn caps(list: &[Capability]) -> BTreeSet<Capability> {
    list.iter().cloned().collect()
}

#[test]
fn genesis_is_checked() {
    let w = world();
    assert_eq!(w.log.state().role(&w.owner.public()), Some(Role::Owner));
    assert!(w.log.state().node(&w.laptop.id.public(), T).is_some());

    let stranger = Identity::generate();
    let other = Device::new();
    let forged = GroupLog::genesis(
        group(),
        Founding {
            owner: &w.owner,
            owner_recovery: w.owner_root.public(),
            group_recovery: w.owner_root.public(),
            node: &other.id,
            node_kem: other.kem.public(),
            class: NodeClass::Desktop,
            expires: LATER,
        },
        T,
    );
    assert!(
        matches!(forged, Err(GroupError::Invalid(_))),
        "recovery keys must differ"
    );
    let mut entries = w.log.entries().to_vec();
    entries[0].body.signer = stranger.public();
    assert!(
        GroupLog::verify(entries).is_err(),
        "a genesis signed by someone else is refused"
    );
}

#[test]
fn roles_decide_who_adds_members_and_nodes() {
    let mut w = world();
    let alice = Identity::generate();
    let alice_root = RecoveryRoot::generate();
    w.log
        .append(
            &w.laptop.id,
            Op::AddMember {
                member: alice.public(),
                recovery: alice_root.public(),
                role: Role::Member,
            },
            T,
        )
        .unwrap();
    let alice_phone = Device::new();
    w.log
        .append(
            &w.laptop.id,
            Op::CertifyNode {
                cert: alice_phone.cert(&alice),
            },
            T,
        )
        .unwrap();

    let bob = Identity::generate();
    let r = w.log.append(
        &alice_phone.id,
        Op::AddMember {
            member: bob.public(),
            recovery: RecoveryRoot::generate().public(),
            role: Role::Member,
        },
        T,
    );
    assert!(
        matches!(r, Err(GroupError::NotAuthorized(_))),
        "a member cannot add members"
    );

    let owners_device = Device::new();
    let r = w.log.append(
        &alice_phone.id,
        Op::CertifyNode {
            cert: owners_device.cert(&w.owner),
        },
        T,
    );
    assert!(
        matches!(r, Err(GroupError::NotAuthorized(_))),
        "a member cannot certify another member's node"
    );

    let forged = NodeCert {
        member: alice.public(),
        ..owners_device.cert(&w.owner)
    };
    let r = w
        .log
        .append(&alice_phone.id, Op::CertifyNode { cert: forged }, T);
    assert_eq!(
        r,
        Err(GroupError::BadSignature),
        "a certificate not signed by its member is refused"
    );

    let expired = NodeCert::new(
        &alice,
        &Device::new().id,
        KemSecret::generate().public(),
        NodeClass::Phone,
        Timestamp(1),
    );
    assert!(matches!(
        w.log
            .append(&alice_phone.id, Op::CertifyNode { cert: expired }, T),
        Err(GroupError::Invalid(_))
    ));

    w.log
        .append(
            &w.laptop.id,
            Op::RevokeNode {
                node: alice_phone.id.public(),
            },
            T,
        )
        .unwrap();
    let again = w.log.append(
        &w.laptop.id,
        Op::CertifyNode {
            cert: alice_phone.cert(&alice),
        },
        T,
    );
    assert!(
        matches!(again, Err(GroupError::Invalid(_))),
        "a revoked key never comes back"
    );
    let r = w.log.append(
        &alice_phone.id,
        Op::CreateResource { resource: res("x") },
        T,
    );
    assert!(
        matches!(r, Err(GroupError::NotAuthorized(_))),
        "a revoked node signs nothing"
    );

    let r = w.log.append(
        &w.laptop.id,
        Op::RemoveMember {
            member: w.owner.public(),
        },
        T,
    );
    assert!(
        matches!(r, Err(GroupError::Invalid(_))),
        "the last owner stays"
    );
}

#[test]
fn shared_and_private_resources_keep_their_keys_apart() {
    let mut w = world();
    let alice = Identity::generate();
    w.log
        .append(
            &w.laptop.id,
            Op::AddMember {
                member: alice.public(),
                recovery: RecoveryRoot::generate().public(),
                role: Role::Member,
            },
            T,
        )
        .unwrap();
    let alice_phone = Device::new();
    w.log
        .append(
            &w.laptop.id,
            Op::CertifyNode {
                cert: alice_phone.cert(&alice),
            },
            T,
        )
        .unwrap();

    w.log
        .append(
            &w.laptop.id,
            Op::CreateResource {
                resource: res("family-inbox"),
            },
            T,
        )
        .unwrap();
    w.log
        .append(
            &w.laptop.id,
            Op::CreateResource {
                resource: res("owner-private"),
            },
            T,
        )
        .unwrap();
    w.log
        .append(
            &w.laptop.id,
            Op::Grant {
                resource: res("family-inbox"),
                principal: Principal::Member(alice.public()),
                capabilities: caps(&[Capability::Read, Capability::Command("flag".into())]),
            },
            T,
        )
        .unwrap();

    let (op, shared) = epochs::new_epoch(w.log.state(), &res("family-inbox"), T).unwrap();
    w.log.append(&w.laptop.id, op, T).unwrap();
    let (op, private) = epochs::new_epoch(w.log.state(), &res("owner-private"), T).unwrap();
    w.log.append(&w.laptop.id, op, T).unwrap();

    let mine = epochs::open(
        &w.log,
        &res("family-inbox"),
        1,
        &alice_phone.recipient(),
        &alice_phone.kem,
    )
    .unwrap();
    assert_eq!(mine.data.expose(), shared.data.expose());
    assert!(
        mine.secret.is_none(),
        "a reader without lead never gets the secret key"
    );
    assert!(
        epochs::open(
            &w.log,
            &res("owner-private"),
            1,
            &alice_phone.recipient(),
            &alice_phone.kem
        )
        .is_err(),
        "a member of the shared box cannot open the private one"
    );
    let owner = epochs::open(
        &w.log,
        &res("owner-private"),
        1,
        &w.laptop.recipient(),
        &w.laptop.kem,
    )
    .unwrap();
    assert_eq!(
        owner.secret.unwrap().expose(),
        private.secret.as_ref().unwrap().expose()
    );

    assert!(!w.log.state().may(
        &alice_phone.id.public(),
        &res("family-inbox"),
        &Capability::Command("send".into()),
        T
    ));
    assert!(w.log.state().may(
        &alice_phone.id.public(),
        &res("family-inbox"),
        &Capability::Command("flag".into()),
        T
    ));
    let r = w.log.append(
        &alice_phone.id,
        Op::Grant {
            resource: res("family-inbox"),
            principal: Principal::Member(alice.public()),
            capabilities: caps(&[Capability::Read, Capability::Lead]),
        },
        T,
    );
    assert!(
        matches!(r, Err(GroupError::NotAuthorized(_))),
        "nobody grants themselves more"
    );
    for bad in [
        caps(&[Capability::Command("send".into())]),
        caps(&[Capability::Read, Capability::Command("Bad Class".into())]),
    ] {
        let r = w.log.append(
            &w.laptop.id,
            Op::Grant {
                resource: res("family-inbox"),
                principal: Principal::Member(alice.public()),
                capabilities: bad,
            },
            T,
        );
        assert!(matches!(r, Err(GroupError::Invalid(_))));
    }
}

#[test]
fn epochs_go_to_exactly_the_authorized_recipients() {
    let mut w = world();
    w.log
        .append(&w.laptop.id, Op::CreateResource { resource: res("r") }, T)
        .unwrap();
    let (op, _) = epochs::new_epoch(w.log.state(), &res("r"), T).unwrap();
    let Op::KeyEpoch {
        resource,
        epoch,
        commitments,
        mut boxes,
    } = op
    else {
        unreachable!()
    };

    let mut missing = boxes.clone();
    missing.pop();
    let r = w.log.append(
        &w.laptop.id,
        Op::KeyEpoch {
            commitments: commitments.clone(),
            resource: resource.clone(),
            epoch,
            boxes: missing,
        },
        T,
    );
    assert!(
        matches!(r, Err(GroupError::Invalid(_))),
        "a missing recipient is refused"
    );

    let outsider = Device::new();
    let mut extra = boxes.clone();
    extra.push(KeyBox {
        recipient: outsider.recipient(),
        data: boxes[0].data.clone(),
        secret: None,
    });
    let r = w.log.append(
        &w.laptop.id,
        Op::KeyEpoch {
            commitments: commitments.clone(),
            resource: resource.clone(),
            epoch,
            boxes: extra,
        },
        T,
    );
    assert!(
        matches!(r, Err(GroupError::Invalid(_))),
        "a box for an outsider is refused"
    );

    let mut dup = boxes.clone();
    dup.push(boxes[0].clone());
    assert!(
        w.log
            .append(
                &w.laptop.id,
                Op::KeyEpoch {
                    commitments: commitments.clone(),
                    resource: resource.clone(),
                    epoch,
                    boxes: dup
                },
                T
            )
            .is_err()
    );

    let r = w.log.append(
        &w.laptop.id,
        Op::KeyEpoch {
            commitments: commitments.clone(),
            resource: resource.clone(),
            epoch: 2,
            boxes: boxes.clone(),
        },
        T,
    );
    assert!(
        matches!(r, Err(GroupError::Invalid(_))),
        "epochs follow each other"
    );

    for b in boxes.iter_mut() {
        b.secret = None;
    }
    let r = w.log.append(
        &w.laptop.id,
        Op::KeyEpoch {
            commitments: commitments.clone(),
            resource,
            epoch,
            boxes,
        },
        T,
    );
    assert!(
        matches!(r, Err(GroupError::Invalid(_))),
        "those who lead get the secret key"
    );
}

#[test]
fn revocation_forces_a_new_epoch_the_revoked_node_cannot_open() {
    let mut w = world();
    let phone = Device::new();
    w.log
        .append(
            &w.laptop.id,
            Op::CertifyNode {
                cert: phone.cert(&w.owner),
            },
            T,
        )
        .unwrap();
    w.log
        .append(&w.laptop.id, Op::CreateResource { resource: res("r") }, T)
        .unwrap();
    let (op, _) = epochs::new_epoch(w.log.state(), &res("r"), T).unwrap();
    w.log.append(&w.laptop.id, op, T).unwrap();
    assert!(epochs::open(&w.log, &res("r"), 1, &phone.recipient(), &phone.kem).is_ok());
    assert!(!w.log.state().needs_rotation(&res("r"), T));

    w.log
        .append(
            &w.laptop.id,
            Op::RevokeNode {
                node: phone.id.public(),
            },
            T,
        )
        .unwrap();
    assert!(
        w.log.state().needs_rotation(&res("r"), T),
        "the stolen phone still holds epoch 1"
    );
    assert!(w.log.state().was_certified(&phone.id.public()));
    assert!(w.log.state().was_certified(&w.laptop.id.public()));
    assert!(!w.log.state().was_certified(&Device::new().id.public()));
    let (op, fresh) = epochs::new_epoch(w.log.state(), &res("r"), T).unwrap();
    w.log.append(&w.laptop.id, op, T).unwrap();
    assert!(!w.log.state().needs_rotation(&res("r"), T));
    assert!(epochs::open(&w.log, &res("r"), 2, &phone.recipient(), &phone.kem).is_err());
    let laptop = epochs::open(&w.log, &res("r"), 2, &w.laptop.recipient(), &w.laptop.kem).unwrap();
    assert_eq!(laptop.data.expose(), fresh.data.expose());
}

#[test]
fn a_new_device_gets_past_epochs_shared_and_nobody_else() {
    let mut w = world();
    w.log
        .append(&w.laptop.id, Op::CreateResource { resource: res("r") }, T)
        .unwrap();
    let (op, keys) = epochs::new_epoch(w.log.state(), &res("r"), T).unwrap();
    w.log.append(&w.laptop.id, op, T).unwrap();
    let desktop = Device::new();
    w.log
        .append(
            &w.laptop.id,
            Op::CertifyNode {
                cert: desktop.cert(&w.owner),
            },
            T,
        )
        .unwrap();
    let op = epochs::share_epoch(w.log.state(), &res("r"), 1, &keys, T)
        .unwrap()
        .expect("the desktop is missing");
    w.log.append(&w.laptop.id, op, T).unwrap();
    let got = epochs::open(&w.log, &res("r"), 1, &desktop.recipient(), &desktop.kem).unwrap();
    assert_eq!(got.data.expose(), keys.data.expose());
    assert!(
        epochs::share_epoch(w.log.state(), &res("r"), 1, &keys, T)
            .unwrap()
            .is_none()
    );

    let outsider = Device::new();
    let bogus = Op::ShareEpoch {
        resource: res("r"),
        epoch: 1,
        boxes: vec![KeyBox {
            recipient: outsider.recipient(),
            data: baton_keys::seal_box(&outsider.kem.public(), b"x", b"y").unwrap(),
            secret: None,
        }],
    };
    assert!(matches!(
        w.log.append(&w.laptop.id, bogus, T),
        Err(GroupError::Invalid(_))
    ));
}

#[test]
fn the_chain_cannot_be_rewritten_and_forks_are_detected() {
    let mut w = world();
    w.log
        .append(&w.laptop.id, Op::CreateResource { resource: res("a") }, T)
        .unwrap();
    w.log
        .append(&w.laptop.id, Op::CreateResource { resource: res("b") }, T)
        .unwrap();
    let entries = w.log.entries().to_vec();

    let mut swapped = entries.clone();
    swapped.swap(1, 2);
    assert!(GroupLog::verify(swapped).is_err());
    let mut dropped = entries.clone();
    dropped.remove(1);
    assert!(GroupLog::verify(dropped).is_err());
    let mut tampered = entries.clone();
    tampered[2].body.op = Op::CreateResource {
        resource: res("evil"),
    };
    assert_eq!(
        GroupLog::verify(tampered).unwrap_err(),
        GroupError::BadSignature
    );

    let mut other = World {
        log: GroupLog::verify(entries[..2].to_vec()).unwrap(),
        ..world()
    };
    other.log = GroupLog::verify(entries[..2].to_vec()).unwrap();
    let fork_entry = other
        .log
        .append(&w.laptop.id, Op::CreateResource { resource: res("c") }, T)
        .unwrap();
    assert_eq!(w.log.check_head(2, fork_entry.hash()), HeadCheck::Fork);
    assert_eq!(w.log.check_head(1, entries[1].hash()), HeadCheck::Behind);
    assert_eq!(w.log.check_head(2, entries[2].hash()), HeadCheck::Same);
    assert_eq!(w.log.check_head(9, [0; 32]), HeadCheck::Ahead);
    assert!(
        w.log.apply(fork_entry).is_err(),
        "an entry for an occupied position does not apply"
    );
    assert!(Entry::decode(b"junk").is_err());
    assert!(Entry::decode(&vec![0; MAX_ENTRY + 1]).is_err());
}

#[test]
fn a_certificate_assembled_from_a_remote_proof_verifies() {
    let mut w = world();
    let phone = Device::new();
    let proof = NodeCert::node_proof(
        &phone.id,
        &phone.kem.public(),
        NodeClass::Phone,
        &w.owner.public(),
        LATER,
    );
    let cert = NodeCert::assemble(
        &w.owner,
        phone.id.public(),
        phone.kem.public(),
        NodeClass::Phone,
        LATER,
        proof,
    )
    .unwrap();
    w.log
        .append(&w.laptop.id, Op::CertifyNode { cert }, T)
        .unwrap();
    assert!(w.log.state().node(&phone.id.public(), T).is_some());

    let other = Device::new();
    let proof = NodeCert::node_proof(
        &other.id,
        &other.kem.public(),
        NodeClass::Phone,
        &w.owner.public(),
        LATER,
    );
    for (class, expires) in [(NodeClass::Server, LATER), (NodeClass::Phone, T)] {
        assert_eq!(
            NodeCert::assemble(
                &w.owner,
                other.id.public(),
                other.kem.public(),
                class,
                expires,
                proof
            ),
            Err(GroupError::BadSignature),
            "a proof covers exactly the terms the node signed"
        );
    }
    assert_eq!(
        NodeCert::assemble(
            &w.owner,
            Identity::generate().public(),
            other.kem.public(),
            NodeClass::Phone,
            LATER,
            proof
        ),
        Err(GroupError::BadSignature),
        "a proof by another key"
    );
}

#[test]
fn renewal_moves_the_expiry_and_nothing_else() {
    let mut w = world();
    let later = Timestamp(LATER.0 + 1_000);
    let renewed = NodeCert::new(
        &w.owner,
        &w.laptop.id,
        w.laptop.kem.public(),
        NodeClass::Desktop,
        later,
    );
    w.log
        .append(&w.laptop.id, Op::RenewNode { cert: renewed }, T)
        .unwrap();
    assert!(w.log.state().node(&w.laptop.id.public(), later).is_some());

    for (kem, class, expires) in [
        (
            KemSecret::generate().public(),
            NodeClass::Desktop,
            Timestamp(later.0 + 1),
        ),
        (
            w.laptop.kem.public(),
            NodeClass::Server,
            Timestamp(later.0 + 1),
        ),
        (w.laptop.kem.public(), NodeClass::Desktop, later),
        (w.laptop.kem.public(), NodeClass::Desktop, LATER),
    ] {
        let cert = NodeCert::new(&w.owner, &w.laptop.id, kem, class, expires);
        assert!(matches!(
            w.log.append(&w.laptop.id, Op::RenewNode { cert }, T),
            Err(GroupError::Invalid(_))
        ));
    }

    let stranger = Device::new();
    let cert = stranger.cert(&w.owner);
    assert!(
        matches!(
            w.log.append(&w.laptop.id, Op::RenewNode { cert }, T),
            Err(GroupError::Invalid(_))
        ),
        "only certified nodes are renewed"
    );

    let phone = Device::new();
    w.log
        .append(
            &w.laptop.id,
            Op::CertifyNode {
                cert: phone.cert(&w.owner),
            },
            T,
        )
        .unwrap();
    w.log
        .append(
            &w.laptop.id,
            Op::RevokeNode {
                node: phone.id.public(),
            },
            T,
        )
        .unwrap();
    let cert = NodeCert::new(
        &w.owner,
        &phone.id,
        phone.kem.public(),
        NodeClass::Desktop,
        later,
    );
    assert!(
        matches!(
            w.log.append(&w.laptop.id, Op::RenewNode { cert }, T),
            Err(GroupError::Invalid(_))
        ),
        "a revoked node is never renewed"
    );

    let other_member = Identity::generate();
    let cert = NodeCert::new(
        &other_member,
        &w.laptop.id,
        w.laptop.kem.public(),
        NodeClass::Desktop,
        Timestamp(later.0 + 5),
    );
    assert!(
        w.log
            .append(&w.laptop.id, Op::RenewNode { cert }, T)
            .is_err(),
        "a renewal by another member key"
    );
}

#[test]
fn checkpoints_and_recovery_rotation_need_the_right_keys() {
    let mut w = world();
    let r = w.log.append(&w.laptop.id, Op::Checkpoint, T);
    assert!(matches!(r, Err(GroupError::NotAuthorized(_))));
    let group_keys = w.group_root.keys();
    w.log.append(&group_keys.sign, Op::Checkpoint, T).unwrap();
    assert_eq!(w.log.state().checkpoint(), Some(1));

    let new_root = RecoveryRoot::generate();
    let r = w.log.append(
        &group_keys.sign,
        Op::RotateRecovery {
            member: Some(w.owner.public()),
            recovery: new_root.public(),
        },
        T,
    );
    assert!(
        matches!(r, Err(GroupError::NotAuthorized(_))),
        "the group key does not rotate a member's key"
    );
    let by_node = w.log.append(
        &w.laptop.id,
        Op::RotateRecovery {
            member: Some(w.owner.public()),
            recovery: new_root.public(),
        },
        T,
    );
    assert!(
        matches!(by_node, Err(GroupError::NotAuthorized(_))),
        "a node alone cannot replace its member's recovery key"
    );
    w.log
        .append(
            &w.owner_root.keys().sign,
            Op::RotateRecovery {
                member: Some(w.owner.public()),
                recovery: new_root.public(),
            },
            T,
        )
        .unwrap();
    assert_eq!(
        w.log.state().member_recovery(&w.owner.public()),
        Some(&new_root.public())
    );
    let reuse = w.log.append(
        &group_keys.sign,
        Op::RotateRecovery {
            member: None,
            recovery: new_root.public(),
        },
        T,
    );
    assert!(
        matches!(reuse, Err(GroupError::Invalid(_))),
        "a recovery key is used once"
    );
    let old = w.owner_root.keys();
    let r = w.log.append(
        &old.sign,
        Op::RevokeNode {
            node: w.laptop.id.public(),
        },
        T,
    );
    assert!(
        matches!(r, Err(GroupError::NotAuthorized(_))),
        "a rotated-out recovery key has no power"
    );
}

#[tokio::test]
async fn the_store_orders_writers_and_refuses_gaps_and_tampering() {
    let mut w = world();
    let store: Arc<dyn StateStore> = Arc::new(MemoryState::new());
    store::save(&store, &w.log).await.unwrap();
    let e1 = w
        .log
        .append(&w.laptop.id, Op::CreateResource { resource: res("a") }, T)
        .unwrap();
    store::append(&store, &e1).await.unwrap();
    store::append(&store, &e1).await.unwrap();

    let mut rival = store::load(&store, &group()).await.unwrap();
    let mut late = GroupLog::verify(w.log.entries()[..1].to_vec()).unwrap();
    let competing = late
        .append(&w.laptop.id, Op::CreateResource { resource: res("b") }, T)
        .unwrap();
    assert_eq!(
        store::append(&store, &competing).await,
        Err(GroupError::Fork),
        "one writer per position"
    );
    assert_eq!(rival.head_seq(), 1);
    rival
        .append(&w.laptop.id, Op::CreateResource { resource: res("c") }, T)
        .unwrap();
    store::save(&store, &rival).await.unwrap();
    let loaded = store::load(&store, &group()).await.unwrap();
    assert_eq!(loaded.head_hash(), rival.head_hash());

    let mem = Arc::new(MemoryState::new());
    let dyn_mem: Arc<dyn StateStore> = mem.clone();
    store::save(&dyn_mem, &rival).await.unwrap();
    mem.tamper(
        &group(),
        &RecordName::new(format!("group/{:020}", 1)).unwrap(),
        Bytes::from_static(b"garbage"),
    );
    assert!(store::load(&dyn_mem, &group()).await.is_err());

    let gap = Arc::new(MemoryState::new());
    let dyn_gap: Arc<dyn StateStore> = gap.clone();
    store::save(&dyn_gap, &rival).await.unwrap();
    dyn_gap
        .delete(
            &group(),
            &RecordName::new(format!("group/{:020}", 1)).unwrap(),
            baton_state::Expect::Any,
        )
        .await
        .unwrap();
    assert_eq!(
        store::load(&dyn_gap, &group()).await.unwrap_err(),
        GroupError::Chain
    );
}

use baton_state::RecordName;
use bytes::Bytes;

/// Every device is lost; the person has the recovery roots and the store. The group comes back.
#[tokio::test]
async fn recovery_drill_restores_a_group_from_scratch() {
    let store: Arc<dyn StateStore> = Arc::new(MemoryState::new());
    let (owner_root_bytes, group_root_bytes, original_data, original_secret) = {
        let mut w = world();
        let phone = Device::new();
        w.log
            .append(
                &w.laptop.id,
                Op::CertifyNode {
                    cert: phone.cert(&w.owner),
                },
                T,
            )
            .unwrap();
        w.log
            .append(
                &w.laptop.id,
                Op::CreateResource {
                    resource: res("mail"),
                },
                T,
            )
            .unwrap();
        let (op, keys) = epochs::new_epoch(w.log.state(), &res("mail"), T).unwrap();
        w.log.append(&w.laptop.id, op, T).unwrap();
        w.log
            .append(&w.group_root.keys().sign, Op::Checkpoint, T)
            .unwrap();
        store::save(&store, &w.log).await.unwrap();
        (
            *w.owner_root.expose(),
            *w.group_root.expose(),
            *keys.data.expose(),
            *keys.secret.unwrap().expose(),
        )
    };

    let owner_root = RecoveryRoot::from_bytes(owner_root_bytes);
    let group_root = RecoveryRoot::from_bytes(group_root_bytes);
    let mut log = store::load(&store, &group())
        .await
        .expect("the stored log verifies from genesis");
    let owner = log
        .state()
        .members()
        .find(|(_, r)| *r == Role::Owner)
        .map(|(k, _)| *k)
        .unwrap();
    assert_eq!(
        log.state().member_recovery(&owner),
        Some(&owner_root.public()),
        "the typed root matches the log"
    );
    assert_eq!(log.state().group_recovery(), &group_root.public());
    assert!(log.state().checkpoint().is_some());

    let recovered = owner_root.keys();
    let keys = epochs::open(
        &log,
        &res("mail"),
        1,
        &Recipient::Recovery(recovered.sign.public()),
        &recovered.kem,
    )
    .unwrap();
    assert_eq!(keys.data.expose(), &original_data);
    assert_eq!(
        keys.secret.as_ref().unwrap().expose(),
        &original_secret,
        "provider credentials can be opened again"
    );
    let group_keys = group_root.keys();
    let via_group = epochs::open(
        &log,
        &res("mail"),
        1,
        &Recipient::Recovery(group_keys.sign.public()),
        &group_keys.kem,
    );
    assert!(
        via_group.is_err(),
        "the group's recovery key opens no member's private resource"
    );

    let new_member = Identity::generate();
    let new_device = Device::new();
    let premature = NodeCert::new(
        &new_member,
        &new_device.id,
        new_device.kem.public(),
        NodeClass::Desktop,
        LATER,
    );
    assert!(
        log.append(&recovered.sign, Op::CertifyNode { cert: premature }, T)
            .is_err(),
        "a cert by an unknown member key is refused"
    );
    let r = log.append(
        &group_keys.sign,
        Op::RekeyMember {
            member: owner,
            new_key: new_member.public(),
        },
        T,
    );
    assert!(
        matches!(r, Err(GroupError::NotAuthorized(_))),
        "only the member's own recovery key replaces the member key"
    );

    let old_nodes: Vec<_> = log.state().nodes(T).iter().map(|c| c.node).collect();
    for n in &old_nodes {
        log.append(&recovered.sign, Op::RevokeNode { node: *n }, T)
            .unwrap();
    }
    log.append(
        &recovered.sign,
        Op::RekeyMember {
            member: owner,
            new_key: new_member.public(),
        },
        T,
    )
    .unwrap();
    assert_eq!(log.state().role(&new_member.public()), Some(Role::Owner));
    assert_eq!(log.state().role(&owner), None);
    log.append(
        &recovered.sign,
        Op::CertifyNode {
            cert: new_device.cert(&new_member),
        },
        T,
    )
    .unwrap();
    assert!(
        log.state().needs_rotation(&res("mail"), T),
        "the lost devices held epoch 1"
    );

    let (op, fresh) = epochs::new_epoch(log.state(), &res("mail"), T).unwrap();
    log.append(&new_device.id, op, T).unwrap();
    assert!(!log.state().needs_rotation(&res("mail"), T));
    let opened = epochs::open(
        &log,
        &res("mail"),
        2,
        &new_device.recipient(),
        &new_device.kem,
    )
    .unwrap();
    assert_eq!(opened.data.expose(), fresh.data.expose());
    for n in &old_nodes {
        assert!(
            epochs::open(
                &log,
                &res("mail"),
                2,
                &Recipient::Node(*n),
                &KemSecret::generate()
            )
            .is_err()
        );
    }

    let new_root = RecoveryRoot::generate();
    log.append(
        &recovered.sign,
        Op::RotateRecovery {
            member: Some(new_member.public()),
            recovery: new_root.public(),
        },
        T,
    )
    .unwrap();
    let spent = log.append(
        &recovered.sign,
        Op::RevokeNode {
            node: new_device.id.public(),
        },
        T,
    );
    assert!(
        matches!(spent, Err(GroupError::NotAuthorized(_))),
        "after rotation the used root has no power"
    );
    store::save(&store, &log).await.unwrap();
    assert_eq!(
        store::load(&store, &group()).await.unwrap().head_hash(),
        log.head_hash()
    );
}

proptest::proptest! {
    #[test]
    fn arbitrary_bytes_never_decode_into_a_valid_entry(raw in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2000)) {
        proptest::prop_assert!(Entry::decode(&raw).is_err());
    }
}

#[test]
fn a_server_holds_only_node_grants_and_no_member_authority() {
    let mut w = world();
    let r = res("vault-1");
    w.log
        .append(
            &w.laptop.id,
            Op::CreateResource {
                resource: r.clone(),
            },
            T,
        )
        .unwrap();
    let server = Device::new();
    let cert = NodeCert::new(
        &w.owner,
        &server.id,
        server.kem.public(),
        NodeClass::Server,
        LATER,
    );
    w.log
        .append(&w.laptop.id, Op::CertifyNode { cert }, T)
        .unwrap();
    let s = server.id.public();
    assert!(
        w.log.state().capabilities(&r, &s, T).is_empty(),
        "a member grant does not reach the member's servers"
    );
    assert!(
        !w.log
            .state()
            .required_recipients(&r, T)
            .contains_key(&server.recipient())
    );
    w.log
        .append(
            &w.laptop.id,
            Op::Grant {
                resource: r.clone(),
                principal: Principal::Node(s),
                capabilities: caps(&[Capability::Read, Capability::Lead]),
            },
            T,
        )
        .unwrap();
    assert_eq!(
        w.log.state().capabilities(&r, &s, T),
        caps(&[Capability::Read, Capability::Lead])
    );

    let attacker = Identity::generate();
    let forged = [
        Op::AddMember {
            member: attacker.public(),
            recovery: RecoveryRoot::generate().public(),
            role: Role::Owner,
        },
        Op::RemoveMember {
            member: w.owner.public(),
        },
        Op::RevokeNode {
            node: w.laptop.id.public(),
        },
        Op::CreateResource {
            resource: res("vault-2"),
        },
        Op::CertifyNode {
            cert: Device::new().cert(&w.owner),
        },
        Op::Grant {
            resource: r.clone(),
            principal: Principal::Node(s),
            capabilities: caps(&[Capability::Read, Capability::Lead, Capability::Admin]),
        },
        Op::Grant {
            resource: r.clone(),
            principal: Principal::Member(w.owner.public()),
            capabilities: caps(&[Capability::Read]),
        },
    ];
    for op in forged {
        let label = format!("{op:?}");
        assert!(
            matches!(
                w.log.append(&server.id, op, T),
                Err(GroupError::NotAuthorized(_))
            ),
            "{label}"
        );
    }
    w.log
        .append(&server.id, Op::RevokeNode { node: s }, T)
        .unwrap();
    assert!(w.log.state().node(&s, T).is_none());
}
