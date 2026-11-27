use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use baton_group::{Founding, NodeCert, Op, Principal, epochs};
use baton_identity::RosterHandle;
use baton_keys::{KemSecret, RecoveryRoot};
use baton_lease::NodeClass;
use baton_mesh::Transport;
use baton_mesh_memory::MemoryHub;
use futures::StreamExt;

use super::*;

const T: Timestamp = Timestamp(1_700_000_000_000);
const LATER: Timestamp = Timestamp(1_800_000_000_000);

struct W {
    laptop: Identity,
    server: Identity,
    alice: Identity,
    alice_phone: Identity,
    log: GroupLog,
    key: Key,
}

fn res() -> ResourceId {
    ResourceId::new("inbox").unwrap()
}

fn w() -> W {
    let owner = Identity::generate();
    let laptop = Identity::generate();
    let mut log = GroupLog::genesis(
        GroupId::new("g").unwrap(),
        Founding {
            owner: &owner,
            owner_recovery: RecoveryRoot::generate().public(),
            group_recovery: RecoveryRoot::generate().public(),
            node: &laptop,
            node_kem: KemSecret::generate().public(),
            class: NodeClass::Desktop,
            expires: LATER,
        },
        T,
    )
    .unwrap();
    let server = Identity::generate();
    log.append(
        &laptop,
        Op::CertifyNode {
            cert: NodeCert::new(
                &owner,
                &server,
                KemSecret::generate().public(),
                NodeClass::Server,
                LATER,
            ),
        },
        T,
    )
    .unwrap();
    let alice = Identity::generate();
    log.append(
        &laptop,
        Op::AddMember {
            member: alice.public(),
            recovery: RecoveryRoot::generate().public(),
            role: baton_group::Role::Member,
        },
        T,
    )
    .unwrap();
    let alice_phone = Identity::generate();
    log.append(
        &laptop,
        Op::CertifyNode {
            cert: NodeCert::new(
                &alice,
                &alice_phone,
                KemSecret::generate().public(),
                NodeClass::Phone,
                LATER,
            ),
        },
        T,
    )
    .unwrap();
    log.append(&laptop, Op::CreateResource { resource: res() }, T)
        .unwrap();
    let caps: BTreeSet<_> = [Capability::Read, Capability::Command("flag".into())]
        .into_iter()
        .collect();
    log.append(
        &laptop,
        Op::Grant {
            resource: res(),
            principal: Principal::Member(alice.public()),
            capabilities: caps,
        },
        T,
    )
    .unwrap();
    log.append(
        &laptop,
        Op::Grant {
            resource: res(),
            principal: Principal::Node(server.public()),
            capabilities: [Capability::Read, Capability::Lead].into(),
        },
        T,
    )
    .unwrap();
    let (op, keys) = epochs::new_epoch(log.state(), &res(), T).unwrap();
    log.append(&laptop, op, T).unwrap();
    W {
        laptop,
        server,
        alice,
        alice_phone,
        log,
        key: keys.data,
    }
}

fn flag<'a>(key: &'a Key, resource: &'a ResourceId, payload: &'a [u8]) -> Request<'a> {
    Request {
        resource,
        epoch: 1,
        data_key: key,
        class: "flag",
        idempotency_key: "k-1",
        payload,
    }
}

#[test]
fn a_member_with_the_capability_issues_and_the_leaseholder_opens() {
    let w = w();
    let r = res();
    let c = Command::issue(
        &w.alice_phone,
        &w.log,
        flag(&w.key, &r, b"msg-42 \\Seen"),
        T,
        60_000,
    )
    .unwrap();
    let wire = Command::decode(&c.encode()).unwrap();
    let checked = wire.check(&w.log, &r, &w.key, T).unwrap();
    assert_eq!(&checked.payload[..], b"msg-42 \\Seen");
    assert_eq!(checked.class, "flag");
    assert_eq!(checked.issuer, w.alice_phone.public());

    let result = CommandResult::sign(&w.server, &checked, &w.key, &Outcome::Applied, T).unwrap();
    let back = CommandResult::decode(&result.encode()).unwrap();
    assert_eq!(back.check(&c, &w.log, &w.key, T).unwrap(), Outcome::Applied);
    let conflict = CommandResult::sign(
        &w.server,
        &checked,
        &w.key,
        &Outcome::Conflict {
            state: b"v2".to_vec(),
        },
        T,
    )
    .unwrap();
    assert_eq!(
        conflict.check(&c, &w.log, &w.key, T).unwrap(),
        Outcome::Conflict {
            state: b"v2".to_vec()
        }
    );
}

#[test]
fn commands_outside_the_issuers_capabilities_are_refused() {
    let w = w();
    let r = res();
    let send = Request {
        class: "send",
        ..flag(&w.key, &r, b"x")
    };
    let c = Command::issue(&w.alice_phone, &w.log, send, T, 60_000).unwrap();
    assert_eq!(
        c.check(&w.log, &r, &w.key, T).unwrap_err(),
        CommandError::NotAuthorized
    );
    let outsider = Identity::generate();
    let c = Command::issue(&outsider, &w.log, flag(&w.key, &r, b"x"), T, 60_000).unwrap();
    assert_eq!(
        c.check(&w.log, &r, &w.key, T).unwrap_err(),
        CommandError::NotAuthorized
    );
    let other = ResourceId::new("other").unwrap();
    let c = Command::issue(
        &w.alice_phone,
        &w.log,
        flag(&w.key, &other, b"x"),
        T,
        60_000,
    )
    .unwrap();
    assert_eq!(
        c.check(&w.log, &r, &w.key, T).unwrap_err(),
        CommandError::WrongGroup
    );
}

#[test]
fn revocation_expiry_tampering_and_wrong_keys_are_refused() {
    let w = w();
    let r = res();
    let c = Command::issue(&w.alice_phone, &w.log, flag(&w.key, &r, b"x"), T, 60_000).unwrap();
    assert_eq!(
        c.check(&w.log, &r, &w.key, T.plus_ms(60_001)).unwrap_err(),
        CommandError::Expired
    );
    assert_eq!(
        c.check(&w.log, &r, &Key::generate().unwrap(), T)
            .unwrap_err(),
        CommandError::Sealed
    );

    let mut tampered = c.clone();
    tampered.body.class = "send".into();
    assert_eq!(
        tampered.check(&w.log, &r, &w.key, T).unwrap_err(),
        CommandError::BadSignature
    );
    assert_eq!(
        Command::decode(&tampered.encode()).unwrap_err(),
        CommandError::BadSignature
    );
    let mut moved = c.clone();
    moved.body.issuer = w.alice.public();
    assert_eq!(
        moved.check(&w.log, &r, &w.key, T).unwrap_err(),
        CommandError::BadSignature
    );
}

#[test]
fn a_command_from_a_revoked_node_is_refused_after_the_revocation_is_known() {
    let w = w();
    let r = res();
    let c = Command::issue(&w.alice_phone, &w.log, flag(&w.key, &r, b"x"), T, 60_000).unwrap();
    let mut log = GroupLog::verify(w.log.entries().to_vec()).unwrap();
    log.append(
        &w.laptop,
        Op::RevokeNode {
            node: w.alice_phone.public(),
        },
        T,
    )
    .unwrap();
    assert_eq!(
        c.check(&log, &r, &w.key, T).unwrap_err(),
        CommandError::NotAuthorized,
        "a revoked node commands nothing"
    );
}

#[test]
fn heads_the_leaseholder_has_not_seen_or_that_forked_are_refused() {
    let mut w = w();
    let r = res();
    let behind = GroupLog::verify(w.log.entries()[..w.log.entries().len() - 1].to_vec()).unwrap();
    let c = Command::issue(&w.alice_phone, &w.log, flag(&w.key, &r, b"x"), T, 60_000).unwrap();
    assert_eq!(
        c.check(&behind, &r, &w.key, T).unwrap_err(),
        CommandError::CatchUp
    );
    let old = Command::issue(&w.alice_phone, &behind, flag(&w.key, &r, b"x"), T, 60_000).unwrap();
    assert!(
        old.check(&w.log, &r, &w.key, T).is_ok(),
        "a command made against an older head is checked against the newer log"
    );
    let mut forked =
        GroupLog::verify(w.log.entries()[..w.log.entries().len() - 1].to_vec()).unwrap();
    forked
        .append(
            &w.alice_phone,
            Op::CreateResource {
                resource: ResourceId::new("x").unwrap(),
            },
            T,
        )
        .unwrap();
    let f = Command::issue(&w.alice_phone, &forked, flag(&w.key, &r, b"x"), T, 60_000).unwrap();
    assert_eq!(
        f.check(&w.log, &r, &w.key, T).unwrap_err(),
        CommandError::Fork
    );
    w.log
        .append(
            &w.alice_phone,
            Op::CreateResource {
                resource: ResourceId::new("y").unwrap(),
            },
            T,
        )
        .unwrap();
    assert!(c.check(&w.log, &r, &w.key, T).is_ok());
}

#[test]
fn results_must_come_from_a_node_that_may_lead_and_answer_this_command() {
    let w = w();
    let r = res();
    let c = Command::issue(&w.alice_phone, &w.log, flag(&w.key, &r, b"x"), T, 60_000).unwrap();
    let checked = c.check(&w.log, &r, &w.key, T).unwrap();
    let forged =
        CommandResult::sign(&w.alice_phone, &checked, &w.key, &Outcome::Applied, T).unwrap();
    assert_eq!(
        forged.check(&c, &w.log, &w.key, T).unwrap_err(),
        CommandError::NotAuthorized,
        "a reader cannot fake a result"
    );
    let other = Command::issue(&w.alice_phone, &w.log, flag(&w.key, &r, b"y"), T, 60_000).unwrap();
    let real = CommandResult::sign(&w.server, &checked, &w.key, &Outcome::Applied, T).unwrap();
    assert!(matches!(
        real.check(&other, &w.log, &w.key, T),
        Err(CommandError::Invalid(_))
    ));
    assert_eq!(
        real.check(&c, &w.log, &Key::generate().unwrap(), T)
            .unwrap_err(),
        CommandError::Sealed
    );
}

#[test]
fn arguments_are_bounded() {
    let w = w();
    let r = res();
    for class in ["", "Send", "a b", &"x".repeat(33)] {
        assert!(matches!(
            Command::issue(
                &w.alice_phone,
                &w.log,
                Request {
                    class,
                    ..flag(&w.key, &r, b"")
                },
                T,
                1
            ),
            Err(CommandError::Invalid(_))
        ));
    }
    let long = "k".repeat(MAX_IDEMPOTENCY_KEY + 1);
    assert!(
        Command::issue(
            &w.alice_phone,
            &w.log,
            Request {
                idempotency_key: &long,
                ..flag(&w.key, &r, b"")
            },
            T,
            1
        )
        .is_err()
    );
    assert!(
        Command::issue(
            &w.alice_phone,
            &w.log,
            Request {
                idempotency_key: "",
                ..flag(&w.key, &r, b"")
            },
            T,
            1
        )
        .is_err()
    );
    let big = vec![0u8; MAX_ENCODED];
    assert!(Command::issue(&w.alice_phone, &w.log, flag(&w.key, &r, &big), T, 1).is_err());
    let c = Command::issue(&w.alice_phone, &w.log, flag(&w.key, &r, b"x"), T, 1).unwrap();
    let mut bytes = c.encode();
    bytes.push(0);
    assert_eq!(
        Command::decode(&bytes).unwrap_err(),
        CommandError::Malformed
    );
    assert_eq!(
        Command::decode(&vec![0; MAX_ENCODED + 1]).unwrap_err(),
        CommandError::Malformed
    );
}

#[tokio::test]
async fn the_bus_carries_commands_and_results_and_drops_garbage() {
    let w = w();
    let r = res();
    let roster = baton_identity::Roster::genesis(&w.alice_phone, GroupId::new("g").unwrap())
        .with_member(&w.alice_phone, w.server.public())
        .unwrap();
    let hub = MemoryHub::new();
    let phone = Arc::new(hub.join(
        w.alice_phone.clone(),
        RosterHandle::new(roster.clone()).unwrap(),
    ));
    let server = Arc::new(hub.join(w.server.clone(), RosterHandle::new(roster).unwrap()));
    let mut incoming = bus::commands(&*server).await.unwrap();
    let mut answers = bus::results(&*phone).await.unwrap();
    phone
        .send(
            &w.server.node_id(),
            bus::COMMANDS,
            Bytes::from_static(b"garbage"),
        )
        .await
        .unwrap();
    let c = Command::issue(&w.alice_phone, &w.log, flag(&w.key, &r, b"x"), T, 60_000).unwrap();
    bus::send_command(&*phone, &w.server.node_id(), &c)
        .await
        .unwrap();
    let (from, got) = tokio::time::timeout(Duration::from_secs(2), incoming.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(from, w.alice_phone.node_id());
    let checked = got.check(&w.log, &r, &w.key, T).unwrap();
    let res = CommandResult::sign(&w.server, &checked, &w.key, &Outcome::Applied, T).unwrap();
    bus::send_result(&*server, &w.alice_phone.node_id(), &res)
        .await
        .unwrap();
    let (_, back) = tokio::time::timeout(Duration::from_secs(2), answers.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(back.check(&c, &w.log, &w.key, T).unwrap(), Outcome::Applied);
}

use bytes::Bytes;

proptest::proptest! {
    #[test]
    fn arbitrary_bytes_never_decode(raw in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..800)) {
        proptest::prop_assert!(Command::decode(&raw).is_err());
        proptest::prop_assert!(CommandResult::decode(&raw).is_err());
    }
}

/// Regression tests for the first adversarial review of this crate.
mod review {
    use super::*;

    fn resign(w: &W, mut c: Command, edit: impl FnOnce(&mut CommandBody)) -> Command {
        edit(&mut c.body);
        let bytes = postcard::to_stdvec(&c.body).unwrap();
        c.signature = w.alice_phone.sign(COMMAND_CONTEXT, &bytes);
        c
    }

    #[test]
    fn the_payload_is_bound_to_its_resource_class_and_body() {
        let mut w = w();
        let r = res();
        let other = ResourceId::new("other").unwrap();
        w.log
            .append(
                &w.laptop,
                Op::CreateResource {
                    resource: other.clone(),
                },
                T,
            )
            .unwrap();
        let send: BTreeSet<_> = [Capability::Read, Capability::Command("send".into())]
            .into_iter()
            .collect();
        w.log
            .append(
                &w.laptop,
                Op::Grant {
                    resource: other.clone(),
                    principal: Principal::Member(w.alice.public()),
                    capabilities: send,
                },
                T,
            )
            .unwrap();
        let (op, other_keys) = epochs::new_epoch(w.log.state(), &other, T).unwrap();
        w.log.append(&w.laptop, op, T).unwrap();
        let c = Command::issue(&w.alice_phone, &w.log, flag(&w.key, &r, b"x"), T, 60_000).unwrap();
        let moved = resign(&w, c.clone(), |b| {
            b.resource = other.clone();
            b.class = "send".into();
        });
        assert_eq!(
            moved.check(&w.log, &other, &w.key, T).unwrap_err(),
            CommandError::Sealed,
            "a payload sealed for an inbox flag never opens as a send on another resource"
        );
        assert_eq!(
            moved
                .check(&w.log, &other, &other_keys.data, T)
                .unwrap_err(),
            CommandError::Sealed
        );
        let reclassed = resign(&w, c.clone(), |b| b.class = "send".into());
        assert!(reclassed.check(&w.log, &r, &w.key, T).is_err());
        let rebound = resign(&w, c.clone(), |b| b.epoch = 1);
        assert!(
            rebound.check(&w.log, &r, &w.key, T).is_ok(),
            "the same binding still opens"
        );
        assert_eq!(
            c.check(&w.log, &other, &w.key, T).unwrap_err(),
            CommandError::WrongGroup,
            "a leaseholder of another resource refuses it"
        );
    }

    #[test]
    fn signed_but_out_of_bounds_commands_are_refused() {
        let w = w();
        let r = res();
        let c = Command::issue(&w.alice_phone, &w.log, flag(&w.key, &r, b"x"), T, 60_000).unwrap();
        let forever = resign(&w, c.clone(), |b| b.expires_at = Timestamp(i64::MAX));
        assert_eq!(
            forever.check(&w.log, &r, &w.key, T).unwrap_err(),
            CommandError::Expired
        );
        let future = resign(&w, c.clone(), |b| {
            b.issued_at = T.plus_ms(MAX_SKEW_MS + 1);
            b.expires_at = T.plus_ms(MAX_SKEW_MS + 2);
        });
        assert_eq!(
            future.check(&w.log, &r, &w.key, T).unwrap_err(),
            CommandError::Expired
        );
        let backwards = resign(&w, c.clone(), |b| b.expires_at = Timestamp(T.0 - 1));
        assert_eq!(
            backwards.check(&w.log, &r, &w.key, T).unwrap_err(),
            CommandError::Expired
        );
        let no_epoch = resign(&w, c.clone(), |b| b.epoch = 999);
        assert!(matches!(
            no_epoch.check(&w.log, &r, &w.key, T),
            Err(CommandError::Invalid(_))
        ));
        let bad_class = resign(&w, c.clone(), |b| b.class = "Bad Class".into());
        assert!(matches!(
            bad_class.check(&w.log, &r, &w.key, T),
            Err(CommandError::Invalid(_))
        ));
        let mut empty_key = c.clone();
        let inner = postcard::to_stdvec(&Inner {
            idempotency_key: String::new(),
            payload: b"x".to_vec(),
        })
        .unwrap();
        empty_key.body.payload = baton_seal::seal(
            &w.key,
            Context::new(COMMAND_CONTEXT, &empty_key.body.binding()),
            &inner,
        )
        .unwrap();
        let empty_key = resign(&w, empty_key, |_| {});
        assert!(matches!(
            empty_key.check(&w.log, &r, &w.key, T),
            Err(CommandError::Invalid(_))
        ));
        assert!(
            Command::issue(
                &w.alice_phone,
                &w.log,
                flag(&w.key, &r, b"x"),
                T,
                MAX_TTL_MS + 1
            )
            .is_err()
        );
        assert!(Command::issue(&w.alice_phone, &w.log, flag(&w.key, &r, b"x"), T, 0).is_err());
    }

    #[test]
    fn the_idempotency_key_is_sealed() {
        let w = w();
        let r = res();
        let c = Command::issue(
            &w.alice_phone,
            &w.log,
            Request {
                idempotency_key: "very-secret-key",
                ..flag(&w.key, &r, b"x")
            },
            T,
            60_000,
        )
        .unwrap();
        let wire = c.encode();
        assert!(!wire.windows(15).any(|win| win == b"very-secret-key"));
        assert_eq!(
            c.check(&w.log, &r, &w.key, T).unwrap().idempotency_key,
            "very-secret-key"
        );
    }

    #[test]
    fn results_from_a_lead_whose_certificate_expired_are_refused() {
        let w = w();
        let r = res();
        let c = Command::issue(&w.alice_phone, &w.log, flag(&w.key, &r, b"x"), T, 60_000).unwrap();
        let checked = c.check(&w.log, &r, &w.key, T).unwrap();
        let old = CommandResult::sign(&w.server, &checked, &w.key, &Outcome::Applied, T).unwrap();
        assert!(old.check(&c, &w.log, &w.key, T).is_ok());
        assert_eq!(
            old.check(&c, &w.log, &w.key, LATER.plus_ms(1)).unwrap_err(),
            CommandError::NotAuthorized
        );
        let ahead = CommandResult::sign(
            &w.server,
            &checked,
            &w.key,
            &Outcome::Applied,
            T.plus_ms(MAX_SKEW_MS + 1),
        )
        .unwrap();
        assert_eq!(
            ahead.check(&c, &w.log, &w.key, T).unwrap_err(),
            CommandError::Expired
        );
    }
}
