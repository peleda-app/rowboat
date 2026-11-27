use baton_group::GroupLog;

use super::*;
use crate::fixtures::{Clock, T0, found, group, keys, store};
use crate::{DAY_MS, account_resource};

const CLASSES: &[&str] = &["mail-flags", "mail-send"];

fn res() -> ResourceId {
    account_resource(&format!("a{}", "b".repeat(26))).unwrap()
}

async fn add_device(
    m: &Membership,
    member: &Identity,
    class: NodeClass,
    clock: &Clock,
) -> (NodeKeys, Vec<Entry>) {
    let k = keys(Some(member));
    let expires = Timestamp(clock.now()().0 + 400 * DAY_MS);
    let proof = NodeCert::node_proof(
        &k.identity,
        &k.kem.public(),
        class,
        &member.public(),
        expires,
    );
    let cert = NodeCert::assemble(
        member,
        k.identity.public(),
        k.kem.public(),
        class,
        expires,
        proof,
    )
    .unwrap();
    let entries = m.certify(cert).await.unwrap();
    (k, entries)
}

async fn view_of(m: &Membership, k: NodeKeys, clock: &Clock) -> Membership {
    Membership::adopt(store(), m.log(), k, Vec::new(), clock.now())
        .await
        .unwrap()
}

#[tokio::test]
async fn found_open_and_refuse_strangers() {
    let clock = Clock::new();
    let (m, member, st) = found(&clock).await;
    assert!(m.can_certify());
    assert_eq!(m.role(), Some(Role::Owner));
    let again = Membership::open(
        st.clone(),
        group(),
        NodeKeys {
            identity: m.keys().identity.clone(),
            kem: KemSecret::from_bytes(m.keys().kem.expose()).unwrap(),
            member: Some(member.clone()),
        },
        clock.now(),
    )
    .await
    .unwrap();
    assert_eq!(again.head(), m.head());
    assert!(matches!(
        Membership::open(store(), group(), keys(None), clock.now()).await,
        Err(MembershipError::NotFound)
    ));
    assert!(matches!(
        Membership::open(st, group(), keys(None), clock.now()).await,
        Err(MembershipError::Unverified)
    ));
}

#[tokio::test]
async fn resources_are_created_once_with_every_class() {
    let clock = Clock::new();
    let (m, _, _) = found(&clock).await;
    m.ensure_resource(&res(), CLASSES).await.unwrap();
    let head = m.head();
    m.ensure_resource(&res(), CLASSES).await.unwrap();
    assert_eq!(m.head(), head, "a second call appends nothing");
    for cap in [
        Capability::Read,
        Capability::Lead,
        Capability::Command("mail-send".into()),
    ] {
        assert!(m.may(&res(), &cap));
    }
    assert!(!m.may(&res(), &Capability::Command("mail-delete".into())));
    assert!(m.resource_keys(&res(), 1).unwrap().secret.is_some());
}

#[tokio::test]
async fn a_certified_device_gets_the_epochs_and_counts() {
    let clock = Clock::new();
    let (m, member, _) = found(&clock).await;
    m.ensure_resource(&res(), CLASSES).await.unwrap();
    let (phone, entries) = add_device(&m, &member, NodeClass::Phone, &clock).await;
    assert!(entries.len() >= 2, "a certificate and a shared epoch");
    let phone_key = phone.identity.public();
    assert!(m.counts(&phone_key));
    assert!(m.trust().allows(&phone_key));
    assert!(
        !m.trust().allows(&m.node()),
        "a node never trusts itself as a peer"
    );
    let nodes = m.nodes();
    assert_eq!(nodes.len(), 2);
    assert!(nodes.iter().all(|n| n.counts && !n.revoked));
    let view = view_of(&m, phone, &clock).await;
    let keys = view.resource_keys(&res(), 1).unwrap();
    assert_eq!(
        keys.data.expose(),
        m.resource_keys(&res(), 1).unwrap().data.expose()
    );
    assert!(view.may(&res(), &Capability::Command("mail-flags".into())));
    assert_eq!(m.resources(), vec![res()]);
    assert!(m.node_may(&phone_key, &res(), &Capability::Lead));
    assert!(view.node_may(&m.node(), &res(), &Capability::Read));
    let stranger = crate::fixtures::keys(None).identity.public();
    assert!(!m.node_may(&stranger, &res(), &Capability::Read));
    assert!(m.was_certified(&phone_key) && !m.was_certified(&stranger));
    m.revoke(&phone_key).await.unwrap();
    assert!(
        m.was_certified(&phone_key),
        "a revoked node stays in the history"
    );
    assert!(!m.node_may(&phone_key, &res(), &Capability::Read));
}

#[tokio::test]
async fn revocation_rotates_and_locks_the_node_out() {
    let clock = Clock::new();
    let (m, member, _) = found(&clock).await;
    m.ensure_resource(&res(), CLASSES).await.unwrap();
    let (phone, _) = add_device(&m, &member, NodeClass::Phone, &clock).await;
    let phone_key = phone.identity.public();
    let phone_kem = KemSecret::from_bytes(phone.kem.expose()).unwrap();
    let view = view_of(&m, phone, &clock).await;
    let mut events = view.subscribe();

    assert_eq!(
        m.revoke(&m.node()).await.unwrap_err(),
        MembershipError::Invalid
    );
    assert_eq!(
        m.revoke(&Identity::generate().public()).await.unwrap_err(),
        MembershipError::NotFound
    );
    let r = m.revoke(&phone_key).await.unwrap();
    assert_eq!(r.secrets_rotation_required, vec![res()]);
    assert_eq!(r.rotated, vec![res()]);
    assert_eq!(
        m.revoke(&phone_key).await.unwrap_err(),
        MembershipError::Invalid
    );
    assert!(!m.trust().allows(&phone_key));
    assert!(
        m.nodes()
            .iter()
            .any(|n| n.node == phone_key && n.revoked && !n.counts)
    );

    let log = m.log();
    assert!(
        epochs::open(&log, &res(), 2, &Recipient::Node(phone_key), &phone_kem).is_err(),
        "the revoked node cannot open the new epoch"
    );
    let new = view.apply_remote(log.entries().to_vec()).await.unwrap();
    assert!(new > 0);
    assert!(view.is_revoked());
    assert!(
        !view.may(&res(), &Capability::Read),
        "a revoked node may nothing"
    );
    let mut saw = false;
    while let Ok(e) = events.try_recv() {
        saw |= e == MembershipEvent::Revoked;
    }
    assert!(saw, "the revocation hook fires");
}

#[tokio::test]
async fn forged_entries_change_nothing() {
    let clock = Clock::new();
    let (m, member, _) = found(&clock).await;
    let (phone, _) = add_device(&m, &member, NodeClass::Phone, &clock).await;
    let view = Arc::new(view_of(&m, phone, &clock).await);
    let head = view.head();

    let stranger = Identity::generate();
    let mut other = m.log();
    let forged = other.append(&m.keys().identity, Op::Checkpoint, clock.now()());
    assert!(forged.is_err(), "only the recovery key signs checkpoints");

    let (outsider, _, _) = found(&clock).await;
    let foreign = outsider.log().entries().to_vec();
    assert_eq!(
        view.apply_remote(foreign).await.unwrap_err(),
        MembershipError::Fork,
        "a log of another group"
    );

    let mut rogue = m.log();
    let fake = keys(Some(&stranger));
    let cert = NodeCert::new(
        &stranger,
        &fake.identity,
        fake.kem.public(),
        NodeClass::Desktop,
        Timestamp(T0 + DAY_MS),
    );
    assert!(
        rogue
            .append(
                &fake.identity,
                Op::CertifyNode { cert: cert.clone() },
                clock.now()()
            )
            .is_err(),
        "a stranger cannot certify itself"
    );
    assert!(
        rogue
            .append(&m.keys().identity, Op::CertifyNode { cert }, clock.now()())
            .is_err(),
        "a node of this group cannot certify a stranger's member key"
    );
    assert_eq!(view.head(), head);
}

#[tokio::test]
async fn the_log_never_moves_back_or_forks() {
    let clock = Clock::new();
    let (m, member, _) = found(&clock).await;
    let genesis_only = m.log().entries().to_vec();
    let (phone, _) = add_device(&m, &member, NodeClass::Phone, &clock).await;
    let view = view_of(&m, phone, &clock).await;
    let head = view.head();

    assert_eq!(
        view.apply_remote(genesis_only).await.unwrap(),
        0,
        "a shorter log is a no-op"
    );
    assert_eq!(view.head(), head);

    let mut fork = GroupLog::verify(m.log().entries()[..1].to_vec()).unwrap();
    fork.append(
        &m.keys().identity,
        Op::CreateResource { resource: res() },
        clock.now()(),
    )
    .unwrap();
    assert_eq!(
        view.apply_remote(fork.entries().to_vec())
            .await
            .unwrap_err(),
        MembershipError::Fork
    );
    assert_eq!(view.head(), head);

    let mut ahead = m.log();
    ahead
        .append(
            &m.keys().identity,
            Op::CreateResource { resource: res() },
            Timestamp(clock.now()().0 + MAX_SKEW_MS + 1),
        )
        .unwrap();
    assert!(
        view.apply_remote(ahead.entries().to_vec()).await.is_err(),
        "an entry dated past the skew"
    );
    assert_eq!(view.head(), head);
}

#[tokio::test]
async fn expiry_and_renewal() {
    let clock = Clock::new();
    let (m, member, _) = found(&clock).await;
    m.ensure_resource(&res(), CLASSES).await.unwrap();
    assert!(!m.renew_if_due(400 * DAY_MS, 30 * DAY_MS).await.unwrap());
    clock.advance(371 * DAY_MS);
    assert!(m.renew_if_due(400 * DAY_MS, 30 * DAY_MS).await.unwrap());
    clock.advance(100 * DAY_MS);
    assert!(
        m.may(&res(), &Capability::Read),
        "renewed past the first term"
    );

    let (phone, _) = add_device(&m, &member, NodeClass::Phone, &clock).await;
    let phone_key = phone.identity.public();
    let headless = NodeKeys {
        identity: phone.identity.clone(),
        kem: KemSecret::from_bytes(phone.kem.expose()).unwrap(),
        member: None,
    };
    let view = view_of(&m, headless, &clock).await;
    clock.advance(390 * DAY_MS);
    assert_eq!(
        view.renew_if_due(400 * DAY_MS, 30 * DAY_MS)
            .await
            .unwrap_err(),
        MembershipError::NotAuthorized,
        "renewal needs the member key"
    );
    clock.advance(20 * DAY_MS);
    assert!(!m.counts(&phone_key), "an expired node stops counting");
    assert!(!m.trust().allows(&phone_key));
    assert!(!view.may(&res(), &Capability::Read));
}

#[tokio::test]
async fn peers_are_remembered_only_for_certified_nodes() {
    let clock = Clock::new();
    let (m, member, st) = found(&clock).await;
    let (phone, _) = add_device(&m, &member, NodeClass::Phone, &clock).await;
    let record = PeerRecord {
        hint: WireHint {
            direct: vec!["127.0.0.1:7".parse().unwrap()],
            relay: None,
        },
        label: Some("Pixel\u{7}\nphone".into()),
    };
    m.remember_peer(&phone.identity.public(), record.clone())
        .await
        .unwrap();
    m.remember_peer(&Identity::generate().public(), record.clone())
        .await
        .unwrap();
    assert_eq!(m.peers().len(), 1);
    assert_eq!(
        m.peer(&phone.identity.public()).unwrap().label.as_deref(),
        Some("Pixelphone")
    );
    let reopened = Membership::open(
        st,
        group(),
        NodeKeys {
            identity: m.keys().identity.clone(),
            kem: KemSecret::from_bytes(m.keys().kem.expose()).unwrap(),
            member: Some(member),
        },
        clock.now(),
    )
    .await
    .unwrap();
    assert_eq!(reopened.peers(), m.peers());
    assert_eq!(reopened.head(), m.head());
}

#[tokio::test]
async fn an_adopted_server_holds_only_what_it_was_granted_and_cannot_change_the_group() {
    let clock = Clock::new();
    let (m, member, _) = found(&clock).await;
    let acct = res();
    let other = account_resource(&format!("c{}", "d".repeat(26))).unwrap();
    m.ensure_resource(&acct, CLASSES).await.unwrap();
    m.ensure_resource(&other, CLASSES).await.unwrap();
    let (server, _) = add_device(&m, &member, NodeClass::Server, &clock).await;
    let sk = server.identity.public();
    let now = clock.now()();
    let st = m.log();
    for r in [&acct, &other] {
        for cap in [
            Capability::Read,
            Capability::Lead,
            Capability::Admin,
            Capability::Command("mail-send".into()),
        ] {
            assert!(!st.state().may(&sk, r, &cap, now), "{cap:?} on {r:?}");
        }
        assert!(epochs::open(&st, r, 1, &Recipient::Node(sk), &server.kem).is_err());
    }

    m.grant_server(&sk, std::slice::from_ref(&acct))
        .await
        .unwrap();
    let st = m.log();
    assert!(st.state().may(&sk, &acct, &Capability::Lead, now));
    assert!(st.state().may(&sk, &acct, &Capability::Read, now));
    assert!(!st.state().may(&sk, &acct, &Capability::Admin, now));
    assert!(
        !st.state()
            .may(&sk, &acct, &Capability::Command("mail-send".into()), now)
    );
    assert!(epochs::open(&st, &acct, 1, &Recipient::Node(sk), &server.kem).is_ok());
    assert!(!st.state().may(&sk, &other, &Capability::Read, now));
    assert!(epochs::open(&st, &other, 1, &Recipient::Node(sk), &server.kem).is_err());

    let desktop = m.node();
    let attacker = Identity::generate();
    let evil = Identity::generate();
    let at = Timestamp(now.0 + 1);
    let attempts = vec![
        Op::AddMember {
            member: attacker.public(),
            recovery: baton_keys::RecoveryRoot::generate().public(),
            role: Role::Owner,
        },
        Op::RevokeNode { node: desktop },
        Op::Grant {
            resource: other.clone(),
            principal: Principal::Node(sk),
            capabilities: [Capability::Read, Capability::Lead].into(),
        },
        Op::Grant {
            resource: acct.clone(),
            principal: Principal::Node(sk),
            capabilities: [Capability::Read, Capability::Lead, Capability::Admin].into(),
        },
        Op::RemoveMember {
            member: member.public(),
        },
        Op::CreateResource {
            resource: account_resource(&format!("e{}", "f".repeat(26))).unwrap(),
        },
        Op::CertifyNode {
            cert: NodeCert::new(
                &member,
                &evil,
                KemSecret::generate().public(),
                NodeClass::Desktop,
                Timestamp(now.0 + DAY_MS),
            ),
        },
    ];
    for op in attempts {
        let mut forged = m.log();
        let label = format!("{op:?}");
        assert!(forged.append(&server.identity, op, at).is_err(), "{label}");
    }
    let head = m.head();
    let mut forged = m.log();
    if forged
        .append(&server.identity, Op::RevokeNode { node: desktop }, at)
        .is_ok()
    {
        let tail = forged.entries()[head.0 as usize + 1..].to_vec();
        assert!(m.apply_remote(tail).await.is_err());
    }
    assert_eq!(m.head(), head);
    assert!(m.counts(&desktop));
}

#[tokio::test]
async fn a_server_revokes_only_itself() {
    let clock = Clock::new();
    let (m, member, _) = found(&clock).await;
    let (server, _) = add_device(&m, &member, NodeClass::Server, &clock).await;
    let (phone, _) = add_device(&m, &member, NodeClass::Phone, &clock).await;
    let at = Timestamp(clock.now()().0 + 1);
    let mut log = m.log();
    assert!(
        log.append(
            &server.identity,
            Op::RevokeNode {
                node: phone.identity.public()
            },
            at
        )
        .is_err()
    );
    let mut log = m.log();
    log.append(
        &server.identity,
        Op::RevokeNode {
            node: server.identity.public(),
        },
        at,
    )
    .unwrap();
}
