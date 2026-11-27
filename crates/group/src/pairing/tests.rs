use std::sync::Mutex as StdMutex;

use baton_keys::KemSecret;
use rowboat_endpoint_iroh::IrohEndpoints;
use rowboat_endpoint_memory::MemoryEndpoints;
use tokio::task::JoinHandle;

use super::*;
use crate::NodeKeys;
use crate::fixtures::{Answer, Clock, Recorder, found, keys};

type Served = Vec<Result<(u64, Outcome), MembershipError>>;

/// Long enough that no step of a correct run ever reaches it, however loaded the machine.
const HANG: Duration = Duration::from_secs(300);

fn limits() -> Limits {
    Limits {
        step: HANG,
        handshake: HANG,
        confirm: HANG,
        fail_delay: Duration::ZERO,
        ..Limits::default()
    }
}

fn certifier(m: &Arc<Membership>, confirm: Arc<dyn Confirm>) -> Arc<Certifier> {
    Arc::new(Certifier {
        membership: m.clone(),
        confirm,
        hint: WireHint::default(),
        server_grants: Vec::new(),
    })
}

async fn host_device(
    endpoints: Arc<dyn Endpoints>,
    inviter: Arc<Inviter>,
    cert: Arc<Certifier>,
    streams: usize,
) -> (Issued, JoinHandle<Served>) {
    let ep = PairingEndpoint::open(&*endpoints).await.unwrap();
    let m = &cert.membership;
    let issued = inviter
        .issue(
            InviteKind::Device,
            Some(m.group().clone()),
            Some(m.node()),
            ep.key(),
            ep.hint().clone(),
        )
        .unwrap();
    let task = tokio::spawn(async move {
        let mut out = Vec::new();
        for _ in 0..streams {
            let inc = ep.next().await.unwrap();
            out.push(
                inviter
                    .serve(inc.stream, inc.peer, ep.key(), Side::Certifier(&cert))
                    .await,
            );
        }
        ep.close().await;
        out
    });
    (issued, task)
}

struct Server {
    keys: NodeKeys,
    bound: Option<[u8; 32]>,
}

async fn host_server(
    endpoints: Arc<dyn Endpoints>,
    inviter: Arc<Inviter>,
    server: Server,
    streams: usize,
) -> (Issued, JoinHandle<Served>) {
    let ep = PairingEndpoint::open(&*endpoints).await.unwrap();
    let issued = inviter
        .issue(InviteKind::Server, None, None, ep.key(), ep.hint().clone())
        .unwrap();
    let task = tokio::spawn(async move {
        let cand = Candidate {
            identity: &server.keys.identity,
            kem: &server.keys.kem,
            class: NodeClass::Server,
            label: "server".into(),
            hint: WireHint::default(),
            bound: server.bound,
            confirm: Arc::new(Answer(true)),
        };
        let mut out = Vec::new();
        for _ in 0..streams {
            let inc = ep.next().await.unwrap();
            out.push(
                inviter
                    .serve(inc.stream, inc.peer, ep.key(), Side::Candidate(&cand))
                    .await,
            );
        }
        ep.close().await;
        out
    });
    (issued, task)
}

async fn join_as_device(
    endpoints: &dyn Endpoints,
    code: &PairingCode,
    k: &NodeKeys,
    class: NodeClass,
    confirm: Arc<dyn Confirm>,
) -> Result<Outcome, MembershipError> {
    let cand = Candidate {
        identity: &k.identity,
        kem: &k.kem,
        class,
        label: "Laptop".into(),
        hint: WireHint::default(),
        bound: None,
        confirm,
    };
    join(endpoints, code, Side::Candidate(&cand), &limits()).await
}

fn joined(o: Outcome) -> Joined {
    match o {
        Outcome::Joined(j) => *j,
        Outcome::Certified(_) => panic!("expected to join"),
    }
}

fn certified(o: Outcome) -> Certified {
    match o {
        Outcome::Certified(c) => *c,
        Outcome::Joined(_) => panic!("expected to certify"),
    }
}

fn qr(issued: &Issued) -> PairingCode {
    PairingCode::Qr(Box::new(Invite::from_qr(&issued.invite.to_qr()).unwrap()))
}

fn copy_keys(k: &NodeKeys) -> NodeKeys {
    NodeKeys {
        identity: k.identity.clone(),
        kem: KemSecret::from_bytes(k.kem.expose()).unwrap(),
        member: k.member.clone(),
    }
}

async fn device_pairing(endpoints: Arc<dyn Endpoints>) {
    let clock = Clock::new();
    let (a, member, _) = found(&clock).await;
    let resource = crate::account_resource(&format!("a{}", "c".repeat(26))).unwrap();
    a.ensure_resource(&resource, &["mail-send"]).await.unwrap();
    let inviter = Arc::new(Inviter::new(limits(), clock.now()));
    let a_checks = Arc::new(Recorder(StdMutex::new(Vec::new()), true));
    let (issued, task) = host_device(
        endpoints.clone(),
        inviter.clone(),
        certifier(&a, a_checks.clone()),
        1,
    )
    .await;
    assert!(issued.short.is_none(), "device invites are QR only");
    let b = keys(None);
    let b_checks = Arc::new(Recorder(StdMutex::new(Vec::new()), true));
    let outcome = join_as_device(
        &*endpoints,
        &qr(&issued),
        &b,
        NodeClass::Phone,
        b_checks.clone(),
    )
    .await
    .unwrap();
    let j = joined(outcome);
    let served = task.await.unwrap();
    let c = certified(served.into_iter().next().unwrap().unwrap().1);
    assert_eq!(c.node, b.identity.public());
    assert_eq!(c.class, NodeClass::Phone);

    assert_eq!(j.member.as_ref().unwrap().public(), member.public());
    assert_eq!(j.certifier, a.node());
    assert_eq!(j.log.genesis_hash(), a.genesis_hash());
    assert_eq!(j.log.head_hash(), a.head().1);
    assert!(a.counts(&b.identity.public()));
    assert!(
        !inviter.is_pending(issued.invite.id),
        "the invite is used up"
    );

    let fa = a_checks.0.lock().unwrap()[0].fingerprint.clone();
    let fb = b_checks.0.lock().unwrap()[0].fingerprint.clone();
    assert_eq!(fa, fb, "both screens show the same fingerprint");
    assert_eq!(fa.len(), 7);
    assert_eq!(
        a_checks.0.lock().unwrap()[0].label.as_deref(),
        Some("Laptop")
    );

    let view = Membership::adopt(
        crate::fixtures::store(),
        j.log,
        NodeKeys {
            identity: b.identity.clone(),
            kem: KemSecret::from_bytes(b.kem.expose()).unwrap(),
            member: j.member,
        },
        j.peers,
        clock.now(),
    )
    .await
    .unwrap();
    assert!(
        view.can_certify(),
        "a phone holds the member key and may invite"
    );
    assert!(view.resource_keys(&resource, 1).unwrap().secret.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_pairs_by_qr_in_memory() {
    device_pairing(Arc::new(MemoryEndpoints::new())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_pairs_by_qr_over_iroh_on_loopback() {
    device_pairing(Arc::new(IrohEndpoints::loopback())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_paired_device_invites_a_third() {
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let clock = Clock::new();
    let (a, _, _) = found(&clock).await;
    let inviter = Arc::new(Inviter::new(limits(), clock.now()));
    let (issued, task) = host_device(
        endpoints.clone(),
        inviter.clone(),
        certifier(&a, Arc::new(Answer(true))),
        1,
    )
    .await;
    let b = keys(None);
    let j = joined(
        join_as_device(
            &*endpoints,
            &qr(&issued),
            &b,
            NodeClass::Desktop,
            Arc::new(Answer(true)),
        )
        .await
        .unwrap(),
    );
    task.await.unwrap();
    let b_view = Arc::new(
        Membership::adopt(
            crate::fixtures::store(),
            j.log,
            NodeKeys {
                identity: b.identity.clone(),
                kem: KemSecret::from_bytes(b.kem.expose()).unwrap(),
                member: j.member,
            },
            j.peers,
            clock.now(),
        )
        .await
        .unwrap(),
    );
    let b_inviter = Arc::new(Inviter::new(limits(), clock.now()));
    let (issued, task) = host_device(
        endpoints.clone(),
        b_inviter,
        certifier(&b_view, Arc::new(Answer(true))),
        1,
    )
    .await;
    let c = keys(None);
    let j = joined(
        join_as_device(
            &*endpoints,
            &qr(&issued),
            &c,
            NodeClass::Phone,
            Arc::new(Answer(true)),
        )
        .await
        .unwrap(),
    );
    task.await.unwrap();
    assert_eq!(j.certifier, b.identity.public());
    let state = j.log.state();
    let at = state.last_at();
    for k in [a.node(), b.identity.public(), c.identity.public()] {
        assert!(state.node(&k, at).is_some());
    }
    assert!(
        j.peers.iter().any(|(k, _)| k == &b.identity.public()),
        "the third node learns where its certifier is"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_secret_fails_and_kills_a_qr_invite() {
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let clock = Clock::new();
    let (a, _, _) = found(&clock).await;
    let inviter = Arc::new(Inviter::new(limits(), clock.now()));
    let (issued, task) = host_device(
        endpoints.clone(),
        inviter.clone(),
        certifier(&a, Arc::new(Answer(true))),
        2,
    )
    .await;
    let i = &issued.invite;
    let guessed = Invite::new(
        i.kind,
        i.group.clone(),
        i.inviter,
        i.id,
        [0x55; 16],
        i.endpoint,
        i.hint.clone(),
        i.expires_at,
    );
    let b = keys(None);
    let r = join_as_device(
        &*endpoints,
        &PairingCode::Qr(Box::new(guessed)),
        &b,
        NodeClass::Phone,
        Arc::new(Answer(true)),
    )
    .await;
    assert_eq!(r.unwrap_err(), MembershipError::WrongCode);
    let r = join_as_device(
        &*endpoints,
        &qr(&issued),
        &b,
        NodeClass::Phone,
        Arc::new(Answer(true)),
    )
    .await;
    assert_eq!(
        r.unwrap_err(),
        MembershipError::WrongCode,
        "the first failure killed the QR invite"
    );
    let served = task.await.unwrap();
    assert!(served.iter().all(|r| r.is_err()));
    assert_eq!(a.nodes().len(), 1, "nobody joined");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_used_and_unknown_invites_look_alike() {
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let clock = Clock::new();
    let (a, _, _) = found(&clock).await;
    let inviter = Arc::new(Inviter::new(limits(), clock.now()));
    let (issued, task) = host_device(
        endpoints.clone(),
        inviter.clone(),
        certifier(&a, Arc::new(Answer(true))),
        4,
    )
    .await;
    let i = &issued.invite;
    let unknown = Invite::new(
        i.kind,
        i.group.clone(),
        i.inviter,
        i.id ^ 1,
        *i.secret(),
        i.endpoint,
        i.hint.clone(),
        i.expires_at,
    );
    let b = keys(None);
    let r = join_as_device(
        &*endpoints,
        &PairingCode::Qr(Box::new(unknown)),
        &b,
        NodeClass::Phone,
        Arc::new(Answer(true)),
    )
    .await;
    assert_eq!(r.unwrap_err(), MembershipError::WrongCode);
    assert!(
        inviter.is_pending(i.id),
        "an attempt on another id costs this invite nothing"
    );

    join_as_device(
        &*endpoints,
        &qr(&issued),
        &b,
        NodeClass::Phone,
        Arc::new(Answer(true)),
    )
    .await
    .unwrap();
    let c = keys(None);
    let replayed = join_as_device(
        &*endpoints,
        &qr(&issued),
        &c,
        NodeClass::Phone,
        Arc::new(Answer(true)),
    )
    .await;
    assert_eq!(
        replayed.unwrap_err(),
        MembershipError::WrongCode,
        "a used invite"
    );

    let inviter2 = Arc::new(Inviter::new(limits(), clock.now()));
    let (issued2, task2) = host_device(
        endpoints.clone(),
        inviter2.clone(),
        certifier(&a, Arc::new(Answer(true))),
        1,
    )
    .await;
    clock.advance(limits().ttl_ms + 1);
    let expired = join_as_device(
        &*endpoints,
        &qr(&issued2),
        &c,
        NodeClass::Phone,
        Arc::new(Answer(true)),
    )
    .await;
    assert_eq!(
        expired.unwrap_err(),
        MembershipError::WrongCode,
        "an expired invite"
    );
    assert!(!inviter2.is_pending(issued2.invite.id));
    task2.await.unwrap();
    task.abort();
    assert!(!a.counts(&c.identity.public()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejected_fingerprint_adds_nobody() {
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let clock = Clock::new();
    let (a, _, _) = found(&clock).await;
    let head = a.head();
    let inviter = Arc::new(Inviter::new(limits(), clock.now()));
    let (issued, task) = host_device(
        endpoints.clone(),
        inviter.clone(),
        certifier(&a, Arc::new(Answer(false))),
        1,
    )
    .await;
    let b = keys(None);
    let r = join_as_device(
        &*endpoints,
        &qr(&issued),
        &b,
        NodeClass::Phone,
        Arc::new(Answer(true)),
    )
    .await;
    assert_eq!(r.unwrap_err(), MembershipError::Refused);
    assert!(matches!(
        task.await.unwrap()[0],
        Err(MembershipError::Rejected)
    ));
    assert_eq!(a.head(), head);
    assert!(!inviter.is_pending(issued.invite.id));

    let inviter = Arc::new(Inviter::new(limits(), clock.now()));
    let (issued, task) = host_device(
        endpoints.clone(),
        inviter,
        certifier(&a, Arc::new(Answer(true))),
        1,
    )
    .await;
    let r = join_as_device(
        &*endpoints,
        &qr(&issued),
        &b,
        NodeClass::Phone,
        Arc::new(Answer(false)),
    )
    .await;
    assert_eq!(
        r.unwrap_err(),
        MembershipError::Rejected,
        "the joiner may say no too"
    );
    assert!(task.await.unwrap()[0].is_err());
    assert_eq!(a.head(), head);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_joiner_claiming_the_wrong_class_is_refused() {
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let clock = Clock::new();
    let (a, _, _) = found(&clock).await;
    let head = a.head();
    let inviter = Arc::new(Inviter::new(limits(), clock.now()));
    let (issued, task) = host_device(
        endpoints.clone(),
        inviter,
        certifier(&a, Arc::new(Answer(true))),
        1,
    )
    .await;
    let b = keys(None);
    let r = join_as_device(
        &*endpoints,
        &qr(&issued),
        &b,
        NodeClass::Server,
        Arc::new(Answer(true)),
    )
    .await;
    assert_eq!(r.unwrap_err(), MembershipError::Refused);
    assert!(matches!(
        task.await.unwrap()[0],
        Err(MembershipError::Invalid)
    ));
    assert_eq!(a.head(), head);

    let inviter = Arc::new(Inviter::new(limits(), clock.now()));
    let server = Server {
        keys: keys(None),
        bound: None,
    };
    let (issued, task) = host_server(endpoints.clone(), inviter, server, 1).await;
    let cert = certifier(&a, Arc::new(Answer(true)));
    let r = join(&*endpoints, &qr(&issued), Side::Certifier(&cert), &limits()).await;
    assert!(r.is_ok(), "a server adopted by QR");
    task.await.unwrap();

    let b2 = keys(None);
    assert_eq!(
        join_as_device(
            &*endpoints,
            &qr(&issued),
            &b2,
            NodeClass::Desktop,
            Arc::new(Answer(true))
        )
        .await
        .unwrap_err(),
        MembershipError::Invalid,
        "a server invite is not joined as a device"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_is_adopted_by_short_code_with_three_attempts() {
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let clock = Clock::new();
    let (a, _, _) = found(&clock).await;
    let inviter = Arc::new(Inviter::new(limits(), clock.now()));
    let server_keys = keys(None);
    let server_key = server_keys.identity.public();
    let server_kem = KemSecret::from_bytes(server_keys.kem.expose()).unwrap();
    let (issued, task) = host_server(
        endpoints.clone(),
        inviter.clone(),
        Server {
            keys: server_keys,
            bound: None,
        },
        3,
    )
    .await;
    let short = issued.short.clone().unwrap();
    let address = PairAddress::parse(&issued.address.to_text()).unwrap();
    let moved = crate::account_resource(&format!("a{}", "b".repeat(26))).unwrap();
    let kept = crate::account_resource(&format!("c{}", "d".repeat(26))).unwrap();
    a.ensure_resource(&moved, &["mail-send"]).await.unwrap();
    a.ensure_resource(&kept, &["mail-send"]).await.unwrap();
    let cert = Arc::new(Certifier {
        membership: a.clone(),
        confirm: Arc::new(Answer(true)),
        hint: WireHint::default(),
        server_grants: vec![moved.clone()],
    });
    for wrong in 0..2u8 {
        let mut secret = *short.secret();
        secret[0] ^= wrong + 1;
        let code = PairingCode::Short {
            code: ShortCode::new(short.id(), secret),
            address: address.clone(),
        };
        let r = join(&*endpoints, &code, Side::Certifier(&cert), &limits()).await;
        assert_eq!(r.unwrap_err(), MembershipError::WrongCode);
    }
    let typed = ShortCode::parse(&short.display().to_ascii_lowercase()).unwrap();
    let code = PairingCode::Short {
        code: typed,
        address,
    };
    let c = certified(
        join(&*endpoints, &code, Side::Certifier(&cert), &limits())
            .await
            .unwrap(),
    );
    assert_eq!(c.node, server_key);
    assert_eq!(c.class, NodeClass::Server);
    let served = task.await.unwrap();
    let j = joined(served.into_iter().nth(2).unwrap().unwrap().1);
    assert!(j.member.is_none(), "a server never receives the member key");
    assert_eq!(j.log.genesis_hash(), a.genesis_hash());
    let expires = a.with_log(|l| {
        l.state()
            .node(&server_key, l.state().last_at())
            .unwrap()
            .expires
    });
    assert_eq!(expires.0, clock.now()().0 + limits().server_term_ms);
    use baton_group::{Capability, Recipient, epochs};
    let at = clock.now()();
    let st = j.log.state();
    assert!(st.may(&server_key, &moved, &Capability::Lead, at));
    for cap in [Capability::Admin, Capability::Command("mail-send".into())] {
        assert!(!st.may(&server_key, &moved, &cap, at));
    }
    assert!(!st.may(&server_key, &kept, &Capability::Read, at));
    let rcpt = Recipient::Node(server_key);
    assert!(epochs::open(&j.log, &moved, 1, &rcpt, &server_kem).is_ok());
    assert!(epochs::open(&j.log, &kept, 1, &rcpt, &server_kem).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_third_wrong_short_code_kills_the_invite() {
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let clock = Clock::new();
    let (a, _, _) = found(&clock).await;
    let inviter = Arc::new(Inviter::new(limits(), clock.now()));
    let (issued, task) = host_server(
        endpoints.clone(),
        inviter.clone(),
        Server {
            keys: keys(None),
            bound: None,
        },
        4,
    )
    .await;
    let short = issued.short.clone().unwrap();
    let cert = certifier(&a, Arc::new(Answer(true)));
    for n in 0..3u8 {
        let mut secret = *short.secret();
        secret[4] ^= n + 1;
        let code = PairingCode::Short {
            code: ShortCode::new(short.id(), secret),
            address: issued.address.clone(),
        };
        assert!(
            join(&*endpoints, &code, Side::Certifier(&cert), &limits())
                .await
                .is_err()
        );
    }
    let code = PairingCode::Short {
        code: short,
        address: issued.address.clone(),
    };
    assert_eq!(
        join(&*endpoints, &code, Side::Certifier(&cert), &limits())
            .await
            .unwrap_err(),
        MembershipError::WrongCode
    );
    assert!(task.await.unwrap().iter().all(|r| r.is_err()));
    assert_eq!(a.nodes().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bound_server_refuses_another_group() {
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let clock = Clock::new();
    let (a, _, _) = found(&clock).await;
    let (other, _, _) = found(&clock).await;
    let inviter = Arc::new(Inviter::new(limits(), clock.now()));
    let (issued, task) = host_server(
        endpoints.clone(),
        inviter,
        Server {
            keys: keys(None),
            bound: Some(other.genesis_hash()),
        },
        1,
    )
    .await;
    let head = a.head();
    let cert = certifier(&a, Arc::new(Answer(true)));
    let r = join(&*endpoints, &qr(&issued), Side::Certifier(&cert), &limits()).await;
    assert_eq!(r.unwrap_err(), MembershipError::Refused);
    assert!(task.await.unwrap()[0].is_err());
    assert_eq!(a.head(), head, "nothing was certified");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revoked_node_cannot_pair_again() {
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let clock = Clock::new();
    let (a, _, _) = found(&clock).await;
    let inviter = Arc::new(Inviter::new(limits(), clock.now()));
    let (issued, task) = host_device(
        endpoints.clone(),
        inviter.clone(),
        certifier(&a, Arc::new(Answer(true))),
        1,
    )
    .await;
    let b = keys(None);
    join_as_device(
        &*endpoints,
        &qr(&issued),
        &b,
        NodeClass::Phone,
        Arc::new(Answer(true)),
    )
    .await
    .unwrap();
    task.await.unwrap();
    a.revoke(&b.identity.public()).await.unwrap();
    let head = a.head();
    let (issued, task) = host_device(
        endpoints.clone(),
        inviter,
        certifier(&a, Arc::new(Answer(true))),
        1,
    )
    .await;
    let again = copy_keys(&b);
    let r = join_as_device(
        &*endpoints,
        &qr(&issued),
        &again,
        NodeClass::Phone,
        Arc::new(Answer(true)),
    )
    .await;
    assert_eq!(r.unwrap_err(), MembershipError::Refused);
    assert!(matches!(
        task.await.unwrap()[0],
        Err(MembershipError::Invalid)
    ));
    assert_eq!(a.head(), head);
    assert!(!a.counts(&b.identity.public()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tampered_invite_of_another_group_fails_the_pake() {
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let clock = Clock::new();
    let (a, _, _) = found(&clock).await;
    let inviter = Arc::new(Inviter::new(limits(), clock.now()));
    let (issued, task) = host_device(
        endpoints.clone(),
        inviter,
        certifier(&a, Arc::new(Answer(true))),
        1,
    )
    .await;
    let i = &issued.invite;
    let swapped = Invite::new(
        i.kind,
        Some(GroupId::new("gothergroup").unwrap()),
        i.inviter,
        i.id,
        *i.secret(),
        i.endpoint,
        i.hint.clone(),
        i.expires_at,
    );
    let b = keys(None);
    let r = join_as_device(
        &*endpoints,
        &PairingCode::Qr(Box::new(swapped)),
        &b,
        NodeClass::Phone,
        Arc::new(Answer(true)),
    )
    .await;
    assert_eq!(r.unwrap_err(), MembershipError::WrongCode);
    assert!(task.await.unwrap()[0].is_err());
}

#[tokio::test]
async fn invites_are_capped() {
    let clock = Clock::new();
    let inviter = Inviter::new(limits(), clock.now());
    let key = baton_identity::Identity::generate().public();
    for _ in 0..limits().max_pending {
        inviter
            .issue(InviteKind::Server, None, None, key, WireHint::default())
            .unwrap();
    }
    assert_eq!(
        inviter
            .issue(InviteKind::Server, None, None, key, WireHint::default())
            .unwrap_err(),
        MembershipError::Busy
    );
    assert_eq!(
        inviter
            .issue(InviteKind::Device, None, None, key, WireHint::default())
            .unwrap_err(),
        MembershipError::Busy
    );
    clock.advance(limits().ttl_ms + 1);
    assert_eq!(inviter.pending(), 0, "expired invites free their places");
    assert_eq!(
        inviter
            .issue(InviteKind::Device, None, None, key, WireHint::default())
            .unwrap_err(),
        MembershipError::Invalid,
        "a device invite names its group and inviter"
    );
}

#[test]
fn fingerprints_bind_both_nodes_and_the_group() {
    let a = baton_identity::Identity::generate().public();
    let b = baton_identity::Identity::generate().public();
    let g = GroupId::new("gone").unwrap();
    let f = fingerprint(&[1; 32], &a, &b, &g);
    assert_eq!(f.len(), 7);
    assert_eq!(&f[3..4], " ");
    assert_ne!(f, fingerprint(&[2; 32], &a, &b, &g));
    assert_ne!(f, fingerprint(&[1; 32], &b, &a, &g));
    assert_ne!(
        f,
        fingerprint(&[1; 32], &a, &b, &GroupId::new("gtwo").unwrap())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_candidate_refuses_a_log_over_its_byte_cap() {
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let clock = Clock::new();
    let (a, _, _) = found(&clock).await;
    for c in ['c', 'd', 'e'] {
        let r = crate::account_resource(&format!("a{}", c.to_string().repeat(26))).unwrap();
        a.ensure_resource(&r, &["mail-send"]).await.unwrap();
    }
    let bytes: usize = a.with_log(|l| l.entries().iter().map(|e| e.encode().len()).sum());
    let head = a.head();
    let inviter = Arc::new(Inviter::new(limits(), clock.now()));
    let (issued, task) = host_device(
        endpoints.clone(),
        inviter,
        certifier(&a, Arc::new(Answer(true))),
        1,
    )
    .await;
    let b = keys(None);
    let cand = Candidate {
        identity: &b.identity,
        kem: &b.kem,
        class: NodeClass::Desktop,
        label: "Laptop".into(),
        hint: WireHint::default(),
        bound: None,
        confirm: Arc::new(Answer(true)),
    };
    let small = Limits {
        max_log_bytes: bytes / 2,
        ..limits()
    };
    let r = join(&*endpoints, &qr(&issued), Side::Candidate(&cand), &small).await;
    assert_eq!(r.unwrap_err(), MembershipError::Malformed);
    let _ = task.await;
    assert_ne!(
        a.head(),
        head,
        "the certifier went ahead; the candidate kept nothing"
    );
}

async fn raw_hello(endpoints: &dyn Endpoints, address: &PairAddress, invite: InviteRef) {
    let me = Identity::generate();
    let bound = endpoints
        .bind(&me, Arc::new(PinnedKeys::new([address.endpoint])))
        .await
        .unwrap();
    bound
        .link
        .add_hint(&address.endpoint, address.hint.to_peer().unwrap())
        .unwrap();
    let protocol = Protocol::new(PAIR_PROTOCOL).unwrap();
    let mut stream = bound.link.open(&address.endpoint, &protocol).await.unwrap();
    let hello = wire::encode(&Hello {
        v: PAIR_VERSION,
        invite,
        message: [0; 32],
    });
    wire::write_frame(&mut *stream, &hello, HANG).await.unwrap();
    let _ = wire::read_frame(&mut *stream, 1024, HANG).await;
    bound.link.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hellos_with_an_invalid_point_never_burn_an_invite() {
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let clock = Clock::new();
    let (a, _, _) = found(&clock).await;
    let inviter = Arc::new(Inviter::new(limits(), clock.now()));
    let (issued, task) = host_server(
        endpoints.clone(),
        inviter.clone(),
        Server {
            keys: keys(None),
            bound: None,
        },
        5,
    )
    .await;
    let short = issued.short.clone().unwrap();
    for _ in 0..4 {
        raw_hello(&*endpoints, &issued.address, InviteRef::Short(short.id())).await;
    }
    assert!(
        inviter.is_pending(issued.invite.id),
        "no attempt was counted"
    );
    let cert = certifier(&a, Arc::new(Answer(true)));
    let code = PairingCode::Short {
        code: short,
        address: issued.address.clone(),
    };
    join(&*endpoints, &code, Side::Certifier(&cert), &limits())
        .await
        .unwrap();
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_failed_handshake_holds_its_slot_for_the_fail_delay() {
    let endpoints: Arc<dyn Endpoints> = Arc::new(MemoryEndpoints::new());
    let clock = Clock::new();
    let paced = Limits {
        fail_delay: Duration::from_secs(1),
        ..limits()
    };
    let inviter = Arc::new(Inviter::new(paced, clock.now()));
    let ep = PairingEndpoint::open(&*endpoints).await.unwrap();
    let issued = inviter
        .issue(InviteKind::Server, None, None, ep.key(), ep.hint().clone())
        .unwrap();
    let server = keys(None);
    let served = {
        let inviter = inviter.clone();
        tokio::spawn(async move {
            let cand = Candidate {
                identity: &server.identity,
                kem: &server.kem,
                class: NodeClass::Server,
                label: "server".into(),
                hint: WireHint::default(),
                bound: None,
                confirm: Arc::new(Answer(true)),
            };
            let inc = ep.next().await.unwrap();
            let start = tokio::time::Instant::now();
            let r = inviter
                .serve(inc.stream, inc.peer, ep.key(), Side::Candidate(&cand))
                .await;
            (r.map(|_| ()), start.elapsed())
        })
    };
    raw_hello(&*endpoints, &issued.address, InviteRef::Short(0x3ff)).await;
    let (r, elapsed) = served.await.unwrap();
    assert_eq!(r, Err(MembershipError::Refused));
    assert_eq!(elapsed, Duration::from_secs(1));
}

#[tokio::test]
async fn a_peer_hanging_up_mid_pairing_reads_as_refused_on_either_side() {
    let start = |role| Pake::start(role, b"secret", b"channel", b"session", b"");
    let (i, r) = (start(PakeRole::Initiator), start(PakeRole::Responder));
    let (im, rm) = (i.message(), r.message());
    let (is, rs) = (i.finish(&rm, b"").unwrap(), r.finish(&im, b"").unwrap());
    let (ours, theirs) = tokio::io::duplex(64);
    let mut sending = Channel::new(Box::new(ours), &is, PakeRole::Initiator, &limits(), 1);
    drop(theirs);
    assert_eq!(
        sending.send(&Msg::Refuse).await,
        Err(MembershipError::Refused),
        "a write into a closed pairing"
    );
    let (ours, theirs) = tokio::io::duplex(64);
    let mut reading = Channel::new(Box::new(ours), &rs, PakeRole::Responder, &limits(), 1);
    drop(theirs);
    assert!(
        matches!(reading.recv(1024).await, Err(MembershipError::Refused)),
        "a read from a closed pairing"
    );
}
