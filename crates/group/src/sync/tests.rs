use baton_core::{ResourceId, Timestamp};
use baton_group::{NodeCert, Op};
use baton_identity::Identity;
use baton_keys::KemSecret;
use baton_lease::NodeClass;
use baton_link::PinnedKeys;
use rowboat_endpoint::Endpoints;
use rowboat_endpoint_iroh::IrohEndpoints;
use rowboat_endpoint_memory::MemoryEndpoints;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::fixtures::{Clock, found, keys, store};
use crate::{DAY_MS, NodeKeys, account_resource};

/// Long enough that no step of a correct run ever reaches it, however loaded the machine.
const LIMIT: Duration = Duration::from_secs(300);

struct Net {
    m: Arc<Membership>,
    link: Arc<dyn Link>,
    hint: WireHint,
    task: JoinHandle<()>,
}

async fn up(endpoints: &dyn Endpoints, m: Arc<Membership>) -> Net {
    let bound = endpoints.bind(&m.keys().identity, m.trust()).await.unwrap();
    let hint = WireHint::from_peer(&bound.hint);
    let task = serve(m.clone(), bound.link.clone(), hint.clone(), LIMIT)
        .await
        .unwrap();
    Net {
        m,
        link: bound.link,
        hint,
        task,
    }
}

async fn certify(a: &Membership, member: &Identity, clock: &Clock) -> NodeKeys {
    let k = keys(Some(member));
    let expires = Timestamp(clock.now()().0 + 400 * DAY_MS);
    let proof = NodeCert::node_proof(
        &k.identity,
        &k.kem.public(),
        NodeClass::Desktop,
        &member.public(),
        expires,
    );
    a.certify(
        NodeCert::assemble(
            member,
            k.identity.public(),
            k.kem.public(),
            NodeClass::Desktop,
            expires,
            proof,
        )
        .unwrap(),
    )
    .await
    .unwrap();
    k
}

async fn view(a: &Membership, k: NodeKeys, clock: &Clock) -> Arc<Membership> {
    Arc::new(
        Membership::adopt(store(), a.log(), k, Vec::new(), clock.now())
            .await
            .unwrap(),
    )
}

async fn trio(endpoints: &dyn Endpoints) -> (Clock, Identity, [Net; 3]) {
    let clock = Clock::new();
    let (a, member, _) = found(&clock).await;
    let kb = certify(&a, &member, &clock).await;
    let kc = certify(&a, &member, &clock).await;
    let b = view(&a, kb, &clock).await;
    let c = view(&a, kc, &clock).await;
    let nets = [
        up(endpoints, a).await,
        up(endpoints, b).await,
        up(endpoints, c).await,
    ];
    for x in &nets {
        for y in &nets {
            if x.m.node() != y.m.node() {
                x.m.remember_peer(
                    &y.m.node(),
                    PeerRecord {
                        hint: y.hint.clone(),
                        label: None,
                    },
                )
                .await
                .unwrap();
            }
        }
    }
    (clock, member, nets)
}

async fn three_nodes_follow_and_revoke(endpoints: Arc<dyn Endpoints>) {
    let (_clock, _, [a, b, c]) = trio(&*endpoints).await;
    let resource = account_resource(&format!("a{}", "d".repeat(26))).unwrap();
    a.m.ensure_resource(&resource, &["mail-send"])
        .await
        .unwrap();
    let results = announce(&a.m, &a.link, &a.hint, LIMIT).await;
    assert_eq!(results.len(), 2);
    for (_, r) in &results {
        assert!(matches!(r, Ok(Synced::Sent(n)) if *n > 0), "{r:?}");
    }
    assert_eq!(b.m.head(), a.m.head());
    assert_eq!(c.m.head(), a.m.head());
    assert!(b.m.resource_keys(&resource, 1).is_ok());

    assert_eq!(
        exchange_with(&b.m, &b.link, &c.m.node(), &b.hint, LIMIT)
            .await
            .unwrap(),
        Synced::Same
    );

    a.m.revoke(&b.m.node()).await.unwrap();
    a.link.disconnect_untrusted().await.unwrap();
    let r = exchange_with(&b.m, &b.link, &a.m.node(), &b.hint, LIMIT).await;
    assert_eq!(
        r.unwrap_err(),
        MembershipError::Unreachable,
        "a revoked node is refused on the link"
    );
    assert_eq!(
        exchange_with(&a.m, &a.link, &c.m.node(), &a.hint, LIMIT)
            .await
            .unwrap(),
        Synced::Sent(2)
    );
    assert!(c.m.with_log(|l| l.state().is_revoked(&b.m.node())));
    let r = exchange_with(&b.m, &b.link, &c.m.node(), &b.hint, LIMIT).await;
    assert!(
        r.is_err(),
        "the revocation spread: the third node refuses too"
    );
    assert!(
        !b.m.is_revoked(),
        "the revoked node has not heard (revocation notices are B4)"
    );
    for n in [&a, &b, &c] {
        n.task.abort();
        n.link.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_nodes_in_memory() {
    three_nodes_follow_and_revoke(Arc::new(MemoryEndpoints::new())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_nodes_over_iroh_on_loopback() {
    three_nodes_follow_and_revoke(Arc::new(IrohEndpoints::loopback())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_behind_peer_never_moves_this_log_back_and_a_fork_changes_nothing() {
    let endpoints = MemoryEndpoints::new();
    let clock = Clock::new();
    let (a, member, _) = found(&clock).await;
    let kb = certify(&a, &member, &clock).await;
    let b = view(&a, kb, &clock).await;
    let resource = account_resource(&format!("a{}", "e".repeat(26))).unwrap();
    a.ensure_resource(&resource, &[]).await.unwrap();
    let a_net = up(&endpoints, a.clone()).await;
    let b_net = up(&endpoints, b.clone()).await;
    let head = a.head();
    assert!(matches!(
        exchange_with(&a, &a_net.link, &b.node(), &a_net.hint, LIMIT).await,
        Ok(Synced::Sent(_))
    ));
    assert_eq!(a.head(), head);
    assert_eq!(b.head(), head);

    a.append(vec![Op::CreateResource {
        resource: account_resource(&format!("a{}", "f".repeat(26))).unwrap(),
    }])
    .await
    .unwrap();
    b.append(vec![Op::CreateResource {
        resource: account_resource(&format!("a{}", "g".repeat(26))).unwrap(),
    }])
    .await
    .unwrap();
    let (ha, hb) = (a.head(), b.head());
    assert_eq!(
        exchange_with(&b, &b_net.link, &a.node(), &b_net.hint, LIMIT)
            .await
            .unwrap(),
        Synced::Forked
    );
    assert_eq!((a.head(), b.head()), (ha, hb));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_of_another_group_is_refused() {
    let endpoints = MemoryEndpoints::new();
    let clock = Clock::new();
    let (a, _, _) = found(&clock).await;
    let (other, _, _) = found(&clock).await;
    let a_net = up(&endpoints, a.clone()).await;
    let o_net = up(&endpoints, other.clone()).await;
    let r = exchange_with(&other, &o_net.link, &a.node(), &o_net.hint, LIMIT).await;
    assert_eq!(r.unwrap_err(), MembershipError::Unreachable);
    let r = exchange_with(&a, &a_net.link, &other.node(), &a_net.hint, LIMIT).await;
    assert_eq!(r.unwrap_err(), MembershipError::Unreachable);
}

async fn hostile(
    endpoints: &MemoryEndpoints,
    ident: &Identity,
    target: PublicKey,
    script: Vec<Vec<u8>>,
) -> JoinHandle<()> {
    let bound = endpoints
        .bind(ident, Arc::new(PinnedKeys::new([target])))
        .await
        .unwrap();
    let mut incoming = bound.link.listen(&protocol()).await.unwrap();
    tokio::spawn(async move {
        let _keep = bound.link.clone();
        if let Some(mut inc) = incoming.next().await {
            let mut len = [0u8; 4];
            let _ = inc.stream.read_exact(&mut len).await;
            let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
            let _ = inc.stream.read_exact(&mut buf).await;
            for frame in script {
                let _ = inc
                    .stream
                    .write_all(&(frame.len() as u32).to_be_bytes())
                    .await;
                let _ = inc.stream.write_all(&frame).await;
            }
            let _ = inc.stream.flush().await;
            std::future::pending::<()>().await;
        }
    })
}

#[tokio::test(start_paused = true)]
async fn hostile_peers_serving_bad_entries_change_nothing() {
    let endpoints = MemoryEndpoints::new();
    let clock = Clock::new();
    let (a, member, _) = found(&clock).await;
    let kb = certify(&a, &member, &clock).await;
    let mut liars = Vec::new();
    for _ in 0..6 {
        liars.push(certify(&a, &member, &clock).await.identity);
    }
    let a_net = up(&endpoints, a.clone()).await;
    let head = a.head();
    let offer = |seq: u64| {
        wire::encode(&SyncMsg::Offer {
            v: SYNC_VERSION,
            group: a.group().clone(),
            genesis: a.genesis_hash(),
            seq,
            hash: [9; 32],
            hint: WireHint::default(),
        })
    };

    let mut forged_log = a.log();
    forged_log
        .append(
            &kb.identity,
            Op::CreateResource {
                resource: account_resource(&format!("a{}", "h".repeat(26))).unwrap(),
            },
            clock.now()(),
        )
        .unwrap();
    let good = forged_log.entries().last().unwrap().encode();
    let mut flipped = good.clone();
    let n = flipped.len();
    flipped[n - 3] ^= 0x10;
    let stranger = Identity::generate();
    let mut stranger_log = a.log();
    let stranger_entry = {
        let k = KemSecret::generate();
        let cert = NodeCert::new(
            &stranger,
            &stranger,
            k.public(),
            NodeClass::Desktop,
            Timestamp(i64::MAX),
        );
        stranger_log
            .append(&stranger, Op::CertifyNode { cert }, clock.now()())
            .err()
    };
    assert!(
        stranger_entry.is_some(),
        "a stranger's entry never verifies"
    );

    let scripts: Vec<Vec<Vec<u8>>> = vec![
        vec![
            offer(head.0 + 1),
            wire::encode(&SyncMsg::Entry { bytes: flipped }),
        ],
        vec![
            offer(head.0 + 1),
            wire::encode(&SyncMsg::Entry {
                bytes: vec![0xff; 40],
            }),
        ],
        vec![offer(head.0 + 1), vec![0xff; 16]],
        vec![offer(head.0 + 5)],
        vec![wire::encode(&SyncMsg::End)],
        vec![
            offer(head.0 + 1),
            wire::encode(&SyncMsg::Entry {
                bytes: a.log().entries()[0].encode(),
            }),
            wire::encode(&SyncMsg::End),
        ],
    ];
    let expected = [
        Err(MembershipError::Unverified),
        Err(MembershipError::Unverified),
        Err(MembershipError::Malformed),
        Err(MembershipError::TimedOut),
        Err(MembershipError::Malformed),
        Ok(Synced::Received(0)),
    ];
    for ((script, liar), want) in scripts.into_iter().zip(&liars).zip(expected) {
        let task = hostile(&endpoints, liar, a.node(), script).await;
        let limit = Duration::from_millis(500);
        let r = exchange_with(&a, &a_net.link, &liar.public(), &a_net.hint, limit).await;
        assert_eq!(r, want);
        assert_eq!(a.head(), head, "nothing applied");
        task.abort();
    }
}

fn big_grant(resource: &ResourceId, member: &Identity, tag: usize) -> Op {
    let mut capabilities: std::collections::BTreeSet<baton_group::Capability> = (0..29_000)
        .map(|i| baton_group::Capability::Command(format!("c{tag:03}{i:028}")))
        .collect();
    capabilities.extend([
        baton_group::Capability::Read,
        baton_group::Capability::Lead,
        baton_group::Capability::Admin,
    ]);
    Op::Grant {
        resource: resource.clone(),
        principal: baton_group::Principal::Member(member.public()),
        capabilities,
    }
}

#[tokio::test(start_paused = true)]
async fn a_peer_streaming_entries_that_do_not_continue_the_log_is_dropped_at_the_first() {
    let endpoints = MemoryEndpoints::new();
    let clock = Clock::new();
    let (a, member, _) = found(&clock).await;
    let liar = certify(&a, &member, &clock).await.identity;
    let a_net = up(&endpoints, a.clone()).await;
    let head = a.head();
    let (other, other_member, _) = found(&clock).await;
    let resource = account_resource(&format!("a{}", "q".repeat(26))).unwrap();
    other.ensure_resource(&resource, &[]).await.unwrap();
    let mut log = other.log();
    let signer = &other.keys().identity;
    while log.head_seq() < head.0 + 3 {
        let tag = log.entries().len();
        log.append(
            signer,
            big_grant(&resource, &other_member, tag),
            clock.now()(),
        )
        .unwrap();
    }
    let mut script = vec![wire::encode(&SyncMsg::Offer {
        v: SYNC_VERSION,
        group: a.group().clone(),
        genesis: a.genesis_hash(),
        seq: head.0 + 3,
        hash: [9; 32],
        hint: WireHint::default(),
    })];
    for e in &log.entries()[(head.0 + 1) as usize..] {
        script.push(wire::encode(&SyncMsg::Entry { bytes: e.encode() }));
    }
    let task = hostile(&endpoints, &liar, a.node(), script).await;
    let start = tokio::time::Instant::now();
    let r = exchange_with(&a, &a_net.link, &liar.public(), &a_net.hint, LIMIT).await;
    assert_eq!(r, Ok(Synced::Forked));
    assert!(start.elapsed() < LIMIT, "no wait for the rest of the batch");
    assert_eq!(a.head(), head);
    task.abort();
}

#[tokio::test(start_paused = true)]
async fn a_batch_over_the_byte_cap_is_dropped() {
    let endpoints = MemoryEndpoints::new();
    let clock = Clock::new();
    let (a, member, _) = found(&clock).await;
    let resource = account_resource(&format!("a{}", "r".repeat(26))).unwrap();
    a.ensure_resource(&resource, &[]).await.unwrap();
    let kl = certify(&a, &member, &clock).await;
    let a_net = up(&endpoints, a.clone()).await;
    let head = a.head();
    let mut log = a.log();
    let mut script = Vec::new();
    let mut total = 0;
    while total <= MAX_BATCH_BYTES {
        let tag = log.entries().len();
        let e = log
            .append(
                &kl.identity,
                big_grant(&resource, &member, tag),
                clock.now()(),
            )
            .unwrap();
        let bytes = e.encode();
        assert!(bytes.len() <= baton_group::MAX_ENTRY);
        total += bytes.len();
        script.push(wire::encode(&SyncMsg::Entry { bytes }));
    }
    script.insert(
        0,
        wire::encode(&SyncMsg::Offer {
            v: SYNC_VERSION,
            group: a.group().clone(),
            genesis: a.genesis_hash(),
            seq: log.head_seq(),
            hash: log.head_hash(),
            hint: WireHint::default(),
        }),
    );
    let task = hostile(&endpoints, &kl.identity, a.node(), script).await;
    let r = exchange_with(&a, &a_net.link, &kl.identity.public(), &a_net.hint, LIMIT).await;
    assert_eq!(r, Err(MembershipError::Malformed));
    assert_eq!(a.head(), head);
    task.abort();
}

#[tokio::test(start_paused = true)]
async fn a_long_log_is_sent_in_batches_under_the_byte_cap() {
    let endpoints = MemoryEndpoints::new();
    let clock = Clock::new();
    let (a, member, _) = found(&clock).await;
    let resource = account_resource(&format!("a{}", "s".repeat(26))).unwrap();
    a.ensure_resource(&resource, &[]).await.unwrap();
    let kb = certify(&a, &member, &clock).await;
    let b = view(&a, kb, &clock).await;
    let mut n = 0;
    while n * 900_000 <= MAX_BATCH_BYTES {
        a.append(vec![big_grant(&resource, &member, n)])
            .await
            .unwrap();
        n += 1;
    }
    let a_net = up(&endpoints, a.clone()).await;
    let _b_net = up(&endpoints, b.clone()).await;
    let first = exchange_with(&a, &a_net.link, &b.node(), &a_net.hint, LIMIT)
        .await
        .unwrap();
    let Synced::Sent(sent) = first else {
        panic!("{first:?}");
    };
    assert!(sent > 0 && sent < n, "{sent} of {n}");
    assert_ne!(b.head(), a.head());
    assert_eq!(
        exchange_with(&a, &a_net.link, &b.node(), &a_net.hint, LIMIT)
            .await
            .unwrap(),
        Synced::Sent(n - sent)
    );
    assert_eq!(b.head(), a.head());
}
