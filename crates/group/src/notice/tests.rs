use baton_core::Timestamp;
use baton_group::NodeCert;
use baton_identity::Identity;
use baton_lease::NodeClass;
use rowboat_endpoint::Endpoints;
use rowboat_endpoint_memory::MemoryEndpoints;

use super::*;
use crate::fixtures::{Clock, found, keys, store};
use crate::{DAY_MS, MembershipEvent, NodeKeys, account_resource};

const LIMIT: Duration = Duration::from_secs(300);

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

struct Pair {
    a: Arc<Membership>,
    b: Arc<Membership>,
    _a_link: Arc<dyn Link>,
    b_link: Arc<dyn Link>,
    serving: JoinHandle<()>,
}

async fn pair(endpoints: &MemoryEndpoints) -> (Clock, Identity, Pair) {
    let clock = Clock::new();
    let (a, member, _) = found(&clock).await;
    let kb = certify(&a, &member, &clock).await;
    let b = view(&a, kb, &clock).await;
    let a_link = endpoints
        .bind(&a.keys().identity, a.trust())
        .await
        .unwrap()
        .link;
    let b_link = endpoints
        .bind(&b.keys().identity, b.trust())
        .await
        .unwrap()
        .link;
    let serving = serve(a.clone(), a_link.clone(), LIMIT).await.unwrap();
    (
        clock,
        member,
        Pair {
            a,
            b,
            _a_link: a_link,
            b_link,
            serving,
        },
    )
}

#[tokio::test]
async fn a_revoked_node_learns_of_its_revocation_once() {
    let endpoints = MemoryEndpoints::new();
    let (_clock, _, p) = pair(&endpoints).await;
    let resource = account_resource(&format!("a{}", "h".repeat(26))).unwrap();
    p.a.ensure_resource(&resource, &[]).await.unwrap();
    assert_eq!(
        ask(&p.b, &p.b_link, &p.a.node(), LIMIT).await.unwrap(),
        Noticed::NotRevoked,
        "a counting node is told it is not revoked"
    );
    p.a.revoke(&p.b.node()).await.unwrap();
    let mut events = p.b.subscribe();
    let got = ask(&p.b, &p.b_link, &p.a.node(), LIMIT).await.unwrap();
    assert!(matches!(got, Noticed::Applied(n) if n >= 2), "{got:?}");
    assert!(p.b.is_revoked());
    let mut revoked = 0;
    while let Ok(e) = events.try_recv() {
        if e == MembershipEvent::Revoked {
            revoked += 1;
        }
    }
    assert_eq!(revoked, 1);
    assert_eq!(
        ask(&p.b, &p.b_link, &p.a.node(), LIMIT).await.unwrap(),
        Noticed::Applied(0),
        "a repeated notice takes nothing"
    );
    let entries_before = p.b.head();
    p.a.ensure_resource(
        &account_resource(&format!("a{}", "i".repeat(26))).unwrap(),
        &[],
    )
    .await
    .unwrap();
    ask(&p.b, &p.b_link, &p.a.node(), LIMIT).await.unwrap();
    assert_eq!(
        p.b.head(),
        entries_before,
        "a notice never carries what comes after the revocation"
    );
    let r = crate::sync::exchange_with(
        &p.b,
        &p.b_link,
        &p.a.node(),
        &crate::invite::WireHint::default(),
        LIMIT,
    )
    .await;
    assert!(r.is_err(), "every other protocol still refuses it");
    p.serving.abort();
}

#[tokio::test]
async fn a_stranger_cannot_ask() {
    let endpoints = MemoryEndpoints::new();
    let (clock, _, p) = pair(&endpoints).await;
    let (other, _, _) = found(&clock).await;
    let link = endpoints
        .bind(
            &other.keys().identity,
            Arc::new(baton_link::PinnedKeys::new([p.a.node()])),
        )
        .await
        .unwrap()
        .link;
    assert_eq!(
        ask(&other, &link, &p.a.node(), LIMIT).await.unwrap_err(),
        MembershipError::Unreachable
    );
    p.serving.abort();
}

async fn forged(b: &Membership, frames: Vec<NoticeMsg>) -> Result<Noticed, MembershipError> {
    let (mut near, mut far) = tokio::io::duplex(1 << 20);
    for f in &frames {
        wire::write_frame(&mut far, &wire::encode(f), LIMIT)
            .await
            .unwrap();
    }
    receive(&mut near, b, LIMIT).await
}

#[tokio::test]
async fn forged_or_unchained_notices_change_nothing() {
    let endpoints = MemoryEndpoints::new();
    let (_clock, _, p) = pair(&endpoints).await;
    p.a.ensure_resource(
        &account_resource(&format!("a{}", "j".repeat(26))).unwrap(),
        &[],
    )
    .await
    .unwrap();
    p.a.revoke(&p.b.node()).await.unwrap();
    let head = p.b.head();
    let entries: Vec<Vec<u8>> = p.a.with_log(|l| {
        l.entries()[(head.0 + 1) as usize..]
            .iter()
            .map(|e| e.encode())
            .collect()
    });
    assert!(entries.len() >= 3);

    let mut flipped = entries.clone();
    let last = flipped.last_mut().unwrap();
    let mid = last.len() / 2;
    last[mid] ^= 1;
    let mut frames: Vec<NoticeMsg> = flipped
        .into_iter()
        .map(|bytes| NoticeMsg::Entry { bytes })
        .collect();
    frames.push(NoticeMsg::End);
    assert!(forged(&p.b, frames).await.is_err(), "a flipped byte");
    assert_eq!(p.b.head(), head);
    assert!(!p.b.is_revoked());

    let mut frames: Vec<NoticeMsg> = entries[1..]
        .iter()
        .cloned()
        .map(|bytes| NoticeMsg::Entry { bytes })
        .collect();
    frames.push(NoticeMsg::End);
    assert!(
        forged(&p.b, frames).await.is_err(),
        "entries that do not chain from the head"
    );
    assert_eq!(p.b.head(), head);

    let (stranger, _, _) = found(&Clock::new()).await;
    let foreign: Vec<NoticeMsg> = stranger
        .with_log(|l| l.entries().iter().map(|e| e.encode()).collect::<Vec<_>>())
        .into_iter()
        .map(|bytes| NoticeMsg::Entry { bytes })
        .chain([NoticeMsg::End])
        .collect();
    assert!(forged(&p.b, foreign).await.is_err(), "another group's log");
    assert!(!p.b.is_revoked());

    let mut frames: Vec<NoticeMsg> = entries
        .iter()
        .cloned()
        .map(|bytes| NoticeMsg::Entry { bytes })
        .collect();
    frames.push(NoticeMsg::End);
    assert!(matches!(
        forged(&p.b, frames).await,
        Ok(Noticed::Applied(_))
    ));
    assert!(p.b.is_revoked(), "the genuine entries do apply");
    p.serving.abort();
}

#[test]
fn hostile_frames_never_panic() {
    for bytes in [&[][..], &[0xff; 64][..], &[3, 0, 0, 0][..]] {
        fuzz_decoders(bytes);
    }
}
