use std::sync::atomic::AtomicI64;
use std::time::Duration;

use baton_identity::{Identity, Roster, RosterHandle};
use baton_lease::NodeClass;
use baton_lease::testing::profile;
use baton_mesh::frame::seal;
use baton_mesh_memory::MemoryHub;

use super::*;

fn g() -> GroupId {
    GroupId::new("conf-live").unwrap()
}

fn manual() -> Arc<AtomicI64> {
    Arc::new(AtomicI64::new(1_000_000))
}

async fn mesh(n: usize) -> (MemoryHub, Vec<Identity>, Vec<Arc<MeshLiveness>>) {
    let ids: Vec<_> = (0..n).map(|_| Identity::generate()).collect();
    let mut roster = Roster::genesis(&ids[0], g());
    for id in &ids[1..] {
        roster = roster.with_member(&ids[0], id.public()).unwrap();
    }
    let hub = MemoryHub::new();
    let mut out = Vec::new();
    for id in &ids {
        let t = Arc::new(hub.join(id.clone(), RosterHandle::new(roster.clone()).unwrap()));
        out.push(Arc::new(
            MeshLiveness::start(
                t,
                g(),
                RosterHandle::new(roster.clone()).unwrap(),
                10_000,
                Duration::from_millis(300),
            )
            .await
            .unwrap(),
        ));
    }
    (hub, ids, out)
}

#[tokio::test]
async fn conformance() {
    let (_hub, _, nodes) = mesh(1).await;
    baton_lease::testing::liveness(nodes[0].clone()).await;
}

fn me(id: &Identity) -> NodeProfile {
    NodeProfile {
        node: id.node_id(),
        ..profile("x", NodeClass::Desktop)
    }
}

#[tokio::test]
async fn heartbeats_spread_and_expire_on_the_observers_clock() {
    let now = manual();
    let (_hub, ids, n) = mesh(3).await;
    n[0].heartbeat(&g(), &me(&ids[0]), Timestamp(0))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let t = Timestamp(now.load(Ordering::SeqCst));
    assert!(
        n[2].alive(&g(), t)
            .await
            .unwrap()
            .iter()
            .any(|p| p.node == ids[0].node_id())
    );
    now.fetch_add(10_001, Ordering::SeqCst);
    let t = Timestamp(now.load(Ordering::SeqCst));
    assert!(
        n[2].alive(&g(), t).await.unwrap().is_empty(),
        "silence for the time-to-live drops a node"
    );
    assert!(
        n[2].alive(&GroupId::new("other").unwrap(), t)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        n[2].heartbeat(&GroupId::new("other").unwrap(), &me(&ids[2]), t)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn members_cannot_speak_for_others_replay_old_beats_or_cross_groups() {
    let now = manual();
    let (hub, ids, n) = mesh(3).await;
    let target = ids[0].node_id();
    let beat = |group: GroupId, p: NodeProfile, counter: u64| {
        postcard::to_stdvec(&Msg::Beat {
            group,
            profile: p,
            epoch: 7,
            counter,
        })
        .unwrap()
    };
    let mut seq = 1u64 << 60;
    let mut inject = |from: &Identity, bytes: Vec<u8>| {
        seq += 1;
        hub.inject(&target, &seal(from, &target, CHANNEL, seq, &bytes));
    };
    inject(&ids[1], beat(g(), me(&ids[2]), 5));
    inject(
        &ids[1],
        beat(GroupId::new("other").unwrap(), me(&ids[1]), 6),
    );
    let mut big = beat(g(), me(&ids[1]), 7);
    big.resize(MAX_HEARTBEAT + 1, 0);
    inject(&ids[1], big);
    tokio::time::sleep(Duration::from_millis(30)).await;
    let t = Timestamp(now.load(Ordering::SeqCst));
    assert!(
        n[0].alive(&g(), t).await.unwrap().is_empty(),
        "nothing above counts"
    );

    inject(&ids[1], beat(g(), me(&ids[1]), 100));
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(n[0].alive(&g(), t).await.unwrap().len(), 1);
    now.fetch_add(10_001, Ordering::SeqCst);
    inject(&ids[1], beat(g(), me(&ids[1]), 100));
    inject(&ids[1], beat(g(), me(&ids[1]), 50));
    tokio::time::sleep(Duration::from_millis(30)).await;
    let t = Timestamp(now.load(Ordering::SeqCst));
    assert!(
        n[0].alive(&g(), t).await.unwrap().is_empty(),
        "a replayed or older heartbeat does not revive a node"
    );
}

#[tokio::test]
async fn an_isolated_node_learns_that_its_heartbeats_failed() {
    let now = manual();
    let (hub, ids, n) = mesh(3).await;
    let t = Timestamp(now.load(Ordering::SeqCst));
    n[0].heartbeat(&g(), &me(&ids[0]), t)
        .await
        .expect("a majority acknowledges");
    hub.partition(&[&[ids[0].node_id()], &[ids[1].node_id(), ids[2].node_id()]]);
    assert!(
        matches!(
            n[0].heartbeat(&g(), &me(&ids[0]), t).await,
            Err(LeaseError::Unavailable)
        ),
        "without a majority of acknowledgements the heartbeat fails, so the holder must stop"
    );
    n[1].heartbeat(&g(), &me(&ids[1]), t)
        .await
        .expect("two of three is a majority");
}

#[tokio::test]
async fn a_restarted_node_with_a_clock_behind_is_heard_again() {
    let now = manual();
    let (hub, ids, n) = mesh(2).await;
    let target = ids[0].node_id();
    let beat = |epoch: u64, counter: u64| {
        postcard::to_stdvec(&Msg::Beat {
            group: g(),
            profile: me(&ids[1]),
            epoch,
            counter,
        })
        .unwrap()
    };
    let mut seq = 1u64 << 60;
    let mut inject = |bytes: Vec<u8>| {
        seq += 1;
        hub.inject(&target, &seal(&ids[1], &target, CHANNEL, seq, &bytes));
    };
    inject(beat(1, 1_000_000));
    tokio::time::sleep(Duration::from_millis(30)).await;
    let t = Timestamp(now.load(Ordering::SeqCst));
    assert_eq!(n[0].alive(&g(), t).await.unwrap().len(), 1);
    now.fetch_add(10_001, Ordering::SeqCst);
    inject(beat(2, 5));
    tokio::time::sleep(Duration::from_millis(30)).await;
    let t = Timestamp(now.load(Ordering::SeqCst));
    assert_eq!(
        n[0].alive(&g(), t).await.unwrap().len(),
        1,
        "a new boot epoch counts even with a lower counter"
    );
}
