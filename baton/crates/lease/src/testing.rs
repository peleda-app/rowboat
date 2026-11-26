//! Conformance suites for [`Leases`] and [`Liveness`], including attacks and contention.

use std::collections::HashSet;
use std::future::Future;
use std::sync::Arc;

use baton_core::{FencingToken, GroupId, LeaseKey, NodeId, Timestamp};

use crate::{Lease, Leases, Liveness, NodeClass, NodeProfile, TakeoverOutcome};

/// A profile for the suites.
pub fn profile(name: &str, class: NodeClass) -> NodeProfile {
    NodeProfile {
        node: NodeId::new(name).unwrap(),
        class,
        weight: 1,
        can_run: true,
    }
}

/// What the suite needs from the harness besides the implementation.
pub trait Harness: Send + Sync {
    /// Makes `profile`'s node alive for the implementation (for example a heartbeat now).
    fn alive(&self, profile: &NodeProfile) -> impl Future<Output = ()> + Send;
    /// Makes `node` no longer alive (for example stop its heartbeats and move time on).
    fn kill(&self, node: &NodeId) -> impl Future<Output = ()> + Send;
}

/// The [`Leases`] contract. The suite calls `harness.alive` for every node before it uses it and
/// `harness.kill` when a node must be gone. Uses the group `conf-lease`.
pub async fn leases<H: Harness + 'static>(leases: Arc<dyn Leases>, harness: Arc<H>) {
    let g = GroupId::new("conf-lease").unwrap();
    basics(&leases, &g, &*harness).await;
    priorities(&leases, &g, &*harness).await;
    forged_releases(&leases, &g, &*harness).await;
    never_lead(&leases, &g, &*harness).await;
    race(&leases, &g, "race-one", 64, &harness).await;
    many_keys(&leases, &g, &harness).await;
}

async fn basics<H: Harness>(leases: &Arc<dyn Leases>, g: &GroupId, h: &H) {
    let k = LeaseKey::new("basic").unwrap();
    let a = profile("node-a", NodeClass::Desktop);
    let b = profile("node-b", NodeClass::Desktop);
    h.alive(&a).await;
    h.alive(&b).await;
    assert!(leases.holder(g, &k).await.unwrap().is_none());
    let first = leases
        .acquire(g, &k, &a)
        .await
        .unwrap()
        .expect("a free key is granted");
    assert_eq!(first.node, a.node);
    assert!(first.fence > FencingToken(0));
    let again = leases
        .acquire(g, &k, &a)
        .await
        .unwrap()
        .expect("the holder renews");
    assert_eq!(again.fence, first.fence, "renewing keeps the token");
    assert!(
        leases.acquire(g, &k, &b).await.unwrap().is_none(),
        "a live holder keeps it"
    );
    assert_eq!(leases.holder(g, &k).await.unwrap().unwrap().node, a.node);

    h.kill(&a.node).await;
    let taken = leases
        .acquire(g, &k, &b)
        .await
        .unwrap()
        .expect("a dead holder loses it");
    assert_eq!(taken.node, b.node);
    assert!(
        taken.fence > first.fence,
        "a new holder gets a higher token"
    );
    assert!(
        leases.acquire(g, &k, &a).await.unwrap().is_none(),
        "the old holder cannot renew once replaced"
    );

    leases.release(&first).await.unwrap();
    assert_eq!(
        leases.holder(g, &k).await.unwrap().unwrap().node,
        b.node,
        "a stale lease cannot release"
    );
    leases.release(&taken).await.unwrap();
    assert!(leases.holder(g, &k).await.unwrap().is_none());
    let after = leases
        .acquire(g, &k, &b)
        .await
        .unwrap()
        .expect("released is free");
    assert!(
        after.fence > taken.fence,
        "release keeps the token, the next grant is higher"
    );
}

async fn priorities<H: Harness>(leases: &Arc<dyn Leases>, g: &GroupId, h: &H) {
    let k = LeaseKey::new("prio").unwrap();
    let phone = profile("prio-phone", NodeClass::Phone);
    let desk = profile("prio-desk", NodeClass::Desktop);
    let desk2 = profile("prio-desk2", NodeClass::Desktop);
    let srv = profile("prio-srv", NodeClass::Server);
    for p in [&phone, &desk, &desk2, &srv] {
        h.alive(p).await;
    }

    let held = leases.acquire(g, &k, &phone).await.unwrap().unwrap();
    assert!(
        leases.acquire(g, &k, &srv).await.unwrap().is_none(),
        "a stronger node never steals a live lease"
    );
    assert_eq!(
        leases.request_takeover(g, &k, &phone).await.unwrap(),
        TakeoverOutcome::AlreadyHolder
    );
    assert_eq!(
        leases.request_takeover(g, &k, &desk).await.unwrap(),
        TakeoverOutcome::Recorded
    );
    assert_eq!(
        leases.request_takeover(g, &k, &desk2).await.unwrap(),
        TakeoverOutcome::Refused,
        "an equally strong requester does not displace the waiting one"
    );
    assert_eq!(
        leases.request_takeover(g, &k, &srv).await.unwrap(),
        TakeoverOutcome::Recorded,
        "a stronger requester displaces a weaker one"
    );
    let renewed = leases.acquire(g, &k, &phone).await.unwrap().unwrap();
    assert_eq!(renewed.fence, held.fence);
    assert_eq!(
        renewed.takeover.as_ref().map(|t| t.node.clone()),
        Some(srv.node.clone()),
        "the holder sees the pending takeover when it renews"
    );
    leases.release(&renewed).await.unwrap();
    assert!(
        leases.acquire(g, &k, &desk).await.unwrap().is_none(),
        "a handed-over lease is reserved for the requester"
    );
    let won = leases
        .acquire(g, &k, &srv)
        .await
        .unwrap()
        .expect("the requester gets it");
    assert!(won.fence > held.fence);
    assert!(won.takeover.is_none());

    assert_eq!(
        leases.request_takeover(g, &k, &desk).await.unwrap(),
        TakeoverOutcome::Refused,
        "a weaker node cannot ask a server to hand over"
    );

    let k2 = LeaseKey::new("prio-dead").unwrap();
    leases.acquire(g, &k2, &phone).await.unwrap().unwrap();
    let ghost = profile("prio-ghost", NodeClass::Server);
    h.alive(&ghost).await;
    assert_eq!(
        leases.request_takeover(g, &k2, &ghost).await.unwrap(),
        TakeoverOutcome::Recorded
    );
    let renewed2 = leases.acquire(g, &k2, &phone).await.unwrap().unwrap();
    leases.release(&renewed2).await.unwrap();
    h.kill(&ghost.node).await;
    assert!(
        leases.acquire(g, &k2, &desk).await.unwrap().is_some(),
        "a reservation for a dead node does not block the key"
    );
}

async fn forged_releases<H: Harness>(leases: &Arc<dyn Leases>, g: &GroupId, h: &H) {
    let k = LeaseKey::new("forged").unwrap();
    let a = profile("forge-a", NodeClass::Desktop);
    h.alive(&a).await;
    let real = leases.acquire(g, &k, &a).await.unwrap().unwrap();
    let forgeries = [
        Lease {
            fence: FencingToken(real.fence.0 + 1),
            ..real.clone()
        },
        Lease {
            fence: FencingToken(real.fence.0.saturating_sub(1)),
            ..real.clone()
        },
        Lease {
            node: NodeId::new("forge-mallory").unwrap(),
            ..real.clone()
        },
        Lease {
            key: LeaseKey::new("forged-other").unwrap(),
            ..real.clone()
        },
        Lease {
            group: GroupId::new("conf-lease-other").unwrap(),
            ..real.clone()
        },
    ];
    for f in forgeries {
        leases.release(&f).await.unwrap();
        assert_eq!(
            leases.holder(g, &k).await.unwrap(),
            Some(real.clone()),
            "a forged release changes nothing: {f:?}"
        );
    }
}

async fn never_lead<H: Harness>(leases: &Arc<dyn Leases>, g: &GroupId, h: &H) {
    let k = LeaseKey::new("never").unwrap();
    let blind = profile("never-blind", NodeClass::Blind);
    let asleep = NodeProfile {
        can_run: false,
        ..profile("never-asleep", NodeClass::Phone)
    };
    let zero = NodeProfile {
        weight: 0,
        ..profile("never-zero", NodeClass::Server)
    };
    for p in [&blind, &asleep, &zero] {
        h.alive(p).await;
    }
    for p in [&blind, &asleep, &zero] {
        assert!(leases.acquire(g, &k, p).await.unwrap().is_none(), "{p:?}");
        assert_eq!(
            leases.request_takeover(g, &k, p).await.unwrap(),
            TakeoverOutcome::Refused
        );
    }
    assert!(leases.holder(g, &k).await.unwrap().is_none());
}

async fn race<H: Harness + 'static>(
    leases: &Arc<dyn Leases>,
    g: &GroupId,
    key: &str,
    n: usize,
    h: &Arc<H>,
) {
    let k = LeaseKey::new(key).unwrap();
    let racers: Vec<_> = (0..n)
        .map(|i| profile(&format!("racer-{i}"), NodeClass::Desktop))
        .collect();
    for p in &racers {
        h.alive(p).await;
    }
    let mut tasks = Vec::new();
    for p in racers {
        let leases = leases.clone();
        let g = g.clone();
        let k = k.clone();
        tasks.push(tokio::spawn(async move {
            leases.acquire(&g, &k, &p).await.unwrap()
        }));
    }
    let mut won = Vec::new();
    for t in tasks {
        if let Some(l) = t.await.unwrap() {
            won.push(l);
        }
    }
    assert_eq!(
        won.len(),
        1,
        "exactly one of many live racers wins a free key"
    );
    let fences: HashSet<_> = won.iter().map(|l| l.fence).collect();
    assert_eq!(fences.len(), won.len());
    let last = won.iter().max_by_key(|l| l.fence).unwrap();
    assert_eq!(
        leases.holder(g, &k).await.unwrap().as_ref(),
        Some(last),
        "the holder is the winner with the highest token"
    );
}

async fn many_keys<H: Harness + 'static>(leases: &Arc<dyn Leases>, g: &GroupId, h: &Arc<H>) {
    let nodes: Vec<_> = (0..4)
        .map(|n| profile(&format!("many-{n}"), NodeClass::Server))
        .collect();
    for p in &nodes {
        h.alive(p).await;
    }
    let mut tasks = Vec::new();
    for p in nodes {
        let leases = leases.clone();
        let g = g.clone();
        tasks.push(tokio::spawn(async move {
            let mut got = Vec::new();
            for i in 0..100 {
                let k = LeaseKey::new(format!("many-{i}")).unwrap();
                if let Some(l) = leases.acquire(&g, &k, &p).await.unwrap() {
                    got.push(l);
                }
            }
            got
        }));
    }
    let mut holders = std::collections::HashMap::new();
    for t in tasks {
        for l in t.await.unwrap() {
            assert!(
                holders.insert(l.key.clone(), l.node.clone()).is_none(),
                "one holder per key"
            );
        }
    }
    assert_eq!(holders.len(), 100, "every key found a holder");
}

/// The [`Liveness`] contract. The implementation's time-to-live must equal `ttl_ms()` and be at
/// least 4 ms.
pub async fn liveness(live: Arc<dyn Liveness>) {
    let ttl = live.ttl_ms() as i64;
    assert!(ttl >= 4);
    let g = GroupId::new("conf-live").unwrap();
    let other = GroupId::new("conf-live-other").unwrap();
    let t0 = Timestamp(1_000_000);
    let x = profile("live-x", NodeClass::Desktop);
    let y = profile("live-y", NodeClass::Server);
    let names = |v: Vec<NodeProfile>| {
        let mut n: Vec<_> = v.into_iter().map(|p| p.node.as_str().to_owned()).collect();
        n.sort();
        n
    };
    live.heartbeat(&g, &x, t0).await.unwrap();
    live.heartbeat(&g, &y, t0).await.unwrap();
    assert_eq!(
        names(live.alive(&g, t0).await.unwrap()),
        ["live-x", "live-y"]
    );
    assert!(
        live.alive(&other, t0).await.unwrap().is_empty(),
        "groups never mix"
    );

    live.heartbeat(&g, &y, t0.plus_ms(ttl / 2)).await.unwrap();
    assert_eq!(
        names(live.alive(&g, t0.plus_ms(ttl / 2)).await.unwrap()),
        ["live-x", "live-y"]
    );
    assert_eq!(
        names(live.alive(&g, t0.plus_ms(ttl)).await.unwrap()),
        ["live-x", "live-y"],
        "alive up to the time-to-live, inclusive"
    );
    assert_eq!(
        names(live.alive(&g, t0.plus_ms(ttl + 1)).await.unwrap()),
        ["live-y"],
        "a silent node drops out right after the time-to-live"
    );

    let x_now_phone = NodeProfile {
        class: NodeClass::Phone,
        can_run: false,
        ..x.clone()
    };
    live.heartbeat(&g, &x_now_phone, t0.plus_ms(ttl + 2))
        .await
        .unwrap();
    let alive = live.alive(&g, t0.plus_ms(ttl + 3)).await.unwrap();
    assert!(
        alive.contains(&x_now_phone),
        "alive reports the latest profile"
    );

    let future = profile("live-future", NodeClass::Desktop);
    let t1 = t0.plus_ms(10 * ttl);
    live.heartbeat(&g, &future, t1.plus_ms(1_000 * ttl))
        .await
        .unwrap();
    assert!(
        live.alive(&g, t1)
            .await
            .unwrap()
            .iter()
            .any(|p| p.node == future.node)
    );
    assert!(
        !live
            .alive(&g, t1.plus_ms(ttl + 1))
            .await
            .unwrap()
            .iter()
            .any(|p| p.node == future.node),
        "a heartbeat stamped far in the future does not keep a node alive"
    );
    let past = profile("live-past", NodeClass::Desktop);
    live.heartbeat(&g, &past, Timestamp(i64::MIN))
        .await
        .unwrap();
    assert!(
        live.alive(&g, t1.plus_ms(ttl + 2))
            .await
            .unwrap()
            .iter()
            .any(|p| p.node == past.node),
        "a heartbeat stamped in the distant past still counts when it is new to the observer"
    );
}
