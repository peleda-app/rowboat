use proptest::prelude::*;

use super::*;

fn p(name: &str, class: NodeClass) -> NodeProfile {
    NodeProfile {
        node: NodeId::new(name).unwrap(),
        class,
        weight: 1,
        can_run: true,
    }
}

fn ids() -> (GroupId, LeaseKey) {
    (GroupId::new("g").unwrap(), LeaseKey::new("k").unwrap())
}

fn inc(f: u64) -> Option<u64> {
    f.checked_add(1)
}

fn all(_: &NodeId) -> bool {
    true
}

const TTL: u64 = 10;

const FRESH: View<'static> = View {
    alive: &all,
    quiet_ms: 0,
    ttl_ms: TTL,
};

fn view(alive: &dyn Fn(&NodeId) -> bool, quiet_ms: u64) -> View<'_> {
    View {
        alive,
        quiet_ms,
        ttl_ms: TTL,
    }
}

fn written(step: Step) -> LeaseRecord {
    match step {
        Step::Write(r, _) => r,
        other => panic!("expected a write, got {other:?}"),
    }
}

fn t(name: &str, class: NodeClass) -> Takeover {
    Takeover {
        node: NodeId::new(name).unwrap(),
        class,
    }
}

#[test]
fn decode_refuses_anything_inconsistent() {
    let ok = LeaseRecord::held_by(&p("a", NodeClass::Desktop), 3);
    assert_eq!(LeaseRecord::decode(&ok.encode()).unwrap(), ok);
    let mut bad = Vec::new();
    let mut v2 = ok.clone();
    v2.v = 2;
    bad.push(v2);
    let mut blind = ok.clone();
    blind.holder.as_mut().unwrap().class = NodeClass::Blind;
    bad.push(blind);
    let mut zero = ok.clone();
    zero.fence = 0;
    bad.push(zero);
    let mut weak_takeover = ok.clone();
    weak_takeover.takeover = Some(t("p", NodeClass::Phone));
    bad.push(weak_takeover);
    let mut takeover_without_holder = ok.clone();
    takeover_without_holder.holder = None;
    takeover_without_holder.takeover = Some(t("s", NodeClass::Server));
    bad.push(takeover_without_holder);
    let mut reserved_with_holder = ok.clone();
    reserved_with_holder.reserved = Some(t("s", NodeClass::Server));
    bad.push(reserved_with_holder);
    for r in bad {
        assert!(
            matches!(LeaseRecord::decode(&r.encode()), Err(LeaseError::Corrupted)),
            "{r:?}"
        );
    }
    for raw in [
        &b""[..],
        b"null",
        b"{}",
        b"{\"v\":1,\"holder\":null,\"fence\":1,\"takeover\":null,\"reserved\":null,\"extra\":1}",
        b"{\"v\":1,\"holder\":{\"node\":\"../x\",\"class\":\"server\"},\"fence\":1,\"takeover\":null,\"reserved\":null}",
    ] {
        assert!(LeaseRecord::decode(raw).is_err(), "{:?}", String::from_utf8_lossy(raw));
    }
    assert!(LeaseRecord::decode(&vec![b' '; MAX_RECORD + 1]).is_err());
}

#[test]
fn a_token_at_the_top_never_wraps() {
    let (g, k) = ids();
    let mut r = LeaseRecord::held_by(&p("a", NodeClass::Desktop), u64::MAX);
    r.holder = None;
    let b = p("b", NodeClass::Desktop);
    assert!(matches!(
        acquire(Some(&r), &g, &k, &b, &FRESH, &inc),
        Err(LeaseError::Corrupted)
    ));
    assert!(
        matches!(
            acquire(Some(&r), &g, &k, &b, &FRESH, &|_| Some(0)),
            Err(LeaseError::Corrupted)
        ),
        "a token generator going backwards is refused"
    );
}

#[test]
fn handover_reserves_the_lease_for_the_stronger_node() {
    let (g, k) = ids();
    let phone = p("phone", NodeClass::Phone);
    let desktop = p("desk", NodeClass::Desktop);
    let server = p("srv", NodeClass::Server);
    let r = written(acquire(None, &g, &k, &phone, &FRESH, &inc).unwrap());
    let r = written(request_takeover(Some(&r), &desktop, &FRESH).unwrap());
    assert_eq!(r.takeover.as_ref().unwrap().node, desktop.node);
    let r = written(request_takeover(Some(&r), &server, &FRESH).unwrap());
    assert_eq!(
        r.takeover.as_ref().unwrap().node,
        server.node,
        "a stronger requester replaces a weaker one"
    );
    assert_eq!(
        request_takeover(Some(&r), &desktop, &FRESH).unwrap(),
        Step::Reply(Reply::Takeover(TakeoverOutcome::Refused))
    );
    let lease = r.lease(&g, &k).unwrap();
    let r = written(release(Some(&r), &lease));
    assert_eq!(r.reserved.as_ref().unwrap().node, server.node);
    assert_eq!(
        acquire(Some(&r), &g, &k, &desktop, &FRESH, &inc).unwrap(),
        Step::Reply(Reply::Lease(None))
    );
    let r2 = written(acquire(Some(&r), &g, &k, &server, &FRESH, &inc).unwrap());
    assert_eq!(r2.holder.unwrap().node, server.node);
    assert_eq!(r2.fence, r.fence + 1);
    let dead_server = |n: &NodeId| n.as_str() != "srv";
    let r3 = written(acquire(Some(&r), &g, &k, &desktop, &view(&dead_server, 0), &inc).unwrap());
    assert_eq!(
        r3.holder.unwrap().node,
        desktop.node,
        "a dead reservation does not block"
    );
}

#[test]
fn a_stale_reservation_does_not_block_and_a_drained_requester_does_not_either() {
    let (g, k) = ids();
    let desk = p("desk", NodeClass::Desktop);
    let s1 = p("s1", NodeClass::Server);
    let s2 = p("s2", NodeClass::Server);
    let r = written(acquire(None, &g, &k, &desk, &FRESH, &inc).unwrap());
    let r = written(request_takeover(Some(&r), &s1, &FRESH).unwrap());
    let r = written(release(Some(&r), &r.lease(&g, &k).unwrap()));
    assert_eq!(
        acquire(Some(&r), &g, &k, &s2, &FRESH, &inc).unwrap(),
        Step::Reply(Reply::Lease(None))
    );
    assert_eq!(
        request_takeover(Some(&r), &s2, &FRESH).unwrap(),
        Step::Reply(Reply::Takeover(TakeoverOutcome::Refused))
    );
    assert_eq!(
        acquire(Some(&r), &g, &k, &s2, &view(&all, 2 * TTL), &inc).unwrap(),
        Step::Reply(Reply::Lease(None)),
        "a reservation holds for two time-to-lives"
    );
    assert_eq!(
        written(acquire(Some(&r), &g, &k, &s2, &view(&all, 2 * TTL + 1), &inc).unwrap())
            .holder
            .unwrap()
            .node,
        s2.node,
        "a reservation nobody took within two time-to-lives expires"
    );
    let s1_drained = |n: &NodeId| n.as_str() != "s1";
    assert_eq!(
        written(acquire(Some(&r), &g, &k, &s2, &view(&s1_drained, 0), &inc).unwrap())
            .holder
            .unwrap()
            .node,
        s2.node,
        "a reservation for a node that may not lead does not block"
    );
}

#[test]
fn a_dead_holder_goes_to_the_waiting_stronger_node_not_to_whoever_calls_first() {
    let (g, k) = ids();
    let desk = p("desk", NodeClass::Desktop);
    let srv = p("srv", NodeClass::Server);
    let phone = p("phone", NodeClass::Phone);
    let r = written(acquire(None, &g, &k, &desk, &FRESH, &inc).unwrap());
    let r = written(request_takeover(Some(&r), &srv, &FRESH).unwrap());
    let desk_dead = |n: &NodeId| n.as_str() != "desk";
    assert_eq!(
        acquire(Some(&r), &g, &k, &srv, &view(&desk_dead, TTL), &inc).unwrap(),
        Step::Reply(Reply::Lease(None)),
        "a dead holder whose record changed within the time-to-live still counts as alive"
    );
    let gone = view(&desk_dead, TTL + 1);
    assert_eq!(
        acquire(Some(&r), &g, &k, &phone, &gone, &inc).unwrap(),
        Step::Reply(Reply::Lease(None))
    );
    let got = written(acquire(Some(&r), &g, &k, &srv, &gone, &inc).unwrap());
    assert_eq!(got.holder.unwrap().node, srv.node);
    assert_eq!(
        written(
            acquire(
                Some(&r),
                &g,
                &k,
                &phone,
                &view(&desk_dead, 2 * TTL + 1),
                &inc
            )
            .unwrap()
        )
        .holder
        .unwrap()
        .node,
        phone.node,
        "a takeover nobody completes within two time-to-lives does not block"
    );
}

#[test]
fn every_write_raises_seq_and_tokens_follow_the_shared_rule() {
    let (g, k) = ids();
    let a = p("a", NodeClass::Desktop);
    let s = p("s", NodeClass::Server);
    let r1 = written(acquire(None, &g, &k, &a, &FRESH, &inc).unwrap());
    let r2 = written(request_takeover(Some(&r1), &s, &FRESH).unwrap());
    let r3 = written(release(Some(&r2), &r2.lease(&g, &k).unwrap()));
    assert_eq!((r1.seq, r2.seq, r3.seq), (1, 2, 3));
    assert_eq!(next_token(5, 0, 0), Some(6));
    assert_eq!(next_token(5, 9, 0), Some(10));
    assert_eq!(next_token(5, 0, 2), Some(2000));
    assert_eq!(next_token(u64::MAX, 0, 0), None);
    assert_eq!(next_token(0, u64::MAX, 0), None);
    assert_eq!(next_token(0, 0, -5), Some(1));
}

#[test]
fn asking_again_refreshes_a_stale_request() {
    let (g, k) = ids();
    let desk = p("desk", NodeClass::Desktop);
    let srv = p("srv", NodeClass::Server);
    let r = written(acquire(None, &g, &k, &desk, &FRESH, &inc).unwrap());
    let r = written(request_takeover(Some(&r), &srv, &FRESH).unwrap());
    assert_eq!(
        request_takeover(Some(&r), &srv, &FRESH).unwrap(),
        Step::Reply(Reply::Takeover(TakeoverOutcome::Recorded)),
        "asking again while fresh writes nothing"
    );
    assert!(matches!(
        request_takeover(Some(&r), &srv, &view(&all, TTL + 1)).unwrap(),
        Step::Write(_, _)
    ));
}

#[derive(Debug, Clone)]
enum Op {
    Acquire(usize),
    Takeover(usize),
    ReleaseCurrent,
    ReleaseForgedFence(usize),
    ReleaseForgedNode(usize),
    Kill(usize),
    Revive(usize),
    Reclass(usize, u8),
    Quiet(u8),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0..5usize).prop_map(Op::Acquire),
        (0..5usize).prop_map(Op::Takeover),
        Just(Op::ReleaseCurrent),
        (0..5usize).prop_map(Op::ReleaseForgedFence),
        (0..5usize).prop_map(Op::ReleaseForgedNode),
        (0..5usize).prop_map(Op::Kill),
        (0..5usize).prop_map(Op::Revive),
        ((0..5usize), (0..4u8)).prop_map(|(i, c)| Op::Reclass(i, c)),
        (0..4u8).prop_map(Op::Quiet),
    ]
}

fn class(c: u8) -> NodeClass {
    [
        NodeClass::Server,
        NodeClass::Desktop,
        NodeClass::Phone,
        NodeClass::Blind,
    ][c as usize % 4]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2048, ..ProptestConfig::default() })]
    #[test]
    fn invariants_hold_under_any_sequence(ops in proptest::collection::vec(op(), 1..120)) {
        let (g, k) = ids();
        let mut nodes = vec![
            p("s", NodeClass::Server),
            p("d1", NodeClass::Desktop),
            p("d2", NodeClass::Desktop),
            p("ph", NodeClass::Phone),
            p("bl", NodeClass::Blind),
        ];
        let mut dead = [false; 5];
        let mut quiet = 0u64;
        let mut rec: Option<LeaseRecord> = None;
        let mut max_fence = 0u64;
        let mut granted = std::collections::HashSet::new();
        for o in ops {
            let snapshot = nodes.clone();
            let dead_now = dead;
            let alive_fn = move |n: &NodeId| {
                snapshot.iter().position(|x| &x.node == n).is_some_and(|i| !dead_now[i] && snapshot[i].may_lead())
            };
            let view = View { alive: &alive_fn, quiet_ms: quiet, ttl_ms: TTL };
            let step = match &o {
                Op::Acquire(i) => Some(acquire(rec.as_ref(), &g, &k, &nodes[*i], &view, &inc).unwrap()),
                Op::Takeover(i) => Some(request_takeover(rec.as_ref(), &nodes[*i], &view).unwrap()),
                Op::ReleaseCurrent => rec.as_ref().and_then(|r| r.lease(&g, &k)).map(|l| release(rec.as_ref(), &l)),
                Op::ReleaseForgedFence(i) => rec.as_ref().map(|r| {
                    let forged = Lease {
                        group: g.clone(), key: k.clone(), node: nodes[*i].node.clone(),
                        class: nodes[*i].class, fence: FencingToken(r.fence.wrapping_add(1)), takeover: None,
                    };
                    release(rec.as_ref(), &forged)
                }),
                Op::ReleaseForgedNode(i) => rec.as_ref().and_then(|r| {
                    let holder = r.holder.as_ref()?;
                    (holder.node != nodes[*i].node).then(|| {
                        let forged = Lease {
                            group: g.clone(), key: k.clone(), node: nodes[*i].node.clone(),
                            class: nodes[*i].class, fence: FencingToken(r.fence), takeover: None,
                        };
                        release(rec.as_ref(), &forged)
                    })
                }),
                Op::Kill(i) => { dead[*i] = true; None }
                Op::Revive(i) => { dead[*i] = false; None }
                Op::Reclass(i, c) => { nodes[*i].class = class(*c); None }
                Op::Quiet(q) => { quiet = [0, TTL, TTL + 1, 2 * TTL + 1][*q as usize]; None }
            };
            let before = rec.clone();
            match step {
                Some(Step::Write(next, reply)) => {
                    prop_assert!(LeaseRecord::decode(&next.encode()).is_ok(), "written records stay valid: {next:?}");
                    prop_assert!(next.fence >= max_fence, "tokens never go back");
                    prop_assert_eq!(next.seq, before.as_ref().map_or(1, |b| b.seq + 1), "every write raises seq");
                    prop_assert!(
                        !matches!(o, Op::ReleaseForgedFence(_) | Op::ReleaseForgedNode(_)),
                        "a forged release never writes"
                    );
                    if let Reply::Lease(Some(l)) = &reply {
                        let me = nodes.iter().position(|n| n.node == l.node).unwrap();
                        prop_assert!(nodes[me].may_lead(), "only nodes that may lead get leases");
                        let prev_holder = before.as_ref().and_then(|b| b.holder.as_ref()).map(|h| h.node.clone());
                        if prev_holder.as_ref() != Some(&l.node) {
                            prop_assert!(granted.insert(l.fence.0), "a token is granted once");
                            if let Some(prev) = &prev_holder {
                                prop_assert!(!alive_fn(prev) && quiet > TTL, "a live or freshly written holder is never replaced");
                            }
                            if let Some(b) = &before {
                                let blocker = b.takeover.as_ref().filter(|_| b.holder.is_some())
                                    .or(b.reserved.as_ref());
                                if let Some(w) = blocker {
                                    prop_assert!(
                                        w.node == l.node || !alive_fn(&w.node) || quiet > 2 * TTL,
                                        "a live waiter within its window is never skipped"
                                    );
                                }
                            }
                        }
                    }
                    max_fence = next.fence;
                    rec = Some(next);
                }
                Some(Step::Reply(Reply::Lease(Some(l)))) => {
                    let holder = before.as_ref().and_then(|b| b.holder.as_ref());
                    prop_assert_eq!(holder.map(|h| &h.node), Some(&l.node), "a lease without a write is only a renewal");
                    prop_assert_eq!(holder.map(|h| h.class), Some(l.class));
                }
                _ => {}
            }
        }
    }
}
