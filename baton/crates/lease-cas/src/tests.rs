use std::sync::atomic::{AtomicI64, Ordering};

use baton_lease::NodeClass;
use baton_lease::testing::{self, Harness, profile};
use baton_state_memory::MemoryState;

use super::*;

const TTL: u64 = 10_000;
const T0: i64 = 1_700_000_000_000;

fn g() -> GroupId {
    GroupId::new("conf-lease").unwrap()
}

fn key(k: &str) -> LeaseKey {
    LeaseKey::new(k).unwrap()
}

fn manual(at: i64) -> (Arc<AtomicI64>, Clock) {
    let a = Arc::new(AtomicI64::new(at));
    let b = a.clone();
    (a, Arc::new(move || Timestamp(b.load(Ordering::SeqCst))))
}

struct H {
    live: Arc<CasLiveness>,
    now: Arc<AtomicI64>,
    registered: Mutex<Vec<NodeProfile>>,
}

impl H {
    fn at(&self) -> Timestamp {
        Timestamp(self.now.load(Ordering::SeqCst))
    }
}

impl Harness for H {
    async fn alive(&self, p: &NodeProfile) {
        self.registered.lock().unwrap().push(p.clone());
        self.live.heartbeat(&g(), p, self.at()).await.unwrap();
    }

    async fn kill(&self, node: &NodeId) {
        self.live.alive(&g(), self.at()).await.unwrap();
        self.registered.lock().unwrap().retain(|p| &p.node != node);
        self.now.fetch_add(TTL as i64 + 1, Ordering::SeqCst);
        let others = self.registered.lock().unwrap().clone();
        for p in &others {
            self.live.heartbeat(&g(), p, self.at()).await.unwrap();
        }
        self.live.alive(&g(), self.at()).await.unwrap();
    }
}

struct Setup {
    state: Arc<MemoryState>,
    live: Arc<CasLiveness>,
    now: Arc<AtomicI64>,
    leases: CasLeases,
}

fn setup() -> Setup {
    let state = Arc::new(MemoryState::new());
    let live = Arc::new(CasLiveness::new(state.clone(), TTL));
    let (now, clock) = manual(T0);
    let leases = CasLeases::new(state.clone(), live.clone()).with_clock(clock);
    Setup {
        state,
        live,
        now,
        leases,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn conformance() {
    let s = setup();
    let h = Arc::new(H {
        live: s.live.clone(),
        now: s.now.clone(),
        registered: Mutex::new(Vec::new()),
    });
    testing::leases(Arc::new(s.leases), h).await;
    testing::liveness(Arc::new(CasLiveness::new(
        Arc::new(MemoryState::new()),
        TTL,
    )))
    .await;
}

#[tokio::test]
async fn a_skewed_observer_cannot_steal_a_live_lease() {
    let state = Arc::new(MemoryState::new());
    let live = Arc::new(CasLiveness::new(state.clone(), TTL));
    let live_b = Arc::new(CasLiveness::new(state.clone(), TTL));
    let (_, ca) = manual(T0);
    let (nb, cb) = manual(T0 + 10 * TTL as i64);
    let la = CasLeases::new(state.clone(), live.clone()).with_clock(ca);
    let lb = CasLeases::new(state.clone(), live_b).with_clock(cb);
    let a = profile("a", NodeClass::Desktop);
    let b = profile("b", NodeClass::Desktop);
    live.heartbeat(&g(), &a, Timestamp(T0)).await.unwrap();
    live.heartbeat(&g(), &b, Timestamp(T0 + 10 * TTL as i64))
        .await
        .unwrap();
    la.acquire(&g(), &key("k"), &a).await.unwrap().unwrap();
    assert!(
        lb.acquire(&g(), &key("k"), &b).await.unwrap().is_none(),
        "a heartbeat that is new to the observer counts, whatever its timestamp"
    );
    nb.fetch_add(TTL as i64, Ordering::SeqCst);
    live.heartbeat(&g(), &a, Timestamp(T0 - 100 * TTL as i64))
        .await
        .unwrap();
    assert!(
        lb.acquire(&g(), &key("k"), &b).await.unwrap().is_none(),
        "a holder whose clock is far behind stays alive while it heartbeats"
    );
    nb.fetch_add(TTL as i64 + 1, Ordering::SeqCst);
    assert!(
        lb.acquire(&g(), &key("k"), &b).await.unwrap().is_some(),
        "once a holder stops, it is gone after the time-to-live of the observer's clock"
    );
}

#[tokio::test]
async fn hostile_heartbeat_timestamps_never_panic() {
    let s = setup();
    for (n, at) in [("min", i64::MIN), ("max", i64::MAX), ("zero", 0)] {
        let p = profile(n, NodeClass::Desktop);
        let bytes = serde_json::to_vec(&serde_json::json!({"v":1,"profile":p,"at":at})).unwrap();
        s.state.tamper(
            &g(),
            &RecordName::new(format!("nodes/{n}")).unwrap(),
            Bytes::from(bytes),
        );
    }
    let alive = s.live.alive(&g(), Timestamp(i64::MAX)).await.unwrap();
    assert_eq!(alive.len(), 3);
    let alive = s.live.alive(&g(), Timestamp(i64::MIN)).await.unwrap();
    assert_eq!(
        alive.len(),
        3,
        "time going backwards on the observer never panics"
    );
    s.leases
        .acquire(&g(), &key("k"), &profile("x", NodeClass::Server))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_reservation_nobody_takes_expires_and_a_drained_requester_does_not_block() {
    let s = setup();
    let desk = profile("desk", NodeClass::Desktop);
    let s1 = profile("s1", NodeClass::Server);
    let s2 = profile("s2", NodeClass::Server);
    for p in [&desk, &s1, &s2] {
        s.live.heartbeat(&g(), p, Timestamp(T0)).await.unwrap();
    }
    let k = key("k");
    s.leases.acquire(&g(), &k, &desk).await.unwrap().unwrap();
    assert_eq!(
        s.leases.request_takeover(&g(), &k, &s1).await.unwrap(),
        TakeoverOutcome::Recorded
    );
    let r = s.leases.acquire(&g(), &k, &desk).await.unwrap().unwrap();
    s.leases.release(&r).await.unwrap();
    assert!(
        s.leases.acquire(&g(), &k, &s2).await.unwrap().is_none(),
        "reserved for s1"
    );

    let s1_drained = NodeProfile {
        weight: 0,
        ..s1.clone()
    };
    s.live
        .heartbeat(&g(), &s1_drained, Timestamp(T0))
        .await
        .unwrap();
    assert!(
        s.leases.acquire(&g(), &k, &s2).await.unwrap().is_some(),
        "a reservation for a node that announced it may not lead does not block"
    );

    let k2 = key("k2");
    s.leases.acquire(&g(), &k2, &desk).await.unwrap().unwrap();
    let s3 = profile("s3", NodeClass::Server);
    s.live.heartbeat(&g(), &s3, Timestamp(T0)).await.unwrap();
    assert_eq!(
        s.leases.request_takeover(&g(), &k2, &s3).await.unwrap(),
        TakeoverOutcome::Recorded
    );
    let r = s.leases.acquire(&g(), &k2, &desk).await.unwrap().unwrap();
    s.leases.release(&r).await.unwrap();
    assert!(s.leases.acquire(&g(), &k2, &s2).await.unwrap().is_none());
    s.now.fetch_add(2 * TTL as i64 + 1, Ordering::SeqCst);
    for p in [&desk, &s2, &s3] {
        s.live.heartbeat(&g(), p, Timestamp(0)).await.unwrap();
    }
    assert!(
        s.leases.acquire(&g(), &k2, &s2).await.unwrap().is_some(),
        "a live requester that never acquires blocks the key for at most two time-to-lives"
    );
}

#[tokio::test]
async fn a_dead_holder_goes_to_the_waiting_stronger_node() {
    let s = setup();
    let desk = profile("desk", NodeClass::Desktop);
    let srv = profile("srv", NodeClass::Server);
    let phone = profile("phone", NodeClass::Phone);
    for p in [&desk, &srv, &phone] {
        s.live.heartbeat(&g(), p, Timestamp(T0)).await.unwrap();
    }
    let k = key("k");
    s.leases.acquire(&g(), &k, &desk).await.unwrap().unwrap();
    assert_eq!(
        s.leases.request_takeover(&g(), &k, &srv).await.unwrap(),
        TakeoverOutcome::Recorded
    );
    let desk_off = NodeProfile {
        can_run: false,
        ..desk.clone()
    };
    s.live
        .heartbeat(&g(), &desk_off, Timestamp(T0))
        .await
        .unwrap();
    assert!(
        s.leases.acquire(&g(), &k, &srv).await.unwrap().is_none(),
        "a holder whose record just changed still counts as alive"
    );
    s.now.fetch_add(TTL as i64 + 1, Ordering::SeqCst);
    for p in [&desk_off, &srv, &phone] {
        s.live.heartbeat(&g(), p, Timestamp(0)).await.unwrap();
    }
    assert!(s.leases.acquire(&g(), &k, &phone).await.unwrap().is_none());
    assert_eq!(
        s.leases
            .acquire(&g(), &k, &srv)
            .await
            .unwrap()
            .unwrap()
            .node,
        srv.node
    );
}

#[tokio::test]
async fn tokens_survive_a_restart_and_a_lost_record() {
    let live: Arc<dyn Liveness> = Arc::new(CasLiveness::new(Arc::new(MemoryState::new()), TTL));
    let p = profile("solo", NodeClass::Desktop);
    let (_, c1) = manual(T0);
    let first = CasLeases::new(Arc::new(MemoryState::new()), live.clone()).with_clock(c1);
    let mut last = 0;
    for i in 0..1000 {
        last = first
            .acquire(&g(), &key(&format!("k{i}")), &p)
            .await
            .unwrap()
            .unwrap()
            .fence
            .0;
    }
    let (_, c2) = manual(T0 + 500);
    let second = CasLeases::new(Arc::new(MemoryState::new()), live).with_clock(c2);
    let after = second
        .acquire(&g(), &key("k999"), &p)
        .await
        .unwrap()
        .unwrap()
        .fence
        .0;
    assert!(
        after > last,
        "after a restart 500 ms later: {after} must exceed {last}"
    );

    let s = setup();
    let a = profile("a", NodeClass::Desktop);
    s.live.heartbeat(&g(), &a, Timestamp(T0)).await.unwrap();
    let before = s
        .leases
        .acquire(&g(), &key("lost"), &a)
        .await
        .unwrap()
        .unwrap()
        .fence;
    s.state
        .delete(&g(), &RecordName::new("lease/lost").unwrap(), Expect::Any)
        .await
        .unwrap();
    s.now.fetch_add(1, Ordering::SeqCst);
    let again = s
        .leases
        .acquire(&g(), &key("lost"), &a)
        .await
        .unwrap()
        .unwrap()
        .fence;
    assert!(again > before, "a lost record does not reset the token");
}

struct Capped(MemoryState);

#[async_trait]
impl StateStore for Capped {
    async fn get(
        &self,
        g: &GroupId,
        n: &RecordName,
    ) -> Result<Option<(Bytes, Version)>, StateError> {
        self.0.get(g, n).await
    }
    async fn put(
        &self,
        g: &GroupId,
        n: &RecordName,
        v: Bytes,
        e: Expect,
    ) -> Result<Version, StateError> {
        self.0.put(g, n, v, e).await
    }
    async fn delete(&self, g: &GroupId, n: &RecordName, e: Expect) -> Result<(), StateError> {
        self.0.delete(g, n, e).await
    }
    async fn list(
        &self,
        g: &GroupId,
        p: &RecordName,
        a: Option<&RecordName>,
        l: usize,
    ) -> Result<Vec<RecordName>, StateError> {
        self.0.list(g, p, a, l.min(3)).await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn short_pages_do_not_hide_live_nodes() {
    baton_state::testing::state(Arc::new(Capped(MemoryState::new()))).await;
    let live = CasLiveness::new(Arc::new(Capped(MemoryState::new())), TTL);
    for n in ["a", "b", "c", "d", "e", "f", "g"] {
        live.heartbeat(&g(), &profile(n, NodeClass::Server), Timestamp(T0))
            .await
            .unwrap();
    }
    assert_eq!(live.alive(&g(), Timestamp(T0)).await.unwrap().len(), 7);
}

#[tokio::test]
async fn liveness_of_one_group_never_counts_for_another() {
    let s = setup();
    let other = GroupId::new("other").unwrap();
    let a = profile("a", NodeClass::Desktop);
    let b = profile("b", NodeClass::Desktop);
    s.live.heartbeat(&other, &a, Timestamp(T0)).await.unwrap();
    s.live.heartbeat(&g(), &b, Timestamp(T0)).await.unwrap();
    s.leases
        .acquire(&g(), &key("k"), &a)
        .await
        .unwrap()
        .unwrap();
    s.now.fetch_add(TTL as i64 + 1, Ordering::SeqCst);
    s.live.heartbeat(&other, &a, Timestamp(0)).await.unwrap();
    s.live.heartbeat(&g(), &b, Timestamp(0)).await.unwrap();
    assert!(
        s.leases
            .acquire(&g(), &key("k"), &b)
            .await
            .unwrap()
            .is_some(),
        "a holder alive only in another group is gone here"
    );
}

#[tokio::test]
async fn a_corrupted_record_grants_nothing() {
    let s = setup();
    let p = profile("victim", NodeClass::Server);
    s.live.heartbeat(&g(), &p, Timestamp(T0)).await.unwrap();
    let k = key("tampered");
    let name = RecordName::new("lease/tampered").unwrap();
    for junk in [
        &b"garbage"[..],
        b"{\"v\":9,\"holder\":null,\"fence\":5,\"takeover\":null,\"reserved\":null,\"seq\":0}",
        b"{\"v\":1,\"holder\":{\"node\":\"victim\",\"class\":\"blind\"},\"fence\":5,\"takeover\":null,\"reserved\":null,\"seq\":0}",
    ] {
        s.state.tamper(&g(), &name, Bytes::copy_from_slice(junk));
        assert!(matches!(s.leases.acquire(&g(), &k, &p).await, Err(LeaseError::Corrupted)));
        assert!(matches!(s.leases.holder(&g(), &k).await, Err(LeaseError::Corrupted)));
        assert_eq!(&s.state.get(&g(), &name).await.unwrap().unwrap().0[..], junk);
    }
    s.state.tamper(
        &g(),
        &name,
        Bytes::from_static(b"{\"v\":1,\"holder\":null,\"fence\":18446744073709551615,\"takeover\":null,\"reserved\":null,\"seq\":0}"),
    );
    assert!(
        matches!(
            s.leases.acquire(&g(), &k, &p).await,
            Err(LeaseError::Corrupted)
        ),
        "a token at the top refuses instead of wrapping to a low token"
    );
}

#[tokio::test]
async fn heartbeats_cannot_speak_for_another_node() {
    let s = setup();
    let victim = profile("victim", NodeClass::Server);
    let beat = |p: &NodeProfile| {
        Bytes::from(serde_json::to_vec(&serde_json::json!({"v":1,"profile":p,"at":T0})).unwrap())
    };
    s.state.tamper(
        &g(),
        &RecordName::new("nodes/mallory").unwrap(),
        beat(&victim),
    );
    let mut big = serde_json::to_vec(
        &serde_json::json!({"v":1,"profile":profile("big", NodeClass::Desktop),"at":T0}),
    )
    .unwrap();
    big.resize(MAX_HEARTBEAT + 10, b' ');
    s.state.tamper(
        &g(),
        &RecordName::new("nodes/big").unwrap(),
        Bytes::from(big),
    );
    s.state.tamper(
        &g(),
        &RecordName::new("nodes/junk").unwrap(),
        Bytes::from_static(b"\xff\x00"),
    );
    let extra = serde_json::to_vec(
        &serde_json::json!({"v":1,"profile":profile("extra", NodeClass::Desktop),"at":T0,"x":1}),
    )
    .unwrap();
    s.state.tamper(
        &g(),
        &RecordName::new("nodes/extra").unwrap(),
        Bytes::from(extra),
    );
    let v2 = serde_json::to_vec(
        &serde_json::json!({"v":2,"profile":profile("v2", NodeClass::Desktop),"at":T0}),
    )
    .unwrap();
    s.state
        .tamper(&g(), &RecordName::new("nodes/v2").unwrap(), Bytes::from(v2));
    assert!(s.live.alive(&g(), Timestamp(T0)).await.unwrap().is_empty());
}

struct Failing;

#[async_trait]
impl StateStore for Failing {
    async fn get(
        &self,
        _: &GroupId,
        _: &RecordName,
    ) -> Result<Option<(Bytes, Version)>, StateError> {
        Err(StateError::backend("down"))
    }
    async fn put(
        &self,
        _: &GroupId,
        _: &RecordName,
        _: Bytes,
        _: Expect,
    ) -> Result<Version, StateError> {
        Err(StateError::backend("down"))
    }
    async fn delete(&self, _: &GroupId, _: &RecordName, _: Expect) -> Result<(), StateError> {
        Err(StateError::backend("down"))
    }
    async fn list(
        &self,
        _: &GroupId,
        _: &RecordName,
        _: Option<&RecordName>,
        _: usize,
    ) -> Result<Vec<RecordName>, StateError> {
        Err(StateError::backend("down"))
    }
}

#[tokio::test]
async fn a_failing_store_grants_nothing() {
    let leases = CasLeases::new(
        Arc::new(Failing),
        Arc::new(CasLiveness::new(Arc::new(Failing), TTL)),
    );
    let p = profile("a", NodeClass::Server);
    assert!(matches!(
        leases.acquire(&g(), &key("k"), &p).await,
        Err(LeaseError::Backend(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn conformance_with_reused_liveness_answers() {
    let s = setup();
    let h = Arc::new(H {
        live: s.live.clone(),
        now: s.now.clone(),
        registered: Mutex::new(Vec::new()),
    });
    testing::leases(Arc::new(s.leases.reuse_alive_for(TTL / 4)), h).await;
}

struct CountingLiveness {
    inner: Arc<CasLiveness>,
    asked: std::sync::atomic::AtomicU64,
}

#[async_trait]
impl Liveness for CountingLiveness {
    async fn heartbeat(
        &self,
        group: &GroupId,
        profile: &NodeProfile,
        now: Timestamp,
    ) -> Result<(), LeaseError> {
        self.inner.heartbeat(group, profile, now).await
    }

    async fn alive(&self, group: &GroupId, now: Timestamp) -> Result<Vec<NodeProfile>, LeaseError> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        self.inner.alive(group, now).await
    }

    fn ttl_ms(&self) -> u64 {
        self.inner.ttl_ms()
    }
}

#[tokio::test]
async fn reused_answers_ask_liveness_once_per_interval_for_many_leases() {
    let state = Arc::new(MemoryState::new());
    let live = Arc::new(CountingLiveness {
        inner: Arc::new(CasLiveness::new(state.clone(), TTL)),
        asked: Default::default(),
    });
    let (now, clock) = manual(T0);
    let leases = CasLeases::new(state, live.clone())
        .with_clock(clock)
        .reuse_alive_for(60_000);
    let a = profile("node-a", NodeClass::Server);
    live.heartbeat(&g(), &a, Timestamp(T0)).await.unwrap();
    for tick in 0..4 {
        for i in 0..100 {
            leases
                .acquire(&g(), &key(&format!("k{i}")), &a)
                .await
                .unwrap()
                .expect("free or own");
        }
        assert_eq!(
            live.asked.load(Ordering::SeqCst),
            tick + 1,
            "one liveness answer per interval, clamped to a quarter of the ttl"
        );
        now.fetch_add((TTL / 4) as i64, Ordering::SeqCst);
        live.heartbeat(&g(), &a, Timestamp(now.load(Ordering::SeqCst)))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn a_reused_answer_never_outlives_a_quarter_ttl_so_a_dead_holder_still_moves() {
    let s = setup();
    let leases = s.leases.reuse_alive_for(u64::MAX);
    let a = profile("node-a", NodeClass::Server);
    let b = profile("node-b", NodeClass::Server);
    s.live.heartbeat(&g(), &a, Timestamp(T0)).await.unwrap();
    s.live.heartbeat(&g(), &b, Timestamp(T0)).await.unwrap();
    let held = leases.acquire(&g(), &key("x"), &a).await.unwrap().unwrap();
    assert!(leases.acquire(&g(), &key("x"), &b).await.unwrap().is_none());
    for _ in 0..12 {
        s.now.fetch_add((TTL / 4) as i64, Ordering::SeqCst);
        let t = Timestamp(s.now.load(Ordering::SeqCst));
        s.live.heartbeat(&g(), &b, t).await.unwrap();
    }
    let taken = leases
        .acquire(&g(), &key("x"), &b)
        .await
        .unwrap()
        .expect("the dead holder's lease moves although answers are reused");
    assert!(taken.fence > held.fence);
}
