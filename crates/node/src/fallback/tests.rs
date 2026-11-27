use std::sync::Arc;

use baton_core::{GroupId, Timestamp};
use baton_group::NodeCert;
use baton_keys::{KemSecret, RecoveryRoot};
use baton_state_memory::MemoryState;
use proptest::prelude::*;
use rowboat_group::{DAY_MS, NodeKeys};

use super::*;

const T0: i64 = 1_800_000_000_000;
const MIN: u64 = 60_000;

fn timing() -> FallbackTiming {
    FallbackTiming::after(Duration::from_millis(5 * MIN))
}

fn keys(member: Option<&Identity>) -> NodeKeys {
    NodeKeys {
        identity: Identity::generate(),
        kem: KemSecret::generate(),
        member: member.cloned(),
    }
}

struct Group {
    m: Arc<Membership>,
    member: Identity,
}

impl Group {
    async fn new() -> Self {
        let member = Identity::generate();
        let now: rowboat_group::Now = Arc::new(|| Timestamp(T0));
        let m = Membership::found(
            Arc::new(MemoryState::new()),
            GroupId::new("gfallback").unwrap(),
            keys(Some(&member)),
            RecoveryRoot::generate().public(),
            RecoveryRoot::generate().public(),
            NodeClass::Desktop,
            Timestamp(T0 + 400 * DAY_MS),
            now,
        )
        .await
        .unwrap();
        Self {
            m: Arc::new(m),
            member,
        }
    }

    async fn add(&self, class: NodeClass) -> Identity {
        let k = keys(None);
        let cert = NodeCert::new(
            &self.member,
            &k.identity,
            k.kem.public(),
            class,
            Timestamp(T0 + 90 * DAY_MS),
        );
        self.m.certify(cert).await.unwrap();
        k.identity
    }
}

#[test]
fn the_server_is_silent_only_after_the_takeover_delay() {
    let mut w = ServerWatch::new(0, timing());
    assert_eq!(w.tick(5 * MIN - 1), None);
    w.contact(4 * MIN);
    assert_eq!(w.tick(5 * MIN + 1), None, "a contact restarts the delay");
    assert_eq!(w.tick(9 * MIN), Some(Change::Fallback(Reason::Silence)));
    assert!(w.in_fallback());
    assert_eq!(w.since(), Some(9 * MIN));
    assert_eq!(w.tick(10 * MIN), None);
}

#[test]
fn a_leaving_notice_skips_the_delay() {
    let mut w = ServerWatch::new(0, timing());
    w.leaving();
    assert_eq!(w.tick(1), Some(Change::Fallback(Reason::Leaving)));
    assert_eq!(w.reason(), Some(Reason::Leaving));
}

#[test]
fn the_server_is_back_only_after_answering_without_a_break() {
    let mut w = ServerWatch::new(0, timing());
    w.tick(5 * MIN);
    let back = w.return_after().as_millis() as u64;
    assert_eq!(back, 75_000);
    w.contact(6 * MIN);
    assert_eq!(w.tick(6 * MIN + back - 1), None);
    w.failed();
    w.contact(6 * MIN + back);
    assert_eq!(
        w.tick(6 * MIN + back + 1),
        None,
        "a break starts the return delay again"
    );
    assert_eq!(w.tick(6 * MIN + 2 * back), Some(Change::Back));
    assert!(!w.in_fallback());
    assert_eq!(w.tick(6 * MIN + 2 * back + 5 * MIN - 1), None);
}

#[test]
fn a_server_that_keeps_coming_and_going_is_trusted_later_each_time() {
    let mut w = ServerWatch::new(0, timing());
    let mut now = 0;
    let mut returns = Vec::new();
    for _ in 0..6 {
        now += 5 * MIN;
        assert!(matches!(w.tick(now), Some(Change::Fallback(_))));
        returns.push(w.return_after());
        w.contact(now);
        now += w.return_after().as_millis() as u64;
        assert_eq!(w.tick(now), Some(Change::Back));
    }
    assert_eq!(returns[0], Duration::from_millis(75_000));
    assert_eq!(returns[1], returns[0] * 2);
    assert_eq!(returns[2], returns[0] * 4);
    assert_eq!(returns[3], returns[0] * 8);
    assert_eq!(returns[5], returns[0] * 8, "capped");
    now += 30 * MIN;
    w.tick(now);
    assert!(w.in_fallback());
    assert_eq!(
        w.return_after(),
        returns[0],
        "a server that stayed a long time is trusted as before"
    );
}

#[test]
fn a_flapping_server_never_ends_the_fallback() {
    let mut w = ServerWatch::new(0, timing());
    w.tick(5 * MIN);
    let mut now = 5 * MIN;
    for _ in 0..100 {
        w.contact(now);
        now += 30_000;
        assert_eq!(w.tick(now), None);
        w.failed();
        now += 30_000;
        assert_eq!(w.tick(now), None);
    }
    assert!(w.in_fallback());
}

#[tokio::test]
async fn only_counting_devices_are_candidates_desktops_first() {
    let g = Group::new().await;
    let founder = g.m.node();
    let server = g.add(NodeClass::Server).await.public();
    let phone = g.add(NodeClass::Phone).await.public();
    let desktop = g.add(NodeClass::Desktop).await.public();
    let revoked = g.add(NodeClass::Desktop).await.public();
    g.m.revoke(&revoked).await.unwrap();
    let c = candidates(&g.m);
    assert!(!c.contains(&server));
    assert!(
        !c.contains(&revoked),
        "a revoked device never arbitrates for the group"
    );
    assert_eq!(c.len(), 3);
    assert_eq!(c[2], phone);
    let mut desktops = [founder, desktop];
    desktops.sort();
    assert_eq!(&c[..2], &desktops[..]);
}

#[tokio::test]
async fn a_leaving_notice_verifies_only_from_the_groups_server() {
    let g = Group::new().await;
    let server = g.add(NodeClass::Server).await;
    let desktop = g.add(NodeClass::Desktop).await;
    let group = g.m.group().as_str().to_owned();
    let good = Leaving::sign(&server, &group, T0);
    assert!(Leaving::verify(&good, &server.public(), &g.m, T0 + 1000).is_some());
    assert!(
        Leaving::verify(&good, &desktop.public(), &g.m, T0).is_none(),
        "relayed by another peer"
    );
    let forged = Leaving::sign(&desktop, &group, T0);
    assert!(
        Leaving::verify(&forged, &desktop.public(), &g.m, T0).is_none(),
        "a device is not the server"
    );
    let stranger = Identity::generate();
    let foreign = Leaving::sign(&stranger, &group, T0);
    assert!(Leaving::verify(&foreign, &stranger.public(), &g.m, T0).is_none());
    let elsewhere = Leaving::sign(&server, "gother", T0);
    assert!(Leaving::verify(&elsewhere, &server.public(), &g.m, T0).is_none());
    assert!(
        Leaving::verify(&good, &server.public(), &g.m, T0 + LEAVING_SKEW_MS + 1).is_none(),
        "a replayed old notice"
    );
    let mut flipped = good.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    assert!(Leaving::verify(&flipped, &server.public(), &g.m, T0).is_none());
    let mut n: Leaving = rowboat_group::wire::decode(&good).unwrap();
    n.at_ms += 1;
    let moved = rowboat_group::wire::encode(&n);
    assert!(Leaving::verify(&moved, &server.public(), &g.m, T0).is_none());
    assert!(Leaving::verify(&[0; MAX_LEAVING + 1], &server.public(), &g.m, T0).is_none());
    g.m.revoke(&server.public()).await.unwrap();
    assert!(
        Leaving::verify(&good, &server.public(), &g.m, T0).is_none(),
        "a revoked server"
    );
}

#[test]
fn the_server_remembers_gaps() {
    let a = Identity::generate().public();
    let b = Identity::generate().public();
    let (gap, window) = (150_000, 20 * MIN as i64);
    let mut w = GapWatch::default();
    assert!(w.silent(&a, 0, gap, window), "never heard of");
    w.observe(a, Some(1_000), gap);
    w.observe(b, Some(1_000), gap);
    assert!(!w.silent(&a, 1_000 + gap - 1, gap, window));
    assert!(w.silent(&a, 1_000 + gap, gap, window), "silent now");
    w.observe(a, Some(1_000 + gap + 10), gap);
    assert!(
        w.silent(&a, 1_000 + gap + 20, gap, window),
        "a long gap that just ended still counts"
    );
    let mut t = 1_000 + gap + 10;
    while t < 1_000 + gap + 10 + window {
        t += 1_000;
        w.observe(a, Some(t), gap);
    }
    assert!(
        !w.silent(&a, t + 1, gap, window),
        "a gap that ended long ago no longer counts"
    );
    w.observe(b, Some(2_000), gap);
    w.observe(b, Some(3_000), gap);
    assert!(
        !w.silent(&b, 3_100, gap, window),
        "a device that kept talking was never silent"
    );
    w.left_gracefully(10_000);
    assert!(w.silent(&b, 3_100, gap, window));
    assert!(!w.silent(&b, 10_000, gap, window));
    w.retain(&[a]);
    assert!(w.silent(&b, 10_000, gap, window), "forgotten");
}

#[test]
fn the_servers_own_downtime_is_no_device_silence_until_the_takeover_delay() {
    let a = Identity::generate().public();
    let (gap, takeover, window) = (8_000, 16_000, 64_000);
    let mut w = GapWatch::default();
    w.observe(a, Some(1_000), gap);
    w.serving_since(12_000, takeover);
    w.serving_since(50_000, 1);
    w.observe(a, Some(1_000), gap);
    assert!(
        !w.silent(&a, 12_500, gap, window),
        "a heartbeat from before the outage is not yet a takeover delay old"
    );
    w.observe(a, Some(13_000), gap);
    assert!(
        !w.silent(&a, 13_100, gap, window),
        "an outage shorter than the takeover delay left no silence"
    );
    let mut long = GapWatch::default();
    long.observe(a, Some(1_000), gap);
    long.serving_since(20_000, takeover);
    assert!(long.silent(&a, 20_000, gap, window));
    long.observe(a, Some(30_000), gap);
    assert!(
        long.silent(&a, 30_100, gap, window),
        "an outage the devices fell back for counts"
    );
    let mut up = GapWatch::default();
    up.serving_since(0, takeover);
    up.observe(a, Some(1_000), gap);
    up.observe(a, Some(1_000 + gap), gap);
    assert!(
        up.silent(&a, 1_000 + gap, gap, window),
        "a gap that began while serving needs only the minimum gap"
    );
}

fn view(
    me: PublicKey,
    holder: Option<(PublicKey, bool)>,
    gaps: bool,
    everyone: bool,
) -> ServerView {
    ServerView {
        me,
        holder,
        gaps,
        everyone,
        newer: true,
    }
}

#[test]
fn which_heads_a_node_admits() {
    use GrantKind::*;
    let server = Identity::generate().public();
    let b = Identity::generate().public();
    let a = Identity::generate().public();
    assert!(admit(Some(Server), Some(Fallback), &b, false, None, false));
    assert!(admit(Some(Server), None, &b, false, None, false));
    assert!(admit(None, None, &b, false, None, false));
    assert!(
        !admit(None, Some(Server), &b, false, None, false),
        "a head without a grant never replaces a server's"
    );
    assert!(!admit(None, Some(Fallback), &b, true, None, false));
    assert!(admit(Some(Fallback), None, &b, false, None, false));
    assert!(admit(
        Some(Fallback),
        Some(Fallback),
        &b,
        false,
        None,
        false
    ));
    assert!(
        !admit(Some(Fallback), Some(Server), &b, false, None, false),
        "a device that sees the server never follows a fallback grant over the server's"
    );
    assert!(admit(Some(Fallback), Some(Server), &b, true, None, false));
    for local in [None, Some(Fallback), Some(Server)] {
        assert!(
            !admit(Some(Fallback), local, &b, false, None, true),
            "a device that sees a live server never follows a fallback grant, whatever it holds"
        );
        assert!(admit(Some(Fallback), local, &b, true, None, true));
    }
    let fresh = |v: ServerView, local| admit(Some(Fallback), local, &b, false, Some(&v), true);
    for local in [None, Some(Fallback)] {
        assert!(
            !fresh(view(server, Some((server, true)), true, false), local),
            "a server without the account's journal, or with a fallback one, judges by its view"
        );
        assert!(fresh(view(server, None, true, false), local));
    }
    let s = |holder, gaps, everyone| view(server, holder, gaps, everyone);
    let on_server = |v: ServerView| admit(Some(Fallback), Some(Server), &b, false, Some(&v), false);
    assert!(on_server(s(None, true, false)));
    assert!(!on_server(s(None, false, true)), "the arbiter kept talking");
    assert!(
        on_server(s(Some((b, true)), true, false)),
        "the holder itself"
    );
    assert!(
        !on_server(s(Some((a, true)), true, true)),
        "another live holder"
    );
    assert!(on_server(s(Some((a, false)), true, false)));
    assert!(
        on_server(s(Some((server, true)), true, true)),
        "a server cut off from every device"
    );
    assert!(
        !on_server(s(Some((server, true)), true, false)),
        "a server other devices still reach"
    );
    let stale = ServerView {
        newer: false,
        ..s(Some((server, true)), true, true)
    };
    assert!(
        !on_server(stale),
        "a fallback grant from before the server's latest grant is replayed"
    );
}

proptest! {
    #[test]
    fn leaving_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..600)) {
        fuzz_leaving(&bytes);
    }

    #[test]
    fn the_watch_never_falls_back_while_the_server_answers(
        steps in prop::collection::vec(1u64..60_000, 1..200)
    ) {
        let mut w = ServerWatch::new(0, timing());
        let mut now = 0;
        for s in steps {
            now += s;
            w.contact(now);
            prop_assert_eq!(w.tick(now), None);
        }
    }
}

#[tokio::test]
async fn a_revoked_device_never_grants_as_fallback_arbiter() {
    let g = Group::new().await;
    let arbiter = g.add(NodeClass::Desktop).await;
    let holder = g.m.node();
    let account = skein_core::AccountId::new("acc").unwrap();
    let head = skein_storage::JournalHead {
        fence: skein_core::FencingToken(9),
        ..skein_storage::JournalHead::empty(skein_core::TenantId::new("t").unwrap(), account)
    };
    let grant = rowboat_sync::Grant::sign(
        &arbiter,
        GrantKind::Fallback,
        g.m.group().as_str(),
        "acc",
        holder,
        9,
    );
    assert!(rowboat_sync::Grant::check(&grant, &g.m, &head, &holder).is_ok());
    g.m.revoke(&arbiter.public()).await.unwrap();
    assert!(
        rowboat_sync::Grant::check(&grant, &g.m, &head, &holder).is_err(),
        "a grant from a revoked arbiter, even one signed before, is refused"
    );
}
