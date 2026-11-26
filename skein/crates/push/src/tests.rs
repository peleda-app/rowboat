use std::sync::Mutex;

use async_trait::async_trait;
use base64::Engine;
use baton_signal_local::LocalSignal;
use futures::StreamExt;
use skein_core::coordination::group;
use skein_mail::MailSession;
use skein_storage::Storage;
use skein_storage_memory::MemoryObjects;

use super::*;

const DAY: i64 = 24 * 3600 * 1000;

fn t(id: &str) -> TenantId {
    TenantId::new(id).unwrap()
}

fn a(id: &str) -> AccountId {
    AccountId::new(id).unwrap()
}

fn registry() -> PushRegistry {
    let objects: Arc<dyn Objects> = Arc::new(MemoryObjects::new());
    let storage = Storage::over(objects.clone());
    PushRegistry::new(objects, storage.control)
}

fn graph_sub(id: &str, expires_at: i64) -> Subscription {
    Subscription {
        id: id.into(),
        provider_kind: PUSH_GRAPH.into(),
        expires_at: Timestamp(expires_at),
        resource: "me/messages".into(),
    }
}

fn gmail_sub(email: &str, expires_at: i64) -> Subscription {
    Subscription {
        id: "1000".into(),
        provider_kind: PUSH_GMAIL.into(),
        expires_at: Timestamp(expires_at),
        resource: email.into(),
    }
}

fn target(state: &str) -> PushTarget {
    PushTarget {
        url: "https://skein.example.com/v1/push/graph".into(),
        client_state: state.into(),
        gmail_topic: None,
    }
}

#[tokio::test]
async fn registry_round_trip() {
    let r = registry();
    let sub = graph_sub("7f105c7d-2dc5-4530-97cd-4e7ae6534c07", 10 * DAY);
    r.register(&sub, &t("acme"), &a("box"), "secret-state")
        .await
        .unwrap();
    assert_eq!(
        r.lookup_graph(&sub.id, "secret-state").await.unwrap(),
        Some((t("acme"), a("box")))
    );
    for wrong in ["", "secret-statf", "secret-state-", "SECRET-STATE", "s"] {
        assert_eq!(
            r.lookup_graph(&sub.id, wrong).await.unwrap(),
            None,
            "{wrong}"
        );
    }
    for id in ["unknown", "../escape", "", "a/b", ".hidden"] {
        assert_eq!(r.lookup_graph(id, "secret-state").await.unwrap(), None);
    }

    let gmail = gmail_sub("Ada.Lovelace@Example.com", 7 * DAY);
    r.register(&gmail, &t("acme"), &a("mail"), "ignored")
        .await
        .unwrap();
    assert_eq!(
        r.lookup_gmail(" ada.lovelace@example.com").await.unwrap(),
        Some((t("acme"), a("mail")))
    );
    assert_eq!(r.lookup_gmail("bob@example.org").await.unwrap(), None);

    let keys = r
        .objects
        .list(&ObjectKey::root("system").unwrap(), None, 100)
        .await
        .unwrap();
    let text = format!("{keys:?}");
    assert!(!text.to_lowercase().contains("ada"), "{text}");
    for key in &keys {
        let (bytes, _) = r.objects.get(key).await.unwrap().unwrap();
        let body = String::from_utf8_lossy(&bytes).to_lowercase();
        assert!(
            !body.contains("secret-state") && !body.contains("ada"),
            "{body}"
        );
    }

    r.remove(&gmail, &t("other"), &a("mail")).await.unwrap();
    assert!(
        r.lookup_gmail("ada.lovelace@example.com")
            .await
            .unwrap()
            .is_some()
    );
    r.remove(&gmail, &t("acme"), &a("mail")).await.unwrap();
    assert!(
        r.lookup_gmail("ada.lovelace@example.com")
            .await
            .unwrap()
            .is_none()
    );
    r.remove(&sub, &t("acme"), &a("box")).await.unwrap();
    r.remove(&sub, &t("acme"), &a("box")).await.unwrap();
    assert_eq!(r.lookup_graph(&sub.id, "secret-state").await.unwrap(), None);

    let other = Subscription {
        provider_kind: "jmap".into(),
        ..graph_sub("x", 0)
    };
    assert!(matches!(
        r.register(&other, &t("acme"), &a("box"), "s").await,
        Err(PushError::Unsupported)
    ));
}

#[test]
fn parses_graph_posts() {
    let body = br#"{"value":[
        {"subscriptionId":"s1","clientState":"c1","changeType":"created","resource":"Users/x/Messages/y","tenantId":"z"},
        {"subscriptionId":"s2","clientState":"c2","lifecycleEvent":"reauthorizationRequired"},
        {"clientState":"no-id"},
        {"subscriptionId":""}
    ]}"#;
    let items = parse_graph(body).unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].subscription_id, "s1");
    assert_eq!(items[0].client_state.as_deref(), Some("c1"));
    assert_eq!(
        items[1].lifecycle_event.as_deref(),
        Some("reauthorizationRequired")
    );
    assert!(!format!("{items:?}").contains("c1"));
    for bad in [&b"[]"[..], b"{}", b"not json", br#"{"value":{}}"#] {
        assert!(matches!(parse_graph(bad), Err(PushError::Invalid)));
    }
    let many = format!(
        "{{\"value\":[{}]}}",
        vec![r#"{"subscriptionId":"s","clientState":"c"}"#; MAX_GRAPH_ITEMS + 5].join(",")
    );
    assert_eq!(parse_graph(many.as_bytes()).unwrap().len(), MAX_GRAPH_ITEMS);
}

#[test]
fn checks_validation_tokens() {
    assert_eq!(
        validation_token("Validation: Testing client application reachability"),
        Some("Validation: Testing client application reachability")
    );
    assert_eq!(validation_token(""), None);
    assert_eq!(validation_token("a\nb"), None);
    assert_eq!(validation_token("<script>\u{7f}"), None);
    assert_eq!(validation_token("é"), None);
    assert!(validation_token(&"x".repeat(MAX_VALIDATION_TOKEN)).is_some());
    assert!(validation_token(&"x".repeat(MAX_VALIDATION_TOKEN + 1)).is_none());
}

pub(crate) fn gmail_envelope(email: &str, history: serde_json::Value) -> Vec<u8> {
    let data = serde_json::json!({ "emailAddress": email, "historyId": history }).to_string();
    serde_json::json!({
        "message": {
            "data": base64::engine::general_purpose::STANDARD.encode(data),
            "messageId": "2070443601311540",
            "publishTime": "2026-11-21T10:00:00Z",
        },
        "subscription": "projects/acme-mail/subscriptions/skein-push",
    })
    .to_string()
    .into_bytes()
}

#[test]
fn parses_gmail_envelopes() {
    let n = parse_gmail(&gmail_envelope(
        "ada@example.com",
        serde_json::json!(9876543210u64),
    ))
    .unwrap();
    assert_eq!(n.email, "ada@example.com");
    assert_eq!(n.history_id, Some(9_876_543_210));
    assert!(!format!("{n:?}").contains("ada"));
    let n = parse_gmail(&gmail_envelope("ada@example.com", serde_json::json!("12"))).unwrap();
    assert_eq!(n.history_id, Some(12));
    let url_safe = serde_json::json!({"message": {"data": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"emailAddress":"bob@example.org"}"#)}});
    assert_eq!(
        parse_gmail(url_safe.to_string().as_bytes()).unwrap().email,
        "bob@example.org"
    );
    for bad in [
        b"{}".to_vec(),
        br#"{"message":{}}"#.to_vec(),
        br#"{"message":{"data":"!!!"}}"#.to_vec(),
        gmail_envelope("not-an-address", serde_json::json!(1)),
    ] {
        assert!(matches!(parse_gmail(&bad), Err(PushError::Invalid)));
    }
}

#[tokio::test]
async fn accepted_notifications_publish_one_hint_per_account() {
    let r = registry();
    let eph = LocalSignal::new();
    let mut hints = eph.subscribe(&group(&t("acme")), "push/box").await.unwrap();
    let mut mail_hints = eph
        .subscribe(&group(&t("acme")), "push/mail")
        .await
        .unwrap();
    r.register(&graph_sub("s1", DAY), &t("acme"), &a("box"), "c1")
        .await
        .unwrap();
    r.register(
        &gmail_sub("ada@example.com", DAY),
        &t("acme"),
        &a("mail"),
        "",
    )
    .await
    .unwrap();
    let body = br#"{"value":[
        {"subscriptionId":"s1","clientState":"c1"},
        {"subscriptionId":"s1","clientState":"c1"},
        {"subscriptionId":"s1","clientState":"wrong"},
        {"subscriptionId":"s1"},
        {"subscriptionId":"nope","clientState":"c1"}
    ]}"#;
    let got = r.accept_graph(body, &eph).await.unwrap();
    assert_eq!(
        got,
        Accepted {
            received: 5,
            hinted: 1
        }
    );
    assert_eq!(&hints.next().await.unwrap()[..], br#"{"provider":"graph"}"#);

    let got = r
        .accept_gmail(
            &gmail_envelope("ADA@example.com", serde_json::json!(5)),
            &eph,
        )
        .await
        .unwrap();
    assert_eq!(got.hinted, 1);
    assert_eq!(
        &mail_hints.next().await.unwrap()[..],
        br#"{"provider":"gmail"}"#
    );
    let got = r
        .accept_gmail(
            &gmail_envelope("eve@example.org", serde_json::json!(5)),
            &eph,
        )
        .await
        .unwrap();
    assert_eq!(got.hinted, 0);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), hints.next())
            .await
            .is_err()
    );
}

#[derive(Default)]
struct FakeState {
    clock: i64,
    lifetime: i64,
    next: u32,
    live: Vec<Subscription>,
    subscribes: u32,
    renews: u32,
    unsubscribes: u32,
    forget_on_renew: bool,
    fail_renew: bool,
    unsupported: bool,
    kind: &'static str,
    states: Vec<String>,
}

#[derive(Default)]
struct FakeProvider {
    st: Mutex<FakeState>,
}

impl FakeProvider {
    fn graph(lifetime: i64) -> Self {
        Self {
            st: Mutex::new(FakeState {
                lifetime,
                kind: PUSH_GRAPH,
                ..Default::default()
            }),
        }
    }

    fn set_clock(&self, now: i64) {
        self.st.lock().unwrap().clock = now;
    }

    fn make(st: &mut FakeState) -> Subscription {
        st.next += 1;
        let sub = match st.kind {
            PUSH_GMAIL => gmail_sub("ada@example.com", st.clock + st.lifetime),
            _ => graph_sub(&format!("sub-{}", st.next), st.clock + st.lifetime),
        };
        let gmail = st.kind == PUSH_GMAIL;
        st.live.retain(|s| !gmail || s.resource != sub.resource);
        st.live.push(sub.clone());
        sub
    }
}

#[async_trait]
impl MailProvider for FakeProvider {
    async fn connect(&self) -> Result<Box<dyn MailSession>, MailError> {
        Err(MailError::Config("not used".into()))
    }

    async fn subscribe(&self, target: &PushTarget) -> Result<Option<Subscription>, MailError> {
        let mut st = self.st.lock().unwrap();
        if st.unsupported {
            return Ok(None);
        }
        st.subscribes += 1;
        st.states.push(target.client_state.clone());
        Ok(Some(Self::make(&mut st)))
    }

    async fn renew(
        &self,
        sub: &Subscription,
        target: &PushTarget,
    ) -> Result<Option<Subscription>, MailError> {
        let mut st = self.st.lock().unwrap();
        if st.fail_renew {
            return Err(MailError::Network("down".into()));
        }
        st.renews += 1;
        let clock = st.clock;
        let lifetime = st.lifetime;
        let known = !st.forget_on_renew && st.live.iter().any(|s| s.id == sub.id);
        if known && st.kind == PUSH_GRAPH {
            let live = st.live.iter_mut().find(|s| s.id == sub.id).unwrap();
            live.expires_at = Timestamp(clock + lifetime);
            return Ok(Some(live.clone()));
        }
        st.live.retain(|s| s.id != sub.id);
        st.states.push(target.client_state.clone());
        Ok(Some(Self::make(&mut st)))
    }

    async fn unsubscribe(&self, sub: &Subscription) -> Result<(), MailError> {
        let mut st = self.st.lock().unwrap();
        st.unsubscribes += 1;
        st.live.retain(|s| s.id != sub.id);
        Ok(())
    }
}

#[tokio::test]
async fn renews_once_a_third_of_the_lifetime_is_left() {
    let r = registry();
    let renewer = Renewer::new(r.clone());
    let p = FakeProvider::graph(3 * DAY);
    let (tn, ac) = (t("acme"), a("box"));
    let start = 1_000 * DAY;
    p.set_clock(start);

    assert!(r.due_for_renewal(&tn, &ac, Timestamp(start)).await.unwrap());
    let sub = match renewer
        .ensure(&p, &tn, &ac, &target("first"), Timestamp(start))
        .await
        .unwrap()
    {
        Ensured::Subscribed(s) => s,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        r.lookup_graph(&sub.id, "first").await.unwrap(),
        Some((tn.clone(), ac.clone()))
    );
    assert_eq!(
        renewer.next_check(&tn, &ac).await.unwrap(),
        Some(Timestamp(start + 2 * DAY))
    );

    for at in [start + 1, start + DAY, start + 2 * DAY - 1] {
        p.set_clock(at);
        assert!(!r.due_for_renewal(&tn, &ac, Timestamp(at)).await.unwrap());
        assert!(matches!(
            renewer
                .ensure(&p, &tn, &ac, &target("unused"), Timestamp(at))
                .await
                .unwrap(),
            Ensured::Current(_)
        ));
    }
    assert_eq!(p.st.lock().unwrap().renews, 0);

    let at = start + 2 * DAY;
    p.set_clock(at);
    assert!(r.due_for_renewal(&tn, &ac, Timestamp(at)).await.unwrap());
    let renewed = match renewer
        .ensure(&p, &tn, &ac, &target("second"), Timestamp(at))
        .await
        .unwrap()
    {
        Ensured::Renewed(s) => s,
        other => panic!("{other:?}"),
    };
    assert_eq!(renewed.id, sub.id);
    assert_eq!(renewed.expires_at, Timestamp(at + 3 * DAY));
    assert_eq!(
        r.lookup_graph(&sub.id, "first").await.unwrap(),
        Some((tn.clone(), ac.clone())),
        "a renewal keeps the client state Graph holds"
    );
    assert_eq!(r.lookup_graph(&sub.id, "second").await.unwrap(), None);
    assert_eq!(
        renewer.next_check(&tn, &ac).await.unwrap(),
        Some(Timestamp(at + 2 * DAY))
    );
    let st = p.st.lock().unwrap();
    assert_eq!((st.subscribes, st.renews), (1, 1));
}

#[tokio::test]
async fn a_forgotten_subscription_is_replaced_and_rerouted() {
    let r = registry();
    let renewer = Renewer::new(r.clone());
    let p = FakeProvider::graph(3 * DAY);
    let (tn, ac) = (t("acme"), a("box"));
    p.set_clock(0);
    let Ensured::Subscribed(old) = renewer
        .ensure(&p, &tn, &ac, &target("one"), Timestamp(0))
        .await
        .unwrap()
    else {
        panic!()
    };
    p.st.lock().unwrap().forget_on_renew = true;
    p.set_clock(4 * DAY);
    let Ensured::Renewed(new) = renewer
        .ensure(&p, &tn, &ac, &target("two"), Timestamp(4 * DAY))
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_ne!(new.id, old.id);
    assert_eq!(r.lookup_graph(&old.id, "one").await.unwrap(), None);
    assert_eq!(
        r.lookup_graph(&new.id, "two").await.unwrap(),
        Some((tn, ac))
    );
}

#[tokio::test]
async fn failures_keep_the_old_subscription_and_lifecycle_forces_renewal() {
    let r = registry();
    let renewer = Renewer::new(r.clone());
    let p = FakeProvider::graph(3 * DAY);
    let (tn, ac) = (t("acme"), a("box"));
    let Ensured::Subscribed(sub) = renewer
        .ensure(&p, &tn, &ac, &target("one"), Timestamp(0))
        .await
        .unwrap()
    else {
        panic!()
    };
    p.st.lock().unwrap().fail_renew = true;
    assert!(
        renewer
            .ensure(&p, &tn, &ac, &target("one"), Timestamp(2 * DAY))
            .await
            .is_err()
    );
    assert!(r.lookup_graph(&sub.id, "one").await.unwrap().is_some());
    assert!(
        r.due_for_renewal(&tn, &ac, Timestamp(2 * DAY))
            .await
            .unwrap()
    );
    p.st.lock().unwrap().fail_renew = false;

    let eph = LocalSignal::new();
    let mut hints = eph.subscribe(&group(&tn), "push/box").await.unwrap();
    assert!(!r.due_for_renewal(&tn, &ac, Timestamp(DAY)).await.unwrap());
    let body = format!(
        r#"{{"value":[{{"subscriptionId":"{}","clientState":"one","lifecycleEvent":"reauthorizationRequired"}}]}}"#,
        sub.id
    );
    assert_eq!(
        r.accept_graph(body.as_bytes(), &eph).await.unwrap().hinted,
        1
    );
    hints.next().await.unwrap();
    assert!(r.due_for_renewal(&tn, &ac, Timestamp(DAY)).await.unwrap());
    assert!(matches!(
        renewer
            .ensure(&p, &tn, &ac, &target("one"), Timestamp(DAY))
            .await
            .unwrap(),
        Ensured::Renewed(_)
    ));
    assert!(
        !r.due_for_renewal(&tn, &ac, Timestamp(DAY + 1))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_new_target_resubscribes_and_stop_cleans_up() {
    let r = registry();
    let renewer = Renewer::new(r.clone());
    let p = FakeProvider::graph(3 * DAY);
    let (tn, ac) = (t("acme"), a("box"));
    let Ensured::Subscribed(old) = renewer
        .ensure(&p, &tn, &ac, &target("one"), Timestamp(0))
        .await
        .unwrap()
    else {
        panic!()
    };
    let moved = PushTarget {
        url: "https://new.example.com/v1/push/graph".into(),
        ..target("two")
    };
    let Ensured::Subscribed(new) = renewer
        .ensure(&p, &tn, &ac, &moved, Timestamp(1))
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_ne!(old.id, new.id);
    assert_eq!(p.st.lock().unwrap().unsubscribes, 1);
    assert_eq!(r.lookup_graph(&old.id, "one").await.unwrap(), None);

    renewer.stop(&p, &tn, &ac).await.unwrap();
    assert_eq!(p.st.lock().unwrap().unsubscribes, 2);
    assert!(p.st.lock().unwrap().live.is_empty());
    assert_eq!(r.lookup_graph(&new.id, "two").await.unwrap(), None);
    assert_eq!(r.state(&tn, &ac).await.unwrap(), None);
}

#[tokio::test]
async fn gmail_watches_again_and_keeps_routing_by_address() {
    let r = registry();
    let renewer = Renewer::new(r.clone());
    let p = FakeProvider::graph(7 * DAY);
    p.st.lock().unwrap().kind = PUSH_GMAIL;
    let (tn, ac) = (t("acme"), a("mail"));
    let gmail_target = PushTarget {
        gmail_topic: Some("projects/acme/topics/push".into()),
        ..target("x")
    };
    assert!(matches!(
        renewer
            .ensure(&p, &tn, &ac, &gmail_target, Timestamp(0))
            .await
            .unwrap(),
        Ensured::Subscribed(_)
    ));
    p.set_clock(5 * DAY);
    let Ensured::Renewed(sub) = renewer
        .ensure(&p, &tn, &ac, &gmail_target, Timestamp(5 * DAY))
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(sub.expires_at, Timestamp(12 * DAY));
    assert_eq!(
        r.lookup_gmail("ada@example.com").await.unwrap(),
        Some((tn, ac))
    );
}

#[tokio::test]
async fn providers_without_push_store_nothing() {
    let r = registry();
    let renewer = Renewer::new(r.clone());
    let p = FakeProvider::graph(DAY);
    p.st.lock().unwrap().unsupported = true;
    let (tn, ac) = (t("acme"), a("imap"));
    assert_eq!(
        renewer
            .ensure(&p, &tn, &ac, &target("x"), Timestamp(0))
            .await
            .unwrap(),
        Ensured::Unsupported
    );
    assert_eq!(r.state(&tn, &ac).await.unwrap(), None);
    assert_eq!(renewer.next_check(&tn, &ac).await.unwrap(), None);
}

#[test]
fn client_states_are_random_and_fit_graph() {
    let one = random_client_state().unwrap();
    let two = random_client_state().unwrap();
    assert_ne!(one, two);
    assert_eq!(one.len(), 43);
    assert!(one.bytes().all(|b| b.is_ascii_graphic()));
    assert_eq!(
        graph_url("https://skein.example.com/"),
        "https://skein.example.com/v1/push/graph"
    );
}
