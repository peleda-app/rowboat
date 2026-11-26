use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use serde_json::json;
use skein_core::{CollectionKind, Credentials, ItemRef, PartStat};
use skein_pim::testing::PimServerControl;
use skein_pim::{PimChange, PimError, PimProvider, PimWrite, Scheduling, WriteOutcome};

use crate::fake::{FakeGoogle, HOLIDAYS, PRIMARY, TOKEN};
use crate::suite::{Shape, drain, json_conformance};
use crate::*;

fn settings(fake: &FakeGoogle) -> GoogleSettings {
    GoogleSettings {
        calendar_url: format!("{}/calendar/v3", fake.url),
        people_url: format!("{}/v1", fake.url),
        calendars: true,
        contacts: true,
    }
}

fn token(t: &str) -> Credentials {
    Credentials::AccessToken { token: t.into() }
}

fn provider(fake: &FakeGoogle) -> GoogleProvider {
    GoogleProvider::new(settings(fake), token(TOKEN))
        .unwrap()
        .with_rate(600_000, 600_000)
        .with_timeout(Duration::from_secs(10))
}

fn event(tag: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "summary": format!("Planning {tag}"),
        "start": { "dateTime": "2026-12-01T10:00:00Z" },
        "end": { "dateTime": "2026-12-01T11:00:00Z" },
        "iCalUID": format!("{tag}@example.com"),
    }))
    .unwrap()
}

fn person(tag: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "names": [{ "givenName": "Test", "familyName": format!("Person {tag}") }],
        "emailAddresses": [{ "value": format!("person-{tag}@example.org") }],
    }))
    .unwrap()
}

fn item(id: &str) -> ItemRef {
    ItemRef {
        id: id.into(),
        uid: None,
    }
}

const CALENDAR_SHAPE: Shape = Shape {
    kind: CollectionKind::Calendar,
    name: |n| format!("conf{n}"),
    sample: event,
    missing: "missingevent0",
};

const CONTACTS_SHAPE: Shape = Shape {
    kind: CollectionKind::AddressBook,
    name: |n| format!("c9000{n}"),
    sample: person,
    missing: "people/c999999",
};

#[tokio::test]
async fn calendars_keep_the_contract() {
    let fake = FakeGoogle::start().await;
    json_conformance(
        Arc::new(provider(&fake)),
        Arc::new(fake.clone()),
        PRIMARY,
        &CALENDAR_SHAPE,
    )
    .await;
}

#[tokio::test]
async fn contacts_keep_the_contract() {
    let fake = FakeGoogle::start().await;
    json_conformance(
        Arc::new(provider(&fake)),
        Arc::new(fake.clone()),
        CONTACTS,
        &CONTACTS_SHAPE,
    )
    .await;
}

#[tokio::test]
async fn collections_carry_names_colors_and_access() {
    let fake = FakeGoogle::start().await;
    let mut s = provider(&fake).connect().await.unwrap();
    let list = s.collections().await.unwrap();
    assert_eq!(list.len(), 3);
    let primary = list.iter().find(|c| c.id == PRIMARY).unwrap();
    assert_eq!(primary.kind, CollectionKind::Calendar);
    assert_eq!(primary.name, "Ada");
    assert_eq!(primary.color.as_deref(), Some("#9fe1e7"));
    assert!(!primary.read_only);
    assert_eq!(primary.components, vec!["VEVENT".to_owned()]);
    let holidays = list.iter().find(|c| c.id == HOLIDAYS).unwrap();
    assert!(holidays.read_only, "a reader calendar is read-only");
    let book = list.iter().find(|c| c.id == CONTACTS).unwrap();
    assert_eq!(book.kind, CollectionKind::AddressBook);

    fake.put(HOLIDAYS, "newyear01", &event("new-year")).await;
    let (_, changes) = drain(&mut s, HOLIDAYS, None, 10).await;
    assert_eq!(changes.len(), 1, "an id with # and @ is read: {changes:?}");
    let out = s
        .apply(&PimWrite::Put {
            collection: HOLIDAYS.into(),
            item: None,
            bytes: Bytes::from(event("x")),
            if_version: None,
            key: "k1".into(),
            notify: false,
        })
        .await
        .unwrap();
    assert_eq!(out, failed("read_only"));

    let only_calendars = GoogleProvider::new(
        GoogleSettings {
            contacts: false,
            ..settings(&fake)
        },
        token(TOKEN),
    )
    .unwrap();
    let mut s = only_calendars.connect().await.unwrap();
    assert_eq!(s.collections().await.unwrap().len(), 2);
    assert!(matches!(
        s.changes(CONTACTS, None, 10).await,
        Err(PimError::NotFound)
    ));
    assert!(matches!(
        s.changes("nobody@example.com", None, 10).await,
        Err(PimError::NotFound)
    ));
}

#[tokio::test]
async fn expired_sync_tokens_reset() {
    let fake = FakeGoogle::start().await;
    let mut s = provider(&fake).connect().await.unwrap();
    fake.put(PRIMARY, "event0001", &event("a")).await;
    let (cursor, _) = drain(&mut s, PRIMARY, None, 10).await;
    fake.invalidate(PRIMARY).await;
    let batch = s.changes(PRIMARY, Some(&cursor), 10).await.unwrap();
    assert_eq!(
        batch.changes[0],
        PimChange::Reset {
            reason: "sync_token_expired".into()
        }
    );
    assert!(matches!(batch.changes[1], PimChange::Upserted { .. }));

    fake.put(CONTACTS, "c1", &person("a")).await;
    let (cursor, _) = drain(&mut s, CONTACTS, None, 10).await;
    fake.invalidate(CONTACTS).await;
    let batch = s.changes(CONTACTS, Some(&cursor), 10).await.unwrap();
    assert_eq!(
        batch.changes[0],
        PimChange::Reset {
            reason: "sync_token_expired".into()
        },
        "400 EXPIRED_SYNC_TOKEN resets"
    );
    let cursor = batch.cursor;
    fake.state.lock().unwrap().expire_with_410 = true;
    fake.invalidate(CONTACTS).await;
    let batch = s.changes(CONTACTS, Some(&cursor), 10).await.unwrap();
    assert_eq!(
        batch.changes[0],
        PimChange::Reset {
            reason: "sync_token_expired".into()
        },
        "410 resets"
    );
    let calendar_cursor = cursor;
    let batch = s
        .changes(PRIMARY, Some(&calendar_cursor), 10)
        .await
        .unwrap();
    assert_eq!(
        batch.changes[0],
        PimChange::Reset {
            reason: "invalid_cursor".into()
        },
        "a contacts cursor is no calendar cursor"
    );
}

#[tokio::test]
async fn cancelled_events_and_deleted_contacts_are_removed() {
    let fake = FakeGoogle::start().await;
    let mut s = provider(&fake).connect().await.unwrap();
    fake.put(PRIMARY, "event0001", &event("a")).await;
    fake.put(PRIMARY, "event0002", &event("b")).await;
    fake.remove(PRIMARY, "event0002").await;
    let (cursor, changes) = drain(&mut s, PRIMARY, None, 10).await;
    assert_eq!(
        changes,
        vec![PimChange::Upserted {
            item: item("event0001"),
            version: Some("\"1\"".into())
        }],
        "a full listing leaves cancelled events out"
    );
    fake.remove(PRIMARY, "event0001").await;
    let (_, changes) = drain(&mut s, PRIMARY, Some(cursor), 10).await;
    assert_eq!(
        changes,
        vec![PimChange::Removed {
            item: item("event0001")
        }]
    );
    assert!(
        s.fetch(PRIMARY, &[item("event0001")])
            .await
            .unwrap()
            .is_empty(),
        "a cancelled event is not fetched"
    );

    fake.put(CONTACTS, "c1", &person("a")).await;
    let (cursor, _) = drain(&mut s, CONTACTS, None, 10).await;
    fake.remove(CONTACTS, "c1").await;
    let (_, changes) = drain(&mut s, CONTACTS, Some(cursor), 10).await;
    assert_eq!(
        changes,
        vec![PimChange::Removed {
            item: item("people/c1")
        }]
    );
}

#[tokio::test]
async fn fetch_without_a_listing_reads_exact_bytes() {
    let fake = FakeGoogle::start().await;
    fake.put(PRIMARY, "event0001", &event("a")).await;
    fake.put(CONTACTS, "c1", &person("a")).await;
    fake.put(CONTACTS, "c2", &person("b")).await;
    let mut s = provider(&fake).connect().await.unwrap();
    let got = s
        .fetch(
            PRIMARY,
            &[item("event0001"), item("event0001"), item("../x")],
        )
        .await
        .unwrap();
    assert_eq!(got.len(), 1);
    let (version, held) = fake.read(PRIMARY, &got[0].item).await.unwrap();
    assert_eq!(got[0].bytes, held);
    assert_eq!(got[0].version, version);
    assert_eq!(got[0].content_type, EVENT_TYPE);

    let got = s
        .fetch(
            CONTACTS,
            &[item("people/c1"), item("people/c2"), item("people/c404")],
        )
        .await
        .unwrap();
    assert_eq!(got.len(), 2);
    for o in &got {
        assert_eq!(o.bytes, fake.read(CONTACTS, &o.item).await.unwrap().1);
        assert_eq!(o.content_type, PERSON_TYPE);
    }
    let batch: Vec<_> = fake
        .requests()
        .into_iter()
        .filter(|r| r.path.ends_with("people:batchGet"))
        .collect();
    assert_eq!(batch.len(), 1, "contacts are fetched in one batch");
}

#[tokio::test]
async fn writes_carry_preconditions_and_keep_bytes() {
    let fake = FakeGoogle::start().await;
    let p = provider(&fake);
    let mut s = p.connect().await.unwrap();
    let sent = Bytes::from(event("a"));
    let create = PimWrite::Put {
        collection: PRIMARY.into(),
        item: None,
        bytes: sent.clone(),
        if_version: None,
        key: "01KCREATE".into(),
        notify: false,
    };
    let WriteOutcome::Applied {
        item: Some(created),
        current: Some(current),
    } = s.apply(&create).await.unwrap()
    else {
        panic!("applied");
    };
    assert_eq!(Some(created.id.clone()), calendar::id_for_key("01KCREATE"));
    let posted = fake.requests().last().unwrap().clone();
    assert!(posted.query.contains("sendUpdates=none"));
    let prefix = format!("{{\"id\":\"{}\",", created.id);
    assert_eq!(
        posted.body,
        [prefix.as_bytes(), &sent[1..]].concat(),
        "the id is spliced in and every other byte kept"
    );

    let mut other = p.connect().await.unwrap();
    assert!(
        matches!(other.apply(&create).await.unwrap(), WriteOutcome::Applied { item: Some(i), .. } if i == created),
        "a create repeated in another session meets the event it made"
    );

    let replace = |bytes: Vec<u8>, v: Option<String>| PimWrite::Put {
        collection: PRIMARY.into(),
        item: Some(created.clone()),
        bytes: Bytes::from(bytes),
        if_version: v,
        key: "01KREPLACE".into(),
        notify: false,
    };
    fake.clear_requests();
    let out = s
        .apply(&replace(event("b"), Some("\"old\"".into())))
        .await
        .unwrap();
    assert_eq!(
        out,
        WriteOutcome::Conflict {
            current: current.version.clone()
        }
    );
    let reqs = fake.requests();
    assert_eq!(reqs[0].method, "PUT");
    assert_eq!(reqs[0].if_match.as_deref(), Some("\"old\""));
    assert_eq!(
        reqs[0].body,
        event("b"),
        "a replace sends the blob unchanged"
    );
    let out = s
        .apply(&PimWrite::Delete {
            collection: PRIMARY.into(),
            item: created.clone(),
            if_version: Some("\"old\"".into()),
            notify: false,
        })
        .await
        .unwrap();
    assert!(matches!(out, WriteOutcome::Conflict { current: Some(_) }));
    let out = s.apply(&replace(event("c"), None)).await.unwrap();
    assert!(matches!(out, WriteOutcome::Applied { .. }));
    assert!(
        fake.requests().last().unwrap().if_match.is_none(),
        "no version, no precondition"
    );
    let missing = PimWrite::Put {
        collection: PRIMARY.into(),
        item: Some(item("missingevent0")),
        bytes: Bytes::from(event("d")),
        if_version: Some("\"1\"".into()),
        key: "k".into(),
        notify: false,
    };
    assert_eq!(
        s.apply(&missing).await.unwrap(),
        WriteOutcome::Conflict { current: None }
    );
    assert_eq!(
        s.apply(&PimWrite::Put {
            collection: PRIMARY.into(),
            item: None,
            bytes: Bytes::from_static(b"BEGIN:VCALENDAR\r\n"),
            if_version: None,
            key: "k2".into(),
            notify: false,
        })
        .await
        .unwrap(),
        failed("invalid_object")
    );

    let c = PimWrite::Put {
        collection: CONTACTS.into(),
        item: None,
        bytes: Bytes::from(person("a")),
        if_version: None,
        key: "01KCONTACT".into(),
        notify: false,
    };
    let WriteOutcome::Applied {
        item: Some(contact),
        current: Some(cur),
    } = s.apply(&c).await.unwrap()
    else {
        panic!("applied");
    };
    assert_eq!(
        fake.requests().last().unwrap().body,
        person("a"),
        "a contact create sends the blob unchanged"
    );
    let update = PimWrite::Put {
        collection: CONTACTS.into(),
        item: Some(contact.clone()),
        bytes: Bytes::from(person("b")),
        if_version: cur.version.clone(),
        key: "01KUPDATE".into(),
        notify: false,
    };
    assert!(matches!(
        s.apply(&update).await.unwrap(),
        WriteOutcome::Applied { .. }
    ));
    let patched = fake.requests().last().unwrap().clone();
    assert_eq!(patched.method, "PATCH");
    assert!(patched.query.contains("updatePersonFields="));
    let etag = cur.version.clone().unwrap();
    let prefix = format!("{{\"etag\":\"{etag}\",");
    assert_eq!(
        patched.body,
        [prefix.as_bytes(), &person("b")[1..]].concat()
    );
    let out = s.apply(&update).await.unwrap();
    assert!(
        matches!(out, WriteOutcome::Conflict { current: Some(ref v) } if Some(v) != cur.version.as_ref()),
        "a stale etag conflicts with the current one: {out:?}"
    );
}

#[tokio::test]
async fn notify_chooses_send_updates() {
    let fake = FakeGoogle::start().await;
    let mut s = provider(&fake).connect().await.unwrap();
    let WriteOutcome::Applied {
        item: Some(created),
        ..
    } = s
        .apply(&PimWrite::Put {
            collection: PRIMARY.into(),
            item: None,
            bytes: Bytes::from(event("a")),
            if_version: None,
            key: "01KNOTIFY".into(),
            notify: true,
        })
        .await
        .unwrap()
    else {
        panic!("applied");
    };
    let sent = |fake: &FakeGoogle| fake.requests().last().unwrap().send_updates.clone();
    assert_eq!(sent(&fake).as_deref(), Some("all"));
    s.apply(&PimWrite::Put {
        collection: PRIMARY.into(),
        item: Some(created.clone()),
        bytes: Bytes::from(event("b")),
        if_version: None,
        key: "01KQUIET".into(),
        notify: false,
    })
    .await
    .unwrap();
    assert_eq!(sent(&fake).as_deref(), Some("none"));
    let out = s
        .apply(&PimWrite::Delete {
            collection: PRIMARY.into(),
            item: created,
            if_version: None,
            notify: true,
        })
        .await
        .unwrap();
    assert!(matches!(out, WriteOutcome::Applied { .. }));
    let last = fake.requests().last().unwrap().clone();
    assert_eq!(last.method, "DELETE");
    assert_eq!(last.send_updates.as_deref(), Some("all"));
}

fn invitation() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "summary": "Planning",
        "start": { "dateTime": "2026-12-01T10:00:00Z" },
        "end": { "dateTime": "2026-12-01T11:00:00Z" },
        "organizer": { "email": "organizer@example.org" },
        "attendees": [
            { "email": "organizer@example.org", "organizer": true, "responseStatus": "accepted" },
            { "email": "person-b@example.org", "responseStatus": "needsAction" },
            { "email": "ada@example.com", "self": true, "responseStatus": "needsAction" }
        ]
    }))
    .unwrap()
}

fn respond(
    attendee: Option<&str>,
    answer: PartStat,
    if_version: Option<String>,
    notify: bool,
) -> PimWrite {
    PimWrite::Respond {
        collection: PRIMARY.into(),
        item: item("invite0001"),
        answer,
        attendee: attendee.map(str::to_owned),
        comment: Some("See you there".into()),
        if_version,
        notify,
    }
}

fn attendees(bytes: &[u8]) -> Vec<serde_json::Value> {
    serde_json::from_slice::<serde_json::Value>(bytes).unwrap()["attendees"]
        .as_array()
        .unwrap()
        .clone()
}

#[tokio::test]
async fn respond_patches_one_attendee() {
    let fake = FakeGoogle::start().await;
    fake.put(PRIMARY, "invite0001", &invitation()).await;
    let mut s = provider(&fake).connect().await.unwrap();
    let (version, _) = fake.read(PRIMARY, &item("invite0001")).await.unwrap();
    fake.clear_requests();

    let out = s
        .apply(&respond(None, PartStat::Accepted, version.clone(), true))
        .await
        .unwrap();
    let WriteOutcome::Applied {
        item: Some(answered),
        current: Some(current),
    } = out
    else {
        panic!("applied: {out:?}");
    };
    assert_eq!(answered, item("invite0001"));
    let (held_version, held) = fake.read(PRIMARY, &answered).await.unwrap();
    assert_eq!(current.bytes, held);
    assert_eq!(current.version, held_version);
    assert_eq!(current.content_type, EVENT_TYPE);
    let list = attendees(&held);
    assert_eq!(list[2]["responseStatus"], "accepted");
    assert_eq!(list[2]["comment"], "See you there");
    assert_eq!(list[1]["responseStatus"], "needsAction");
    assert_eq!(list[0]["responseStatus"], "accepted");
    let reqs = fake.requests();
    let patch = reqs.iter().find(|r| r.method == "PATCH").unwrap();
    assert_eq!(patch.send_updates.as_deref(), Some("all"));
    assert_eq!(patch.if_match, version);
    let body: serde_json::Value = serde_json::from_slice(&patch.body).unwrap();
    assert_eq!(
        body.as_object().unwrap().keys().collect::<Vec<_>>(),
        vec!["attendees"],
        "only the attendees are patched"
    );

    let out = s
        .apply(&respond(
            Some("PERSON-B@example.org"),
            PartStat::Declined,
            None,
            false,
        ))
        .await
        .unwrap();
    assert!(matches!(out, WriteOutcome::Applied { .. }), "{out:?}");
    let (_, held) = fake.read(PRIMARY, &item("invite0001")).await.unwrap();
    let list = attendees(&held);
    assert_eq!(list[1]["responseStatus"], "declined");
    assert_eq!(list[2]["responseStatus"], "accepted");
    assert_eq!(
        fake.requests().last().unwrap().send_updates.as_deref(),
        Some("none")
    );
}

#[tokio::test]
async fn respond_refuses_what_it_cannot_answer() {
    let fake = FakeGoogle::start().await;
    fake.put(PRIMARY, "invite0001", &invitation()).await;
    fake.put(PRIMARY, "event0001", &event("a")).await;
    let mut s = provider(&fake).connect().await.unwrap();

    let out = s
        .apply(&respond(
            Some("nobody@example.org"),
            PartStat::Tentative,
            None,
            true,
        ))
        .await
        .unwrap();
    assert_eq!(out, failed("attendee_not_found"));
    let out = s
        .apply(&PimWrite::Respond {
            collection: PRIMARY.into(),
            item: item("event0001"),
            answer: PartStat::Accepted,
            attendee: None,
            comment: None,
            if_version: None,
            notify: true,
        })
        .await
        .unwrap();
    assert_eq!(out, failed("attendee_not_found"), "no attendees, no self");

    let (version, _) = fake.read(PRIMARY, &item("invite0001")).await.unwrap();
    fake.clear_requests();
    let out = s
        .apply(&respond(
            None,
            PartStat::Accepted,
            Some("\"old\"".into()),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(out, WriteOutcome::Conflict { current: version });
    assert!(
        fake.requests().iter().all(|r| r.method == "GET"),
        "a stale version patches nothing"
    );

    let out = s
        .apply(&PimWrite::Respond {
            collection: PRIMARY.into(),
            item: item("missingevent0"),
            answer: PartStat::Accepted,
            attendee: None,
            comment: None,
            if_version: None,
            notify: true,
        })
        .await
        .unwrap();
    assert_eq!(out, WriteOutcome::Conflict { current: None });

    let out = s
        .apply(&PimWrite::Respond {
            collection: CONTACTS.into(),
            item: item("people/c1"),
            answer: PartStat::Accepted,
            attendee: None,
            comment: None,
            if_version: None,
            notify: true,
        })
        .await
        .unwrap();
    assert_eq!(out, failed("not_a_calendar"));
}

#[tokio::test]
async fn scheduling_and_addresses() {
    let fake = FakeGoogle::start().await;
    let mut s = provider(&fake).connect().await.unwrap();
    assert_eq!(s.scheduling(PRIMARY).await.unwrap(), Scheduling::Server);
    assert_eq!(s.scheduling(CONTACTS).await.unwrap(), Scheduling::Client);
    assert!(matches!(s.scheduling("").await, Err(PimError::NotFound)));

    assert_eq!(s.addresses().await.unwrap(), vec![PRIMARY.to_owned()]);
    fake.state.lock().unwrap().primary = Some("Ada.Lovelace@Example.COM".into());
    assert_eq!(
        s.addresses().await.unwrap(),
        vec!["ada.lovelace@example.com".to_owned()]
    );
    fake.state.lock().unwrap().primary = Some("primary-calendar".into());
    assert!(s.addresses().await.unwrap().is_empty());
    fake.state.lock().unwrap().primary = None;
    assert!(s.addresses().await.unwrap().is_empty());

    let only_contacts = GoogleProvider::new(
        GoogleSettings {
            calendars: false,
            ..settings(&fake)
        },
        token(TOKEN),
    )
    .unwrap();
    let mut s = only_contacts.connect().await.unwrap();
    assert!(matches!(
        s.scheduling(PRIMARY).await,
        Err(PimError::NotFound)
    ));
    fake.clear_requests();
    assert!(s.addresses().await.unwrap().is_empty());
    assert!(fake.requests().is_empty());
}

#[tokio::test]
async fn throttling_and_auth_are_reported() {
    let fake = FakeGoogle::start().await;
    let mut s = provider(&fake).connect().await.unwrap();
    fake.state.lock().unwrap().throttle = Some((429, "rateLimitExceeded", Some(7)));
    assert!(matches!(
        s.collections().await,
        Err(PimError::Throttled { retry_after: Some(d) }) if d == Duration::from_secs(7)
    ));
    fake.state.lock().unwrap().throttle = Some((403, "userRateLimitExceeded", None));
    assert!(matches!(
        s.changes(CONTACTS, None, 10).await,
        Err(PimError::Throttled { retry_after: None })
    ));
    fake.state.lock().unwrap().throttle = Some((403, "quotaExceeded", Some(2)));
    let write = PimWrite::Delete {
        collection: PRIMARY.into(),
        item: item("event0001"),
        if_version: None,
        notify: false,
    };
    assert!(matches!(
        s.apply(&write).await,
        Err(PimError::Throttled {
            retry_after: Some(_)
        })
    ));
    fake.state.lock().unwrap().throttle = Some((503, "backendError", None));
    let create = PimWrite::Put {
        collection: CONTACTS.into(),
        item: None,
        bytes: Bytes::from(person("a")),
        if_version: None,
        key: "k".into(),
        notify: false,
    };
    assert_eq!(
        s.apply(&create).await.unwrap(),
        WriteOutcome::Uncertain,
        "a contact create that may have happened is uncertain"
    );

    let wrong = GoogleProvider::new(settings(&fake), token("ya29.wrong")).unwrap();
    let mut s = wrong.connect().await.unwrap();
    assert!(matches!(s.collections().await, Err(PimError::Auth)));
    assert!(matches!(
        s.changes(CONTACTS, None, 10).await,
        Err(PimError::Auth)
    ));
}

#[tokio::test]
async fn the_token_stays_on_the_configured_origins() {
    let fake = FakeGoogle::start().await;
    let evil = FakeGoogle::start().await;
    let mut s = provider(&fake).connect().await.unwrap();
    fake.state.lock().unwrap().redirect =
        Some(format!("{}/calendar/v3/users/me/calendarList", evil.url));
    assert!(matches!(s.collections().await, Err(PimError::Protocol(_))));
    assert!(evil.requests().is_empty(), "a redirect is never followed");
    fake.state.lock().unwrap().redirect = Some(format!("{}/v1/people/me/connections", evil.url));
    assert!(matches!(
        s.changes(CONTACTS, None, 10).await,
        Err(PimError::Protocol(_))
    ));
    assert!(evil.requests().is_empty());
    assert!(fake.requests().iter().all(|r| r.authorized));

    let config = |s: GoogleSettings, c: Credentials| {
        matches!(GoogleProvider::new(s, c), Err(PimError::Config(_)))
    };
    let base = settings(&fake);
    assert!(config(
        GoogleSettings {
            calendar_url: "http://calendar.example.com/calendar/v3".into(),
            ..base.clone()
        },
        token(TOKEN)
    ));
    assert!(config(
        GoogleSettings {
            people_url: "https://user:pw@people.example.com/v1".into(),
            ..base.clone()
        },
        token(TOKEN)
    ));
    assert!(config(
        base.clone(),
        Credentials::Password {
            secret: "hunter2".into()
        }
    ));
    assert!(config(base.clone(), token("  ")));
    assert!(config(
        GoogleSettings {
            calendars: false,
            contacts: false,
            ..base.clone()
        },
        token(TOKEN)
    ));
    let defaults = GoogleSettings::from_json(&json!({})).unwrap();
    assert_eq!(defaults, GoogleSettings::default());
    assert_eq!(
        defaults.calendar_url,
        "https://www.googleapis.com/calendar/v3"
    );
    assert_eq!(defaults.people_url, "https://people.googleapis.com/v1");
}

#[tokio::test]
async fn answers_and_writes_are_capped() {
    let fake = FakeGoogle::start().await;
    let big = serde_json::to_vec(&json!({ "summary": "x".repeat(20_000) })).unwrap();
    fake.put(PRIMARY, "bigevent1", &big).await;
    let mut s = provider(&fake)
        .with_limits(4096, 8192)
        .connect()
        .await
        .unwrap();
    assert!(matches!(
        s.changes(PRIMARY, None, 10).await,
        Err(PimError::Protocol(_))
    ));
    assert!(matches!(
        s.fetch(PRIMARY, &[item("bigevent1")]).await,
        Err(PimError::Protocol(_))
    ));
    let out = s
        .apply(&PimWrite::Put {
            collection: PRIMARY.into(),
            item: None,
            bytes: Bytes::from(big),
            if_version: None,
            key: "k".into(),
            notify: false,
        })
        .await
        .unwrap();
    assert_eq!(out, failed("too_large"));
}

#[tokio::test]
async fn debug_never_shows_the_token() {
    let fake = FakeGoogle::start().await;
    let p = provider(&fake);
    let shown = format!("{p:?}");
    assert!(!shown.contains(TOKEN), "{shown}");
    assert!(shown.contains("redacted"));
}

#[test]
fn spliced_fields_keep_the_rest() {
    let map = |b: &[u8]| object(b, 1024).unwrap();
    let b = Bytes::from_static(b" { \"a\": 1 }");
    assert_eq!(
        with_field(&b, &map(&b), "id", "x"),
        Bytes::from_static(b" {\"id\":\"x\", \"a\": 1 }")
    );
    let e = Bytes::from_static(b"{ }");
    assert_eq!(
        with_field(&e, &map(&e), "id", "x"),
        Bytes::from_static(b"{\"id\":\"x\" }")
    );
    let same = Bytes::from_static(b"{\"id\": \"x\"}");
    assert_eq!(with_field(&same, &map(&same), "id", "x"), same);
    let other = Bytes::from_static(b"{\"id\": \"y\", \"b\": 2}");
    let out = with_field(&other, &map(&other), "id", "x");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&out).unwrap(),
        json!({ "id": "x", "b": 2 })
    );
    assert_eq!(object(b"[1]", 1024).unwrap_err(), "invalid_object");
    assert_eq!(object(b"{}", 1).unwrap_err(), "too_large");
}
