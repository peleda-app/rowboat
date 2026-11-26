//! The `skein_pim::testing::conformance` steps for JSON objects.
//!
//! The contract's own suite builds iCalendar and vCard text, appends a property line to change an
//! object and expects a create to store exactly the bytes sent. Google holds JSON resources and
//! adds `id`, `etag`, `kind` and metadata to what it stores, so this suite keeps every check
//! except two that cannot hold: changed objects are other JSON objects, and a create is checked
//! by its content and by the read-back bytes being what the server holds.

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use skein_core::{CollectionKind, ItemRef};
use skein_pim::testing::PimServerControl;
use skein_pim::{Cursor, PimChange, PimProvider, PimSession, PimWrite, WriteOutcome};

pub(crate) struct Shape {
    pub kind: CollectionKind,
    /// The server-side name for object `n`, as `PimServerControl::put` takes it.
    pub name: fn(u32) -> String,
    /// An invented object carrying `tag` in its content.
    pub sample: fn(&str) -> Vec<u8>,
    /// The id of an object that does not exist.
    pub missing: &'static str,
}

#[derive(Default)]
struct Mirror {
    by_id: HashMap<String, (Option<String>, Bytes)>,
}

impl Mirror {
    fn contents(&self) -> Vec<Bytes> {
        let mut v: Vec<Bytes> = self.by_id.values().map(|(_, b)| b.clone()).collect();
        v.sort();
        v
    }
}

pub(crate) async fn drain(
    session: &mut Box<dyn PimSession>,
    collection: &str,
    cursor: Option<Cursor>,
    limit: usize,
) -> (Cursor, Vec<PimChange>) {
    let mut mirror = Mirror::default();
    drain_into(session, collection, cursor, &mut mirror, limit).await
}

async fn drain_into(
    session: &mut Box<dyn PimSession>,
    collection: &str,
    cursor: Option<Cursor>,
    mirror: &mut Mirror,
    limit: usize,
) -> (Cursor, Vec<PimChange>) {
    let mut cursor = cursor;
    let mut all = Vec::new();
    for _ in 0..10_000 {
        let batch = session
            .changes(collection, cursor.as_ref(), limit)
            .await
            .unwrap();
        let mut upserted = Vec::new();
        for change in &batch.changes {
            match change {
                PimChange::Reset { .. } => mirror.by_id.clear(),
                PimChange::Upserted { item, .. } => upserted.push(item.clone()),
                PimChange::Removed { item } => {
                    mirror.by_id.remove(&item.id);
                }
            }
        }
        let raw = session.fetch(collection, &upserted).await.unwrap();
        assert_eq!(
            raw.len(),
            upserted.len(),
            "every upserted object can be fetched"
        );
        for obj in raw {
            assert!(
                upserted.contains(&obj.item),
                "fetch answers only what was asked"
            );
            mirror.by_id.insert(obj.item.id, (obj.version, obj.bytes));
        }
        all.extend(batch.changes);
        cursor = Some(batch.cursor);
        if !batch.more {
            return (cursor.unwrap(), all);
        }
    }
    panic!("the change feed never ended");
}

fn count(changes: &[PimChange], upserts: bool) -> usize {
    changes
        .iter()
        .filter(|c| {
            if upserts {
                matches!(c, PimChange::Upserted { .. })
            } else {
                matches!(c, PimChange::Removed { .. })
            }
        })
        .count()
}

fn holds(bytes: &[u8], tag: &str) -> bool {
    String::from_utf8_lossy(bytes).contains(tag)
}

/// The contract against a server that `control` can change. `collection` must exist, be empty,
/// writable and of `shape.kind`.
pub(crate) async fn json_conformance(
    provider: Arc<dyn PimProvider>,
    control: Arc<dyn PimServerControl>,
    collection: &str,
    shape: &Shape,
) {
    let kind = shape.kind;
    let name = shape.name;
    let obj = |n: u32| (shape.sample)(&format!("conformance-{n}"));
    let mut session = provider.connect().await.unwrap();
    let listed = session.collections().await.unwrap();
    let info = listed
        .iter()
        .find(|c| c.id == collection)
        .expect("the collection is listed");
    assert_eq!(info.kind, kind, "the collection has its kind");
    assert!(!info.read_only, "the collection is writable");
    assert_eq!(
        listed.iter().filter(|c| c.id == collection).count(),
        1,
        "each collection is listed once"
    );

    for n in 1..=5 {
        control.put(collection, &name(n), &obj(n)).await;
    }
    let mut mirror = Mirror::default();
    let (cursor, _) = drain_into(&mut session, collection, None, &mut mirror, 2).await;
    assert_eq!(
        mirror.contents(),
        control.contents(collection).await,
        "a listing without a cursor sees everything, paged, with the exact bytes"
    );
    for (id, (version, bytes)) in &mirror.by_id {
        let item = ItemRef {
            id: id.clone(),
            uid: None,
        };
        let (now, held) = control.read(collection, &item).await.expect("listed item");
        assert_eq!(&held, bytes);
        assert_eq!(version, &now, "the version belongs to the bytes");
    }

    let (cursor, changes) =
        drain_into(&mut session, collection, Some(cursor), &mut mirror, 2).await;
    assert!(
        changes.is_empty(),
        "nothing changed, nothing reported: {changes:?}"
    );

    control
        .put(
            collection,
            &name(3),
            &(shape.sample)("conformance-3-changed"),
        )
        .await;
    control.remove(collection, &name(2)).await;
    control.put(collection, &name(6), &obj(6)).await;
    let (cursor, changes) =
        drain_into(&mut session, collection, Some(cursor), &mut mirror, 2).await;
    assert_eq!(
        (count(&changes, true), count(&changes, false)),
        (2, 1),
        "exactly the three changes are reported: {changes:?}"
    );
    assert_eq!(mirror.contents(), control.contents(collection).await);

    assert!(control.invalidate(collection).await);
    let (_, changes) = drain_into(&mut session, collection, Some(cursor), &mut mirror, 100).await;
    assert!(
        matches!(changes.first(), Some(PimChange::Reset { .. })),
        "an invalid cursor resets: {changes:?}"
    );
    assert_eq!(
        mirror.contents(),
        control.contents(collection).await,
        "the reset lists everything again"
    );
    let garbage = Cursor(Bytes::from_static(b"\xff not a cursor"));
    let (_, changes) = drain(&mut session, collection, Some(garbage), 100).await;
    assert!(
        matches!(changes.first(), Some(PimChange::Reset { .. })),
        "an unreadable cursor resets"
    );

    let missing = ItemRef {
        id: shape.missing.into(),
        uid: None,
    };
    let none = session
        .fetch(collection, std::slice::from_ref(&missing))
        .await
        .unwrap();
    assert!(none.is_empty(), "vanished objects are left out");

    let create = PimWrite::Put {
        collection: collection.to_owned(),
        item: None,
        bytes: Bytes::from((shape.sample)("conformance-7")),
        if_version: None,
        key: "01KCONFORMANCECREATE000000".into(),
        notify: false,
    };
    let WriteOutcome::Applied {
        item: Some(created),
        current,
    } = session.apply(&create).await.unwrap()
    else {
        panic!("a create is applied and names its object");
    };
    let (version, held) = control
        .read(collection, &created)
        .await
        .expect("the created object is there");
    assert!(holds(&held, "conformance-7"), "a create stores the object");
    let current = current.expect("a create reads the object back");
    assert_eq!(current.item, created);
    assert_eq!(
        current.bytes, held,
        "the object read back is what the server holds"
    );
    assert_eq!(current.version, version);
    let again = session.apply(&create).await.unwrap();
    assert!(
        matches!(&again, WriteOutcome::Applied { item: Some(i), .. } if *i == created),
        "repeating a create answers with the same object: {again:?}"
    );
    assert_eq!(
        control.contents(collection).await.len(),
        6,
        "one object per key"
    );

    let stale = PimWrite::Put {
        collection: collection.to_owned(),
        item: Some(created.clone()),
        bytes: Bytes::from((shape.sample)("conformance-8")),
        if_version: Some("\"stale-version\"".into()),
        key: "01KCONFORMANCESTALE0000000".into(),
        notify: false,
    };
    assert!(
        matches!(
            session.apply(&stale).await.unwrap(),
            WriteOutcome::Conflict { .. }
        ),
        "a stale version conflicts"
    );
    assert_eq!(control.read(collection, &created).await.unwrap().1, held);

    let update = PimWrite::Put {
        collection: collection.to_owned(),
        item: Some(created.clone()),
        bytes: Bytes::from((shape.sample)("conformance-9")),
        if_version: version.clone(),
        key: "01KCONFORMANCEUPDATE000000".into(),
        notify: false,
    };
    let WriteOutcome::Applied {
        current: Some(after),
        ..
    } = session.apply(&update).await.unwrap()
    else {
        panic!("the current version is accepted");
    };
    let (now, held) = control.read(collection, &created).await.unwrap();
    assert!(holds(&held, "conformance-9") && !holds(&held, "conformance-7"));
    assert_eq!(after.bytes, held);
    assert_eq!(after.version, now);
    assert_ne!(now, version, "a write changes the version");

    let stale_delete = PimWrite::Delete {
        collection: collection.to_owned(),
        item: created.clone(),
        if_version: version.clone(),
        notify: false,
    };
    assert!(
        matches!(
            session.apply(&stale_delete).await.unwrap(),
            WriteOutcome::Conflict { current: Some(_) }
        ),
        "a delete with a stale version conflicts"
    );
    assert!(control.read(collection, &created).await.is_some());
    let delete = PimWrite::Delete {
        collection: collection.to_owned(),
        item: created.clone(),
        if_version: now,
        notify: false,
    };
    assert!(matches!(
        session.apply(&delete).await.unwrap(),
        WriteOutcome::Applied { .. }
    ));
    assert!(control.read(collection, &created).await.is_none());
    let gone = PimWrite::Delete {
        collection: collection.to_owned(),
        item: created.clone(),
        if_version: None,
        notify: false,
    };
    assert!(
        matches!(
            session.apply(&gone).await.unwrap(),
            WriteOutcome::Applied { .. }
        ),
        "deleting a gone object counts as applied"
    );

    for n in [1, 3, 4, 5, 6] {
        control.remove(collection, &name(n)).await;
    }
    session.logout().await.unwrap();
}
