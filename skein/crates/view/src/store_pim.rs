use rusqlite::{OptionalExtension, Row, Transaction, params};
use serde::Serialize;
use skein_core::{BlobHash, CollectionInfo, EventBody};
use skein_storage::Snapshot;

use super::{Store, StoreError, lock, to_json};
use crate::pim::{Format, ObjectFields, ParsedObject};

/// A calendar or address book with how many objects it holds.
#[derive(Debug, Serialize)]
pub struct CollectionRow {
    /// The collection's provider id.
    pub id: String,
    /// `calendar` or `address_book`.
    pub kind: String,
    /// Its display name.
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Its color, as the provider gives it.
    pub color: Option<String>,
    /// Whether the provider refuses writes to it.
    pub read_only: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    /// The component types it holds (`VEVENT`, `VTODO`).
    pub components: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Its role, when the provider names one.
    pub role: Option<String>,
    /// How many objects it holds.
    pub count: u64,
}

/// What every object answer holds.
#[derive(Debug, Serialize)]
pub struct ObjectSummary {
    /// The object id in this API: the BLAKE3 hash of its original bytes.
    pub id: String,
    /// The content type the provider gave.
    pub content_type: String,
    /// How the bytes are written, such as `icalendar` or `google_event`.
    pub format: String,
    /// Size of the original in bytes.
    pub size: u64,
    /// False when the bytes could not be read from Skein or parsed.
    pub available: bool,
    #[serde(flatten)]
    /// Fields parsed from the original.
    pub fields: ObjectFields,
}

/// An object as one collection holds it.
#[derive(Debug, Serialize)]
pub struct ObjectInCollection {
    #[serde(flatten)]
    /// The object.
    pub object: ObjectSummary,
    /// The provider's id of the object in this collection.
    pub item: String,
    /// The provider's version of the bytes (an ETag, a `changeKey`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Where an object is.
#[derive(Debug, Serialize)]
pub struct Placement {
    /// The collection id.
    pub collection: String,
    /// The provider's item id in that collection.
    pub item: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The provider's version (ETag), when it has one.
    pub version: Option<String>,
}

/// An object with every collection holding it.
#[derive(Debug, Serialize)]
pub struct ObjectDetail {
    #[serde(flatten)]
    /// The object.
    pub object: ObjectSummary,
    /// Where it is, by collection and item.
    pub placements: Vec<Placement>,
}

/// A time range for listing events: objects overlapping `[from, to)`, milliseconds.
#[derive(Debug, Clone, Copy, Default)]
pub struct Range {
    /// Only objects ending after this time, milliseconds since the epoch.
    pub from: Option<i64>,
    /// Only objects starting before this time, milliseconds since the epoch.
    pub to: Option<i64>,
}

const SUMMARY: &str = "o.blob, o.content_type, o.format, o.size, o.available, o.fields";
const PLACED: &str = "EXISTS (SELECT 1 FROM placements p WHERE p.object = o.id)";

fn summary(row: &Row<'_>) -> rusqlite::Result<ObjectSummary> {
    Ok(ObjectSummary {
        id: row.get(0)?,
        content_type: row.get(1)?,
        format: row.get(2)?,
        size: row.get::<_, i64>(3)? as u64,
        available: row.get(4)?,
        fields: serde_json::from_str(&row.get::<_, String>(5)?).unwrap_or_default(),
    })
}

fn kind_name(info: &CollectionInfo) -> String {
    serde_json::to_value(info.kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

impl Store {
    /// Whether the parsed content of the object `blob` is stored for the account.
    pub fn has_object(&self, account: &str, blob: &BlobHash) -> Result<bool, StoreError> {
        Ok(lock(&self.write)
            .query_row(
                "SELECT 1 FROM objects WHERE account = ?1 AND blob = ?2",
                params![account, blob.to_string()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Stores an object's parsed content and indexes contacts for search. Idempotent: content
    /// already stored for the blob is kept. Content no placement refers to is dropped by the
    /// next page or rebuild.
    pub fn insert_object(
        &self,
        account: &str,
        blob: &BlobHash,
        size: u64,
        content_type: &str,
        parsed: &ParsedObject,
    ) -> Result<(), StoreError> {
        let mut conn = lock(&self.write);
        let tx = conn.transaction()?;
        let f = &parsed.fields;
        let sort_name = f
            .full_name
            .as_deref()
            .or(f.summary.as_deref())
            .map(str::to_lowercase);
        let inserted = tx.execute(
            "INSERT INTO objects (account, blob, size, content_type, format, kind, available,
                starts, ends, recurring, sort_name, fields)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT (account, blob) DO NOTHING",
            params![
                account,
                blob.to_string(),
                size as i64,
                content_type,
                parsed.format.as_str(),
                f.kind,
                parsed.available,
                f.start,
                f.end,
                f.recurring,
                sort_name,
                to_json(f),
            ],
        )?;
        if inserted == 1 && f.kind == "contact" {
            let names = [f.full_name.as_deref(), f.org.as_deref()]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" ");
            tx.execute(
                "INSERT INTO contact_search (rowid, names, emails) VALUES (?1, ?2, ?3)",
                params![tx.last_insert_rowid(), names, f.emails.join(" ")],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// The account's calendars and address books by name, with object counts.
    pub fn collections(&self, account: &str) -> Result<Vec<CollectionRow>, StoreError> {
        let conn = self.reader();
        let mut q = conn.prepare_cached(
            "SELECT c.id, c.kind, c.name, c.color, c.read_only, c.components, c.role,
                (SELECT COUNT(*) FROM placements p WHERE p.account = c.account AND p.collection = c.id)
             FROM collections c WHERE c.account = ?1 ORDER BY c.name, c.id",
        )?;
        let rows = q.query_map(params![account], |r| {
            Ok(CollectionRow {
                id: r.get(0)?,
                kind: r.get(1)?,
                name: r.get(2)?,
                color: r.get(3)?,
                read_only: r.get(4)?,
                components: serde_json::from_str(&r.get::<_, String>(5)?).unwrap_or_default(),
                role: r.get(6)?,
                count: r.get::<_, i64>(7)? as u64,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Whether the account has the collection.
    pub fn has_collection(&self, account: &str, collection: &str) -> Result<bool, StoreError> {
        Ok(self
            .reader()
            .query_row(
                "SELECT 1 FROM collections WHERE account = ?1 AND id = ?2",
                params![account, collection],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Objects of a collection by item id, strictly after `after`, optionally only those
    /// overlapping `range`. Recurring objects are not expanded: with a range, one is listed when
    /// its first instance starts before `to`, whatever its end. Objects without a start are left
    /// out when a range is given.
    pub fn objects(
        &self,
        account: &str,
        collection: &str,
        after: Option<&str>,
        range: Range,
        limit: usize,
    ) -> Result<Vec<ObjectInCollection>, StoreError> {
        let conn = self.reader();
        let sql = format!(
            "SELECT {SUMMARY}, p.item_id, p.version
             FROM placements p JOIN objects o ON o.id = p.object
             WHERE p.account = ?1 AND p.collection = ?2
               AND (?3 IS NULL OR p.item_id > ?3)
               AND (?4 IS NULL OR (o.starts IS NOT NULL AND (o.recurring = 1
                    OR MAX(COALESCE(o.ends, o.starts), o.starts + 1) > ?4)))
               AND (?5 IS NULL OR (o.starts IS NOT NULL AND o.starts < ?5))
             ORDER BY p.item_id LIMIT ?6"
        );
        let mut q = conn.prepare_cached(&sql)?;
        let rows = q.query_map(
            params![
                account,
                collection,
                after,
                range.from,
                range.to,
                limit.min(crate::store::MAX_LIMIT) as i64
            ],
            |r| {
                Ok(ObjectInCollection {
                    object: summary(r)?,
                    item: r.get(6)?,
                    version: r.get(7)?,
                })
            },
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// One object with its placements, if some collection of the account holds it.
    pub fn object(&self, account: &str, id: &str) -> Result<Option<ObjectDetail>, StoreError> {
        let conn = self.reader();
        let sql = format!(
            "SELECT {SUMMARY}, o.id FROM objects o
             WHERE o.account = ?1 AND o.blob = ?2 AND {PLACED}"
        );
        let found = conn
            .query_row(&sql, params![account, id], |r| {
                Ok((summary(r)?, r.get::<_, i64>(6)?))
            })
            .optional()?;
        let Some((object, rowid)) = found else {
            return Ok(None);
        };
        let placements = placements(&conn, rowid)?;
        Ok(Some(ObjectDetail { object, placements }))
    }

    /// Contacts matching an FTS5 query from [`crate::search::fts_query`] over names,
    /// organizations and addresses, best first.
    pub fn search_contacts(
        &self,
        account: &str,
        fts: &str,
        limit: usize,
    ) -> Result<Vec<ObjectDetail>, StoreError> {
        let conn = self.reader();
        let sql = format!(
            "SELECT {SUMMARY}, o.id FROM contact_search s JOIN objects o ON o.id = s.rowid
             WHERE contact_search MATCH ?2 AND o.account = ?1 AND {PLACED}
             ORDER BY s.rank LIMIT ?3"
        );
        let run = || -> rusqlite::Result<Vec<ObjectDetail>> {
            let found: Vec<(ObjectSummary, i64)> = conn
                .prepare_cached(&sql)?
                .query_map(
                    params![account, fts, limit.min(crate::store::MAX_LIMIT) as i64],
                    |r| Ok((summary(r)?, r.get::<_, i64>(6)?)),
                )?
                .collect::<Result<_, _>>()?;
            found
                .into_iter()
                .map(|(object, rowid)| {
                    Ok(ObjectDetail {
                        object,
                        placements: placements(&conn, rowid)?,
                    })
                })
                .collect()
        };
        run().map_err(|e| match e {
            rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::Unknown => {
                StoreError::BadQuery
            }
            other => StoreError::Db(other),
        })
    }
}

fn placements(conn: &rusqlite::Connection, rowid: i64) -> rusqlite::Result<Vec<Placement>> {
    conn.prepare_cached(
        "SELECT collection, item_id, version FROM placements
         WHERE object = ?1 ORDER BY collection, item_id",
    )?
    .query_map(params![rowid], |r| {
        Ok(Placement {
            collection: r.get(0)?,
            item: r.get(1)?,
            version: r.get(2)?,
        })
    })?
    .collect()
}

pub(super) fn upsert_collection(
    tx: &Transaction<'_>,
    account: &str,
    info: &CollectionInfo,
) -> rusqlite::Result<()> {
    let role = info
        .role
        .and_then(|r| serde_json::to_value(r).ok())
        .and_then(|v| v.as_str().map(str::to_owned));
    tx.execute(
        "INSERT INTO collections (account, id, kind, name, color, read_only, components, role)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT (account, id) DO UPDATE SET kind = excluded.kind, name = excluded.name,
            color = excluded.color, read_only = excluded.read_only,
            components = excluded.components, role = excluded.role",
        params![
            account,
            info.id,
            kind_name(info),
            info.name,
            info.color,
            info.read_only,
            to_json(&info.components),
            role,
        ],
    )?;
    Ok(())
}

fn put_placement(
    tx: &Transaction<'_>,
    account: &str,
    collection: &str,
    item: &str,
    blob: &BlobHash,
    version: Option<&str>,
    content_type: &str,
) -> Result<(), StoreError> {
    let object: i64 = tx
        .query_row(
            "SELECT id FROM objects WHERE account = ?1 AND blob = ?2",
            params![account, blob.to_string()],
            |r| r.get(0),
        )
        .optional()?
        .ok_or(StoreError::MissingContent)?;
    let kind = match Format::of(content_type).kind() {
        "contact" => "address_book",
        _ => "calendar",
    };
    tx.execute(
        "INSERT INTO collections (account, id, kind, name, read_only, components)
         VALUES (?1, ?2, ?3, ?2, 0, '[]') ON CONFLICT DO NOTHING",
        params![account, collection, kind],
    )?;
    tx.execute(
        "INSERT INTO placements (account, collection, item_id, object, version)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT (account, collection, item_id) DO UPDATE SET object = excluded.object,
            version = excluded.version",
        params![account, collection, item, object, version],
    )?;
    Ok(())
}

fn clear_collection(tx: &Transaction<'_>, account: &str, collection: &str) -> rusqlite::Result<()> {
    tx.execute(
        "DELETE FROM placements WHERE account = ?1 AND collection = ?2",
        params![account, collection],
    )?;
    Ok(())
}

/// Applies a calendar or contact event; false when the event is not one.
pub(super) fn apply(
    tx: &Transaction<'_>,
    account: &str,
    body: &EventBody,
) -> Result<bool, StoreError> {
    match body {
        EventBody::CollectionUpserted { collection } => upsert_collection(tx, account, collection)?,
        EventBody::CollectionDeleted { collection } => {
            clear_collection(tx, account, collection)?;
            tx.execute(
                "DELETE FROM collections WHERE account = ?1 AND id = ?2",
                params![account, collection],
            )?;
        }
        EventBody::ObjectUpserted {
            collection,
            item,
            blob,
            version,
            content_type,
            ..
        } => put_placement(
            tx,
            account,
            collection,
            &item.id,
            blob,
            version.as_deref(),
            content_type,
        )?,
        EventBody::ObjectRemoved { collection, item } => {
            tx.execute(
                "DELETE FROM placements WHERE account = ?1 AND collection = ?2 AND item_id = ?3",
                params![account, collection, item.id],
            )?;
        }
        EventBody::ResyncRequired {
            collection,
            domain: None | Some(skein_core::Domain::Calendar | skein_core::Domain::Contacts),
            ..
        } => clear_collection(tx, account, collection)?,
        _ => return Ok(false),
    }
    Ok(true)
}

/// Replaces the account's collections and placements with the snapshot's.
pub(super) fn rebuild(
    tx: &Transaction<'_>,
    account: &str,
    snapshot: &Snapshot,
) -> Result<(), StoreError> {
    tx.execute(
        "DELETE FROM placements WHERE account = ?1",
        params![account],
    )?;
    tx.execute(
        "DELETE FROM collections WHERE account = ?1",
        params![account],
    )?;
    for (id, collection) in &snapshot.collections {
        let mut info = collection.info.clone();
        info.id.clone_from(id);
        upsert_collection(tx, account, &info)?;
        for state in collection.items.values() {
            put_placement(
                tx,
                account,
                id,
                &state.item.id,
                &state.blob,
                state.version.as_deref(),
                &state.content_type,
            )?;
        }
    }
    Ok(())
}

pub(super) fn drop_orphans(tx: &Transaction<'_>, account: &str) -> rusqlite::Result<()> {
    let orphans: Vec<i64> = tx
        .prepare_cached(
            "SELECT o.id FROM objects o WHERE o.account = ?1
             AND NOT EXISTS (SELECT 1 FROM placements p WHERE p.object = o.id)",
        )?
        .query_map(params![account], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    let mut fts = tx.prepare_cached("DELETE FROM contact_search WHERE rowid = ?1")?;
    let mut obj = tx.prepare_cached("DELETE FROM objects WHERE id = ?1")?;
    for id in orphans {
        fts.execute(params![id])?;
        obj.execute(params![id])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use skein_core::{CollectionKind, Domain, ItemRef, Seq};
    use skein_storage::{CollectionState, ObjectState};

    use super::super::tests::{ev, temp_store};
    use super::*;
    use crate::parse::tests::fixture;
    use crate::pim::parse_object;

    fn calendar(id: &str) -> CollectionInfo {
        CollectionInfo {
            id: id.into(),
            kind: CollectionKind::Calendar,
            name: "Garden".into(),
            color: Some("#336699FF".into()),
            read_only: false,
            components: vec!["VEVENT".into()],
            role: None,
        }
    }

    fn upserted(
        seq: u64,
        collection: &str,
        item: &str,
        ct: &str,
        bytes: &[u8],
    ) -> skein_core::Event {
        ev(
            seq,
            EventBody::ObjectUpserted {
                collection: collection.into(),
                item: ItemRef {
                    id: item.into(),
                    uid: None,
                },
                blob: BlobHash::of(bytes),
                size: bytes.len() as u64,
                version: Some(format!("v{seq}")),
                content_type: ct.into(),
            },
        )
    }

    fn store_object(s: &Store, ct: &str, bytes: &[u8]) {
        s.insert_object(
            "box",
            &BlobHash::of(bytes),
            bytes.len() as u64,
            ct,
            &parse_object(ct, Some(bytes)),
        )
        .unwrap();
    }

    #[test]
    fn collections_and_objects_follow_the_journal() {
        let (_d, s) = temp_store();
        let event = fixture("event.ics");
        let allday = fixture("allday.ics");
        let card = fixture("contact.vcf");
        store_object(&s, "text/calendar", &event);
        store_object(&s, "text/calendar", &allday);
        store_object(&s, "text/vcard", &card);
        let page = [
            ev(
                1,
                EventBody::CollectionUpserted {
                    collection: calendar("/cal/"),
                },
            ),
            upserted(2, "/cal/", "/cal/swap.ics", "text/calendar", &event),
            upserted(3, "/cal/", "/cal/closed.ics", "text/calendar", &allday),
            upserted(4, "/book/", "/book/j.vcf", "text/vcard", &card),
        ];
        s.apply_page("box", &page).unwrap();

        let cols = s.collections("box").unwrap();
        assert_eq!(cols.len(), 2);
        let book = cols.iter().find(|c| c.id == "/book/").unwrap();
        assert_eq!((book.kind.as_str(), book.count), ("address_book", 1));
        let cal = cols.iter().find(|c| c.id == "/cal/").unwrap();
        assert_eq!((cal.name.as_str(), cal.count), ("Garden", 2));

        let all = s
            .objects("box", "/cal/", None, Range::default(), 10)
            .unwrap();
        let items: Vec<&str> = all.iter().map(|o| o.item.as_str()).collect();
        assert_eq!(items, vec!["/cal/closed.ics", "/cal/swap.ics"]);
        assert_eq!(all[1].version.as_deref(), Some("v2"));
        let page = s
            .objects(
                "box",
                "/cal/",
                Some("/cal/closed.ics"),
                Range::default(),
                10,
            )
            .unwrap();
        assert_eq!(page.len(), 1);

        let dec = |d: u32| crate::pim::tests::day(2026, 12, d);
        let in_range = |from, to| {
            s.objects(
                "box",
                "/cal/",
                None,
                Range {
                    from: Some(from),
                    to: Some(to),
                },
                10,
            )
            .unwrap()
            .into_iter()
            .map(|o| o.item)
            .collect::<Vec<_>>()
        };
        assert_eq!(
            in_range(dec(24), dec(25)),
            vec!["/cal/closed.ics", "/cal/swap.ics"]
        );
        assert_eq!(in_range(dec(25), dec(26)), vec!["/cal/swap.ics"]);
        assert_eq!(
            in_range(dec(20), dec(21)),
            vec!["/cal/swap.ics"],
            "a recurring event starting earlier is listed"
        );
        assert!(in_range(dec(1), dec(5)).is_empty(), "nothing starts before");

        let fts = crate::search::fts_query("jord*").unwrap();
        let found = s.search_contacts("box", &fts, 10).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].placements[0].item, "/book/j.vcf");
        let fts = crate::search::fts_query("example.org").unwrap();
        assert_eq!(s.search_contacts("box", &fts, 10).unwrap().len(), 1);

        let removed = ev(
            5,
            EventBody::ObjectRemoved {
                collection: "/book/".into(),
                item: ItemRef {
                    id: "/book/j.vcf".into(),
                    uid: None,
                },
            },
        );
        let resync = ev(
            6,
            EventBody::ResyncRequired {
                collection: "/cal/".into(),
                reason: "sync_token".into(),
                domain: Some(Domain::Mail),
            },
        );
        s.apply_page("box", &[removed, resync]).unwrap();
        assert!(
            s.object("box", &BlobHash::of(&card).to_string())
                .unwrap()
                .is_none()
        );
        assert!(!s.has_object("box", &BlobHash::of(&card)).unwrap());
        let fts = crate::search::fts_query("jordan").unwrap();
        assert!(s.search_contacts("box", &fts, 10).unwrap().is_empty());
        assert_eq!(
            s.objects("box", "/cal/", None, Range::default(), 10)
                .unwrap()
                .len(),
            2
        );

        let resync = ev(
            7,
            EventBody::ResyncRequired {
                collection: "/cal/".into(),
                reason: "sync_token".into(),
                domain: Some(Domain::Calendar),
            },
        );
        let deleted = ev(
            8,
            EventBody::CollectionDeleted {
                collection: "/book/".into(),
            },
        );
        s.apply_page("box", &[resync, deleted]).unwrap();
        assert!(
            s.objects("box", "/cal/", None, Range::default(), 10)
                .unwrap()
                .is_empty()
        );
        assert!(!s.has_collection("box", "/book/").unwrap());
        assert!(!s.has_object("box", &BlobHash::of(&event)).unwrap());
    }

    #[test]
    fn objects_need_their_content_first_and_rebuild_from_snapshots() {
        let (_d, s) = temp_store();
        let event = fixture("event.ics");
        let card = fixture("contact.vcf");
        let missing = upserted(1, "/cal/", "a", "text/calendar", &event);
        assert!(matches!(
            s.apply_page("box", &[missing]),
            Err(StoreError::MissingContent)
        ));
        store_object(&s, "text/calendar", &event);
        s.apply_page("box", &[upserted(1, "/cal/", "a", "text/calendar", &event)])
            .unwrap();

        store_object(&s, "text/vcard", &card);
        let mut snap = Snapshot::empty(skein_core::AccountId::new("box").unwrap());
        snap.seq = Seq(30);
        let mut info = calendar("/book/");
        info.kind = CollectionKind::AddressBook;
        snap.collections.insert(
            "/book/".into(),
            CollectionState {
                info,
                items: [(
                    "j".to_owned(),
                    ObjectState {
                        item: ItemRef {
                            id: "j".into(),
                            uid: None,
                        },
                        blob: BlobHash::of(&card),
                        size: card.len() as u64,
                        version: Some("e1".into()),
                        content_type: "text/vcard".into(),
                    },
                )]
                .into(),
            },
        );
        s.rebuild("box", &snap).unwrap();
        let cols = s.collections("box").unwrap();
        assert_eq!(cols.len(), 1);
        assert_eq!(cols[0].kind, "address_book");
        let detail = s
            .object("box", &BlobHash::of(&card).to_string())
            .unwrap()
            .unwrap();
        assert_eq!(
            detail.object.fields.full_name.as_deref(),
            Some("Jordan Example")
        );
        assert_eq!(detail.placements[0].version.as_deref(), Some("e1"));
        assert!(!s.has_object("box", &BlobHash::of(&event)).unwrap());
    }
}
