use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use skein_core::{
    AccountId, BlobHash, CollectionInfo, CollectionKind, Event, EventBody, Flags, ItemRef,
    MailboxInfo, Seq, Timestamp,
};

/// The snapshot format version this build writes.
pub const SNAPSHOT_VERSION: u16 = 1;

/// The state of an account at a position of its log: every mailbox and every message in it, and
/// every address book and calendar with every object in it, as the events up to `seq` describe
/// them. A consumer loads the latest snapshot and reads the
/// log after `seq` instead of reading the log from the start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// Format version.
    pub v: u16,
    /// The account.
    pub account: AccountId,
    /// The last event the snapshot includes; `Seq(0)` for an empty snapshot.
    pub seq: Seq,
    /// When the snapshot was made.
    pub at: Timestamp,
    /// Mailboxes by id.
    pub mailboxes: BTreeMap<String, MailboxState>,
    /// Address books and calendars by id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub collections: BTreeMap<String, CollectionState>,
}

/// An address book or calendar in a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionState {
    /// The collection as last described.
    pub info: CollectionInfo,
    /// Objects by provider id.
    pub items: BTreeMap<String, ObjectState>,
}

/// An event, task or contact in a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectState {
    /// The object.
    pub item: ItemRef,
    /// Its original bytes.
    pub blob: BlobHash,
    /// Size of the blob.
    pub size: u64,
    /// The provider's version of those bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The media type of the bytes.
    pub content_type: String,
}

/// A mailbox in a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxState {
    /// The mailbox as last described.
    pub info: MailboxInfo,
    /// Messages by provider id.
    pub items: BTreeMap<String, ItemState>,
}

/// A message in a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemState {
    /// The message.
    pub item: ItemRef,
    /// Its original bytes.
    pub blob: BlobHash,
    /// Size of the blob.
    pub size: u64,
    /// Current flags.
    pub flags: Flags,
    /// Current labels, on servers that have them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
    /// When the server received it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_at: Option<Timestamp>,
}

impl Snapshot {
    /// The state before the first event.
    pub fn empty(account: AccountId) -> Self {
        Self {
            v: SNAPSHOT_VERSION,
            account,
            seq: Seq(0),
            at: Timestamp(0),
            mailboxes: BTreeMap::new(),
            collections: BTreeMap::new(),
        }
    }

    fn collection(&mut self, id: &str, content_type: &str) -> &mut CollectionState {
        self.collections
            .entry(id.to_owned())
            .or_insert_with(|| CollectionState {
                info: CollectionInfo {
                    id: id.to_owned(),
                    kind: if content_type.starts_with("text/vcard") {
                        CollectionKind::AddressBook
                    } else {
                        CollectionKind::Calendar
                    },
                    name: id.to_owned(),
                    color: None,
                    read_only: false,
                    components: Vec::new(),
                    role: None,
                },
                items: BTreeMap::new(),
            })
    }

    fn mailbox(&mut self, id: &str) -> &mut MailboxState {
        self.mailboxes
            .entry(id.to_owned())
            .or_insert_with(|| MailboxState {
                info: MailboxInfo {
                    id: id.to_owned(),
                    path: id.to_owned(),
                    role: None,
                    selectable: true,
                    label: false,
                },
                items: BTreeMap::new(),
            })
    }

    /// Applies the next event. Events must come in log order without gaps; others are ignored
    /// so applying a page twice is harmless. Events that do not change mailbox or collection
    /// state (command outcomes, health) only move `seq`. `resync_required` empties the mailbox
    /// and the collection with that id, since the listing that follows names everything still
    /// there.
    pub fn apply(&mut self, event: &Event) {
        if event.seq.0 != self.seq.0 + 1 {
            return;
        }
        self.seq = event.seq;
        match &event.body {
            EventBody::MailboxUpserted { mailbox } => {
                self.mailbox(&mailbox.id).info = mailbox.clone();
            }
            EventBody::MailboxDeleted { mailbox } => {
                self.mailboxes.remove(mailbox);
            }
            EventBody::MessageAdded {
                mailbox,
                item,
                blob,
                size,
                flags,
                labels,
                received_at,
            } => {
                self.mailbox(mailbox).items.insert(
                    item.id.clone(),
                    ItemState {
                        item: item.clone(),
                        blob: *blob,
                        size: *size,
                        flags: flags.clone(),
                        labels: labels.clone(),
                        received_at: *received_at,
                    },
                );
            }
            EventBody::MessageRemoved { mailbox, item } => {
                if let Some(m) = self.mailboxes.get_mut(mailbox) {
                    m.items.remove(&item.id);
                }
            }
            EventBody::FlagsChanged {
                mailbox,
                item,
                flags,
            } => {
                if let Some(state) = self
                    .mailboxes
                    .get_mut(mailbox)
                    .and_then(|m| m.items.get_mut(&item.id))
                {
                    state.flags = flags.clone();
                }
            }
            EventBody::LabelsChanged {
                mailbox,
                item,
                labels,
            } => {
                if let Some(state) = self
                    .mailboxes
                    .get_mut(mailbox)
                    .and_then(|m| m.items.get_mut(&item.id))
                {
                    state.labels = Some(labels.clone());
                }
            }
            EventBody::ResyncRequired {
                collection, domain, ..
            } => {
                let mail = matches!(domain, None | Some(skein_core::Domain::Mail));
                let pim = !matches!(domain, Some(skein_core::Domain::Mail));
                if mail && let Some(m) = self.mailboxes.get_mut(collection) {
                    m.items.clear();
                }
                if pim && let Some(c) = self.collections.get_mut(collection) {
                    c.items.clear();
                }
            }
            EventBody::CollectionUpserted { collection } => {
                let ct = collection.kind.media_type();
                self.collection(&collection.id, ct).info = collection.clone();
            }
            EventBody::CollectionDeleted { collection } => {
                self.collections.remove(collection);
            }
            EventBody::ObjectUpserted {
                collection,
                item,
                blob,
                size,
                version,
                content_type,
            } => {
                self.collection(collection, content_type).items.insert(
                    item.id.clone(),
                    ObjectState {
                        item: item.clone(),
                        blob: *blob,
                        size: *size,
                        version: version.clone(),
                        content_type: content_type.clone(),
                    },
                );
            }
            EventBody::ObjectRemoved { collection, item } => {
                if let Some(c) = self.collections.get_mut(collection) {
                    c.items.remove(&item.id);
                }
            }
            _ => {}
        }
    }

    /// How many messages the snapshot holds, over all mailboxes.
    pub fn message_count(&self) -> usize {
        self.mailboxes.values().map(|m| m.items.len()).sum()
    }

    /// How many events, tasks and contacts the snapshot holds, over all collections.
    pub fn object_count(&self) -> usize {
        self.collections.values().map(|c| c.items.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use skein_core::{SCHEMA_VERSION, TenantId};

    use super::*;

    fn ev(seq: u64, body: EventBody) -> Event {
        Event {
            v: SCHEMA_VERSION,
            seq: Seq(seq),
            at: Timestamp(seq as i64),
            account: AccountId::new("a").unwrap(),
            key: format!("k{seq}"),
            origin: None,
            trace: None,
            body,
        }
    }

    fn item(n: u32) -> ItemRef {
        ItemRef {
            id: format!("1:{n}"),
            uid: Some(n),
        }
    }

    fn added(seq: u64, mailbox: &str, n: u32) -> Event {
        ev(
            seq,
            EventBody::MessageAdded {
                mailbox: mailbox.into(),
                item: item(n),
                blob: BlobHash::of(&n.to_le_bytes()),
                size: 4,
                flags: Flags::default(),
                labels: None,
                received_at: None,
            },
        )
    }

    #[test]
    fn folds_events_into_state_and_ignores_gaps_and_repeats() {
        let _ = TenantId::new("t").unwrap();
        let mut s = Snapshot::empty(AccountId::new("a").unwrap());
        let events = vec![
            added(1, "INBOX", 1),
            added(2, "INBOX", 2),
            ev(
                3,
                EventBody::FlagsChanged {
                    mailbox: "INBOX".into(),
                    item: item(1),
                    flags: Flags::new(["\\Seen"]),
                },
            ),
            ev(
                4,
                EventBody::MessageRemoved {
                    mailbox: "INBOX".into(),
                    item: item(2),
                },
            ),
            added(5, "Archive", 7),
            ev(
                6,
                EventBody::ResyncRequired {
                    collection: "Archive".into(),
                    reason: "uidvalidity".into(),
                    domain: None,
                },
            ),
            added(7, "Archive", 8),
            ev(8, EventBody::FirstSyncCompleted),
        ];
        for e in &events {
            s.apply(e);
        }
        s.apply(&events[2]);
        s.apply(&added(20, "INBOX", 99));
        assert_eq!(s.seq, Seq(8));
        assert_eq!(s.message_count(), 2);
        assert!(s.mailboxes["INBOX"].items["1:1"].flags.contains("\\Seen"));
        assert!(!s.mailboxes["INBOX"].items.contains_key("1:2"));
        assert_eq!(
            s.mailboxes["Archive"].items.keys().collect::<Vec<_>>(),
            vec!["1:8"],
            "a reset drops what is not listed again"
        );
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<Snapshot>(&json).unwrap(), s);
    }

    fn object(seq: u64, collection: &str, id: &str, version: &str) -> Event {
        ev(
            seq,
            EventBody::ObjectUpserted {
                collection: collection.into(),
                item: ItemRef {
                    id: id.into(),
                    uid: None,
                },
                blob: BlobHash::of(version.as_bytes()),
                size: version.len() as u64,
                version: Some(version.into()),
                content_type: "text/calendar".into(),
            },
        )
    }

    #[test]
    fn folds_collections_and_objects() {
        let mut s = Snapshot::empty(AccountId::new("a").unwrap());
        let info = CollectionInfo {
            id: "/cal/".into(),
            kind: CollectionKind::Calendar,
            name: "Work".into(),
            color: Some("#336699".into()),
            read_only: false,
            components: vec!["VEVENT".into()],
            role: None,
        };
        let events = vec![
            ev(
                1,
                EventBody::CollectionUpserted {
                    collection: info.clone(),
                },
            ),
            object(2, "/cal/", "/cal/a.ics", "1"),
            object(3, "/cal/", "/cal/b.ics", "2"),
            object(4, "/cal/", "/cal/a.ics", "3"),
            ev(
                5,
                EventBody::ObjectRemoved {
                    collection: "/cal/".into(),
                    item: ItemRef {
                        id: "/cal/b.ics".into(),
                        uid: None,
                    },
                },
            ),
            object(6, "/book/", "/book/c.vcf", "4"),
            ev(
                7,
                EventBody::ResyncRequired {
                    collection: "/book/".into(),
                    reason: "sync_token".into(),
                    domain: Some(skein_core::Domain::Contacts),
                },
            ),
            object(8, "/old/", "/old/x.ics", "5"),
            ev(
                9,
                EventBody::CollectionDeleted {
                    collection: "/old/".into(),
                },
            ),
        ];
        for e in &events {
            s.apply(e);
        }
        assert_eq!(s.seq, Seq(9));
        assert_eq!(s.collections["/cal/"].info, info);
        assert_eq!(s.object_count(), 1);
        let a = &s.collections["/cal/"].items["/cal/a.ics"];
        assert_eq!(a.version.as_deref(), Some("3"));
        assert!(s.collections["/book/"].items.is_empty());
        assert!(!s.collections.contains_key("/old/"));
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<Snapshot>(&json).unwrap(), s);
        let empty = serde_json::to_string(&Snapshot::empty(AccountId::new("a").unwrap())).unwrap();
        assert!(
            !empty.contains("collections"),
            "old readers see the same format"
        );
    }
}

#[cfg(test)]
mod domain_tests {
    use skein_core::{Domain, SCHEMA_VERSION, Seq, Timestamp};

    use super::*;

    fn ev(seq: u64, body: EventBody) -> Event {
        Event {
            v: SCHEMA_VERSION,
            seq: Seq(seq),
            at: Timestamp(0),
            account: AccountId::new("a").unwrap(),
            key: format!("k{seq}"),
            origin: None,
            trace: None,
            body,
        }
    }

    #[test]
    fn a_reset_clears_only_its_own_domain() {
        let mut s = Snapshot::empty(AccountId::new("a").unwrap());
        s.apply(&ev(
            1,
            EventBody::MessageAdded {
                mailbox: "same".into(),
                item: ItemRef {
                    id: "m".into(),
                    uid: Some(1),
                },
                blob: BlobHash::of(b"m"),
                size: 1,
                flags: Flags::default(),
                labels: None,
                received_at: None,
            },
        ));
        s.apply(&ev(
            2,
            EventBody::ObjectUpserted {
                collection: "same".into(),
                item: ItemRef {
                    id: "o".into(),
                    uid: None,
                },
                blob: BlobHash::of(b"o"),
                size: 1,
                version: Some("1".into()),
                content_type: "text/calendar".into(),
            },
        ));
        s.apply(&ev(
            3,
            EventBody::ResyncRequired {
                collection: "same".into(),
                reason: "x".into(),
                domain: Some(Domain::Calendar),
            },
        ));
        assert_eq!(
            s.message_count(),
            1,
            "the mailbox with the same id keeps its messages"
        );
        assert_eq!(s.object_count(), 0);
    }
}
