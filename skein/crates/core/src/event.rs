use serde::{Deserialize, Serialize};

use crate::{AccountId, BlobHash, CommandId, Seq, Timestamp};

/// The version of the event format this build writes. Readers accept every version up to this
/// one; fields added in later versions are optional.
pub const SCHEMA_VERSION: u16 = 1;

/// One entry of an account's journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Format version the event was written with.
    pub v: u16,
    /// Position in the account's log, assigned when the event is appended.
    pub seq: Seq,
    /// When the node wrote the event.
    pub at: Timestamp,
    /// The account the event belongs to.
    pub account: AccountId,
    /// A key that is the same for the same change seen twice (for example after a node crashed
    /// between appending and saving its cursor), so the engine can drop repeats.
    pub key: String,
    /// The command that caused this change, when Skein made it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<CommandId>,
    /// W3C `traceparent` of the request that caused this change, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<String>,
    /// What happened.
    pub body: EventBody,
}

/// What an event says happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventBody {
    /// A mailbox appeared or changed its name, role or attributes.
    MailboxUpserted {
        /// The mailbox as it is now.
        mailbox: MailboxInfo,
    },
    /// A mailbox is gone.
    MailboxDeleted {
        /// Its id.
        mailbox: String,
    },
    /// A message is in a mailbox; its original bytes are the blob.
    MessageAdded {
        /// Mailbox id.
        mailbox: String,
        /// The message.
        item: ItemRef,
        /// Original RFC 5322 bytes.
        blob: BlobHash,
        /// Size of the blob in bytes.
        size: u64,
        /// Flags at the time it was seen.
        flags: Flags,
        /// Labels on servers that have them.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        labels: Option<Vec<String>>,
        /// When the server received it, if it says.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        received_at: Option<Timestamp>,
    },
    /// A message left a mailbox.
    MessageRemoved {
        /// Mailbox id.
        mailbox: String,
        /// The message.
        item: ItemRef,
    },
    /// A message's flags changed; `flags` is the full new set.
    FlagsChanged {
        /// Mailbox id.
        mailbox: String,
        /// The message.
        item: ItemRef,
        /// Every flag the message has now.
        flags: Flags,
    },
    /// A message's labels changed; `labels` is the full new set.
    LabelsChanged {
        /// Mailbox id.
        mailbox: String,
        /// The message.
        item: ItemRef,
        /// Every label the message has now.
        labels: Vec<String>,
    },
    /// The provider stopped accepting the cursor; a full listing of the collection follows, and
    /// consumers should treat items not listed again as gone.
    ResyncRequired {
        /// The collection (mailbox id) that is listed again.
        collection: String,
        /// A short machine-readable reason, such as `uidvalidity`.
        reason: String,
        /// Whether `collection` is a mailbox (`mail`) or a calendar or address book; missing in
        /// events written before this field existed, where readers clear both.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        domain: Option<crate::Domain>,
    },
    /// The first full listing of the account finished.
    FirstSyncCompleted,
    /// The account's health changed.
    AccountHealthChanged {
        /// The new state.
        health: AccountHealth,
    },
    /// A command reached the provider and was applied.
    WriteApplied {
        /// The command.
        command: CommandId,
    },
    /// A command's version precondition failed; the server's current version is the blob.
    Conflict {
        /// The command.
        command: CommandId,
        /// The server's version, when it could be read.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server_blob: Option<BlobHash>,
    },
    /// A command failed for good.
    WriteFailed {
        /// The command.
        command: CommandId,
        /// A short machine-readable reason.
        reason: String,
    },
    /// A command was sent but no answer came back; it may or may not have been applied.
    WriteUncertain {
        /// The command.
        command: CommandId,
    },
    /// What became of a `send` command's recipients and its copy in Sent. Follows the command's
    /// `WriteApplied`, or its `WriteFailed` when every recipient was refused.
    SendResult {
        /// The command.
        command: CommandId,
        /// Recipients the sending service refused; the message did not go to them. Empty when it
        /// took every recipient.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        refused: Vec<RefusedRecipient>,
        /// Where the sent copy is, when the message was sent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sent_copy: Option<SentCopy>,
        /// The `Message-ID` recipients got (`<id@host>`), when the sending service replaced the
        /// message's own (Amazon SES does). A sent copy the engine saved carries this one, with
        /// the original in `X-Skein-Original-Message-ID`. Absent when the service kept the
        /// message's own `Message-ID` or the sender cannot know.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message_id: Option<String>,
        /// The sending service's own id for the message (an SES `MessageId`, a Gmail message
        /// id, a JMAP submission id), for matching the service's notifications. Absent when it
        /// gave none.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider_message_id: Option<String>,
        /// The command was a dry run: every check passed and nothing was handed over or saved,
        /// so `refused` is empty and `sent_copy` absent.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        dry_run: bool,
    },
    /// An address book or calendar appeared or changed its name, color or access.
    CollectionUpserted {
        /// The collection as it is now.
        collection: CollectionInfo,
    },
    /// An address book or calendar is gone, with every object in it.
    CollectionDeleted {
        /// Its id.
        collection: String,
    },
    /// An event, task or contact is in a collection as these bytes; a later one for the same item
    /// replaces it.
    ObjectUpserted {
        /// Collection id.
        collection: String,
        /// The object.
        item: ItemRef,
        /// Original iCalendar or vCard bytes, exactly as the provider sent them.
        blob: BlobHash,
        /// Size of the blob in bytes.
        size: u64,
        /// The provider's version of these bytes (an ETag, a `changeKey`), for `if_version`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        version: Option<String>,
        /// The media type of the bytes, such as `text/calendar` or `text/vcard`.
        content_type: String,
    },
    /// An object left a collection.
    ObjectRemoved {
        /// Collection id.
        collection: String,
        /// The object.
        item: ItemRef,
    },
    /// A message in a mailbox carries an iTIP message (an iMIP invitation, answer or
    /// cancellation, RFC 6047). Follows the message's `message_added`; the blob is its
    /// `text/calendar` part, decoded. Whether to trust or apply it is the consumer's decision.
    ItipReceived {
        /// Mailbox id.
        mailbox: String,
        /// The message.
        item: ItemRef,
        /// The `text/calendar` part's bytes.
        blob: BlobHash,
        /// Size of the blob in bytes.
        size: u64,
        /// What the part says.
        itip: Box<crate::ItipSummary>,
    },
    /// Who was told about a scheduling command (`put_object` or `delete_object` with `notify`,
    /// `respond_object`). Follows the command's `write_applied`.
    ScheduleResult {
        /// The command.
        command: CommandId,
        /// Who told them.
        via: crate::ScheduleVia,
        /// For `mail`, each iMIP message.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        messages: Vec<crate::ScheduleMessage>,
        /// A short machine-readable reason, for `none` (such as `not_organizer`, `no_attendees`
        /// or `no_sender`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// What the account's mail provider can do changed, or is known for the first time.
    AccountCapabilities {
        /// The mail capabilities.
        mail: MailCapabilities,
    },
    /// An event type this build does not know, written by a newer one.
    #[serde(other)]
    Unknown,
}

/// What a mail provider can do for an account, so consumers offer only commands that can
/// work.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailCapabilities {
    /// System flags `set_flags` can change, such as `\Seen` and `\Flagged`.
    #[serde(default)]
    pub system_flags: Vec<String>,
    /// Whether other keywords (`$Forwarded`, custom words) can be set.
    #[serde(default)]
    pub keywords: bool,
    /// Whether messages carry labels that `set_labels` changes.
    #[serde(default)]
    pub labels: bool,
    /// Whether `delete` with `to_trash` works.
    #[serde(default)]
    pub trash: bool,
    /// Whether `copy` works.
    #[serde(default)]
    pub copy: bool,
    /// Whether `append` honours `received_at`.
    #[serde(default)]
    pub append_received_at: bool,
    /// Whether `create_mailbox`, `rename_mailbox` and `delete_mailbox` work.
    #[serde(default)]
    pub mailboxes: bool,
}

/// A recipient the sending service refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefusedRecipient {
    /// The address as it was in the envelope.
    pub address: String,
    /// The SMTP reply code, or the closest one for services that do not speak SMTP.
    pub code: u16,
    /// Whether the service said not to try again (`5xx`).
    pub permanent: bool,
}

/// Where the copy of a sent message is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SentCopy {
    /// The sending service keeps it in Sent by itself.
    Provider,
    /// Skein appended it to the mailbox the command named.
    Saved,
    /// Appending it failed; the message was sent all the same.
    Failed,
}

/// How an account is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountHealth {
    /// Syncing normally.
    Healthy,
    /// The provider refused the credentials; a person must sign in again.
    ReauthRequired,
    /// The provider is limiting requests; syncing continues more slowly.
    Throttled,
    /// Repeated errors other than the above.
    Degraded,
}

/// A message, event or contact as the provider identifies it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ItemRef {
    /// The provider's id, stable for as long as the provider keeps it.
    pub id: String,
    /// The IMAP UID, where there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
}

/// A mailbox or label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxInfo {
    /// Stable id: the path with `/` between levels on IMAP, the provider's id elsewhere.
    pub id: String,
    /// Path with `/` between levels, for display.
    pub path: String,
    /// What the mailbox is for, when the provider says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<MailboxRole>,
    /// Whether it can hold messages.
    pub selectable: bool,
    /// Whether it is a label shown as a mailbox (Gmail), whose messages also sit in `All`.
    #[serde(default)]
    pub label: bool,
}

/// An address book or calendar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionInfo {
    /// Stable id: the collection's path on DAV servers, the provider's id elsewhere.
    pub id: String,
    /// Calendar or address book.
    pub kind: CollectionKind,
    /// The name the provider gives it, or one made from its id.
    pub name: String,
    /// The color the provider gives it, as written (such as `#336699FF`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    /// Whether the account may not change objects in it.
    #[serde(default)]
    pub read_only: bool,
    /// For calendars, the component types it may hold in upper case (`VEVENT`, `VTODO`); empty
    /// when the provider does not say, and for address books.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<String>,
    /// What the collection is for, when it is not an ordinary calendar or address book.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<CollectionRole>,
}

/// The special purpose of a collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionRole {
    /// A CalDAV scheduling inbox (RFC 6638): iTIP messages the server delivered to the account,
    /// such as invitations from users of the same server. Consumers delete them with
    /// `delete_object` once handled.
    ScheduleInbox,
}

/// What a collection holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionKind {
    /// iCalendar objects: events, tasks or both.
    Calendar,
    /// vCards.
    AddressBook,
}

impl CollectionKind {
    /// The media type of the objects it holds: `text/calendar` or `text/vcard`.
    pub fn media_type(self) -> &'static str {
        match self {
            Self::Calendar => "text/calendar",
            Self::AddressBook => "text/vcard",
        }
    }
}

/// The purpose of a mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailboxRole {
    /// Incoming mail.
    Inbox,
    /// Sent mail.
    Sent,
    /// Drafts.
    Drafts,
    /// Deleted mail.
    Trash,
    /// Spam.
    Junk,
    /// Archived mail.
    Archive,
    /// Every message (Gmail's All Mail).
    All,
    /// Flagged messages, a virtual mailbox.
    Flagged,
}

/// A message's flags: IMAP system flags (`\Seen`, `\Flagged`, `\Answered`, `\Draft`,
/// `\Deleted`) and keywords, sorted and without repeats.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Flags(Vec<String>);

impl Flags {
    /// The flags in `items`, sorted and without repeats.
    pub fn new<I, S>(items: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut v: Vec<String> = items.into_iter().map(Into::into).collect();
        v.sort();
        v.dedup();
        Self(v)
    }

    /// Whether `flag` is set.
    pub fn contains(&self, flag: &str) -> bool {
        self.0.binary_search_by(|f| f.as_str().cmp(flag)).is_ok()
    }

    /// The flags, sorted.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(body: EventBody) -> Event {
        Event {
            v: SCHEMA_VERSION,
            seq: Seq(1),
            at: Timestamp(0),
            account: AccountId::new("a").unwrap(),
            key: "k".into(),
            origin: None,
            trace: None,
            body,
        }
    }

    #[test]
    fn round_trips_through_json() {
        let e = event(EventBody::MessageAdded {
            mailbox: "INBOX".into(),
            item: ItemRef {
                id: "7:42".into(),
                uid: Some(42),
            },
            blob: BlobHash::of(b"x"),
            size: 1,
            flags: Flags::new(["\\Seen"]),
            labels: None,
            received_at: Some(Timestamp(5)),
        });
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"type\":\"message_added\""));
        assert_eq!(serde_json::from_str::<Event>(&json).unwrap(), e);
    }

    #[test]
    fn collection_events_round_trip() {
        let e = event(EventBody::CollectionUpserted {
            collection: CollectionInfo {
                id: "/dav/calendars/ada/work/".into(),
                kind: CollectionKind::Calendar,
                name: "Work".into(),
                color: None,
                read_only: false,
                components: vec!["VEVENT".into()],
                role: None,
            },
        });
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"type\":\"collection_upserted\""));
        assert!(json.contains("\"kind\":\"calendar\""));
        assert_eq!(serde_json::from_str::<Event>(&json).unwrap(), e);
        let o = event(EventBody::ObjectUpserted {
            collection: "/c/".into(),
            item: ItemRef {
                id: "/c/a.ics".into(),
                uid: None,
            },
            blob: BlobHash::of(b"x"),
            size: 1,
            version: Some("\"1\"".into()),
            content_type: "text/calendar".into(),
        });
        let json = serde_json::to_string(&o).unwrap();
        assert_eq!(serde_json::from_str::<Event>(&json).unwrap(), o);
        assert_eq!(CollectionKind::AddressBook.media_type(), "text/vcard");
    }

    #[test]
    fn unknown_event_types_from_newer_writers_still_parse() {
        let json = r#"{"v":9,"seq":3,"at":0,"account":"a","key":"k","body":{"type":"from_the_future","x":1}}"#;
        let e: Event = serde_json::from_str(json).unwrap();
        assert_eq!(e.body, EventBody::Unknown);
    }

    #[test]
    fn flags_are_sorted_and_unique() {
        let f = Flags::new(["\\Seen", "\\Flagged", "\\Seen"]);
        assert_eq!(f.iter().collect::<Vec<_>>(), vec!["\\Flagged", "\\Seen"]);
        assert!(f.contains("\\Seen"));
        assert!(!f.contains("\\Draft"));
    }
}
