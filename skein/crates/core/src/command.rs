use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use crate::{AccountId, BlobHash, Flags, InvalidId, ItemRef, PartStat, Timestamp};

/// A command's id: a ULID chosen by whoever submits it. It is also the idempotency key, so
/// submitting the same id twice runs the command once. ULIDs sort by creation time.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct CommandId(String);

impl CommandId {
    /// A new id for now.
    pub fn generate() -> Self {
        Self(ulid::Ulid::generate().to_string())
    }

    /// Checks that `value` is a ULID in canonical form (26 Crockford base32 characters).
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidId> {
        let value = value.into();
        match ulid::Ulid::from_string(&value) {
            Ok(u) if u.to_string() == value => Ok(Self(value)),
            _ => Err(InvalidId),
        }
    }

    /// The id as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CommandId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for CommandId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CommandId({})", self.0)
    }
}

impl<'de> Deserialize<'de> for CommandId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::new(s).map_err(serde::de::Error::custom)
    }
}

/// A request to change something at the provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Command {
    /// Id and idempotency key.
    pub id: CommandId,
    /// The account to change.
    pub account: AccountId,
    /// When it was submitted.
    pub created_at: Timestamp,
    /// W3C `traceparent` of the request, carried to the events the command causes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<String>,
    /// What to do.
    pub body: CommandBody,
}

/// What a command asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CommandBody {
    /// Add and remove flags. Adding and removing commute, so this never conflicts.
    SetFlags {
        /// Mailbox id.
        mailbox: String,
        /// Messages to change.
        items: Vec<ItemRef>,
        /// Flags to add.
        add: Flags,
        /// Flags to remove.
        remove: Flags,
    },
    /// Move messages to another mailbox.
    Move {
        /// Source mailbox id.
        from: String,
        /// Target mailbox id.
        to: String,
        /// Messages to move.
        items: Vec<ItemRef>,
    },
    /// Delete messages: for good, or into the account's trash.
    Delete {
        /// Mailbox id.
        mailbox: String,
        /// Messages to delete.
        items: Vec<ItemRef>,
        /// Move them to the account's trash (Gmail's `TRASH`, Graph's Deleted Items, the IMAP or
        /// JMAP mailbox with the trash role) instead of deleting them for good. Fails with
        /// `no_trash` where the account has none. Messages already in the trash stay there.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        to_trash: bool,
    },
    /// Copy messages into another mailbox; the originals stay. On servers with labels (Gmail)
    /// this adds the target's label.
    Copy {
        /// Source mailbox id.
        from: String,
        /// Target mailbox id.
        to: String,
        /// Messages to copy.
        items: Vec<ItemRef>,
    },
    /// Add and remove labels without moving messages, on servers with labels (Gmail, IMAP on
    /// Gmail). Labels are named as `message_added` reports them. Adding and removing commute.
    SetLabels {
        /// Mailbox id the items were listed in.
        mailbox: String,
        /// Messages to change.
        items: Vec<ItemRef>,
        /// Labels to add.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        add: Vec<String>,
        /// Labels to remove.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        remove: Vec<String>,
    },
    /// Create a mailbox (or label) at `path`, with `/` between levels. Fails with `exists` when
    /// one is there.
    CreateMailbox {
        /// The new mailbox's path.
        path: String,
    },
    /// Rename or move a mailbox. Fails with `protected` for system mailboxes such as the inbox.
    RenameMailbox {
        /// Mailbox id.
        mailbox: String,
        /// The new path, with `/` between levels.
        path: String,
    },
    /// Delete a mailbox and, where the server does so, the messages in it. Fails with
    /// `protected` for system mailboxes.
    DeleteMailbox {
        /// Mailbox id.
        mailbox: String,
    },
    /// Put a message from the blob store into a mailbox.
    Append {
        /// Mailbox id.
        mailbox: String,
        /// The message bytes.
        blob: BlobHash,
        /// Flags to set.
        flags: Flags,
        /// The time the server records as received (IMAP's internal date, JMAP's `receivedAt`),
        /// where the provider can set it (`append_received_at` in the account's capabilities);
        /// ignored elsewhere.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        received_at: Option<Timestamp>,
    },
    /// Download a message again (its blob expired from the store).
    Refetch {
        /// Mailbox id.
        mailbox: String,
        /// The message.
        item: ItemRef,
    },
    /// Send a message from the blob store through the account's sending service.
    ///
    /// The bytes are handed over unchanged, to exactly the envelope's recipients (Bcc recipients
    /// are in the envelope and not in the bytes). A message whose outcome is unknown is never sent
    /// again.
    Send {
        /// The RFC 5322 message, with CRLF line endings.
        blob: BlobHash,
        /// Who it is from and who gets it.
        envelope: SendEnvelope,
        /// The mailbox id to keep a copy in, when the sending service does not keep one itself.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        save_to_sent: Option<String>,
        /// Not before this time; the command stays queued until then.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        send_at: Option<Timestamp>,
        /// Check everything a real send checks (the envelope, the blob, the message, the
        /// account's sender) without handing the message over or saving a copy. It succeeds with
        /// `write_applied` and a `send_result` marked `dry_run`, and fails with the same reasons
        /// a real send would.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        dry_run: bool,
    },
    /// Create an object in a collection, or replace one, with bytes from the blob store.
    ///
    /// The bytes are sent unchanged. A create (`item` is `None`) never overwrites anything; the
    /// provider names the new object. A replace with `if_version` conflicts when the provider's
    /// version is no longer that one.
    PutObject {
        /// Collection id.
        collection: String,
        /// The object to replace; `None` creates one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        item: Option<ItemRef>,
        /// The iCalendar or vCard bytes.
        blob: BlobHash,
        /// The version the change was made against, from `object_upserted`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        if_version: Option<String>,
        /// Tell the attendees when the account organizes the event: the provider's server does
        /// where it schedules, otherwise Skein mails `REQUEST` to every attendee and `CANCEL` to
        /// those removed. Off by default; servers that always schedule (Graph, CalDAV with
        /// `calendar-auto-schedule`) tell them either way.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        notify: bool,
    },
    /// Delete an object from a collection. One that is already gone counts as deleted.
    DeleteObject {
        /// Collection id.
        collection: String,
        /// The object.
        item: ItemRef,
        /// The version the deletion was decided against; it conflicts when the provider's version
        /// is no longer that one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        if_version: Option<String>,
        /// Tell the attendees when the account organizes the event, as for `put_object`; where
        /// Skein mails, they get `CANCEL`.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        notify: bool,
    },
    /// Answer an invitation held in a calendar: set the account's participation status on the
    /// event and, with `notify`, tell the organizer (through the provider's server where it
    /// schedules, otherwise as an iMIP `REPLY`). For one instance of a recurring event, name the
    /// instance's object where the provider has one per instance.
    RespondObject {
        /// Collection id.
        collection: String,
        /// The event.
        item: ItemRef,
        /// The answer.
        answer: PartStat,
        /// The attendee address that answers; by default the account's own address among the
        /// attendees, as the provider knows it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        attendee: Option<String>,
        /// A note for the organizer.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        comment: Option<String>,
        /// The version the answer was made against.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        if_version: Option<String>,
        /// Tell the organizer. On by default.
        #[serde(default = "yes", skip_serializing_if = "Clone::clone")]
        notify: bool,
    },
    /// Answer an invitation that came by mail (iMIP) with an iTIP `REPLY` mailed to its
    /// organizer through the account's sending service, with the retry and uncertainty rules of
    /// `send`. Nothing in any calendar changes.
    RespondInvitation {
        /// The invitation: the whole message from `message_added`, or its `text/calendar` part
        /// from `itip_received`.
        invitation: BlobHash,
        /// The answer.
        answer: PartStat,
        /// The attendee address that answers; by default the one attendee the message was
        /// addressed to (`To` or `Cc`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        attendee: Option<String>,
        /// A note for the organizer.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        comment: Option<String>,
        /// The mailbox id to keep a copy in, when the sending service does not keep one itself.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        save_to_sent: Option<String>,
    },
    /// A command type this build does not know.
    #[serde(other)]
    Unknown,
}

impl CommandBody {
    /// Whether the command changes calendars or address books (`put_object`, `delete_object`,
    /// `respond_object`)
    /// rather than mail, so it is run against the account's calendar and contacts provider.
    pub fn is_collection_command(&self) -> bool {
        matches!(
            self,
            Self::PutObject { .. } | Self::DeleteObject { .. } | Self::RespondObject { .. }
        )
    }

    /// Whether the command sends mail (`send`, `respond_invitation`), so it follows the sending
    /// rules: scheduled and retried while certainly not sent, never repeated once it may have
    /// left.
    pub fn is_send(&self) -> bool {
        matches!(self, Self::Send { .. } | Self::RespondInvitation { .. })
    }
}

fn yes() -> bool {
    true
}

/// The most recipients one `send` command may have.
pub const MAX_RECIPIENTS: usize = 500;

const MAX_ADDRESS: usize = 320;

/// Who a message is from and who it goes to, separate from its headers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendEnvelope {
    /// The return path (`MAIL FROM`), a bare address.
    pub from: String,
    /// Every recipient (`RCPT TO`), bare addresses, in the order they are offered.
    pub to: Vec<String>,
    /// Delivery status notifications to ask for, where the sending service offers them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dsn: Option<Dsn>,
}

/// Why a [`SendEnvelope`] cannot be used. The text never repeats an address.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct InvalidEnvelope(pub &'static str);

impl SendEnvelope {
    /// Checks that `from` and every recipient look like bare addresses (an `@` with text on both
    /// sides, at most 320 bytes, no whitespace, control characters, angle brackets, commas,
    /// semicolons or quotes, so nothing can end a header or an SMTP command), and that there are
    /// 1 to [`MAX_RECIPIENTS`] recipients.
    pub fn check(&self) -> Result<(), InvalidEnvelope> {
        if !plausible_address(&self.from) {
            return Err(InvalidEnvelope("the sender is not an address"));
        }
        if self.to.is_empty() {
            return Err(InvalidEnvelope("there is no recipient"));
        }
        if self.to.len() > MAX_RECIPIENTS {
            return Err(InvalidEnvelope("there are more than 500 recipients"));
        }
        if !self.to.iter().all(|r| plausible_address(r)) {
            return Err(InvalidEnvelope("a recipient is not an address"));
        }
        Ok(())
    }
}

/// Whether `address` looks like a bare address that is safe in a header or an SMTP command.
pub fn plausible_address(address: &str) -> bool {
    let Some((local, domain)) = address.rsplit_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && address.len() <= MAX_ADDRESS
        && !address.chars().any(|c| {
            c.is_whitespace() || c.is_control() || matches!(c, '<' | '>' | ',' | ';' | '"')
        })
}

/// Delivery status notifications to ask for (RFC 3461).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dsn {
    /// When to notify; empty leaves it to the server. `never` alone turns notifications off.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notify: Vec<DsnNotify>,
    /// How much of the message a notification returns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ret: Option<DsnReturn>,
}

/// When a delivery status notification is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DsnNotify {
    /// Never.
    Never,
    /// On delivery.
    Success,
    /// On failure.
    Failure,
    /// When delivery is delayed.
    Delay,
}

/// What a delivery status notification carries of the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DsnReturn {
    /// The whole message.
    Full,
    /// Only its header.
    Headers,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_ulids_parse_and_new_ones_sort_after_them() {
        let old = CommandId::new("01D39ZY06FGSCTVN4T2V9PKHFZ").unwrap();
        let parsed = ulid::Ulid::from_string(old.as_str()).unwrap();
        assert_eq!(parsed.timestamp_ms(), 1_549_744_931_023);
        assert_eq!(parsed.to_string(), old.as_str());
        let first = CommandId::generate();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let later = CommandId::generate();
        assert_eq!(later.as_str().len(), 26);
        assert!(old < first && first < later, "{old} {first} {later}");
    }

    #[test]
    fn ids_are_canonical_ulids() {
        let id = CommandId::generate();
        assert_eq!(CommandId::new(id.as_str()).unwrap(), id);
        assert!(CommandId::new("01arz3ndektsv4rrffq69g5fav").is_err());
        assert!(CommandId::new("../../etc/passwd").is_err());
        assert!(CommandId::new("").is_err());
    }

    fn envelope(from: &str, to: &[&str]) -> SendEnvelope {
        SendEnvelope {
            from: from.into(),
            to: to.iter().map(|s| (*s).to_owned()).collect(),
            dsn: None,
        }
    }

    #[test]
    fn send_envelopes_refuse_injection_and_odd_counts() {
        assert!(
            envelope("ada@example.com", &["bob@example.org"])
                .check()
                .is_ok()
        );
        for bad in [
            "",
            "ada",
            "@example.com",
            "ada@",
            "ada@example.com\r\nBcc: eve@example.org",
            "ada@example.com>",
            "a da@example.com",
            "ada@example.com,eve@example.org",
        ] {
            assert!(
                envelope(bad, &["bob@example.org"]).check().is_err(),
                "{bad:?}"
            );
            assert!(
                envelope("ada@example.com", &[bad]).check().is_err(),
                "{bad:?}"
            );
        }
        assert!(envelope("ada@example.com", &[]).check().is_err());
        let many: Vec<String> = (0..=MAX_RECIPIENTS)
            .map(|i| format!("r{i}@example.org"))
            .collect();
        let refs: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(envelope("ada@example.com", &refs).check().is_err());
        assert!(
            envelope("ada@example.com", &refs[..MAX_RECIPIENTS])
                .check()
                .is_ok()
        );
    }

    #[test]
    fn object_commands_round_trip() {
        let json = r#"{"type":"put_object","collection":"/c/","blob":"0000000000000000000000000000000000000000000000000000000000000000"}"#;
        let body: CommandBody = serde_json::from_str(json).unwrap();
        assert!(body.is_collection_command());
        assert!(matches!(
            &body,
            CommandBody::PutObject {
                item: None,
                if_version: None,
                ..
            }
        ));
        assert_eq!(serde_json::to_string(&body).unwrap(), json);
        let delete = CommandBody::DeleteObject {
            collection: "/c/".into(),
            item: ItemRef {
                id: "/c/a.vcf".into(),
                uid: None,
            },
            if_version: Some("\"7\"".into()),
            notify: false,
        };
        let again: CommandBody =
            serde_json::from_str(&serde_json::to_string(&delete).unwrap()).unwrap();
        assert_eq!(again, delete);
        assert!(!CommandBody::Unknown.is_collection_command());
    }

    #[test]
    fn scheduling_commands_default_and_route() {
        let json = r#"{"type":"respond_object","collection":"/c/","item":{"id":"/c/e.ics"},"answer":"accepted"}"#;
        let body: CommandBody = serde_json::from_str(json).unwrap();
        assert!(body.is_collection_command());
        assert!(matches!(
            &body,
            CommandBody::RespondObject {
                notify: true,
                answer: PartStat::Accepted,
                ..
            }
        ));
        assert_eq!(serde_json::to_string(&body).unwrap(), json);
        let quiet = r#"{"type":"respond_object","collection":"/c/","item":{"id":"/c/e.ics"},"answer":"declined","notify":false}"#;
        let body: CommandBody = serde_json::from_str(quiet).unwrap();
        assert_eq!(serde_json::to_string(&body).unwrap(), quiet);
        let mail = r#"{"type":"respond_invitation","invitation":"0000000000000000000000000000000000000000000000000000000000000000","answer":"tentative"}"#;
        let body: CommandBody = serde_json::from_str(mail).unwrap();
        assert!(!body.is_collection_command());
        assert!(body.is_send());
        let put = r#"{"type":"put_object","collection":"/c/","blob":"0000000000000000000000000000000000000000000000000000000000000000","notify":true}"#;
        let body: CommandBody = serde_json::from_str(put).unwrap();
        assert!(matches!(&body, CommandBody::PutObject { notify: true, .. }));
        assert_eq!(serde_json::to_string(&body).unwrap(), put);
    }

    #[test]
    fn send_commands_round_trip_and_default_their_options() {
        let json = r#"{"type":"send","blob":"0000000000000000000000000000000000000000000000000000000000000000","envelope":{"from":"ada@example.com","to":["bob@example.org"],"dsn":{"notify":["success","failure"],"ret":"headers"}}}"#;
        let body: CommandBody = serde_json::from_str(json).unwrap();
        let CommandBody::Send {
            envelope,
            save_to_sent,
            send_at,
            dry_run,
            ..
        } = &body
        else {
            panic!("not a send");
        };
        assert_eq!(save_to_sent, &None);
        assert_eq!(send_at, &None);
        assert!(!dry_run);
        assert_eq!(
            envelope.dsn.as_ref().unwrap().notify,
            vec![DsnNotify::Success, DsnNotify::Failure]
        );
        let again: CommandBody =
            serde_json::from_str(&serde_json::to_string(&body).unwrap()).unwrap();
        assert_eq!(again, body);
        assert!(!serde_json::to_string(&body).unwrap().contains("dry_run"));
    }

    #[test]
    fn dry_runs_round_trip() {
        let json = r#"{"type":"send","blob":"0000000000000000000000000000000000000000000000000000000000000000","envelope":{"from":"ada@example.com","to":["bob@example.org"]},"dry_run":true}"#;
        let body: CommandBody = serde_json::from_str(json).unwrap();
        assert!(matches!(body, CommandBody::Send { dry_run: true, .. }));
        assert_eq!(serde_json::to_string(&body).unwrap(), json);

        let result = crate::EventBody::SendResult {
            command: CommandId::new("01JD0000000000000000000000").unwrap(),
            refused: vec![],
            sent_copy: None,
            message_id: None,
            provider_message_id: None,
            dry_run: true,
        };
        let text = serde_json::to_string(&result).unwrap();
        assert_eq!(
            text,
            r#"{"type":"send_result","command":"01JD0000000000000000000000","dry_run":true}"#
        );
        assert_eq!(
            serde_json::from_str::<crate::EventBody>(&text).unwrap(),
            result
        );
        let real: crate::EventBody = serde_json::from_str(
            r#"{"type":"send_result","command":"01JD0000000000000000000000"}"#,
        )
        .unwrap();
        assert!(matches!(
            real,
            crate::EventBody::SendResult { dry_run: false, .. }
        ));
    }

    #[test]
    fn send_results_carry_delivered_ids() {
        let result = crate::EventBody::SendResult {
            command: CommandId::new("01JD0000000000000000000000").unwrap(),
            refused: vec![],
            sent_copy: Some(crate::SentCopy::Saved),
            message_id: Some("<0102-abc-000000@eu-west-1.amazonses.com>".into()),
            provider_message_id: Some("0102-abc-000000".into()),
            dry_run: false,
        };
        let text = serde_json::to_string(&result).unwrap();
        assert_eq!(
            text,
            r#"{"type":"send_result","command":"01JD0000000000000000000000","sent_copy":"saved","message_id":"<0102-abc-000000@eu-west-1.amazonses.com>","provider_message_id":"0102-abc-000000"}"#
        );
        assert_eq!(
            serde_json::from_str::<crate::EventBody>(&text).unwrap(),
            result
        );
    }
}
