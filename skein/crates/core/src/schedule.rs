use serde::{Deserialize, Serialize};

use crate::RefusedRecipient;

/// An attendee's answer to an invitation (iCalendar `PARTSTAT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartStat {
    /// `ACCEPTED`.
    Accepted,
    /// `DECLINED`.
    Declined,
    /// `TENTATIVE`.
    Tentative,
}

impl PartStat {
    /// The value as iCalendar writes it, such as `ACCEPTED`.
    pub fn as_ical(self) -> &'static str {
        match self {
            Self::Accepted => "ACCEPTED",
            Self::Declined => "DECLINED",
            Self::Tentative => "TENTATIVE",
        }
    }
}

/// The scheduling facts of an iTIP message (RFC 5546), read from its first event or task.
/// Derived from the bytes, which stay the truth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItipSummary {
    /// `METHOD` in upper case: `REQUEST`, `REPLY`, `CANCEL`, `COUNTER`, `REFRESH`, `ADD`,
    /// `PUBLISH` or `DECLINECOUNTER`.
    pub method: String,
    /// The component type in upper case: `VEVENT`, `VTODO` or `VJOURNAL`.
    pub component: String,
    /// The `UID`.
    pub uid: String,
    /// The `SEQUENCE`, 0 when missing.
    pub sequence: u32,
    /// The `RECURRENCE-ID` value when the message is about one instance only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recurrence_id: Option<String>,
    /// The organizer's address, lower case, without `mailto:`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organizer: Option<String>,
    /// The attendees, at most [`ItipSummary::MAX_ATTENDEES`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attendees: Vec<ItipAttendee>,
    /// Whether attendees were left out because there were more.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub more_attendees: bool,
}

impl ItipSummary {
    /// The most attendees a summary lists.
    pub const MAX_ATTENDEES: usize = 100;
}

/// An attendee as an iTIP message names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItipAttendee {
    /// The address, lower case, without `mailto:`.
    pub address: String,
    /// `PARTSTAT` in upper case, when given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partstat: Option<String>,
    /// Whether the organizer asked for an answer (`RSVP=TRUE`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rsvp: bool,
}

/// Who told the other side about a scheduling change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleVia {
    /// The provider's server sends the messages itself.
    Server,
    /// Skein mailed iTIP messages (iMIP) through the account's sending service.
    Mail,
    /// Nobody was told; `reason` says why.
    None,
}

/// What became of one iMIP message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleStatus {
    /// The sending service took it (for the recipients not listed as refused).
    Sent,
    /// It was not sent; `reason` says why.
    Failed,
    /// It may or may not have left; it is never sent again.
    Uncertain,
}

/// One iMIP message a scheduling command sent or tried to send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleMessage {
    /// The iTIP method: `REQUEST`, `REPLY` or `CANCEL`.
    pub method: String,
    /// Its recipients.
    pub to: Vec<String>,
    /// What became of it.
    pub status: ScheduleStatus,
    /// Recipients the sending service refused.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refused: Vec<RefusedRecipient>,
    /// A short machine-readable reason, for `failed` and `uncertain`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
