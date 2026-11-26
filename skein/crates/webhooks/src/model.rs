use serde::{Deserialize, Serialize};
use skein_core::{AccountId, Event, EventBody, TenantId, Timestamp};
use skein_storage::Migrate;

/// Every event type an endpoint may filter on: the `type` of [`EventBody`].
pub const EVENT_TYPES: &[&str] = &[
    "mailbox_upserted",
    "mailbox_deleted",
    "message_added",
    "message_removed",
    "flags_changed",
    "labels_changed",
    "resync_required",
    "first_sync_completed",
    "account_health_changed",
    "write_applied",
    "conflict",
    "write_failed",
    "write_uncertain",
    "send_result",
    "collection_upserted",
    "collection_deleted",
    "object_upserted",
    "object_removed",
    "itip_received",
    "schedule_result",
    "account_capabilities",
];

/// The `type` of an event body, as in [`EVENT_TYPES`]; `unknown` for types written by a newer
/// build.
pub fn event_type(body: &EventBody) -> &'static str {
    match body {
        EventBody::MailboxUpserted { .. } => "mailbox_upserted",
        EventBody::MailboxDeleted { .. } => "mailbox_deleted",
        EventBody::MessageAdded { .. } => "message_added",
        EventBody::MessageRemoved { .. } => "message_removed",
        EventBody::FlagsChanged { .. } => "flags_changed",
        EventBody::LabelsChanged { .. } => "labels_changed",
        EventBody::ResyncRequired { .. } => "resync_required",
        EventBody::FirstSyncCompleted => "first_sync_completed",
        EventBody::AccountHealthChanged { .. } => "account_health_changed",
        EventBody::WriteApplied { .. } => "write_applied",
        EventBody::Conflict { .. } => "conflict",
        EventBody::WriteFailed { .. } => "write_failed",
        EventBody::WriteUncertain { .. } => "write_uncertain",
        EventBody::SendResult { .. } => "send_result",
        EventBody::CollectionUpserted { .. } => "collection_upserted",
        EventBody::CollectionDeleted { .. } => "collection_deleted",
        EventBody::ObjectUpserted { .. } => "object_upserted",
        EventBody::ObjectRemoved { .. } => "object_removed",
        EventBody::ItipReceived { .. } => "itip_received",
        EventBody::ScheduleResult { .. } => "schedule_result",
        EventBody::AccountCapabilities { .. } => "account_capabilities",
        EventBody::Unknown => "unknown",
    }
}

/// A webhook endpoint as stored at tenant control path `webhooks/{id}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    /// A lowercase ULID.
    pub id: String,
    /// Where batches are posted.
    pub url: String,
    /// Only these event types are sent, when set; other events still move the cursor.
    #[serde(default)]
    pub events: Option<Vec<String>>,
    /// Only these accounts are delivered, when set.
    #[serde(default)]
    pub accounts: Option<Vec<AccountId>>,
    /// When it was created.
    pub created_at: Timestamp,
    /// Paused endpoints get nothing; their cursors stay where they are.
    #[serde(default)]
    pub paused: bool,
    /// Why delivery paused it, when it did; cleared when it is resumed.
    #[serde(default)]
    pub paused_reason: Option<String>,
    /// The signing secret sealed by the keyring with context `webhooks/{id}`, base64url. Never
    /// returned by the API.
    pub sealed_secret: String,
}

impl Migrate for Endpoint {
    const VERSION: u16 = 1;
}

impl Endpoint {
    /// Whether deliveries for `account` go to this endpoint.
    pub fn wants_account(&self, account: &AccountId) -> bool {
        self.accounts.as_ref().is_none_or(|a| a.contains(account))
    }

    /// Whether `event` is sent to this endpoint.
    pub fn wants_event(&self, event: &Event) -> bool {
        let kind = event_type(&event.body);
        self.events
            .as_ref()
            .is_none_or(|e| e.iter().any(|t| t == kind))
    }
}

/// Where delivery of one account to one endpoint stands, at tenant control path
/// `webhook-cursors/{endpoint}/{account}`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    /// The last event delivered (or skipped by the filter); delivery resumes after it.
    pub seq: u64,
    /// Failed attempts in a row.
    #[serde(default)]
    pub failures: u32,
    /// When the current run of failures began.
    #[serde(default)]
    pub failing_since: Option<Timestamp>,
    /// No attempt before this time.
    #[serde(default)]
    pub next_attempt_at: Option<Timestamp>,
    /// The kind of the last failure: `http_status` or a [`crate::SendError::kind`].
    #[serde(default)]
    pub last_error: Option<String>,
    /// The status code of the last answer.
    #[serde(default)]
    pub last_status: Option<u16>,
    /// When a batch was last accepted.
    #[serde(default)]
    pub delivered_at: Option<Timestamp>,
}

impl Migrate for Cursor {
    const VERSION: u16 = 1;
}

/// The notice sent instead of events the log no longer holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Compacted {
    /// The first event still in the log; load the latest snapshot and read on from there.
    pub first: u64,
}

/// The JSON body of every request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Batch {
    /// The endpoint id.
    pub endpoint: String,
    /// The tenant.
    pub tenant: TenantId,
    /// The account the events belong to; absent on a ping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<AccountId>,
    /// Events in log order, consecutive except for those the endpoint's filter leaves out.
    #[serde(default)]
    pub events: Vec<Event>,
    /// Set on a compaction notice, which carries no events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compacted: Option<Compacted>,
    /// Set on a test request from the API, which carries no events.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ping: bool,
}
