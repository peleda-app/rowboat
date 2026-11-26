//! Parsing what providers post to us. Nothing here trusts the body: sizes, counts and fields are
//! checked, and unknown fields are ignored.

use std::fmt;

use base64::Engine;
use serde::Deserialize;

use crate::PushError;

/// Most notifications read from one Graph post; the rest are ignored.
pub const MAX_GRAPH_ITEMS: usize = 1000;
/// Longest validation token echoed back to Graph.
pub const MAX_VALIDATION_TOKEN: usize = 1024;

/// One item of a Graph notification post: a change or a lifecycle event.
#[derive(Clone, PartialEq, Eq)]
pub struct GraphNotification {
    /// The subscription it is for.
    pub subscription_id: String,
    /// The `clientState` it carries; checked against the registry, never logged.
    pub client_state: Option<String>,
    /// `reauthorizationRequired`, `subscriptionRemoved` or `missed` for lifecycle events, `None`
    /// for a change.
    pub lifecycle_event: Option<String>,
}

impl fmt::Debug for GraphNotification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GraphNotification")
            .field("subscription_id", &self.subscription_id)
            .field("client_state", &"<redacted>")
            .field("lifecycle_event", &self.lifecycle_event)
            .finish()
    }
}

/// What Gmail published through Pub/Sub: whose mailbox changed and up to which history id.
#[derive(Clone, PartialEq, Eq)]
pub struct GmailNotification {
    /// The mailbox address. Never logged.
    pub email: String,
    /// The mailbox's history id after the change, when Gmail sent one.
    pub history_id: Option<u64>,
}

impl fmt::Debug for GmailNotification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GmailNotification")
            .field("email", &"<redacted>")
            .field("history_id", &self.history_id)
            .finish()
    }
}

#[derive(Deserialize)]
struct GraphBody {
    value: Vec<GraphItem>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphItem {
    subscription_id: Option<String>,
    client_state: Option<String>,
    lifecycle_event: Option<String>,
}

/// The notifications in a Graph post (`{"value": [...]}`), at most [`MAX_GRAPH_ITEMS`]; items
/// without a subscription id are skipped. `Invalid` when the body is not such an object.
pub fn parse_graph(body: &[u8]) -> Result<Vec<GraphNotification>, PushError> {
    let parsed: GraphBody = serde_json::from_slice(body).map_err(|_| PushError::Invalid)?;
    Ok(parsed
        .value
        .into_iter()
        .take(MAX_GRAPH_ITEMS)
        .filter_map(|item| {
            let id = item.subscription_id?;
            (!id.is_empty() && id.len() <= 128).then_some(GraphNotification {
                subscription_id: id,
                client_state: item.client_state,
                lifecycle_event: item.lifecycle_event,
            })
        })
        .collect())
}

/// The token of a Graph validation request, when it is safe to echo: 1 to
/// [`MAX_VALIDATION_TOKEN`] bytes of printable ASCII or spaces.
pub fn validation_token(raw: &str) -> Option<&str> {
    (!raw.is_empty()
        && raw.len() <= MAX_VALIDATION_TOKEN
        && raw.bytes().all(|b| (0x20..0x7f).contains(&b)))
    .then_some(raw)
}

#[derive(Deserialize)]
struct Envelope {
    message: EnvelopeMessage,
}

#[derive(Deserialize)]
struct EnvelopeMessage {
    data: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GmailData {
    email_address: String,
    history_id: Option<serde_json::Value>,
}

/// The Gmail notification inside a Pub/Sub push envelope
/// (`{"message": {"data": base64({emailAddress, historyId}), ...}, "subscription": ...}`).
/// `Invalid` for anything else.
pub fn parse_gmail(body: &[u8]) -> Result<GmailNotification, PushError> {
    let envelope: Envelope = serde_json::from_slice(body).map_err(|_| PushError::Invalid)?;
    let data = envelope.message.data.ok_or(PushError::Invalid)?;
    let data = data.trim().trim_end_matches('=');
    let lenient = base64::engine::GeneralPurposeConfig::new()
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent);
    let decoded = base64::engine::GeneralPurpose::new(&base64::alphabet::STANDARD, lenient)
        .decode(data)
        .or_else(|_| {
            base64::engine::GeneralPurpose::new(&base64::alphabet::URL_SAFE, lenient).decode(data)
        })
        .map_err(|_| PushError::Invalid)?;
    let inner: GmailData = serde_json::from_slice(&decoded).map_err(|_| PushError::Invalid)?;
    let email = inner.email_address.trim().to_owned();
    if email.is_empty() || email.len() > 320 || !email.contains('@') {
        return Err(PushError::Invalid);
    }
    let history_id = match inner.history_id {
        Some(serde_json::Value::Number(n)) => n.as_u64(),
        Some(serde_json::Value::String(s)) => s.trim().parse().ok(),
        _ => None,
    };
    Ok(GmailNotification { email, history_id })
}
