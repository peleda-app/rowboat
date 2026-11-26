//! Signed webhooks over Skein's journal.
//!
//! A tenant configures endpoints ([`WebhookStore`]); the node that owns an account posts the
//! account's new events to them in batches ([`WebhookDelivery`], an engine
//! [`skein_engine::AccountObserver`]), signed with HMAC-SHA256 ([`sign`], [`verify`]), at least
//! once and in log order per endpoint and account. Requests go only where a [`WebhookPolicy`]
//! allows: `https` to public addresses, connecting to the address that was checked.
//!
//! See `docs/README.md` for the payload, the headers, how receivers verify requests, the retry
//! policy and the address rules.

mod delivery;
mod error;
mod model;
mod policy;
mod signature;
mod store;
mod transport;

pub(crate) use delivery::send_signed;
pub use delivery::{
    BATCH_SIZE, Clock, DeliveryReport, FIRST_BACKOFF_SECS, MAX_BACKOFF_SECS, MAX_BATCHES_PER_RUN,
    PAUSE_AFTER_MS, SystemClock, WebhookDelivery, backoff_secs,
};
pub use error::{SendError, WebhookError};
pub use model::{Batch, Compacted, Cursor, EVENT_TYPES, Endpoint, event_type};
pub use policy::{InvalidNetwork, MAX_URL_LEN, Network, WebhookPolicy};
pub use signature::{
    ID_HEADER, SECRET_PREFIX, SIGNATURE_HEADER, TIMESTAMP_HEADER, TOLERANCE_SECS, VerifyError,
    new_secret, sign, verify,
};
pub use store::{
    DeliveryState, EndpointPatch, MAX_FILTER, NewEndpoint, WebhookStore, cursor_path,
    endpoint_path, valid_id,
};
pub use transport::{HttpTransport, MAX_ANSWER, Transport};

#[cfg(test)]
mod tests;
