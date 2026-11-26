//! The mail provider contract.
//!
//! A provider maps its own change mechanism (IMAP UIDs and mod-sequences, JMAP states, Gmail
//! history ids, Graph delta links) onto one model: per mailbox, an opaque [`Cursor`] and a batch
//! of [`MailChange`]s since that cursor. Reading never changes the server; writes go through
//! [`MailSession::apply`] only.

#[cfg(feature = "testing")]
pub mod testing;

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use skein_core::{CommandBody, Flags, ItemRef, MailCapabilities, MailboxInfo, Timestamp};

/// An opaque position in one mailbox's changes. Only the provider that made it can read it; it
/// never holds credentials. It may be large (an IMAP server without `QRESYNC` needs the known UIDs
/// and their flags to report removals and flag changes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor(pub Bytes);

/// One change in a mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailChange {
    /// The provider no longer accepts the cursor (new `UIDVALIDITY`, expired history). Every
    /// message still in the mailbox follows as `Added`; consumers treat the rest as gone.
    Reset {
        /// A short machine-readable reason.
        reason: String,
    },
    /// A message is in the mailbox. Its bytes come from [`MailSession::fetch`].
    Added {
        /// The message.
        item: ItemRef,
        /// Its flags.
        flags: Flags,
        /// Labels on servers that have them.
        labels: Option<Vec<String>>,
        /// When the server received it.
        received_at: Option<Timestamp>,
    },
    /// A message left the mailbox.
    Removed {
        /// The message.
        item: ItemRef,
    },
    /// A message's flags changed; the full new set.
    Flags {
        /// The message.
        item: ItemRef,
        /// Every flag it has now.
        flags: Flags,
    },
    /// A message's labels changed; the full new set.
    Labels {
        /// The message.
        item: ItemRef,
        /// Every label it has now.
        labels: Vec<String>,
    },
}

/// Changes since a cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxChanges {
    /// What changed, oldest first as far as the provider can tell.
    pub changes: Vec<MailChange>,
    /// Where the next call continues. Store it only after the changes are safely recorded.
    pub cursor: Cursor,
    /// Whether more changes are waiting; call again with the new cursor.
    pub more: bool,
}

/// A message's original bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawMessage {
    /// The message.
    pub item: ItemRef,
    /// RFC 5322 bytes exactly as the server holds them.
    pub bytes: Bytes,
}

/// What became of a write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteOutcome {
    /// The server applied it.
    Applied,
    /// A version precondition failed.
    Conflict,
    /// The server refused it for good.
    Failed {
        /// A short machine-readable reason.
        reason: String,
    },
    /// The request left but no answer came back.
    Uncertain,
}

/// Something may have changed in these mailboxes; `None` means any of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Changed {
    /// Mailbox ids, each once.
    pub mailboxes: Option<Vec<String>>,
}

/// Where a provider that pushes from outside (a webhook rather than a held connection) sends its
/// notifications.
///
/// Notifications are hints: each one only says that something may have changed, and the change
/// itself is always read through [`MailSession::changes`]. A lost or late notification only delays
/// a sync until the next one or the next poll; it never loses a change.
#[derive(Clone, PartialEq, Eq)]
pub struct PushTarget {
    /// Our public `https` address the provider calls, such as
    /// `https://skein.example.com/v1/push/graph`.
    pub url: String,
    /// A random secret the provider repeats in every notification (Graph's `clientState`, at most
    /// 128 characters), so forged notifications can be told apart. Never logged.
    pub client_state: String,
    /// The Cloud Pub/Sub topic (`projects/{project}/topics/{topic}`) Gmail publishes to; Gmail
    /// cannot push without one.
    pub gmail_topic: Option<String>,
}

impl fmt::Debug for PushTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PushTarget")
            .field("url", &self.url)
            .field("client_state", &"<redacted>")
            .field("gmail_topic", &self.gmail_topic)
            .finish()
    }
}

/// Gmail's [`Subscription::provider_kind`].
pub const PUSH_GMAIL: &str = "gmail";
/// Microsoft Graph's [`Subscription::provider_kind`].
pub const PUSH_GRAPH: &str = "graph";

/// A push subscription a provider holds for us until `expires_at`.
///
/// It must be renewed before `expires_at` (see [`MailProvider::renew`]); after that the provider
/// stops calling and the account falls back to polling until a new one is made.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscription {
    /// The provider's id: Graph's subscription id; for Gmail, which has none, the history id at
    /// the time of the watch.
    pub id: String,
    /// Which provider made it: [`PUSH_GMAIL`], [`PUSH_GRAPH`] or another implementation's name.
    pub provider_kind: String,
    /// When the provider stops calling.
    pub expires_at: Timestamp,
    /// What is watched: the mailbox address for Gmail (notifications name it), the Graph resource
    /// path such as `me/messages`. May be an address, so it is never logged.
    pub resource: String,
}

impl fmt::Debug for Subscription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Subscription")
            .field("id", &self.id)
            .field("provider_kind", &self.provider_kind)
            .field("expires_at", &self.expires_at)
            .field("resource", &"<redacted>")
            .finish()
    }
}

/// Errors of the mail contract.
#[derive(Debug, thiserror::Error)]
pub enum MailError {
    /// The server refused the credentials.
    #[error("authentication failed")]
    Auth,
    /// The account settings cannot work (bad host, plain text to a remote host, missing token).
    #[error("bad configuration: {0}")]
    Config(String),
    /// The server is limiting requests; try again after the delay, if it gave one.
    #[error("throttled")]
    Throttled {
        /// How long the server asked to wait.
        retry_after: Option<Duration>,
    },
    /// The mailbox does not exist.
    #[error("mailbox not found")]
    MailboxNotFound,
    /// The server said something the provider cannot understand.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// The connection failed or timed out; retrying may help.
    #[error("network error: {0}")]
    Network(String),
}

/// A mail account at a provider.
#[async_trait]
pub trait MailProvider: Send + Sync {
    /// Signs in and opens a session.
    async fn connect(&self) -> Result<Box<dyn MailSession>, MailError>;

    /// A watch that wakes when the named mailboxes may have changed, on connections of its own.
    /// `Ok(None)` when the provider cannot push.
    async fn watch(&self, mailboxes: &[String]) -> Result<Option<Box<dyn MailWatch>>, MailError> {
        let _ = mailboxes;
        Ok(None)
    }

    /// Asks the provider to call `target` when the account may have changed. `Ok(None)` when the
    /// provider cannot push from outside (the default) or `target` lacks what it needs, such as a
    /// Gmail topic. Subscribing again makes a new subscription or refreshes the existing one; it
    /// never fails because one exists.
    async fn subscribe(&self, target: &PushTarget) -> Result<Option<Subscription>, MailError> {
        let _ = target;
        Ok(None)
    }

    /// Extends `subscription` and returns it with its new `expires_at`, or a replacement with a
    /// different id when the provider no longer knew it. The default subscribes again.
    async fn renew(
        &self,
        subscription: &Subscription,
        target: &PushTarget,
    ) -> Result<Option<Subscription>, MailError> {
        let _ = subscription;
        self.subscribe(target).await
    }

    /// Ends `subscription`. Ending one that already expired or is unknown succeeds. The default
    /// does nothing.
    async fn unsubscribe(&self, subscription: &Subscription) -> Result<(), MailError> {
        let _ = subscription;
        Ok(())
    }
}

/// A signed-in session.
///
/// Guarantees (checked by [`testing::conformance`]):
///
/// - `changes` without a cursor lists every message as `Added` (in pages, with `more`).
/// - With the cursor from the previous call, it reports exactly what changed since: new messages,
///   removed ones, and flag or label changes of messages that stayed. A change made before the
///   previous call returned is never reported again; one made after it is never lost.
/// - A cursor the server no longer accepts, or one that cannot be read, yields `Reset` followed by
///   a full listing. `Added` changes need not be in any particular order.
/// - `fetch` returns the exact bytes for each message still present and leaves out vanished ones.
/// - Reading never changes the server (no flags set, nothing moved).
/// - Writes do what their command says, as far as `capabilities` claims (checked by
///   [`testing::write_conformance`]): flags and labels change only as asked, moved and copied
///   messages keep their bytes, appended messages appear with their flags.
#[async_trait]
pub trait MailSession: Send {
    /// Every mailbox.
    async fn mailboxes(&mut self) -> Result<Vec<MailboxInfo>, MailError>;

    /// Changes in `mailbox` since `cursor`, at most about `limit` per call.
    async fn changes(
        &mut self,
        mailbox: &str,
        cursor: Option<&Cursor>,
        limit: usize,
    ) -> Result<MailboxChanges, MailError>;

    /// Original bytes of messages in `mailbox`.
    async fn fetch(
        &mut self,
        mailbox: &str,
        items: &[ItemRef],
    ) -> Result<Vec<RawMessage>, MailError>;

    /// Carries out a write. `content` holds the message bytes for `Append`.
    ///
    /// A command the provider cannot carry out (see [`MailSession::capabilities`]) is
    /// `Failed { reason: "unsupported" }`. Errors say whether anything changed: `Network` means
    /// the outcome is unknown; `Auth`, `Config`, `Throttled` and `MailboxNotFound` mean nothing
    /// was changed, so the command can run again later; `Protocol` may follow a partial change.
    async fn apply(
        &mut self,
        command: &CommandBody,
        content: Option<Bytes>,
    ) -> Result<WriteOutcome, MailError>;

    /// What `apply` can do for this account. The default is the least every provider offers:
    /// `\Seen`, `\Flagged`, `\Answered` and `\Draft`, nothing else.
    async fn capabilities(&mut self) -> Result<MailCapabilities, MailError> {
        Ok(basic_capabilities())
    }

    /// Signs out.
    async fn logout(&mut self) -> Result<(), MailError>;
}

/// The capabilities every provider has: `\Seen`, `\Flagged`, `\Answered` and `\Draft`.
pub fn basic_capabilities() -> MailCapabilities {
    MailCapabilities {
        system_flags: ["\\Answered", "\\Draft", "\\Flagged", "\\Seen"]
            .map(str::to_owned)
            .to_vec(),
        ..MailCapabilities::default()
    }
}

/// A push channel from the provider. Dropping it ends the watch and closes its connections.
#[async_trait]
pub trait MailWatch: Send {
    /// Returns once something may have changed since the watch started or the last return. A
    /// change while the watch is alive is never swallowed; returns without a change are allowed.
    async fn next(&mut self) -> Result<Changed, MailError>;
}
