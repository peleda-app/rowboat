//! The calendar and contacts provider contract.
//!
//! A provider maps its own change mechanism (DAV sync tokens or ETag listings, Google sync
//! tokens, Graph delta links, JMAP states) onto one model: per collection, an opaque [`Cursor`]
//! and a batch of [`PimChange`]s since that cursor. Objects are the provider's original iCalendar
//! or vCard bytes; Skein never parses or rewrites them. Reading never changes the server; writes
//! go through [`PimSession::apply`] only, under the version preconditions the command carries.

#[cfg(feature = "testing")]
pub mod testing;

use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use skein_core::{CollectionInfo, ItemRef, PartStat};

/// An opaque position in one collection's changes. Only the provider that made it can read it;
/// it never holds credentials. It may be large (a server without sync tokens needs every known
/// item with its version to report changes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor(pub Bytes);

/// One change in a collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PimChange {
    /// The provider no longer accepts the cursor (an invalid sync token). Every object still in
    /// the collection follows as `Upserted`; consumers treat the rest as gone.
    Reset {
        /// A short machine-readable reason, such as `sync_token`.
        reason: String,
    },
    /// An object is new or changed. Its bytes come from [`PimSession::fetch`].
    Upserted {
        /// The object.
        item: ItemRef,
        /// Its version when it was listed (an ETag), when the provider gave one.
        version: Option<String>,
    },
    /// An object left the collection.
    Removed {
        /// The object.
        item: ItemRef,
    },
}

/// Changes since a cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PimChanges {
    /// What changed. Each item appears at most once per batch, except after a `Reset`.
    pub changes: Vec<PimChange>,
    /// Where the next call continues. Store it only after the changes are safely recorded.
    pub cursor: Cursor,
    /// Whether more changes are waiting; call again with the new cursor.
    pub more: bool,
}

/// An object's original bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawObject {
    /// The object.
    pub item: ItemRef,
    /// The version of exactly these bytes, when the provider gave one with them.
    pub version: Option<String>,
    /// The object exactly as the server holds or returns it: iCalendar or vCard for DAV, the
    /// provider's JSON resource for APIs without either (`content_type` says which, for example
    /// `application/json; profile=google-calendar-event`).
    pub bytes: Bytes,
    /// Their media type, such as `text/calendar` or `text/vcard`.
    pub content_type: String,
}

/// A write to carry out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PimWrite {
    /// Create an object (`item` is `None`) or replace one.
    Put {
        /// Collection id.
        collection: String,
        /// The object to replace; `None` creates one.
        item: Option<ItemRef>,
        /// The whole object, sent unchanged except for identity or version fields the provider
        /// requires (an event id derived from the command for idempotent creates, an `etag` in a
        /// replaced contact).
        bytes: Bytes,
        /// Replace only while the provider's version is still this one.
        if_version: Option<String>,
        /// The command's id. A create with the same key makes at most one object: repeating it
        /// after it succeeded is answered with the object it made.
        key: String,
        /// Ask the server to tell the attendees, where it schedules ([`Scheduling::Server`]);
        /// without it the provider asks the server not to, where it can.
        notify: bool,
    },
    /// Delete an object.
    Delete {
        /// Collection id.
        collection: String,
        /// The object.
        item: ItemRef,
        /// Delete only while the provider's version is still this one.
        if_version: Option<String>,
        /// Ask the server to tell the attendees, as for `Put`.
        notify: bool,
    },
    /// Answer an invitation: set one attendee's participation status on an event, on the
    /// series and every instance the attendee is invited to, through the provider's own way of
    /// answering where it has one.
    Respond {
        /// Collection id.
        collection: String,
        /// The event.
        item: ItemRef,
        /// The answer.
        answer: PartStat,
        /// The attendee address that answers; `None` for the account's own attendee, as the
        /// provider knows it. Fails with `attendee_not_found` when no attendee matches.
        attendee: Option<String>,
        /// A note for the organizer, where the provider carries one.
        comment: Option<String>,
        /// Answer only while the provider's version is still this one.
        if_version: Option<String>,
        /// Ask the server to tell the organizer, where it schedules; without it the provider asks
        /// the server not to, where it can.
        notify: bool,
    },
}

impl PimWrite {
    /// The collection the write is in.
    pub fn collection(&self) -> &str {
        match self {
            Self::Put { collection, .. }
            | Self::Delete { collection, .. }
            | Self::Respond { collection, .. } => collection,
        }
    }
}

/// Who tells attendees and organizers about changes written to a collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheduling {
    /// The provider's server sends iTIP messages when a write asks it to (`notify`): Google
    /// Calendar, Graph, JMAP, CalDAV with `calendar-auto-schedule` (RFC 6638). Some servers send
    /// them even without `notify`.
    Server,
    /// The server tells nobody: whoever writes must send iTIP messages itself (iMIP).
    Client,
}

/// What became of a write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteOutcome {
    /// The server applied it.
    Applied {
        /// The object written or deleted; for a create, the one the provider made.
        item: Option<ItemRef>,
        /// For a put, the object as the server holds it right after the write, read back with
        /// its version: servers may rewrite what they store (reorder or refold properties), so
        /// these bytes need not equal the ones sent. `None` for deletes and when it could not be
        /// read back.
        current: Option<RawObject>,
    },
    /// A version precondition failed, or a create met an object that is not the one it would
    /// have made. Nothing changed.
    Conflict {
        /// The server's current version, when it could tell; `None` when the object is gone.
        current: Option<String>,
    },
    /// The server refused it for good (read-only collection, invalid or too large object).
    /// Nothing changed.
    Failed {
        /// A short machine-readable reason.
        reason: String,
    },
    /// The request left but no answer came back; it may or may not have been applied.
    Uncertain,
}

/// Errors of the calendar and contacts contract. Messages never hold names, contents, addresses
/// or secrets.
#[derive(Debug, thiserror::Error)]
pub enum PimError {
    /// The server refused the credentials.
    #[error("authentication failed")]
    Auth,
    /// The account settings cannot work (bad address, plain text to a remote host, no
    /// collections address).
    #[error("bad configuration: {0}")]
    Config(String),
    /// The server is limiting requests; try again after the delay, if it gave one.
    #[error("throttled")]
    Throttled {
        /// How long the server asked to wait.
        retry_after: Option<Duration>,
    },
    /// The collection does not exist (any more).
    #[error("collection not found")]
    NotFound,
    /// The server said something the provider cannot understand.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// The connection failed or timed out; retrying may help.
    #[error("network error: {0}")]
    Network(String),
}

/// A calendar and contacts account at a provider.
#[async_trait]
pub trait PimProvider: Send + Sync {
    /// Signs in and opens a session. Nothing is changed on the server.
    async fn connect(&self) -> Result<Box<dyn PimSession>, PimError>;
}

/// A signed-in session.
///
/// Guarantees (checked by [`testing::conformance`]):
///
/// - `collections` lists every address book and calendar of the account, each once, with a
///   stable id; scheduling outboxes are left out, and a scheduling inbox only appears when the
///   provider was asked to list it, with the role `schedule_inbox`.
/// - `changes` without a cursor lists every object as `Upserted` (in pages, with `more`).
/// - With the cursor from the previous call, it reports exactly what changed since: new and
///   changed objects as `Upserted`, removed ones as `Removed`. A change made before the previous
///   call returned is never reported again; one made after it is never lost.
/// - A cursor the server no longer accepts, or one that cannot be read, yields `Reset` followed
///   by a full listing.
/// - `fetch` returns the exact bytes for each object still present, each at most once, and leaves
///   out vanished ones.
/// - `apply` honours `if_version` (`Conflict` when it fails), never overwrites on create, makes
///   at most one object per create key, and counts deleting a gone object as applied.
/// - A `Respond` changes only the answering attendee's participation status (and comment); an
///   applied one returns the object as the server holds it afterwards where it can read it.
/// - Reading never changes the server.
#[async_trait]
pub trait PimSession: Send {
    /// Every address book and calendar.
    async fn collections(&mut self) -> Result<Vec<CollectionInfo>, PimError>;

    /// Changes in `collection` since `cursor`, at most about `limit` per call. `NotFound` for a
    /// collection that is gone.
    async fn changes(
        &mut self,
        collection: &str,
        cursor: Option<&Cursor>,
        limit: usize,
    ) -> Result<PimChanges, PimError>;

    /// Original bytes of objects in `collection`, in any order.
    async fn fetch(
        &mut self,
        collection: &str,
        items: &[ItemRef],
    ) -> Result<Vec<RawObject>, PimError>;

    /// Carries out a write. `Network` errors mean the outcome is unknown.
    async fn apply(&mut self, write: &PimWrite) -> Result<WriteOutcome, PimError>;

    /// Who tells attendees about writes to `collection`. [`Scheduling::Client`] unless the
    /// provider knows its server schedules. `NotFound` for a collection that is gone.
    async fn scheduling(&mut self, collection: &str) -> Result<Scheduling, PimError> {
        let _ = collection;
        Ok(Scheduling::Client)
    }

    /// The account's own calendar addresses (CalDAV `calendar-user-address-set`, the signed-in
    /// user's address elsewhere), lower case and without `mailto:`; empty when the provider
    /// cannot tell. Used to find the account's attendee and to check that it organizes an event.
    async fn addresses(&mut self) -> Result<Vec<String>, PimError> {
        Ok(Vec::new())
    }

    /// Signs out.
    async fn logout(&mut self) -> Result<(), PimError>;
}
