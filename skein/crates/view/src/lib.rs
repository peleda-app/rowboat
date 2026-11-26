//! `skein-view`: a mail database over Skein's journal. A [`Follower`] reads one tenant's journals
//! straight from Skein's storage contracts, verifying every segment through the hash chain, and
//! applies them to a [`Store`]: envelopes, threads, full-text search, parsed content, calendars
//! and contacts in SQLite with FTS5. The Peleda app embeds it next to its node; nothing here
//! listens on the network. Skein's engine stays dumb: all parsing of journal content for display
//! lives here.

mod follower;
mod parse;
mod pim;
mod search;
mod store;
mod threads;

#[cfg(test)]
mod e2e;

pub use follower::{DEFAULT_MAX_BLOB, DEFAULT_PAGE, FollowError, Follower, Timing};
pub use parse::{Addr, Attachment, HTML_CAP, SNIPPET_CHARS, TEXT_CAP};
pub use pim::{Format, LIST_CAP, OBJECT_CAP, ObjectFields, TEXT_CHARS};
pub use search::{MAX_TERMS, fts_query};
pub use store::{
    AccountRow, CollectionRow, Envelope, MAX_LIMIT, MailboxRow, Membership, MessageDetail,
    ObjectDetail, ObjectInCollection, ObjectSummary, Placement, Range, Store, StoreError,
    ThreadMessage, ThreadRow,
};
pub use threads::{Link, Node, subject_key, tree};
