//! `skein-view`: a mail database over Skein's journal. A [`Follower`] reads one tenant's journals
//! straight from Skein's storage contracts, verifying every segment through the hash chain, and
//! applies them to a [`Store`]: envelopes, threads, full-text search, parsed content, calendars
//! and contacts in SQLite with FTS5. The Peleda app embeds it next to its node; nothing here
//! listens on the network. Skein's engine stays dumb: all parsing of journal content for display
//! lives here.

mod follower;
mod observe;
mod parse;
mod pim;
mod search;
mod store;
mod threads;

#[cfg(test)]
mod e2e;

pub use follower::{
    DEFAULT_MAX_BLOB, DEFAULT_PAGE, FollowError, Follower, REPARSE_PER_ROUND, Timing,
};
pub use observe::{
    Added, CommandOutcome, MAX_ADDED, MAX_OUTCOMES, MAX_TOUCHED, OutcomeKind, PageReport, Touched,
    ViewObserver,
};
pub use parse::{
    Addr, Attachment, HTML_CAP, MAX_TAGS, MailParser, MessageParser, ParseContext, ParseError,
    Parsed, SNIPPET_CHARS, TEXT_CAP, clean_tags, parse, valid_tag,
};
pub use pim::{Format, LIST_CAP, OBJECT_CAP, ObjectFields, TEXT_CHARS};
pub use search::{MAX_TERMS, fts_query};
pub use store::{
    AccountRow, AddressRow, CollectionRow, Envelope, Filter, MAX_LIMIT, MAX_SUGGESTIONS,
    MailboxRow, Membership, MessageDetail, ObjectDetail, ObjectInCollection, ObjectSummary,
    Placement, Range, StaleMessage, Store, StoreError, ThreadMessage, ThreadRow,
};
pub use threads::{Link, Node, subject_key, tree};
