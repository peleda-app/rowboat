use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{Connection, OptionalExtension, Row, Transaction, named_params, params};
use serde::Serialize;
use skein_core::{BlobHash, Event, EventBody, Flags, ItemRef, MailboxInfo};
use skein_storage::{SegmentRef, Snapshot};

use crate::parse::{Addr, Attachment, Parsed};
use crate::threads;

#[path = "store_pim.rs"]
mod pim;

pub use pim::{CollectionRow, ObjectDetail, ObjectInCollection, ObjectSummary, Placement, Range};

/// Schema changes in order; a database at `user_version` n has had the first n applied.
/// Released entries never change: a new change is a new entry.
const MIGRATIONS: &[&str] = &[V1, V2, V3, V4];

const V1: &str = "
CREATE TABLE accounts (
    account TEXT PRIMARY KEY,
    checkpoint INTEGER NOT NULL DEFAULT 0,
    head INTEGER NOT NULL DEFAULT 0,
    first_sync INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE mailboxes (
    account TEXT NOT NULL,
    id TEXT NOT NULL,
    path TEXT NOT NULL,
    role TEXT,
    selectable INTEGER NOT NULL,
    label INTEGER NOT NULL,
    PRIMARY KEY (account, id)
);
CREATE TABLE messages (
    id INTEGER PRIMARY KEY,
    account TEXT NOT NULL,
    blob TEXT NOT NULL,
    size INTEGER NOT NULL,
    available INTEGER NOT NULL,
    message_id TEXT,
    in_reply_to TEXT NOT NULL,
    refs TEXT NOT NULL,
    subject TEXT,
    from_json TEXT NOT NULL,
    to_json TEXT NOT NULL,
    cc_json TEXT NOT NULL,
    date INTEGER,
    received_at INTEGER,
    sort_date INTEGER NOT NULL,
    has_attachments INTEGER NOT NULL,
    attachments TEXT NOT NULL,
    text TEXT,
    html TEXT,
    snippet TEXT,
    thread_id INTEGER NOT NULL,
    UNIQUE (account, blob)
);
CREATE INDEX messages_sort ON messages (account, sort_date, blob);
CREATE INDEX messages_thread ON messages (account, thread_id);
CREATE TABLE memberships (
    account TEXT NOT NULL,
    mailbox TEXT NOT NULL,
    item_id TEXT NOT NULL,
    uid INTEGER,
    message INTEGER NOT NULL REFERENCES messages (id),
    flags TEXT NOT NULL,
    labels TEXT,
    seen INTEGER NOT NULL,
    PRIMARY KEY (account, mailbox, item_id)
);
CREATE INDEX memberships_message ON memberships (message);
CREATE TABLE threads (
    id INTEGER PRIMARY KEY,
    account TEXT NOT NULL,
    subject_key TEXT
);
CREATE INDEX threads_subject ON threads (account, subject_key);
CREATE TABLE thread_ids (
    account TEXT NOT NULL,
    msgid TEXT NOT NULL,
    thread INTEGER NOT NULL,
    PRIMARY KEY (account, msgid)
);
CREATE INDEX thread_ids_thread ON thread_ids (account, thread);
CREATE VIRTUAL TABLE search USING fts5 (
    subject, names, addresses, body,
    content = '', contentless_delete = 1,
    tokenize = 'unicode61 remove_diacritics 2'
);
";

const V2: &str = "
ALTER TABLE messages ADD COLUMN itip TEXT;
CREATE TABLE collections (
    account TEXT NOT NULL,
    id TEXT NOT NULL,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    color TEXT,
    read_only INTEGER NOT NULL,
    components TEXT NOT NULL,
    role TEXT,
    PRIMARY KEY (account, id)
);
CREATE TABLE objects (
    id INTEGER PRIMARY KEY,
    account TEXT NOT NULL,
    blob TEXT NOT NULL,
    size INTEGER NOT NULL,
    content_type TEXT NOT NULL,
    format TEXT NOT NULL,
    kind TEXT NOT NULL,
    available INTEGER NOT NULL,
    starts INTEGER,
    ends INTEGER,
    recurring INTEGER NOT NULL,
    sort_name TEXT,
    fields TEXT NOT NULL,
    UNIQUE (account, blob)
);
CREATE TABLE placements (
    account TEXT NOT NULL,
    collection TEXT NOT NULL,
    item_id TEXT NOT NULL,
    object INTEGER NOT NULL REFERENCES objects (id),
    version TEXT,
    PRIMARY KEY (account, collection, item_id)
);
CREATE INDEX placements_object ON placements (object);
CREATE VIRTUAL TABLE contact_search USING fts5 (
    names, emails,
    content = '', contentless_delete = 1,
    tokenize = 'unicode61 remove_diacritics 2'
);
";

/// The most rows any query returns, whatever limit it is given.
pub const MAX_LIMIT: usize = 1000;

const V3: &str = "ALTER TABLE accounts ADD COLUMN tip TEXT;";

const V4: &str = "
ALTER TABLE messages ADD COLUMN tags TEXT NOT NULL DEFAULT '[]';
ALTER TABLE messages ADD COLUMN parser TEXT;
CREATE TABLE addresses (
    account TEXT NOT NULL,
    address TEXT NOT NULL,
    name TEXT,
    last_seen INTEGER NOT NULL,
    as_sender INTEGER NOT NULL DEFAULT 0,
    as_recipient INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (account, address)
);
CREATE INDEX addresses_name ON addresses (name);
";

/// The JSON form of the `\Flagged` flag inside a membership's flags.
const FLAGGED_JSON: &str = r#""\\Flagged""#;

/// Most address suggestions any call returns.
pub const MAX_SUGGESTIONS: usize = 50;

/// Narrows message, thread and search reads. Every field left `None` matches everything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    /// Only messages with a membership in one of these mailboxes; an empty list matches nothing.
    pub mailboxes: Option<Vec<String>>,
    /// Only unread (`true`) or only read (`false`) messages.
    pub unread: Option<bool>,
    /// Only messages flagged in some mailbox (`true`) or in none (`false`).
    pub flagged: Option<bool>,
    /// Only messages with (`true`) or without (`false`) attachments.
    pub has_attachments: Option<bool>,
    /// Only messages carrying this tag.
    pub tag: Option<String>,
}

impl Filter {
    /// Only messages in `mailbox`.
    pub fn mailbox(mailbox: &str) -> Self {
        Self {
            mailboxes: Some(vec![mailbox.to_owned()]),
            ..Self::default()
        }
    }

    fn mailboxes_json(&self) -> Option<String> {
        self.mailboxes.as_ref().map(to_json)
    }
}

/// The SQL condition of a [`Filter`] on the message alias `m`, with named parameters.
const FILTER: &str = "(:mailboxes IS NULL OR EXISTS (SELECT 1 FROM memberships fb
        WHERE fb.message = m.id AND fb.mailbox IN (SELECT value FROM json_each(:mailboxes))))
    AND (:unread IS NULL OR ((SELECT MIN(fb.seen) FROM memberships fb WHERE fb.message = m.id) = 0) = :unread)
    AND (:flagged IS NULL OR EXISTS (SELECT 1 FROM memberships fb
        WHERE fb.message = m.id AND instr(fb.flags, :flag) > 0) = :flagged)
    AND (:attachments IS NULL OR m.has_attachments = :attachments)
    AND (:tag IS NULL OR EXISTS (SELECT 1 FROM json_each(m.tags) WHERE value = :tag))";

/// A known correspondent of an account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddressRow {
    /// The account that saw it.
    pub account: String,
    /// The address, lower case.
    pub address: String,
    /// The latest display name seen with it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// When it was last seen, milliseconds since the epoch.
    pub last_seen: i64,
    /// Messages it sent.
    pub as_sender: u64,
    /// Messages it received.
    pub as_recipient: u64,
}

/// Why a store operation failed.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// SQLite failed.
    #[error("database: {0}")]
    Db(#[from] rusqlite::Error),
    /// An event skipped a position; nothing of the page was applied.
    #[error("event {got} does not follow checkpoint {checkpoint}")]
    Gap {
        /// The account's checkpoint.
        checkpoint: u64,
        /// The position that came next.
        got: u64,
    },
    /// An added message's content was not stored first; nothing of the page was applied.
    #[error("the content of an added message was not stored first")]
    MissingContent,
    /// The search query was refused by FTS5.
    #[error("the search query is not valid")]
    BadQuery,
    /// The database was written by a newer build.
    #[error("the database has schema version {0}, newer than this build knows")]
    TooNew(i64),
}

/// Applies every migration after the database's `user_version`, each in its own transaction
/// together with the new version, so a crash leaves the database at the last whole step.
fn migrate(conn: &mut Connection) -> Result<(), StoreError> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version > MIGRATIONS.len() as i64 {
        return Err(StoreError::TooNew(version));
    }
    for (n, sql) in MIGRATIONS.iter().enumerate().skip(version as usize) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", n as i64 + 1)?;
        tx.commit()?;
    }
    Ok(())
}

/// The view's SQLite database: one connection for writes (the follower), one read-only
/// connection for the API, in WAL mode so reads never wait for a page being applied.
///
/// Guarantees: every page of events, and every rebuild from a snapshot, is applied together
/// with the account's checkpoint in one transaction, so each event is applied exactly once
/// and readers see either all of a page or none of it. A message is stored once per blob per
/// account; it stays only while at least one membership (mailbox, item) refers to it.
pub struct Store {
    write: Mutex<Connection>,
    read: Mutex<Connection>,
}

/// An account the view follows.
#[derive(Debug, Serialize)]
pub struct AccountRow {
    /// The account id.
    pub account: String,
    /// The last event applied.
    pub checkpoint: u64,
    /// The account's head when Skein was last asked.
    pub head: u64,
    /// `head - checkpoint`, never negative.
    pub lag: u64,
    /// Whether a `first_sync_completed` event was applied.
    pub first_sync_completed: bool,
}

/// A mailbox with its counts.
#[derive(Debug, Serialize)]
pub struct MailboxRow {
    /// The mailbox's provider id.
    pub id: String,
    /// Its path, levels separated by `/`.
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Its role (`inbox`, `sent`, ...), when the provider names one.
    pub role: Option<String>,
    /// Whether it can hold messages.
    pub selectable: bool,
    /// Whether it is a Gmail-style label rather than a folder.
    pub label: bool,
    /// Messages in the mailbox.
    pub total: u64,
    /// Messages in the mailbox without `\Seen`.
    pub unread: u64,
}

/// What a message list shows.
#[derive(Debug, Clone, Serialize)]
pub struct Envelope {
    /// The message id in this API: the BLAKE3 hash of its original bytes.
    pub id: String,
    /// The thread it belongs to.
    pub thread: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The `Message-ID` header without angle brackets.
    pub message_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The `Subject` header, decoded.
    pub subject: Option<String>,
    /// `From` addresses.
    pub from: Vec<Addr>,
    /// `To` addresses.
    pub to: Vec<Addr>,
    /// `Cc` addresses.
    pub cc: Vec<Addr>,
    /// The `Date` header, milliseconds since the epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<i64>,
    /// When the server received it, milliseconds since the epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_at: Option<i64>,
    /// The time lists sort by: `received_at`, else `date`, else when Skein saw it.
    pub sort_date: i64,
    /// Size of the original in bytes.
    pub size: u64,
    /// Whether it has attachments.
    pub has_attachments: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The start of the text body, for lists.
    pub snippet: Option<String>,
    /// Whether some membership lacks `\Seen`.
    pub unread: bool,
    /// Mailboxes holding it, sorted.
    pub mailboxes: Vec<String>,
    /// False when the original bytes could not be read or parsed.
    pub available: bool,
    /// Whether some membership has `\Flagged`.
    pub flagged: bool,
    /// Tags the parser attached, sorted.
    pub tags: Vec<String>,
}

/// A message in one mailbox.
#[derive(Debug, Serialize)]
pub struct Membership {
    /// The mailbox id.
    pub mailbox: String,
    /// The provider's item id in that mailbox.
    pub item: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The IMAP UID, when the provider has one.
    pub uid: Option<u32>,
    /// Flags, such as `\\Seen`.
    pub flags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Gmail labels, when the provider has them.
    pub labels: Option<Vec<String>>,
}

/// Everything the view keeps of a message.
#[derive(Debug, Serialize)]
pub struct MessageDetail {
    #[serde(flatten)]
    /// What lists show of it.
    pub envelope: Envelope,
    /// `In-Reply-To` ids.
    pub in_reply_to: Vec<String>,
    /// `References` ids, in header order.
    pub references: Vec<String>,
    /// Where it is.
    pub memberships: Vec<Membership>,
    /// Its attachments, in part order.
    pub attachments: Vec<Attachment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The text body, capped at [`crate::TEXT_CAP`].
    pub text: Option<String>,
    /// The HTML body exactly as the message has it. Unsanitized: clients must sanitize it
    /// before rendering.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
    /// What the message's iMIP calendar part says, when it carries one. Derived from the
    /// bytes; whether to trust it is the client's decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub itip: Option<skein_core::ItipSummary>,
}

/// A message of a thread with the ids that place it in the reply tree.
#[derive(Debug)]
pub struct ThreadMessage {
    /// What lists show of it.
    pub envelope: Envelope,
    /// `References` ids, in header order.
    pub references: Vec<String>,
    /// `In-Reply-To` ids.
    pub in_reply_to: Vec<String>,
}

/// A thread in a list.
#[derive(Debug, Serialize)]
pub struct ThreadRow {
    /// The thread id, positive.
    pub id: i64,
    /// Messages in the thread, over every mailbox.
    pub count: u64,
    /// Of those, how many are unread.
    pub unread: u64,
    /// The newest message.
    pub latest: Envelope,
}

const ENVELOPE: &str = r#"m.blob, m.thread_id, m.message_id, m.subject, m.from_json, m.to_json,
    m.cc_json, m.date, m.received_at, m.sort_date, m.size, m.has_attachments, m.snippet,
    m.available,
    (SELECT json_group_array(b.mailbox) FROM memberships b WHERE b.message = m.id),
    (SELECT MIN(b.seen) FROM memberships b WHERE b.message = m.id),
    (SELECT MAX(instr(b.flags, '"\\Flagged"') > 0) FROM memberships b WHERE b.message = m.id),
    m.tags"#;

const VISIBLE: &str = "EXISTS (SELECT 1 FROM memberships b WHERE b.message = m.id)";

fn json<T: serde::de::DeserializeOwned + Default>(text: &str) -> T {
    serde_json::from_str(text).unwrap_or_default()
}

fn envelope(row: &Row<'_>) -> rusqlite::Result<Envelope> {
    let mut mailboxes: Vec<String> = json(&row.get::<_, String>(14)?);
    mailboxes.sort();
    mailboxes.dedup();
    Ok(Envelope {
        id: row.get(0)?,
        thread: row.get(1)?,
        message_id: row.get(2)?,
        subject: row.get(3)?,
        from: json(&row.get::<_, String>(4)?),
        to: json(&row.get::<_, String>(5)?),
        cc: json(&row.get::<_, String>(6)?),
        date: row.get(7)?,
        received_at: row.get(8)?,
        sort_date: row.get(9)?,
        size: row.get::<_, i64>(10)? as u64,
        has_attachments: row.get(11)?,
        snippet: row.get(12)?,
        available: row.get(13)?,
        mailboxes,
        unread: row.get::<_, Option<i64>>(15)? == Some(0),
        flagged: row.get::<_, Option<i64>>(16)? == Some(1),
        tags: json(&row.get::<_, String>(17)?),
    })
}

/// A message parsed by another parser version, from [`Store::stale_messages`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleMessage {
    /// The account.
    pub account: String,
    /// The original's hash.
    pub blob: BlobHash,
    /// The original's size in bytes.
    pub size: u64,
    /// One mailbox the message sits in, when it sits in any.
    pub mailbox: Option<String>,
    /// That mailbox's role as the journal named it (`inbox`, `junk`, ...).
    pub role: Option<String>,
}

fn lock(m: &Mutex<Connection>) -> MutexGuard<'_, Connection> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn to_json<T: Serialize + ?Sized>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".into())
}

impl Store {
    /// Opens or creates the database at `path` (created with mode 0600 on Unix) and brings its
    /// schema up to date.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        #[cfg(unix)]
        if !path.exists() {
            use std::os::unix::fs::OpenOptionsExt;
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path);
        }
        let mut write = Connection::open(path)?;
        write.pragma_update(None, "journal_mode", "WAL")?;
        write.pragma_update(None, "synchronous", "NORMAL")?;
        write.pragma_update(None, "foreign_keys", true)?;
        write.busy_timeout(std::time::Duration::from_secs(10))?;
        migrate(&mut write)?;
        let read = Connection::open(path)?;
        read.pragma_update(None, "query_only", true)?;
        read.busy_timeout(std::time::Duration::from_secs(10))?;
        Ok(Self {
            write: Mutex::new(write),
            read: Mutex::new(read),
        })
    }

    /// Records the account's head as Skein reported it, adding the account if it is new.
    pub fn note_head(&self, account: &str, head: u64) -> Result<(), StoreError> {
        lock(&self.write).execute(
            "INSERT INTO accounts (account, head) VALUES (?1, ?2)
             ON CONFLICT (account) DO UPDATE SET head = excluded.head",
            params![account, head as i64],
        )?;
        Ok(())
    }

    /// The last event applied for the account; 0 when none was.
    pub fn checkpoint(&self, account: &str) -> Result<u64, StoreError> {
        Ok(lock(&self.write)
            .query_row(
                "SELECT checkpoint FROM accounts WHERE account = ?1",
                params![account],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .unwrap_or(0) as u64)
    }

    /// The last journal segment applied in full, as verified when it was read; `None` before
    /// the first one and after a rebuild from a snapshot.
    pub fn tip(&self, account: &str) -> Result<Option<SegmentRef>, StoreError> {
        let text: Option<String> = lock(&self.write)
            .query_row(
                "SELECT tip FROM accounts WHERE account = ?1",
                params![account],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        Ok(text.and_then(|t| serde_json::from_str(&t).ok()))
    }

    /// Whether the content of `blob` is stored for the account.
    pub fn has_content(&self, account: &str, blob: &BlobHash) -> Result<bool, StoreError> {
        Ok(lock(&self.write)
            .query_row(
                "SELECT 1 FROM messages WHERE account = ?1 AND blob = ?2",
                params![account, blob.to_string()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Stores a message's parsed content, indexes it for search and threads it. Idempotent:
    /// content already stored for the blob is left as it is. Content no membership refers to
    /// is dropped by the next page or rebuild.
    pub fn insert_content(
        &self,
        account: &str,
        blob: &BlobHash,
        size: u64,
        received_at: Option<i64>,
        seen_at: i64,
        parsed: &Parsed,
    ) -> Result<(), StoreError> {
        self.insert_parsed(account, blob, size, received_at, seen_at, parsed, None)
    }

    /// [`Store::insert_content`], also recording the version of the parser that produced
    /// `parsed`, its tags (checked with [`crate::clean_tags`]) and its addresses in the
    /// account's address book.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_parsed(
        &self,
        account: &str,
        blob: &BlobHash,
        size: u64,
        received_at: Option<i64>,
        seen_at: i64,
        parsed: &Parsed,
        parser: Option<&str>,
    ) -> Result<(), StoreError> {
        let mut conn = lock(&self.write);
        let tx = conn.transaction()?;
        let blob = blob.to_string();
        let exists = tx
            .query_row(
                "SELECT 1 FROM messages WHERE account = ?1 AND blob = ?2",
                params![account, blob],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if exists {
            return Ok(());
        }
        let thread = threads::assign(&tx, account, parsed)?;
        let sort_date = received_at.or(parsed.date).unwrap_or(seen_at);
        tx.execute(
            "INSERT INTO messages (account, blob, size, available, message_id, in_reply_to, refs,
                subject, from_json, to_json, cc_json, date, received_at, sort_date,
                has_attachments, attachments, text, html, snippet, thread_id, itip, tags, parser)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
                ?18, ?19, ?20, ?21, ?22, ?23)",
            params![
                account,
                blob,
                size as i64,
                parsed.available,
                parsed.message_id,
                to_json(&parsed.in_reply_to),
                to_json(&parsed.references),
                parsed.subject,
                to_json(&parsed.from),
                to_json(&parsed.to),
                to_json(&parsed.cc),
                parsed.date,
                received_at,
                sort_date,
                parsed.has_attachments,
                to_json(&parsed.attachments),
                parsed.text,
                parsed.html,
                parsed.snippet,
                thread,
                parsed.itip.as_ref().map(to_json),
                to_json(&crate::parse::clean_tags(&parsed.tags)),
                parser,
            ],
        )?;
        let id = tx.last_insert_rowid();
        let people = || parsed.from.iter().chain(&parsed.to).chain(&parsed.cc);
        let names: Vec<&str> = people().filter_map(|a| a.name.as_deref()).collect();
        let addresses: Vec<&str> = people().filter_map(|a| a.address.as_deref()).collect();
        tx.execute(
            "INSERT INTO search (rowid, subject, names, addresses, body) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, parsed.subject, names.join(" "), addresses.join(" "), parsed.text],
        )?;
        if parsed.available {
            note_addresses(&tx, account, parsed, sort_date)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Messages whose stored content came from a parser version other than `version` (or from
    /// a build that recorded none while the message was available), oldest row first, at most
    /// `limit`: the account, the blob, its size and one mailbox it sits in with that mailbox's
    /// role. Messages whose original was unavailable when parsed are not listed.
    pub fn stale_messages(
        &self,
        version: &str,
        limit: usize,
    ) -> Result<Vec<StaleMessage>, StoreError> {
        let conn = lock(&self.write);
        let mut stmt = conn.prepare(
            "SELECT m.account, m.blob, m.size,
                    (SELECT b.mailbox FROM memberships b WHERE b.message = m.id LIMIT 1),
                    (SELECT x.role FROM memberships b JOIN mailboxes x
                        ON x.account = b.account AND x.id = b.mailbox
                        WHERE b.message = m.id LIMIT 1)
             FROM messages m
             WHERE (m.parser IS NOT NULL AND m.parser != ?1)
                OR (m.parser IS NULL AND m.available = 1)
             ORDER BY m.id LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![version, limit.min(10_000) as i64], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows
            .into_iter()
            .filter_map(|(account, blob, size, mailbox, role)| {
                Some(StaleMessage {
                    account,
                    blob: BlobHash::parse(&blob).ok()?,
                    size: size.max(0) as u64,
                    mailbox,
                    role,
                })
            })
            .collect())
    }

    /// Replaces the parsed fields of the account's stored message `blob` with `parsed` from
    /// parser `version`: envelope, body, attachments, invitation, tags and the search entry.
    /// The thread, the sort date, the memberships and the address book stay as they are. Does
    /// nothing when the message is not stored.
    pub fn replace_parsed(
        &self,
        account: &str,
        blob: &BlobHash,
        parsed: &Parsed,
        version: &str,
    ) -> Result<(), StoreError> {
        let mut conn = lock(&self.write);
        let tx = conn.transaction()?;
        let blob = blob.to_string();
        let Some(id) = tx
            .query_row(
                "SELECT id FROM messages WHERE account = ?1 AND blob = ?2",
                params![account, blob],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
        else {
            return Ok(());
        };
        tx.execute(
            "UPDATE messages SET available = ?2, message_id = ?3, in_reply_to = ?4, refs = ?5,
                subject = ?6, from_json = ?7, to_json = ?8, cc_json = ?9, date = ?10,
                has_attachments = ?11, attachments = ?12, text = ?13, html = ?14, snippet = ?15,
                itip = ?16, tags = ?17, parser = ?18
             WHERE id = ?1",
            params![
                id,
                parsed.available,
                parsed.message_id,
                to_json(&parsed.in_reply_to),
                to_json(&parsed.references),
                parsed.subject,
                to_json(&parsed.from),
                to_json(&parsed.to),
                to_json(&parsed.cc),
                parsed.date,
                parsed.has_attachments,
                to_json(&parsed.attachments),
                parsed.text,
                parsed.html,
                parsed.snippet,
                parsed.itip.as_ref().map(to_json),
                to_json(&crate::parse::clean_tags(&parsed.tags)),
                version,
            ],
        )?;
        let people = || parsed.from.iter().chain(&parsed.to).chain(&parsed.cc);
        let names: Vec<&str> = people().filter_map(|a| a.name.as_deref()).collect();
        let addresses: Vec<&str> = people().filter_map(|a| a.address.as_deref()).collect();
        tx.execute("DELETE FROM search WHERE rowid = ?1", params![id])?;
        tx.execute(
            "INSERT INTO search (rowid, subject, names, addresses, body) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, parsed.subject, names.join(" "), addresses.join(" "), parsed.text],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Records `version` for the account's message `blob` without changing its content: for a
    /// stale message whose original is no longer available, so it is not listed again.
    pub fn mark_parsed(
        &self,
        account: &str,
        blob: &BlobHash,
        version: &str,
    ) -> Result<(), StoreError> {
        lock(&self.write).execute(
            "UPDATE messages SET parser = ?3 WHERE account = ?1 AND blob = ?2",
            params![account, blob.to_string(), version],
        )?;
        Ok(())
    }

    /// Applies a page of the account's events in log order and advances the checkpoint, in one
    /// transaction. Events at or before the checkpoint are skipped, so a page read twice is
    /// harmless; a gap fails the whole page. Returns the new checkpoint.
    ///
    /// `message_added` needs its content stored first ([`Store::insert_content`]), and
    /// `object_upserted` its object ([`Store::insert_object`]). `resync_required` empties the
    /// mailbox or collection of its domain (both without one), as the listing that follows adds
    /// back what is still there. Command outcomes and unknown types only move the checkpoint.
    pub fn apply_page(&self, account: &str, events: &[Event]) -> Result<u64, StoreError> {
        self.apply_page_to(account, events, None)
    }

    /// [`Store::apply_page`], also recording `tip` as the last journal segment applied in full
    /// when it is given, in the same transaction.
    pub fn apply_page_to(
        &self,
        account: &str,
        events: &[Event],
        tip: Option<&SegmentRef>,
    ) -> Result<u64, StoreError> {
        let mut conn = lock(&self.write);
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO accounts (account) VALUES (?1) ON CONFLICT DO NOTHING",
            params![account],
        )?;
        let mut checkpoint = tx.query_row(
            "SELECT checkpoint FROM accounts WHERE account = ?1",
            params![account],
            |r| r.get::<_, i64>(0),
        )? as u64;
        for event in events {
            if event.seq.0 <= checkpoint {
                continue;
            }
            if event.seq.0 != checkpoint + 1 {
                return Err(StoreError::Gap {
                    checkpoint,
                    got: event.seq.0,
                });
            }
            apply_event(&tx, account, &event.body)?;
            pim::apply(&tx, account, &event.body)?;
            checkpoint = event.seq.0;
        }
        drop_orphans(&tx, account)?;
        pim::drop_orphans(&tx, account)?;
        tx.execute(
            "UPDATE accounts SET checkpoint = ?2, head = MAX(head, ?2) WHERE account = ?1",
            params![account, checkpoint as i64],
        )?;
        if let Some(tip) = tip {
            tx.execute(
                "UPDATE accounts SET tip = ?2 WHERE account = ?1",
                params![account, to_json(tip)],
            )?;
        }
        tx.commit()?;
        Ok(checkpoint)
    }

    /// Replaces the account's mailboxes, memberships, collections and placements with the
    /// snapshot's and sets the checkpoint to its `seq`, in one transaction. The content of every
    /// message and object in the snapshot must be stored first; content kept from before is
    /// reused, the rest dropped.
    pub fn rebuild(&self, account: &str, snapshot: &Snapshot) -> Result<(), StoreError> {
        let mut conn = lock(&self.write);
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO accounts (account) VALUES (?1) ON CONFLICT DO NOTHING",
            params![account],
        )?;
        tx.execute(
            "DELETE FROM memberships WHERE account = ?1",
            params![account],
        )?;
        tx.execute("DELETE FROM mailboxes WHERE account = ?1", params![account])?;
        for (id, mailbox) in &snapshot.mailboxes {
            let mut info = mailbox.info.clone();
            info.id.clone_from(id);
            upsert_mailbox(&tx, account, &info)?;
            for state in mailbox.items.values() {
                put_membership(
                    &tx,
                    account,
                    id,
                    &state.item,
                    &state.blob,
                    &state.flags,
                    state.labels.as_deref(),
                )?;
            }
        }
        pim::rebuild(&tx, account, snapshot)?;
        drop_orphans(&tx, account)?;
        pim::drop_orphans(&tx, account)?;
        tx.execute(
            "UPDATE accounts SET checkpoint = ?2, head = MAX(head, ?2), tip = NULL WHERE account = ?1",
            params![account, snapshot.seq.0 as i64],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn reader(&self) -> MutexGuard<'_, Connection> {
        lock(&self.read)
    }

    /// Every followed account, by id.
    pub fn accounts(&self) -> Result<Vec<AccountRow>, StoreError> {
        let conn = self.reader();
        let mut q = conn.prepare(
            "SELECT account, checkpoint, head, first_sync FROM accounts ORDER BY account",
        )?;
        let rows = q.query_map([], |r| {
            let checkpoint = r.get::<_, i64>(1)? as u64;
            let head = r.get::<_, i64>(2)? as u64;
            Ok(AccountRow {
                account: r.get(0)?,
                checkpoint,
                head,
                lag: head.saturating_sub(checkpoint),
                first_sync_completed: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Whether the account is followed.
    pub fn has_account(&self, account: &str) -> Result<bool, StoreError> {
        Ok(self
            .reader()
            .query_row(
                "SELECT 1 FROM accounts WHERE account = ?1",
                params![account],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// The account's mailboxes by path, with message counts.
    pub fn mailboxes(&self, account: &str) -> Result<Vec<MailboxRow>, StoreError> {
        let conn = self.reader();
        let mut q = conn.prepare(
            "SELECT x.id, x.path, x.role, x.selectable, x.label,
                (SELECT COUNT(*) FROM memberships b WHERE b.account = x.account AND b.mailbox = x.id),
                (SELECT COUNT(*) FROM memberships b
                    WHERE b.account = x.account AND b.mailbox = x.id AND b.seen = 0)
             FROM mailboxes x WHERE x.account = ?1 ORDER BY x.path, x.id",
        )?;
        let rows = q.query_map(params![account], |r| {
            Ok(MailboxRow {
                id: r.get(0)?,
                path: r.get(1)?,
                role: r.get(2)?,
                selectable: r.get(3)?,
                label: r.get(4)?,
                total: r.get::<_, i64>(5)? as u64,
                unread: r.get::<_, i64>(6)? as u64,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Envelopes newest first (by `sort_date`, then id), optionally only those in `mailbox`,
    /// strictly before the cursor `(sort_date, id)`.
    pub fn messages(
        &self,
        account: &str,
        mailbox: Option<&str>,
        before: Option<(i64, String)>,
        limit: usize,
    ) -> Result<Vec<Envelope>, StoreError> {
        let conn = self.reader();
        let sql = format!(
            "SELECT {ENVELOPE} FROM messages m
             WHERE m.account = ?1
               AND EXISTS (SELECT 1 FROM memberships b
                           WHERE b.message = m.id AND (?2 IS NULL OR b.mailbox = ?2))
               AND (?3 IS NULL OR (m.sort_date, m.blob) < (?3, ?4))
             ORDER BY m.sort_date DESC, m.blob DESC LIMIT ?5"
        );
        let (date, blob) = before.unzip();
        let mut q = conn.prepare_cached(&sql)?;
        let rows = q.query_map(
            params![
                account,
                mailbox,
                date,
                blob,
                limit.min(crate::store::MAX_LIMIT) as i64
            ],
            envelope,
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Whether the account has the message with this id in some mailbox.
    pub fn has_message(&self, account: &str, id: &str) -> Result<bool, StoreError> {
        let sql =
            format!("SELECT 1 FROM messages m WHERE m.account = ?1 AND m.blob = ?2 AND {VISIBLE}");
        Ok(self
            .reader()
            .query_row(&sql, params![account, id], |_| Ok(()))
            .optional()?
            .is_some())
    }

    /// One message with its memberships and content, if the account has it.
    pub fn message(&self, account: &str, id: &str) -> Result<Option<MessageDetail>, StoreError> {
        let conn = self.reader();
        let sql = format!(
            "SELECT {ENVELOPE}, m.id, m.in_reply_to, m.refs, m.attachments, m.text, m.html, m.itip
             FROM messages m WHERE m.account = ?1 AND m.blob = ?2 AND {VISIBLE}"
        );
        let found = conn
            .query_row(&sql, params![account, id], |r| {
                Ok((
                    envelope(r)?,
                    r.get::<_, i64>(18)?,
                    json::<Vec<String>>(&r.get::<_, String>(19)?),
                    json::<Vec<String>>(&r.get::<_, String>(20)?),
                    json::<Vec<Attachment>>(&r.get::<_, String>(21)?),
                    r.get::<_, Option<String>>(22)?,
                    r.get::<_, Option<String>>(23)?,
                    r.get::<_, Option<String>>(24)?
                        .and_then(|t| serde_json::from_str(&t).ok()),
                ))
            })
            .optional()?;
        let Some((envelope, rowid, in_reply_to, references, attachments, text, html, itip)) = found
        else {
            return Ok(None);
        };
        let mut q = conn.prepare_cached(
            "SELECT mailbox, item_id, uid, flags, labels FROM memberships
             WHERE message = ?1 ORDER BY mailbox, item_id",
        )?;
        let memberships = q
            .query_map(params![rowid], |r| {
                Ok(Membership {
                    mailbox: r.get(0)?,
                    item: r.get(1)?,
                    uid: r.get::<_, Option<i64>>(2)?.map(|u| u as u32),
                    flags: json(&r.get::<_, String>(3)?),
                    labels: r
                        .get::<_, Option<String>>(4)?
                        .map(|l| json::<Vec<String>>(&l)),
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(Some(MessageDetail {
            envelope,
            in_reply_to,
            references,
            memberships,
            attachments,
            text,
            html,
            itip,
        }))
    }

    /// Threads newest first by their newest message, optionally only those with a message in
    /// `mailbox`, strictly before the cursor `(latest sort_date, thread id)`.
    pub fn threads(
        &self,
        account: &str,
        mailbox: Option<&str>,
        before: Option<(i64, i64)>,
        limit: usize,
    ) -> Result<Vec<ThreadRow>, StoreError> {
        let conn = self.reader();
        let sql = format!(
            "SELECT m.thread_id, MAX(m.sort_date) AS latest, COUNT(*),
                SUM((SELECT MIN(b.seen) FROM memberships b WHERE b.message = m.id) = 0)
             FROM messages m
             WHERE m.account = ?1 AND {VISIBLE}
             GROUP BY m.thread_id
             HAVING (?2 IS NULL OR EXISTS (
                        SELECT 1 FROM messages m2 JOIN memberships b2 ON b2.message = m2.id
                        WHERE m2.account = ?1 AND m2.thread_id = m.thread_id AND b2.mailbox = ?2))
                AND (?3 IS NULL OR (latest, m.thread_id) < (?3, ?4))
             ORDER BY latest DESC, m.thread_id DESC LIMIT ?5"
        );
        let (date, thread) = before.unzip();
        let groups: Vec<(i64, u64, u64)> = conn
            .prepare_cached(&sql)?
            .query_map(
                params![
                    account,
                    mailbox,
                    date,
                    thread,
                    limit.min(crate::store::MAX_LIMIT) as i64
                ],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get::<_, i64>(2)? as u64,
                        r.get::<_, i64>(3)? as u64,
                    ))
                },
            )?
            .collect::<Result<_, _>>()?;
        let latest_sql = format!(
            "SELECT {ENVELOPE} FROM messages m
             WHERE m.account = ?1 AND m.thread_id = ?2 AND {VISIBLE}
             ORDER BY m.sort_date DESC, m.blob DESC LIMIT 1"
        );
        let mut latest = conn.prepare_cached(&latest_sql)?;
        let mut out = Vec::with_capacity(groups.len());
        for (id, count, unread) in groups {
            if let Some(env) = latest
                .query_row(params![account, id], envelope)
                .optional()?
            {
                out.push(ThreadRow {
                    id,
                    count,
                    unread,
                    latest: env,
                });
            }
        }
        Ok(out)
    }

    /// The thread's messages oldest first, at most `limit`, each with its `References` and
    /// `In-Reply-To` ids; empty when there is no such thread.
    pub fn thread(
        &self,
        account: &str,
        thread: i64,
        limit: usize,
    ) -> Result<Vec<ThreadMessage>, StoreError> {
        let conn = self.reader();
        let sql = format!(
            "SELECT {ENVELOPE}, m.refs, m.in_reply_to FROM messages m
             WHERE m.account = ?1 AND m.thread_id = ?2 AND {VISIBLE}
             ORDER BY m.sort_date ASC, m.blob ASC LIMIT ?3"
        );
        let mut q = conn.prepare_cached(&sql)?;
        let rows = q.query_map(
            params![account, thread, limit.min(crate::store::MAX_LIMIT) as i64],
            |r| {
                Ok(ThreadMessage {
                    envelope: envelope(r)?,
                    references: json(&r.get::<_, String>(18)?),
                    in_reply_to: json(&r.get::<_, String>(19)?),
                })
            },
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Messages matching an FTS5 query from [`crate::search::fts_query`], best first.
    pub fn search(
        &self,
        account: &str,
        fts: &str,
        limit: usize,
    ) -> Result<Vec<Envelope>, StoreError> {
        let conn = self.reader();
        let sql = format!(
            "SELECT {ENVELOPE} FROM search s JOIN messages m ON m.id = s.rowid
             WHERE search MATCH ?2 AND m.account = ?1 AND {VISIBLE}
             ORDER BY s.rank LIMIT ?3"
        );
        let run = || -> rusqlite::Result<Vec<Envelope>> {
            let mut q = conn.prepare_cached(&sql)?;
            let rows = q.query_map(
                params![account, fts, limit.min(crate::store::MAX_LIMIT) as i64],
                envelope,
            )?;
            rows.collect()
        };
        run().map_err(|e| match e {
            rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::Unknown => {
                StoreError::BadQuery
            }
            other => StoreError::Db(other),
        })
    }
}

impl Store {
    /// Envelopes of the account matching `filter`, newest first by `(sort_date, id)`, strictly
    /// before the cursor `(sort_date, id)`; at most `limit` and never more than [`MAX_LIMIT`].
    pub fn messages_where(
        &self,
        account: &str,
        filter: &Filter,
        before: Option<(i64, String)>,
        limit: usize,
    ) -> Result<Vec<Envelope>, StoreError> {
        let conn = self.reader();
        let sql = format!(
            "SELECT {ENVELOPE} FROM messages m
             WHERE m.account = :account AND {VISIBLE} AND {FILTER}
               AND (:date IS NULL OR (m.sort_date, m.blob) < (:date, :cursor))
             ORDER BY m.sort_date DESC, m.blob DESC LIMIT :limit"
        );
        let (date, cursor) = before.unzip();
        let mailboxes = filter.mailboxes_json();
        let mut q = conn.prepare_cached(&sql)?;
        let rows = q.query_map(
            named_params! {
                ":account": account,
                ":mailboxes": mailboxes,
                ":unread": filter.unread,
                ":flagged": filter.flagged,
                ":flag": FLAGGED_JSON,
                ":attachments": filter.has_attachments,
                ":tag": filter.tag,
                ":date": date,
                ":cursor": cursor,
                ":limit": limit.min(MAX_LIMIT) as i64,
            },
            envelope,
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Threads of the account with at least one message matching `filter`, newest first by
    /// their newest message, strictly before the cursor `(latest sort_date, thread id)`. Counts
    /// and the latest envelope cover the whole thread.
    pub fn threads_where(
        &self,
        account: &str,
        filter: &Filter,
        before: Option<(i64, i64)>,
        limit: usize,
    ) -> Result<Vec<ThreadRow>, StoreError> {
        let conn = self.reader();
        let sql = format!(
            "SELECT t.thread_id, MAX(t.sort_date) AS latest, COUNT(*),
                SUM((SELECT MIN(b.seen) FROM memberships b WHERE b.message = t.id) = 0)
             FROM messages t
             WHERE t.account = :account
               AND EXISTS (SELECT 1 FROM memberships b WHERE b.message = t.id)
               AND t.thread_id IN (
                   SELECT m.thread_id FROM messages m
                   WHERE m.account = :account AND {VISIBLE} AND {FILTER})
             GROUP BY t.thread_id
             HAVING (:date IS NULL OR (latest, t.thread_id) < (:date, :cursor))
             ORDER BY latest DESC, t.thread_id DESC LIMIT :limit"
        );
        let (date, cursor) = before.unzip();
        let mailboxes = filter.mailboxes_json();
        let groups: Vec<(i64, u64, u64)> = conn
            .prepare_cached(&sql)?
            .query_map(
                named_params! {
                    ":account": account,
                    ":mailboxes": mailboxes,
                    ":unread": filter.unread,
                    ":flagged": filter.flagged,
                    ":flag": FLAGGED_JSON,
                    ":attachments": filter.has_attachments,
                    ":tag": filter.tag,
                    ":date": date,
                    ":cursor": cursor,
                    ":limit": limit.min(MAX_LIMIT) as i64,
                },
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get::<_, i64>(2)? as u64,
                        r.get::<_, i64>(3)? as u64,
                    ))
                },
            )?
            .collect::<Result<_, _>>()?;
        let latest_sql = format!(
            "SELECT {ENVELOPE} FROM messages m
             WHERE m.account = ?1 AND m.thread_id = ?2 AND {VISIBLE}
             ORDER BY m.sort_date DESC, m.blob DESC LIMIT 1"
        );
        let mut latest = conn.prepare_cached(&latest_sql)?;
        let mut out = Vec::with_capacity(groups.len());
        for (id, count, unread) in groups {
            if let Some(env) = latest
                .query_row(params![account, id], envelope)
                .optional()?
            {
                out.push(ThreadRow {
                    id,
                    count,
                    unread,
                    latest: env,
                });
            }
        }
        Ok(out)
    }

    /// Messages of the account matching an FTS5 query from [`crate::search::fts_query`] and
    /// `filter`, best first; at most `limit` and never more than [`MAX_LIMIT`].
    pub fn search_where(
        &self,
        account: &str,
        fts: &str,
        filter: &Filter,
        limit: usize,
    ) -> Result<Vec<Envelope>, StoreError> {
        let conn = self.reader();
        let sql = format!(
            "SELECT {ENVELOPE} FROM search s JOIN messages m ON m.id = s.rowid
             WHERE search MATCH :fts AND m.account = :account AND {VISIBLE} AND {FILTER}
             ORDER BY s.rank LIMIT :limit"
        );
        let mailboxes = filter.mailboxes_json();
        let run = || -> rusqlite::Result<Vec<Envelope>> {
            let mut q = conn.prepare_cached(&sql)?;
            let rows = q.query_map(
                named_params! {
                    ":fts": fts,
                    ":account": account,
                    ":mailboxes": mailboxes,
                    ":unread": filter.unread,
                    ":flagged": filter.flagged,
                    ":flag": FLAGGED_JSON,
                    ":attachments": filter.has_attachments,
                    ":tag": filter.tag,
                    ":limit": limit.min(MAX_LIMIT) as i64,
                },
                envelope,
            )?;
            rows.collect()
        };
        run().map_err(|e| match e {
            rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::Unknown => {
                StoreError::BadQuery
            }
            other => StoreError::Db(other),
        })
    }

    /// Known correspondents whose address or name starts with `prefix` (case-insensitive), of
    /// one account or of every account, most used first; at most `limit` and never more than
    /// [`MAX_SUGGESTIONS`]. An empty prefix matches nothing.
    pub fn suggest_addresses(
        &self,
        account: Option<&str>,
        prefix: &str,
        limit: usize,
    ) -> Result<Vec<AddressRow>, StoreError> {
        if prefix.is_empty() {
            return Ok(Vec::new());
        }
        let pattern = format!("{}%", like_escape(&prefix.to_lowercase()));
        let conn = self.reader();
        let mut q = conn.prepare_cached(
            "SELECT account, address, name, last_seen, as_sender, as_recipient FROM addresses
             WHERE (?1 IS NULL OR account = ?1)
               AND (address LIKE ?2 ESCAPE '\\' OR lower(name) LIKE ?2 ESCAPE '\\')
             ORDER BY as_sender + as_recipient DESC, last_seen DESC, address, account
             LIMIT ?3",
        )?;
        let rows = q.query_map(
            params![account, pattern, limit.min(MAX_SUGGESTIONS) as i64],
            |r| {
                Ok(AddressRow {
                    account: r.get(0)?,
                    address: r.get(1)?,
                    name: r.get(2)?,
                    last_seen: r.get(3)?,
                    as_sender: r.get::<_, i64>(4)? as u64,
                    as_recipient: r.get::<_, i64>(5)? as u64,
                })
            },
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Whether the account has mailed `address` (compared in lower case): it is a `To` or `Cc`
    /// of a parsed message in one of the account's mailboxes with the `sent` role. Mail it only
    /// received, whoever it names, never counts.
    pub fn knows_address(&self, account: &str, address: &str) -> Result<bool, StoreError> {
        let address = address.to_lowercase();
        if !address.contains('@') || !address.chars().any(char::is_alphanumeric) {
            return Ok(false);
        }
        let phrase = format!("addresses : \"{}\"", address.replace('"', "\"\""));
        Ok(self
            .reader()
            .query_row(
                "SELECT 1 FROM search s
                 JOIN messages m ON m.id = s.rowid
                 JOIN memberships mb ON mb.message = m.id
                 JOIN mailboxes x ON x.account = mb.account AND x.id = mb.mailbox
                 WHERE search MATCH ?3 AND m.account = ?1 AND m.available
                   AND x.role = 'sent'
                   AND EXISTS (
                     SELECT 1 FROM json_each(m.to_json) j
                       WHERE lower(json_extract(j.value, '$.address')) = ?2
                     UNION ALL
                     SELECT 1 FROM json_each(m.cc_json) j
                       WHERE lower(json_extract(j.value, '$.address')) = ?2)
                 LIMIT 1",
                params![account, address, phrase],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// The role of the account's mailbox `id`, as the journal named it.
    pub fn mailbox_role(&self, account: &str, id: &str) -> Result<Option<String>, StoreError> {
        Ok(self
            .reader()
            .query_row(
                "SELECT role FROM mailboxes WHERE account = ?1 AND id = ?2",
                params![account, id],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten())
    }

    /// Up to `limit` (at most [`MAX_LIMIT`]) blob hashes of the account's messages and objects
    /// after `after`, in ascending order, for paging through what the account names.
    pub fn blobs_of(
        &self,
        account: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>, StoreError> {
        let conn = self.reader();
        let mut q = conn.prepare_cached(
            "SELECT blob FROM (SELECT blob FROM messages WHERE account = ?1
                 UNION SELECT blob FROM objects WHERE account = ?1)
             WHERE (?2 IS NULL OR blob > ?2) ORDER BY blob LIMIT ?3",
        )?;
        let rows = q.query_map(params![account, after, limit.min(MAX_LIMIT) as i64], |r| {
            r.get(0)
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Whether any account stores the message or object whose original is `blob`.
    pub fn knows_blob(&self, blob: &str) -> Result<bool, StoreError> {
        let conn = self.reader();
        let found = conn
            .query_row(
                "SELECT 1 FROM messages WHERE blob = ?1
                 UNION ALL SELECT 1 FROM objects WHERE blob = ?1 LIMIT 1",
                params![blob],
                |_| Ok(()),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// Removes everything the database holds for the account, in one transaction: mailboxes,
    /// messages, search entries, threads, addresses, collections and objects. Following the
    /// account again starts from an empty checkpoint.
    pub fn forget_account(&self, account: &str) -> Result<(), StoreError> {
        let mut conn = lock(&self.write);
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM search WHERE rowid IN (SELECT id FROM messages WHERE account = ?1)",
            params![account],
        )?;
        tx.execute(
            "DELETE FROM contact_search WHERE rowid IN (SELECT id FROM objects WHERE account = ?1)",
            params![account],
        )?;
        for table in [
            "memberships",
            "messages",
            "mailboxes",
            "threads",
            "thread_ids",
            "addresses",
            "placements",
            "objects",
            "collections",
            "accounts",
        ] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE account = ?1"),
                params![account],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}

fn like_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn note_addresses(
    tx: &Transaction<'_>,
    account: &str,
    parsed: &Parsed,
    seen: i64,
) -> rusqlite::Result<()> {
    let mut q = tx.prepare_cached(
        "INSERT INTO addresses (account, address, name, last_seen, as_sender, as_recipient)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (account, address) DO UPDATE SET
            name = COALESCE(excluded.name, name),
            last_seen = MAX(last_seen, excluded.last_seen),
            as_sender = as_sender + excluded.as_sender,
            as_recipient = as_recipient + excluded.as_recipient",
    )?;
    let senders = parsed.from.iter().map(|a| (a, 1, 0));
    let recipients = parsed.to.iter().chain(&parsed.cc).map(|a| (a, 0, 1));
    for (addr, sent, received) in senders.chain(recipients).take(64) {
        let Some(address) = addr.address.as_deref() else {
            continue;
        };
        if address.len() > 320 || !address.contains('@') || address.chars().any(char::is_control) {
            continue;
        }
        let name = addr
            .name
            .as_deref()
            .filter(|n| n.chars().count() <= 200 && !n.chars().any(char::is_control));
        q.execute(params![
            account,
            address.to_lowercase(),
            name,
            seen,
            sent,
            received
        ])?;
    }
    Ok(())
}

fn upsert_mailbox(tx: &Transaction<'_>, account: &str, info: &MailboxInfo) -> rusqlite::Result<()> {
    let role = info
        .role
        .and_then(|r| serde_json::to_value(r).ok())
        .and_then(|v| v.as_str().map(str::to_owned));
    tx.execute(
        "INSERT INTO mailboxes (account, id, path, role, selectable, label)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (account, id) DO UPDATE SET path = excluded.path, role = excluded.role,
            selectable = excluded.selectable, label = excluded.label",
        params![
            account,
            info.id,
            info.path,
            role,
            info.selectable,
            info.label
        ],
    )?;
    Ok(())
}

fn put_membership(
    tx: &Transaction<'_>,
    account: &str,
    mailbox: &str,
    item: &ItemRef,
    blob: &BlobHash,
    flags: &Flags,
    labels: Option<&[String]>,
) -> Result<(), StoreError> {
    let message: i64 = tx
        .query_row(
            "SELECT id FROM messages WHERE account = ?1 AND blob = ?2",
            params![account, blob.to_string()],
            |r| r.get(0),
        )
        .optional()?
        .ok_or(StoreError::MissingContent)?;
    tx.execute(
        "INSERT INTO mailboxes (account, id, path, selectable, label) VALUES (?1, ?2, ?2, 1, 0)
         ON CONFLICT DO NOTHING",
        params![account, mailbox],
    )?;
    tx.execute(
        "INSERT INTO memberships (account, mailbox, item_id, uid, message, flags, labels, seen)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT (account, mailbox, item_id) DO UPDATE SET uid = excluded.uid,
            message = excluded.message, flags = excluded.flags, labels = excluded.labels,
            seen = excluded.seen",
        params![
            account,
            mailbox,
            item.id,
            item.uid,
            message,
            to_json(flags),
            labels.map(to_json),
            flags.contains("\\Seen"),
        ],
    )?;
    Ok(())
}

fn apply_event(tx: &Transaction<'_>, account: &str, body: &EventBody) -> Result<(), StoreError> {
    match body {
        EventBody::MailboxUpserted { mailbox } => upsert_mailbox(tx, account, mailbox)?,
        EventBody::MailboxDeleted { mailbox } => {
            tx.execute(
                "DELETE FROM memberships WHERE account = ?1 AND mailbox = ?2",
                params![account, mailbox],
            )?;
            tx.execute(
                "DELETE FROM mailboxes WHERE account = ?1 AND id = ?2",
                params![account, mailbox],
            )?;
        }
        EventBody::MessageAdded {
            mailbox,
            item,
            blob,
            flags,
            labels,
            ..
        } => put_membership(tx, account, mailbox, item, blob, flags, labels.as_deref())?,
        EventBody::MessageRemoved { mailbox, item } => {
            tx.execute(
                "DELETE FROM memberships WHERE account = ?1 AND mailbox = ?2 AND item_id = ?3",
                params![account, mailbox, item.id],
            )?;
        }
        EventBody::FlagsChanged {
            mailbox,
            item,
            flags,
        } => {
            tx.execute(
                "UPDATE memberships SET flags = ?4, seen = ?5
                 WHERE account = ?1 AND mailbox = ?2 AND item_id = ?3",
                params![
                    account,
                    mailbox,
                    item.id,
                    to_json(flags),
                    flags.contains("\\Seen")
                ],
            )?;
        }
        EventBody::LabelsChanged {
            mailbox,
            item,
            labels,
        } => {
            tx.execute(
                "UPDATE memberships SET labels = ?4
                 WHERE account = ?1 AND mailbox = ?2 AND item_id = ?3",
                params![account, mailbox, item.id, to_json(labels)],
            )?;
        }
        EventBody::ResyncRequired {
            collection,
            domain: None | Some(skein_core::Domain::Mail),
            ..
        } => {
            tx.execute(
                "DELETE FROM memberships WHERE account = ?1 AND mailbox = ?2",
                params![account, collection],
            )?;
        }
        EventBody::FirstSyncCompleted => {
            tx.execute(
                "UPDATE accounts SET first_sync = 1 WHERE account = ?1",
                params![account],
            )?;
        }
        _ => {}
    }
    Ok(())
}

fn drop_orphans(tx: &Transaction<'_>, account: &str) -> rusqlite::Result<()> {
    let orphans: Vec<i64> = tx
        .prepare_cached(
            "SELECT m.id FROM messages m WHERE m.account = ?1
             AND NOT EXISTS (SELECT 1 FROM memberships b WHERE b.message = m.id)",
        )?
        .query_map(params![account], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    let mut fts = tx.prepare_cached("DELETE FROM search WHERE rowid = ?1")?;
    let mut msg = tx.prepare_cached("DELETE FROM messages WHERE id = ?1")?;
    for id in orphans {
        fts.execute(params![id])?;
        msg.execute(params![id])?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use skein_core::{AccountId, Domain, SCHEMA_VERSION, Seq, Timestamp};
    use skein_storage::{ItemState, MailboxState};

    use super::*;
    use crate::parse::{parse, tests::fixture};

    pub(crate) fn temp_store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("view.sqlite")).unwrap();
        (dir, store)
    }

    pub(crate) fn ev(seq: u64, body: EventBody) -> Event {
        Event {
            v: SCHEMA_VERSION,
            seq: Seq(seq),
            at: Timestamp(seq as i64),
            account: AccountId::new("box").unwrap(),
            key: format!("k{seq}"),
            origin: None,
            trace: None,
            body,
        }
    }

    pub(crate) fn item(id: &str) -> ItemRef {
        ItemRef {
            id: id.into(),
            uid: None,
        }
    }

    pub(crate) fn added(seq: u64, mailbox: &str, id: &str, bytes: &[u8]) -> Event {
        ev(
            seq,
            EventBody::MessageAdded {
                mailbox: mailbox.into(),
                item: item(id),
                blob: BlobHash::of(bytes),
                size: bytes.len() as u64,
                flags: Flags::default(),
                labels: None,
                received_at: Some(Timestamp(1_000 + seq as i64)),
            },
        )
    }

    fn store_content(store: &Store, bytes: &[u8]) -> String {
        let blob = BlobHash::of(bytes);
        store
            .insert_content("box", &blob, bytes.len() as u64, None, 0, &parse(bytes))
            .unwrap();
        blob.to_string()
    }

    fn apply(store: &Store, events: &[(&Event, Option<&[u8]>)]) {
        for (event, bytes) in events {
            if let (Some(b), EventBody::MessageAdded { received_at, .. }) = (bytes, &event.body) {
                store
                    .insert_content(
                        "box",
                        &BlobHash::of(b),
                        b.len() as u64,
                        received_at.map(|t| t.0),
                        0,
                        &parse(b),
                    )
                    .unwrap();
            }
        }
        let list: Vec<Event> = events.iter().map(|(e, _)| (*e).clone()).collect();
        store.apply_page("box", &list).unwrap();
    }

    #[test]
    fn filters_narrow_messages_threads_and_search() {
        let (_d, store) = temp_store();
        let plain = fixture("plain.eml");
        let multi = fixture("multipart.eml");
        let mut flagged = added(2, "Archive", "2", &multi);
        if let EventBody::MessageAdded { flags, .. } = &mut flagged.body {
            *flags = Flags::new(["\\Flagged", "\\Seen"]);
        }
        apply(
            &store,
            &[
                (&added(1, "INBOX", "1", &plain), Some(&plain)),
                (&flagged, Some(&multi)),
            ],
        );
        let ids = |f: &Filter| -> Vec<String> {
            store
                .messages_where("box", f, None, 10)
                .unwrap()
                .into_iter()
                .map(|e| e.id)
                .collect()
        };
        let p = BlobHash::of(&plain).to_string();
        let m = BlobHash::of(&multi).to_string();
        assert_eq!(ids(&Filter::default()), vec![m.clone(), p.clone()]);
        assert_eq!(ids(&Filter::mailbox("INBOX")), vec![p.clone()]);
        assert_eq!(
            ids(&Filter {
                mailboxes: Some(vec![]),
                ..Filter::default()
            }),
            Vec::<String>::new()
        );
        let flag = Filter {
            flagged: Some(true),
            ..Filter::default()
        };
        assert_eq!(ids(&flag), vec![m.clone()]);
        assert_eq!(
            ids(&Filter {
                unread: Some(true),
                ..Filter::default()
            }),
            vec![p.clone()]
        );
        assert_eq!(
            ids(&Filter {
                has_attachments: Some(true),
                ..Filter::default()
            }),
            vec![m.clone()]
        );
        let envs = store.messages_where("box", &flag, None, 10).unwrap();
        assert!(envs[0].flagged && !envs[0].unread);
        let threads = store.threads_where("box", &flag, None, 10).unwrap();
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].latest.id, m);
        let page = store
            .messages_where(
                "box",
                &Filter::default(),
                Some((envs[0].sort_date, m.clone())),
                10,
            )
            .unwrap();
        assert_eq!(page.len(), 1);
        let fts = crate::search::fts_query("seating").unwrap();
        assert_eq!(
            store
                .search_where("box", &fts, &Filter::mailbox("INBOX"), 10)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            store
                .search_where("box", &fts, &Filter::mailbox("Archive"), 10)
                .unwrap()
                .len(),
            1
        );
        let hostile_tag = Filter {
            tag: Some("x' OR 1=1 --".into()),
            mailboxes: Some(vec!["INBOX') OR ('1'='1".into()]),
            ..Filter::default()
        };
        assert!(ids(&hostile_tag).is_empty());
    }

    #[test]
    fn addresses_are_learned_suggested_and_forgotten() {
        let (_d, store) = temp_store();
        let plain = fixture("plain.eml");
        apply(&store, &[(&added(1, "INBOX", "1", &plain), Some(&plain))]);
        assert!(!store.knows_address("box", "PAT@example.com").unwrap());
        let s = store.suggest_addresses(None, "pa", 10).unwrap();
        assert_eq!(s[0].address, "pat@example.com");
        assert_eq!(s[0].as_sender, 1);
        assert_eq!(s[0].name.as_deref(), Some("Pat Doe"));
        assert_eq!(
            store
                .suggest_addresses(Some("box"), "pat d", 10)
                .unwrap()
                .len(),
            1
        );
        assert!(store.suggest_addresses(None, "", 10).unwrap().is_empty());
        assert!(store.suggest_addresses(None, "%", 10).unwrap().is_empty());
        assert!(store.suggest_addresses(None, "_", 10).unwrap().is_empty());
        assert!(store.knows_blob(&BlobHash::of(&plain).to_string()).unwrap());
        assert_eq!(
            store.blobs_of("box", None, 10).unwrap(),
            vec![BlobHash::of(&plain).to_string()]
        );
        assert!(
            store
                .blobs_of("box", Some(&BlobHash::of(&plain).to_string()), 10)
                .unwrap()
                .is_empty()
        );
        store.forget_account("box").unwrap();
        assert!(!store.knows_address("box", "pat@example.com").unwrap());
        assert!(!store.knows_blob(&BlobHash::of(&plain).to_string()).unwrap());
        assert!(store.accounts().unwrap().is_empty());
        assert!(store.messages("box", None, None, 10).unwrap().is_empty());
        let fts = crate::search::fts_query("tomatoes").unwrap();
        assert!(store.search("box", &fts, 10).unwrap().is_empty());
    }

    fn mailbox(seq: u64, id: &str, role: skein_core::MailboxRole) -> Event {
        ev(
            seq,
            EventBody::MailboxUpserted {
                mailbox: MailboxInfo {
                    id: id.into(),
                    path: id.into(),
                    role: Some(role),
                    selectable: true,
                    label: false,
                },
            },
        )
    }

    #[test]
    fn only_mail_the_account_sent_makes_an_address_known() {
        use skein_core::MailboxRole;
        let (_d, store) = temp_store();
        let hostile = b"From: Stranger <stranger@evil.example>\r\nTo: box@example.com\r\nCc: exfil@evil.example, Pat <pat@example.com>\r\nSubject: Hi\r\nMessage-ID: <h@evil.example>\r\n\r\nHello\r\n";
        let junk = b"From: Junk <junk@evil.example>\r\nTo: drop@evil.example\r\nSubject: Win\r\nMessage-ID: <j@evil.example>\r\n\r\nWin\r\n";
        let sent = b"From: Box <box@example.com>\r\nTo: Pat <PAT@example.com>\r\nCc: sam@example.org\r\nSubject: Re: Hi\r\nMessage-ID: <s@example.com>\r\n\r\nThanks\r\n";
        apply(
            &store,
            &[
                (&mailbox(1, "INBOX", MailboxRole::Inbox), None),
                (&mailbox(2, "Junk", MailboxRole::Junk), None),
                (&mailbox(3, "Sent", MailboxRole::Sent), None),
                (&added(4, "INBOX", "1", hostile), Some(hostile)),
                (&added(5, "Junk", "2", junk), Some(junk)),
            ],
        );
        for address in [
            "stranger@evil.example",
            "exfil@evil.example",
            "pat@example.com",
            "junk@evil.example",
            "drop@evil.example",
        ] {
            assert!(!store.knows_address("box", address).unwrap(), "{address}");
        }
        apply(&store, &[(&added(6, "Sent", "3", sent), Some(sent))]);
        assert!(store.knows_address("box", "pat@example.com").unwrap());
        assert!(store.knows_address("box", "SAM@example.org").unwrap());
        assert!(!store.knows_address("box", "exfil@evil.example").unwrap());
        assert!(!store.knows_address("box", "example.org").unwrap());
        assert!(!store.knows_address("box", "\"").unwrap());
        assert!(!store.knows_address("other", "pat@example.com").unwrap());
    }

    #[test]
    fn older_databases_are_migrated_in_place_and_newer_ones_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v1.sqlite");
        let plain = fixture("plain.eml");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(V1).unwrap();
            conn.pragma_update(None, "user_version", 1).unwrap();
            conn.execute(
                "INSERT INTO accounts (account, checkpoint, head) VALUES ('box', 7, 7)",
                [],
            )
            .unwrap();
        }
        let s = Store::open(&path).unwrap();
        assert_eq!(s.checkpoint("box").unwrap(), 7);
        let version: i64 = lock(&s.write)
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, MIGRATIONS.len() as i64);
        let a = added(8, "INBOX", "i1", &plain);
        apply(&s, &[(&a, Some(&plain))]);
        assert!(s.collections("box").unwrap().is_empty());
        drop(s);
        assert!(Store::open(&path).is_ok(), "opening again changes nothing");

        let conn = Connection::open(&path).unwrap();
        conn.pragma_update(None, "user_version", 99).unwrap();
        drop(conn);
        assert!(matches!(Store::open(&path), Err(StoreError::TooNew(99))));
    }

    #[test]
    fn invitations_in_mail_are_read_from_the_bytes() {
        let (_d, s) = temp_store();
        let invite = fixture("invite.eml");
        let a = added(1, "INBOX", "i1", &invite);
        apply(&s, &[(&a, Some(&invite))]);
        let m = s
            .message("box", &BlobHash::of(&invite).to_string())
            .unwrap()
            .unwrap();
        let itip = m.itip.unwrap();
        assert_eq!(
            (itip.method.as_str(), itip.uid.as_str()),
            ("REQUEST", "plant-swap@example.com")
        );
        assert_eq!(itip.organizer.as_deref(), Some("pat@example.com"));
    }

    #[test]
    fn messages_live_while_a_membership_refers_to_them() {
        let (_d, s) = temp_store();
        let plain = fixture("plain.eml");
        let id = BlobHash::of(&plain).to_string();
        let a = added(1, "INBOX", "i1", &plain);
        let b = added(2, "Archive", "a1", &plain);
        apply(&s, &[(&a, Some(&plain)), (&b, Some(&plain))]);
        let m = s.message("box", &id).unwrap().unwrap();
        assert_eq!(m.memberships.len(), 2, "one message, two mailboxes");
        assert_eq!(m.envelope.mailboxes, vec!["Archive", "INBOX"]);
        assert_eq!(s.messages("box", None, None, 10).unwrap().len(), 1);

        let r = ev(
            3,
            EventBody::MessageRemoved {
                mailbox: "INBOX".into(),
                item: item("i1"),
            },
        );
        apply(&s, &[(&r, None)]);
        assert_eq!(s.message("box", &id).unwrap().unwrap().memberships.len(), 1);
        assert!(
            s.messages("box", Some("INBOX"), None, 10)
                .unwrap()
                .is_empty()
        );

        let r = ev(
            4,
            EventBody::MessageRemoved {
                mailbox: "Archive".into(),
                item: item("a1"),
            },
        );
        apply(&s, &[(&r, None)]);
        assert!(s.message("box", &id).unwrap().is_none());
        assert!(!s.has_content("box", &BlobHash::of(&plain)).unwrap());
        assert!(s.search("box", "\"tomatoes\"", 10).unwrap().is_empty());
        assert_eq!(s.checkpoint("box").unwrap(), 4);
    }

    #[test]
    fn flags_labels_and_counts() {
        let (_d, s) = temp_store();
        let plain = fixture("plain.eml");
        let multi = fixture("multipart.eml");
        let mbox = ev(
            1,
            EventBody::MailboxUpserted {
                mailbox: MailboxInfo {
                    id: "INBOX".into(),
                    path: "INBOX".into(),
                    role: Some(skein_core::MailboxRole::Inbox),
                    selectable: true,
                    label: false,
                },
            },
        );
        let a = added(2, "INBOX", "i1", &plain);
        let b = added(3, "INBOX", "i2", &multi);
        apply(&s, &[(&mbox, None), (&a, Some(&plain)), (&b, Some(&multi))]);
        let boxes = s.mailboxes("box").unwrap();
        assert_eq!((boxes[0].total, boxes[0].unread), (2, 2));
        assert_eq!(boxes[0].role.as_deref(), Some("inbox"));

        let f = ev(
            4,
            EventBody::FlagsChanged {
                mailbox: "INBOX".into(),
                item: item("i1"),
                flags: Flags::new(["\\Seen", "\\Flagged"]),
            },
        );
        let l = ev(
            5,
            EventBody::LabelsChanged {
                mailbox: "INBOX".into(),
                item: item("i1"),
                labels: vec!["garden".into()],
            },
        );
        apply(&s, &[(&f, None), (&l, None)]);
        let boxes = s.mailboxes("box").unwrap();
        assert_eq!((boxes[0].total, boxes[0].unread), (2, 1));
        let m = s
            .message("box", &BlobHash::of(&plain).to_string())
            .unwrap()
            .unwrap();
        assert!(!m.envelope.unread);
        assert_eq!(m.memberships[0].flags, vec!["\\Flagged", "\\Seen"]);
        assert_eq!(m.memberships[0].labels, Some(vec!["garden".to_owned()]));
    }

    #[test]
    fn resync_drops_the_mailbox_listing_until_it_is_listed_again() {
        let (_d, s) = temp_store();
        let plain = fixture("plain.eml");
        let multi = fixture("multipart.eml");
        let a = added(1, "INBOX", "i1", &plain);
        let b = added(2, "INBOX", "i2", &multi);
        let c = added(3, "Archive", "a1", &multi);
        apply(
            &s,
            &[(&a, Some(&plain)), (&b, Some(&multi)), (&c, Some(&multi))],
        );
        let pim = ev(
            4,
            EventBody::ResyncRequired {
                collection: "INBOX".into(),
                reason: "sync_token".into(),
                domain: Some(Domain::Calendar),
            },
        );
        apply(&s, &[(&pim, None)]);
        assert_eq!(s.messages("box", Some("INBOX"), None, 10).unwrap().len(), 2);
        let r = ev(
            5,
            EventBody::ResyncRequired {
                collection: "INBOX".into(),
                reason: "uidvalidity".into(),
                domain: None,
            },
        );
        let again = added(6, "INBOX", "i9", &plain);
        apply(&s, &[(&r, None), (&again, Some(&plain))]);
        let inbox = s.messages("box", Some("INBOX"), None, 10).unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].id, BlobHash::of(&plain).to_string());
        assert_eq!(
            s.messages("box", Some("Archive"), None, 10).unwrap().len(),
            1
        );
    }

    #[test]
    fn pages_apply_exactly_once_and_refuse_gaps() {
        let (_d, s) = temp_store();
        let plain = fixture("plain.eml");
        let a = added(1, "INBOX", "i1", &plain);
        apply(&s, &[(&a, Some(&plain))]);
        apply(&s, &[(&a, Some(&plain))]);
        assert_eq!(s.checkpoint("box").unwrap(), 1);
        let gap = ev(3, EventBody::FirstSyncCompleted);
        assert!(matches!(
            s.apply_page("box", &[gap]),
            Err(StoreError::Gap {
                checkpoint: 1,
                got: 3
            })
        ));
        let unknown = ev(2, EventBody::Unknown);
        let missing = added(3, "INBOX", "i2", b"never stored");
        assert!(matches!(
            s.apply_page("box", &[unknown.clone(), missing]),
            Err(StoreError::MissingContent)
        ));
        assert_eq!(
            s.checkpoint("box").unwrap(),
            1,
            "a failed page changes nothing"
        );
        let done = ev(3, EventBody::FirstSyncCompleted);
        assert_eq!(s.apply_page("box", &[unknown, done]).unwrap(), 3);
        assert!(s.accounts().unwrap()[0].first_sync_completed);
    }

    #[test]
    fn threads_join_by_references_even_when_the_reply_comes_first() {
        let (_d, s) = temp_store();
        let reply2 = fixture("reply2.eml");
        let parent = fixture("parent.eml");
        let reply = fixture("reply.eml");
        let plain = fixture("plain.eml");
        let a = added(1, "INBOX", "r2", &reply2);
        let b = added(2, "INBOX", "p", &parent);
        let c = added(3, "Sent", "r1", &reply);
        let d = added(4, "INBOX", "x", &plain);
        apply(
            &s,
            &[
                (&a, Some(&reply2)),
                (&b, Some(&parent)),
                (&c, Some(&reply)),
                (&d, Some(&plain)),
            ],
        );
        let threads = s.threads("box", None, None, 10).unwrap();
        assert_eq!(threads.len(), 2);
        let lunch = threads.iter().find(|t| t.count == 3).unwrap();
        let msgs = s.thread("box", lunch.id, 10).unwrap();
        let ids: Vec<_> = msgs
            .iter()
            .map(|m| m.envelope.message_id.clone().unwrap())
            .collect();
        assert_eq!(
            ids,
            vec![
                "reply2@example.com",
                "root@example.com",
                "reply1@example.com"
            ],
            "ordered by sort_date, which is received_at here"
        );
        assert_eq!(lunch.unread, 3);
        assert_eq!(s.threads("box", Some("Sent"), None, 10).unwrap().len(), 1);
    }

    #[test]
    fn a_reply_threads_with_a_sent_copy_whose_message_id_the_service_replaced() {
        let (_d, s) = temp_store();
        let sent = b"From: Ada <ada@example.com>\r\nTo: Bob <bob@example.org>\r\nMessage-ID: <0102-abc-000000@eu-west-1.amazonses.com>\r\nX-Skein-Original-Message-ID: <own-1@example.com>\r\nSubject: Lunch\r\n\r\nNoon?\r\n".to_vec();
        let reply = b"From: Bob <bob@example.org>\r\nTo: Ada <ada@example.com>\r\nMessage-ID: <bob-1@example.org>\r\nIn-Reply-To: <0102-abc-000000@eu-west-1.amazonses.com>\r\nReferences: <0102-abc-000000@eu-west-1.amazonses.com>\r\nSubject: Re: Lunch\r\n\r\nYes\r\n".to_vec();
        let a = added(1, "Sent", "s", &sent);
        let b = added(2, "INBOX", "r", &reply);
        apply(&s, &[(&a, Some(&sent)), (&b, Some(&reply))]);
        let threads = s.threads("box", None, None, 10).unwrap();
        assert_eq!(threads.len(), 1, "the reply did not join the sent copy");
        assert_eq!(threads[0].count, 2);
    }

    #[test]
    fn a_message_linking_two_threads_merges_them() {
        let (_d, s) = temp_store();
        let left = b"Message-ID: <left@example.com>\r\nSubject: one\r\n\r\nx".to_vec();
        let right = b"Message-ID: <right@example.com>\r\nSubject: two\r\n\r\ny".to_vec();
        let both = b"Message-ID: <both@example.com>\r\nReferences: <left@example.com> <right@example.com>\r\nSubject: three\r\n\r\nz".to_vec();
        let a = added(1, "INBOX", "l", &left);
        let b = added(2, "INBOX", "r", &right);
        apply(&s, &[(&a, Some(&left)), (&b, Some(&right))]);
        assert_eq!(s.threads("box", None, None, 10).unwrap().len(), 2);
        let c = added(3, "INBOX", "b", &both);
        apply(&s, &[(&c, Some(&both))]);
        let threads = s.threads("box", None, None, 10).unwrap();
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].count, 3);
    }

    #[test]
    fn replies_without_references_join_by_subject() {
        let (_d, s) = temp_store();
        let first = b"Message-ID: <s1@example.com>\r\nSubject: Plant swap\r\n\r\nx".to_vec();
        let reply =
            b"Message-ID: <s2@example.com>\r\nSubject: RE: [garden] Plant swap\r\n\r\ny".to_vec();
        let same = b"Message-ID: <s3@example.com>\r\nSubject: Plant swap\r\n\r\nz".to_vec();
        let a = added(1, "INBOX", "1", &first);
        let b = added(2, "INBOX", "2", &reply);
        let c = added(3, "INBOX", "3", &same);
        apply(
            &s,
            &[(&a, Some(&first)), (&b, Some(&reply)), (&c, Some(&same))],
        );
        let threads = s.threads("box", None, None, 10).unwrap();
        let counts: Vec<u64> = threads.iter().map(|t| t.count).collect();
        assert_eq!(counts.iter().sum::<u64>(), 3);
        assert!(counts.contains(&2), "the prefixed reply joined: {counts:?}");
        assert_eq!(
            threads.len(),
            2,
            "same subject without a prefix stays apart"
        );
    }

    #[test]
    fn search_covers_subject_people_and_body_and_never_fails_on_input() {
        let (_d, s) = temp_store();
        let plain = fixture("plain.eml");
        let enc = fixture("encoded.eml");
        let a = added(1, "INBOX", "1", &plain);
        let b = added(2, "INBOX", "2", &enc);
        apply(&s, &[(&a, Some(&plain)), (&b, Some(&enc))]);
        let q = |text: &str| {
            let fts = crate::search::fts_query(text).unwrap();
            s.search("box", &fts, 10).unwrap()
        };
        assert_eq!(q("zucchini").len(), 1);
        assert_eq!(q("garden report").len(), 1);
        assert_eq!(q("sam@example.org").len(), 1);
        assert_eq!(q("Jurgen").len(), 1, "diacritics folded");
        assert_eq!(q("koln").len(), 1);
        assert_eq!(q("rhei*").len(), 1);
        assert_eq!(q("tomatoes rhein").len(), 0);
        for hostile in ["\"", "a OR", "NEAR(", "x:y", "*", "-a", "^b", "AND AND"] {
            if let Some(fts) = crate::search::fts_query(hostile) {
                assert!(s.search("box", &fts, 10).is_ok(), "{hostile}");
            }
        }
        assert!(matches!(
            s.search("box", "\"unterminated", 10),
            Err(StoreError::BadQuery)
        ));
    }

    #[test]
    fn cursor_paging_walks_every_message_once() {
        let (_d, s) = temp_store();
        let mut events = Vec::new();
        let mut bodies = Vec::new();
        for n in 0..7u64 {
            bodies.push(
                format!("Message-ID: <m{n}@example.com>\r\nSubject: n{n}\r\n\r\nbody").into_bytes(),
            );
        }
        for (n, body) in bodies.iter().enumerate() {
            events.push(added(n as u64 + 1, "INBOX", &format!("i{n}"), body));
        }
        let pairs: Vec<(&Event, Option<&[u8]>)> = events
            .iter()
            .zip(&bodies)
            .map(|(e, b)| (e, Some(b.as_slice())))
            .collect();
        apply(&s, &pairs);
        let mut seen = Vec::new();
        let mut before = None;
        loop {
            let page = s.messages("box", Some("INBOX"), before.clone(), 3).unwrap();
            if page.is_empty() {
                break;
            }
            let last = page.last().unwrap();
            before = Some((last.sort_date, last.id.clone()));
            seen.extend(page.into_iter().map(|e| e.subject.unwrap()));
        }
        assert_eq!(seen, vec!["n6", "n5", "n4", "n3", "n2", "n1", "n0"]);
    }

    #[test]
    fn rebuild_replaces_state_with_the_snapshot() {
        let (_d, s) = temp_store();
        let plain = fixture("plain.eml");
        let multi = fixture("multipart.eml");
        let a = added(1, "INBOX", "i1", &plain);
        apply(&s, &[(&a, Some(&plain))]);
        store_content(&s, &multi);
        let mut snap = Snapshot::empty(AccountId::new("box").unwrap());
        snap.seq = Seq(40);
        snap.mailboxes.insert(
            "Archive".into(),
            MailboxState {
                info: MailboxInfo {
                    id: "Archive".into(),
                    path: "Archive".into(),
                    role: None,
                    selectable: true,
                    label: false,
                },
                items: [(
                    "a1".to_owned(),
                    ItemState {
                        item: item("a1"),
                        blob: BlobHash::of(&multi),
                        size: multi.len() as u64,
                        flags: Flags::new(["\\Seen"]),
                        labels: None,
                        received_at: None,
                    },
                )]
                .into(),
            },
        );
        s.rebuild("box", &snap).unwrap();
        assert_eq!(s.checkpoint("box").unwrap(), 40);
        let all = s.messages("box", None, None, 10).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].mailboxes, vec!["Archive"]);
        assert!(!s.has_content("box", &BlobHash::of(&plain)).unwrap());
        let boxes = s.mailboxes("box").unwrap();
        assert_eq!(boxes.len(), 1);
    }
}
