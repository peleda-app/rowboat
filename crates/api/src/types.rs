use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::ids::{
    AccountId, CommandId, DraftId, EmailAddress, MailboxId, MessageId, Tag, ThreadId,
};

pub use rowboat_discover::{Endpoint, Security};

/// Most rows a list or search returns through the API.
pub const MAX_PAGE: u32 = 200;
/// Most targets of one mutating call.
pub const MAX_TARGETS: usize = 1_000;
/// Most recipients of one draft (To, Cc and Bcc together).
pub const MAX_RECIPIENTS: usize = 500;
/// Most attachments of one draft.
pub const MAX_ATTACHMENTS: usize = 100;
/// Most bytes of all attachments of one draft.
pub const MAX_ATTACHMENT_BYTES: usize = 25 * 1024 * 1024;
/// Most bytes of a draft's text.
pub const MAX_TEXT_BYTES: usize = 1024 * 1024;
/// Most characters of a subject.
pub const MAX_SUBJECT_CHARS: usize = 998;
/// Most characters of a display name or attachment name.
pub const MAX_NAME_CHARS: usize = 200;
/// Most local drafts of the node.
pub const MAX_DRAFTS: usize = 200;
/// Most address suggestions.
pub const MAX_SUGGESTIONS: u32 = 20;
/// Most characters of a search text or an address prefix.
pub const MAX_QUERY_CHARS: usize = 256;
/// Most mailboxes an account may skip.
pub const MAX_SKIPPED: usize = 256;

/// What the node is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeInfo {
    /// The node id (Baton identity).
    pub node_id: String,
    /// The group id, which is also Skein's tenant.
    pub group_id: String,
    /// The profile the node runs (`desktop`, `test`).
    pub profile: String,
    /// The node build's version.
    pub version: String,
    /// Bytes under the objects directory, when known.
    pub objects_bytes: Option<u64>,
    /// Bytes of the mail database files, when known.
    pub database_bytes: Option<u64>,
}

/// How to reach a new account. Holds no secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountSetup {
    /// The address mail is sent from.
    pub address: EmailAddress,
    /// The name shown with it: one line, at most [`MAX_NAME_CHARS`] characters.
    pub display_name: Option<String>,
    /// The user name for both servers: one line, 1 to 320 bytes.
    pub username: String,
    /// The IMAP server.
    pub imap: Endpoint,
    /// The SMTP submission server.
    pub smtp: Endpoint,
}

/// Changes to an account; `None` fields stay as they are.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountPatch {
    /// A new display name; `Some(None)` removes it.
    #[serde(default)]
    pub display_name: Option<Option<String>>,
    /// Pause or resume syncing.
    #[serde(default)]
    pub paused: Option<bool>,
    /// Mailboxes never synced, at most [`MAX_SKIPPED`].
    #[serde(default)]
    pub skip_mailboxes: Option<Vec<MailboxId>>,
    /// The mailbox `archive` moves to when the provider names none; `Some(None)` clears it.
    #[serde(default)]
    pub archive_mailbox: Option<Option<MailboxId>>,
    /// Turn new-mail notifications for the account on or off.
    #[serde(default)]
    pub notify: Option<bool>,
}

/// Which provider an account uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    /// IMAP for reading, SMTP for sending.
    Imap,
}

/// How an account is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Health {
    /// Nothing tried yet.
    Unknown,
    /// Syncing normally.
    Healthy,
    /// The provider refused the credentials; the person must enter a new password.
    ReauthRequired,
    /// The provider is limiting requests.
    Throttled,
    /// Repeated errors.
    Degraded,
}

/// The latest outcome in one domain (mail sync or sending): `ok` or the kind of failure
/// (`auth_failed`, `config`, `throttled`, `network`, `protocol`, `storage`, `other`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainState {
    /// The outcome kind.
    pub outcome: String,
    /// When an attempt last finished, milliseconds since the epoch.
    pub last_ok_at: Option<i64>,
    /// When an attempt last failed.
    pub last_error_at: Option<i64>,
}

/// An account as lists show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountInfo {
    /// The account.
    pub id: AccountId,
    /// Its address.
    pub address: EmailAddress,
    /// Its display name.
    pub display_name: Option<String>,
    /// Its provider.
    pub provider: ProviderKind,
    /// Whether syncing is paused.
    pub paused: bool,
    /// The worst health over its domains.
    pub health: Health,
    /// Mail sync.
    pub mail: Option<DomainState>,
    /// Sending.
    pub send: Option<DomainState>,
    /// Whether the first full listing finished.
    pub first_sync_completed: bool,
    /// Messages over every mailbox.
    pub messages: u64,
    /// Unread messages in the inbox.
    pub unread: u64,
    /// Mailboxes never synced, as set by [`AccountPatch::skip_mailboxes`].
    pub skipped_mailboxes: Vec<MailboxId>,
    /// The mailbox `archive` moves to when the provider names none.
    pub archive_mailbox: Option<MailboxId>,
    /// Whether new mail of the account may notify ([`crate::NodeEvent::NewMail`]).
    pub notify: bool,
}

/// What a mailbox is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailboxRole {
    /// Incoming mail.
    Inbox,
    /// Sent mail.
    Sent,
    /// Drafts.
    Drafts,
    /// Archived mail.
    Archive,
    /// Spam.
    Junk,
    /// Deleted mail.
    Trash,
    /// Every message (Gmail's All Mail).
    All,
    /// Flagged messages.
    Flagged,
}

impl MailboxRole {
    /// The role's name as the mail database stores it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inbox => "inbox",
            Self::Sent => "sent",
            Self::Drafts => "drafts",
            Self::Archive => "archive",
            Self::Junk => "junk",
            Self::Trash => "trash",
            Self::All => "all",
            Self::Flagged => "flagged",
        }
    }

    /// The role stored as `name`.
    pub fn from_name(name: &str) -> Option<Self> {
        [
            Self::Inbox,
            Self::Sent,
            Self::Drafts,
            Self::Archive,
            Self::Junk,
            Self::Trash,
            Self::All,
            Self::Flagged,
        ]
        .into_iter()
        .find(|r| r.as_str() == name)
    }
}

/// A mailbox with its counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxInfo {
    /// The mailbox.
    pub id: MailboxId,
    /// Its path, levels separated by `/`.
    pub path: String,
    /// Its role.
    pub role: Option<MailboxRole>,
    /// Whether it can hold messages.
    pub selectable: bool,
    /// Messages in it.
    pub total: u64,
    /// Unread messages in it.
    pub unread: u64,
}

/// Which messages a list covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum Scope {
    /// One mailbox of one account.
    Mailbox {
        /// The account.
        account: AccountId,
        /// The mailbox.
        mailbox: MailboxId,
    },
    /// The mailboxes with a role, of one account or of every account.
    Role {
        /// The account, or every account.
        account: Option<AccountId>,
        /// The role.
        role: MailboxRole,
    },
    /// Flagged messages, of one account or of every account.
    Flagged {
        /// The account, or every account.
        account: Option<AccountId>,
    },
    /// Messages carrying a tag, of one account or of every account.
    Tagged {
        /// The account, or every account.
        account: Option<AccountId>,
        /// The tag.
        tag: Tag,
    },
    /// Every message, of one account or of every account.
    All {
        /// The account, or every account.
        account: Option<AccountId>,
    },
}

impl Scope {
    /// The one account the scope names, `None` for every account.
    pub fn account(&self) -> Option<&AccountId> {
        match self {
            Self::Mailbox { account, .. } => Some(account),
            Self::Role { account, .. }
            | Self::Flagged { account }
            | Self::Tagged { account, .. }
            | Self::All { account } => account.as_ref(),
        }
    }
}

/// An opaque position in a list, as the node returned it: at most 512 printable ASCII
/// characters. Only the node that made it can read it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Cursor(String);

impl Cursor {
    /// Checks and wraps `text`.
    pub fn new(text: impl Into<String>) -> Result<Self, crate::NodeError> {
        let text = text.into();
        if !text.is_empty() && text.len() <= 512 && text.bytes().all(|b| b.is_ascii_graphic()) {
            Ok(Self(text))
        } else {
            Err(crate::NodeError::InvalidInput)
        }
    }

    /// The cursor as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Cursor {
    type Error = crate::NodeError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Cursor> for String {
    fn from(value: Cursor) -> String {
        value.0
    }
}

/// A list request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListQuery {
    /// Which messages.
    pub scope: Scope,
    /// Only unread messages.
    #[serde(default)]
    pub unread_only: bool,
    /// Continue after this position.
    #[serde(default)]
    pub cursor: Option<Cursor>,
    /// Rows per page, 1 to [`MAX_PAGE`].
    pub limit: u32,
}

/// One page of a list, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page<T> {
    /// The rows.
    pub items: Vec<T>,
    /// Where the next page starts; `None` on the last page.
    pub next: Option<Cursor>,
}

/// A mailbox in an address header, as the content pipeline normalized it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Address {
    /// The display name.
    pub name: Option<String>,
    /// `local@domain`, when the header had one.
    pub address: Option<String>,
}

/// What a message list shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// The account.
    pub account: AccountId,
    /// The message.
    pub id: MessageId,
    /// Its thread.
    pub thread: ThreadId,
    /// The subject.
    pub subject: Option<String>,
    /// `From`.
    pub from: Vec<Address>,
    /// `To`.
    pub to: Vec<Address>,
    /// `Cc`.
    pub cc: Vec<Address>,
    /// The `Date` header, milliseconds since the epoch.
    pub date: Option<i64>,
    /// When the server received it.
    pub received_at: Option<i64>,
    /// The time lists sort by.
    pub sort_date: i64,
    /// Size of the original in bytes.
    pub size: u64,
    /// Whether it has attachments.
    pub has_attachments: bool,
    /// The start of the text.
    pub snippet: Option<String>,
    /// Unread, with the node's pending changes applied.
    pub unread: bool,
    /// Flagged, with the node's pending changes applied.
    pub flagged: bool,
    /// Mailboxes holding it, with pending moves applied.
    pub mailboxes: Vec<MailboxId>,
    /// Tags the node attached.
    pub tags: Vec<Tag>,
    /// False when the original could not be read or the content pipeline refused it.
    pub available: bool,
}

/// A thread in a list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadSummary {
    /// The account.
    pub account: AccountId,
    /// The thread.
    pub id: ThreadId,
    /// Messages in it.
    pub count: u64,
    /// Unread messages in it.
    pub unread: u64,
    /// The newest message.
    pub latest: Envelope,
}

/// A node of a thread's reply tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeNode {
    /// The message, `None` for a placeholder of a referenced message that is not here.
    pub message: Option<MessageId>,
    /// Replies, oldest first.
    pub children: Vec<TreeNode>,
}

/// A thread with its messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadDetail {
    /// The account.
    pub account: AccountId,
    /// The thread.
    pub id: ThreadId,
    /// Its messages, oldest first, at most 1,000.
    pub messages: Vec<Envelope>,
    /// The reply tree.
    pub tree: Vec<TreeNode>,
}

/// A message in one mailbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Membership {
    /// The mailbox.
    pub mailbox: MailboxId,
    /// Its flags there.
    pub flags: Vec<String>,
}

/// An attachment of a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentInfo {
    /// The part id to decode through the content pipeline.
    pub part: u32,
    /// The file name.
    pub name: Option<String>,
    /// The declared type.
    pub content_type: String,
    /// Decoded size in bytes.
    pub size: u64,
}

/// Everything the node keeps of a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageDetail {
    /// What lists show.
    pub envelope: Envelope,
    /// The `Message-ID` header without angle brackets.
    pub message_id: Option<String>,
    /// `In-Reply-To` ids.
    pub in_reply_to: Vec<String>,
    /// `References` ids.
    pub references: Vec<String>,
    /// Where it is.
    pub memberships: Vec<Membership>,
    /// Its attachments.
    pub attachments: Vec<AttachmentInfo>,
}

/// One message of one account.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageRef {
    /// The account.
    pub account: AccountId,
    /// The message.
    pub message: MessageId,
}

/// The messages a mutating call acts on: 1 to [`MAX_TARGETS`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Targets(pub Vec<MessageRef>);

/// What a mutating call queued.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Queued {
    /// One command per account and mailbox, to match `CommandSettled` events.
    pub commands: Vec<CommandId>,
    /// Targets the node does not know; nothing was queued for them.
    pub skipped: Vec<MessageRef>,
}

/// A recipient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recipient {
    /// The display name: one line, at most [`MAX_NAME_CHARS`].
    pub name: Option<String>,
    /// The address.
    pub address: EmailAddress,
}

/// What a reply answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyTo {
    /// The answered message's `Message-ID`, without angle brackets.
    pub message_id: String,
    /// Its `References` followed by nothing else, at most 32 ids.
    pub references: Vec<String>,
}

/// An attachment of a draft.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DraftAttachment {
    /// The file name: 1 to [`MAX_NAME_CHARS`] characters, no control characters, `/` or `\`.
    pub name: String,
    /// The bytes; base64 in serialized form.
    #[serde(with = "b64")]
    pub bytes: Bytes,
}

mod b64 {
    use bytes::Bytes;
    use data_encoding::BASE64;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Bytes, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Bytes, D::Error> {
        let text = <std::borrow::Cow<'de, str>>::deserialize(d)?;
        BASE64
            .decode(text.as_bytes())
            .map(Bytes::from)
            .map_err(|_| serde::de::Error::custom("bad base64"))
    }
}

/// A message being written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Draft {
    /// The draft, `None` for a new one.
    #[serde(default)]
    pub id: Option<DraftId>,
    /// The account it is sent from.
    pub account: AccountId,
    /// Recipients.
    #[serde(default)]
    pub to: Vec<Recipient>,
    /// Copy recipients.
    #[serde(default)]
    pub cc: Vec<Recipient>,
    /// Blind copy recipients: only in the envelope, never in the message.
    #[serde(default)]
    pub bcc: Vec<Recipient>,
    /// The subject: one line, at most [`MAX_SUBJECT_CHARS`].
    #[serde(default)]
    pub subject: String,
    /// The plain text body, at most [`MAX_TEXT_BYTES`].
    #[serde(default)]
    pub text: String,
    /// What it answers.
    #[serde(default)]
    pub reply: Option<ReplyTo>,
    /// Attachments.
    #[serde(default)]
    pub attachments: Vec<DraftAttachment>,
}

/// A draft in a list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DraftSummary {
    /// The draft.
    pub id: DraftId,
    /// Its account.
    pub account: AccountId,
    /// Its subject.
    pub subject: String,
    /// How many recipients.
    pub recipients: u32,
    /// How many attachments.
    pub attachments: u32,
    /// When it was last saved, milliseconds since the epoch.
    pub updated_at: i64,
}

/// A queued send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendQueued {
    /// The account.
    pub account: AccountId,
    /// The command, for `cancel_send` and `SendSettled`.
    pub command: CommandId,
    /// The draft the send keeps: `cancel_send` brings it back under this id, for `get_draft`.
    pub draft: DraftId,
    /// When the undo window ends and the message may leave, milliseconds since the epoch.
    pub due_at: i64,
}

/// A send waiting in the queue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxItem {
    /// The account.
    pub account: AccountId,
    /// The command.
    pub command: CommandId,
    /// When it may leave.
    pub due_at: Option<i64>,
    /// When it was queued.
    pub created_at: i64,
}

/// Narrows a search.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchFilter {
    /// One mailbox (needs an account).
    #[serde(default)]
    pub mailbox: Option<MailboxId>,
    /// The mailboxes with this role.
    #[serde(default)]
    pub role: Option<MailboxRole>,
    /// Only unread.
    #[serde(default)]
    pub unread: Option<bool>,
    /// Only flagged.
    #[serde(default)]
    pub flagged: Option<bool>,
    /// Only with attachments.
    #[serde(default)]
    pub has_attachments: Option<bool>,
    /// Only with this tag.
    #[serde(default)]
    pub tag: Option<Tag>,
}

/// A search request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchQuery {
    /// The account, or every account.
    #[serde(default)]
    pub account: Option<AccountId>,
    /// The words: 1 to [`MAX_QUERY_CHARS`] characters, one line.
    pub text: String,
    /// Narrowing.
    #[serde(default)]
    pub filter: SearchFilter,
    /// Results, 1 to [`MAX_PAGE`].
    pub limit: u32,
}

/// A known correspondent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressSuggestion {
    /// The account that knows it.
    pub account: AccountId,
    /// The address.
    pub address: String,
    /// The latest display name.
    pub name: Option<String>,
}
