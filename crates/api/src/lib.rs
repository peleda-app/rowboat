//! The node's whole surface for an app: every request, response and event, the errors, and the
//! checks every caller and the node run.
//!
//! The app holds only `Arc<dyn NodeApi>`, never the node itself, so a node on another device can
//! answer behind the same contract later. Every mutating call has a reserved Baton command class
//! ([`CommandClass`]); in phase 1 every call is in process. Implementations run
//! [`testing::validation`] and [`testing::seeded`].

pub mod check;
pub mod cursor;
mod error;
mod events;
mod ids;
pub mod request;
#[cfg(feature = "testing")]
pub mod testing;
mod types;

use async_trait::async_trait;
use bytes::Bytes;

pub use error::NodeError;
pub use events::{
    Attention, CommandOutcome, EVENT_BUFFER, EventStream, MAX_NEW_MAIL, NewMail, NodeEvent,
    SendOutcome,
};
pub use ids::{
    AccountId, CommandId, DraftId, EmailAddress, MAX_ADDRESS, MailboxId, MessageId, Tag, ThreadId,
    is_ulid, plausible_address,
};
pub use request::{CommandClass, Request, decode_request, encode_request};
pub use rowboat_discover::{AuthHint, Candidate, Source, UsernameForm};
pub use rowboat_keystore::Secret;
pub use types::*;

/// The node, as an app sees it.
///
/// Guarantees of every implementation (checked by the suites in [`testing`]):
///
/// - Every request is checked with [`check`] first; a broken rule is
///   [`NodeError::InvalidInput`] and changes nothing. Unknown accounts, threads, messages, drafts
///   and commands are [`NodeError::NotFound`].
/// - Errors and events carry kinds, ids and counts only; secrets are never returned, logged or
///   put into an event or error.
/// - Lists are newest first with stable paging: following `next` gives every row once while
///   nothing changes. At most [`MAX_PAGE`] rows per page.
/// - Mutating calls queue commands for the provider and return at once; their effect shows in
///   reads immediately (pending changes) and settles with [`NodeEvent::CommandSettled`]. A target
///   the node does not know is reported in [`Queued::skipped`], never an error for the call.
/// - Calls may run concurrently from several tasks.
#[async_trait]
pub trait NodeApi: Send + Sync {
    /// The node's identity, profile and data sizes.
    async fn node_info(&self) -> Result<NodeInfo, NodeError>;

    /// Candidate servers for `address`. No credential is used and nothing is stored.
    async fn discover(&self, address: &EmailAddress) -> Result<Vec<Candidate>, NodeError>;

    /// Signs in to IMAP and SMTP with `secret`, then stores the account and its sealed password
    /// and starts syncing. Nothing is stored when either sign-in fails.
    async fn add_account(
        &self,
        setup: AccountSetup,
        secret: Secret,
    ) -> Result<AccountId, NodeError>;

    /// Signs in with `secret` first, then replaces the stored password.
    async fn update_password(&self, account: &AccountId, secret: Secret) -> Result<(), NodeError>;

    /// Changes the display name, pausing, skipped mailboxes or the archive mailbox.
    async fn update_account(
        &self,
        account: &AccountId,
        patch: AccountPatch,
    ) -> Result<(), NodeError>;

    /// Removes the account, its password, its journal and its mail; finishes after a crash on
    /// the next start.
    async fn remove_account(&self, account: &AccountId) -> Result<(), NodeError>;

    /// Every account, by address.
    async fn list_accounts(&self) -> Result<Vec<AccountInfo>, NodeError>;

    /// Asks one account's worker, or every worker, to run now. Calls are coalesced.
    async fn sync_now(&self, account: Option<&AccountId>) -> Result<(), NodeError>;

    /// The account's mailboxes by path.
    async fn list_mailboxes(&self, account: &AccountId) -> Result<Vec<MailboxInfo>, NodeError>;

    /// Threads of a scope, newest first.
    async fn list_threads(&self, query: ListQuery) -> Result<Page<ThreadSummary>, NodeError>;

    /// One thread with its messages and reply tree.
    async fn get_thread(
        &self,
        account: &AccountId,
        thread: ThreadId,
    ) -> Result<ThreadDetail, NodeError>;

    /// Messages of a scope, newest first.
    async fn list_messages(&self, query: ListQuery) -> Result<Page<Envelope>, NodeError>;

    /// One message.
    async fn get_message(
        &self,
        account: &AccountId,
        message: &MessageId,
    ) -> Result<MessageDetail, NodeError>;

    /// The original bytes, checked against the message id, for the app to render through its
    /// content pipeline; [`NodeError::Unavailable`] when they are gone.
    async fn message_raw(
        &self,
        account: &AccountId,
        message: &MessageId,
    ) -> Result<Bytes, NodeError>;

    /// Marks read or unread.
    async fn set_read(&self, targets: Targets, read: bool) -> Result<Queued, NodeError>;

    /// Flags or unflags.
    async fn set_flagged(&self, targets: Targets, flagged: bool) -> Result<Queued, NodeError>;

    /// Moves to a mailbox of the same account.
    async fn move_to(&self, targets: Targets, mailbox: &MailboxId) -> Result<Queued, NodeError>;

    /// Moves to each account's archive mailbox; [`NodeError::NoArchive`] when an account has
    /// none.
    async fn archive(&self, targets: Targets) -> Result<Queued, NodeError>;

    /// Moves to the trash, or deletes for good with `permanent`.
    async fn delete(&self, targets: Targets, permanent: bool) -> Result<Queued, NodeError>;

    /// Saves a local draft (new when `id` is `None`); at most [`MAX_DRAFTS`].
    async fn save_draft(&self, draft: Draft) -> Result<DraftId, NodeError>;

    /// Every local draft, newest first.
    async fn list_drafts(&self) -> Result<Vec<DraftSummary>, NodeError>;

    /// One local draft.
    async fn get_draft(&self, id: &DraftId) -> Result<Draft, NodeError>;

    /// Deletes a local draft; `true` when one was there.
    async fn delete_draft(&self, id: &DraftId) -> Result<bool, NodeError>;

    /// Queues the draft for sending after the undo window and deletes it as a draft.
    async fn send(&self, draft: Draft) -> Result<SendQueued, NodeError>;

    /// Cancels a send inside its undo window and brings it back as a draft;
    /// [`NodeError::AlreadyStarted`] once it may have left.
    async fn cancel_send(&self, account: &AccountId, command: &CommandId) -> Result<(), NodeError>;

    /// Sends waiting in the queue.
    async fn outbox(&self) -> Result<Vec<OutboxItem>, NodeError>;

    /// Full-text search over one or every account, best first within an account and newest
    /// first across accounts.
    async fn search(&self, query: SearchQuery) -> Result<Vec<Envelope>, NodeError>;

    /// Known correspondents starting with `prefix`, at most `limit` (1 to [`MAX_SUGGESTIONS`]).
    async fn suggest_addresses(
        &self,
        prefix: &str,
        limit: u32,
    ) -> Result<Vec<AddressSuggestion>, NodeError>;

    /// Whether the account has mailed `address`: a `To` or `Cc` of a message in its Sent
    /// mailbox. Mail it only received never counts.
    async fn knows_address(
        &self,
        account: &AccountId,
        address: &EmailAddress,
    ) -> Result<bool, NodeError>;

    /// A new subscription to the node's events, buffering at most [`EVENT_BUFFER`].
    fn events(&self) -> EventStream;
}

#[cfg(test)]
mod tests;
