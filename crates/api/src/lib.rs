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
pub mod group;
mod ids;
pub mod request;
#[cfg(feature = "testing")]
pub mod testing;
mod types;

use async_trait::async_trait;
use bytes::Bytes;

pub use error::NodeError;
pub use events::{
    Attention, CommandOutcome, EVENT_BUFFER, EventStream, GroupEvent, GroupEventStream,
    MAX_NEW_MAIL, NewMail, NodeEvent, SendOutcome,
};
pub use group::{
    AccountLeader, GroupStatus, InviteInfo, InviteKind, NodeSummary, PairingInvite, PairingResult,
    Revoked, ServerState,
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

    /// Makes a device invite: a QR code a new desktop or phone scans to join this node's group,
    /// valid 10 minutes, usable once. When a device answers it, [`GroupEvent::PairingCheck`] asks
    /// the person to compare fingerprints and [`NodeApi::confirm_pairing`] answers. Needs a node
    /// that holds the member key ([`NodeError::Forbidden`] otherwise) and the network
    /// ([`NodeError::PeerUnreachable`] without one).
    async fn create_invite(&self) -> Result<PairingInvite, NodeError>;

    /// Withdraws an invite this node made; [`NodeError::NotFound`] when it is not pending.
    async fn cancel_invite(&self, invite: &str) -> Result<(), NodeError>;

    /// What `code` (with `address` for a typed short code) is, without dialing anything:
    /// [`NodeError::InvalidInput`] when it does not decode, [`NodeError::PairingExpired`] for a
    /// QR invite whose expiry passed by this node's clock.
    async fn inspect_invite(
        &self,
        code: &str,
        address: Option<&str>,
    ) -> Result<InviteInfo, NodeError>;

    /// Pairs with a scanned QR payload, or with a typed short code and the pairing address shown
    /// next to it. A device invite makes this node join the inviter's group (only a node with no
    /// accounts and no other nodes may: [`NodeError::Busy`] otherwise), after which
    /// [`PairingResult::restart_required`] is set and the data this node kept for its old group
    /// is deleted. A server invite makes this node adopt the server into its group, granting it
    /// every account this node's member created, after the person confirms the fingerprint.
    ///
    /// Failures: [`NodeError::PairingExpired`] (a QR invite past its expiry, nothing dialed),
    /// [`NodeError::PairingCodeRejected`] (a wrong, used, withdrawn or expired code),
    /// [`NodeError::PairingRefused`] (the other side said no), [`NodeError::PeerUnreachable`],
    /// [`NodeError::Forbidden`] (adopting a server needs the member key).
    async fn accept_invite(
        &self,
        code: &str,
        address: Option<&str>,
    ) -> Result<PairingResult, NodeError>;

    /// Adopts a server like [`NodeApi::accept_invite`], granting it `read` and `lead` on exactly
    /// `accounts` (at most [`group::MAX_GRANTS`], each created by this node's member, else
    /// [`NodeError::NotFound`]) and on the group's storage. A device invite is
    /// [`NodeError::InvalidInput`] and dials nothing.
    async fn adopt_server(
        &self,
        code: &str,
        address: Option<&str>,
        accounts: &[AccountId],
    ) -> Result<PairingResult, NodeError>;

    /// Lets the server `server` lead `accounts` too (question 65): grants `read` and `lead` and
    /// shares their keys. Accounts it already may lead are skipped. [`NodeError::NotFound`] for a
    /// node that is not a counting server of this member or an account this member did not
    /// create; [`NodeError::Forbidden`] without the member key.
    async fn grant_to_server(&self, server: &str, accounts: &[AccountId]) -> Result<(), NodeError>;

    /// The person's answer to a [`GroupEvent::PairingCheck`] that asked for confirmation:
    /// whether both screens show the same fingerprint. [`NodeError::NotFound`] when nothing
    /// waits for that answer.
    async fn confirm_pairing(&self, pairing: &str, matches: bool) -> Result<(), NodeError>;

    /// Every node the group ever certified, this one included, sorted by node id.
    async fn list_nodes(&self) -> Result<Vec<NodeSummary>, NodeError>;

    /// Names a node on this node only (display, never trusted; [`group::node_label`]); `None`
    /// goes back to the label it gave when it paired. Naming this node also changes the label it
    /// gives in later pairings. [`NodeError::NotFound`] for a node the group never certified.
    async fn rename_node(&self, node_id: &str, label: Option<&str>) -> Result<(), NodeError>;

    /// Revokes a node for good and rotates the keys of everything it could read. Refuses this
    /// node itself ([`NodeError::InvalidInput`]); [`NodeError::NotFound`] for a node the group
    /// never certified, [`NodeError::Forbidden`] when this node may not revoke it.
    async fn revoke_node(&self, node_id: &str) -> Result<Revoked, NodeError>;

    /// Whether the group's server answers and which node leads each account this node reads.
    /// Asks the arbiter for each account, so it may take up to its timeout when the arbiter is
    /// silent.
    async fn group_status(&self) -> Result<GroupStatus, NodeError>;

    /// A new subscription to the node's events, buffering at most [`EVENT_BUFFER`].
    fn events(&self) -> EventStream;

    /// A new subscription to the group's events (pairing checks, nodes changed, this node
    /// revoked), buffering at most [`EVENT_BUFFER`].
    fn group_events(&self) -> GroupEventStream;
}

#[cfg(test)]
mod tests;
