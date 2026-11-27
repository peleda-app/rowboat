use std::pin::Pin;

use futures::Stream;
use serde::{Deserialize, Serialize};

use crate::ids::{AccountId, CommandId, MailboxId, MessageId, ThreadId};
use crate::types::{DomainState, Health};

/// Most events buffered per subscriber before it gets [`NodeEvent::Lagged`].
pub const EVENT_BUFFER: usize = 256;
/// Most arrivals one [`NodeEvent::NewMail`] names; more in one batch are dropped from it.
pub const MAX_NEW_MAIL: usize = 64;

/// How much attention an arrival deserves, from the node's notification policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Attention {
    /// Badge and notification list, no banner or sound.
    Silent,
    /// A banner with sound.
    Alert,
}

/// One arrival the node decided to notify about. Ids and the policy's answer only; the app reads
/// the sender and subject itself and shows them only as `show_*` allow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewMail {
    /// The message.
    pub message: MessageId,
    /// Its thread.
    pub thread: ThreadId,
    /// The mailbox it arrived in.
    pub mailbox: MailboxId,
    /// How strongly to notify.
    pub attention: Attention,
    /// The sender's display name may be shown.
    pub show_sender: bool,
    /// The subject may be shown on an unlocked device.
    pub show_subject: bool,
}

/// What became of a command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CommandOutcome {
    /// The provider applied it.
    Applied,
    /// It failed for good; `reason` is one word of `[a-z0-9_]`.
    Failed {
        /// Why.
        reason: String,
    },
    /// The provider's version changed meanwhile.
    Conflict,
    /// No answer came back; it may or may not have been applied.
    Uncertain,
    /// It was cancelled before it started.
    Cancelled,
}

/// What became of a send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SendOutcome {
    /// The message left; `refused` recipients did not get it.
    Sent {
        /// How many recipients were refused.
        refused: u32,
    },
    /// It failed for good.
    Failed {
        /// Why, one word.
        reason: String,
    },
    /// No answer came back; it is never sent again.
    Uncertain,
    /// It waits for the undo window or a retry.
    Waiting {
        /// When it may leave, milliseconds since the epoch.
        due_at: i64,
    },
}

/// Something changed. Events carry ids, counts and kinds only; the app treats them as hints and
/// reads what it shows again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NodeEvent {
    /// An account was added, removed or changed.
    AccountsChanged,
    /// An account's status changed.
    AccountStatus {
        /// The account.
        account: AccountId,
        /// Its worst health.
        health: Health,
        /// Mail sync.
        mail: Option<DomainState>,
        /// Sending.
        send: Option<DomainState>,
    },
    /// The mail database moved forward while behind the journal or during the first sync.
    SyncProgress {
        /// The account.
        account: AccountId,
        /// Whether the first full listing finished.
        first_sync_completed: bool,
        /// Messages added by this step.
        messages: u64,
        /// Journal events not yet in the database.
        behind: u64,
    },
    /// Mailboxes were added, removed or renamed.
    MailboxesChanged {
        /// The account.
        account: AccountId,
    },
    /// Memberships, flags or messages changed in these mailboxes; empty means many.
    MessagesChanged {
        /// The account.
        account: AccountId,
        /// The mailboxes, at most 64.
        mailboxes: Vec<MailboxId>,
    },
    /// A command settled.
    CommandSettled {
        /// The account.
        account: AccountId,
        /// The command.
        command: CommandId,
        /// What happened.
        outcome: CommandOutcome,
    },
    /// A send settled or is waiting.
    SendSettled {
        /// The account.
        account: AccountId,
        /// The command.
        command: CommandId,
        /// What happened.
        outcome: SendOutcome,
    },
    /// New mail the node's notification policy wants shown: fresh arrivals in an inbox after
    /// the account's first sync, never spam, never for an account with notifications off.
    NewMail {
        /// The account.
        account: AccountId,
        /// The arrivals, oldest first, at most [`MAX_NEW_MAIL`].
        items: Vec<NewMail>,
    },
    /// The subscriber fell behind and missed events; reload everything shown.
    Lagged {
        /// How many were missed.
        missed: u64,
    },
}

/// A subscription to the node's events: bounded, never holds the node up.
pub type EventStream = Pin<Box<dyn Stream<Item = NodeEvent> + Send>>;

/// Something changed in the node's group. Kept apart from [`NodeEvent`] so apps that match node
/// events exhaustively keep compiling; ids, kinds and the fingerprint only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GroupEvent {
    /// A pairing reached the fingerprint: show it. When `confirm` is set the person must compare
    /// it with the other screen and answer with `confirm_pairing`.
    PairingCheck {
        /// The pairing, for `confirm_pairing`.
        pairing: String,
        /// Six digits in two groups.
        fingerprint: String,
        /// The other node.
        node: String,
        /// The class of the node being added (`server`, `desktop`, `phone`).
        class: String,
        /// Whether the person must answer.
        confirm: bool,
    },
    /// A node joined, was revoked or renewed: reload the list of nodes.
    NodesChanged,
    /// This node was revoked: the app runs its "lost or stolen" path.
    NodeRevoked,
    /// Which node leads an account, or whether the server answers, may have changed: reload
    /// [`crate::NodeApi::group_status`].
    LeadersChanged,
    /// The journal of an account this node follows forked: two valid heads of its owner
    /// disagree. The node stopped following it; ids only.
    JournalForked {
        /// The account.
        account: AccountId,
    },
    /// The subscriber fell behind and missed events; reload the list of nodes.
    Lagged {
        /// How many were missed.
        missed: u64,
    },
}

/// A subscription to the group's events, bounded like [`EventStream`].
pub type GroupEventStream = Pin<Box<dyn Stream<Item = GroupEvent> + Send>>;
