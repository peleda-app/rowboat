//! The mutating calls as data: the payloads phase 2 carries to another node as signed Baton
//! commands, one class per call. Phase 1 calls everything in process; the decoder exists so the
//! payload format is fixed and fuzzed from the start.

use serde::{Deserialize, Serialize};

use crate::NodeError;
use crate::check;
use crate::ids::{AccountId, CommandId, DraftId, MailboxId};
use crate::types::{AccountPatch, AccountSetup, Draft, Targets};

/// Most bytes of an encoded request.
pub const MAX_REQUEST: usize = 40 * 1024 * 1024;

/// The Baton command class reserved for each mutating call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommandClass {
    /// `add_account`.
    AccountAdd,
    /// `update_password`.
    AccountPassword,
    /// `update_account`.
    AccountUpdate,
    /// `remove_account`.
    AccountRemove,
    /// `sync_now`.
    Sync,
    /// `set_read`, `set_flagged`.
    Flags,
    /// `move_to`, `archive`.
    Move,
    /// `delete`.
    Delete,
    /// The draft calls.
    Draft,
    /// `send`.
    Send,
    /// `cancel_send`.
    SendCancel,
}

impl CommandClass {
    /// The class name as Baton carries it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccountAdd => "mail-account-add",
            Self::AccountPassword => "mail-account-password",
            Self::AccountUpdate => "mail-account-update",
            Self::AccountRemove => "mail-account-remove",
            Self::Sync => "mail-sync",
            Self::Flags => "mail-flags",
            Self::Move => "mail-move",
            Self::Delete => "mail-delete",
            Self::Draft => "mail-draft",
            Self::Send => "mail-send",
            Self::SendCancel => "mail-send-cancel",
        }
    }
}

/// A mutating call. Secrets never travel in a request: a password reaches the node only
/// through `add_account` and `update_password` in process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Add an account (the password follows separately).
    AddAccount {
        /// The setup.
        setup: AccountSetup,
    },
    /// Change an account.
    UpdateAccount {
        /// The account.
        account: AccountId,
        /// The changes.
        patch: AccountPatch,
    },
    /// Remove an account.
    RemoveAccount {
        /// The account.
        account: AccountId,
    },
    /// Sync one account or every account now.
    SyncNow {
        /// The account, or every account.
        account: Option<AccountId>,
    },
    /// Mark read or unread.
    SetRead {
        /// The messages.
        targets: Targets,
        /// Read or unread.
        read: bool,
    },
    /// Flag or unflag.
    SetFlagged {
        /// The messages.
        targets: Targets,
        /// Flagged or not.
        flagged: bool,
    },
    /// Move.
    MoveTo {
        /// The messages, all of one account.
        targets: Targets,
        /// The target mailbox.
        mailbox: MailboxId,
    },
    /// Archive.
    Archive {
        /// The messages.
        targets: Targets,
    },
    /// Delete.
    Delete {
        /// The messages.
        targets: Targets,
        /// For good instead of to the trash.
        permanent: bool,
    },
    /// Save a draft.
    SaveDraft {
        /// The draft.
        draft: Draft,
    },
    /// Delete a draft.
    DeleteDraft {
        /// The draft.
        id: DraftId,
    },
    /// Send.
    Send {
        /// The draft.
        draft: Draft,
    },
    /// Cancel a send inside its undo window.
    CancelSend {
        /// The account.
        account: AccountId,
        /// The command.
        command: CommandId,
    },
}

impl Request {
    /// The command class the request travels under.
    pub fn class(&self) -> CommandClass {
        match self {
            Self::AddAccount { .. } => CommandClass::AccountAdd,
            Self::UpdateAccount { .. } => CommandClass::AccountUpdate,
            Self::RemoveAccount { .. } => CommandClass::AccountRemove,
            Self::SyncNow { .. } => CommandClass::Sync,
            Self::SetRead { .. } | Self::SetFlagged { .. } => CommandClass::Flags,
            Self::MoveTo { .. } | Self::Archive { .. } => CommandClass::Move,
            Self::Delete { .. } => CommandClass::Delete,
            Self::SaveDraft { .. } | Self::DeleteDraft { .. } => CommandClass::Draft,
            Self::Send { .. } => CommandClass::Send,
            Self::CancelSend { .. } => CommandClass::SendCancel,
        }
    }

    /// Runs the checks of [`crate::check`] that apply.
    pub fn check(&self) -> Result<(), NodeError> {
        match self {
            Self::AddAccount { setup } => check::setup(setup),
            Self::UpdateAccount { patch, .. } => check::patch(patch),
            Self::RemoveAccount { .. } | Self::SyncNow { .. } | Self::DeleteDraft { .. } => Ok(()),
            Self::CancelSend { .. } => Ok(()),
            Self::SetRead { targets, .. }
            | Self::SetFlagged { targets, .. }
            | Self::Archive { targets }
            | Self::Delete { targets, .. } => check::targets(targets),
            Self::MoveTo { targets, .. } => check::targets_of_one_account(targets),
            Self::SaveDraft { draft } => check::draft(draft),
            Self::Send { draft } => check::sendable(draft),
        }
    }
}

/// The JSON form of `request`.
pub fn encode_request(request: &Request) -> Vec<u8> {
    serde_json::to_vec(request).unwrap_or_default()
}

/// Reads a request from untrusted bytes: at most [`MAX_REQUEST`] bytes of JSON, every id and
/// field checked on the way in and the request's checks run. Never panics.
pub fn decode_request(bytes: &[u8]) -> Result<Request, NodeError> {
    if bytes.len() > MAX_REQUEST {
        return Err(NodeError::InvalidInput);
    }
    let request: Request = serde_json::from_slice(bytes).map_err(|_| NodeError::InvalidInput)?;
    request.check()?;
    Ok(request)
}
