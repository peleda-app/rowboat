//! The engine: under a fenced lease on each account, it turns a provider's changes into journal
//! events and carries out queued commands.
//!
//! Leases, liveness and signals come from Baton's contracts (`baton-lease`, `baton-signal`); the
//! mapping from tenants and accounts to Baton's groups and lease keys is
//! [`skein_core::coordination`].
//!
//! Order of writes for every batch, which is what makes a crash at any point safe:
//!
//! 1. message bytes into the blob store (idempotent, content-addressed);
//! 2. previews as signals (may be lost);
//! 3. events into the log, fenced by the owner's token;
//! 4. the provider cursor, with compare-and-swap and the same token.
//!
//! A crash between 3 and 4 makes the next run see the same changes again; their event keys are
//! already in the log after the saved position, so they are dropped instead of appended twice.

mod collections;
mod commands;
mod lease;
mod message_id;
mod run;
mod schedule;
mod snapshot;
mod state;
mod status;
mod submit;
mod sync;

use std::sync::Arc;

use baton_lease::{LeaseError, Leases, NodeProfile};
use baton_signal::Signal;
use skein_core::{AccountId, NodeId, TenantId};
use skein_mail::MailError;
use skein_storage::{Storage, StorageError};

pub use collections::{CollectionReport, CollectionsError, CollectionsReport};
pub use commands::{CommandReport, SendPolicy, SenderDirectory};
pub use lease::{NODES_GROUP, OneGroupLiveness, node_profile};
pub use message_id::ORIGINAL_MESSAGE_ID;
pub use run::{
    AccountDirectory, AccountEntry, AccountObserver, ObserverError, PushConfig, RunConfig, run,
};
pub use snapshot::Maintenance;
pub use status::{STATUS_REFRESH_MS, load_status};
pub use submit::{
    MAX_COMMENT, MAX_FLAG, MAX_FLAGS, MAX_ID, MAX_ITEMS, MAX_PATH, Submission, SubmitError,
    cancel_command, check_command, submit_command, valid_path,
};
pub use sync::{MailboxReport, SyncReport};

/// Which account to sync and how.
#[derive(Debug, Clone)]
pub struct AccountConfig {
    /// The tenant.
    pub tenant: TenantId,
    /// The account.
    pub account: AccountId,
    /// When set, only these mailbox ids are synced.
    pub include: Option<Vec<String>>,
    /// Mailbox ids never synced.
    pub exclude: Vec<String>,
    /// Changes asked from the provider per call.
    pub page: usize,
    /// Messages fetched per request.
    pub fetch_batch: usize,
}

impl AccountConfig {
    /// Defaults for `account`: every mailbox, pages of 500 changes, fetches of 50 messages.
    pub fn new(tenant: TenantId, account: AccountId) -> Self {
        Self {
            tenant,
            account,
            include: None,
            exclude: Vec::new(),
            page: 500,
            fetch_batch: 50,
        }
    }
}

/// Errors of the engine.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// Another node holds the account's lease (or took it over during the run), a stronger node
    /// asked to take it over, or this node's lease may have expired because its heartbeats stopped
    /// succeeding.
    #[error("this node does not own the account")]
    NotOwner,
    /// The provider failed.
    #[error(transparent)]
    Mail(#[from] MailError),
    /// Storage failed.
    #[error(transparent)]
    Storage(StorageError),
    /// The lease could not be decided.
    #[error(transparent)]
    Lease(#[from] LeaseError),
}

impl From<StorageError> for EngineError {
    fn from(e: StorageError) -> Self {
        match e {
            StorageError::Fenced => EngineError::NotOwner,
            e => EngineError::Storage(e),
        }
    }
}

/// What the engine works with.
#[derive(Clone)]
pub struct Engine {
    pub(crate) storage: Storage,
    pub(crate) leases: Arc<dyn Leases>,
    pub(crate) signal: Arc<dyn Signal>,
    pub(crate) profile: NodeProfile,
    pub(crate) holding: Arc<lease::Holding>,
    pub(crate) senders: Option<Arc<dyn SenderDirectory>>,
    pub(crate) send_policy: SendPolicy,
}

impl Engine {
    /// An engine for the node `profile` describes (see [`node_profile`]), taking account leases
    /// from `leases` and publishing previews and hints to `signal`.
    ///
    /// Called directly (without [`run`]), the engine renews the lease at the start of every call
    /// and the caller is responsible for the node's heartbeats; under [`run`] it also stops acting
    /// on a lease once its heartbeats have not succeeded for most of the liveness time-to-live.
    pub fn new(
        storage: Storage,
        leases: Arc<dyn Leases>,
        signal: Arc<dyn Signal>,
        profile: NodeProfile,
    ) -> Self {
        Self {
            storage,
            leases,
            signal,
            profile,
            holding: Arc::new(lease::Holding::default()),
            senders: None,
            send_policy: SendPolicy::default(),
        }
    }

    /// The node this engine runs as.
    pub fn node(&self) -> &NodeId {
        &self.profile.node
    }

    /// The profile it acquires leases and heartbeats with.
    pub fn profile(&self) -> &NodeProfile {
        &self.profile
    }

    /// The storage it writes to.
    pub fn storage(&self) -> &Storage {
        &self.storage
    }
}

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;
