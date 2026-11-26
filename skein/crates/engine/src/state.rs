use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use skein_core::{
    AccountHealth, AccountId, FencingToken, MailCapabilities, MailboxInfo, Seq, TenantId,
};
use skein_storage::{ControlStore, Expect, StorageError, Version};

use crate::EngineError;

/// Saved position in one mailbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CursorRecord {
    pub cursor: String,
    pub log_seq: Seq,
    pub fence: FencingToken,
}

impl CursorRecord {
    pub fn cursor_bytes(&self) -> Result<Bytes, EngineError> {
        STANDARD
            .decode(&self.cursor)
            .map(Bytes::from)
            .map_err(|e| EngineError::Storage(StorageError::Corrupt(e.to_string())))
    }
}

/// Per-account state the engine keeps between runs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct AccountState {
    pub mailboxes: Vec<MailboxInfo>,
    pub first_sync_done: bool,
    pub health: Option<AccountHealth>,
    pub fence: FencingToken,
    /// The log head when the state was last saved: account-level events after it may repeat
    /// ones a node wrote before crashing, so they are checked against the log.
    #[serde(default)]
    pub log_seq: Seq,
    #[serde(default)]
    pub capabilities: Option<MailCapabilities>,
}

fn mailbox_path(account: &AccountId, mailbox: &str) -> String {
    let h = blake3::hash(mailbox.as_bytes()).to_hex();
    format!("cursors/{account}/{}", &h[..32])
}

fn state_path(account: &AccountId) -> String {
    format!("state/{account}")
}

pub(crate) fn command_marker(account: &AccountId, id: &str) -> String {
    format!("started/{account}/{id}")
}

fn corrupt(e: impl std::fmt::Display) -> EngineError {
    EngineError::Storage(StorageError::Corrupt(e.to_string()))
}

pub(crate) async fn load_cursor(
    control: &dyn ControlStore,
    tenant: &TenantId,
    account: &AccountId,
    mailbox: &str,
) -> Result<(Option<CursorRecord>, Expect), EngineError> {
    match control.get(tenant, &mailbox_path(account, mailbox)).await? {
        None => Ok((None, Expect::Absent)),
        Some((bytes, v)) => Ok((
            Some(serde_json::from_slice(&bytes).map_err(corrupt)?),
            Expect::Version(v),
        )),
    }
}

/// Saves a cursor unless a newer owner already saved one.
pub(crate) async fn save_cursor(
    control: &dyn ControlStore,
    tenant: &TenantId,
    account: &AccountId,
    mailbox: &str,
    record: &CursorRecord,
    expect: Expect,
) -> Result<Version, EngineError> {
    let bytes = Bytes::from(serde_json::to_vec(record).map_err(corrupt)?);
    match control
        .put(tenant, &mailbox_path(account, mailbox), bytes, expect)
        .await
    {
        Ok(v) => Ok(v),
        Err(StorageError::Conflict) => {
            let (current, _) = load_cursor(control, tenant, account, mailbox).await?;
            match current {
                Some(c) if c.fence > record.fence => Err(EngineError::NotOwner),
                _ => Err(EngineError::Storage(StorageError::Conflict)),
            }
        }
        Err(e) => Err(e.into()),
    }
}

pub(crate) async fn load_state(
    control: &dyn ControlStore,
    tenant: &TenantId,
    account: &AccountId,
) -> Result<(AccountState, Expect), EngineError> {
    match control.get(tenant, &state_path(account)).await? {
        None => Ok((AccountState::default(), Expect::Absent)),
        Some((bytes, v)) => Ok((
            serde_json::from_slice(&bytes).map_err(corrupt)?,
            Expect::Version(v),
        )),
    }
}

pub(crate) async fn save_state(
    control: &dyn ControlStore,
    tenant: &TenantId,
    account: &AccountId,
    state: &AccountState,
    expect: Expect,
) -> Result<Version, EngineError> {
    let bytes = Bytes::from(serde_json::to_vec(state).map_err(corrupt)?);
    match control
        .put(tenant, &state_path(account), bytes, expect)
        .await
    {
        Ok(v) => Ok(v),
        Err(StorageError::Conflict) => {
            let (current, _) = load_state(control, tenant, account).await?;
            if current.fence > state.fence {
                Err(EngineError::NotOwner)
            } else {
                Err(EngineError::Storage(StorageError::Conflict))
            }
        }
        Err(e) => Err(e.into()),
    }
}

pub(crate) fn encode_cursor(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}
