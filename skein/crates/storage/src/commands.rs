use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use skein_core::{AccountId, Command, CommandId, TenantId};

use crate::{Expect, ObjectKey, Objects, StorageError};

/// Whether a submitted command is new.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Submitted {
    /// The command was queued.
    New,
    /// The same command (same id and content) was already queued; nothing changed.
    Duplicate,
}

/// Write requests waiting for an account's owner.
///
/// - The command id is the idempotency key: submitting the same command again is
///   [`Submitted::Duplicate`]; submitting a different command under a used id is
///   [`StorageError::Conflict`].
/// - `pending` lists commands in id order, which is submission-time order for ULIDs.
/// - A command stays pending until `complete` removes it; its outcome is recorded in the log.
#[async_trait]
pub trait CommandQueue: Send + Sync {
    /// Queues a command.
    async fn submit(&self, tenant: &TenantId, command: &Command)
    -> Result<Submitted, StorageError>;

    /// Up to `limit` pending commands of the account, oldest first.
    async fn pending(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        limit: usize,
    ) -> Result<Vec<Command>, StorageError> {
        self.pending_after(tenant, account, None, limit).await
    }

    /// Up to `limit` pending commands of the account with ids after `after`, oldest first; page
    /// through the queue by passing the last id of the previous page.
    async fn pending_after(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        after: Option<&CommandId>,
        limit: usize,
    ) -> Result<Vec<Command>, StorageError>;

    /// The pending command with this id, if it is still queued.
    async fn get(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        id: &CommandId,
    ) -> Result<Option<Command>, StorageError>;

    /// Removes a command once its outcome is in the log. Removing a missing command succeeds.
    async fn complete(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        id: &CommandId,
    ) -> Result<(), StorageError>;

    /// Deletes every queued command of every account of the tenant; returns how many.
    async fn purge(&self, tenant: &TenantId) -> Result<u64, StorageError>;
}

/// A [`CommandQueue`] on top of [`Objects`], under `tenants/{tenant}/commands/{account}/{id}`.
pub struct ObjectCommands {
    objects: Arc<dyn Objects>,
}

impl ObjectCommands {
    /// Commands in `objects`.
    pub fn new(objects: Arc<dyn Objects>) -> Self {
        Self { objects }
    }

    fn prefix(tenant: &TenantId, account: &AccountId) -> ObjectKey {
        ObjectKey::account(tenant, "commands", account).expect("ids are valid segments")
    }

    fn key(tenant: &TenantId, account: &AccountId, id: &CommandId) -> ObjectKey {
        Self::prefix(tenant, account)
            .join(id.as_str())
            .expect("ULIDs are valid segments")
    }
}

#[async_trait]
impl CommandQueue for ObjectCommands {
    async fn submit(
        &self,
        tenant: &TenantId,
        command: &Command,
    ) -> Result<Submitted, StorageError> {
        let bytes = Bytes::from(
            serde_json::to_vec(command).map_err(|e| StorageError::Corrupt(e.to_string()))?,
        );
        let key = Self::key(tenant, &command.account, &command.id);
        match self.objects.put(&key, bytes, Expect::Absent).await {
            Ok(_) => Ok(Submitted::New),
            Err(StorageError::Conflict) => {
                let existing = self.objects.get(&key).await?;
                match existing {
                    Some((stored, _)) => {
                        let stored: Command = serde_json::from_slice(&stored)
                            .map_err(|e| StorageError::Corrupt(e.to_string()))?;
                        if &stored == command {
                            Ok(Submitted::Duplicate)
                        } else {
                            Err(StorageError::Conflict)
                        }
                    }
                    None => Err(StorageError::Conflict),
                }
            }
            Err(e) => Err(e),
        }
    }

    async fn get(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        id: &CommandId,
    ) -> Result<Option<Command>, StorageError> {
        let Some((bytes, _)) = self.objects.get(&Self::key(tenant, account, id)).await? else {
            return Ok(None);
        };
        let command: Command =
            serde_json::from_slice(&bytes).map_err(|e| StorageError::Corrupt(e.to_string()))?;
        if &command.account != account || &command.id != id {
            return Err(StorageError::Corrupt(
                "a command key holds another command".into(),
            ));
        }
        Ok(Some(command))
    }

    async fn pending_after(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        after: Option<&CommandId>,
        limit: usize,
    ) -> Result<Vec<Command>, StorageError> {
        let after = after.map(|id| Self::key(tenant, account, id));
        let keys = self
            .objects
            .list(&Self::prefix(tenant, account), after.as_ref(), limit)
            .await?;
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some((bytes, _)) = self.objects.get(&key).await? {
                let command: Command = serde_json::from_slice(&bytes)
                    .map_err(|e| StorageError::Corrupt(e.to_string()))?;
                if &command.account != account || key.last() != command.id.as_str() {
                    return Err(StorageError::Corrupt(format!(
                        "{key} holds another command"
                    )));
                }
                out.push(command);
            }
        }
        Ok(out)
    }

    async fn complete(
        &self,
        tenant: &TenantId,
        account: &AccountId,
        id: &CommandId,
    ) -> Result<(), StorageError> {
        self.objects
            .delete(&Self::key(tenant, account, id), Expect::Any)
            .await
    }

    async fn purge(&self, tenant: &TenantId) -> Result<u64, StorageError> {
        let prefix = ObjectKey::tenant(tenant).join("commands")?;
        crate::delete_prefix(&*self.objects, &prefix, |_| false).await
    }
}
