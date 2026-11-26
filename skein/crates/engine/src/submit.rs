//! Queuing and cancelling commands from outside the owner: the checks every command passes before
//! it is queued, the idempotent submit and the cancel that races the owner fairly.

use baton_signal::Signal;
use bytes::Bytes;
use skein_core::{
    AccountId, Command, CommandBody, CommandId, Flags, ItemRef, TenantId, plausible_address,
};
use skein_storage::{Expect, Storage, StorageError, Submitted};
use tracing::info;

/// Longest comment of a scheduling answer, in bytes.
pub const MAX_COMMENT: usize = 4096;
/// Longest mailbox, collection or item id, or version, in a command.
pub const MAX_ID: usize = 1024;
/// Most messages one command may name.
pub const MAX_ITEMS: usize = 10_000;
/// Most flags (or labels) one command may add or remove.
pub const MAX_FLAGS: usize = 100;
/// Longest flag, in bytes.
pub const MAX_FLAG: usize = 256;
/// Longest mailbox path or label, in bytes.
pub const MAX_PATH: usize = 1000;

/// Why a command was not queued or not cancelled. `Display` never carries the command's content.
#[derive(Debug, thiserror::Error)]
pub enum SubmitError {
    /// The command breaks a rule; `code` is stable, `reason` says which rule.
    #[error("{code}: {reason}")]
    Invalid {
        /// A stable code, such as `invalid_path`.
        code: &'static str,
        /// The rule that was broken.
        reason: &'static str,
    },
    /// A blob the command refers to is not stored yet; store it first.
    #[error("the blob the command refers to is not stored")]
    BlobMissing,
    /// Another command already uses this id.
    #[error("another command already uses this id")]
    IdConflict,
    /// The command already started; its outcome will be in the journal.
    #[error("the command already started")]
    AlreadyStarted,
    /// No such queued command: never submitted, or already finished.
    #[error("no such queued command")]
    NotQueued,
    /// Storage failed.
    #[error(transparent)]
    Storage(#[from] StorageError),
}

fn invalid(code: &'static str, reason: &'static str) -> SubmitError {
    SubmitError::Invalid { code, reason }
}

fn clean(text: &str, max: usize) -> bool {
    text.len() <= max && !text.chars().any(char::is_control)
}

/// Whether `path` may name a mailbox or a label: 1 to [`MAX_PATH`] bytes of text without control
/// characters, empty levels or a leading or trailing `/`.
pub fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_PATH
        && !path.chars().any(char::is_control)
        && path.split('/').all(|level| !level.trim().is_empty())
}

/// The checks every command passes before it is queued, without reading storage: a known type;
/// ids, versions and flags bounded and free of control characters, so nothing oversized or
/// holding line breaks reaches a provider protocol; at most [`MAX_ITEMS`] messages; clean
/// mailbox paths and labels; a send envelope that passes [`skein_core::SendEnvelope::check`]; an
/// attendee that is an address and a comment of at most [`MAX_COMMENT`] bytes.
pub fn check_command(body: &CommandBody) -> Result<(), SubmitError> {
    if *body == CommandBody::Unknown {
        return Err(invalid("unknown_command", "unknown command type"));
    }
    fields_ok(body)?;
    if let CommandBody::Send { envelope, .. } = body
        && let Err(e) = envelope.check()
    {
        return Err(invalid("invalid_envelope", e.0));
    }
    if let CommandBody::CreateMailbox { path } | CommandBody::RenameMailbox { path, .. } = body
        && !valid_path(path)
    {
        return Err(invalid(
            "invalid_path",
            "a mailbox path is 1 to 1000 bytes of text without control characters, empty levels or a leading or trailing slash",
        ));
    }
    if let CommandBody::SetLabels { add, remove, .. } = body
        && (add.is_empty() && remove.is_empty() || add.iter().chain(remove).any(|l| !valid_path(l)))
    {
        return Err(invalid(
            "invalid_labels",
            "name at least one label, each 1 to 1000 bytes of text without control characters",
        ));
    }
    if let CommandBody::RespondObject {
        attendee, comment, ..
    }
    | CommandBody::RespondInvitation {
        attendee, comment, ..
    } = body
    {
        if attendee
            .as_deref()
            .is_some_and(|a| !plausible_address(&skein_itip::address(a)))
        {
            return Err(invalid(
                "invalid_attendee",
                "the attendee is not an address",
            ));
        }
        if comment.as_ref().is_some_and(|c| c.len() > MAX_COMMENT) {
            return Err(invalid(
                "comment_too_long",
                "the comment is longer than 4096 bytes",
            ));
        }
    }
    Ok(())
}

fn fields_ok(body: &CommandBody) -> Result<(), SubmitError> {
    let mut ids: Vec<&str> = Vec::new();
    let mut items: &[ItemRef] = &[];
    let mut flags: Vec<&Flags> = Vec::new();
    let mut item: Option<&ItemRef> = None;
    match body {
        CommandBody::SetFlags {
            mailbox,
            items: i,
            add,
            remove,
        } => {
            ids.push(mailbox);
            items = i;
            flags.extend([add, remove]);
        }
        CommandBody::Move { from, to, items: i } | CommandBody::Copy { from, to, items: i } => {
            ids.extend([from.as_str(), to.as_str()]);
            items = i;
        }
        CommandBody::Delete {
            mailbox, items: i, ..
        }
        | CommandBody::SetLabels {
            mailbox, items: i, ..
        } => {
            ids.push(mailbox);
            items = i;
        }
        CommandBody::RenameMailbox { mailbox, .. } | CommandBody::DeleteMailbox { mailbox } => {
            ids.push(mailbox);
        }
        CommandBody::Append {
            mailbox, flags: f, ..
        } => {
            ids.push(mailbox);
            flags.push(f);
        }
        CommandBody::Refetch { mailbox, item: i } => {
            ids.push(mailbox);
            item = Some(i);
        }
        CommandBody::Send { save_to_sent, .. }
        | CommandBody::RespondInvitation { save_to_sent, .. } => {
            ids.extend(save_to_sent.as_deref());
        }
        CommandBody::PutObject {
            collection,
            item: i,
            if_version,
            ..
        } => {
            ids.push(collection);
            ids.extend(if_version.as_deref());
            item = i.as_ref();
        }
        CommandBody::DeleteObject {
            collection,
            item: i,
            if_version,
            ..
        }
        | CommandBody::RespondObject {
            collection,
            item: i,
            if_version,
            ..
        } => {
            ids.push(collection);
            ids.extend(if_version.as_deref());
            item = Some(i);
        }
        CommandBody::CreateMailbox { .. } | CommandBody::Unknown => {}
    }
    if let CommandBody::SetLabels { add, remove, .. } = body
        && add.len() + remove.len() > MAX_FLAGS
    {
        return Err(invalid(
            "invalid_labels",
            "a command changes at most 100 labels",
        ));
    }
    if items.len() > MAX_ITEMS {
        return Err(invalid(
            "too_many_items",
            "a command names at most 10000 messages",
        ));
    }
    let item_ids = items.iter().chain(item).map(|i| i.id.as_str());
    if !ids.into_iter().chain(item_ids).all(|id| clean(id, MAX_ID)) {
        return Err(invalid(
            "invalid_id",
            "ids and versions are at most 1024 bytes without control characters",
        ));
    }
    let flags_ok = flags
        .iter()
        .all(|f| f.iter().count() <= MAX_FLAGS && f.iter().all(|f| clean(f, MAX_FLAG)));
    if !flags_ok {
        return Err(invalid(
            "invalid_flags",
            "at most 100 flags of up to 256 bytes without control characters",
        ));
    }
    Ok(())
}

/// What [`submit_command`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Submission {
    /// Whether the same command was already queued (or already finished), so nothing changed.
    pub duplicate: bool,
}

/// Queues `command` for its account's owner after [`check_command`] and a check that every blob
/// it names is stored. The id is the idempotency key: the same body under the same id is a
/// duplicate (also once it finished), differences in trace context do not count, another body
/// under a used id is [`SubmitError::IdConflict`]. A new command is hinted on the signal topic
/// `commands/{account}` in the tenant's group; hints may be lost, the owner also polls. The
/// caller checks that the account exists.
pub async fn submit_command(
    storage: &Storage,
    signal: &dyn Signal,
    tenant: &TenantId,
    command: &Command,
) -> Result<Submission, SubmitError> {
    check_command(&command.body)?;
    if let CommandBody::Append { blob, .. }
    | CommandBody::Send { blob, .. }
    | CommandBody::PutObject { blob, .. }
    | CommandBody::RespondInvitation {
        invitation: blob, ..
    } = &command.body
        && !storage.blobs.contains(tenant, blob).await?
    {
        return Err(SubmitError::BlobMissing);
    }
    let duplicate = match storage.commands.submit(tenant, command).await {
        Ok(Submitted::New) => false,
        Ok(Submitted::Duplicate) => true,
        Err(StorageError::Conflict) => {
            match storage
                .commands
                .get(tenant, &command.account, &command.id)
                .await?
            {
                Some(stored) if stored.body != command.body => {
                    return Err(SubmitError::IdConflict);
                }
                _ => true,
            }
        }
        Err(e) => return Err(e.into()),
    };
    if !duplicate {
        let _ = signal
            .publish(
                &skein_core::coordination::group(tenant),
                &format!("commands/{}", command.account),
                Bytes::from(command.id.to_string()),
            )
            .await;
        info!(tenant = %tenant, account = %command.account, command = %command.id, "command queued");
    }
    Ok(Submission { duplicate })
}

/// Cancels a queued command so it never reaches the provider. It claims the command's start
/// marker first, the same marker the owner claims before it acts, so exactly one of the two
/// wins: a command the owner already started is [`SubmitError::AlreadyStarted`] and its outcome
/// will be in the journal. Cancelling again succeeds; an id that was never queued, or whose
/// command finished, is [`SubmitError::NotQueued`].
pub async fn cancel_command(
    storage: &Storage,
    tenant: &TenantId,
    account: &AccountId,
    id: &CommandId,
) -> Result<(), SubmitError> {
    let control = &storage.control;
    let marker = format!("started/{account}/{id}");
    let is_cancelled = |m: &Option<(Bytes, skein_storage::Version)>| matches!(m, Some((b, _)) if &b[..] == b"cancelled");
    if storage.commands.get(tenant, account, id).await?.is_none() {
        return if is_cancelled(&control.get(tenant, &marker).await?) {
            Ok(())
        } else {
            Err(SubmitError::NotQueued)
        };
    }
    match control
        .put(
            tenant,
            &marker,
            Bytes::from_static(b"cancelled"),
            Expect::Absent,
        )
        .await
    {
        Ok(_) => {}
        Err(StorageError::Conflict) => {
            if !is_cancelled(&control.get(tenant, &marker).await?) {
                return Err(SubmitError::AlreadyStarted);
            }
        }
        Err(e) => return Err(e.into()),
    }
    storage.commands.complete(tenant, account, id).await?;
    info!(tenant = %tenant, account = %account, command = %id, "command cancelled");
    Ok(())
}

#[cfg(test)]
#[path = "submit_tests.rs"]
mod tests;
