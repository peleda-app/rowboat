use bytes::Bytes;
use skein_core::{
    AccountId, AccountStatus, DomainStatus, FencingToken, SyncOutcome, TenantId, Timestamp,
};
use skein_mail::MailError;
use skein_pim::PimError;
use skein_send::SendError;
use skein_storage::{ControlStore, Expect, StorageError};
use tracing::debug;

use crate::{AccountConfig, CollectionsError, Engine, EngineError};

/// How long an unchanged outcome goes without being written again.
pub const STATUS_REFRESH_MS: i64 = 60_000;

const ATTEMPTS: usize = 4;

#[derive(Debug, Clone, Copy)]
pub(crate) enum Area {
    Mail,
    Pim,
    Send,
}

fn status_path(account: &AccountId) -> String {
    format!("status/{account}")
}

/// The account's status record (see [`AccountStatus`]), `None` until the engine first wrote
/// one. One control-store read. A record that does not parse reads as `None`, so a damaged or
/// newer record never fails a caller.
pub async fn load_status(
    control: &dyn ControlStore,
    tenant: &TenantId,
    account: &AccountId,
) -> Result<Option<AccountStatus>, StorageError> {
    Ok(control
        .get(tenant, &status_path(account))
        .await?
        .and_then(|(bytes, _)| serde_json::from_slice(&bytes).ok()))
}

pub(crate) fn mail_outcome(e: &EngineError) -> Option<SyncOutcome> {
    Some(match e {
        EngineError::NotOwner => return None,
        EngineError::Mail(m) => match m {
            MailError::Auth => SyncOutcome::AuthFailed,
            MailError::Config(_) => SyncOutcome::Config,
            MailError::Throttled { .. } => SyncOutcome::Throttled,
            MailError::Network(_) => SyncOutcome::Network,
            MailError::Protocol(_) | MailError::MailboxNotFound => SyncOutcome::Protocol,
        },
        EngineError::Storage(_) => SyncOutcome::Storage,
        EngineError::Lease(_) => SyncOutcome::Other,
    })
}

pub(crate) fn pim_outcome(e: &CollectionsError) -> Option<SyncOutcome> {
    match e {
        CollectionsError::Engine(e) => mail_outcome(e),
        CollectionsError::Pim(p) => Some(match p {
            PimError::Auth => SyncOutcome::AuthFailed,
            PimError::Config(_) => SyncOutcome::Config,
            PimError::Throttled { .. } => SyncOutcome::Throttled,
            PimError::Network(_) => SyncOutcome::Network,
            PimError::Protocol(_) | PimError::NotFound => SyncOutcome::Protocol,
        }),
    }
}

/// Only failures that say something about the account, not about one message. The envelope and
/// the message are validated before they are handed over, so `Invalid` means the sending
/// settings or the service account cannot send.
pub(crate) fn send_outcome(e: &SendError) -> Option<SyncOutcome> {
    match e {
        SendError::Auth(_) => Some(SyncOutcome::AuthFailed),
        SendError::Invalid(_) => Some(SyncOutcome::Config),
        SendError::Throttled { .. } => Some(SyncOutcome::Throttled),
        SendError::Temporary(_) | SendError::Unavailable(_) | SendError::Uncertain(_) => {
            Some(SyncOutcome::Network)
        }
        _ => None,
    }
}

fn next(
    prev: Option<&DomainStatus>,
    outcome: SyncOutcome,
    reset_seen: bool,
    now: Timestamp,
) -> DomainStatus {
    let ok = outcome == SyncOutcome::Ok;
    DomainStatus {
        outcome,
        last_ok_at: if ok {
            Some(now)
        } else {
            prev.and_then(|p| p.last_ok_at)
        },
        last_error_at: if ok {
            prev.and_then(|p| p.last_error_at)
        } else {
            Some(now)
        },
        error: if ok {
            prev.and_then(|p| p.error)
        } else {
            Some(outcome)
        },
        resync_required: !ok && (reset_seen || prev.is_some_and(|p| p.resync_required)),
        updated_at: now,
    }
}

impl Engine {
    /// Records an attempt's outcome in the account's status record. Never fails the caller:
    /// storage errors are logged and dropped, and an owner with an older token writes nothing.
    pub(crate) async fn record_status(
        &self,
        config: &AccountConfig,
        fence: FencingToken,
        area: Area,
        outcome: SyncOutcome,
        reset_seen: bool,
    ) {
        let control = &*self.storage.control;
        let path = status_path(&config.account);
        for _ in 0..ATTEMPTS {
            let (mut status, expect) = match control.get(&config.tenant, &path).await {
                Ok(None) => (AccountStatus::default(), Expect::Absent),
                Ok(Some((bytes, v))) => (
                    serde_json::from_slice(&bytes).unwrap_or_default(),
                    Expect::Version(v),
                ),
                Err(e) => {
                    debug!(account = %config.account, error = %e, "status not read");
                    return;
                }
            };
            if status.fence > fence {
                return;
            }
            let slot = match area {
                Area::Mail => &mut status.mail,
                Area::Pim => &mut status.pim,
                Area::Send => &mut status.send,
            };
            let now = Timestamp::now();
            let entry = next(slot.as_ref(), outcome, reset_seen, now);
            if let Some(prev) = slot.as_ref()
                && status.fence == fence
                && prev.outcome == entry.outcome
                && prev.resync_required == entry.resync_required
                && now.0 - prev.updated_at.0 < STATUS_REFRESH_MS
            {
                return;
            }
            *slot = Some(entry);
            status.fence = fence;
            let bytes = Bytes::from(serde_json::to_vec(&status).expect("plain struct"));
            match control.put(&config.tenant, &path, bytes, expect).await {
                Ok(_) => return,
                Err(StorageError::Conflict) => continue,
                Err(e) => {
                    debug!(account = %config.account, error = %e, "status not saved");
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_keeps_the_last_error_and_clears_resync() {
        let failed = next(None, SyncOutcome::Network, true, Timestamp(10));
        assert_eq!(failed.error, Some(SyncOutcome::Network));
        assert_eq!(failed.last_error_at, Some(Timestamp(10)));
        assert!(failed.resync_required);
        let still = next(Some(&failed), SyncOutcome::Throttled, false, Timestamp(20));
        assert!(
            still.resync_required,
            "a later failure keeps the pending resync"
        );
        let ok = next(Some(&still), SyncOutcome::Ok, false, Timestamp(30));
        assert_eq!(ok.last_ok_at, Some(Timestamp(30)));
        assert_eq!(ok.last_error_at, Some(Timestamp(20)));
        assert_eq!(ok.error, Some(SyncOutcome::Throttled));
        assert!(!ok.resync_required);
    }
}
