use serde::{Deserialize, Serialize};

use crate::{AccountHealth, FencingToken, Timestamp};

/// What became of the latest attempt in one domain of an account: `ok`, or the kind of error.
/// Kinds name a class of failure, never the provider's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncOutcome {
    /// The attempt finished.
    Ok,
    /// The provider refused the credentials; a person must sign in again.
    AuthFailed,
    /// The account settings cannot work (bad host, missing address or token).
    Config,
    /// The provider is limiting requests.
    Throttled,
    /// The provider could not be reached, or the connection broke.
    Network,
    /// The provider answered something that could not be understood.
    Protocol,
    /// Skein's own storage failed.
    Storage,
    /// Any other failure, including kinds a newer build knows.
    #[serde(other)]
    Other,
}

impl SyncOutcome {
    /// The coarse health this outcome stands for, the same mapping the engine uses for
    /// `account_health_changed`.
    pub fn health(self) -> AccountHealth {
        match self {
            Self::Ok => AccountHealth::Healthy,
            Self::AuthFailed => AccountHealth::ReauthRequired,
            Self::Throttled => AccountHealth::Throttled,
            _ => AccountHealth::Degraded,
        }
    }
}

/// The engine's latest word on one domain (mail sync, calendar and contacts sync, sending).
/// A change of `outcome` or `resync_required` is written at once; while they stay the same the
/// entry is rewritten at most once a minute, so `last_ok_at` and `last_error_at` may lag the
/// latest attempt by up to a minute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainStatus {
    /// The latest attempt's outcome.
    pub outcome: SyncOutcome,
    /// When an attempt last finished, if ever.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_ok_at: Option<Timestamp>,
    /// When an attempt last failed, if ever.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error_at: Option<Timestamp>,
    /// The kind of the latest failure, kept after the domain recovers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<SyncOutcome>,
    /// The provider dropped a cursor and the full listing that follows has not finished yet:
    /// until an attempt succeeds, consumers' copies of this domain may lack items or keep
    /// removed ones. Always `false` for sending.
    #[serde(default)]
    pub resync_required: bool,
    /// When this entry was last written.
    pub updated_at: Timestamp,
}

/// The per-account status record the owning node keeps, one small record per account, written
/// when an outcome changes and at most once a minute otherwise. A domain is missing until the
/// engine first tried it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountStatus {
    /// Mail sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail: Option<DomainStatus>,
    /// Calendar and contacts sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pim: Option<DomainStatus>,
    /// Sending, from `send` and `respond_invitation` commands that reached the sending service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send: Option<DomainStatus>,
    /// The fencing token of the owner that wrote it; an older owner never overwrites it.
    #[serde(default)]
    pub fence: FencingToken,
}

impl AccountStatus {
    /// The worst health over the domains present, `None` when none is.
    pub fn health(&self) -> Option<AccountHealth> {
        let rank = |h: AccountHealth| match h {
            AccountHealth::Healthy => 0,
            AccountHealth::Throttled => 1,
            AccountHealth::Degraded => 2,
            AccountHealth::ReauthRequired => 3,
        };
        [&self.mail, &self.pim, &self.send]
            .into_iter()
            .flatten()
            .map(|d| d.outcome.health())
            .max_by_key(|h| rank(*h))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(outcome: SyncOutcome) -> DomainStatus {
        DomainStatus {
            outcome,
            last_ok_at: None,
            last_error_at: None,
            error: None,
            resync_required: false,
            updated_at: Timestamp(1),
        }
    }

    #[test]
    fn worst_domain_wins() {
        assert_eq!(AccountStatus::default().health(), None);
        let status = AccountStatus {
            mail: Some(domain(SyncOutcome::Throttled)),
            pim: Some(domain(SyncOutcome::AuthFailed)),
            send: Some(domain(SyncOutcome::Ok)),
            fence: FencingToken(1),
        };
        assert_eq!(status.health(), Some(AccountHealth::ReauthRequired));
    }

    #[test]
    fn unknown_kinds_read_as_other() {
        let d: DomainStatus =
            serde_json::from_str(r#"{"outcome":"quota","updated_at":5}"#).unwrap();
        assert_eq!(d.outcome, SyncOutcome::Other);
        assert!(!d.resync_required);
    }
}
