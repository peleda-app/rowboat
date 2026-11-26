use rowboat_api::NodeError;
use skein_mail::{MailCause, MailError};
use skein_send::{SendCause, SendError};
use skein_storage::StorageError;
use tracing::warn;

/// A provider error as the API says it, by its typed cause; the provider's text never leaves.
pub(crate) fn mail(e: &MailError) -> NodeError {
    match e.cause() {
        MailCause::Auth => NodeError::AuthFailed,
        MailCause::Throttled => NodeError::Throttled {
            retry_after_secs: match e {
                MailError::Throttled { retry_after } => retry_after.map(|d| d.as_secs()),
                _ => None,
            },
        },
        MailCause::Tls => NodeError::TlsFailed,
        MailCause::Insecure => NodeError::InsecureRefused,
        MailCause::Unreachable | MailCause::Timeout => NodeError::ServerUnreachable,
        MailCause::Config => NodeError::InvalidInput,
        MailCause::Quota => NodeError::QuotaFull,
        MailCause::Refused | MailCause::Protocol | MailCause::MailboxNotFound => {
            NodeError::ServerRefused
        }
    }
}

/// A sender error as the API says it, by its typed cause.
pub(crate) fn send(e: &SendError) -> NodeError {
    match e.cause() {
        SendCause::Auth => NodeError::AuthFailed,
        SendCause::Throttled => NodeError::Throttled {
            retry_after_secs: e.retry_after().map(|d| d.as_secs()),
        },
        SendCause::Tls => NodeError::TlsFailed,
        SendCause::Insecure => NodeError::InsecureRefused,
        SendCause::Unreachable | SendCause::Temporary | SendCause::Timeout => {
            NodeError::ServerUnreachable
        }
        SendCause::Invalid => NodeError::InvalidInput,
        SendCause::TooLarge => NodeError::QuotaFull,
        SendCause::Refused | SendCause::RecipientsRefused | SendCause::Uncertain => {
            NodeError::ServerRefused
        }
    }
}

/// A storage failure: logged with its kind, reported as `Storage`.
pub(crate) fn storage(e: StorageError) -> NodeError {
    warn!(error = %kind(&e), "storage failed");
    NodeError::Storage
}

fn kind(e: &StorageError) -> &'static str {
    match e {
        StorageError::Conflict => "conflict",
        StorageError::Fenced => "fenced",
        StorageError::Compacted { .. } => "compacted",
        StorageError::Corrupt(_) => "corrupt",
        StorageError::Integrity(_) => "integrity",
        StorageError::InvalidKey(_) => "invalid_key",
        StorageError::Backend(_) => "backend",
    }
}

/// A mail database failure.
pub(crate) fn view(e: skein_view::StoreError) -> NodeError {
    match e {
        skein_view::StoreError::BadQuery => NodeError::InvalidInput,
        _ => {
            warn!("mail database failed");
            NodeError::Storage
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn provider_errors_map_by_cause_not_by_text() {
        let tls_words = "TLS certificate STARTTLS plain without TLS".to_owned();
        let cases = [
            (MailError::Auth, NodeError::AuthFailed),
            (MailError::Tls("x".into()), NodeError::TlsFailed),
            (
                MailError::Network(tls_words.clone()),
                NodeError::ServerUnreachable,
            ),
            (
                MailError::Timeout(tls_words.clone()),
                NodeError::ServerUnreachable,
            ),
            (MailError::Insecure("x".into()), NodeError::InsecureRefused),
            (
                MailError::Config(tls_words.clone()),
                NodeError::InvalidInput,
            ),
            (MailError::Quota, NodeError::QuotaFull),
            (
                MailError::Refused(tls_words.clone()),
                NodeError::ServerRefused,
            ),
            (MailError::Protocol("x".into()), NodeError::ServerRefused),
            (MailError::MailboxNotFound, NodeError::ServerRefused),
            (
                MailError::Throttled {
                    retry_after: Some(Duration::from_secs(7)),
                },
                NodeError::Throttled {
                    retry_after_secs: Some(7),
                },
            ),
        ];
        for (error, kind) in cases {
            assert_eq!(mail(&error), kind, "{:?}", error.cause());
        }
        let cases = [
            (SendError::Auth("535 no".into()), NodeError::AuthFailed),
            (SendError::Tls("x".into()), NodeError::TlsFailed),
            (SendError::Insecure("x".into()), NodeError::InsecureRefused),
            (
                SendError::Unavailable(tls_words.clone()),
                NodeError::ServerUnreachable,
            ),
            (SendError::Timeout("x".into()), NodeError::ServerUnreachable),
            (
                SendError::Temporary(tls_words.clone()),
                NodeError::ServerUnreachable,
            ),
            (SendError::Invalid(tls_words), NodeError::InvalidInput),
            (SendError::TooLarge { limit: None }, NodeError::QuotaFull),
            (
                SendError::Throttled {
                    retry_after: Some(Duration::from_secs(3)),
                },
                NodeError::Throttled {
                    retry_after_secs: Some(3),
                },
            ),
        ];
        for (error, kind) in cases {
            assert_eq!(send(&error), kind, "{:?}", error.cause());
        }
        let e = mail(&MailError::Protocol("secret-canary in reply".into()));
        assert!(!format!("{e} {e:?}").contains("canary"));
    }
}
