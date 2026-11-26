//! The sending contract.
//!
//! Skein is not an MTA: it never delivers to recipient hosts. A [`Sender`] hands the exact bytes
//! of a message, with an explicit [`Envelope`], to the account's sending service (SMTP submission,
//! the Gmail API, Microsoft Graph, JMAP), which signs, queues and delivers it.
//!
//! The one distinction every caller depends on is whether a failed send may have reached the
//! service: [`SendError::may_have_been_sent`] is true only for [`SendError::Uncertain`], and every
//! other error guarantees that nothing was sent, so sending again cannot deliver twice.

use std::time::Duration;

use async_trait::async_trait;
use skein_core::Dsn;

#[cfg(feature = "testing")]
pub mod testing;

/// Who a message is from and who it goes to, separate from its headers.
///
/// Bcc recipients are in `recipients` and never in the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// The return path (`MAIL FROM`) that bounces go to. Empty is the null return path `<>`.
    pub mail_from: String,
    /// Every recipient (`RCPT TO`), in the order they are offered to the service.
    pub recipients: Vec<String>,
    /// Delivery status notifications to ask for. Services that do not offer them ignore it.
    pub dsn: Option<Dsn>,
    /// An id for the transmission, returned in delivery status notifications (`ENVID`). Only
    /// printable ASCII is sent; services without notifications ignore it.
    pub envid: Option<String>,
}

impl Envelope {
    /// An envelope from `mail_from` to `recipients`, without notifications.
    pub fn new(mail_from: impl Into<String>, recipients: Vec<String>) -> Self {
        Self {
            mail_from: mail_from.into(),
            recipients,
            dsn: None,
            envid: None,
        }
    }

    /// Checks the envelope and the message against what every [`Sender`] accepts, so a caller
    /// can refuse a message before handing it over.
    ///
    /// Fails with [`SendError::Invalid`] when there is no recipient, when an address is empty
    /// (other than the null return path), has no `@`, or holds whitespace, control characters or
    /// angle brackets, when `envid` holds anything but printable ASCII, and when the message is
    /// empty, holds a NUL, a `CR` or `LF` outside a `CRLF` pair, or does not end with `CRLF`.
    pub fn validate(&self, message: &[u8]) -> Result<(), SendError> {
        if self.recipients.is_empty() {
            return Err(SendError::Invalid("the envelope has no recipient".into()));
        }
        if !self.mail_from.is_empty() && !valid_address(&self.mail_from) {
            return Err(SendError::Invalid(
                "the return path is not an address".into(),
            ));
        }
        if let Some(at) = self.recipients.iter().position(|r| !valid_address(r)) {
            return Err(SendError::Invalid(format!(
                "recipient {} is not an address",
                at + 1
            )));
        }
        if self.envid.as_deref().is_some_and(|id| {
            id.is_empty() || id.len() > 100 || !id.bytes().all(|b| b.is_ascii_graphic())
        }) {
            return Err(SendError::Invalid(
                "the envelope id is not printable ASCII".into(),
            ));
        }
        if message.is_empty() {
            return Err(SendError::Invalid("the message is empty".into()));
        }
        if !message.ends_with(b"\r\n") {
            return Err(SendError::Invalid(
                "the message does not end with CRLF".into(),
            ));
        }
        let mut previous = 0u8;
        for (at, &byte) in message.iter().enumerate() {
            let bare_cr = previous == b'\r' && byte != b'\n';
            let bare_lf = byte == b'\n' && previous != b'\r';
            if byte == 0 || bare_cr || bare_lf {
                return Err(SendError::Invalid(format!(
                    "the message has a NUL or a bare CR or LF at byte {at}"
                )));
            }
            previous = byte;
        }
        Ok(())
    }
}

fn valid_address(address: &str) -> bool {
    address.contains('@')
        && !address
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '<' || c == '>')
}

/// What the service answered to a refused recipient or message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// `true` when the service said not to try again (an SMTP `5xx`), `false` for a temporary
    /// refusal (`4xx`).
    pub permanent: bool,
    /// The SMTP reply code, or the closest SMTP code for services that do not speak SMTP.
    pub code: u16,
    /// The service's text, with its enhanced status code when it gave one. It may name
    /// addresses: never log it.
    pub text: String,
}

/// What became of one recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipientOutcome {
    /// The service took the message for this recipient.
    Accepted,
    /// The service refused this recipient; the message did not go to it.
    Refused(Refusal),
}

/// One recipient of the envelope and what became of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientResult {
    /// The address as it was in the envelope.
    pub address: String,
    /// Whether the service took the message for it.
    pub outcome: RecipientOutcome,
}

/// The result of a message the service took.
///
/// New fields may be added; build one with [`SendReport::new`] or [`SendReport::all_accepted`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SendReport {
    /// One entry per envelope recipient, in envelope order. At least one is accepted.
    pub recipients: Vec<RecipientResult>,
    /// The `Message-ID` recipients get when the service replaced the message's own, as the
    /// header value with its angle brackets (`<id@host>`). `None` means the service keeps the
    /// message's own `Message-ID`, or the sender cannot know what it delivered.
    pub message_id: Option<String>,
    /// The service's own id for the message (an SES `MessageId`, a Gmail message id, a JMAP
    /// submission id), for matching later notifications from the service. `None` when the
    /// service gave none. It is not a `Message-ID` and is never shown to recipients.
    pub provider_message_id: Option<String>,
}

impl SendReport {
    /// A report with these recipient results and no ids.
    pub fn new(recipients: Vec<RecipientResult>) -> Self {
        Self {
            recipients,
            message_id: None,
            provider_message_id: None,
        }
    }

    /// A report in which the service took every recipient of `envelope`.
    pub fn all_accepted(envelope: &Envelope) -> Self {
        Self::new(
            envelope
                .recipients
                .iter()
                .map(|address| RecipientResult {
                    address: address.clone(),
                    outcome: RecipientOutcome::Accepted,
                })
                .collect(),
        )
    }

    /// Says recipients got `message_id` (`<id@host>`) instead of the message's own `Message-ID`.
    pub fn with_message_id(mut self, message_id: impl Into<String>) -> Self {
        self.message_id = Some(message_id.into());
        self
    }

    /// Records the service's own id for the message.
    pub fn with_provider_message_id(mut self, id: impl Into<String>) -> Self {
        self.provider_message_id = Some(id.into());
        self
    }

    /// The recipients the service refused.
    pub fn refused(&self) -> impl Iterator<Item = (&str, &Refusal)> {
        refused(&self.recipients)
    }
}

fn refused(results: &[RecipientResult]) -> impl Iterator<Item = (&str, &Refusal)> {
    results.iter().filter_map(|r| match &r.outcome {
        RecipientOutcome::Refused(refusal) => Some((r.address.as_str(), refusal)),
        RecipientOutcome::Accepted => None,
    })
}

/// What a sending service has said about itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Limits {
    /// The largest message the service takes, in bytes, when it said so.
    pub max_size: Option<u64>,
    /// The service takes internationalized addresses (RFC 6531). False when it did not say so.
    pub smtputf8: bool,
    /// The service honors [`Envelope::dsn`]. False when it did not say so.
    pub dsn: bool,
}

/// Why a message was not handed over.
///
/// Every error except [`SendError::Uncertain`] guarantees the service did not take the message
/// for any recipient, so sending it again cannot deliver it twice. [`SendError::is_retryable`]
/// tells which of those are worth trying again later without a change.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SendError {
    /// The service refused the credentials, or signing in is not possible with them.
    #[error("authentication failed: {0}")]
    Auth(String),
    /// The service refused the whole message.
    #[error("refused ({code})")]
    Refused {
        /// `true` for a permanent refusal (`5xx`), `false` for a temporary one (`4xx`).
        permanent: bool,
        /// The SMTP reply code or its closest equivalent.
        code: u16,
        /// The service's text. It may name addresses: never log it.
        text: String,
    },
    /// The service refused every recipient, so nothing was sent.
    #[error("every recipient was refused")]
    RecipientsRefused(Vec<RecipientResult>),
    /// The exchange broke before the message was complete: the service cannot have taken it.
    #[error("temporary failure: {0}")]
    Temporary(String),
    /// The service refused the message because too many requests reached it (an HTTP `429`, or
    /// a `503` the service marked as throttling) before it took the message, so nothing was
    /// sent. `retry_after` is the wait the service asked for, when it named one; a caller should
    /// not try again sooner.
    #[error("throttled by the service")]
    Throttled {
        /// The service's requested wait (`Retry-After`), when it gave one.
        retry_after: Option<Duration>,
    },
    /// The connection was lost after the whole message was sent and before the service
    /// answered, or the answer did not say whether it took the message. It may have been
    /// delivered; it must not be sent again on its own.
    #[error("the outcome is unknown: {0}")]
    Uncertain(String),
    /// The message is larger than the service takes.
    #[error("the message is too large")]
    TooLarge {
        /// The service's limit in bytes, when it said one.
        limit: Option<u64>,
    },
    /// The envelope, the message or the configuration cannot be sent as it is.
    #[error("invalid: {0}")]
    Invalid(String),
    /// The service could not be reached, or would not start a session (connection refused, TLS
    /// failure, a `421` greeting).
    #[error("unavailable: {0}")]
    Unavailable(String),
}

impl SendError {
    /// Whether the same message may go through later without a change: temporary refusals,
    /// broken exchanges, unreachable services, and recipient refusals of which at least one is
    /// temporary. Never true for [`SendError::Uncertain`].
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Refused { permanent, .. } => !permanent,
            Self::RecipientsRefused(results) => refused(results).any(|(_, r)| !r.permanent),
            Self::Temporary(_) | Self::Throttled { .. } | Self::Unavailable(_) => true,
            Self::Auth(_) | Self::Uncertain(_) | Self::TooLarge { .. } | Self::Invalid(_) => false,
        }
    }

    /// The wait the service asked for before the next try: only for [`SendError::Throttled`]
    /// with a `Retry-After`. `None` means the service named no delay (SMTP never does), and the
    /// caller picks its own.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Throttled { retry_after } => *retry_after,
            _ => None,
        }
    }

    /// Whether the service may have taken the message: only for [`SendError::Uncertain`].
    pub fn may_have_been_sent(&self) -> bool {
        matches!(self, Self::Uncertain(_))
    }

    /// A short machine-readable reason that never holds an address or server text: `auth`,
    /// `refused`, `recipients_refused`, `temporary`, `throttled`, `uncertain`, `too_large`,
    /// `invalid` or `unavailable`.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Auth(_) => "auth",
            Self::Refused { .. } => "refused",
            Self::RecipientsRefused(_) => "recipients_refused",
            Self::Temporary(_) => "temporary",
            Self::Throttled { .. } => "throttled",
            Self::Uncertain(_) => "uncertain",
            Self::TooLarge { .. } => "too_large",
            Self::Invalid(_) => "invalid",
            Self::Unavailable(_) => "unavailable",
        }
    }
}

/// Hands prebuilt messages to one sending service.
///
/// Implementations are safe to share between tasks; concurrent calls do not interfere.
#[async_trait]
pub trait Sender: Send + Sync {
    /// Connects and signs in without sending anything, and returns what the service said about
    /// itself.
    async fn check(&self) -> Result<Limits, SendError>;

    /// Hands `message` to the service for the recipients in `envelope`.
    ///
    /// - **At most once.** One call offers the message to the service at most once and never
    ///   retries on its own, so a message is never delivered twice by one call.
    /// - **Bytes unchanged.** The service receives exactly `message`, except that a service which
    ///   takes recipients only from the header (Gmail, Graph) receives one added `Bcc` field
    ///   naming the envelope recipients the header does not; line endings are not touched.
    /// - Inputs that fail [`Envelope::validate`] are refused with [`SendError::Invalid`] before
    ///   connecting. A message larger than a limit the service announced is refused with
    ///   [`SendError::TooLarge`] before it is sent.
    /// - `Ok` means the service took the message for at least one recipient; the report says what
    ///   became of each. When the service replaces the message's `Message-ID` and the sender
    ///   knows the new one, [`SendReport::message_id`] holds it; otherwise it is `None`. When every recipient is refused nothing is sent and the result is
    ///   [`SendError::RecipientsRefused`].
    /// - Errors other than [`SendError::Uncertain`] mean nothing was sent.
    async fn send(&self, envelope: &Envelope, message: &[u8]) -> Result<SendReport, SendError>;

    /// Whether the service keeps a copy of every message it takes in the account's Sent mailbox
    /// by itself, so the caller must not append one.
    fn saves_to_sent(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> Envelope {
        Envelope::new("ada@example.com", vec!["bob@example.org".into()])
    }

    #[test]
    fn validates_envelopes_and_line_endings() {
        let good = b"Subject: Hi\r\n\r\nHello\r\n";
        assert_eq!(envelope().validate(good), Ok(()));
        let null = Envelope {
            mail_from: String::new(),
            ..envelope()
        };
        assert_eq!(null.validate(good), Ok(()));

        let invalid = |e: &Envelope, m: &[u8]| matches!(e.validate(m), Err(SendError::Invalid(_)));
        let none = Envelope {
            recipients: vec![],
            ..envelope()
        };
        assert!(invalid(&none, good));
        for bad in [
            "bob",
            "bob @example.org",
            "<bob@example.org>",
            "bob@example.org\r\nRCPT",
        ] {
            let e = Envelope {
                recipients: vec![bad.into()],
                ..envelope()
            };
            assert!(invalid(&e, good), "{bad:?} passed");
        }
        let envid = Envelope {
            envid: Some("a b".into()),
            ..envelope()
        };
        assert!(invalid(&envid, good));
        assert!(invalid(&envelope(), b""));
        assert!(invalid(&envelope(), b"Subject: Hi\r\n\r\nHello"));
        assert!(invalid(&envelope(), b"Subject: Hi\n\nHello\r\n"));
        assert!(invalid(&envelope(), b"Subject: Hi\r\n\r\nA\rB\r\n"));
        assert!(invalid(&envelope(), b"Subject: Hi\r\n\r\nA\0B\r\n"));
    }

    #[test]
    fn tells_which_errors_may_be_retried() {
        let refusal = |permanent| Refusal {
            permanent,
            code: if permanent { 550 } else { 450 },
            text: String::new(),
        };
        let refused = |permanent| {
            SendError::RecipientsRefused(vec![RecipientResult {
                address: "bob@example.org".into(),
                outcome: RecipientOutcome::Refused(refusal(permanent)),
            }])
        };
        assert!(refused(false).is_retryable());
        assert!(!refused(true).is_retryable());
        assert!(SendError::Temporary(String::new()).is_retryable());
        assert!(!SendError::Uncertain(String::new()).is_retryable());
        assert!(SendError::Uncertain(String::new()).may_have_been_sent());
        assert!(!SendError::Temporary(String::new()).may_have_been_sent());
        assert!(
            SendError::Refused {
                permanent: false,
                code: 451,
                text: String::new()
            }
            .is_retryable()
        );
        assert_eq!(refused(true).reason(), "recipients_refused");
        let throttled = SendError::Throttled {
            retry_after: Some(Duration::from_secs(30)),
        };
        assert!(throttled.is_retryable());
        assert!(!throttled.may_have_been_sent());
        assert_eq!(throttled.retry_after(), Some(Duration::from_secs(30)));
        assert_eq!(throttled.reason(), "throttled");
        assert_eq!(SendError::Temporary(String::new()).retry_after(), None);
    }

    #[test]
    fn refusal_text_stays_out_of_messages() {
        let e = SendError::Refused {
            permanent: true,
            code: 550,
            text: "5.1.1 <bob@example.org> unknown".into(),
        };
        assert!(!e.to_string().contains("bob"));
    }
}
