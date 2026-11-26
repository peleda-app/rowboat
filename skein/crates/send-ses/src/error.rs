//! What an SES error answer means for the sender.

use std::time::Duration;

use reqwest::StatusCode;
use reqwest::header::{HeaderMap, RETRY_AFTER};
use skein_send::SendError;

const ERROR_TYPE: &str = "x-amzn-errortype";

/// An error answer: its status, the SES error code, the service's text and any requested wait.
pub(crate) struct Failure {
    pub(crate) status: StatusCode,
    pub(crate) code: String,
    pub(crate) message: String,
    pub(crate) retry_after: Option<Duration>,
}

/// A `Retry-After` given in seconds; an HTTP date is ignored.
fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let seconds: u64 = headers
        .get(RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()?;
    Some(Duration::from_secs(seconds))
}

/// The bare error name from `x-amzn-ErrorType` (`Name:uri`) or a body `__type`
/// (`namespace#Name`).
fn bare(code: &str) -> String {
    let code = code.split(':').next().unwrap_or_default();
    code.rsplit('#')
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned()
}

pub(crate) async fn read_failure(response: reqwest::Response) -> Failure {
    let status = response.status();
    let headers = response.headers().clone();
    let body = crate::read_body(response).await;
    parse_failure(status, &headers, &body)
}

pub(crate) fn parse_failure(status: StatusCode, headers: &HeaderMap, body: &[u8]) -> Failure {
    let value: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    let field = |names: &[&str]| {
        names
            .iter()
            .find_map(|n| value.get(*n).and_then(serde_json::Value::as_str))
            .unwrap_or_default()
            .to_owned()
    };
    let header = headers
        .get(ERROR_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let code = if header.is_empty() {
        bare(&field(&["__type", "code", "Code"]))
    } else {
        bare(header)
    };
    Failure {
        status,
        code,
        message: field(&["message", "Message"]),
        retry_after: retry_after(headers),
    }
}

impl Failure {
    /// The sender's error for this answer. Texts that `Display` shows carry only the status and
    /// the SES code; the service's text, which may name addresses, goes only into
    /// [`SendError::Refused`].
    pub(crate) fn to_error(&self) -> SendError {
        let code = self.code.as_str();
        let status = self.status;
        let named = if code.is_empty() {
            status.to_string()
        } else {
            code.to_owned()
        };
        let refused = |smtp: u16| SendError::Refused {
            permanent: true,
            code: smtp,
            text: if self.message.is_empty() {
                named.clone()
            } else {
                format!("{named}: {}", self.message)
            },
        };
        match code {
            "TooManyRequestsException"
            | "ThrottlingException"
            | "Throttling"
            | "LimitExceededException" => {
                return SendError::Throttled {
                    retry_after: self.retry_after,
                };
            }
            "UnrecognizedClientException"
            | "InvalidSignatureException"
            | "SignatureDoesNotMatch"
            | "IncompleteSignature"
            | "IncompleteSignatureException"
            | "InvalidClientTokenId"
            | "ExpiredTokenException"
            | "ExpiredToken"
            | "MissingAuthenticationToken"
            | "MissingAuthenticationTokenException"
            | "NotAuthorized"
            | "AccessDeniedException"
            | "AccessDenied" => {
                return SendError::Auth(format!("Amazon SES refused the access key ({named})"));
            }
            "AccountSuspendedException"
            | "SendingPausedException"
            | "MailFromDomainNotVerifiedException"
            | "NotFoundException"
            | "OptInRequired" => {
                return SendError::Invalid(format!(
                    "the Amazon SES account cannot send as configured ({named})"
                ));
            }
            "MessageRejected" => return refused(554),
            "RequestEntityTooLargeException" => return SendError::TooLarge { limit: None },
            "RequestTimeoutException" | "RequestTimeout" | "RequestAbortedException" => {
                return SendError::Temporary(format!(
                    "Amazon SES did not get the whole request ({named})"
                ));
            }
            _ => {}
        }
        match status {
            StatusCode::TOO_MANY_REQUESTS => SendError::Throttled {
                retry_after: self.retry_after,
            },
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                SendError::Auth(format!("Amazon SES refused the access key ({named})"))
            }
            StatusCode::NOT_FOUND => SendError::Invalid(format!(
                "the Amazon SES account cannot send as configured ({named})"
            )),
            StatusCode::PAYLOAD_TOO_LARGE => SendError::TooLarge { limit: None },
            StatusCode::REQUEST_TIMEOUT => SendError::Temporary(format!(
                "Amazon SES did not get the whole request ({named})"
            )),
            s if s.is_server_error() => SendError::Uncertain(format!(
                "Amazon SES answered {named} after it had the message"
            )),
            _ => refused(554),
        }
    }
}
