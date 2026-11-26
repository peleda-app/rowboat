use skein_keyring::KeyringError;
use skein_storage::StorageError;

/// Why one request to an endpoint got no answer, or was never sent. Messages never hold the
/// address, the payload or the secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SendError {
    /// The address is not usable: not a URL, not `https`, has credentials, too long. Sending
    /// again gives the same answer.
    #[error("invalid address: {0}")]
    InvalidUrl(&'static str),
    /// The host is, or resolves to, an address the policy refuses (private, loopback,
    /// link-local, CGNAT, multicast, unspecified, reserved).
    #[error("address refused: {0}")]
    AddressRefused(&'static str),
    /// The host name did not resolve to any address.
    #[error("the host name does not resolve")]
    Unresolved,
    /// No answer within the timeout.
    #[error("no answer in time")]
    Timeout,
    /// The connection or TLS failed.
    #[error("the endpoint is unreachable")]
    Unreachable,
}

impl SendError {
    /// A short machine-readable kind: `invalid_url`, `address_refused`, `unresolved`,
    /// `timeout` or `unreachable`.
    pub fn kind(&self) -> &'static str {
        match self {
            SendError::InvalidUrl(_) => "invalid_url",
            SendError::AddressRefused(_) => "address_refused",
            SendError::Unresolved => "unresolved",
            SendError::Timeout => "timeout",
            SendError::Unreachable => "unreachable",
        }
    }
}

/// Errors of webhook configuration and delivery. Messages carry ids and kinds only.
#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    /// Storage failed or a record changed meanwhile ([`StorageError::Conflict`]).
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// The secret could not be sealed or opened.
    #[error(transparent)]
    Keyring(#[from] KeyringError),
    /// No endpoint with that id in the tenant.
    #[error("no such webhook")]
    NotFound,
    /// The request does not describe a valid endpoint; the text says which field.
    #[error("invalid webhook: {0}")]
    Invalid(&'static str),
    /// The address is refused by the policy or does not resolve.
    #[error(transparent)]
    Url(#[from] SendError),
    /// The HTTP client could not be built.
    #[error("the HTTP client could not be built")]
    Client,
    /// The system's random source failed.
    #[error("no random source")]
    Random,
}
