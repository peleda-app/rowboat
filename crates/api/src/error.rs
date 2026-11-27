use serde::{Deserialize, Serialize};

/// Why a node call failed. Kinds only: never a provider's text, an address, a subject, a path or
/// a secret, in `Display`, `Debug` or the serialized form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NodeError {
    /// The request breaks a rule of this contract.
    #[error("invalid input")]
    InvalidInput,
    /// The account, mailbox, thread, message, draft or command does not exist.
    #[error("not found")]
    NotFound,
    /// An account for this address already exists.
    #[error("the account already exists")]
    AccountExists,
    /// The provider refused the credentials.
    #[error("authentication failed")]
    AuthFailed,
    /// The server could not be reached or the connection broke.
    #[error("server unreachable")]
    ServerUnreachable,
    /// The TLS handshake or certificate check failed.
    #[error("TLS failed")]
    TlsFailed,
    /// The settings would send credentials without encryption.
    #[error("insecure connection refused")]
    InsecureRefused,
    /// The server answered with a refusal or something the node does not understand.
    #[error("the server refused")]
    ServerRefused,
    /// The provider is limiting requests.
    #[error("throttled")]
    Throttled {
        /// How long the provider asked to wait, when it said.
        retry_after_secs: Option<u64>,
    },
    /// The account has no way to send mail.
    #[error("the account cannot send")]
    NoSender,
    /// The account has no archive mailbox.
    #[error("the account has no archive mailbox")]
    NoArchive,
    /// The account has no trash mailbox.
    #[error("the account has no trash mailbox")]
    NoTrash,
    /// A limit of the node or the provider is reached.
    #[error("quota full")]
    QuotaFull,
    /// The original bytes are not available.
    #[error("unavailable")]
    Unavailable,
    /// The command already started and can no longer be cancelled.
    #[error("already started")]
    AlreadyStarted,
    /// The node's storage failed.
    #[error("storage failed")]
    Storage,
    /// The node's keys are missing or do not open its data.
    #[error("the node's keys are lost")]
    KeysLost,
    /// The node is busy with this account (removal in progress, too many calls).
    #[error("busy")]
    Busy,
    /// A pairing code the other node did not accept: wrong, used up, withdrawn, unknown to it or
    /// expired there. The joining side cannot tell these apart, by design.
    #[error("pairing code rejected")]
    PairingCodeRejected,
    /// The invite expired before it was used.
    #[error("pairing expired")]
    PairingExpired,
    /// The other side refused the pairing after the code was accepted: the person there said the
    /// fingerprints differ or did not answer in time, or that node would not take this one.
    #[error("pairing refused")]
    PairingRefused,
    /// This node may not do this: it holds no member key, or the group log does not allow it.
    #[error("forbidden")]
    Forbidden,
    /// The other node (a device or a server) could not be reached.
    #[error("peer unreachable")]
    PeerUnreachable,
    /// Anything else.
    #[error("internal error")]
    Internal,
}
