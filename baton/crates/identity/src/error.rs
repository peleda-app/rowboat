/// Errors of identity, roster and pairing checks. None of them carries key material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    /// Bytes that are not a valid public key, signature or node id of a key.
    #[error("invalid key, signature or node id")]
    InvalidKey,
    /// A signature that does not verify.
    #[error("bad signature")]
    BadSignature,
    /// Bytes that do not decode into the expected structure.
    #[error("malformed data")]
    Malformed,
    /// A roster that breaks its own rules: no members, duplicates, a revoked member or a signer
    /// that is not a member.
    #[error("inconsistent roster")]
    InconsistentRoster,
    /// The signer or subject is not a member of the trusted roster.
    #[error("not a member")]
    NotMember,
    /// The key was revoked and can never be a member again.
    #[error("revoked")]
    Revoked,
    /// The key is already a member.
    #[error("already a member")]
    AlreadyMember,
    /// A roster whose epoch is not higher than the trusted one.
    #[error("stale roster epoch")]
    StaleEpoch,
    /// A roster or invite of another group.
    #[error("group mismatch")]
    GroupMismatch,
    /// A member that tries to remove itself; another member revokes it.
    #[error("a member cannot revoke itself")]
    SelfRevocation,
    /// An invite that was never issued, was already used or was cancelled.
    #[error("unknown or used invite")]
    UnknownInvite,
    /// An invite past its expiry.
    #[error("invite expired")]
    InviteExpired,
    /// A join request whose proof of the invite secret does not verify.
    #[error("bad invite proof")]
    BadProof,
}
