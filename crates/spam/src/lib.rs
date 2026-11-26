//! The node's spam hook: a verdict for one message as rinse rendered it.
//!
//! Synchronous and CPU-bound: a filter never sees raw bytes, never reaches the network and never
//! panics on a hostile [`Rendered`]. Implementations run [`testing::filter`].

use rinse_mail::Rendered;

#[cfg(feature = "testing")]
pub mod testing;

/// What a filter sees of one message.
#[derive(Debug, Clone, Copy)]
pub struct SpamInput<'a> {
    /// The message as rinse rendered and the node verified it.
    pub rendered: &'a Rendered,
    /// The account id.
    pub account: &'a str,
    /// The provider placed the message in a mailbox with the junk role.
    pub in_junk: bool,
    /// Domains whose servers receive mail for the account; a filter trusts authentication
    /// results only from an authserv-id that is one of them or under one of them.
    pub receivers: &'a [String],
}

/// A spam verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpamVerdict {
    /// Nothing points at spam.
    Clean,
    /// Signals point at spam or forgery; shown as a warning, never acted on alone.
    Suspicious,
    /// Spam.
    Junk,
    /// The filter could not judge (no signals).
    NotChecked,
}

impl SpamVerdict {
    /// The tag the node stores for the verdict: `spam.junk`, `spam.suspicious`, or none.
    pub fn tag(self) -> Option<&'static str> {
        match self {
            Self::Junk => Some("spam.junk"),
            Self::Suspicious => Some("spam.suspicious"),
            Self::Clean | Self::NotChecked => None,
        }
    }
}

/// Judges one message.
///
/// Guarantees: equal input gives an equal verdict; never panics, never blocks on I/O; a change
/// that may change any verdict changes [`SpamFilter::version`].
pub trait SpamFilter: Send + Sync {
    /// The verdict for `input`.
    fn verdict(&self, input: &SpamInput<'_>) -> SpamVerdict;

    /// The filter's version: 1 to 64 characters of `[a-z0-9._-]`.
    fn version(&self) -> String;
}

/// Whether `version` has the shape every hook version must have.
pub fn valid_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 64
        && version.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_and_versions() {
        assert_eq!(SpamVerdict::Junk.tag(), Some("spam.junk"));
        assert_eq!(SpamVerdict::Suspicious.tag(), Some("spam.suspicious"));
        assert_eq!(SpamVerdict::Clean.tag(), None);
        assert!(valid_version("signals-1"));
        assert!(!valid_version("Signals 1"));
        assert!(!valid_version(""));
    }
}
