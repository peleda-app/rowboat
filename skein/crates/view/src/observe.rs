/// Most mailboxes a [`PageReport`] names before it says [`Touched::Many`].
pub const MAX_TOUCHED: usize = 64;
/// Most command outcomes a [`PageReport`] carries; later ones in the same page are left out.
pub const MAX_OUTCOMES: usize = 1024;
/// Most added messages a [`PageReport`] names; later ones in the same page are only counted.
pub const MAX_ADDED: usize = 256;

/// One `message_added` event of a page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Added {
    /// The mailbox id.
    pub mailbox: String,
    /// The message (the hex hash of its original bytes).
    pub message: String,
    /// `\Seen` was set when it was seen.
    pub seen: bool,
}

/// Which mailboxes a page changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Touched {
    /// These mailboxes, sorted, at most [`MAX_TOUCHED`].
    Some(Vec<String>),
    /// More than [`MAX_TOUCHED`], or every mailbox (a rebuild).
    Many,
}

impl Default for Touched {
    fn default() -> Self {
        Self::Some(Vec::new())
    }
}

/// What became of a command, as the journal recorded it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeKind {
    /// `write_applied`.
    Applied,
    /// `write_failed`.
    Failed,
    /// `conflict`.
    Conflict,
    /// `write_uncertain`.
    Uncertain,
    /// `send_result`, with how many recipients were refused.
    Sent {
        /// Refused recipients.
        refused: u32,
    },
}

/// One command outcome in a page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutcome {
    /// The command id.
    pub command: String,
    /// What happened.
    pub kind: OutcomeKind,
    /// For failures, the reason as one word of `[a-z0-9_]` (at most 32 characters), else `other`.
    pub reason: Option<String>,
}

/// What one committed page (or rebuild) did to an account. Carries ids, counts and kinds only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PageReport {
    /// The account.
    pub account: String,
    /// The checkpoint after the page.
    pub checkpoint: u64,
    /// The journal head the follower was reading towards.
    pub head: u64,
    /// The page held `first_sync_completed`.
    pub first_sync_completed: bool,
    /// The page was a rebuild from a snapshot.
    pub rebuilt: bool,
    /// `message_added` events in the page.
    pub messages_added: usize,
    /// The first [`MAX_ADDED`] of them, in journal order.
    pub added: Vec<Added>,
    /// Mailboxes whose memberships or flags changed.
    pub mailboxes: Touched,
    /// Mailboxes were added, changed or removed.
    pub mailboxes_changed: bool,
    /// Command outcomes, in journal order.
    pub outcomes: Vec<CommandOutcome>,
}

/// Told about every committed page. Called from the follower's task after the commit, in
/// commit order; it must return quickly and never block on the follower.
pub trait ViewObserver: Send + Sync {
    /// A page (or a rebuild) was committed.
    fn page_applied(&self, report: &PageReport);
}

pub(crate) fn reason_word(reason: &str) -> String {
    let ok = !reason.is_empty()
        && reason.len() <= 32
        && reason
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if ok {
        reason.to_owned()
    } else {
        "other".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reasons_are_single_words_or_other() {
        assert_eq!(reason_word("no_trash"), "no_trash");
        assert_eq!(reason_word("mailbox gone: INBOX"), "other");
        assert_eq!(reason_word(""), "other");
        assert_eq!(reason_word(&"a".repeat(33)), "other");
    }
}
