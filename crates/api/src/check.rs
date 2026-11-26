//! The pure checks every caller and the node run on requests.

use crate::NodeError;
use crate::ids::is_ulid;
use crate::types::{
    AccountPatch, AccountSetup, Draft, ListQuery, MAX_ATTACHMENT_BYTES, MAX_ATTACHMENTS,
    MAX_NAME_CHARS, MAX_PAGE, MAX_QUERY_CHARS, MAX_RECIPIENTS, MAX_SKIPPED, MAX_SUBJECT_CHARS,
    MAX_SUGGESTIONS, MAX_TARGETS, MAX_TEXT_BYTES, SearchQuery, Targets,
};

/// Whether `text` is one line of at most `max` characters: no control character.
pub fn one_line(text: &str, max: usize) -> bool {
    text.chars().count() <= max && !text.chars().any(char::is_control)
}

/// The longest id [`header_id`] accepts: `In-Reply-To: <id>` still fits a 998-byte line.
pub const MAX_HEADER_ID: usize = 980;

/// Whether `id` is a `Message-ID` value without brackets: 1 to [`MAX_HEADER_ID`] printable
/// ASCII characters, no space, `<`, `>` or `"`.
pub fn header_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_HEADER_ID
        && id
            .bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'<' | b'>' | b'"'))
}

fn ok(cond: bool) -> Result<(), NodeError> {
    if cond {
        Ok(())
    } else {
        Err(NodeError::InvalidInput)
    }
}

/// A new account's setup.
pub fn setup(s: &AccountSetup) -> Result<(), NodeError> {
    ok(s.display_name
        .as_deref()
        .is_none_or(|n| one_line(n, MAX_NAME_CHARS)))?;
    ok(!s.username.is_empty() && s.username.len() <= 320 && one_line(&s.username, 320))?;
    ok(s.imap.is_valid() && s.smtp.is_valid())
}

/// A password: 1 to 4,096 bytes of UTF-8 without NUL, CR or LF.
pub fn password(secret: &rowboat_keystore::Secret) -> Result<(), NodeError> {
    let text = secret.expose_str().ok_or(NodeError::InvalidInput)?;
    ok(!text.is_empty() && text.len() <= 4096 && !text.contains(['\0', '\r', '\n']))
}

/// An account patch.
pub fn patch(p: &AccountPatch) -> Result<(), NodeError> {
    ok(p.display_name
        .as_ref()
        .is_none_or(|n| n.as_deref().is_none_or(|n| one_line(n, MAX_NAME_CHARS))))?;
    ok(p.skip_mailboxes
        .as_ref()
        .is_none_or(|m| m.len() <= MAX_SKIPPED))
}

/// A list query.
pub fn list(q: &ListQuery) -> Result<(), NodeError> {
    ok((1..=MAX_PAGE).contains(&q.limit))
}

/// Targets: 1 to [`MAX_TARGETS`], no repeats.
pub fn targets(t: &Targets) -> Result<(), NodeError> {
    ok(!t.0.is_empty() && t.0.len() <= MAX_TARGETS)?;
    let mut seen = std::collections::BTreeSet::new();
    ok(t.0
        .iter()
        .all(|r| seen.insert((r.account.as_str(), r.message.as_str()))))
}

/// Targets that must all be of one account (moves).
pub fn targets_of_one_account(t: &Targets) -> Result<(), NodeError> {
    targets(t)?;
    let first = &t.0[0].account;
    ok(t.0.iter().all(|r| &r.account == first))
}

/// A draft as saved: every limit, any number of recipients from zero.
pub fn draft(d: &Draft) -> Result<(), NodeError> {
    ok(d.id.as_ref().is_none_or(|i| is_ulid(i.as_str())))?;
    let recipients = d.to.len() + d.cc.len() + d.bcc.len();
    ok(recipients <= MAX_RECIPIENTS)?;
    ok(d.to.iter().chain(&d.cc).chain(&d.bcc).all(|r| {
        r.name
            .as_deref()
            .is_none_or(|n| one_line(n, MAX_NAME_CHARS))
    }))?;
    ok(one_line(&d.subject, MAX_SUBJECT_CHARS))?;
    ok(d.text.len() <= MAX_TEXT_BYTES && !d.text.contains('\0'))?;
    if let Some(reply) = &d.reply {
        ok(header_id(&reply.message_id))?;
        ok(reply.references.len() <= 32 && reply.references.iter().all(|r| header_id(r)))?;
    }
    ok(d.attachments.len() <= MAX_ATTACHMENTS)?;
    let mut total = 0usize;
    for a in &d.attachments {
        ok(!a.name.trim().is_empty()
            && one_line(&a.name, MAX_NAME_CHARS)
            && !a.name.contains(['/', '\\']))?;
        total = total.saturating_add(a.bytes.len());
    }
    ok(total <= MAX_ATTACHMENT_BYTES)
}

/// A draft about to be sent: [`draft`] and at least one recipient.
pub fn sendable(d: &Draft) -> Result<(), NodeError> {
    draft(d)?;
    ok(d.to.len() + d.cc.len() + d.bcc.len() > 0)
}

/// A search query.
pub fn search(q: &SearchQuery) -> Result<(), NodeError> {
    ok((1..=MAX_PAGE).contains(&q.limit))?;
    ok(!q.text.trim().is_empty() && one_line(&q.text, MAX_QUERY_CHARS))?;
    ok(q.filter.mailbox.is_none() || q.account.is_some())
}

/// An address prefix and limit for suggestions.
pub fn suggest(prefix: &str, limit: u32) -> Result<(), NodeError> {
    ok(!prefix.is_empty() && prefix.chars().count() <= 64 && one_line(prefix, 64))?;
    ok((1..=MAX_SUGGESTIONS).contains(&limit))
}
