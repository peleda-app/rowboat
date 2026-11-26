//! Gmail `X-GM-LABELS` values as readable label names, and back.

use crate::{quote, utf7};

const SYSTEM: [(&str, &str); 7] = [
    ("Inbox", "\\Inbox"),
    ("Sent", "\\Sent"),
    ("Important", "\\Important"),
    ("Starred", "\\Starred"),
    ("Drafts", "\\Draft"),
    ("Trash", "\\Trash"),
    ("Spam", "\\Spam"),
];

/// Whether `name` can be sent as a label.
pub(crate) fn label_ok(name: &str) -> bool {
    !name.is_empty() && !name.chars().any(char::is_control)
}

/// One label for `STORE X-GM-LABELS`, the reverse of [`label_name`]: system labels by their
/// backslash name, others in modified UTF-7, always as a quoted string.
pub(crate) fn label_wire(name: &str) -> String {
    let raw = SYSTEM
        .iter()
        .find(|(readable, _)| *readable == name)
        .map_or_else(|| utf7::encode(name), |(_, system)| (*system).to_owned());
    quote(&raw)
}

/// The readable name of one `X-GM-LABELS` value as the IMAP parser returns it: still escaped
/// when it was a quoted string, and in modified UTF-7. System labels lose their backslash and
/// read as Gmail shows them.
pub(crate) fn label_name(raw: &str) -> String {
    let unescaped = unescape(raw);
    if let Some(system) = unescaped.strip_prefix('\\') {
        return match system.to_ascii_lowercase().as_str() {
            "inbox" => "Inbox".into(),
            "sent" => "Sent".into(),
            "important" => "Important".into(),
            "starred" => "Starred".into(),
            "draft" | "drafts" => "Drafts".into(),
            "trash" => "Trash".into(),
            "spam" => "Spam".into(),
            _ => system.to_owned(),
        };
    }
    utf7::decode(&unescaped)
}

/// Readable names of a message's labels, sorted and without duplicates or empty names.
pub(crate) fn label_names<'a>(raw: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut names: Vec<String> = raw
        .into_iter()
        .map(label_name)
        .filter(|name| !name.is_empty())
        .collect();
    names.sort();
    names.dedup();
    names
}

fn unescape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.clone().next() {
                Some(next @ ('\\' | '"')) => {
                    chars.next();
                    out.push(next);
                }
                _ => out.push(c),
            },
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_system_labels() {
        assert_eq!(label_name("\\Inbox"), "Inbox");
        assert_eq!(label_name("\\\\Important"), "Important");
        assert_eq!(label_name("\\\\Starred"), "Starred");
        assert_eq!(label_name("\\Sent"), "Sent");
        assert_eq!(label_name("\\Draft"), "Drafts");
        assert_eq!(label_name("\\Muted"), "Muted");
    }

    #[test]
    fn decodes_quoted_and_utf7_labels() {
        assert_eq!(label_name("Projects/2025"), "Projects/2025");
        assert_eq!(label_name(r#"Say \"hi\""#), r#"Say "hi""#);
        assert_eq!(label_name(r"back\\slash"), r"back\slash");
        assert_eq!(label_name("&BBIEMAQ2BD0EPgQ1-"), "Важное");
        assert_eq!(label_name("Fish &- Chips"), "Fish & Chips");
    }

    #[test]
    fn sends_labels_as_they_are_read() {
        assert_eq!(label_wire("Inbox"), r#""\\Inbox""#);
        assert_eq!(label_wire("Drafts"), r#""\\Draft""#);
        assert_eq!(
            label_wire("Projects/Важное"),
            r#""Projects/&BBIEMAQ2BD0EPgQ1-""#
        );
        assert_eq!(label_wire(r#"Say "hi""#), r#""Say \"hi\"""#);
        for name in [
            "Inbox",
            "Drafts",
            "Projects/Важное",
            "Fish & Chips",
            r#"Say "hi""#,
        ] {
            let wire = label_wire(name);
            assert_eq!(label_name(&wire[1..wire.len() - 1]), name);
        }
        assert!(!label_ok("") && !label_ok("a\r\nb") && label_ok("Work"));
    }

    #[test]
    fn sorts_and_dedups() {
        assert_eq!(
            label_names(["Work", "\\Inbox", "Work", ""]),
            ["Inbox", "Work"]
        );
    }
}
