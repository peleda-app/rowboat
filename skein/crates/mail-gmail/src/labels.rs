//! Gmail labels as mailboxes, flags and label names.

use std::collections::HashMap;

use serde::Deserialize;
use skein_core::{Flags, MailboxInfo, MailboxRole};

use crate::ALL;

pub(crate) const INBOX: &str = "INBOX";
pub(crate) const TRASH: &str = "TRASH";
pub(crate) const SPAM: &str = "SPAM";
pub(crate) const UNREAD: &str = "UNREAD";
pub(crate) const STARRED: &str = "STARRED";
pub(crate) const DRAFT: &str = "DRAFT";

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Label {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
}

#[derive(Default, Deserialize)]
pub(crate) struct LabelList {
    #[serde(default)]
    pub labels: Vec<Label>,
}

/// System labels shown as mailboxes: id, readable name, role, whether it is a label mailbox.
const SYSTEM: &[(&str, &str, Option<MailboxRole>, bool)] = &[
    (INBOX, "Inbox", Some(MailboxRole::Inbox), true),
    ("SENT", "Sent", Some(MailboxRole::Sent), true),
    (DRAFT, "Drafts", Some(MailboxRole::Drafts), true),
    ("IMPORTANT", "Important", None, true),
    (TRASH, "Trash", Some(MailboxRole::Trash), false),
    (SPAM, "Spam", Some(MailboxRole::Junk), false),
];

/// Readable names of system labels in message label lists, as Gmail's IMAP shows them.
fn system_name(id: &str) -> Option<&'static str> {
    Some(match id {
        INBOX => "Inbox",
        "SENT" => "Sent",
        DRAFT => "Drafts",
        "IMPORTANT" => "Important",
        TRASH => "Trash",
        SPAM => "Spam",
        "CHAT" => "Chat",
        _ => return None,
    })
}

/// The label id for a name as [`names`] reports it: a system label by its readable name, a user
/// label by name, any other label by id.
pub(crate) fn id_for(name: &str, labels: &HashMap<String, Label>) -> Option<String> {
    const READABLE: &[&str] = &[INBOX, "SENT", DRAFT, "IMPORTANT", TRASH, SPAM, "CHAT"];
    if let Some(id) = READABLE.iter().find(|id| system_name(id) == Some(name)) {
        return Some((*id).to_owned());
    }
    if let Some(l) = labels.values().find(|l| is_user(l) && l.name == name) {
        return Some(l.id.clone());
    }
    labels
        .get(name)
        .filter(|l| is_named_label(&l.id))
        .map(|l| l.id.clone())
}

/// Whether a path is taken: by a user label (Gmail compares names without case) or by a system
/// mailbox's path.
pub(crate) fn path_taken(path: &str, labels: &HashMap<String, Label>) -> bool {
    let same = |a: &str| a.eq_ignore_ascii_case(path);
    same("All Mail")
        || SYSTEM.iter().any(|(id, name, ..)| same(name) || same(id))
        || labels.values().any(|l| is_user(l) && same(&l.name))
}

pub(crate) fn is_user(label: &Label) -> bool {
    label.kind.as_deref() == Some("user")
}

/// `ALL`, `TRASH` and `SPAM`, which exist in every account.
pub(crate) fn is_builtin(mailbox: &str) -> bool {
    matches!(mailbox, ALL | TRASH | SPAM)
}

/// Whether a label is shown as a mailbox.
pub(crate) fn is_mailbox(label: &Label) -> bool {
    is_user(label) || SYSTEM.iter().any(|(id, ..)| *id == label.id)
}

/// Whether a label id looks like a user label, whose name comes from the label list.
pub(crate) fn needs_name(id: &str) -> bool {
    id.starts_with("Label_")
}

/// Every mailbox: `ALL` first, then the system mailboxes, then user labels by path.
pub(crate) fn mailboxes(labels: &HashMap<String, Label>) -> Vec<MailboxInfo> {
    let mut out = vec![MailboxInfo {
        id: ALL.into(),
        path: "All Mail".into(),
        role: Some(MailboxRole::All),
        selectable: true,
        label: false,
    }];
    for (id, name, role, label) in SYSTEM {
        let always = matches!(*id, INBOX | "SENT" | DRAFT | TRASH | SPAM);
        if always || labels.contains_key(*id) {
            out.push(MailboxInfo {
                id: (*id).into(),
                path: (*name).into(),
                role: *role,
                selectable: true,
                label: *label,
            });
        }
    }
    let mut user: Vec<MailboxInfo> = labels
        .values()
        .filter(|l| is_user(l))
        .map(|l| MailboxInfo {
            id: l.id.clone(),
            path: if l.name.is_empty() {
                l.id.clone()
            } else {
                l.name.clone()
            },
            role: None,
            selectable: true,
            label: true,
        })
        .collect();
    user.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.id.cmp(&b.id)));
    out.extend(user);
    out
}

/// Whether a message with these labels is in `mailbox`. Label mailboxes, like `messages.list`
/// without `includeSpamTrash`, leave out messages in Spam or Trash.
pub(crate) fn member(mailbox: &str, label_ids: &[String]) -> bool {
    let has = |l: &str| label_ids.iter().any(|x| x == l);
    match mailbox {
        TRASH => has(TRASH),
        SPAM => has(SPAM),
        _ if has(TRASH) || has(SPAM) => false,
        ALL => true,
        label => has(label),
    }
}

/// Flags from labels: no `UNREAD` is `\Seen`, `STARRED` is `\Flagged`, `DRAFT` is `\Draft`.
pub(crate) fn flags(label_ids: &[String]) -> Flags {
    let has = |l: &str| label_ids.iter().any(|x| x == l);
    let mut f = Vec::new();
    if !has(UNREAD) {
        f.push("\\Seen");
    }
    if has(STARRED) {
        f.push("\\Flagged");
    }
    if has(DRAFT) {
        f.push("\\Draft");
    }
    Flags::new(f)
}

/// Whether a label change shows in the flags.
pub(crate) fn is_flag_label(id: &str) -> bool {
    matches!(id, UNREAD | STARRED | DRAFT)
}

/// Whether a label change shows in the label names.
pub(crate) fn is_named_label(id: &str) -> bool {
    !matches!(id, UNREAD | STARRED)
}

/// Readable names of a message's labels, sorted and without repeats: system labels as Gmail's
/// IMAP names them, user labels by name, anything else (categories, unknown ids) by id.
/// `UNREAD` and `STARRED` are flags and left out.
pub(crate) fn names(label_ids: &[String], labels: &HashMap<String, Label>) -> Vec<String> {
    let mut out: Vec<String> = label_ids
        .iter()
        .filter(|id| is_named_label(id))
        .map(|id| {
            if let Some(name) = system_name(id) {
                return name.to_owned();
            }
            match labels.get(id) {
                Some(l) if is_user(l) && !l.name.is_empty() => l.name.clone(),
                _ => id.clone(),
            }
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn label(id: &str, name: &str, kind: &str) -> Label {
        Label {
            id: id.into(),
            name: name.into(),
            kind: Some(kind.into()),
        }
    }

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    fn map() -> HashMap<String, Label> {
        [
            label("INBOX", "INBOX", "system"),
            label("SENT", "SENT", "system"),
            label("IMPORTANT", "IMPORTANT", "system"),
            label("UNREAD", "UNREAD", "system"),
            label("STARRED", "STARRED", "system"),
            label("CHAT", "CHAT", "system"),
            label("CATEGORY_SOCIAL", "CATEGORY_SOCIAL", "system"),
            label("Label_2", "Projects/2025", "user"),
            label("Label_1", "Receipts", "user"),
        ]
        .into_iter()
        .map(|l| (l.id.clone(), l))
        .collect()
    }

    #[test]
    fn maps_labels_to_mailboxes() {
        let boxes = mailboxes(&map());
        let view: Vec<(&str, &str, Option<MailboxRole>, bool)> = boxes
            .iter()
            .map(|b| (b.id.as_str(), b.path.as_str(), b.role, b.label))
            .collect();
        assert_eq!(
            view,
            vec![
                ("ALL", "All Mail", Some(MailboxRole::All), false),
                ("INBOX", "Inbox", Some(MailboxRole::Inbox), true),
                ("SENT", "Sent", Some(MailboxRole::Sent), true),
                ("DRAFT", "Drafts", Some(MailboxRole::Drafts), true),
                ("IMPORTANT", "Important", None, true),
                ("TRASH", "Trash", Some(MailboxRole::Trash), false),
                ("SPAM", "Spam", Some(MailboxRole::Junk), false),
                ("Label_2", "Projects/2025", None, true),
                ("Label_1", "Receipts", None, true),
            ]
        );
        assert!(boxes.iter().all(|b| b.selectable));
    }

    #[test]
    fn membership_and_flags() {
        assert!(member(ALL, &ids(&["INBOX", "UNREAD"])));
        assert!(member(ALL, &ids(&[])));
        assert!(!member(ALL, &ids(&["TRASH"])));
        assert!(!member(ALL, &ids(&["SPAM"])));
        assert!(member(TRASH, &ids(&["TRASH", "Label_1"])));
        assert!(!member("Label_1", &ids(&["TRASH", "Label_1"])));
        assert!(member("Label_1", &ids(&["Label_1"])));
        assert!(!member(INBOX, &ids(&["Label_1"])));
        assert_eq!(flags(&ids(&["UNREAD", "INBOX"])), Flags::default());
        assert_eq!(
            flags(&ids(&["STARRED", "DRAFT"])),
            Flags::new(["\\Seen", "\\Flagged", "\\Draft"])
        );
    }

    #[test]
    fn names_labels() {
        assert_eq!(
            names(
                &ids(&[
                    "INBOX",
                    "UNREAD",
                    "STARRED",
                    "Label_2",
                    "IMPORTANT",
                    "CATEGORY_SOCIAL",
                    "Label_9"
                ]),
                &map()
            ),
            ids(&[
                "CATEGORY_SOCIAL",
                "Important",
                "Inbox",
                "Label_9",
                "Projects/2025"
            ])
        );
        assert_eq!(id_for("Inbox", &map()).as_deref(), Some("INBOX"));
        assert_eq!(id_for("Projects/2025", &map()).as_deref(), Some("Label_2"));
        assert_eq!(
            id_for("CATEGORY_SOCIAL", &map()).as_deref(),
            Some("CATEGORY_SOCIAL")
        );
        assert_eq!(id_for("UNREAD", &map()), None);
        assert_eq!(id_for("Nope", &map()), None);
        assert!(path_taken("receipts", &map()));
        assert!(path_taken("inbox", &map()));
        assert!(!path_taken("Receipts/2026", &map()));
        assert!(needs_name("Label_9"));
        assert!(!needs_name("CATEGORY_SOCIAL"));
        assert!(!needs_name("UNREAD"));
    }
}
