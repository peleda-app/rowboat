//! Writes as label changes (`messages.batchModify`), trash and untrash, `messages.batchDelete`,
//! `messages.insert` and user label management (`labels.create`, `patch`, `delete`).

use bytes::Bytes;
use reqwest::Method;
use serde_json::json;
use skein_core::{CommandBody, Flags, ItemRef};
use skein_mail::{MailError, WriteOutcome};

use crate::http::Wrote;
use crate::labels::{self, INBOX, SPAM, STARRED, TRASH, UNREAD, is_builtin};
use crate::{ALL, GmailSession, plausible_id, quota};

/// Most ids one `batchModify` or `batchDelete` takes.
const BATCH: usize = 1000;

fn failed(reason: &str) -> WriteOutcome {
    WriteOutcome::Failed {
        reason: reason.into(),
    }
}

fn ids(items: &[ItemRef]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for i in items {
        if plausible_id(&i.id) && !out.contains(&i.id) {
            out.push(i.id.clone());
        }
    }
    out
}

/// What a step did: go on, or stop with this outcome.
fn step(wrote: Wrote) -> Option<WriteOutcome> {
    match wrote {
        Wrote::Done | Wrote::Missing => None,
        Wrote::Uncertain => Some(WriteOutcome::Uncertain),
        Wrote::Failed(reason) => Some(failed(reason)),
    }
}

pub(crate) async fn apply(
    s: &mut GmailSession,
    command: &CommandBody,
    content: Option<Bytes>,
) -> Result<WriteOutcome, MailError> {
    match command {
        CommandBody::SetFlags {
            mailbox,
            items,
            add,
            remove,
        } => {
            s.check_mailbox(mailbox).await?;
            let Some((add_labels, remove_labels)) = flag_labels(add, remove) else {
                return Ok(failed("unsupported_flag"));
            };
            modify(s, &ids(items), &add_labels, &remove_labels).await
        }
        CommandBody::Move { from, to, items } => {
            s.check_mailbox(from).await?;
            match s.check_mailbox(to).await {
                Err(MailError::MailboxNotFound) => return Ok(failed("no_such_mailbox")),
                other => other?,
            }
            if from == to {
                return Ok(WriteOutcome::Applied);
            }
            move_items(s, from, to, &ids(items)).await
        }
        CommandBody::Delete {
            mailbox,
            items,
            to_trash: false,
        } => {
            s.check_mailbox(mailbox).await?;
            let ids = ids(items);
            if is_builtin(mailbox) {
                for chunk in ids.chunks(BATCH) {
                    let url = s.http.endpoint(false, &["messages", "batchDelete"]);
                    let body = json!({ "ids": chunk });
                    let wrote = s
                        .http
                        .write(
                            Method::POST,
                            url,
                            Some(json_body(&body)),
                            quota::BATCH_DELETE,
                            true,
                        )
                        .await?;
                    if let Some(outcome) = step(wrote) {
                        return Ok(outcome);
                    }
                }
                Ok(WriteOutcome::Applied)
            } else {
                modify(s, &ids, &[], std::slice::from_ref(mailbox)).await
            }
        }
        CommandBody::Append { mailbox, flags, .. } => {
            let Some(bytes) = content else {
                return Ok(failed("missing_content"));
            };
            s.check_mailbox(mailbox).await?;
            let Some(mut label_ids) = append_labels(flags) else {
                return Ok(failed("unsupported_flag"));
            };
            if mailbox != ALL {
                label_ids.push(mailbox.clone());
            }
            insert(s, &label_ids, bytes).await
        }
        CommandBody::Delete {
            mailbox,
            items,
            to_trash: true,
        } => {
            s.check_mailbox(mailbox).await?;
            if mailbox == TRASH {
                return Ok(WriteOutcome::Applied);
            }
            Ok(trash(s, &ids(items), "trash")
                .await?
                .unwrap_or(WriteOutcome::Applied))
        }
        CommandBody::Copy { from, to, items } => {
            s.check_mailbox(from).await?;
            match s.check_mailbox(to).await {
                Err(MailError::MailboxNotFound) => return Ok(failed("no_such_mailbox")),
                other => other?,
            }
            if to == TRASH || to == SPAM {
                return Ok(failed("unsupported"));
            }
            if from == to || to == ALL {
                return Ok(WriteOutcome::Applied);
            }
            modify(s, &ids(items), std::slice::from_ref(to), &[]).await
        }
        CommandBody::SetLabels {
            mailbox,
            items,
            add,
            remove,
        } => {
            s.check_mailbox(mailbox).await?;
            let Some(add_ids) = label_ids(s, add).await? else {
                return Ok(failed("no_such_label"));
            };
            let Some(remove_ids) = label_ids(s, remove).await? else {
                return Ok(failed("no_such_label"));
            };
            let remove_ids: Vec<String> = remove_ids
                .into_iter()
                .filter(|r| !add_ids.contains(r))
                .collect();
            modify(s, &ids(items), &add_ids, &remove_ids).await
        }
        CommandBody::CreateMailbox { path } => create_label(s, path).await,
        CommandBody::RenameMailbox { mailbox, path } => rename_label(s, mailbox, path).await,
        CommandBody::DeleteMailbox { mailbox } => delete_label(s, mailbox).await,
        CommandBody::Refetch { .. }
        | CommandBody::Send { .. }
        | CommandBody::PutObject { .. }
        | CommandBody::DeleteObject { .. }
        | CommandBody::RespondObject { .. }
        | CommandBody::RespondInvitation { .. }
        | CommandBody::Unknown => Ok(failed("unsupported")),
    }
}

fn json_body(value: &serde_json::Value) -> (String, Bytes) {
    ("application/json".into(), Bytes::from(value.to_string()))
}

/// Labels to add and remove for a flag change; `None` when a flag has no Gmail label. Adding
/// wins over removing.
fn flag_labels(add: &Flags, remove: &Flags) -> Option<(Vec<String>, Vec<String>)> {
    let mut add_labels = Vec::new();
    let mut remove_labels = Vec::new();
    for f in add.iter() {
        match f {
            "\\Seen" => remove_labels.push(UNREAD.to_owned()),
            "\\Flagged" => add_labels.push(STARRED.to_owned()),
            _ => return None,
        }
    }
    for f in remove.iter() {
        match f {
            "\\Seen" if !add.contains(f) => add_labels.push(UNREAD.to_owned()),
            "\\Flagged" if !add.contains(f) => remove_labels.push(STARRED.to_owned()),
            "\\Seen" | "\\Flagged" => {}
            _ => return None,
        }
    }
    Some((add_labels, remove_labels))
}

fn append_labels(flags: &Flags) -> Option<Vec<String>> {
    let mut out = Vec::new();
    if !flags.contains("\\Seen") {
        out.push(UNREAD.to_owned());
    }
    for f in flags.iter() {
        match f {
            "\\Seen" => {}
            "\\Flagged" => out.push(STARRED.to_owned()),
            _ => return None,
        }
    }
    Some(out)
}

/// Label ids for names as `labels` reports them; `None` when one is unknown, after reloading the
/// label list once.
async fn label_ids(
    s: &mut GmailSession,
    names: &[String],
) -> Result<Option<Vec<String>>, MailError> {
    let resolve = |map: &std::collections::HashMap<String, labels::Label>| {
        names
            .iter()
            .map(|n| labels::id_for(n, map))
            .collect::<Option<Vec<String>>>()
    };
    if let Some(found) = resolve(s.labels().await?) {
        return Ok(Some(dedup(found)));
    }
    Ok(resolve(s.load_labels().await?).map(dedup))
}

fn dedup(mut ids: Vec<String>) -> Vec<String> {
    ids.sort();
    ids.dedup();
    ids
}

/// What a label mailbox is to label management: a user label, a system mailbox, or nothing.
enum Kind {
    User,
    Protected,
    Missing,
}

async fn kind(s: &mut GmailSession, mailbox: &str) -> Result<Kind, MailError> {
    if is_builtin(mailbox) {
        return Ok(Kind::Protected);
    }
    let map = s.load_labels().await?;
    Ok(match map.get(mailbox) {
        Some(l) if labels::is_user(l) => Kind::User,
        Some(_) => Kind::Protected,
        None => Kind::Missing,
    })
}

fn valid_path(path: &str) -> bool {
    !path.trim().is_empty()
        && !path.chars().any(char::is_control)
        && path.split('/').all(|p| !p.trim().is_empty())
}

async fn create_label(s: &mut GmailSession, path: &str) -> Result<WriteOutcome, MailError> {
    if !valid_path(path) {
        return Ok(failed("invalid_path"));
    }
    if labels::path_taken(path, s.load_labels().await?) {
        return Ok(failed("exists"));
    }
    let url = s.http.endpoint(false, &["labels"]);
    let body = json!({
        "name": path,
        "labelListVisibility": "labelShow",
        "messageListVisibility": "show",
    });
    let wrote = s
        .http
        .write(
            Method::POST,
            url,
            Some(json_body(&body)),
            quota::LABELS_WRITE,
            false,
        )
        .await;
    s.labels = None;
    Ok(match wrote? {
        Wrote::Done => WriteOutcome::Applied,
        Wrote::Uncertain => WriteOutcome::Uncertain,
        Wrote::Missing => failed("refused"),
        Wrote::Failed(reason) => failed(reason),
    })
}

async fn rename_label(
    s: &mut GmailSession,
    mailbox: &str,
    path: &str,
) -> Result<WriteOutcome, MailError> {
    match kind(s, mailbox).await? {
        Kind::User => {}
        Kind::Protected => return Ok(failed("protected")),
        Kind::Missing => return Err(MailError::MailboxNotFound),
    }
    if !valid_path(path) {
        return Ok(failed("invalid_path"));
    }
    let map = s.labels().await?;
    if map.get(mailbox).is_some_and(|l| l.name == path) {
        return Ok(WriteOutcome::Applied);
    }
    let renames_itself = map
        .get(mailbox)
        .is_some_and(|l| l.name.eq_ignore_ascii_case(path));
    if !renames_itself && labels::path_taken(path, map) {
        return Ok(failed("exists"));
    }
    let url = s.http.endpoint(false, &["labels", mailbox]);
    let wrote = s
        .http
        .write(
            Method::PATCH,
            url,
            Some(json_body(&json!({ "name": path }))),
            quota::LABELS_WRITE,
            true,
        )
        .await;
    s.labels = None;
    Ok(match wrote? {
        Wrote::Done => WriteOutcome::Applied,
        Wrote::Uncertain => WriteOutcome::Uncertain,
        Wrote::Missing => return Err(MailError::MailboxNotFound),
        Wrote::Failed(reason) => failed(reason),
    })
}

async fn delete_label(s: &mut GmailSession, mailbox: &str) -> Result<WriteOutcome, MailError> {
    match kind(s, mailbox).await? {
        Kind::User => {}
        Kind::Protected => return Ok(failed("protected")),
        Kind::Missing => return Err(MailError::MailboxNotFound),
    }
    let url = s.http.endpoint(false, &["labels", mailbox]);
    let wrote = s
        .http
        .write(Method::DELETE, url, None, quota::LABELS_WRITE, true)
        .await;
    s.labels = None;
    Ok(step(wrote?).unwrap_or(WriteOutcome::Applied))
}

async fn modify(
    s: &GmailSession,
    ids: &[String],
    add: &[String],
    remove: &[String],
) -> Result<WriteOutcome, MailError> {
    if add.is_empty() && remove.is_empty() {
        return Ok(WriteOutcome::Applied);
    }
    for chunk in ids.chunks(BATCH) {
        let url = s.http.endpoint(false, &["messages", "batchModify"]);
        let body = json!({ "ids": chunk, "addLabelIds": add, "removeLabelIds": remove });
        let wrote = s
            .http
            .write(
                Method::POST,
                url,
                Some(json_body(&body)),
                quota::BATCH_MODIFY,
                true,
            )
            .await?;
        if let Some(outcome) = step(wrote) {
            return Ok(outcome);
        }
    }
    Ok(WriteOutcome::Applied)
}

async fn trash(
    s: &GmailSession,
    ids: &[String],
    action: &str,
) -> Result<Option<WriteOutcome>, MailError> {
    let cost = if action == "trash" {
        quota::TRASH
    } else {
        quota::UNTRASH
    };
    for id in ids {
        let url = s.http.endpoint(false, &["messages", id, action]);
        let wrote = s.http.write(Method::POST, url, None, cost, true).await?;
        if let Some(outcome) = step(wrote) {
            return Ok(Some(outcome));
        }
    }
    Ok(None)
}

/// A move as label changes: into Trash with `trash`, out of it with `untrash`; otherwise the
/// source label is removed (none for `ALL`) and the target label added (none for `ALL`). Into
/// Spam also removes `INBOX`, as Gmail's "Report spam" does.
async fn move_items(
    s: &GmailSession,
    from: &str,
    to: &str,
    ids: &[String],
) -> Result<WriteOutcome, MailError> {
    if ids.is_empty() {
        return Ok(WriteOutcome::Applied);
    }
    if to == TRASH {
        return Ok(trash(s, ids, "trash")
            .await?
            .unwrap_or(WriteOutcome::Applied));
    }
    if from == TRASH
        && let Some(outcome) = trash(s, ids, "untrash").await?
    {
        return Ok(outcome);
    }
    let mut add = Vec::new();
    let mut remove = Vec::new();
    if to != ALL {
        add.push(to.to_owned());
    }
    if from != ALL && from != TRASH {
        remove.push(from.to_owned());
    }
    if to == SPAM && from != INBOX {
        remove.push(INBOX.to_owned());
    }
    modify(s, ids, &add, &remove).await
}

/// A boundary that does not occur in the message.
fn boundary(content: &[u8]) -> String {
    (0u32..)
        .map(|n| format!("skein_part_{n:08x}"))
        .find(|b| !content.windows(b.len()).any(|w| w == b.as_bytes()))
        .expect("some boundary is free")
}

async fn insert(
    s: &GmailSession,
    label_ids: &[String],
    content: Bytes,
) -> Result<WriteOutcome, MailError> {
    let b = boundary(&content);
    let metadata = json!({ "labelIds": label_ids }).to_string();
    let mut body = Vec::with_capacity(content.len() + metadata.len() + 256);
    body.extend_from_slice(
        format!("--{b}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{metadata}\r\n--{b}\r\nContent-Type: message/rfc822\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(&content);
    body.extend_from_slice(format!("\r\n--{b}--\r\n").as_bytes());
    let mut url = s.http.endpoint(true, &["messages"]);
    url.query_pairs_mut()
        .append_pair("uploadType", "multipart")
        .append_pair("internalDateSource", "dateHeader");
    let wrote = s
        .http
        .write(
            Method::POST,
            url,
            Some((
                format!("multipart/related; boundary={b}"),
                Bytes::from(body),
            )),
            quota::INSERT,
            false,
        )
        .await?;
    Ok(match wrote {
        Wrote::Done => WriteOutcome::Applied,
        Wrote::Uncertain => WriteOutcome::Uncertain,
        Wrote::Missing => failed("refused"),
        Wrote::Failed(reason) => failed(reason),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_become_labels() {
        let (a, r) = flag_labels(&Flags::new(["\\Seen", "\\Flagged"]), &Flags::default()).unwrap();
        assert_eq!((a, r), (vec!["STARRED".into()], vec!["UNREAD".into()]));
        let (a, r) = flag_labels(&Flags::default(), &Flags::new(["\\Seen", "\\Flagged"])).unwrap();
        assert_eq!((a, r), (vec!["UNREAD".into()], vec!["STARRED".into()]));
        let (a, r) = flag_labels(&Flags::new(["\\Seen"]), &Flags::new(["\\Seen"])).unwrap();
        assert_eq!((a, r), (vec![], vec!["UNREAD".to_owned()]));
        assert!(flag_labels(&Flags::new(["$Junk"]), &Flags::default()).is_none());
        assert!(flag_labels(&Flags::default(), &Flags::new(["\\Answered"])).is_none());
        assert_eq!(append_labels(&Flags::default()).unwrap(), vec!["UNREAD"]);
        assert_eq!(
            append_labels(&Flags::new(["\\Seen", "\\Flagged"])).unwrap(),
            vec!["STARRED"]
        );
    }

    #[test]
    fn boundaries_avoid_the_content() {
        assert_eq!(boundary(b"hello"), "skein_part_00000000");
        assert_eq!(boundary(b"x skein_part_00000000 y"), "skein_part_00000001");
    }
}
