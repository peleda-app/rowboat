//! Folder management: create along a path, rename and move, delete.

use reqwest::Method;
use serde_json::{Value, json};
use skein_core::MailboxInfo;
use skein_mail::{MailError, MailSession, WriteOutcome};

use crate::http::{Body, Wrote};
use crate::write::failed;
use crate::{GraphSession, WELL_KNOWN, endpoint};

/// The well-known name of the folder that holds the top-level folders.
const ROOT: &str = "msgfolderroot";

fn same(a: &str, b: &str) -> bool {
    a == b || a.to_lowercase() == b.to_lowercase()
}

fn segments(path: &str) -> Option<Vec<&str>> {
    let parts: Vec<&str> = path.split('/').collect();
    let ok = parts
        .iter()
        .all(|p| !p.trim().is_empty() && !p.chars().any(char::is_control));
    ok.then_some(parts)
}

fn find<'a>(boxes: &'a [MailboxInfo], path: &str) -> Option<&'a MailboxInfo> {
    boxes
        .iter()
        .find(|b| b.path == path)
        .or_else(|| boxes.iter().find(|b| same(&b.path, path)))
}

fn protected(id: &str, info: Option<&MailboxInfo>) -> bool {
    WELL_KNOWN.iter().any(|(name, _)| same(name, id))
        || same(id, ROOT)
        || info.is_some_and(|b| b.role.is_some())
}

/// Creates a folder called `name` under `parent` (the root when `None`).
async fn create_one(
    session: &GraphSession,
    parent: Option<&str>,
    name: &str,
) -> Result<Result<String, WriteOutcome>, MailError> {
    let url = match parent {
        Some(p) => endpoint(
            &session.base,
            &["me", "mailFolders", p, "childFolders"],
            &[],
        )?,
        None => endpoint(&session.base, &["me", "mailFolders"], &[])?,
    };
    let body = Body::Json(json!({ "displayName": name }));
    Ok(
        match session.http.write(Method::POST, url, body, false).await? {
            Wrote::Done(Some(v)) => match v.get("id").and_then(Value::as_str) {
                Some(id) => Ok(id.to_owned()),
                None => Err(WriteOutcome::Uncertain),
            },
            Wrote::Done(None) | Wrote::Uncertain => Err(WriteOutcome::Uncertain),
            Wrote::Missing => return Err(MailError::MailboxNotFound),
            Wrote::Refused(409) => Err(failed("exists")),
            Wrote::Refused(status) => Err(failed(&format!("http_{status}"))),
        },
    )
}

/// The id of the folder at `parents`, creating the missing levels; `None` for the root.
async fn parent(
    session: &GraphSession,
    boxes: &[MailboxInfo],
    parents: &[&str],
) -> Result<Result<Option<String>, WriteOutcome>, MailError> {
    let mut id: Option<String> = None;
    for depth in 1..=parents.len() {
        let path = parents[..depth].join("/");
        id = Some(match find(boxes, &path) {
            Some(b) => b.id.clone(),
            None => match create_one(session, id.as_deref(), parents[depth - 1]).await? {
                Ok(created) => created,
                Err(outcome) => return Ok(Err(outcome)),
            },
        });
    }
    Ok(Ok(id))
}

pub(crate) async fn create(
    session: &mut GraphSession,
    path: &str,
) -> Result<WriteOutcome, MailError> {
    let Some(parts) = segments(path) else {
        return Ok(failed("invalid_path"));
    };
    let boxes = session.mailboxes().await?;
    if find(&boxes, path).is_some() {
        return Ok(failed("exists"));
    }
    let (name, parents) = parts.split_last().expect("split yields one part");
    let under = match parent(session, &boxes, parents).await? {
        Ok(id) => id,
        Err(outcome) => return Ok(outcome),
    };
    Ok(match create_one(session, under.as_deref(), name).await? {
        Ok(_) => WriteOutcome::Applied,
        Err(outcome) => outcome,
    })
}

pub(crate) async fn rename(
    session: &mut GraphSession,
    mailbox: &str,
    path: &str,
) -> Result<WriteOutcome, MailError> {
    if protected(mailbox, None) {
        return Ok(failed("protected"));
    }
    let boxes = session.mailboxes().await?;
    let Some(current) = boxes.iter().find(|b| b.id == mailbox) else {
        return Err(MailError::MailboxNotFound);
    };
    if protected(mailbox, Some(current)) {
        return Ok(failed("protected"));
    }
    let Some(parts) = segments(path) else {
        return Ok(failed("invalid_path"));
    };
    if current.path == path {
        return Ok(WriteOutcome::Applied);
    }
    if find(&boxes, path).is_some_and(|b| b.id != current.id) {
        return Ok(failed("exists"));
    }
    let n = current.path.len();
    let inside =
        path.get(..n).is_some_and(|p| same(p, &current.path)) && path[n..].starts_with('/');
    if inside {
        return Ok(failed("invalid_path"));
    }
    let (name, parents) = parts.split_last().expect("split yields one part");
    let old: Vec<&str> = current.path.split('/').collect();
    let (old_name, old_parents) = old.split_last().expect("split yields one part");
    let mut id = current.id.clone();
    let mut changed = false;

    if !same(&parents.join("/"), &old_parents.join("/")) {
        let target = match parent(session, &boxes, parents).await? {
            Ok(target) => target.unwrap_or_else(|| ROOT.to_owned()),
            Err(outcome) => return Ok(outcome),
        };
        let url = endpoint(&session.base, &["me", "mailFolders", &id, "move"], &[])?;
        let body = Body::Json(json!({ "destinationId": target }));
        match session.http.write(Method::POST, url, body, true).await? {
            Wrote::Done(moved) => {
                if let Some(new_id) = moved
                    .as_ref()
                    .and_then(|v| v.get("id"))
                    .and_then(Value::as_str)
                {
                    id = new_id.to_owned();
                }
            }
            Wrote::Uncertain => return Ok(WriteOutcome::Uncertain),
            Wrote::Missing => return Err(MailError::MailboxNotFound),
            Wrote::Refused(409) => return Ok(failed("exists")),
            Wrote::Refused(status) => return Ok(failed(&format!("http_{status}"))),
        }
        changed = true;
    }

    if name != old_name {
        let url = endpoint(&session.base, &["me", "mailFolders", &id], &[])?;
        let body = Body::Json(json!({ "displayName": name }));
        match session.http.write(Method::PATCH, url, body, true).await? {
            Wrote::Done(_) => {}
            Wrote::Uncertain => return Ok(WriteOutcome::Uncertain),
            Wrote::Missing if changed => {
                return Err(MailError::Protocol(
                    "a moved Graph folder vanished before its rename".into(),
                ));
            }
            Wrote::Missing => return Err(MailError::MailboxNotFound),
            Wrote::Refused(409) => return Ok(failed("exists")),
            Wrote::Refused(status) => return Ok(failed(&format!("http_{status}"))),
        }
    }
    Ok(WriteOutcome::Applied)
}

pub(crate) async fn delete(
    session: &mut GraphSession,
    mailbox: &str,
) -> Result<WriteOutcome, MailError> {
    if protected(mailbox, None) {
        return Ok(failed("protected"));
    }
    let boxes = session.mailboxes().await?;
    let Some(current) = boxes.iter().find(|b| b.id == mailbox) else {
        return Err(MailError::MailboxNotFound);
    };
    if protected(mailbox, Some(current)) {
        return Ok(failed("protected"));
    }
    let url = endpoint(&session.base, &["me", "mailFolders", mailbox], &[])?;
    Ok(
        match session
            .http
            .write(Method::DELETE, url, Body::Empty, true)
            .await?
        {
            Wrote::Done(_) | Wrote::Missing => WriteOutcome::Applied,
            Wrote::Uncertain => WriteOutcome::Uncertain,
            Wrote::Refused(status) => failed(&format!("http_{status}")),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_split_into_named_levels() {
        assert_eq!(segments("A/B").unwrap(), vec!["A", "B"]);
        assert!(segments("").is_none());
        assert!(segments("A//B").is_none());
        assert!(segments("A/ ").is_none());
        assert!(segments("A\u{7}").is_none());
        assert!(same("Projects", "PROJECTS"));
        assert!(protected("Inbox", None));
        assert!(protected("msgfolderroot", None));
        assert!(!protected("AAMkProjects", None));
    }
}
