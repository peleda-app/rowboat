use base64::Engine;
use bytes::Bytes;
use reqwest::Method;
use serde_json::{Map, Value, json};
use skein_core::{CommandBody, Flags, ItemRef};
use skein_mail::{MailError, WriteOutcome};

use crate::http::{Answer, Body, Scope, Wrote};
use crate::{GraphSession, endpoint, flags, folders, string};

/// Graph takes at most 4 MiB of base64 in one request.
pub(crate) const MAX_APPEND: usize = 3 * 1024 * 1024;

pub(crate) fn failed(reason: &str) -> WriteOutcome {
    WriteOutcome::Failed {
        reason: reason.to_owned(),
    }
}

/// `isRead` and `flag` for what the flags should become, `None` when one of them is a flag
/// Graph cannot hold.
fn patch(add: &Flags, remove: &Flags) -> Option<Map<String, Value>> {
    let mut out = Map::new();
    for flag in remove.iter() {
        match flag {
            "\\Seen" => out.insert("isRead".into(), json!(false)),
            "\\Flagged" => out.insert("flag".into(), json!({ "flagStatus": "notFlagged" })),
            _ => return None,
        };
    }
    for flag in add.iter() {
        match flag {
            "\\Seen" => out.insert("isRead".into(), json!(true)),
            "\\Flagged" => out.insert("flag".into(), json!({ "flagStatus": "flagged" })),
            _ => return None,
        };
    }
    Some(out)
}

enum Step {
    Next,
    Stop(WriteOutcome),
}

fn step(wrote: Wrote) -> Step {
    match wrote {
        Wrote::Done(_) | Wrote::Missing => Step::Next,
        Wrote::Uncertain => Step::Stop(WriteOutcome::Uncertain),
        Wrote::Refused(status) => Step::Stop(failed(&format!("http_{status}"))),
    }
}

async fn each(
    session: &GraphSession,
    items: &[ItemRef],
    action: &str,
    repeatable: bool,
    body: impl Fn() -> Body,
) -> Result<WriteOutcome, MailError> {
    for item in items {
        let mut segments = vec!["me", "messages", item.id.as_str()];
        if !action.is_empty() {
            segments.push(action);
        }
        let url = endpoint(&session.base, &segments, &[])?;
        let method = if action.is_empty() {
            Method::PATCH
        } else {
            Method::POST
        };
        if let Step::Stop(outcome) =
            step(session.http.write(method, url, body(), repeatable).await?)
        {
            tracing::debug!(items = items.len(), "a Graph write stopped part way");
            return Ok(outcome);
        }
    }
    Ok(WriteOutcome::Applied)
}

/// The folder's id, `None` when it does not exist. Takes ids and well-known names.
async fn folder_id(session: &GraphSession, folder: &str) -> Result<Option<String>, MailError> {
    let url = endpoint(
        &session.base,
        &["me", "mailFolders", folder],
        &[("$select", "id")],
    )?;
    Ok(
        match session.http.get_json(url, Scope::Mailbox, None).await? {
            Answer::Found(v) => Some(string(&v, "id")?),
            Answer::Missing | Answer::Refused => None,
        },
    )
}

async fn folder_exists(session: &GraphSession, folder: &str) -> Result<bool, MailError> {
    Ok(folder_id(session, folder).await?.is_some())
}

async fn source(session: &GraphSession, folder: &str) -> Result<(), MailError> {
    if folder_exists(session, folder).await? {
        Ok(())
    } else {
        Err(MailError::MailboxNotFound)
    }
}

pub(crate) async fn apply(
    session: &mut GraphSession,
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
            let Some(patch) = patch(add, remove) else {
                return Ok(failed("unsupported_flag"));
            };
            source(session, mailbox).await?;
            if patch.is_empty() {
                return Ok(WriteOutcome::Applied);
            }
            each(session, items, "", true, || {
                Body::Json(Value::Object(patch.clone()))
            })
            .await
        }
        CommandBody::Move { from, to, items } => {
            source(session, from).await?;
            if from == to {
                return Ok(WriteOutcome::Applied);
            }
            if !folder_exists(session, to).await? {
                return Ok(failed("no_such_mailbox"));
            }
            each(session, items, "move", true, || {
                Body::Json(json!({ "destinationId": to }))
            })
            .await
        }
        CommandBody::Copy { from, to, items } => {
            source(session, from).await?;
            if !folder_exists(session, to).await? {
                return Ok(failed("no_such_mailbox"));
            }
            each(session, items, "copy", false, || {
                Body::Json(json!({ "destinationId": to }))
            })
            .await
        }
        CommandBody::Delete {
            mailbox,
            items,
            to_trash: false,
        } => {
            source(session, mailbox).await?;
            each(session, items, "permanentDelete", true, || Body::Empty).await
        }
        CommandBody::Delete {
            mailbox,
            items,
            to_trash: true,
        } => {
            source(session, mailbox).await?;
            let Some(trash) = folder_id(session, "deleteditems").await? else {
                return Ok(failed("no_trash"));
            };
            if *mailbox == trash || mailbox == "deleteditems" {
                return Ok(WriteOutcome::Applied);
            }
            each(session, items, "move", true, || {
                Body::Json(json!({ "destinationId": trash }))
            })
            .await
        }
        CommandBody::CreateMailbox { path } => folders::create(session, path).await,
        CommandBody::RenameMailbox { mailbox, path } => {
            folders::rename(session, mailbox, path).await
        }
        CommandBody::DeleteMailbox { mailbox } => folders::delete(session, mailbox).await,
        CommandBody::Append { mailbox, flags, .. } => {
            let Some(bytes) = content else {
                return Ok(failed("missing_content"));
            };
            append(session, mailbox, &bytes, flags).await
        }
        CommandBody::Refetch { .. }
        | CommandBody::Send { .. }
        | CommandBody::PutObject { .. }
        | CommandBody::DeleteObject { .. }
        | CommandBody::SetLabels { .. }
        | CommandBody::RespondObject { .. }
        | CommandBody::RespondInvitation { .. }
        | CommandBody::Unknown => Ok(failed("unsupported")),
    }
}

async fn append(
    session: &GraphSession,
    mailbox: &str,
    bytes: &[u8],
    wanted: &Flags,
) -> Result<WriteOutcome, MailError> {
    if bytes.len() > MAX_APPEND {
        return Ok(failed("too_large"));
    }
    let seen = wanted.contains("\\Seen");
    let flagged = wanted.contains("\\Flagged");
    let url = endpoint(
        &session.base,
        &["me", "mailFolders", mailbox, "messages"],
        &[],
    )?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    let created = match session
        .http
        .write(Method::POST, url, Body::Mime(encoded), false)
        .await?
    {
        Wrote::Done(Some(created)) => created,
        Wrote::Done(None) | Wrote::Uncertain => return Ok(WriteOutcome::Uncertain),
        Wrote::Missing => return Err(MailError::MailboxNotFound),
        Wrote::Refused(status) => return Ok(failed(&format!("http_{status}"))),
    };
    let Some(id) = created.get("id").and_then(Value::as_str) else {
        return Ok(WriteOutcome::Uncertain);
    };
    let now = flags(&created);
    if now.contains("\\Seen") == seen && now.contains("\\Flagged") == flagged {
        return Ok(WriteOutcome::Applied);
    }
    let url = endpoint(&session.base, &["me", "messages", id], &[])?;
    let body = json!({
        "isRead": seen,
        "flag": { "flagStatus": if flagged { "flagged" } else { "notFlagged" } },
    });
    if let Ok(Wrote::Done(_)) = session
        .http
        .write(Method::PATCH, url, Body::Json(body), true)
        .await
    {
        return Ok(WriteOutcome::Applied);
    }
    let url = endpoint(
        &session.base,
        &["me", "messages", id, "permanentDelete"],
        &[],
    )?;
    Ok(
        match session
            .http
            .write(Method::POST, url, Body::Empty, true)
            .await
        {
            Ok(Wrote::Done(_) | Wrote::Missing) => failed("flags_not_set"),
            _ => {
                tracing::warn!(
                    "an uploaded Graph message kept the wrong flags and could not be removed"
                );
                WriteOutcome::Uncertain
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patches_only_what_graph_can_hold() {
        let p = patch(&Flags::new(["\\Seen"]), &Flags::new(["\\Flagged"])).unwrap();
        assert_eq!(p["isRead"], json!(true));
        assert_eq!(p["flag"]["flagStatus"], json!("notFlagged"));
        let p = patch(&Flags::new(["\\Seen"]), &Flags::new(["\\Seen"])).unwrap();
        assert_eq!(p["isRead"], json!(true), "adding wins, as in the fake");
        assert!(patch(&Flags::new(["\\Answered"]), &Flags::default()).is_none());
        assert!(patch(&Flags::default(), &Flags::new(["$label1"])).is_none());
    }
}
