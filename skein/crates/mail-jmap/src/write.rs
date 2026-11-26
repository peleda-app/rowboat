use bytes::Bytes;
use serde_json::{Map, Value, json};
use skein_core::{CommandBody, Flags, ItemRef, MailCapabilities, Timestamp};
use skein_mail::{MailError, WriteOutcome, basic_capabilities};

use crate::http::Posted;
use crate::{JmapSession, expand, in_mailbox, list, protocol, string, time};

const ATTEMPTS: usize = 5;

fn failed(reason: &str) -> WriteOutcome {
    WriteOutcome::Failed {
        reason: reason.to_owned(),
    }
}

/// The JMAP keyword for a flag; `None` for one JMAP cannot spell (such as `\Deleted`).
pub(crate) fn keyword(flag: &str) -> Option<String> {
    let name = match flag {
        "\\Seen" => "$seen",
        "\\Answered" => "$answered",
        "\\Flagged" => "$flagged",
        "\\Draft" => "$draft",
        other => other,
    };
    let spellable = !name.is_empty()
        && name
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && !b"(){]%*\"\\".contains(&b));
    spellable.then(|| name.to_ascii_lowercase())
}

/// Patches for `keywords/<name>`; a flag in both lists ends up set.
fn keyword_patch(add: &Flags, remove: &Flags) -> Option<Map<String, Value>> {
    let mut patch = Map::new();
    for flag in remove.iter() {
        patch.insert(format!("keywords/{}", keyword(flag)?), Value::Null);
    }
    for flag in add.iter() {
        patch.insert(format!("keywords/{}", keyword(flag)?), json!(true));
    }
    Some(patch)
}

enum Change {
    Update(String, Map<String, Value>),
    Destroy(String),
}

enum Applied {
    Done,
    Uncertain,
    StateMismatch,
    Refused(String),
}

fn refusals(answer: &Value, key: &str) -> Option<String> {
    answer
        .get(key)
        .and_then(Value::as_object)?
        .values()
        .filter_map(|e| e.get("type").and_then(Value::as_str))
        .find(|kind| *kind != "notFound")
        .map(str::to_owned)
}

fn first_error(answer: &Value, key: &str) -> Option<String> {
    answer
        .get(key)
        .and_then(Value::as_object)?
        .values()
        .find_map(|e| e.get("type").and_then(Value::as_str))
        .map(str::to_owned)
}

/// The contract's reason for a name clash; other JMAP error types pass through.
fn clash(kind: &str) -> &str {
    if kind == "alreadyExists" {
        "exists"
    } else {
        kind
    }
}

struct Folder {
    id: String,
    name: String,
    parent: Option<String>,
    role: Option<String>,
    may_set_keywords: Option<bool>,
}

/// The names in a path, or `None` when one is empty.
fn segments(path: &str) -> Option<Vec<&str>> {
    let names: Vec<&str> = path.split('/').collect();
    names.iter().all(|n| !n.is_empty()).then_some(names)
}

fn child<'a>(boxes: &'a [Folder], parent: Option<&str>, name: &str) -> Option<&'a str> {
    boxes
        .iter()
        .find(|b| b.parent.as_deref() == parent && b.name == name)
        .map(|b| b.id.as_str())
}

/// Whether `id` is `ancestor` or below it.
fn within(boxes: &[Folder], id: &str, ancestor: &str) -> bool {
    let mut next = Some(id);
    for _ in 0..=boxes.len() {
        match next {
            Some(current) if current == ancestor => return true,
            Some(current) => {
                next = boxes
                    .iter()
                    .find(|b| b.id == current)
                    .and_then(|b| b.parent.as_deref());
            }
            None => return false,
        }
    }
    false
}

/// Where a new mailbox goes: under an existing one (`None` for the top), or under one created
/// in the same `Mailbox/set`.
enum Parent {
    Existing(Option<String>),
    Created(String),
}

impl Parent {
    fn reference(&self) -> Value {
        match self {
            Self::Existing(id) => json!(id),
            Self::Created(key) => json!(format!("#{key}")),
        }
    }
}

/// The mailboxes to create so that `names` exists, keyed by creation id, each referring to its
/// parent, and the last of them.
fn plan(boxes: &[Folder], names: &[&str]) -> (Map<String, Value>, Parent) {
    let mut create = Map::new();
    let mut parent = Parent::Existing(None);
    for name in names {
        if let Parent::Existing(at) = &parent
            && let Some(id) = child(boxes, at.as_deref(), name)
        {
            parent = Parent::Existing(Some(id.to_owned()));
            continue;
        }
        let key = format!("p{}", create.len());
        create.insert(
            key.clone(),
            json!({ "name": name, "parentId": parent.reference() }),
        );
        parent = Parent::Created(key);
    }
    (create, parent)
}

impl JmapSession {
    /// Whether each of `ids` names a mailbox, in one `Mailbox/get`.
    async fn existing(&self, ids: &[&str]) -> Result<Vec<bool>, MailError> {
        let answers = self
            .call(vec![(
                "Mailbox/get",
                json!({ "accountId": self.account, "ids": ids, "properties": ["id"] }),
            )])
            .await?;
        let found: Vec<String> = list(&answers[0])?
            .iter()
            .filter_map(|m| m.get("id").and_then(Value::as_str).map(str::to_owned))
            .collect();
        Ok(ids.iter().map(|id| found.iter().any(|f| f == id)).collect())
    }

    /// Every mailbox.
    async fn boxes(&self) -> Result<Vec<Folder>, MailError> {
        let answers = self
            .call(vec![(
                "Mailbox/get",
                json!({
                    "accountId": self.account,
                    "ids": null,
                    "properties": ["id", "name", "parentId", "role", "myRights"],
                }),
            )])
            .await?;
        list(&answers[0])?
            .iter()
            .map(|m| {
                Ok(Folder {
                    id: string(m, "id")?,
                    name: string(m, "name")?,
                    parent: m.get("parentId").and_then(Value::as_str).map(str::to_owned),
                    role: m
                        .get("role")
                        .and_then(Value::as_str)
                        .map(str::to_ascii_lowercase),
                    may_set_keywords: m
                        .pointer("/myRights/maySetKeywords")
                        .and_then(Value::as_bool),
                })
            })
            .collect()
    }

    /// Sends one `Mailbox/set`; its answer, or the outcome when there is none.
    async fn mailbox_set(&self, mut args: Value) -> Result<Result<Value, WriteOutcome>, MailError> {
        args["accountId"] = json!(self.account);
        Ok(match self.post_calls(vec![("Mailbox/set", args)]).await? {
            None => Err(WriteOutcome::Uncertain),
            Some(mut answers) => match answers.pop() {
                Some(Ok(answer)) => Ok(answer),
                Some(Err(kind)) => Err(failed(&kind)),
                None => return Err(protocol("the JMAP server left a call unanswered")),
            },
        })
    }

    /// Sends `Email/set` in chunks of `maxObjectsInSet`. Each later chunk is guarded by the
    /// previous chunk's `newState` when `state` is given. Emails already gone count as done.
    async fn set(
        &self,
        changes: Vec<Change>,
        mut state: Option<String>,
    ) -> Result<Applied, MailError> {
        let mut changes = changes.into_iter().peekable();
        while changes.peek().is_some() {
            let mut update = Map::new();
            let mut destroy = Vec::new();
            for change in changes.by_ref().take(self.max_set) {
                match change {
                    Change::Update(id, patch) => {
                        update.insert(id, Value::Object(patch));
                    }
                    Change::Destroy(id) => destroy.push(id),
                }
            }
            let mut args = json!({ "accountId": self.account });
            if !update.is_empty() {
                args["update"] = Value::Object(update);
            }
            if !destroy.is_empty() {
                args["destroy"] = json!(destroy);
            }
            if let Some(state) = &state {
                args["ifInState"] = json!(state);
            }
            let answer = match self.post_calls(vec![("Email/set", args)]).await? {
                None => return Ok(Applied::Uncertain),
                Some(mut answers) => match answers.pop() {
                    Some(Ok(answer)) => answer,
                    Some(Err(kind)) if kind == "stateMismatch" => {
                        return Ok(Applied::StateMismatch);
                    }
                    Some(Err(kind)) => return Ok(Applied::Refused(kind)),
                    None => return Err(protocol("the JMAP server left a call unanswered")),
                },
            };
            if let Some(kind) =
                refusals(&answer, "notUpdated").or_else(|| refusals(&answer, "notDestroyed"))
            {
                return Ok(Applied::Refused(kind));
            }
            if state.is_some() {
                state = answer
                    .get("newState")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
            }
        }
        Ok(Applied::Done)
    }

    async fn delete(&self, mailbox: &str, items: &[ItemRef]) -> Result<WriteOutcome, MailError> {
        let ids: Vec<String> = items.iter().map(|i| i.id.clone()).collect();
        for _ in 0..ATTEMPTS {
            let (emails, state) = self.emails(&ids, &["id", "mailboxIds"]).await?;
            let mut changes = Vec::new();
            for email in emails.iter().filter(|e| in_mailbox(e, mailbox)) {
                let id = string(email, "id")?;
                let elsewhere = email
                    .get("mailboxIds")
                    .and_then(Value::as_object)
                    .is_some_and(|m| {
                        m.iter()
                            .any(|(m, on)| m != mailbox && on.as_bool() == Some(true))
                    });
                changes.push(if elsewhere {
                    let mut patch = Map::new();
                    patch.insert(format!("mailboxIds/{mailbox}"), Value::Null);
                    Change::Update(id, patch)
                } else {
                    Change::Destroy(id)
                });
            }
            if changes.is_empty() {
                return self.gone(mailbox).await;
            }
            let state = state.ok_or_else(|| protocol("the JMAP server gave no Email state"))?;
            match self.set(changes, Some(state)).await? {
                Applied::StateMismatch => continue,
                other => return Ok(outcome(other)),
            }
        }
        tracing::debug!("a JMAP account kept changing during a delete");
        Err(MailError::Throttled { retry_after: None })
    }

    /// `Applied` when nothing was left to change in `mailbox`, `MailboxNotFound` when it is gone.
    async fn gone(&self, mailbox: &str) -> Result<WriteOutcome, MailError> {
        if self.existing(&[mailbox]).await?[0] {
            Ok(WriteOutcome::Applied)
        } else {
            Err(MailError::MailboxNotFound)
        }
    }

    /// Puts the emails of `mailbox` in the trash and nowhere else.
    async fn trash(&self, mailbox: &str, items: &[ItemRef]) -> Result<WriteOutcome, MailError> {
        let boxes = self.boxes().await?;
        if !boxes.iter().any(|b| b.id == mailbox) {
            return Err(MailError::MailboxNotFound);
        }
        let Some(trash) = boxes.iter().find(|b| b.role.as_deref() == Some("trash")) else {
            return Ok(failed("no_trash"));
        };
        if trash.id == mailbox || items.is_empty() {
            return Ok(WriteOutcome::Applied);
        }
        let ids: Vec<String> = items.iter().map(|i| i.id.clone()).collect();
        let (emails, _) = self.emails(&ids, &["id", "mailboxIds"]).await?;
        let mut patch = Map::new();
        patch.insert("mailboxIds".into(), json!({ trash.id.as_str(): true }));
        let changes = emails
            .iter()
            .filter(|e| in_mailbox(e, mailbox))
            .map(|e| Ok(Change::Update(string(e, "id")?, patch.clone())))
            .collect::<Result<Vec<_>, MailError>>()?;
        if changes.is_empty() {
            return Ok(WriteOutcome::Applied);
        }
        Ok(outcome(self.set(changes, None).await?))
    }

    async fn create_mailbox(&self, path: &str) -> Result<WriteOutcome, MailError> {
        let Some(names) = segments(path) else {
            return Ok(failed("invalid_path"));
        };
        let boxes = self.boxes().await?;
        let (mut create, parent) = plan(&boxes, &names[..names.len() - 1]);
        let name = names[names.len() - 1];
        if let Parent::Existing(at) = &parent
            && child(&boxes, at.as_deref(), name).is_some()
        {
            return Ok(failed("exists"));
        }
        create.insert(
            format!("p{}", create.len()),
            json!({ "name": name, "parentId": parent.reference() }),
        );
        let answer = match self.mailbox_set(json!({ "create": create })).await? {
            Ok(answer) => answer,
            Err(outcome) => return Ok(outcome),
        };
        Ok(match first_error(&answer, "notCreated") {
            Some(kind) => failed(clash(&kind)),
            None => WriteOutcome::Applied,
        })
    }

    async fn rename_mailbox(&self, mailbox: &str, path: &str) -> Result<WriteOutcome, MailError> {
        let boxes = self.boxes().await?;
        let Some(current) = boxes.iter().find(|b| b.id == mailbox) else {
            return Err(MailError::MailboxNotFound);
        };
        if current.role.is_some() {
            return Ok(failed("protected"));
        }
        let Some(names) = segments(path) else {
            return Ok(failed("invalid_path"));
        };
        let (create, parent) = plan(&boxes, &names[..names.len() - 1]);
        let name = names[names.len() - 1];
        if let Parent::Existing(at) = &parent {
            if let Some(at) = at
                && within(&boxes, at, mailbox)
            {
                return Ok(failed("invalid_path"));
            }
            match child(&boxes, at.as_deref(), name) {
                Some(same) if same == mailbox => return Ok(WriteOutcome::Applied),
                Some(_) => return Ok(failed("exists")),
                None => {}
            }
        }
        let mut args = json!({
            "update": { mailbox: { "name": name, "parentId": parent.reference() } },
        });
        if !create.is_empty() {
            args["create"] = Value::Object(create);
        }
        let answer = match self.mailbox_set(args).await? {
            Ok(answer) => answer,
            Err(outcome) => return Ok(outcome),
        };
        Ok(
            match first_error(&answer, "notCreated").or_else(|| first_error(&answer, "notUpdated"))
            {
                Some(kind) if kind == "notFound" => return Err(MailError::MailboxNotFound),
                Some(kind) => failed(clash(&kind)),
                None => WriteOutcome::Applied,
            },
        )
    }

    async fn delete_mailbox(&self, mailbox: &str) -> Result<WriteOutcome, MailError> {
        let boxes = self.boxes().await?;
        let Some(current) = boxes.iter().find(|b| b.id == mailbox) else {
            return Err(MailError::MailboxNotFound);
        };
        if current.role.is_some() {
            return Ok(failed("protected"));
        }
        let answer = match self
            .mailbox_set(json!({ "destroy": [mailbox], "onDestroyRemoveEmails": true }))
            .await?
        {
            Ok(answer) => answer,
            Err(outcome) => return Ok(outcome),
        };
        Ok(match first_error(&answer, "notDestroyed").as_deref() {
            None | Some("notFound") => WriteOutcome::Applied,
            Some("mailboxHasChild") => failed("has_children"),
            Some(kind) => failed(kind),
        })
    }

    async fn append(
        &self,
        mailbox: &str,
        bytes: Bytes,
        wanted: &Flags,
        received_at: Option<Timestamp>,
    ) -> Result<WriteOutcome, MailError> {
        let Some(keywords) = wanted
            .iter()
            .map(|f| keyword(f).map(|k| (k, json!(true))))
            .collect::<Option<Map<String, Value>>>()
        else {
            return Ok(failed("unsupported_flag"));
        };
        if self.max_upload.is_some_and(|max| bytes.len() as u64 > max) {
            return Ok(failed("too_large"));
        }
        if !self.existing(&[mailbox]).await?[0] {
            return Err(MailError::MailboxNotFound);
        }
        let template = self
            .upload_url
            .clone()
            .ok_or_else(|| protocol("the JMAP session has no uploadUrl"))?;
        let url = expand(&template, &[("accountId", &self.account)]);
        let uploaded = match self
            .http
            .post_raw(&url, "message/rfc822", bytes.to_vec())
            .await?
        {
            Posted::Answer(answer) => answer,
            Posted::Lost => return Err(MailError::Network("the upload broke off".into())),
        };
        let blob = string(&uploaded, "blobId")?;
        let mut email =
            json!({ "blobId": blob, "mailboxIds": { mailbox: true }, "keywords": keywords });
        if let Some(at) = received_at {
            email["receivedAt"] = json!(time::format_utc(at.0.div_euclid(1000)));
        }
        let answer = match self
            .post_calls(vec![(
                "Email/import",
                json!({ "accountId": self.account, "emails": { "m": email } }),
            )])
            .await?
        {
            None => return Ok(WriteOutcome::Uncertain),
            Some(mut answers) => match answers.pop() {
                Some(Ok(answer)) => answer,
                Some(Err(kind)) => return Ok(failed(&kind)),
                None => return Err(protocol("the JMAP server left a call unanswered")),
            },
        };
        if answer
            .pointer("/created/m/id")
            .and_then(Value::as_str)
            .is_some()
        {
            return Ok(WriteOutcome::Applied);
        }
        Ok(failed(
            answer
                .pointer("/notCreated/m/type")
                .and_then(Value::as_str)
                .unwrap_or("not_created"),
        ))
    }
}

fn outcome(applied: Applied) -> WriteOutcome {
    match applied {
        Applied::Done => WriteOutcome::Applied,
        Applied::Uncertain => WriteOutcome::Uncertain,
        Applied::StateMismatch => WriteOutcome::Conflict,
        Applied::Refused(kind) => failed(&kind),
    }
}

pub(crate) async fn capabilities(session: &JmapSession) -> Result<MailCapabilities, MailError> {
    let boxes = session.boxes().await?;
    let mut caps = basic_capabilities();
    caps.keywords = boxes.is_empty() || boxes.iter().any(|b| b.may_set_keywords != Some(false));
    caps.trash = boxes.iter().any(|b| b.role.as_deref() == Some("trash"));
    caps.copy = true;
    caps.append_received_at = true;
    caps.mailboxes = true;
    Ok(caps)
}

fn patch_all(items: &[ItemRef], patch: &Map<String, Value>) -> Vec<Change> {
    items
        .iter()
        .map(|i| Change::Update(i.id.clone(), patch.clone()))
        .collect()
}

/// Checks `from` (`MailboxNotFound`) and `to` (`no_such_mailbox`) for a move or copy.
async fn endpoints(
    session: &JmapSession,
    from: &str,
    to: &str,
) -> Result<Option<WriteOutcome>, MailError> {
    let found = session.existing(&[from, to]).await?;
    if !found[0] {
        return Err(MailError::MailboxNotFound);
    }
    if !found[1] {
        return Ok(Some(failed("no_such_mailbox")));
    }
    Ok(None)
}

pub(crate) async fn apply(
    session: &JmapSession,
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
            let Some(patch) = keyword_patch(add, remove) else {
                return Ok(failed("unsupported_flag"));
            };
            if !session.existing(&[mailbox]).await?[0] {
                return Err(MailError::MailboxNotFound);
            }
            if patch.is_empty() || items.is_empty() {
                return Ok(WriteOutcome::Applied);
            }
            Ok(outcome(session.set(patch_all(items, &patch), None).await?))
        }
        CommandBody::Move { from, to, items } => {
            if let Some(refused) = endpoints(session, from, to).await? {
                return Ok(refused);
            }
            if from == to || items.is_empty() {
                return Ok(WriteOutcome::Applied);
            }
            let mut patch = Map::new();
            patch.insert(format!("mailboxIds/{from}"), Value::Null);
            patch.insert(format!("mailboxIds/{to}"), json!(true));
            Ok(outcome(session.set(patch_all(items, &patch), None).await?))
        }
        CommandBody::Copy { from, to, items } => {
            if let Some(refused) = endpoints(session, from, to).await? {
                return Ok(refused);
            }
            if from == to || items.is_empty() {
                return Ok(WriteOutcome::Applied);
            }
            let mut patch = Map::new();
            patch.insert(format!("mailboxIds/{to}"), json!(true));
            Ok(outcome(session.set(patch_all(items, &patch), None).await?))
        }
        CommandBody::Delete {
            mailbox,
            items,
            to_trash: false,
        } => session.delete(mailbox, items).await,
        CommandBody::Delete {
            mailbox,
            items,
            to_trash: true,
        } => session.trash(mailbox, items).await,
        CommandBody::Append {
            mailbox,
            flags,
            received_at,
            ..
        } => {
            let Some(bytes) = content else {
                return Ok(failed("missing_content"));
            };
            session.append(mailbox, bytes, flags, *received_at).await
        }
        CommandBody::CreateMailbox { path } => session.create_mailbox(path).await,
        CommandBody::RenameMailbox { mailbox, path } => session.rename_mailbox(mailbox, path).await,
        CommandBody::DeleteMailbox { mailbox } => session.delete_mailbox(mailbox).await,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spells_keywords_and_refuses_the_rest() {
        assert_eq!(keyword("\\Seen").as_deref(), Some("$seen"));
        assert_eq!(keyword("$Forwarded").as_deref(), Some("$forwarded"));
        assert_eq!(keyword("\\Deleted"), None);
        assert_eq!(keyword("two words"), None);
        let patch = keyword_patch(
            &Flags::new(["\\Seen"]),
            &Flags::new(["\\Seen", "\\Flagged"]),
        )
        .unwrap();
        assert_eq!(patch["keywords/$seen"], json!(true));
        assert_eq!(patch["keywords/$flagged"], Value::Null);
    }
}
