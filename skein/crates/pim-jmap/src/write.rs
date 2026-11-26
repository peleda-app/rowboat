use bytes::Bytes;
use serde_json::{Map, Value, json};
use skein_core::{CollectionKind, ItemRef, PartStat};
use skein_pim::{PimError, PimWrite, RawObject, WriteOutcome};

use crate::{JmapSession, Kind, MAX_ITEM, member_of, method_error, split};

/// Properties the server sets itself. They are never sent, so an object fetched, changed and put
/// back is accepted.
const NOT_SENT: &[&str] = &[
    "id",
    "blobId",
    "created",
    "updated",
    "isOrigin",
    "utcStart",
    "utcEnd",
    "baseEventId",
];

/// Properties a replace never clears when the new object lacks them. Booleans are kept too:
/// JSCalendar gives them defaults, and Stalwart refuses `null` for them.
const KEPT: &[&str] = &["uid", "@type", "version"];

/// How often a write whose `ifInState` failed because another object changed is tried again.
const TRIES: usize = 5;

fn failed(reason: &str) -> WriteOutcome {
    WriteOutcome::Failed {
        reason: reason.into(),
    }
}

/// The object to send: a JSON object without server-set properties or the collection map. `Err`
/// with the refusal for anything else.
pub(crate) fn body(bytes: &Bytes, kind: &Kind) -> Result<Map<String, Value>, &'static str> {
    if bytes.len() > MAX_ITEM {
        return Err("too_large");
    }
    let Ok(Value::Object(mut object)) = serde_json::from_slice::<Value>(bytes) else {
        return Err("not_json");
    };
    object.retain(|key, _| !NOT_SENT.contains(&key.as_str()) && key != kind.member);
    Ok(object)
}

fn same_version(wanted: &str, held: Option<&str>) -> bool {
    held == Some(wanted.trim().trim_matches('"'))
}

/// Whether `found` holds every property of `sent` with the same value.
fn holds(found: &Value, sent: &Map<String, Value>) -> bool {
    sent.iter().all(|(k, v)| found.get(k) == Some(v))
}

/// A method error on `/set`: the refusals that are final for this write, or an error.
fn set_error(kind: &str) -> Result<WriteOutcome, PimError> {
    match kind {
        "accountReadOnly" | "forbidden" | "invalidArguments" => Ok(failed(kind)),
        "requestTooLarge" => Ok(failed("too_large")),
        _ => Err(method_error(kind)),
    }
}

fn item_error(answer: &Value, key: &str, id: &str) -> Option<String> {
    answer
        .get(key)?
        .get(id)?
        .get("type")
        .and_then(Value::as_str)
        .filter(|k| !k.is_empty() && k.len() <= 64 && k.chars().all(|c| c.is_ascii_alphanumeric()))
        .map(str::to_owned)
        .or_else(|| Some("unknown".into()))
}

/// The object in the collection with its raw form, and the item state of the read.
async fn current(
    session: &JmapSession,
    kind: &Kind,
    collection: &str,
    id: &str,
) -> Result<(Option<(Value, RawObject)>, String), PimError> {
    let (found, state) = session.get(kind, &[id.to_owned()], None).await?;
    let state = state.ok_or_else(|| crate::protocol("a JMAP get answer has no state"))?;
    let object = found
        .into_iter()
        .find(|v| v.get("id").and_then(Value::as_str) == Some(id))
        .filter(|v| member_of(v, kind.member, collection))
        .and_then(|v| Some((v.clone(), JmapSession::raw(kind, v)?)));
    Ok((object, state))
}

async fn applied(session: &JmapSession, kind: &Kind, collection: &str, id: &str) -> WriteOutcome {
    let current = current(session, kind, collection, id)
        .await
        .ok()
        .and_then(|(o, _)| o.map(|(_, raw)| raw));
    WriteOutcome::Applied {
        item: Some(ItemRef {
            id: id.to_owned(),
            uid: None,
        }),
        current,
    }
}

async fn set(
    session: &JmapSession,
    kind: &Kind,
    args: Value,
) -> Result<Option<Result<Value, String>>, PimError> {
    Ok(session
        .post(kind, vec![(format!("{}/set", kind.item), args)], false)
        .await?
        .and_then(|mut answers| answers.pop()))
}

async fn create(
    session: &JmapSession,
    kind: &Kind,
    collection: &str,
    bytes: &Bytes,
    key: &str,
    notify: bool,
) -> Result<WriteOutcome, PimError> {
    let mut object = match body(bytes, kind) {
        Ok(o) => o,
        Err(reason) => return Ok(failed(reason)),
    };
    object.insert(kind.member.into(), json!({ collection: true }));
    let uid = match object
        .get("uid")
        .and_then(Value::as_str)
        .filter(|u| !u.is_empty())
    {
        Some(uid) => uid.to_owned(),
        None => {
            object.insert("uid".into(), json!(key));
            key.to_owned()
        }
    };
    let account = session.account(kind)?;
    if let Some(outcome) = earlier(session, kind, collection, account, &uid, &object).await? {
        return Ok(outcome);
    }
    let mut args = json!({ "accountId": account, "create": { "c": object } });
    scheduling(&mut args, kind, notify);
    let Some(answer) = set(session, kind, args).await? else {
        return Ok(WriteOutcome::Uncertain);
    };
    let answer = match answer {
        Ok(a) => a,
        Err(kind) => return set_error(&kind),
    };
    if let Some(id) = answer.pointer("/created/c/id").and_then(Value::as_str) {
        return Ok(applied(session, kind, collection, id).await);
    }
    if uid_taken(&answer) {
        for attempt in 1..=5u64 {
            tokio::time::sleep(std::time::Duration::from_millis(100 * attempt)).await;
            if let Some(outcome) =
                earlier(session, kind, collection, account, &uid, &object).await?
            {
                return Ok(outcome);
            }
        }
        return Ok(WriteOutcome::Conflict { current: None });
    }
    Ok(match item_error(&answer, "notCreated", "c") {
        Some(reason) => WriteOutcome::Failed { reason },
        None => WriteOutcome::Uncertain,
    })
}

/// Whether a create was refused because an object with its `UID` exists already: `alreadyExists`,
/// or `invalidProperties` naming `uid` (Stalwart), which happens when the earlier object was
/// not yet visible to `/query`.
fn uid_taken(answer: &Value) -> bool {
    let Some(error) = answer.pointer("/notCreated/c") else {
        return false;
    };
    match error.get("type").and_then(Value::as_str) {
        Some("alreadyExists") => true,
        Some("invalidProperties") => error
            .get("properties")
            .and_then(Value::as_array)
            .is_some_and(|p| p.iter().any(|v| v.as_str() == Some("uid"))),
        _ => false,
    }
}

/// What an earlier create with the same `UID` left in the collection: the object itself when it
/// holds what this create would make (`Applied`), another one (`Conflict`), or nothing.
async fn earlier(
    session: &JmapSession,
    kind: &Kind,
    collection: &str,
    account: &str,
    uid: &str,
    object: &Map<String, Value>,
) -> Result<Option<WriteOutcome>, PimError> {
    let answers = session
        .read(
            kind,
            vec![(
                format!("{}/query", kind.item),
                json!({
                    "accountId": account,
                    "filter": { kind.filter: collection, "uid": uid },
                    "limit": 10,
                }),
            )],
        )
        .await?;
    let earlier = answers[0].as_ref().map_err(|k| method_error(k))?;
    let ids: Vec<String> = earlier
        .get("ids")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    if !ids.is_empty() {
        let (found, _) = session.get(kind, &ids, None).await?;
        let found: Vec<Value> = found
            .into_iter()
            .filter(|v| member_of(v, kind.member, collection))
            .collect();
        if let Some(same) = found.iter().find(|v| holds(v, object)) {
            let id = same.get("id").and_then(Value::as_str).unwrap_or_default();
            return Ok(Some(applied(session, kind, collection, id).await));
        }
        if let Some(other) = found.into_iter().next() {
            return Ok(Some(WriteOutcome::Conflict {
                current: JmapSession::raw(kind, other).and_then(|r| r.version),
            }));
        }
    }
    Ok(None)
}

/// Sets `sendSchedulingMessages` on a calendar `/set`; address books have no such argument.
fn scheduling(args: &mut Value, kind: &Kind, notify: bool) {
    if kind.kind == CollectionKind::Calendar {
        args["sendSchedulingMessages"] = json!(notify);
    }
}

/// Reads the object, checks `if_version`, and sends the update `make` builds from what is held,
/// under `ifInState` when a version was asked for. `make` may answer at once instead.
#[allow(clippy::too_many_arguments)]
async fn update(
    session: &JmapSession,
    kind: &Kind,
    collection: &str,
    id: &str,
    if_version: Option<&str>,
    notify: bool,
    mut make: impl FnMut(&Value, RawObject) -> Result<Map<String, Value>, Box<WriteOutcome>>,
) -> Result<WriteOutcome, PimError> {
    let account = session.account(kind)?;
    for _ in 0..TRIES {
        let (held, state) = current(session, kind, collection, id).await?;
        let Some((value, raw)) = held else {
            return Ok(WriteOutcome::Conflict { current: None });
        };
        if let Some(wanted) = if_version
            && !same_version(wanted, raw.version.as_deref())
        {
            return Ok(WriteOutcome::Conflict {
                current: raw.version,
            });
        }
        let patch = match make(&value, raw) {
            Ok(p) => p,
            Err(outcome) => return Ok(*outcome),
        };
        let mut args = json!({ "accountId": account, "update": { id: patch } });
        if if_version.is_some() {
            args["ifInState"] = json!(state);
        }
        scheduling(&mut args, kind, notify);
        let Some(answer) = set(session, kind, args).await? else {
            return Ok(WriteOutcome::Uncertain);
        };
        let answer = match answer {
            Ok(a) => a,
            Err(k) if k == "stateMismatch" => continue,
            Err(k) => return set_error(&k),
        };
        if answer.get("updated").and_then(|u| u.get(id)).is_some() {
            return Ok(applied(session, kind, collection, id).await);
        }
        return Ok(match item_error(&answer, "notUpdated", id) {
            Some(k) if k == "notFound" => WriteOutcome::Conflict { current: None },
            Some(reason) => WriteOutcome::Failed { reason },
            None => WriteOutcome::Uncertain,
        });
    }
    Err(PimError::Throttled { retry_after: None })
}

async fn replace(
    session: &JmapSession,
    kind: &Kind,
    collection: &str,
    id: &str,
    bytes: &Bytes,
    if_version: Option<&str>,
    notify: bool,
) -> Result<WriteOutcome, PimError> {
    let object = match body(bytes, kind) {
        Ok(o) => o,
        Err(reason) => return Ok(failed(reason)),
    };
    update(
        session,
        kind,
        collection,
        id,
        if_version,
        notify,
        |value, raw| {
            let mut patch = Map::new();
            for (k, v) in &object {
                if value.get(k) != Some(v) {
                    patch.insert(k.clone(), v.clone());
                }
            }
            if let Some(held) = value.as_object() {
                for (k, v) in held {
                    let kept = KEPT.contains(&k.as_str())
                        || NOT_SENT.contains(&k.as_str())
                        || k == kind.member
                        || v.is_boolean();
                    if !kept && !object.contains_key(k) {
                        patch.insert(k.clone(), Value::Null);
                    }
                }
            }
            if patch.is_empty() {
                return Err(Box::new(WriteOutcome::Applied {
                    item: Some(raw.item.clone()),
                    current: Some(raw),
                }));
            }
            Ok(patch)
        },
    )
    .await
}

async fn delete(
    session: &JmapSession,
    kind: &Kind,
    collection: &str,
    target: &ItemRef,
    if_version: Option<&str>,
    notify: bool,
) -> Result<WriteOutcome, PimError> {
    let gone = WriteOutcome::Applied {
        item: Some(target.clone()),
        current: None,
    };
    let account = session.account(kind)?;
    for _ in 0..TRIES {
        let (held, state) = current(session, kind, collection, &target.id).await?;
        let Some((_, raw)) = held else {
            return Ok(gone);
        };
        if let Some(wanted) = if_version
            && !same_version(wanted, raw.version.as_deref())
        {
            return Ok(WriteOutcome::Conflict {
                current: raw.version,
            });
        }
        let mut args = json!({ "accountId": account, "destroy": [target.id] });
        if if_version.is_some() {
            args["ifInState"] = json!(state);
        }
        scheduling(&mut args, kind, notify);
        let Some(answer) = set(session, kind, args).await? else {
            return Ok(WriteOutcome::Uncertain);
        };
        let answer = match answer {
            Ok(a) => a,
            Err(k) if k == "stateMismatch" => continue,
            Err(k) => return set_error(&k),
        };
        let destroyed = answer
            .get("destroyed")
            .and_then(Value::as_array)
            .is_some_and(|d| d.iter().any(|i| i.as_str() == Some(target.id.as_str())));
        if destroyed {
            return Ok(gone);
        }
        return Ok(match item_error(&answer, "notDestroyed", &target.id) {
            Some(k) if k == "notFound" => gone,
            Some(reason) => WriteOutcome::Failed { reason },
            None => WriteOutcome::Uncertain,
        });
    }
    Err(PimError::Throttled { retry_after: None })
}

/// A calendar address as Skein compares it: trimmed, without `mailto:`, lower case.
pub(crate) fn address(value: &str) -> String {
    let value = value.trim();
    let bare = match value.get(..7) {
        Some(scheme) if scheme.eq_ignore_ascii_case("mailto:") => &value[7..],
        _ => value,
    };
    bare.to_lowercase()
}

pub(crate) fn is_mailto(value: &str) -> bool {
    value
        .trim()
        .get(..7)
        .is_some_and(|s| s.eq_ignore_ascii_case("mailto:"))
}

/// The addresses a JSCalendar participant is reached at: its `mailto:` `calendarAddress`
/// (JSCalendar-bis, as Stalwart writes it) or `sendTo.imip` (RFC 8984), and its `email`.
pub(crate) fn reached_at(participant: &Value) -> Vec<String> {
    let uris = ["/calendarAddress", "/sendTo/imip"]
        .into_iter()
        .filter_map(|p| participant.pointer(p).and_then(Value::as_str))
        .filter(|v| is_mailto(v));
    let email = participant.get("email").and_then(Value::as_str);
    uris.chain(email).map(address).collect()
}

/// The id of the participant reached at one of `wanted`, preferring one with the `attendee` role.
pub(crate) fn participant(event: &Value, wanted: &[String]) -> Option<String> {
    let participants = event.get("participants")?.as_object()?;
    let matching: Vec<(&String, &Value)> = participants
        .iter()
        .filter(|(_, p)| reached_at(p).iter().any(|a| wanted.contains(a)))
        .collect();
    matching
        .iter()
        .find(|(_, p)| p.pointer("/roles/attendee").and_then(Value::as_bool) == Some(true))
        .or_else(|| matching.first())
        .map(|(id, _)| (*id).clone())
}

/// A participant id as one segment of a JMAP patch path (RFC 6901 escapes).
fn segment(id: &str) -> String {
    id.replace('~', "~0").replace('/', "~1")
}

fn status(answer: PartStat) -> &'static str {
    match answer {
        PartStat::Accepted => "accepted",
        PartStat::Declined => "declined",
        PartStat::Tentative => "tentative",
    }
}

/// The patch that answers as participant `who`: on the event's own `participants`, and on every
/// instance in `recurrenceOverrides` that is not excluded and changes participants itself,
/// either as a whole `participants` map (the participant reached at `wanted` there) or as a
/// patch of `participants/{who}/participationStatus`.
pub(crate) fn answer_patch(
    event: &Value,
    who: &str,
    wanted: &[String],
    answer: PartStat,
    comment: Option<&str>,
) -> Map<String, Value> {
    let mut patch = Map::new();
    let answer_at = |base: String, patch: &mut Map<String, Value>| {
        patch.insert(format!("{base}/participationStatus"), json!(status(answer)));
        if let Some(c) = comment {
            patch.insert(format!("{base}/participationComment"), json!(c));
        }
    };
    answer_at(format!("participants/{}", segment(who)), &mut patch);
    let Some(overrides) = event.get("recurrenceOverrides").and_then(Value::as_object) else {
        return patch;
    };
    for (rid, change) in overrides {
        if change.get("excluded").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let root = format!("recurrenceOverrides/{}", segment(rid));
        if change.get("participants").is_some() {
            if let Some(there) = participant(change, wanted) {
                answer_at(
                    format!("{root}/participants/{}", segment(&there)),
                    &mut patch,
                );
            }
            continue;
        }
        let key = format!("participants/{who}/participationStatus");
        if change.get(&key).is_some() {
            patch.insert(format!("{root}/{}", segment(&key)), json!(status(answer)));
        }
    }
    patch
}

#[allow(clippy::too_many_arguments)]
async fn respond(
    session: &JmapSession,
    kind: &Kind,
    collection: &str,
    id: &str,
    answer: PartStat,
    attendee: Option<&str>,
    comment: Option<&str>,
    if_version: Option<&str>,
    notify: bool,
) -> Result<WriteOutcome, PimError> {
    if kind.kind != CollectionKind::Calendar {
        return Ok(failed("not_a_calendar"));
    }
    let wanted = match attendee {
        Some(a) => vec![address(a)],
        None => session.own_addresses().await?,
    };
    update(
        session,
        kind,
        collection,
        id,
        if_version,
        notify,
        |value, _| {
            let Some(who) = participant(value, &wanted) else {
                return Err(Box::new(failed("attendee_not_found")));
            };
            Ok(answer_patch(value, &who, &wanted, answer, comment))
        },
    )
    .await
}

pub(crate) async fn apply(
    session: &JmapSession,
    write: &PimWrite,
) -> Result<WriteOutcome, PimError> {
    match write {
        PimWrite::Put {
            collection,
            item: None,
            bytes,
            key,
            notify,
            ..
        } => {
            let (kind, id) = split(collection)?;
            create(session, kind, id, bytes, key, *notify).await
        }
        PimWrite::Put {
            collection,
            item: Some(target),
            bytes,
            if_version,
            notify,
            ..
        } => {
            let (kind, id) = split(collection)?;
            replace(
                session,
                kind,
                id,
                &target.id,
                bytes,
                if_version.as_deref(),
                *notify,
            )
            .await
        }
        PimWrite::Delete {
            collection,
            item: target,
            if_version,
            notify,
        } => {
            let (kind, id) = split(collection)?;
            delete(session, kind, id, target, if_version.as_deref(), *notify).await
        }
        PimWrite::Respond {
            collection,
            item,
            answer,
            attendee,
            comment,
            if_version,
            notify,
        } => {
            let (kind, id) = split(collection)?;
            respond(
                session,
                kind,
                id,
                &item.id,
                *answer,
                attendee.as_deref(),
                comment.as_deref(),
                if_version.as_deref(),
                *notify,
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BOOKS, CALENDARS_KIND};

    #[test]
    fn server_set_properties_and_the_collection_map_are_not_sent() {
        let raw = Bytes::from_static(
            br#"{"id":"e1","uid":"u1@example.com","calendarIds":{"b":true},"updated":"2026-11-21T01:56:46Z","isOrigin":true,"title":"Planning"}"#,
        );
        let object = body(&raw, &CALENDARS_KIND).unwrap();
        let keys: Vec<&str> = object.keys().map(String::as_str).collect();
        assert_eq!(keys, ["title", "uid"]);
        assert_eq!(
            body(&Bytes::from_static(b"BEGIN:VCARD"), &BOOKS),
            Err("not_json")
        );
        assert!(same_version("\"abc\"", Some("abc")));
        assert!(!same_version("abc", None));
        assert_eq!(set_error("forbidden").unwrap(), failed("forbidden"));
        assert!(matches!(
            set_error("serverFail"),
            Err(PimError::Protocol(_))
        ));
    }

    #[test]
    fn participants_are_found_by_address_preferring_attendees() {
        assert_eq!(address(" MAILTO:Ada@Example.COM "), "ada@example.com");
        assert_eq!(address("ada@example.com"), "ada@example.com");
        let event = json!({ "participants": {
            "org": { "roles": { "owner": true }, "sendTo": { "imip": "mailto:ada@example.com" } },
            "a/1": { "roles": { "attendee": true }, "email": "Ada@example.com" },
            "web": { "sendTo": { "imip": "https://example.com/ada@example.org" } },
            "bis": { "calendarAddress": "mailto:Carol@example.org" },
        }});
        assert_eq!(
            participant(&event, &["carol@example.org".into()]).as_deref(),
            Some("bis")
        );
        assert_eq!(
            participant(&event, &["ada@example.com".into()]).as_deref(),
            Some("a/1")
        );
        assert_eq!(participant(&event, &["ada@example.org".into()]), None);
        assert_eq!(segment("a/1~x"), "a~11~0x");
    }

    #[test]
    fn creates_refused_for_a_taken_uid_are_recognised() {
        assert!(uid_taken(
            &json!({ "notCreated": { "c": { "type": "alreadyExists" } } })
        ));
        assert!(uid_taken(&json!({ "notCreated": { "c": {
            "type": "invalidProperties", "properties": ["uid"] } } })));
        assert!(!uid_taken(&json!({ "notCreated": { "c": {
            "type": "invalidProperties", "properties": ["title"] } } })));
        assert!(!uid_taken(&json!({ "created": { "c": { "id": "x" } } })));
    }

    #[test]
    fn answers_reach_instances_that_change_participants() {
        let event = json!({
            "participants": { "me": { "calendarAddress": "mailto:ada@example.com" } },
            "recurrenceOverrides": {
                "2026-12-08T10:00:00": { "participants": { "x": { "calendarAddress": "mailto:ada@example.com" } } },
                "2026-12-15T10:00:00": { "participants/me/participationStatus": "declined" },
                "2026-12-22T10:00:00": { "excluded": true, "participants/me/participationStatus": "declined" },
                "2026-12-29T10:00:00": { "title": "Moved" },
            },
        });
        let patch = answer_patch(
            &event,
            "me",
            &["ada@example.com".into()],
            PartStat::Accepted,
            Some("Fine"),
        );
        let keys: Vec<&str> = patch.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            vec![
                "participants/me/participationComment",
                "participants/me/participationStatus",
                "recurrenceOverrides/2026-12-08T10:00:00/participants/x/participationComment",
                "recurrenceOverrides/2026-12-08T10:00:00/participants/x/participationStatus",
                "recurrenceOverrides/2026-12-15T10:00:00/participants~1me~1participationStatus",
            ]
        );
        assert!(patch.values().all(|v| v == "accepted" || v == "Fine"));
    }
}
