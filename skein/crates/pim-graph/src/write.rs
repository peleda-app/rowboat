use bytes::Bytes;
use reqwest::Method;
use serde_json::{Map, Value, json};
use skein_core::{ItemRef, PartStat};
use skein_pim::{PimError, PimWrite, RawObject, WriteOutcome};

use crate::http::{MAX_ITEM, Read, Scope, Wrote};
use crate::{GraphSession, Place, bare, json, string};

/// The single-value extended property a contact created through Skein carries its command id
/// in, so a repeated create finds the contact instead of making a second one. Events use Graph's
/// own `transactionId`.
pub const CREATE_KEY_PROPERTY: &str =
    "String {3b8e5f1a-9c2d-4e7b-a6f0-5d1c8b2e7a94} Name SkeinCreateKey";

/// The largest object Graph takes in one request.
pub const MAX_WRITE: usize = 4 * 1024 * 1024;

/// Properties Graph sets itself. They are dropped from what is sent, so an object fetched,
/// changed and put back is accepted.
const READ_ONLY: &[&str] = &[
    "id",
    "changeKey",
    "createdDateTime",
    "lastModifiedDateTime",
    "parentFolderId",
    "iCalUId",
    "uid",
    "seriesMasterId",
    "type",
    "webLink",
    "isOrganizer",
    "responseStatus",
    "bodyPreview",
    "isCancelled",
    "originalStart",
    "occurrenceId",
    "cancelledOccurrences",
    "exceptionOccurrences",
    "hasAttachments",
    "isDraft",
    "transactionId",
];

fn quoted(tag: &str) -> String {
    format!("W/\"{}\"", bare(tag))
}

fn failed(reason: &str) -> WriteOutcome {
    WriteOutcome::Failed {
        reason: reason.into(),
    }
}

/// The object to send: a JSON object without Graph's own properties. `Err` with the refusal for
/// anything else.
pub(crate) fn body(bytes: &Bytes) -> Result<Map<String, Value>, &'static str> {
    if bytes.len() > MAX_WRITE {
        return Err("too_large");
    }
    let Ok(Value::Object(mut object)) = serde_json::from_slice::<Value>(bytes) else {
        return Err("not_json");
    };
    object.retain(|key, _| {
        !key.starts_with("@odata.") && !key.contains("@odata.") && !READ_ONLY.contains(&&**key)
    });
    Ok(object)
}

async fn applied(session: &GraphSession, place: &Place, id: &str) -> WriteOutcome {
    let current = session.read_one(place, id).await.ok().flatten();
    WriteOutcome::Applied {
        item: Some(ItemRef {
            id: id.to_owned(),
            uid: None,
        }),
        current,
    }
}

pub(crate) fn usable(id: &str) -> bool {
    !id.is_empty() && !id.contains('/')
}

/// The contact an earlier create with `key` made, if any.
async fn created_contact(
    session: &GraphSession,
    place: &Place,
    key: &str,
) -> Result<Option<String>, PimError> {
    let filter = format!(
        "singleValueExtendedProperties/Any(ep: ep/id eq '{CREATE_KEY_PROPERTY}' and ep/value eq '{}')",
        key.replace('\'', "''")
    );
    let url = session.endpoint(&place.items(), &[("$filter", &filter), ("$select", "id")])?;
    match session
        .http
        .get(url, Scope::Account, None, crate::http::MAX_LISTING)
        .await?
    {
        Read::Found(body) => Ok(json(&body)?
            .get("value")
            .and_then(Value::as_array)
            .and_then(|items| items.iter().find_map(|i| string(i, "id")))),
        Read::Missing | Read::Gone => Err(PimError::NotFound),
        Read::Refused => Err(crate::protocol(
            "Microsoft Graph refused to look up a created contact",
        )),
    }
}

async fn create(
    session: &GraphSession,
    place: &Place,
    bytes: &Bytes,
    key: &str,
) -> Result<WriteOutcome, PimError> {
    let mut object = match body(bytes) {
        Ok(o) => o,
        Err(reason) => return Ok(failed(reason)),
    };
    match place {
        Place::Calendar(_) => {
            object.insert("transactionId".into(), json!(key));
        }
        Place::Contacts(_) => {
            if let Some(id) = created_contact(session, place, key).await? {
                return Ok(applied(session, place, &id).await);
            }
            let mut properties = match object.remove("singleValueExtendedProperties") {
                Some(Value::Array(list)) => list,
                _ => Vec::new(),
            };
            properties.retain(|p| p.get("id").and_then(Value::as_str) != Some(CREATE_KEY_PROPERTY));
            properties.push(json!({ "id": CREATE_KEY_PROPERTY, "value": key }));
            object.insert(
                "singleValueExtendedProperties".into(),
                Value::Array(properties),
            );
        }
    }
    let url = session.endpoint(&place.items(), &[])?;
    let reply = session
        .http
        .write(Method::POST, url, Some(&Value::Object(object)), None)
        .await?;
    Ok(match reply {
        Wrote::Done(answer) => match serde_json::from_slice::<Value>(&answer)
            .ok()
            .and_then(|v| string(&v, "id"))
            .filter(|id| usable(id))
        {
            Some(id) => applied(session, place, &id).await,
            None => WriteOutcome::Uncertain,
        },
        Wrote::Missing => return Err(PimError::NotFound),
        Wrote::Stale => WriteOutcome::Conflict { current: None },
        Wrote::Refused(reason) | Wrote::Invalid(reason) => WriteOutcome::Failed { reason },
        Wrote::Uncertain => WriteOutcome::Uncertain,
    })
}

async fn replace(
    session: &GraphSession,
    place: &Place,
    id: &str,
    bytes: &Bytes,
    if_version: Option<&str>,
) -> Result<WriteOutcome, PimError> {
    let object = match body(bytes) {
        Ok(o) => o,
        Err(reason) => return Ok(failed(reason)),
    };
    let if_match = if_version.map(quoted);
    let reply = session
        .http
        .write(
            Method::PATCH,
            session.item_url(place, id)?,
            Some(&Value::Object(object)),
            if_match.as_deref(),
        )
        .await?;
    Ok(match reply {
        Wrote::Done(_) => applied(session, place, id).await,
        Wrote::Missing => WriteOutcome::Conflict { current: None },
        Wrote::Stale => WriteOutcome::Conflict {
            current: session.read_one(place, id).await?.and_then(|o| o.version),
        },
        Wrote::Refused(reason) | Wrote::Invalid(reason) => WriteOutcome::Failed { reason },
        Wrote::Uncertain => WriteOutcome::Uncertain,
    })
}

async fn delete(
    session: &GraphSession,
    place: &Place,
    target: &ItemRef,
    if_version: Option<&str>,
) -> Result<WriteOutcome, PimError> {
    let gone = WriteOutcome::Applied {
        item: Some(target.clone()),
        current: None,
    };
    let if_match = if_version.map(quoted);
    let reply = session
        .http
        .write(
            Method::DELETE,
            session.item_url(place, &target.id)?,
            None,
            if_match.as_deref(),
        )
        .await?;
    Ok(match reply {
        Wrote::Done(_) | Wrote::Missing => gone,
        Wrote::Stale => match session.read_one(place, &target.id).await? {
            None => gone,
            Some(o) => WriteOutcome::Conflict { current: o.version },
        },
        Wrote::Refused(reason) | Wrote::Invalid(reason) => WriteOutcome::Failed { reason },
        Wrote::Uncertain => WriteOutcome::Uncertain,
    })
}

pub(crate) async fn apply(
    session: &GraphSession,
    write: &PimWrite,
) -> Result<WriteOutcome, PimError> {
    match write {
        PimWrite::Put {
            collection,
            item: None,
            bytes,
            key,
            ..
        } => create(session, &Place::of(collection)?, bytes, key).await,
        PimWrite::Put {
            collection,
            item: Some(target),
            bytes,
            if_version,
            ..
        } => {
            let place = Place::of(collection)?;
            if !usable(&target.id) {
                return Ok(failed("not_in_collection"));
            }
            replace(session, &place, &target.id, bytes, if_version.as_deref()).await
        }
        PimWrite::Delete {
            collection,
            item: target,
            if_version,
            ..
        } => {
            let place = Place::of(collection)?;
            if !usable(&target.id) {
                return Ok(failed("not_in_collection"));
            }
            delete(session, &place, target, if_version.as_deref()).await
        }
        PimWrite::Respond {
            collection,
            item: target,
            answer,
            attendee,
            comment,
            if_version,
            notify,
        } => {
            let place = Place::of(collection)?;
            if matches!(place, Place::Contacts(_)) {
                return Ok(failed("not_a_calendar"));
            }
            if !usable(&target.id) {
                return Ok(failed("not_in_collection"));
            }
            respond(
                session,
                &place,
                &target.id,
                *answer,
                Answer {
                    attendee: attendee.as_deref(),
                    comment: comment.as_deref(),
                    if_version: if_version.as_deref(),
                    notify: *notify,
                },
            )
            .await
        }
    }
}

struct Answer<'a> {
    attendee: Option<&'a str>,
    comment: Option<&'a str>,
    if_version: Option<&'a str>,
    notify: bool,
}

fn action(answer: PartStat) -> &'static str {
    match answer {
        PartStat::Accepted => "accept",
        PartStat::Declined => "decline",
        PartStat::Tentative => "tentativelyAccept",
    }
}

pub(crate) fn invites(event: &Value, address: &str) -> bool {
    event
        .get("attendees")
        .and_then(Value::as_array)
        .is_some_and(|list| {
            list.iter().any(|a| {
                a.pointer("/emailAddress/address")
                    .and_then(Value::as_str)
                    .is_some_and(|e| e.trim().eq_ignore_ascii_case(address.trim()))
            })
        })
}

pub(crate) fn organizes(event: Option<&RawObject>) -> bool {
    event
        .and_then(|o| serde_json::from_slice::<Value>(&o.bytes).ok())
        .and_then(|v| v.get("isOrganizer").and_then(Value::as_bool))
        == Some(true)
}

/// `accept`, `decline` or `tentativelyAccept` on the event. Graph answers only for the signed-in
/// attendee, so a named attendee is only checked against the event's attendees.
async fn respond(
    session: &GraphSession,
    place: &Place,
    id: &str,
    answer: PartStat,
    with: Answer<'_>,
) -> Result<WriteOutcome, PimError> {
    if with.if_version.is_some() || with.attendee.is_some() {
        let Some(current) = session.read_one(place, id).await? else {
            return Ok(WriteOutcome::Conflict { current: None });
        };
        if let Some(want) = with.if_version
            && current.version.as_deref().map(bare) != Some(bare(want))
        {
            return Ok(WriteOutcome::Conflict {
                current: current.version,
            });
        }
        if let Some(address) = with.attendee
            && !invites(&json(&current.bytes)?, address)
        {
            return Ok(failed("attendee_not_found"));
        }
    }
    let mut body = Map::new();
    if let Some(comment) = with.comment {
        body.insert("comment".into(), json!(comment));
    }
    body.insert("sendResponse".into(), json!(with.notify));
    let mut url = session.item_url(place, id)?;
    url.path_segments_mut()
        .map_err(|_| PimError::Config("the Graph address cannot take a path".into()))?
        .push(action(answer));
    let reply = session
        .http
        .write(Method::POST, url, Some(&Value::Object(body)), None)
        .await?;
    Ok(match reply {
        Wrote::Done(_) => applied(session, place, id).await,
        Wrote::Missing => WriteOutcome::Conflict { current: None },
        Wrote::Stale => WriteOutcome::Conflict {
            current: session.read_one(place, id).await?.and_then(|o| o.version),
        },
        Wrote::Invalid(reason) => {
            if organizes(session.read_one(place, id).await?.as_ref()) {
                failed("not_invited")
            } else {
                WriteOutcome::Failed { reason }
            }
        }
        Wrote::Refused(reason) => WriteOutcome::Failed { reason },
        Wrote::Uncertain => WriteOutcome::Uncertain,
    })
}

/// The mailbox user's `mail` and `userPrincipalName`, lower case, each once, only addresses.
pub(crate) async fn addresses(session: &GraphSession) -> Result<Vec<String>, PimError> {
    let url = session.endpoint(&[], &[("$select", "mail,userPrincipalName")])?;
    let user = match session
        .http
        .get(url, Scope::Account, None, MAX_ITEM)
        .await?
    {
        Read::Found(body) => json(&body)?,
        Read::Missing | Read::Gone => return Ok(Vec::new()),
        Read::Refused => return Err(crate::protocol("Microsoft Graph refused to read the user")),
    };
    let mut out: Vec<String> = Vec::new();
    for key in ["mail", "userPrincipalName"] {
        if let Some(address) = string(&user, key)
            .map(|a| a.to_lowercase())
            .filter(|a| a.contains('@'))
            && !out.contains(&address)
        {
            out.push(address);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_owned_properties_are_dropped_and_others_kept() {
        let raw = Bytes::from_static(
            br#"{"@odata.context":"x","@odata.etag":"W/\"1\"","id":"AAMk","changeKey":"1",
            "subject":"Planning","calendar@odata.navigationLink":"y","start":{"dateTime":"2026-12-01T10:00:00","timeZone":"UTC"}}"#,
        );
        let object = body(&raw).unwrap();
        let keys: Vec<&str> = object.keys().map(String::as_str).collect();
        assert_eq!(keys, ["start", "subject"]);
        assert_eq!(
            body(&Bytes::from_static(b"BEGIN:VCALENDAR")),
            Err("not_json")
        );
        assert_eq!(body(&Bytes::from_static(b"[1]")), Err("not_json"));
        assert_eq!(
            body(&Bytes::from(vec![b' '; MAX_WRITE + 1])),
            Err("too_large")
        );
        assert_eq!(quoted("W/\"abc\""), "W/\"abc\"");
        assert_eq!(quoted("abc"), "W/\"abc\"");
    }
}
