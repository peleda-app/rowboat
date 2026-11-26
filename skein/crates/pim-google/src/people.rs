//! Contacts: `people.connections.list` of `people/me` with sync tokens, `people.batchGet`,
//! `people.get`, and `people.createContact`/`updateContact`/`deleteContact`.

use std::collections::HashMap;

use bytes::Bytes;
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use serde_json::value::RawValue;
use skein_core::ItemRef;
use skein_pim::{Cursor, PimChange, PimChanges, PimError, PimWrite, RawObject, WriteOutcome};

use crate::calendar::write_failure;
use crate::cursor::{Feed, Position};
use crate::http::{Api, Fail, Reply, endpoint, read_error, unexpected};
use crate::{CONTACTS, GoogleSession, Inner, Page, failed, item, object, reset, with_field};

/// The media type of a contact: the People API's person resource as JSON.
pub const PERSON_TYPE: &str = "application/json; profile=google-people-person";
/// The person fields read for every contact. Every field written is read too, so a replace
/// never clears a field the consumer could not see.
pub const READ_FIELDS: &str = "addresses,biographies,birthdays,emailAddresses,events,metadata,names,nicknames,organizations,phoneNumbers,photos,relations,urls,userDefined";
/// The person fields a replace sets: the read fields that `updateContact` accepts. Fields
/// missing from the object are cleared; photos change only through Google's own photo calls.
pub const UPDATE_FIELDS: &str = "addresses,biographies,birthdays,emailAddresses,events,names,nicknames,organizations,phoneNumbers,relations,urls,userDefined";
const MAX_PAGE: usize = 1000;
const BATCH: usize = 200;
const MAX_RESOURCE: usize = 128;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConnectionsPage<'a> {
    #[serde(borrow, default)]
    connections: Vec<&'a RawValue>,
    next_page_token: Option<String>,
    next_sync_token: Option<String>,
}

#[derive(Deserialize, Default)]
struct PersonMetadata {
    #[serde(default)]
    deleted: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersonMeta {
    resource_name: String,
    etag: Option<String>,
    #[serde(default)]
    metadata: PersonMetadata,
}

#[derive(Deserialize)]
struct BatchGet<'a> {
    #[serde(borrow, default)]
    responses: Vec<BatchEntry<'a>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BatchEntry<'a> {
    #[serde(borrow, default)]
    person: Option<&'a RawValue>,
}

/// The contact part of a resource name (`c123` in `people/c123`), when it is one.
fn contact_id(resource: &str) -> Option<&str> {
    let id = resource.strip_prefix("people/")?;
    (!id.is_empty() && id.len() <= MAX_RESOURCE && id.bytes().all(|b| b.is_ascii_alphanumeric()))
        .then_some(id)
}

fn raw_person(body: Bytes) -> Result<Option<RawObject>, PimError> {
    let meta: PersonMeta = serde_json::from_slice(&body).map_err(|_| unexpected())?;
    if meta.metadata.deleted || contact_id(&meta.resource_name).is_none() {
        return Ok(None);
    }
    Ok(Some(RawObject {
        item: item(&meta.resource_name),
        version: meta.etag,
        bytes: body,
        content_type: PERSON_TYPE.into(),
    }))
}

async fn list(s: &GoogleSession, pos: &Position, limit: usize) -> Result<Reply, PimError> {
    let mut url = endpoint(&s.inner.people, &["people", "me", "connections"]);
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("personFields", READ_FIELDS)
            .append_pair("pageSize", &limit.clamp(1, MAX_PAGE).to_string())
            .append_pair("requestSyncToken", "true");
        if let Some(sync) = &pos.s {
            q.append_pair("syncToken", sync);
        }
        if let Some(page) = &pos.p {
            q.append_pair("pageToken", page);
        }
    }
    s.inner
        .http
        .get(Api::People, url, s.inner.max_response)
        .await
}

pub(crate) async fn changes(
    s: &mut GoogleSession,
    cursor: Option<&Cursor>,
    limit: usize,
) -> Result<PimChanges, PimError> {
    let mut changes = Vec::new();
    let mut pos = match cursor {
        None => Position::start(Feed::Contacts),
        Some(c) => Position::read(c, Feed::Contacts).unwrap_or_else(|| {
            changes.push(reset("invalid_cursor"));
            Position::start(Feed::Contacts)
        }),
    };
    s.page = None;
    let reply = loop {
        let reply = list(s, &pos, limit).await?;
        if reply.status.is_success() {
            break reply;
        }
        let had_token = pos.s.is_some() || pos.p.is_some();
        let reason = match reply.status {
            StatusCode::GONE => "sync_token_expired",
            StatusCode::BAD_REQUEST if reply.has(&["EXPIRED_SYNC_TOKEN"]) => "sync_token_expired",
            StatusCode::BAD_REQUEST => "invalid_token",
            _ => return Err(read_error(&reply)),
        };
        if !had_token {
            return Err(read_error(&reply));
        }
        tracing::debug!(reason, "google contacts sync token refused");
        changes.push(reset(reason));
        pos = Position::start(Feed::Contacts);
    };
    let page: ConnectionsPage<'_> =
        serde_json::from_slice(&reply.body).map_err(|_| unexpected())?;
    let full = pos.full();
    let first = changes.len();
    let mut objects = HashMap::new();
    let mut seen: HashMap<String, usize> = HashMap::new();
    for raw in page.connections {
        let meta: PersonMeta = serde_json::from_str(raw.get()).map_err(|_| unexpected())?;
        if contact_id(&meta.resource_name).is_none() {
            continue;
        }
        let change = if meta.metadata.deleted {
            objects.remove(&meta.resource_name);
            if full {
                continue;
            }
            PimChange::Removed {
                item: item(&meta.resource_name),
            }
        } else {
            objects.insert(
                meta.resource_name.clone(),
                (
                    meta.etag.clone(),
                    reply.body.slice_ref(raw.get().as_bytes()),
                ),
            );
            PimChange::Upserted {
                item: item(&meta.resource_name),
                version: meta.etag,
            }
        };
        match seen.get(&meta.resource_name) {
            Some(&at) => changes[at] = change,
            None => {
                seen.insert(meta.resource_name, changes.len());
                changes.push(change);
            }
        }
    }
    let (next, more) = match (page.next_page_token, page.next_sync_token) {
        (Some(p), _) => (Position::new(Feed::Contacts, pos.s.clone(), Some(p)), true),
        (None, Some(sync)) => (Position::new(Feed::Contacts, Some(sync), None), false),
        (None, None) => {
            return Err(PimError::Protocol(
                "the People API ended a listing without a sync token".into(),
            ));
        }
    };
    tracing::debug!(
        changes = changes.len() - first,
        full,
        more,
        "google contacts changes"
    );
    s.page = Some(Page {
        collection: CONTACTS.to_owned(),
        objects,
    });
    Ok(PimChanges {
        changes,
        cursor: next.cursor(),
        more,
    })
}

pub(crate) async fn fetch(
    s: &mut GoogleSession,
    items: &[ItemRef],
) -> Result<Vec<RawObject>, PimError> {
    let mut out: Vec<RawObject> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    for it in items {
        if contact_id(&it.id).is_none()
            || out.iter().any(|o| o.item.id == it.id)
            || missing.contains(&it.id)
        {
            continue;
        }
        match s.cached(CONTACTS, &it.id) {
            Some((version, bytes)) => out.push(RawObject {
                item: item(&it.id),
                version,
                bytes,
                content_type: PERSON_TYPE.into(),
            }),
            None => missing.push(it.id.clone()),
        }
    }
    let inner = &s.inner;
    for chunk in missing.chunks(BATCH) {
        let mut url = endpoint(&inner.people, &["people:batchGet"]);
        {
            let mut q = url.query_pairs_mut();
            for rn in chunk {
                q.append_pair("resourceNames", rn);
            }
            q.append_pair("personFields", READ_FIELDS);
        }
        let reply = inner.http.get(Api::People, url, inner.max_response).await?;
        if !reply.status.is_success() {
            return Err(read_error(&reply));
        }
        let batch: BatchGet<'_> = serde_json::from_slice(&reply.body).map_err(|_| unexpected())?;
        for entry in batch.responses {
            let Some(raw) = entry.person else { continue };
            let Some(obj) = raw_person(reply.body.slice_ref(raw.get().as_bytes()))? else {
                continue;
            };
            if chunk.contains(&obj.item.id) && !out.iter().any(|o| o.item.id == obj.item.id) {
                out.push(obj);
            }
        }
    }
    Ok(out)
}

/// `people.get`; `None` when the contact is gone.
async fn get(inner: &Inner, contact: &str) -> Result<Option<RawObject>, PimError> {
    let mut url = endpoint(&inner.people, &["people", contact]);
    url.query_pairs_mut()
        .append_pair("personFields", READ_FIELDS);
    let reply = inner.http.get(Api::People, url, inner.max_response).await?;
    match reply.status {
        s if s.is_success() => raw_person(reply.body),
        StatusCode::NOT_FOUND | StatusCode::GONE => Ok(None),
        _ => Err(read_error(&reply)),
    }
}

fn applied(body: Bytes) -> Result<WriteOutcome, PimError> {
    let Some(current) = raw_person(body)? else {
        return Err(unexpected());
    };
    Ok(WriteOutcome::Applied {
        item: Some(current.item.clone()),
        current: Some(current),
    })
}

pub(crate) async fn apply(s: &mut GoogleSession, w: &PimWrite) -> Result<WriteOutcome, PimError> {
    let inner = s.inner.clone();
    let inner = &*inner;
    match w {
        PimWrite::Put {
            item: None,
            bytes,
            key,
            ..
        } => {
            if let Err(reason) = object(bytes, inner.max_object) {
                return Ok(failed(reason));
            }
            if let Some(rn) = s.created.get(key) {
                let contact = contact_id(rn).expect("a stored resource name is valid");
                return Ok(match get(inner, contact).await? {
                    Some(current) => WriteOutcome::Applied {
                        item: Some(current.item.clone()),
                        current: Some(current),
                    },
                    None => WriteOutcome::Conflict { current: None },
                });
            }
            let mut url = endpoint(&inner.people, &["people:createContact"]);
            url.query_pairs_mut()
                .append_pair("personFields", READ_FIELDS);
            let reply = match inner
                .http
                .call(
                    Api::People,
                    Method::POST,
                    url,
                    None,
                    Some(bytes.clone()),
                    inner.max_response,
                )
                .await
            {
                Ok(r) => r,
                Err(Fail::NotSent(e)) => return Err(e),
                Err(Fail::Lost(_)) => return Ok(WriteOutcome::Uncertain),
            };
            if !reply.status.is_success() {
                return write_failure(&reply, false);
            }
            let Ok(Some(current)) = raw_person(reply.body) else {
                return Ok(WriteOutcome::Uncertain);
            };
            s.created.insert(key.clone(), current.item.id.clone());
            Ok(WriteOutcome::Applied {
                item: Some(current.item.clone()),
                current: Some(current),
            })
        }
        PimWrite::Put {
            item: Some(target),
            bytes,
            if_version,
            ..
        } => {
            let Some(contact) = contact_id(&target.id) else {
                return Ok(failed("not_in_collection"));
            };
            let map = match object(bytes, inner.max_object) {
                Ok(m) => m,
                Err(reason) => return Ok(failed(reason)),
            };
            let etag = match if_version {
                Some(v) => v.clone(),
                None => match get(inner, contact).await?.and_then(|o| o.version) {
                    Some(v) => v,
                    None => return Ok(WriteOutcome::Conflict { current: None }),
                },
            };
            let body = with_field(bytes, &map, "etag", &etag);
            let mut url = endpoint(
                &inner.people,
                &["people", &format!("{contact}:updateContact")],
            );
            url.query_pairs_mut()
                .append_pair("updatePersonFields", UPDATE_FIELDS)
                .append_pair("personFields", READ_FIELDS);
            let reply = inner
                .http
                .call(
                    Api::People,
                    Method::PATCH,
                    url,
                    None,
                    Some(body),
                    inner.max_response,
                )
                .await
                .map_err(Fail::into_error)?;
            match reply.status {
                s if s.is_success() => applied(reply.body),
                StatusCode::BAD_REQUEST if reply.has(&["FAILED_PRECONDITION"]) => {
                    Ok(WriteOutcome::Conflict {
                        current: get(inner, contact).await?.and_then(|o| o.version),
                    })
                }
                StatusCode::NOT_FOUND | StatusCode::GONE => {
                    Ok(WriteOutcome::Conflict { current: None })
                }
                _ => write_failure(&reply, true),
            }
        }
        PimWrite::Delete {
            item: target,
            if_version,
            ..
        } => {
            let gone = WriteOutcome::Applied {
                item: Some(target.clone()),
                current: None,
            };
            let Some(contact) = contact_id(&target.id) else {
                return Ok(gone);
            };
            if let Some(want) = if_version {
                match get(inner, contact).await?.and_then(|o| o.version) {
                    None => return Ok(gone),
                    Some(have) if &have != want => {
                        return Ok(WriteOutcome::Conflict {
                            current: Some(have),
                        });
                    }
                    Some(_) => {}
                }
            }
            let url = endpoint(
                &inner.people,
                &["people", &format!("{contact}:deleteContact")],
            );
            let reply = inner
                .http
                .call(
                    Api::People,
                    Method::DELETE,
                    url,
                    None,
                    None,
                    inner.max_response,
                )
                .await
                .map_err(Fail::into_error)?;
            match reply.status {
                s if s.is_success() => Ok(gone),
                StatusCode::NOT_FOUND | StatusCode::GONE => Ok(gone),
                _ => write_failure(&reply, true),
            }
        }
        PimWrite::Respond { .. } => Ok(failed("not_a_calendar")),
    }
}

/// Reads `bytes` as each People API answer: a connections page, a batch get and one person.
/// For the fuzz targets.
pub(crate) fn fuzz(bytes: &[u8]) {
    let body = Bytes::copy_from_slice(bytes);
    if let Ok(page) = serde_json::from_slice::<ConnectionsPage<'_>>(&body) {
        for raw in page.connections {
            if let Ok(meta) = serde_json::from_str::<PersonMeta>(raw.get()) {
                let _ = contact_id(&meta.resource_name);
                let _ = body.slice_ref(raw.get().as_bytes());
            }
        }
    }
    if let Ok(batch) = serde_json::from_slice::<BatchGet<'_>>(&body) {
        for entry in batch.responses {
            if let Some(raw) = entry.person {
                let _ = raw_person(body.slice_ref(raw.get().as_bytes()));
            }
        }
    }
    let _ = raw_person(body);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_names_are_checked() {
        assert_eq!(contact_id("people/c123"), Some("c123"));
        assert_eq!(contact_id("people/c1/x"), None);
        assert_eq!(contact_id("people/"), None);
        assert_eq!(contact_id("people/me:x"), None);
        assert_eq!(contact_id("contactGroups/abc"), None);
        assert!(
            UPDATE_FIELDS
                .split(',')
                .all(|f| READ_FIELDS.split(',').any(|r| r == f))
        );
    }
}
