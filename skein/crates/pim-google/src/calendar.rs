//! Calendars: `calendarList.list`, `events.list` with sync tokens, `events.get`,
//! `events.insert`/`update`/`delete`, and answers as `events.patch` of `attendees`.

use std::collections::HashMap;

use bytes::Bytes;
use futures::StreamExt;
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use serde_json::value::RawValue;
use skein_core::{CollectionInfo, CollectionKind, ItemRef, PartStat};
use skein_pim::{Cursor, PimChange, PimChanges, PimError, PimWrite, RawObject, WriteOutcome};

use crate::cursor::{Feed, Position};
use crate::http::{self, Api, Fail, Reply, endpoint, read_error, unexpected};
use crate::{GoogleSession, Inner, Page, failed, item, object, reset, with_field};

/// The media type of an event: the Calendar API's event resource as JSON.
pub const EVENT_TYPE: &str = "application/json; profile=google-calendar-event";
const MAX_PAGE: usize = 2500;
const CONCURRENCY: usize = 4;
const MAX_CALENDAR_PAGES: usize = 100;
/// Event ids that `insert` accepts: base32hex letters and digits, 5 to 1024 of them.
const MAX_ID: usize = 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CalendarList {
    #[serde(default)]
    items: Vec<CalendarEntry>,
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CalendarEntry {
    id: String,
    summary: Option<String>,
    summary_override: Option<String>,
    background_color: Option<String>,
    access_role: Option<String>,
    #[serde(default)]
    deleted: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EventsPage<'a> {
    #[serde(borrow, default)]
    items: Vec<&'a RawValue>,
    next_page_token: Option<String>,
    next_sync_token: Option<String>,
}

#[derive(Deserialize)]
struct EventMeta {
    id: String,
    etag: Option<String>,
    status: Option<String>,
}

impl EventMeta {
    fn cancelled(&self) -> bool {
        self.status.as_deref() == Some("cancelled")
    }
}

/// Ids that can be event ids; anything else is treated as an event that does not exist.
fn plausible(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'@'))
}

/// The event id a create with `key` gets: `skein` and the key in lower-case base32hex, so
/// different keys never share an id and a repeated create meets the event it made.
pub(crate) fn id_for_key(key: &str) -> Option<String> {
    const ALPHABET: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
    if key.is_empty() {
        return None;
    }
    let mut out = String::from("skein");
    let mut acc: u32 = 0;
    let mut bits = 0;
    for b in key.bytes() {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((acc >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((acc << (5 - bits)) & 31) as usize]));
    }
    (out.len() <= MAX_ID).then_some(out)
}

pub(crate) async fn collections(inner: &Inner) -> Result<Vec<CollectionInfo>, PimError> {
    let mut out = Vec::new();
    let mut page: Option<String> = None;
    for _ in 0..MAX_CALENDAR_PAGES {
        let mut url = endpoint(&inner.calendar, &["users", "me", "calendarList"]);
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("maxResults", "250")
                .append_pair("showHidden", "true");
            if let Some(p) = &page {
                q.append_pair("pageToken", p);
            }
        }
        let reply = inner
            .http
            .get(Api::Calendar, url, inner.max_response)
            .await?;
        if !reply.status.is_success() {
            return Err(read_error(&reply));
        }
        let list: CalendarList = serde_json::from_slice(&reply.body).map_err(|_| unexpected())?;
        for c in list.items {
            if c.deleted || c.id.is_empty() || out.iter().any(|o: &CollectionInfo| o.id == c.id) {
                continue;
            }
            let read_only = matches!(
                c.access_role.as_deref(),
                Some("reader" | "freeBusyReader") | None
            );
            out.push(CollectionInfo {
                name: c
                    .summary_override
                    .or(c.summary)
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| c.id.clone()),
                id: c.id,
                kind: CollectionKind::Calendar,
                color: c.background_color,
                read_only,
                components: vec!["VEVENT".into()],
                role: None,
            });
        }
        match list.next_page_token {
            Some(next) => page = Some(next),
            None => return Ok(out),
        }
    }
    Err(PimError::Protocol("the calendar list never ended".into()))
}

async fn list(
    s: &GoogleSession,
    calendar: &str,
    pos: &Position,
    limit: usize,
) -> Result<Reply, PimError> {
    let mut url = endpoint(&s.inner.calendar, &["calendars", calendar, "events"]);
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("maxResults", &limit.clamp(1, MAX_PAGE).to_string())
            .append_pair("showDeleted", "true")
            .append_pair("singleEvents", "false");
        if let Some(sync) = &pos.s {
            q.append_pair("syncToken", sync);
        }
        if let Some(page) = &pos.p {
            q.append_pair("pageToken", page);
        }
    }
    s.inner
        .http
        .get(Api::Calendar, url, s.inner.max_response)
        .await
}

pub(crate) async fn changes(
    s: &mut GoogleSession,
    calendar: &str,
    cursor: Option<&Cursor>,
    limit: usize,
) -> Result<PimChanges, PimError> {
    let mut changes = Vec::new();
    let mut pos = match cursor {
        None => Position::start(Feed::Events),
        Some(c) => Position::read(c, Feed::Events).unwrap_or_else(|| {
            changes.push(reset("invalid_cursor"));
            Position::start(Feed::Events)
        }),
    };
    s.page = None;
    let reply = loop {
        let reply = list(s, calendar, &pos, limit).await?;
        if reply.status.is_success() {
            break reply;
        }
        let had_token = pos.s.is_some() || pos.p.is_some();
        let reason = match reply.status {
            StatusCode::GONE => "sync_token_expired",
            StatusCode::BAD_REQUEST => "invalid_token",
            _ => return Err(read_error(&reply)),
        };
        if !had_token {
            return Err(read_error(&reply));
        }
        tracing::debug!(reason, "google calendar sync token refused");
        changes.push(reset(reason));
        pos = Position::start(Feed::Events);
    };
    let page: EventsPage<'_> = serde_json::from_slice(&reply.body).map_err(|_| unexpected())?;
    let mut objects = HashMap::new();
    let mut seen: HashMap<String, usize> = HashMap::new();
    let full = pos.full();
    let first = changes.len();
    for raw in page.items {
        let meta: EventMeta = serde_json::from_str(raw.get()).map_err(|_| unexpected())?;
        let change = if meta.cancelled() {
            objects.remove(&meta.id);
            if full {
                continue;
            }
            PimChange::Removed {
                item: item(&meta.id),
            }
        } else {
            objects.insert(
                meta.id.clone(),
                (
                    meta.etag.clone(),
                    reply.body.slice_ref(raw.get().as_bytes()),
                ),
            );
            PimChange::Upserted {
                item: item(&meta.id),
                version: meta.etag,
            }
        };
        match seen.get(&meta.id) {
            Some(&at) => changes[at] = change,
            None => {
                seen.insert(meta.id, changes.len());
                changes.push(change);
            }
        }
    }
    let (next, more) = match (page.next_page_token, page.next_sync_token) {
        (Some(p), _) => (Position::new(Feed::Events, pos.s.clone(), Some(p)), true),
        (None, Some(sync)) => (Position::new(Feed::Events, Some(sync), None), false),
        (None, None) => {
            return Err(PimError::Protocol(
                "the Calendar API ended a listing without a sync token".into(),
            ));
        }
    };
    tracing::debug!(
        changes = changes.len() - first,
        full,
        more,
        "google calendar changes"
    );
    s.page = Some(Page {
        collection: calendar.to_owned(),
        objects,
    });
    Ok(PimChanges {
        changes,
        cursor: next.cursor(),
        more,
    })
}

fn raw_event(id: &str, body: Bytes) -> Result<Option<RawObject>, PimError> {
    let meta: EventMeta = serde_json::from_slice(&body).map_err(|_| unexpected())?;
    if meta.cancelled() {
        return Ok(None);
    }
    Ok(Some(RawObject {
        item: item(id),
        version: meta.etag,
        bytes: body,
        content_type: EVENT_TYPE.into(),
    }))
}

enum Probe {
    Live(RawObject),
    Cancelled,
    Missing,
}

/// `events.get`. Google keeps deleted events as cancelled ones, and their ids stay taken.
async fn probe(inner: &Inner, calendar: &str, id: &str) -> Result<Probe, PimError> {
    let url = endpoint(&inner.calendar, &["calendars", calendar, "events", id]);
    let reply = inner
        .http
        .get(Api::Calendar, url, inner.max_response)
        .await?;
    match reply.status {
        s if s.is_success() => Ok(match raw_event(id, reply.body)? {
            Some(o) => Probe::Live(o),
            None => Probe::Cancelled,
        }),
        StatusCode::GONE => Ok(Probe::Cancelled),
        StatusCode::NOT_FOUND => Ok(Probe::Missing),
        _ => Err(read_error(&reply)),
    }
}

/// `events.get`; `None` when the event is gone or cancelled.
async fn get(inner: &Inner, calendar: &str, id: &str) -> Result<Option<RawObject>, PimError> {
    Ok(match probe(inner, calendar, id).await? {
        Probe::Live(o) => Some(o),
        Probe::Cancelled | Probe::Missing => None,
    })
}

pub(crate) async fn fetch(
    s: &mut GoogleSession,
    calendar: &str,
    items: &[ItemRef],
) -> Result<Vec<RawObject>, PimError> {
    let mut out = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    for it in items {
        if !plausible(&it.id)
            || out.iter().any(|o: &RawObject| o.item.id == it.id)
            || missing.contains(&it.id)
        {
            continue;
        }
        match s.cached(calendar, &it.id) {
            Some((version, bytes)) => out.push(RawObject {
                item: item(&it.id),
                version,
                bytes,
                content_type: EVENT_TYPE.into(),
            }),
            None => missing.push(it.id.clone()),
        }
    }
    let inner = s.inner.clone();
    let got: Vec<Result<Option<RawObject>, PimError>> = futures::stream::iter(missing)
        .map(|id| {
            let inner = inner.clone();
            let calendar = calendar.to_owned();
            async move { get(&inner, &calendar, &id).await }
        })
        .buffered(CONCURRENCY)
        .collect()
        .await;
    for r in got {
        if let Some(o) = r? {
            out.push(o);
        }
    }
    Ok(out)
}

/// The outcome of an unsuccessful write that the caller did not handle itself.
pub(crate) fn write_failure(reply: &Reply, repeatable: bool) -> Result<WriteOutcome, PimError> {
    if let Some(e) = http::common(reply) {
        return Err(e);
    }
    if http::scope_missing(reply) {
        return Ok(failed("insufficient_scope"));
    }
    Ok(match reply.status {
        StatusCode::FORBIDDEN if reply.has(&["requiredAccessLevel", "PERMISSION_DENIED"]) => {
            failed("read_only")
        }
        StatusCode::FORBIDDEN => failed("forbidden"),
        StatusCode::PAYLOAD_TOO_LARGE => failed("too_large"),
        StatusCode::BAD_REQUEST => failed("invalid_object"),
        s if s.is_server_error() && repeatable => {
            return Err(PimError::Network(format!("a Google API answered {s}")));
        }
        s if s.is_server_error() => WriteOutcome::Uncertain,
        s => failed(&format!("refused_{}", s.as_u16())),
    })
}

fn applied(id: &str, body: Bytes) -> WriteOutcome {
    WriteOutcome::Applied {
        item: Some(item(id)),
        current: raw_event(id, body).ok().flatten(),
    }
}

async fn current_version(
    inner: &Inner,
    calendar: &str,
    id: &str,
) -> Result<Option<String>, PimError> {
    Ok(get(inner, calendar, id).await?.and_then(|o| o.version))
}

fn events_url(inner: &Inner, calendar: &str, id: Option<&str>, notify: bool) -> url::Url {
    let mut url = match id {
        Some(id) => endpoint(&inner.calendar, &["calendars", calendar, "events", id]),
        None => endpoint(&inner.calendar, &["calendars", calendar, "events"]),
    };
    url.query_pairs_mut()
        .append_pair("sendUpdates", if notify { "all" } else { "none" });
    url
}

pub(crate) async fn apply(s: &mut GoogleSession, w: &PimWrite) -> Result<WriteOutcome, PimError> {
    let inner = s.inner.clone();
    let inner = &*inner;
    match w {
        PimWrite::Put {
            collection,
            item: None,
            bytes,
            key,
            notify,
            ..
        } => {
            let map = match object(bytes, inner.max_object) {
                Ok(m) => m,
                Err(reason) => return Ok(failed(reason)),
            };
            let Some(id) = id_for_key(key) else {
                return Ok(failed("invalid_key"));
            };
            let body = with_field(bytes, &map, "id", &id);
            let url = events_url(inner, collection, None, *notify);
            let reply = inner
                .http
                .call(
                    Api::Calendar,
                    Method::POST,
                    url,
                    None,
                    Some(body),
                    inner.max_response,
                )
                .await
                .map_err(Fail::into_error)?;
            match reply.status {
                s if s.is_success() => Ok(applied(&id, reply.body)),
                StatusCode::CONFLICT => match probe(inner, collection, &id).await? {
                    Probe::Live(current) => Ok(WriteOutcome::Applied {
                        item: Some(item(&id)),
                        current: Some(current),
                    }),
                    Probe::Cancelled => Ok(WriteOutcome::Conflict { current: None }),
                    Probe::Missing => Ok(failed("duplicate")),
                },
                StatusCode::NOT_FOUND => Err(PimError::NotFound),
                _ => write_failure(&reply, true),
            }
        }
        PimWrite::Put {
            collection,
            item: Some(target),
            bytes,
            if_version,
            notify,
            ..
        } => {
            if !plausible(&target.id) {
                return Ok(failed("not_in_collection"));
            }
            if let Err(reason) = object(bytes, inner.max_object) {
                return Ok(failed(reason));
            }
            let url = events_url(inner, collection, Some(&target.id), *notify);
            let reply = inner
                .http
                .call(
                    Api::Calendar,
                    Method::PUT,
                    url,
                    if_version.as_deref(),
                    Some(bytes.clone()),
                    inner.max_response,
                )
                .await
                .map_err(Fail::into_error)?;
            match reply.status {
                s if s.is_success() => Ok(applied(&target.id, reply.body)),
                StatusCode::PRECONDITION_FAILED => Ok(WriteOutcome::Conflict {
                    current: current_version(inner, collection, &target.id).await?,
                }),
                StatusCode::NOT_FOUND | StatusCode::GONE => {
                    Ok(WriteOutcome::Conflict { current: None })
                }
                _ => write_failure(&reply, true),
            }
        }
        PimWrite::Delete {
            collection,
            item: target,
            if_version,
            notify,
        } => {
            let gone = WriteOutcome::Applied {
                item: Some(target.clone()),
                current: None,
            };
            if !plausible(&target.id) {
                return Ok(gone);
            }
            let url = events_url(inner, collection, Some(&target.id), *notify);
            let reply = inner
                .http
                .call(
                    Api::Calendar,
                    Method::DELETE,
                    url,
                    if_version.as_deref(),
                    None,
                    inner.max_response,
                )
                .await
                .map_err(Fail::into_error)?;
            match reply.status {
                s if s.is_success() => Ok(gone),
                StatusCode::NOT_FOUND | StatusCode::GONE => Ok(gone),
                StatusCode::PRECONDITION_FAILED => Ok(WriteOutcome::Conflict {
                    current: current_version(inner, collection, &target.id).await?,
                }),
                _ => write_failure(&reply, true),
            }
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
            respond(
                inner,
                collection,
                &target.id,
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

const RESPOND_ATTEMPTS: usize = 3;

fn response_status(answer: PartStat) -> &'static str {
    match answer {
        PartStat::Accepted => "accepted",
        PartStat::Declined => "declined",
        PartStat::Tentative => "tentative",
    }
}

/// The event's `attendees` with the answering one changed, or `None` when no attendee matches.
fn answered(
    event: &[u8],
    answer: PartStat,
    attendee: Option<&str>,
    comment: Option<&str>,
) -> Result<Option<Vec<serde_json::Value>>, PimError> {
    let mut event: serde_json::Value = serde_json::from_slice(event).map_err(|_| unexpected())?;
    let Some(serde_json::Value::Array(mut list)) = event.get_mut("attendees").map(|a| a.take())
    else {
        return Ok(None);
    };
    let found = list.iter_mut().find(|a| match attendee {
        Some(want) => a["email"]
            .as_str()
            .is_some_and(|e| e.trim().eq_ignore_ascii_case(want.trim())),
        None => a["self"].as_bool() == Some(true),
    });
    let Some(serde_json::Value::Object(found)) = found else {
        return Ok(None);
    };
    found.insert(
        "responseStatus".into(),
        serde_json::Value::String(response_status(answer).into()),
    );
    if let Some(comment) = comment {
        found.insert("comment".into(), serde_json::Value::String(comment.into()));
    }
    Ok(Some(list))
}

/// Reads the event, changes one attendee's `responseStatus` and patches `attendees` back under
/// the etag it read, so a concurrent change to another attendee is never overwritten.
#[allow(clippy::too_many_arguments)]
async fn respond(
    inner: &Inner,
    calendar: &str,
    id: &str,
    answer: PartStat,
    attendee: Option<&str>,
    comment: Option<&str>,
    if_version: Option<&str>,
    notify: bool,
) -> Result<WriteOutcome, PimError> {
    if !plausible(id) {
        return Ok(WriteOutcome::Conflict { current: None });
    }
    for _ in 0..RESPOND_ATTEMPTS {
        let Some(current) = get(inner, calendar, id).await? else {
            return Ok(WriteOutcome::Conflict { current: None });
        };
        if let Some(want) = if_version
            && current.version.as_deref() != Some(want)
        {
            return Ok(WriteOutcome::Conflict {
                current: current.version,
            });
        }
        let Some(attendees) = answered(&current.bytes, answer, attendee, comment)? else {
            return Ok(failed("attendee_not_found"));
        };
        let body = serde_json::to_vec(&serde_json::json!({ "attendees": attendees }))
            .expect("a JSON value serializes");
        let url = events_url(inner, calendar, Some(id), notify);
        let reply = inner
            .http
            .call(
                Api::Calendar,
                Method::PATCH,
                url,
                if_version.or(current.version.as_deref()),
                Some(Bytes::from(body)),
                inner.max_response,
            )
            .await
            .map_err(Fail::into_error)?;
        match reply.status {
            s if s.is_success() => return Ok(applied(id, reply.body)),
            StatusCode::PRECONDITION_FAILED if if_version.is_none() => continue,
            StatusCode::PRECONDITION_FAILED => {
                return Ok(WriteOutcome::Conflict {
                    current: current_version(inner, calendar, id).await?,
                });
            }
            StatusCode::NOT_FOUND | StatusCode::GONE => {
                return Ok(WriteOutcome::Conflict { current: None });
            }
            _ => return write_failure(&reply, true),
        }
    }
    Ok(WriteOutcome::Conflict {
        current: current_version(inner, calendar, id).await?,
    })
}

/// The primary calendar's id when it is an address: the account's own calendar address.
pub(crate) async fn addresses(inner: &Inner) -> Result<Vec<String>, PimError> {
    #[derive(Deserialize)]
    struct Primary {
        id: Option<String>,
    }
    let url = endpoint(&inner.calendar, &["users", "me", "calendarList", "primary"]);
    let reply = inner
        .http
        .get(Api::Calendar, url, inner.max_response)
        .await?;
    match reply.status {
        s if s.is_success() => {}
        StatusCode::NOT_FOUND => return Ok(Vec::new()),
        _ => return Err(read_error(&reply)),
    }
    let primary: Primary = serde_json::from_slice(&reply.body).map_err(|_| unexpected())?;
    Ok(primary
        .id
        .map(|id| id.trim().to_lowercase())
        .filter(|id| id.contains('@'))
        .into_iter()
        .collect())
}

/// Reads `bytes` as each Calendar API answer: a calendar list, an events page, one event, and
/// the event an answer is written into. For the fuzz targets.
pub(crate) fn fuzz(bytes: &[u8]) {
    if let Ok(list) = serde_json::from_slice::<CalendarList>(bytes) {
        for entry in &list.items {
            let _ = plausible(&entry.id);
        }
    }
    let body = Bytes::copy_from_slice(bytes);
    if let Ok(page) = serde_json::from_slice::<EventsPage<'_>>(&body) {
        for raw in page.items {
            if serde_json::from_str::<EventMeta>(raw.get()).is_ok() {
                let _ = body.slice_ref(raw.get().as_bytes());
            }
        }
    }
    let _ = raw_event("e1", body);
    for attendee in [None, Some("ada@example.com")] {
        let _ = answered(bytes, PartStat::Declined, attendee, Some("Away"));
    }
    if let Some(id) = id_for_key(&String::from_utf8_lossy(bytes)) {
        assert!(plausible(&id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_ids_are_base32hex_and_distinct() {
        let a = id_for_key("01KCREATE").unwrap();
        assert!(a.starts_with("skein"));
        assert!(
            a.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'v').contains(&b))
        );
        assert_ne!(id_for_key("a/b"), id_for_key("a_b"));
        assert_eq!(id_for_key("f").unwrap(), "skeinco");
        assert_eq!(id_for_key(""), None);
        assert_eq!(id_for_key(&"x".repeat(1000)), None);
        assert!(plausible("abc_20261201T100000Z"));
        assert!(!plausible("../x"));
        assert!(!plausible(""));
    }
}
