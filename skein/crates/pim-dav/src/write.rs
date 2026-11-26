use bytes::Bytes;
use reqwest::header::ETAG;
use skein_core::{CollectionKind, ItemRef};
use skein_pim::{PimError, PimWrite, RawObject, WriteOutcome};
use url::Url;

use crate::http::{Answer, Http, MAX_ITEM, MAX_XML, status_error};
use crate::xml::{self, DAV};
use crate::{Found, etag, ok_props, path};

/// The name a create with `key` gets: letters, digits, `-` and `.` kept, every other byte as `_`
/// and two hex digits, so different keys never share a name.
pub(crate) fn file_name(key: &str, kind: CollectionKind) -> String {
    let mut out = String::with_capacity(key.len() + 4);
    for b in key.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'.' {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("_{b:02x}"));
        }
    }
    out.push_str(match kind {
        CollectionKind::AddressBook => ".vcf",
        CollectionKind::Calendar => ".ics",
    });
    out
}

fn child(collection: &Url, name: &str) -> Option<Url> {
    let mut base = collection.clone();
    if !base.path().ends_with('/') {
        base.set_path(&format!("{}/", base.path()));
    }
    base.join(&path::encode(name)).ok()
}

pub(crate) fn header_etag(answer: &Answer) -> Option<String> {
    answer
        .headers
        .get(ETAG)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

/// A short reason for a refusal: the DAV precondition the server named (such as
/// `valid-calendar-data`), or `refused_{status}`. Only the element name of the server's error
/// is kept, and only when it is a plain token.
fn refusal(answer: &Answer) -> String {
    let condition = xml::parse(&answer.body)
        .filter(|root| root.is(DAV, "error"))
        .and_then(|root| root.children.first().map(|c| c.name.clone()))
        .filter(|n| {
            !n.is_empty()
                && n.len() <= 64
                && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    condition.unwrap_or_else(|| format!("refused_{}", answer.status.as_u16()))
}

fn write_error(answer: &Answer) -> Result<WriteOutcome, PimError> {
    match answer.status.as_u16() {
        403 | 405 | 409 | 413 | 415 | 422 | 507 => Ok(WriteOutcome::Failed {
            reason: refusal(answer),
        }),
        _ => Err(status_error(answer.status, &answer.url)),
    }
}

async fn current(http: &Http, url: &Url) -> Result<Option<(Option<String>, Bytes)>, PimError> {
    let Some(answer) = http.get(url).await? else {
        return Ok(None);
    };
    let tag = match header_etag(&answer) {
        Some(tag) => Some(tag),
        None => etag_of(http, url).await,
    };
    Ok(Some((tag, answer.body)))
}

async fn etag_of(http: &Http, url: &Url) -> Option<String> {
    let body = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
                <d:propfind xmlns:d=\"DAV:\"><d:prop><d:getetag/></d:prop></d:propfind>";
    let answer = http
        .dav("PROPFIND", url, Some("0"), Some(body), MAX_XML)
        .await
        .ok()?;
    let root = xml::parse(&answer.body)?;
    etag(&ok_props(root.child(DAV, "response")?))
}

async fn put(
    http: &Http,
    url: &Url,
    kind: CollectionKind,
    bytes: &Bytes,
    headers: &[(&str, &str)],
) -> Result<Answer, PimError> {
    let content_type = format!("{}; charset=utf-8", kind.media_type());
    http.request(
        "PUT",
        url,
        None,
        Some((&content_type, bytes)),
        headers,
        MAX_XML,
    )
    .await
}

fn item_url(found: &Found, collection: &str, item: &ItemRef) -> Option<Url> {
    let name = item.id.strip_prefix(collection)?;
    if name.is_empty() || name.contains('/') {
        return None;
    }
    found.url.join(&path::encode(&item.id)).ok()
}

/// The outcome of a put that the server took, with the object read back as the server now
/// holds it: servers such as Radicale rewrite objects and still answer with a strong ETag, so the
/// answer's tag never vouches for the bytes sent.
async fn applied(http: &Http, url: &Url, kind: CollectionKind) -> WriteOutcome {
    let item = ItemRef {
        id: path::id(url),
        uid: None,
    };
    let current = match current(http, url).await {
        Ok(Some((version, bytes))) => Some(RawObject {
            item: item.clone(),
            version: version.filter(|t| !t.starts_with("W/")),
            bytes,
            content_type: kind.media_type().into(),
        }),
        _ => None,
    };
    WriteOutcome::Applied {
        item: Some(item),
        current,
    }
}

pub(crate) async fn apply(
    http: &Http,
    found: &Found,
    collection: &str,
    write: &PimWrite,
    own: &[String],
) -> Result<WriteOutcome, PimError> {
    match write {
        PimWrite::Respond {
            item: target,
            answer,
            attendee,
            comment,
            if_version,
            notify,
            ..
        } => {
            if found.kind != CollectionKind::Calendar {
                return Ok(WriteOutcome::Failed {
                    reason: "not_a_calendar".into(),
                });
            }
            let Some(url) = item_url(found, collection, target) else {
                return Ok(not_in_collection());
            };
            let Some((tag, held)) = current(http, &url).await? else {
                return Ok(WriteOutcome::Conflict { current: None });
            };
            if let Some(want) = if_version
                && tag.as_ref() != Some(want)
            {
                return Ok(WriteOutcome::Conflict { current: tag });
            }
            let who = match attendee {
                Some(a) => Some(a.clone()),
                None => skein_itip::facts(&held)
                    .ok()
                    .and_then(|f| f.own_attendee(own).map(|a| a.address.clone())),
            };
            let Some(who) = who else {
                return Ok(WriteOutcome::Failed {
                    reason: "attendee_not_found".into(),
                });
            };
            let next = match skein_itip::set_partstat(&held, &who, *answer, comment.as_deref()) {
                Ok(next) => next,
                Err(e) => {
                    return Ok(WriteOutcome::Failed {
                        reason: e.reason().into(),
                    });
                }
            };
            let mut headers = Vec::new();
            if let Some(t) = tag.as_deref().filter(|t| !t.starts_with("W/")) {
                headers.push(("If-Match", t));
            }
            if !notify {
                headers.push(("Schedule-Reply", "F"));
            }
            let answer = put(http, &url, found.kind, &next, &headers).await?;
            if answer.status.is_success() {
                return Ok(applied(http, &url, found.kind).await);
            }
            match answer.status.as_u16() {
                412 => Ok(WriteOutcome::Conflict {
                    current: current(http, &url).await?.and_then(|(t, _)| t),
                }),
                404 | 410 => Ok(WriteOutcome::Conflict { current: None }),
                _ => write_error(&answer),
            }
        }
        PimWrite::Put {
            item: None,
            bytes,
            key,
            ..
        } => {
            if bytes.len() > MAX_ITEM {
                return Ok(too_large());
            }
            let Some(url) = child(&found.url, &file_name(key, found.kind)) else {
                return Ok(not_in_collection());
            };
            let answer = put(http, &url, found.kind, bytes, &[("If-None-Match", "*")]).await?;
            if answer.status.is_success() {
                return Ok(applied(http, &url, found.kind).await);
            }
            match answer.status.as_u16() {
                412 => match current(http, &url).await? {
                    Some((_, held)) if held == *bytes => Ok(applied(http, &url, found.kind).await),
                    Some((tag, _)) => Ok(WriteOutcome::Conflict { current: tag }),
                    None => Ok(WriteOutcome::Conflict { current: None }),
                },
                404 | 410 => Err(PimError::NotFound),
                _ => write_error(&answer),
            }
        }
        PimWrite::Put {
            item: Some(target),
            bytes,
            if_version,
            ..
        } => {
            if bytes.len() > MAX_ITEM {
                return Ok(too_large());
            }
            let Some(url) = item_url(found, collection, target) else {
                return Ok(not_in_collection());
            };
            let mut headers = Vec::new();
            if let Some(v) = if_version {
                headers.push(("If-Match", v.as_str()));
            }
            let answer = put(http, &url, found.kind, bytes, &headers).await?;
            if answer.status.is_success() {
                return Ok(applied(http, &url, found.kind).await);
            }
            match answer.status.as_u16() {
                412 => Ok(WriteOutcome::Conflict {
                    current: current(http, &url).await?.and_then(|(t, _)| t),
                }),
                404 | 410 if if_version.is_some() => Ok(WriteOutcome::Conflict { current: None }),
                404 | 410 => Err(PimError::NotFound),
                _ => write_error(&answer),
            }
        }
        PimWrite::Delete {
            item: target,
            if_version,
            ..
        } => {
            let Some(url) = item_url(found, collection, target) else {
                return Ok(not_in_collection());
            };
            let mut headers = Vec::new();
            if let Some(v) = if_version {
                headers.push(("If-Match", v.as_str()));
            }
            let answer = http
                .request("DELETE", &url, None, None, &headers, MAX_XML)
                .await?;
            match answer.status.as_u16() {
                200..=299 | 404 | 410 => Ok(WriteOutcome::Applied {
                    item: Some(target.clone()),
                    current: None,
                }),
                412 => match current(http, &url).await? {
                    None => Ok(WriteOutcome::Applied {
                        item: Some(target.clone()),
                        current: None,
                    }),
                    Some((tag, _)) => Ok(WriteOutcome::Conflict { current: tag }),
                },
                _ => write_error(&answer),
            }
        }
    }
}

fn too_large() -> WriteOutcome {
    WriteOutcome::Failed {
        reason: "too_large".into(),
    }
}

fn not_in_collection() -> WriteOutcome {
    WriteOutcome::Failed {
        reason: "not_in_collection".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_from_keys_never_collide_or_escape() {
        assert_eq!(file_name("01KABC", CollectionKind::Calendar), "01KABC.ics");
        assert_eq!(file_name("../x", CollectionKind::AddressBook), ".._2fx.vcf");
        assert_ne!(
            file_name("a/b", CollectionKind::Calendar),
            file_name("a_2fb", CollectionKind::Calendar)
        );
    }
}
