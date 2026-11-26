use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, IF_MATCH, RETRY_AFTER};
use reqwest::{Method, StatusCode};
use skein_pim::PimError;
use url::{Host, Origin, Url};

use crate::limit::Limiter;

const MAX_ERROR: usize = 64 * 1024;

/// `https`, or plain `http` to a loopback address.
pub(crate) fn allowed(url: &Url) -> bool {
    match url.scheme() {
        "https" => true,
        "http" => match url.host() {
            Some(Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
            Some(Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
            Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
            None => false,
        },
        _ => false,
    }
}

/// An address under `base` with every segment percent-encoded, so no id can change the host or
/// climb out of the path.
pub(crate) fn endpoint(base: &Url, segments: &[&str]) -> Url {
    let mut url = base.clone();
    url.set_query(None);
    url.set_fragment(None);
    {
        let mut path = url
            .path_segments_mut()
            .expect("an http(s) address has a path");
        path.pop_if_empty();
        path.extend(segments);
    }
    url
}

/// Which API a request goes to: each has its own origin and its own limiter.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Api {
    Calendar,
    People,
}

/// An answer that arrived in full.
pub(crate) struct Reply {
    pub status: StatusCode,
    pub body: Bytes,
    pub reasons: Vec<String>,
    pub retry_after: Option<Duration>,
}

impl Reply {
    pub(crate) fn has(&self, names: &[&str]) -> bool {
        self.reasons.iter().any(|r| names.contains(&r.as_str()))
    }
}

/// Why no reply came back.
pub(crate) enum Fail {
    /// Nothing reached the server.
    NotSent(PimError),
    /// The request left; the answer did not come back in full.
    Lost(PimError),
}

impl Fail {
    pub(crate) fn into_error(self) -> PimError {
        match self {
            Self::NotSent(e) | Self::Lost(e) => e,
        }
    }
}

#[derive(Clone)]
pub(crate) struct Http {
    client: reqwest::Client,
    token: Arc<str>,
    calendar: Origin,
    people: Origin,
    calendar_limit: Arc<Limiter>,
    people_limit: Arc<Limiter>,
}

fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

/// The machine-readable reasons in a Google error body (`error.errors[].reason`,
/// `error.details[].reason`, `error.status`). Messages are never read: they can echo user data.
pub(crate) fn reasons(body: &[u8]) -> Vec<String> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Vec::new();
    };
    let error = &value["error"];
    let mut out = Vec::new();
    for list in ["errors", "details"] {
        if let Some(items) = error[list].as_array() {
            out.extend(
                items
                    .iter()
                    .filter_map(|e| e["reason"].as_str().map(str::to_owned)),
            );
        }
    }
    if let Some(status) = error["status"].as_str() {
        out.push(status.to_owned());
    }
    out
}

const RATE: &[&str] = &[
    "rateLimitExceeded",
    "userRateLimitExceeded",
    "quotaExceeded",
    "RATE_LIMIT_EXCEEDED",
    "RESOURCE_EXHAUSTED",
];
const SCOPE: &[&str] = &["insufficientPermissions", "ACCESS_TOKEN_SCOPE_INSUFFICIENT"];

/// `Auth` for `401` and `Throttled` for `429` or a `403` rate reason; `None` for anything else.
pub(crate) fn common(reply: &Reply) -> Option<PimError> {
    match reply.status {
        StatusCode::UNAUTHORIZED => Some(PimError::Auth),
        StatusCode::TOO_MANY_REQUESTS => Some(throttled(reply)),
        StatusCode::FORBIDDEN if reply.has(RATE) => Some(throttled(reply)),
        _ => None,
    }
}

fn throttled(reply: &Reply) -> PimError {
    tracing::debug!(
        status = reply.status.as_u16(),
        "a Google API is limiting requests"
    );
    PimError::Throttled {
        retry_after: reply.retry_after,
    }
}

/// Whether a `403` names a missing OAuth scope.
pub(crate) fn scope_missing(reply: &Reply) -> bool {
    reply.status == StatusCode::FORBIDDEN && reply.has(SCOPE)
}

/// The error for an unsuccessful read that the caller did not handle itself.
pub(crate) fn read_error(reply: &Reply) -> PimError {
    if let Some(e) = common(reply) {
        return e;
    }
    match reply.status {
        StatusCode::FORBIDDEN => PimError::Auth,
        StatusCode::NOT_FOUND | StatusCode::GONE => PimError::NotFound,
        s if s.is_server_error() => PimError::Network(format!("a Google API answered {s}")),
        s => PimError::Protocol(format!("a Google API answered {s}")),
    }
}

pub(crate) fn unexpected() -> PimError {
    PimError::Protocol("a Google API sent an unexpected answer".into())
}

fn too_large() -> PimError {
    PimError::Protocol("a Google API sent an answer that is too large".into())
}

fn network(error: &reqwest::Error) -> PimError {
    PimError::Network(if error.is_timeout() {
        "a Google API did not answer in time".into()
    } else {
        "a Google API could not be reached".into()
    })
}

async fn body(mut response: reqwest::Response, limit: usize) -> Result<Bytes, PimError> {
    if response.content_length().is_some_and(|n| n > limit as u64) {
        return Err(too_large());
    }
    let mut out = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| PimError::Network("a Google API broke off an answer".into()))?
    {
        if out.len() + chunk.len() > limit {
            return Err(too_large());
        }
        out.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(out))
}

impl Http {
    pub(crate) fn new(
        token: String,
        calendar: &Url,
        people: &Url,
        timeout: Duration,
        calendar_limit: Arc<Limiter>,
        people_limit: Arc<Limiter>,
    ) -> Result<Self, PimError> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(30).min(timeout))
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("Skein/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| PimError::Config(e.to_string()))?;
        Ok(Self {
            client,
            token: token.into(),
            calendar: calendar.origin(),
            people: people.origin(),
            calendar_limit,
            people_limit,
        })
    }

    /// Checks that `url` is on the origin configured for `api`, so the token never goes anywhere
    /// else.
    pub(crate) fn check_origin(&self, api: Api, url: &Url) -> Result<(), PimError> {
        let origin = match api {
            Api::Calendar => &self.calendar,
            Api::People => &self.people,
        };
        if !allowed(url) || url.origin() != *origin {
            return Err(PimError::Protocol(
                "refused to send the token to another host".into(),
            ));
        }
        Ok(())
    }

    /// One request. A successful body is capped at `limit`, an error body at 64 KiB. Redirects
    /// are never followed and count as a protocol error.
    pub(crate) async fn call(
        &self,
        api: Api,
        method: Method,
        url: Url,
        if_match: Option<&str>,
        payload: Option<Bytes>,
        limit: usize,
    ) -> Result<Reply, Fail> {
        self.check_origin(api, &url).map_err(Fail::NotSent)?;
        match api {
            Api::Calendar => self.calendar_limit.take().await,
            Api::People => self.people_limit.take().await,
        }
        let started = std::time::Instant::now();
        let mut builder = self
            .client
            .request(method.clone(), url)
            .bearer_auth(&*self.token)
            .header(ACCEPT, "application/json");
        if let Some(tag) = if_match {
            builder = builder.header(IF_MATCH, tag);
        }
        builder = match payload {
            Some(bytes) => builder.header(CONTENT_TYPE, "application/json").body(bytes),
            None if method == Method::GET => builder,
            None => builder.body(Vec::new()),
        };
        let response = match builder.send().await {
            Ok(r) => r,
            Err(e) if e.is_connect() || e.is_builder() => return Err(Fail::NotSent(network(&e))),
            Err(e) => return Err(Fail::Lost(network(&e))),
        };
        let status = response.status();
        tracing::trace!(
            api = ?api,
            method = %method,
            status = status.as_u16(),
            ms = started.elapsed().as_millis() as u64,
            "google request"
        );
        if status.is_redirection() {
            return Err(Fail::Lost(PimError::Protocol(
                "a Google API answered with a redirect, which is not followed".into(),
            )));
        }
        let headers = response.headers().clone();
        if status.is_success() {
            let body = body(response, limit).await.map_err(Fail::Lost)?;
            return Ok(Reply {
                status,
                body,
                reasons: Vec::new(),
                retry_after: None,
            });
        }
        let body = body(response, MAX_ERROR).await.unwrap_or_default();
        Ok(Reply {
            status,
            reasons: reasons(&body),
            body,
            retry_after: retry_after(&headers),
        })
    }

    /// A read: like [`Http::call`] with `GET`, every failure as a [`PimError`].
    pub(crate) async fn get(&self, api: Api, url: Url, limit: usize) -> Result<Reply, PimError> {
        self.call(api, Method::GET, url, None, None, limit)
            .await
            .map_err(Fail::into_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_stay_on_the_origin() {
        let base = Url::parse("https://calendar.example.com/calendar/v3/").unwrap();
        assert_eq!(
            endpoint(&base, &["calendars", "a#b@example.com", "events"]).as_str(),
            "https://calendar.example.com/calendar/v3/calendars/a%23b@example.com/events"
        );
        let evil = endpoint(&base, &["calendars", "../../@evil.example.org/x", "events"]);
        assert_eq!(evil.host_str(), Some("calendar.example.com"));
        assert!(!evil.path().contains("/../"));
        let people = Url::parse("https://people.example.com/v1").unwrap();
        assert_eq!(
            endpoint(&people, &["people", "c12:updateContact"]).as_str(),
            "https://people.example.com/v1/people/c12:updateContact"
        );
        let http = Http::new(
            "t".into(),
            &base,
            &people,
            Duration::from_secs(5),
            Arc::new(Limiter::new(600, 10)),
            Arc::new(Limiter::new(600, 10)),
        )
        .unwrap();
        assert!(http.check_origin(Api::Calendar, &evil).is_ok());
        assert!(
            http.check_origin(Api::Calendar, &endpoint(&people, &["x"]))
                .is_err(),
            "each API keeps its own origin"
        );
        assert!(
            http.check_origin(
                Api::Calendar,
                &Url::parse("http://calendar.example.com/calendar/v3").unwrap()
            )
            .is_err()
        );
        assert!(
            http.check_origin(
                Api::People,
                &Url::parse("https://evil.example.org/v1").unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn reads_google_error_reasons_without_messages() {
        let body = br#"{"error":{"code":403,"message":"ada@example.com secret","errors":[{"reason":"quotaExceeded"}],"status":"PERMISSION_DENIED"}}"#;
        let reply = Reply {
            status: StatusCode::FORBIDDEN,
            body: Bytes::from_static(body),
            reasons: reasons(body),
            retry_after: Some(Duration::from_secs(3)),
        };
        assert_eq!(reply.reasons, vec!["quotaExceeded", "PERMISSION_DENIED"]);
        assert!(matches!(
            common(&reply),
            Some(PimError::Throttled { retry_after: Some(d) }) if d == Duration::from_secs(3)
        ));
        let expired = br#"{"error":{"code":400,"status":"FAILED_PRECONDITION","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"EXPIRED_SYNC_TOKEN"}]}}"#;
        assert_eq!(
            reasons(expired),
            vec!["EXPIRED_SYNC_TOKEN", "FAILED_PRECONDITION"]
        );
        assert!(reasons(b"<html>").is_empty());
    }

    #[test]
    fn only_https_or_loopback() {
        assert!(allowed(
            &Url::parse("https://www.googleapis.com/calendar/v3").unwrap()
        ));
        assert!(allowed(&Url::parse("http://127.0.0.1:8080").unwrap()));
        assert!(allowed(&Url::parse("http://[::1]:8080").unwrap()));
        assert!(allowed(&Url::parse("http://localhost").unwrap()));
        assert!(!allowed(
            &Url::parse("http://people.googleapis.com").unwrap()
        ));
        assert!(!allowed(&Url::parse("ftp://127.0.0.1").unwrap()));
    }
}
