use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, RETRY_AFTER};
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use skein_mail::MailError;
use url::{Host, Url};

use crate::quota::Quota;

pub(crate) const MAX_JSON: usize = 16 * 1024 * 1024;
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

/// What became of a write.
pub(crate) enum Wrote {
    Done,
    Missing,
    Uncertain,
    Failed(&'static str),
}

enum Refusal {
    Auth,
    Throttled(Option<Duration>),
    Scope,
    Forbidden,
    Server(u16),
    Other(u16),
}

#[derive(Clone)]
pub(crate) struct Http {
    client: reqwest::Client,
    token: Arc<str>,
    base: Url,
    user: Arc<str>,
    quota: Arc<Quota>,
}

pub(crate) fn retry_after(headers: &HeaderMap) -> Option<Duration> {
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

fn refusal(status: StatusCode, headers: &HeaderMap, body: &[u8]) -> Refusal {
    let reasons = reasons(body);
    let has = |names: &[&str]| reasons.iter().any(|r| names.contains(&r.as_str()));
    let rate = has(&[
        "rateLimitExceeded",
        "userRateLimitExceeded",
        "RATE_LIMIT_EXCEEDED",
    ]);
    match status {
        StatusCode::TOO_MANY_REQUESTS => Refusal::Throttled(retry_after(headers)),
        StatusCode::FORBIDDEN if rate => Refusal::Throttled(retry_after(headers)),
        StatusCode::UNAUTHORIZED => Refusal::Auth,
        StatusCode::FORBIDDEN
            if has(&["insufficientPermissions", "ACCESS_TOKEN_SCOPE_INSUFFICIENT"]) =>
        {
            Refusal::Scope
        }
        StatusCode::FORBIDDEN => Refusal::Forbidden,
        s if s.is_server_error() => Refusal::Server(s.as_u16()),
        s => Refusal::Other(s.as_u16()),
    }
}

pub(crate) fn network(error: &reqwest::Error) -> MailError {
    MailError::Network(if error.is_timeout() {
        "the Gmail API did not answer in time".into()
    } else {
        "the Gmail API could not be reached".into()
    })
}

pub(crate) async fn read(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Bytes, MailError> {
    let too_large = || MailError::Protocol("the Gmail API sent an answer that is too large".into());
    if response.content_length().is_some_and(|n| n > limit as u64) {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| MailError::Network("the Gmail API broke off an answer".into()))?
    {
        if body.len() + chunk.len() > limit {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(body))
}

pub(crate) async fn error_body(response: reqwest::Response) -> Bytes {
    read(response, MAX_ERROR).await.unwrap_or_default()
}

impl Http {
    pub(crate) fn new(
        token: String,
        base: Url,
        user: String,
        timeout: Duration,
        quota: Arc<Quota>,
    ) -> Result<Self, MailError> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(30).min(timeout))
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("Skein/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| MailError::Config(e.to_string()))?;
        Ok(Self {
            client,
            token: token.into(),
            base,
            user: user.into(),
            quota,
        })
    }

    /// An address under `{api_url}/gmail/v1/users/{user}/` (or `/upload/gmail/...`). Every
    /// segment is percent-encoded, so an id or user name can never change the host or climb out
    /// of the path.
    pub(crate) fn endpoint(&self, upload: bool, segments: &[&str]) -> Url {
        let mut url = self.base.clone();
        url.set_query(None);
        url.set_fragment(None);
        {
            let mut path = url
                .path_segments_mut()
                .expect("an http(s) address has a path");
            path.pop_if_empty();
            if upload {
                path.push("upload");
            }
            path.extend(["gmail", "v1", "users", &self.user]);
            path.extend(segments);
        }
        url
    }

    /// Checks that `url` is on the configured origin, so the token never goes anywhere else.
    fn check_origin(&self, url: &Url) -> Result<(), MailError> {
        if !allowed(url) || url.origin() != self.base.origin() {
            return Err(MailError::Protocol(
                "refused to send the token to another host".into(),
            ));
        }
        Ok(())
    }

    pub(crate) async fn send(
        &self,
        method: Method,
        url: Url,
        body: Option<(String, Bytes)>,
        cost: u32,
    ) -> Result<Result<reqwest::Response, reqwest::Error>, MailError> {
        self.check_origin(&url)?;
        self.quota.take(cost).await;
        let builder = self
            .client
            .request(method.clone(), url)
            .bearer_auth(&*self.token)
            .header(ACCEPT, "application/json");
        let builder = match body {
            Some((content_type, bytes)) => builder.header(CONTENT_TYPE, content_type).body(bytes),
            None if method == Method::GET => builder,
            None => builder.body(Vec::new()),
        };
        Ok(builder.send().await)
    }

    /// A read. `Ok(None)` on `404`.
    pub(crate) async fn get<T: DeserializeOwned>(
        &self,
        url: Url,
        cost: u32,
        limit: usize,
    ) -> Result<Option<T>, MailError> {
        self.read_json(url, cost, limit, false).await
    }

    /// A read that also takes `400` as `Ok(None)`: Gmail's answer to a page token or history
    /// id it no longer accepts.
    pub(crate) async fn get_lenient<T: DeserializeOwned>(
        &self,
        url: Url,
        cost: u32,
        limit: usize,
    ) -> Result<Option<T>, MailError> {
        self.read_json(url, cost, limit, true).await
    }

    async fn read_json<T: DeserializeOwned>(
        &self,
        url: Url,
        cost: u32,
        limit: usize,
        lenient: bool,
    ) -> Result<Option<T>, MailError> {
        let started = std::time::Instant::now();
        let response = self
            .send(Method::GET, url, None, cost)
            .await?
            .map_err(|e| network(&e))?;
        let status = response.status();
        tracing::trace!(
            status = status.as_u16(),
            ms = started.elapsed().as_millis() as u64,
            "gmail read"
        );
        if status == StatusCode::NOT_FOUND || (lenient && status == StatusCode::BAD_REQUEST) {
            return Ok(None);
        }
        if status.is_redirection() {
            return Err(MailError::Protocol(
                "the Gmail API answered with a redirect, which is not followed".into(),
            ));
        }
        if !status.is_success() {
            let headers = response.headers().clone();
            let body = error_body(response).await;
            return Err(match refusal(status, &headers, &body) {
                Refusal::Auth | Refusal::Scope | Refusal::Forbidden => MailError::Auth,
                Refusal::Throttled(retry_after) => {
                    tracing::debug!(
                        status = status.as_u16(),
                        "the Gmail API is limiting requests"
                    );
                    MailError::Throttled { retry_after }
                }
                Refusal::Server(s) => MailError::Network(format!("the Gmail API answered {s}")),
                Refusal::Other(s) => MailError::Protocol(format!("the Gmail API answered {s}")),
            });
        }
        let body = read(response, limit).await?;
        serde_json::from_slice(&body)
            .map(Some)
            .map_err(|_| MailError::Protocol("the Gmail API sent an unexpected answer".into()))
    }

    /// A write. `repeatable` writes (label changes, deletes) report a server error as `Network`,
    /// since repeating them is harmless; for an insert it is [`Wrote::Uncertain`].
    pub(crate) async fn write(
        &self,
        method: Method,
        url: Url,
        body: Option<(String, Bytes)>,
        cost: u32,
        repeatable: bool,
    ) -> Result<Wrote, MailError> {
        let response = match self.send(method, url, body, cost).await? {
            Ok(r) => r,
            Err(e) if e.is_connect() => return Err(network(&e)),
            Err(_) => return Ok(Wrote::Uncertain),
        };
        let status = response.status();
        if status.is_success() {
            return Ok(match read(response, MAX_JSON).await {
                Ok(_) => Wrote::Done,
                Err(_) => Wrote::Uncertain,
            });
        }
        if status == StatusCode::NOT_FOUND {
            return Ok(Wrote::Missing);
        }
        if status.is_redirection() {
            return Err(MailError::Protocol(
                "the Gmail API answered with a redirect, which is not followed".into(),
            ));
        }
        let headers = response.headers().clone();
        let body = error_body(response).await;
        Ok(match refusal(status, &headers, &body) {
            Refusal::Auth => return Err(MailError::Auth),
            Refusal::Throttled(retry_after) => return Err(MailError::Throttled { retry_after }),
            Refusal::Scope => Wrote::Failed("insufficient_scope"),
            Refusal::Forbidden => Wrote::Failed("forbidden"),
            Refusal::Server(s) if repeatable => {
                return Err(MailError::Network(format!("the Gmail API answered {s}")));
            }
            Refusal::Server(_) => Wrote::Uncertain,
            Refusal::Other(409) => Wrote::Failed("exists"),
            Refusal::Other(_) => Wrote::Failed("refused"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http(base: &str, user: &str) -> Http {
        Http::new(
            "t".into(),
            Url::parse(base).unwrap(),
            user.into(),
            Duration::from_secs(5),
            Arc::new(Quota::new(250)),
        )
        .unwrap()
    }

    #[test]
    fn endpoints_stay_on_the_origin() {
        let h = http("https://gmail.example.com/prefix/", "me");
        assert_eq!(
            h.endpoint(false, &["messages", "abc"]).as_str(),
            "https://gmail.example.com/prefix/gmail/v1/users/me/messages/abc"
        );
        assert_eq!(
            h.endpoint(true, &["messages"]).as_str(),
            "https://gmail.example.com/prefix/upload/gmail/v1/users/me/messages"
        );
        let evil = h.endpoint(false, &["messages", "../../@evil.example.org/x"]);
        assert_eq!(evil.host_str(), Some("gmail.example.com"));
        assert!(!evil.path().contains("/../"));
        let h = http("https://gmail.example.com", "//evil.example.org");
        assert_eq!(
            h.endpoint(false, &["profile"]).host_str(),
            Some("gmail.example.com")
        );
        assert!(
            h.check_origin(&Url::parse("https://evil.example.org/gmail/v1").unwrap())
                .is_err()
        );
        assert!(
            h.check_origin(&Url::parse("http://gmail.example.com/gmail/v1").unwrap())
                .is_err()
        );
        assert!(h.check_origin(&h.endpoint(false, &["profile"])).is_ok());
    }

    #[test]
    fn reads_google_error_reasons() {
        let body = br#"{"error":{"code":403,"message":"ada@example.com secret","errors":[{"reason":"userRateLimitExceeded"}],"status":"PERMISSION_DENIED"}}"#;
        let r = reasons(body);
        assert_eq!(r, vec!["userRateLimitExceeded", "PERMISSION_DENIED"]);
        assert!(matches!(
            refusal(StatusCode::FORBIDDEN, &HeaderMap::new(), body),
            Refusal::Throttled(None)
        ));
        let scope =
            br#"{"error":{"code":403,"details":[{"reason":"ACCESS_TOKEN_SCOPE_INSUFFICIENT"}]}}"#;
        assert!(matches!(
            refusal(StatusCode::FORBIDDEN, &HeaderMap::new(), scope),
            Refusal::Scope
        ));
        assert!(matches!(
            refusal(StatusCode::FORBIDDEN, &HeaderMap::new(), b"<html>"),
            Refusal::Forbidden
        ));
    }

    #[test]
    fn only_https_or_loopback() {
        assert!(allowed(
            &Url::parse("https://gmail.googleapis.com").unwrap()
        ));
        assert!(allowed(&Url::parse("http://127.0.0.1:8080").unwrap()));
        assert!(allowed(&Url::parse("http://[::1]:8080").unwrap()));
        assert!(allowed(&Url::parse("http://localhost").unwrap()));
        assert!(!allowed(
            &Url::parse("http://gmail.googleapis.com").unwrap()
        ));
        assert!(!allowed(&Url::parse("ftp://127.0.0.1").unwrap()));
    }
}
