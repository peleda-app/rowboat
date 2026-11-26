use std::net::IpAddr;
use std::time::Duration;

use bytes::Bytes;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, IF_MATCH, RETRY_AFTER};
use reqwest::{Method, StatusCode};
use serde_json::Value;
use skein_core::TlsRoots;
use skein_pim::PimError;
use skein_throttle::{Permit, Throttle};
use url::{Host, Url};

const ATTEMPTS: u32 = 3;
const LONGEST_WAIT: Duration = Duration::from_secs(10);
const MAX_ERROR: usize = 64 * 1024;
pub(crate) const MAX_LISTING: usize = 64 * 1024 * 1024;
pub(crate) const MAX_ITEM: usize = 16 * 1024 * 1024;

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

/// What a `403` on a read means: for a listing a sign-in without the scope, for one item that
/// item's problem.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    Account,
    Item,
}

/// A read whose `400`, `404` and `410` the caller handles.
pub(crate) enum Read {
    Found(Bytes),
    Missing,
    Gone,
    Refused,
}

/// What became of a write.
pub(crate) enum Wrote {
    Done(Bytes),
    Missing,
    Stale,
    /// Refused for good, with Graph's error code when it is a plain name, else `refused_{status}`.
    Refused(String),
    /// Refused with `400`, with the reason as for `Refused`.
    Invalid(String),
    /// The request went out but no usable answer came back.
    Uncertain,
}

#[derive(Clone)]
pub(crate) struct Http {
    client: reqwest::Client,
    token: String,
    origin: url::Origin,
    roots: TlsRoots,
    pub(crate) throttle: Option<Throttle>,
}

fn host(url: &Url) -> String {
    url.host_str().unwrap_or("Microsoft Graph").to_owned()
}

fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

pub(crate) fn wait_for(headers: &HeaderMap, attempt: u32) -> Duration {
    retry_after(headers)
        .unwrap_or_else(|| Duration::from_millis(500 << attempt.min(4)))
        .min(LONGEST_WAIT)
}

/// `429` always, `503` and `504` only with a `Retry-After`: without one they are outages.
fn throttled(status: StatusCode, headers: &HeaderMap) -> Option<PimError> {
    let wait = retry_after(headers);
    match status {
        StatusCode::TOO_MANY_REQUESTS => Some(PimError::Throttled { retry_after: wait }),
        StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT if wait.is_some() => {
            Some(PimError::Throttled { retry_after: wait })
        }
        _ => None,
    }
}

fn network(host: &str, error: &reqwest::Error) -> PimError {
    PimError::Network(if error.is_timeout() {
        format!("{host} did not answer in time")
    } else {
        format!("{host} could not be reached")
    })
}

fn client(timeout: Duration, roots: &TlsRoots) -> Result<reqwest::Client, PimError> {
    let certs = roots
        .iter()
        .map(|der| {
            reqwest::Certificate::from_der(der)
                .map_err(|e| PimError::Config(format!("an extra trusted certificate: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(30).min(timeout))
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("Skein/", env!("CARGO_PKG_VERSION")))
        .tls_certs_merge(certs)
        .build()
        .map_err(|e| PimError::Config(e.to_string()))
}

async fn read_limited(
    mut response: reqwest::Response,
    limit: usize,
    host: &str,
) -> Result<Bytes, PimError> {
    let too_large = || PimError::Protocol(format!("{host} sent an answer that is too large"));
    if response.content_length().is_some_and(|n| n > limit as u64) {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| PimError::Network(format!("{host} broke off an answer")))?
    {
        if body.len() + chunk.len() > limit {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(body))
}

/// Graph's error code from an error body, kept only when it is a short plain name: the message
/// next to it may quote the object.
pub(crate) fn error_code(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let code = value.pointer("/error/code")?.as_str()?;
    (!code.is_empty() && code.len() <= 64 && code.bytes().all(|b| b.is_ascii_alphanumeric()))
        .then(|| code.to_owned())
}

impl Http {
    pub(crate) fn new(
        token: String,
        base: &Url,
        timeout: Duration,
        roots: &TlsRoots,
    ) -> Result<Self, PimError> {
        Ok(Self {
            client: client(timeout, roots)?,
            token,
            origin: base.origin(),
            roots: roots.clone(),
            throttle: None,
        })
    }

    pub(crate) fn with_timeout(mut self, timeout: Duration) -> Result<Self, PimError> {
        self.client = client(timeout, &self.roots)?;
        Ok(self)
    }

    /// Parses an address and checks that it is on the configured Graph origin, so the token never
    /// goes anywhere else, even when an answer or a stored cursor names another host.
    pub(crate) fn url(&self, raw: &str) -> Result<Url, PimError> {
        let url = Url::parse(raw)
            .map_err(|_| PimError::Protocol("Microsoft Graph named an invalid address".into()))?;
        if !self.may_sign_in(&url) {
            return Err(PimError::Protocol(
                "Microsoft Graph named an address on another host".into(),
            ));
        }
        Ok(url)
    }

    async fn permit(&self) -> Option<Permit> {
        match &self.throttle {
            Some(throttle) => Some(throttle.acquire().await),
            None => None,
        }
    }

    fn pause_on_busy(&self, error: &PimError) {
        if let (
            Some(throttle),
            PimError::Throttled {
                retry_after: Some(wait),
            },
        ) = (&self.throttle, error)
        {
            throttle.pause(*wait);
        }
    }

    fn paused_beyond(&self, wait: Duration) -> bool {
        self.throttle
            .as_ref()
            .and_then(Throttle::paused_until)
            .is_some_and(|until| until > tokio::time::Instant::now() + wait)
    }

    pub(crate) fn may_sign_in(&self, url: &Url) -> bool {
        allowed(url) && url.origin() == self.origin
    }

    fn request(
        &self,
        method: Method,
        url: Url,
        page: Option<usize>,
        body: Option<&Value>,
        if_match: Option<&str>,
    ) -> reqwest::RequestBuilder {
        let prefer = match page {
            Some(n) => format!("IdType=\"ImmutableId\", odata.maxpagesize={n}"),
            None => "IdType=\"ImmutableId\"".to_owned(),
        };
        let mut builder = self
            .client
            .request(method.clone(), url)
            .bearer_auth(&self.token)
            .header("Prefer", prefer)
            .header(ACCEPT, "application/json");
        if let Some(tag) = if_match {
            builder = builder.header(IF_MATCH, tag);
        }
        match body {
            Some(value) => builder
                .header(CONTENT_TYPE, "application/json")
                .body(value.to_string()),
            None if method == Method::GET => builder,
            None => builder.body(Vec::new()),
        }
    }

    /// A `GET` with the token. Busy answers are waited out three times within about ten seconds,
    /// then reported as `Throttled`.
    pub(crate) async fn get(
        &self,
        url: Url,
        scope: Scope,
        page: Option<usize>,
        limit: usize,
    ) -> Result<Read, PimError> {
        if !self.may_sign_in(&url) {
            return Err(PimError::Protocol(
                "Microsoft Graph named an address on another host".into(),
            ));
        }
        let host = host(&url);
        let mut attempt = 0;
        let (response, _permit) = loop {
            let permit = self.permit().await;
            let response = self
                .request(Method::GET, url.clone(), page, None, None)
                .send()
                .await
                .map_err(|e| network(&host, &e))?;
            let status = response.status();
            let Some(error) = throttled(status, response.headers()) else {
                break (response, permit);
            };
            drop(permit);
            self.pause_on_busy(&error);
            attempt += 1;
            let wait = wait_for(response.headers(), attempt);
            if attempt >= ATTEMPTS || self.paused_beyond(wait) {
                return Err(error);
            }
            tracing::debug!(
                status = status.as_u16(),
                attempt,
                wait_ms = wait.as_millis() as u64,
                "Microsoft Graph is limiting requests"
            );
            tokio::time::sleep(wait).await;
        };
        let status = response.status();
        match status {
            s if s.is_success() => Ok(Read::Found(read_limited(response, limit, &host).await?)),
            StatusCode::NOT_FOUND => Ok(Read::Missing),
            StatusCode::GONE => Ok(Read::Gone),
            StatusCode::BAD_REQUEST => Ok(Read::Refused),
            StatusCode::UNAUTHORIZED => Err(PimError::Auth),
            StatusCode::FORBIDDEN if scope == Scope::Account => Err(PimError::Auth),
            StatusCode::FORBIDDEN => Err(PimError::Protocol(format!(
                "{host} refused access to an object"
            ))),
            s if s.is_server_error() => {
                Err(PimError::Network(format!("{host} answered {}", s.as_u16())))
            }
            s => Err(PimError::Protocol(format!(
                "{host} answered {}",
                s.as_u16()
            ))),
        }
    }

    /// Sends a write once; busy answers are `Throttled`, nothing is repeated here.
    pub(crate) async fn write(
        &self,
        method: Method,
        url: Url,
        body: Option<&Value>,
        if_match: Option<&str>,
    ) -> Result<Wrote, PimError> {
        if !self.may_sign_in(&url) {
            return Err(PimError::Protocol(
                "Microsoft Graph named an address on another host".into(),
            ));
        }
        let host = host(&url);
        let _permit = self.permit().await;
        let response = match self.request(method, url, None, body, if_match).send().await {
            Ok(r) => r,
            Err(e) if e.is_connect() || e.is_builder() => return Err(network(&host, &e)),
            Err(_) => return Ok(Wrote::Uncertain),
        };
        let status = response.status();
        if status.is_success() {
            return Ok(match read_limited(response, MAX_ITEM, &host).await {
                Ok(body) => Wrote::Done(body),
                Err(_) => Wrote::Uncertain,
            });
        }
        if let Some(error) = throttled(status, response.headers()) {
            self.pause_on_busy(&error);
            return Err(error);
        }
        Ok(match status {
            StatusCode::UNAUTHORIZED => return Err(PimError::Auth),
            StatusCode::NOT_FOUND | StatusCode::GONE => Wrote::Missing,
            StatusCode::PRECONDITION_FAILED => Wrote::Stale,
            StatusCode::FORBIDDEN => Wrote::Refused("forbidden".into()),
            s if s.is_server_error() => Wrote::Uncertain,
            s => {
                let body = read_limited(response, MAX_ERROR, &host)
                    .await
                    .unwrap_or_default();
                let reason = error_code(&body).unwrap_or_else(|| format!("refused_{}", s.as_u16()));
                if s == StatusCode::BAD_REQUEST {
                    Wrote::Invalid(reason)
                } else {
                    Wrote::Refused(reason)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_or_loopback_and_the_configured_origin() {
        let base = Url::parse("https://graph.example.com/v1.0/").unwrap();
        let http = Http::new(
            "t".into(),
            &base,
            Duration::from_secs(5),
            &TlsRoots::default(),
        )
        .unwrap();
        assert!(
            http.url("https://graph.example.com/v1.0/me/contacts")
                .is_ok()
        );
        assert!(http.url("https://evil.example.com/v1.0/me").is_err());
        assert!(http.url("http://graph.example.com/v1.0/me").is_err());
        assert!(http.url("https://graph.example.com:8443/v1.0/me").is_err());
        assert!(allowed(&Url::parse("http://127.0.0.1:9/").unwrap()));
        assert!(!allowed(&Url::parse("http://example.com/").unwrap()));
    }

    #[test]
    fn waits_are_bounded_and_codes_are_plain() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, "86400".parse().unwrap());
        assert_eq!(wait_for(&headers, 1), LONGEST_WAIT);
        assert_eq!(wait_for(&HeaderMap::new(), 1), Duration::from_secs(1));
        assert_eq!(
            error_code(br#"{"error":{"code":"ErrorInvalidProperty","message":"x"}}"#),
            Some("ErrorInvalidProperty".into())
        );
        assert_eq!(
            error_code(br#"{"error":{"code":"has spaces ada@example.com"}}"#),
            None
        );
    }
}
