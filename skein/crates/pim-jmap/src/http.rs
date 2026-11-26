use std::net::IpAddr;
use std::time::Duration;

use bytes::Bytes;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, LOCATION, RETRY_AFTER};
use reqwest::{Method, StatusCode};
use serde_json::Value;
use skein_core::TlsRoots;
use skein_pim::PimError;
use url::{Host, Url};

const ATTEMPTS: u32 = 3;
const LONGEST_WAIT: Duration = Duration::from_secs(10);
const MAX_REDIRECTS: usize = 5;
pub(crate) const MAX_SESSION: usize = 1024 * 1024;
pub(crate) const MAX_ANSWER: usize = 64 * 1024 * 1024;

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

#[derive(Clone)]
pub(crate) enum Auth {
    Basic(String, String),
    Bearer(String),
}

/// An answer to an API request.
pub(crate) enum Posted {
    Answer(Value),
    /// The request went out but no usable answer came back.
    Lost,
}

#[derive(Clone)]
pub(crate) struct Http {
    client: reqwest::Client,
    auth: Auth,
    roots: TlsRoots,
}

fn host(url: &Url) -> String {
    url.host_str().unwrap_or("the JMAP server").to_owned()
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

fn status_error(status: StatusCode, host: &str) -> PimError {
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => PimError::Auth,
        s if s.is_server_error() => PimError::Network(format!("{host} answered {}", s.as_u16())),
        s => PimError::Protocol(format!("{host} answered {}", s.as_u16())),
    }
}

impl Http {
    pub(crate) fn new(auth: Auth, timeout: Duration, roots: &TlsRoots) -> Result<Self, PimError> {
        Ok(Self {
            client: client(timeout, roots)?,
            auth,
            roots: roots.clone(),
        })
    }

    pub(crate) fn with_timeout(mut self, timeout: Duration) -> Result<Self, PimError> {
        self.client = client(timeout, &self.roots)?;
        Ok(self)
    }

    fn signed(&self, method: Method, url: Url) -> reqwest::RequestBuilder {
        let builder = self
            .client
            .request(method, url)
            .header(ACCEPT, "application/json");
        match &self.auth {
            Auth::Basic(user, password) => builder.basic_auth(user, Some(password)),
            Auth::Bearer(token) => builder.bearer_auth(token),
        }
    }

    /// Where a well-known address leads, followed through redirects without credentials and
    /// never from https to plain http.
    pub(crate) async fn resolve(&self, start: Url) -> Result<Url, PimError> {
        let mut url = start;
        for _ in 0..MAX_REDIRECTS {
            let host = host(&url);
            let response = self
                .client
                .get(url.clone())
                .header(ACCEPT, "application/json")
                .send()
                .await
                .map_err(|e| network(&host, &e))?;
            if !response.status().is_redirection() {
                return Ok(url);
            }
            let next = response
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|l| url.join(l).ok())
                .ok_or_else(|| {
                    PimError::Protocol(format!("{host} redirected without an address"))
                })?;
            if !allowed(&next) || (url.scheme() == "https" && next.scheme() != "https") {
                return Err(PimError::Protocol(format!(
                    "{host} redirected away from https"
                )));
            }
            url = next;
        }
        Err(PimError::Protocol(
            "the JMAP address redirects too often".into(),
        ))
    }

    /// The session at `url`, asked with credentials; a redirect is not followed.
    pub(crate) async fn session(&self, url: &Url) -> Result<Value, PimError> {
        let host = host(url);
        let response = self
            .signed(Method::GET, url.clone())
            .send()
            .await
            .map_err(|e| network(&host, &e))?;
        let status = response.status();
        if status.is_redirection() {
            return Err(PimError::Protocol(format!(
                "{host} redirected the session address, which is not followed with credentials"
            )));
        }
        if status == StatusCode::NOT_FOUND {
            return Err(PimError::Config(format!(
                "{host} has no JMAP session at this address"
            )));
        }
        if let Some(error) = throttled(status, response.headers()) {
            return Err(error);
        }
        if !status.is_success() {
            return Err(status_error(status, &host));
        }
        let body = read_limited(response, MAX_SESSION, &host).await?;
        serde_json::from_slice(&body)
            .map_err(|_| PimError::Protocol(format!("{host} did not answer with a JMAP session")))
    }

    /// Posts a JMAP request. `repeatable` requests (reads) are tried again on busy answers, three
    /// times within about ten seconds; others report `Throttled` at once. A request that went out
    /// without a usable answer is [`Posted::Lost`]; one that never left is an error.
    pub(crate) async fn post(
        &self,
        url: &Url,
        body: &Value,
        repeatable: bool,
    ) -> Result<Posted, PimError> {
        let host = host(url);
        let body = body.to_string();
        let mut attempt = 0;
        let response = loop {
            let response = match self
                .signed(Method::POST, url.clone())
                .header(CONTENT_TYPE, "application/json")
                .body(body.clone())
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) if e.is_connect() || e.is_builder() || repeatable => {
                    return Err(network(&host, &e));
                }
                Err(_) => return Ok(Posted::Lost),
            };
            let status = response.status();
            let Some(error) = throttled(status, response.headers()) else {
                break response;
            };
            attempt += 1;
            if !repeatable || attempt >= ATTEMPTS {
                return Err(error);
            }
            let wait = wait_for(response.headers(), attempt);
            tracing::debug!(
                status = status.as_u16(),
                attempt,
                wait_ms = wait.as_millis() as u64,
                "JMAP server busy"
            );
            tokio::time::sleep(wait).await;
        };
        let status = response.status();
        if status.is_server_error() && !repeatable {
            return Ok(Posted::Lost);
        }
        if !status.is_success() {
            return Err(status_error(status, &host));
        }
        match read_limited(response, MAX_ANSWER, &host).await {
            Ok(body) => match serde_json::from_slice(&body) {
                Ok(v) => Ok(Posted::Answer(v)),
                Err(_) if repeatable => Err(PimError::Protocol(format!(
                    "{host} did not answer with JMAP"
                ))),
                Err(_) => Ok(Posted::Lost),
            },
            Err(PimError::Network(_)) if !repeatable => Ok(Posted::Lost),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waits_are_bounded() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, "86400".parse().unwrap());
        assert_eq!(wait_for(&headers, 1), LONGEST_WAIT);
        assert_eq!(wait_for(&HeaderMap::new(), 1), Duration::from_secs(1));
        assert!(allowed(&Url::parse("http://[::1]:8080/").unwrap()));
        assert!(!allowed(&Url::parse("http://jmap.example.com/").unwrap()));
        assert!(!allowed(&Url::parse("ftp://jmap.example.com/").unwrap()));
    }
}
