use std::net::IpAddr;
use std::time::Duration;

use bytes::Bytes;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, LOCATION, RETRY_AFTER};
use reqwest::{RequestBuilder, StatusCode};
use serde_json::Value;
use skein_core::TlsRoots;
use skein_mail::MailError;
use url::{Host, Url};

const MAX_REDIRECTS: usize = 5;
pub(crate) const MAX_JSON: usize = 64 * 1024 * 1024;
pub(crate) const MAX_DOWNLOAD: usize = 256 * 1024 * 1024;

#[derive(Clone)]
pub(crate) enum Auth {
    Basic(String, String),
    Bearer(String),
}

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

/// An answer to a request that changes something.
pub(crate) enum Posted {
    Answer(Value),
    /// The request went out but no usable answer came back.
    Lost,
}

#[derive(Clone)]
pub(crate) struct Http {
    client: reqwest::Client,
    still: reqwest::Client,
    auth: Auth,
    roots: TlsRoots,
    pub(crate) max_download: usize,
}

fn host(url: &Url) -> String {
    url.host_str().unwrap_or("the JMAP server").to_owned()
}

fn client(timeout: Duration, roots: &TlsRoots, follow: bool) -> Result<reqwest::Client, MailError> {
    let certs = roots
        .iter()
        .map(|der| {
            reqwest::Certificate::from_der(der)
                .map_err(|e| MailError::Config(format!("an extra trusted certificate: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let policy = if follow {
        reqwest::redirect::Policy::custom(|attempt| {
            let downgrade = attempt
                .previous()
                .last()
                .is_some_and(|p| p.scheme() == "https" && attempt.url().scheme() != "https");
            if attempt.previous().len() >= MAX_REDIRECTS || !allowed(attempt.url()) || downgrade {
                attempt.stop()
            } else {
                attempt.follow()
            }
        })
    } else {
        reqwest::redirect::Policy::none()
    };
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(30).min(timeout))
        .timeout(timeout)
        .redirect(policy)
        .user_agent(concat!("Skein/", env!("CARGO_PKG_VERSION")))
        .tls_certs_merge(certs)
        .build()
        .map_err(|e| MailError::Config(e.to_string()))
}

fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

fn network(host: &str, error: &reqwest::Error) -> MailError {
    MailError::Network(if error.is_timeout() {
        format!("{host} did not answer in time")
    } else if error.is_redirect() {
        format!("{host} redirected too often or away from https")
    } else {
        format!("{host} could not be reached")
    })
}

fn check(status: StatusCode, headers: &HeaderMap, host: &str) -> Result<(), MailError> {
    match status {
        s if s.is_success() => Ok(()),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(MailError::Auth),
        StatusCode::TOO_MANY_REQUESTS => Err(MailError::Throttled {
            retry_after: retry_after(headers),
        }),
        StatusCode::SERVICE_UNAVAILABLE if retry_after(headers).is_some() => {
            Err(MailError::Throttled {
                retry_after: retry_after(headers),
            })
        }
        s if s.is_server_error() => Err(MailError::Network(format!(
            "{host} answered {}",
            s.as_u16()
        ))),
        s => Err(MailError::Protocol(format!(
            "{host} answered {}",
            s.as_u16()
        ))),
    }
}

async fn read(
    mut response: reqwest::Response,
    limit: usize,
    host: &str,
) -> Result<Bytes, MailError> {
    let too_large = || MailError::Protocol(format!("{host} sent an answer that is too large"));
    if response.content_length().is_some_and(|n| n > limit as u64) {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| MailError::Network(format!("{host} broke off an answer")))?
    {
        if body.len() + chunk.len() > limit {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(body))
}

fn json(body: &[u8], host: &str) -> Result<Value, MailError> {
    serde_json::from_slice(body)
        .map_err(|_| MailError::Protocol(format!("{host} did not answer with JMAP")))
}

impl Http {
    pub(crate) fn new(auth: Auth, timeout: Duration, roots: &TlsRoots) -> Result<Self, MailError> {
        Ok(Self {
            client: client(timeout, roots, true)?,
            still: client(timeout, roots, false)?,
            auth,
            roots: roots.clone(),
            max_download: MAX_DOWNLOAD,
        })
    }

    pub(crate) fn with_timeout(mut self, timeout: Duration) -> Result<Self, MailError> {
        self.client = client(timeout, &self.roots, true)?;
        self.still = client(timeout, &self.roots, false)?;
        Ok(self)
    }

    /// Where a well-known address leads, followed through redirects without credentials.
    pub(crate) async fn resolve(&self, start: Url) -> Result<Url, MailError> {
        let mut url = start;
        for _ in 0..MAX_REDIRECTS {
            let host = host(&url);
            let response = self
                .still
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
                    MailError::Protocol(format!("{host} redirected without an address"))
                })?;
            if !allowed(&next) || (url.scheme() == "https" && next.scheme() != "https") {
                return Err(MailError::Protocol(format!(
                    "{host} redirected away from https"
                )));
            }
            url = next;
        }
        Err(MailError::Protocol(
            "the JMAP address redirects too often".into(),
        ))
    }

    fn request(
        &self,
        client: &reqwest::Client,
        method: reqwest::Method,
        raw: &str,
    ) -> Result<(RequestBuilder, String), MailError> {
        let url = Url::parse(raw)
            .map_err(|_| MailError::Protocol("the JMAP server named an invalid address".into()))?;
        if !allowed(&url) {
            return Err(MailError::Protocol(
                "the JMAP server named an address without https".into(),
            ));
        }
        let host = host(&url);
        let builder = client.request(method, url);
        let builder = match &self.auth {
            Auth::Basic(user, password) => builder.basic_auth(user, Some(password)),
            Auth::Bearer(token) => builder.bearer_auth(token),
        };
        Ok((builder, host))
    }

    /// The session at `url`, asked with credentials; a redirect is not followed.
    pub(crate) async fn session(&self, url: &Url) -> Result<Value, MailError> {
        let (builder, host) = self.request(&self.still, reqwest::Method::GET, url.as_str())?;
        let response = builder
            .header(ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| network(&host, &e))?;
        if response.status().is_redirection() {
            return Err(MailError::Protocol(format!(
                "{host} redirected the session address, which is not followed with credentials"
            )));
        }
        if response.status() == StatusCode::NOT_FOUND {
            return Err(MailError::Config(format!(
                "{host} has no JMAP session at this address"
            )));
        }
        check(response.status(), response.headers(), &host)?;
        json(&read(response, MAX_JSON, &host).await?, &host)
    }

    /// Posts a JMAP request. A request that went out without a usable answer is
    /// [`Posted::Lost`]; one that never left is an error.
    pub(crate) async fn post(&self, url: &str, body: &Value) -> Result<Posted, MailError> {
        self.post_raw(url, "application/json", body.to_string().into_bytes())
            .await
    }

    pub(crate) async fn post_raw(
        &self,
        url: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> Result<Posted, MailError> {
        let (builder, host) = self.request(&self.client, reqwest::Method::POST, url)?;
        let response = match builder
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, content_type)
            .body(body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) if e.is_connect() || e.is_redirect() || e.is_builder() => {
                return Err(network(&host, &e));
            }
            Err(_) => return Ok(Posted::Lost),
        };
        let status = response.status();
        if status.is_server_error()
            && !matches!(
                check(status, response.headers(), &host),
                Err(MailError::Throttled { .. })
            )
        {
            return Ok(Posted::Lost);
        }
        check(status, response.headers(), &host)?;
        match read(response, MAX_JSON, &host).await {
            Ok(body) => Ok(match serde_json::from_slice(&body) {
                Ok(v) => Posted::Answer(v),
                Err(_) => Posted::Lost,
            }),
            Err(MailError::Network(_)) => Ok(Posted::Lost),
            Err(e) => Err(e),
        }
    }

    /// An open `text/event-stream` answer, read as it arrives; the overall timeout does not
    /// apply, so the caller watches for silence itself.
    pub(crate) async fn stream(&self, url: &str) -> Result<reqwest::Response, MailError> {
        let (builder, host) = self.request(&self.client, reqwest::Method::GET, url)?;
        let response = builder
            .header(ACCEPT, "text/event-stream")
            .timeout(Duration::from_secs(30 * 24 * 60 * 60))
            .send()
            .await
            .map_err(|e| network(&host, &e))?;
        check(response.status(), response.headers(), &host)?;
        Ok(response)
    }

    /// The body, or `None` when the server no longer has it.
    pub(crate) async fn get_bytes(&self, url: &str) -> Result<Option<Bytes>, MailError> {
        let (builder, host) = self.request(&self.client, reqwest::Method::GET, url)?;
        let response = builder.send().await.map_err(|e| network(&host, &e))?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        check(response.status(), response.headers(), &host)?;
        read(response, self.max_download, &host).await.map(Some)
    }
}
