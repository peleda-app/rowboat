use std::net::IpAddr;
use std::time::Duration;

use bytes::Bytes;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, RETRY_AFTER};
use reqwest::{Method, StatusCode};
use serde_json::Value;
use skein_core::TlsRoots;
use skein_mail::MailError;
use skein_throttle::{Permit, Throttle};
use url::{Host, Url};

pub(crate) const MAX_JSON: usize = 64 * 1024 * 1024;
pub(crate) const MAX_DOWNLOAD: usize = 256 * 1024 * 1024;

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

/// Whether a `403` to a write says the sign-in lacks access (a missing permission or consent),
/// rather than refusing this one change (such as deleting a well-known folder). Without a
/// readable error code it counts as lacking access.
pub(crate) fn access_denied(body: &[u8]) -> bool {
    let code = serde_json::from_slice::<Value>(body).ok().and_then(|v| {
        v.pointer("/error/code")
            .and_then(Value::as_str)
            .map(str::to_owned)
    });
    match code {
        None => true,
        Some(code) => matches!(
            code.as_str(),
            "ErrorAccessDenied"
                | "AccessDenied"
                | "Authorization_RequestDenied"
                | "ErrorInsufficientPermission"
                | "InvalidAuthenticationToken"
        ),
    }
}

/// What a `403` means: on the mailbox as a whole a sign-in without access, on one message that
/// message's problem.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    Mailbox,
    Item,
}

pub(crate) enum Body {
    Empty,
    Json(Value),
    /// A MIME message in base64, as Graph takes it with `Content-Type: text/plain`.
    Mime(String),
}

/// A read whose `404` and `410` the caller handles.
pub(crate) enum Answer<T> {
    Found(T),
    Missing,
    /// `400` with a body, which Graph also uses for delta tokens it no longer accepts.
    Refused,
}

/// What became of a write.
pub(crate) enum Wrote {
    Done(Option<Value>),
    Missing,
    /// The request may have been carried out but no usable answer came back.
    Uncertain,
    Refused(u16),
}

#[derive(Clone)]
pub(crate) struct Http {
    client: reqwest::Client,
    token: String,
    origin: url::Origin,
    roots: TlsRoots,
    pub(crate) max_download: usize,
    pub(crate) throttle: Option<Throttle>,
}

fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

fn throttled(status: StatusCode, headers: &HeaderMap) -> Option<MailError> {
    let wait = retry_after(headers);
    match status {
        StatusCode::TOO_MANY_REQUESTS => Some(MailError::Throttled { retry_after: wait }),
        StatusCode::SERVICE_UNAVAILABLE if wait.is_some() => {
            Some(MailError::Throttled { retry_after: wait })
        }
        _ => None,
    }
}

fn host(url: &Url) -> String {
    url.host_str().unwrap_or("Microsoft Graph").to_owned()
}

fn network(host: &str, error: &reqwest::Error) -> MailError {
    MailError::Network(if error.is_timeout() {
        format!("{host} did not answer in time")
    } else {
        format!("{host} could not be reached")
    })
}

fn client(timeout: Duration, roots: &TlsRoots) -> Result<reqwest::Client, MailError> {
    let certs = roots
        .iter()
        .map(|der| {
            reqwest::Certificate::from_der(der)
                .map_err(|e| MailError::Config(format!("an extra trusted certificate: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(30).min(timeout))
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("Skein/", env!("CARGO_PKG_VERSION")))
        .tls_certs_merge(certs)
        .build()
        .map_err(|e| MailError::Config(e.to_string()))
}

impl Http {
    pub(crate) fn new(
        token: String,
        base: &Url,
        timeout: Duration,
        roots: &TlsRoots,
    ) -> Result<Self, MailError> {
        Ok(Self {
            client: client(timeout, roots)?,
            token,
            origin: base.origin(),
            roots: roots.clone(),
            max_download: MAX_DOWNLOAD,
            throttle: None,
        })
    }

    pub(crate) fn with_timeout(mut self, timeout: Duration) -> Result<Self, MailError> {
        self.client = client(timeout, &self.roots)?;
        Ok(self)
    }

    /// Parses an address and checks that it is on the configured Graph origin, so the token never
    /// goes anywhere else, even when an answer or a stored cursor names another host.
    pub(crate) fn url(&self, raw: &str) -> Result<Url, MailError> {
        let url = Url::parse(raw)
            .map_err(|_| MailError::Protocol("Microsoft Graph named an invalid address".into()))?;
        if !allowed(&url) || url.origin() != self.origin {
            return Err(MailError::Protocol(
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

    fn pause_on_busy(&self, status: StatusCode, headers: &HeaderMap) {
        if let Some(throttle) = &self.throttle
            && matches!(
                status,
                StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
            )
            && let Some(wait) = retry_after(headers)
        {
            throttle.pause(wait);
        }
    }

    async fn send(
        &self,
        method: Method,
        url: Url,
        body: &Body,
        page: Option<usize>,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let prefer = match page {
            Some(n) => format!("IdType=\"ImmutableId\", odata.maxpagesize={n}"),
            None => "IdType=\"ImmutableId\"".to_owned(),
        };
        let builder = self
            .client
            .request(method.clone(), url)
            .bearer_auth(&self.token)
            .header("Prefer", prefer)
            .header(ACCEPT, "application/json");
        let builder = match body {
            Body::Empty if method == Method::GET => builder,
            Body::Empty => builder.body(Vec::new()),
            Body::Json(value) => builder
                .header(CONTENT_TYPE, "application/json")
                .body(value.to_string()),
            Body::Mime(encoded) => builder
                .header(CONTENT_TYPE, "text/plain")
                .body(encoded.clone()),
        };
        builder.send().await
    }

    fn check(
        status: StatusCode,
        headers: &HeaderMap,
        host: &str,
        scope: Scope,
    ) -> Result<(), MailError> {
        if status.is_success() {
            return Ok(());
        }
        if let Some(e) = throttled(status, headers) {
            tracing::debug!(
                status = status.as_u16(),
                "Microsoft Graph is limiting requests"
            );
            return Err(e);
        }
        Err(match status {
            StatusCode::UNAUTHORIZED => MailError::Auth,
            StatusCode::FORBIDDEN if scope == Scope::Mailbox => MailError::Auth,
            StatusCode::FORBIDDEN => {
                MailError::Protocol(format!("{host} refused access to a message"))
            }
            s if s.is_server_error() => {
                MailError::Network(format!("{host} answered {}", s.as_u16()))
            }
            s => MailError::Protocol(format!("{host} answered {}", s.as_u16())),
        })
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

    async fn get(
        &self,
        url: Url,
        scope: Scope,
        page: Option<usize>,
        limit: usize,
    ) -> Result<Answer<Bytes>, MailError> {
        let host = host(&url);
        let _permit = self.permit().await;
        let response = self
            .send(Method::GET, url, &Body::Empty, page)
            .await
            .map_err(|e| network(&host, &e))?;
        let status = response.status();
        self.pause_on_busy(status, response.headers());
        if matches!(status, StatusCode::NOT_FOUND | StatusCode::GONE) {
            return Ok(Answer::Missing);
        }
        if status == StatusCode::BAD_REQUEST {
            return Ok(Answer::Refused);
        }
        Self::check(status, response.headers(), &host, scope)?;
        Ok(Answer::Found(Self::read(response, limit, &host).await?))
    }

    pub(crate) async fn get_json(
        &self,
        url: Url,
        scope: Scope,
        page: Option<usize>,
    ) -> Result<Answer<Value>, MailError> {
        let host = host(&url);
        Ok(match self.get(url, scope, page, MAX_JSON).await? {
            Answer::Found(body) => Answer::Found(
                serde_json::from_slice(&body)
                    .map_err(|_| MailError::Protocol(format!("{host} did not answer with JSON")))?,
            ),
            Answer::Missing => Answer::Missing,
            Answer::Refused => Answer::Refused,
        })
    }

    pub(crate) async fn get_bytes(&self, url: Url) -> Result<Answer<Bytes>, MailError> {
        self.get(url, Scope::Item, None, self.max_download).await
    }

    /// Sends a write. `repeatable` writes (patches, moves, deletes) treat a `503` with
    /// `Retry-After` as throttling, since repeating them is harmless; for an upload it is
    /// [`Wrote::Uncertain`].
    pub(crate) async fn write(
        &self,
        method: Method,
        url: Url,
        body: Body,
        repeatable: bool,
    ) -> Result<Wrote, MailError> {
        let host = host(&url);
        let _permit = self.permit().await;
        let response = match self.send(method, url, &body, None).await {
            Ok(r) => r,
            Err(e) if e.is_connect() => return Err(network(&host, &e)),
            Err(_) => return Ok(Wrote::Uncertain),
        };
        let status = response.status();
        self.pause_on_busy(status, response.headers());
        if status.is_success() {
            let Ok(body) = Self::read(response, MAX_JSON, &host).await else {
                return Ok(Wrote::Uncertain);
            };
            if body.iter().all(u8::is_ascii_whitespace) {
                return Ok(Wrote::Done(None));
            }
            return Ok(match serde_json::from_slice(&body) {
                Ok(v) => Wrote::Done(Some(v)),
                Err(_) => Wrote::Uncertain,
            });
        }
        if matches!(status, StatusCode::NOT_FOUND | StatusCode::GONE) {
            return Ok(Wrote::Missing);
        }
        if (status == StatusCode::TOO_MANY_REQUESTS
            || (repeatable && status == StatusCode::SERVICE_UNAVAILABLE))
            && let Some(e) = throttled(status, response.headers())
        {
            return Err(e);
        }
        if status == StatusCode::FORBIDDEN {
            let body = Self::read(response, MAX_JSON, &host)
                .await
                .unwrap_or_default();
            return if access_denied(&body) {
                Err(MailError::Auth)
            } else {
                Ok(Wrote::Refused(403))
            };
        }
        Ok(match status {
            StatusCode::UNAUTHORIZED => return Err(MailError::Auth),
            s if s.is_server_error() => Wrote::Uncertain,
            s => Wrote::Refused(s.as_u16()),
        })
    }
}
