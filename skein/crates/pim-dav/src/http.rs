use std::net::IpAddr;
use std::time::Duration;

use bytes::Bytes;
use reqwest::header::{CONTENT_TYPE, HeaderMap, LOCATION, RETRY_AFTER};
use reqwest::{Method, StatusCode};
use skein_core::{Credentials, TlsRoots};
use skein_pim::PimError;
use url::{Host, Url};

const ATTEMPTS: u32 = 3;
const LONGEST_WAIT: Duration = Duration::from_secs(10);
const MAX_REDIRECTS: usize = 5;
pub(crate) const MAX_XML: usize = 64 * 1024 * 1024;
pub(crate) const MAX_ITEM: usize = 16 * 1024 * 1024;

pub(crate) fn loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
        Some(Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
        Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

pub(crate) fn allowed_scheme(url: &Url, insecure: bool) -> bool {
    match url.scheme() {
        "https" => true,
        "http" => insecure || loopback(url),
        _ => false,
    }
}

fn host(url: &Url) -> String {
    url.host_str().unwrap_or("the server").to_owned()
}

fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

fn wait_for(headers: &HeaderMap, attempt: u32) -> Duration {
    retry_after(headers)
        .unwrap_or_else(|| Duration::from_millis(500 << attempt.min(4)))
        .min(LONGEST_WAIT)
}

pub(crate) struct Answer {
    pub status: StatusCode,
    pub url: Url,
    pub body: Bytes,
    pub headers: HeaderMap,
}

/// What a request signs in with: a user name with a password, or a bearer token.
#[derive(Clone)]
pub(crate) enum Auth {
    Basic { user: String, password: String },
    Bearer(String),
}

impl Auth {
    pub(crate) fn new(username: &str, credentials: &Credentials) -> Result<Self, PimError> {
        Ok(match credentials {
            Credentials::Password { secret } => Self::Basic {
                user: username.to_owned(),
                password: secret.clone(),
            },
            Credentials::AccessToken { token } => Self::Bearer(token.clone()),
            Credentials::AccessKey { .. } => {
                return Err(PimError::Config(
                    "CalDAV and CardDAV sign in with a password or a token, not an access key"
                        .into(),
                ));
            }
        })
    }
}

pub(crate) struct Http {
    client: reqwest::Client,
    auth: Auth,
    origins: Vec<url::Origin>,
    insecure: bool,
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
        .map_err(|_| PimError::Network(format!("{host} broke off its answer")))?
    {
        if body.len() + chunk.len() > limit {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(body))
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

impl Http {
    pub(crate) fn new(
        auth: Auth,
        origins: Vec<url::Origin>,
        timeout: Duration,
        roots: &TlsRoots,
        insecure: bool,
    ) -> Result<Self, PimError> {
        Ok(Self {
            client: client(timeout, roots)?,
            auth,
            origins,
            insecure,
        })
    }

    /// Whether credentials may go to `url`: https (or plain http to loopback, or anywhere when
    /// plain text was allowed explicitly), and the origin of a configured address.
    pub(crate) fn may_sign_in(&self, url: &Url) -> bool {
        allowed_scheme(url, self.insecure) && self.origins.contains(&url.origin())
    }

    async fn send_once(
        &self,
        method: &Method,
        url: &Url,
        depth: Option<&str>,
        body: Option<(&str, &Bytes)>,
        extra: &[(&str, &str)],
        sign_in: bool,
    ) -> Result<reqwest::Response, PimError> {
        let host = host(url);
        let mut attempt = 0;
        loop {
            let mut builder = self.client.request(method.clone(), url.clone());
            if let Some(depth) = depth {
                builder = builder.header("Depth", depth);
            }
            for (name, value) in extra {
                builder = builder.header(*name, *value);
            }
            if let Some((content_type, body)) = body {
                builder = builder
                    .header(CONTENT_TYPE, content_type)
                    .body(body.clone());
            }
            if sign_in {
                builder = match &self.auth {
                    Auth::Basic { user, password } => builder.basic_auth(user, Some(password)),
                    Auth::Bearer(token) => builder.bearer_auth(token),
                };
            }
            let response = builder.send().await.map_err(|e| {
                PimError::Network(if e.is_timeout() {
                    format!("{host} did not answer in time")
                } else {
                    format!("{host} could not be reached")
                })
            })?;
            let busy = matches!(
                response.status(),
                StatusCode::TOO_MANY_REQUESTS
                    | StatusCode::SERVICE_UNAVAILABLE
                    | StatusCode::GATEWAY_TIMEOUT
            );
            if !busy {
                return Ok(response);
            }
            attempt += 1;
            if attempt >= ATTEMPTS {
                return Err(PimError::Throttled {
                    retry_after: retry_after(response.headers()),
                });
            }
            let wait = wait_for(response.headers(), attempt);
            tracing::debug!(
                attempt,
                wait_ms = wait.as_millis() as u64,
                "DAV server busy"
            );
            tokio::time::sleep(wait).await;
        }
    }

    fn redirect_target(response: &reqwest::Response, from: &Url) -> Option<Url> {
        if !matches!(response.status().as_u16(), 301 | 302 | 307 | 308) {
            return None;
        }
        let location = response.headers().get(LOCATION)?.to_str().ok()?;
        from.join(location).ok()
    }

    /// A request with an XML body and credentials.
    pub(crate) async fn dav(
        &self,
        method: &str,
        url: &Url,
        depth: Option<&str>,
        body: Option<&str>,
        limit: usize,
    ) -> Result<Answer, PimError> {
        let body = body.map(|b| Bytes::copy_from_slice(b.as_bytes()));
        let body = body.as_ref().map(|b| ("application/xml; charset=utf-8", b));
        self.request(method, url, depth, body, &[], limit).await
    }

    /// A request with credentials. Redirects are followed, with the same method and body, only
    /// to addresses [`Http::may_sign_in`] allows; any other redirect is an error.
    pub(crate) async fn request(
        &self,
        method: &str,
        url: &Url,
        depth: Option<&str>,
        body: Option<(&str, &Bytes)>,
        extra: &[(&str, &str)],
        limit: usize,
    ) -> Result<Answer, PimError> {
        let method = Method::from_bytes(method.as_bytes()).expect("a valid method");
        let mut url = url.clone();
        for _ in 0..=MAX_REDIRECTS {
            if !self.may_sign_in(&url) {
                return Err(PimError::Protocol(
                    "the server pointed to another server, where the credentials are not sent"
                        .into(),
                ));
            }
            let response = self
                .send_once(&method, &url, depth, body, extra, true)
                .await?;
            if let Some(next) = Self::redirect_target(&response, &url) {
                url = next;
                continue;
            }
            let status = response.status();
            if status == StatusCode::UNAUTHORIZED {
                return Err(PimError::Auth);
            }
            let headers = response.headers().clone();
            let body = read_limited(response, limit, &host(&url)).await?;
            return Ok(Answer {
                status,
                url,
                body,
                headers,
            });
        }
        Err(PimError::Protocol(format!(
            "{} redirected too often",
            host(&url)
        )))
    }

    /// Looks up a well-known address without credentials, following redirects on the same
    /// origin only. `None` when the lookup leads nowhere useful or to another origin.
    pub(crate) async fn well_known(&self, url: &Url) -> Result<Option<Url>, PimError> {
        let method = Method::from_bytes(b"PROPFIND").expect("a valid method");
        let mut url = url.clone();
        let mut moved = false;
        for _ in 0..=MAX_REDIRECTS {
            if !self.may_sign_in(&url) {
                tracing::debug!("well-known lookup leads to another origin; ignored");
                return Ok(None);
            }
            let response = match self
                .send_once(&method, &url, Some("0"), None, &[], false)
                .await
            {
                Ok(response) => response,
                Err(PimError::Network(_)) if moved => return Ok(None),
                Err(error) => return Err(error),
            };
            if let Some(next) = Self::redirect_target(&response, &url) {
                url = next;
                moved = true;
                continue;
            }
            let status = response.status();
            if moved
                || status.is_success()
                || status == StatusCode::UNAUTHORIZED
                || status.as_u16() == 207
            {
                return Ok(Some(url));
            }
            return Ok(None);
        }
        Ok(None)
    }

    /// A GET with credentials. `None` when the object is gone.
    pub(crate) async fn get(&self, url: &Url) -> Result<Option<Answer>, PimError> {
        let answer = self.dav("GET", url, None, None, MAX_ITEM).await?;
        match answer.status {
            StatusCode::NOT_FOUND | StatusCode::GONE => Ok(None),
            s if s.is_success() => Ok(Some(answer)),
            s => Err(status_error(s, &answer.url)),
        }
    }
}

/// The error for an answer that is neither success nor something the caller handles.
pub(crate) fn status_error(status: StatusCode, url: &Url) -> PimError {
    let host = host(url);
    match status {
        StatusCode::UNAUTHORIZED => PimError::Auth,
        StatusCode::NOT_FOUND | StatusCode::GONE => PimError::NotFound,
        s if s.is_server_error() => PimError::Network(format!("{host} answered {}", s.as_u16())),
        s => PimError::Protocol(format!("{host} answered {}", s.as_u16())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http(origins: &[&str], insecure: bool) -> Http {
        Http::new(
            Auth::Bearer("t".into()),
            origins
                .iter()
                .map(|o| Url::parse(o).unwrap().origin())
                .collect(),
            Duration::from_secs(5),
            &TlsRoots::default(),
            insecure,
        )
        .unwrap()
    }

    #[test]
    fn credentials_stay_with_the_configured_origin() {
        let http = http(&["https://dav.example.com/"], false);
        let ok = |u: &str| http.may_sign_in(&Url::parse(u).unwrap());
        assert!(ok("https://dav.example.com/remote.php/dav/"));
        assert!(!ok("https://dav.example.com:8443/"), "another port");
        assert!(!ok("http://dav.example.com/"), "plain http");
        assert!(!ok("https://evil.example.com/"), "a sibling host");
        assert!(!ok("https://example.com/"), "the parent domain");
        let local = super::tests::http(&["http://127.0.0.1:8080/"], false);
        assert!(local.may_sign_in(&Url::parse("http://127.0.0.1:8080/dav/").unwrap()));
        assert!(!local.may_sign_in(&Url::parse("http://127.0.0.1:9090/dav/").unwrap()));
        let plain = super::tests::http(&["http://dav.example.com/"], false);
        assert!(!plain.may_sign_in(&Url::parse("http://dav.example.com/").unwrap()));
        let allowed = super::tests::http(&["http://dav.example.com/"], true);
        assert!(allowed.may_sign_in(&Url::parse("http://dav.example.com/x/").unwrap()));
    }

    #[test]
    fn waits_are_bounded() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, "86400".parse().unwrap());
        assert_eq!(wait_for(&headers, 1), LONGEST_WAIT);
        headers.insert(RETRY_AFTER, "3".parse().unwrap());
        assert_eq!(wait_for(&headers, 1), Duration::from_secs(3));
        assert_eq!(wait_for(&HeaderMap::new(), 1), Duration::from_secs(1));
    }
}
