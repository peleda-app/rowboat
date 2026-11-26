//! A [`Mailbox`](baton_mailbox::Mailbox) on a drop service reached over HTTP(S) (`drop-http`).
//!
//! It is `baton_drop::DropMailbox`, the one drop client, over [`HttpExchange`]: every request is
//! signed by the box key under the realm the application configured, and every reply is checked
//! before it is believed. The exchange adds transport limits: replies are read in chunks and
//! refused beyond what the service's info allows, timeouts sit above each request's long-poll
//! wait, redirects are not followed, no proxy is used, and plain `http` is refused except to a
//! loopback address unless explicitly allowed.

use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::Duration;

use async_trait::async_trait;
use baton_drop::service::max_reply;
use baton_drop::{Clock, DropMailbox, Exchange, wire};
use baton_mailbox::MailboxError;
use url::Url;

/// Client settings.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// How long connecting (TCP and TLS) may take (default 10 s).
    pub connect_timeout: Duration,
    /// How long a request may take beyond its long-poll wait (default 15 s).
    pub margin: Duration,
    /// Allow plain `http` to hosts other than loopback (default false: the operator would see
    /// nothing more, but anyone on the path would see the traffic pattern).
    pub allow_http: bool,
    /// Extra trusted root certificates (DER), for a private deployment's own certificate
    /// authority.
    pub roots: Vec<Vec<u8>>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            margin: Duration::from_secs(15),
            allow_http: false,
            roots: Vec::new(),
        }
    }
}

/// An [`Exchange`] over HTTP(S) to a `drop-http` server.
pub struct HttpExchange {
    client: reqwest::Client,
    info_url: Url,
    request_url: Url,
    margin: Duration,
    max_reply: OnceLock<usize>,
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(a)) => a.is_loopback(),
        Some(url::Host::Ipv6(a)) => a.is_loopback(),
        Some(url::Host::Domain(d)) => {
            d.eq_ignore_ascii_case("localhost")
                || d.parse::<IpAddr>().is_ok_and(|a| a.is_loopback())
        }
        None => false,
    }
}

impl HttpExchange {
    /// An exchange with the service at `base` (for example `https://drop.example.com/`).
    pub fn new(base: &Url, config: &ClientConfig) -> Result<Self, MailboxError> {
        match base.scheme() {
            "https" => {}
            "http" if config.allow_http || is_loopback(base) => {}
            _ => return Err(MailboxError::Rejected("drop url must be https")),
        }
        if base.cannot_be_a_base() || !base.username().is_empty() || base.password().is_some() {
            return Err(MailboxError::Rejected("drop url must be a plain base url"));
        }
        let mut builder = reqwest::Client::builder()
            .connect_timeout(config.connect_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .http1_only()
            .user_agent("baton-drop");
        for der in &config.roots {
            let cert = reqwest::Certificate::from_der(der)
                .map_err(|_| MailboxError::Rejected("bad root certificate"))?;
            builder = builder.add_root_certificate(cert);
        }
        let client = builder.build().map_err(MailboxError::unavailable)?;
        let join = |p: &str| {
            base.join(p.trim_start_matches('/'))
                .map_err(|_| MailboxError::Rejected("bad drop url"))
        };
        Ok(Self {
            client,
            info_url: join(baton_drop_paths::INFO)?,
            request_url: join(baton_drop_paths::REQUEST)?,
            margin: config.margin,
            max_reply: OnceLock::new(),
        })
    }

    async fn read(resp: reqwest::Response, cap: usize) -> Result<Vec<u8>, MailboxError> {
        match resp.status().as_u16() {
            200 => {}
            413 => return Err(MailboxError::TooLarge),
            429 | 503 => return Err(MailboxError::Busy),
            504 => return Err(MailboxError::unavailable("drop request outcome unknown")),
            _ => return Err(MailboxError::unavailable("unexpected http status")),
        }
        if resp.content_length().is_some_and(|n| n > cap as u64) {
            return Err(MailboxError::unavailable("reply too large"));
        }
        let mut resp = resp;
        let mut out = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(transport)? {
            if out.len() + chunk.len() > cap {
                return Err(MailboxError::unavailable("reply too large"));
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }
}

/// The paths `drop-http` serves, restated so the client does not depend on the server crate.
mod baton_drop_paths {
    pub const INFO: &str = "/v1/info";
    pub const REQUEST: &str = "/v1/request";
}

fn transport(e: reqwest::Error) -> MailboxError {
    if e.is_timeout() {
        MailboxError::unavailable("drop request timed out")
    } else if e.is_connect() {
        MailboxError::unavailable("cannot connect to drop service")
    } else {
        MailboxError::unavailable("drop transport failed")
    }
}

#[async_trait]
impl Exchange for HttpExchange {
    async fn info(&self) -> Result<Vec<u8>, MailboxError> {
        let resp = self
            .client
            .get(self.info_url.clone())
            .timeout(self.margin)
            .send()
            .await
            .map_err(transport)?;
        let raw = Self::read(resp, wire::MAX_INFO).await?;
        if let Ok(info) = wire::decode_info(&raw) {
            let _ = self.max_reply.set(max_reply(&info));
        }
        Ok(raw)
    }

    async fn exchange(&self, request: Vec<u8>, wait: Duration) -> Result<Vec<u8>, MailboxError> {
        let cap = *self
            .max_reply
            .get()
            .ok_or(MailboxError::unavailable("service info not fetched"))?;
        let resp = self
            .client
            .post(self.request_url.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .timeout(wait + self.margin)
            .body(request)
            .send()
            .await
            .map_err(transport)?;
        Self::read(resp, cap).await
    }
}

/// Connects to the drop service at `base`: fetches and checks its info (the realm must be
/// `realm`, from the application's configuration) and returns the drop client over HTTP.
pub async fn connect(
    base: &Url,
    realm: impl Into<String>,
    clock: Clock,
    config: &ClientConfig,
) -> Result<DropMailbox, MailboxError> {
    let exchange = HttpExchange::new(base, config)?;
    DropMailbox::connect(std::sync::Arc::new(exchange), realm, clock).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn plain_http_only_to_loopback_unless_allowed() {
        let c = ClientConfig::default();
        assert!(HttpExchange::new(&url("https://drop.example.com/"), &c).is_ok());
        assert!(HttpExchange::new(&url("http://127.0.0.1:9/"), &c).is_ok());
        assert!(HttpExchange::new(&url("http://[::1]:9/"), &c).is_ok());
        assert!(HttpExchange::new(&url("http://localhost:9/"), &c).is_ok());
        assert!(HttpExchange::new(&url("http://drop.example.com/"), &c).is_err());
        assert!(HttpExchange::new(&url("ftp://drop.example.com/"), &c).is_err());
        assert!(HttpExchange::new(&url("https://user:pw@drop.example.com/"), &c).is_err());
        let open = ClientConfig {
            allow_http: true,
            ..ClientConfig::default()
        };
        assert!(HttpExchange::new(&url("http://drop.example.com/"), &open).is_ok());
    }

    #[test]
    fn paths_join_under_a_prefix() {
        let x =
            HttpExchange::new(&url("https://example.com/drop/"), &ClientConfig::default()).unwrap();
        assert_eq!(
            x.request_url.as_str(),
            "https://example.com/drop/v1/request"
        );
        assert_eq!(x.info_url.as_str(), "https://example.com/drop/v1/info");
    }
}
