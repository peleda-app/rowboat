use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::header::{CONTENT_TYPE, HeaderName, HeaderValue};

use crate::policy::resolve;
use crate::{SendError, WebhookError, WebhookPolicy};

/// Most bytes of an answer read before the rest is dropped.
pub const MAX_ANSWER: usize = 4 * 1024;

/// Carries one signed request to an endpoint.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Sends `body` as one `POST` with `Content-Type: application/json` and `headers`, and
    /// returns the answer's status code, whatever it is: a `3xx`, `4xx` or `5xx` is an answer,
    /// not an error. Redirects are never followed, no cookies or credentials are sent, and the
    /// answer's body is not kept.
    async fn post(
        &self,
        url: &str,
        headers: &[(&'static str, String)],
        body: Bytes,
    ) -> Result<u16, SendError>;
}

#[derive(Debug)]
struct Refused(SendError);

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl StdError for Refused {}

struct CheckedResolver {
    policy: Arc<WebhookPolicy>,
}

impl Resolve for CheckedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let policy = self.policy.clone();
        let name = name.as_str().to_owned();
        Box::pin(async move {
            let ips = resolve(&name)
                .await
                .map_err(|e| Box::new(Refused(e)) as Box<dyn StdError + Send + Sync>)?;
            policy
                .judge(&name, &ips)
                .map_err(|e| Box::new(Refused(e)) as Box<dyn StdError + Send + Sync>)?;
            let addrs: Addrs = Box::new(
                ips.into_iter()
                    .map(|ip| std::net::SocketAddr::new(ip, 0))
                    .collect::<Vec<_>>()
                    .into_iter(),
            );
            Ok(addrs)
        })
    }
}

/// [`Transport`] over HTTPS (reqwest, rustls) under a [`WebhookPolicy`]: host names are resolved
/// by a resolver that applies the policy, and the connection goes to the addresses it approved.
/// No proxy, no redirects, no cookies; the policy's timeout covers the whole request.
#[derive(Clone)]
pub struct HttpTransport {
    client: reqwest::Client,
    policy: Arc<WebhookPolicy>,
}

impl HttpTransport {
    /// A transport that sends only where `policy` allows.
    pub fn new(policy: WebhookPolicy) -> Result<Self, WebhookError> {
        let policy = Arc::new(policy);
        let client = reqwest::Client::builder()
            .timeout(policy.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .user_agent(concat!("Skein-Webhooks/", env!("CARGO_PKG_VERSION")))
            .dns_resolver(CheckedResolver {
                policy: policy.clone(),
            })
            .build()
            .map_err(|_| WebhookError::Client)?;
        Ok(Self { client, policy })
    }
}

fn refused_in(error: &reqwest::Error) -> Option<SendError> {
    let mut source: Option<&(dyn StdError + 'static)> = error.source();
    while let Some(e) = source {
        if let Some(Refused(kind)) = e.downcast_ref::<Refused>() {
            return Some(*kind);
        }
        source = e.source();
    }
    None
}

#[async_trait]
impl Transport for HttpTransport {
    async fn post(
        &self,
        url: &str,
        headers: &[(&'static str, String)],
        body: Bytes,
    ) -> Result<u16, SendError> {
        let url = self.policy.parse(url)?;
        let mut request = self
            .client
            .post(url)
            .header(CONTENT_TYPE, "application/json")
            .body(body);
        for (name, value) in headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| SendError::InvalidUrl("a header name is not valid"))?;
            let value = HeaderValue::from_str(value)
                .map_err(|_| SendError::InvalidUrl("a header value is not valid"))?;
            request = request.header(name, value);
        }
        let mut response = match request.send().await {
            Ok(r) => r,
            Err(e) => {
                if let Some(kind) = refused_in(&e) {
                    return Err(kind);
                }
                return Err(if e.is_timeout() {
                    SendError::Timeout
                } else {
                    SendError::Unreachable
                });
            }
        };
        let status = response.status().as_u16();
        let mut read = 0usize;
        while read < MAX_ANSWER {
            match response.chunk().await {
                Ok(Some(chunk)) => read += chunk.len(),
                _ => break,
            }
        }
        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[tokio::test]
    async fn the_resolver_applies_the_policy_at_connect_time() {
        let strict = CheckedResolver {
            policy: Arc::new(WebhookPolicy::default()),
        };
        let refused = strict
            .resolve(Name::from_str("localhost").unwrap())
            .await
            .err()
            .expect("loopback answers are refused");
        assert!(matches!(
            refused.downcast_ref::<Refused>(),
            Some(Refused(SendError::AddressRefused(_)))
        ));
        let local = CheckedResolver {
            policy: Arc::new(WebhookPolicy {
                allow_http_loopback: true,
                ..Default::default()
            }),
        };
        let addrs: Vec<_> = local
            .resolve(Name::from_str("localhost").unwrap())
            .await
            .unwrap()
            .collect();
        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(|a| a.ip().is_loopback()));
    }
}
