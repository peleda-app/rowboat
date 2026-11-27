use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use rowboat_discover::{DiscoverError, HttpsFetcher, HttpsUrl, MAX_FETCH_BYTES};

/// An [`HttpsFetcher`] over `reqwest`: `GET` only, HTTPS only, the certificate verified against
/// the platform's roots, no redirect followed, no cookie store, no credential, a fixed user
/// agent without a version, the whole call within the timeout (10 s by default).
#[derive(Clone)]
pub struct Https {
    client: reqwest::Client,
}

impl std::fmt::Debug for Https {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Https").finish_non_exhaustive()
    }
}

/// How the fetcher is built; the defaults suit the node.
#[derive(Debug, Clone)]
pub struct HttpsOptions {
    /// The whole call, from connecting to the last byte.
    pub timeout: Duration,
    /// DER certificates trusted besides the platform's roots (tests).
    pub extra_roots: Vec<Vec<u8>>,
    /// Host names answered from this table instead of DNS (tests).
    pub resolve: Vec<(String, SocketAddr)>,
}

impl Default for HttpsOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            extra_roots: Vec::new(),
            resolve: Vec::new(),
        }
    }
}

impl Https {
    /// A fetcher with the default options.
    pub fn new() -> Result<Self, DiscoverError> {
        Self::with_options(HttpsOptions::default())
    }

    /// A fetcher with `options`. [`DiscoverError::Invalid`] for an extra root that is not a
    /// certificate.
    pub fn with_options(options: HttpsOptions) -> Result<Self, DiscoverError> {
        let certs = options
            .extra_roots
            .iter()
            .map(|der| reqwest::Certificate::from_der(der).map_err(|_| DiscoverError::Invalid))
            .collect::<Result<Vec<_>, _>>()?;
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(options.timeout)
            .timeout(options.timeout)
            .user_agent("mail-client-autoconfig")
            .tls_certs_merge(certs);
        for (host, address) in &options.resolve {
            builder = builder.resolve(host, *address);
        }
        Ok(Self {
            client: builder.build().map_err(|_| DiscoverError::Invalid)?,
        })
    }
}

fn failure(error: &reqwest::Error) -> DiscoverError {
    if error.is_timeout() {
        DiscoverError::Timeout
    } else if error.is_connect() {
        DiscoverError::Unreachable
    } else {
        DiscoverError::Unavailable
    }
}

#[async_trait]
impl HttpsFetcher for Https {
    async fn get(&self, url: &HttpsUrl, max_bytes: usize) -> Result<Vec<u8>, DiscoverError> {
        if max_bytes > MAX_FETCH_BYTES {
            return Err(DiscoverError::Invalid);
        }
        let mut response = self
            .client
            .get(url.as_string())
            .send()
            .await
            .map_err(|e| failure(&e))?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(DiscoverError::Unavailable);
        }
        if response
            .content_length()
            .is_some_and(|n| n > max_bytes as u64)
        {
            return Err(DiscoverError::TooLarge);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| failure(&e))? {
            if body.len() + chunk.len() > max_bytes {
                return Err(DiscoverError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use skein_core::tls::testing::TestCa;

    use super::*;

    const BODY: &str = "<clientConfig/>";

    #[tokio::test(flavor = "multi_thread")]
    async fn keeps_the_fetcher_contract_over_a_test_ca() {
        let ca = TestCa::new(&["autoconfig.example.com", "big.example.com"]);
        let small = ca.serve_https(200, BODY).await;
        let big: &'static str = Box::leak("x".repeat(4096).into_boxed_str());
        let large = ca.serve_https(200, big).await;
        let options = HttpsOptions {
            timeout: Duration::from_secs(5),
            extra_roots: ca.roots().iter().map(<[u8]>::to_vec).collect(),
            resolve: vec![
                ("autoconfig.example.com".into(), small),
                ("big.example.com".into(), large),
            ],
        };
        let fetcher = Https::with_options(options.clone()).unwrap();
        let url = HttpsUrl::new("autoconfig.example.com", "/mail/config-v1.1.xml").unwrap();
        let oversized = HttpsUrl::new("big.example.com", "/mail/config-v1.1.xml").unwrap();
        rowboat_discover::testing::fetcher(&fetcher, &url, BODY.as_bytes(), &oversized).await;

        let untrusted = Https::with_options(HttpsOptions {
            extra_roots: Vec::new(),
            ..options.clone()
        })
        .unwrap();
        assert!(untrusted.get(&url, 1024).await.is_err());

        let missing = ca.serve_https(404, BODY).await;
        let redirecting = ca.serve_https(302, BODY).await;
        for answer in [missing, redirecting] {
            let f = Https::with_options(HttpsOptions {
                resolve: vec![("autoconfig.example.com".into(), answer)],
                ..options.clone()
            })
            .unwrap();
            assert_eq!(f.get(&url, 1024).await, Err(DiscoverError::Unavailable));
        }
        assert!(
            Https::with_options(HttpsOptions {
                extra_roots: vec![vec![1, 2, 3]],
                ..HttpsOptions::default()
            })
            .is_err()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_silent_server_times_out() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut open = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                open.push(socket);
            }
        });
        let fetcher = Https::with_options(HttpsOptions {
            timeout: Duration::from_millis(300),
            extra_roots: Vec::new(),
            resolve: vec![("autoconfig.example.com".into(), address)],
        })
        .unwrap();
        let url = HttpsUrl::new("autoconfig.example.com", "/x").unwrap();
        let got = tokio::time::timeout(Duration::from_secs(30), fetcher.get(&url, 1024))
            .await
            .expect("the fetcher's own timeout fires");
        assert_eq!(got, Err(DiscoverError::Timeout));
    }
}
