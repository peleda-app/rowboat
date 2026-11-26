//! The conformance suites of discovery's contracts and in-memory fakes for tests.

use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::{
    Candidate, DiscoverError, DiscoverySource, Domain, Endpoint, HttpsFetcher, HttpsUrl,
    MAX_CANDIDATES, MAX_FETCH_BYTES, MAX_SRV_RECORDS, Probed, Prober, SrvRecord, SrvResolver,
    valid_srv_name,
};

/// Looks up each of `domains` twice and checks: at most [`MAX_CANDIDATES`] candidates, each
/// valid, equal answers both times, and hostile-looking but valid domains answered without a
/// panic. Returns the answers for further checks.
pub async fn source(source: &dyn DiscoverySource, domains: &[&str]) -> Vec<Vec<Candidate>> {
    let mut out = Vec::new();
    let mut all: Vec<String> = domains.iter().map(|d| (*d).to_owned()).collect();
    all.push(format!("{}.example.com", "a".repeat(63)));
    all.push("xn--e1afmkfd.example.net".into());
    all.push("x.y".into());
    for d in &all {
        let domain = Domain::new(d).expect("valid test domain");
        let first = source.lookup(&domain).await;
        let second = source.lookup(&domain).await;
        assert_eq!(first, second, "{} answers differ", source.name());
        if let Ok(list) = first {
            assert!(list.len() <= MAX_CANDIDATES, "{} too many", source.name());
            assert!(
                list.iter().all(Candidate::is_valid),
                "{} invalid",
                source.name()
            );
            out.push(list);
        }
    }
    assert!(!source.name().is_empty());
    out
}

/// Fetches `url` and checks the answer is `body`; fetches `oversized` (a document larger than
/// 1 KiB) with a 1 KiB cap and checks it fails with [`DiscoverError::TooLarge`] rather than a
/// truncated body; asks for more than [`MAX_FETCH_BYTES`] and checks
/// [`DiscoverError::Invalid`].
pub async fn fetcher(
    fetcher: &dyn HttpsFetcher,
    url: &HttpsUrl,
    body: &[u8],
    oversized: &HttpsUrl,
) {
    assert_eq!(fetcher.get(url, MAX_FETCH_BYTES).await.as_deref(), Ok(body));
    assert_eq!(
        fetcher.get(oversized, 1024).await,
        Err(DiscoverError::TooLarge)
    );
    assert_eq!(
        fetcher.get(url, MAX_FETCH_BYTES + 1).await,
        Err(DiscoverError::Invalid)
    );
}

/// Resolves `name` and checks the records equal `records` in any order and stay within
/// [`MAX_SRV_RECORDS`]; resolves `missing` and checks an empty answer; checks invalid names are
/// [`DiscoverError::Invalid`].
pub async fn resolver(
    resolver: &dyn SrvResolver,
    name: &str,
    records: &[SrvRecord],
    missing: &str,
) {
    let mut got = resolver.srv(name).await.expect("answer");
    got.sort();
    let mut want = records.to_vec();
    want.sort();
    assert_eq!(got, want);
    assert!(got.len() <= MAX_SRV_RECORDS);
    assert_eq!(resolver.srv(missing).await, Ok(Vec::new()));
    for bad in [
        "",
        "example.com",
        "_imaps._tcp.localhost",
        "_imaps._tcp.a..b",
    ] {
        assert_eq!(
            resolver.srv(bad).await,
            Err(DiscoverError::Invalid),
            "{bad}"
        );
    }
}

/// A fetcher answering from a fixed map of URLs to bodies; unknown URLs are
/// [`DiscoverError::Unavailable`]. Records every URL asked for.
#[derive(Debug, Default)]
pub struct FakeFetcher {
    bodies: BTreeMap<String, Vec<u8>>,
    asked: Mutex<Vec<String>>,
}

impl FakeFetcher {
    /// A fetcher with `bodies` keyed by the whole URL.
    pub fn new(bodies: impl IntoIterator<Item = (String, Vec<u8>)>) -> Self {
        Self {
            bodies: bodies.into_iter().collect(),
            asked: Mutex::new(Vec::new()),
        }
    }

    /// Every URL asked for, in order.
    pub fn asked(&self) -> Vec<String> {
        self.asked.lock().expect("asked").clone()
    }
}

#[async_trait]
impl HttpsFetcher for FakeFetcher {
    async fn get(&self, url: &HttpsUrl, max_bytes: usize) -> Result<Vec<u8>, DiscoverError> {
        if max_bytes > MAX_FETCH_BYTES {
            return Err(DiscoverError::Invalid);
        }
        self.asked.lock().expect("asked").push(url.as_string());
        let body = self
            .bodies
            .get(&url.as_string())
            .ok_or(DiscoverError::Unavailable)?;
        if body.len() > max_bytes {
            return Err(DiscoverError::TooLarge);
        }
        Ok(body.clone())
    }
}

/// A resolver answering from a fixed map of names to records; other valid names have none.
#[derive(Debug, Default)]
pub struct FakeResolver {
    records: BTreeMap<String, Vec<SrvRecord>>,
    asked: Mutex<Vec<String>>,
}

impl FakeResolver {
    /// A resolver with `records` keyed by owner name.
    pub fn new(records: impl IntoIterator<Item = (String, Vec<SrvRecord>)>) -> Self {
        Self {
            records: records.into_iter().collect(),
            asked: Mutex::new(Vec::new()),
        }
    }

    /// Every name asked for, in order.
    pub fn asked(&self) -> Vec<String> {
        self.asked.lock().expect("asked").clone()
    }
}

#[async_trait]
impl SrvResolver for FakeResolver {
    async fn srv(&self, name: &str) -> Result<Vec<SrvRecord>, DiscoverError> {
        if !valid_srv_name(name) {
            return Err(DiscoverError::Invalid);
        }
        self.asked.lock().expect("asked").push(name.to_owned());
        Ok(self
            .records
            .get(name)
            .map(|r| r.iter().take(MAX_SRV_RECORDS).cloned().collect())
            .unwrap_or_default())
    }
}

/// A prober with fixed answers per host; unknown hosts are [`DiscoverError::Unreachable`].
/// Records every probe as `imap host:port` or `smtp host:port`.
#[derive(Debug, Default)]
pub struct FakeProber {
    answers: BTreeMap<String, Result<Probed, DiscoverError>>,
    asked: Mutex<Vec<String>>,
}

impl FakeProber {
    /// A prober answering `answers` keyed by host.
    pub fn new(answers: impl IntoIterator<Item = (String, Result<Probed, DiscoverError>)>) -> Self {
        Self {
            answers: answers.into_iter().collect(),
            asked: Mutex::new(Vec::new()),
        }
    }

    /// Every probe, in order.
    pub fn asked(&self) -> Vec<String> {
        self.asked.lock().expect("asked").clone()
    }

    fn answer(&self, kind: &str, e: &Endpoint) -> Result<Probed, DiscoverError> {
        self.asked
            .lock()
            .expect("asked")
            .push(format!("{kind} {}:{}", e.host, e.port));
        self.answers
            .get(&e.host)
            .copied()
            .unwrap_or(Err(DiscoverError::Unreachable))
    }
}

#[async_trait]
impl Prober for FakeProber {
    async fn probe_imap(&self, endpoint: &Endpoint) -> Result<Probed, DiscoverError> {
        self.answer("imap", endpoint)
    }

    async fn probe_smtp(&self, endpoint: &Endpoint) -> Result<Probed, DiscoverError> {
        self.answer("smtp", endpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_fakes_keep_their_contracts() {
        let url = HttpsUrl::new("autoconfig.example.com", "/a.xml").unwrap();
        let big = HttpsUrl::new("autoconfig.example.com", "/big.xml").unwrap();
        let f = FakeFetcher::new([
            (url.as_string(), b"<x/>".to_vec()),
            (big.as_string(), vec![b'a'; 2048]),
        ]);
        fetcher(&f, &url, b"<x/>", &big).await;
        let record = SrvRecord {
            priority: 0,
            weight: 1,
            port: 993,
            target: "imap.example.com".into(),
        };
        let r = FakeResolver::new([("_imaps._tcp.example.com".to_owned(), vec![record.clone()])]);
        resolver(
            &r,
            "_imaps._tcp.example.com",
            &[record],
            "_imap._tcp.example.com",
        )
        .await;
    }
}
