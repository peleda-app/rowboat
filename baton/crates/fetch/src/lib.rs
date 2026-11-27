//! Objects by content hash.
//!
//! A node serves objects it holds to peers that may read the resource ([`serve`], link protocol
//! `fetch`), and fetches objects it lacks from peers first, then from a [`Source`] the
//! application plugs in ([`Fetcher`]). Every byte that comes back is checked against its
//! [`ContentId`] (BLAKE3) before it is returned, whoever served it.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use baton_core::ResourceId;
use baton_identity::PublicKey;
use baton_link::{Link, LinkError, Protocol};
use bytes::Bytes;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

/// The link protocol objects travel on.
pub const PROTOCOL: &str = "fetch";

const MAX_REQUEST: usize = 1024;
/// The longest locator a request may carry, in bytes.
pub const MAX_LOCATOR: usize = 256;
const VERSION: u8 = 2;
const FOUND: u8 = 1;
const NOT_HERE: u8 = 0;

/// Errors of fetching and serving.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// No peer and no source had a copy that matches the content id.
    #[error("object not found")]
    NotFound,
    /// The link failed.
    #[error("link failed: {0}")]
    Link(#[from] LinkError),
    /// The application's source failed.
    #[error("source failed: {0}")]
    Source(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// The BLAKE3 hash of an object's bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentId(pub [u8; 32]);

impl ContentId {
    /// The id of `bytes`.
    pub fn of(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }

    /// Whether `bytes` are the object with this id.
    pub fn matches(&self, bytes: &[u8]) -> bool {
        Self::of(bytes) == *self
    }
}

/// Where objects come from when no peer has them: the application's storage (for Peleda, S3
/// directly or through presigned URLs). What it returns is verified like any peer's answer.
#[async_trait]
pub trait Source: Send + Sync {
    /// The object, if the source has it.
    async fn fetch(
        &self,
        resource: &ResourceId,
        id: &ContentId,
    ) -> Result<Option<Bytes>, FetchError>;
}

/// What this node holds and may serve.
#[async_trait]
pub trait LocalObjects: Send + Sync {
    /// The object, if held here **for `resource`**. An implementation must return `None` for an
    /// object that belongs only to another resource, even when a content-addressed store holds it,
    /// so a reader of one resource can neither fetch nor probe another's objects.
    ///
    /// `locator` is what the requester added to help find the object where content ids are not
    /// the storage key (at most [`MAX_LOCATOR`] bytes, empty when none). It comes from the peer
    /// and is untrusted: it may only narrow where to look, never change what is served, and the
    /// requester checks the bytes against `id` whatever the locator said.
    async fn get(&self, resource: &ResourceId, id: &ContentId, locator: &[u8]) -> Option<Bytes>;
}

/// Decides whether `peer` may read `resource` (normally: its node holds `Read` in the group log).
pub type Authorize = Arc<dyn Fn(&PublicKey, &ResourceId) -> bool + Send + Sync>;

#[derive(Serialize, Deserialize)]
struct Request {
    v: u8,
    resource: ResourceId,
    id: ContentId,
    locator: Vec<u8>,
}

fn decode_request(raw: &[u8]) -> Option<Request> {
    if raw.len() > MAX_REQUEST {
        return None;
    }
    postcard::from_bytes::<Request>(raw).ok()
}

fn reply_len(header: &[u8], max: u64) -> Option<u64> {
    let (&tag, rest) = header.split_first()?;
    if tag != FOUND {
        return None;
    }
    let len = u64::from_be_bytes(rest.get(..8)?.try_into().ok()?);
    (len <= max).then_some(len)
}

/// Runs the decoders of untrusted fetch bytes over `bytes`, for the fuzz target: a serving node's
/// request header (a 2-byte length, then the request) and a fetching node's reply header. Never
/// panics.
pub fn fuzz_decoders(bytes: &[u8]) {
    let _ = decode_request(bytes);
    if let Some((len, rest)) = bytes.split_first_chunk::<2>() {
        let len = u16::from_be_bytes(*len) as usize;
        if let Some(req) = rest.get(..len).and_then(decode_request) {
            let _ = (req.v == VERSION, req.locator.len() <= MAX_LOCATOR);
        }
    }
    if let Some(len) = reply_len(bytes, FetchConfig::default().max_object) {
        assert!(len <= FetchConfig::default().max_object);
    }
}

/// Limits of serving and fetching.
#[derive(Debug, Clone)]
pub struct FetchConfig {
    /// The largest object served or accepted, in bytes.
    pub max_object: u64,
    /// How long one peer may take to answer, from opening the stream to the last byte, plus the
    /// object's size at [`FetchConfig::min_rate`].
    pub peer_timeout: Duration,
    /// The slowest transfer accepted, in bytes per second: an object of `n` bytes gets
    /// `n / min_rate` seconds on top of `peer_timeout`, on both sides. 0 adds nothing.
    pub min_rate: u64,
    /// How long a requester may take to send its request before the stream is dropped.
    pub header_timeout: Duration,
    /// How long the application's source may take.
    pub source_timeout: Duration,
    /// How many peers are asked at once.
    pub parallel: usize,
    /// How many requests a serving node handles at once, across all peers.
    pub max_serving: usize,
    /// How many requests one peer may have open at once.
    pub max_per_peer: usize,
    /// How many bytes of objects a serving node holds in memory at once.
    pub serving_budget: u64,
    /// How long a peer that served wrong bytes is skipped for that resource.
    pub liar_ttl: Duration,
}

impl FetchConfig {
    fn transfer(&self, len: u64) -> Duration {
        match self.min_rate {
            0 => Duration::ZERO,
            rate => Duration::from_millis(len.saturating_mul(1000) / rate),
        }
    }
}

impl Default for FetchConfig {
    fn default() -> Self {
        Self {
            max_object: 64 * 1024 * 1024,
            peer_timeout: Duration::from_millis(1500),
            min_rate: 0,
            header_timeout: Duration::from_millis(500),
            source_timeout: Duration::from_secs(10),
            parallel: 2,
            max_serving: 16,
            max_per_peer: 4,
            serving_budget: 256 * 1024 * 1024,
            liar_ttl: Duration::from_secs(600),
        }
    }
}

/// Serves objects on `link` until the returned task is aborted. A request is answered with the
/// object only when `authorize` allows the requesting peer (authenticated by the link) to read the
/// resource, `objects` holds it for that resource, and it fits `config.max_object`; otherwise with
/// "not here", so a peer cannot tell a refusal from a missing object.
///
/// Resources a peer can make this node spend are bounded: the request must arrive within
/// `header_timeout` and before any shared slot is taken; one peer may have `max_per_peer` requests
/// open; `max_serving` requests are served at once; objects in memory never exceed
/// `serving_budget` bytes; every request ends within `peer_timeout` plus the object's size at
/// `min_rate`.
pub async fn serve(
    link: Arc<dyn Link>,
    objects: Arc<dyn LocalObjects>,
    authorize: Authorize,
    config: FetchConfig,
) -> Result<JoinHandle<()>, FetchError> {
    let protocol = Protocol::new(PROTOCOL).expect("valid protocol name");
    let mut incoming = link.listen(&protocol).await?;
    let slots = Arc::new(Semaphore::new(config.max_serving.max(1)));
    let kib = |n: u64| u32::try_from(n.div_ceil(1024)).unwrap_or(u32::MAX);
    let budget = Arc::new(Semaphore::new(kib(config.serving_budget) as usize));
    let per_peer: Arc<Mutex<std::collections::HashMap<PublicKey, usize>>> = Arc::default();
    Ok(tokio::spawn(async move {
        while let Some(inc) = incoming.next().await {
            {
                let mut open = per_peer.lock().expect("per-peer lock");
                let n = open.entry(inc.peer).or_insert(0);
                if *n >= config.max_per_peer.max(1) {
                    continue;
                }
                *n += 1;
            }
            let (objects, authorize, config) = (objects.clone(), authorize.clone(), config.clone());
            let (slots, budget, per_peer) = (slots.clone(), budget.clone(), per_peer.clone());
            tokio::spawn(async move {
                let peer = inc.peer;
                let mut s = inc.stream;
                let header = async {
                    let len = s.read_u16().await.ok()? as usize;
                    if len > MAX_REQUEST {
                        return None;
                    }
                    let mut raw = vec![0u8; len];
                    s.read_exact(&mut raw).await.ok()?;
                    decode_request(&raw)
                };
                let req = tokio::time::timeout(config.header_timeout, header)
                    .await
                    .ok()
                    .flatten();
                let deadline = tokio::time::Instant::now() + config.peer_timeout;
                let serve_one = async {
                    let req = req?;
                    let allowed = req.v == VERSION
                        && req.locator.len() <= MAX_LOCATOR
                        && authorize(&peer, &req.resource);
                    let found = tokio::time::timeout_at(deadline, async {
                        let slot = slots.acquire().await.ok()?;
                        let found = if allowed {
                            objects.get(&req.resource, &req.id, &req.locator).await
                        } else {
                            None
                        };
                        Some((slot, found))
                    })
                    .await
                    .ok()
                    .flatten();
                    let (_slot, found) = found?;
                    let found = found.filter(|b| b.len() as u64 <= config.max_object);
                    let _bytes = match &found {
                        Some(b) => Some(budget.try_acquire_many(kib(b.len() as u64).max(1)).ok()?),
                        None => None,
                    };
                    let until =
                        deadline + config.transfer(found.as_ref().map_or(0, |b| b.len() as u64));
                    let send = async {
                        match found {
                            Some(b) => {
                                s.write_u8(FOUND).await.ok()?;
                                s.write_u64(b.len() as u64).await.ok()?;
                                s.write_all(&b).await.ok()?;
                            }
                            None => s.write_u8(NOT_HERE).await.ok()?,
                        }
                        s.shutdown().await.ok()
                    };
                    tokio::time::timeout_at(until, send).await.ok().flatten()
                };
                let _ = serve_one.await;
                let mut open = per_peer.lock().expect("per-peer lock");
                if let Some(n) = open.get_mut(&peer) {
                    *n -= 1;
                    if *n == 0 {
                        open.remove(&peer);
                    }
                }
            });
        }
    }))
}

/// Where a fetched object came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// A peer, by its key.
    Peer(PublicKey),
    /// The application's source.
    Source,
}

/// Fetches objects: peers first, in the order given, `config.parallel` at a time, then the
/// source. A peer that served wrong bytes is skipped for that resource for `liar_ttl`.
pub struct Fetcher {
    link: Arc<dyn Link>,
    source: Option<Arc<dyn Source>>,
    config: FetchConfig,
    liars: Mutex<std::collections::HashMap<(PublicKey, ResourceId), std::time::Instant>>,
}

impl Fetcher {
    /// A fetcher on `link`, falling back to `source`.
    pub fn new(link: Arc<dyn Link>, source: Option<Arc<dyn Source>>, config: FetchConfig) -> Self {
        Self {
            link,
            source,
            config,
            liars: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Peers skipped for `resource` because they served bytes not matching a content id within
    /// the last `liar_ttl`.
    pub fn liars(&self, resource: &ResourceId) -> Vec<PublicKey> {
        let ttl = self.config.liar_ttl;
        let liars = self.liars.lock().expect("liars lock");
        liars
            .iter()
            .filter(|((_, r), at)| r == resource && at.elapsed() < ttl)
            .map(|((p, _), _)| *p)
            .collect()
    }

    async fn ask(
        &self,
        peer: PublicKey,
        resource: &ResourceId,
        id: &ContentId,
        locator: &[u8],
    ) -> Option<Bytes> {
        let protocol = Protocol::new(PROTOCOL).expect("valid protocol name");
        let max = self.config.max_object;
        let deadline = tokio::time::Instant::now() + self.config.peer_timeout;
        let head = async {
            let mut s = self.link.open(&peer, &protocol).await.ok()?;
            let req = postcard::to_stdvec(&Request {
                v: VERSION,
                resource: resource.clone(),
                id: *id,
                locator: locator.to_vec(),
            })
            .ok()?;
            s.write_u16(req.len() as u16).await.ok()?;
            s.write_all(&req).await.ok()?;
            let mut header = [0u8; 9];
            s.read_exact(&mut header[..1]).await.ok()?;
            if header[0] != FOUND {
                return None;
            }
            s.read_exact(&mut header[1..]).await.ok()?;
            reply_len(&header, max).map(|len| (s, len))
        };
        let (mut s, len) = tokio::time::timeout_at(deadline, head)
            .await
            .ok()
            .flatten()?;
        let body = async {
            let mut buf = Vec::with_capacity(usize::try_from(len.min(1024 * 1024)).ok()?);
            let read = (&mut s).take(len).read_to_end(&mut buf).await.ok()?;
            (read as u64 == len).then(|| Bytes::from(buf))
        };
        let bytes = tokio::time::timeout_at(deadline + self.config.transfer(len), body)
            .await
            .ok()
            .flatten()?;
        if id.matches(&bytes) {
            Some(bytes)
        } else {
            self.liars
                .lock()
                .expect("liars lock")
                .insert((peer, resource.clone()), std::time::Instant::now());
            None
        }
    }

    /// The object with `id` of `resource`: from the first of `peers` (asked in order,
    /// `config.parallel` at once, skipping known liars and this node) whose bytes match, else from
    /// the source if its bytes match, else [`FetchError::NotFound`].
    pub async fn fetch(
        &self,
        resource: &ResourceId,
        id: &ContentId,
        peers: &[PublicKey],
    ) -> Result<(Bytes, Origin), FetchError> {
        self.fetch_located(resource, id, &[], peers).await
    }

    /// [`Fetcher::fetch`] with a `locator` the serving peers' [`LocalObjects`] get to find the
    /// object (at most [`MAX_LOCATOR`] bytes, else [`FetchError::NotFound`] without asking
    /// anyone). The answer is checked against `id` as always.
    pub async fn fetch_located(
        &self,
        resource: &ResourceId,
        id: &ContentId,
        locator: &[u8],
        peers: &[PublicKey],
    ) -> Result<(Bytes, Origin), FetchError> {
        if locator.len() > MAX_LOCATOR {
            return Err(FetchError::NotFound);
        }
        let local = self.link.local();
        let liars = self.liars(resource);
        let mut seen = HashSet::new();
        let candidates: Vec<PublicKey> = peers
            .iter()
            .copied()
            .filter(|p| *p != local && !liars.contains(p) && seen.insert(*p))
            .collect();
        for batch in candidates.chunks(self.config.parallel.max(1)) {
            let mut asks: futures::stream::FuturesUnordered<_> = batch
                .iter()
                .map(|p| async move { (*p, self.ask(*p, resource, id, locator).await) })
                .collect();
            while let Some((peer, got)) = asks.next().await {
                if let Some(bytes) = got {
                    return Ok((bytes, Origin::Peer(peer)));
                }
            }
        }
        if let Some(source) = &self.source
            && let Ok(found) =
                tokio::time::timeout(self.config.source_timeout, source.fetch(resource, id)).await
            && let Some(bytes) = found?
            && bytes.len() as u64 <= self.config.max_object
            && id.matches(&bytes)
        {
            return Ok((bytes, Origin::Source));
        }
        Err(FetchError::NotFound)
    }
}

#[cfg(test)]
mod tests;
