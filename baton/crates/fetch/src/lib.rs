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

const MAX_REQUEST: usize = 512;
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
    async fn get(&self, resource: &ResourceId, id: &ContentId) -> Option<Bytes>;
}

/// Decides whether `peer` may read `resource` (normally: its node holds `Read` in the group log).
pub type Authorize = Arc<dyn Fn(&PublicKey, &ResourceId) -> bool + Send + Sync>;

#[derive(Serialize, Deserialize)]
struct Request {
    v: u8,
    resource: ResourceId,
    id: ContentId,
}

/// Limits of serving and fetching.
#[derive(Debug, Clone)]
pub struct FetchConfig {
    /// The largest object served or accepted, in bytes.
    pub max_object: u64,
    /// How long one peer may take to answer, from opening the stream to the last byte.
    pub peer_timeout: Duration,
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

impl Default for FetchConfig {
    fn default() -> Self {
        Self {
            max_object: 64 * 1024 * 1024,
            peer_timeout: Duration::from_millis(1500),
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
/// `serving_budget` bytes; every request ends within `peer_timeout`.
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
                    postcard::from_bytes::<Request>(&raw).ok()
                };
                let req = tokio::time::timeout(config.header_timeout, header)
                    .await
                    .ok()
                    .flatten();
                let serve_one = async {
                    let req = req?;
                    let allowed = req.v == 1 && authorize(&peer, &req.resource);
                    let _slot = slots.acquire().await.ok()?;
                    let found = if allowed {
                        objects.get(&req.resource, &req.id).await
                    } else {
                        None
                    };
                    let found = found.filter(|b| b.len() as u64 <= config.max_object);
                    let _bytes = match &found {
                        Some(b) => Some(budget.try_acquire_many(kib(b.len() as u64).max(1)).ok()?),
                        None => None,
                    };
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
                let _ = tokio::time::timeout(config.peer_timeout, serve_one).await;
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

    async fn ask(&self, peer: PublicKey, resource: &ResourceId, id: &ContentId) -> Option<Bytes> {
        let protocol = Protocol::new(PROTOCOL).expect("valid protocol name");
        let max = self.config.max_object;
        let work = async {
            let mut s = self.link.open(&peer, &protocol).await.ok()?;
            let req = postcard::to_stdvec(&Request {
                v: 1,
                resource: resource.clone(),
                id: *id,
            })
            .ok()?;
            s.write_u16(req.len() as u16).await.ok()?;
            s.write_all(&req).await.ok()?;
            if s.read_u8().await.ok()? != FOUND {
                return None;
            }
            let len = s.read_u64().await.ok()?;
            if len > max {
                return None;
            }
            let mut buf = Vec::with_capacity(usize::try_from(len.min(1024 * 1024)).ok()?);
            let read = (&mut s).take(len).read_to_end(&mut buf).await.ok()?;
            (read as u64 == len).then(|| Bytes::from(buf))
        };
        let bytes = tokio::time::timeout(self.config.peer_timeout, work)
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
                .map(|p| async move { (*p, self.ask(*p, resource, id).await) })
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
