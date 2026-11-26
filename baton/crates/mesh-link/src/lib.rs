//! `baton-mesh`'s [`Transport`] over any [`Link`], so the mesh components
//! (`signal-mesh`, `lease-quorum`, `liveness-mesh`) run over a real link between nodes.
//!
//! Every message is still sealed with [`frame::seal`] and checked with [`frame::Opener`]: the
//! link authenticates and encrypts the channel, the frame signature and the roster check bind
//! each message to its sender and receiver, so a stolen session cannot be replayed to another
//! node. See `docs/README.md` for the wire layout and limits.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use baton_core::{NodeId, Timestamp};
use baton_identity::{Identity, PublicKey, RosterHandle};
use baton_link::{Duplex, Incoming, Link, LinkError, Protocol};
use baton_mesh::frame::{self, FrameError, Opener};
use baton_mesh::{Envelope, MAX_PAYLOAD, Transport, TransportError, check_channel};
use bytes::Bytes;
use futures::StreamExt;
use futures::stream::BoxStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// The link protocol mesh frames travel on.
pub const MESH_PROTOCOL: &str = "mesh";

/// The largest frame accepted from a stream.
pub use baton_mesh::frame::MAX_FRAME;

/// Why a [`LinkTransport`] could not start.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    /// The link's key is not the identity's key.
    #[error("the link does not belong to this identity")]
    WrongIdentity,
    /// The link refused to listen.
    #[error("link failed: {0}")]
    Link(#[from] LinkError),
}

/// Tuning for [`LinkTransport`].
#[derive(Debug, Clone)]
pub struct LinkTransportConfig {
    /// How long one `send` may wait for a stream to open and a frame to be written.
    pub send_timeout: Duration,
    /// How long `peers` waits for streams to members that are not connected yet.
    pub probe_timeout: Duration,
    /// After a failed attempt to reach a member, how long it counts as unreachable without
    /// trying again.
    pub retry_after: Duration,
}

impl Default for LinkTransportConfig {
    fn default() -> Self {
        Self {
            send_timeout: Duration::from_secs(5),
            probe_timeout: Duration::from_secs(1),
            retry_after: Duration::from_secs(2),
        }
    }
}

type Subscribers = Mutex<HashMap<String, Vec<mpsc::Sender<Envelope>>>>;

struct Writer {
    generation: u64,
    half: WriteHalf<Box<dyn Duplex>>,
    dead: Arc<AtomicBool>,
    _stop: oneshot::Sender<()>,
}

#[derive(Default)]
struct Peer {
    writer: Option<Writer>,
    failed_at: Option<Instant>,
}

struct Inner {
    link: Arc<dyn Link>,
    identity: Identity,
    local: NodeId,
    roster: RosterHandle,
    opener: Opener,
    config: LinkTransportConfig,
    protocol: Protocol,
    subscribers: Subscribers,
    peers: Mutex<HashMap<PublicKey, Arc<tokio::sync::Mutex<Peer>>>>,
    seq: AtomicU64,
    generation: AtomicU64,
    dropped: AtomicU64,
}

/// A [`Transport`] whose messages travel over a [`Link`].
///
/// Guarantees beyond the contract:
///
/// - Each message is one frame sealed by [`frame::seal`]; a frame reaches subscribers only if
///   [`Opener::open`] accepts it (addressed to this node, signed by a member of the roster held
///   at that moment, sent by the key that opened the stream it came on, sequence number higher
///   than any accepted before from that sender). One opener serves every stream: a frame relayed
///   by another member is refused before it can move its signer's counter.
/// - Frames from one sender to one receiver go over one stream at a time, in order; when a stream
///   breaks, the next send opens a new one, and a late frame from the old stream is dropped by the
///   sequence check rather than delivered out of order.
/// - `send` returns `Unreachable` when no stream can be opened or written within
///   [`LinkTransportConfig::send_timeout`]; success means the frame was handed to the link, not
///   that it arrived. A stream whose write was cut short (by the timeout or a dropped `send`)
///   is never written to again: it is dropped and the next send opens a new one, so frame
///   boundaries hold.
/// - A receiver drops a stream that carries a malformed frame, a bad signature or a frame from
///   another sender, so a broken stream ends and its opener reopens instead of losing frames.
/// - `peers` tries to reach every member it has no stream to (for at most
///   [`LinkTransportConfig::probe_timeout`], skipping members that failed within
///   [`LinkTransportConfig::retry_after`]) and lists those it has a stream to.
pub struct LinkTransport {
    inner: Arc<Inner>,
    accept: JoinHandle<()>,
}

impl Drop for LinkTransport {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

impl LinkTransport {
    /// Starts on `link`, which must belong to `identity` and should trust `roster` (for example
    /// by being built with the roster handle as its [`Trust`](baton_link::Trust)). Listens on
    /// [`MESH_PROTOCOL`]; the link must not have another listener for it. Needs a Tokio runtime.
    pub async fn start(
        link: Arc<dyn Link>,
        identity: Identity,
        roster: RosterHandle,
        config: LinkTransportConfig,
    ) -> Result<Self, StartError> {
        if link.local() != identity.public() {
            return Err(StartError::WrongIdentity);
        }
        let protocol = Protocol::new(MESH_PROTOCOL).expect("valid protocol name");
        let listener = link.listen(&protocol).await?;
        let local = identity.node_id();
        let start_seq = Timestamp::now().0.max(0) as u64 * 1000;
        let inner = Arc::new(Inner {
            link,
            opener: Opener::new(identity.node_id(), roster.clone()),
            identity,
            local,
            roster,
            config,
            protocol,
            subscribers: Mutex::new(HashMap::new()),
            peers: Mutex::new(HashMap::new()),
            seq: AtomicU64::new(start_seq),
            generation: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        });
        let accept = tokio::spawn(accept_loop(Arc::downgrade(&inner), listener));
        Ok(Self { inner, accept })
    }

    /// How many incoming frames were dropped because they failed a check or were malformed.
    pub fn dropped(&self) -> u64 {
        self.inner.dropped.load(Ordering::Relaxed)
    }
}

async fn accept_loop(weak: Weak<Inner>, mut listener: BoxStream<'static, Incoming>) {
    while let Some(incoming) = listener.next().await {
        tokio::spawn(read_frames(weak.clone(), incoming));
    }
}

async fn read_frames(weak: Weak<Inner>, incoming: Incoming) {
    let peer = incoming.peer;
    if let Some(inner) = weak.upgrade() {
        inner.opener.reset(&peer);
    }
    let mut stream = incoming.stream;
    loop {
        let Ok(len) = stream.read_u32().await else {
            return;
        };
        let len = len as usize;
        if len > MAX_FRAME {
            if let Some(inner) = weak.upgrade() {
                inner.dropped.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        let mut raw = vec![0u8; len];
        if stream.read_exact(&mut raw).await.is_err() {
            return;
        }
        let Some(inner) = weak.upgrade() else { return };
        match inner.opener.open(&raw, Some(&peer)) {
            Ok(env) => inner.deliver(env),
            Err(FrameError::Malformed | FrameError::BadSignature | FrameError::WrongSender) => {
                inner.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
            Err(_) => {
                inner.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl Inner {
    fn deliver(&self, env: Envelope) {
        let mut subs = self.subscribers.lock().expect("subscribers lock");
        if let Some(list) = subs.get_mut(&env.channel) {
            list.retain(|tx| {
                !matches!(
                    tx.try_send(env.clone()),
                    Err(mpsc::error::TrySendError::Closed(_))
                )
            });
        }
    }

    fn slot(&self, peer: &PublicKey) -> Arc<tokio::sync::Mutex<Peer>> {
        self.peers
            .lock()
            .expect("peers lock")
            .entry(*peer)
            .or_default()
            .clone()
    }

    async fn connect(
        self: &Arc<Self>,
        key: &PublicKey,
        slot: &Arc<tokio::sync::Mutex<Peer>>,
        state: &mut Peer,
        respect_backoff: bool,
    ) -> Result<(), TransportError> {
        if state
            .writer
            .as_ref()
            .is_some_and(|w| w.dead.load(Ordering::SeqCst))
        {
            state.writer = None;
        }
        if state.writer.is_some() {
            return Ok(());
        }
        if respect_backoff
            && state
                .failed_at
                .is_some_and(|t| t.elapsed() < self.config.retry_after)
        {
            return Err(TransportError::Unreachable);
        }
        match self.link.open(key, &self.protocol).await {
            Ok(stream) => {
                let (read, write) = tokio::io::split(stream);
                let generation = self.generation.fetch_add(1, Ordering::Relaxed);
                let dead = Arc::new(AtomicBool::new(false));
                let (stop, stopped) = oneshot::channel();
                state.writer = Some(Writer {
                    generation,
                    half: write,
                    dead: dead.clone(),
                    _stop: stop,
                });
                state.failed_at = None;
                tokio::spawn(watch(Arc::downgrade(slot), generation, read, dead, stopped));
                Ok(())
            }
            Err(LinkError::Closed) => Err(TransportError::Backend(Box::new(LinkError::Closed))),
            Err(_) => {
                state.failed_at = Some(Instant::now());
                Err(TransportError::Unreachable)
            }
        }
    }

    async fn write(
        self: &Arc<Self>,
        key: &PublicKey,
        to: &NodeId,
        channel: &str,
        payload: &[u8],
    ) -> Result<(), TransportError> {
        let slot = self.slot(key);
        let mut state = slot.lock().await;
        for attempt in 0..2 {
            self.connect(key, &slot, &mut state, attempt == 0).await?;
            let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
            let sealed = frame::seal(&self.identity, to, channel, seq, payload);
            let mut buf = Vec::with_capacity(4 + sealed.len());
            buf.extend_from_slice(&(sealed.len() as u32).to_be_bytes());
            buf.extend_from_slice(&sealed);
            let mut writer = state.writer.take().expect("connected");
            let ok = async {
                writer.half.write_all(&buf).await?;
                writer.half.flush().await
            }
            .await
            .is_ok();
            if ok {
                state.writer = Some(writer);
                return Ok(());
            }
        }
        state.failed_at = Some(Instant::now());
        Err(TransportError::Unreachable)
    }
}

async fn watch(
    slot: Weak<tokio::sync::Mutex<Peer>>,
    generation: u64,
    mut read: ReadHalf<Box<dyn Duplex>>,
    dead: Arc<AtomicBool>,
    mut stopped: oneshot::Receiver<()>,
) {
    let mut sink = [0u8; 64];
    loop {
        tokio::select! {
            _ = &mut stopped => break,
            read = read.read(&mut sink) => match read {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            },
        }
    }
    dead.store(true, Ordering::SeqCst);
    if let Some(slot) = slot.upgrade() {
        let mut state = slot.lock().await;
        if state
            .writer
            .as_ref()
            .is_some_and(|w| w.generation == generation)
        {
            state.writer = None;
        }
    }
}

#[async_trait]
impl Transport for LinkTransport {
    fn local(&self) -> NodeId {
        self.inner.local.clone()
    }

    async fn send(&self, to: &NodeId, channel: &str, payload: Bytes) -> Result<(), TransportError> {
        check_channel(channel)?;
        if payload.len() > MAX_PAYLOAD {
            return Err(TransportError::TooLarge);
        }
        if *to == self.inner.local {
            return Err(TransportError::Unreachable);
        }
        let key = PublicKey::from_node_id(to).map_err(|_| TransportError::Unreachable)?;
        tokio::time::timeout(
            self.inner.config.send_timeout,
            self.inner.write(&key, to, channel, &payload),
        )
        .await
        .map_err(|_| TransportError::Unreachable)?
    }

    async fn subscribe(
        &self,
        channel: &str,
    ) -> Result<BoxStream<'static, Envelope>, TransportError> {
        check_channel(channel)?;
        let (tx, rx) = mpsc::channel(baton_mesh::SUBSCRIBER_BUFFER);
        self.inner
            .subscribers
            .lock()
            .expect("subscribers lock")
            .entry(channel.to_owned())
            .or_default()
            .push(tx);
        Ok(
            futures::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|e| (e, rx)) })
                .boxed(),
        )
    }

    async fn peers(&self) -> Result<Vec<NodeId>, TransportError> {
        let roster = self.inner.roster.current();
        let me = self.inner.identity.public();
        let probes = roster.members().iter().filter(|k| **k != me).map(|key| {
            let inner = self.inner.clone();
            let key = *key;
            async move {
                let slot = inner.slot(&key);
                let attempt = async {
                    let mut state = slot.lock().await;
                    inner.connect(&key, &slot, &mut state, true).await.is_ok()
                };
                let up = tokio::time::timeout(inner.config.probe_timeout, attempt)
                    .await
                    .unwrap_or(false);
                up.then(|| key.node_id())
            }
        });
        let mut peers: Vec<NodeId> = futures::future::join_all(probes)
            .await
            .into_iter()
            .flatten()
            .collect();
        peers.sort();
        Ok(peers)
    }
}

#[cfg(test)]
mod tests;
