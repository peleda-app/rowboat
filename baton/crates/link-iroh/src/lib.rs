//! [`Link`] over [iroh](https://github.com/n0-computer/iroh) 1.x: QUIC with TLS 1.3 using raw
//! public keys, so each side is authenticated by its pinned Ed25519 node key; direct paths with
//! hole punching, relays as fallback, and a hybrid post-quantum key exchange (X25519MLKEM768).
//!
//! No iroh type crosses the public API. See `docs/README.md` for the configuration, the wire
//! layout and the limits.

mod config;
mod gate;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use async_trait::async_trait;
use baton_identity::Identity;
use baton_link::{Duplex, Incoming, Link, LinkError, PeerHint, Protocol, PublicKey, Trust};
use futures::Stream;
use futures::stream::BoxStream;
use iroh::endpoint::{
    ConnectOptions, ConnectWithOptsError, ConnectingError, Connection, ConnectionError, RecvStream,
    SendStream, VarInt,
};
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub use config::{AlpnPrefix, Discovery, IrohConfig, PostQuantum};
use gate::{CODE_PQ, CODE_UNTRUSTED, Gate, to_baton, to_iroh};

const HELLO: u8 = 0x50;
const ACCEPT: u8 = 1;
const REFUSE: u8 = 0;
const CODE_CLOSED: u32 = 0;
const CODE_REVOKED: u32 = 401;

/// The ALPN identifier of `protocol` under `prefix`: `<prefix>/<protocol>/1`.
pub fn alpn(prefix: &AlpnPrefix, protocol: &Protocol) -> Vec<u8> {
    format!("{}/{}/1", prefix.as_str(), protocol.as_str()).into_bytes()
}

/// The fallback ALPN every endpoint serves, offered second by every dialer: `<prefix>/link/1`. A
/// connection that lands on it names its protocol in each stream header; it exists so that
/// dialing a protocol nothing listens for ends in a clean refusal instead of a failed TLS
/// handshake.
pub fn generic_alpn(prefix: &AlpnPrefix) -> Vec<u8> {
    format!("{}/link/1", prefix.as_str()).into_bytes()
}

fn protocol_of(prefix: &AlpnPrefix, alpn: &[u8]) -> Option<Protocol> {
    let s = std::str::from_utf8(alpn).ok()?;
    let name = s
        .strip_prefix(prefix.as_str())?
        .strip_prefix('/')?
        .strip_suffix("/1")?;
    Protocol::new(name).ok()
}

type Listeners = Mutex<HashMap<Protocol, (u64, mpsc::UnboundedSender<Incoming>)>>;
type Slot = Arc<tokio::sync::Mutex<Option<Connection>>>;

struct Inner {
    endpoint: Endpoint,
    key: PublicKey,
    trust: Arc<dyn Trust>,
    config: IrohConfig,
    hints: Mutex<HashMap<PublicKey, PeerHint>>,
    listeners: Listeners,
    next_listener: AtomicU64,
    pool: Mutex<HashMap<(PublicKey, Protocol), Slot>>,
    live: Mutex<HashMap<usize, (PublicKey, Connection)>>,
    closed: AtomicBool,
}

/// A [`Link`] on an iroh endpoint whose key is the node's identity.
///
/// Guarantees beyond the contract:
///
/// - The endpoint's secret key is the node's Ed25519 identity, so its iroh endpoint id is the
///   node's public key; the secret is copied straight from the zeroizing buffer of
///   [`Identity::secret_bytes`] into iroh's signing key and never kept elsewhere.
/// - Each protocol listened for is served as its own ALPN (`<prefix>/<protocol>/1`), plus the
///   fallback [`generic_alpn`]; a stream for a protocol nothing listens for is refused in-band
///   (`Rejected`) instead of failing the TLS handshake.
/// - `open` finishes within [`IrohConfig::open_timeout`] in total, and opens to the same peer and
///   protocol run concurrently on a pooled connection.
/// - Trust is checked before dialing, again by an endpoint hook right after every TLS handshake
///   in both directions (the connection is closed with code 403 before any stream is accepted),
///   and again for every stream.
/// - With [`PostQuantum::Required`] (the default) a connection whose TLS handshake did not
///   negotiate X25519MLKEM768 is closed by the same hook before any stream is accepted.
/// - Outgoing connections are reused per peer and protocol; every stream still asks the trust.
pub struct IrohLink {
    inner: Arc<Inner>,
    accept: JoinHandle<()>,
}

impl Drop for IrohLink {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

impl std::fmt::Debug for IrohLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IrohLink({:?})", self.inner.key)
    }
}

impl IrohLink {
    /// Binds an endpoint for `identity` that trusts what `trust` allows. Needs a Tokio runtime.
    pub async fn bind(
        identity: &Identity,
        trust: Arc<dyn Trust>,
        config: IrohConfig,
    ) -> Result<Self, LinkError> {
        let secret = SecretKey::from_bytes(&identity.secret_bytes());
        let gate = Gate::new(trust.clone(), config.post_quantum);
        let mut builder = Endpoint::builder(iroh::endpoint::presets::Empty)
            .crypto_provider(config::crypto_provider())
            .secret_key(secret)
            .alpns(vec![generic_alpn(&config.alpn_prefix)])
            .hooks(gate);
        builder = match config.relays.is_empty() {
            true => builder.relay_mode(RelayMode::Disabled),
            false => builder.relay_mode(RelayMode::custom(
                config
                    .relays
                    .iter()
                    .map(config::relay_url)
                    .collect::<Result<Vec<_>, _>>()?,
            )),
        };
        builder = config.discovery.apply(builder)?;
        if !config.bind.is_empty() {
            builder = builder.clear_ip_transports();
            for addr in &config.bind {
                builder = builder.bind_addr(*addr).map_err(LinkError::backend)?;
            }
        }
        let endpoint = builder.bind().await.map_err(LinkError::backend)?;
        let inner = Arc::new(Inner {
            endpoint,
            key: identity.public(),
            trust,
            config,
            hints: Mutex::new(HashMap::new()),
            listeners: Mutex::new(HashMap::new()),
            next_listener: AtomicU64::new(0),
            pool: Mutex::new(HashMap::new()),
            live: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
        });
        let accept = tokio::spawn(accept_loop(Arc::downgrade(&inner), inner.endpoint.clone()));
        Ok(Self { inner, accept })
    }

    /// The local socket addresses the endpoint is bound to. Addresses on an unspecified IP
    /// (`0.0.0.0`, `::`) mean every interface.
    pub fn bound_addrs(&self) -> Vec<SocketAddr> {
        self.inner.endpoint.bound_sockets()
    }
}

impl Inner {
    fn ensure_open(&self) -> Result<(), LinkError> {
        if self.closed.load(Ordering::SeqCst) {
            Err(LinkError::Closed)
        } else {
            Ok(())
        }
    }

    fn update_alpns(&self) {
        let mut alpns: Vec<Vec<u8>> = self
            .listeners
            .lock()
            .expect("listeners lock")
            .keys()
            .map(|p| alpn(&self.config.alpn_prefix, p))
            .collect();
        alpns.push(generic_alpn(&self.config.alpn_prefix));
        self.endpoint.set_alpns(alpns);
    }

    fn track(self: &Arc<Self>, peer: PublicKey, conn: &Connection) {
        let id = conn.stable_id();
        self.live
            .lock()
            .expect("live lock")
            .insert(id, (peer, conn.clone()));
        let weak = Arc::downgrade(self);
        let watch = conn.weak_handle();
        tokio::spawn(async move {
            let _ = watch.closed().await;
            if let Some(inner) = weak.upgrade() {
                inner.live.lock().expect("live lock").remove(&id);
            }
        });
    }

    fn address(&self, peer: &PublicKey) -> Result<EndpointAddr, LinkError> {
        let mut addr = EndpointAddr::new(to_iroh(peer)?);
        if let Some(hint) = self.hints.lock().expect("hints lock").get(peer) {
            for a in &hint.direct {
                addr = addr.with_ip_addr(*a);
            }
            if let Some(relay) = &hint.relay {
                addr = addr.with_relay_url(config::relay_url(relay)?);
            }
        }
        Ok(addr)
    }

    async fn connect(
        self: &Arc<Self>,
        peer: &PublicKey,
        protocol: &Protocol,
        deadline: tokio::time::Instant,
    ) -> Result<Connection, LinkError> {
        let addr = self.address(peer)?;
        let alpn = alpn(&self.config.alpn_prefix, protocol);
        let opts = ConnectOptions::new()
            .with_additional_alpns(vec![generic_alpn(&self.config.alpn_prefix)]);
        let fut = async {
            let connecting = self
                .endpoint
                .connect_with_opts(addr, &alpn, opts)
                .await
                .map_err(|e| self.map_connect(e))?;
            connecting.await.map_err(|e| self.map_connecting(e))
        };
        let conn = tokio::time::timeout_at(deadline, fut)
            .await
            .map_err(|_| LinkError::Unreachable)??;
        self.track(*peer, &conn);
        Ok(conn)
    }

    fn map_connect(&self, e: ConnectWithOptsError) -> LinkError {
        if self.closed.load(Ordering::SeqCst) {
            return LinkError::Closed;
        }
        match e {
            ConnectWithOptsError::NoAddress { .. } => LinkError::Unreachable,
            ConnectWithOptsError::EndpointClosed { .. } => LinkError::Closed,
            ConnectWithOptsError::LocallyRejected { .. } => LinkError::Untrusted,
            other => LinkError::backend(other),
        }
    }

    fn map_connecting(&self, e: ConnectingError) -> LinkError {
        if self.closed.load(Ordering::SeqCst) {
            return LinkError::Closed;
        }
        match e {
            ConnectingError::ConnectionError { source, .. } => map_connection(&source),
            ConnectingError::LocallyRejected { .. } => LinkError::Rejected,
            other => LinkError::backend(other),
        }
    }

    async fn handshake(
        &self,
        conn: &Connection,
        protocol: &Protocol,
        deadline: tokio::time::Instant,
    ) -> Result<(SendStream, RecvStream), LinkError> {
        let fut = async {
            let (mut send, mut recv) = conn.open_bi().await.map_err(|e| map_connection(&e))?;
            send.write_all(&hello(protocol)).await.map_err(map_write)?;
            let mut ack = [0u8; 1];
            recv.read_exact(&mut ack).await.map_err(map_read_exact)?;
            match ack[0] {
                ACCEPT => Ok((send, recv)),
                _ => Err(LinkError::Rejected),
            }
        };
        tokio::time::timeout_at(deadline, fut)
            .await
            .map_err(|_| LinkError::Unreachable)?
    }
}

fn hello(protocol: &Protocol) -> Vec<u8> {
    let name = protocol.as_str().as_bytes();
    let mut v = Vec::with_capacity(2 + name.len());
    v.push(HELLO);
    v.push(name.len() as u8);
    v.extend_from_slice(name);
    v
}

async fn read_hello(recv: &mut RecvStream) -> Option<Protocol> {
    let mut head = [0u8; 2];
    recv.read_exact(&mut head).await.ok()?;
    if head[0] != HELLO || head[1] as usize > baton_link::MAX_PROTOCOL_LEN {
        return None;
    }
    let mut name = vec![0u8; head[1] as usize];
    recv.read_exact(&mut name).await.ok()?;
    Protocol::new(std::str::from_utf8(&name).ok()?).ok()
}

fn map_connection(e: &ConnectionError) -> LinkError {
    match e {
        ConnectionError::ApplicationClosed(c)
            if c.error_code == VarInt::from_u32(CODE_UNTRUSTED)
                || c.error_code == VarInt::from_u32(CODE_PQ)
                || c.error_code == VarInt::from_u32(CODE_REVOKED) =>
        {
            LinkError::Rejected
        }
        ConnectionError::ConnectionClosed(c)
            if c.error_code == iroh::endpoint::TransportErrorCode::crypto(120) =>
        {
            LinkError::Rejected
        }
        ConnectionError::LocallyClosed => LinkError::Closed,
        _ => LinkError::Unreachable,
    }
}

fn map_write(e: iroh::endpoint::WriteError) -> LinkError {
    match e {
        iroh::endpoint::WriteError::ConnectionLost(c) => map_connection(&c),
        _ => LinkError::Rejected,
    }
}

fn map_read_exact(e: iroh::endpoint::ReadExactError) -> LinkError {
    match e {
        iroh::endpoint::ReadExactError::ReadError(iroh::endpoint::ReadError::ConnectionLost(c)) => {
            map_connection(&c)
        }
        _ => LinkError::Rejected,
    }
}

fn is_stale(e: &LinkError) -> bool {
    matches!(e, LinkError::Unreachable | LinkError::Closed)
}

async fn accept_loop(weak: std::sync::Weak<Inner>, endpoint: Endpoint) {
    while let Some(incoming) = endpoint.accept().await {
        let weak = weak.clone();
        tokio::spawn(async move {
            let Ok(accepting) = incoming.accept() else {
                return;
            };
            let Ok(conn) = accepting.await else {
                return;
            };
            let Some(inner) = weak.upgrade() else {
                return;
            };
            let Ok(peer) = to_baton(&conn.remote_id()) else {
                conn.close(VarInt::from_u32(CODE_UNTRUSTED), b"untrusted");
                return;
            };
            let prefix = &inner.config.alpn_prefix;
            let pinned = match conn.alpn() {
                a if a == generic_alpn(prefix).as_slice() => None,
                a => match protocol_of(prefix, a) {
                    Some(p) => Some(p),
                    None => {
                        conn.close(VarInt::from_u32(CODE_UNTRUSTED), b"protocol");
                        return;
                    }
                },
            };
            inner.track(peer, &conn);
            drop(inner);
            while let Ok((send, recv)) = conn.accept_bi().await {
                let weak = weak.clone();
                let pinned = pinned.clone();
                tokio::spawn(async move {
                    serve_stream(weak, peer, pinned, send, recv).await;
                });
            }
        });
    }
}

async fn serve_stream(
    weak: std::sync::Weak<Inner>,
    peer: PublicKey,
    pinned: Option<Protocol>,
    mut send: SendStream,
    mut recv: RecvStream,
) {
    let Some(inner) = weak.upgrade() else { return };
    let read = tokio::time::timeout(inner.config.open_timeout, read_hello(&mut recv)).await;
    let protocol = match read {
        Ok(Some(p)) if pinned.as_ref().is_none_or(|q| *q == p) => p,
        _ => {
            let _ = send.reset(VarInt::from_u32(CODE_UNTRUSTED));
            return;
        }
    };
    let tx = if inner.closed.load(Ordering::SeqCst) || !inner.trust.allows_on(&peer, &protocol) {
        None
    } else {
        inner
            .listeners
            .lock()
            .expect("listeners lock")
            .get(&protocol)
            .map(|(_, tx)| tx.clone())
    };
    let Some(tx) = tx else {
        let _ = send.write_all(&[REFUSE]).await;
        let _ = send.finish();
        return;
    };
    if send.write_all(&[ACCEPT]).await.is_err() {
        return;
    }
    let _ = tx.send(Incoming {
        peer,
        stream: Box::new(tokio::io::join(recv, send)),
    });
}

struct Listener {
    rx: mpsc::UnboundedReceiver<Incoming>,
    inner: std::sync::Weak<Inner>,
    protocol: Protocol,
    id: u64,
}

impl Stream for Listener {
    type Item = Incoming;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Incoming>> {
        self.rx.poll_recv(cx)
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        let removed = {
            let mut listeners = inner.listeners.lock().expect("listeners lock");
            if listeners
                .get(&self.protocol)
                .is_some_and(|(id, _)| *id == self.id)
            {
                listeners.remove(&self.protocol);
                true
            } else {
                false
            }
        };
        if removed && !inner.closed.load(Ordering::SeqCst) {
            inner.update_alpns();
        }
    }
}

#[async_trait]
impl Link for IrohLink {
    fn local(&self) -> PublicKey {
        self.inner.key
    }

    async fn open(
        &self,
        peer: &PublicKey,
        protocol: &Protocol,
    ) -> Result<Box<dyn Duplex>, LinkError> {
        let inner = &self.inner;
        inner.ensure_open()?;
        if !inner.trust.allows_on(peer, protocol) {
            return Err(LinkError::Untrusted);
        }
        if *peer == inner.key {
            return Err(LinkError::Unreachable);
        }
        let deadline = tokio::time::Instant::now() + inner.config.open_timeout;
        let slot = inner
            .pool
            .lock()
            .expect("pool lock")
            .entry((*peer, protocol.clone()))
            .or_default()
            .clone();
        let pooled = tokio::time::timeout_at(deadline, slot.lock())
            .await
            .map_err(|_| LinkError::Unreachable)?
            .as_ref()
            .filter(|c| c.close_reason().is_none())
            .cloned();
        if let Some(conn) = &pooled {
            match inner.handshake(conn, protocol, deadline).await {
                Ok((send, recv)) => return Ok(Box::new(tokio::io::join(recv, send))),
                Err(e) if is_stale(&e) && !inner.closed.load(Ordering::SeqCst) => {}
                Err(e) => return Err(e),
            }
        }
        let conn = {
            let mut held = tokio::time::timeout_at(deadline, slot.lock())
                .await
                .map_err(|_| LinkError::Unreachable)?;
            match held.as_ref().filter(|c| {
                c.close_reason().is_none()
                    && pooled
                        .as_ref()
                        .is_none_or(|p| p.stable_id() != c.stable_id())
            }) {
                Some(fresh) => fresh.clone(),
                None => {
                    *held = None;
                    let conn = inner.connect(peer, protocol, deadline).await?;
                    *held = Some(conn.clone());
                    conn
                }
            }
        };
        inner.ensure_open()?;
        let (send, recv) = inner.handshake(&conn, protocol, deadline).await?;
        Ok(Box::new(tokio::io::join(recv, send)))
    }

    async fn listen(&self, protocol: &Protocol) -> Result<BoxStream<'static, Incoming>, LinkError> {
        let inner = &self.inner;
        inner.ensure_open()?;
        let id = inner.next_listener.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::unbounded_channel();
        {
            let mut listeners = inner.listeners.lock().expect("listeners lock");
            if listeners.contains_key(protocol) {
                return Err(LinkError::AlreadyListening);
            }
            listeners.insert(protocol.clone(), (id, tx));
        }
        let listener = Listener {
            rx,
            inner: Arc::downgrade(inner),
            protocol: protocol.clone(),
            id,
        };
        inner.ensure_open()?;
        inner.update_alpns();
        Ok(Box::pin(listener))
    }

    fn add_hint(&self, peer: &PublicKey, hint: PeerHint) -> Result<(), LinkError> {
        self.inner.ensure_open()?;
        if let Some(relay) = &hint.relay {
            config::relay_url(relay)?;
        }
        let mut hints = self.inner.hints.lock().expect("hints lock");
        let entry = hints.entry(*peer).or_default();
        for a in hint.direct {
            if !entry.direct.contains(&a) {
                entry.direct.push(a);
            }
        }
        if hint.relay.is_some() {
            entry.relay = hint.relay;
        }
        Ok(())
    }

    async fn disconnect_untrusted(&self) -> Result<usize, LinkError> {
        let inner = &self.inner;
        inner.ensure_open()?;
        let doomed: Vec<(PublicKey, Connection)> = inner
            .live
            .lock()
            .expect("live lock")
            .values()
            .filter(|(peer, _)| !inner.trust.reachable(peer))
            .cloned()
            .collect();
        let mut peers = HashSet::new();
        for (peer, conn) in doomed {
            if conn.close_reason().is_none() {
                peers.insert(peer);
            }
            conn.close(VarInt::from_u32(CODE_REVOKED), b"revoked");
            inner
                .live
                .lock()
                .expect("live lock")
                .remove(&conn.stable_id());
        }
        inner
            .pool
            .lock()
            .expect("pool lock")
            .retain(|(peer, protocol), _| inner.trust.allows_on(peer, protocol));
        Ok(peers.len())
    }

    async fn close(&self) {
        let inner = &self.inner;
        if inner.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        inner.listeners.lock().expect("listeners lock").clear();
        let live: Vec<Connection> = inner
            .live
            .lock()
            .expect("live lock")
            .drain()
            .map(|(_, (_, c))| c)
            .collect();
        for conn in live {
            conn.close(VarInt::from_u32(CODE_CLOSED), b"closed");
        }
        inner.pool.lock().expect("pool lock").clear();
        self.accept.abort();
        inner.endpoint.close().await;
    }
}

#[cfg(test)]
mod tests;
