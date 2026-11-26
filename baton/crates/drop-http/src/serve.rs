use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::{Pin, pin};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::{GracefulShutdown, Watcher};
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tower::{Service, ServiceExt};
use tracing::debug;

use crate::{ClientIp, HttpConfig, limit};

/// IO whose writes fail once they have made no progress for `timeout`: a client that never reads
/// its reply loses its connection instead of holding it and the reply forever.
struct WriteDeadline<I> {
    io: I,
    timeout: Duration,
    stall: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<I> WriteDeadline<I> {
    fn new(io: I, timeout: Duration) -> Self {
        Self {
            io,
            timeout,
            stall: None,
        }
    }

    fn watch<T>(&mut self, cx: &mut Context<'_>, r: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        if r.is_ready() {
            self.stall = None;
            return r;
        }
        let timeout = self.timeout;
        let stall = self
            .stall
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(timeout)));
        match stall.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(io::ErrorKind::TimedOut.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for WriteDeadline<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for WriteDeadline<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.io).poll_write(cx, buf);
        self.watch(cx, r)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.io).poll_write_vectored(cx, bufs);
        self.watch(cx, r)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let r = Pin::new(&mut self.io).poll_flush(cx);
        self.watch(cx, r)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let r = Pin::new(&mut self.io).poll_shutdown(cx);
        self.watch(cx, r)
    }
}

/// One connection counted against its client; uncounted when dropped.
struct ClientSlot {
    open: Arc<Mutex<HashMap<u128, usize>>>,
    key: u128,
}

impl ClientSlot {
    fn take(open: &Arc<Mutex<HashMap<u128, usize>>>, key: u128, max: usize) -> Option<Self> {
        let mut m = open.lock().expect("per-client lock");
        let n = m.entry(key).or_insert(0);
        if *n >= max.max(1) {
            return None;
        }
        *n += 1;
        Some(Self {
            open: open.clone(),
            key,
        })
    }
}

impl Drop for ClientSlot {
    fn drop(&mut self) {
        let mut m = self.open.lock().expect("per-client lock");
        if let Some(n) = m.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.key);
            }
        }
    }
}

/// Serves `router` (from [`router`](crate::router)) on `listener` over HTTP/1.1, with TLS when
/// `tls` is given, until `shutdown` completes; then stops accepting, lets requests in flight finish
/// for up to [`HttpConfig::shutdown_grace`] and returns.
///
/// A client that sends its headers (or completes its TLS handshake) slower than
/// [`HttpConfig::header_timeout`] is disconnected without holding up anyone else, a connection
/// whose reply makes no progress for [`HttpConfig::write_timeout`] is closed, at most
/// [`HttpConfig::max_connections`] connections are served at once and, with [`ClientIp::Peer`],
/// at most [`HttpConfig::max_connections_per_client`] from one client. Accept errors are retried,
/// never returned. Logs carry no addresses.
pub async fn serve(
    listener: TcpListener,
    router: Router,
    config: &HttpConfig,
    tls: Option<Arc<rustls::ServerConfig>>,
    shutdown: impl Future<Output = ()> + Send,
) {
    let mut make = router.into_make_service_with_connect_info::<SocketAddr>();
    let permits = Arc::new(Semaphore::new(config.max_connections.max(1)));
    let graceful = GracefulShutdown::new();
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(config.header_timeout)
        .keep_alive(true);
    let builder = Arc::new(builder);
    let acceptor = tls.map(TlsAcceptor::from);
    let handshake_timeout = config.header_timeout;
    let write_timeout = config.write_timeout;
    let per_client =
        (config.client_ip == ClientIp::Peer).then_some(config.max_connections_per_client);
    let open: Arc<Mutex<HashMap<u128, usize>>> = Arc::default();
    let mut shutdown = pin!(shutdown);
    loop {
        let permit = tokio::select! {
            permit = permits.clone().acquire_owned() => permit.expect("never closed"),
            () = &mut shutdown => break,
        };
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(e) => {
                    debug!(error = %e.kind(), "accepting a connection failed");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        let client = match per_client {
            None => None,
            Some(max) => match ClientSlot::take(&open, limit::client_key(peer.ip()), max) {
                Some(slot) => Some(slot),
                None => continue,
            },
        };
        let _ = stream.set_nodelay(true);
        let stream = WriteDeadline::new(stream, write_timeout);
        let Ok(service) = make.call(peer).await;
        let service = service.map_request(|r: Request<hyper::body::Incoming>| r.map(Body::new));
        let service = TowerToHyperService::new(service);
        let (builder, watcher, acceptor) = (builder.clone(), graceful.watcher(), acceptor.clone());
        tokio::spawn(async move {
            match acceptor {
                None => connection(&builder, watcher, stream, service).await,
                Some(a) => {
                    if let Ok(Ok(tls)) =
                        tokio::time::timeout(handshake_timeout, a.accept(stream)).await
                    {
                        connection(&builder, watcher, tls, service).await;
                    }
                }
            }
            drop(client);
            drop(permit);
        });
    }
    drop(listener);
    if tokio::time::timeout(config.shutdown_grace, graceful.shutdown())
        .await
        .is_err()
    {
        debug!("connections still open after the shutdown grace period");
    }
}

async fn connection<I, S>(builder: &http1::Builder, watcher: Watcher, io: I, service: S)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: hyper::service::Service<
            Request<hyper::body::Incoming>,
            Response = axum::response::Response,
            Error = std::convert::Infallible,
        > + Send
        + 'static,
    S::Future: Send + 'static,
{
    let conn = builder.serve_connection(TokioIo::new(io), service);
    if let Err(e) = watcher.watch(conn).await {
        debug!(timeout = e.is_timeout(), "connection ended with an error");
    }
}
