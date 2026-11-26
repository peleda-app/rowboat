use std::future::Future;
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tower::{Service, ServiceExt};
use tracing::{debug, warn};

/// How long a client may take to send a request's headers, on a new connection or between
/// requests on a kept-alive one, before the connection is closed.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Connections served at once; further ones wait in the listen backlog until one closes.
pub const MAX_CONNECTIONS: usize = 4096;

/// Serves `router` on `listener` over HTTP/1.1 and HTTP/2 with the peer address as
/// `ConnectInfo<SocketAddr>`, until `shutdown` completes; then stops accepting, lets requests in
/// flight finish and returns. Unlike `axum::serve`, a client that sends its headers slower than
/// [`HEADER_READ_TIMEOUT`] is disconnected, and at most [`MAX_CONNECTIONS`] connections are
/// served at once. Accept errors are logged and retried, never returned.
pub async fn serve(
    listener: TcpListener,
    router: Router,
    shutdown: impl Future<Output = ()> + Send,
) {
    serve_with(
        listener,
        router,
        shutdown,
        HEADER_READ_TIMEOUT,
        MAX_CONNECTIONS,
    )
    .await;
}

pub(crate) async fn serve_with(
    listener: TcpListener,
    router: Router,
    shutdown: impl Future<Output = ()> + Send,
    header_timeout: Duration,
    max_connections: usize,
) {
    let mut make = router.into_make_service_with_connect_info::<SocketAddr>();
    let permits = Arc::new(Semaphore::new(max_connections));
    let graceful = GracefulShutdown::new();
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(header_timeout);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(Some(Duration::from_secs(60)))
        .keep_alive_timeout(Duration::from_secs(20));
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
                    debug!(error = %e, "accepting a connection failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        let Ok(service) = make.call(peer).await;
        let service = service.map_request(|r: Request<hyper::body::Incoming>| r.map(Body::new));
        let service = TowerToHyperService::new(service);
        let connection = builder.serve_connection_with_upgrades(TokioIo::new(stream), service);
        let connection = graceful.watch(connection.into_owned());
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                debug!(error = %e, "connection ended with an error");
            }
            drop(permit);
        });
    }
    drop(listener);
    if tokio::time::timeout(Duration::from_secs(30), graceful.shutdown())
        .await
        .is_err()
    {
        warn!("connections still open after 30 seconds of shutdown");
    }
}
