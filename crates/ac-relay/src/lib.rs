//! # ac-relay
//!
//! The bag reference relay: a dumb, interchangeable store-and-forward mailbox host with exactly three
//! calls, publish, subscribe and fetch, and the optional pairing rendezvous
//! (src/pair.rs), on one port: HTTP for publish,
//! fetch and health, a WebSocket for subscribe. It verifies the outer envelope and the authority chain with
//! [`ac_core`], enforces each mailbox owner's accept-from record and per-sender rate limits, stores each envelope
//! once in SQLite, and pushes it to live subscribers. It never opens the sealed part and never evaluates a
//! caveat.
//!
//! The binary `ac-relay` (src/main.rs) wires a [`store::sqlite::SqliteStore`], the system clock and the
//! command-line settings into [`run`]. Tests use [`store::memory::MemoryStore`] and [`clock::ManualClock`].
#![forbid(unsafe_code)]

pub mod abuse;
pub mod auth;
pub mod clock;
pub mod config;
pub mod dns;
pub mod http;
pub mod metrics;
pub mod net;
pub mod pair;
pub mod policy;
pub mod probe;
pub mod ratelimit;
pub mod relay;
pub mod resolver;
pub mod server;
pub mod store;
pub mod sweeper;
pub mod ws;

pub use config::Config;
pub use relay::{Published, Rejection, Relay};

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};

/// How long shutdown waits for subscribers to be closed.
const DRAIN: Duration = Duration::from_secs(5);

/// Serves the relay on `listener` until `shutdown` resolves, with the sweeper running beside it. Each connection
/// is counted against its client address and has the header timeout of `relay.config` ([`server`]). On shutdown it
/// stops accepting, finishes the HTTP requests in flight, closes every subscriber with 1001 and stops the
/// sweeper, then returns.
///
/// # Errors
///
/// An I/O error from the listener.
pub async fn run<F>(listener: TcpListener, relay: Arc<Relay>, shutdown: F) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    run_with_metrics(listener, None, relay, shutdown).await
}

/// [`run`], and with `metrics` the metrics listener ([`metrics::router`]) beside it, with the same connection limits,
/// until the same shutdown.
///
/// # Errors
///
/// An I/O error from the relay's listener.
pub async fn run_with_metrics<F>(
    listener: TcpListener,
    metrics: Option<TcpListener>,
    relay: Arc<Relay>,
    shutdown: F,
) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let (stop_tx, stop_rx) = watch::channel(false);
    let (tracker, mut drained) = mpsc::channel::<()>(1);
    metrics::METRICS.started(relay.now());
    metrics::METRICS.limits(&relay.config);
    let sweeper = tokio::spawn(sweeper::run(Arc::clone(&relay), stop_rx.clone()));
    let limits = server::Limits {
        header_timeout: relay.config.header_timeout,
        connections_per_ip: relay.config.connections_per_ip,
        subscriptions_per_ip: relay.config.subscriptions_per_ip(),
        front: relay.config.front.clone(),
        metered: true,
    };
    let metrics = metrics.map(|listener| {
        let mut stop = stop_rx.clone();
        let stopped = async move {
            let _ = stop.wait_for(|stop| *stop).await;
        };
        let unmetered = server::Limits { metered: false, ..limits.clone() };
        tokio::spawn(server::serve(listener, metrics::router(Arc::clone(&relay)), unmetered, stopped))
    });
    let app = http::router(http::AppState { relay, stop: stop_rx, tracker });
    let served = server::serve(listener, app, limits, async move {
        shutdown.await;
        let _ = stop_tx.send(true);
    })
    .await;
    // Every subscriber task holds a tracker clone; recv() returns None once the last one is dropped.
    let _ = tokio::time::timeout(DRAIN, drained.recv()).await;
    let _ = sweeper.await;
    if let Some(metrics) = metrics {
        let _ = metrics.await;
    }
    served
}

#[cfg(test)]
pub(crate) mod testkit;
