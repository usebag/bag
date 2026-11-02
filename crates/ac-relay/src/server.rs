//! The relay's connections: each accepted TCP connection
//! is counted against its client address and closed at once over the per-address cap, and is served by hyper with a
//! timer, so that hyper's header read timeout runs; a publish body is timed out by its handler ([`crate::http`]).
//!
//! `axum::serve` builds hyper's connection with no timer, and hyper then drops its own 30-s default header timeout, so
//! a client could once hold a connection forever by sending a request head one byte every few seconds. Here
//! hyper-util's builder gets [`TokioTimer`] and the relay's header timeout. hyper-util first reads up to 24 bytes to
//! tell an HTTP/2 preface from HTTP/1 and starts hyper's timer only after them, so until a connection's bytes stop
//! matching that preface (or there are 24 of them) [`Conn`] holds a deadline of its own, the same header timeout from
//! the accept: a connection that sends nothing, or drips the preface, is closed too. hyper starts its timer again for
//! a kept-alive connection's next request head, so a client that keeps a connection after its answer (a metrics
//! scraper, a proxy's pool) is closed at the header timeout too; that end is quiet, neither logged nor counted as a
//! timeout, unless bytes of another request came after the answer ([`timeout_reason`]).
//!
//! Shutdown, as `axum::serve` did it: the listener stops accepting, every connection is told to finish its request
//! in flight and close, and [`serve`] returns once each has. An upgraded connection (a subscriber's WebSocket) leaves
//! hyper at the upgrade; the subscriber's own task closes it (src/ws.rs) and keeps its place in the address's count
//! until then.
//! A trusted proxy's connection carries many clients, so it is not counted at accept; a WebSocket
//! through it takes its client's place ([`Admission`]), and over the cap is refused `rate-limited` after the upgrade:
//! a proxy answers for a relay that closed with no answer, so its client read a healthy relay as unreachable.

use crate::metrics::{CONNECTIONS_ACCEPTED, CONNECTIONS_OPEN, CONNECTIONS_REFUSED, METRICS};
use crate::net::{Front, LogIp, bucket, client_ip};
use axum::extract::ConnectInfo;
use axum::{Extension, Router};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use std::collections::HashMap;
use std::error::Error;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::time::Sleep;

/// The HTTP/2 connection preface, which hyper-util reads before it hands a connection to hyper's HTTP/1.
const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Where a connection stands after its answers ([`Conn`]'s `answer`): none written yet; one written and nothing heard
/// since, a kept-alive connection between requests; or one written and bytes of another request heard since.
const FRESH: u8 = 0;
const IDLE: u8 = 1;
const HEARD: u8 = 2;

/// How the relay accepts connections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// The longest a client may take to send a request head; on a new connection also its first bytes.
    pub header_timeout: Duration,
    /// The most connections one client address may hold open at once.
    pub connections_per_ip: usize,
    /// The most of them a direct client's subscriptions may hold.
    pub subscriptions_per_ip: usize,
    /// The trusted proxies, not counted at accept, and the log mode.
    pub front: Front,
    /// Whether its connections are metered ([`CONNECTIONS_ACCEPTED`], [`CONNECTIONS_OPEN`]): the relay's port's are,
    /// the metrics port's are not.
    pub metered: bool,
}

/// The open connections of each client address.
#[derive(Debug, Default)]
struct Counts(Mutex<HashMap<IpAddr, usize>>);

impl Counts {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, usize>> {
        // Every update completes under the lock, so a panic elsewhere leaves usable counts.
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A place for one more connection of `ip`, or `None` when it holds `cap` already.
    fn take(self: &Arc<Counts>, ip: IpAddr, cap: usize) -> Option<Slot> {
        let mut counts = self.lock();
        let open = counts.entry(ip).or_default();
        if *open >= cap {
            return None;
        }
        *open += 1;
        Some(Slot { counts: Arc::clone(self), ip })
    }

    /// The connections of `ip` open now (its bucket), 0 when it holds none: a released last place removes the
    /// entry. A snapshot: another connection of the address may take or free a place the next instant.
    fn held(&self, ip: IpAddr) -> usize {
        self.lock().get(&ip).copied().unwrap_or(0)
    }
}

/// One open connection of `ip`; dropping it frees its place.
#[derive(Debug)]
pub(crate) struct Slot {
    counts: Arc<Counts>,
    ip: IpAddr,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut counts = self.counts.lock();
        let open = counts.entry(self.ip).or_default();
        *open = open.saturating_sub(1);
        if *open == 0 {
            counts.remove(&self.ip);
        }
    }
}

/// The deadline of a new connection's first bytes, while they could still be the HTTP/2 preface.
#[derive(Debug)]
struct Preface {
    deadline: Pin<Box<Sleep>>,
    seen: usize,
}

/// An accepted connection: its stream, its place in its address's count (none for a trusted proxy), whether it is
/// in [`CONNECTIONS_OPEN`] until dropped (with its WebSocket), the deadline of its first bytes and whether it fired,
/// and where it stands after its answers ([`IDLE`]).
#[derive(Debug)]
struct Conn {
    stream: TcpStream,
    preface: Option<Preface>,
    _slot: Option<Slot>,
    metered: bool,
    timed_out: Arc<AtomicBool>,
    answer: Arc<AtomicU8>,
}

impl Conn {
    /// `polled`, a write: bytes written are an answer, after which the connection is idle until it hears more.
    fn wrote(&self, polled: Poll<io::Result<usize>>) -> Poll<io::Result<usize>> {
        if matches!(polled, Poll::Ready(Ok(n)) if n > 0) {
            self.answer.store(IDLE, Ordering::Relaxed);
        }
        polled
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        if self.metered {
            METRICS.shift(CONNECTIONS_OPEN, -1);
        }
    }
}

/// What a handler needs to count a WebSocket under its client behind a trusted proxy.
#[derive(Debug, Clone)]
pub(crate) struct Admission {
    counts: Arc<Counts>,
    cap: usize,
    subscribers: Arc<Counts>,
    subscription_limit: usize,
    log_ip: LogIp,
}

impl Admission {
    /// The connections of `client`'s bucket open now, as [`Counts`] holds them; a point-in-time snapshot.
    pub(crate) fn held(&self, client: IpAddr) -> usize {
        self.counts.held(bucket(client))
    }

    /// A place for one more WebSocket of `client` through a trusted proxy; over the cap none, and the upgrade is refused
    /// `rate-limited`.
    pub(crate) fn take(&self, client: IpAddr) -> Option<Slot> {
        let slot = self.counts.take(bucket(client), self.cap);
        if slot.is_none() {
            let ip = self.log_ip.show(client);
            tracing::info!(event = "connection-refused", ip = %ip, open = self.cap, reason = "connections-per-ip");
            METRICS.count(CONNECTIONS_REFUSED, "reason", "connections-per-ip");
        }
        slot
    }

    /// A place for one more subscription of a direct `client`, whose connection holds its place already: a limit below
    /// the cap leaves the rest to its calls (ruling 8). Over it none, and the upgrade is refused `rate-limited`.
    pub(crate) fn subscription(&self, client: IpAddr) -> Option<Slot> {
        let (limit, slot) =
            (self.subscription_limit, self.subscribers.take(bucket(client), self.subscription_limit));
        if slot.is_none() {
            let ip = self.log_ip.show(client);
            tracing::info!(event = "connection-refused", ip = %ip, open = limit, reason = "subscriptions-per-ip");
            METRICS.count(CONNECTIONS_REFUSED, "reason", "subscriptions-per-ip");
        }
        slot
    }
}

impl AsyncRead for Conn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.stream).poll_read(cx, buf);
        if matches!(polled, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            // Bytes after an answer: another request has begun, so its header timeout is one.
            let _ = this.answer.compare_exchange(IDLE, HEARD, Ordering::Relaxed, Ordering::Relaxed);
        }
        let Some(preface) = this.preface.as_mut() else { return polled };
        match polled {
            Poll::Ready(Ok(())) => {
                let new = &buf.filled()[before..];
                let end = (preface.seen + new.len()).min(H2_PREFACE.len());
                let matching = !new.is_empty() && new[..end - preface.seen] == H2_PREFACE[preface.seen..end];
                preface.seen += new.len();
                if !matching || preface.seen >= H2_PREFACE.len() {
                    // hyper's own header timer runs from here.
                    this.preface = None;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending if preface.deadline.as_mut().poll(cx).is_ready() => {
                this.timed_out.store(true, Ordering::Relaxed);
                let e = io::Error::new(io::ErrorKind::TimedOut, "no request within the header timeout");
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for Conn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.stream).poll_write(cx, buf);
        this.wrote(polled)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.stream).poll_write_vectored(cx, bufs);
        this.wrote(polled)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
}

/// Serves `app` on `listener` until `shutdown` resolves, then finishes the requests in flight and returns once every
/// connection is closed. Each connection's handlers find the TCP peer as `ConnectInfo<SocketAddr>`.
///
/// # Errors
///
/// None so far: accept errors are logged and retried, as `axum::serve` did; the result keeps `run`'s shape.
pub async fn serve<F>(listener: TcpListener, app: Router, limits: Limits, shutdown: F) -> io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let counts = Arc::new(Counts::default());
    let subscribers = Arc::new(Counts::default());
    // The signal is a channel whose receiver is dropped at shutdown; every connection waits for it to close.
    let (signal_tx, signal_rx) = watch::channel(());
    tokio::spawn(async move {
        shutdown.await;
        drop(signal_rx);
    });
    // Every connection task holds a receiver; serve returns when the last one is dropped.
    let (close_tx, close_rx) = watch::channel(());
    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    accept_error(e).await;
                    continue;
                }
            },
            () = signal_tx.closed() => break,
        };
        let (ip, cap, log_ip) = (client_ip(peer), limits.connections_per_ip, limits.front.log_ip);
        let trusted = limits.front.trusts(ip);
        let slot = if trusted { None } else { counts.take(bucket(ip), cap) };
        if !trusted && slot.is_none() {
            tracing::info!(event = "connection-refused", ip = %log_ip.show(ip), open = cap, reason = "connections-per-ip");
            METRICS.count(CONNECTIONS_REFUSED, "reason", "connections-per-ip");
            drop(stream);
            continue;
        }
        let (timed_out, answer) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicU8::new(FRESH)));
        let accepted = Instant::now();
        let admission = Admission {
            counts: Arc::clone(&counts),
            cap,
            subscribers: Arc::clone(&subscribers),
            subscription_limit: limits.subscriptions_per_ip,
            log_ip,
        };
        let deadline = Box::pin(tokio::time::sleep(limits.header_timeout));
        let (preface, metered) = (Some(Preface { deadline, seen: 0 }), limits.metered);
        if metered {
            METRICS.tick(CONNECTIONS_ACCEPTED);
            METRICS.shift(CONNECTIONS_OPEN, 1);
        }
        let io = TokioIo::new(Conn {
            stream,
            preface,
            _slot: slot,
            metered,
            timed_out: Arc::clone(&timed_out),
            answer: Arc::clone(&answer),
        });
        let routes =
            app.clone().layer(Extension(ConnectInfo::<SocketAddr>(peer))).layer(Extension(admission));
        let service = TowerToHyperService::new(routes);
        let header_timeout = limits.header_timeout;
        let signal_tx = signal_tx.clone();
        let close_rx = close_rx.clone();
        tokio::spawn(async move {
            let mut builder = Builder::new(TokioExecutor::new());
            builder.http1().timer(TokioTimer::new()).header_read_timeout(header_timeout);
            let mut conn = pin!(builder.serve_connection_with_upgrades(io, service));
            let mut signalled = pin!(signal_tx.closed());
            let mut shutting = false;
            loop {
                tokio::select! {
                    // A connection's own failure (a header timeout, a reset) only ends it; a timeout is logged, and an
                    // idle kept-alive connection's end is not one.
                    ended = conn.as_mut() => {
                        let idle = answer.load(Ordering::Relaxed) == IDLE;
                        let reason = timeout_reason(timed_out.load(Ordering::Relaxed), idle, &ended);
                        if let Some(reason) = reason {
                            let age_ms = u64::try_from(accepted.elapsed().as_millis()).unwrap_or(u64::MAX);
                            tracing::info!(event = "connection-timeout", ip = %log_ip.show(ip), reason, age_ms);
                            METRICS.count("ac_relay_connection_timeouts_total", "reason", reason);
                        }
                        break;
                    }
                    () = &mut signalled, if !shutting => {
                        shutting = true;
                        conn.as_mut().graceful_shutdown();
                    }
                }
            }
            drop(close_rx);
        });
    }
    drop(close_rx);
    drop(listener);
    close_tx.closed().await;
    Ok(())
}

/// Why a connection ended in a timeout, if it did: its first bytes missed the relay's own deadline (`timed_out`), or
/// hyper's header read timer fired. hyper starts that timer for every request head, a kept-alive connection's next
/// one included (hyper 1.12.0, src/proto/h1/conn.rs, `poll_read_head` and `idle`), so when it ends a connection that
/// is `idle`, answered and silent since, no request was waiting: that is no timeout. hyper-util boxes hyper's error
/// and ac-relay has no `hyper` dependency to downcast it, so the timer is told by its text (hyper 1.12.0, the locked
/// version; the unit test fails if a bump changes it), in the error or a source of it. A reset, a clean end or any
/// other error is no timeout.
fn timeout_reason(
    timed_out: bool,
    idle: bool,
    ended: &Result<(), Box<dyn Error + Send + Sync>>,
) -> Option<&'static str> {
    if timed_out {
        return Some("first-bytes");
    }
    let mut cause = ended.as_ref().err().map(|e| &**e as &(dyn Error + 'static));
    while let Some(e) = cause {
        if e.to_string().contains("read header from client timeout") {
            return (!idle).then_some("header-timeout");
        }
        cause = e.source();
    }
    None
}

/// An accept error: a connection error is the client's and is skipped; any other (too many open files, say) is
/// logged and waited out for a second, as `axum::serve` does.
async fn accept_error(e: io::Error) {
    if matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionReset
    ) {
        return;
    }
    tracing::error!(event = "accept-error", error = %e);
    tokio::time::sleep(Duration::from_secs(1)).await;
}

#[cfg(test)]
mod tests;
