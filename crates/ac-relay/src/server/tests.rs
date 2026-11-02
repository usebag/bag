use super::{Conn, Counts, FRESH, H2_PREFACE, HEARD, IDLE, Limits, Preface, accept_error, serve};
use crate::net::{Front, LogIp};
use crate::testkit::counted;
use axum::Router;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt as _, AsyncWrite as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

const IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const OTHER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

#[test]
fn each_address_holds_at_most_its_cap_and_a_closed_connection_frees_its_place() {
    let counts = Arc::new(Counts::default());
    let first = counts.take(IP, 2).unwrap();
    let second = counts.take(IP, 2).unwrap();
    assert!(counts.take(IP, 2).is_none(), "the third of a cap of 2");
    assert!(counts.take(OTHER, 2).is_some(), "another address has its own");
    drop(first);
    let third = counts.take(IP, 2).unwrap();
    drop((second, third));
    assert!(!counts.lock().contains_key(&IP), "an address with no connection leaves no entry");
}

/// A connection pair on loopback: the accepted side wrapped in a [`Conn`] with a deadline of `ms`, and the client.
async fn pair(ms: u64) -> (Conn, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
    let (stream, _) = listener.accept().await.unwrap();
    let slot = Arc::new(Counts::default()).take(IP, 1).unwrap();
    let deadline = Box::pin(tokio::time::sleep(Duration::from_millis(ms)));
    let timed_out = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let preface = Some(Preface { deadline, seen: 0 });
    let answer = Arc::new(AtomicU8::new(FRESH));
    (Conn { stream, preface, _slot: Some(slot), metered: false, timed_out, answer }, client)
}

#[tokio::test]
async fn an_answer_leaves_a_connection_idle_until_it_hears_more() {
    let (mut conn, mut client) = pair(1_000).await;
    let at = |conn: &Conn| conn.answer.load(Ordering::Relaxed);
    let mut buf = [0u8; 64];
    assert_eq!(conn.write(b"").await.unwrap(), 0);
    assert_eq!(at(&conn), FRESH, "writing nothing is no answer");
    client.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
    assert!(conn.read(&mut buf).await.unwrap() > 0);
    assert_eq!(at(&conn), FRESH, "a request heard before any answer");
    conn.write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n").await.unwrap();
    assert_eq!(at(&conn), IDLE, "answered and silent since: kept alive");
    client.write_all(b"GET").await.unwrap();
    assert_eq!(conn.read(&mut buf).await.unwrap(), 3);
    assert_eq!(at(&conn), HEARD, "the next request has begun");
    conn.write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n").await.unwrap();
    assert_eq!(at(&conn), IDLE, "answered again");
}

#[tokio::test]
async fn a_connection_that_sends_nothing_is_refused_at_its_deadline() {
    let (mut conn, _client) = pair(100).await;
    let started = Instant::now();
    let mut buf = [0u8; 64];
    let e = conn.read(&mut buf).await.unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::TimedOut);
    assert!(started.elapsed() >= Duration::from_millis(90), "{:?}", started.elapsed());
}

#[tokio::test]
async fn http1_bytes_end_the_deadline_at_once() {
    let (mut conn, mut client) = pair(100).await;
    client.write_all(b"POST /v0/publish HTTP/1.1\r\n").await.unwrap();
    let mut buf = [0u8; 64];
    assert!(conn.read(&mut buf).await.unwrap() > 0);
    assert!(conn.preface.is_none(), "not the preface: hyper's own timer takes over");
    // Past the deadline, reads wait as long as the client does.
    tokio::time::sleep(Duration::from_millis(150)).await;
    client.write_all(b"x").await.unwrap();
    assert_eq!(conn.read(&mut buf).await.unwrap(), 1);
}

#[tokio::test]
async fn a_dripped_preface_keeps_the_deadline_and_a_whole_one_ends_it() {
    let (mut conn, mut client) = pair(200).await;
    let mut buf = [0u8; 64];
    client.write_all(&H2_PREFACE[..3]).await.unwrap();
    assert_eq!(conn.read(&mut buf).await.unwrap(), 3);
    assert_eq!(conn.preface.as_ref().map(|p| p.seen), Some(3), "still the preface");
    // The rest of it: the deadline ends, the bytes go on.
    client.write_all(&H2_PREFACE[3..]).await.unwrap();
    let mut got = 0;
    while got < H2_PREFACE.len() - 3 {
        got += conn.read(&mut buf).await.unwrap();
    }
    assert!(conn.preface.is_none());
    // A drip that stops is closed at the deadline.
    let (mut slow, mut client) = pair(100).await;
    client.write_all(b"PRI").await.unwrap();
    assert_eq!(slow.read(&mut buf).await.unwrap(), 3);
    assert_eq!(slow.read(&mut buf).await.unwrap_err().kind(), io::ErrorKind::TimedOut);
    // A client that closes at once ends the deadline with the end of the stream.
    let (mut gone, client) = pair(100).await;
    drop(client);
    assert_eq!(gone.read(&mut buf).await.unwrap(), 0);
    assert!(gone.preface.is_none());
}

#[tokio::test]
async fn writes_go_through() {
    let (mut conn, mut client) = pair(1_000).await;
    conn.write_all(b"hello").await.unwrap();
    let parts = [io::IoSlice::new(b" wor"), io::IoSlice::new(b"ld")];
    let mut sent = 0;
    while sent < 6 {
        sent += conn.write_vectored(&parts).await.unwrap();
        if sent < 6 {
            conn.write_all(&b" world"[sent..]).await.unwrap();
            sent = 6;
        }
    }
    let _ = conn.is_write_vectored();
    conn.flush().await.unwrap();
    conn.shutdown().await.unwrap();
    let mut text = String::new();
    client.read_to_string(&mut text).await.unwrap();
    assert_eq!(text, "hello world");
}

#[tokio::test]
async fn an_accept_error_of_the_client_is_skipped_and_any_other_waited_out() {
    let started = Instant::now();
    for kind in
        [io::ErrorKind::ConnectionReset, io::ErrorKind::ConnectionAborted, io::ErrorKind::ConnectionRefused]
    {
        accept_error(io::Error::from(kind)).await;
    }
    assert!(started.elapsed() < Duration::from_millis(500));
    accept_error(io::Error::other("too many open files")).await;
    assert!(started.elapsed() >= Duration::from_secs(1));
}

#[tokio::test]
async fn a_reset_before_the_first_bytes_is_the_read_s_error() {
    let (mut conn, client) = pair(1_000).await;
    client.set_zero_linger().unwrap();
    drop(client);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut buf = [0u8; 16];
    // A reset reads as an error here; a system that reads it as the end of the stream is answered the same way.
    let got = conn.read(&mut buf).await;
    assert!(matches!(got, Err(_) | Ok(0)), "{got:?}");
}

/// A log sink the test reads back.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Serves one connection with the real [`serve`] (header timeout `ms`, `--log-ip full`), lets the client send `heads`,
/// each after the first once the answer before it has begun to arrive, and then, with `reset`, reset the connection
/// at once or, otherwise, wait to be closed; shuts the relay down once the connection is gone and returns the `fields`
/// of every line the relay logged meanwhile. The current-thread test runtime keeps the connection task on the thread
/// that holds the subscriber.
async fn logged_after(ms: u64, heads: &[&[u8]], reset: bool) -> Vec<serde_json::Value> {
    let captured = Captured::default();
    let sink = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::INFO)
        .with_writer(move || sink.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let limits = Limits {
        header_timeout: Duration::from_millis(ms),
        connections_per_ip: 8,
        subscriptions_per_ip: 4,
        front: Front { log_ip: LogIp::Full, ..Front::default() },
        metered: true,
    };
    let (stop, stopped) = oneshot::channel::<()>();
    let relay = tokio::spawn(serve(listener, Router::new(), limits, async move {
        let _ = stopped.await;
    }));
    let mut client = TcpStream::connect(addr).await.unwrap();
    for (i, head) in heads.iter().enumerate() {
        if i > 0 {
            let mut answer = [0u8; 12];
            client.read_exact(&mut answer).await.unwrap();
            assert_eq!(&answer, b"HTTP/1.1 404", "the answer before head {i}");
        }
        client.write_all(head).await.unwrap();
    }
    if reset {
        client.set_zero_linger().unwrap();
        drop(client);
        // The relay reads the reset well inside the timeout; only then is it shut down.
        tokio::time::sleep(Duration::from_millis(ms / 3)).await;
    } else {
        let mut got = Vec::new();
        let ended = tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut got)).await;
        assert!(ended.is_ok(), "the relay closed the connection");
    }
    stop.send(()).unwrap();
    relay.await.unwrap().unwrap();
    let text = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    text.lines().map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["fields"].clone()).collect()
}

/// Hyper's header read timer ends a slow head, and the relay logs it as `header-timeout` with its age. The
/// text it is told by is hyper 1.12.0's: a bump that changes it fails here.
#[tokio::test]
async fn a_slow_head_is_logged_as_a_header_timeout() {
    let lines = logged_after(300, &[b"GET /v0/health HTTP/1.1\r\nHost: x\r\nX-Slow: "], false).await;
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["event"], "connection-timeout");
    assert_eq!(lines[0]["reason"], "header-timeout");
    assert_eq!(lines[0]["ip"], "127.0.0.1");
    assert!(lines[0]["age_ms"].as_u64().unwrap() >= 300, "{lines:?}");
}

/// A connection that sends nothing misses the relay's own deadline and is logged as `first-bytes`.
#[tokio::test]
async fn a_silent_connection_is_logged_as_a_first_bytes_timeout() {
    let lines = logged_after(300, &[b""], false).await;
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["event"], "connection-timeout");
    assert_eq!(lines[0]["reason"], "first-bytes");
    assert!(lines[0]["age_ms"].as_u64().unwrap() >= 300, "{lines:?}");
}

/// A connection kept alive after its answer, as a metrics scraper keeps one, is closed by hyper's header timer for
/// the next head and is no timeout: no line, and so no count, which is written with the line or not at all
/// (`tests/metrics_binary.rs` reads the count in a relay of its own).
#[tokio::test]
async fn an_answered_connection_idle_past_the_header_timeout_ends_quietly() {
    let lines = logged_after(300, &[b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"], false).await;
    assert_eq!(lines, Vec::<serde_json::Value>::new());
}

/// After an answer, a second head begun and not finished within the timeout is a header timeout, as a first is.
#[tokio::test]
async fn a_second_head_begun_after_an_answer_and_left_unfinished_is_a_header_timeout() {
    let heads: [&[u8]; 2] = [b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", b"GET / HTTP/1.1\r\nHost: x\r\nX-Slow: "];
    let lines = logged_after(300, &heads, false).await;
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["event"], "connection-timeout");
    assert_eq!(lines[0]["reason"], "header-timeout");
}

/// A metered listener counts a connection it serves as accepted, and as open while it is.
#[tokio::test]
async fn a_metered_connection_is_counted_accepted_and_open_while_it_is() {
    let (accepted, open) = ("ac_relay_connections_accepted_total", "ac_relay_connections_open");
    let before = counted(accepted);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let limits = Limits {
        header_timeout: Duration::from_secs(5),
        connections_per_ip: 8,
        subscriptions_per_ip: 4,
        front: Front::default(),
        metered: true,
    };
    let (stop, stopped) = oneshot::channel::<()>();
    let relay = tokio::spawn(serve(listener, Router::new(), limits, async move {
        let _ = stopped.await;
    }));
    let mut client = TcpStream::connect(addr).await.unwrap();
    // An answer read means the connection was served, and HTTP/1.1 keeps it open after.
    client.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
    let mut answer = [0u8; 12];
    client.read_exact(&mut answer).await.unwrap();
    assert_eq!(&answer, b"HTTP/1.1 404");
    assert!(counted(accepted) > before);
    assert!(counted(open) >= 1);
    drop(client);
    stop.send(()).unwrap();
    relay.await.unwrap().unwrap();
}

/// The same slow head, reset by the client before the timer, is no timeout and writes no line.
#[tokio::test]
async fn a_reset_in_a_head_is_not_a_timeout_and_writes_no_line() {
    let lines = logged_after(600, &[b"GET /v0/health HTTP/1.1\r\nHost: x\r\nX-Slow: "], true).await;
    assert_eq!(lines, Vec::<serde_json::Value>::new());
}
