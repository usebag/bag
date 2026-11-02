//! Slow clients are shed. A connection that
//! has not sent a whole request head within the header timeout (10 s by default) is closed; a publish whose body
//! stalls past the body timeout is answered 408 and closed; one client address holds at most its cap of connections
//! (79 by default), a WebSocket included until it closes, and one more is closed at once. Its subscriptions stop
//! short of the cap, so that its calls still get in. `/v0/health` answers
//! throughout. In-process relay on a real loopback socket (`common::Server`); every client is 127.0.0.1, so L5's health
//! rule runs with the cap at 128 (with 64 slow connections open, health is the 65th), and the cap has its own case.

mod common;

use ac_core::chain::{Hop, MAX_CAVEAT_BYTES, MAX_CAVEATS};
use ac_core::records::Roots;
use ac_relay::Config;
use common::{NOW, Server, addr, key, request, subscribe, ws_close_code, ws_connect, ws_json};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout};

/// One slow HTTP client: the request line, then one header byte every 5 s, until the relay ends the connection or
/// `hold` passes. Returns when the relay closed it, if it did.
async fn slow_http(addr: SocketAddr, hold: Duration) -> Option<Duration> {
    let started = Instant::now();
    let stream = TcpStream::connect(addr).await.unwrap();
    let (mut read, mut write) = stream.into_split();
    write.write_all(b"POST /v0/publish HTTP/1.1\r\n").await.ok()?;
    let mut tick = tokio::time::interval_at(started + Duration::from_secs(5), Duration::from_secs(5));
    let mut chunk = [0u8; 512];
    loop {
        tokio::select! {
            _ = tick.tick() => {
                if started.elapsed() >= hold {
                    return None;
                }
                if write.write_all(b"x").await.is_err() {
                    return Some(started.elapsed());
                }
            }
            got = read.read(&mut chunk) => {
                // EOF, an error, or an answer: the relay ended it.
                let _ = got;
                return Some(started.elapsed());
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l5_sixty_four_slow_connections_are_closed_at_the_header_timeout_while_health_answers() {
    let s = Server::start(Config { connections_per_ip: 128, ..Config::default() }).await;
    let hold = Duration::from_secs(14);
    let slow: Vec<_> = (0..64).map(|_| tokio::spawn(slow_http(s.addr, hold))).collect();
    let started = Instant::now();
    let (mut checks, mut failures, mut worst) = (0, 0, Duration::ZERO);
    while started.elapsed() < Duration::from_secs(12) {
        let t = Instant::now();
        let answer = timeout(Duration::from_secs(1), request(s.addr, "GET", "/v0/health", &[], b"")).await;
        let took = t.elapsed();
        worst = worst.max(took);
        checks += 1;
        if !matches!(answer, Ok(ref r) if r.status == 200) {
            failures += 1;
        }
        tokio::time::sleep(Duration::from_secs(1).saturating_sub(took)).await;
    }
    let mut closed = Vec::new();
    for task in slow {
        closed.push(task.await.unwrap());
    }
    let at: Vec<Duration> = closed.iter().flatten().copied().collect();
    let (first, last) = (at.iter().min().copied(), at.iter().max().copied());
    eprintln!(
        "MEASURE L5: 64 slow HTTP connections: {} closed by the relay, from {first:?} to {last:?}; health {checks} \
         checks, {failures} failed or over 1 s, worst {worst:?}",
        at.len()
    );
    assert_eq!(failures, 0, "health 200 within 1 s throughout");
    assert_eq!(at.len(), 64, "every slow connection closed: {closed:?}");
    assert!(first >= Some(Duration::from_millis(9_900)) && last <= Some(Duration::from_secs(11)), "{at:?}");
    s.stop().await;
}

/// Opens a connection and waits for the relay to close it: true when it closed at once with nothing written.
async fn refused_at_once(addr: SocketAddr) -> bool {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let mut buf = [0u8; 64];
    matches!(timeout(Duration::from_secs(1), stream.read(&mut buf)).await, Ok(Ok(0) | Err(_)))
}

#[tokio::test]
async fn one_connection_past_the_default_cap_of_an_address_is_closed_at_once_and_a_freed_place_is_served() {
    let config = Config::default();
    let cap = config.connections_per_ip;
    let s = Server::start(config).await;
    let mut open = Vec::new();
    for _ in 0..cap {
        open.push(TcpStream::connect(s.addr).await.unwrap());
    }
    // The relay has accepted them all once a request on one more is refused; give it a moment to count.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let refused = refused_at_once(s.addr).await;
    eprintln!("MEASURE L5: with {cap} connections open from one address, one more closed at once: {refused}");
    assert!(refused);
    drop(open.pop());
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let r = timeout(Duration::from_secs(1), request(s.addr, "GET", "/v0/health", &[], b"")).await;
        if matches!(r, Ok(ref r) if r.status == 200) {
            break;
        }
        assert!(Instant::now() < deadline, "the freed place was not served");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    s.stop().await;
}

#[tokio::test]
async fn a_websocket_keeps_its_place_until_it_closes() {
    let s = Server::start(Config { connections_per_ip: 2, ..Config::default() }).await;
    s.host(2, Roots::Any, 65_536, 3_600, NOW).await;
    let (ws, _) = subscribe(&s, &key(2), &addr(2), &[], None).await;
    let _held = TcpStream::connect(s.addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(refused_at_once(s.addr).await, "a WebSocket and a connection fill a cap of 2");
    drop(ws);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let r = timeout(Duration::from_secs(1), request(s.addr, "GET", "/v0/health", &[], b"")).await;
        if matches!(r, Ok(ref r) if r.status == 200) {
            break;
        }
        assert!(Instant::now() < deadline, "the WebSocket's place was not freed");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    s.stop().await;
}

#[tokio::test]
async fn subscriptions_stop_short_of_the_cap_so_that_the_calls_of_the_address_still_get_in() {
    let config = Config { connections_per_ip: 16, ..Config::default() };
    let limit = config.subscriptions_per_ip();
    assert_eq!(limit, 8);
    let s = Server::start(config).await;
    let mut held = Vec::new();
    for n in 0..limit {
        let owner = u8::try_from(n + 1).unwrap();
        s.host(owner, Roots::Any, 65_536, 3_600, NOW).await;
        held.push(subscribe(&s, &key(owner), &addr(owner), &[], None).await.0);
    }
    // The next is upgraded and refused at once, before any challenge, with a code a client retries.
    let mut refused = ws_connect(&s).await;
    assert_eq!(ws_json(&mut refused).await, serde_json::json!({"t": "error", "error": "rate-limited"}));
    assert_eq!(ws_close_code(&mut refused).await, 1013);
    drop(refused);
    // A call gets in, while the limit is full.
    assert_eq!(request(s.addr, "GET", "/v0/health", &[], b"").await.status, 200);
    // A subscription that closes frees its place for the next.
    drop(held.pop());
    let owner = 99;
    s.host(owner, Roots::Any, 65_536, 3_600, NOW).await;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let mut next = ws_connect(&s).await;
        if ws_json(&mut next).await["t"] == "challenge" {
            break;
        }
        assert!(Instant::now() < deadline, "the subscription's place was not freed");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    s.stop().await;
}

/// The read buffer of a subscription (`ws::READ_BUFFER`, 4 KiB) bounds no frame: an auth frame whose one hop holds the
/// most caveats a chain may, over 8 KiB of them, subscribes.
#[tokio::test]
async fn an_auth_frame_past_the_read_buffer_still_subscribes() {
    let s = Server::start(Config::default()).await;
    s.host(2, Roots::Any, 65_536, 3_600, NOW).await;
    let caveats = (0..MAX_CAVEATS).map(|n| format!("{n:0>MAX_CAVEAT_BYTES$}")).collect();
    let hop = Hop::sign(&key(2), &addr(30), caveats, NOW + 3_600).unwrap();
    let (_held, cursor) = subscribe(&s, &key(30), &addr(2), &[hop], None).await;
    assert_eq!(cursor, 0);
    s.stop().await;
}

#[tokio::test]
async fn a_publish_whose_body_stalls_is_408_at_the_body_timeout_and_closed() {
    let s = Server::start(Config { body_timeout: Duration::from_secs(1), ..Config::default() }).await;
    let mut stream = TcpStream::connect(s.addr).await.unwrap();
    let head = format!("POST /v0/publish HTTP/1.1\r\nHost: {}\r\nContent-Length: 1000\r\n\r\n", s.addr);
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(b"{\"v\":1,").await.unwrap();
    let started = Instant::now();
    let mut answer = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut answer)).await.unwrap().unwrap();
    let took = started.elapsed();
    let text = String::from_utf8_lossy(&answer);
    eprintln!(
        "MEASURE L5: a stalled publish body at a body timeout of 1 s: {:?} after {took:?}",
        text.lines().next()
    );
    assert!(text.starts_with("HTTP/1.1 408"), "{text}");
    assert!(text.to_ascii_lowercase().contains("connection: close"), "{text}");
    assert!(took >= Duration::from_millis(950) && took <= Duration::from_millis(1_500), "{took:?}");
    // A body that arrives in time is read as before.
    let r = s.publish(b"{}").await;
    assert_eq!((r.status, r.error()), (400, "bad-shape".to_owned()));
    s.stop().await;
}

#[tokio::test]
async fn a_connection_that_sends_nothing_is_closed_at_the_header_timeout() {
    let s = Server::start(Config { header_timeout: Duration::from_millis(300), ..Config::default() }).await;
    let mut stream = TcpStream::connect(s.addr).await.unwrap();
    let started = Instant::now();
    let mut buf = [0u8; 64];
    let n = timeout(Duration::from_secs(5), stream.read(&mut buf)).await.unwrap().unwrap_or(0);
    let took = started.elapsed();
    eprintln!(
        "MEASURE L5: a connection that sends nothing, header timeout 300 ms: closed after {took:?}, {n} bytes"
    );
    assert_eq!(n, 0);
    assert!(took >= Duration::from_millis(280) && took <= Duration::from_secs(1), "{took:?}");
    // A keep-alive connection idle after its answer is closed at the header timeout too.
    let mut kept = TcpStream::connect(s.addr).await.unwrap();
    let get = format!("GET /v0/health HTTP/1.1\r\nHost: {}\r\n\r\n", s.addr);
    kept.write_all(get.as_bytes()).await.unwrap();
    let n = timeout(Duration::from_secs(5), kept.read(&mut buf)).await.unwrap().unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
    let idle = Instant::now();
    let mut rest = Vec::new();
    let _ = timeout(Duration::from_secs(5), kept.read_to_end(&mut rest)).await.unwrap();
    assert!(idle.elapsed() <= Duration::from_secs(2), "{:?}", idle.elapsed());
    s.stop().await;
}
