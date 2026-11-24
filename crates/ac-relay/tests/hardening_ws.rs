//! The WebSocket paths beside the hardening lines: a ping or a close before the auth frame, ack frames
//! read without a derive (the auth frame's reader), and a full unacknowledged window when more mail arrives.
//! In-process relay on a real loopback socket (`common::Server`), with the raw client of `socket::Raw`, which
//! sends any frame.

mod common;
mod socket;

use ac_core::records::Roots;
use ac_relay::Config;
use common::{NOW, Server, addr, bytes, envelope, key, subscribe, ws_env, ws_send};
use futures_util::StreamExt as _;
use socket::Raw;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

async fn hosted() -> Server {
    let s = Server::start(Config::default()).await;
    s.host(2, Roots::Any, 65_536, 3_600, NOW).await;
    s
}

#[tokio::test]
async fn a_ping_before_the_auth_frame_is_heard_and_the_handshake_goes_on() {
    let s = hosted().await;
    let mut ws = Raw::connect(s.addr).await;
    let challenge = ws.json().await;
    ws.send(0x9, b"before auth").await;
    let nonce = challenge["nonce"].as_str().unwrap().to_owned();
    ws.send_json(&common::auth_frame(&key(2), &addr(2), &[], None, &nonce)).await;
    assert_eq!(ws.json().await["t"], "ok");
    s.stop().await;
}

#[tokio::test]
async fn a_client_that_leaves_before_its_auth_frame_ends_the_session_and_nothing_else() {
    let s = hosted().await;
    let mut ws = Raw::connect(s.addr).await;
    assert_eq!(ws.json().await["t"], "challenge");
    ws.send(0x8, &1000u16.to_be_bytes()).await;
    let (texts, _) = ws.until_closed(Duration::from_secs(5)).await;
    assert!(texts.is_empty(), "{texts:?}");
    assert_eq!(s.get("/v0/health", &[]).await.status, 200);
    let (_, cursor) = subscribe(&s, &key(2), &addr(2), &[], None).await;
    assert_eq!(cursor, 0);
    s.stop().await;
}

#[tokio::test]
async fn an_ack_frame_is_exactly_t_ack_and_an_integer_cursor() {
    let s = hosted().await;
    assert_eq!(s.publish(&bytes(&envelope(1, &[addr(2)], vec![], NOW))).await.status, 200);
    for bad in [
        "not json",
        r#"{"t":"ack","cursor":null}"#,
        r#"{"t":"ack","cursor":"1"}"#,
        r#"{"t":1,"cursor":1}"#,
        "[1]",
    ] {
        let mut ws = Raw::connect(s.addr).await;
        assert_eq!(ws.handshake(&key(2), &[], Some(0)).await["t"], "ok", "{bad}");
        assert_eq!(ws.json().await["t"], "env", "{bad}");
        ws.send(0x1, bad.as_bytes()).await;
        let (texts, close) = ws.until_closed(Duration::from_secs(5)).await;
        assert_eq!(
            (texts.first().map(|t| t["error"].clone()), close),
            (Some("bad-shape".into()), Some(4002)),
            "{bad}"
        );
    }
    // The positive control: a well-formed ack is stored.
    let (mut ws, _) = subscribe(&s, &key(2), &addr(2), &[], Some(0)).await;
    assert_eq!(ws_env(&mut ws).await.0, 1);
    ws_send(&mut ws, &serde_json::json!({"t": "ack", "cursor": 1})).await;
    for _ in 0..50 {
        if s.relay.store().acked(addr(2).as_str(), addr(2).as_str()).unwrap() == Some(1) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(s.relay.store().acked(addr(2).as_str(), addr(2).as_str()).unwrap(), Some(1));
    s.stop().await;
}

#[tokio::test]
async fn mail_that_arrives_while_the_window_is_full_waits_for_an_ack() {
    let s = hosted().await;
    for i in 0..32 {
        assert_eq!(s.publish(&bytes(&envelope(1, &[addr(2)], vec![], NOW - i))).await.status, 200);
    }
    let (mut ws, _) = subscribe(&s, &key(2), &addr(2), &[], None).await;
    for i in 1..=32 {
        assert_eq!(ws_env(&mut ws).await.0, i);
    }
    // The 33rd is stored while 32 are unacknowledged: its notification finds no room.
    assert_eq!(s.publish(&bytes(&envelope(1, &[addr(2)], vec![], NOW - 32))).await.status, 200);
    let early = tokio::time::timeout(Duration::from_millis(300), ws.next()).await;
    assert!(early.is_err(), "a frame beyond the window: {early:?}");
    ws_send(&mut ws, &serde_json::json!({"t": "ack", "cursor": 32})).await;
    assert_eq!(ws_env(&mut ws).await.0, 33);
    s.stop().await;
}

/// One connection that pings without pause and never authenticates: the close code it reads, if any, and when.
async fn flood_until_closed() -> (Option<u16>, Duration) {
    let config = Config {
        ping_interval: Duration::from_millis(100),
        idle_timeout: Duration::from_millis(200),
        ..Config::default()
    };
    let s = Server::start(config).await;
    let mut ws = Raw::connect(s.addr).await;
    assert_eq!(ws.json().await["t"], "challenge");
    let started = tokio::time::Instant::now();
    let close = loop {
        ws.send(0x9, b"p").await;
        match ws.frame(tokio::time::Instant::now() + Duration::from_millis(2)).await {
            Some((0x8, payload)) => break Some(u16::from_be_bytes([payload[0], payload[1]])),
            None if started.elapsed() > Duration::from_secs(3) => break None,
            _ => {}
        }
    };
    let took = started.elapsed();
    s.stop().await;
    (close, took)
}

#[tokio::test]
async fn a_flood_of_pings_does_not_hold_off_the_auth_deadline() {
    // Alone, the close 4003 is read about 200 ms in, on the first try. The relay sends it at the deadline and drops the
    // socket while this client's pings still arrive, so the client's next ping is answered by a TCP reset; a client
    // that reads late, as on a loaded machine, can have the unread close frame discarded with it and read nothing
    // (once in the 0.4.5 gate, at a load average of 12 to 49; 4 of 20 in a scratch run that read 400 to 800 ms late
    // while pinging, 0 of 10 when it stopped pinging at the deadline). So the flood runs up to three times, each on a
    // new relay, and fails only when no try reads 4003 within 1 s. A deadline that the pings hold off sends no close
    // while they last, so every try reads none and the test still fails.
    let mut tries = Vec::new();
    for _ in 0..3 {
        let (close, took) = flood_until_closed().await;
        tries.push((close, took));
        if close == Some(4003) && took < Duration::from_secs(1) {
            break;
        }
    }
    let (close, took) = *tries.last().unwrap();
    assert_eq!(close, Some(4003), "no auth: closed for silence although it pinged; every try: {tries:?}");
    assert!(took < Duration::from_secs(1), "every try: {tries:?}");
}

/// How the flood of `a_flood_that_always_has_a_frame_waiting_is_ended_at_the_auth_deadline` ended.
#[derive(Debug, PartialEq, Eq)]
enum Flood {
    /// The relay ended the connection while the pings still went out: a write failed, or the reader saw the end.
    Ended,
    /// Every ping went out for the whole flood and the relay never ended the connection.
    Spent,
}

/// What the reader saw: the close code if a close frame came, and whether the connection ended at all.
#[derive(Debug, Default)]
struct Seen {
    close: Option<u16>,
    ended: bool,
}

/// A subscribe connection with send and receive buffers of 1 MiB, upgraded: its halves and the bytes read past the
/// upgrade's answer.
async fn upgraded(addr: std::net::SocketAddr) -> (OwnedReadHalf, OwnedWriteHalf, Vec<u8>) {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_send_buffer_size(1 << 20).unwrap();
    socket.set_recv_buffer_size(1 << 20).unwrap();
    let mut stream = socket.connect(addr).await.unwrap();
    let request = format!(
        "GET /v0/subscribe HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 16_384];
    let head = loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break end + 4;
        }
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0, "no upgrade answer");
        buf.extend_from_slice(&chunk[..n]);
    };
    assert!(buf.starts_with(b"HTTP/1.1 101"), "{}", String::from_utf8_lossy(&buf));
    buf.drain(..head);
    let (read, write) = stream.into_split();
    (read, write, buf)
}

/// Reads the relay's frames (unmasked, unfragmented: the challenge, then pongs) until a close frame, EOF or an error,
/// and says so in `ended` for the flood.
async fn read_until_end(mut read: OwnedReadHalf, mut buf: Vec<u8>, ended: Arc<AtomicBool>) -> Seen {
    let mut seen = Seen::default();
    let mut chunk = vec![0u8; 65_536];
    let mut challenged = false;
    while seen.close.is_none() {
        while buf.len() >= 2 {
            let (len, header) = match buf[1] & 0x7f {
                126 if buf.len() >= 4 => (usize::from(u16::from_be_bytes([buf[2], buf[3]])), 4),
                126 | 127 => break,
                n => (usize::from(n), 2),
            };
            if buf.len() < header + len {
                break;
            }
            let opcode = buf[0] & 0x0f;
            if opcode == 0x1 {
                let text: serde_json::Value = serde_json::from_slice(&buf[header..header + len]).unwrap();
                assert_eq!((challenged, &text["t"]), (false, &"challenge".into()), "{text}");
                challenged = true;
            }
            if opcode == 0x8 && len >= 2 {
                seen.close = Some(u16::from_be_bytes([buf[header], buf[header + 1]]));
            }
            buf.drain(..header + len);
        }
        if seen.close.is_some() {
            break;
        }
        match read.read(&mut chunk).await {
            Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
            _ => break,
        }
    }
    seen.ended = true;
    ended.store(true, Ordering::SeqCst);
    seen
}

#[tokio::test]
async fn a_flood_that_always_has_a_frame_waiting_is_ended_at_the_auth_deadline() {
    // The fault of ee0baa28, reproduced as its log entry names it: the wait for the auth frame is a `biased;` select
    // that polls the socket before the deadline, "so a client sending pings without pause would never let the
    // deadline's arm run". The test above paces its pings 2 ms apart, so the relay's read goes pending between them
    // and the deadline's arm runs anyway: it passes with the in-loop check removed. Here a client writes pings with no
    // pause into a send buffer of 1 MiB, far more than the relay reads in one turn, and on this test's one thread it
    // writes again whenever the relay yields, so a frame is always waiting and the select's read is ready every time
    // it is polled. Only the deadline checked at each turn of the loop ends the session then. The proof is an order,
    // not a time: the relay must end the connection while the flood still runs (FLOOD is 50 times the deadline);
    // without the check it ends it only after the flood stops. The close frame itself may not be read: the relay
    // drops the socket with this client's pings unread, and the TCP reset that follows can discard it (see the test
    // above), so a close that is read must be 4003, and an end without one counts as the end.
    const FLOOD: Duration = Duration::from_secs(10);
    let config = Config {
        ping_interval: Duration::from_millis(100),
        idle_timeout: Duration::from_millis(200),
        ..Config::default()
    };
    let s = Server::start(config).await;
    let (read, mut write, buf) = upgraded(s.addr).await;
    let ended = Arc::new(AtomicBool::new(false));
    let reader = tokio::spawn(read_until_end(read, buf, Arc::clone(&ended)));
    // Empty masked pings, six bytes each, 11,000 to a write.
    let ping = [0x89_u8, 0x80, 0x37, 0xfa, 0x21, 0x3d];
    let pings: Vec<u8> = ping.iter().copied().cycle().take(ping.len() * 11_000).collect();
    let started = tokio::time::Instant::now();
    let flood = loop {
        if ended.load(Ordering::SeqCst) {
            break Flood::Ended;
        }
        if started.elapsed() >= FLOOD {
            break Flood::Spent;
        }
        if write.write_all(&pings).await.is_err() {
            break Flood::Ended;
        }
    };
    let flooded = started.elapsed();
    let seen = tokio::time::timeout(Duration::from_mins(1), reader).await.expect("the reader ended").unwrap();
    assert_eq!(
        flood,
        Flood::Ended,
        "the relay ended it only after {flooded:?} of pings ({seen:?}): the pings held off the deadline"
    );
    assert!(seen.ended, "{seen:?}");
    assert!(seen.close.is_none_or(|c| c == 4003), "a close read is the auth deadline's: {seen:?}");
    drop(write);
    assert_eq!(s.get("/v0/health", &[]).await.status, 200);
    s.stop().await;
}
