//! The relay under abuse on a real socket: A1 (sizes, and an oversized WebSocket frame before
//! and after the handshake), A3 (the per-address burst), A4 (subscribing as a non-owner), A6 (hostile frames),
//! A8 (slow clients, measured for 70 s; its slow HTTP connections closed at the header timeout) and A9
//! (after each: health 200, a genuine publish stored, and no `panicked` on the relay's stderr).
//!
//! Where each runs: A1, A4, A6, A8 and A9 start the `ac-relay` binary on port 0 on 127.0.0.1 (the one cargo
//! builds for these tests, `CARGO_BIN_EXE_ac-relay`), on the system clock, with its stderr read to the end. A3
//! runs on the in-process relay bound to a real loopback socket (`common::Server`) with a `ManualClock`: the
//! binary's rate windows are aligned to the wall clock's minutes and cannot be held still, so a burst could straddle
//! two windows; the in-process clock cannot move during the burst. Nothing here reaches any other host.

mod common;
mod socket;

use ac_core::chain::Hop;
use ac_core::envelope::Envelope;
use ac_core::keys::SigningKey;
use ac_core::records::Roots;
use ac_relay::Config;
use common::{NOW, Server, addr, auth_frame, bytes, envelope, key, request};
use socket::{Bin, Raw, envelope_of, now};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::time::Instant;

#[tokio::test]
async fn a1_oversized_bodies_envelopes_and_frames_are_refused() {
    let bin = Bin::spawn();
    bin.host().await;
    let r = bin.publish(&vec![b' '; 262_145]).await;
    assert_eq!((r.status, r.error()), (413, "body-too-large".to_owned()));
    let r = bin.publish(&envelope_of(196_609, now())).await;
    assert_eq!((r.status, r.error()), (413, "envelope-too-large".to_owned()));
    let r = bin.publish(&envelope_of(196_608, now() - 1)).await;
    assert_eq!(
        (r.status, r.json()["delivered"].clone()),
        (200, 1.into()),
        "196,608 bytes parse: {}",
        r.text()
    );
    let before = bin.last_cursor().await;
    let big = vec![b'a'; 262_145];
    let mut ws = Raw::connect(bin.addr).await;
    assert_eq!(ws.json().await["t"], "challenge");
    ws.send(0x1, &big).await;
    let (texts, code) = ws.until_closed(Duration::from_secs(5)).await;
    eprintln!("A1: a 262,145-byte frame before the handshake: frames {texts:?}, close {code:?}");
    assert!(texts.iter().all(|t| t["t"] != "ok" && t["t"] != "env"), "{texts:?}");
    let mut ws = Raw::connect(bin.addr).await;
    assert_eq!(ws.handshake(&key(2), &[], Some(before)).await["t"], "ok");
    ws.send(0x1, &big).await;
    let (texts, code) = ws.until_closed(Duration::from_secs(5)).await;
    eprintln!("A1: a 262,145-byte frame after the handshake: frames {texts:?}, close {code:?}");
    assert!(texts.iter().all(|t| t["t"] != "env"), "{texts:?}");
    assert_eq!(bin.last_cursor().await, before, "nothing stored");
    bin.a9("A1", 10).await;
}

/// A3 runs in process (see the file's doc comment): the burst cannot straddle two rate windows.
#[tokio::test]
async fn a3_a_burst_from_one_address_is_refused_at_the_601st() {
    let s = Server::start(Config::default()).await;
    s.host(2, Roots::Any, 65_536, 3_600, NOW).await;
    // The record publish counted against the address too (Appendix B item 24): start a fresh window.
    s.clock.advance(60);
    let t = NOW + 60;
    let keys: Vec<SigningKey> = (0..602u16)
        .map(|i| {
            let mut seed = [0xa3u8; 32];
            seed[..2].copy_from_slice(&i.to_le_bytes());
            SigningKey::from_seed(&seed)
        })
        .collect();
    let envelopes: Vec<Vec<u8>> = keys
        .iter()
        .map(|k| {
            Envelope::sign(k, vec![addr(2)], vec![], t, common::sealed(&[addr(2)], 32)).unwrap().to_bytes()
        })
        .collect();
    let started = std::time::Instant::now();
    for (i, env) in envelopes[..600].iter().enumerate() {
        let r = s.publish(env).await;
        assert_eq!(r.status, 200, "publish {} of 600: {}", i + 1, r.text());
    }
    let r = s.publish(&envelopes[600]).await;
    eprintln!(
        "MEASURE A3: 600 publishes from 600 self-rooted keys in {:?}; the 601st: {} {}",
        started.elapsed(),
        r.status,
        r.text()
    );
    assert_eq!((r.status, r.error()), (429, "rate-limited".to_owned()), "the 601st");
    // A second client connection from the same loopback address shares the bucket.
    let mut second = TcpStream::connect(s.addr).await.unwrap();
    let body = &envelopes[601];
    let head = format!(
        "POST /v0/publish HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        s.addr,
        body.len()
    );
    second.write_all(head.as_bytes()).await.unwrap();
    second.write_all(body).await.unwrap();
    let mut answer = Vec::new();
    second.read_to_end(&mut answer).await.unwrap();
    let answer = String::from_utf8_lossy(&answer);
    eprintln!("MEASURE A3: the second client: {}", answer.lines().next().unwrap_or_default());
    assert!(answer.starts_with("HTTP/1.1 429") && answer.contains("rate-limited"), "{answer}");
    assert_eq!(s.relay.store().last_cursor(addr(2).as_str()).unwrap(), 600);
    s.clock.advance(60);
    assert_eq!(s.publish(&envelopes[601]).await.status, 200, "A9: the next window accepts a genuine publish");
    assert_eq!(s.get("/v0/health", &[]).await.status, 200);
    s.stop().await;
}

#[tokio::test]
async fn a4_a_non_owner_never_subscribes() {
    let bin = Bin::spawn();
    bin.host().await;
    assert_eq!(bin.publish(&bytes(&envelope(1, &[addr(2)], vec![], now()))).await.status, 200);
    let exp = now() + 3_600;
    let elsewhere = Hop::sign(&key(8), &addr(9), vec![], exp).unwrap();
    let genuine = Hop::sign(&key(2), &addr(31), vec![], exp).unwrap();
    let pre = ac_core::chain::hop_preimage(&addr(31), &addr(30), &[], exp);
    let forged =
        Hop { iss: addr(31), sub: addr(30), caveats: vec![], exp, sig: key(30).sign_preimage(&pre).unwrap() };
    let cases: [(&str, SigningKey, Vec<Hop>, &str); 3] = [
        ("auth [] by another signer", key(9), vec![], "not-authorized"),
        ("a chain rooted elsewhere", key(9), vec![elsewhere], "not-authorized"),
        ("a forged last hop", key(30), vec![genuine, forged], "bad-hop-sig"),
    ];
    for (label, signer, hops, code) in cases {
        let mut ws = Raw::connect(bin.addr).await;
        let error = ws.handshake(&signer, &hops, None).await;
        let (rest, close) = ws.until_closed(Duration::from_secs(5)).await;
        assert_eq!(
            (error["t"].as_str(), error["error"].as_str(), close),
            (Some("error"), Some(code), Some(4001)),
            "{label}"
        );
        assert!(rest.iter().all(|t| t["t"] != "env"), "{label}: {rest:?}");
    }
    // The right signer, over another nonce.
    let mut ws = Raw::connect(bin.addr).await;
    assert_eq!(ws.json().await["t"], "challenge");
    ws.send_json(&auth_frame(&key(2), &addr(2), &[], None, &"00".repeat(32))).await;
    let (texts, close) = ws.until_closed(Duration::from_secs(5)).await;
    assert_eq!((texts.first().map(|t| t["error"].clone()), close), (Some("bad-auth".into()), Some(4001)));
    assert!(texts.iter().all(|t| t["t"] != "env"));
    // Positive control: the owner subscribes and receives the envelope.
    let mut ws = Raw::connect(bin.addr).await;
    assert_eq!(ws.handshake(&key(2), &[], None).await["t"], "ok");
    assert_eq!(ws.json().await["t"], "env");
    bin.a9("A4", 10).await;
}

/// Each hostile frame before the challenge is answered: `bad-auth` and close 4001.
async fn a6_before(bin: &Bin) {
    let mut cases: Vec<(&str, u8, Vec<u8>)> =
        vec![("binary", 0x2, vec![1, 2, 3]), ("not JSON", 0x1, b"{nope".to_vec())];
    for (label, cursor) in
        [("extra member", "null"), ("cursor -1", "-1"), ("cursor 1e308", "1e308"), ("cursor \"1\"", "\"1\"")]
    {
        let extra = if label == "extra member" { ",\"x\":1" } else { "" };
        let frame = format!(
            "{{\"t\":\"auth\",\"mailbox\":\"{a}\",\"signer\":\"{a}\",\"auth\":[],\"cursor\":{cursor},\"sig\":\"{s}\"{extra}}}",
            a = addr(2),
            s = "00".repeat(64)
        );
        cases.push((label, 0x1, frame.into_bytes()));
    }
    for (label, opcode, payload) in cases {
        let mut ws = Raw::connect(bin.addr).await;
        assert_eq!(ws.json().await["t"], "challenge");
        ws.send(opcode, &payload).await;
        let (texts, close) = ws.until_closed(Duration::from_secs(5)).await;
        assert_eq!(
            (texts.first().map(|t| t["error"].clone()), close),
            (Some("bad-auth".into()), Some(4001)),
            "{label}"
        );
        assert_eq!(bin.health().await, 200, "{label}");
    }
}

#[tokio::test]
async fn a6_hostile_frames_meet_their_closes() {
    let bin = Bin::spawn();
    bin.host().await;
    a6_before(&bin).await;
    let last = bin.last_cursor().await;
    let challenge_frame =
        serde_json::json!({"t": "challenge", "nonce": "00".repeat(32), "ts": now()}).to_string();
    let auth = auth_frame(&key(2), &addr(2), &[], None, &"00".repeat(32)).to_string();
    let never_sent = format!("{{\"t\":\"ack\",\"cursor\":{}}}", last + 1_000);
    for (label, frame) in [
        ("a challenge frame", challenge_frame),
        ("an auth frame", auth),
        ("an ack never sent", never_sent),
        ("an ack with cursor null", r#"{"t":"ack","cursor":null}"#.to_owned()),
    ] {
        let mut ws = Raw::connect(bin.addr).await;
        assert_eq!(ws.handshake(&key(2), &[], Some(last)).await["t"], "ok", "{label}");
        ws.send(0x1, frame.as_bytes()).await;
        let (texts, close) = ws.until_closed(Duration::from_secs(5)).await;
        assert_eq!(
            (texts.first().map(|t| t["error"].clone()), close),
            (Some("bad-shape".into()), Some(4002)),
            "{label}"
        );
        assert_eq!(bin.health().await, 200, "{label}");
    }
    assert_eq!(bin.last_cursor().await, last, "nothing stored");
    // 1,000 pings in one second: answered, and the connection kept.
    let mut ws = Raw::connect(bin.addr).await;
    assert_eq!(ws.handshake(&key(2), &[], Some(last)).await["t"], "ok");
    for i in 0..1_000u32 {
        ws.send(0x9, &i.to_be_bytes()).await;
        if i % 10 == 9 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    assert_eq!(bin.publish(&bytes(&envelope(1, &[addr(2)], vec![], now() - 3))).await.status, 200);
    let (mut pongs, mut env) = (0, false);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !env {
        match ws.frame(deadline).await {
            Some((0xa, _)) => pongs += 1,
            Some((0x1, payload)) => {
                env = serde_json::from_slice::<serde_json::Value>(&payload).unwrap()["t"] == "env";
            }
            Some(_) => {}
            None => panic!("the connection ended after the pings ({pongs} pongs)"),
        }
    }
    eprintln!(
        "MEASURE A6: 1,000 pings in about a second: {pongs} pongs before the next env frame; connection kept"
    );
    assert!(pongs >= 1, "the pings are answered");
    // A text frame that is not UTF-8: closed by the WebSocket layer.
    ws.send(0x1, &[0xff, 0xfe, 0xc0, 0x80]).await;
    let (texts, close) = ws.until_closed(Duration::from_secs(5)).await;
    eprintln!("MEASURE A6: invalid UTF-8 text frame: frames {texts:?}, close {close:?}");
    assert!(texts.iter().all(|t| t["t"] != "env"));
    bin.a9("A6", 10).await;
}

/// One slow HTTP client: the request line, then one header byte every 5 s until `hold` passes or the relay ends the
/// connection. Returns when the relay closed it, if it did.
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
                // EOF, an error or an answer (a 408, say): the relay ended the request.
                let _ = got;
                return Some(started.elapsed());
            }
        }
    }
}

/// A8: wall time about 71 s (held 70 s, reduced from the pre-registered 120 s to keep the gate usable under
/// coverage; the idle close at 60 s is still observed). The rule (health 200 within 1 s throughout) is asserted; the closes are measured.
/// Since fixed: the slow HTTP connections are now closed at the relay's
/// header timeout (10 s), where the relay before the fix kept all 64 open; the binary runs with `--connections-per-ip 256`, since
/// this line opens 129 connections from one address and the default cap is 64 (its own case is in
/// `tests/hardening_socket.rs`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a8_slow_clients_never_starve_health() {
    let bin = Bin::spawn_with(&["--connections-per-ip", "256"]);
    bin.host().await;
    let hold = Duration::from_secs(70);
    let slow: Vec<_> = (0..64).map(|_| tokio::spawn(slow_http(bin.addr, hold))).collect();
    let mut idle = Vec::new();
    for _ in 0..64 {
        let mut ws = Raw::connect(bin.addr).await;
        let opened = Instant::now();
        idle.push(tokio::spawn(async move {
            assert_eq!(ws.json().await["t"], "challenge");
            let (_, close) = ws.until_closed(hold).await;
            (close, opened.elapsed())
        }));
    }
    let started = Instant::now();
    let (mut checks, mut worst, mut failures) = (0, Duration::ZERO, 0);
    while started.elapsed() < hold {
        let t = Instant::now();
        let ok =
            tokio::time::timeout(Duration::from_secs(1), request(bin.addr, "GET", "/v0/health", &[], b""))
                .await;
        let took = t.elapsed();
        worst = worst.max(took);
        checks += 1;
        if !matches!(ok, Ok(ref r) if r.status == 200) {
            failures += 1;
        }
        tokio::time::sleep(Duration::from_secs(1).saturating_sub(took)).await;
    }
    let mut ws_closes = Vec::new();
    for task in idle {
        ws_closes.push(task.await.unwrap());
    }
    let mut http_closed = Vec::new();
    for task in slow {
        if let Some(at) = task.await.unwrap() {
            http_closed.push(at.as_secs());
        }
    }
    let codes: Vec<Option<u16>> = ws_closes.iter().map(|c| c.0).collect();
    let secs: Vec<u64> = ws_closes.iter().map(|c| c.1.as_secs()).collect();
    let (first, last) = (secs.iter().min().copied(), secs.iter().max().copied());
    eprintln!("MEASURE A8: health {checks} checks, {failures} failed or over 1 s, worst {worst:?}");
    eprintln!(
        "MEASURE A8: 64 idle WebSockets: {} closed 4003, close after {first:?} to {last:?} s",
        codes.iter().filter(|c| **c == Some(4003)).count()
    );
    eprintln!(
        "MEASURE A8: 64 slow HTTP connections held {hold:?}: {} closed by the relay, at {http_closed:?} s",
        http_closed.len()
    );
    assert_eq!(failures, 0, "the rule: health 200 within 1 s throughout");
    assert!(codes.iter().all(|c| *c == Some(4003)), "{codes:?}");
    assert!(first >= Some(59) && last <= Some(62), "closed at 60 s: {secs:?}");
    assert_eq!(http_closed.len(), 64, "every slow HTTP connection closed: {http_closed:?}");
    assert!(
        http_closed.iter().all(|at| (10..=11).contains(at)),
        "closed at the 10 s header timeout: {http_closed:?}"
    );
    bin.a9("A8", 10).await;
}

#[tokio::test]
async fn a9_no_panic_after_hostile_bodies_and_flipped_envelopes() {
    let bin = Bin::spawn();
    bin.host().await;
    let genuine = bytes(&envelope(1, &[addr(2)], vec![], now() - 20));
    let mut statuses = std::collections::BTreeMap::<u16, usize>::new();
    let hostile: Vec<Vec<u8>> = vec![
        "[".repeat(100_000).into_bytes(),
        "[".repeat(60_000).into_bytes(),
        b"{\"kind\":".to_vec(),
        vec![0xff; 1_000],
        vec![0; 10],
        b"\xef\xbb\xbf{}".to_vec(),
    ];
    for body in hostile {
        let r = bin.publish(&body).await;
        *statuses.entry(r.status).or_default() += 1;
    }
    for pos in 0..genuine.len() {
        let mut flipped = genuine.clone();
        flipped[pos] ^= 0x01;
        let r = bin.publish(&flipped).await;
        assert!(r.status != 200 && r.status < 500, "a flip at byte {pos}: {} {}", r.status, r.text());
        *statuses.entry(r.status).or_default() += 1;
    }
    eprintln!("A9: {} flipped envelopes and 6 hostile bodies: statuses {statuses:?}", genuine.len());
    bin.a9("A9", 0).await;
}
