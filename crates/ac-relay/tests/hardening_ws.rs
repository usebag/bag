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
use std::time::Duration;

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

#[tokio::test]
async fn a_flood_of_pings_does_not_hold_off_the_auth_deadline() {
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
    assert_eq!(close, Some(4003), "no auth: closed for silence although it pinged");
    assert!(took < Duration::from_secs(1), "{took:?}");
    s.stop().await;
}
