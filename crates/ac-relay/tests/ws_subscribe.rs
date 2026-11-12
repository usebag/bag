//! Subscribe over a real WebSocket: the handshake and each refusal, pushes in cursor order, acks, reconnects
//! with a cursor, the unacknowledged window, protocol errors, pings, idle closes and shutdown.

mod common;

use ac_core::chain::Hop;
use ac_core::envelope::Envelope;
use ac_core::records::Roots;
use ac_relay::Config;
use common::{
    NOW, RawWs, Server, addr, auth_frame, bytes, envelope, key, sealed, subscribe, ws_close_code, ws_connect,
    ws_env, ws_json, ws_send,
};
use futures_util::{SinkExt as _, StreamExt as _};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

async fn hosted(config: Config) -> Server {
    let s = Server::start(config).await;
    s.host(2, Roots::Any, 65_536, 3_600, NOW).await;
    s
}

async fn publish_n(s: &Server, n: u64) -> Vec<String> {
    let mut ids = Vec::new();
    for i in 0..n {
        let env = envelope(1, &[addr(2)], vec![], NOW - i);
        assert_eq!(s.publish(&bytes(&env)).await.status, 200);
        ids.push(env.id_hex());
    }
    ids
}

#[tokio::test]
async fn the_mailbox_key_subscribes_and_receives_live_pushes_as_exact_json() {
    let s = hosted(Config::default()).await;
    let (mut ws, cursor) = subscribe(&s, &key(2), &addr(2), &[], None).await;
    assert_eq!(cursor, 0);
    let env = envelope(1, &[addr(2)], vec![], NOW);
    assert_eq!(s.publish(&bytes(&env)).await.status, 200);
    let frame = ws_json(&mut ws).await;
    assert_eq!(frame["t"], "env");
    assert_eq!(frame["cursor"], 1);
    // The envelope is a JSON string of its exact stored bytes, beside the second the relay stored it.
    assert_eq!(frame["envelope"], env.to_json_text());
    assert_eq!(frame["received_at"], NOW);
    s.stop().await;
}

#[tokio::test]
async fn the_backlog_arrives_in_cursor_order() {
    let s = hosted(Config::default()).await;
    let ids = publish_n(&s, 3).await;
    let (mut ws, _) = subscribe(&s, &key(2), &addr(2), &[], None).await;
    for (i, id) in ids.iter().enumerate() {
        assert_eq!(ws_env(&mut ws).await, (u64::try_from(i).unwrap() + 1, id.clone()));
    }
    s.stop().await;
}

#[tokio::test]
async fn an_ack_is_stored_and_a_reconnect_resumes_after_it() {
    let s = hosted(Config::default()).await;
    let ids = publish_n(&s, 2).await;
    let (mut ws, _) = subscribe(&s, &key(2), &addr(2), &[], None).await;
    assert_eq!(ws_env(&mut ws).await.0, 1);
    assert_eq!(ws_env(&mut ws).await.0, 2);
    ws_send(&mut ws, &serde_json::json!({"t": "ack", "cursor": 2})).await;
    // The ack is stored when the relay reads it; wait until it is.
    for _ in 0..50 {
        if s.relay.store().acked(addr(2).as_str(), addr(2).as_str()).unwrap() == Some(2) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(s.relay.store().acked(addr(2).as_str(), addr(2).as_str()).unwrap(), Some(2));
    ws.close(None).await.unwrap();
    let third = publish_n(&s, 3).await.pop().unwrap();
    // cursor null resumes after the stored ack.
    let (mut ws, cursor) = subscribe(&s, &key(2), &addr(2), &[], None).await;
    assert_eq!(cursor, 2);
    assert_eq!(ws_env(&mut ws).await, (3, third));
    // An explicit cursor resumes after it; an ack never deletes, so everything is still there.
    let (mut again, cursor) = subscribe(&s, &key(2), &addr(2), &[], Some(0)).await;
    assert_eq!(cursor, 0);
    assert_eq!(ws_env(&mut again).await, (1, ids[0].clone()));
    // A cursor past the end is clamped to the last one.
    let (_, cursor) = subscribe(&s, &key(2), &addr(2), &[], Some(1_000)).await;
    assert_eq!(cursor, 3);
    s.stop().await;
}

#[tokio::test]
async fn a_delegate_of_the_mailbox_subscribes_and_acks_are_per_signer() {
    let s = hosted(Config::default()).await;
    publish_n(&s, 1).await;
    let hop = Hop::sign(&key(2), &addr(30), vec!["role=session".into()], NOW + 600).unwrap();
    let (mut ws, cursor) = subscribe(&s, &key(30), &addr(2), &[hop], None).await;
    assert_eq!(cursor, 0);
    assert_eq!(ws_env(&mut ws).await.0, 1);
    ws_send(&mut ws, &serde_json::json!({"t": "ack", "cursor": 1})).await;
    for _ in 0..50 {
        if s.relay.store().acked(addr(2).as_str(), addr(30).as_str()).unwrap() == Some(1) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(s.relay.store().acked(addr(2).as_str(), addr(30).as_str()).unwrap(), Some(1));
    assert_eq!(s.relay.store().acked(addr(2).as_str(), addr(2).as_str()).unwrap(), None);
    // The mailbox key itself still starts from 0.
    let (_, cursor) = subscribe(&s, &key(2), &addr(2), &[], None).await;
    assert_eq!(cursor, 0);
    s.stop().await;
}

async fn refused(s: &Server, frame: Message) -> (String, u16) {
    let mut ws = ws_connect(s).await;
    let challenge = ws_json(&mut ws).await;
    assert_eq!(challenge["t"], "challenge");
    assert_eq!(challenge["nonce"].as_str().unwrap().len(), 64);
    assert_eq!(challenge["ts"], NOW);
    let frame = match frame {
        Message::Text(t) if t.as_str() == "SIGN" => Message::Text(
            auth_frame(&key(2), &addr(2), &[], None, challenge["nonce"].as_str().unwrap()).to_string().into(),
        ),
        other => other,
    };
    ws.send(frame).await.unwrap();
    let error = ws_json(&mut ws).await;
    assert_eq!(error["t"], "error");
    (error["error"].as_str().unwrap().to_owned(), ws_close_code(&mut ws).await)
}

#[tokio::test]
async fn each_handshake_failure_is_an_error_frame_and_close_4001() {
    let s = hosted(Config::default()).await;
    let nonce = "00".repeat(32);
    let cases = [
        (Message::Text("{".into()), "bad-auth"),
        (Message::Text(r#"{"t":"ack","cursor":1}"#.into()), "bad-auth"),
        (Message::Binary(vec![1, 2, 3].into()), "bad-auth"),
        (Message::Text(auth_frame(&key(2), &addr(2), &[], None, &nonce).to_string().into()), "bad-auth"),
    ];
    for (frame, code) in cases {
        assert_eq!(refused(&s, frame).await, (code.to_owned(), 4001));
    }
    // Signed over the real nonce but by a key that is not the mailbox's and has no chain from it.
    let mut ws = ws_connect(&s).await;
    let challenge = ws_json(&mut ws).await;
    ws_send(&mut ws, &auth_frame(&key(9), &addr(2), &[], None, challenge["nonce"].as_str().unwrap())).await;
    assert_eq!(ws_json(&mut ws).await["error"], "not-authorized");
    assert_eq!(ws_close_code(&mut ws).await, 4001);
    // An expired delegation.
    let expired = Hop::sign(&key(2), &addr(30), vec![], NOW - 1).unwrap();
    let mut ws = ws_connect(&s).await;
    let challenge = ws_json(&mut ws).await;
    ws_send(&mut ws, &auth_frame(&key(30), &addr(2), &[expired], None, challenge["nonce"].as_str().unwrap()))
        .await;
    assert_eq!(ws_json(&mut ws).await["error"], "hop-expired");
    assert_eq!(ws_close_code(&mut ws).await, 4001);
    // The well-signed frame through the same helper is accepted, not refused.
    let mut ws = ws_connect(&s).await;
    let challenge = ws_json(&mut ws).await;
    ws_send(&mut ws, &auth_frame(&key(2), &addr(2), &[], None, challenge["nonce"].as_str().unwrap())).await;
    assert_eq!(ws_json(&mut ws).await["t"], "ok");
    s.stop().await;
}

#[tokio::test]
async fn at_most_32_unacknowledged_then_more_after_an_ack() {
    let s = hosted(Config::default()).await;
    publish_n(&s, 40).await;
    let (mut ws, _) = subscribe(&s, &key(2), &addr(2), &[], None).await;
    for i in 1..=32 {
        assert_eq!(ws_env(&mut ws).await.0, i);
    }
    // Nothing more until an ack.
    let more = tokio::time::timeout(Duration::from_millis(300), ws.next()).await;
    assert!(more.is_err(), "a 33rd frame arrived before any ack: {more:?}");
    ws_send(&mut ws, &serde_json::json!({"t": "ack", "cursor": 10})).await;
    for i in 33..=40 {
        assert_eq!(ws_env(&mut ws).await.0, i);
    }
    s.stop().await;
}

#[tokio::test]
async fn a_frame_that_breaks_the_protocol_closes_with_4002() {
    let s = hosted(Config::default()).await;
    publish_n(&s, 1).await;
    for bad in [
        Message::Text(r#"{"t":"ack","cursor":5}"#.into()),
        Message::Text(r#"{"t":"hello"}"#.into()),
        Message::Text(r#"{"t":"nack","cursor":1}"#.into()),
        Message::Binary(vec![0].into()),
    ] {
        let (mut ws, _) = subscribe(&s, &key(2), &addr(2), &[], None).await;
        assert_eq!(ws_env(&mut ws).await.0, 1);
        ws.send(bad).await.unwrap();
        assert_eq!(ws_json(&mut ws).await["error"], "bad-shape");
        assert_eq!(ws_close_code(&mut ws).await, 4002);
    }
    s.stop().await;
}

#[tokio::test]
async fn the_relay_pings_and_closes_a_silent_subscriber_with_4003() {
    let config = Config {
        ping_interval: Duration::from_millis(100),
        idle_timeout: Duration::from_millis(400),
        ..Config::default()
    };
    let s = hosted(config).await;
    // A subscriber that keeps reading answers the pings and stays open past the idle timeout.
    let (mut ws, _) = subscribe(&s, &key(2), &addr(2), &[], None).await;
    let mut pings = 0;
    let until = tokio::time::Instant::now() + Duration::from_millis(900);
    while let Ok(frame) = tokio::time::timeout_at(until, ws.next()).await {
        match frame.unwrap().unwrap() {
            Message::Ping(_) => pings += 1,
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(pings >= 3, "{pings} pings");
    // One that authenticates and then never sends a frame again, not even a pong, is closed for silence.
    let mut silent = RawWs::connect(s.addr).await;
    let challenge = silent.json().await;
    let nonce = challenge["nonce"].as_str().unwrap().to_owned();
    silent.send_text(&auth_frame(&key(2), &addr(2), &[], None, &nonce).to_string()).await;
    assert_eq!(silent.json().await["t"], "ok");
    assert_eq!(silent.close_code().await, 4003);
    // One that never sends its auth frame is closed too.
    let mut quiet = RawWs::connect(s.addr).await;
    assert_eq!(quiet.json().await["t"], "challenge");
    assert_eq!(quiet.close_code().await, 4003);
    s.stop().await;
}

#[tokio::test]
async fn shutdown_closes_subscribers_with_1001() {
    let s = hosted(Config::default()).await;
    let (mut ws, _) = subscribe(&s, &key(2), &addr(2), &[], None).await;
    let mut waiting = ws_connect(&s).await;
    assert_eq!(ws_json(&mut waiting).await["t"], "challenge");
    let stopping = tokio::spawn(s.stop());
    assert_eq!(ws_close_code(&mut ws).await, 1001);
    assert_eq!(ws_close_code(&mut waiting).await, 1001);
    stopping.await.unwrap();
}

#[tokio::test]
async fn two_recipients_of_one_envelope_each_get_it_with_their_own_cursor() {
    let s = hosted(Config::default()).await;
    s.host(3, Roots::Any, 65_536, 3_600, NOW).await;
    publish_n(&s, 1).await;
    let env = envelope(4, &[addr(2), addr(3)], vec![], NOW);
    let (mut two, _) = subscribe(&s, &key(2), &addr(2), &[], None).await;
    let (mut three, _) = subscribe(&s, &key(3), &addr(3), &[], None).await;
    assert_eq!(ws_env(&mut two).await.0, 1);
    assert_eq!(s.publish(&bytes(&env)).await.json()["delivered"], 2);
    assert_eq!(ws_env(&mut two).await, (2, env.id_hex()));
    assert_eq!(ws_env(&mut three).await, (1, env.id_hex()));
    s.stop().await;
}

/// No frame within 300 ms: the batch has stopped and waits for an ack.
async fn quiet(ws: &mut common::Ws) {
    let next = tokio::time::timeout(Duration::from_millis(300), ws.next()).await;
    assert!(next.is_err(), "no frame until an ack: {next:?}");
}

#[tokio::test]
async fn a_batch_stops_at_one_mib_of_envelopes_and_the_ack_sends_the_rest() {
    let s = Server::start(Config::default()).await;
    s.host(2, Roots::Any, 196_608, 3_600, NOW).await;
    let mut ids = Vec::new();
    for i in 0..7 {
        let env =
            Envelope::sign(&key(1), vec![addr(2)], vec![], NOW - i, sealed(&[addr(2)], 94_000)).unwrap();
        let size = bytes(&env).len();
        assert!((188_000..196_608).contains(&size), "{size} bytes");
        let r = s.publish(&bytes(&env)).await;
        assert_eq!(r.status, 200, "{}", r.text());
        ids.push(env.id_hex());
    }
    let (mut ws, _) = subscribe(&s, &key(2), &addr(2), &[], None).await;
    // Five rows are about 0.95 MiB; a sixth would pass 1 MiB, though the window of 32 has room.
    for (i, id) in ids.iter().take(5).enumerate() {
        assert_eq!(ws_env(&mut ws).await, (u64::try_from(i).unwrap() + 1, id.clone()));
    }
    quiet(&mut ws).await;
    ws_send(&mut ws, &serde_json::json!({"t": "ack", "cursor": 5})).await;
    assert_eq!(ws_env(&mut ws).await, (6, ids[5].clone()));
    assert_eq!(ws_env(&mut ws).await, (7, ids[6].clone()));
    s.stop().await;
}

#[tokio::test]
async fn a_row_over_the_batch_budget_is_still_sent_one_a_batch() {
    let s = hosted(Config { batch_bytes: 100, ..Config::default() }).await;
    let ids = publish_n(&s, 3).await;
    let (mut ws, _) = subscribe(&s, &key(2), &addr(2), &[], None).await;
    for (i, id) in ids.iter().enumerate() {
        let cursor = u64::try_from(i).unwrap() + 1;
        assert_eq!(ws_env(&mut ws).await, (cursor, id.clone()));
        quiet(&mut ws).await;
        ws_send(&mut ws, &serde_json::json!({"t": "ack", "cursor": cursor})).await;
    }
    s.stop().await;
}
