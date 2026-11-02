//! A subscription under a chain ends once the relay's clock is
//! past the chain's earliest `exp`. No `env` frame is sent after it; the relay sends `{"t":"error","error":
//! "hop-expired"}` and closes with 4001 within half a second (it looks before each frame and every 500 ms). Before
//! the fix the chain was checked once, at the challenge, and M3 measured `env` frames 3 s and 6 s after `exp`.
//! In-process relay on a real loopback socket on a `ManualClock` (`common::Server`).

mod common;

use ac_core::chain::Hop;
use ac_core::records::Roots;
use ac_relay::Config;
use common::{NOW, Server, Ws, addr, bytes, envelope, key, subscribe, ws_json};
use futures_util::StreamExt as _;
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;

async fn hosted() -> Server {
    let s = Server::start(Config::default()).await;
    s.host(2, Roots::Any, 65_536, 3_600, NOW).await;
    s
}

/// A session key, `key(30)`, delegated by the mailbox key until `exp`.
fn session(exp: u64) -> Vec<Hop> {
    vec![Hop::sign(&key(2), &addr(30), vec![], exp).unwrap()]
}

/// The frames until the relay closes the socket (pings skipped), and the close code; panics after 5 s.
async fn until_closed(ws: &mut Ws) -> (Vec<serde_json::Value>, Option<u16>) {
    let mut texts = Vec::new();
    loop {
        let frame =
            tokio::time::timeout(Duration::from_secs(5), ws.next()).await.expect("a close within 5 s");
        match frame {
            Some(Ok(Message::Text(t))) => texts.push(serde_json::from_str(t.as_str()).unwrap()),
            Some(Ok(Message::Close(c))) => return (texts, c.map(|c| u16::from(c.code))),
            Some(Ok(_)) => {}
            Some(Err(_)) | None => return (texts, None),
        }
    }
}

#[tokio::test]
async fn l2_a_subscription_ends_with_hop_expired_and_4001_within_a_second_of_its_exp() {
    let s = hosted().await;
    let exp = NOW + 10;
    let (mut ws, _) = subscribe(&s, &key(30), &addr(2), &session(exp), None).await;
    assert_eq!(s.publish(&bytes(&envelope(1, &[addr(2)], vec![], NOW))).await.status, 200);
    assert_eq!(ws_json(&mut ws).await["t"], "env");
    // At exp the chain is still valid: delivered.
    s.clock.set(exp);
    assert_eq!(s.publish(&bytes(&envelope(1, &[addr(2)], vec![], exp))).await.status, 200);
    let at_exp = ws_json(&mut ws).await;
    assert_eq!((at_exp["t"].as_str(), at_exp["cursor"].as_u64()), (Some("env"), Some(2)));
    // One second past it, with nothing published: the relay's own check ends it.
    s.clock.set(exp + 1);
    let set = Instant::now();
    let (texts, close) = until_closed(&mut ws).await;
    let took = set.elapsed();
    eprintln!("MEASURE L2: clock set past exp; frames {texts:?}, close {close:?}, {took:?} later");
    assert_eq!(texts, vec![serde_json::json!({"t": "error", "error": "hop-expired"})]);
    assert_eq!(close, Some(4001));
    assert!(took <= Duration::from_secs(1), "{took:?}");
    s.stop().await;
}

#[tokio::test]
async fn l2_no_env_frame_is_sent_after_exp_even_when_mail_arrives_first() {
    let s = hosted().await;
    let exp = NOW + 10;
    let (mut ws, _) = subscribe(&s, &key(30), &addr(2), &session(exp), None).await;
    s.clock.set(exp + 1);
    // Mail arrives before the relay's next look at the clock: it is not sent, the error frame is.
    assert_eq!(s.publish(&bytes(&envelope(1, &[addr(2)], vec![], exp + 1))).await.status, 200);
    let (texts, close) = until_closed(&mut ws).await;
    assert_eq!(texts, vec![serde_json::json!({"t": "error", "error": "hop-expired"})]);
    assert_eq!(close, Some(4001));
    s.stop().await;
}

/// M3 again: a 5-second chain, mail published 3 s and 6 s after `exp`: none of it reaches the expired subscription.
#[tokio::test]
async fn m3_again_no_frame_after_exp() {
    let s = hosted().await;
    let exp = NOW + 5;
    let (mut ws, _) = subscribe(&s, &key(30), &addr(2), &session(exp), None).await;
    let mut after_exp = Vec::new();
    for later in [3, 6] {
        s.clock.set(exp + later);
        assert_eq!(s.publish(&bytes(&envelope(1, &[addr(2)], vec![], exp + later))).await.status, 200);
    }
    let (texts, close) = until_closed(&mut ws).await;
    after_exp.extend(texts.iter().filter(|t| t["t"] == "env").cloned());
    eprintln!(
        "MEASURE M3 again: env frames after exp: {}; frames {texts:?}, close {close:?}",
        after_exp.len()
    );
    assert!(after_exp.is_empty());
    assert_eq!(close, Some(4001));
    // The same chain is refused at a new handshake: hop-expired, 4001 (unchanged).
    let mut again = common::ws_connect(&s).await;
    let challenge = ws_json(&mut again).await;
    let frame =
        common::auth_frame(&key(30), &addr(2), &session(exp), None, challenge["nonce"].as_str().unwrap());
    common::ws_send(&mut again, &frame).await;
    assert_eq!(ws_json(&mut again).await["error"], "hop-expired");
    assert_eq!(common::ws_close_code(&mut again).await, 4001);
    s.stop().await;
}

#[tokio::test]
async fn the_mailbox_key_itself_has_no_chain_to_expire() {
    let s = hosted().await;
    let (mut ws, _) = subscribe(&s, &key(2), &addr(2), &[], None).await;
    s.clock.advance(30 * 86_400);
    tokio::time::sleep(Duration::from_millis(700)).await;
    let ts = NOW + 30 * 86_400;
    assert_eq!(s.publish(&bytes(&envelope(1, &[addr(2)], vec![], ts))).await.status, 200);
    assert_eq!(ws_json(&mut ws).await["t"], "env");
    s.stop().await;
}
