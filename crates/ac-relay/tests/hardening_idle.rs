//! A subscriber that answers the relay's pings and sends nothing else is never closed as idle.
//! Before the fix a pong moved `heard` without ending the relay's wait, so the idle deadline stayed the one computed
//! before the last ping; with the idle timeout at twice the ping interval (the 30 s and 60 s defaults), the second
//! ping and that stale deadline fell due together and the relay closed 4003 at exactly 60 s about half the time
//! In-process relay on a real loopback socket (`common::Server`); the
//! subscriber is tokio-tungstenite, which answers each ping with a pong as it reads.

mod common;

use ac_core::chain::Hop;
use ac_core::envelope::Envelope;
use ac_core::records::Roots;
use ac_relay::Config;
use ac_relay::config::RateLimits;
use common::{NOW, RawWs, Server, Ws, addr, auth_frame, bytes, envelope, key, sealed, subscribe};
use futures_util::StreamExt as _;
use std::time::Duration;
use tokio::time::{Instant, sleep_until, timeout_at};
use tokio_tungstenite::tungstenite::Message;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

async fn hosted(ping: u64, idle: u64) -> Server {
    let config = Config { ping_interval: ms(ping), idle_timeout: ms(idle), ..Config::default() };
    let s = Server::start(config).await;
    s.host(2, Roots::Any, 65_536, 3_600, NOW).await;
    s
}

/// What a reading subscriber saw until `until`: the pings it answered, the `env` frames' cursors and when each
/// arrived, and the close, if the relay closed it.
#[derive(Debug, Default)]
struct Seen {
    pings: u32,
    envs: Vec<(u64, Duration)>,
    closed: Option<(String, Duration)>,
}

/// Reads (and so answers pings) until `until`, publishing `publish` at `publish_at` when given.
async fn read_until(
    ws: &mut Ws,
    s: &Server,
    started: Instant,
    until: Instant,
    publish: Option<(Instant, Vec<u8>)>,
) -> Seen {
    let mut seen = Seen::default();
    let mut publish = publish;
    loop {
        let publish_at = publish.as_ref().map_or(until, |(at, _)| *at);
        tokio::select! {
            frame = timeout_at(until, ws.next()) => match frame {
                Err(_) => return seen,
                Ok(Some(Ok(Message::Ping(_)))) => seen.pings += 1,
                Ok(Some(Ok(Message::Text(t)))) => {
                    let frame: serde_json::Value = serde_json::from_str(t.as_str()).unwrap();
                    assert_eq!(frame["t"], "env", "{frame}");
                    seen.envs.push((frame["cursor"].as_u64().unwrap(), started.elapsed()));
                }
                Ok(Some(Ok(Message::Close(c)))) => {
                    seen.closed = Some((format!("{c:?}"), started.elapsed()));
                    return seen;
                }
                Ok(other) => {
                    seen.closed = Some((format!("{other:?}"), started.elapsed()));
                    return seen;
                }
            },
            () = sleep_until(publish_at), if publish.is_some() => {
                let (_, body) = publish.take().unwrap();
                assert_eq!(s.publish(&body).await.status, 200);
            }
        }
    }
}

/// The brief's case (a): ping 50 ms, idle 120 ms; held 1 s, and an envelope published at 900 ms
/// arrives. This case also passes on the relay before the fix; (c) below is the one that tells them apart.
#[tokio::test]
async fn l8a_a_pong_only_subscriber_stays_a_second_and_gets_the_frame_published_at_900_ms() {
    let s = hosted(50, 120).await;
    let (mut ws, _) = subscribe(&s, &key(2), &addr(2), &[], None).await;
    let started = Instant::now();
    let body = bytes(&envelope(1, &[addr(2)], vec![], NOW));
    let seen = read_until(&mut ws, &s, started, started + ms(1_100), Some((started + ms(900), body))).await;
    eprintln!("MEASURE L8a: ping 50 ms, idle 120 ms, 1.1 s: {seen:?}");
    assert_eq!(seen.closed, None, "closed while it answered every ping");
    assert!((18..=22).contains(&seen.pings), "{} pings in 1.1 s", seen.pings);
    let [(cursor, at)] = seen.envs[..] else { panic!("one env frame: {:?}", seen.envs) };
    assert_eq!(cursor, 1);
    assert!(at >= ms(900) && at < ms(1_100), "the frame at {at:?}");
    s.stop().await;
}

/// Case (b): the idle timeout at exactly twice the ping interval, 20 sessions held 1 s, none closed.
#[tokio::test]
async fn l8b_twenty_pong_only_subscribers_at_twice_the_ping_interval_all_stay() {
    let s = hosted(50, 100).await;
    let mut sessions = Vec::new();
    for _ in 0..20 {
        sessions.push(subscribe(&s, &key(2), &addr(2), &[], None).await.0);
    }
    let started = Instant::now();
    let until = started + ms(1_000);
    let mut tasks = Vec::new();
    for mut ws in sessions {
        tasks.push(tokio::spawn(async move {
            let mut pings = 0u32;
            loop {
                match timeout_at(until, ws.next()).await {
                    Err(_) => return (pings, None),
                    Ok(Some(Ok(Message::Ping(_)))) => pings += 1,
                    Ok(other) => return (pings, Some(format!("{other:?} at {:?}", started.elapsed()))),
                }
            }
        }));
    }
    let mut closed = Vec::new();
    let mut pings = Vec::new();
    for task in tasks {
        let (n, close) = task.await.unwrap();
        pings.push(n);
        closed.extend(close);
    }
    eprintln!(
        "MEASURE L8b: ping 50 ms, idle 100 ms, 20 sessions for 1 s: {} closed {closed:?}; pings {pings:?}",
        closed.len()
    );
    assert!(closed.is_empty(), "{closed:?}");
    s.stop().await;
}

/// Case (c), the case that tells the fix from the relay before it: an idle timeout under twice the ping interval (a Config
/// the binary refuses, as a test may build it). Before the fix the pong at about 50 ms moved `heard` but not the deadline
/// computed before it, and the relay closed 4003 at 80 ms; now the pong renews it.
#[tokio::test]
async fn l8c_a_pong_renews_the_idle_deadline() {
    let s = hosted(50, 80).await;
    let (mut ws, _) = subscribe(&s, &key(2), &addr(2), &[], None).await;
    let started = Instant::now();
    let seen = read_until(&mut ws, &s, started, started + ms(1_000), None).await;
    eprintln!("MEASURE L8c: ping 50 ms, idle 80 ms, 1 s: {seen:?}");
    assert_eq!(seen.closed, None, "closed although every ping was answered");
    assert!(seen.pings >= 15, "{} pings", seen.pings);
    s.stop().await;
}

/// Case (d): a subscriber that sends nothing after its auth frame, not even a pong, is still closed 4003 at
/// the idle timeout.
#[tokio::test]
async fn l8d_a_silent_subscriber_is_still_closed_at_the_idle_timeout() {
    let s = hosted(50, 100).await;
    let mut silent = RawWs::connect(s.addr).await;
    let challenge = silent.json().await;
    let nonce = challenge["nonce"].as_str().unwrap().to_owned();
    silent.send_text(&auth_frame(&key(2), &addr(2), &[], None, &nonce).to_string()).await;
    assert_eq!(silent.json().await["t"], "ok");
    let after_ok = Instant::now();
    assert_eq!(silent.close_code().await, 4003);
    let at = after_ok.elapsed();
    eprintln!("MEASURE L8d: a silent subscriber at idle 100 ms closed 4003 {at:?} after its ok frame");
    assert!(at >= ms(90) && at <= ms(400), "closed {at:?} after ok");
    s.stop().await;
}

/// A relay holding more big envelopes for mailbox 2 than a loopback socket's buffers take, with no window to stop it
/// sending them, and a subscriber that takes its `ok` frame and then reads nothing.
async fn stuck_subscriber(config: Config, signer: u8, hops: &[Hop]) -> (Server, RawWs) {
    let rate = RateLimits {
        per_from: 100_000,
        per_root: 100_000,
        per_ip: 100_000,
        bytes_per_day: 0,
        ..RateLimits::default()
    };
    let s = Server::start(Config { max_unacked: 100_000, rate, ..config }).await;
    s.host(2, Roots::Any, 65_536, 3_600, NOW).await;
    for i in 0..300 {
        let to = [addr(2)];
        let env = Envelope::sign(&key(1), to.to_vec(), vec![], NOW - i, sealed(&to, 30_000)).unwrap();
        assert_eq!(s.publish(&bytes(&env)).await.status, 200);
    }
    let mut stuck = RawWs::connect(s.addr).await;
    let challenge = stuck.json().await;
    let nonce = challenge["nonce"].as_str().unwrap().to_owned();
    stuck.send_text(&auth_frame(&key(signer), &addr(2), hops, None, &nonce).to_string()).await;
    assert_eq!(stuck.json().await["t"], "ok");
    (s, stuck)
}

/// A session still held at the socket keeps the relay's stop waiting for its whole drain, 5 s; one that ended does not.
async fn stops_promptly(s: Server) {
    let started = Instant::now();
    s.stop().await;
    assert!(started.elapsed() < ms(2_000), "the stop waited {:?} on a stuck session", started.elapsed());
}

#[tokio::test]
async fn ld_2_a_subscriber_that_stops_reading_is_let_go_at_the_idle_timeout() {
    let config = Config { ping_interval: ms(50), idle_timeout: ms(200), ..Config::default() };
    let (s, stuck) = stuck_subscriber(config, 2, &[]).await;
    tokio::time::sleep(ms(1_500)).await;
    stops_promptly(s).await;
    drop(stuck);
}

#[tokio::test]
async fn ld_2_a_chain_that_ends_while_a_frame_waits_at_the_socket_ends_the_session() {
    let hop = Hop::sign(&key(2), &addr(20), vec![], NOW + 100).unwrap();
    let (s, stuck) = stuck_subscriber(Config::default(), 20, &[hop]).await;
    tokio::time::sleep(ms(200)).await;
    s.clock.advance(101);
    // Half a second to look at the clock, then at most a second each for the error frame and the close.
    tokio::time::sleep(ms(2_600)).await;
    stops_promptly(s).await;
    drop(stuck);
}
