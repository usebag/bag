//! A subscriber that answers the relay's pings and sends nothing else is never closed as idle.
//! Before the fix a pong moved `heard` without ending the relay's wait, so the idle deadline stayed the one computed
//! before the last ping; with the idle timeout at twice the ping interval (the 30 s and 60 s defaults), the second
//! ping and that stale deadline fell due together and the relay closed 4003 at exactly 60 s about half the time
//! In-process relay on a real loopback socket (`common::Server`); the
//! subscriber is tokio-tungstenite, which answers each ping with a pong as it reads.
//!
//! These cases measure real time, so a busy machine can starve them: `#[tokio::test]` is a current-thread runtime,
//! and the relay's sessions, the subscribers and a [`Watch`] share its one thread. A relay whose session is not
//! polled for about the idle timeout less the ping interval closes a healthy subscriber too (it writes the late ping
//! and finds the deadline passed), so a close is judged against the worst lateness the watch saw in the same hold:
//! under half that margin it fails the test at once; at or over it the hold cannot be judged and runs again with
//! every time in it (ping, idle, hold, publish) doubled, up to eight times as long, [`ATTEMPTS`] holds in all
//! ([`held`]). A relay that closes a pong-only subscriber closes it on every attempt, so it never passes. Every bound on a time is one the relay cannot pass however busy the machine (a close no earlier than the
//! idle timeout after the auth frame went, an env frame no earlier than its publish, at most one ping a period), or
//! one widened by the lateness measured.
//! (2026-11-27: l8b, l8c and l8d failed under a 1-minute load of 44 and 103 during bag 0.4.7's release, each a close
//! early by the test's own clock: l8b read none of its 20 sessions until all had subscribed, and l8d timed the close
//! from the `ok` frame's arrival, not from the auth frame's sending.)

mod common;

use ac_core::chain::Hop;
use ac_core::envelope::Envelope;
use ac_core::records::Roots;
use ac_relay::Config;
use ac_relay::config::RateLimits;
use common::{NOW, RawWs, Server, Ws, addr, auth_frame, bytes, envelope, key, sealed, subscribe};
use futures_util::StreamExt as _;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::time::{Instant, sleep_until, timeout, timeout_at};
use tokio_tungstenite::tungstenite::Message;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// How often the [`Watch`] looks at the clock.
const TICK: Duration = Duration::from_millis(2);

/// How many holds [`held`] runs before it gives up on a machine that starved every one.
const ATTEMPTS: u32 = 8;

/// The most [`held`] multiplies a case's times by.
const MOST_SCALE: u32 = 8;

async fn hosted(ping: u64, idle: u64) -> Server {
    let config = Config { ping_interval: ms(ping), idle_timeout: ms(idle), ..Config::default() };
    let s = Server::start(config).await;
    s.host(2, Roots::Any, 65_536, 3_600, NOW).await;
    s
}

/// The test runtime's worst lateness: a task that sleeps [`TICK`] at a time and keeps the most any wake came after
/// its due time. On the current-thread runtime of `#[tokio::test]` a relay timer is late by about as much.
struct Watch {
    worst_us: Arc<AtomicU64>,
    task: tokio::task::JoinHandle<()>,
}

impl Watch {
    fn start() -> Watch {
        let worst_us = Arc::new(AtomicU64::new(0));
        let worst = Arc::clone(&worst_us);
        let task = tokio::spawn(async move {
            loop {
                let due = Instant::now() + TICK;
                sleep_until(due).await;
                worst.fetch_max(
                    u64::try_from(due.elapsed().as_micros()).unwrap_or(u64::MAX),
                    Ordering::Relaxed,
                );
            }
        });
        Watch { worst_us, task }
    }

    fn worst(&self) -> Duration {
        Duration::from_micros(self.worst_us.load(Ordering::Relaxed))
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// One hold: the closes the relay made (none for a pass), the watch's worst lateness, what the case saw, and (set
/// by [`held`]) the factor its times were multiplied by.
struct Hold<T> {
    closes: Vec<String>,
    worst: Duration,
    seen: T,
    scale: u32,
}

/// Runs `attempt(scale)`, a hold with every time multiplied by `scale`, until a hold ends with no close, and returns
/// it. `margin` is how long the relay's session may go unpolled at scale 1 before a healthy relay closes the
/// subscriber too (the idle timeout less the ping interval): a close with the runtime late by less than half the
/// scaled margin fails at once; one at or over half cannot be judged and the hold runs again at twice the scale, up to
/// [`MOST_SCALE`], [`ATTEMPTS`] holds in all.
async fn held<T, F, Fut>(name: &str, margin: Duration, mut attempt: F) -> Hold<T>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = Hold<T>>,
{
    let mut starved = Vec::new();
    for n in 0..ATTEMPTS {
        let scale = (1 << n.min(3)).min(MOST_SCALE);
        let margin = margin * scale;
        let mut hold = attempt(scale).await;
        hold.scale = scale;
        if hold.closes.is_empty() {
            eprintln!(
                "MEASURE {name}: held at scale {scale}, worst lateness {:?}, after {} starved: {starved:?}",
                hold.worst,
                starved.len()
            );
            return hold;
        }
        assert!(
            hold.worst >= margin / 2,
            "{name}: closed {:?} with the runtime at most {:?} late (margin {margin:?})",
            hold.closes,
            hold.worst
        );
        starved.push(format!("scale {scale}: {:?} at worst lateness {:?}", hold.closes, hold.worst));
    }
    panic!("{name}: the machine starved every one of {ATTEMPTS} holds: {starved:?}");
}

/// The fewest pings a relay pinging every `period` writes in `hold` when its timers are at most `worst` late: each
/// next ping is due a period after the last one went, so the lateness of each adds to the gap.
fn fewest_pings(hold: Duration, period: Duration, worst: Duration) -> u32 {
    let gap = period + worst + ms(2);
    u32::try_from(hold.as_micros() / gap.as_micros()).unwrap_or(u32::MAX).saturating_sub(2)
}

/// The most pings a reader can see in `hold`: one a period at most, and one written before the hold began.
fn most_pings(hold: Duration, period: Duration) -> u32 {
    u32::try_from(hold.as_micros() / period.as_micros()).unwrap_or(u32::MAX) + 2
}

/// What a reading subscriber saw until `until`: the pings it answered, the `env` frames' cursors and when each
/// arrived, and the close, if the relay closed it.
#[derive(Debug, Default)]
struct Seen {
    pings: u32,
    envs: Vec<(u64, Duration)>,
    closed: Option<(String, Duration)>,
}

impl Seen {
    fn closes(&self) -> Vec<String> {
        self.closed.iter().map(|(c, at)| format!("{c} at {at:?}")).collect()
    }
}

/// Reads (and so answers pings) until `until`, publishing `publish` at `publish_at` when given; with `first_env`,
/// it returns at the first `env` frame instead.
async fn read_until(
    ws: &mut Ws,
    s: &Server,
    started: Instant,
    until: Instant,
    publish: Option<(Instant, Vec<u8>)>,
    first_env: bool,
) -> Seen {
    let mut seen = Seen::default();
    let mut publish = publish;
    loop {
        if first_env && !seen.envs.is_empty() {
            return seen;
        }
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

/// The brief's case (a): ping 50 ms, idle 120 ms; held 1.1 s, and an envelope published at 900 ms
/// arrives. This case also passes on the relay before the fix; (c) below is the one that tells them apart.
#[tokio::test]
async fn l8a_a_pong_only_subscriber_stays_a_second_and_gets_the_frame_published_at_900_ms() {
    let h = held("L8a", ms(120 - 50), |k| async move {
        let watch = Watch::start();
        let s = hosted(50 * u64::from(k), 120 * u64::from(k)).await;
        let (mut ws, _) = subscribe(&s, &key(2), &addr(2), &[], None).await;
        let started = Instant::now();
        let body = bytes(&envelope(1, &[addr(2)], vec![], NOW));
        let (hold, publish_at) = (ms(1_100) * k, started + ms(900) * k);
        let mut seen =
            read_until(&mut ws, &s, started, started + hold, Some((publish_at, body)), false).await;
        if seen.closed.is_none() && seen.envs.is_empty() {
            // A starved relay may deliver after the hold: the frame must still come, on the same live session.
            let late = read_until(&mut ws, &s, started, Instant::now() + ms(5_000), None, true).await;
            (seen.envs, seen.closed) = (late.envs, late.closed);
        }
        s.stop().await;
        Hold { closes: seen.closes(), worst: watch.worst(), seen, scale: k }
    })
    .await;
    let (seen, k) = (h.seen, h.scale);
    let (period, hold) = (ms(50) * k, ms(1_100) * k);
    eprintln!(
        "MEASURE L8a: ping {period:?}, idle {:?}, {hold:?}: {seen:?}, worst lateness {:?}",
        ms(120) * k,
        h.worst
    );
    let (fewest, most) = (fewest_pings(hold, period, h.worst), most_pings(hold, period));
    assert!(
        (fewest..=most).contains(&seen.pings),
        "{} pings in {hold:?}, not {fewest} to {most}",
        seen.pings
    );
    let [(cursor, at)] = seen.envs[..] else { panic!("one env frame: {:?}", seen.envs) };
    assert_eq!(cursor, 1);
    assert!(at >= ms(900) * k, "the frame at {at:?}, before its publish");
}

/// Case (b): the idle timeout at exactly twice the ping interval, 20 sessions held 1.5 s each, none closed. Each
/// session is read from the moment it subscribes, as a client does.
#[tokio::test]
async fn l8b_twenty_pong_only_subscribers_at_twice_the_ping_interval_all_stay() {
    let h = held("L8b", ms(200 - 100), |k| async move {
        let watch = Watch::start();
        let s = hosted(100 * u64::from(k), 200 * u64::from(k)).await;
        let hold = ms(1_500) * k;
        let mut tasks = Vec::new();
        for _ in 0..20 {
            let mut ws = subscribe(&s, &key(2), &addr(2), &[], None).await.0;
            let started = Instant::now();
            tasks.push(tokio::spawn(async move {
                let mut pings = 0u32;
                loop {
                    match timeout_at(started + hold, ws.next()).await {
                        Err(_) => return (pings, None),
                        Ok(Some(Ok(Message::Ping(_)))) => pings += 1,
                        Ok(other) => return (pings, Some(format!("{other:?} at {:?}", started.elapsed()))),
                    }
                }
            }));
        }
        let (mut closes, mut pings) = (Vec::new(), Vec::new());
        for task in tasks {
            let (n, close) = task.await.unwrap();
            pings.push(n);
            closes.extend(close);
        }
        s.stop().await;
        Hold { closes, worst: watch.worst(), seen: pings, scale: k }
    })
    .await;
    let k = h.scale;
    eprintln!(
        "MEASURE L8b: ping {:?}, idle {:?}, 20 sessions for {:?}: pings {:?}",
        ms(100) * k,
        ms(200) * k,
        ms(1_500) * k,
        h.seen
    );
}

/// Case (c), the case that tells the fix from the relay before it: an idle timeout under twice the ping interval (a Config
/// the binary refuses, as a test may build it). Before the fix the pong at about 100 ms moved `heard` but not the
/// deadline computed before it, and the relay closed 4003 at 180 ms; now the pong renews it.
#[tokio::test]
async fn l8c_a_pong_renews_the_idle_deadline() {
    let h = held("L8c", ms(180 - 100), |k| async move {
        let watch = Watch::start();
        let s = hosted(100 * u64::from(k), 180 * u64::from(k)).await;
        let (mut ws, _) = subscribe(&s, &key(2), &addr(2), &[], None).await;
        let started = Instant::now();
        let seen = read_until(&mut ws, &s, started, started + ms(1_500) * k, None, false).await;
        s.stop().await;
        Hold { closes: seen.closes(), worst: watch.worst(), seen, scale: k }
    })
    .await;
    let (period, hold) = (ms(100) * h.scale, ms(1_500) * h.scale);
    eprintln!(
        "MEASURE L8c: ping {period:?}, idle {:?}, {hold:?}: {:?}, worst lateness {:?}",
        ms(180) * h.scale,
        h.seen,
        h.worst
    );
    let fewest = fewest_pings(hold, period, h.worst);
    assert!(h.seen.pings >= fewest.max(2), "{} pings, under {fewest}", h.seen.pings);
}

/// Case (d): a subscriber that sends nothing after its auth frame, not even a pong, is still closed 4003 at
/// the idle timeout: never before it, counted from when the auth frame went (the relay's silence starts no earlier
/// than its arrival), and at most 300 ms after it plus the lateness measured.
#[tokio::test]
async fn l8d_a_silent_subscriber_is_still_closed_at_the_idle_timeout() {
    let watch = Watch::start();
    let s = hosted(50, 100).await;
    let mut silent = RawWs::connect(s.addr).await;
    let challenge = silent.json().await;
    let nonce = challenge["nonce"].as_str().unwrap().to_owned();
    let auth = auth_frame(&key(2), &addr(2), &[], None, &nonce).to_string();
    let sent = Instant::now();
    silent.send_text(&auth).await;
    assert_eq!(silent.json().await["t"], "ok");
    let code =
        timeout(ms(100 + 5_000), silent.close_code()).await.expect("a close within 5 s of the idle timeout");
    let (at, worst) = (sent.elapsed(), watch.worst());
    eprintln!(
        "MEASURE L8d: a silent subscriber at idle 100 ms closed {code} {at:?} after its auth frame went, worst lateness {worst:?}"
    );
    assert_eq!(code, 4003);
    assert!(at >= ms(100), "closed {at:?} after the auth frame went, before the idle timeout");
    assert!(
        at <= ms(100 + 300) + worst,
        "closed {at:?} after the auth frame went, the runtime at most {worst:?} late"
    );
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
