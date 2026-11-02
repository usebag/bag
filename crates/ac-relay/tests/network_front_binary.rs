//! The binary's network front. L2 the log modes (prefix by default; full; none) change only the `ip`
//! field of every line that names a client; L3 the announced URL keeps `--advertise`'s port, names none for
//! https and health answers it; L1 (h) the proxy flags' errors exit 2; L4 `ac-relay probe` exits 0, 1 or 2;
//! the memory of a held subscription; a database restored to a new volume raises its cursors. The binary is
//! the one cargo builds for the tests, on 127.0.0.1 (or `::1`).
//!
//! Each relay runs on `--port 0`, so that no port is picked free and given back for another socket to take,
//! and the port it is used on is the one its `listening` line names; it is used only once its health answers,
//! and its log is read as it is written, so that a test waits for a line instead of sleeping.

mod common;

use ac_core::records::Roots;
use ac_relay::store::sqlite::RESTORE_CURSOR_GAP;
use common::{
    PATIENCE, POLL, TempDir, Ws, accept, addr, auth_frame, bytes, connect, envelope, exit_within, key,
    read_url_line, record_bytes, request, wait_healthy, ws_json, ws_send,
};
use futures_util::{SinkExt as _, StreamExt as _};
use std::io::{BufRead as _, BufReader};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio_tungstenite::tungstenite::Message;

const BIN: &str = env!("CARGO_BIN_EXE_ac-relay");

/// These tests one at a time: `freed_after_refusal` waits for a client's FIN, and on macOS a socket's close-on-exec is a
/// second call after `socket`, so a relay another test spawned between the two would hold the socket open and the FIN
/// would never come (`tests/stdout_closed.rs` has the measurement of the same gap in a pipe).
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// Whether a line of `log` has `event` as its event.
fn has_logged(log: &Mutex<Vec<String>>, event: &str) -> bool {
    log.lock()
        .unwrap()
        .iter()
        .any(|l| serde_json::from_str::<serde_json::Value>(l).is_ok_and(|v| v["fields"]["event"] == event))
}

/// Whether a `connection-closed` line with `held` 0 follows the first `subscribe-refused` line in `log`.
fn closed_after_refusal(log: &Mutex<Vec<String>>) -> bool {
    let lines = log.lock().unwrap();
    let fields = |l: &String| serde_json::from_str::<serde_json::Value>(l).ok().map(|v| v["fields"].clone());
    let refused = |l: &String| fields(l).is_some_and(|f| f["event"] == "subscribe-refused");
    let Some(at) = lines.iter().position(refused) else { return false };
    lines[at + 1..].iter().filter_map(fields).any(|f| f["event"] == "connection-closed" && f["held"] == 0)
}

/// A relay process: its port, its stdout line, and its stderr lines as it writes them (a thread reads them).
struct Relay {
    child: Child,
    port: u16,
    line: String,
    log: Arc<Mutex<Vec<String>>>,
    reader: JoinHandle<()>,
}

impl Relay {
    /// The relay with `args` on `--port 0`, once it has printed its URL line and logged `listening`, whose
    /// `port` is the one it is bound to. A relay that exits before its line fails the test with the relay's
    /// log, so that a test never goes on to talk to whatever holds a port.
    fn spawn(dir: &TempDir, name: &str, args: &[&str]) -> Relay {
        let mut child = Command::new(BIN)
            .args(["--port", "0", "--db"])
            .arg(dir.path().join(format!("{name}.sqlite")))
            .args(args)
            // Its stdin is a pipe the Child holds: it stops when this test process ends, however that ends.
            .arg("--exit-on-stdin-eof")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let (stderr, sink) = (child.stderr.take().unwrap(), Arc::clone(&log));
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                sink.lock().unwrap().push(line);
            }
        });
        let started = Instant::now();
        let (line, stdout) = match read_url_line(child.stdout.take().unwrap(), PATIENCE) {
            Ok(read) => read,
            Err(failure) => {
                let what = failure.reap(&mut child, started.elapsed());
                reader.join().unwrap();
                let said = log.lock().unwrap().join("\n");
                panic!("{what}; stderr:\n{said}");
            }
        };
        child.stdout = Some(stdout);
        let started = Instant::now();
        let port = loop {
            let listening = log.lock().unwrap().iter().find_map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).ok()?;
                if v["fields"]["event"] == "listening" { v["fields"]["port"].as_u64() } else { None }
            });
            if let Some(port) = listening {
                break u16::try_from(port).unwrap();
            }
            let died = child.try_wait().unwrap().is_some();
            if died || started.elapsed() >= PATIENCE {
                let waited = started.elapsed();
                let state = if died { "it has exited" } else { "it is still running" };
                let _ = child.kill();
                let _ = child.wait();
                reader.join().unwrap();
                let said = log.lock().unwrap().join("\n");
                panic!("no listening line after {waited:?}, {state}: {said}");
            }
            std::thread::sleep(POLL);
        };
        Relay { child, port, line, log, reader }
    }

    fn at(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.port))
    }

    /// Waits until the relay has logged a line whose event is `event`, for up to [`PATIENCE`].
    ///
    /// Takes `&mut self` so that a failure can kill the relay (`Child::kill` needs it) before it panics: the
    /// panic carries the stderr read so far, which a thread still reading may be a line short of.
    async fn logged(&mut self, event: &str) {
        let started = Instant::now();
        while !has_logged(&self.log, event) {
            if started.elapsed() >= PATIENCE {
                let _ = self.child.kill();
                let _ = self.child.wait();
                let said = self.log.lock().unwrap().join("\n");
                panic!("no {event} line within {PATIENCE:?}; stderr:\n{said}");
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// Waits until the relay has logged a `connection-closed` line with `held` 0 after its
    /// `subscribe-refused` line, for up to [`PATIENCE`]: the refused subscriber's place is free. As
    /// [`Relay::logged`], a failure kills the relay and panics with the stderr so far.
    async fn freed_after_refusal(&mut self) {
        let started = Instant::now();
        while !closed_after_refusal(&self.log) {
            if started.elapsed() >= PATIENCE {
                let _ = self.child.kill();
                let _ = self.child.wait();
                let said = self.log.lock().unwrap().join("\n");
                panic!("no connection-closed line with held 0 within {PATIENCE:?}; stderr:\n{said}");
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// SIGTERM, a clean exit, and the fields of every log line.
    fn stop(self) -> Vec<serde_json::Value> {
        let Relay { mut child, log, reader, .. } = self;
        let pid = child.id();
        let killed = Command::new("kill").args(["-TERM", &pid.to_string()]).status().unwrap();
        if !killed.success() {
            let _ = child.kill();
            let _ = child.wait();
            reader.join().unwrap();
            let said = log.lock().unwrap().join("\n");
            panic!("`kill -TERM {pid}` failed: {killed:?}; the relay was killed; stderr:\n{said}");
        }
        // The `stopped` line ends the drain (up to the relay's 5 s); the exit, the runtime's drop and an
        // instrumented build's profile write, is waited for after it, each within PATIENCE by the clock.
        let started = Instant::now();
        while !has_logged(&log, "stopped") && child.try_wait().unwrap().is_none() {
            if started.elapsed() >= PATIENCE {
                let _ = child.kill();
                let _ = child.wait();
                reader.join().unwrap();
                let said = log.lock().unwrap().join("\n");
                panic!("no stopped line within {PATIENCE:?} of SIGTERM; stderr:\n{said}");
            }
            std::thread::sleep(POLL);
        }
        let Some(status) = exit_within(&mut child, PATIENCE) else {
            let _ = child.kill();
            let _ = child.wait();
            reader.join().unwrap();
            let said = log.lock().unwrap().join("\n");
            panic!("no exit within {PATIENCE:?} of the stopped line; stderr:\n{said}");
        };
        reader.join().unwrap();
        let said = log.lock().unwrap().join("\n");
        assert!(status.success(), "the relay did not exit 0 after SIGTERM: {status:?}; stderr:\n{said}");
        assert!(has_logged(&log, "stopped"), "the relay exited with no stopped line; stderr:\n{said}");
        let lines = log.lock().unwrap();
        lines
            .iter()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .map(|v| v["fields"].clone())
            .collect()
    }
}

/// Subscribes to mailbox 2 as key 2, or with a broken signature: the first frame after the auth frame. The
/// socket is then closed and read until the relay has closed it too, which the relay does as it frees the
/// connection's place.
async fn subscribe(at: SocketAddr, broken: bool) -> serde_json::Value {
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{at}/v0/subscribe")).await.unwrap();
    let next = |m: Option<Result<Message, _>>| match m {
        Some(Ok(Message::Text(t))) => serde_json::from_str::<serde_json::Value>(t.as_str()).unwrap(),
        other => panic!("{other:?}"),
    };
    let challenge = next(ws.next().await);
    let mut frame = auth_frame(&key(2), &addr(2), &[], None, challenge["nonce"].as_str().unwrap());
    if broken {
        frame["sig"] = serde_json::json!("00".repeat(64));
    }
    ws.send(Message::Text(frame.to_string().into())).await.unwrap();
    let answer = next(ws.next().await);
    let _ = ws.close(None).await;
    let closed = tokio::time::timeout(PATIENCE, async { while let Some(Ok(_)) = ws.next().await {} }).await;
    assert!(closed.is_ok(), "the relay's close within {PATIENCE:?} of the subscriber's");
    answer
}

/// The first mail to mailbox 2 past cursor `after`, as a subscription of key 2 is sent it.
async fn frame_after(at: SocketAddr, after: u64) -> serde_json::Value {
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{at}/v0/subscribe")).await.unwrap();
    let next = |m: Option<Result<Message, _>>| match m {
        Some(Ok(Message::Text(t))) => serde_json::from_str::<serde_json::Value>(t.as_str()).unwrap(),
        other => panic!("{other:?}"),
    };
    let challenge = next(ws.next().await);
    let frame = auth_frame(&key(2), &addr(2), &[], Some(after), challenge["nonce"].as_str().unwrap());
    ws.send(Message::Text(frame.to_string().into())).await.unwrap();
    assert_eq!(next(ws.next().await)["t"], "ok");
    next(ws.next().await)
}

/// A database that reaches a new volume, as a restore lays it down: the first start logs the raise, the mail after it
/// takes a cursor past everything the copy issued, and the next start raises nothing.
#[tokio::test]
async fn a_database_on_a_new_volume_raises_its_cursors_on_that_boot_alone() {
    let _one = ONE_AT_A_TIME.lock().await;
    let (old, new) = (TempDir::new("restore-old"), TempDir::new("restore-new"));
    let t = now();
    let record = record_bytes(&accept(2, Roots::Any, 65_536, 3_600, t));
    let json = [("Content-Type", "application/json")];
    let first = Relay::spawn(&old, "relay", &[]);
    wait_healthy(first.at()).await;
    assert_eq!(request(first.at(), "POST", "/v0/publish", &json, &record).await.status, 200);
    let mail = bytes(&envelope(1, &[addr(2)], vec![], t - 1));
    assert_eq!(request(first.at(), "POST", "/v0/publish", &json, &mail).await.status, 200);
    let events = first.stop();
    assert!(!events.iter().any(|f| f["event"] == "cursors-raised"), "a first start raises nothing");
    std::fs::copy(old.path().join("relay.sqlite"), new.path().join("relay.sqlite")).unwrap();
    if old.path().join("relay.sqlite-wal").exists() {
        std::fs::copy(old.path().join("relay.sqlite-wal"), new.path().join("relay.sqlite-wal")).unwrap();
    }

    let second = Relay::spawn(&new, "relay", &[]);
    wait_healthy(second.at()).await;
    let after = bytes(&envelope(1, &[addr(2)], vec![], t - 2));
    assert_eq!(request(second.at(), "POST", "/v0/publish", &json, &after).await.status, 200);
    assert_eq!(frame_after(second.at(), 1).await["cursor"], 2 + RESTORE_CURSOR_GAP);
    let events = second.stop();
    let raised = events.iter().find(|f| f["event"] == "cursors-raised").expect("the raise is logged");
    assert_eq!((raised["mailboxes"].as_u64(), raised["by"].as_u64()), (Some(1), Some(RESTORE_CURSOR_GAP)));

    let third = Relay::spawn(&new, "relay", &[]);
    wait_healthy(third.at()).await;
    assert!(!third.stop().iter().any(|f| f["event"] == "cursors-raised"), "a restart raises nothing");
}

/// A subscription to mailbox 2 as key 2, held open.
async fn held_subscription(at: SocketAddr) -> Ws {
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{at}/v0/subscribe")).await.unwrap();
    let nonce = ws_json(&mut ws).await["nonce"].as_str().unwrap().to_owned();
    ws_send(&mut ws, &auth_frame(&key(2), &addr(2), &[], None, &nonce)).await;
    assert_eq!(ws_json(&mut ws).await["t"], "ok");
    ws
}

/// A process's resident memory in KiB, as `ps` reads it.
fn resident_kib(pid: u32) -> u64 {
    let read = Command::new("ps").args(["-o", "rss=", "-p", &pid.to_string()]).output().unwrap();
    String::from_utf8(read.stdout).unwrap().trim().parse().unwrap()
}

/// The dry run: with tungstenite's default read buffer each subscription cost the relay 138 to 140 KiB. The
/// growth is read over `MORE` subscriptions past the first `FIRST`, so that it leaves out what the relay allocates
/// once. The ceiling is half that read buffer, and this build is unoptimised.
#[tokio::test]
async fn a_held_subscription_costs_the_relay_a_small_part_of_tungstenite_s_default_read_buffer() {
    const FIRST: usize = 40;
    const MORE: usize = 200;
    const MOST_KIB: u64 = 64;
    let _one = ONE_AT_A_TIME.lock().await;
    let dir = TempDir::new("subscription-memory");
    let relay = Relay::spawn(&dir, "memory", &["--connections-per-ip", "1000"]);
    let at = relay.at();
    wait_healthy(at).await;
    let record = record_bytes(&accept(2, Roots::Any, 65_536, 3_600, now()));
    let json = [("Content-Type", "application/json")];
    assert_eq!(request(at, "POST", "/v0/publish", &json, &record).await.status, 200);
    let mut held = Vec::new();
    for _ in 0..FIRST {
        held.push(held_subscription(at).await);
    }
    let before = resident_kib(relay.child.id());
    for _ in 0..MORE {
        held.push(held_subscription(at).await);
    }
    let after = resident_kib(relay.child.id());
    let each = after.saturating_sub(before) / MORE as u64;
    eprintln!("MEASURE a held subscription: {before} KiB to {after} KiB over {MORE}, {each} KiB each");
    assert!(each < MOST_KIB, "{each} KiB a subscription, from {before} KiB to {after} KiB over {MORE}");
    drop(held);
    relay.stop();
}

const CLIENT_EVENTS: [&str; 7] = [
    "publish",
    "publish-record",
    "publish-refused",
    "rate-limited",
    "subscribe",
    "subscribe-refused",
    "connection-refused",
];

/// The same requests to a relay: a record, an envelope, bad JSON, the envelope twice more (the last over
/// --rate-per-ip 3), a subscribe and a refused one, then a connection over --connections-per-ip 2. Its client
/// lines.
async fn sequence(
    dir: &TempDir,
    name: &str,
    mode: &[&str],
    record: &[u8],
    env: &[u8],
) -> Vec<serde_json::Value> {
    // No reserve: at a cap of 2 it would leave one subscription, and two follow each other here.
    let mut args = vec!["--rate-window", "3600", "--rate-per-ip", "3", "--connections-per-ip", "2"];
    args.extend_from_slice(&["--connection-reserve-permille", "0"]);
    args.extend_from_slice(mode);
    let mut relay = Relay::spawn(dir, name, &args);
    let at = relay.at();
    wait_healthy(at).await;
    let json = [("Content-Type", "application/json")];
    assert_eq!(request(at, "POST", "/v0/publish", &json, record).await.status, 200);
    assert_eq!(request(at, "POST", "/v0/publish", &json, env).await.status, 200);
    assert_eq!(request(at, "POST", "/v0/publish", &json, b"{").await.status, 400);
    assert_eq!(request(at, "POST", "/v0/publish", &json, env).await.status, 200);
    assert_eq!(request(at, "POST", "/v0/publish", &json, env).await.status, 429);
    assert_eq!(subscribe(at, false).await["t"], "ok");
    assert_eq!(subscribe(at, true).await["error"], "bad-auth");
    // The relay frees a connection's place when the subscriber's task ends, after the FIN, so the subscriber
    // can see the close before the place is free; a probe that arrives early is refused and logged, which
    // would add a `connection-refused` line. The relay writes `connection-closed` after the place is free.
    // `held` is a point-in-time snapshot (another connection on the IP could change it), deterministic here
    // only because this test controls the concurrency at teardown: the one connection has just closed.
    relay.freed_after_refusal().await;
    let held = [connect(at).await, connect(at).await];
    // No sleep between them: the relay accepts in the order the connections were made and counts each as it
    // accepts it, so the third is refused after the two held, and a held connection logs nothing to wait on.
    let refused = connect(at).await;
    // The relay logs the refusal as it accepts the third connection; it is stopped only once that line is
    // written.
    relay.logged("connection-refused").await;
    drop((held, refused));
    let lines = relay.stop();
    let listening = &lines[0];
    assert_eq!(listening["event"], "listening");
    assert_eq!(listening["log_ip"], mode.get(1).copied().unwrap_or("prefix"), "{listening}");
    lines.into_iter().filter(|l| CLIENT_EVENTS.contains(&l["event"].as_str().unwrap_or(""))).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l2_the_log_names_a_client_by_its_prefix_by_default_and_the_mode_changes_nothing_else() {
    let _one = ONE_AT_A_TIME.lock().await;
    let dir = TempDir::new("log-modes");
    let t = now();
    let record = record_bytes(&accept(2, Roots::Any, 65_536, 3_600, t));
    let env = bytes(&envelope(1, &[addr(2)], vec![], t - 1));
    let prefix = sequence(&dir, "prefix", &[], &record, &env).await;
    let full = sequence(&dir, "full", &["--log-ip", "full"], &record, &env).await;
    let none = sequence(&dir, "none", &["--log-ip", "none"], &record, &env).await;
    let events: Vec<&str> = prefix.iter().map(|l| l["event"].as_str().unwrap()).collect();
    eprintln!("MEASURE L2: {} client lines a relay: {events:?}", prefix.len());
    for event in CLIENT_EVENTS {
        assert!(events.contains(&event), "{event} in {events:?}");
    }
    for (lines, ip) in [(&prefix, "127.0.0.0/24"), (&full, "127.0.0.1"), (&none, "-")] {
        assert!(lines.iter().all(|l| l["ip"] == ip), "{ip}: {lines:?}");
    }
    let without_ip = |lines: &[serde_json::Value]| -> Vec<serde_json::Value> {
        lines
            .iter()
            .map(|l| {
                // The second of the run aside: a rate window's Retry-After depends on it.
                let mut l = l.clone();
                l.as_object_mut().unwrap().remove("ip");
                l.as_object_mut().unwrap().remove("retry_after");
                l
            })
            .collect()
    };
    assert_eq!(without_ip(&prefix), without_ip(&full), "nothing but ip differs");
    assert_eq!(without_ip(&prefix), without_ip(&none));
    eprintln!(
        "MEASURE L2: prefix 127.0.0.0/24, full 127.0.0.1, none -, the other fields equal in {} lines",
        prefix.len()
    );
}

#[tokio::test]
async fn l2_an_ipv6_client_is_logged_by_its_48_and_a_trusted_proxy_s_client_by_its_own_prefix() {
    let _one = ONE_AT_A_TIME.lock().await;
    let dir = TempDir::new("log-v6");
    let t = now();
    let record = record_bytes(&accept(2, Roots::Any, 65_536, 3_600, t));
    // On a host without IPv6 loopback this fails rather than passing unread: a case that cannot run is not
    // run.
    let relay = Relay::spawn(&dir, "v6", &["--bind", "::1"]);
    let at = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), relay.port);
    wait_healthy(at).await;
    assert_eq!(request(at, "POST", "/v0/publish", &[], &record).await.status, 200);
    let lines = relay.stop();
    let published: Vec<_> = lines.iter().filter(|l| l["event"] == "publish-record").collect();
    eprintln!("MEASURE L2: a relay bound to ::1 logs its client ::1 as {}", published[0]["ip"]);
    assert_eq!(published[0]["ip"], "::/48");
    let relay = Relay::spawn(&dir, "proxied", &["--trust-proxy", "127.0.0.0/8"]);
    let at = relay.at();
    wait_healthy(at).await;
    let headers = [("cf-connecting-ip", "2001:db8:5:6::7")];
    assert_eq!(request(at, "POST", "/v0/publish", &headers, &record).await.status, 200);
    let lines = relay.stop();
    assert_eq!(lines[0]["trust_proxy"], "127.0.0.0/8");
    assert_eq!(lines[0]["client_ip_header"], "cf-connecting-ip");
    let published: Vec<_> = lines.iter().filter(|l| l["event"] == "publish-record").collect();
    eprintln!(
        "MEASURE L2: a client named 2001:db8:5:6::7 behind a trusted proxy is logged {}",
        published[0]["ip"]
    );
    assert_eq!(published[0]["ip"], "2001:db8:5::/48");
}

#[tokio::test]
async fn l3_the_announced_url_keeps_a_written_port_names_none_for_https_and_health_answers_it() {
    let _one = ONE_AT_A_TIME.lock().await;
    let dir = TempDir::new("advertise");
    for (advertise, want) in [
        (Some("https://relay.example"), "https://relay.example".to_owned()),
        (Some("https://relay.example:8443/"), "https://relay.example:8443".to_owned()),
        (Some("http://192.0.2.7:9"), "http://192.0.2.7:9".to_owned()),
        (Some("http://relay.example"), "http://relay.example:{port}".to_owned()),
        (None, "http://127.0.0.1:{port}".to_owned()),
    ] {
        let args: Vec<&str> = advertise.map_or_else(Vec::new, |a| vec!["--advertise", a]);
        let relay = Relay::spawn(&dir, "advertise", &args);
        let want = want.replace("{port}", &relay.port.to_string());
        let health = wait_healthy(relay.at()).await;
        let line = relay.line.clone();
        let lines = relay.stop();
        eprintln!(
            "MEASURE L3: --advertise {advertise:?}: {} and health url {}",
            line.trim(),
            health.json()["url"]
        );
        assert_eq!(line, format!("AC_RELAY_URL={want}\n"));
        assert_eq!(health.json()["url"], want.as_str());
        assert_eq!(lines[0]["url"], want.as_str());
    }
    for bad in ["https://relay.example:0", "https://relay.example:65536"] {
        let out =
            Command::new(BIN).args(["--advertise", bad, "--db"]).arg(dir.path().join("x.sqlite")).output();
        assert_eq!(out.unwrap().status.code(), Some(2), "{bad}");
    }
}

#[tokio::test]
async fn l1_the_proxy_and_log_flags_refuse_what_they_cannot_read_with_exit_2() {
    let _one = ONE_AT_A_TIME.lock().await;
    let dir = TempDir::new("front-flags");
    let db = dir.path().join("r.sqlite");
    let cases: [&[&str]; 7] = [
        &["--trust-proxy", "10.0.0.1/8"],
        &["--trust-proxy", "relay.example"],
        &["--trust-proxy", "10.0.0.0/33"],
        &["--client-ip-header", "x-real-ip"],
        &["--trust-proxy", "127.0.0.1", "--client-ip-header", "bad header"],
        &["--log-ip", "loud"],
        &["--log-ip", ""],
    ];
    for args in cases {
        let out = Command::new(BIN).args(args).arg("--db").arg(&db).output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(out.stdout.is_empty(), "{args:?}");
    }
    assert!(!db.exists(), "no database is opened on a flag error");
    // The last --log-ip wins, so a harness default can be overridden. The relay is stopped once it serves, so
    // that SIGTERM never comes before it has logged its listening line or can take the signal.
    let relay = Relay::spawn(&dir, "twice", &["--log-ip", "full", "--log-ip", "none"]);
    wait_healthy(relay.at()).await;
    assert_eq!(relay.stop()[0]["log_ip"], "none");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l4_ac_relay_probe_exits_0_with_the_id_1_naming_the_step_and_2_on_a_usage_error() {
    let _one = ONE_AT_A_TIME.lock().await;
    let dir = TempDir::new("probe-bin");
    let relay = Relay::spawn(&dir, "probed", &[]);
    wait_healthy(relay.at()).await;
    let file = dir.path().join("probe.key");
    let url = format!("http://127.0.0.1:{}", relay.port);
    let ok = Command::new(BIN).args(["probe", &url, "--key"]).arg(&file).output().unwrap();
    let stdout = String::from_utf8_lossy(&ok.stdout).into_owned();
    eprintln!("MEASURE L4: ac-relay probe: exit {:?}, {}", ok.status.code(), stdout.trim());
    // The probe writes its key file only after the relay's health has answered it, so its exit is read before
    // the file: a failure names the probe's step instead of a missing file.
    assert_eq!(ok.status.code(), Some(0), "{}", String::from_utf8_lossy(&ok.stderr));
    let seed = std::fs::read_to_string(&file).unwrap();
    let id = stdout.strip_prefix("probe ok ").and_then(|s| s.strip_suffix('\n')).unwrap();
    assert_eq!(id.len(), 64);
    assert!(!stdout.contains(seed.trim()) && ok.stderr.is_empty(), "the seed is never printed");
    relay.stop();
    let dead = Command::new(BIN).args(["probe", &url, "--key"]).arg(&file).output().unwrap();
    let stderr = String::from_utf8_lossy(&dead.stderr).into_owned();
    eprintln!("MEASURE L4: against no relay: exit {:?}, {}", dead.status.code(), stderr.trim());
    assert_eq!(dead.status.code(), Some(1));
    assert!(stderr.starts_with("probe: health: ") && dead.stdout.is_empty(), "{stderr}");
    for args in [&["probe"][..], &["probe", &url][..], &["probe", &url, "--key"][..]] {
        assert_eq!(Command::new(BIN).args(args).output().unwrap().status.code(), Some(2), "{args:?}");
    }
}
