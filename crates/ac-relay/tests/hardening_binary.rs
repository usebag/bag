//! The binary's hardening flags. Each count and duration is at least 1 (0 is a
//! flag error, exit 2, naming the flag); `--idle-timeout` is at least twice `--ping-interval` (exit 2); each
//! flag takes effect; and a database whose schema is newer than the relay's makes it exit 1 with a line
//! naming the version. The binary is the one cargo builds for the tests, on port 0 on 127.0.0.1.

mod common;

use common::{PATIENCE, TempDir, accept, addr, bytes, envelope, read_url_line, record_bytes, request};
use std::io::Read as _;
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt as _;
use tokio::net::TcpStream;

const BIN: &str = env!("CARGO_BIN_EXE_ac-relay");

/// Every hardening flag, with a valid value.
const FLAGS: [(&str, &str); 12] = [
    ("--header-timeout", "10"),
    ("--body-timeout", "30"),
    ("--connections-per-ip", "64"),
    ("--rate-window", "60"),
    ("--rate-per-from", "120"),
    ("--rate-per-root", "1200"),
    ("--rate-per-ip", "600"),
    ("--fetch-per-ip", "6000"),
    ("--record-signers-per-day", "100"),
    ("--sweep-interval", "60"),
    ("--ping-interval", "30"),
    ("--idle-timeout", "60"),
];

/// Flags whose 0 turns them off, so that it is no error.
const OFF_AT_ZERO: [&str; 2] = ["--fetch-global-per-minute", "--bytes-per-ip-per-day"];

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn run(dir: &TempDir, args: &[&str]) -> std::process::Output {
    Command::new(BIN)
        .args(["--port", "0", "--db"])
        .arg(dir.path().join("relay.sqlite"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn l6_each_new_flag_at_zero_exits_2_naming_it() {
    let dir = TempDir::new("flags-zero");
    let mut refused = Vec::new();
    for (flag, _) in FLAGS {
        let out = run(&dir, &[flag, "0"]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{flag} 0: {stderr}");
        assert!(stderr.contains(flag) && stderr.contains("at least 1"), "{flag}: {stderr}");
        assert!(out.stdout.is_empty(), "{flag}: nothing on stdout");
        refused.push(flag);
    }
    eprintln!("MEASURE L6: {} new flags at 0, each exit 2 naming the flag: {refused:?}", refused.len());
    for (flag, bad) in [("--rate-per-ip", "4294967296"), ("--header-timeout", "x"), ("--rate-window", "-1")] {
        assert_eq!(run(&dir, &[flag, bad]).status.code(), Some(2), "{flag} {bad}");
    }
    let help = Command::new(BIN).arg("--help").output().unwrap();
    let help = String::from_utf8_lossy(&help.stdout);
    for flag in FLAGS.map(|(flag, _)| flag).into_iter().chain(OFF_AT_ZERO) {
        assert!(help.contains(flag), "--help names {flag}");
    }
    assert!(
        help.contains("--trust-proxy"),
        "the help says the per-address limits follow a trusted proxy's client"
    );
}

#[test]
fn l6_an_idle_timeout_under_twice_the_ping_interval_exits_2() {
    let dir = TempDir::new("flags-idle");
    let out = run(&dir, &["--ping-interval", "30", "--idle-timeout", "59"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    eprintln!("MEASURE L6: --ping-interval 30 --idle-timeout 59: exit {:?}", out.status.code());
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("--idle-timeout") && stderr.contains("twice --ping-interval"), "{stderr}");
}

/// The relay binary on port 0 with `args`; its stdout's URL line read.
struct Relay {
    child: Child,
    addr: SocketAddr,
}

impl Relay {
    fn spawn(dir: &TempDir, args: &[&str]) -> Relay {
        let mut child = Command::new(BIN)
            .args(["--port", "0", "--db"])
            .arg(dir.path().join("relay.sqlite"))
            .args(args)
            // Its stdin is a pipe the Child holds: it stops when this test process ends, however that ends.
            .arg("--exit-on-stdin-eof")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        // Its stderr is discarded (`Stdio::null()`): a failure here names the stdout wait and the exit only.
        let started = Instant::now();
        let (line, stdout) = match read_url_line(child.stdout.take().unwrap(), PATIENCE) {
            Ok(read) => read,
            Err(failure) => panic!("{}", failure.reap(&mut child, started.elapsed())),
        };
        child.stdout = Some(stdout);
        let port: u16 = line.trim_end().rsplit_once(':').and_then(|(_, p)| p.parse().ok()).unwrap();
        Relay { child, addr: SocketAddr::from(([127, 0, 0, 1], port)) }
    }
}

impl Drop for Relay {
    /// SIGTERM, so that the relay exits on its own (and an instrumented build writes its coverage), then
    /// SIGKILL after 5 s.
    fn drop(&mut self) {
        let _ = Command::new("kill").args(["-TERM", &self.child.id().to_string()]).status();
        for _ in 0..200 {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test]
async fn the_new_flags_take_effect() {
    let dir = TempDir::new("flags-effect");
    let relay = Relay::spawn(
        &dir,
        &[
            "--rate-per-ip",
            "5",
            "--rate-per-from",
            "1",
            "--record-signers-per-day",
            "1",
            "--header-timeout",
            "1",
            "--connections-per-ip",
            "4",
        ],
    );
    let t = now();
    let publish = |body: Vec<u8>| async move { request(relay.addr, "POST", "/v0/publish", &[], &body).await };
    let first = publish(record_bytes(&accept(2, ac_core::records::Roots::Any, 65_536, 3_600, t))).await;
    assert_eq!(first.status, 200, "{}", first.text());
    // --record-signers-per-day 1: a second new signer from this address today is 429.
    let second = publish(record_bytes(&accept(3, ac_core::records::Roots::Any, 65_536, 3_600, t))).await;
    assert_eq!(
        (second.status, second.error()),
        (429, "rate-limited".to_owned()),
        "--record-signers-per-day 1"
    );
    // --rate-per-from 1: the second envelope from one key in a window is 429.
    assert_eq!(publish(bytes(&envelope(1, &[addr(2)], vec![], t))).await.status, 200);
    let again = publish(bytes(&envelope(1, &[addr(2)], vec![], t - 1))).await;
    assert_eq!((again.status, again.error()), (429, "rate-limited".to_owned()), "--rate-per-from 1");
    // --rate-per-ip 5: the sixth publish from this address in a window is 429, whoever signed it.
    let other = publish(bytes(&envelope(4, &[addr(2)], vec![], t))).await;
    let sixth =
        if other.status == 200 { publish(bytes(&envelope(5, &[addr(2)], vec![], t))).await } else { other };
    assert_eq!((sixth.status, sixth.error()), (429, "rate-limited".to_owned()), "--rate-per-ip 5");
    // --header-timeout 1: a connection that sends nothing is closed after about a second.
    let mut idle = TcpStream::connect(relay.addr).await.unwrap();
    let started = Instant::now();
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(5), idle.read(&mut buf)).await.unwrap().unwrap_or(0);
    assert_eq!(n, 0);
    assert!(started.elapsed() >= Duration::from_millis(900) && started.elapsed() <= Duration::from_secs(3));
    // --connections-per-ip 4: a fifth connection from one address is closed at once.
    let mut open = Vec::new();
    for _ in 0..4 {
        open.push(TcpStream::connect(relay.addr).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut fifth = TcpStream::connect(relay.addr).await.unwrap();
    let n =
        tokio::time::timeout(Duration::from_millis(500), fifth.read(&mut buf)).await.unwrap().unwrap_or(0);
    assert_eq!(n, 0, "closed at once");
    drop((open, fifth, idle));
}

#[test]
fn l4_a_database_of_a_newer_schema_makes_the_relay_exit_1_naming_the_version() {
    let dir = TempDir::new("newer-schema");
    let path = dir.path().join("relay.sqlite");
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute_batch("CREATE TABLE envelopes (id TEXT PRIMARY KEY) STRICT;").unwrap();
    c.pragma_update(None, "user_version", 6).unwrap();
    drop(c);
    let mut child = Command::new(BIN)
        .args(["--port", "0", "--db"])
        .arg(&path)
        // Its stdin is a pipe the Child holds: it stops when this test process ends, however that ends.
        .arg("--exit-on-stdin-eof")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let status = child.wait().unwrap();
    let mut stderr = String::new();
    child.stderr.take().unwrap().read_to_string(&mut stderr).unwrap();
    let mut stdout = String::new();
    child.stdout.take().unwrap().read_to_string(&mut stdout).unwrap();
    eprintln!("MEASURE L4: a database at schema version 6: exit {:?}; {}", status.code(), stderr.trim());
    assert_eq!(status.code(), Some(1));
    assert!(
        stderr.contains("\"event\":\"fatal\"") && stderr.contains("version 6, newer than this relay's 5"),
        "{stderr}"
    );
    assert!(stdout.is_empty(), "no URL line: it never listened");
}
