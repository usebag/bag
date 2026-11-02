//! `--exit-on-stdin-eof`: the relay stops gracefully, as on SIGTERM (exit 0, a `stopped` log line), when its
//! stdin reaches its end, so that a relay a test or the e2e harness spawned with a pipe on its stdin does not
//! outlive the process that holds the pipe's other end, however that process ends. Without the flag stdin is
//! never read.

mod common;

use common::{PATIENCE, TempDir, read_url_line};
use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_ac-relay");

/// A spawned relay and its port, killed on drop if it is still running, so that a failed assertion leaves no
/// relay behind.
struct Relay {
    child: Child,
    port: u16,
}

impl Drop for Relay {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Every process this file starts, one at a time: on macOS a pipe's close-on-exec is a second call after `pipe`, so a
/// child spawned between the two would inherit the write end of another relay's stdin, which then never ends
/// (`tests/stdout_closed.rs` has the measurement). Held around the spawn, where the pipes are made.
fn one_spawn() -> MutexGuard<'static, ()> {
    static SPAWN: Mutex<()> = Mutex::new(());
    SPAWN.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The relay on port 0 with `extra` and `stdin`, once it has printed its URL line; its stderr in the panic
/// message when the first line is not that line (a binary from before the flag exits 2 and prints nothing on
/// stdout). No line within `PATIENCE`, a read error and an early end of stdout kill the relay and panic the
/// same way.
fn spawn(dir: &TempDir, extra: &[&str], stdin: Stdio) -> Relay {
    let spawning = one_spawn();
    let mut child = Command::new(BIN)
        .args(["--port", "0", "--db"])
        .arg(dir.path().join("relay.sqlite"))
        .args(extra)
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(spawning);
    let started = Instant::now();
    let (line, stdout) = match read_url_line(child.stdout.take().unwrap(), PATIENCE) {
        Ok(read) => read,
        Err(failure) => {
            let what = failure.reap(&mut child, started.elapsed());
            let mut log = String::new();
            let _ = child.stderr.take().unwrap().read_to_string(&mut log);
            panic!("{what}; stderr: {log}");
        }
    };
    let port = line.trim_end().strip_prefix("AC_RELAY_URL=http://127.0.0.1:").and_then(|p| p.parse().ok());
    let Some(port) = port else {
        let _ = child.kill();
        let _ = child.wait();
        let mut log = String::new();
        let _ = child.stderr.take().unwrap().read_to_string(&mut log);
        panic!("first line {line:?}; stderr: {log}");
    };
    child.stdout = Some(stdout);
    Relay { child, port }
}

/// The status of GET /v0/health, asked over a fresh connection (0 when the relay does not answer one).
fn health(relay: &Relay) -> u16 {
    let Ok(mut socket) = TcpStream::connect(("127.0.0.1", relay.port)) else { return 0 };
    let _ = socket.set_read_timeout(Some(Duration::from_secs(5)));
    let asked = socket.write_all(b"GET /v0/health HTTP/1.1\r\nhost: 127.0.0.1\r\nconnection: close\r\n\r\n");
    let mut reply = String::new();
    if asked.is_err() || socket.read_to_string(&mut reply).is_err() {
        return 0;
    }
    reply.get(9..12).and_then(|code| code.parse().ok()).unwrap_or(0)
}

/// The relay's exit status once it has exited, or None if it is still running after `within`.
fn exited(relay: &mut Relay, within: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + within;
    loop {
        if let Some(status) = relay.child.try_wait().unwrap() {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// The fields of each JSON log line the relay wrote to stderr, read once it has exited.
fn fields(relay: &mut Relay) -> Vec<serde_json::Value> {
    let mut log = String::new();
    relay.child.stderr.take().unwrap().read_to_string(&mut log).unwrap();
    log.lines()
        .map(|l| {
            let line: serde_json::Value = serde_json::from_str(l).unwrap_or_else(|e| panic!("{e}: {l}"));
            line["fields"].clone()
        })
        .collect()
}

fn events(fields: &[serde_json::Value]) -> Vec<&str> {
    fields.iter().map(|f| f["event"].as_str().unwrap_or_default()).collect()
}

/// The clean stop: exit 0, the `listening` line first, `stopped` last, and one `stdin-eof` line between them;
/// returns that line's `read`, how the read of stdin ended.
fn assert_stopped_at_eof(relay: &mut Relay, within: Duration) -> String {
    let status = exited(relay, within);
    let status = status.unwrap_or_else(|| panic!("no exit within {within:?} of the end of stdin"));
    assert_eq!(status.code(), Some(0), "{status:?}");
    let fields = fields(relay);
    let events = events(&fields);
    assert_eq!(events.first(), Some(&"listening"), "{events:?}");
    assert_eq!(events.last(), Some(&"stopped"), "{events:?}");
    let eof: Vec<_> = fields.iter().filter(|f| f["event"] == "stdin-eof").collect();
    assert_eq!(eof.len(), 1, "{events:?}");
    eof[0]["read"].as_str().unwrap_or_default().to_owned()
}

#[test]
fn with_the_flag_closing_stdin_stops_it_gracefully_and_bytes_before_do_not() {
    let dir = TempDir::new("stdin-eof");
    let mut relay = spawn(&dir, &["--exit-on-stdin-eof"], Stdio::piped());
    let mut stdin = relay.child.stdin.take().unwrap();
    stdin.write_all(b"anything at all\n").unwrap();
    stdin.flush().unwrap();
    let early = exited(&mut relay, Duration::from_millis(500));
    assert!(early.is_none(), "bytes on stdin are read and discarded: {early:?}");
    assert_eq!(health(&relay), 200, "still serving, no drain begun, after the bytes");
    let closed = Instant::now();
    drop(stdin);
    assert_eq!(assert_stopped_at_eof(&mut relay, Duration::from_secs(5)), "eof");
    eprintln!("MEASURE stdin-eof: exit 0 with a stopped line {:?} after stdin closed", closed.elapsed());
}

#[test]
fn with_the_flag_and_no_stdin_it_announces_and_stops_at_once() {
    // A stdin already at its end (the harness's old 'ignore', /dev/null): the URL line is still printed,
    // since the stop is awaited only once the relay serves, and then it stops as at any end of stdin.
    let dir = TempDir::new("stdin-null");
    let mut relay = spawn(&dir, &["--exit-on-stdin-eof"], Stdio::null());
    assert_eq!(assert_stopped_at_eof(&mut relay, Duration::from_secs(5)), "eof");
}

#[test]
fn with_the_flag_a_stdin_that_fails_to_read_stops_it_the_same_way_naming_the_error() {
    // A directory opened as stdin: the first read fails (EISDIR), and the relay stops as at the end of stdin,
    // its `stdin-eof` line naming the error in place of `eof`.
    let dir = TempDir::new("stdin-dir");
    let stdin = std::fs::File::open(dir.path()).unwrap();
    let mut relay = spawn(&dir, &["--exit-on-stdin-eof"], Stdio::from(stdin));
    let read = assert_stopped_at_eof(&mut relay, Duration::from_secs(5));
    assert!(read.contains("os error"), "{read:?}");
}

#[test]
fn without_the_flag_closing_stdin_does_not_stop_it() {
    let dir = TempDir::new("stdin-control");
    let mut relay = spawn(&dir, &[], Stdio::piped());
    drop(relay.child.stdin.take());
    assert!(exited(&mut relay, Duration::from_secs(2)).is_none(), "without the flag stdin is not read");
    assert_eq!(health(&relay), 200, "still serving, no drain begun, 2 s after stdin closed");
    let spawning = one_spawn();
    let term = Command::new("kill").args(["-TERM", &relay.child.id().to_string()]).status().unwrap();
    drop(spawning);
    assert!(term.success());
    let status = exited(&mut relay, Duration::from_secs(5)).expect("an exit within 5 s of SIGTERM");
    assert_eq!(status.code(), Some(0), "{status:?}");
    let fields = fields(&mut relay);
    let events = events(&fields);
    assert_eq!(events.last(), Some(&"stopped"), "{events:?}");
    assert!(!events.contains(&"stdin-eof"), "{events:?}");
}

#[test]
fn the_help_names_the_flag() {
    let spawning = one_spawn();
    let help = Command::new(BIN).arg("--help").output().unwrap();
    drop(spawning);
    assert!(help.status.success());
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(help.contains("--exit-on-stdin-eof") && help.contains("SIGTTIN"), "{help}");
}
