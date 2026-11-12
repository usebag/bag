//! The `ac-relay` binary as a process: the one URL line on stdout, the API through it, JSON logs on stderr
//! with no envelope bytes, a graceful SIGTERM, the flag errors, the bind address with the URL it
//! announces, and the bases a fetch proof may name (that URL and each `--accept-base`).

mod common;

use ac_core::records::Roots;
use common::{
    PATIENCE, Tail, TempDir, accept, addr, bytes, envelope, exit_within, read_url_line, record_bytes, request,
};
use std::io::Read as _;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const BIN: &str = env!("CARGO_BIN_EXE_ac-relay");

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

struct Relay {
    child: Child,
    /// 127.0.0.1 and the port: where a relay bound to 127.0.0.1 or 0.0.0.0 is reached.
    addr: SocketAddr,
    port: u16,
    line: String,
    /// Its stderr, read as it writes it.
    log: Tail,
}

/// The relay on `--port 0`. `port` is the one its `listening` log line names, which is the one it is bound to
/// whatever its URL line says (`--advertise` with a port).
fn spawn(dir: &TempDir, extra: &[&str]) -> Relay {
    let db = dir.path().join("relay.sqlite");
    let mut child = Command::new(BIN)
        .args(["--port", "0", "--db"])
        .arg(&db)
        .args(extra)
        // Its stdin is a pipe the Child holds: it stops when this test process ends, however that ends.
        .arg("--exit-on-stdin-eof")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut log = Tail::new(&mut child);
    let started = Instant::now();
    let (line, stdout) = match read_url_line(child.stdout.take().unwrap(), PATIENCE) {
        Ok(read) => read,
        Err(failure) => {
            let what = failure.reap(&mut child, started.elapsed());
            let said = log.rest();
            panic!("{what}; stderr:\n{said}");
        }
    };
    child.stdout = Some(stdout);
    let started = Instant::now();
    if !log.until("listening", PATIENCE) {
        let waited = started.elapsed();
        let _ = child.kill();
        let _ = child.wait();
        let said = log.rest();
        panic!("no listening line within {PATIENCE:?} (waited {waited:?}) after {line:?}; stderr:\n{said}");
    }
    let listening = log.fields("listening").unwrap();
    let port = u16::try_from(listening["port"].as_u64().unwrap()).unwrap();
    Relay { child, addr: SocketAddr::from(([127, 0, 0, 1], port)), port, line, log }
}

/// SIGTERM, a clean exit, and everything the relay wrote to stderr: its JSON log lines.
fn stop(relay: &mut Relay) -> String {
    sigterm(&relay.child);
    let status = finish(relay);
    let log = relay.log.rest();
    assert!(status.success(), "the relay did not exit 0 after SIGTERM: {status:?}; stderr:\n{log}");
    log
}

/// The fields of the first JSON log line (a line that is not JSON is skipped), which must be the `listening`
/// event.
fn first_line(log: &str) -> serde_json::Value {
    let first: serde_json::Value = log.lines().find_map(|l| serde_json::from_str(l).ok()).expect(log);
    assert_eq!(first["fields"]["event"], "listening", "{log}");
    first["fields"].clone()
}

fn sigterm(child: &Child) {
    let status = Command::new("kill").args(["-TERM", &child.id().to_string()]).status().unwrap();
    assert!(status.success(), "`kill -TERM {}` failed: {status:?}", child.id());
}

/// The relay's exit status, waited for up to `PATIENCE` by the clock. When that passes it is killed and the
/// panic names the time waited and what it wrote to stderr.
fn wait(child: &mut Child, log: &mut Tail) -> ExitStatus {
    let started = Instant::now();
    if let Some(status) = exit_within(child, PATIENCE) {
        return status;
    }
    let waited = started.elapsed();
    let _ = child.kill();
    let _ = child.wait();
    let said = log.rest();
    panic!("the relay did not exit within {PATIENCE:?} (waited {waited:?}); stderr:\n{said}");
}

/// After a SIGTERM: the relay's `stopped` line, which ends its drain (up to the 5 s of `DRAIN` in lib.rs,
/// while a subscriber is open), then its exit, which the runtime's drop and an instrumented build's profile
/// write follow.
fn finish(relay: &mut Relay) -> ExitStatus {
    let started = Instant::now();
    if !relay.log.until("stopped", PATIENCE) {
        let waited = started.elapsed();
        let _ = relay.child.kill();
        let _ = relay.child.wait();
        let said = relay.log.rest();
        panic!("no stopped line within {PATIENCE:?} of SIGTERM (waited {waited:?}); stderr:\n{said}");
    }
    wait(&mut relay.child, &mut relay.log)
}

#[tokio::test]
async fn prints_one_url_line_serves_the_api_and_stops_on_sigterm() {
    let dir = TempDir::new("binary");
    let mut relay = spawn(&dir, &[]);
    assert_eq!(relay.line, format!("AC_RELAY_URL=http://127.0.0.1:{}\n", relay.port));
    let health = request(relay.addr, "GET", "/v0/health", &[], b"").await;
    assert_eq!(health.status, 200);
    let t = now();
    assert!(health.json()["now"].as_u64().unwrap().abs_diff(t) <= 2);
    assert_eq!(health.json()["max_envelope_bytes"], 196_608, "the default --max-envelope-bytes");
    let accepted = request(
        relay.addr,
        "POST",
        "/v0/publish",
        &[],
        &record_bytes(&accept(2, Roots::Any, 65_536, 3_600, t)),
    )
    .await;
    assert_eq!(accepted.status, 200, "{}", accepted.text());
    let env = envelope(1, &[addr(2)], vec![], t);
    let published = request(relay.addr, "POST", "/v0/publish", &[], &bytes(&env)).await;
    assert_eq!(published.json()["delivered"], 1);
    sigterm(&relay.child);
    let status = finish(&mut relay);
    let log = relay.log.rest();
    assert!(status.success(), "the relay did not exit 0 after SIGTERM: {status:?}; stderr:\n{log}");
    let mut rest = String::new();
    relay.child.stdout.take().unwrap().read_to_string(&mut rest).unwrap();
    assert_eq!(rest, "", "stdout holds exactly one line");
    let events: Vec<serde_json::Value> = log.lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
    let names: Vec<&str> = events.iter().filter_map(|e| e["fields"]["event"].as_str()).collect();
    for expected in ["listening", "publish", "stopped"] {
        assert!(names.contains(&expected), "{names:?}");
    }
    // The log names the id and addresses, never the envelope's bytes.
    assert!(log.contains(&env.id_hex()));
    assert!(!log.contains(&env.sealed.ct) && !log.contains(&ac_core::hex::encode(&env.sig)));
    // The database survives the process.
    let mut again = spawn(&dir, &[]);
    let republished = request(again.addr, "POST", "/v0/publish", &[], &bytes(&env)).await;
    assert_eq!(republished.json()["duplicate"], true);
    sigterm(&again.child);
    let status = finish(&mut again);
    let said = again.log.rest();
    assert!(status.success(), "the second relay did not exit 0 after SIGTERM: {status:?}; stderr:\n{said}");
}

#[test]
fn bad_flags_and_settings_exit_non_zero() {
    let dir = TempDir::new("flags");
    let usage = Command::new(BIN).output().unwrap();
    assert_eq!(usage.status.code(), Some(2), "--db is required");
    let bad_port = Command::new(BIN).args(["--port", "70000", "--db", "x"]).output().unwrap();
    assert_eq!(bad_port.status.code(), Some(2));
    let db = dir.path().join("r.sqlite");
    let too_big =
        Command::new(BIN).args(["--max-envelope-bytes", "300000", "--db"]).arg(&db).output().unwrap();
    assert_eq!(too_big.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&too_big.stderr).contains("max-envelope-bytes"));
    assert!(too_big.stdout.is_empty());
    let no_dir =
        Command::new(BIN).arg("--db").arg(dir.path().join("missing").join("r.sqlite")).output().unwrap();
    assert_eq!(no_dir.status.code(), Some(1));
    assert!(no_dir.stdout.is_empty());
    let help = Command::new(BIN).arg("--help").output().unwrap();
    assert!(help.status.success());
    let help = String::from_utf8_lossy(&help.stdout);
    for flag in ["--max-envelope-bytes", "--bind", "--advertise"] {
        assert!(help.contains(flag), "{flag}");
    }
}

#[test]
fn a_bind_advertise_or_accept_base_it_cannot_read_exits_2_before_anything_is_opened() {
    let dir = TempDir::new("bind-flags");
    let db = dir.path().join("r.sqlite");
    let cases: [&[&str]; 9] = [
        &["--bind", "nope"],
        &["--bind", "300.1.1.1"],
        &["--bind", "127.0.0.1:7777"],
        &["--bind", ""],
        &["--advertise", "ftp://relay.example"],
        &["--advertise", "http://"],
        &["--advertise", "http://relay.example/v0"],
        &["--accept-base", "relay.example"],
        &["--accept-base", "https://relay.example/v0"],
    ];
    for args in cases {
        let out = Command::new(BIN).args(args).arg("--db").arg(&db).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains(args[0]), "{args:?}");
    }
    assert!(!db.exists(), "no database is opened on a flag error");
}

#[tokio::test]
async fn bound_to_every_interface_it_prints_the_loopback_url_or_the_advertised_one_and_logs_both() {
    let dir = TempDir::new("bind-any");
    let mut any = spawn(&dir, &["--bind", "0.0.0.0"]);
    let url = format!("http://127.0.0.1:{}", any.port);
    assert_eq!(any.line, format!("AC_RELAY_URL={url}\n"));
    let t = now();
    let record = record_bytes(&accept(2, Roots::Any, 65_536, 3_600, t));
    let stored = request(any.addr, "POST", "/v0/publish", &[], &record).await;
    assert_eq!(stored.status, 200, "{}", stored.text());
    let log = stop(&mut any);
    let first = first_line(&log);
    assert_eq!((&first["bind"], &first["url"]), (&"0.0.0.0".into(), &url.clone().into()));
    assert_eq!(first["port"], any.port);
    // Every publish line names the client's address: here the loopback one it connected from, by its /24, the
    // default of --log-ip.
    let published: Vec<serde_json::Value> = log
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .map(|v| v["fields"].clone())
        .filter(|f| f["event"] == "publish-record")
        .collect();
    assert_eq!(published.len(), 1, "{log}");
    assert_eq!(published[0]["ip"], "127.0.0.0/24");

    // --advertise: a port written in it is kept, and health answers the same URL.
    // On `--port 0`, as the first relay: a port picked free and given back could be taken, on 127.0.0.1, by
    // another test's relay, which then answers the GET and resets it.
    let mut advertised = spawn(&dir, &["--bind", "0.0.0.0", "--advertise", "http://192.0.2.7:9"]);
    let url = "http://192.0.2.7:9".to_owned();
    assert_eq!(advertised.line, format!("AC_RELAY_URL={url}\n"));
    let health = request(advertised.addr, "GET", "/v0/health", &[], b"").await;
    assert_eq!(health.status, 200, "reached through 127.0.0.1, whatever it advertises");
    assert_eq!(health.json()["url"], url.as_str());
    let first = first_line(&stop(&mut advertised));
    assert_eq!((&first["bind"], &first["url"]), (&"0.0.0.0".into(), &url.into()));
}

/// A fetch of `id` from `relay` by `key(2)`, its proof's audience `audience`.
async fn fetch_for(relay: &Relay, id: &str, audience: &str) -> u16 {
    let signer = common::key(2);
    let t = now();
    let proof = ac_core::requests::fetch_preimage(&signer.address(), id, t, audience);
    let sig = ac_core::hex::encode(&signer.sign_preimage(&proof).unwrap());
    let (who, ts) = (signer.address().to_string(), t.to_string());
    let headers = [("AC-Signer", who.as_str()), ("AC-Ts", ts.as_str()), ("AC-Sig", sig.as_str())];
    request(relay.addr, "GET", &format!("/v0/fetch/{id}"), &headers, b"").await.status
}

#[tokio::test]
async fn a_fetch_proof_names_the_announced_url_or_an_accept_base_and_not_the_address_it_reached() {
    let dir = TempDir::new("accept-base");
    let flags = [
        "--advertise",
        "https://relay.example",
        "--accept-base",
        "https://old.example/",
        "--accept-base",
        "https://two.example",
    ];
    let mut relay = spawn(&dir, &flags);
    let t = now();
    let record = record_bytes(&accept(2, Roots::Any, 65_536, 3_600, t));
    assert_eq!(request(relay.addr, "POST", "/v0/publish", &[], &record).await.status, 200);
    let env = envelope(1, &[addr(2)], vec![], t);
    assert_eq!(request(relay.addr, "POST", "/v0/publish", &[], &bytes(&env)).await.status, 200);
    let id = env.id_hex();
    for base in ["https://relay.example", "https://old.example", "https://two.example"] {
        assert_eq!(fetch_for(&relay, &id, base).await, 200, "{base}");
    }
    let reached = format!("http://{}", relay.addr);
    for other in [reached.as_str(), "https://old.example/", "https://three.example"] {
        assert_eq!(fetch_for(&relay, &id, other).await, 401, "{other}");
    }
    let first = first_line(&stop(&mut relay));
    assert_eq!(first["accept_bases"], "https://old.example https://two.example");
}

#[tokio::test]
async fn with_no_advertise_a_fetch_proof_names_the_url_the_relay_prints() {
    // What the e2e harness does: --port 0, no --advertise, the AC_RELAY_URL line read back and signed for.
    let dir = TempDir::new("printed-base");
    let mut relay = spawn(&dir, &[]);
    let printed = relay.line.trim_end().strip_prefix("AC_RELAY_URL=").unwrap().to_owned();
    assert_eq!(printed, format!("http://127.0.0.1:{}", relay.port), "no trailing slash");
    let t = now();
    let record = record_bytes(&accept(2, Roots::Any, 65_536, 3_600, t));
    assert_eq!(request(relay.addr, "POST", "/v0/publish", &[], &record).await.status, 200);
    let env = envelope(1, &[addr(2)], vec![], t);
    assert_eq!(request(relay.addr, "POST", "/v0/publish", &[], &bytes(&env)).await.status, 200);
    assert_eq!(fetch_for(&relay, &env.id_hex(), &printed).await, 200);
    assert_eq!(fetch_for(&relay, &env.id_hex(), &format!("{printed}/")).await, 401);
    stop(&mut relay);
}

#[tokio::test]
async fn bound_to_an_ipv6_address_it_prints_the_address_in_brackets() {
    let dir = TempDir::new("bind-v6");
    if std::net::TcpListener::bind("[::1]:0").is_err() {
        // A host without IPv6 loopback: the relay fails as for any address it cannot listen on.
        let out = Command::new(BIN).args(["--bind", "::1", "--db"]).arg(dir.path().join("r.sqlite")).output();
        let out = out.unwrap();
        assert_eq!(out.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&out.stderr).contains("cannot listen on [::1]:0"));
        return;
    }
    let mut relay = spawn(&dir, &["--bind", "::1"]);
    assert_eq!(relay.line, format!("AC_RELAY_URL=http://[::1]:{}\n", relay.port));
    let at = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), relay.port);
    assert_eq!(request(at, "GET", "/v0/health", &[], b"").await.status, 200);
    let first = first_line(&stop(&mut relay));
    assert_eq!(first["bind"], "::1");
}

#[test]
fn a_taken_port_exits_non_zero() {
    let dir = TempDir::new("port");
    let holder = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = holder.local_addr().unwrap().port().to_string();
    let out =
        Command::new(BIN).args(["--port", &port, "--db"]).arg(dir.path().join("r.sqlite")).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot listen"));
}

/// A SIGTERM sent the
/// moment the URL line is read, by a shell whose builtin `kill` starts no process in between, stops the relay
/// gracefully, exit 0 with its `stopped` line, in each of 20 runs. The relay registers its handlers before it
/// prints the line; on an earlier main they were registered when the server's task first ran, after the line,
/// the `listening` line and `Relay::new`, so a SIGTERM in between ended it by the signal's default action,
/// with no drain and no `stopped`.
#[test]
fn a_sigterm_sent_the_moment_the_url_line_is_read_stops_it_gracefully() {
    let dir = TempDir::new("sigterm-window");
    let mut failed = Vec::new();
    for run in 0..20 {
        let mut relay = Command::new(BIN)
            .args(["--port", "0", "--db"])
            .arg(dir.path().join(format!("r{run}.sqlite")))
            // Its stdin is a pipe the Child holds: it stops when this test process ends, however that ends.
            .arg("--exit-on-stdin-eof")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut tail = Tail::new(&mut relay);
        let pid = relay.id().to_string();
        let mut shell = Command::new("sh")
            .args(["-c", r#"read -r line && kill -TERM "$1" && printf '%s\n' "$line""#, "sh", &pid])
            .stdin(Stdio::from(relay.stdout.take().unwrap()))
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        // The shell returns once it has read the URL line and sent the signal; a relay that prints nothing
        // leaves it reading, so it is waited for by the clock, and the shell and the relay are killed when it
        // does not return.
        if exit_within(&mut shell, PATIENCE).is_none() {
            let _ = shell.kill();
            let _ = shell.wait();
            let _ = relay.kill();
            let _ = relay.wait();
            let said = tail.rest();
            panic!("run {run}: the shell reading the URL line hung past {PATIENCE:?}; stderr:\n{said}");
        }
        let mut line = String::new();
        shell.stdout.take().unwrap().read_to_string(&mut line).unwrap();
        // The `stopped` line ends the drain; a relay that the signal ended by its default action never writes
        // one, and the pipe's end then answers at once.
        tail.until("stopped", PATIENCE);
        let status = wait(&mut relay, &mut tail);
        let log = tail.rest();
        assert!(line.starts_with("AC_RELAY_URL=http://127.0.0.1:"), "run {run}: {line:?} {log}");
        let stopped = log.lines().any(|l| l.contains(r#""event":"stopped""#));
        if !(status.success() && stopped) {
            failed.push(format!("run {run}: {status:?}, stopped line {stopped}"));
        }
    }
    eprintln!("MEASURE L6: {} of 20 runs did not exit 0 with a stopped line {failed:?}", failed.len());
    assert!(failed.is_empty(), "{failed:?}");
}
