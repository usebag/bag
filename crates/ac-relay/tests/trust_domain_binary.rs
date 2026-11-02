//! The binary's flags for `domain:` roots: the timeout and the cache ceiling with their
//! bounds, the two test-only flags (a warning line after `listening`, refused unless `--bind` is loopback), a
//! domain root resolved end to end through the process, and the operator's `--pin-reset`.

mod common;

use ac_core::chain::Hop;
use ac_core::records::{AddressRecord, Domain, Record, Root, Roots};
use ac_relay::store::sqlite::SqliteStore;
use ac_relay::store::{DomainPin, Store as _};
use common::{PATIENCE, TempDir, accept, addr, bytes, envelope, key, read_url_line, record_bytes, request};
use std::io::Read as _;
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const BIN: &str = env!("CARGO_BIN_EXE_ac-relay");

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// Starts the relay on port 0 with `extra`, and returns it with the address its URL line names.
fn spawn(dir: &TempDir, extra: &[&str]) -> (Child, SocketAddr) {
    let mut child = Command::new(BIN)
        .args(["--port", "0", "--db"])
        .arg(dir.path().join("relay.sqlite"))
        .args(extra)
        // Its stdin is a pipe the Child holds: it stops when this test process ends, however that ends.
        .arg("--exit-on-stdin-eof")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    let (line, stdout) = match read_url_line(child.stdout.take().unwrap(), PATIENCE) {
        Ok(read) => read,
        Err(failure) => {
            let what = failure.reap(&mut child, started.elapsed());
            let mut said = String::new();
            let _ = child.stderr.take().unwrap().read_to_string(&mut said);
            panic!("{what}; stderr:\n{said}");
        }
    };
    let port: u16 = line
        .trim_end()
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse().ok())
        .unwrap_or_else(|| panic!("{line:?}"));
    child.stdout = Some(stdout);
    (child, SocketAddr::from(([127, 0, 0, 1], port)))
}

/// SIGTERM, a clean exit, and the JSON log lines' fields.
fn stop(mut child: Child) -> Vec<serde_json::Value> {
    assert!(Command::new("kill").args(["-TERM", &child.id().to_string()]).status().unwrap().success());
    for _ in 0..200 {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "{status:?}");
            let mut log = String::new();
            child.stderr.take().unwrap().read_to_string(&mut log).unwrap();
            return log
                .lines()
                .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["fields"].clone())
                .collect();
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    child.kill().unwrap();
    panic!("the relay did not exit within 5 s of SIGTERM");
}

/// A server that answers every request with `body` as JSON, 200.
async fn well_known(body: Vec<u8>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4_096];
                let _ = socket.read(&mut buf).await;
                let head =
                    format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", body.len());
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(&body).await;
            });
        }
    });
    at
}

fn org(n: u8, iat: u64) -> Vec<u8> {
    let a = AddressRecord {
        key: addr(n),
        sealing_key: None,
        relays: vec![],
        rotation_key: None,
        revoked: vec![],
        ttl: 3_600,
        iat,
        rotated_from: None,
        rotation_sig: None,
        sig: [0; 64],
    };
    let mut r = Record::Address(a);
    r.sign(&key(n)).unwrap();
    r.to_bytes()
}

#[tokio::test]
async fn trust_domain_test_only_flags_warn_after_listening_and_a_domain_root_resolves_through_the_process() {
    let t = now();
    let at = well_known(org(10, t)).await;
    let dir = TempDir::new("trust-domain-flags");
    let resolve = format!("acme.test={at}");
    let flags =
        ["--well-known-insecure-http", "--well-known-resolve", resolve.as_str(), "--well-known-timeout", "5"];
    let (child, relay) = spawn(&dir, &flags);
    let roots = Roots::WithDomains(vec![Root::Domain(Domain::parse("acme.test").unwrap())]);
    let hosted =
        request(relay, "POST", "/v0/publish", &[], &record_bytes(&accept(2, roots, 65_536, 3_600, t))).await;
    assert_eq!(hosted.status, 200, "{}", hosted.text());
    let chain = vec![
        Hop::sign(&key(10), &addr(20), vec![], t + 3_600).unwrap(),
        Hop::sign(&key(20), &addr(1), vec![], t + 3_600).unwrap(),
    ];
    let published =
        request(relay, "POST", "/v0/publish", &[], &bytes(&envelope(1, &[addr(2)], chain, t))).await;
    assert_eq!(
        (published.status, published.json()["delivered"].as_u64()),
        (200, Some(1)),
        "{}",
        published.text()
    );
    let log = stop(child);
    assert_eq!(log[0]["event"], "listening");
    assert_eq!(
        (log[0]["well_known_timeout"].as_u64(), log[0]["well_known_cache_max"].as_u64()),
        (Some(5), Some(86_400))
    );
    assert_eq!(log[1]["event"], "well-known-insecure-http");
    assert_eq!(
        (log[2]["event"].as_str(), log[2]["hosts"].as_str()),
        (Some("well-known-resolve"), Some(resolve.as_str()))
    );
    let pinned: Vec<&serde_json::Value> = log.iter().filter(|f| f["event"] == "well-known").collect();
    assert_eq!(pinned.len(), 1);
    assert_eq!(
        (pinned[0]["outcome"].as_str(), pinned[0]["key"].as_str()),
        (Some("pinned"), Some(addr(10).as_str()))
    );
}

#[test]
fn trust_domain_a_test_only_flag_needs_a_loopback_bind_and_the_settings_have_bounds() {
    let dir = TempDir::new("trust-domain-refusals");
    let db = dir.path().join("r.sqlite");
    let run = |args: &[&str]| Command::new(BIN).args(args).arg("--db").arg(&db).output().unwrap();
    for args in [
        &["--bind", "0.0.0.0", "--well-known-insecure-http"][..],
        &["--bind", "192.0.2.1", "--well-known-resolve", "acme.test=127.0.0.1:1"],
        &["--well-known-resolve", "acme.test"],
        &["--well-known-resolve", "127.0.0.1=127.0.0.1:1"],
        &["--pin-reset", "127.0.0.1"],
    ] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
    }
    let refused = run(&["--bind", "0.0.0.0", "--well-known-insecure-http"]);
    assert!(String::from_utf8_lossy(&refused.stderr).contains("loopback --bind"));
    for (args, flag) in [
        (&["--well-known-timeout", "0"][..], "--well-known-timeout"),
        (&["--well-known-timeout", "61"], "--well-known-timeout"),
        (&["--well-known-cache-max", "0"], "--well-known-cache-max"),
    ] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains(flag), "{args:?}");
    }
    assert!(!db.exists(), "no database is opened on a flag error");
    let help = Command::new(BIN).arg("--help").output().unwrap();
    let help = String::from_utf8_lossy(&help.stdout);
    for flag in [
        "--well-known-timeout",
        "--well-known-cache-max",
        "--well-known-insecure-http",
        "--well-known-resolve",
        "--pin-reset",
    ] {
        assert!(help.contains(flag), "{flag}");
    }
}

/// `--pin-reset <domain>` with the record of the reset, plus `extra`.
fn reset(db: &Path, domain: &str, extra: &[&str]) -> std::process::Output {
    Command::new(BIN)
        .args(["--pin-reset", domain, "--new-key"])
        .arg(addr(30).to_string())
        .args([
            "--operator",
            "Sam, confirmed by A. Rivera of Acme",
            "--reason",
            "the org lost its rotation key",
        ])
        .args(["--channel", "a voice call to A. Rivera on the number in the contract"])
        .args(extra)
        .arg("--db")
        .arg(db)
        .output()
        .unwrap()
}

/// A database holding a pin for each of `domains`, all for `addr(10)`.
fn pinned(db: &Path, domains: &[&str]) {
    let store = SqliteStore::open(db).unwrap();
    for domain in domains {
        let pin = DomainPin {
            domain: (*domain).into(),
            key: addr(10).to_string(),
            record: org(10, 1_800_000_000),
            pinned_at: 1_800_000_000,
            expires_at: 1_800_003_600,
        };
        store.put_domain_pin(&pin).unwrap();
    }
}

#[test]
fn trust_domain_pin_reset_deletes_one_pin_prints_it_and_logs_it() {
    let dir = TempDir::new("trust-domain-pin-reset");
    let db = dir.path().join("relay.sqlite");
    pinned(&db, &["acme.test", "globex.test"]);
    let out = reset(&db, "acme.test", &[]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&out.stdout), format!("pin-reset acme.test {}\n", addr(10)));
    let log: serde_json::Value =
        serde_json::from_slice(out.stderr.split(|b| *b == b'\n').next().unwrap()).unwrap();
    assert_eq!((log["fields"]["event"].as_str(), log["level"].as_str()), (Some("pin-reset"), Some("WARN")));
    assert_eq!(log["fields"]["pinned_at"].as_u64(), Some(1_800_000_000));
    // The record of the reset: subject, old and new key, who, the channel, why, when.
    let fields = &log["fields"];
    let kept = ["domain", "old_key", "new_key", "operator", "channel", "reason"].map(|k| fields[k].as_str());
    assert_eq!(
        kept,
        [
            Some("acme.test"),
            Some(addr(10).as_str()),
            Some(addr(30).as_str()),
            Some("Sam, confirmed by A. Rivera of Acme"),
            Some("a voice call to A. Rivera on the number in the contract"),
            Some("the org lost its rotation key"),
        ]
    );
    assert!(fields["requested_at"].as_u64().unwrap() >= now() - 60);
    let again = reset(&db, "acme.test", &[]);
    assert_eq!(String::from_utf8_lossy(&again.stdout), "pin-reset acme.test none\n");
    let store = SqliteStore::open(&db).unwrap();
    assert_eq!(store.domain_pin("acme.test").unwrap(), None);
    assert!(store.domain_pin("globex.test").unwrap().is_some(), "only the named domain");
    let missing = dir.path().join("missing").join("relay.sqlite");
    let out = reset(&missing, "acme.test", &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
}

#[test]
fn trust_domain_a_pin_reset_without_its_record_is_refused_and_deletes_nothing() {
    let dir = TempDir::new("trust-domain-pin-reset-record");
    let db = dir.path().join("relay.sqlite");
    pinned(&db, &["acme.test"]);
    for flags in [
        &["--pin-reset", "acme.test"][..],
        &["--pin-reset", "acme.test", "--operator", "Sam", "--channel", "voice", "--reason", "lost"],
        &[
            "--pin-reset",
            "acme.test",
            "--new-key",
            "ed25519:00",
            "--operator",
            "D",
            "--channel",
            "v",
            "--reason",
            "r",
        ],
        &["--queue"],
    ] {
        let out = Command::new(BIN).args(flags).arg("--db").arg(&db).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{flags:?}");
        assert!(out.stdout.is_empty(), "{flags:?}");
    }
    assert!(SqliteStore::open(&db).unwrap().domain_pin("acme.test").unwrap().is_some());
}

#[test]
fn trust_domain_a_queued_pin_reset_opens_no_database_and_is_applied_at_the_next_start() {
    let dir = TempDir::new("trust-domain-pin-reset-queue");
    let db = dir.path().join("relay.sqlite");
    let queue = dir.path().join("relay.sqlite.pin-resets");
    pinned(&db, &["acme.test", "globex.test"]);
    let out = reset(&db, "acme.test", &["--queue"]);
    assert_eq!(
        (out.status.code(), &*String::from_utf8_lossy(&out.stdout)),
        (Some(0), "pin-reset-queued acme.test\n")
    );
    let request: serde_json::Value =
        serde_json::from_str(std::fs::read_to_string(&queue).unwrap().trim()).unwrap();
    assert_eq!(
        (request["domain"].as_str(), request["new_key"].as_str()),
        (Some("acme.test"), Some(addr(30).as_str()))
    );
    assert!(
        SqliteStore::open(&db).unwrap().domain_pin("acme.test").unwrap().is_some(),
        "queued, not applied"
    );
    // A relay that starts applies it before it listens, logs it in its own stream, and consumes the file.
    let (child, _) = spawn(&dir, &[]);
    let store = SqliteStore::open(&db).unwrap();
    assert_eq!(store.domain_pin("acme.test").unwrap(), None);
    assert!(store.domain_pin("globex.test").unwrap().is_some(), "only the named domain");
    let log = stop(child);
    assert_eq!((log[0]["event"].as_str(), log[1]["event"].as_str()), (Some("pin-reset"), Some("listening")));
    let kept = ["domain", "old_key", "new_key", "operator"].map(|k| log[0][k].as_str());
    assert_eq!(
        kept,
        [
            Some("acme.test"),
            Some(addr(10).as_str()),
            Some(addr(30).as_str()),
            Some("Sam, confirmed by A. Rivera of Acme")
        ]
    );
    assert!(!queue.exists(), "applied once");
    let names: Vec<_> = std::fs::read_dir(dir.path()).unwrap().flatten().map(|e| e.file_name()).collect();
    let done = names.iter().filter(|n| n.to_string_lossy().starts_with("relay.sqlite.pin-resets.")).count();
    assert_eq!(done, 1, "consumed under a name with its time: {names:?}");
}

#[test]
fn trust_domain_a_bad_queued_request_is_refused_and_skipped_and_the_relay_starts() {
    let dir = TempDir::new("trust-domain-pin-reset-bad");
    let db = dir.path().join("relay.sqlite");
    pinned(&db, &["acme.test"]);
    let good = reset(&db, "acme.test", &["--queue"]);
    assert_eq!(good.status.code(), Some(0));
    let queue = dir.path().join("relay.sqlite.pin-resets");
    let text = std::fs::read_to_string(&queue).unwrap();
    let no_channel = text.replace("\"channel\"", "\"chan\"");
    std::fs::write(&queue, format!("not json\n{no_channel}{text}")).unwrap();
    let (child, _) = spawn(&dir, &[]);
    let log = stop(child);
    // The hourly `store-size` line follows `listening`; it is not what this test reads.
    let events: Vec<_> =
        log.iter().map(|f| f["event"].as_str().unwrap_or_default()).filter(|e| *e != "store-size").collect();
    assert_eq!(events, ["pin-reset-refused", "pin-reset-refused", "pin-reset", "listening", "stopped"]);
    assert_eq!((log[0]["line"].as_u64(), log[1]["line"].as_u64()), (Some(1), Some(2)));
    assert!(log[1]["error"].as_str().unwrap().contains("channel"), "{}", log[1]);
    assert_eq!(
        SqliteStore::open(&db).unwrap().domain_pin("acme.test").unwrap(),
        None,
        "the good request applied"
    );
    assert!(!queue.exists());
}
