//! The binary's TXT path and its test-only `--dns-resolve` (spec/SPEC.md §12.2, §8.8): a TXT record
//! given by the flag, `host=bag`, leads the relay to the org's origin `bag.<domain>` through the process,
//! with the `txt` and `well-known` lines naming where it went; the flag is refused unless `--bind` is
//! loopback, a bad value is a flag error, and
//! the `listening` line names the TXT source: `fixed` with any test-only flag, `dns` with none. No test here
//! asks a DNS server: every relay that resolves a domain runs with a test-only flag.

mod common;

use ac_core::chain::Hop;
use ac_core::records::{AddressRecord, Domain, Record, Root, Roots};
use common::{PATIENCE, TempDir, accept, addr, bytes, envelope, key, read_url_line, record_bytes, request};
use std::io::Read as _;
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const BIN: &str = env!("CARGO_BIN_EXE_ac-relay");

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

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

/// A server that answers every request with `body`, 200, and keeps each request's first line and host.
async fn record_host(body: Vec<u8>) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let (body, kept) = (body.clone(), Arc::clone(&kept));
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4_096];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
                let first = head.lines().next().unwrap_or_default().to_owned();
                let host = head.lines().find_map(|l| l.strip_prefix("host: ")).unwrap_or_default().to_owned();
                kept.lock().unwrap().push(format!("{host} {first}"));
                let answer =
                    format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", body.len());
                let _ = socket.write_all(answer.as_bytes()).await;
                let _ = socket.write_all(&body).await;
            });
        }
    });
    (at, seen)
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
async fn discovery_a_txt_record_given_by_the_flag_leads_the_process_to_the_bag_origin() {
    let t = now();
    let (at, seen) = record_host(org(10, t)).await;
    let dir = TempDir::new("discovery-flag");
    let resolve = format!("bag.acme.test={at}");
    let txt = format!(r#"_bag.acme.test="v=ac1; key={}; host=bag""#, addr(10));
    let flags = ["--well-known-insecure-http", "--well-known-resolve", &resolve, "--dns-resolve", &txt];
    let (child, relay) = spawn(&dir, &flags);
    let roots = Roots::WithDomains(vec![Root::Domain(Domain::parse("acme.test").unwrap())]);
    let hosted =
        request(relay, "POST", "/v0/publish", &[], &record_bytes(&accept(2, roots, 65_536, 3_600, t))).await;
    assert_eq!(hosted.status, 200, "{}", hosted.text());
    let chain = vec![Hop::sign(&key(10), &addr(1), vec![], t + 3_600).unwrap()];
    let published =
        request(relay, "POST", "/v0/publish", &[], &bytes(&envelope(1, &[addr(2)], chain, t))).await;
    assert_eq!(
        (published.status, published.json()["delivered"].as_u64()),
        (200, Some(1)),
        "{}",
        published.text()
    );
    assert_eq!(*seen.lock().unwrap(), ["bag.acme.test get /.well-known/bag/address.json http/1.1"]);
    let log = stop(child);
    assert_eq!((log[0]["event"].as_str(), log[0]["txt"].as_str()), (Some("listening"), Some("fixed")));
    let warned = log.iter().find(|f| f["event"] == "dns-resolve").expect("a dns-resolve warning");
    assert_eq!(warned["names"].as_str(), Some("_bag.acme.test"));
    let looked: Vec<_> = log.iter().filter(|f| f["event"] == "txt").collect();
    assert_eq!(looked.len(), 1);
    assert_eq!(
        (looked[0]["source"].as_str(), looked[0]["records"].as_u64(), looked[0]["ok"].as_bool()),
        (Some("fixed"), Some(1), Some(true))
    );
    let pinned: Vec<_> = log.iter().filter(|f| f["event"] == "well-known").collect();
    assert_eq!(
        (pinned.len(), pinned[0]["source"].as_str(), pinned[0]["url"].as_str()),
        (1, Some("txt"), Some("https://bag.acme.test/.well-known/bag/address.json"))
    );
}

#[test]
fn discovery_the_flag_needs_a_loopback_bind_and_a_relay_without_test_flags_names_dns() {
    let dir = TempDir::new("discovery-refusals");
    let db = dir.path().join("r.sqlite");
    let run = |args: &[&str]| Command::new(BIN).args(args).arg("--db").arg(&db).output().unwrap();
    for args in [
        &["--bind", "0.0.0.0", "--dns-resolve", "_bag.acme.test=v=ac1"][..],
        &["--dns-resolve", "no-equals"],
        &["--dns-resolve", "a..b=x"],
        &["--dns-resolve", r#"_bag.acme.test="open"#],
    ] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
    }
    let refused = run(&["--bind", "0.0.0.0", "--dns-resolve", "_bag.acme.test=v=ac1"]);
    assert!(String::from_utf8_lossy(&refused.stderr).contains("loopback --bind"));
    assert!(!db.exists(), "no database is opened on a flag error");
    let help = Command::new(BIN).arg("--help").output().unwrap();
    assert!(String::from_utf8_lossy(&help.stdout).contains("--dns-resolve"));
    let plain = TempDir::new("discovery-plain");
    let (child, _) = spawn(&plain, &[]);
    let log = stop(child);
    assert_eq!((log[0]["event"].as_str(), log[0]["txt"].as_str()), (Some("listening"), Some("dns")));
    assert!(log.iter().all(|f| f["event"] != "txt"), "it resolved nothing, so it asked nothing");
}
