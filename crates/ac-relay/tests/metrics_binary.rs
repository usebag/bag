//! The `ac-relay` binary with `--metrics-port`: the counts in Prometheus's text format on that port only, `/metrics`
//! 404 `not-found` on the relay's own port, no address, key or client IP in the counts, Litestream's read at 0 when it
//! is not there, the open subscriptions and the day's mailboxes at 0 and the store's size from the start, the W1.2
//! families (headers not read, signatures, claims, connections, limits, build, networks), both listeners stopped by
//! one SIGTERM, a kept-alive connection's quiet end at the header timeout on either port, and the flag errors.

mod common;

use ac_core::records::Roots;
use common::{
    PATIENCE, Tail, TempDir, accept, addr, connect, exit_within, read_url_line, record_bytes, request,
};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

const BIN: &str = env!("CARGO_BIN_EXE_ac-relay");

/// The relay on `--port 0` and `--metrics-port 0`, with `extra`, and the two addresses its `listening` line names.
fn spawn(dir: &TempDir, extra: &[&str]) -> (Child, Tail, SocketAddr, SocketAddr) {
    let mut child = Command::new(BIN)
        .args(["--port", "0", "--metrics-port", "0", "--db"])
        .arg(dir.path().join("relay.sqlite"))
        .args(extra)
        .arg("--exit-on-stdin-eof")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut log = Tail::new(&mut child);
    let started = Instant::now();
    let (_, stdout) = read_url_line(child.stdout.take().unwrap(), PATIENCE).unwrap_or_else(|failure| {
        panic!("{}; stderr:\n{}", failure.reap(&mut child, started.elapsed()), log.rest())
    });
    child.stdout = Some(stdout);
    assert!(log.until("listening", PATIENCE), "no listening line; stderr:\n{}", log.rest());
    let listening = log.fields("listening").unwrap();
    let port = u16::try_from(listening["port"].as_u64().unwrap()).unwrap();
    let metrics: SocketAddr = listening["metrics"].as_str().unwrap().parse().unwrap();
    (child, log, SocketAddr::from(([127, 0, 0, 1], port)), metrics)
}

/// The calls the W1.2 families count, on the relay at `relay` at time `t`: a record whose signature does not verify
/// (the first hex digit of its one signature changed), a claim with a client-address header from a peer that no
/// --trust-proxy names, and one connection served once and held open, returned so that it is open at the scrape.
async fn w12_calls(relay: SocketAddr, t: u64) -> TcpStream {
    let good = String::from_utf8(record_bytes(&accept(3, Roots::Any, 65_536, 3_600, t))).unwrap();
    assert_eq!(good.matches("\"sig\":\"").count(), 1, "{good}");
    let at = good.find("\"sig\":\"").unwrap() + 7;
    let other = if good[at..].starts_with('0') { "1" } else { "0" };
    let forged = format!("{}{other}{}", &good[..at], &good[at + 1..]);
    let forged = request(relay, "POST", "/v0/publish", &[], forged.as_bytes()).await;
    assert_eq!((forged.status, forged.error()), (422, "bad-record-sig".to_owned()));
    let spoofed = [("cf-connecting-ip", "203.0.113.7")];
    let claim = request(relay, "GET", "/v0/pair/claim/100", &spoofed, b"").await;
    assert_eq!((claim.status, claim.error()), (404, "no-nameplate".to_owned()));
    let mut held = connect(relay).await;
    held.write_all(b"GET /v0/health HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
    let mut answer = [0u8; 12];
    held.read_exact(&mut answer).await.unwrap();
    assert_eq!(&answer, b"HTTP/1.1 200");
    held
}

/// The value of the sample `name` (with its labels, as written) in `text`.
fn sample(text: &str, name: &str) -> Option<u64> {
    text.lines().find_map(|l| l.strip_prefix(name)?.strip_prefix(' ')?.parse().ok())
}

#[tokio::test]
async fn the_metrics_port_counts_what_the_relay_did_and_names_no_one() {
    let dir = TempDir::new("metrics");
    let (mut child, mut log, relay, metrics) =
        spawn(&dir, &["--metrics-litestream", "http://127.0.0.1:1/metrics"]);
    assert_eq!(metrics.ip(), relay.ip(), "--metrics-bind defaults to 127.0.0.1");
    assert_ne!(metrics.port(), relay.port());

    let public = request(relay, "GET", "/metrics", &[], b"").await;
    assert_eq!(
        (public.status, public.error()),
        (404, "not-found".to_owned()),
        "/metrics is not on the relay's port"
    );
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let stored =
        request(relay, "POST", "/v0/publish", &[], &record_bytes(&accept(2, Roots::Any, 65_536, 3_600, t)))
            .await;
    assert_eq!(stored.status, 200, "{}", stored.text());
    let bad = request(relay, "POST", "/v0/publish", &[], b"{").await;
    assert_eq!(bad.status, 400);
    let fetched = request(relay, "GET", "/v0/fetch/zz", &[], b"").await;
    let refused = format!("ac_relay_fetches_total{{result=\"{}\"}}", fetched.error());
    let held = w12_calls(relay, t).await;
    // The sweeper's first tick is at start, and its store-size line comes after the store's gauges are set.
    assert!(log.until("store-size", PATIENCE), "no store-size line at start; stderr:\n{}", log.rest());

    let scraped = request(metrics, "GET", "/metrics", &[], b"").await;
    assert_eq!(scraped.status, 200);
    assert_eq!(scraped.header("content-type"), Some("text/plain; version=0.0.4; charset=utf-8"));
    let text = scraped.text();
    for (name, value) in [
        ("ac_relay_publishes_total{result=\"record\"}", 1),
        ("ac_relay_publishes_total{result=\"bad-json\"}", 1),
        ("ac_relay_new_signers_total", 1),
        ("ac_relay_litestream_up", 0),
        ("ac_relay_subscriptions_open", 0),
        ("ac_relay_mailboxes_subscribed_today", 0),
        // Seeded at 0 at start, for the alerts' increase() (src/metrics.rs SEEDED and SEEDED_BY_LABEL).
        ("ac_relay_blocked_total", 0),
        ("ac_relay_blocklist_invalid_total", 0),
        ("ac_relay_domain_resolutions_total{outcome=\"pin-mismatch\"}", 0),
        ("ac_relay_publishes_total{result=\"bad-sig\"}", 0),
        ("ac_relay_rate_limited_total{limit=\"fetch-global\"}", 0),
        ("ac_relay_record_fetches_total{result=\"not-found\"}", 0),
        // W1.2: the security note's M1 to M4, signatures by what was signed, claims, nameplates, connections (the
        // public port's seven, none of the metrics port's), the limits run with, and the day's networks.
        ("ac_relay_proxy_header_ignored_total{reason=\"untrusted-source\"}", 1),
        ("ac_relay_proxy_header_ignored_total{reason=\"malformed\"}", 0),
        ("ac_relay_resolutions_capped_total", 0),
        ("ac_relay_signature_failures_total{kind=\"record\"}", 1),
        ("ac_relay_signature_failures_total{kind=\"envelope\"}", 0),
        ("ac_relay_pending_dropped_total{reason=\"revoked\"}", 0),
        ("ac_relay_pair_claims_total{result=\"no-nameplate\"}", 1),
        ("ac_relay_pair_claims_total{result=\"ok\"}", 0),
        ("ac_relay_pair_opens_total{result=\"body-timeout\"}", 0),
        ("ac_relay_nameplates_open", 0),
        ("ac_relay_connections_accepted_total", 7),
        ("ac_relay_limit{limit=\"ip\"}", 600),
        ("ac_relay_limit{limit=\"window\"}", 60),
        ("ac_relay_client_networks_today", 1),
        (
            "http_server_request_duration_seconds_count{http_route=\"/v0/publish\",http_response_status_code=\"200\"}",
            1,
        ),
        (
            "http_server_request_duration_seconds_count{http_route=\"not-found\",http_response_status_code=\"404\"}",
            1,
        ),
    ] {
        assert_eq!(sample(&text, name), Some(value), "{name} in\n{text}");
    }
    assert_eq!(sample(&text, &refused), Some(1), "{refused} ({}) in\n{text}", fetched.status);
    assert!(sample(&text, "process_start_time_seconds").is_some_and(|s| s.abs_diff(t) < 60), "{text}");
    assert!(
        sample(&text, "ac_relay_store_bytes").is_some_and(|b| b > 0),
        "the store's size from the start:\n{text}"
    );
    assert!(sample(&text, "ac_relay_connections_open").is_some_and(|n| n >= 1), "the held one:\n{text}");
    let build: Vec<&str> = text.lines().filter(|l| l.starts_with("ac_relay_build_info")).collect();
    let one = |l: &&str| l.starts_with("ac_relay_build_info{rev=\"") && l.ends_with("\"} 1");
    assert!(build.len() == 1 && build.iter().all(one), "{build:?}");
    let signer = addr(2).to_string();
    for never in [signer.as_str(), "ed25519:", "127.0.0", "/24", "203.0.113"] {
        assert!(!text.contains(never), "{never:?} in the counts:\n{text}");
    }
    drop(held);

    let other = request(metrics, "GET", "/v0/health", &[], b"").await;
    assert_eq!(
        (other.status, other.error()),
        (404, "not-found".to_owned()),
        "the metrics port answers nothing else"
    );

    let status = Command::new("kill").args(["-TERM", &child.id().to_string()]).status().unwrap();
    assert!(status.success());
    assert!(log.until("stopped", PATIENCE), "no stopped line; stderr:\n{}", log.rest());
    let exited = exit_within(&mut child, PATIENCE).expect("the relay exits after SIGTERM");
    assert!(exited.success(), "{exited:?}; stderr:\n{}", log.rest());
}

/// A connection kept alive after its answer and closed at the header timeout is no timeout, neither on the metrics
/// port (as Fly's scraper keeps one every 15 s) nor on the relay's; one whose next head began after the answer and was
/// not finished is one, the only one counted.
#[tokio::test]
async fn a_kept_alive_connection_closed_at_the_header_timeout_counts_only_when_a_next_head_began() {
    let dir = TempDir::new("metrics-idle");
    let (mut child, mut log, relay, metrics) = spawn(&dir, &["--header-timeout", "1"]);
    let scrape = &b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n"[..];
    let health = &b"GET /v0/health HTTP/1.1\r\nHost: x\r\n\r\n"[..];
    let (nothing, begun) = (&b""[..], &b"GET /v0/health HTTP/1.1\r\nX-Slow: "[..]);
    for (at, first, next) in [(metrics, scrape, nothing), (relay, health, nothing), (relay, health, begun)] {
        let mut kept = connect(at).await;
        kept.write_all(first).await.unwrap();
        let mut answer = [0u8; 12];
        kept.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer, b"HTTP/1.1 200");
        kept.write_all(next).await.unwrap();
        let mut rest = Vec::new();
        let closed = tokio::time::timeout(PATIENCE, kept.read_to_end(&mut rest)).await;
        assert!(closed.is_ok(), "{at}: closed at the header timeout");
    }
    let text = request(metrics, "GET", "/metrics", &[], b"").await.text();
    let series = |reason: &str| format!("ac_relay_connection_timeouts_total{{reason=\"{reason}\"}}");
    let timeouts = |reason: &str| sample(&text, &series(reason));
    assert_eq!((timeouts("header-timeout"), timeouts("first-bytes")), (Some(1), None), "{text}");

    let status = Command::new("kill").args(["-TERM", &child.id().to_string()]).status().unwrap();
    assert!(status.success());
    assert!(log.until("stopped", PATIENCE), "no stopped line; stderr:\n{}", log.rest());
    let exited = exit_within(&mut child, PATIENCE).expect("the relay exits after SIGTERM");
    assert!(exited.success(), "{exited:?}; stderr:\n{}", log.rest());
}

#[test]
fn a_metrics_flag_needs_the_port_and_litestream_s_url_must_be_on_this_host() {
    let dir = TempDir::new("metrics-flags");
    let db = dir.path().join("relay.sqlite");
    for args in [
        vec!["--metrics-bind", "::"],
        vec!["--metrics-litestream", "http://127.0.0.1:9090/metrics"],
        vec!["--metrics-port", "0", "--metrics-litestream", "https://127.0.0.1:9090/metrics"],
        vec!["--metrics-port", "0", "--metrics-litestream", "http://198.51.100.7:9090/metrics"],
        vec!["--metrics-port", "0", "--metrics-litestream", "http://localhost/metrics"],
    ] {
        let out = Command::new(BIN).args(["--port", "0", "--db"]).arg(&db).args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
    }
    assert!(!db.exists(), "a flag error opens no database");
}
