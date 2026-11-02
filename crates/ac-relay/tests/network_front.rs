//! The relay's network front through an in-process relay over a real SQLite file on a real loopback
//! socket (`common::Server`). Every client here is 127.0.0.1, so a trusted proxy is 127.0.0.0/8, and the
//! clients it names come in a header: L1 the buckets of step 3a, the signer quota and the connection cap
//! follow them; L4 the probe; L6 the record answer; L8 a pending recipient delivered by the sweeper once its
//! domain resolves; L9 a well-known record over 65,536 bytes.

mod common;

use ac_core::chain::Hop;
use ac_core::records::{AcceptFromRecord, AddressRecord, Domain, KeyRecord, Kind, Record, Root, Roots};
use ac_relay::config::{RateLimits, WellKnown};
use ac_relay::net::{Cidr, Front, LogIp};
use ac_relay::{Config, probe};
use axum::http::HeaderName;
use common::{
    NOW, PATIENCE, POLL, Server, TempDir, Ws, accept, addr, bytes, connect, envelope, key, read_until_closed,
    record_bytes, request, subscribe, ws_close_code, ws_json,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

fn trusting(cidrs: &[&str], header: Option<&str>) -> Front {
    let header = header.map(|h| HeaderName::from_bytes(h.as_bytes()).unwrap());
    Front { trusted: cidrs.iter().map(|c| Cidr::parse(c).unwrap()).collect(), header, log_ip: LogIp::Full }
}

/// A relay on the manual clock with `front` and `rate`, hosting mailbox 2 for every root (one request from the
/// peer itself, 127.0.0.1).
async fn relay(front: Front, rate: RateLimits) -> Server {
    let s = Server::start(Config { front, rate, ..Config::default() }).await;
    s.host(2, Roots::Any, 65_536, 3_600, NOW).await;
    s
}

/// A publish of a new envelope (one second earlier each `n`) to mailbox 2, with `headers`: its status.
async fn publish_as(s: &Server, n: u64, headers: &[(&str, &str)]) -> u16 {
    let body = bytes(&envelope(1, &[addr(2)], vec![], NOW - n));
    let mut all = vec![("Content-Type", "application/json")];
    all.extend_from_slice(headers);
    request(s.addr, "POST", "/v0/publish", &all, &body).await.status
}

const A: (&str, &str) = ("cf-connecting-ip", "203.0.113.7");
const B: (&str, &str) = ("cf-connecting-ip", "198.51.100.9");

#[tokio::test]
async fn the_fetch_ceiling_counts_every_client_together() {
    let rate = RateLimits { fetch_global_per_minute: 2, ..RateLimits::default() };
    let s = relay(trusting(&["127.0.0.0/8"], None), rate).await;
    let path = format!("/v0/fetch/record/{}/accept-from", addr(9));
    assert_eq!(request(s.addr, "GET", &path, &[A], &[]).await.status, 404);
    assert_eq!(request(s.addr, "GET", &path, &[B], &[]).await.status, 404);
    let over = request(s.addr, "GET", &path, &[A], &[]).await;
    assert_eq!((over.status, over.error().as_str()), (429, "rate-limited"), "{}", over.text());
    assert_eq!(over.header("retry-after"), Some((60 - NOW % 60).to_string().as_str()));
}

#[tokio::test]
async fn behind_a_trusted_proxy_each_client_has_its_own_daily_bytes() {
    let size = u64::try_from(bytes(&envelope(1, &[addr(2)], vec![], NOW - 1)).len()).unwrap();
    let rate = RateLimits { bytes_per_day: size, ..RateLimits::default() };
    let s = relay(trusting(&["127.0.0.0/8"], None), rate).await;
    let mut statuses = Vec::new();
    for (n, h) in [(1, A), (2, A), (3, B)] {
        statuses.push(publish_as(&s, n, &[h]).await);
    }
    assert_eq!(statuses, [200, 429, 200], "A's quota of one envelope, and B's own");
}

#[tokio::test]
async fn behind_a_trusted_proxy_the_fetch_window_counts_the_client_the_header_names() {
    let rate = RateLimits { fetch_per_ip: 2, ..RateLimits::default() };
    let s = relay(trusting(&["127.0.0.0/8"], None), rate).await;
    let path = format!("/v0/fetch/record/{}/accept-from", addr(9));
    let mut statuses = Vec::new();
    for h in [A, A, A, B] {
        statuses.push(request(s.addr, "GET", &path, &[h], &[]).await.status);
    }
    assert_eq!(statuses, [404, 404, 429, 404], "A's window of 2, and B's own");
}

#[tokio::test]
async fn l1_behind_a_trusted_proxy_each_client_named_in_the_header_has_its_own_step_3a_bucket() {
    let rate = RateLimits { per_ip: 3, ..RateLimits::default() };
    let s = relay(trusting(&["127.0.0.0/8"], None), rate).await;
    let mut statuses = Vec::new();
    for n in 1..=4 {
        statuses.push(publish_as(&s, n, &[A]).await);
    }
    statuses.push(publish_as(&s, 5, &[B]).await);
    statuses.push(publish_as(&s, 6, &[]).await);
    eprintln!("MEASURE L1 (b): trusted 127.0.0.0/8, 3 a window: A x4, B, the proxy itself -> {statuses:?}");
    assert_eq!(statuses, [200, 200, 200, 429, 200, 200], "three buckets: A, B and the proxy");
    // The same requests from a peer the relay does not trust: one bucket, the TCP peer's.
    for front in [trusting(&["10.0.0.0/8"], None), Front::default()] {
        let s = relay(front, rate).await;
        let mut statuses = Vec::new();
        for (n, h) in [(1, A), (2, A), (3, A), (4, A), (5, B)] {
            statuses.push(publish_as(&s, n, &[h]).await);
        }
        statuses.push(publish_as(&s, 6, &[]).await);
        eprintln!("MEASURE L1 (c): untrusted, the host record and the same requests -> {statuses:?}");
        assert_eq!(statuses, [200, 200, 429, 429, 429, 429], "the host record was the first of 3");
    }
}

#[tokio::test]
async fn l1_a_malformed_value_from_a_trusted_peer_counts_as_the_peer_and_x_forwarded_for_takes_the_right_most()
 {
    let rate = RateLimits { per_ip: 2, ..RateLimits::default() };
    let s = relay(trusting(&["127.0.0.0/8"], None), rate).await;
    let bad = [("cf-connecting-ip", "not-an-ip")];
    let port = [("cf-connecting-ip", "203.0.113.7:80")];
    let statuses =
        [publish_as(&s, 1, &bad).await, publish_as(&s, 2, &port).await, publish_as(&s, 3, &[A]).await];
    eprintln!("MEASURE L1 (d): host, not-an-ip, 203.0.113.7:80, then A, at 2 a window -> {statuses:?}");
    assert_eq!(statuses, [200, 429, 200], "the two malformed values in the proxy's bucket; A its own");
    let s =
        relay(trusting(&["127.0.0.0/8"], Some("x-forwarded-for")), RateLimits { per_ip: 1, ..rate }).await;
    let xff = [("x-forwarded-for", "192.0.2.1, 203.0.113.7, 127.0.0.1")];
    let statuses =
        [publish_as(&s, 1, &xff).await, publish_as(&s, 2, &xff).await, publish_as(&s, 3, &[A]).await];
    eprintln!(
        "MEASURE L1 (d): x-forwarded-for 192.0.2.1, 203.0.113.7, 127.0.0.1 twice, then cf-connecting-ip -> {statuses:?}"
    );
    assert_eq!(
        statuses,
        [200, 429, 429],
        "203.0.113.7 once; the cf-connecting-ip header is not read, the proxy's spent"
    );
}

#[tokio::test]
async fn l1_the_record_signers_quota_follows_the_named_client() {
    let rate = RateLimits { signers_per_day: 2, ..RateLimits::default() };
    let s =
        Server::start(Config { front: trusting(&["127.0.0.0/8"], None), rate, ..Config::default() }).await;
    let new_signer = |n: u8| record_bytes(&accept(n, Roots::Any, 65_536, 3_600, NOW));
    let mut statuses = Vec::new();
    for (n, h) in [(30, A), (31, A), (32, A), (33, B)] {
        let all = [("Content-Type", "application/json"), h];
        statuses.push(request(s.addr, "POST", "/v0/publish", &all, &new_signer(n)).await.status);
    }
    eprintln!("MEASURE L1 (e): 2 new signers a day, A x3 then B -> {statuses:?}");
    assert_eq!(statuses, [200, 200, 429, 200]);
}

/// A WebSocket from 127.0.0.1 naming `client` in cf-connecting-ip. The relay's first frame says what became of it.
async fn upgrade(s: &Server, client: Option<&str>) -> Ws {
    let mut call = s.ws_url().into_client_request().unwrap();
    if let Some(client) = client {
        call.headers_mut().insert("cf-connecting-ip", client.parse().unwrap());
    }
    tokio_tungstenite::connect_async(call).await.unwrap().0
}

#[tokio::test]
async fn l1_behind_a_trusted_proxy_the_cap_counts_websockets_by_client_and_never_the_proxy_itself() {
    let config =
        Config { front: trusting(&["127.0.0.0/8"], None), connections_per_ip: 3, ..Config::default() };
    let s = Server::start(config).await;
    // The proxy's own connections are not capped: ten held open at once, each then served. Every request is
    // written before any answer is read, so that none waits on the others' answers past the relay's header
    // timeout.
    let mut held = Vec::new();
    for _ in 0..10 {
        held.push(connect(s.addr).await);
    }
    for c in &mut held {
        c.write_all(b"GET /v0/health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await.unwrap();
    }
    let mut served = 0;
    for mut c in held {
        let (answer, _) = read_until_closed(&mut c, Instant::now() + PATIENCE).await;
        served += usize::from(answer.starts_with(b"HTTP/1.1 200"));
    }
    // One client's WebSockets: three, then the fourth refused with a code a client retries; another client's opens.
    let mut a = Vec::new();
    for _ in 0..3 {
        let mut ws = upgrade(&s, Some("203.0.113.7")).await;
        assert_eq!(ws_json(&mut ws).await["t"], "challenge");
        a.push(ws);
    }
    let mut fourth = upgrade(&s, Some("203.0.113.7")).await;
    let refused = ws_json(&mut fourth).await;
    let closed = ws_close_code(&mut fourth).await;
    let other = ws_json(&mut upgrade(&s, Some("198.51.100.9")).await).await;
    eprintln!(
        "MEASURE L1 (f): cap 3, 10 proxy connections {served} served; A's 4th {refused} {closed}; B's 1st {other}"
    );
    assert_eq!(served, 10);
    assert_eq!(refused, serde_json::json!({"t": "error", "error": "rate-limited"}), "over A's cap");
    assert_eq!(closed, 1013);
    assert_eq!(other["t"], "challenge", "B has its own places");
    // A place freed by a close is taken again, once the relay has read the close.
    drop(a.pop());
    tokio::time::sleep(Duration::from_millis(300)).await;
    let deadline = Instant::now() + PATIENCE;
    while ws_json(&mut upgrade(&s, Some("203.0.113.7")).await).await["t"] != "challenge" {
        assert!(Instant::now() < deadline, "the freed place taken again within {PATIENCE:?}");
        tokio::time::sleep(POLL).await;
    }
    // Without a header the proxy's own WebSockets count under its own address.
    assert_eq!(ws_json(&mut upgrade(&s, None).await).await["t"], "challenge");
}

// --- L6: the record answer ----------------------------------------------------------------------------

#[tokio::test]
async fn l6_a_record_publish_answers_its_kind_signer_iat_and_last_valid_second() {
    let s = Server::start(Config::default()).await;
    let address = {
        let mut r = Record::Address(AddressRecord {
            key: addr(5),
            sealing_key: None,
            relays: vec![],
            rotation_key: None,
            revoked: vec![],
            ttl: 600,
            iat: NOW - 10,
            rotated_from: None,
            rotation_sig: None,
            sig: [0; 64],
        });
        r.sign(&key(5)).unwrap();
        r
    };
    let keyed =
        KeyRecord { key: addr(6), sealing_key: "ab".repeat(32), iat: NOW, exp: NOW + 900, sig: [0; 64] };
    let mut keyed = Record::Key(keyed);
    keyed.sign(&key(6)).unwrap();
    let mut accepting = Record::AcceptFrom(AcceptFromRecord {
        owner: addr(7),
        roots: Roots::Any,
        max_bytes: 1,
        ttl: 1,
        iat: NOW,
        sig: [0; 64],
    });
    accepting.sign(&key(7)).unwrap();
    for (record, kind, signer, iat, until) in [
        (&address, "address", 5, NOW - 10, serde_json::json!(NOW + 590)),
        (&keyed, "key", 6, NOW, serde_json::json!(NOW + 900)),
        (&accepting, "accept-from", 7, NOW, serde_json::Value::Null),
    ] {
        let answer = s.publish(&record_bytes(record)).await;
        let want = serde_json::json!({"ok": true, "kind": kind, "signer": addr(signer).as_str(), "iat": iat,
            "valid_until": until});
        eprintln!("MEASURE L6: {kind} -> {}", answer.text());
        assert_eq!((answer.status, answer.json()), (200, want));
    }
    assert_eq!(s.relay.store().record(addr(7).as_str(), Kind::AcceptFrom).unwrap().unwrap().iat, NOW);
}

// --- L4: the probe ---------------------------------------------------------------------------------------

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

async fn run_probe(url: String, key_file: std::path::PathBuf) -> Result<String, String> {
    tokio::task::spawn_blocking(move || probe::run(&url, &key_file)).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l4_the_probe_checks_a_relay_end_to_end_storing_one_envelope_a_run_and_its_record_once() {
    let s = Server::start_system(Config::default()).await;
    let dir = TempDir::new("probe");
    let file = dir.path().join("probe.key");
    let url = format!("http://{}/", s.addr);
    let first = run_probe(url.clone(), file.clone()).await.unwrap();
    let seed = std::fs::read_to_string(&file).unwrap();
    let probe_key =
        ac_core::keys::SigningKey::from_seed(&ac_core::hex::decode_array::<32>(seed.trim()).unwrap());
    let me = probe_key.address();
    let store = s.relay.store();
    let record = store.record(me.as_str(), Kind::AcceptFrom).unwrap().unwrap();
    let second = run_probe(url.clone(), file.clone()).await.unwrap();
    assert_eq!(store.record(me.as_str(), Kind::AcceptFrom).unwrap().unwrap(), record, "published once");
    assert!(store.has_records(me.as_str()).unwrap());
    for kind in [Kind::Address, Kind::Key] {
        assert!(store.record(me.as_str(), kind).unwrap().is_none(), "nothing but its accept-from record");
    }
    let rows = store.mailbox_after(me.as_str(), 0, 10, now()).unwrap();
    eprintln!(
        "MEASURE L4: two runs: ids {first} and {second}; the probe's mailbox {} rows; one record",
        rows.len()
    );
    assert_ne!(first, second);
    assert_eq!(rows.len(), 2, "one envelope a run, in the probe's own mailbox");
    assert!(!first.contains(seed.trim()) && !second.contains(seed.trim()), "the seed is never printed");
    // Each row expires 60 s after it was stored, and the next sweep leaves only a tombstone.
    let later = now() + 61;
    let swept = store.sweep(later, 604_800 + 300).unwrap();
    assert_eq!((swept.mailbox, swept.envelopes, swept.tombstoned), (2, 2, 2));
    assert!(store.envelope(&first, later).unwrap().is_none() && store.has_envelope(&first, later).unwrap());
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l4_the_probe_names_the_step_that_failed() {
    let dir = TempDir::new("probe-fail");
    let file = dir.path().join("probe.key");
    // Over the per-address limit: the record counts, then the envelope is refused.
    let rate = RateLimits { per_ip: 1, ..RateLimits::default() };
    let s = Server::start_system(Config { rate, ..Config::default() }).await;
    let why = run_probe(format!("http://{}", s.addr), file.clone()).await.unwrap_err();
    eprintln!("MEASURE L4: --rate-per-ip 1 -> probe: {why}");
    assert!(why.starts_with("publish: 429 ") && why.contains("rate-limited"), "{why}");
    s.stop().await;
    // A relay whose clock is 1,000 s ahead: the envelope is inside the ts window, the fetch's AC-Ts is not.
    let s = Server::start(Config::default()).await;
    s.clock.set(now() + 1_000);
    let why = run_probe(format!("http://{}", s.addr), file.clone()).await.unwrap_err();
    eprintln!("MEASURE L4: a relay 1,000 s ahead -> probe: {why}");
    assert!(why.starts_with("fetch: 401 ") && why.contains("stale-ts"), "{why}");
    s.stop().await;
    // Health from something that is not a relay.
    let fake = FakeRelay::start().await;
    fake.set("/v0/health", "404 Not Found", b"{}");
    let why = run_probe(fake.url(), file.clone()).await.unwrap_err();
    assert_eq!(why, "health: 404 {}");
    fake.set("/v0/health", "200 OK", br#"{"ok":false}"#);
    assert_eq!(run_probe(fake.url(), file.clone()).await.unwrap_err(), r#"health: 200 {"ok":false}"#);
    fake.set("/v0/health", "200 Truncated", br#"{"ok":true}"#);
    let why = run_probe(fake.url(), file.clone()).await.unwrap_err();
    eprintln!("MEASURE L4: a health answer cut short -> probe: {why}");
    assert!(why.starts_with("health: ") && !why.starts_with("health: 200"), "{why}");
    // A key file of other content.
    fake.set("/v0/health", "200 OK", br#"{"ok":true}"#);
    let other = dir.path().join("other.key");
    std::fs::write(&other, "0123\n").unwrap();
    let why = run_probe(fake.url(), other.clone()).await.unwrap_err();
    assert_eq!(why, format!("key: {}: it does not hold 64 hex characters", other.display()));
    // The record step: a record fetch that fails, or a record publish that is refused.
    fake.set("/v0/fetch/record/", "500 Internal Server Error", br#"{"error":"internal"}"#);
    assert_eq!(run_probe(fake.url(), file.clone()).await.unwrap_err(), r#"record: 500 {"error":"internal"}"#);
    fake.set("/v0/fetch/record/", "404 Not Found", br#"{"error":"not-found"}"#);
    fake.set("/v0/publish", "409 Conflict", br#"{"error":"stale-record"}"#);
    assert_eq!(
        run_probe(fake.url(), file.clone()).await.unwrap_err(),
        r#"record: 409 {"error":"stale-record"}"#
    );
    // The publish step: a 200 that is not this envelope's delivery.
    fake.set("/v0/fetch/record/", "200 OK", b"{}");
    fake.set("/v0/publish", "200 OK", br#"{"ok":true,"id":"other","duplicate":false,"delivered":1}"#);
    let why = run_probe(fake.url(), file.clone()).await.unwrap_err();
    assert!(why.starts_with(r#"publish: 200 {"ok":true,"id":"other""#), "{why}");
    assert_eq!(fake.hits("/v0/publish"), 2, "the record (404 above) and this envelope");
}

/// The answers of a [`FakeRelay`]: a path prefix, a status line and a body each.
type Answers = Arc<Mutex<Vec<(String, String, Vec<u8>)>>>;

/// An HTTP server on loopback that answers each path prefix as a test set it, else 404, once it has read the
/// whole request ([`read_request`]).
struct FakeRelay {
    addr: SocketAddr,
    answers: Answers,
    hits: Arc<Mutex<Vec<String>>>,
}

impl FakeRelay {
    async fn start() -> FakeRelay {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let answers: Answers = Arc::default();
        let hits: Arc<Mutex<Vec<String>>> = Arc::default();
        let (a, h) = (Arc::clone(&answers), Arc::clone(&hits));
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let (a, h) = (Arc::clone(&a), Arc::clone(&h));
                tokio::spawn(async move {
                    let Some(head) = read_request(&mut socket).await else { return };
                    let path = head.split(' ').nth(1).unwrap_or("").to_owned();
                    h.lock().unwrap().push(path.clone());
                    let answer =
                        a.lock().unwrap().iter().rev().find(|(p, ..)| path.starts_with(p.as_str())).cloned();
                    let (_, status, body) = answer.unwrap_or_default();
                    let status = if status.is_empty() { "404 Not Found".to_owned() } else { status };
                    // "200 Truncated" promises ten bytes more than it sends, so the client's read of the body fails.
                    let (status, extra) =
                        if status == "200 Truncated" { ("200 OK".to_owned(), 10) } else { (status, 0) };
                    let reply = format!(
                        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len() + extra
                    );
                    let _ = socket.write_all(reply.as_bytes()).await;
                    let _ = socket.write_all(&body).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        FakeRelay { addr, answers, hits }
    }

    fn set(&self, path: &str, status: &str, body: &[u8]) {
        let mut answers = self.answers.lock().unwrap();
        answers.retain(|(p, ..)| p != path);
        answers.push((path.to_owned(), status.to_owned(), body.to_vec()));
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn hits(&self, prefix: &str) -> usize {
        self.hits.lock().unwrap().iter().filter(|p| p.starts_with(prefix)).count()
    }
}

/// Reads one HTTP request from `socket`: its head, then the body bytes its Content-Length names. A server
/// that answers and closes with request bytes unread, or still arriving, has the kernel reset the connection,
/// and the client then fails where it should read the answer: the probe's client sets a socket timeout before
/// each read, and on macOS that call fails with EINVAL on a reset socket (a red run:
/// `publish: io: Invalid argument (os error 22)`). The head, or `None` when the client went away first.
async fn read_request(socket: &mut TcpStream) -> Option<String> {
    let mut got = Vec::new();
    let mut chunk = [0u8; 4_096];
    loop {
        if let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&got[..end]).into_owned();
            let length = head
                .split("\r\n")
                .filter_map(|l| l.split_once(':'))
                .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
                .map_or(0, |(_, v)| v.trim().parse::<usize>().unwrap_or(0));
            if got.len() >= end + 4 + length {
                return Some(head);
            }
        }
        match socket.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => got.extend_from_slice(&chunk[..n]),
        }
    }
}

// --- L8 and L9: pending rows and the well-known cap ----------------------------------------------

const ACME: &str = "acme.test";

/// A well-known server on loopback: every request, read whole ([`read_request`]), gets the current answer
/// after `delay`; requests are counted.
struct WellKnownServer {
    addr: SocketAddr,
    answer: Arc<Mutex<(String, Vec<u8>, Duration)>>,
    requests: Arc<AtomicUsize>,
}

impl WellKnownServer {
    async fn start() -> WellKnownServer {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let answer =
            Arc::new(Mutex::new(("500 Internal Server Error".to_owned(), b"{}".to_vec(), Duration::ZERO)));
        let requests = Arc::new(AtomicUsize::new(0));
        let (a, n) = (Arc::clone(&answer), Arc::clone(&requests));
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let (a, n) = (Arc::clone(&a), Arc::clone(&n));
                tokio::spawn(async move {
                    if read_request(&mut socket).await.is_none() {
                        return;
                    }
                    n.fetch_add(1, Ordering::SeqCst);
                    let (status, body, delay) = a.lock().unwrap().clone();
                    tokio::time::sleep(delay).await;
                    let head = format!(
                        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = socket.write_all(head.as_bytes()).await;
                    let _ = socket.write_all(&body).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        WellKnownServer { addr, answer, requests }
    }

    fn serve(&self, status: &str, body: Vec<u8>, delay: Duration) {
        *self.answer.lock().unwrap() = (status.to_owned(), body, delay);
    }

    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

/// org key `key(n)`'s address record at `iat`, valid an hour, padded after its opening brace to `size` bytes.
fn org(n: u8, iat: u64, size: usize) -> Vec<u8> {
    let mut r = Record::Address(AddressRecord {
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
    });
    r.sign(&key(n)).unwrap();
    let bytes = r.to_bytes();
    let mut out = vec![b'{'];
    out.resize(size.max(bytes.len()) - bytes.len() + 1, b' ');
    out.extend_from_slice(&bytes[1..]);
    out
}

/// An envelope from key 1 to `to` under a chain from org key `root` through principal key 20, at `ts`.
fn rooted(root: u8, to: &[ac_core::Address], ts: u64) -> Vec<u8> {
    let chain = vec![
        Hop::sign(&key(root), &addr(20), vec![], NOW + 86_400).unwrap(),
        Hop::sign(&key(20), &addr(1), vec![], NOW + 86_400).unwrap(),
    ];
    bytes(&envelope(1, to, chain, ts))
}

fn domain_config(at: SocketAddr) -> Config {
    let resolve = vec![(Domain::parse(ACME).unwrap(), at)];
    let well_known = WellKnown { insecure_http: true, resolve, ..WellKnown::default() };
    Config { well_known, sweep_interval: Duration::from_secs(1), ..Config::default() }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l8_a_recipient_waiting_on_a_domain_is_delivered_by_the_sweeper_once_it_resolves_and_once_only() {
    let wk = WellKnownServer::start().await;
    let s = Server::start(domain_config(wk.addr)).await;
    s.host(2, Roots::WithDomains(vec![Root::Domain(Domain::parse(ACME).unwrap())]), 65_536, 600, NOW).await;
    s.host(5, Roots::Any, 65_536, 3_600, NOW).await;
    let env = rooted(10, &[addr(2), addr(5)], NOW);
    let id = serde_json::from_slice::<serde_json::Value>(&env).unwrap()["id"].as_str().unwrap().to_owned();
    let first = s.publish(&env).await;
    assert_eq!(
        (first.status, first.json()["delivered"].clone()),
        (200, serde_json::json!(1)),
        "{}",
        first.text()
    );
    let store = s.relay.store();
    assert_eq!(store.pending(NOW, 10).unwrap(), vec![(id.clone(), addr(2).to_string())]);
    assert!(store.mailbox_after(addr(2).as_str(), 0, 10, NOW).unwrap().is_empty());
    let again = s.publish(&env).await;
    assert_eq!(again.json()["duplicate"], true, "the duplicate rule");
    // The host answers now, and the manual clock passes the failure's minute: the sweeper's next round delivers.
    wk.serve("200 OK", org(10, NOW, 0), Duration::ZERO);
    s.clock.advance(61);
    let started = std::time::Instant::now();
    while store.mailbox_after(addr(2).as_str(), 0, 10, NOW + 61).unwrap().is_empty() {
        assert!(started.elapsed() < Duration::from_secs(5), "delivered within 5 s of the clock's step");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    eprintln!(
        "MEASURE L8: the pending row delivered {} ms after the clock passed the failure's minute",
        started.elapsed().as_millis()
    );
    assert!(store.pending(NOW + 61, 10).unwrap().is_empty());
    let (mut ws, _) = subscribe(&s, &key(2), &addr(2), &[], Some(0)).await;
    let frame = ws_json(&mut ws).await;
    assert_eq!(
        (frame["cursor"].clone(), frame["received_at"].clone()),
        (serde_json::json!(1), serde_json::json!(NOW))
    );
    assert_eq!(store.mailbox_after(addr(2).as_str(), 0, 10, NOW + 599).unwrap().len(), 1);
    assert!(
        store.mailbox_after(addr(2).as_str(), 0, 10, NOW + 600).unwrap().is_empty(),
        "received_at + min(TTL, 600)"
    );
    let third = s.publish(&env).await;
    assert_eq!(third.json()["duplicate"], true);
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert_eq!(store.last_cursor(addr(2).as_str()).unwrap(), 1, "one row, however many sweeps");
    assert_eq!(wk.requests(), 2);
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ld_1_a_retry_waiting_on_a_slow_host_does_not_hold_up_the_sweep() {
    let wk = WellKnownServer::start().await;
    let config = Config { sweep_interval: Duration::from_millis(50), ..domain_config(wk.addr) };
    let s = Server::start(config).await;
    s.host(2, Roots::WithDomains(vec![Root::Domain(Domain::parse(ACME).unwrap())]), 65_536, 600, NOW).await;
    s.host(5, Roots::Any, 65_536, 90, NOW).await;
    assert_eq!(s.publish(&rooted(10, &[addr(2), addr(5)], NOW)).await.status, 200);
    wk.serve("200 OK", org(10, NOW, 0), Duration::from_secs(4));
    s.clock.advance(61);
    let started = std::time::Instant::now();
    while wk.requests() < 2 {
        assert!(started.elapsed() < PATIENCE, "the sweeper's retry at the host within {PATIENCE:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Mailbox 5's row expires while the host holds the retry for 4 s: the next sweep takes it all the same.
    s.clock.advance(30);
    let store = s.relay.store();
    let expired = std::time::Instant::now();
    while !store.mailbox_after(addr(5).as_str(), 0, 10, NOW).unwrap().is_empty() {
        assert!(expired.elapsed() < Duration::from_secs(2), "the sweep waited for the retry");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    s.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l8_a_retry_waiting_on_a_slow_host_does_not_hold_up_the_relay_s_stop() {
    let wk = WellKnownServer::start().await;
    let s = Server::start(domain_config(wk.addr)).await;
    s.host(2, Roots::WithDomains(vec![Root::Domain(Domain::parse(ACME).unwrap())]), 65_536, 600, NOW).await;
    s.host(5, Roots::Any, 65_536, 3_600, NOW).await;
    assert_eq!(s.publish(&rooted(10, &[addr(2), addr(5)], NOW)).await.status, 200);
    wk.serve("200 OK", org(10, NOW, 0), Duration::from_secs(4));
    s.clock.advance(61);
    let started = std::time::Instant::now();
    while wk.requests() < 2 {
        assert!(started.elapsed() < PATIENCE, "the sweeper's retry at the host within {PATIENCE:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let stopping = std::time::Instant::now();
    s.stop().await;
    eprintln!(
        "MEASURE L8: stopped {} ms after the request, the host slow by 4 s",
        stopping.elapsed().as_millis()
    );
    assert!(stopping.elapsed() < Duration::from_millis(2_500), "{:?}", stopping.elapsed());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l9_a_well_known_record_over_65_536_bytes_resolves_as_at_an_edge() {
    let wk = WellKnownServer::start().await;
    let s = Server::start(domain_config(wk.addr)).await;
    s.host(2, Roots::WithDomains(vec![Root::Domain(Domain::parse(ACME).unwrap())]), 65_536, 600, NOW).await;
    let big = org(10, NOW, 100_000);
    assert_eq!(big.len(), 100_000);
    wk.serve("200 OK", big, Duration::ZERO);
    let r = s.publish(&rooted(10, &[addr(2)], NOW)).await;
    eprintln!("MEASURE L9: a 100,000-byte well-known record -> {} {}", r.status, r.text());
    assert_eq!((r.status, r.json()["delivered"].clone()), (200, serde_json::json!(1)));
    assert_eq!(s.relay.store().domain_pin(ACME).unwrap().unwrap().key, addr(10).to_string());
    s.stop().await;
}
