//! `--max-store-bytes`. Once the store's live bytes (its pages in use, not its file) reach the bound, an
//! envelope that would be stored is refused 503 `store-full` with a `Retry-After` of one sweep, and so is a record of a
//! signer the relay holds none of; a duplicate, a known signer's record, a fetch and the sweep go on, and once
//! the sweep has freed pages the publishes are taken again. The flag works in the binary.

mod common;

use ac_core::records::Roots;
use ac_relay::Config;
use ac_relay::config::RateLimits;
use ac_relay::store::sqlite::SqliteStore;
use common::{
    NOW, PATIENCE, Server, TempDir, accept, addr, bytes, envelope, key, read_url_line, record_bytes, request,
};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const BIN: &str = env!("CARGO_BIN_EXE_ac-relay");

#[tokio::test]
async fn a_publish_over_the_bound_is_refused_until_a_sweep_frees_pages() {
    let dir = TempDir::new("store-bound");
    let store = SqliteStore::open(&dir.path().join("relay.sqlite")).unwrap();
    let max = ac_relay::store::Store::live_bytes(&store).unwrap() + 32 * 1024;
    let s =
        Server::start_with_store(Config { max_store_bytes: max, ..Config::default() }, Arc::new(store)).await;
    s.host(2, Roots::Any, 65_536, 3_600, NOW).await;
    let mut stored = Vec::new();
    let refused = loop {
        let env = envelope(1, &[addr(2)], vec![], NOW - u64::try_from(stored.len()).unwrap());
        let r = s.publish(&bytes(&env)).await;
        if r.status != 200 {
            break r;
        }
        stored.push(env);
        assert!(stored.len() < 100, "no publish was refused: live {}", s.relay.store().live_bytes().unwrap());
    };
    assert_eq!((refused.status, refused.error().as_str()), (503, "store-full"), "{}", refused.text());
    assert_eq!(refused.header("retry-after"), Some("60"), "one sweep");
    let live = s.relay.store().live_bytes().unwrap();
    assert!(live >= max);
    eprintln!("MEASURE: refused after {} envelopes, live {live} against a bound of {max}", stored.len());
    // Reads and known signers go on: a fetch of a stored envelope, the same envelope published again (a duplicate
    // writes nothing), and a newer record of a mailbox the relay holds, so that a rotation or a revocation still lands.
    assert_eq!(s.fetch(&stored[0].id_hex(), &key(2), NOW, &[]).await.status, 200);
    let again = s.publish(&bytes(&stored[0])).await;
    assert_eq!((again.status, again.json()["duplicate"].clone()), (200, true.into()), "{}", again.text());
    s.host(2, Roots::Any, 65_536, 86_400, NOW + 1).await;
    // A signer it holds no record of is refused, and the refusal spends none of its address's quota of new signers.
    let stranger = record_bytes(&accept(3, Roots::Any, 65_536, 3_600, NOW));
    let full = s.publish(&stranger).await;
    assert_eq!((full.status, full.error().as_str()), (503, "store-full"), "{}", full.text());
    assert_eq!(full.header("retry-after"), Some("60"), "one sweep");
    // The rows expire and the sweep frees their pages: the live bytes fall under the bound, and publishes are taken.
    s.clock.advance(4_000);
    let swept = ac_relay::sweeper::sweep_once(&s.relay).unwrap();
    assert_eq!(swept.envelopes, stored.len());
    assert!(s.relay.store().live_bytes().unwrap() < max, "the sweep freed no pages");
    let next = s.publish(&bytes(&envelope(1, &[addr(2)], vec![], NOW + 4_000))).await;
    assert_eq!(next.status, 200, "{}", next.text());
    assert_eq!(s.publish(&stranger).await.status, 200, "the new signer is taken again");
    s.stop().await;
}

#[tokio::test]
async fn an_address_stores_its_daily_bytes_then_waits_for_the_next_utc_day() {
    let first = bytes(&envelope(1, &[addr(2)], vec![], NOW));
    let rate = RateLimits { bytes_per_day: 2 * u64::try_from(first.len()).unwrap(), ..RateLimits::default() };
    let s = Server::start(Config { rate, ..Config::default() }).await;
    s.host(2, Roots::Any, 65_536, 3_600, NOW).await;
    assert_eq!(s.publish(&first).await.status, 200);
    // A duplicate stores nothing and counts nothing.
    assert_eq!(s.publish(&first).await.json()["duplicate"], true);
    assert_eq!(s.publish(&bytes(&envelope(1, &[addr(2)], vec![], NOW - 1))).await.status, 200);
    let over = s.publish(&bytes(&envelope(1, &[addr(2)], vec![], NOW - 2))).await;
    assert_eq!((over.status, over.error().as_str()), (429, "rate-limited"), "{}", over.text());
    let wait = (86_400 - NOW % 86_400).to_string();
    assert_eq!(over.header("retry-after"), Some(wait.as_str()));
    // A record is not mail: it counts nothing and is taken past the quota.
    s.host(2, Roots::Any, 65_536, 3_600, NOW + 1).await;
    s.clock.advance(86_400 - NOW % 86_400);
    let next = s.publish(&bytes(&envelope(1, &[addr(2)], vec![], NOW + 86_400 - NOW % 86_400))).await;
    assert_eq!(next.status, 200, "{}", next.text());
    s.stop().await;
}

#[tokio::test]
async fn a_refused_new_signer_spends_none_of_its_addresss_quota() {
    let dir = TempDir::new("store-bound-quota");
    let store = SqliteStore::open(&dir.path().join("relay.sqlite")).unwrap();
    let rate = RateLimits { signers_per_day: 1, ..RateLimits::default() };
    let config = Config { rate, max_store_bytes: 1, ..Config::default() };
    let s = Server::start_with_store(config, Arc::new(store)).await;
    for owner in [3, 4, 5] {
        let r = s.publish(&record_bytes(&accept(owner, Roots::Any, 65_536, 3_600, NOW))).await;
        assert_eq!((r.status, r.error().as_str()), (503, "store-full"), "{}", r.text());
    }
    s.stop().await;
}

/// The relay binary, on a database of `dir`.
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
        let started = std::time::Instant::now();
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
    /// SIGTERM, so that the relay exits on its own (and an instrumented build writes its coverage), then SIGKILL.
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
async fn the_flag_bounds_the_binary_for_envelopes_and_new_signers_not_for_a_known_one() {
    let dir = TempDir::new("store-bound-binary");
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let publish = |addr, body: Vec<u8>| async move { request(addr, "POST", "/v0/publish", &[], &body).await };
    // Hosted with no bound, then started again with one no store can be under.
    {
        let relay = Relay::spawn(&dir, &[]);
        let hosted = publish(relay.addr, record_bytes(&accept(2, Roots::Any, 65_536, 3_600, now))).await;
        assert_eq!(hosted.status, 200, "{}", hosted.text());
    }
    let relay = Relay::spawn(&dir, &["--max-store-bytes", "1"]);
    let refused = publish(relay.addr, bytes(&envelope(1, &[addr(2)], vec![], now))).await;
    assert_eq!((refused.status, refused.error().as_str()), (503, "store-full"), "{}", refused.text());
    assert_eq!(refused.header("retry-after"), Some("60"));
    let stranger = publish(relay.addr, record_bytes(&accept(3, Roots::Any, 65_536, 3_600, now))).await;
    assert_eq!((stranger.status, stranger.error().as_str()), (503, "store-full"), "{}", stranger.text());
    let known = publish(relay.addr, record_bytes(&accept(2, Roots::Any, 65_536, 3_600, now + 1))).await;
    assert_eq!(known.status, 200, "a known signer is not bounded: {}", known.text());
    let health = request(relay.addr, "GET", "/v0/health", &[], b"").await;
    assert_eq!(health.status, 200, "reads go on");
}
