//! The domain resolver: the real fetch against raw servers on loopback (the guard, the caps, no redirect, the
//! address it connects to, TLS with the host's name), then the cache, the pins, rotations, failures and their
//! memory through a relay with a fake fetch and a manual clock.

use super::testkit::{FakeFetch, FakeTxt, RawServer, domain, org, org_bytes, well_known};
use super::{CACHE_FLOOR, FAILURE_TTL, Failure, Grant, HttpsFetcher, WellKnownFetch as _, system_lookup};
use crate::clock::ManualClock;
use crate::config::{Config, WellKnown};
use crate::relay::Relay;
use crate::store::memory::MemoryStore;
use crate::store::{
    Delivery, DomainPin, MailboxEntry, NewEnvelope, Store, StoreResult, StoredEnvelope, StoredRecord, Swept,
};
use crate::testkit::{NOW, accept, addr, record_bytes};
use ac_core::Code;
use ac_core::net::Category;
use ac_core::records::{Kind, Record, Roots};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const ACME: &str = "acme.example";

/// A fetcher over plain http with no guard, every host resolved to `at`: the test-only settings.
fn insecure(at: SocketAddr) -> HttpsFetcher {
    HttpsFetcher::new(&WellKnown {
        timeout: Duration::from_secs(2),
        insecure_http: true,
        resolve: vec![(domain(ACME), at)],
        ..WellKnown::default()
    })
}

#[test]
fn every_failure_has_its_reason() {
    let reasons = [
        (Failure::Dns("x".into()), "dns-failed"),
        (Failure::NoAddress, "no-address"),
        (
            Failure::NonPublic { address: IpAddr::V4(Ipv4Addr::LOCALHOST), category: Category::Loopback },
            "non-public-address",
        ),
        (Failure::Timeout, "timeout"),
        (Failure::Fetch("x".into()), "fetch-failed"),
        (Failure::Status(404), "http-status"),
        (Failure::TooLarge, "too-large"),
        (Failure::Record(Code::BadRecordSig), "bad-record-sig"),
        (Failure::NotAddress, "not-an-address-record"),
        (
            Failure::PinMismatch { pinned: "a".into(), offered: "b".into(), check: Code::BadRotation },
            "pin-mismatch",
        ),
        (Failure::NotCached, "not-cached"),
    ];
    for (f, reason) in reasons {
        assert_eq!(f.reason(), reason);
    }
}

#[tokio::test]
async fn it_gets_the_record_at_the_well_known_path_and_nothing_else() {
    let body = org_bytes(10, NOW, 3_600, &[], None);
    let server = RawServer::http("200 OK", &body, "").await;
    assert_eq!(insecure(server.addr).fetch(&well_known(ACME)).await, Ok(body));
    let request = String::from_utf8(server.first_bytes()).unwrap();
    assert!(request.starts_with("GET /.well-known/bag/address.json HTTP/1.1\r\n"), "{request}");
    let head = request.to_ascii_lowercase();
    assert!(
        head.contains("host: acme.example\r\n") && head.contains("accept: application/json\r\n"),
        "{head}"
    );
    assert!(head.contains("user-agent: ac-relay/"), "{head}");
}

#[tokio::test]
async fn a_status_other_than_200_a_redirect_and_a_large_body_are_failures() {
    let missing = RawServer::http("404 Not Found", b"{}", "").await;
    assert_eq!(insecure(missing.addr).fetch(&well_known(ACME)).await, Err(Failure::Status(404)));
    let target = RawServer::http("200 OK", &org_bytes(10, NOW, 3_600, &[], None), "").await;
    let location = format!("location: http://{}/.well-known/bag/address.json\r\n", target.addr);
    let redirect = RawServer::http("302 Found", b"", &location).await;
    assert_eq!(insecure(redirect.addr).fetch(&well_known(ACME)).await, Err(Failure::Status(302)));
    assert_eq!(target.connections(), 0, "no redirect is followed");
    // One cap with the edge's: 262,144 bytes read, one more refused.
    let large = RawServer::http("200 OK", &vec![b' '; 262_145], "").await;
    assert_eq!(insecure(large.addr).fetch(&well_known(ACME)).await, Err(Failure::TooLarge));
    let exact = RawServer::http("200 OK", &vec![b' '; 262_144], "").await;
    assert_eq!(insecure(exact.addr).fetch(&well_known(ACME)).await.map(|b| b.len()), Ok(262_144));
    let main_s = RawServer::http("200 OK", &vec![b' '; 65_537], "").await;
    assert_eq!(
        insecure(main_s.addr).fetch(&well_known(ACME)).await.map(|b| b.len()),
        Ok(65_537),
        "too large on main"
    );
}

#[tokio::test]
async fn a_silent_server_times_out_and_a_closed_port_fails() {
    let silent = RawServer::start(None).await;
    let mut f = insecure(silent.addr);
    f.timeout = Duration::from_secs(1);
    assert_eq!(f.fetch(&well_known(ACME)).await, Err(Failure::Timeout));
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    assert!(matches!(insecure(closed).fetch(&well_known(ACME)).await, Err(Failure::Fetch(_))));
}

static LOOKUPS: AtomicUsize = AtomicUsize::new(0);
static STUB: std::sync::Mutex<Option<SocketAddr>> = std::sync::Mutex::new(None);

#[allow(clippy::unnecessary_wraps, reason = "a Lookup returns a Result")]
fn counting_lookup(_host: &str, _port: u16) -> std::io::Result<Vec<SocketAddr>> {
    LOOKUPS.fetch_add(1, Ordering::SeqCst);
    Ok(STUB.lock().unwrap().iter().copied().collect())
}

#[tokio::test]
async fn the_host_is_resolved_once_and_the_connection_goes_to_that_address() {
    // DNS rebinding: one lookup, the guard on its answer, and ureq handed exactly those addresses. The host,
    // acme.example, resolves nowhere else, so a second lookup by the client would fail the fetch.
    let body = org_bytes(10, NOW, 3_600, &[], None);
    let server = RawServer::http("200 OK", &body, "").await;
    *STUB.lock().unwrap() = Some(server.addr);
    let f = HttpsFetcher { resolve: vec![], lookup: counting_lookup, ..insecure(server.addr) };
    assert_eq!(f.fetch(&well_known(ACME)).await, Ok(body));
    assert_eq!((LOOKUPS.load(Ordering::SeqCst), server.connections()), (1, 1));
}

#[allow(clippy::unnecessary_wraps, reason = "a Lookup returns a Result")]
fn no_address(_host: &str, _port: u16) -> std::io::Result<Vec<SocketAddr>> {
    Ok(vec![])
}

fn no_dns(_host: &str, _port: u16) -> std::io::Result<Vec<SocketAddr>> {
    Err(std::io::Error::other("no such host"))
}

#[allow(clippy::unnecessary_wraps, reason = "a Lookup returns a Result")]
fn public_then_private(_host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    Ok(vec![SocketAddr::from(([8, 8, 8, 8], port)), SocketAddr::from(([10, 0, 0, 1], port))])
}

#[tokio::test]
async fn the_guard_refuses_a_host_with_any_address_that_is_not_public_before_connecting() {
    let server = RawServer::http("200 OK", &org_bytes(10, NOW, 3_600, &[], None), "").await;
    let guarded = HttpsFetcher { http: false, any_address: false, ..insecure(server.addr) };
    let refused = guarded.fetch(&well_known(ACME)).await;
    let loopback = Failure::NonPublic { address: server.addr.ip(), category: Category::Loopback };
    assert_eq!(refused, Err(loopback));
    let mixed = HttpsFetcher { resolve: vec![], lookup: public_then_private, ..guarded.clone() };
    let private = Failure::NonPublic { address: "10.0.0.1".parse().unwrap(), category: Category::Private };
    assert_eq!(mixed.fetch(&well_known(ACME)).await, Err(private));
    assert_eq!(server.connections(), 0, "a refused host is never connected to");
    let empty = HttpsFetcher { resolve: vec![], lookup: no_address, ..guarded.clone() };
    assert_eq!(empty.fetch(&well_known(ACME)).await, Err(Failure::NoAddress));
    let failing = HttpsFetcher { resolve: vec![], lookup: no_dns, ..guarded };
    assert_eq!(failing.fetch(&well_known(ACME)).await, Err(Failure::Dns("no such host".into())));
}

#[tokio::test]
async fn https_presents_the_host_name_to_the_address_it_connects_to_and_fails_closed_on_a_bad_handshake() {
    let server = RawServer::start(Some(b"HTTP/1.1 200 OK\r\n\r\nnot tls".to_vec())).await;
    let tls = HttpsFetcher { http: false, ..insecure(server.addr) };
    assert!(matches!(tls.fetch(&well_known(ACME)).await, Err(Failure::Fetch(_))));
    let hello = server.first_bytes();
    // A TLS handshake record whose ClientHello names acme.example (server name indication, in the clear).
    assert_eq!(hello.first(), Some(&0x16));
    assert!(hello.windows(ACME.len()).any(|w| w == ACME.as_bytes()));
}

#[test]
fn the_system_lookup_reads_the_hosts_file() {
    let addrs = system_lookup("localhost", 80).unwrap();
    assert!(!addrs.is_empty() && addrs.iter().all(|a| a.ip().is_loopback() && a.port() == 80), "{addrs:?}");
}

struct World {
    relay: Relay,
    clock: Arc<ManualClock>,
    store: Arc<dyn Store>,
    fake: Arc<FakeFetch>,
}

fn world_with(config: Config, store: Arc<dyn Store>) -> World {
    let clock = Arc::new(ManualClock::new(NOW));
    let fake = FakeFetch::new();
    let relay = Relay::new(Arc::clone(&store), clock.clone(), config).with_fetcher(fake.clone());
    World { relay, clock, store, fake }
}

fn world() -> World {
    world_with(Config::default(), Arc::new(MemoryStore::new()))
}

impl World {
    fn serve(&self, bytes: Vec<u8>) {
        self.fake.set(ACME, Ok(bytes));
    }

    async fn grant(&self) -> Grant {
        self.relay.resolve_grant(&domain(ACME)).await.unwrap()
    }

    fn pin(&self) -> DomainPin {
        self.store.domain_pin(ACME).unwrap().unwrap()
    }
}

fn key_of(grant: &Grant) -> String {
    match grant {
        Grant::Key { key, .. } => key.to_string(),
        Grant::Unresolved(f) => panic!("unresolved: {f:?}"),
    }
}

#[tokio::test]
async fn first_contact_pins_the_key_and_the_cache_answers_until_the_record_expires() {
    let w = world();
    let first = org_bytes(10, NOW, 3_600, &[addr(50)], None);
    w.serve(first.clone());
    assert_eq!(w.relay.cached_grant(&domain(ACME)).unwrap(), None);
    assert_eq!(w.grant().await, Grant::Key { key: addr(10), revoked: vec![addr(50)] });
    assert_eq!(
        w.pin(),
        DomainPin {
            domain: ACME.into(),
            key: addr(10).to_string(),
            record: first,
            pinned_at: NOW,
            expires_at: NOW + 3_600
        }
    );
    w.clock.advance(3_599);
    assert_eq!(key_of(&w.grant().await), addr(10).to_string());
    assert_eq!(w.fake.calls(ACME), 1, "answered from the cache");
    // At iat + ttl the record is read again: the same key refreshes the pin and keeps its first contact.
    w.clock.advance(1);
    let again = org_bytes(10, NOW + 3_600, 3_600, &[], None);
    w.serve(again.clone());
    assert_eq!(w.grant().await, Grant::Key { key: addr(10), revoked: vec![] });
    assert_eq!(w.fake.calls(ACME), 2);
    let pin = w.pin();
    assert_eq!((pin.record, pin.pinned_at, pin.expires_at), (again.clone(), NOW, NOW + 7_200));
    // An older record of the same key rolls nothing back, however long it lives: the grant, the pin and its expiry
    // stay the newer record's while that is valid.
    w.clock.advance(3_600);
    let older = org_bytes(10, NOW + 3_500, 86_400, &[addr(51)], None);
    w.serve(older.clone());
    assert_eq!(w.grant().await, Grant::Key { key: addr(10), revoked: vec![] });
    let pin = w.pin();
    assert_eq!((pin.record, pin.expires_at), (again, NOW + 7_200 + CACHE_FLOOR));
    // Once the newer record has lapsed, the older one is the newest valid record.
    w.clock.advance(CACHE_FLOOR);
    assert_eq!(w.grant().await, Grant::Key { key: addr(10), revoked: vec![addr(51)] });
    assert_eq!(w.pin().record, older);
}

#[tokio::test]
async fn the_cache_has_a_60_second_floor_and_the_relay_s_ceiling() {
    let w = world();
    w.serve(org_bytes(10, NOW, 10, &[], None));
    w.grant().await;
    assert_eq!(w.pin().expires_at, NOW + CACHE_FLOOR);
    for (cache_max, expires) in [(100, NOW + 100), (1, NOW + 1)] {
        let config =
            Config { well_known: WellKnown { cache_max, ..WellKnown::default() }, ..Config::default() };
        let w = world_with(config, Arc::new(MemoryStore::new()));
        w.serve(org_bytes(10, NOW, 3_600, &[], None));
        w.grant().await;
        assert_eq!(w.pin().expires_at, expires, "cache max {cache_max}");
    }
}

/// A world whose ceiling of 60 s reads acme's record again every minute while each record stays valid for an hour.
fn minute_world() -> World {
    let config =
        Config { well_known: WellKnown { cache_max: 60, ..WellKnown::default() }, ..Config::default() };
    world_with(config, Arc::new(MemoryStore::new()))
}

#[tokio::test]
async fn a_countersigned_rotation_moves_the_pin_and_a_mismatch_keeps_the_pinned_key_while_its_record_is_valid()
 {
    let w = minute_world();
    w.serve(org_bytes(10, NOW, 3_600, &[], None));
    w.grant().await;
    w.clock.advance(60);
    w.serve(org_bytes(11, NOW + 60, 3_600, &[], Some((10, Some(10)))));
    assert_eq!(key_of(&w.grant().await), addr(11).to_string());
    assert_eq!((w.pin().key, w.pin().pinned_at), (addr(11).to_string(), NOW + 60));
    // A bare rotation: a mismatch, remembered; the pin stays, and its key stays current.
    w.clock.advance(60);
    w.serve(org_bytes(12, NOW + 120, 3_600, &[], Some((11, None))));
    let kept = Grant::Key { key: addr(11), revoked: vec![] };
    assert_eq!(w.grant().await, kept);
    assert_eq!(w.pin().key, addr(11).to_string(), "the pin stays");
    w.clock.advance(FAILURE_TTL - 1);
    assert_eq!(w.relay.cached_grant(&domain(ACME)).unwrap(), Some(kept.clone()));
    assert_eq!(w.fake.calls(ACME), 3, "remembered: no new fetch inside 60 s");
    // A rotation countersigned by another key is a mismatch too, and the pinned key is still current.
    w.clock.advance(1);
    w.serve(org_bytes(13, NOW + 180, 3_600, &[], Some((11, Some(13)))));
    assert_eq!(w.grant().await, kept);
    assert_eq!(w.fake.calls(ACME), 4);
    // Past the pinned record's iat + ttl, a mismatch grants nothing.
    w.clock.set(NOW + 60 + 3_601);
    let mismatch = Failure::PinMismatch {
        pinned: addr(11).to_string(),
        offered: addr(13).to_string(),
        check: Code::BadRotation,
    };
    assert_eq!(w.grant().await, Grant::Unresolved(mismatch.clone()));
    assert_eq!(w.relay.cached_grant(&domain(ACME)).unwrap(), Some(Grant::Unresolved(mismatch)));
    // A new record of the pinned key restores it.
    w.clock.advance(FAILURE_TTL);
    w.serve(org_bytes(11, NOW + 3_721, 3_600, &[], None));
    assert_eq!(key_of(&w.grant().await), addr(11).to_string());
    assert_eq!(w.fake.calls(ACME), 6);
}

#[tokio::test]
async fn a_failed_fetch_keeps_a_valid_pin_current_and_grants_nothing_without_one() {
    let w = minute_world();
    w.serve(org_bytes(10, NOW, 3_600, &[addr(50)], None));
    w.grant().await;
    w.clock.advance(60);
    w.fake.set(ACME, Err(Failure::Timeout));
    assert_eq!(w.grant().await, Grant::Key { key: addr(10), revoked: vec![addr(50)] });
    assert_eq!(
        w.relay.cached_grant(&domain(ACME)).unwrap(),
        Some(Grant::Key { key: addr(10), revoked: vec![addr(50)] })
    );
    let fresh = minute_world();
    fresh.fake.set(ACME, Err(Failure::Timeout));
    assert_eq!(fresh.grant().await, Grant::Unresolved(Failure::Timeout));
    assert_eq!(fresh.relay.cached_grant(&domain(ACME)).unwrap(), Some(Grant::Unresolved(Failure::Timeout)));
}

#[tokio::test]
async fn a_record_that_does_not_verify_or_is_not_an_address_record_grants_nothing() {
    let cases = [
        (b"not json".to_vec(), Failure::Record(Code::BadJson)),
        (b"{\"kind\":\"address\"}".to_vec(), Failure::Record(Code::BadRecord)),
        (org_bytes(10, NOW - 3_601, 3_600, &[], None), Failure::Record(Code::RecordExpired)),
        (org_bytes(10, NOW + 301, 3_600, &[], None), Failure::Record(Code::FutureIat)),
        (record_bytes(&accept(10, Roots::Any, 1, 1, NOW)), Failure::NotAddress),
    ];
    for (bytes, failure) in cases {
        let w = world();
        w.serve(bytes);
        assert_eq!(w.grant().await, Grant::Unresolved(failure.clone()), "{failure:?}");
        assert_eq!(w.store.domain_pin(ACME).unwrap(), None);
    }
    let w = world();
    let mut forged = org(10, NOW, 3_600, &[], None);
    forged.ttl = 60;
    w.serve(Record::Address(forged).to_bytes());
    assert_eq!(w.grant().await, Grant::Unresolved(Failure::Record(Code::BadRecordSig)));
}

#[tokio::test]
async fn concurrent_publishes_resolve_a_domain_once() {
    let w = world();
    w.serve(org_bytes(10, NOW, 3_600, &[], None));
    *w.fake.delay.lock().unwrap() = Duration::from_millis(200);
    let (a, b, c) = tokio::join!(w.grant(), w.grant(), w.grant());
    assert_eq!(
        (key_of(&a), key_of(&b), key_of(&c)),
        (addr(10).to_string(), addr(10).to_string(), addr(10).to_string())
    );
    assert_eq!(w.fake.calls(ACME), 1);
    assert!(w.relay.domains.flights.lock().unwrap().is_empty(), "no flight is left behind");
}

#[tokio::test]
async fn remembered_failures_are_pruned_once_they_expire() {
    let w = world();
    for (i, host) in ["a.example", "b.example", "c.example"].into_iter().enumerate() {
        w.clock.set(NOW + 61 * u64::try_from(i).unwrap());
        assert!(matches!(w.relay.resolve_grant(&domain(host)).await.unwrap(), Grant::Unresolved(_)));
    }
    let failures = w.relay.domains.failures();
    assert_eq!(failures.keys().map(String::as_str).collect::<Vec<_>>(), ["c.example"]);
}

/// A store that keeps no domain pins: Store's defaults.
struct NoPins(MemoryStore);

impl Store for NoPins {
    fn record(&self, a: &str, k: Kind) -> StoreResult<Option<StoredRecord>> {
        self.0.record(a, k)
    }
    fn put_record(&self, a: &str, k: Kind, iat: u64, e: Option<u64>, b: &[u8]) -> StoreResult<bool> {
        self.0.put_record(a, k, iat, e, b)
    }
    fn revoked(&self, a: &str) -> StoreResult<Vec<String>> {
        self.0.revoked(a)
    }
    fn has_envelope(&self, id: &str, now: u64) -> StoreResult<bool> {
        self.0.has_envelope(id, now)
    }
    fn insert_envelope(&self, e: &NewEnvelope<'_>, d: &[Delivery]) -> StoreResult<Option<Vec<u64>>> {
        self.0.insert_envelope(e, d)
    }
    fn envelope(&self, id: &str, now: u64) -> StoreResult<Option<StoredEnvelope>> {
        self.0.envelope(id, now)
    }
    fn mailbox_after(&self, a: &str, after: u64, l: usize, now: u64) -> StoreResult<Vec<MailboxEntry>> {
        self.0.mailbox_after(a, after, l, now)
    }
    fn last_cursor(&self, a: &str) -> StoreResult<u64> {
        self.0.last_cursor(a)
    }
    fn ack(&self, a: &str, s: &str, c: u64) -> StoreResult<()> {
        self.0.ack(a, s, c)
    }
    fn acked(&self, a: &str, s: &str) -> StoreResult<Option<u64>> {
        self.0.acked(a, s)
    }
    fn sweep(&self, now: u64, w: u64) -> StoreResult<Swept> {
        self.0.sweep(now, w)
    }
    fn pending(&self, now: u64, limit: usize) -> StoreResult<Vec<(String, String)>> {
        self.0.pending(now, limit)
    }
    fn settle_pending(&self, id: &str, addr: &str, deliver: Option<u64>) -> StoreResult<Option<u64>> {
        self.0.settle_pending(id, addr, deliver)
    }
}

#[tokio::test]
async fn a_store_without_pins_or_with_a_corrupt_pin_is_a_500() {
    let w = world_with(Config::default(), Arc::new(NoPins(MemoryStore::new())));
    w.serve(org_bytes(10, NOW, 3_600, &[], None));
    assert_eq!(w.relay.resolve_grant(&domain(ACME)).await.unwrap_err().status, 500);
    assert!(w.store.put_domain_pin(&acme_pin(b"x")).is_err());
    assert!(w.store.delete_domain_pin(ACME).is_err());
    let w = world();
    w.store.put_domain_pin(&acme_pin(b"{not a record")).unwrap();
    assert_eq!(w.relay.cached_grant(&domain(ACME)).unwrap_err().status, 500);
    // A pin whose record is another key's.
    w.store
        .put_domain_pin(&DomainPin {
            key: addr(11).to_string(),
            ..acme_pin(&org_bytes(10, NOW, 60, &[], None))
        })
        .unwrap();
    assert_eq!(w.relay.cached_grant(&domain(ACME)).unwrap_err().status, 500);
    // An expired pin is read only to check a rotation: corrupt then, it is a 500 too.
    w.clock.advance(7_200);
    w.serve(org_bytes(12, NOW + 7_200, 60, &[], Some((11, Some(11)))));
    assert_eq!(w.relay.resolve_grant(&domain(ACME)).await.unwrap_err().status, 500);
}

/// A pin of acme.example holding `record`, fresh for an hour.
fn acme_pin(record: &[u8]) -> DomainPin {
    DomainPin {
        domain: ACME.into(),
        key: addr(10).to_string(),
        record: record.to_vec(),
        pinned_at: NOW,
        expires_at: NOW + 3_600,
    }
}

// ---- The TXT path (spec/SPEC.md §12.2, §8.8 item 1) ----------------

const BAG: &str = "bag.acme.example";

/// A world whose TXT lookups go to a fake, so that a test sets acme's TXT records.
fn txt_world(config: Config) -> (World, Arc<FakeTxt>) {
    let w = world_with(config, Arc::new(MemoryStore::new()));
    let txt = FakeTxt::new();
    let relay = w.relay.with_txt(txt.clone());
    (World { relay, ..w }, txt)
}

/// The TXT record naming `key(key)`, with `host=bag` when `host`.
fn txt_of(key: u8, host: bool) -> String {
    let host = if host { "; host=bag" } else { "" };
    format!("v=ac1; key={}{host}", addr(key))
}

#[tokio::test]
async fn a_txt_record_with_host_leads_to_the_bag_origin_and_its_key_is_pinned() {
    let (w, txt) = txt_world(Config::default());
    assert_eq!(w.relay.txt_source(), "fixed");
    txt.set(ACME, &["v=spf1 -all", &txt_of(10, true)]);
    w.fake.set(BAG, Ok(org_bytes(10, NOW, 3_600, &[], None)));
    assert_eq!(key_of(&w.grant().await), addr(10).to_string());
    assert_eq!((txt.lookups(), w.fake.calls(BAG), w.fake.calls(ACME)), (1, 1, 0));
    assert_eq!(w.fake.urls(), ["https://bag.acme.example/.well-known/bag/address.json"]);
    assert_eq!(w.pin().key, addr(10).to_string());
}

#[tokio::test]
async fn a_record_of_another_key_than_the_txt_s_pins_nothing_and_is_remembered() {
    let (w, txt) = txt_world(Config::default());
    txt.set(ACME, &[&txt_of(11, false)]);
    w.serve(org_bytes(10, NOW, 3_600, &[], None));
    let refused = Failure::TxtKeyMismatch { txt: addr(11).to_string(), offered: addr(10).to_string() };
    assert_eq!(w.grant().await, Grant::Unresolved(refused.clone()));
    assert_eq!(w.store.domain_pin(ACME).unwrap(), None, "nothing pinned");
    assert_eq!(
        w.fake.urls(),
        [format!("https://{ACME}/.well-known/bag/address.json")],
        "no rec: the well-known URL"
    );
    w.clock.advance(FAILURE_TTL - 1);
    assert_eq!(w.grant().await, Grant::Unresolved(refused));
    assert_eq!((txt.lookups(), w.fake.calls(ACME)), (1, 1), "remembered: no lookup and no fetch inside 60 s");
    assert_eq!(
        Failure::TxtKeyMismatch { txt: String::new(), offered: String::new() }.reason(),
        "txt-key-mismatch"
    );
}

#[tokio::test]
async fn no_txt_record_reads_the_well_known_url_and_a_key_only_txt_checks_the_key() {
    let (w, txt) = txt_world(Config::default());
    w.serve(org_bytes(10, NOW, 3_600, &[], None));
    assert_eq!(key_of(&w.grant().await), addr(10).to_string());
    assert_eq!((txt.lookups(), w.fake.urls().len()), (1, 1));
    let (w, txt) = txt_world(Config::default());
    txt.set(ACME, &[&txt_of(10, false)]);
    w.serve(org_bytes(10, NOW, 3_600, &[], None));
    assert_eq!(key_of(&w.grant().await), addr(10).to_string(), "the TXT's key signs the record");
    assert_eq!(w.fake.urls(), [format!("https://{ACME}/.well-known/bag/address.json")]);
}

#[tokio::test]
async fn a_malformed_txt_two_records_and_a_failed_lookup_fetch_nothing_and_pin_nothing() {
    type SetTxt<'a> = &'a dyn Fn(&FakeTxt);
    let rec = format!("{}; rec=https://{BAG}/.well-known/bag/address.json", txt_of(10, true));
    let cases: [(SetTxt, Failure); 5] = [
        (
            &|t| t.set(ACME, &[&format!("{}; key={}", txt_of(10, false), addr(10))]),
            Failure::TxtMalformed("a TXT field given twice"),
        ),
        (&|t| t.set(ACME, &[&txt_of(10, false), &txt_of(10, true)]), Failure::TxtAmbiguous(2)),
        (&|t| t.fail(ACME, "servfail"), Failure::TxtLookup("servfail".into())),
        // DNS names no URL, and `host` is exactly bag.
        (&|t| t.set(ACME, &[&rec]), Failure::TxtMalformed("the TXT names a rec: DNS names no URL")),
        (
            &|t| t.set(ACME, &[&format!("{}; host=agents", txt_of(10, false))]),
            Failure::TxtMalformed("the TXT host is bag or absent"),
        ),
    ];
    for (set, failure) in cases {
        let (w, txt) = txt_world(Config::default());
        set(&txt);
        w.serve(org_bytes(10, NOW, 3_600, &[], None));
        w.fake.set(BAG, Ok(org_bytes(10, NOW, 3_600, &[], None)));
        assert_eq!(w.grant().await, Grant::Unresolved(failure.clone()));
        let fetched = w.fake.calls(ACME) + w.fake.calls(BAG);
        assert_eq!((fetched, w.store.domain_pin(ACME).unwrap()), (0, None), "{failure:?}");
    }
    let reasons = [
        (Failure::TxtLookup("x".into()), "txt-lookup-failed"),
        (Failure::TxtMalformed("x"), "txt-malformed"),
        (Failure::TxtAmbiguous(2), "txt-ambiguous"),
    ];
    for (f, reason) in reasons {
        assert_eq!(f.reason(), reason);
    }
}

#[tokio::test]
async fn a_pinned_key_stays_current_when_the_txt_names_another_and_a_countersigned_rotation_moves_it() {
    let config =
        Config { well_known: WellKnown { cache_max: 60, ..WellKnown::default() }, ..Config::default() };
    let (w, txt) = txt_world(config);
    txt.set(ACME, &[&txt_of(10, false)]);
    w.serve(org_bytes(10, NOW, 3_600, &[], None));
    w.grant().await;
    // The TXT moves to k11 while k10's record is served: a mismatch, and k10 stays current while its record is valid.
    w.clock.advance(60);
    txt.set(ACME, &[&txt_of(11, false)]);
    assert_eq!(w.grant().await, Grant::Key { key: addr(10), revoked: vec![] });
    assert_eq!(w.pin().key, addr(10).to_string());
    // k11's record, countersigned by k10, agrees with the TXT and moves the pin.
    w.clock.advance(FAILURE_TTL);
    w.serve(org_bytes(11, NOW + 120, 3_600, &[], Some((10, Some(10)))));
    assert_eq!(key_of(&w.grant().await), addr(11).to_string());
    assert_eq!(w.pin().key, addr(11).to_string());
}

#[tokio::test]
async fn a_record_countersigned_by_the_txt_key_is_pinned_at_first_contact_and_moves_its_pin() {
    // The TXT still names k10 and the record is k11, countersigned by k10.
    let (w, txt) = txt_world(Config::default());
    txt.set(ACME, &[&txt_of(10, false)]);
    w.serve(org_bytes(11, NOW, 3_600, &[], Some((10, Some(10)))));
    assert_eq!(key_of(&w.grant().await), addr(11).to_string());
    assert_eq!((w.pin().key, w.pin().pinned_at), (addr(11).to_string(), NOW), "k11 pinned at first contact");
    let config =
        Config { well_known: WellKnown { cache_max: 60, ..WellKnown::default() }, ..Config::default() };
    let (w, txt) = txt_world(config);
    txt.set(ACME, &[&txt_of(10, false)]);
    w.serve(org_bytes(10, NOW, 3_600, &[], None));
    w.grant().await;
    w.clock.advance(60);
    w.serve(org_bytes(11, NOW + 60, 3_600, &[], Some((10, Some(10)))));
    assert_eq!(key_of(&w.grant().await), addr(11).to_string());
    assert_eq!(
        (w.pin().key, w.pin().pinned_at),
        (addr(11).to_string(), NOW + 60),
        "the k10 pin moved to k11"
    );
}

#[tokio::test]
async fn a_record_that_agrees_with_the_txt_key_in_neither_way_writes_and_moves_no_pin() {
    // Another countersigner, a claim with no rotation_sig, no claim, two steps.
    let records = [
        org_bytes(11, NOW, 3_600, &[], Some((10, Some(12)))),
        org_bytes(11, NOW, 3_600, &[], Some((10, None))),
        org_bytes(11, NOW, 3_600, &[], None),
        org_bytes(12, NOW, 3_600, &[], Some((11, Some(11)))),
    ];
    for (i, bytes) in records.iter().enumerate() {
        let (w, txt) = txt_world(Config::default());
        txt.set(ACME, &[&txt_of(10, false)]);
        w.serve(bytes.clone());
        let offered = if i == 3 { addr(12) } else { addr(11) };
        let refused = Failure::TxtKeyMismatch { txt: addr(10).to_string(), offered: offered.to_string() };
        assert_eq!(w.grant().await, Grant::Unresolved(refused), "case {i}");
        assert_eq!(w.store.domain_pin(ACME).unwrap(), None, "case {i}: no pin written");
    }
    let config =
        Config { well_known: WellKnown { cache_max: 60, ..WellKnown::default() }, ..Config::default() };
    let (w, txt) = txt_world(config);
    txt.set(ACME, &[&txt_of(10, false)]);
    w.serve(org_bytes(10, NOW, 3_600, &[], None));
    w.grant().await;
    w.clock.advance(60);
    w.serve(records[0].clone());
    assert_eq!(w.grant().await, Grant::Key { key: addr(10), revoked: vec![] }, "k10 stays current");
    assert_eq!((w.pin().key, w.pin().pinned_at), (addr(10).to_string(), NOW), "the pin is not moved");
}

#[test]
fn a_relay_with_a_test_only_setting_or_a_fake_fetch_asks_no_dns_server() {
    let at: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
    let store = || -> Arc<dyn Store> { Arc::new(MemoryStore::new()) };
    let clock = || Arc::new(ManualClock::new(NOW));
    let source = |well_known: WellKnown| {
        Relay::new(store(), clock(), Config { well_known, ..Config::default() }).txt_source()
    };
    assert_eq!(source(WellKnown::default()), "dns");
    assert_eq!(source(WellKnown { insecure_http: true, ..WellKnown::default() }), "fixed");
    assert_eq!(source(WellKnown { resolve: vec![(domain(ACME), at)], ..WellKnown::default() }), "fixed");
    let given = WellKnown::parse_dns_resolve("_bag.acme.example=v=ac1").unwrap();
    assert_eq!(source(WellKnown { dns_resolve: vec![given], ..WellKnown::default() }), "fixed");
    let faked = Relay::new(store(), clock(), Config::default()).with_fetcher(FakeFetch::new());
    assert_eq!(faked.txt_source(), "fixed");
}
