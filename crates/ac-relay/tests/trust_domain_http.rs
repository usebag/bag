//! Trust by domain through HTTP: a relay served in-process over a real SQLite file
//! and real sockets, whose `domain:` roots resolve with the real fetch (ureq) against a well-known server on
//! loopback, reached with the test-only settings (`insecure_http`, and the host resolved to the server's address).
//! It fails closed with 503 `resolve-failed` while nothing resolves and remembers the failure, resolves and pins,
//! answers from its cache, follows a countersigned rotation with no republish, keeps the pinned key current through a
//! bare rotation and a failed fetch while the pinned record is valid (refusing the foreign key 403), refuses a revoked
//! key, and fails closed again once the pinned record is past its time; and without the test-only setting it refuses
//! the loopback host before connecting.

mod common;

use ac_core::chain::Hop;
use ac_core::records::{AddressRecord, Domain, Kind, Record, Root, Roots};
use ac_core::{Address, Code};
use ac_relay::Config;
use ac_relay::config::WellKnown;
use common::{NOW, Server, addr, bytes, envelope, key};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

const ACME: &str = "acme.test";

/// A well-known server on loopback: every request gets the current answer; the requests are counted.
struct WellKnownServer {
    addr: SocketAddr,
    answer: Arc<Mutex<(String, Vec<u8>)>>,
    requests: Arc<AtomicUsize>,
}

impl WellKnownServer {
    async fn start() -> WellKnownServer {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let answer = Arc::new(Mutex::new(("404 Not Found".to_owned(), b"{}".to_vec())));
        let requests = Arc::new(AtomicUsize::new(0));
        let (a, n) = (Arc::clone(&answer), Arc::clone(&requests));
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let (a, n) = (Arc::clone(&a), Arc::clone(&n));
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4_096];
                    if socket.read(&mut buf).await.unwrap_or(0) == 0 {
                        return;
                    }
                    n.fetch_add(1, Ordering::SeqCst);
                    let (status, body) = a.lock().unwrap().clone();
                    let head = format!(
                        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                         connection: close\r\n\r\n",
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

    fn serve(&self, status: &str, body: Vec<u8>) {
        *self.answer.lock().unwrap() = (status.to_owned(), body);
    }

    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

/// The address record of org key `key(n)`, rotated from `key(from)` and countersigned by `key(by)` when given.
fn org(n: u8, iat: u64, ttl: u64, revoked: &[Address], rotation: Option<(u8, Option<u8>)>) -> Vec<u8> {
    let mut a = AddressRecord {
        key: addr(n),
        sealing_key: None,
        relays: vec![],
        rotation_key: None,
        revoked: revoked.to_vec(),
        ttl,
        iat,
        rotated_from: rotation.map(|(from, _)| addr(from)),
        rotation_sig: None,
        sig: [0; 64],
    };
    if let Some((_, Some(by))) = rotation {
        a.countersign(&key(by)).unwrap();
    }
    let mut r = Record::Address(a);
    r.sign(&key(n)).unwrap();
    r.to_bytes()
}

/// An envelope from key 1 to mailbox 2, under a chain from org key `root` through principal key 20.
fn rooted(root: u8, ts: u64) -> Vec<u8> {
    let chain = vec![
        Hop::sign(&key(root), &addr(20), vec![], NOW + 86_400).unwrap(),
        Hop::sign(&key(20), &addr(1), vec![], NOW + 86_400).unwrap(),
    ];
    bytes(&envelope(1, &[addr(2)], chain, ts))
}

/// The test-only settings, and a cache ceiling of 60 s, so that the relay reads acme's record again every minute
/// while each record, of an hour, stays valid.
fn config(at: SocketAddr, insecure_http: bool) -> Config {
    let resolve = vec![(Domain::parse(ACME).unwrap(), at)];
    let well_known = WellKnown { insecure_http, resolve, cache_max: 60, ..WellKnown::default() };
    Config { well_known, ..Config::default() }
}

async fn mailbox_naming_acme(s: &Server) {
    s.host(2, Roots::WithDomains(vec![Root::Domain(Domain::parse(ACME).unwrap())]), 65_536, 3_600, NOW).await;
}

#[tokio::test]
async fn trust_domain_resolve_cache_expiry_rotation_and_fail_closed_through_http() {
    let well_known = WellKnownServer::start().await;
    let s = Server::start(config(well_known.addr, true)).await;
    mailbox_naming_acme(&s).await;
    let hosted = s.relay.store().record(addr(2).as_str(), Kind::AcceptFrom).unwrap().unwrap();
    let pinned = || s.relay.store().domain_pin(ACME).unwrap().unwrap();
    let status = |r: &common::Reply| (r.status, r.error(), r.header("retry-after").map(str::to_owned));
    let resolve_failed = (503, "resolve-failed".to_owned(), Some("60".to_owned()));

    // Nothing resolves and nothing is pinned: 503 with Retry-After, the failure remembered for 60 s.
    well_known.serve("500 Internal Server Error", b"{}".to_vec());
    assert_eq!(status(&s.publish(&rooted(10, NOW)).await), resolve_failed);
    assert_eq!(status(&s.publish(&rooted(10, NOW - 1)).await), resolve_failed);
    assert_eq!(well_known.requests(), 1);

    // First contact: resolved, pinned, delivered; then answered from the cache.
    s.clock.advance(60);
    well_known.serve("200 OK", org(10, NOW + 60, 3_600, &[], None));
    let r = s.publish(&rooted(10, NOW + 60)).await;
    assert_eq!((r.status, r.json()["delivered"].as_u64()), (200, Some(1)), "{}", r.text());
    assert_eq!(s.publish(&rooted(10, NOW + 59)).await.status, 200);
    assert_eq!((well_known.requests(), pinned().key), (2, addr(10).to_string()));

    // A rotation countersigned by the pinned key is followed, with the mailbox's record untouched.
    s.clock.advance(60);
    well_known.serve("200 OK", org(11, NOW + 120, 3_600, &[], Some((10, Some(10)))));
    let r = s.publish(&rooted(11, NOW + 120)).await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!((well_known.requests(), pinned().key), (3, addr(11).to_string()));
    assert_eq!(s.relay.store().record(addr(2).as_str(), Kind::AcceptFrom).unwrap().unwrap(), hosted);

    // A bare rotation while the pinned record is valid: the foreign key 403, the pinned key still delivered.
    s.clock.advance(60);
    well_known.serve("200 OK", org(12, NOW + 180, 3_600, &[], Some((11, None))));
    let r = s.publish(&rooted(12, NOW + 180)).await;
    assert_eq!((r.status, r.error()), (403, Code::RootNotAccepted.as_str().into()));
    assert_eq!(s.publish(&rooted(11, NOW + 179)).await.status, 200);
    assert_eq!((well_known.requests(), pinned().key), (4, addr(11).to_string()));

    // A failed fetch while the pinned record is valid: the pinned key stays current.
    s.clock.advance(60);
    well_known.serve("500 Internal Server Error", b"{}".to_vec());
    assert_eq!(s.publish(&rooted(11, NOW + 240)).await.status, 200);
    assert_eq!(well_known.requests(), 5);

    // The org's record now revokes the principal: 403 revoked.
    s.clock.advance(60);
    well_known.serve("200 OK", org(11, NOW + 300, 3_600, &[addr(20)], None));
    let r = s.publish(&rooted(11, NOW + 300)).await;
    assert_eq!((r.status, r.error()), (403, Code::Revoked.as_str().into()));
    assert_eq!(well_known.requests(), 6);

    // Past the pinned record's iat + ttl, a failure leaves nothing: 503 again.
    s.clock.set(NOW + 300 + 3_601);
    well_known.serve("500 Internal Server Error", b"{}".to_vec());
    assert_eq!(status(&s.publish(&rooted(11, NOW + 3_900)).await), resolve_failed);
    assert_eq!(well_known.requests(), 7);
    s.stop().await;
}

#[tokio::test]
async fn trust_domain_the_guard_refuses_a_loopback_host_before_connecting() {
    let well_known = WellKnownServer::start().await;
    well_known.serve("200 OK", org(10, NOW, 120, &[], None));
    let s = Server::start(config(well_known.addr, false)).await;
    mailbox_naming_acme(&s).await;
    let r = s.publish(&rooted(10, NOW)).await;
    assert_eq!((r.status, r.error()), (503, "resolve-failed".into()));
    assert_eq!(well_known.requests(), 0, "nothing was connected to");
    assert_eq!(s.relay.store().domain_pin(ACME).unwrap(), None);
    s.stop().await;
}
