//! The sweeper in a running relay: expired mailbox rows go, then the envelopes no row refers to, each leaving a
//! tombstone of its id; and the `store-size` line, the database's bytes and rows, after the first sweep and
//! then once an hour of sweeps.

mod common;

use ac_core::records::{Kind, Roots};
use ac_relay::Config;
use ac_relay::store::memory::MemoryStore;
use ac_relay::store::sqlite::SqliteStore;
use ac_relay::store::{Delivery, DomainPin, NewEnvelope, Store};
use common::{NOW, Server, TempDir, addr, bytes, envelope, key};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[tokio::test]
async fn expired_rows_and_orphaned_envelopes_are_swept() {
    let s = Server::start(Config { sweep_interval: Duration::from_millis(50), ..Config::default() }).await;
    s.host(2, Roots::Any, 65_536, 100, NOW).await;
    s.host(3, Roots::Any, 65_536, 200, NOW).await;
    let env = envelope(1, &[addr(2), addr(3)], vec![], NOW);
    assert_eq!(s.publish(&bytes(&env)).await.json()["delivered"], 2);
    let id = env.id_hex();
    s.clock.advance(100);
    // Mailbox 2's row expired and is swept (the sweeper runs every 50 ms here); mailbox 3 still holds the envelope.
    eventually(|| s.relay.store().mailbox_after(addr(2).as_str(), 0, 10, NOW).unwrap().is_empty()).await;
    assert_eq!(s.relay.store().mailbox_after(addr(3).as_str(), 0, 10, NOW).unwrap().len(), 1);
    assert_eq!(s.fetch(&id, &key(3), NOW + 100, &[]).await.status, 200);
    s.clock.advance(100);
    // The last row expired: the bytes go, and a tombstone keeps the id for dedup until ts + ttl + skew.
    eventually(|| s.relay.store().envelope(&id, 0).unwrap().is_none()).await;
    assert!(s.relay.store().has_envelope(&id, NOW + 200).unwrap(), "the tombstone");
    assert_eq!(s.fetch(&id, &key(3), NOW + 200, &[]).await.status, 404);
    // The cursor keeps counting: a new envelope gets cursor 2 in mailbox 3.
    let next = envelope(1, &[addr(3)], vec![], NOW + 200);
    assert_eq!(s.publish(&bytes(&next)).await.status, 200);
    assert_eq!(s.relay.store().last_cursor(addr(3).as_str()).unwrap(), 2);
    s.stop().await;
}

/// Waits up to 5 s for `done`, checking every 10 ms.
async fn eventually(done: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !done() {
        assert!(tokio::time::Instant::now() < deadline, "not swept within 5 s");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A log sink the test reads back.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Captured {
    /// The `fields` of every line logged so far. A current-thread test runtime keeps the sweeper's task on the
    /// thread that holds the subscriber.
    fn fields(&self) -> Vec<serde_json::Value> {
        let text = String::from_utf8(self.0.lock().unwrap().clone()).unwrap();
        text.lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["fields"].clone())
            .collect()
    }

    fn has(&self, event: &str) -> bool {
        self.fields().iter().any(|f| f["event"] == event)
    }
}

fn capture() -> (Captured, tracing::subscriber::DefaultGuard) {
    let sink = Captured::default();
    let writer = sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::INFO)
        .with_writer(move || writer.clone())
        .finish();
    (sink, tracing::subscriber::set_default(subscriber))
}

/// An hour-long sweep interval logs `store-size` at the first sweep (an hour of sweeps is one): the database's bytes
/// and its rows by table, which the test filled through the store first.
#[tokio::test]
async fn store_size_reports_the_database_and_its_rows() {
    let (log, _guard) = capture();
    let dir = TempDir::new("store-size");
    let store = SqliteStore::open(&dir.path().join("relay.sqlite")).unwrap();
    let env = NewEnvelope {
        id: "e1",
        bytes: b"{1}",
        from: "ed25519:from",
        root: "ed25519:root",
        ts: NOW,
        received_at: NOW,
        pending: &[],
    };
    let rows = [
        Delivery { addr: "a".into(), expires_at: NOW + 1_000 },
        Delivery { addr: "b".into(), expires_at: NOW + 1_000 },
    ];
    store.insert_envelope(&env, &rows).unwrap();
    store.put_record("a", Kind::AcceptFrom, NOW, None, b"{}").unwrap();
    let pin = DomainPin {
        domain: "example.test".into(),
        key: "ed25519:k".into(),
        record: vec![1],
        pinned_at: NOW,
        expires_at: NOW + 1_000,
    };
    store.put_domain_pin(&pin).unwrap();
    let hour = Config { sweep_interval: Duration::from_hours(1), ..Config::default() };
    let s = Server::start_with_store(hour, Arc::new(store)).await;
    eventually(|| log.has("store-size")).await;
    let line = log.fields().into_iter().find(|f| f["event"] == "store-size").unwrap();
    for (field, rows) in [("envelopes", 1), ("mailbox", 2), ("records", 1), ("pins", 1)] {
        assert_eq!(line[field], rows, "{field}: {line}");
    }
    let size = line["bytes"].as_u64().unwrap();
    assert!(size > 0 && size.is_multiple_of(4_096), "{line}");
    s.stop().await;
}

/// A sweep every 50 ms is not an hour of sweeps: the first sweep logs `store-size`, and the next is 72,000 sweeps on.
#[tokio::test]
async fn store_size_is_not_logged_on_every_sweep() {
    let (log, _guard) = capture();
    let s = Server::start(Config { sweep_interval: Duration::from_millis(50), ..Config::default() }).await;
    eventually(|| log.has("store-size")).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let lines = log.fields().into_iter().filter(|f| f["event"] == "store-size").count();
    assert_eq!(lines, 1, "{:?}", log.fields());
    s.stop().await;
}

/// A store that reports no size is logged as a `store-error`, once, and the sweeper goes on.
#[tokio::test]
async fn a_store_without_a_size_logs_a_store_error() {
    let (log, _guard) = capture();
    let hour = Config { sweep_interval: Duration::from_hours(1), ..Config::default() };
    let s = Server::start_with_store(hour, Arc::new(MemoryStore::new())).await;
    eventually(|| log.has("store-error")).await;
    let line = log.fields().into_iter().find(|f| f["event"] == "store-error").unwrap();
    assert!(line["error"].as_str().unwrap().contains("reports no size"), "{line}");
    assert!(!log.has("store-size"));
    s.stop().await;
}
