//! A store failing under a subscriber: the relay closes it with 1011 (no code of Appendix A names the relay's own
//! failure, so no error frame precedes the close). A store that cannot read the revoked list the relay
//! keeps for a chain's root fails a chained handshake, a live subscription, a fetch and a publish the same way.

mod common;

use ac_core::chain::Hop;
use ac_core::records::{Kind, Roots};
use ac_relay::Config;
use ac_relay::store::memory::MemoryStore;
use ac_relay::store::{
    Delivery, MailboxEntry, NewEnvelope, Store, StoreError, StoreResult, StoredEnvelope, StoredRecord, Swept,
};
use common::{
    NOW, Server, addr, address_record, auth_frame, bytes, envelope, key, subscribe, ws_close_code,
    ws_connect, ws_json, ws_send,
};
use futures_util::StreamExt as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio_tungstenite::tungstenite::Message;

/// Fails one call by name while armed (from the start, unless a test arms it later), delegates the rest.
struct FailOne(MemoryStore, &'static str, AtomicBool, Calls);

/// How often a subscriber's loop reached the store.
#[derive(Default)]
struct Calls {
    acks: AtomicUsize,
    mailbox_reads: AtomicUsize,
    /// Set by a test: a sweep waits, up to 5 s, until it is cleared.
    hold_sweep: AtomicBool,
    sweeping: AtomicBool,
    held_too_long: AtomicBool,
}

impl FailOne {
    fn check(&self, call: &str) -> StoreResult<()> {
        if self.1 == call && self.2.load(Ordering::SeqCst) {
            Err(StoreError(format!("{call} failed")))
        } else {
            Ok(())
        }
    }
}

impl Store for FailOne {
    fn record(&self, a: &str, k: Kind) -> StoreResult<Option<StoredRecord>> {
        self.0.record(a, k)
    }
    fn put_record(&self, a: &str, k: Kind, iat: u64, e: Option<u64>, b: &[u8]) -> StoreResult<bool> {
        self.0.put_record(a, k, iat, e, b)
    }
    fn revoked(&self, a: &str) -> StoreResult<Vec<String>> {
        self.check("revoked")?;
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
        self.check("mailbox_after")?;
        self.3.mailbox_reads.fetch_add(1, Ordering::SeqCst);
        self.0.mailbox_after(a, after, l, now)
    }
    fn last_cursor(&self, a: &str) -> StoreResult<u64> {
        self.check("last_cursor")?;
        self.0.last_cursor(a)
    }
    fn ack(&self, a: &str, s: &str, c: u64) -> StoreResult<()> {
        self.check("ack")?;
        self.3.acks.fetch_add(1, Ordering::SeqCst);
        self.0.ack(a, s, c)
    }
    fn acked(&self, a: &str, s: &str) -> StoreResult<Option<u64>> {
        self.check("acked")?;
        self.0.acked(a, s)
    }
    fn sweep(&self, now: u64, w: u64) -> StoreResult<Swept> {
        self.3.sweeping.store(true, Ordering::SeqCst);
        let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while self.3.hold_sweep.load(Ordering::SeqCst) {
            if std::time::Instant::now() > until {
                self.3.held_too_long.store(true, Ordering::SeqCst);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        self.0.sweep(now, w)
    }
    fn pending(&self, now: u64, limit: usize) -> StoreResult<Vec<(String, String)>> {
        self.0.pending(now, limit)
    }
    fn settle_pending(&self, id: &str, addr: &str, deliver: Option<u64>) -> StoreResult<Option<u64>> {
        self.0.settle_pending(id, addr, deliver)
    }
}

async fn server(failing: &'static str) -> Server {
    let store = FailOne(MemoryStore::new(), failing, AtomicBool::new(true), Calls::default());
    let s = Server::start_with_store(Config::default(), Arc::new(store)).await;
    s.host(2, Roots::Any, 65_536, 3_600, NOW).await;
    assert_eq!(s.publish(&bytes(&envelope(1, &[addr(2)], vec![], NOW))).await.status, 200);
    s
}

#[tokio::test]
async fn a_failing_resume_cursor_closes_with_1011() {
    for failing in ["last_cursor", "acked"] {
        let s = server(failing).await;
        let mut ws = ws_connect(&s).await;
        let challenge = ws_json(&mut ws).await;
        ws_send(&mut ws, &auth_frame(&key(2), &addr(2), &[], None, challenge["nonce"].as_str().unwrap()))
            .await;
        assert_eq!(ws_close_code(&mut ws).await, 1011);
        s.stop().await;
    }
}

#[tokio::test]
async fn a_failing_mailbox_read_closes_with_1011() {
    let s = server("mailbox_after").await;
    let (mut ws, _) = subscribe(&s, &key(2), &addr(2), &[], Some(0)).await;
    assert_eq!(ws_close_code(&mut ws).await, 1011);
    s.stop().await;
}

#[tokio::test]
async fn a_failing_ack_closes_with_1011() {
    let s = server("ack").await;
    let (mut ws, _) = subscribe(&s, &key(2), &addr(2), &[], None).await;
    assert_eq!(ws_json(&mut ws).await["t"], "env");
    ws_send(&mut ws, &serde_json::json!({"t": "ack", "cursor": 1})).await;
    assert_eq!(ws_close_code(&mut ws).await, 1011);
    s.stop().await;
}

/// A relay holding `n` envelopes for mailbox 2 on a store that counts its calls and fails none.
async fn counted(n: u64) -> (Server, Arc<FailOne>) {
    let store = Arc::new(FailOne(MemoryStore::new(), "none", AtomicBool::new(false), Calls::default()));
    let s = Server::start_with_store(Config::default(), store.clone()).await;
    s.host(2, Roots::Any, 65_536, 3_600, NOW).await;
    for i in 0..n {
        assert_eq!(s.publish(&bytes(&envelope(1, &[addr(2)], vec![], NOW - i))).await.status, 200);
    }
    (s, store)
}

fn ack(cursor: u64) -> serde_json::Value {
    serde_json::json!({"t": "ack", "cursor": cursor})
}

/// Waits until mailbox 2's stored ack is `cursor`; panics after 5 s.
async fn until_stored(store: &FailOne, cursor: u64) {
    for _ in 0..250 {
        if store.0.acked(addr(2).as_str(), addr(2).as_str()).unwrap() == Some(cursor) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("the ack of {cursor} was not stored within 5 s");
}

#[tokio::test]
async fn an_ack_at_or_below_the_last_reaches_no_store_call() {
    let (s, store) = counted(3).await;
    let (mut ws, _) = subscribe(&s, &key(2), &addr(2), &[], Some(0)).await;
    for _ in 0..3 {
        assert_eq!(ws_json(&mut ws).await["t"], "env");
    }
    ws_send(&mut ws, &ack(3)).await;
    until_stored(&store, 3).await;
    let reads = store.3.mailbox_reads.load(Ordering::SeqCst);
    for cursor in [3, 2, 1, 3] {
        ws_send(&mut ws, &ack(cursor)).await;
    }
    assert_eq!(s.publish(&bytes(&envelope(1, &[addr(2)], vec![], NOW + 1))).await.status, 200);
    assert_eq!(ws_json(&mut ws).await["t"], "env");
    // Frames are read in order, so once this one is stored the four before it have been taken.
    ws_send(&mut ws, &ack(4)).await;
    until_stored(&store, 4).await;
    assert_eq!(store.3.acks.load(Ordering::SeqCst), 2, "the first and the last");
    // The fourth envelope's read, its ack's, and the first ack's if that came after the count above.
    let more = store.3.mailbox_reads.load(Ordering::SeqCst) - reads;
    assert!(more <= 3, "{more} reads: a repeated ack made the session read the mailbox");
    s.stop().await;
}

#[tokio::test]
async fn a_burst_of_acks_writes_once_and_then_the_latest_within_a_second() {
    let (s, store) = counted(5).await;
    let (mut ws, _) = subscribe(&s, &key(2), &addr(2), &[], Some(0)).await;
    for _ in 0..5 {
        assert_eq!(ws_json(&mut ws).await["t"], "env");
    }
    for cursor in 1..=5 {
        ws_send(&mut ws, &ack(cursor)).await;
    }
    until_stored(&store, 5).await;
    let writes = store.3.acks.load(Ordering::SeqCst);
    assert!(writes < 5, "{writes} writes for a burst of 5 acks");
    s.stop().await;
}

#[tokio::test]
async fn a_held_ack_is_stored_within_a_second_while_the_subscription_stays() {
    let (s, store) = counted(3).await;
    let (mut ws, _) = subscribe(&s, &key(2), &addr(2), &[], Some(0)).await;
    for _ in 0..3 {
        assert_eq!(ws_json(&mut ws).await["t"], "env");
    }
    ws_send(&mut ws, &ack(1)).await;
    ws_send(&mut ws, &ack(3)).await;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let stored = store.0.acked(addr(2).as_str(), addr(2).as_str()).unwrap();
    assert_eq!(stored, Some(3), "the subscriber sent nothing more and has not gone");
    // It has not gone: the next envelope still reaches it.
    assert_eq!(s.publish(&bytes(&envelope(1, &[addr(2)], vec![], NOW + 1))).await.status, 200);
    assert_eq!(ws_json(&mut ws).await["t"], "env");
    s.stop().await;
}

#[tokio::test]
async fn the_latest_ack_is_stored_when_the_subscriber_goes() {
    let (s, store) = counted(3).await;
    let (mut ws, _) = subscribe(&s, &key(2), &addr(2), &[], Some(0)).await;
    for _ in 0..3 {
        assert_eq!(ws_json(&mut ws).await["t"], "env");
    }
    ws_send(&mut ws, &ack(1)).await;
    ws_send(&mut ws, &ack(3)).await;
    ws.close(None).await.unwrap();
    until_stored(&store, 3).await;
    s.stop().await;
}

/// A test's runtime has one thread, as a Machine with one CPU does: a sweep on it would stop the relay answering.
#[tokio::test]
async fn a_sweep_in_progress_leaves_the_relay_answering() {
    let calls = Calls { hold_sweep: AtomicBool::new(true), ..Calls::default() };
    let store = Arc::new(FailOne(MemoryStore::new(), "none", AtomicBool::new(false), calls));
    let s = Server::start_with_store(Config::default(), store.clone()).await;
    while !store.3.sweeping.load(Ordering::SeqCst) {
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    assert_eq!(s.get("/v0/health", &[]).await.status, 200);
    assert!(!store.3.held_too_long.load(Ordering::SeqCst), "the sweep stopped the runtime");
    store.3.hold_sweep.store(false, Ordering::SeqCst);
    s.stop().await;
}

/// The frames until the close, none of them text, and the close code; panics after 5 s.
async fn close_with_no_frame(ws: &mut common::Ws) -> u16 {
    loop {
        let next = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next()).await;
        match next.expect("a close within 5 s") {
            Some(Ok(Message::Close(Some(c)))) => return u16::from(c.code),
            Some(Ok(Message::Text(t))) => panic!("no error frame before a 1011, got {t}"),
            Some(Ok(_)) => {}
            other => panic!("expected a close frame, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_failing_revoked_list_read_fails_a_chained_handshake_1011_and_a_fetch_and_a_publish_500() {
    let s = server("revoked").await;
    let session = Hop::sign(&key(2), &addr(30), vec![], NOW + 60).unwrap();
    let mut ws = ws_connect(&s).await;
    let challenge = ws_json(&mut ws).await;
    let nonce = challenge["nonce"].as_str().unwrap().to_owned();
    ws_send(&mut ws, &auth_frame(&key(30), &addr(2), std::slice::from_ref(&session), None, &nonce)).await;
    assert_eq!(close_with_no_frame(&mut ws).await, 1011);
    // The mailbox key itself reads no list.
    let (_own, _) = subscribe(&s, &key(2), &addr(2), &[], None).await;
    let id = envelope(1, &[addr(2)], vec![], NOW).id_hex();
    let fetched = s.fetch(&id, &key(30), NOW, std::slice::from_ref(&session)).await;
    assert_eq!((fetched.status, fetched.error()), (500, "internal".to_owned()));
    s.host(4, Roots::Listed(vec![addr(2)]), 65_536, 3_600, NOW).await;
    let published = s.publish(&bytes(&envelope(30, &[addr(4)], vec![session], NOW))).await;
    assert_eq!((published.status, published.error()), (500, "internal".to_owned()));
    s.stop().await;
}

#[tokio::test]
async fn a_failing_revoked_list_read_under_a_live_subscription_closes_it_with_1011() {
    let store = Arc::new(FailOne(MemoryStore::new(), "revoked", AtomicBool::new(false), Calls::default()));
    let s = Server::start_with_store(Config::default(), Arc::clone(&store) as Arc<dyn Store>).await;
    s.host(2, Roots::Any, 65_536, 3_600, NOW).await;
    let session = Hop::sign(&key(2), &addr(30), vec![], NOW + 60).unwrap();
    let (mut ws, _) = subscribe(&s, &key(30), &addr(2), &[session], None).await;
    store.2.store(true, Ordering::SeqCst);
    // Mailbox 2's address record moves the subscription to read the list again, and the read fails.
    assert_eq!(s.publish(&address_record(2, NOW, 3_600, &[])).await.status, 200);
    assert_eq!(close_with_no_frame(&mut ws).await, 1011);
    s.stop().await;
}
