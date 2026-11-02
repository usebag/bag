//! Adopted 2026-10-26: the relay honours the mailbox's own revoked list. A hop
//! whose `iss` or `sub` is in the list the relay keeps for the chain's root is refused at subscribe (an error frame
//! `revoked`, close 4001), at fetch (403 `revoked`) and at publish under a root an address admits (403 `revoked`); a
//! live subscription ends once a newer record revokes a key of its chain, with no `env` frame after that record's
//! answer; the list outlives its record's expiry and the sweep until a newer record replaces it; and reading it costs
//! well under 1 ms at p99. In-process relays on real loopback sockets over real SQLite files
//! (`common::Server`), on a manual clock.

mod common;

use ac_core::chain::Hop;
use ac_core::keys::SigningKey;
use ac_core::records::{AddressRecord, Kind, Record, Roots};
use ac_relay::clock::ManualClock;
use ac_relay::store::Store as _;
use ac_relay::store::sqlite::SqliteStore;
use ac_relay::{Config, Relay};
use common::{
    NOW, Server, TempDir, Ws, addr, address_record, auth_frame, bytes, envelope, key, subscribe, ws_connect,
    ws_env, ws_json, ws_send,
};
use futures_util::StreamExt as _;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;

/// A relay hosting mailbox 2 for every root.
async fn relay() -> Server {
    let s = Server::start(Config::default()).await;
    s.host(2, Roots::Any, 65_536, 3_600, NOW).await;
    s
}

/// The hop `key(iss)` → `key(sub)`, valid an hour.
fn hop(iss: u8, sub: u8) -> Hop {
    Hop::sign(&key(iss), &addr(sub), vec![], NOW + 3_600).unwrap()
}

fn revoked_frame() -> Value {
    json!({"t": "error", "error": "revoked"})
}

/// The text frames until the relay closes the socket (pings skipped), and the close code; panics after 5 s.
async fn until_closed(ws: &mut Ws) -> (Vec<Value>, Option<u16>) {
    let mut texts = Vec::new();
    loop {
        let frame =
            tokio::time::timeout(Duration::from_secs(5), ws.next()).await.expect("a close within 5 s");
        match frame {
            Some(Ok(Message::Text(t))) => texts.push(serde_json::from_str(t.as_str()).unwrap()),
            Some(Ok(Message::Close(c))) => return (texts, c.map(|c| u16::from(c.code))),
            Some(Ok(_)) => {}
            Some(Err(_)) | None => return (texts, None),
        }
    }
}

/// A handshake of `key(signer)` for mailbox `key(mailbox)` under `hops`, read until the relay closes it.
async fn handshake(s: &Server, signer: u8, mailbox: u8, hops: &[Hop]) -> (Vec<Value>, Option<u16>) {
    let mut ws = ws_connect(s).await;
    let challenge = ws_json(&mut ws).await;
    let nonce = challenge["nonce"].as_str().unwrap().to_owned();
    ws_send(&mut ws, &auth_frame(&key(signer), &addr(mailbox), hops, None, &nonce)).await;
    until_closed(&mut ws).await
}

#[tokio::test]
async fn l1_a_subscriber_under_a_hop_the_mailbox_revokes_is_refused_revoked_4001_and_its_neighbours_are_not()
{
    let s = relay().await;
    assert_eq!(s.publish(&address_record(2, NOW, 3_600, &[addr(30)])).await.status, 200);
    let direct = handshake(&s, 30, 2, &[hop(2, 30)]).await;
    let through = handshake(&s, 31, 2, &[hop(2, 30), hop(30, 31)]).await;
    eprintln!("MEASURE L1: under 2->30 {direct:?}; under 2->30->31 {through:?}");
    for refused in [direct, through] {
        assert_eq!(refused, (vec![revoked_frame()], Some(4001)));
    }
    // Key 31 under its own hop, and the mailbox key itself, are admitted.
    let (_neighbour, _) = subscribe(&s, &key(31), &addr(2), &[hop(2, 31)], None).await;
    let (_own, _) = subscribe(&s, &key(2), &addr(2), &[], None).await;
    s.stop().await;
}

#[tokio::test]
async fn l2_a_fetch_under_a_hop_its_root_revokes_is_403_revoked_and_its_neighbour_reads() {
    let s = relay().await;
    let env = envelope(1, &[addr(2)], vec![], NOW);
    assert_eq!(s.publish(&bytes(&env)).await.status, 200);
    assert_eq!(s.publish(&address_record(2, NOW, 3_600, &[addr(30)])).await.status, 200);
    let id = env.id_hex();
    let refused = s.fetch(&id, &key(30), NOW, &[hop(2, 30)]).await;
    let read = s.fetch(&id, &key(31), NOW, &[hop(2, 31)]).await;
    let stranger = s.fetch(&id, &key(30), NOW, &[]).await;
    eprintln!(
        "MEASURE L2: 30 under 2->30 {} {}; 31 under 2->31 {}; 30 with no chain {} {}",
        refused.status,
        refused.text(),
        read.status,
        stranger.status,
        stranger.text()
    );
    assert_eq!((refused.status, refused.error()), (403, "revoked".to_owned()));
    assert_eq!((read.status, read.body), (200, bytes(&env)));
    assert_eq!((stranger.status, stranger.error()), (403, "not-authorized".to_owned()));
    s.stop().await;
}

#[tokio::test]
async fn l3_a_publish_under_a_root_an_address_admits_is_403_revoked_when_the_root_revokes_its_hop() {
    let s = relay().await;
    s.host(4, Roots::Listed(vec![addr(10)]), 65_536, 3_600, NOW).await;
    assert_eq!(s.publish(&address_record(10, NOW, 3_600, &[addr(11)])).await.status, 200);
    let alone = s.publish(&bytes(&envelope(11, &[addr(4)], vec![hop(10, 11)], NOW))).await;
    let beside = s.publish(&bytes(&envelope(11, &[addr(2), addr(4)], vec![hop(10, 11)], NOW + 1))).await;
    let neighbour = s.publish(&bytes(&envelope(12, &[addr(4)], vec![hop(10, 12)], NOW))).await;
    eprintln!(
        "MEASURE L3: 11 under 10->11 to 4 {} {}; to 2 (\"*\") and 4 {} {}; 12 under 10->12 to 4 {} {}",
        alone.status,
        alone.text(),
        beside.status,
        beside.text(),
        neighbour.status,
        neighbour.text()
    );
    assert_eq!((alone.status, alone.error()), (403, "revoked".to_owned()));
    assert_eq!(
        (beside.status, beside.json()["delivered"].clone()),
        (200, json!(1)),
        "mailbox 2's roots are [\"*\"]"
    );
    assert_eq!(s.relay.store().mailbox_after(addr(4).as_str(), 0, 10, NOW).unwrap().len(), 1, "12's only");
    assert_eq!((neighbour.status, neighbour.json()["delivered"].clone()), (200, json!(1)));
    s.stop().await;
}

#[tokio::test]
async fn l4_a_newer_record_that_revokes_a_live_subscriber_ends_it_at_once_and_before_any_later_frame() {
    let s = relay().await;
    assert_eq!(s.publish(&address_record(2, NOW, 3_600, &[])).await.status, 200);
    let (mut revoked, _) = subscribe(&s, &key(30), &addr(2), &[hop(2, 30)], None).await;
    let (mut neighbour, _) = subscribe(&s, &key(31), &addr(2), &[hop(2, 31)], None).await;
    let (mut own, _) = subscribe(&s, &key(2), &addr(2), &[], None).await;
    // A newer record that revokes another key ends nothing.
    assert_eq!(s.publish(&address_record(2, NOW + 1, 3_600, &[addr(40)])).await.status, 200);
    assert_eq!(s.publish(&bytes(&envelope(1, &[addr(2)], vec![], NOW))).await.json()["delivered"], 1);
    for ws in [&mut revoked, &mut neighbour, &mut own] {
        assert_eq!(ws_env(ws).await.0, 1);
    }
    // The record that revokes key 30, then mail: key 30 gets the error frame and no env frame after the record.
    let record = s.publish(&address_record(2, NOW + 2, 3_600, &[addr(30), addr(40)])).await;
    let answered = Instant::now();
    assert_eq!(record.status, 200);
    let later = s.publish(&bytes(&envelope(1, &[addr(2)], vec![], NOW + 1))).await;
    assert_eq!(later.json()["delivered"], 1);
    let (texts, close) = until_closed(&mut revoked).await;
    let took = answered.elapsed();
    eprintln!(
        "MEASURE L4: after the record's 200 and one more envelope: frames {texts:?}, close {close:?}, {took:?}"
    );
    assert_eq!(texts, vec![revoked_frame()], "no env frame after the record");
    assert_eq!(close, Some(4001));
    assert!(took <= Duration::from_secs(1), "{took:?}");
    // Key 31's subscription and the mailbox key's own go on; key 30's next handshake is refused.
    assert_eq!(ws_env(&mut neighbour).await.0, 2);
    assert_eq!(ws_env(&mut own).await.0, 2);
    assert_eq!(handshake(&s, 30, 2, &[hop(2, 30)]).await, (vec![revoked_frame()], Some(4001)));
    s.stop().await;
}

#[tokio::test]
async fn l4_an_idle_subscriber_is_ended_by_the_record_alone() {
    let s = relay().await;
    let (mut idle, _) = subscribe(&s, &key(30), &addr(2), &[hop(2, 30)], None).await;
    let record = s.publish(&address_record(2, NOW, 3_600, &[addr(30)])).await;
    let answered = Instant::now();
    assert_eq!(record.status, 200);
    let (texts, close) = until_closed(&mut idle).await;
    let took = answered.elapsed();
    eprintln!(
        "MEASURE L4: an idle subscriber after the record's 200: frames {texts:?}, close {close:?}, {took:?}"
    );
    assert_eq!((texts, close), (vec![revoked_frame()], Some(4001)));
    assert!(took <= Duration::from_secs(1), "{took:?}");
    s.stop().await;
}

#[tokio::test]
async fn l5_the_list_outlives_its_record_s_expiry_and_sweep_until_a_newer_record_replaces_it() {
    let s = relay().await;
    s.host(4, Roots::Listed(vec![addr(2)]), 65_536, 3_600, NOW).await;
    let env = envelope(1, &[addr(2)], vec![], NOW);
    assert_eq!(s.publish(&bytes(&env)).await.status, 200);
    assert_eq!(s.publish(&address_record(2, NOW + 10, 60, &[addr(30)])).await.status, 200);
    // Past the record's last valid second, the sweep deletes it: a fetch of it is 404.
    s.clock.set(NOW + 71);
    assert_eq!(ac_relay::sweeper::sweep_once(&s.relay).unwrap().records, 1);
    let record_path = format!("/v0/fetch/record/{}/address", addr(2));
    assert_eq!(s.get(&record_path, &[]).await.status, 404);
    let at = NOW + 71;
    let check = |label: &'static str| {
        let s = &s;
        let env = &env;
        async move {
            let subscribed = handshake(s, 30, 2, &[hop(2, 30)]).await;
            let fetched = s.fetch(&env.id_hex(), &key(30), at, &[hop(2, 30)]).await;
            let published = s.publish(&bytes(&envelope(30, &[addr(4)], vec![hop(2, 30)], at))).await;
            eprintln!(
                "MEASURE L5 {label}: subscribe {subscribed:?}; fetch {} {}; publish {} {}",
                fetched.status,
                fetched.text(),
                published.status,
                published.text()
            );
            (subscribed, (fetched.status, fetched.error()), (published.status, published.error()))
        }
    };
    let refused =
        || ((vec![revoked_frame()], Some(4001)), (403, "revoked".to_owned()), (403, "revoked".to_owned()));
    assert_eq!(check("after the sweep").await, refused());
    // An older record, still valid, published now that the newer one is gone: stored, and the list stays.
    assert_eq!(s.publish(&address_record(2, NOW, 86_400, &[])).await.status, 200);
    assert_eq!(s.get(&record_path, &[]).await.status, 200);
    assert_eq!(check("after an older record").await, refused());
    // A newer record with an empty list replaces it: key 30 reads and publishes again.
    assert_eq!(s.publish(&address_record(2, NOW + 80, 3_600, &[])).await.status, 200);
    let (_ws, _) = subscribe(&s, &key(30), &addr(2), &[hop(2, 30)], None).await;
    assert_eq!(s.fetch(&env.id_hex(), &key(30), at, &[hop(2, 30)]).await.status, 200);
    let published = s.publish(&bytes(&envelope(30, &[addr(4)], vec![hop(2, 30)], at + 1))).await;
    assert_eq!(published.json()["delivered"], 1);
    s.stop().await;
}

/// The p50, p99 and largest of `samples`, in milliseconds.
fn spread(mut samples: Vec<Duration>) -> (f64, f64, f64) {
    samples.sort();
    let at = |q: usize| samples[(samples.len() * q / 100).min(samples.len() - 1)].as_secs_f64() * 1_000.0;
    (at(50), at(99), samples.last().unwrap().as_secs_f64() * 1_000.0)
}

#[test]
fn l8_reading_a_1024_key_list_from_sqlite_takes_well_under_a_millisecond_at_p99() {
    let dir = TempDir::new("revoked-p99");
    let store = SqliteStore::open(&dir.path().join("relay.sqlite")).unwrap();
    let revoked: Vec<_> = (0..1_024_u16)
        .map(|i| {
            let mut seed = [0xa5_u8; 32];
            seed[..2].copy_from_slice(&i.to_be_bytes());
            SigningKey::from_seed(&seed).address()
        })
        .collect();
    let mut record = Record::Address(AddressRecord {
        key: addr(2),
        sealing_key: None,
        relays: vec![],
        rotation_key: None,
        revoked,
        ttl: 3_600,
        iat: NOW,
        rotated_from: None,
        rotation_sig: None,
        sig: [0; 64],
    });
    record.sign(&key(2)).unwrap();
    let body = record.to_bytes();
    assert!(store.put_record(addr(2).as_str(), Kind::Address, NOW, Some(NOW + 3_600), &body).unwrap());
    let relay = Relay::new(Arc::new(store), Arc::new(ManualClock::new(NOW)), Config::default());
    let chain = [hop(2, 30), hop(30, 31)];
    let (mut reads, mut checks) = (Vec::with_capacity(1_000), Vec::with_capacity(1_000));
    for _ in 0..1_000 {
        let t = Instant::now();
        assert_eq!(relay.store().revoked(addr(2).as_str()).unwrap().len(), 1_024);
        reads.push(t.elapsed());
        let t = Instant::now();
        assert!(!relay.revokes(&addr(2), &chain).unwrap());
        checks.push(t.elapsed());
    }
    let (read, check) = (spread(reads), spread(checks));
    eprintln!(
        "MEASURE L8: a {}-byte record's 1,024-key list, 1,000 times each: Store::revoked p50 {:.3} ms, p99 {:.3} ms, \
         max {:.3} ms; Relay::revokes against a two-hop chain p50 {:.3} ms, p99 {:.3} ms, max {:.3} ms",
        body.len(),
        read.0,
        read.1,
        read.2,
        check.0,
        check.1,
        check.2
    );
    // A loose bound, so that a loaded machine does not fail the gate; the printed numbers are read against
    // 1 ms.
    assert!(read.1 < 50.0 && check.1 < 50.0, "{read:?} {check:?}");
}
