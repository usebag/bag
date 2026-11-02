//! What a key can store at the relay is bounded. A record body over 131,072 bytes is 413
//! `body-too-large` and is not stored (20 fresh keys stored 4,955,820 bytes of 242 KiB accept-from records
//! before); a client address brings at most its quota of new record signers a UTC day (429 `rate-limited`
//! with `Retry-After` to the next 00:00 UTC); address and key records are swept once they expire, and then
//! 404 at fetch. In-process relay on a real loopback socket, over a real SQLite file, on a `ManualClock`
//! (`common::Server`).

mod common;

use ac_core::records::{AddressRecord, KeyRecord, Record, Roots};
use ac_relay::Config;
use ac_relay::config::RateLimits;
use common::{NOW, Reply, Server, accept, addr, key, record_bytes};

fn address_record(n: u8, iat: u64, ttl: u64) -> Record {
    let mut r = Record::Address(AddressRecord {
        key: addr(n),
        sealing_key: Some("aa".repeat(32)),
        relays: vec!["http://127.0.0.1:1".into()],
        rotation_key: None,
        revoked: vec![],
        ttl,
        iat,
        rotated_from: None,
        rotation_sig: None,
        sig: [0; 64],
    });
    r.sign(&key(n)).unwrap();
    r
}

fn status(r: &Reply) -> (u16, String) {
    let code = if r.status == 200 { String::new() } else { r.error() };
    (r.status, code)
}

async fn fetch_record(s: &Server, n: u8, kind: &str) -> u16 {
    s.get(&format!("/v0/fetch/record/{}/{kind}", addr(n)), &[]).await.status
}

#[tokio::test]
async fn l1a_a_record_over_128_kib_is_413_and_one_at_the_cap_is_stored() {
    let s = Server::start(Config::default()).await;
    let bytes = record_bytes(&address_record(5, NOW, 3_600));
    let pad = |size: usize| -> Vec<u8> {
        let mut out = vec![b'{'];
        out.resize(size - bytes.len() + 1, b' ');
        out.extend_from_slice(&bytes[1..]);
        out
    };
    let over = s.publish(&pad(131_073)).await;
    assert_eq!(status(&over), (413, "body-too-large".to_owned()));
    assert_eq!(fetch_record(&s, 5, "address").await, 404, "not stored");
    let at = s.publish(&pad(131_072)).await;
    assert_eq!(status(&at), (200, String::new()), "{}", at.text());
    let stored = s.get(&format!("/v0/fetch/record/{}/address", addr(5)), &[]).await;
    assert_eq!((stored.status, stored.body.len()), (200, 131_072));
    eprintln!("MEASURE L1a: a record of 131,073 bytes {:?}; one of 131,072 bytes stored", status(&over));
    s.stop().await;
}

#[tokio::test]
async fn l1b_m4_again_twenty_fresh_keys_store_no_242_kib_record() {
    let s = Server::start(Config::default()).await;
    let roots: Vec<String> = (0..3_300u32).map(|i| format!("\"ed25519:{i:064x}\"")).collect();
    let (mut refused, mut sent) = (0, 0);
    for n in 0..20u8 {
        let text = String::from_utf8(record_bytes(&accept(60 + n, Roots::Any, 65_536, 86_400, NOW))).unwrap();
        let body = text.replace("\"roots\":[\"*\"]", &format!("\"roots\":[{}]", roots.join(",")));
        sent += body.len();
        let r = s.publish(body.as_bytes()).await;
        if status(&r) == (413, "body-too-large".to_owned()) {
            refused += 1;
        }
        assert_eq!(fetch_record(&s, 60 + n, "accept-from").await, 404);
    }
    eprintln!(
        "MEASURE L1b: 20 fresh keys sent {sent} bytes of accept-from records of 3,300 roots: {refused} refused 413, 0 stored"
    );
    assert_eq!(refused, 20);
    s.stop().await;
}

#[tokio::test]
async fn l1c_past_the_quota_the_next_new_signer_from_one_address_is_429_until_midnight() {
    let rate = RateLimits { signers_per_day: 3, ..RateLimits::default() };
    let s = Server::start(Config { rate, ..Config::default() }).await;
    for n in 40..43 {
        let r = s.publish(&record_bytes(&address_record(n, NOW, 3_600))).await;
        assert_eq!(r.status, 200, "{}", r.text());
    }
    let r = s.publish(&record_bytes(&address_record(43, NOW, 3_600))).await;
    let retry = r.header("retry-after").map(str::to_owned);
    eprintln!("MEASURE L1c: the 4th new signer from one address: {:?}, Retry-After {retry:?}", status(&r));
    assert_eq!(status(&r), (429, "rate-limited".to_owned()));
    // NOW is 2027-01-15 08:00:00 UTC.
    assert_eq!(retry.as_deref(), Some("57600"));
    assert_eq!(fetch_record(&s, 43, "address").await, 404);
    // A known signer is not new.
    s.clock.advance(1);
    assert_eq!(s.publish(&record_bytes(&address_record(40, NOW + 1, 3_600))).await.status, 200);
    // After midnight, a new quota.
    s.clock.set(NOW + 57_600);
    assert_eq!(s.publish(&record_bytes(&address_record(43, NOW + 57_600, 3_600))).await.status, 200);
    s.stop().await;
}

#[tokio::test]
async fn l1d_expired_address_and_key_records_are_swept_and_404_at_fetch() {
    let s = Server::start(Config::default()).await;
    assert_eq!(s.publish(&record_bytes(&address_record(5, NOW, 60))).await.status, 200);
    let mut k = Record::Key(KeyRecord {
        key: addr(6),
        sealing_key: "bb".repeat(32),
        iat: NOW,
        exp: NOW + 30,
        sig: [0; 64],
    });
    k.sign(&key(6)).unwrap();
    assert_eq!(s.publish(&record_bytes(&k)).await.status, 200);
    s.host(7, Roots::Any, 65_536, 60, NOW).await;
    assert_eq!(fetch_record(&s, 5, "address").await, 200);
    assert_eq!(fetch_record(&s, 6, "key").await, 200);
    s.clock.set(NOW + 61);
    let swept = ac_relay::sweeper::sweep_once(&s.relay).unwrap();
    let after = (fetch_record(&s, 5, "address").await, fetch_record(&s, 6, "key").await);
    let accept_from = fetch_record(&s, 7, "accept-from").await;
    eprintln!(
        "MEASURE L1d: after iat + ttl and exp: swept {swept:?}; fetch {after:?}; accept-from {accept_from}"
    );
    assert_eq!(swept.records, 2);
    assert_eq!(after, (404, 404));
    assert_eq!(accept_from, 200, "an accept-from record does not expire");
    s.stop().await;
}
