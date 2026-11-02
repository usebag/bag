//! Every publish policy step with the in-memory store and a manual clock, in the order of spec/SPEC.md §8.2 (steps 3a
//! and 6a were added and the store moved to 9), then records.

use super::check_receipt;
use crate::clock::ManualClock;
use crate::config::{Config, RateLimits};
use crate::metrics::{PENDING_DROPPED, RESOLUTIONS_CAPPED, SEEDED_BY_LABEL};
use crate::relay::{Published, Rejection, Relay};
use crate::resolver::testkit::{FakeFetch, domain, org_bytes};
use crate::resolver::{Failure, MAX_FETCHES_PER_PUBLISH, MAX_FETCHES_PER_RETRY, RETRY_AFTER};
use crate::store::memory::MemoryStore;
use crate::store::{
    Delivery, MailboxEntry, NewEnvelope, Store, StoreError, StoreResult, StoredEnvelope, StoredRecord, Swept,
};
use crate::testkit::{
    NOW, accept, addr, address_record, bytes, counted, envelope, key, record_bytes, sealed,
};
use ac_core::chain::Hop;
use ac_core::envelope::Envelope;
use ac_core::records::{KeyRecord, Kind, Record, Root, Roots};
use ac_core::{Address, Code};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

const IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

struct World {
    relay: Relay,
    clock: Arc<ManualClock>,
    store: Arc<dyn Store>,
}

fn world_with(config: Config, store: Arc<dyn Store>) -> World {
    let clock = Arc::new(ManualClock::new(NOW));
    World { relay: Relay::new(Arc::clone(&store), clock.clone(), config), clock, store }
}

fn world() -> World {
    world_with(Config::default(), Arc::new(MemoryStore::new()))
}

impl World {
    fn publish(&self, body: &[u8]) -> Result<Published, Rejection> {
        self.relay.publish(body, IP)
    }

    fn code(&self, body: &[u8]) -> (u16, Option<Code>) {
        let r = self.publish(body).expect_err("a rejection");
        (r.status, r.code)
    }

    /// Hosts mailbox `owner` with an accept-from record.
    fn host(&self, owner: u8, roots: Roots, max_bytes: u64, ttl: u64) {
        let r = self.publish(&record_bytes(&accept(owner, roots, max_bytes, ttl, NOW)));
        assert!(matches!(r, Ok(Published::Record { .. })), "{r:?}");
    }

    fn delivered(&self, body: &[u8]) -> usize {
        match self.publish(body) {
            Ok(Published::Envelope { delivered, .. }) => delivered,
            other => panic!("not an accepted envelope: {other:?}"),
        }
    }

    fn duplicate(&self, body: &[u8]) -> bool {
        match self.publish(body) {
            Ok(Published::Envelope { duplicate, .. }) => duplicate,
            other => panic!("not an accepted envelope: {other:?}"),
        }
    }
}

fn simple(to: &[Address]) -> Vec<u8> {
    bytes(&envelope(1, to, vec![], NOW))
}

#[test]
fn an_accepted_envelope_is_stored_once_with_a_row_per_delivered_recipient() {
    let w = world();
    w.host(2, Roots::Any, 65_536, 3_600);
    w.host(3, Roots::Listed(vec![addr(1)]), 65_536, 3_600);
    let mut events = w.relay.events();
    let env = envelope(1, &[addr(2), addr(3), addr(4)], vec![], NOW);
    let published = w.publish(&bytes(&env)).unwrap();
    assert_eq!(
        published,
        Published::Envelope {
            id: env.id_hex(),
            duplicate: false,
            delivered: 2,
            from: addr(1).to_string(),
            root: addr(1).to_string(),
        }
    );
    assert_eq!(
        w.store.mailbox_after(addr(2).as_str(), 0, 10, NOW).unwrap(),
        vec![MailboxEntry { cursor: 1, bytes: bytes(&env), received_at: NOW }]
    );
    assert_eq!(w.store.mailbox_after(addr(3).as_str(), 0, 10, NOW).unwrap().len(), 1);
    assert!(w.store.mailbox_after(addr(4).as_str(), 0, 10, NOW).unwrap().is_empty());
    assert_eq!(events.try_recv().unwrap(), addr(2).to_string());
    assert_eq!(events.try_recv().unwrap(), addr(3).to_string());
}

#[test]
fn the_mailbox_row_expires_at_the_smaller_of_the_relay_ttl_and_the_record_ttl() {
    let w = world();
    w.host(2, Roots::Any, 65_536, 100);
    w.host(3, Roots::Any, 65_536, 10 * 604_800);
    w.publish(&simple(&[addr(2), addr(3)])).unwrap();
    assert_eq!(w.store.mailbox_after(addr(2).as_str(), 0, 10, NOW + 99).unwrap().len(), 1);
    assert!(w.store.mailbox_after(addr(2).as_str(), 0, 10, NOW + 100).unwrap().is_empty());
    assert_eq!(w.store.mailbox_after(addr(3).as_str(), 0, 10, NOW + 604_799).unwrap().len(), 1);
    assert!(w.store.mailbox_after(addr(3).as_str(), 0, 10, NOW + 604_800).unwrap().is_empty());
}

#[test]
fn step_1_size() {
    let w =
        world_with(Config { max_envelope_bytes: 1_000, ..Config::default() }, Arc::new(MemoryStore::new()));
    w.host(2, Roots::Any, 65_536, 3_600);
    assert_eq!(w.code(&vec![b' '; 262_145]), (413, Some(Code::BodyTooLarge)));
    let big = Envelope::sign(&key(1), vec![addr(2)], vec![], NOW, sealed(&[addr(2)], 600)).unwrap();
    assert!(bytes(&big).len() > 1_000);
    assert_eq!(w.code(&bytes(&big)), (413, Some(Code::EnvelopeTooLarge)));
    // Bytes over the envelope cap that are not even JSON are refused as an oversized envelope, unread.
    assert_eq!(w.code(&vec![b'x'; 1_001]), (413, Some(Code::EnvelopeTooLarge)));
    // A record may be larger than the envelope cap.
    let mut wide = address_record(5, NOW, None);
    if let Record::Address(a) = &mut wide {
        a.revoked = (0..40).map(|i| addr(100 + i)).collect();
    }
    wide.sign(&key(5)).unwrap();
    assert!(record_bytes(&wide).len() > 1_000);
    assert!(w.publish(&record_bytes(&wide)).is_ok());
}

/// `record`'s bytes with spaces after its opening brace, `size` bytes in all: still the same record to every reader.
fn padded(record: &Record, size: usize) -> Vec<u8> {
    let bytes = record_bytes(record);
    assert!(bytes.len() <= size);
    let mut out = vec![b'{'];
    out.resize(size - bytes.len() + 1, b' ');
    out.extend_from_slice(&bytes[1..]);
    assert_eq!(out.len(), size);
    out
}

#[test]
fn step_1_a_record_over_131_072_bytes_is_413_and_never_stored() {
    let w = world();
    let record = address_record(5, NOW, None);
    let checks_before = checks(&w);
    assert_eq!(w.code(&padded(&record, 131_073)), (413, Some(Code::BodyTooLarge)));
    assert_eq!(checks(&w), checks_before, "refused before its signature is verified");
    assert_eq!(w.store.record(addr(5).as_str(), Kind::Address).unwrap(), None);
    // At the cap it is the record, stored with the exact bytes it came in.
    assert!(w.publish(&padded(&record, 131_072)).is_ok());
    assert_eq!(w.store.record(addr(5).as_str(), Kind::Address).unwrap().unwrap().bytes.len(), 131_072);
    // M4 again: 20 fresh keys, each a 242 KiB accept-from record of 3,300 roots; none stored.
    let roots: Vec<String> = (0..3_300u32).map(|i| format!("\"ed25519:{i:064x}\"")).collect();
    for n in 0..20u8 {
        let text = String::from_utf8(record_bytes(&accept(60 + n, Roots::Any, 1_000, 3_600, NOW))).unwrap();
        let body = text.replace("\"roots\":[\"*\"]", &format!("\"roots\":[{}]", roots.join(",")));
        assert!((240_000..262_144).contains(&body.len()), "{}", body.len());
        assert_eq!(w.code(body.as_bytes()), (413, Some(Code::BodyTooLarge)), "key {n}");
        assert!(!w.store.has_records(addr(60 + n).as_str()).unwrap());
    }
}

#[test]
fn a_client_address_brings_at_most_its_quota_of_new_record_signers_a_utc_day() {
    let rate = RateLimits { signers_per_day: 3, ..RateLimits::default() };
    let w = world_with(Config { rate, ..Config::default() }, Arc::new(MemoryStore::new()));
    for n in 40..43 {
        assert!(w.publish(&record_bytes(&address_record(n, NOW, None))).is_ok(), "new signer {n}");
    }
    // NOW is 08:00:00 UTC: 57,600 s to the next midnight.
    let r = w.publish(&record_bytes(&address_record(43, NOW, None))).unwrap_err();
    assert_eq!((r.status, r.code, r.retry_after), (429, Some(Code::RateLimited), Some(57_600)));
    assert!(!w.store.has_records(addr(43).as_str()).unwrap(), "not stored");
    // A signer the relay holds is not new: its next record, of any kind, still goes in.
    w.clock.advance(1);
    assert!(w.publish(&record_bytes(&address_record(40, NOW + 1, None))).is_ok());
    assert!(w.publish(&record_bytes(&accept(41, Roots::Any, 1_000, 3_600, NOW + 1))).is_ok());
    // A record refused before the quota does not use it up; another address has its own.
    let mut forged = String::from_utf8(record_bytes(&address_record(44, NOW, None))).unwrap();
    let at = forged.rfind("\"sig\":\"").unwrap() + 7;
    let flipped = if &forged[at..=at] == "0" { "1" } else { "0" };
    forged.replace_range(at..=at, flipped);
    assert_eq!(w.code(forged.as_bytes()), (422, Some(Code::BadRecordSig)));
    let other: IpAddr = "10.0.0.1".parse().unwrap();
    assert!(w.relay.publish(&record_bytes(&address_record(43, NOW, None)), other).is_ok());
    // The next UTC day starts a new quota.
    w.clock.set(NOW + 57_600);
    assert!(w.publish(&record_bytes(&address_record(45, NOW + 57_600, None))).is_ok());
}

#[test]
fn the_default_quota_is_100_new_signers_a_day() {
    let w = world();
    for n in 0..100u8 {
        assert!(w.publish(&record_bytes(&address_record(100 + n, NOW, None))).is_ok(), "signer {n}");
    }
    let r = w.publish(&record_bytes(&address_record(250, NOW, None))).unwrap_err();
    assert_eq!((r.status, r.code), (429, Some(Code::RateLimited)));
}

#[test]
fn expired_address_and_key_records_are_swept_and_404_and_accept_from_records_stay() {
    let w = world();
    w.publish(&record_bytes(&address_record(5, NOW, None))).unwrap();
    let mut k = Record::Key(KeyRecord {
        key: addr(6),
        sealing_key: "bb".repeat(32),
        iat: NOW,
        exp: NOW + 60,
        sig: [0; 64],
    });
    k.sign(&key(6)).unwrap();
    w.publish(&record_bytes(&k)).unwrap();
    w.host(7, Roots::Any, 1_000, 60);
    let window = 604_800 + 300;
    w.clock.set(NOW + 60);
    assert_eq!(w.store.sweep(w.relay.now(), window).unwrap().records, 0, "valid through exp");
    w.clock.set(NOW + 61);
    assert_eq!(crate::sweeper::sweep_once(&w.relay).unwrap().records, 1);
    assert_eq!(w.relay.fetch_record(addr(6).as_str(), "key").unwrap_err().code, Some(Code::NotFound));
    assert!(w.relay.fetch_record(addr(5).as_str(), "address").is_ok());
    w.clock.set(NOW + 3_601);
    assert_eq!(crate::sweeper::sweep_once(&w.relay).unwrap().records, 1);
    assert_eq!(w.relay.fetch_record(addr(5).as_str(), "address").unwrap_err().code, Some(Code::NotFound));
    w.clock.set(NOW + 10 * 86_400);
    assert_eq!(crate::sweeper::sweep_once(&w.relay).unwrap().records, 0);
    assert!(w.relay.fetch_record(addr(7).as_str(), "accept-from").is_ok());
}

#[test]
fn step_2_parse_and_caps() {
    let w = world();
    assert_eq!(w.code(b"not json"), (400, Some(Code::BadJson)));
    assert_eq!(w.code(b"[1,2]"), (400, Some(Code::BadShape)));
    // A top-level `kind` makes a record, whatever its value.
    assert_eq!(w.code(br#"{"kind":"memo"}"#), (400, Some(Code::BadRecord)));
    assert_eq!(w.code(br#"{"kind":"envelope","v":1}"#), (400, Some(Code::BadRecord)));
    let env = envelope(1, &[addr(2)], vec![], NOW);
    let mut j: serde_json::Value = serde_json::from_slice(&bytes(&env)).unwrap();
    j["to"] = serde_json::json!([]);
    assert_eq!(w.code(j.to_string().as_bytes()), (400, Some(Code::BadShape)));
    j["to"] = serde_json::json!(["ed25519:nope"]);
    assert_eq!(w.code(j.to_string().as_bytes()), (400, Some(Code::BadAddress)));
    j["to"] = serde_json::json!((0..17).map(|i| addr(40 + i).to_string()).collect::<Vec<_>>());
    assert_eq!(w.code(j.to_string().as_bytes()), (422, Some(Code::TooManyRecipients)));
    let mut j: serde_json::Value = serde_json::from_slice(&bytes(&env)).unwrap();
    j["v"] = serde_json::json!(2);
    assert_eq!(w.code(j.to_string().as_bytes()), (400, Some(Code::BadVersion)));
}

#[test]
fn steps_3_and_4_the_id_and_the_signature() {
    let w = world();
    let env = envelope(1, &[addr(2)], vec![], NOW);
    let mut j: serde_json::Value = serde_json::from_slice(&bytes(&env)).unwrap();
    j["ts"] = serde_json::json!(NOW + 1);
    assert_eq!(w.code(j.to_string().as_bytes()), (422, Some(Code::BadId)));
    let mut j: serde_json::Value = serde_json::from_slice(&bytes(&env)).unwrap();
    j["sig"] = serde_json::json!(ac_core::hex::encode(&key(9).sign(&env.id)));
    assert_eq!(w.code(j.to_string().as_bytes()), (422, Some(Code::BadSig)));
}

#[test]
fn step_5_the_chain_without_caveat_evaluation() {
    let w = world();
    let expired = Hop::sign(&key(10), &addr(1), vec![], NOW - 1).unwrap();
    assert_eq!(w.code(&bytes(&envelope(1, &[addr(2)], vec![expired], NOW))), (422, Some(Code::HopExpired)));
    let wrong = Hop::sign(&key(10), &addr(7), vec![], NOW + 60).unwrap();
    assert_eq!(
        w.code(&bytes(&envelope(1, &[addr(2)], vec![wrong], NOW))),
        (422, Some(Code::ChainNotToSender))
    );
    let mut forged = Hop::sign(&key(10), &addr(1), vec![], NOW + 60).unwrap();
    forged.sig = key(11).sign(&[0; 32]);
    assert_eq!(w.code(&bytes(&envelope(1, &[addr(2)], vec![forged], NOW))), (422, Some(Code::BadHopSig)));
    // An unknown caveat is the edge's business: the relay delivers.
    w.host(2, Roots::Listed(vec![addr(10)]), 65_536, 3_600);
    let hop = Hop::sign(&key(10), &addr(1), vec!["no-such-profile=anything".into()], NOW + 60).unwrap();
    assert_eq!(w.delivered(&bytes(&envelope(1, &[addr(2)], vec![hop], NOW))), 1);
}

#[test]
fn step_6_the_ts_window() {
    let w = world();
    w.host(2, Roots::Any, 65_536, 3_600);
    assert_eq!(w.code(&bytes(&envelope(1, &[addr(2)], vec![], NOW + 301))), (422, Some(Code::FutureTs)));
    assert_eq!(w.code(&bytes(&envelope(1, &[addr(2)], vec![], NOW - 605_101))), (422, Some(Code::StaleTs)));
    assert!(w.publish(&bytes(&envelope(1, &[addr(2)], vec![], NOW - 605_100))).is_ok());
    assert!(w.publish(&bytes(&envelope(1, &[addr(2)], vec![], NOW + 300))).is_ok());
}

/// Step 6's receipt bound: after the ts window, a chained envelope is `hop-expired` once the relay's
/// clock is past its chain's earliest `exp` plus the skew, whatever `ts` says; an envelope outside the window is
/// `stale-ts` first; an empty chain meets no bound.
#[test]
fn step_6_the_receipt_bound() {
    let w = world();
    w.host(2, Roots::Any, 65_536, 3_600);
    let exp = NOW - 300;
    let hop = Hop::sign(&key(10), &addr(1), vec![], exp).unwrap();
    let at = |ts| bytes(&envelope(1, &[addr(2)], vec![hop.clone()], ts));
    assert_eq!(w.delivered(&at(exp)), 1, "received at exp + skew: stored");
    w.clock.set(exp + 301);
    assert_eq!(w.code(&at(exp - 1)), (422, Some(Code::HopExpired)), "inside the ts window, past the bound");
    assert_eq!(w.code(&at(exp + 301 - 605_101)), (422, Some(Code::StaleTs)), "the ts window first");
    assert_eq!(w.delivered(&bytes(&envelope(1, &[addr(2)], vec![], exp - 1))), 1, "an empty chain");
}

/// The bound takes the earliest `exp` over every hop, whatever their order, and the skew it is given; a chain that
/// reaches it holds rule 7, so this case is a test of its own.
#[test]
fn the_receipt_bound_takes_the_earliest_exp_of_every_hop() {
    let hop = |exp| Hop::sign(&key(10), &addr(1), vec![], exp).unwrap();
    let hops = [hop(NOW), hop(NOW + 600)];
    assert_eq!(check_receipt(&hops, NOW + 300, 300), Ok(()));
    assert_eq!(check_receipt(&hops, NOW + 301, 300), Err(Code::HopExpired));
    assert_eq!(check_receipt(&hops, NOW + 10, 10), Ok(()));
    assert_eq!(check_receipt(&hops, NOW + 11, 10), Err(Code::HopExpired));
    assert_eq!(check_receipt(&[], u64::MAX, 0), Ok(()));
    assert_eq!(check_receipt(&hops, u64::MAX, u64::MAX), Ok(()), "exp + skew saturates");
}

#[test]
fn step_7_hosted_recipients_and_partial_delivery() {
    let w = world();
    assert_eq!(w.code(&simple(&[addr(2)])), (403, Some(Code::NotHosted)));
    w.host(2, Roots::Listed(vec![addr(9)]), 65_536, 3_600);
    assert_eq!(w.code(&simple(&[addr(2)])), (403, Some(Code::RootNotAccepted)));
    w.host(3, Roots::Any, 10, 3_600);
    assert_eq!(w.code(&simple(&[addr(3)])), (403, Some(Code::TooLargeForMailbox)));
    // None remains and one refused the root: root-not-accepted, whatever the other refused for.
    assert_eq!(w.code(&simple(&[addr(3), addr(2)])), (403, Some(Code::RootNotAccepted)));
    // Partial: delivered to the recipients that admit it, the others skipped.
    w.host(4, Roots::Any, 65_536, 3_600);
    let env = envelope(1, &[addr(2), addr(4), addr(3), addr(5)], vec![], NOW);
    assert_eq!(w.delivered(&bytes(&env)), 1);
    assert_eq!(w.store.mailbox_after(addr(4).as_str(), 0, 10, NOW).unwrap().len(), 1);
    assert!(w.store.mailbox_after(addr(2).as_str(), 0, 10, NOW).unwrap().is_empty());
}

/// An envelope from `key(28)` under a chain of 8 hops, `key(20)` to `key(28)`, valid until an hour after `NOW`:
/// 9 signatures to verify (the outer one and one per hop).
fn eight_hops(to: &[Address], ts: u64) -> Vec<u8> {
    let hops: Vec<Hop> =
        (20..28).map(|n| Hop::sign(&key(n), &addr(n + 1), vec![], NOW + 3_600).unwrap()).collect();
    bytes(&envelope(28, to, hops, ts))
}

fn checks(w: &World) -> u64 {
    w.relay.signature_checks.load(std::sync::atomic::Ordering::Relaxed)
}

#[test]
fn step_3a_the_client_address_limit_runs_before_any_signature_work() {
    let rate = RateLimits { per_ip: 4, ..RateLimits::default() };
    let w = world_with(Config { rate, ..Config::default() }, Arc::new(MemoryStore::new()));
    w.host(2, Roots::Any, 65_536, 3_600);
    assert_eq!(checks(&w), 1, "the record's signature");
    for ts in [NOW, NOW - 1, NOW - 2] {
        let before = checks(&w);
        assert_eq!(w.delivered(&eight_hops(&[addr(2)], ts)), 1);
        assert_eq!(checks(&w) - before, 9, "the outer signature and eight hops");
    }
    // The address has used its 4 (the record and three envelopes): the next is refused before any signature.
    let before = checks(&w);
    let r = w.publish(&eight_hops(&[addr(2)], NOW - 3)).unwrap_err();
    assert_eq!((r.status, r.code, r.retry_after), (429, Some(Code::RateLimited), Some(60)));
    assert_eq!(checks(&w), before, "no signature verified over the limit");
    // A record over the limit is refused the same way.
    let r = w.publish(&record_bytes(&address_record(5, NOW, None))).unwrap_err();
    assert_eq!((r.status, checks(&w)), (429, before));
    // Another address, and the next window, are not refused.
    assert!(w.relay.publish(&eight_hops(&[addr(2)], NOW - 4), "10.0.0.1".parse().unwrap()).is_ok());
    w.clock.advance(60);
    assert_eq!(w.delivered(&eight_hops(&[addr(2)], NOW - 5)), 1);
}

#[test]
fn step_3a_counts_every_publish_that_reaches_it_and_none_refused_before_it() {
    let rate = RateLimits { per_ip: 2, ..RateLimits::default() };
    let w = world_with(Config { rate, ..Config::default() }, Arc::new(MemoryStore::new()));
    w.clock.set(NOW - 60);
    w.host(2, Roots::Any, 65_536, 3_600);
    w.clock.set(NOW);
    // Refused before step 4 (the form, the id): counted nowhere.
    let mut wrong_id = envelope(1, &[addr(2)], vec![], NOW);
    wrong_id.id[0] ^= 1;
    for _ in 0..5 {
        assert_eq!(w.code(&bytes(&wrong_id)), (422, Some(Code::BadId)));
        assert_eq!(w.code(b"{\"v\":1}"), (400, Some(Code::BadShape)));
    }
    // Refused after it (a bad signature): counted.
    let mut forged = envelope(1, &[addr(2)], vec![], NOW);
    forged.sig[0] ^= 1;
    assert_eq!(w.code(&bytes(&forged)), (422, Some(Code::BadSig)));
    assert_eq!(w.delivered(&simple(&[addr(2)])), 1);
    assert_eq!(w.code(&bytes(&envelope(1, &[addr(2)], vec![], NOW - 1))), (429, Some(Code::RateLimited)));
}

#[test]
fn step_6a_a_duplicate_counts_against_the_client_address_only() {
    let rate = RateLimits { per_from: 2, per_root: 2, per_ip: 100, ..RateLimits::default() };
    let w = world_with(Config { rate, ..Config::default() }, Arc::new(MemoryStore::new()));
    w.host(2, Roots::Any, 65_536, 3_600);
    let captured = simple(&[addr(2)]);
    assert!(!w.duplicate(&captured));
    for _ in 0..50 {
        assert!(w.duplicate(&captured), "a replay is a duplicate, never 429");
    }
    // The sender's `from` and root counted the original only: one more envelope fits, the next does not.
    assert_eq!(w.delivered(&bytes(&envelope(1, &[addr(2)], vec![], NOW - 1))), 1);
    let r = w.publish(&bytes(&envelope(1, &[addr(2)], vec![], NOW - 2))).unwrap_err();
    assert_eq!((r.status, r.code), (429, Some(Code::RateLimited)));
    // The replays counted against their address: 1 record, 1 + 50 + 1 + 1 envelopes.
    let tight = RateLimits { per_ip: 3, ..RateLimits::default() };
    let w = world_with(Config { rate: tight, ..Config::default() }, Arc::new(MemoryStore::new()));
    w.host(2, Roots::Any, 65_536, 3_600);
    assert!(!w.duplicate(&captured));
    assert!(w.duplicate(&captured));
    assert_eq!(w.code(&captured), (429, Some(Code::RateLimited)));
}

#[test]
fn step_8_the_sender_limits_with_retry_after() {
    let rate = RateLimits { window: 60, per_from: 2, per_root: 100, per_ip: 100, ..RateLimits::default() };
    let w = world_with(Config { rate, ..Config::default() }, Arc::new(MemoryStore::new()));
    w.host(2, Roots::Any, 65_536, 3_600);
    for ts in [NOW, NOW - 1] {
        w.publish(&bytes(&envelope(1, &[addr(2)], vec![], ts))).unwrap();
    }
    w.clock.set(NOW + 15);
    let r = w.publish(&bytes(&envelope(1, &[addr(2)], vec![], NOW - 2))).unwrap_err();
    // NOW is 1_800_000_000, a multiple of 60, so 15 s into the window there are 45 left.
    assert_eq!((r.status, r.code, r.retry_after), (429, Some(Code::RateLimited), Some(45)));
    w.clock.set(NOW + 60);
    assert!(w.publish(&bytes(&envelope(1, &[addr(2)], vec![], NOW - 2))).is_ok());
}

#[test]
fn step_6a_dedup_by_id() {
    let w = world();
    w.host(2, Roots::Any, 65_536, 3_600);
    let env = envelope(1, &[addr(2)], vec![], NOW);
    assert!(!w.duplicate(&bytes(&env)));
    assert!(w.duplicate(&bytes(&env)));
    assert_eq!(w.delivered(&bytes(&env)), 0);
    // The same id with other bytes (white space) is the same envelope: nothing is stored again.
    let spaced = String::from_utf8(bytes(&env)).unwrap().replace(',', ", ");
    assert!(w.duplicate(spaced.as_bytes()));
    assert_eq!(w.store.mailbox_after(addr(2).as_str(), 0, 10, NOW).unwrap().len(), 1);
    assert_eq!(
        w.store.envelope(&env.id_hex(), NOW).unwrap(),
        Some(StoredEnvelope { bytes: bytes(&env), received_at: NOW })
    );
}

/// A store whose dedup check always misses and whose record writes always lose: the races.
struct Racy(MemoryStore);

impl Store for Racy {
    fn record(&self, a: &str, k: Kind) -> StoreResult<Option<StoredRecord>> {
        self.0.record(a, k)
    }
    fn put_record(&self, a: &str, k: Kind, iat: u64, e: Option<u64>, b: &[u8]) -> StoreResult<bool> {
        if k == Kind::Key { Ok(false) } else { self.0.put_record(a, k, iat, e, b) }
    }
    fn revoked(&self, a: &str) -> StoreResult<Vec<String>> {
        self.0.revoked(a)
    }
    fn has_envelope(&self, _: &str, _: u64) -> StoreResult<bool> {
        Ok(false)
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

#[test]
fn step_9_a_lost_race_is_a_duplicate_and_a_lost_record_race_is_stale() {
    let w = world_with(Config::default(), Arc::new(Racy(MemoryStore::new())));
    w.host(2, Roots::Any, 65_536, 3_600);
    let env = envelope(1, &[addr(2)], vec![], NOW);
    assert!(!w.duplicate(&bytes(&env)));
    assert!(w.duplicate(&bytes(&env)));
    let mut k = Record::Key(KeyRecord {
        key: addr(6),
        sealing_key: "bb".repeat(32),
        iat: NOW,
        exp: NOW + 60,
        sig: [0; 64],
    });
    k.sign(&key(6)).unwrap();
    assert_eq!(w.code(&record_bytes(&k)), (409, Some(Code::StaleRecord)));
    // A store without its own `has_records` answers it from `record`: a signer it holds a record of is not new.
    w.clock.advance(1);
    assert!(w.publish(&record_bytes(&accept(2, Roots::Any, 65_536, 3_600, NOW + 1))).is_ok());
}

#[test]
fn a_record_counts_against_its_signer_as_an_envelope_against_its_from() {
    let rate = RateLimits { per_from: 1, ..RateLimits::default() };
    let w = world_with(Config { rate, ..Config::default() }, Arc::new(MemoryStore::new()));
    assert!(w.publish(&record_bytes(&address_record(5, NOW, None))).is_ok());
    w.clock.advance(1);
    let r = w.publish(&record_bytes(&address_record(5, NOW + 1, None))).unwrap_err();
    assert_eq!((r.status, r.code), (429, Some(Code::RateLimited)));
}

/// A store whose record reads or record writes fail, the rest delegated.
struct FailsRecords(MemoryStore, &'static str);

impl Store for FailsRecords {
    fn record(&self, a: &str, k: Kind) -> StoreResult<Option<StoredRecord>> {
        if self.1 == "record" { down() } else { self.0.record(a, k) }
    }
    fn put_record(&self, a: &str, k: Kind, iat: u64, e: Option<u64>, b: &[u8]) -> StoreResult<bool> {
        if self.1 == "put" { down() } else { self.0.put_record(a, k, iat, e, b) }
    }
    fn revoked(&self, a: &str) -> StoreResult<Vec<String>> {
        if self.1 == "revoked" { down() } else { self.0.revoked(a) }
    }
    fn has_records(&self, a: &str) -> StoreResult<bool> {
        self.0.has_records(a)
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

#[test]
fn a_store_failure_reading_or_writing_a_record_is_a_500() {
    for failing in ["record", "put"] {
        let w = world_with(Config::default(), Arc::new(FailsRecords(MemoryStore::new(), failing)));
        assert_eq!(w.code(&record_bytes(&address_record(5, NOW, None))), (500, None), "{failing}");
    }
}

/// A store that fails every call.
struct Broken;

fn down<T>() -> StoreResult<T> {
    Err(StoreError("disk on fire".into()))
}

impl Store for Broken {
    fn record(&self, _: &str, _: Kind) -> StoreResult<Option<StoredRecord>> {
        down()
    }
    fn put_record(&self, _: &str, _: Kind, _: u64, _: Option<u64>, _: &[u8]) -> StoreResult<bool> {
        down()
    }
    fn revoked(&self, _: &str) -> StoreResult<Vec<String>> {
        down()
    }
    fn has_envelope(&self, _: &str, _: u64) -> StoreResult<bool> {
        down()
    }
    fn insert_envelope(&self, _: &NewEnvelope<'_>, _: &[Delivery]) -> StoreResult<Option<Vec<u64>>> {
        down()
    }
    fn envelope(&self, _: &str, _: u64) -> StoreResult<Option<StoredEnvelope>> {
        down()
    }
    fn mailbox_after(&self, _: &str, _: u64, _: usize, _: u64) -> StoreResult<Vec<MailboxEntry>> {
        down()
    }
    fn last_cursor(&self, _: &str) -> StoreResult<u64> {
        down()
    }
    fn ack(&self, _: &str, _: &str, _: u64) -> StoreResult<()> {
        down()
    }
    fn acked(&self, _: &str, _: &str) -> StoreResult<Option<u64>> {
        down()
    }
    fn sweep(&self, _: u64, _: u64) -> StoreResult<Swept> {
        down()
    }
    fn pending(&self, _: u64, _: usize) -> StoreResult<Vec<(String, String)>> {
        down()
    }
    fn settle_pending(&self, _: &str, _: &str, _: Option<u64>) -> StoreResult<Option<u64>> {
        down()
    }
}

#[test]
fn a_store_failure_is_a_500() {
    let w = world_with(Config::default(), Arc::new(Broken));
    assert_eq!(w.code(&simple(&[addr(2)])), (500, None));
    assert_eq!(w.code(&record_bytes(&accept(2, Roots::Any, 1, 1, NOW))), (500, None));
    assert!(crate::sweeper::sweep_once(&w.relay).is_none());
}

#[test]
fn a_store_failure_at_dedup_or_insert_is_a_500() {
    struct FailsLate(MemoryStore, bool);
    impl Store for FailsLate {
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
            if self.1 { down() } else { self.0.has_envelope(id, now) }
        }
        fn insert_envelope(&self, _: &NewEnvelope<'_>, _: &[Delivery]) -> StoreResult<Option<Vec<u64>>> {
            down()
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
    for at_dedup in [true, false] {
        let w = world_with(Config::default(), Arc::new(FailsLate(MemoryStore::new(), at_dedup)));
        w.host(2, Roots::Any, 65_536, 3_600);
        assert_eq!(w.code(&simple(&[addr(2)])), (500, None));
    }
}

#[test]
fn a_corrupt_stored_record_is_a_500() {
    let store = Arc::new(MemoryStore::new());
    store.put_record(addr(2).as_str(), Kind::AcceptFrom, 1, None, b"{not a record").unwrap();
    store
        .put_record(addr(3).as_str(), Kind::AcceptFrom, 1, None, &record_bytes(&address_record(3, NOW, None)))
        .unwrap();
    store
        .put_record(
            addr(4).as_str(),
            Kind::Address,
            1,
            None,
            &record_bytes(&accept(4, Roots::Any, 1, 1, NOW)),
        )
        .unwrap();
    let w = world_with(Config::default(), store);
    assert_eq!(w.code(&simple(&[addr(2)])), (500, None));
    assert_eq!(w.code(&simple(&[addr(3)])), (500, None));
    assert_eq!(w.code(&record_bytes(&address_record(5, NOW, Some((4, Some(4)))))), (500, None));
}

#[test]
fn records_are_verified_and_the_newer_iat_wins() {
    let w = world();
    let first = accept(2, Roots::Any, 100, 3_600, NOW);
    assert_eq!(
        w.publish(&record_bytes(&first)).unwrap(),
        Published::Record {
            kind: Kind::AcceptFrom,
            signer: addr(2).to_string(),
            iat: NOW,
            valid_until: None
        }
    );
    // The same record again, an older or an equal iat: 409 stale-record.
    assert_eq!(w.code(&record_bytes(&first)), (409, Some(Code::StaleRecord)));
    assert_eq!(
        w.code(&record_bytes(&accept(2, Roots::Listed(vec![addr(3)]), 100, 3_600, NOW))),
        (409, Some(Code::StaleRecord))
    );
    assert_eq!(
        w.code(&record_bytes(&accept(2, Roots::Any, 100, 3_600, NOW - 1))),
        (409, Some(Code::StaleRecord))
    );
    w.clock.advance(10);
    let newer = accept(2, Roots::Listed(vec![addr(8)]), 100, 3_600, NOW + 10);
    assert!(w.publish(&record_bytes(&newer)).is_ok());
    assert_eq!(
        w.store.record(addr(2).as_str(), Kind::AcceptFrom).unwrap().unwrap().bytes,
        record_bytes(&newer)
    );
}

#[test]
fn record_verification_codes() {
    let w = world();
    let mut j: serde_json::Value =
        serde_json::from_slice(&record_bytes(&accept(2, Roots::Any, 100, 3_600, NOW))).unwrap();
    j["max_bytes"] = serde_json::json!(101);
    assert_eq!(w.code(j.to_string().as_bytes()), (422, Some(Code::BadRecordSig)));
    assert_eq!(w.code(&record_bytes(&accept(2, Roots::Any, 1, 1, NOW + 301))), (422, Some(Code::FutureIat)));
    assert_eq!(
        w.code(&record_bytes(&address_record(3, NOW - 3_601, None))),
        (422, Some(Code::RecordExpired))
    );
    j["max_bytes"] = serde_json::json!(0);
    assert_eq!(w.code(j.to_string().as_bytes()), (400, Some(Code::BadRecord)));
    let mut relays: serde_json::Value =
        serde_json::from_slice(&record_bytes(&address_record(3, NOW, None))).unwrap();
    // One over the cap of 64 (raised from 8 on 2026-10-30, 'relays N').
    relays["relays"] = serde_json::json!((0..65).map(|i| format!("https://r{i}")).collect::<Vec<_>>());
    assert_eq!(w.code(relays.to_string().as_bytes()), (422, Some(Code::TooManyRelays)));
}

#[test]
fn a_rotation_is_checked_when_the_relay_holds_the_previous_record() {
    let w = world();
    // No record of the previous key here: its claim alone is checked, under rotated_from, so a bare rotation is
    // bad-rotation (changed 2026-10-25; it was stored on its own
    // verification), and one countersigned by rotated_from is stored.
    assert_eq!(
        w.code(&record_bytes(&address_record(4, NOW, Some((3, None))))),
        (422, Some(Code::BadRotation))
    );
    assert!(w.publish(&record_bytes(&address_record(4, NOW, Some((3, Some(3)))))).is_ok());
    w.publish(&record_bytes(&address_record(3, NOW - 10, None))).unwrap();
    // Held now: a bare rotation and a wrong countersignature are bad-rotation.
    assert_eq!(
        w.code(&record_bytes(&address_record(6, NOW, Some((3, None))))),
        (422, Some(Code::BadRotation))
    );
    assert_eq!(
        w.code(&record_bytes(&address_record(6, NOW, Some((3, Some(6)))))),
        (422, Some(Code::BadRotation))
    );
    let next = address_record(6, NOW, Some((3, Some(3))));
    assert!(w.publish(&record_bytes(&next)).is_ok());
    assert_eq!(w.store.record(addr(6).as_str(), Kind::Address).unwrap().unwrap().bytes, record_bytes(&next));
}

// --- step 7 with domain roots --------------------------------------------------------

const ACME: &str = "acme.example";

/// A world whose relay fetches well-known records from a fake.
fn domain_world() -> (World, Arc<FakeFetch>) {
    let fake = FakeFetch::new();
    let w = world();
    let relay =
        Relay::new(Arc::clone(&w.store), w.clock.clone(), Config::default()).with_fetcher(fake.clone());
    (World { relay, ..w }, fake)
}

fn acme() -> Root {
    Root::Domain(domain(ACME))
}

/// A chain from org key `root` through principal key 20 to the sender, key 1.
fn chain(root: u8) -> Vec<Hop> {
    vec![
        Hop::sign(&key(root), &addr(20), vec![], NOW + 3_600).unwrap(),
        Hop::sign(&key(20), &addr(1), vec![], NOW + 3_600).unwrap(),
    ]
}

/// An envelope from key 1 under `chain(root)` to `to`, at `ts` (so that each call can be a new id).
fn rooted(root: u8, to: &[Address], ts: u64) -> Vec<u8> {
    bytes(&envelope(1, to, chain(root), ts))
}

impl World {
    async fn resolving(&self, body: &[u8]) -> Result<Published, Rejection> {
        self.relay.publish_resolving(body, IP).await
    }

    async fn resolving_code(&self, body: &[u8]) -> (u16, Option<Code>, Option<u64>) {
        let r = self.resolving(body).await.expect_err("a rejection");
        (r.status, r.code, r.retry_after)
    }

    async fn resolving_delivered(&self, body: &[u8]) -> usize {
        match self.resolving(body).await {
            Ok(Published::Envelope { delivered, .. }) => delivered,
            other => panic!("not an accepted envelope: {other:?}"),
        }
    }
}

const RESOLVE_FAILED: (u16, Option<Code>, Option<u64>) = (503, Some(Code::ResolveFailed), Some(RETRY_AFTER));

#[tokio::test]
async fn step_7_an_address_or_the_wildcard_admits_without_the_network() {
    let (w, fake) = domain_world();
    w.host(2, Roots::WithDomains(vec![Root::Address(addr(10)), acme()]), 65_536, 3_600);
    w.host(3, Roots::Any, 65_536, 3_600);
    assert_eq!(w.resolving_delivered(&rooted(10, &[addr(2), addr(3)], NOW)).await, 2);
    assert_eq!(fake.calls(ACME), 0);
}

#[tokio::test]
async fn step_7_a_domain_whose_current_key_is_the_root_admits_it_and_the_cache_answers_next() {
    let (w, fake) = domain_world();
    w.host(2, Roots::WithDomains(vec![acme()]), 65_536, 3_600);
    fake.set(ACME, Ok(org_bytes(10, NOW, 3_600, &[], None)));
    assert_eq!(w.resolving_delivered(&rooted(10, &[addr(2)], NOW)).await, 1);
    assert_eq!(w.resolving_delivered(&rooted(10, &[addr(2)], NOW - 1)).await, 1);
    assert_eq!(fake.calls(ACME), 1);
    // A domain whose key is another: the root is refused, for good.
    assert_eq!(
        w.resolving_code(&rooted(11, &[addr(2)], NOW)).await,
        (403, Some(Code::RootNotAccepted), None)
    );
    // Through a domain grant, the size limit still holds.
    w.host(3, Roots::WithDomains(vec![acme()]), 10, 3_600);
    assert_eq!(
        w.resolving_code(&rooted(10, &[addr(3)], NOW)).await,
        (403, Some(Code::TooLargeForMailbox), None)
    );
}

#[tokio::test]
async fn step_7_a_domain_that_does_not_resolve_is_503_resolve_failed_and_remembered_for_60_s() {
    let (w, fake) = domain_world();
    w.host(2, Roots::WithDomains(vec![Root::Address(addr(9)), acme()]), 65_536, 3_600);
    assert_eq!(w.resolving_code(&rooted(10, &[addr(2)], NOW)).await, RESOLVE_FAILED);
    assert_eq!(w.resolving_code(&rooted(10, &[addr(2)], NOW - 1)).await, RESOLVE_FAILED);
    assert_eq!(fake.calls(ACME), 1, "the failure is remembered");
    w.clock.advance(60);
    fake.set(ACME, Ok(org_bytes(10, NOW + 60, 3_600, &[], None)));
    assert_eq!(w.resolving_delivered(&rooted(10, &[addr(2)], NOW + 60)).await, 1);
    assert_eq!(fake.calls(ACME), 2);
    assert!(w.store.mailbox_after(addr(2).as_str(), 0, 10, NOW + 60).unwrap().len() == 1);
}

#[tokio::test]
async fn step_7_a_countersigned_rotation_is_accepted_with_no_republish_and_a_bare_one_keeps_the_pinned_key() {
    let (w, fake) = domain_world();
    w.host(2, Roots::WithDomains(vec![acme()]), 65_536, 3_600);
    let hosted = w.store.record(addr(2).as_str(), Kind::AcceptFrom).unwrap().unwrap();
    fake.set(ACME, Ok(org_bytes(10, NOW, 60, &[], None)));
    assert_eq!(w.resolving_delivered(&rooted(10, &[addr(2)], NOW)).await, 1);
    w.clock.advance(60);
    // The rotated record is valid for an hour, past the next read (the cache's 60 s floor at most here).
    fake.set(ACME, Ok(org_bytes(11, NOW + 60, 3_600, &[], Some((10, Some(10))))));
    assert_eq!(w.resolving_delivered(&rooted(11, &[addr(2)], NOW + 60)).await, 1);
    assert_eq!(w.store.record(addr(2).as_str(), Kind::AcceptFrom).unwrap().unwrap(), hosted, "no republish");
    // Make the pin stale while its record stays valid, as a short cache ceiling does.
    let pin = w.store.domain_pin(ACME).unwrap().unwrap();
    w.store.put_domain_pin(&crate::store::DomainPin { expires_at: NOW + 61, ..pin }).unwrap();
    w.clock.advance(60);
    fake.set(ACME, Ok(org_bytes(12, NOW + 120, 3_600, &[], Some((11, None)))));
    // A bare rotation: the foreign key is refused for good, the pinned key still admitted.
    let refused = w.resolving_code(&rooted(12, &[addr(2)], NOW + 120)).await;
    assert_eq!(refused, (403, Some(Code::RootNotAccepted), None));
    assert_eq!(w.resolving_delivered(&rooted(11, &[addr(2)], NOW + 119)).await, 1);
    assert_eq!(w.store.domain_pin(ACME).unwrap().unwrap().key, addr(11).to_string(), "the pin stays");
    assert_eq!(fake.calls(ACME), 3, "the mismatch is remembered");
    // Once the pinned record is past iat + ttl, nothing resolves: 503, for every root.
    w.clock.set(NOW + 60 + 3_601);
    // (The envelopes' ts stay inside the chain's hops, which end at NOW + 3600.)
    assert_eq!(w.resolving_code(&rooted(11, &[addr(2)], NOW + 3_600)).await, RESOLVE_FAILED);
    assert_eq!(w.resolving_code(&rooted(12, &[addr(2)], NOW + 3_599)).await, RESOLVE_FAILED);
}

#[tokio::test]
async fn step_7_a_key_of_the_chain_in_the_granting_record_s_revoked_list_is_403_revoked() {
    for (revoked, why) in
        [(20, "the principal, hop 0's sub and hop 1's iss"), (1, "the session"), (10, "the root")]
    {
        let (w, fake) = domain_world();
        w.host(2, Roots::WithDomains(vec![acme()]), 65_536, 3_600);
        fake.set(ACME, Ok(org_bytes(10, NOW, 3_600, &[addr(revoked)], None)));
        assert_eq!(
            w.resolving_code(&rooted(10, &[addr(2)], NOW)).await,
            (403, Some(Code::Revoked), None),
            "{why}"
        );
    }
    let (w, fake) = domain_world();
    fake.set(ACME, Ok(org_bytes(10, NOW, 3_600, &[addr(21)], None)));
    w.host(2, Roots::WithDomains(vec![acme()]), 65_536, 3_600);
    assert_eq!(w.resolving_delivered(&rooted(10, &[addr(2)], NOW)).await, 1, "no key of the chain is listed");
    // A root admitted by its address is checked against no record, even one the relay holds.
    fake.set(ACME, Ok(org_bytes(10, NOW, 3_600, &[addr(20)], None)));
    w.host(3, Roots::WithDomains(vec![Root::Address(addr(10)), acme()]), 65_536, 3_600);
    assert_eq!(w.resolving_delivered(&rooted(10, &[addr(3)], NOW - 1)).await, 1);
}

#[tokio::test]
async fn step_7_unresolved_comes_first_then_revoked_then_a_refused_root_and_a_partial_delivery_holds_the_unresolved()
 {
    let (w, fake) = domain_world();
    w.host(2, Roots::WithDomains(vec![acme()]), 65_536, 3_600);
    w.host(3, Roots::Listed(vec![addr(9)]), 65_536, 3_600);
    let globex = Root::Domain(domain("globex.example"));
    w.host(4, Roots::WithDomains(vec![globex]), 65_536, 3_600);
    fake.set("globex.example", Ok(org_bytes(10, NOW, 3_600, &[addr(20)], None)));
    // acme does not resolve, globex revokes the principal, 3 refuses the root: 503 first.
    assert_eq!(w.resolving_code(&rooted(10, &[addr(3), addr(4), addr(2)], NOW)).await, RESOLVE_FAILED);
    assert_eq!(
        w.resolving_code(&rooted(10, &[addr(3), addr(4)], NOW)).await,
        (403, Some(Code::Revoked), None)
    );
    // One recipient admits it: delivered there; the unresolved one is held pending, the refused
    // ones skipped.
    w.host(5, Roots::Any, 65_536, 3_600);
    let env = rooted(10, &[addr(2), addr(5), addr(3)], NOW);
    assert_eq!(w.resolving_delivered(&env).await, 1);
    assert_eq!(w.store.mailbox_after(addr(5).as_str(), 0, 10, NOW).unwrap().len(), 1);
    assert!(w.store.mailbox_after(addr(2).as_str(), 0, 10, NOW).unwrap().is_empty());
    let id = serde_json::from_slice::<serde_json::Value>(&env).unwrap()["id"].as_str().unwrap().to_owned();
    assert_eq!(w.store.pending(NOW, 10).unwrap(), vec![(id, addr(2).to_string())], "3, refused, is not held");
}

#[tokio::test]
async fn the_synchronous_publish_counts_a_domain_only_when_its_key_is_cached() {
    let (w, fake) = domain_world();
    w.host(2, Roots::WithDomains(vec![acme()]), 65_536, 3_600);
    fake.set(ACME, Ok(org_bytes(10, NOW, 3_600, &[], None)));
    let r = w.publish(&rooted(10, &[addr(2)], NOW)).unwrap_err();
    assert_eq!((r.status, r.code, r.retry_after), RESOLVE_FAILED);
    assert_eq!(fake.calls(ACME), 0, "no network call");
    assert_eq!(w.resolving_delivered(&rooted(10, &[addr(2)], NOW)).await, 1);
    assert_eq!(w.delivered(&rooted(10, &[addr(2)], NOW - 1)), 1);
    assert_eq!(fake.calls(ACME), 1);
    assert_eq!(Failure::NotCached.reason(), "not-cached");
}

#[tokio::test]
async fn a_store_failure_while_a_domain_resolves_is_a_500() {
    let fake = FakeFetch::new();
    fake.set(ACME, Ok(org_bytes(10, NOW, 3_600, &[], None)));
    let store = Arc::new(FailsPins(MemoryStore::new()));
    let w = world_with(Config::default(), store);
    let w = World {
        relay: Relay::new(Arc::clone(&w.store), w.clock.clone(), Config::default()).with_fetcher(fake),
        ..w
    };
    w.host(2, Roots::WithDomains(vec![acme()]), 65_536, 3_600);
    assert_eq!(w.resolving_code(&rooted(10, &[addr(2)], NOW)).await, (500, None, None));
    let r = w.publish(&rooted(10, &[addr(2)], NOW)).unwrap_err();
    assert_eq!((r.status, r.code), (500, None));
}

/// A store whose pin calls fail, beside a working mailbox and record store.
struct FailsPins(MemoryStore);

impl Store for FailsPins {
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

// --- one refresh a minute on a root mismatch ------------------------------------------

const NOT_ACCEPTED: (u16, Option<Code>, Option<u64>) = (403, Some(Code::RootNotAccepted), None);

#[tokio::test]
async fn r4_54_a_root_other_than_the_cached_key_refreshes_once_a_minute_and_a_rotation_admits_it_at_once() {
    let (w, fake) = domain_world();
    w.host(2, Roots::WithDomains(vec![acme()]), 65_536, 3_600);
    fake.set(ACME, Ok(org_bytes(10, NOW, 3_600, &[], None)));
    assert_eq!(w.resolving_delivered(&rooted(10, &[addr(2)], NOW)).await, 1);
    assert_eq!(fake.calls(ACME), 1);
    // The org rotates to key 11, countersigned by 10, while 10 is cached for an hour.
    fake.set(ACME, Ok(org_bytes(11, NOW + 5, 3_600, &[], Some((10, Some(10))))));
    w.clock.advance(5);
    assert_eq!(w.resolving_delivered(&rooted(11, &[addr(2)], NOW + 5)).await, 1, "admitted in this publish");
    assert_eq!(fake.calls(ACME), 2, "one refresh");
    assert_eq!(w.store.domain_pin(ACME).unwrap().unwrap().key, addr(11).to_string(), "the pin moved");
    // The rotated-away key is refused from then on, and a key the host does not serve fetches nothing inside the
    // minute: the pin stays.
    assert_eq!(w.resolving_code(&rooted(10, &[addr(2)], NOW + 5)).await, NOT_ACCEPTED);
    w.clock.advance(59);
    assert_eq!(w.resolving_code(&rooted(12, &[addr(2)], NOW + 64)).await, NOT_ACCEPTED);
    assert_eq!(fake.calls(ACME), 2, "inside the minute of the refresh");
    assert_eq!(w.store.domain_pin(ACME).unwrap().unwrap().key, addr(11).to_string());
    // A minute after the refresh, a mismatch may fetch again: once.
    w.clock.advance(1);
    assert_eq!(w.resolving_code(&rooted(12, &[addr(2)], NOW + 65)).await, NOT_ACCEPTED);
    assert_eq!(w.resolving_code(&rooted(12, &[addr(2)], NOW + 64)).await, NOT_ACCEPTED);
    assert_eq!(fake.calls(ACME), 3);
    assert_eq!(w.resolving_delivered(&rooted(11, &[addr(2)], NOW + 63)).await, 1, "the pinned key still");
}

#[tokio::test]
async fn r4_54_no_refresh_after_a_resolution_in_the_same_publish_nor_while_a_failure_is_remembered() {
    let (w, fake) = domain_world();
    w.host(2, Roots::WithDomains(vec![acme()]), 65_536, 3_600);
    fake.set(ACME, Ok(org_bytes(10, NOW, 3_600, &[], None)));
    // First contact under another root: one fetch, which pins 10; no second one for the mismatch.
    assert_eq!(w.resolving_code(&rooted(11, &[addr(2)], NOW)).await, NOT_ACCEPTED);
    assert_eq!(fake.calls(ACME), 1);
    // The cache made stale while the pinned record stays valid, and the host down: the failure is remembered.
    let pin = w.store.domain_pin(ACME).unwrap().unwrap();
    w.store.put_domain_pin(&crate::store::DomainPin { expires_at: NOW + 1, ..pin }).unwrap();
    w.clock.advance(70);
    fake.set(ACME, Err(Failure::Status(500)));
    assert_eq!(w.resolving_delivered(&rooted(10, &[addr(2)], NOW + 70)).await, 1, "the pinned key, kept");
    assert_eq!(fake.calls(ACME), 2);
    // A mismatch while that failure is remembered: no fetch (§8.8 item 6), though no refresh happened this minute.
    assert_eq!(w.resolving_code(&rooted(11, &[addr(2)], NOW + 70)).await, NOT_ACCEPTED);
    assert_eq!(fake.calls(ACME), 2);
    // The publish that makes no network call never refreshes either.
    w.clock.advance(60);
    let r = w.publish(&rooted(11, &[addr(2)], NOW + 130)).unwrap_err();
    assert_eq!(r.code, Some(Code::ResolveFailed), "nothing cached: the pin's cache is stale");
    assert_eq!(fake.calls(ACME), 2);
}

// --- pending rows -----------------------------------------------------------------

fn id_of(envelope: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(envelope).unwrap()["id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn r4_55_a_recipient_waiting_on_a_domain_is_held_and_delivered_when_it_resolves_and_the_duplicate_rule_holds()
 {
    let (w, fake) = domain_world();
    w.host(2, Roots::WithDomains(vec![acme()]), 65_536, 600);
    w.host(5, Roots::Any, 65_536, 3_600);
    let env = rooted(10, &[addr(2), addr(5)], NOW);
    assert_eq!(w.resolving_delivered(&env).await, 1);
    assert_eq!(w.store.pending(NOW, 10).unwrap(), vec![(id_of(&env), addr(2).to_string())]);
    assert!(w.store.mailbox_after(addr(2).as_str(), 0, 10, NOW).unwrap().is_empty());
    assert!(w.duplicate(&env), "the same bytes again: a duplicate");
    assert_eq!(w.store.pending(NOW, 10).unwrap().len(), 1, "still one row");
    // Inside the failure's minute the retry fetches nothing and the row waits.
    assert_eq!(w.relay.retry_pending().await.unwrap(), 0);
    assert_eq!(fake.calls(ACME), 1);
    // Once the domain resolves, the next retry delivers it, at its first publish's received_at.
    w.clock.advance(60);
    fake.set(ACME, Ok(org_bytes(10, NOW + 60, 3_600, &[], None)));
    let mut events = w.relay.events();
    assert_eq!(w.relay.retry_pending().await.unwrap(), 1);
    assert_eq!(events.try_recv().unwrap(), addr(2).to_string());
    let row = MailboxEntry { cursor: 1, bytes: env.clone(), received_at: NOW };
    assert_eq!(w.store.mailbox_after(addr(2).as_str(), 0, 10, NOW + 60).unwrap(), vec![row]);
    assert_eq!(w.store.mailbox_after(addr(2).as_str(), 0, 10, NOW + 599).unwrap().len(), 1);
    assert!(
        w.store.mailbox_after(addr(2).as_str(), 0, 10, NOW + 600).unwrap().is_empty(),
        "min(TTL, its ttl)"
    );
    assert!(w.store.pending(NOW + 60, 10).unwrap().is_empty());
    assert!(w.duplicate(&env));
    assert_eq!(w.relay.retry_pending().await.unwrap(), 0);
    assert_eq!(w.store.last_cursor(addr(2).as_str()).unwrap(), 1, "delivered once");
}

#[tokio::test]
async fn r4_55_a_pending_row_is_delivered_when_its_mailbox_admits_the_root_by_address_or_the_wildcard_now() {
    let (w, fake) = domain_world();
    w.host(2, Roots::WithDomains(vec![acme()]), 65_536, 3_600);
    w.host(5, Roots::Any, 65_536, 3_600);
    let env = rooted(10, &[addr(2), addr(5)], NOW);
    assert_eq!(w.resolving_delivered(&env).await, 1);
    // The owner of 2 takes any root now, with the domain still down: no fetch is needed to deliver.
    w.clock.advance(1);
    let wider = accept(2, Roots::Any, 65_536, 3_600, NOW + 1);
    assert!(w.publish(&record_bytes(&wider)).is_ok());
    assert_eq!(w.relay.retry_pending().await.unwrap(), 1);
    assert_eq!(fake.calls(ACME), 1, "the first publish's fetch only");
    let rows = w.store.mailbox_after(addr(2).as_str(), 0, 10, NOW + 1).unwrap();
    assert_eq!(rows, vec![MailboxEntry { cursor: 1, bytes: env, received_at: NOW }]);
}

#[tokio::test]
async fn r4_55_a_pending_row_is_dropped_when_step_7_refuses_it_now() {
    let cases: [(&str, u64, u64, Vec<u8>); 4] = [
        ("root-not-accepted", 65_536, 3_600, org_bytes(11, NOW + 60, 3_600, &[], None)),
        ("revoked", 65_536, 3_600, org_bytes(10, NOW + 60, 3_600, &[addr(20)], None)),
        ("too-large-for-mailbox", 10, 3_600, org_bytes(10, NOW + 60, 3_600, &[], None)),
        ("expired", 65_536, 30, org_bytes(10, NOW + 60, 3_600, &[], None)),
    ];
    for (why, max_bytes, ttl, record) in cases {
        let before = dropped(why);
        let (w, fake) = domain_world();
        w.host(2, Roots::WithDomains(vec![acme()]), max_bytes, ttl);
        w.host(5, Roots::Any, 65_536, 3_600);
        assert_eq!(w.resolving_delivered(&rooted(10, &[addr(2), addr(5)], NOW)).await, 1, "{why}");
        assert_eq!(w.store.pending(NOW, 10).unwrap().len(), 1, "{why}");
        w.clock.advance(60);
        fake.set(ACME, Ok(record));
        assert_eq!(w.relay.retry_pending().await.unwrap(), 0, "{why}");
        assert!(w.store.pending(NOW + 60, 10).unwrap().is_empty(), "{why}: dropped");
        assert!(w.store.mailbox_after(addr(2).as_str(), 0, 10, NOW + 60).unwrap().is_empty(), "{why}");
        assert!(dropped(why) > before, "{why}: counted");
    }
}

/// A store that can lose an envelope, an accept-from record, or an insert to a publish of the same id, or garble an
/// envelope's bytes under a pending row.
struct Tampered {
    inner: MemoryStore,
    what: std::sync::Mutex<&'static str>,
}

impl Store for Tampered {
    fn record(&self, a: &str, k: Kind) -> StoreResult<Option<StoredRecord>> {
        let lost = *self.what.lock().unwrap() == "accept-from" && k == Kind::AcceptFrom;
        if lost { Ok(None) } else { self.inner.record(a, k) }
    }
    fn put_record(&self, a: &str, k: Kind, iat: u64, e: Option<u64>, b: &[u8]) -> StoreResult<bool> {
        self.inner.put_record(a, k, iat, e, b)
    }
    fn revoked(&self, a: &str) -> StoreResult<Vec<String>> {
        self.inner.revoked(a)
    }
    fn has_envelope(&self, id: &str, now: u64) -> StoreResult<bool> {
        self.inner.has_envelope(id, now)
    }
    fn insert_envelope(&self, e: &NewEnvelope<'_>, d: &[Delivery]) -> StoreResult<Option<Vec<u64>>> {
        if *self.what.lock().unwrap() == "lost-race" { Ok(None) } else { self.inner.insert_envelope(e, d) }
    }
    fn envelope(&self, id: &str, now: u64) -> StoreResult<Option<StoredEnvelope>> {
        Ok(match *self.what.lock().unwrap() {
            "envelope" => None,
            "garbled" => Some(StoredEnvelope { bytes: b"{not an envelope".to_vec(), received_at: NOW }),
            "broken-chain" => {
                let mut v: serde_json::Value =
                    serde_json::from_slice(&self.inner.envelope(id, now)?.unwrap().bytes).unwrap();
                v["auth"][0]["sig"] = serde_json::json!("00".repeat(64));
                Some(StoredEnvelope { bytes: v.to_string().into_bytes(), received_at: NOW })
            }
            _ => self.inner.envelope(id, now)?,
        })
    }
    fn mailbox_after(&self, a: &str, after: u64, l: usize, now: u64) -> StoreResult<Vec<MailboxEntry>> {
        self.inner.mailbox_after(a, after, l, now)
    }
    fn last_cursor(&self, a: &str) -> StoreResult<u64> {
        self.inner.last_cursor(a)
    }
    fn ack(&self, a: &str, s: &str, c: u64) -> StoreResult<()> {
        self.inner.ack(a, s, c)
    }
    fn acked(&self, a: &str, s: &str) -> StoreResult<Option<u64>> {
        self.inner.acked(a, s)
    }
    fn sweep(&self, now: u64, w: u64) -> StoreResult<Swept> {
        self.inner.sweep(now, w)
    }
    fn pending(&self, now: u64, limit: usize) -> StoreResult<Vec<(String, String)>> {
        self.inner.pending(now, limit)
    }
    fn settle_pending(&self, id: &str, addr: &str, deliver: Option<u64>) -> StoreResult<Option<u64>> {
        self.inner.settle_pending(id, addr, deliver)
    }
    fn domain_pin(&self, d: &str) -> StoreResult<Option<crate::store::DomainPin>> {
        self.inner.domain_pin(d)
    }
    fn put_domain_pin(&self, pin: &crate::store::DomainPin) -> StoreResult<()> {
        self.inner.put_domain_pin(pin)
    }
}

#[tokio::test]
async fn r4_55_a_pending_row_whose_envelope_or_mailbox_is_gone_or_garbled_is_dropped_alone() {
    let cases = [
        ("envelope", "gone"),
        ("accept-from", "not-hosted"),
        ("garbled", "corrupt"),
        ("broken-chain", "corrupt"),
    ];
    for (what, why) in cases {
        let before = dropped(why);
        let fake = FakeFetch::new();
        let store = Arc::new(Tampered { inner: MemoryStore::new(), what: std::sync::Mutex::new("") });
        let clock = Arc::new(ManualClock::new(NOW));
        let relay = Relay::new(store.clone(), clock.clone(), Config::default()).with_fetcher(fake.clone());
        let w = World { relay, clock, store: store.clone() };
        w.host(2, Roots::WithDomains(vec![acme()]), 65_536, 3_600);
        w.host(5, Roots::Any, 65_536, 3_600);
        assert_eq!(w.resolving_delivered(&rooted(10, &[addr(2), addr(5)], NOW)).await, 1);
        *store.what.lock().unwrap() = what;
        w.clock.advance(60);
        fake.set(ACME, Ok(org_bytes(10, NOW + 60, 3_600, &[], None)));
        assert_eq!(w.relay.retry_pending().await.unwrap(), 0, "{what}");
        assert!(w.store.pending(NOW + 60, 10).unwrap().is_empty(), "{what}: dropped");
        assert!(dropped(why) > before, "{what}: counted {why}");
    }
}

/// The count of pending rows dropped for `why`, a reason the metrics seed (the drops tested here name all seven).
fn dropped(why: &str) -> u64 {
    let (_, _, seeded) = SEEDED_BY_LABEL.into_iter().find(|s| s.0 == PENDING_DROPPED).unwrap();
    assert!(seeded.contains(&why) && seeded.len() == 7, "{why} in {seeded:?}");
    counted(&format!("{PENDING_DROPPED}{{reason=\"{why}\"}}"))
}

#[test]
fn a_publish_that_lost_the_insert_race_spends_none_of_its_addresss_bytes() {
    let body = simple(&[addr(2)]);
    let rate = RateLimits { bytes_per_day: u64::try_from(body.len()).unwrap(), ..RateLimits::default() };
    let store = Arc::new(Tampered { inner: MemoryStore::new(), what: std::sync::Mutex::new("") });
    let w = world_with(Config { rate, ..Config::default() }, store.clone());
    w.host(2, Roots::Any, 65_536, 3_600);
    *store.what.lock().unwrap() = "lost-race";
    for _ in 0..3 {
        assert!(matches!(w.publish(&body), Ok(Published::Envelope { duplicate: true, .. })));
    }
    *store.what.lock().unwrap() = "";
    assert!(matches!(w.publish(&body), Ok(Published::Envelope { duplicate: false, .. })));
}

#[tokio::test]
async fn r4_55_a_store_failure_stops_the_retry_with_a_500() {
    let w = world_with(Config::default(), Arc::new(Broken));
    assert_eq!(w.relay.retry_pending().await.unwrap_err().status, 500);
}

// --- at most MAX_FETCHES_PER_PUBLISH domains of one publish go to the network --------------------------

/// `n` distinct domains, `d0.fanout.example` to `d<n-1>.fanout.example`, none of which serves a record.
fn fanout(n: usize) -> Vec<Root> {
    (0..n).map(|i| Root::Domain(domain(&format!("d{i}.fanout.example")))).collect()
}

/// How many fetches the fanout domains have had, and the most any one had.
fn fetched(fake: &FakeFetch, n: usize) -> (usize, usize) {
    let calls: Vec<usize> = (0..n).map(|i| fake.calls(&format!("d{i}.fanout.example"))).collect();
    (calls.iter().sum(), calls.iter().copied().max().unwrap_or(0))
}

#[tokio::test]
async fn ac_sec_22_one_publish_fetches_eight_domains_at_most_and_each_try_reads_the_next() {
    let (w, fake) = domain_world();
    w.host(2, Roots::WithDomains(fanout(20)), 65_536, 3_600);
    assert_eq!(MAX_FETCHES_PER_PUBLISH, 8);
    let capped = counted(RESOLUTIONS_CAPPED);
    assert_eq!(w.resolving_code(&rooted(10, &[addr(2)], NOW)).await, RESOLVE_FAILED);
    assert_eq!(fetched(&fake, 20), (8, 1), "eight of twenty, once each");
    assert!(counted(RESOLUTIONS_CAPPED) > capped, "the publish passed the cap");
    // The eight failures are remembered for 60 s, so the next try reads the next eight.
    assert_eq!(w.resolving_code(&rooted(10, &[addr(2)], NOW - 1)).await, RESOLVE_FAILED);
    assert_eq!(fetched(&fake, 20), (16, 1));
    // The last domain serves the root's record: the third try reads the last four and delivers.
    fake.set("d19.fanout.example", Ok(org_bytes(10, NOW, 3_600, &[], None)));
    assert_eq!(w.resolving_delivered(&rooted(10, &[addr(2)], NOW - 2)).await, 1);
    assert_eq!(fetched(&fake, 20), (20, 1));
}

#[tokio::test]
async fn ld_1_a_pending_row_reads_eight_domains_at_most_a_pass() {
    let (w, fake) = domain_world();
    w.host(2, Roots::WithDomains(fanout(20)), 65_536, 3_600);
    w.host(5, Roots::Any, 65_536, 3_600);
    assert_eq!(w.resolving_delivered(&rooted(10, &[addr(2), addr(5)], NOW)).await, 1);
    assert_eq!(fetched(&fake, 20), (8, 1), "the publish's eight");
    let capped = counted(RESOLUTIONS_CAPPED);
    assert_eq!(w.relay.retry_pending().await.unwrap(), 0);
    assert_eq!(fetched(&fake, 20), (16, 1), "the failures are remembered, so the pass read the next eight");
    assert!(counted(RESOLUTIONS_CAPPED) > capped, "the pass passed the cap");
    assert_eq!(w.store.pending(NOW, 10).unwrap().len(), 1, "the row waits");
}

#[tokio::test]
async fn ld_1_one_pass_over_the_pending_rows_reads_its_budget_at_most() {
    let (w, fake) = domain_world();
    w.host(5, Roots::Any, 65_536, 3_600);
    // Ten rows: each publish reads eight of the 200 domains, and a pass could read eighty more.
    for (n, owner) in (20..30).enumerate() {
        w.host(owner, Roots::WithDomains(fanout(200)), 65_536, 3_600);
        let ts = NOW - u64::try_from(n).unwrap();
        assert_eq!(w.resolving_delivered(&rooted(10, &[addr(owner), addr(5)], ts)).await, 1);
    }
    assert_eq!(fetched(&fake, 200), (80, 1));
    assert_eq!(w.relay.retry_pending().await.unwrap(), 0);
    assert_eq!(MAX_FETCHES_PER_RETRY, 64);
    assert_eq!(fetched(&fake, 200), (144, 1));
    assert_eq!(w.store.pending(NOW, 20).unwrap().len(), 10, "all ten wait");
}

#[tokio::test]
async fn ac_sec_22_a_recipient_naming_1024_domains_costs_one_publish_eight_fetches() {
    let (w, fake) = domain_world();
    w.host(2, Roots::WithDomains(fanout(1_024)), 65_536, 3_600);
    assert_eq!(w.resolving_code(&rooted(10, &[addr(2)], NOW)).await, RESOLVE_FAILED);
    assert_eq!(fetched(&fake, 1_024), (8, 1), "1,024 fetches before the cap");
}

#[tokio::test]
async fn ac_sec_22_a_domain_whose_pin_names_the_root_goes_first() {
    let (w, fake) = domain_world();
    w.host(2, Roots::WithDomains(vec![acme()]), 65_536, 3_600);
    fake.set(ACME, Ok(org_bytes(10, NOW, 60, &[], None)));
    assert_eq!(w.resolving_delivered(&rooted(10, &[addr(2)], NOW)).await, 1);
    // A mailbox naming twenty dead domains before acme, once acme's cache has expired: acme is read first.
    let mut roots = fanout(20);
    roots.push(acme());
    w.host(3, Roots::WithDomains(roots), 65_536, 3_600);
    w.clock.advance(61);
    fake.set(ACME, Ok(org_bytes(10, NOW + 61, 3_600, &[], None)));
    assert_eq!(w.resolving_delivered(&rooted(10, &[addr(3)], NOW + 61)).await, 1);
    assert_eq!((fake.calls(ACME), fetched(&fake, 20)), (2, (7, 1)), "acme and seven others");
}

// --- a root an address admits, and the list kept for it -------------------------------------

/// An envelope from `key(from)` under the one hop `key(root)` → `key(from)`, to `to`, at `ts`.
fn under(root: u8, from: u8, to: &[Address], ts: u64) -> Vec<u8> {
    let hop = Hop::sign(&key(root), &addr(from), vec![], NOW + 3_600).unwrap();
    bytes(&envelope(from, to, vec![hop], ts))
}

#[test]
fn r6_20_an_address_admits_a_root_only_for_a_chain_the_root_s_kept_list_does_not_revoke() {
    let w = world();
    w.host(2, Roots::Listed(vec![addr(10)]), 65_536, 3_600);
    w.host(3, Roots::Any, 65_536, 3_600);
    // Before key 10 revokes anything, its chains are delivered.
    assert_eq!(w.delivered(&under(10, 11, &[addr(2)], NOW)), 1);
    let mut events = w.relay.events();
    let before = w.relay.address_records();
    assert!(w.publish(&org_bytes(10, NOW, 3_600, &[addr(11)], None)).is_ok());
    assert_eq!(w.relay.address_records(), before + 1, "an address record stored is counted");
    assert_eq!(events.try_recv().unwrap(), addr(10).to_string(), "and its key's mailbox notified");
    assert_eq!(w.code(&under(10, 11, &[addr(2)], NOW + 1)), (403, Some(Code::Revoked)));
    // Beside a recipient whose roots are ["*"], which reads no list (Appendix B 54), the envelope is delivered there.
    assert_eq!(w.delivered(&under(10, 11, &[addr(2), addr(3)], NOW + 2)), 1);
    assert_eq!(w.store.mailbox_after(addr(3).as_str(), 0, 10, NOW).unwrap().len(), 1);
    assert_eq!(w.store.mailbox_after(addr(2).as_str(), 0, 10, NOW).unwrap().len(), 1, "only the first one");
    // Another key under the same root, and the root itself with no chain, are delivered.
    assert_eq!(w.delivered(&under(10, 12, &[addr(2)], NOW)), 1);
    assert_eq!(w.delivered(&bytes(&envelope(10, &[addr(2)], vec![], NOW))), 1);
    // A record of another kind is not counted.
    assert!(w.publish(&record_bytes(&accept(10, Roots::Any, 1, 1, NOW))).is_ok());
    assert_eq!(w.relay.address_records(), before + 1);
}

#[test]
fn r6_20_a_store_failing_to_read_the_kept_list_at_publish_is_a_500() {
    let w = world_with(Config::default(), Arc::new(FailsRecords(MemoryStore::new(), "revoked")));
    w.host(2, Roots::Listed(vec![addr(10)]), 65_536, 3_600);
    assert_eq!(w.code(&under(10, 11, &[addr(2)], NOW)), (500, None));
    assert_eq!(
        w.delivered(&bytes(&envelope(10, &[addr(2)], vec![], NOW))),
        1,
        "an empty chain reads no list"
    );
}

#[tokio::test]
async fn r6_20_a_pending_row_is_dropped_revoked_when_an_address_now_admits_its_root_under_a_list_that_revokes_it()
 {
    let (w, _fake) = domain_world();
    w.host(2, Roots::WithDomains(vec![acme()]), 65_536, 3_600);
    w.host(5, Roots::Any, 65_536, 3_600);
    assert_eq!(w.resolving_delivered(&rooted(10, &[addr(2), addr(5)], NOW)).await, 1);
    assert_eq!(w.store.pending(NOW, 10).unwrap().len(), 1);
    // Key 10 revokes key 20, its chain's principal; the owner of 2 now admits key 10 by its address.
    assert!(w.publish(&org_bytes(10, NOW, 3_600, &[addr(20)], None)).is_ok());
    w.clock.advance(1);
    assert!(
        w.publish(&record_bytes(&accept(2, Roots::Listed(vec![addr(10)]), 65_536, 3_600, NOW + 1))).is_ok()
    );
    assert_eq!(w.relay.retry_pending().await.unwrap(), 0);
    assert!(w.store.pending(NOW + 1, 10).unwrap().is_empty(), "dropped");
    assert!(w.store.mailbox_after(addr(2).as_str(), 0, 10, NOW + 1).unwrap().is_empty());
}

// --- the operator's blocklist and the sender domain's quota ---------------------------------------------

const BLOCKED: (u16, Option<Code>) = (403, Some(Code::NotAuthorized));

/// A world whose relay reads the blocklist file it returns, which holds `entries`.
fn blocked_world(entries: &[&str]) -> (World, crate::testkit::TempDir, std::path::PathBuf) {
    let dir = crate::testkit::TempDir::new("policy-blocklist");
    let path = dir.path().join("blocklist");
    crate::abuse::edit(&path, &entries.iter().map(|e| format!("+{e}")).collect::<Vec<_>>()).unwrap();
    let config = Config { blocklist: Some(path.clone()), ..Config::default() };
    (world_with(config, Arc::new(MemoryStore::new())), dir, path)
}

#[test]
fn the_blocklist_refuses_a_listed_from_root_hop_or_record_signer_and_reads_each_edit_at_once() {
    let (w, _dir, path) = blocked_world(&[]);
    w.host(2, Roots::Any, 65_536, 3_600);
    let cases = [
        (addr(1), bytes(&envelope(1, &[addr(2)], vec![], NOW))),
        (addr(10), rooted(10, &[addr(2)], NOW - 1)),
        (addr(20), rooted(10, &[addr(2)], NOW - 2)),
        (addr(1), rooted(10, &[addr(2)], NOW - 3)),
    ];
    for (listed, body) in cases {
        crate::abuse::edit(&path, &[format!("+{listed}")]).unwrap();
        assert_eq!(w.code(&body), BLOCKED, "{listed} listed");
        crate::abuse::edit(&path, &[format!("-{listed}")]).unwrap();
        assert_eq!(w.delivered(&body), 1, "{listed} removed");
    }
    // A listed key cannot publish its records either: no accept-from record, so no mailbox.
    crate::abuse::edit(&path, &[format!("+{}", addr(3))]).unwrap();
    assert_eq!(w.code(&record_bytes(&accept(3, Roots::Any, 65_536, 3_600, NOW))), BLOCKED);
    assert_eq!(w.store.record(addr(3).as_str(), Kind::AcceptFrom).unwrap(), None);
    // A recipient on the list is not a sender: the list refuses publishes, not deliveries.
    w.host(4, Roots::Any, 65_536, 3_600);
    crate::abuse::edit(&path, &[format!("+{}", addr(4))]).unwrap();
    assert_eq!(w.delivered(&bytes(&envelope(1, &[addr(4)], vec![], NOW - 4))), 1);
}

#[test]
fn a_listed_domain_blocks_the_key_the_relay_has_pinned_for_it() {
    let (w, _dir, path) = blocked_world(&["domain:acme.example"]);
    w.host(2, Roots::Any, 65_536, 3_600);
    assert_eq!(w.delivered(&rooted(10, &[addr(2)], NOW)), 1, "no pin yet: nothing is blocked");
    let pin = crate::store::DomainPin {
        domain: ACME.into(),
        key: addr(10).to_string(),
        record: vec![],
        pinned_at: NOW,
        expires_at: NOW + 3_600,
    };
    w.store.put_domain_pin(&pin).unwrap();
    assert_eq!(w.code(&rooted(10, &[addr(2)], NOW - 1)), BLOCKED);
    assert_eq!(w.code(&bytes(&envelope(10, &[addr(2)], vec![], NOW - 2))), BLOCKED, "the key as a from");
    assert_eq!(w.delivered(&rooted(11, &[addr(2)], NOW - 3)), 1, "another root is not the domain's");
    crate::abuse::edit(&path, &["-domain:acme.example".to_owned()]).unwrap();
    assert_eq!(w.delivered(&rooted(10, &[addr(2)], NOW - 1)), 1);
}

/// A world whose relay fetches well-known records from a fake, with `config`.
fn domain_world_with(config: Config) -> (World, Arc<FakeFetch>) {
    let fake = FakeFetch::new();
    let w = world_with(config.clone(), Arc::new(MemoryStore::new()));
    let relay = Relay::new(Arc::clone(&w.store), w.clock.clone(), config).with_fetcher(fake.clone());
    (World { relay, ..w }, fake)
}

#[tokio::test]
async fn step_8_the_sender_domain_quota_counts_the_granting_domain_and_a_bare_root_none() {
    let (w, fake) = domain_world_with(Config {
        rate: RateLimits { domain_day: 2, ..RateLimits::default() },
        ..Config::default()
    });
    w.host(2, Roots::WithDomains(vec![acme()]), 65_536, 3_600);
    w.host(3, Roots::Any, 65_536, 3_600);
    fake.set(ACME, Ok(org_bytes(10, NOW, 3_600, &[], None)));
    assert_eq!(w.resolving_delivered(&rooted(10, &[addr(2)], NOW)).await, 1);
    assert_eq!(w.resolving_delivered(&rooted(10, &[addr(2)], NOW - 1)).await, 1);
    let day_left = 86_400 - NOW % 86_400;
    assert_eq!(
        w.resolving_code(&rooted(10, &[addr(2)], NOW - 2)).await,
        (429, Some(Code::RateLimited), Some(day_left))
    );
    // Through the wildcard no domain admits the root: no sender domain, so only the per-root window limits it.
    for ts in NOW - 10..NOW - 5 {
        assert_eq!(w.resolving_delivered(&rooted(10, &[addr(3)], ts)).await, 1);
    }
}

#[tokio::test]
async fn a_listed_domain_refuses_the_root_it_grants_before_the_relay_has_pinned_it() {
    let dir = crate::testkit::TempDir::new("policy-blocklist-domain");
    let path = dir.path().join("blocklist");
    crate::abuse::edit(&path, &["+domain:acme.example".to_owned()]).unwrap();
    let (w, fake) = domain_world_with(Config { blocklist: Some(path.clone()), ..Config::default() });
    w.host(2, Roots::WithDomains(vec![acme()]), 65_536, 3_600);
    fake.set(ACME, Ok(org_bytes(10, NOW, 3_600, &[], None)));
    assert_eq!(w.store.domain_pin(ACME).unwrap(), None, "no pin before the first contact");
    let r = w.resolving(&rooted(10, &[addr(2)], NOW)).await.unwrap_err();
    assert_eq!((r.status, r.code), BLOCKED);
    assert_eq!(w.store.last_cursor(addr(2).as_str()).unwrap(), 0, "nothing delivered");
    crate::abuse::edit(&path, &["-domain:acme.example".to_owned()]).unwrap();
    assert_eq!(w.resolving_delivered(&rooted(10, &[addr(2)], NOW)).await, 1);
}
