//! Fetch and subscribe authorization with the in-memory store (spec/SPEC.md §8.3 to §8.5).

use super::{FetchHeaders, Subscriber, decode_auth_header, encode_auth_header};
use crate::clock::ManualClock;
use crate::config::Config;
use crate::relay::Relay;
use crate::resolver::testkit::org_bytes;
use crate::store::memory::MemoryStore;
use crate::store::{
    Delivery, MailboxEntry, NewEnvelope, Store, StoreError, StoreResult, StoredEnvelope, StoredRecord, Swept,
};
use crate::testkit::{NOW, accept, addr, address_record, bytes, envelope, key, record_bytes};
use ac_core::canonical::Value;
use ac_core::chain::Hop;
use ac_core::keys::SigningKey;
use ac_core::records::{Kind, Roots};
use ac_core::requests::{FETCH_TAG, SUBSCRIBE_TAG, fetch_preimage, subscribe_preimage};
use ac_core::{Address, Code, hex};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

const IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// The public base URL of this module's relays, the audience their fetch proofs name.
const BASE: &str = "https://relay.example";

fn config() -> Config {
    Config { url: Some(BASE.to_owned()), ..Config::default() }
}

fn relay() -> (Relay, String) {
    relay_with(config())
}

/// A relay with `config` that holds one envelope from 1 to 2 and 3, and its id.
fn relay_with(config: Config) -> (Relay, String) {
    let relay = Relay::new(Arc::new(MemoryStore::new()), Arc::new(ManualClock::new(NOW)), config);
    relay.publish(&record_bytes(&accept(2, Roots::Any, 65_536, 3_600, NOW)), IP).unwrap();
    let env = envelope(1, &[addr(2), addr(3)], vec![], NOW);
    relay.publish(&bytes(&env), IP).unwrap();
    (relay, env.id_hex())
}

struct Signed {
    signer: String,
    ts: String,
    sig: String,
    auth: Option<String>,
}

fn sign_fetch(key: &SigningKey, id: &str, ts: u64, hops: &[Hop]) -> Signed {
    sign_for(key, id, ts, hops, BASE)
}

/// A fetch proof whose audience is `audience`.
fn sign_for(key: &SigningKey, id: &str, ts: u64, hops: &[Hop], audience: &str) -> Signed {
    let sig = key.sign_preimage(&fetch_preimage(&key.address(), id, ts, audience)).unwrap();
    Signed {
        signer: key.address().to_string(),
        ts: ts.to_string(),
        sig: hex::encode(&sig),
        auth: if hops.is_empty() { None } else { Some(encode_auth_header(hops)) },
    }
}

fn headers(s: &Signed) -> FetchHeaders<'_> {
    FetchHeaders { signer: Some(&s.signer), ts: Some(&s.ts), sig: Some(&s.sig), auth: s.auth.as_deref() }
}

fn fetch_code(relay: &Relay, id: &str, s: &Signed) -> (u16, Option<Code>) {
    let r = relay.fetch(id, &headers(s)).expect_err("a refusal");
    (r.status, r.code)
}

#[test]
fn the_sender_and_every_recipient_fetch_the_exact_bytes() {
    let (relay, id) = relay();
    let stored = relay.store().envelope(&id, NOW).unwrap().unwrap();
    for n in [1, 2, 3] {
        assert_eq!(
            relay.fetch(&id, &headers(&sign_fetch(&key(n), &id, NOW, &[]))).unwrap(),
            stored,
            "key {n}"
        );
    }
}

#[test]
fn a_delegate_of_a_party_may_fetch_and_a_third_party_may_not() {
    let (relay, id) = relay();
    let hop = Hop::sign(&key(2), &addr(20), vec![], NOW + 60).unwrap();
    assert!(relay.fetch(&id, &headers(&sign_fetch(&key(20), &id, NOW, std::slice::from_ref(&hop)))).is_ok());
    assert_eq!(
        fetch_code(&relay, &id, &sign_fetch(&key(9), &id, NOW, &[])),
        (403, Some(Code::NotAuthorized))
    );
    let stranger = Hop::sign(&key(9), &addr(20), vec![], NOW + 60).unwrap();
    assert_eq!(
        fetch_code(&relay, &id, &sign_fetch(&key(20), &id, NOW, &[stranger])),
        (403, Some(Code::NotAuthorized))
    );
    // A chain that does not hold is no chain: 403 not-authorized. It is judged at AC-Ts.
    let expired = Hop::sign(&key(2), &addr(20), vec![], NOW - 1).unwrap();
    assert_eq!(
        fetch_code(&relay, &id, &sign_fetch(&key(20), &id, NOW, &[expired])),
        (403, Some(Code::NotAuthorized))
    );
    let at_edge = Hop::sign(&key(2), &addr(20), vec![], NOW - 100).unwrap();
    assert!(relay.fetch(&id, &headers(&sign_fetch(&key(20), &id, NOW - 100, &[at_edge]))).is_ok());
    assert_eq!(
        fetch_code(&relay, &id, &sign_fetch(&key(21), &id, NOW, &[hop])),
        (403, Some(Code::NotAuthorized))
    );
}

/// The principal of the envelope's chain, its last hop's `iss`, is a party, and so is a key with a
/// chain from it; the org root of a two-hop chain is not. In a one-hop chain the root is the principal.
#[test]
fn the_principal_of_a_chain_may_fetch_and_its_org_root_may_not() {
    let (relay, _) = relay();
    let org = Hop::sign(&key(40), &addr(41), vec![], NOW + 60).unwrap();
    let session = Hop::sign(&key(41), &addr(42), vec![], NOW + 60).unwrap();
    let env = envelope(42, &[addr(2)], vec![org, session], NOW);
    relay.publish(&bytes(&env), IP).unwrap();
    let id = env.id_hex();
    let stored = relay.store().envelope(&id, NOW).unwrap().unwrap();
    assert_eq!(stored.received_at, NOW);
    assert_eq!(relay.fetch(&id, &headers(&sign_fetch(&key(41), &id, NOW, &[]))).unwrap(), stored);
    let own = Hop::sign(&key(41), &addr(43), vec![], NOW + 60).unwrap();
    assert_eq!(relay.fetch(&id, &headers(&sign_fetch(&key(43), &id, NOW, &[own]))).unwrap(), stored);
    assert_eq!(
        fetch_code(&relay, &id, &sign_fetch(&key(40), &id, NOW, &[])),
        (403, Some(Code::NotAuthorized))
    );
    let one = Hop::sign(&key(50), &addr(51), vec![], NOW + 60).unwrap();
    let env = envelope(51, &[addr(2)], vec![one], NOW);
    relay.publish(&bytes(&env), IP).unwrap();
    let id = env.id_hex();
    assert!(relay.fetch(&id, &headers(&sign_fetch(&key(50), &id, NOW, &[]))).is_ok());
}

#[test]
fn the_proof_its_time_and_its_headers() {
    let (relay, id) = relay();
    let mut s = sign_fetch(&key(2), &id, NOW, &[]);
    s.sig = hex::encode(&key(2).sign(&[0; 32]));
    assert_eq!(fetch_code(&relay, &id, &s), (401, Some(Code::BadAuth)));
    assert_eq!(
        fetch_code(&relay, &id, &sign_fetch(&key(2), &"00".repeat(32), NOW, &[])),
        (401, Some(Code::BadAuth))
    );
    assert_eq!(
        fetch_code(&relay, &id, &sign_fetch(&key(2), &id, NOW - 301, &[])),
        (401, Some(Code::StaleTs))
    );
    assert_eq!(
        fetch_code(&relay, &id, &sign_fetch(&key(2), &id, NOW + 301, &[])),
        (401, Some(Code::FutureTs))
    );
    assert!(relay.fetch(&id, &headers(&sign_fetch(&key(2), &id, NOW + 300, &[]))).is_ok());
    let good = sign_fetch(&key(2), &id, NOW, &[]);
    let with = |f: &dyn Fn(&mut FetchHeaders<'_>)| {
        let mut h = headers(&good);
        f(&mut h);
        let r = relay.fetch(&id, &h).unwrap_err();
        (r.status, r.code)
    };
    for broken in [
        &(|h: &mut FetchHeaders<'_>| h.signer = None) as &dyn Fn(&mut FetchHeaders<'_>),
        &|h| h.ts = None,
        &|h| h.sig = None,
        &|h| h.signer = Some("alice"),
        &|h| h.ts = Some("+5"),
        &|h| h.ts = Some(""),
        &|h| h.ts = Some("9007199254740992"),
        &|h| h.ts = Some("99999999999999999999999"),
        &|h| h.sig = Some("00"),
        &|h| h.auth = Some("***"),
        &|h| h.auth = Some("e30"),
    ] {
        assert_eq!(with(broken), (401, Some(Code::BadAuth)));
    }
    assert_eq!(relay.fetch("abc", &headers(&good)).unwrap_err().code, Some(Code::BadHex));
    assert_eq!(relay.fetch(&id.to_uppercase(), &headers(&good)).unwrap_err().status, 400);
    let unknown = "11".repeat(32);
    assert_eq!(
        fetch_code(&relay, &unknown, &sign_fetch(&key(2), &unknown, NOW, &[])),
        (404, Some(Code::NotFound))
    );
}

#[test]
fn an_expired_envelope_is_not_found() {
    let relay = Relay::new(Arc::new(MemoryStore::new()), Arc::new(ManualClock::new(NOW)), config());
    relay.publish(&record_bytes(&accept(2, Roots::Any, 65_536, 10, NOW)), IP).unwrap();
    let env = envelope(1, &[addr(2)], vec![], NOW);
    relay.publish(&bytes(&env), IP).unwrap();
    let later = Relay::new(Arc::clone(&relay.store), Arc::new(ManualClock::new(NOW + 10)), config());
    let s = sign_fetch(&key(2), &env.id_hex(), NOW + 10, &[]);
    assert_eq!(fetch_code(&later, &env.id_hex(), &s), (404, Some(Code::NotFound)));
}

// --- the audience (spec/SPEC.md §8.3, added 2026-11-02) ------------------------------------------

#[test]
fn a_proof_for_another_relay_or_another_spelling_of_the_base_is_bad_auth() {
    let (relay, id) = relay();
    assert!(relay.fetch(&id, &headers(&sign_for(&key(2), &id, NOW, &[], BASE))).is_ok());
    for other in [
        "https://other.example", // another relay's base: a proof replayed from one relay to another
        "https://relay.example/",
        "https://relay.example/bag",
        "https://relay.example:443",
        "https://RELAY.example",
        "http://relay.example",
        "",
    ] {
        let s = sign_for(&key(2), &id, NOW, &[], other);
        assert_eq!(fetch_code(&relay, &id, &s), (401, Some(Code::BadAuth)), "{other:?}");
    }
}

#[test]
fn the_four_fields_of_before_and_a_preimage_of_another_tag_are_bad_auth() {
    let (relay, id) = relay();
    let k = key(2);
    let who = k.address().to_string();
    let (w, i) = (who.as_str(), id.as_str());
    let old = Value::Array(vec![Value::from(FETCH_TAG), Value::from(w), Value::from(i), Value::Int(NOW)]);
    let other_tag = Value::Array(vec![
        Value::from(SUBSCRIBE_TAG),
        Value::from(w),
        Value::from(i),
        Value::Int(NOW),
        Value::from(BASE),
    ]);
    let subscribe = subscribe_preimage(&id, &k.address(), &k.address(), Some(NOW));
    for preimage in [old, other_tag, subscribe] {
        let sig = hex::encode(&k.sign_preimage(&preimage).unwrap());
        let s = Signed { signer: who.clone(), ts: NOW.to_string(), sig, auth: None };
        assert_eq!(fetch_code(&relay, &id, &s), (401, Some(Code::BadAuth)));
    }
}

#[test]
fn each_configured_base_is_an_audience_and_a_relay_with_none_accepts_no_proof() {
    let (relay, id) = relay_with(Config { accept_bases: vec!["https://old.example".into()], ..config() });
    for base in [BASE, "https://old.example"] {
        assert!(relay.fetch(&id, &headers(&sign_for(&key(2), &id, NOW, &[], base))).is_ok(), "{base}");
    }
    let third = sign_for(&key(2), &id, NOW, &[], "https://third.example");
    assert_eq!(fetch_code(&relay, &id, &third), (401, Some(Code::BadAuth)));
    let (bare, id) = relay_with(Config::default());
    assert_eq!(fetch_code(&bare, &id, &sign_for(&key(2), &id, NOW, &[], BASE)), (401, Some(Code::BadAuth)));
}

#[test]
fn a_chain_s_proof_names_the_audience_too_and_the_skew_still_applies() {
    let (relay, id) = relay();
    let hop = Hop::sign(&key(2), &addr(20), vec![], NOW + 60).unwrap();
    let chain = std::slice::from_ref(&hop);
    assert!(relay.fetch(&id, &headers(&sign_for(&key(20), &id, NOW, chain, BASE))).is_ok());
    let elsewhere = sign_for(&key(20), &id, NOW, chain, "https://other.example");
    assert_eq!(fetch_code(&relay, &id, &elsewhere), (401, Some(Code::BadAuth)));
    let stale = sign_for(&key(2), &id, NOW - 301, &[], BASE);
    assert_eq!(fetch_code(&relay, &id, &stale), (401, Some(Code::StaleTs)));
    let future = sign_for(&key(2), &id, NOW + 301, &[], BASE);
    assert_eq!(fetch_code(&relay, &id, &future), (401, Some(Code::FutureTs)));
}

#[test]
fn the_signer_and_the_id_count_only_in_their_canonical_forms() {
    let (relay, id) = relay();
    let canonical = addr(2).to_string();
    let upper_hex = format!("ed25519:{}", canonical["ed25519:".len()..].to_uppercase());
    for signer in [upper_hex, format!(" {canonical}"), canonical.to_uppercase()] {
        let s = Signed { signer, ..sign_for(&key(2), &id, NOW, &[], BASE) };
        assert_eq!(fetch_code(&relay, &id, &s), (401, Some(Code::BadAuth)));
    }
    // An id in another form is refused before its proof is read, even one signed over that form.
    for other in [id.to_uppercase(), format!(" {id}"), format!("{id} "), format!("0x{id}")] {
        let s = sign_for(&key(2), &other, NOW, &[], BASE);
        assert_eq!(fetch_code(&relay, &other, &s), (400, Some(Code::BadHex)), "{other:?}");
    }
}

#[test]
fn auth_headers_round_trip_with_or_without_padding() {
    let hops = vec![Hop::sign(&key(2), &addr(20), vec!["c".into()], NOW + 60).unwrap()];
    let encoded = encode_auth_header(&hops);
    assert!(!encoded.contains('='));
    assert_eq!(decode_auth_header(&encoded).unwrap(), hops);
    let padded = format!("{encoded}{}", "=".repeat((4 - encoded.len() % 4) % 4));
    assert_eq!(decode_auth_header(&padded).unwrap(), hops);
    assert_eq!(decode_auth_header(&encode_auth_header(&[])).unwrap(), vec![]);
    let not_utf8 = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [0xff, 0xfe]);
    assert_eq!(decode_auth_header(&not_utf8), Err(Code::BadAuth));
    let nine = vec![hops[0].clone(); 9];
    assert_eq!(decode_auth_header(&encode_auth_header(&nine)), Err(Code::BadAuth));
}

#[test]
fn records_are_public() {
    let (relay, _) = relay();
    let stored = relay.fetch_record(addr(2).as_str(), "accept-from").unwrap();
    assert_eq!(stored, record_bytes(&accept(2, Roots::Any, 65_536, 3_600, NOW)));
    assert_eq!(relay.fetch_record(addr(2).as_str(), "key").unwrap_err().status, 404);
    assert_eq!(relay.fetch_record("nobody", "key").unwrap_err().code, Some(Code::BadAddress));
    assert_eq!(relay.fetch_record(addr(2).as_str(), "letters").unwrap_err().code, Some(Code::NotFound));
    relay.publish(&record_bytes(&address_record(5, NOW, None)), IP).unwrap();
    assert!(relay.fetch_record(addr(5).as_str(), "address").is_ok());
}

fn auth_frame(
    signer: &SigningKey,
    mailbox: &Address,
    hops: &[Hop],
    cursor: Option<u64>,
    nonce: &str,
) -> String {
    let sig = signer.sign_preimage(&subscribe_preimage(nonce, &signer.address(), mailbox, cursor)).unwrap();
    serde_json::json!({
        "t": "auth",
        "mailbox": mailbox.as_str(),
        "signer": signer.address().as_str(),
        "auth": hops.iter().map(|h| serde_json::from_str::<serde_json::Value>(&h.to_json_text()).unwrap()).collect::<Vec<_>>(),
        "cursor": cursor,
        "sig": hex::encode(&sig),
    })
    .to_string()
}

#[test]
fn a_subscriber_is_the_mailbox_key_or_a_delegate_of_it() {
    let (relay, _) = relay();
    let n = "aa".repeat(32);
    let own = relay.authorize_subscriber(&auth_frame(&key(2), &addr(2), &[], Some(4), &n), &n, NOW).unwrap();
    let mailbox_key =
        Subscriber { mailbox: addr(2), signer: addr(2), cursor: Some(4), expires: None, hops: vec![] };
    assert_eq!(own, mailbox_key);
    let hop = Hop::sign(&key(2), &addr(30), vec![], NOW + 60).unwrap();
    let frame = auth_frame(&key(30), &addr(2), std::slice::from_ref(&hop), None, &n);
    let delegate = relay.authorize_subscriber(&frame, &n, NOW).unwrap();
    assert_eq!(
        delegate,
        Subscriber {
            mailbox: addr(2),
            signer: addr(30),
            cursor: None,
            expires: Some(NOW + 60),
            hops: vec![hop]
        }
    );
    // Two hops: the subscription ends at the earlier exp.
    let first = Hop::sign(&key(2), &addr(31), vec![], NOW + 600).unwrap();
    let second = Hop::sign(&key(31), &addr(30), vec![], NOW + 90).unwrap();
    let two = relay
        .authorize_subscriber(&auth_frame(&key(30), &addr(2), &[first, second], None, &n), &n, NOW)
        .unwrap();
    assert_eq!(two.expires, Some(NOW + 90));
}

#[test]
fn subscriber_refusals() {
    let (relay, _) = relay();
    let n = "aa".repeat(32);
    let code = |frame: &str| relay.authorize_subscriber(frame, &n, NOW).unwrap_err();
    assert_eq!(code("not json"), Code::BadAuth);
    assert_eq!(code(r#"{"t":"ack","cursor":1}"#), Code::BadAuth);
    let good: serde_json::Value =
        serde_json::from_str(&auth_frame(&key(2), &addr(2), &[], None, &n)).unwrap();
    for (field, value) in [
        ("t", serde_json::json!("hello")),
        ("mailbox", serde_json::json!("mb")),
        ("signer", serde_json::json!(1)),
        ("sig", serde_json::json!("00")),
        ("cursor", serde_json::json!(9_007_199_254_740_992_u64)),
        ("cursor", serde_json::json!(-1)),
        ("auth", serde_json::json!({})),
        ("more", serde_json::json!(1)),
    ] {
        let mut f = good.clone();
        f[field] = value;
        assert_eq!(code(&f.to_string()), Code::BadAuth, "{field}");
    }
    let mut missing = good.clone();
    missing.as_object_mut().unwrap().remove("cursor");
    assert_eq!(code(&missing.to_string()), Code::BadAuth);
    // Signed over another nonce.
    assert_eq!(code(&auth_frame(&key(2), &addr(2), &[], None, &"bb".repeat(32))), Code::BadAuth);
    // Another key with no chain, or a chain rooted elsewhere.
    assert_eq!(code(&auth_frame(&key(9), &addr(2), &[], None, &n)), Code::NotAuthorized);
    let elsewhere = Hop::sign(&key(9), &addr(30), vec![], NOW + 60).unwrap();
    assert_eq!(code(&auth_frame(&key(30), &addr(2), &[elsewhere], None, &n)), Code::NotAuthorized);
    // A chain code when the delegation does not hold, judged at the challenge's ts.
    let hop = Hop::sign(&key(2), &addr(30), vec![], NOW - 1).unwrap();
    assert_eq!(code(&auth_frame(&key(30), &addr(2), std::slice::from_ref(&hop), None, &n)), Code::HopExpired);
    assert!(
        relay.authorize_subscriber(&auth_frame(&key(30), &addr(2), &[hop], None, &n), &n, NOW - 1).is_ok()
    );
    let mut frame: serde_json::Value =
        serde_json::from_str(&auth_frame(&key(2), &addr(2), &[], None, &n)).unwrap();
    frame["auth"] = serde_json::json!([{"iss": 1}]);
    assert_eq!(code(&frame.to_string()), Code::BadHop);
}

/// A store that hands back bytes that do not parse as an envelope, or fails.
struct Odd(MemoryStore, bool);

impl Store for Odd {
    fn record(&self, a: &str, k: Kind) -> StoreResult<Option<StoredRecord>> {
        if self.1 { Err(StoreError("down".into())) } else { self.0.record(a, k) }
    }
    fn put_record(&self, a: &str, k: Kind, iat: u64, e: Option<u64>, b: &[u8]) -> StoreResult<bool> {
        self.0.put_record(a, k, iat, e, b)
    }
    fn revoked(&self, a: &str) -> StoreResult<Vec<String>> {
        if self.1 { Err(StoreError("down".into())) } else { self.0.revoked(a) }
    }
    fn has_envelope(&self, id: &str, now: u64) -> StoreResult<bool> {
        self.0.has_envelope(id, now)
    }
    fn insert_envelope(&self, e: &NewEnvelope<'_>, d: &[Delivery]) -> StoreResult<Option<Vec<u64>>> {
        self.0.insert_envelope(e, d)
    }
    fn envelope(&self, _: &str, _: u64) -> StoreResult<Option<StoredEnvelope>> {
        if self.1 {
            Err(StoreError("down".into()))
        } else {
            Ok(Some(StoredEnvelope { bytes: b"{\"not\":\"an envelope\"}".to_vec(), received_at: NOW }))
        }
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
fn a_corrupt_or_failing_store_is_a_500() {
    let id = "11".repeat(32);
    let s = sign_fetch(&key(2), &id, NOW, &[]);
    for failing in [false, true] {
        let relay =
            Relay::new(Arc::new(Odd(MemoryStore::new(), failing)), Arc::new(ManualClock::new(NOW)), config());
        assert_eq!(fetch_code(&relay, &id, &s), (500, None));
        if failing {
            assert_eq!(relay.fetch_record(addr(2).as_str(), "key").unwrap_err().status, 500);
        }
    }
}

// --- the mailbox's own revoked list ------------------------------------------------------------

/// Mailbox 2's address record, revoking keys 30 and 32, published to `relay`.
fn revoke_30_and_32(relay: &Relay) {
    relay.publish(&org_bytes(2, NOW, 3_600, &[addr(30), addr(32)], None), IP).unwrap();
}

#[test]
fn a_subscriber_whose_chain_the_mailbox_revokes_is_refused_and_the_rest_are_not() {
    let (relay, _) = relay();
    revoke_30_and_32(&relay);
    let n = "aa".repeat(32);
    let subscribe = |signer: u8, hops: &[Hop]| {
        relay.authorize_subscriber(&auth_frame(&key(signer), &addr(2), hops, None, &n), &n, NOW)
    };
    let revoked = Hop::sign(&key(2), &addr(30), vec![], NOW + 60).unwrap();
    assert_eq!(subscribe(30, &[revoked]), Err(Code::Revoked));
    // A revoked key in the middle of a chain: hop 0's sub and hop 1's iss.
    let through = Hop::sign(&key(2), &addr(32), vec![], NOW + 60).unwrap();
    let onward = Hop::sign(&key(32), &addr(33), vec![], NOW + 60).unwrap();
    assert_eq!(subscribe(33, &[through, onward]), Err(Code::Revoked));
    let fine = Hop::sign(&key(2), &addr(31), vec![], NOW + 60).unwrap();
    assert_eq!(subscribe(31, std::slice::from_ref(&fine)).unwrap().hops, vec![fine]);
    assert!(subscribe(2, &[]).unwrap().hops.is_empty(), "the mailbox key itself has no chain to revoke");
    // Another mailbox's list is not read: key 30 under mailbox 3's own chain is admitted there.
    let other = Hop::sign(&key(3), &addr(30), vec![], NOW + 60).unwrap();
    let frame = auth_frame(&key(30), &addr(3), &[other], None, &n);
    assert!(relay.authorize_subscriber(&frame, &n, NOW).is_ok());
}

#[test]
fn a_fetch_under_a_chain_its_root_revokes_is_403_revoked_after_the_party_check() {
    let (relay, id) = relay();
    revoke_30_and_32(&relay);
    let revoked = Hop::sign(&key(2), &addr(30), vec![], NOW + 60).unwrap();
    assert_eq!(
        fetch_code(&relay, &id, &sign_fetch(&key(30), &id, NOW, &[revoked])),
        (403, Some(Code::Revoked))
    );
    let fine = Hop::sign(&key(2), &addr(31), vec![], NOW + 60).unwrap();
    assert!(relay.fetch(&id, &headers(&sign_fetch(&key(31), &id, NOW, &[fine]))).is_ok());
    // Key 30 with a chain from key 3, whose list names nothing: admitted.
    let from_three = Hop::sign(&key(3), &addr(30), vec![], NOW + 60).unwrap();
    assert!(relay.fetch(&id, &headers(&sign_fetch(&key(30), &id, NOW, &[from_three]))).is_ok());
    // No party, no chain: not-authorized, as before; a party with no chain reads.
    assert_eq!(
        fetch_code(&relay, &id, &sign_fetch(&key(30), &id, NOW, &[])),
        (403, Some(Code::NotAuthorized))
    );
    assert!(relay.fetch(&id, &headers(&sign_fetch(&key(2), &id, NOW, &[]))).is_ok());
}

#[test]
fn a_store_that_fails_to_read_the_list_at_subscribe_is_the_relay_s_own_failure() {
    let relay = Relay::new(
        Arc::new(Odd(MemoryStore::new(), true)),
        Arc::new(ManualClock::new(NOW)),
        Config::default(),
    );
    let n = "aa".repeat(32);
    let hop = Hop::sign(&key(2), &addr(30), vec![], NOW + 60).unwrap();
    let frame = auth_frame(&key(30), &addr(2), &[hop], None, &n);
    assert_eq!(relay.authorize_subscriber(&frame, &n, NOW), Err(Code::Internal));
    // The mailbox key itself reads no list.
    assert!(relay.authorize_subscriber(&auth_frame(&key(2), &addr(2), &[], None, &n), &n, NOW).is_ok());
}
