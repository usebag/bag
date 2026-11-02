use super::{
    CLAIM_BURST, CLAIM_RATE, MAX_BLOB, MAX_OPEN, MAX_TTL, OPEN_PER_IP, Opening, Pairs, REQUEST_BURST,
    REQUESTS_PER_IP, parse_nameplate, parse_open,
};
use crate::ratelimit::{Limit, Refused};
use crate::testkit::{NOW, addr, counted, key};
use ac_core::Code;
use ac_core::canonical::Value as Signed;
use ac_core::hex;
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The addresses as `request` takes them.
fn to<'a>(addresses: &[&'a ac_core::Address]) -> Vec<&'a str> {
    addresses.iter().map(|a| a.as_str()).collect()
}

const IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const OTHER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

/// The client address of opener `i`, so that no one holds more than [`OPEN_PER_IP`].
fn opener(i: usize) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + u32::try_from(i).unwrap()))
}

fn opening(invitation: &str, ttl: u64) -> Opening {
    Opening {
        inviter: addr(1).to_string(),
        invitation: invitation.to_owned(),
        relays: vec!["https://relay.test".into()],
        ttl,
    }
}

fn code(r: Result<impl std::fmt::Debug, crate::relay::Rejection>) -> (u16, &'static str) {
    let r = r.unwrap_err();
    (r.status, r.error())
}

#[test]
fn a_nameplate_has_three_digits_and_its_blob_is_claimed_until_exp_without_being_consumed() {
    let pairs = Pairs::default();
    let i = addr(2).to_string();
    let (n, exp) = pairs.open(NOW, IP, opening(&i, 600), 0).unwrap();
    assert!((100..=999).contains(&n), "{n}");
    assert_eq!(exp, NOW + 600);
    let blob = json!({"inviter": addr(1).to_string(), "invitation": i, "relays": ["https://relay.test"], "exp": exp});
    for _ in 0..3 {
        assert_eq!(pairs.claim(NOW, OTHER, Some(n)), Ok(Some(blob.clone())));
    }
    assert_eq!(pairs.claim(exp - 1, OTHER, Some(n)), Ok(Some(blob)));
    // Gone at exp, before any sweep.
    assert_eq!(pairs.claim(exp, OTHER, Some(n)), Ok(None));
    assert_eq!(pairs.claim(NOW, OTHER, Some(n + 1_000)), Ok(None));
    assert_eq!(pairs.claim(NOW, OTHER, None), Ok(None));
}

#[test]
fn the_search_starts_where_it_is_told_and_wraps_within_the_length() {
    let pairs = Pairs::default();
    assert_eq!(pairs.open(NOW, IP, opening("a", 60), 0).unwrap().0, 100);
    assert_eq!(pairs.open(NOW, IP, opening("b", 60), 0).unwrap().0, 101);
    assert_eq!(pairs.open(NOW, IP, opening("c", 60), 899).unwrap().0, 999);
    // 999 is open: the search wraps to the first free one from 100.
    assert_eq!(pairs.open(NOW, IP, opening("d", 60), 899).unwrap().0, 102);
    assert_eq!(pairs.open(NOW, IP, opening("e", 60), 900 + 450).unwrap().0, 550);
    // A start near u64::MAX does not overflow.
    assert!((100..=999).contains(&pairs.open(NOW, IP, opening("f", 60), u64::MAX).unwrap().0));
}

#[test]
fn an_open_nameplate_is_never_reused_and_four_digits_follow_when_three_are_used_up() {
    let pairs = Pairs::default();
    let mut seen = std::collections::HashSet::new();
    for i in 0..900 {
        let (n, _) = pairs
            .open(NOW, opener(i / OPEN_PER_IP), opening(&format!("i{i}"), 600), u64::try_from(i * 7).unwrap())
            .unwrap();
        assert!((100..=999).contains(&n) && seen.insert(n), "{i}: {n}");
    }
    let (n, _) = pairs.open(NOW, opener(9_999), opening("four", 600), 12_345).unwrap();
    assert!((1_000..=9_999).contains(&n), "{n}");
    // A short one opened now is four digits too; at NOW + 600 every one has expired and is swept.
    let short = pairs.open(NOW, opener(9_998), opening("short", 1), 0);
    assert!((1_000..=9_999).contains(&short.unwrap().0));
    assert_eq!(pairs.sweep(NOW + 600), 902);
    assert!(pairs.inner().open.is_empty());
    assert!((100..=999).contains(&pairs.open(NOW + 600, IP, opening("again", 600), 0).unwrap().0));
}

#[test]
fn an_expired_nameplate_frees_its_number_its_invitation_and_its_opener_at_once() {
    let pairs = Pairs::default();
    assert_eq!(pairs.open(NOW, IP, opening("a", 10), 0).unwrap().0, 100);
    assert_eq!(code(pairs.open(NOW + 9, IP, opening("a", 10), 0)), (409, "stale-record"));
    // At exp the number and the invitation are free, though nothing swept yet.
    assert_eq!(pairs.inner().open.len(), 1);
    assert_eq!(pairs.open(NOW + 10, IP, opening("a", 10), 0).unwrap().0, 100);
}

#[test]
fn the_sweep_forgets_expired_nameplates_and_full_claim_buckets() {
    let pairs = Pairs::default();
    pairs.open(NOW, IP, opening("a", 10), 0).unwrap();
    pairs.open(NOW, IP, opening("b", 20), 0).unwrap();
    pairs.claim(NOW, OTHER, None).unwrap();
    assert_eq!(pairs.sweep(NOW + 9), 0);
    assert_eq!(pairs.sweep(NOW + 10), 1);
    let held = {
        let inner = pairs.inner();
        (inner.open.len(), inner.claims.len())
    };
    assert_eq!(held, (1, 0));
    assert_eq!(pairs.sweep(NOW + 20), 1);
    let inner = pairs.inner();
    assert!(inner.open.is_empty() && inner.by_invitation.is_empty());
}

#[test]
fn one_client_address_holds_at_most_open_per_ip_and_its_ipv6_64_counts_as_one() {
    let pairs = Pairs::default();
    let v6 = |last: u16| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, last));
    for i in 0..OPEN_PER_IP {
        pairs
            .open(
                NOW + u64::try_from(i).unwrap(),
                v6(u16::try_from(i).unwrap()),
                opening(&format!("i{i}"), 600),
                0,
            )
            .unwrap();
    }
    let refused = pairs.open(NOW + 20, v6(999), opening("over", 600), 0).unwrap_err();
    // The earliest of its nameplates expires at NOW + 600.
    assert_eq!((refused.status, refused.error(), refused.retry_after), (429, "rate-limited", Some(580)));
    assert!(pairs.open(NOW + 20, OTHER, opening("other", 600), 0).is_ok());
    assert!(pairs.open(NOW + 600, v6(999), opening("over", 600), 0).is_ok());
}

#[test]
fn the_relay_holds_at_most_max_open() {
    let pairs = Pairs::default();
    for i in 0..MAX_OPEN {
        pairs.open(NOW, opener(i / OPEN_PER_IP), opening(&format!("i{i}"), 600), 0).unwrap();
    }
    let fresh = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let full = pairs.open(NOW, fresh, opening("full", 600), 0).unwrap_err();
    assert_eq!((full.status, full.error(), full.retry_after), (503, "store-full", Some(MAX_TTL)));
}

#[test]
fn a_claim_bucket_holds_ten_and_refills_five_a_second() {
    let pairs = Pairs::default();
    for _ in 0..CLAIM_BURST {
        assert_eq!(pairs.claim(NOW, IP, Some(100)), Ok(None));
    }
    assert_eq!(pairs.claim(NOW, IP, Some(100)), Err(1));
    // Another client address has its own bucket.
    assert_eq!(pairs.claim(NOW, OTHER, Some(100)), Ok(None));
    for _ in 0..CLAIM_RATE {
        assert_eq!(pairs.claim(NOW + 1, IP, None), Ok(None));
    }
    assert_eq!(pairs.claim(NOW + 1, IP, None), Err(1));
    // A long pause fills it to the burst, no more.
    for _ in 0..CLAIM_BURST {
        assert_eq!(pairs.claim(NOW + 100, IP, None), Ok(None));
    }
    assert_eq!(pairs.claim(NOW + 100, IP, None), Err(1));
}

#[test]
fn each_claim_is_counted_by_its_result_and_the_nameplates_open_are_the_live_ones() {
    let series = |result: &str| format!("ac_relay_pair_claims_total{{result=\"{result}\"}}");
    let before = ["ok", "no-nameplate", "rate-limited"].map(|r| counted(&series(r)));
    let pairs = Pairs::default();
    let (n, _) = pairs.open(NOW, IP, opening("a", 10), 0).unwrap();
    pairs.open(NOW, IP, opening("b", 20), 0).unwrap();
    assert_eq!((pairs.open_at(NOW), pairs.open_at(NOW + 10), pairs.open_at(NOW + 20)), (2, 1, 0));
    let claimer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77));
    assert!(pairs.claim(NOW, claimer, Some(n)).unwrap().is_some());
    for _ in 1..CLAIM_BURST {
        assert_eq!(pairs.claim(NOW, claimer, None), Ok(None));
    }
    assert_eq!(pairs.claim(NOW, claimer, Some(n)), Err(1));
    let after = ["ok", "no-nameplate", "rate-limited"].map(|r| counted(&series(r)));
    let moved = [1, CLAIM_BURST - 1, 1];
    for ((b, a), m) in before.iter().zip(after).zip(moved) {
        assert!(a >= b + m, "{before:?} then {after:?}");
    }
}

#[test]
fn requests_to_an_invitation_take_a_token_of_its_bucket_five_at_once_then_one_a_second_across_addresses() {
    let pairs = Pairs::default();
    let (i, other) = (addr(2), addr(3));
    let (n, exp) = pairs.open(NOW, IP, opening(i.as_str(), 600), 0).unwrap();
    assert_eq!(pairs.request(NOW, OTHER, to(&[&other])), Ok(vec![]));
    // The burst, from five client addresses: the bucket is the nameplate's, across them.
    for k in 0..REQUEST_BURST {
        assert_eq!(
            pairs.request(NOW, opener(usize::try_from(k).unwrap()), to(&[&other, &i])),
            Ok(vec![n]),
            "{k}"
        );
    }
    let empty = Err(Refused { limit: Limit::Pairing, retry_after: 1 });
    assert_eq!(pairs.request(NOW, IP, to(&[&i])), empty);
    // Then one a second, with no total: 600 seconds of guesses at most, never a used-up invitation.
    for t in 1..=100 {
        assert_eq!(pairs.request(NOW + t, opener(usize::try_from(t).unwrap()), to(&[&i])), Ok(vec![n]));
        assert_eq!(pairs.request(NOW + t, IP, to(&[&i])), empty, "{t}");
    }
    // A pause refills it to the burst, no more.
    for _ in 0..REQUEST_BURST {
        assert_eq!(pairs.request(NOW + 400, OTHER, to(&[&i])), Ok(vec![n]));
    }
    assert_eq!(pairs.request(NOW + 400, IP, to(&[&i])), empty);
    // Mail to anyone else is not counted, and an expired nameplate counts nothing.
    assert_eq!(pairs.request(NOW + 400, IP, to(&[&other])), Ok(vec![]));
    assert_eq!(pairs.request(exp, IP, to(&[&i])), Ok(vec![]));
}

#[test]
fn one_client_address_sends_at_most_ten_requests_to_a_nameplate() {
    let pairs = Pairs::default();
    let i = addr(2);
    let (n, exp) = pairs.open(NOW, IP, opening(i.as_str(), 600), 0).unwrap();
    for t in 0..u64::from(REQUESTS_PER_IP) {
        assert_eq!(pairs.request(NOW + t, OTHER, to(&[&i])), Ok(vec![n]), "{t}");
    }
    let t = NOW + 100;
    let over = Err(Refused { limit: Limit::Pairing, retry_after: exp - t });
    assert_eq!(pairs.request(t, OTHER, to(&[&i])), over);
    // Another client address has its own ten.
    assert_eq!(pairs.request(t, IP, to(&[&i])), Ok(vec![n]));
}

#[test]
fn a_refused_request_counts_nothing() {
    let pairs = Pairs::default();
    let (a, b) = (addr(2), addr(3));
    let (na, _) = pairs.open(NOW, IP, opening(a.as_str(), 600), 0).unwrap();
    let (nb, _) = pairs.open(NOW, IP, opening(b.as_str(), 600), 0).unwrap();
    for _ in 0..REQUEST_BURST {
        assert_eq!(pairs.request(NOW, opener(1), to(&[&a])), Ok(vec![na]));
    }
    // b is refused with a, and neither b's bucket nor its per-address count moves.
    assert!(pairs.request(NOW, OTHER, to(&[&b, &a])).is_err());
    let inner = pairs.inner();
    let open = &inner.open[&nb];
    assert_eq!((open.requests.0, open.from.get(&OTHER)), (REQUEST_BURST, None));
}

/// `body` with I's `sig` by `key(by)` over `["ac/pair-open/1", inviter, invitation, relays, ttl]`, built here from the
/// rule's words, not from the code under test.
fn signed(mut body: serde_json::Value, by: u8) -> serde_json::Value {
    let text = |v: &serde_json::Value| Signed::from(v.as_str().unwrap());
    let relays = Signed::Array(body["relays"].as_array().unwrap().iter().map(text).collect());
    let ttl = Signed::Int(body["ttl"].as_u64().unwrap());
    let pre =
        vec![Signed::from("ac/pair-open/1"), text(&body["inviter"]), text(&body["invitation"]), relays, ttl];
    body["sig"] = json!(hex::encode(&key(by).sign_preimage(&Signed::Array(pre)).unwrap()));
    body
}

#[test]
fn an_open_body_is_checked_member_by_member_and_signed_by_its_invitation() {
    let (a, i) = (addr(1).to_string(), addr(2).to_string());
    let good = signed(
        json!({"inviter": a, "invitation": i, "relays": ["https://r.test", "https://s.test"], "ttl": 120}),
        2,
    );
    let parse = |v: &serde_json::Value| parse_open(v.to_string().as_bytes());
    let got = parse(&good).unwrap();
    let relays = vec!["https://r.test".to_owned(), "https://s.test".to_owned()];
    assert_eq!((got.inviter, got.invitation, got.relays, got.ttl), (a.clone(), i.clone(), relays, 120));
    let with = |key: &str, value: serde_json::Value| {
        let mut v = good.clone();
        v[key] = value;
        v
    };
    let without = |key: &str| {
        let mut v = good.clone();
        v.as_object_mut().unwrap().remove(key);
        v
    };
    for bad in [
        with("ttl", json!(0)),
        with("ttl", json!(601)),
        with("ttl", json!(-1)),
        with("ttl", json!("60")),
        without("ttl"),
        without("sig"),
        with("sig", json!(7)),
        with("inviter", json!("not-an-address")),
        with("invitation", json!(7)),
        with("relays", json!([])),
        with("relays", json!(["ftp://r.test"])),
        with("relays", json!(["https://r.test", "https://r.test"])),
        with("words", json!("tulip orbit cedar")),
        json!({"inviter": a, "relays": ["https://r.test"]}),
        json!([1, 2]),
    ] {
        assert_eq!(code(parse(&bad)), (400, "bad-shape"), "{bad}");
    }
    assert_eq!(code(parse(&with("sig", json!("zz".repeat(64))))), (400, "bad-hex"));
    assert_eq!(code(parse(&with("sig", json!("ab".repeat(63))))), (400, "bad-hex"));
    // Signed by another key, or the signed bytes changed after signing: 422 bad-sig, nothing allocated.
    let other = signed(json!({"inviter": a, "invitation": i, "relays": ["https://r.test"], "ttl": 120}), 3);
    for bad in [
        other,
        with("ttl", json!(60)),
        with("inviter", json!(addr(4).to_string())),
        with("relays", json!(["https://s.test", "https://r.test"])),
        with("sig", json!("00".repeat(64))),
    ] {
        assert_eq!(code(parse(&bad)), (422, "bad-sig"), "{bad}");
    }
    assert_eq!(code(parse_open(b"{")), (400, "bad-json"));
    let long = with("relays", json!([format!("https://{}.test", "r".repeat(MAX_BLOB + 256))]));
    assert_eq!(code(parse(&long)), (413, "body-too-large"));
    // Over MAX_RELAYS (64 since 'relays N') cannot fit the body: 65 relays meet the byte cap first.
    let over: Vec<String> = (0..65).map(|k| format!("http://r{k}")).collect();
    assert_eq!(code(parse(&with("relays", json!(over)))), (413, "body-too-large"));
    // A blob near the cap with its signature fits: eight relays of 50 characters.
    let eight: Vec<String> = (0..8).map(|k| format!("https://relay-{k}.{}.test", "r".repeat(30))).collect();
    let full = signed(json!({"inviter": a, "invitation": i, "relays": eight, "ttl": 600}), 2);
    assert!(parse(&full).is_ok(), "{} bytes", full.to_string().len());
    assert_eq!(Code::StaleRecord.as_str(), "stale-record");
}

#[test]
fn a_nameplate_is_three_to_nine_digits_with_no_leading_zero() {
    for (text, n) in
        [("100", Some(100)), ("999", Some(999)), ("1000", Some(1_000)), ("123456789", Some(123_456_789))]
    {
        assert_eq!(parse_nameplate(text), n, "{text}");
    }
    for text in ["", "99", "0472", "047", "1234567890", "472-tulip", " 472", "+472", "４７２"] {
        assert_eq!(parse_nameplate(text), None, "{text}");
    }
}

#[test]
fn at_most_max_open_client_addresses_hold_a_claim_bucket_until_the_sweep() {
    let pairs = Pairs::default();
    for i in 0..MAX_OPEN {
        assert_eq!(pairs.claim(NOW, opener(i), None), Ok(None));
    }
    let fresh = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    assert_eq!(pairs.claim(NOW, fresh, None), Err(1));
    // A client address that has a bucket keeps using it.
    assert_eq!(pairs.claim(NOW, opener(7), None), Ok(None));
    pairs.sweep(NOW + 2);
    assert_eq!(pairs.claim(NOW + 2, fresh, None), Ok(None));
}
