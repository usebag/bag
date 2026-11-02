//! Time, records and the canonical form in the Rust core: R2 (the `ts` window at its bounds),
//! D3 (record times), D4 (the record caps), D1's record half (`bad-rotation`) and P1's Rust half (2,000 seeded
//! canonical values against an independent writer, 300 invalid ones, and `spec/adversarial/canonical-fuzz.json`
//! when it exists). Every record and envelope is valid before it is changed.

mod support;

use ac_core::canonical::{self, MAX_SAFE_INTEGER, Value};
use ac_core::envelope::{DEFAULT_SKEW, DEFAULT_TTL, Envelope, check_window};
use ac_core::records::{self, AcceptFromRecord, AddressRecord, KeyRecord, Record, Roots};
use ac_core::{Address, Code, hash, json};
use support::{NOW, Rng, STUDY_SEED, fixed_key};

#[test]
fn r2_the_ts_window_holds_at_its_bounds() {
    let window = DEFAULT_TTL + DEFAULT_SKEW;
    let cases = [
        (NOW - window - 1, Some(Code::StaleTs)),
        (NOW - window, None),
        (NOW + DEFAULT_SKEW, None),
        (NOW + DEFAULT_SKEW + 1, Some(Code::FutureTs)),
        (0, Some(Code::StaleTs)),
        (MAX_SAFE_INTEGER, Some(Code::FutureTs)),
    ];
    let to = vec![fixed_key(2).address()];
    let sealed = support::sealed(&mut Rng::new(STUDY_SEED + 0x52), &to);
    for (ts, want) in cases {
        let env = Envelope::sign(&fixed_key(1), to.clone(), vec![], ts, sealed.clone()).unwrap();
        let parsed = Envelope::parse(&env.to_bytes()).unwrap();
        assert_eq!(parsed.verify_outer(NOW, DEFAULT_TTL, DEFAULT_SKEW).err(), want, "ts {ts}");
        assert_eq!(check_window(ts, NOW, DEFAULT_TTL, DEFAULT_SKEW).err(), want, "ts {ts}");
        assert_eq!(support::verdict(&env.to_bytes()), want, "ts {ts}, the relay's in-core order");
    }
}

fn address_record(n: u8, ttl: u64, iat: u64) -> AddressRecord {
    AddressRecord {
        key: fixed_key(n).address(),
        sealing_key: Some("aa".repeat(32)),
        relays: vec!["https://relay.example".into()],
        rotation_key: None,
        revoked: vec![],
        ttl,
        iat,
        rotated_from: None,
        rotation_sig: None,
        sig: [0; 64],
    }
}

/// The record's bytes, signed by `key(n)` over its preimage whatever its form (so a cap case carries a real
/// signature and only its form can fail).
fn signed_bytes(mut record: Record, n: u8) -> Vec<u8> {
    let sig = fixed_key(n).sign_preimage(&record.preimage()).unwrap();
    match &mut record {
        Record::Address(r) => r.sig = sig,
        Record::AcceptFrom(r) => r.sig = sig,
        Record::Key(r) => r.sig = sig,
    }
    record.to_bytes()
}

/// The verdict of record bytes: the JSON reader, the form and caps, then §7.5 at `NOW`.
fn record_verdict(bytes: &[u8]) -> Option<Code> {
    Record::parse(bytes).and_then(|r| r.verify(NOW, DEFAULT_SKEW)).err()
}

#[test]
fn d3_record_times_meet_their_codes() {
    let ttl = 3_600;
    let cases = [
        (NOW - ttl + 1, None),
        (NOW - ttl, None),
        (NOW - ttl - 1, Some(Code::RecordExpired)),
        (NOW + DEFAULT_SKEW, None),
        (NOW + DEFAULT_SKEW + 1, Some(Code::FutureIat)),
    ];
    for (iat, want) in cases {
        let bytes = signed_bytes(Record::Address(address_record(5, ttl, iat)), 5);
        assert_eq!(record_verdict(&bytes), want, "address record at iat {iat}");
    }
    for (exp, want) in [(NOW, None), (NOW - 1, Some(Code::RecordExpired))] {
        let key = KeyRecord {
            key: fixed_key(5).address(),
            sealing_key: "bb".repeat(32),
            iat: NOW - 10,
            exp,
            sig: [0; 64],
        };
        assert_eq!(record_verdict(&signed_bytes(Record::Key(key), 5)), want, "key record to {exp}");
    }
    // An older record after a newer one is the relay's 409 (crates/ac-relay/tests/abuse_policy.rs, D3) and the
    // edge's pin; the core judges each record alone.
}

#[test]
fn d4_the_record_caps_meet_their_codes() {
    let base = address_record(6, 3_600, NOW);
    assert_eq!(record_verdict(&signed_bytes(Record::Address(base.clone()), 6)), None, "positive control");
    // One over the cap of 64 (raised from 8 on 2026-10-30, 'relays N').
    let relays: Vec<String> = (1..=65).map(|p| format!("http://127.0.0.1:{p}")).collect();
    let revoked: Vec<Address> = (0..1_025u32)
        .map(|i| {
            let mut k = [7u8; 32];
            k[..4].copy_from_slice(&i.to_le_bytes());
            Address::from_key(k)
        })
        .collect();
    let address_cases = [
        (AddressRecord { ttl: 0, ..base.clone() }, Code::BadRecord),
        (AddressRecord { ttl: 86_401, ..base.clone() }, Code::BadRecord),
        (AddressRecord { relays, ..base.clone() }, Code::TooManyRelays),
        (AddressRecord { revoked, ..base.clone() }, Code::TooManyRevoked),
    ];
    for (record, want) in address_cases {
        assert_eq!(record_verdict(&signed_bytes(Record::Address(record), 6)), Some(want));
    }
    let accept = |max_bytes, ttl| {
        Record::AcceptFrom(AcceptFromRecord {
            owner: fixed_key(6).address(),
            roots: Roots::Any,
            max_bytes,
            ttl,
            iat: NOW,
            sig: [0; 64],
        })
    };
    assert_eq!(record_verdict(&signed_bytes(accept(65_536, 3_600), 6)), None, "positive control");
    assert_eq!(record_verdict(&signed_bytes(accept(65_536, MAX_SAFE_INTEGER), 6)), None, "ttl 2^53 - 1");
    assert_eq!(record_verdict(&signed_bytes(accept(0, 3_600), 6)), Some(Code::BadRecord), "max_bytes 0");
    let key = |exp| {
        Record::Key(KeyRecord {
            key: fixed_key(6).address(),
            sealing_key: "cc".repeat(32),
            iat: NOW,
            exp,
            sig: [0; 64],
        })
    };
    assert_eq!(record_verdict(&signed_bytes(key(NOW + 1), 6)), None, "positive control");
    assert_eq!(record_verdict(&signed_bytes(key(NOW - 1), 6)), Some(Code::BadRecord), "exp < iat");
}

#[test]
fn d1_a_rotation_without_a_valid_countersignature_is_bad_rotation() {
    let prev =
        AddressRecord { rotation_key: Some(fixed_key(8).address()), ..address_record(5, 3_600, NOW - 10) };
    let next = |by: Option<u8>| {
        let mut r =
            AddressRecord { rotated_from: Some(fixed_key(5).address()), ..address_record(6, 3_600, NOW) };
        if let Some(by) = by {
            r.countersign(&fixed_key(by)).unwrap();
        }
        r
    };
    let own = |r: &AddressRecord, n| record_verdict(&signed_bytes(Record::Address(r.clone()), n));
    assert_eq!(own(&prev, 5), None);
    for (by, want) in [
        (Some(5), None),
        (Some(8), None),
        (None, Some(Code::BadRotation)),
        (Some(7), Some(Code::BadRotation)),
    ] {
        let next = next(by);
        assert_eq!(own(&next, 6), None, "the rotation verifies on its own (by {by:?})");
        assert_eq!(records::verify_rotation(&prev, &next).err(), want, "countersigned by {by:?}");
    }
    // Countersigned by the right key but naming another previous key.
    let mut elsewhere =
        AddressRecord { rotated_from: Some(fixed_key(9).address()), ..address_record(6, 3_600, NOW) };
    elsewhere.countersign(&fixed_key(5)).unwrap();
    assert_eq!(records::verify_rotation(&prev, &elsewhere).err(), Some(Code::BadRotation));
}

/// Characters of every class of §2.2: printable ASCII, the short escapes, the other controls, U+007F, U+2028,
/// U+2029, `/`, non-ASCII, astral characters (surrogate pairs in UTF-16).
const CHARS: [char; 20] = [
    'a',
    'Z',
    '0',
    ' ',
    '"',
    '\\',
    '/',
    '\u{8}',
    '\t',
    '\n',
    '\u{c}',
    '\r',
    '\u{0}',
    '\u{1f}',
    '\u{7f}',
    '\u{2028}',
    '\u{2029}',
    '\u{e9}',
    '\u{4e2d}',
    '\u{1f600}',
];

fn fuzz_string(rng: &mut Rng) -> String {
    (0..rng.below(13)).map(|_| CHARS[rng.below(CHARS.len())]).collect()
}

fn fuzz_value(rng: &mut Rng, depth: usize) -> serde_json::Value {
    let choice = rng.below(if depth >= 8 { 3 } else { 4 });
    match choice {
        0 => fuzz_string(rng).into(),
        1 => [0, 1, MAX_SAFE_INTEGER, MAX_SAFE_INTEGER - 1, rng.next_u64() >> 11][rng.below(5)].into(),
        2 => serde_json::Value::Null,
        _ => (0..rng.below(4)).map(|_| fuzz_value(rng, depth + 1)).collect(),
    }
}

/// A list nested to depth 8, a string at the bottom.
fn nested_8(rng: &mut Rng) -> serde_json::Value {
    (0..8).fold(serde_json::Value::from(fuzz_string(rng)), |v, _| serde_json::Value::Array(vec![v]))
}

/// The 2,000 valid values: 1,800 drawn, and 200 preimages of hops, records and envelope ids.
fn valid_values() -> Vec<serde_json::Value> {
    let mut rng = Rng::new(STUDY_SEED + 0xC1);
    let mut values: Vec<serde_json::Value> =
        (0..1_800).map(|i| if i % 50 == 0 { nested_8(&mut rng) } else { fuzz_value(&mut rng, 0) }).collect();
    while values.len() < 2_000 {
        let f = support::envelope(&mut rng);
        let mut pre = vec![f.env.id_preimage(), f.env.sealed.preimage()];
        pre.extend(f.env.auth.iter().map(ac_core::chain::Hop::preimage));
        for p in pre.into_iter().take(2_000 - values.len()) {
            values.push(support::wire(&canonical::to_string(&p).unwrap()));
        }
    }
    values
}

/// The 300 invalid values of P1, as JSON text: fractions, negatives, 2^53 and over, booleans, objects, and each
/// of them inside a list.
fn invalid_texts() -> Vec<String> {
    let mut rng = Rng::new(STUDY_SEED + 0xC2);
    (0..300)
        .map(|i| {
            let n = rng.below(1_000);
            let bad = match i % 6 {
                0 => format!("{n}.5"),
                1 => format!("-{}", n + 1),
                2 => format!("{}", (1u64 << 53) + u64::try_from(n).unwrap()),
                3 => {
                    if n.is_multiple_of(2) {
                        "true".into()
                    } else {
                        "false".into()
                    }
                }
                4 => format!("{{\"a\":{n}}}"),
                _ => "1e0".into(),
            };
            if i % 2 == 0 { bad } else { format!("[\"x\",[{n},{bad}]]") }
        })
        .collect()
}

#[test]
fn p1_canonical_form_matches_an_independent_writer_and_refuses_invalid_values() {
    let values = valid_values();
    assert_eq!(values.len(), 2_000);
    for value in &values {
        let text = canonical::to_string(&canonical::from_json(value).unwrap()).unwrap();
        // serde_json's writer escapes exactly the §2.2 set too: an independent second writer.
        assert_eq!(text, serde_json::to_string(value).unwrap());
        let again = canonical::from_json(&json::parse(text.as_bytes()).unwrap()).unwrap();
        assert_eq!(canonical::to_string(&again).unwrap(), text, "a fixed point");
        assert_eq!(hash::sha256_hex(text.as_bytes()).len(), 64);
    }
    // The 2^53 boundary.
    assert_eq!(canonical::to_string(&Value::Int(MAX_SAFE_INTEGER)).unwrap(), "9007199254740991");
    assert_eq!(canonical::to_string(&Value::Int(MAX_SAFE_INTEGER + 1)).err(), Some(Code::BadCanonical));
    let invalid = invalid_texts();
    for text in &invalid {
        let value = json::parse(text.as_bytes()).unwrap();
        assert_eq!(canonical::from_json(&value).err(), Some(Code::BadCanonical), "{text}");
    }
    // Lone surrogates: JSON text that escapes one is bad-json, and no Rust string can hold one.
    for text in ["\"\\ud800\"", "\"\\udc00x\"", "[\"\\ud83d\"]"] {
        assert_eq!(json::parse(text.as_bytes()).err(), Some(Code::BadJson), "{text}");
    }
    assert!(String::from_utf16(&[0xd800]).is_err());
    eprintln!(
        "P1 (Rust): {} valid values written as serde_json writes them, {} invalid refused",
        values.len(),
        invalid.len()
    );
}

#[test]
fn p1_the_typescript_canonical_cases_are_written_byte_for_byte() {
    let path = support::repo("spec/adversarial/canonical-fuzz.json");
    let Ok(raw) = std::fs::read(&path) else {
        eprintln!("P1: {} is not there yet; nothing to compare", path.display());
        return;
    };
    let file: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    let cases = file["cases"].as_array().unwrap();
    let (mut valid, mut refused) = (0, 0);
    for case in cases.iter().filter(|c| c["kind"] == "canonical") {
        let got = support::canonical_verdict(&case["input"]);
        assert_eq!(got, case["expected"].as_str().unwrap(), "{}", case["name"]);
        if got == "ok" { valid += 1 } else { refused += 1 }
    }
    eprintln!(
        "P1: canonical-fuzz.json: {valid} valid written byte for byte, {refused} refused bad-canonical"
    );
}
