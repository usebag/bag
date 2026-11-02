//! Handles and handle records (spec/SPEC.md §12.3 and §12.4): the form, the preimage, signing and the order of the checks. The
//! shared vectors (`spec/vectors/discovery.json`) are read by `tests/conformance.rs`.

use super::{HANDLE_TAG, Handle, HandleRecord};
use crate::canonical;
use crate::error::Code;
use crate::records::Record;
use crate::testkit::{addr, key};

const T0: u64 = 1_800_000_000;

fn handle(text: &str) -> Handle {
    Handle::parse(text).unwrap()
}

fn signed(org: u8, h: &str, address: u8, iat: u64, ttl: u64) -> HandleRecord {
    let mut r =
        HandleRecord { org: addr(org), handle: handle(h), address: addr(address), iat, ttl, sig: [0; 64] };
    r.sign(&key(org)).unwrap();
    r
}

#[test]
fn handles_parse_by_the_form_and_nothing_else() {
    let h = handle("j.doe-2_x@acme.example");
    assert_eq!((h.local(), h.domain().as_str()), ("j.doe-2_x", "acme.example"));
    assert_eq!(h.to_string(), "j.doe-2_x@acme.example");
    assert_eq!(format!("{h:?}"), "Handle(j.doe-2_x@acme.example)");
    assert_eq!(h.path(), "/.well-known/bag/handles/j.doe-2_x.json");
    assert!(Handle::parse(&format!("{}@acme.example", "a".repeat(64))).is_ok());
    for bad in [
        &format!("{}@acme.example", "a".repeat(65)),
        "Jane@acme.example",
        "jane@ACME.example",
        "jane@acme",
        "jane@192.0.2.1",
        "@acme.example",
        "jane@",
        "jane@@acme.example",
        "ja ne@acme.example",
        "jane@acme.example.",
        ".jane@acme.example",
        "jane.@acme.example",
        "-jane@acme.example",
        "jane+tag@acme.example",
        "jan\u{e9}@acme.example",
        "jane",
        "ed25519:8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
        "jane@acme.example:443",
        "jane@[2001:db8::1]",
        "jane@acme.0x1f",
    ] {
        assert_eq!(Handle::parse(bad), Err(Code::BadAddress), "{bad:?}");
    }
    for tld in super::SPECIAL_USE_TLDS {
        assert_eq!(Handle::parse(&format!("jane@acme.{tld}")), Err(Code::BadAddress), "{tld}");
    }
    assert!(Handle::parse("jane@acme.local.example").is_ok() && Handle::parse("jane@acme.e2e.test").is_ok());
}

#[test]
fn a_record_round_trips_and_signs_its_preimage() {
    let r = signed(1, "jane@acme.example", 2, T0, 86_400);
    let text = r.to_json_text();
    assert!(text.starts_with(r#"{"kind":"handle","org":"ed25519:"#), "{text}");
    assert_eq!(HandleRecord::parse(text.as_bytes()), Ok(r.clone()));
    let pre = canonical::to_string(&r.preimage()).unwrap();
    assert!(pre.starts_with(&format!(
        r#"["{HANDLE_TAG}","{}","jane@acme.example","{}",{T0},86400]"#,
        addr(1),
        addr(2)
    )));
    assert_eq!(r.digest_hex().unwrap().len(), 64);
    let mut by_other = r.clone();
    assert_eq!(by_other.sign(&key(7)), Err(Code::BadKey));
    by_other.ttl = 0;
    assert_eq!(by_other.sign(&key(1)), Err(Code::BadRecord));
}

#[test]
fn the_checks_run_in_their_order() {
    let h = handle("jane@acme.example");
    let r = signed(1, "jane@acme.example", 2, T0, 3_600);
    let check = |r: &HandleRecord, org: u8, h: &Handle, revoked: &[u8], now: u64| {
        let revoked: Vec<_> = revoked.iter().map(|n| addr(*n)).collect();
        r.verify(&addr(org), h, &revoked, now, 300)
    };
    assert_eq!(check(&r, 1, &h, &[], T0), Ok(()));
    assert_eq!(check(&r, 1, &h, &[], T0 + 3_600), Ok(()));
    assert_eq!(check(&r, 1, &h, &[], T0 + 3_601), Err(Code::RecordExpired));
    assert_eq!(check(&r, 1, &h, &[], T0 - 300), Ok(()));
    assert_eq!(check(&r, 1, &h, &[], T0 - 301), Err(Code::FutureIat));
    assert_eq!(check(&r, 9, &h, &[], T0), Err(Code::ResolveFailed));
    assert_eq!(check(&r, 1, &handle("bob@acme.example"), &[], T0), Err(Code::ResolveFailed));
    assert_eq!(check(&r, 1, &handle("jane@globex.example"), &[], T0), Err(Code::ResolveFailed));
    assert_eq!(check(&r, 1, &h, &[2], T0), Err(Code::Revoked));
    let mut forged = r.clone();
    forged.address = addr(7);
    assert_eq!(check(&forged, 1, &h, &[], T0), Err(Code::BadRecordSig));
    forged.ttl = 86_401;
    assert_eq!(check(&forged, 1, &h, &[], T0), Err(Code::BadRecord));
    let by_mallory = signed(7, "jane@acme.example", 2, T0, 3_600);
    assert_eq!(check(&by_mallory, 1, &h, &[], T0), Err(Code::ResolveFailed), "valid alone, another key");
}

#[test]
fn every_form_breach_is_bad_record_and_the_relay_kinds_refuse_it() {
    let base: serde_json::Value =
        serde_json::from_str(&signed(1, "jane@acme.example", 2, T0, 60).to_json_text()).unwrap();
    let with = |name: &str, value: serde_json::Value| {
        let mut v = base.clone();
        v[name] = value;
        HandleRecord::from_json(&v)
    };
    assert!(with("ttl", 60.into()).is_ok());
    for (name, value) in [
        ("kind", "address".into()),
        ("org", "jane".into()),
        ("handle", "Jane@acme.example".into()),
        ("handle", 1.into()),
        ("address", "ed25519:00".into()),
        ("iat", (-1).into()),
        ("ttl", 0.into()),
        ("ttl", 86_401.into()),
        ("sig", "00".into()),
        ("extra", true.into()),
    ] {
        assert_eq!(with(name, value), Err(Code::BadRecord), "{name}");
    }
    let mut missing = base.clone();
    missing.as_object_mut().unwrap().remove("sig");
    assert_eq!(HandleRecord::from_json(&missing), Err(Code::BadRecord));
    assert_eq!(HandleRecord::from_json(&serde_json::json!([1])), Err(Code::BadRecord));
    assert_eq!(HandleRecord::parse(b"{"), Err(Code::BadJson));
    // A relay's Record::parse knows three kinds: a handle record is one it does not store.
    assert_eq!(Record::parse(base.to_string().as_bytes()), Err(Code::BadRecord));
}
