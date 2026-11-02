//! Discovery by DNS: the text form, the TXT fields, the outcome of a lookup and a record's agreement with its TXT
//! (spec/SPEC.md §12.2). The shared vectors (`spec/vectors/discovery.json`) are read by
//! `tests/conformance.rs`; these pin the edges each rule has.

use super::{
    Discovery, MAX_TXT_BYTES, RecordUrl, Refusal, Txt, WELL_KNOWN_RECORD_PATH, discover, parse_presentation,
    parse_txt, txt_name,
};
use crate::address::Address;
use crate::error::Code;
use crate::keys::SigningKey;
use crate::records::{AddressRecord, Domain, Record};

const KEY: &str = "ed25519:8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
const OTHER: &str = "ed25519:8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394";

fn acme() -> Domain {
    Domain::parse("acme.example").unwrap()
}

fn txt(text: &str) -> Result<Option<Txt>, &'static str> {
    parse_txt(text.as_bytes(), &acme())
}

fn records(texts: &[&[&str]]) -> Vec<Vec<Vec<u8>>> {
    texts.iter().map(|r| r.iter().map(|s| s.as_bytes().to_vec()).collect()).collect()
}

fn host(last: usize) -> Domain {
    Domain::parse(&format!("{0}.{0}.{0}.{1}", "a".repeat(63), "b".repeat(last))).unwrap()
}

#[test]
fn the_name_is_under_the_prefix_and_none_past_253_characters_or_under_a_special_use_name() {
    assert_eq!(txt_name(&acme()).as_deref(), Some("_bag.acme.example"));
    assert_eq!(host(56).as_str().len(), 248);
    assert_eq!(txt_name(&host(56)).map(|n| n.len()), Some(253));
    assert_eq!(txt_name(&host(57)), None);
    for special in ["acme.local", "acme.onion", "printer.internal"] {
        assert_eq!(txt_name(&Domain::parse(special).unwrap()), None, "{special}");
    }
    let inner = Domain::parse("acme.local.example").unwrap();
    assert_eq!(txt_name(&inner).as_deref(), Some("_bag.acme.local.example"));
}

#[test]
fn a_well_formed_record_gives_its_key_and_its_host() {
    let t = txt(&format!("v=ac1; key={KEY}; host=bag")).unwrap().unwrap();
    assert_eq!(t.key.as_str(), KEY);
    assert_eq!(t.host.as_ref().map(Domain::as_str), Some("bag.acme.example"));
    let bare = txt(&format!(" v = ac1 ;\tkey= {KEY} ;; ")).unwrap().unwrap();
    assert_eq!((bare.key.as_str(), bare.host), (KEY, None));
    // A domain whose bag host would pass 253 characters has no TXT name either, so no lookup reaches this.
    let long = parse_txt(format!("v=ac1; key={KEY}; host=bag").as_bytes(), &host(58));
    assert!(long.is_err());
    assert!(parse_txt(format!("v=ac1; key={KEY}; host=bag").as_bytes(), &host(57)).unwrap().is_some());
}

#[test]
fn records_that_are_not_ours_are_none() {
    for text in [
        "",
        ";;",
        "v=spf1 -all",
        "v=ac2; key=x",
        "V=ac1",
        &format!("key={KEY}; v=ac1"),
        "v=ac1x",
        "v",
        "=ac1",
    ] {
        assert_eq!(txt(text), Ok(None), "{text:?}");
    }
}

#[test]
fn every_malformed_bag_record_is_refused() {
    let k = format!("key={KEY}");
    let cases = [
        format!("v=ac1; {k}; {k}"),
        format!("v=ac1; {k}; x=1; x=2"),
        "v=ac1".to_owned(),
        "v=ac1; key=ed25519:ABC".to_owned(),
        "v=ac1; host=bag".to_owned(),
        format!("v=ac1; {k}; rec=https://agents.acme.example/org.json"),
        format!("v=ac1; {k}; rec=https://acme.example{WELL_KNOWN_RECORD_PATH}"),
        format!("v=ac1; {k}; rec=x"),
        format!("v=ac1; {k}; host=agents"),
        format!("v=ac1; {k}; host=Bag"),
        format!("v=ac1; {k}; host=bag.acme.example"),
        format!("v=ac1; {k}; host=bag; host=bag"),
        format!("v=ac1; {k}; nothing"),
        format!("v=ac1; {k}; note=a b"),
        format!("v=ac1; {k}; note="),
        format!("v=ac1; {k}; 1x=2"),
        format!("v=ac1; {k}; n\u{e9}=1"),
        format!("v=ac1; {k}; x={}", "y".repeat(MAX_TXT_BYTES)),
        format!("v=ac1; {k}; {}=1", "n".repeat(33)),
    ];
    for text in &cases {
        assert!(txt(text).is_err(), "{text:?}");
    }
    let exact = format!("v=ac1; {k}; x=");
    let pad = "y".repeat(MAX_TXT_BYTES - exact.len());
    assert!(txt(&format!("{exact}{pad}")).unwrap().is_some(), "exactly 1,024 bytes");
    assert!(txt(&format!("{exact}{pad}y")).is_err(), "1,025 bytes");
}

#[test]
fn unknown_fields_are_ignored() {
    let t = txt(&format!("v=ac1; key={KEY}; note=hello; X-Future_1=a=b; host=bag")).unwrap().unwrap();
    assert_eq!(t.host.as_ref().map(Domain::as_str), Some("bag.acme.example"));
}

#[test]
fn the_text_form_reads_quoted_and_bare_strings_with_escapes() {
    let ok = |text: &str| parse_presentation(text).unwrap();
    assert_eq!(ok(r#""v=ac1; key=x""#), vec![b"v=ac1; key=x".to_vec()]);
    assert_eq!(ok("\t\"a\"  \"b\" c "), vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
    assert_eq!(ok(r#""a\"b\\c" d\;e"#), vec![br#"a"b\c"#.to_vec(), b"d;e".to_vec()]);
    assert_eq!(ok(r#""a\059b" "\233""#), vec![b"a;b".to_vec(), vec![233]]);
    assert_eq!(ok(r#""""#), vec![Vec::<u8>::new()]);
    assert_eq!(ok(&"x".repeat(255)), vec![vec![b'x'; 255]]);
    // A parenthesis is legal inside a quoted string; §12.2 item 7 forbids it only in a bare word.
    assert_eq!(ok(r#""a(b)c""#), vec![b"a(b)c".to_vec()]);
    for bad in [
        "",
        "  ",
        r#""abc"#,
        r#""ab"cd"#,
        r#"ab"c"#,
        r#""a\256""#,
        r#""a\05x""#,
        r#""a\"#,
        "a\\",
        "é",
        "a\nb",
        "a(b",
        "a)b",
    ] {
        assert!(parse_presentation(bad).is_err(), "{bad:?}");
    }
    assert!(parse_presentation(&"x".repeat(256)).is_err());
    assert!(parse_presentation(&format!("\"{}\"", "\\120".repeat(256))).is_err());
}

#[test]
fn a_lookup_gives_the_origin_at_the_domain_or_at_bag_or_a_refusal() {
    let d = acme();
    let none = discover(&[], &d).unwrap();
    assert_eq!(none, Discovery::well_known(&d));
    assert_eq!(none.url.to_string(), format!("https://acme.example{WELL_KNOWN_RECORD_PATH}"));
    let other = discover(&records(&[&["v=spf1 -all"], &["google-site-verification=x"]]), &d).unwrap();
    assert_eq!(other.key, None);
    let one = discover(&records(&[&["v=spf1 -all"], &["v=ac1; key=", KEY, "; host=bag"]]), &d).unwrap();
    assert_eq!(one.key.as_ref().map(Address::as_str), Some(KEY));
    assert_eq!(one.url.to_string(), format!("https://bag.acme.example{WELL_KNOWN_RECORD_PATH}"));
    assert_eq!(
        (one.url.host().as_str(), one.url.path(), one.url.origin().as_str()),
        ("bag.acme.example", WELL_KNOWN_RECORD_PATH, "https://bag.acme.example")
    );
    let key_only = discover(&records(&[&[&format!("v=ac1;key={KEY}")]]), &d).unwrap();
    assert_eq!(key_only.url, RecordUrl::well_known(&d));
    let two = records(&[&[&format!("v=ac1; key={KEY}")], &[&format!("v=ac1; key={OTHER}")]]);
    assert_eq!(discover(&two, &d), Err(Refusal::Ambiguous(2)));
    let bad = records(&[&[&format!("v=ac1; key={KEY}; key={KEY}")]]);
    assert!(matches!(discover(&bad, &d), Err(Refusal::Malformed(_))));
    assert_eq!(Refusal::Ambiguous(2).code(), Code::ResolveFailed);
    assert_eq!(Refusal::Malformed("x").code(), Code::ResolveFailed);
    let rec = records(&[&[&format!("v=ac1; key={KEY}; rec=https://acme.example/o")]]);
    assert!(matches!(discover(&rec, &d), Err(Refusal::Malformed(_))));
}

#[test]
fn a_domain_that_is_not_asked_reads_no_record() {
    let handed = records(&[&[&format!("v=ac1; key={KEY}; host=bag")]]);
    for d in [Domain::parse("acme.local").unwrap(), host(57)] {
        assert_eq!(discover(&handed, &d), Ok(Discovery::well_known(&d)), "{d}");
    }
}

/// A test key from a fixed seed (test data by construction, never a real key).
fn key(n: u8) -> SigningKey {
    SigningKey::from_seed(&[n; 32])
}

/// The address record of `key(n)`, rotated from `key(from)` and countersigned by `key(by)` when given.
fn record(n: u8, from: Option<u8>, by: Option<u8>) -> AddressRecord {
    let mut a = AddressRecord {
        key: key(n).address(),
        sealing_key: None,
        relays: vec![],
        rotation_key: None,
        revoked: vec![],
        ttl: 60,
        iat: 0,
        rotated_from: from.map(|f| key(f).address()),
        rotation_sig: None,
        sig: [0; 64],
    };
    if let Some(by) = by {
        a.countersign(&key(by)).unwrap();
    }
    let mut r = Record::Address(a);
    r.sign(&key(n)).unwrap();
    let Record::Address(a) = r else { unreachable!() };
    a
}

#[test]
fn a_record_agrees_with_its_txt_by_its_key_or_one_rotation_the_txt_key_countersigned() {
    let d = acme();
    let named = Discovery { key: Some(key(10).address()), url: RecordUrl::well_known(&d) };
    assert_eq!(named.check(&record(10, None, None)), Ok(()));
    assert_eq!(Discovery::well_known(&d).check(&record(11, None, None)), Ok(()), "no TXT: any key");
    assert_eq!(named.check(&record(11, Some(10), Some(10))), Ok(()), "k11 countersigned by the TXT's k10");
    for (from, by, what) in [
        (None, None, "a bare k11"),
        (Some(10), None, "k11 naming k10 with no rotation_sig"),
        (Some(10), Some(12), "k11 naming k10, countersigned by another key"),
        (Some(12), Some(12), "k11 rotated from another key"),
    ] {
        assert_eq!(named.check(&record(11, from, by)), Err(Code::ResolveFailed), "{what}");
    }
    assert_eq!(named.check(&record(12, Some(11), Some(11))), Err(Code::ResolveFailed), "two steps from k10");
}
