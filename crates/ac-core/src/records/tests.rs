use super::{
    AcceptFromRecord, AddressRecord, DOMAIN_ROOT_PREFIX, Domain, KeyRecord, Kind, MAX_ADDRESS_TTL,
    MAX_DOMAIN_LEN, MAX_KEY_LIFETIME, MAX_RELAYS, MAX_REVOKED, MAX_ROOTS, Record, Root, Roots, is_relay_url,
    verify_rotation, verify_rotation_claim,
};
use crate::canonical::{self, MAX_SAFE_INTEGER};
use crate::error::Code;
use crate::testkit::{NOW, addr, key};
use serde_json::json;

const SKEW: u64 = 300;

fn address_record(n: u8, iat: u64) -> AddressRecord {
    let mut r = Record::Address(AddressRecord {
        key: addr(n),
        sealing_key: Some("aa".repeat(32)),
        relays: vec!["https://relay.example".into()],
        rotation_key: Some(addr(99)),
        revoked: vec![addr(50)],
        ttl: 3_600,
        iat,
        rotated_from: None,
        rotation_sig: None,
        sig: [0; 64],
    });
    r.sign(&key(n)).unwrap();
    let Record::Address(a) = r else { unreachable!() };
    a
}

fn signed(mut r: Record, n: u8) -> Record {
    r.sign(&key(n)).unwrap();
    r
}

fn accept(n: u8, roots: Roots) -> Record {
    signed(
        Record::AcceptFrom(AcceptFromRecord {
            owner: addr(n),
            roots,
            max_bytes: 65_536,
            ttl: 604_800,
            iat: NOW,
            sig: [0; 64],
        }),
        n,
    )
}

fn key_record(n: u8, iat: u64, exp: u64) -> Record {
    signed(Record::Key(KeyRecord { key: addr(n), sealing_key: "bb".repeat(32), iat, exp, sig: [0; 64] }), n)
}

fn wire(r: &Record) -> serde_json::Value {
    serde_json::from_str(&r.to_json_text()).unwrap()
}

fn with(r: &Record, field: &str, value: serde_json::Value) -> crate::error::Result<Record> {
    let mut j = wire(r);
    j[field] = value;
    Record::from_json(&j)
}

#[test]
fn kinds_have_wire_names() {
    for k in Kind::ALL {
        assert_eq!(Kind::from_wire(k.as_str()), Some(k));
    }
    assert_eq!(Kind::from_wire("envelope"), None);
    assert_eq!(
        (Kind::Address.as_str(), Kind::AcceptFrom.as_str(), Kind::Key.as_str()),
        ("address", "accept-from", "key")
    );
}

#[test]
fn preimages_follow_the_position_tables() {
    let a = Record::Address(address_record(1, NOW));
    assert_eq!(
        canonical::to_string(&a.preimage()).unwrap(),
        format!(
            r#"["ac/addr/1","{}","{}",["https://relay.example"],"{}",["{}"],3600,{NOW},null]"#,
            addr(1),
            "aa".repeat(32),
            addr(99),
            addr(50)
        )
    );
    let f = accept(2, Roots::Listed(vec![addr(7), addr(8)]));
    assert_eq!(
        canonical::to_string(&f.preimage()).unwrap(),
        format!(r#"["ac/accept/1","{}",["{}","{}"],65536,604800,{NOW}]"#, addr(2), addr(7), addr(8))
    );
    assert!(canonical::to_string(&accept(2, Roots::Any).preimage()).unwrap().contains(r#",["*"],"#));
    let k = key_record(3, NOW, NOW + 60);
    assert_eq!(
        canonical::to_string(&k.preimage()).unwrap(),
        format!(r#"["ac/key/1","{}","{}",{NOW},{}]"#, addr(3), "bb".repeat(32), NOW + 60)
    );
    assert_eq!(
        a.digest_hex().unwrap(),
        crate::hash::sha256_hex(canonical::to_string(&a.preimage()).unwrap().as_bytes())
    );
}

#[test]
fn every_kind_round_trips_byte_for_byte_and_verifies() {
    let mut nulls = address_record(1, NOW);
    nulls.sealing_key = None;
    nulls.rotation_key = None;
    let nulls = signed(Record::Address(nulls), 1);
    for r in
        [Record::Address(address_record(1, NOW)), nulls, accept(2, Roots::Any), key_record(3, NOW, NOW + 60)]
    {
        let back = Record::parse(&r.to_bytes()).unwrap();
        assert_eq!(back, r);
        assert_eq!(back.to_bytes(), r.to_bytes());
        back.verify(NOW, SKEW).unwrap();
        assert_eq!((back.signer(), back.iat(), back.kind()), (r.signer(), NOW, r.kind()));
    }
    assert!(
        String::from_utf8(accept(2, Roots::Any).to_bytes())
            .unwrap()
            .starts_with(r#"{"kind":"accept-from","owner":"#)
    );
}

#[test]
fn accept_from_roots() {
    let Record::AcceptFrom(f) = accept(2, Roots::Listed(vec![addr(7)])) else { unreachable!() };
    assert!(f.admits(&addr(7)) && !f.admits(&addr(8)));
    let Record::AcceptFrom(any) = accept(2, Roots::Any) else { unreachable!() };
    assert!(any.admits(&addr(8)));
    let r = accept(2, Roots::Any);
    assert_eq!(with(&r, "roots", json!([])), Err(Code::BadRecord));
    assert_eq!(with(&r, "roots", json!(["*", addr(7).to_string()])), Err(Code::BadRecord));
    assert_eq!(with(&r, "roots", json!(["*", "*"])), Err(Code::BadRecord));
    assert_eq!(with(&r, "roots", json!([addr(7).to_string(), addr(7).to_string()])), Err(Code::BadRecord));
    assert_eq!(with(&r, "roots", json!(["nobody"])), Err(Code::BadRecord));
    assert_eq!(with(&r, "roots", json!([7])), Err(Code::BadRecord));
    assert_eq!(with(&r, "max_bytes", json!(0)), Err(Code::BadRecord));
    assert_eq!(with(&r, "ttl", json!(0)), Err(Code::BadRecord));
    // A built record with an empty or repeated list breaks its form.
    let mut empty = Record::AcceptFrom(AcceptFromRecord {
        owner: addr(2),
        roots: Roots::Listed(vec![]),
        max_bytes: 1,
        ttl: 1,
        iat: NOW,
        sig: [0; 64],
    });
    assert_eq!(empty.sign(&key(2)), Err(Code::BadRecord));
}

#[test]
fn every_form_failure_is_bad_record() {
    assert_eq!(Record::parse(b"nope"), Err(Code::BadJson));
    for bad in [json!([1]), json!({"kind": 7}), json!({"kind": "envelope"}), json!({"v": 1}), json!(null)] {
        assert_eq!(Record::from_json(&bad), Err(Code::BadRecord), "{bad}");
    }
    let a = Record::Address(address_record(1, NOW));
    for (field, value) in [
        ("extra", json!(1)),
        ("key", json!("k")),
        ("sealing_key", json!("aa")),
        ("relays", json!("x")),
        ("relays", json!(["ftp://relay.example"])),
        ("relays", json!(["https://"])),
        ("relays", json!(["https:///path"])),
        ("relays", json!(["https://a b"])),
        ("relays", json!(["https://a\u{85}b"])),
        ("relays", json!(["https://a", "https://a"])),
        ("relays", json!([1])),
        ("rotation_key", json!("k")),
        ("revoked", json!({})),
        ("revoked", json!(["k"])),
        ("revoked", json!([addr(50).to_string(), addr(50).to_string()])),
        ("ttl", json!(0)),
        ("ttl", json!(MAX_ADDRESS_TTL + 1)),
        ("iat", json!(MAX_SAFE_INTEGER + 1)),
        ("iat", json!(-1)),
        ("rotated_from", json!("k")),
        ("rotation_sig", json!("00")),
        ("rotation_sig", json!("ab".repeat(64))),
        ("sig", json!("00")),
    ] {
        assert_eq!(with(&a, field, value.clone()), Err(Code::BadRecord), "{field}: {value}");
    }
    let mut missing = wire(&a);
    missing.as_object_mut().unwrap().remove("revoked");
    assert_eq!(Record::from_json(&missing), Err(Code::BadRecord));
    let k = key_record(3, NOW, NOW + 60);
    assert_eq!(with(&k, "sealing_key", json!("x")), Err(Code::BadRecord));
    assert_eq!(with(&k, "exp", json!(NOW - 1)), Err(Code::BadRecord));
    assert_eq!(with(&k, "key", json!(null)), Err(Code::BadRecord));
}

#[test]
fn relay_urls() {
    for good in
        ["http://h", "https://relay.example", "https://h:8080/v0?x=1#f", "https://h/a%20b", "https://h?"]
    {
        assert!(is_relay_url(good), "{good}");
    }
    for bad in [
        "",
        "http://",
        "https://",
        "https:///x",
        "https://?q",
        "https://#f",
        "https://a b",
        "HTTP://h",
        "https:/h",
        "https://h\u{7f}",
        "https://h\u{9f}",
        "wss://h",
    ] {
        assert!(!is_relay_url(bad), "{bad:?}");
    }
}

#[test]
fn the_caps_have_their_own_codes_and_are_inclusive() {
    let a = Record::Address(address_record(1, NOW));
    assert_eq!(
        with(&a, "relays", json!((0..=MAX_RELAYS).map(|i| format!("https://r{i}")).collect::<Vec<_>>())),
        Err(Code::TooManyRelays)
    );
    let revoked: Vec<String> = (0..=MAX_REVOKED).map(|_| addr(50).to_string()).collect();
    assert_eq!(with(&a, "revoked", json!(revoked)), Err(Code::TooManyRevoked));
    let mut full = address_record(1, NOW);
    full.relays = (0..MAX_RELAYS).map(|i| format!("https://r{i}")).collect();
    full.revoked = (0..u8::try_from(32).unwrap()).map(|i| addr(100 + i)).collect();
    full.ttl = MAX_ADDRESS_TTL;
    let full = signed(Record::Address(full), 1);
    Record::parse(&full.to_bytes()).unwrap().verify(NOW, SKEW).unwrap();
    // The caps and the form are checked again for a record built in code.
    let mut over = address_record(1, NOW);
    over.relays = (0..=MAX_RELAYS).map(|i| format!("https://r{i}")).collect();
    assert_eq!(Record::Address(over).verify(NOW, SKEW), Err(Code::TooManyRelays));
    let mut over = address_record(1, NOW);
    over.revoked = vec![addr(50); MAX_REVOKED + 1];
    assert_eq!(Record::Address(over).verify(NOW, SKEW), Err(Code::TooManyRevoked));
    let mut long = address_record(1, NOW);
    long.ttl = MAX_ADDRESS_TTL + 1;
    assert_eq!(Record::Address(long).verify(NOW, SKEW), Err(Code::BadRecord));
}

#[test]
fn signature_time_and_expiry_in_order() {
    let mut a = address_record(1, NOW);
    a.relays.push("https://other.example".into());
    assert_eq!(Record::Address(a).verify(NOW, SKEW), Err(Code::BadRecordSig));
    let a = Record::Address(address_record(1, NOW));
    assert!(a.verify(NOW - SKEW, SKEW).is_ok());
    assert_eq!(a.verify(NOW - SKEW - 1, SKEW), Err(Code::FutureIat));
    assert!(a.verify(NOW + 3_600, SKEW).is_ok());
    assert_eq!(a.verify(NOW + 3_601, SKEW), Err(Code::RecordExpired));
    let k = key_record(3, NOW, NOW + 60);
    assert!(k.verify(NOW + 60, SKEW).is_ok());
    assert_eq!(k.verify(NOW + 61, SKEW), Err(Code::RecordExpired));
    // An accept-from record's ttl is retention: it never expires.
    assert!(accept(2, Roots::Any).verify(NOW + 10 * 604_800, SKEW).is_ok());
}

#[test]
fn signing_needs_the_record_s_own_key_and_form() {
    let mut r = key_record(3, NOW, NOW + 60);
    assert_eq!(r.sign(&key(4)), Err(Code::BadKey));
    let mut big = key_record(3, NOW, NOW + 60);
    if let Record::Key(k) = &mut big {
        k.exp = u64::MAX;
    }
    assert_eq!(big.sign(&key(3)), Err(Code::BadRecord));
    assert_eq!(big.digest_hex(), Err(Code::BadCanonical));
    assert_eq!(big.verify(NOW, SKEW), Err(Code::BadRecord));
    let mut plain = address_record(1, NOW);
    assert_eq!(plain.countersign(&key(1)), Err(Code::BadRecord));
}

fn rotated(from: u8, to: u8, iat: u64, countersigner: Option<u8>) -> AddressRecord {
    let mut next = address_record(to, iat);
    next.rotated_from = Some(addr(from));
    if let Some(c) = countersigner {
        next.countersign(&key(c)).unwrap();
    }
    let mut r = Record::Address(next);
    r.sign(&key(to)).unwrap();
    let Record::Address(next) = r else { unreachable!() };
    next
}

#[test]
fn rotation_countersigned_by_the_previous_key_or_its_rotation_key() {
    let prev = address_record(1, NOW);
    let next = rotated(1, 2, NOW + 1, Some(1));
    verify_rotation(&prev, &next).unwrap();
    Record::Address(next).verify(NOW + 1, SKEW).unwrap();
    verify_rotation(&prev, &rotated(1, 2, NOW + 1, Some(99))).unwrap();
}

#[test]
fn every_other_rotation_is_bad_rotation() {
    let prev = address_record(1, NOW);
    assert_eq!(verify_rotation(&prev, &address_record(2, NOW + 1)), Err(Code::BadRotation));
    assert_eq!(verify_rotation(&prev, &rotated(3, 2, NOW + 1, Some(3))), Err(Code::BadRotation));
    assert_eq!(verify_rotation(&prev, &rotated(1, 2, NOW + 1, None)), Err(Code::BadRotation));
    assert_eq!(verify_rotation(&prev, &rotated(1, 2, NOW + 1, Some(2))), Err(Code::BadRotation));
    let mut bare_prev = address_record(1, NOW);
    bare_prev.rotation_key = None;
    assert_eq!(verify_rotation(&bare_prev, &rotated(1, 2, NOW + 1, Some(99))), Err(Code::BadRotation));
    let mut tampered = rotated(1, 2, NOW + 1, Some(1));
    tampered.relays.push("https://evil.example".into());
    assert_eq!(verify_rotation(&prev, &tampered), Err(Code::BadRotation));
    let mut huge = rotated(1, 2, NOW + 1, Some(1));
    huge.iat = u64::MAX;
    assert_eq!(verify_rotation(&prev, &huge), Err(Code::BadRotation));
}
/// The host grammar's cases, the same lists as packages/core/test/records.test.ts.
fn hosts() -> (Vec<String>, Vec<String>) {
    let a63 = "a".repeat(63);
    let a63 = a63.as_str();
    let valid = vec![
        "acme.example".to_owned(),
        "a.b".to_owned(),
        "relay-acme.usuals.now".to_owned(),
        "acme.e2e.test".to_owned(),
        "xn--bcher-kva.example".to_owned(),
        "1password.com".to_owned(),
        "a1.b2".to_owned(),
        "123.example".to_owned(),
        "0x7f.example".to_owned(),
        format!("{}.example", "a".repeat(63)),
        [a63, a63, a63, &"a".repeat(61)].join("."),
    ];
    let invalid = vec![
        "Acme.example".to_owned(),
        "ACME.EXAMPLE".to_owned(),
        "127.0.0.1".to_owned(),
        "10.0.0.1".to_owned(),
        "127.1".to_owned(),
        "0177.0.0.1".to_owned(),
        "0x7f.1".to_owned(),
        "1.0x7f".to_owned(),
        "example.0x".to_owned(),
        "acme.example.".to_owned(),
        "localhost".to_owned(),
        "example".to_owned(),
        String::new(),
        ".".to_owned(),
        ".example".to_owned(),
        "acme..example".to_owned(),
        "-acme.example".to_owned(),
        "acme-.example".to_owned(),
        format!("{}.example", "a".repeat(64)),
        [a63, a63, a63, &"a".repeat(62)].join("."),
        "acme.example:443".to_owned(),
        "acme_corp.example".to_owned(),
        "acme.example/x".to_owned(),
        "user@acme.example".to_owned(),
        "::1".to_owned(),
        "[::1]".to_owned(),
        "acme .example".to_owned(),
        "\u{e1}cme.example".to_owned(),
    ];
    (valid, invalid)
}

#[test]
fn domain_hosts_follow_the_grammar_of_the_typescript_core() {
    let (valid, invalid) = hosts();
    assert_eq!((valid.len(), invalid.len()), (11, 28));
    for host in &valid {
        assert_eq!(Domain::parse(host).map(|d| d.to_string()), Ok(host.clone()), "{host}");
        let root = format!("{DOMAIN_ROOT_PREFIX}{host}");
        assert_eq!(Root::parse(&root).map(|r| r.to_text()), Ok(root.clone()), "{host}");
    }
    for host in &invalid {
        assert_eq!(Domain::parse(host), Err(Code::BadRecord), "{host:?}");
        assert_eq!(Root::parse(&format!("domain:{host}")), Err(Code::BadRecord), "{host:?}");
    }
    assert_eq!(valid.iter().map(String::len).max(), Some(MAX_DOMAIN_LEN));
    assert_eq!(format!("{:?}", Domain::parse("acme.example").unwrap()), "Domain(acme.example)");
    assert_eq!(Domain::parse("acme.example").unwrap().as_str(), "acme.example");
}

#[test]
fn a_root_is_an_address_or_a_domain_never_a_bare_host_or_the_wildcard() {
    assert_eq!(Root::parse(addr(7).as_str()), Ok(Root::Address(addr(7))));
    assert_eq!(Root::parse(&Root::Address(addr(7)).to_text()), Ok(Root::Address(addr(7))));
    for text in ["*", "acme.example", "Domain:acme.example", "domain: acme.example", "domain:", "dns:a.b", ""]
    {
        assert_eq!(Root::parse(text), Err(Code::BadRecord), "{text:?}");
    }
}

#[test]
fn accept_from_roots_with_domains() {
    let roots = vec![
        Root::Domain(Domain::parse("acme.example").unwrap()),
        Root::Address(addr(7)),
        Root::Domain(Domain::parse("globex.example").unwrap()),
    ];
    let r = accept(2, Roots::WithDomains(roots.clone()));
    assert_eq!(
        canonical::to_string(&r.preimage()).unwrap(),
        format!(
            r#"["ac/accept/1","{}",["domain:acme.example","{}","domain:globex.example"],65536,604800,{NOW}]"#,
            addr(2),
            addr(7)
        )
    );
    let back = Record::parse(&r.to_bytes()).unwrap();
    assert_eq!(back, r);
    back.verify(NOW, SKEW).unwrap();
    let Record::AcceptFrom(f) = back else { unreachable!() };
    assert!(f.admits(&addr(7)) && !f.admits(&addr(8)));
    let names: Vec<&str> = f.domains().iter().map(|d| d.as_str()).collect();
    assert_eq!(names, ["acme.example", "globex.example"]);
    let Record::AcceptFrom(listed) = accept(2, Roots::Listed(vec![addr(7)])) else { unreachable!() };
    assert!(listed.domains().is_empty());
    let Record::AcceptFrom(any) = accept(2, Roots::Any) else { unreachable!() };
    assert!(any.domains().is_empty());
    // Addresses only read back as Listed, whatever list they came in.
    let only = with(&r, "roots", json!([addr(7).to_string()])).unwrap();
    let Record::AcceptFrom(only) = only else { unreachable!() };
    assert_eq!(only.roots, Roots::Listed(vec![addr(7)]));
    // The form: a domain listed twice, the wildcard beside a domain, a bad host, a bare host.
    for bad in [
        json!(["domain:acme.example", "domain:acme.example"]),
        json!(["*", "domain:acme.example"]),
        json!(["domain:ACME.example"]),
        json!(["domain:127.0.0.1"]),
        json!(["domain:acme.example."]),
        json!(["domain:localhost"]),
        json!(["acme.example"]),
    ] {
        assert_eq!(with(&r, "roots", bad.clone()), Err(Code::BadRecord), "{bad}");
    }
    // Built in code: WithDomains needs a domain and distinct entries.
    for roots in [vec![Root::Address(addr(7))], vec![roots[0].clone(), roots[0].clone()], vec![]] {
        let mut built = Record::AcceptFrom(AcceptFromRecord {
            owner: addr(2),
            roots: Roots::WithDomains(roots),
            max_bytes: 1,
            ttl: 1,
            iat: NOW,
            sig: [0; 64],
        });
        assert_eq!(built.sign(&key(2)), Err(Code::BadRecord));
    }
}

/// `n` distinct root addresses, each the hash of its index: the cap is 1,024 entries.
fn root_texts(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("ed25519:{}", crate::hash::sha256_hex(format!("root {i}").as_bytes()))).collect()
}

#[test]
fn accept_from_roots_hold_at_most_1024_entries() {
    // Changed 2026-10-25: the cap is MAX_ROOTS, refused as bad-record.
    assert_eq!(MAX_ROOTS, 1_024);
    let r = accept(2, Roots::Any);
    let full = with(&r, "roots", json!(root_texts(MAX_ROOTS))).unwrap();
    let full = signed(full, 2);
    Record::parse(&full.to_bytes()).unwrap().verify(NOW, SKEW).unwrap();
    assert_eq!(with(&r, "roots", json!(root_texts(MAX_ROOTS + 1))), Err(Code::BadRecord));
    let mut mixed = root_texts(MAX_ROOTS);
    mixed.push(format!("{DOMAIN_ROOT_PREFIX}acme.example"));
    assert_eq!(with(&r, "roots", json!(mixed)), Err(Code::BadRecord));
    assert!(with(&r, "roots", json!(mixed[1..])).is_ok());
    // A record built in code is held to the cap as well, with or without a domain among its roots.
    let over: Vec<Root> = root_texts(MAX_ROOTS + 1).iter().map(|t| Root::parse(t).unwrap()).collect();
    let addresses: Vec<_> = over
        .iter()
        .map(|r| match r {
            Root::Address(a) => a.clone(),
            Root::Domain(_) => unreachable!(),
        })
        .collect();
    let mut domains = over.clone();
    domains[0] = Root::parse(&format!("{DOMAIN_ROOT_PREFIX}acme.example")).unwrap();
    for roots in [Roots::Listed(addresses), Roots::WithDomains(domains)] {
        let mut built = Record::AcceptFrom(AcceptFromRecord {
            owner: addr(2),
            roots,
            max_bytes: 1,
            ttl: 1,
            iat: NOW,
            sig: [0; 64],
        });
        assert_eq!(built.sign(&key(2)), Err(Code::BadRecord));
    }
}

#[test]
fn a_key_record_lives_a_day_at_most() {
    // Changed 2026-10-25: iat <= exp <= iat + 86,400, refused as bad-record.
    assert_eq!(MAX_KEY_LIFETIME, 86_400);
    let day = key_record(3, NOW, NOW + MAX_KEY_LIFETIME);
    day.verify(NOW + MAX_KEY_LIFETIME, SKEW).unwrap();
    assert_eq!(day.verify(NOW + MAX_KEY_LIFETIME + 1, SKEW), Err(Code::RecordExpired));
    key_record(3, NOW, NOW).verify(NOW, SKEW).unwrap();
    assert_eq!(with(&day, "exp", json!(NOW + MAX_KEY_LIFETIME + 1)), Err(Code::BadRecord));
    let mut long = Record::Key(KeyRecord {
        key: addr(3),
        sealing_key: "bb".repeat(32),
        iat: NOW,
        exp: NOW + 2 * MAX_KEY_LIFETIME,
        sig: [0; 64],
    });
    assert_eq!(long.sign(&key(3)), Err(Code::BadRecord));
    assert_eq!(long.verify(NOW, SKEW), Err(Code::BadRecord));
}

#[test]
fn a_rotation_claim_is_checked_under_rotated_from_without_the_previous_record() {
    // Changed 2026-10-25: what a relay that holds no previous record can check.
    verify_rotation_claim(&rotated(1, 2, NOW + 1, Some(1))).unwrap();
    verify_rotation_claim(&address_record(2, NOW)).unwrap();
    assert_eq!(verify_rotation_claim(&rotated(1, 2, NOW + 1, None)), Err(Code::BadRotation));
    assert_eq!(verify_rotation_claim(&rotated(1, 2, NOW + 1, Some(7))), Err(Code::BadRotation));
    assert_eq!(verify_rotation_claim(&rotated(1, 2, NOW + 1, Some(2))), Err(Code::BadRotation));
    // A rotation-key countersignature: only a reader that holds the previous record knows the rotation key.
    let by_rotation_key = rotated(1, 2, NOW + 1, Some(99));
    assert_eq!(verify_rotation_claim(&by_rotation_key), Err(Code::BadRotation));
    verify_rotation(&address_record(1, NOW), &by_rotation_key).unwrap();
    let mut huge = rotated(1, 2, NOW + 1, Some(1));
    huge.iat = u64::MAX;
    assert_eq!(verify_rotation_claim(&huge), Err(Code::BadRotation));
}
