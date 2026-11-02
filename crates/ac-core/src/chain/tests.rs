use super::{
    Hop, MAX_CAVEAT_BYTES, MAX_CAVEATS, MAX_HOPS, check_hops, check_shape, hop_preimage, parse_hops_json,
    verify,
};
use crate::canonical::{self, Value};
use crate::error::Code;
use crate::testkit::{NOW, addr, key};
use serde_json::json;

const EXP: u64 = NOW + 3_600;

/// root(10) -> principal(11) -> session(12), each hop adding one caveat, `exp` non-increasing.
fn two_hops() -> Vec<Hop> {
    vec![
        Hop::sign(&key(10), &addr(11), vec!["type=coding.*".into()], EXP).unwrap(),
        Hop::sign(&key(11), &addr(12), vec!["repo=bag".into()], EXP - 10).unwrap(),
    ]
}

fn wire(hops: &[Hop]) -> serde_json::Value {
    serde_json::from_str(&format!("[{}]", hops.iter().map(Hop::to_json_text).collect::<Vec<_>>().join(",")))
        .unwrap()
}

#[test]
fn an_empty_chain_is_self_rooted() {
    let v = verify(&addr(1), NOW, &[]).unwrap();
    assert_eq!((v.root, v.principal), (addr(1), addr(1)));
    assert!(v.caveats.is_empty());
}

#[test]
fn a_valid_chain_names_its_root_principal_and_caveats_in_order() {
    let v = verify(&addr(12), NOW, &two_hops()).unwrap();
    assert_eq!((v.root, v.principal), (addr(10), addr(11)));
    assert_eq!(v.caveats, vec!["type=coding.*".to_owned(), "repo=bag".to_owned()]);
}

#[test]
fn the_hop_preimage_and_wire_form() {
    let hop = &two_hops()[0];
    let text = canonical::to_string(&hop.preimage()).unwrap();
    assert_eq!(text, format!(r#"["ac/hop/1","{}","{}",["type=coding.*"],{EXP}]"#, addr(10), addr(11)));
    assert_eq!(hop.preimage(), hop_preimage(&hop.iss, &hop.sub, &hop.caveats, hop.exp));
    let entry = canonical::to_string(&hop.id_entry()).unwrap();
    assert!(entry.starts_with(&format!(r#"["{}","{}",["type=coding.*"],{EXP},""#, addr(10), addr(11))));
    assert!(hop.to_json_text().starts_with(&format!(
        r#"{{"iss":"{}","sub":"{}","caveats":["#,
        addr(10),
        addr(11)
    )));
    assert_eq!(check_shape(Some(&wire(&two_hops()))).unwrap(), two_hops());
}

#[test]
fn rule_1_at_most_eight_hops() {
    let mut hops = Vec::new();
    for i in 0..=u8::try_from(MAX_HOPS).unwrap() {
        hops.push(Hop::sign(&key(20 + i), &addr(21 + i), vec![], EXP).unwrap());
    }
    let last = hops.last().unwrap().sub.clone();
    assert_eq!(verify(&last, NOW, &hops), Err(Code::TooManyHops));
    assert_eq!(check_shape(Some(&wire(&hops))), Err(Code::TooManyHops));
    hops.pop();
    let last = hops.last().unwrap().sub.clone();
    assert_eq!(verify(&last, NOW, &hops).unwrap().root, addr(20));
}

#[test]
fn rule_2_each_hop_well_formed() {
    let good = wire(&two_hops())[0].clone();
    let with = |f: &dyn Fn(&mut serde_json::Value)| {
        let mut h = good.clone();
        f(&mut h);
        check_shape(Some(&json!([h])))
    };
    assert_eq!(with(&|h| h["iss"] = json!("ed25519:00")), Err(Code::BadHop));
    assert_eq!(with(&|h| h["sub"] = json!(5)), Err(Code::BadHop));
    assert_eq!(with(&|h| h["sig"] = json!("00")), Err(Code::BadHop));
    assert_eq!(with(&|h| h["exp"] = json!(canonical::MAX_SAFE_INTEGER + 1)), Err(Code::BadHop));
    assert_eq!(with(&|h| h["exp"] = json!(1.5)), Err(Code::BadHop));
    assert_eq!(with(&|h| h["caveats"] = json!("x")), Err(Code::BadHop));
    assert_eq!(with(&|h| h["caveats"] = json!([1])), Err(Code::BadHop));
    assert_eq!(with(&|h| h["caveats"] = json!([""])), Err(Code::BadHop));
    assert_eq!(with(&|h| h["extra"] = json!(1)), Err(Code::BadHop));
    assert_eq!(check_shape(Some(&json!([null]))), Err(Code::BadHop));
    assert_eq!(check_shape(Some(&json!([[]]))), Err(Code::BadHop));
    assert_eq!(check_shape(Some(&json!({}))), Err(Code::BadShape));
    assert_eq!(check_shape(None), Err(Code::BadShape));
    // Built in code: an empty caveat, an exp out of range.
    let mut hops = two_hops();
    hops[1].exp = canonical::MAX_SAFE_INTEGER + 1;
    assert_eq!(verify(&addr(12), NOW, &hops), Err(Code::BadHop));
    let mut hops = two_hops();
    hops[0].caveats.push(String::new());
    assert_eq!(check_hops(&hops), Err(Code::BadHop));
    assert_eq!(Hop::sign(&key(1), &addr(2), vec![String::new()], 1).err(), Some(Code::BadHop));
    assert_eq!(Hop::sign(&key(1), &addr(2), vec![], u64::MAX).err(), Some(Code::BadHop));
}

#[test]
fn rules_3_and_4_the_caveat_caps() {
    let mut hops = two_hops();
    hops[0].caveats = vec!["c".into(); MAX_CAVEATS + 1];
    assert_eq!(verify(&addr(12), NOW, &hops), Err(Code::TooManyCaveats));
    assert_eq!(check_shape(Some(&wire(&hops))), Err(Code::TooManyCaveats));
    let mut hops = two_hops();
    hops[1].caveats = vec!["x".repeat(MAX_CAVEAT_BYTES + 1)];
    assert_eq!(verify(&addr(12), NOW, &hops), Err(Code::CaveatTooLong));
    assert_eq!(check_shape(Some(&wire(&hops))), Err(Code::CaveatTooLong));
    // Inclusive caps, counted in UTF-8 bytes.
    let full = Hop::sign(&key(10), &addr(12), vec!["x".repeat(MAX_CAVEAT_BYTES); MAX_CAVEATS], EXP).unwrap();
    assert_eq!(verify(&addr(12), NOW, &[full]).unwrap().caveats.len(), MAX_CAVEATS);
    assert_eq!(Hop::sign(&key(10), &addr(12), vec!["é".repeat(129)], EXP).err(), Some(Code::CaveatTooLong));
    // Rule 3 runs over every hop before rule 4.
    let mut hops = two_hops();
    hops[0].caveats = vec!["x".repeat(MAX_CAVEAT_BYTES + 1)];
    hops[1].caveats = vec!["c".into(); MAX_CAVEATS + 1];
    assert_eq!(check_shape(Some(&wire(&hops))), Err(Code::TooManyCaveats));
}

#[test]
fn rules_5_to_9() {
    let broken = vec![
        Hop::sign(&key(10), &addr(11), vec![], EXP).unwrap(),
        Hop::sign(&key(13), &addr(12), vec![], EXP).unwrap(),
    ];
    assert_eq!(verify(&addr(12), NOW, &broken), Err(Code::ChainBroken));
    assert_eq!(verify(&addr(1), NOW, &two_hops()), Err(Code::ChainNotToSender));
    let rising = vec![
        Hop::sign(&key(10), &addr(11), vec![], EXP).unwrap(),
        Hop::sign(&key(11), &addr(12), vec![], EXP + 1).unwrap(),
    ];
    assert_eq!(verify(&addr(12), NOW, &rising), Err(Code::ExpNotMonotone));
    assert!(verify(&addr(12), EXP - 10, &two_hops()).is_ok());
    assert_eq!(verify(&addr(12), EXP - 9, &two_hops()), Err(Code::HopExpired));
    let mut forged = two_hops();
    forged[1].sig[0] ^= 1;
    assert_eq!(verify(&addr(12), NOW, &forged), Err(Code::BadHopSig));
    let mut appended = two_hops();
    appended[0].caveats.push("added-after-signing".into());
    assert_eq!(verify(&addr(12), NOW, &appended), Err(Code::BadHopSig));
}

#[test]
fn the_first_broken_rule_wins() {
    let mut hops = vec![
        Hop::sign(&key(10), &addr(11), vec![], NOW - 5).unwrap(),
        Hop::sign(&key(13), &addr(14), vec![], NOW).unwrap(),
    ];
    hops[0].sig[0] ^= 1;
    assert_eq!(verify(&addr(12), NOW, &hops), Err(Code::ChainBroken));
    let hops = vec![
        Hop::sign(&key(10), &addr(11), vec![], NOW - 5).unwrap(),
        Hop::sign(&key(11), &addr(12), vec![], NOW - 1).unwrap(),
    ];
    assert_eq!(verify(&addr(12), NOW, &hops), Err(Code::ExpNotMonotone));
    let mut hops = vec![Hop::sign(&key(10), &addr(12), vec![], NOW - 1).unwrap()];
    hops[0].sig[0] ^= 1;
    assert_eq!(verify(&addr(12), NOW, &hops), Err(Code::HopExpired));
}

#[test]
fn hops_from_json_text() {
    let text = wire(&two_hops()).to_string();
    assert_eq!(parse_hops_json(&text).unwrap(), two_hops());
    assert_eq!(parse_hops_json("[]").unwrap(), vec![]);
    assert_eq!(parse_hops_json("not json"), Err(Code::BadJson));
    assert_eq!(parse_hops_json("{}"), Err(Code::BadShape));
    assert!(matches!(hop_preimage(&addr(1), &addr(2), &[], 1), Value::Array(ref v) if v.len() == 5));
}
