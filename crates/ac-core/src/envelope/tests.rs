use super::{Envelope, MAX_ENVELOPE_BYTES, MAX_RECIPIENTS, Sealed, Wrap, check_window};
use crate::canonical::{self, MAX_SAFE_INTEGER};
use crate::chain::Hop;
use crate::error::Code;
use crate::hash;
use crate::testkit::{NOW, addr, envelope_to, json, key, sealed, with_field};
use serde_json::json;

const TTL: u64 = 604_800;
const SKEW: u64 = 300;

fn code(bytes: &[u8]) -> Code {
    Envelope::parse(bytes).unwrap_err()
}

#[test]
fn round_trips_byte_for_byte_and_verifies() {
    let env = envelope_to(&[addr(2), addr(3)]);
    let bytes = env.to_bytes();
    let parsed = Envelope::parse(&bytes).unwrap();
    assert_eq!(parsed, env);
    assert_eq!(parsed.to_bytes(), bytes);
    parsed.verify_outer(NOW, TTL, SKEW).unwrap();
    assert!(String::from_utf8(bytes).unwrap().starts_with(r#"{"v":1,"id":""#));
}

#[test]
fn the_id_is_the_hash_of_the_documented_preimage() {
    let to = [addr(2)];
    let env = envelope_to(&to);
    let s = sealed(&to);
    let sealed_text =
        format!(r#"[[["{}","{}","{}"]],"{}","{}"]"#, addr(2), s.wraps[0].enc, s.wraps[0].ct, s.nonce, s.ct);
    assert_eq!(canonical::to_string(&s.preimage()).unwrap(), sealed_text);
    let sealed_hash = hash::sha256_hex(sealed_text.as_bytes());
    assert_eq!(s.hash_hex(), sealed_hash);
    let id_text = format!(r#"[1,["{}"],"{}",[],1,{NOW},"{sealed_hash}"]"#, addr(2), addr(1));
    assert_eq!(canonical::to_string(&env.id_preimage()).unwrap(), id_text);
    assert_eq!(env.id, hash::sha256(id_text.as_bytes()));
    assert_eq!(env.compute_id().unwrap(), env.id);
    assert_eq!(env.id_hex(), crate::hex::encode(&env.id));
}

#[test]
fn the_chain_enters_the_id() {
    let hop = Hop::sign(&key(9), &addr(1), vec!["type=x".into()], NOW + 60).unwrap();
    let env = Envelope::sign(&key(1), vec![addr(2)], vec![hop.clone()], NOW, sealed(&[addr(2)])).unwrap();
    let text = canonical::to_string(&env.id_preimage()).unwrap();
    let entry = format!(
        r#"[["{}","{}",["type=x"],{},"{}"]]"#,
        addr(9),
        addr(1),
        NOW + 60,
        crate::hex::encode(&hop.sig)
    );
    assert!(text.contains(&entry));
    let parsed = Envelope::parse(&env.to_bytes()).unwrap();
    assert_eq!(parsed.auth, vec![hop]);
    parsed.verify_outer(NOW, TTL, SKEW).unwrap();
}

#[test]
fn steps_1_to_3_size_json_object() {
    let env = envelope_to(&[addr(2)]);
    let mut padded = env.to_bytes();
    padded.resize(MAX_ENVELOPE_BYTES, b' ');
    assert!(Envelope::parse(&padded).is_ok());
    padded.push(b' ');
    assert_eq!(code(&padded), Code::EnvelopeTooLarge);
    assert_eq!(Envelope::parse_with_cap(&env.to_bytes(), 10), Err(Code::EnvelopeTooLarge));
    assert_eq!(code(b"{"), Code::BadJson);
    assert_eq!(code(b"\xff"), Code::BadJson);
    assert_eq!(code(b"[]"), Code::BadShape);
}

#[test]
fn steps_4_to_6_version_suite_members() {
    let env = envelope_to(&[addr(2)]);
    assert_eq!(code(&with_field(&env, "v", json!(2))), Code::BadVersion);
    assert_eq!(code(&with_field(&env, "v", json!("1"))), Code::BadShape);
    assert_eq!(code(&with_field(&env, "suite", json!(2))), Code::BadSuite);
    assert_eq!(code(&with_field(&env, "suite", json!(null))), Code::BadShape);
    let mut missing = json(&env);
    missing.as_object_mut().unwrap().remove("v");
    assert_eq!(code(missing.to_string().as_bytes()), Code::BadShape);
    assert_eq!(code(&with_field(&env, "extra", json!(1))), Code::BadShape);
    assert_eq!(code(&with_field(&env, "kind", json!("envelope"))), Code::BadShape);
    // v is checked before the members: a v2 envelope with other members is bad-version.
    let mut v2 = json(&env);
    v2["v"] = json!(2);
    v2["new"] = json!(true);
    assert_eq!(code(v2.to_string().as_bytes()), Code::BadVersion);
}

#[test]
fn steps_7_to_9_id_to_from() {
    let env = envelope_to(&[addr(2)]);
    assert_eq!(code(&with_field(&env, "id", json!(1))), Code::BadShape);
    assert_eq!(code(&with_field(&env, "id", json!("AB".repeat(32)))), Code::BadHex);
    assert_eq!(code(&with_field(&env, "to", json!([]))), Code::BadShape);
    assert_eq!(code(&with_field(&env, "to", json!("x"))), Code::BadShape);
    let seventeen: Vec<String> =
        (0..=u8::try_from(MAX_RECIPIENTS).unwrap()).map(|i| addr(40 + i).to_string()).collect();
    assert_eq!(code(&with_field(&env, "to", json!(seventeen))), Code::TooManyRecipients);
    assert_eq!(code(&with_field(&env, "to", json!([1]))), Code::BadShape);
    assert_eq!(code(&with_field(&env, "to", json!(["ed25519:zz"]))), Code::BadAddress);
    let two = addr(2).to_string();
    assert_eq!(code(&with_field(&env, "to", json!([two, two]))), Code::BadShape);
    assert_eq!(code(&with_field(&env, "from", json!(7))), Code::BadShape);
    assert_eq!(code(&with_field(&env, "from", json!("alice"))), Code::BadAddress);
    let sixteen: Vec<_> = (0..u8::try_from(MAX_RECIPIENTS).unwrap()).map(|i| addr(40 + i)).collect();
    let full = Envelope::sign(&key(1), sixteen.clone(), vec![], NOW, sealed(&sixteen)).unwrap();
    assert_eq!(Envelope::parse(&full.to_bytes()).unwrap().to.len(), MAX_RECIPIENTS);
}

#[test]
fn steps_10_and_11_auth_and_ts() {
    let env = envelope_to(&[addr(2)]);
    assert_eq!(code(&with_field(&env, "auth", json!({}))), Code::BadShape);
    let hop: serde_json::Value =
        serde_json::from_str(&Hop::sign(&key(9), &addr(1), vec![], NOW + 60).unwrap().to_json_text())
            .unwrap();
    assert_eq!(code(&with_field(&env, "auth", json!(vec![hop.clone(); 9]))), Code::TooManyHops);
    assert_eq!(code(&with_field(&env, "auth", json!([{"iss": 1}]))), Code::BadHop);
    let mut many = hop.clone();
    many["caveats"] = json!(vec!["c"; 33]);
    assert_eq!(code(&with_field(&env, "auth", json!([many]))), Code::TooManyCaveats);
    let mut long = hop;
    long["caveats"] = json!(["x".repeat(257)]);
    assert_eq!(code(&with_field(&env, "auth", json!([long]))), Code::CaveatTooLong);
    for ts in [json!(-1), json!(1.5), json!("1"), json!(MAX_SAFE_INTEGER + 1)] {
        assert_eq!(code(&with_field(&env, "ts", ts.clone())), Code::BadShape, "{ts}");
    }
}

#[test]
fn step_12_the_sealed_part() {
    let to = [addr(2), addr(3)];
    let env = envelope_to(&to);
    let sealed_with = |f: &dyn Fn(&mut serde_json::Value)| {
        let mut j = json(&env);
        f(&mut j["sealed"]);
        code(j.to_string().as_bytes())
    };
    assert_eq!(sealed_with(&|s| *s = json!([])), Code::BadShape);
    assert_eq!(sealed_with(&|s| s["extra"] = json!(1)), Code::BadShape);
    assert_eq!(
        sealed_with(&|s| {
            s["wraps"].as_array_mut().unwrap().pop();
        }),
        Code::BadShape
    );
    assert_eq!(sealed_with(&|s| s["wraps"] = json!("x")), Code::BadShape);
    assert_eq!(sealed_with(&|s| s["wraps"][1]["to"] = json!(addr(4).to_string())), Code::BadShape);
    assert_eq!(sealed_with(&|s| s["wraps"][1]["more"] = json!(1)), Code::BadShape);
    assert_eq!(sealed_with(&|s| s["wraps"][0] = json!(null)), Code::BadShape);
    // The wraps follow the order of `to`.
    assert_eq!(sealed_with(&|s| s["wraps"].as_array_mut().unwrap().reverse()), Code::BadShape);
    assert_eq!(sealed_with(&|s| s["wraps"][0]["enc"] = json!(1)), Code::BadShape);
    assert_eq!(sealed_with(&|s| s["wraps"][0]["enc"] = json!("ab".repeat(31))), Code::BadHex);
    assert_eq!(sealed_with(&|s| s["wraps"][0]["ct"] = json!("cd".repeat(47))), Code::BadHex);
    assert_eq!(sealed_with(&|s| s["nonce"] = json!("ef".repeat(11))), Code::BadHex);
    assert_eq!(sealed_with(&|s| s["nonce"] = json!(12)), Code::BadShape);
    assert_eq!(sealed_with(&|s| s["ct"] = json!("01".repeat(15))), Code::BadHex);
    assert_eq!(sealed_with(&|s| s["ct"] = json!("0")), Code::BadHex);
    assert!(
        Envelope::parse(&{
            let mut j = json(&env);
            j["sealed"]["ct"] = json!("01".repeat(16));
            j.to_string().into_bytes()
        })
        .is_ok()
    );
}

#[test]
fn step_13_sig() {
    let env = envelope_to(&[addr(2)]);
    assert_eq!(code(&with_field(&env, "sig", json!(null))), Code::BadShape);
    assert_eq!(code(&with_field(&env, "sig", json!("ab".repeat(63)))), Code::BadHex);
}

#[test]
fn the_outer_checks_in_order() {
    let env = envelope_to(&[addr(2)]);
    let mut wrong_id = env.clone();
    wrong_id.id[0] ^= 1;
    assert_eq!(wrong_id.check_id(), Err(Code::BadId));
    let mut moved = env.clone();
    moved.ts += 1;
    assert_eq!(moved.verify_outer(NOW, TTL, SKEW), Err(Code::BadId));
    let mut bad_sig = env.clone();
    bad_sig.sig[0] ^= 1;
    assert_eq!(bad_sig.verify_outer(NOW, TTL, SKEW), Err(Code::BadSig));
    let mut other = env.clone();
    other.sig = key(5).sign(&env.id);
    assert_eq!(other.check_sig(), Err(Code::BadSig));
    let mut none = env.clone();
    none.to.clear();
    assert_eq!(none.verify_outer(NOW, TTL, SKEW), Err(Code::BadShape));
    let mut twice = env.clone();
    twice.to.push(addr(2));
    assert_eq!(twice.check_recipients(), Err(Code::BadShape));
    let mut many = env.clone();
    many.to = (0..17).map(|i| addr(40 + i)).collect();
    assert_eq!(many.check_recipients(), Err(Code::TooManyRecipients));
    let mut out_of_range = env;
    out_of_range.ts = u64::MAX;
    assert_eq!(out_of_range.check_id(), Err(Code::BadCanonical));
}

#[test]
fn the_window_is_ttl_plus_skew_back_and_skew_forward() {
    let env = envelope_to(&[addr(2)]);
    assert!(env.check_ts(NOW, TTL, SKEW).is_ok());
    assert!(env.check_ts(NOW - SKEW, TTL, SKEW).is_ok());
    assert_eq!(env.check_ts(NOW - SKEW - 1, TTL, SKEW), Err(Code::FutureTs));
    assert!(env.check_ts(NOW + TTL + SKEW, TTL, SKEW).is_ok());
    assert_eq!(env.check_ts(NOW + TTL + SKEW + 1, TTL, SKEW), Err(Code::StaleTs));
    assert_eq!(env.verify_outer(NOW + TTL + SKEW + 1, TTL, SKEW), Err(Code::StaleTs));
    assert!(check_window(u64::MAX, u64::MAX, u64::MAX, u64::MAX).is_ok());
    assert_eq!(check_window(5, 7, 1, 0), Err(Code::StaleTs));
}

#[test]
fn the_builder_checks_what_parsing_refuses() {
    let to = vec![addr(2)];
    assert_eq!(
        Envelope::sign(&key(1), to.clone(), vec![], MAX_SAFE_INTEGER + 1, sealed(&to)).err(),
        Some(Code::BadShape)
    );
    assert_eq!(Envelope::sign(&key(1), vec![], vec![], NOW, sealed(&[])).err(), Some(Code::BadShape));
    let nine: Vec<Hop> =
        (0..9).map(|i| Hop::sign(&key(20 + i), &addr(21 + i), vec![], NOW).unwrap()).collect();
    assert_eq!(Envelope::sign(&key(1), to.clone(), nine, NOW, sealed(&to)).err(), Some(Code::TooManyHops));
    let s = Sealed {
        wraps: vec![Wrap { to: addr(2), enc: String::new(), ct: String::new() }],
        nonce: String::new(),
        ct: String::new(),
    };
    assert_eq!(s.hash_hex().len(), 64);
}
