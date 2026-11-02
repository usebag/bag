use super::{PolicyRecord, is_caveat_pattern, is_type_pattern, matches_caveat, type_matches};
use crate::error::Code;

// The shared table that packages/core/test/policy.test.ts writes from fixed seeds. Each served case
// is read from its exact bytes, verified at its time with the skew, and compared with the TypeScript core's verdict; an
// accepted record also has the same preimage digest. The table's members cases are the TypeScript core's alone: a
// members record never leaves the org's edges, so no relay reads one.
const VECTORS: &str = include_str!("../../../../spec/drafts/policy-vectors.json");

fn verdict(text: &str, now: u64, skew: u64) -> (String, Option<PolicyRecord>) {
    match PolicyRecord::parse(text.as_bytes()).and_then(|r| r.verify(now, skew).map(|()| r)) {
        Ok(r) => ("ok".to_owned(), Some(r)),
        Err(code) => (code.as_str().to_owned(), None),
    }
}

#[test]
fn every_served_case_of_the_shared_table_gets_the_typescript_verdict() {
    let doc: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let skew = doc["skew"].as_u64().unwrap();
    let cases = doc["cases"].as_array().unwrap();
    assert!(cases.len() >= 30, "{} cases", cases.len());
    let mut accepted = 0;
    for case in cases {
        let (name, text) = (case["name"].as_str().unwrap(), case["text"].as_str().unwrap());
        let (got, record) = verdict(text, case["now"].as_u64().unwrap(), skew);
        assert_eq!(got, case["expect"].as_str().unwrap(), "{name}");
        if let Some(r) = record {
            accepted += 1;
            assert_eq!(r.digest_hex().unwrap(), case["digest"].as_str().unwrap(), "{name}");
        }
    }
    assert!(accepted >= 5);
}

#[test]
fn the_served_case_reads_into_its_sections() {
    let doc: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let r = PolicyRecord::parse(doc["cases"][1]["text"].as_str().unwrap().as_bytes()).unwrap();
    assert_eq!((r.scopes.len(), r.scopes[1].pattern.as_str(), r.scopes[1].max_bytes), (2, "repo=web", 4096));
    let e = r.external.as_ref().unwrap();
    assert_eq!((e.required_caveats.len(), e.max_hop_lifetime, e.max_hops), (1, Some(86_400), Some(2)));
    assert_eq!(PolicyRecord::parse(b"{\"kind\":"), Err(Code::BadJson));
}

#[test]
fn patterns_match_as_the_typescript_core_matches_them() {
    let caveats = |c: &[&str]| c.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    assert!(matches_caveat("*", &[]));
    assert!(matches_caveat("repo=web", &caveats(&["repo=web"])));
    assert!(!matches_caveat("repo=web", &caveats(&["repo=webx"])));
    assert!(matches_caveat("type=*", &caveats(&["type=chat.*"])));
    assert!(!matches_caveat("type=*", &caveats(&["types=x"])));
    assert!(!matches_caveat("x*", &caveats(&["xy"])));
    assert_eq!(
        [is_caveat_pattern("*", true), is_caveat_pattern("*", false), is_caveat_pattern("=*", true)],
        [true, false, false]
    );
    let types = ["*", "chat.*", "chat.v1", "a*", ".*", ""].map(is_type_pattern);
    assert_eq!(types, [true, true, true, false, false, false]);
    assert!(
        type_matches("*", "x") && type_matches("chat.*", "chat.v1") && type_matches("chat.v1", "chat.v1")
    );
    assert!(!type_matches("chat.*", "chatty") && !type_matches("chat.v1", "chat.v2"));
}
