use super::{Code, Group};
use std::collections::HashSet;

#[test]
fn every_code_is_lower_kebab_case_and_unique() {
    let mut seen = HashSet::new();
    for code in Code::ALL {
        let text = code.as_str();
        assert!(
            !text.is_empty()
                && text.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "{text} is not kebab-case"
        );
        assert!(!text.starts_with('-') && !text.ends_with('-') && !text.contains("--"), "{text}");
        assert!(seen.insert(text), "{text} appears twice");
    }
}

#[test]
fn every_code_round_trips_through_its_wire_form() {
    for code in Code::ALL {
        assert_eq!(Code::from_wire(code.as_str()), Some(*code));
        assert_eq!(code.to_string(), code.as_str());
    }
    assert_eq!(Code::from_wire("no-such-code"), None);
}

#[test]
fn the_groups_of_appendix_a() {
    let count = |g| Code::ALL.iter().filter(|c| c.group() == g).count();
    // 37, 9 and 7 until 2026-10-25; then `internal` was added to the relay's and `unreachable` to the edge's;
    // then `store-full` to the relay's; 2026-10-30 pairing added `no-nameplate` (relay) and `bad-code` and
    // `leaked` (edge), then typed digits `digits-mismatch` (edge).
    assert_eq!((count(Group::Core), count(Group::Relay), count(Group::Edge)), (37, 12, 11));
    // The groups come in order: core, then relay, then edge.
    let groups: Vec<Group> = Code::ALL.iter().map(|c| c.group()).collect();
    let first_relay = groups.iter().position(|g| *g == Group::Relay).unwrap();
    let first_edge = groups.iter().position(|g| *g == Group::Edge).unwrap();
    assert!(groups[..first_relay].iter().all(|g| *g == Group::Core));
    assert!(groups[first_relay..first_edge].iter().all(|g| *g == Group::Relay));
    assert!(groups[first_edge..].iter().all(|g| *g == Group::Edge));
    for name in [
        "not-hosted",
        "root-not-accepted",
        "too-large-for-mailbox",
        "rate-limited",
        "bad-auth",
        "stale-record",
        "store-full",
    ] {
        assert_eq!(Code::from_wire(name).map(Code::group), Some(Group::Relay), "{name}");
    }
}

#[test]
fn a_code_is_an_error() {
    let e: Box<dyn std::error::Error> = Box::new(Code::BadJson);
    assert_eq!(e.to_string(), "bad-json");
}
