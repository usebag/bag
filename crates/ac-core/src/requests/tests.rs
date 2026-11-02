use super::{fetch_preimage, subscribe_preimage};
use crate::canonical::to_string;
use crate::testkit::addr;

#[test]
fn the_fetch_preimage_ends_with_its_audience() {
    let text = to_string(&fetch_preimage(&addr(1), "ab", 7, "https://relay.example")).unwrap();
    assert_eq!(text, format!(r#"["ac/fetch/1","{}","ab",7,"https://relay.example"]"#, addr(1)));
    let other = to_string(&fetch_preimage(&addr(1), "ab", 7, "https://relay.example/")).unwrap();
    assert_ne!(text, other, "the audience is taken as written");
}

#[test]
fn the_subscribe_preimage_with_and_without_a_cursor() {
    let with = to_string(&subscribe_preimage("n0", &addr(1), &addr(2), Some(3))).unwrap();
    assert_eq!(with, format!(r#"["ac/sub/1","n0","{}","{}",3]"#, addr(1), addr(2)));
    let without = to_string(&subscribe_preimage("n0", &addr(1), &addr(2), None)).unwrap();
    assert_eq!(without, format!(r#"["ac/sub/1","n0","{}","{}",null]"#, addr(1), addr(2)));
}
