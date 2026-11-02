use super::{Address, PREFIX};
use crate::error::Code;

const HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

#[test]
fn parses_the_prefix_and_64_lower_case_hex() {
    let a = Address::parse(&format!("{PREFIX}{HEX}")).unwrap();
    assert_eq!(a.as_str(), format!("ed25519:{HEX}"));
    assert_eq!(a.key()[0], 0xd7);
    assert_eq!(a.to_string(), a.as_str());
    assert_eq!(format!("{a:?}"), format!("Address(ed25519:{HEX})"));
    assert_eq!(Address::from_key(*a.key()), a);
    assert_eq!(serde_json::to_string(&a).unwrap(), format!("\"ed25519:{HEX}\""));
}

#[test]
fn refuses_everything_else() {
    let upper = HEX.to_uppercase();
    let cases = [
        HEX.to_owned(),
        format!("ed25519:{}", &HEX[..62]),
        format!("ed25519:{HEX}00"),
        format!("ed25519:{upper}"),
        format!("ED25519:{HEX}"),
        format!("x25519:{HEX}"),
        format!(" ed25519:{HEX}"),
        format!("ed25519:{HEX} "),
        String::new(),
    ];
    for case in cases {
        assert_eq!(Address::parse(&case), Err(Code::BadAddress), "{case:?}");
    }
}
