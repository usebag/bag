use super::{Writer, address_field, array, canonical_integer, has_exact_keys, hex_field, is_hex, parse};
use crate::error::Code;
use serde_json::json;

#[test]
fn reading_refuses_what_is_not_one_utf8_json_value() {
    assert_eq!(parse(b"{\"a\":1}").unwrap(), json!({"a": 1}));
    for bad in
        [&b"not json"[..], b"\xff", b"\xef\xbb\xbf{}", b"{} {}", br#"["\ud800"]"#, br#"{"\udc00":1}"#, b""]
    {
        assert_eq!(parse(bad), Err(Code::BadJson), "{}", String::from_utf8_lossy(bad));
    }
    // A pair of surrogates is one character, and fine.
    assert_eq!(parse(br#"["\ud83d\ude00"]"#).unwrap(), json!(["\u{1f600}"]));
    // Changed 2026-10-25: a member given twice is bad-json; until then it kept its last value.
    assert_eq!(parse(br#"{"a":1,"a":2}"#), Err(Code::BadJson));
}

#[test]
fn an_object_that_names_a_member_twice_is_bad_json() {
    // spec/SPEC.md §2.5 (changed 2026-10-25): two names are one when their decoded strings are equal.
    for twice in [
        r#"{"a":1,"a":2}"#,
        r#"{"a":1,"\u0061":2}"#,
        "{\"\\u00e9\":1,\"\u{e9}\":2}",
        r#"{"\ud83d\ude00":1,"\ud83d\ude00":2}"#,
        r#"{"a\"":1,"a\"":2}"#,
        r#"{"x":{"a":1,"b":2,"a":3}}"#,
        r#"[1,{"a":1,"a":1}]"#,
        r#"{"a":[1,{"b":2}],"a":2}"#,
        r#"{"a":{},"b":[],"a":null}"#,
        r#"{"":1,"":2}"#,
    ] {
        assert_eq!(parse(twice.as_bytes()), Err(Code::BadJson), "{twice}");
    }
    for once in [
        r#"{"a":1,"b":2}"#,
        r#"[{"a":1},{"a":1}]"#,
        r#"{"a":{"a":{"a":1}}}"#,
        r#"{"a":"a","b":"a"}"#,
        r#"{"a\\":1,"a":2}"#,
        r#"{"\u0061b":1,"a":2}"#,
        "{}",
        "[]",
    ] {
        assert_eq!(
            parse(once.as_bytes()).unwrap(),
            serde_json::from_str::<serde_json::Value>(once).unwrap(),
            "{once}"
        );
    }
}

#[test]
fn the_reader_builds_every_kind_of_value_as_serde_json_does() {
    let text = r#"{"t":true,"f":false,"n":null,"u":7,"i":-7,"x":1.5,"z":-0,"s":"\u00e9","l":[[],{}]}"#;
    assert_eq!(parse(text.as_bytes()).unwrap(), serde_json::from_str::<serde_json::Value>(text).unwrap());
    // Nesting past serde_json's limit of 128 is still bad-json.
    let deep = format!("{}{}", "[".repeat(129), "]".repeat(129));
    assert_eq!(parse(deep.as_bytes()), Err(Code::BadJson));
    let fine = format!("{}{}", "[".repeat(100), "]".repeat(100));
    assert!(parse(fine.as_bytes()).is_ok());
    let expected: &dyn serde::de::Expected = &super::DistinctVisitor;
    assert_eq!(expected.to_string(), "a JSON value whose objects name each member once");
}

#[test]
fn canonical_integers_are_json_integers_in_range() {
    assert_eq!(canonical_integer(&json!(0)), Some(0));
    assert_eq!(canonical_integer(&json!(9_007_199_254_740_991_u64)), Some(9_007_199_254_740_991));
    for not in [json!(9_007_199_254_740_992_u64), json!(-1), json!(1.5), json!(1.0), json!("1"), json!(null)]
    {
        assert_eq!(canonical_integer(&not), None, "{not}");
    }
    // "-0" is not a canonical integer here: serde_json reads it as a float.
    assert_eq!(canonical_integer(&parse(b"-0").unwrap()), None);
}

#[test]
fn only_a_plain_decimal_integer_is_a_canonical_integer() {
    // spec/SPEC.md §2.5 (changed 2026-10-25): every reader refuses a number not written as `0` or
    // `[1-9][0-9]*`; the TypeScript and Python readers now agree with this one on each spelling.
    for text in ["1.0", "1e0", "1E0", "-0", "-1", "0.5", "1e-400", "9007199254740990.9", "9007199254740992"] {
        assert_eq!(canonical_integer(&parse(text.as_bytes()).unwrap()), None, "{text}");
    }
    for text in ["01", "1e400", "-1e400", "+1", ".5", "1."] {
        assert_eq!(parse(text.as_bytes()), Err(Code::BadJson), "{text}");
    }
    for (text, n) in [("0", 0), ("1", 1), ("9007199254740991", 9_007_199_254_740_991)] {
        assert_eq!(canonical_integer(&parse(text.as_bytes()).unwrap()), Some(n), "{text}");
    }
}

#[test]
fn fields() {
    let obj = json!({"a": 1, "b": 2});
    assert!(has_exact_keys(obj.as_object().unwrap(), &["b", "a"]));
    assert!(!has_exact_keys(obj.as_object().unwrap(), &["a"]));
    assert!(!has_exact_keys(obj.as_object().unwrap(), &["a", "c"]));
    assert!(is_hex("", None) && is_hex("0a", Some(1)) && !is_hex("0a", Some(2)) && !is_hex("0A", None));
    assert_eq!(hex_field(Some(&json!("0a")), Some(1)).unwrap(), "0a");
    assert_eq!(hex_field(Some(&json!(1)), Some(1)), Err(Code::BadShape));
    assert_eq!(hex_field(None, None), Err(Code::BadShape));
    assert_eq!(hex_field(Some(&json!("0a")), Some(2)), Err(Code::BadHex));
    assert_eq!(address_field(Some(&json!(7))).unwrap_err(), Code::BadShape);
    assert_eq!(address_field(Some(&json!("ed25519:00"))).unwrap_err(), Code::BadAddress);
}

#[test]
fn the_writer_keeps_member_order_and_json_stringify_escaping() {
    let text = Writer::object()
        .int("v", 1)
        .str("s", "a\"b\n\u{1}é")
        .opt_str("n", None)
        .opt_str("o", Some("x"))
        .strs("l", &["p", "q"])
        .raw("r", &array(["1".to_owned(), "[]".to_owned()].into_iter()))
        .finish();
    assert_eq!(
        text,
        "{\"v\":1,\"s\":\"a\\\"b\\n\\u0001é\",\"n\":null,\"o\":\"x\",\"l\":[\"p\",\"q\"],\"r\":[1,[]]}"
    );
    assert_eq!(Writer::object().finish(), "{}");
    assert_eq!(array(std::iter::empty()), "[]");
}
