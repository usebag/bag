use super::{MAX_SAFE_INTEGER, Value, from_json, to_bytes, to_string, write_str};
use crate::error::Code;

fn s(text: &str) -> String {
    let mut out = String::new();
    write_str(&mut out, text);
    out
}

#[test]
fn escapes_exactly_what_json_stringify_escapes() {
    assert_eq!(s(""), r#""""#);
    assert_eq!(s("plain"), r#""plain""#);
    assert_eq!(s("\""), r#""\"""#);
    assert_eq!(s("\\"), r#""\\""#);
    assert_eq!(s("\u{08}\t\n\u{0c}\r"), r#""\b\t\n\f\r""#);
    assert_eq!(s("\u{00}"), r#""\u0000""#);
    assert_eq!(s("\u{01}\u{1f}"), r#""\u0001\u001f""#);
    assert_eq!(s("\u{0b}"), r#""\u000b""#);
    assert_eq!(s("\u{1b}"), r#""\u001b""#);
    // Not escaped: the slash, DEL, U+2028 and U+2029, non-ASCII, astral code points.
    assert_eq!(s("/"), r#""/""#);
    assert_eq!(s("\u{7f}"), "\"\u{7f}\"");
    assert_eq!(s("\u{2028}\u{2029}"), "\"\u{2028}\u{2029}\"");
    assert_eq!(s("é漢字"), "\"é漢字\"");
    assert_eq!(s("😀"), "\"😀\"");
}

#[test]
fn every_control_character_has_its_json_stringify_form() {
    let named = [(0x08, "\\b"), (0x09, "\\t"), (0x0a, "\\n"), (0x0c, "\\f"), (0x0d, "\\r")];
    for cp in 0u32..0x20 {
        let c = char::from_u32(cp).unwrap();
        let want = named
            .iter()
            .find(|(n, _)| *n == cp)
            .map_or_else(|| format!("\\u{cp:04x}"), |(_, e)| (*e).to_owned());
        assert_eq!(s(&c.to_string()), format!("\"{want}\""), "U+{cp:04X}");
    }
}

#[test]
fn no_normalization() {
    // "é" precomposed and decomposed stay distinct.
    assert_ne!(s("\u{e9}"), s("e\u{301}"));
    assert_eq!(s("e\u{301}").as_bytes(), b"\"e\xcc\x81\"");
}

#[test]
fn arrays_integers_and_null() {
    let v = Value::Array(vec![
        Value::Int(1),
        Value::Array(vec![]),
        Value::Null,
        Value::from("a"),
        Value::Array(vec![Value::Int(0), Value::Array(vec![Value::from("b")])]),
    ]);
    assert_eq!(to_string(&v).unwrap(), r#"[1,[],null,"a",[0,["b"]]]"#);
    assert_eq!(to_bytes(&v).unwrap(), br#"[1,[],null,"a",[0,["b"]]]"#.to_vec());
    assert_eq!(to_string(&Value::Int(MAX_SAFE_INTEGER)).unwrap(), "9007199254740991");
}

#[test]
fn integers_over_two_to_the_53_are_refused_anywhere() {
    assert_eq!(to_string(&Value::Int(MAX_SAFE_INTEGER + 1)), Err(Code::BadCanonical));
    let nested = Value::Array(vec![Value::from("x"), Value::Array(vec![Value::Int(u64::MAX)])]);
    assert_eq!(to_string(&nested), Err(Code::BadCanonical));
}

#[test]
fn helpers_build_the_expected_values() {
    assert_eq!(Value::opt_str(None), Value::Null);
    assert_eq!(Value::opt_str(Some("k")), Value::from("k"));
    assert_eq!(Value::strings(&["a", "b"]), Value::Array(vec![Value::from("a"), Value::from("b")]));
    assert_eq!(Value::from(String::from("t")), Value::Str("t".into()));
    assert_eq!(Value::from(7u64), Value::Int(7));
    assert_eq!(Value::from(vec![Value::Null]), Value::Array(vec![Value::Null]));
}

#[test]
fn from_json_takes_the_canonical_subset_only() {
    let parsed: serde_json::Value = serde_json::from_str(r#"[1,"a",null,[2]]"#).unwrap();
    assert_eq!(to_string(&from_json(&parsed).unwrap()).unwrap(), r#"[1,"a",null,[2]]"#);
    for bad in ["true", "{}", "-1", "1.5", "1e3", r#"[{"a":1}]"#] {
        let parsed: serde_json::Value = serde_json::from_str(bad).unwrap();
        assert_eq!(from_json(&parsed), Err(Code::BadCanonical), "{bad}");
    }
    let big: serde_json::Value = serde_json::from_str("9007199254740992").unwrap();
    assert_eq!(from_json(&big), Err(Code::BadCanonical));
}

#[test]
fn matches_serde_json_for_strings_it_escapes_the_same_way() {
    // serde_json escapes control characters as \u00XX with lower-case hex too, and the named five the same way;
    // the two agree on every code point below U+0080. This is a cross-check, not the source of truth.
    for cp in 0u32..0x80 {
        let c = char::from_u32(cp).unwrap().to_string();
        assert_eq!(s(&c), serde_json::to_string(&c).unwrap(), "U+{cp:04X}");
    }
}
