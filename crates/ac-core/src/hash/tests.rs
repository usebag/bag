use super::{digest, sha256, sha256_hex};
use crate::canonical::Value;
use crate::error::Code;

#[test]
fn sha256_of_known_inputs() {
    assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(sha256(b"abc")[0], 0xba);
}

#[test]
fn digest_hashes_the_canonical_text() {
    let v = Value::Array(vec![Value::from("ac/hop/1"), Value::Int(1)]);
    assert_eq!(digest(&v).unwrap(), sha256(br#"["ac/hop/1",1]"#));
    assert_eq!(digest(&Value::Int(u64::MAX)), Err(Code::BadCanonical));
}
