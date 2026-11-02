use super::{check, decode, decode_array, encode};
use crate::error::Code;

#[test]
fn encodes_lower_case() {
    assert_eq!(encode(&[]), "");
    assert_eq!(encode(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
}

#[test]
fn decodes_what_it_encodes() {
    let bytes: Vec<u8> = (0..=255).collect();
    assert_eq!(decode(&encode(&bytes)).unwrap(), bytes);
}

#[test]
fn refuses_upper_case_odd_length_and_other_characters() {
    assert_eq!(decode("AB"), Err(Code::BadHex));
    assert_eq!(decode("abc"), Err(Code::BadHex));
    assert_eq!(decode("zz"), Err(Code::BadHex));
    assert_eq!(decode("0x"), Err(Code::BadHex));
    assert_eq!(decode(" 0"), Err(Code::BadHex));
    assert_eq!(check("AB"), Err(Code::BadHex));
    assert_eq!(check("abc"), Err(Code::BadHex));
    assert_eq!(check("0a1b"), Ok(()));
}

#[test]
fn fixed_arrays_need_the_exact_length() {
    assert_eq!(decode_array::<2>("0a1b").unwrap(), [0x0a, 0x1b]);
    assert_eq!(decode_array::<2>("0a1b2c"), Err(Code::BadHex));
    assert_eq!(decode_array::<2>("0a"), Err(Code::BadHex));
    assert_eq!(decode_array::<2>("0A1b"), Err(Code::BadHex));
}
