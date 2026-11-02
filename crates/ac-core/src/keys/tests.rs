use super::{SigningKey, verify};
use crate::address::Address;
use crate::canonical::Value;
use crate::hex;

// RFC 8032 section 7.1, test 1: the empty message.
const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

fn rfc_key() -> SigningKey {
    SigningKey::from_seed(&hex::decode_array::<32>(SEED).unwrap())
}

#[test]
fn the_rfc_8032_seed_gives_the_rfc_public_key() {
    assert_eq!(rfc_key().address().as_str(), format!("ed25519:{PUBLIC}"));
}

#[test]
fn signs_and_verifies_a_digest() {
    let key = rfc_key();
    let digest = crate::hash::sha256(b"message");
    let sig = key.sign(&digest);
    assert!(verify(&key.address(), &digest, &sig));
    let mut other = digest;
    other[0] ^= 1;
    assert!(!verify(&key.address(), &other, &sig));
    let mut bad = sig;
    bad[10] ^= 1;
    assert!(!verify(&key.address(), &digest, &bad));
    let stranger = SigningKey::from_seed(&[7; 32]).address();
    assert!(!verify(&stranger, &digest, &sig));
}

#[test]
fn signing_is_deterministic_and_matches_the_preimage_digest() {
    let key = rfc_key();
    let pre = Value::Array(vec![Value::from("ac/fetch/1"), Value::Int(1)]);
    let a = key.sign_preimage(&pre).unwrap();
    let b = key.sign(&crate::hash::digest(&pre).unwrap());
    assert_eq!(a, b);
    assert!(key.sign_preimage(&Value::Int(u64::MAX)).is_err());
}

#[test]
fn a_key_that_is_not_a_curve_point_verifies_nothing() {
    // y = 2 does not decompress to a point on edwards25519.
    let mut raw = [0u8; 32];
    raw[0] = 2;
    let not_a_point = Address::from_key(raw);
    assert!(!verify(&not_a_point, &[0; 32], &[0; 64]));
}

#[test]
fn a_small_order_key_is_refused_by_strict_verification() {
    // The identity point (y = 1) has order 1; with R = identity and S = 0 the plain check would pass.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut sig = [0u8; 64];
    sig[0] = 1;
    assert!(!verify(&Address::from_key(identity), &[0; 32], &sig));
}

#[test]
fn debug_never_shows_the_secret() {
    let shown = format!("{:?}", rfc_key());
    assert!(shown.contains(PUBLIC) && shown.contains("redacted") && !shown.contains(SEED));
}

// The eight small-order points of edwards25519, canonically encoded (identity, order 2, two of order 4,
// four of order 8), derived in packages/core/test/keys-strict.test.ts from RFC 8032 section 6.
const SMALL_ORDER: [&str; 8] = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
];
// x = 0 with the sign bit set (the identity, the order-2 point), and y + p of the identity (y = 1) and of the order-4
// points (y = 0), each sign: aliases that OpenSSL decodes as small-order points.
const ALIASES: [&str; 6] = [
    "0100000000000000000000000000000000000000000000000000000000000080",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
];

fn bytes32(h: &str) -> [u8; 32] {
    hex::decode_array::<32>(h).unwrap()
}

fn sig_of(r: [u8; 32], s: [u8; 32]) -> [u8; 64] {
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r);
    sig[32..].copy_from_slice(&s);
    sig
}

fn digests() -> Vec<[u8; 32]> {
    (0..64).map(|i: u32| crate::hash::sha256(format!("message {i}").as_bytes())).collect()
}

#[test]
fn every_small_order_or_aliased_signer_is_refused_with_r_identity_and_s_zero() {
    let forged = sig_of(bytes32(SMALL_ORDER[0]), [0; 32]);
    for key in SMALL_ORDER.iter().chain(ALIASES.iter()) {
        let signer = Address::from_key(bytes32(key));
        for d in digests() {
            assert!(!verify(&signer, &d, &forged), "accepted signer {key}");
        }
    }
}

#[test]
fn every_small_order_or_non_canonical_r_is_refused_under_an_honest_key() {
    let key = rfc_key();
    let d = crate::hash::sha256(b"message");
    let s: [u8; 32] = key.sign(&d)[32..].try_into().unwrap();
    for r in SMALL_ORDER.iter().chain(ALIASES.iter()) {
        assert!(!verify(&key.address(), &d, &sig_of(bytes32(r), s)), "accepted R {r}");
    }
    // A non-canonical R of the honest R is impossible to write (y >= 19); every y + p encoding as R is refused.
    for k in 0u8..19 {
        for sign in [0u8, 0x80] {
            let mut r = [0xffu8; 32];
            r[0] = 0xed + k;
            r[31] = 0x7f | sign;
            assert!(!verify(&key.address(), &d, &sig_of(r, s)));
        }
    }
}

#[test]
fn a_non_canonical_key_is_refused_even_when_its_point_has_large_order() {
    // y = 3 is a point of large order; y + p = 2^255 - 16 writes the same point. dalek decodes it (no reduction
    // check), and verify_strict would refuse it only for small order: verify refuses the encoding itself.
    let mut alias = [0xffu8; 32];
    alias[0] = 0xf0;
    alias[31] = 0x7f;
    assert!(ed25519_dalek::VerifyingKey::from_bytes(&alias).is_ok());
    assert!(!super::is_canonical_point(&alias));
    assert!(super::is_canonical_point(&bytes32(PUBLIC)));
    assert!(!verify(&Address::from_key(alias), &[0; 32], &[0; 64]));
}

#[test]
fn an_s_at_or_above_l_is_refused() {
    let key = rfc_key();
    let d = crate::hash::sha256(b"message");
    let sig = key.sign(&d);
    assert!(verify(&key.address(), &d, &sig));
    let l = bytes32("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    let r: [u8; 32] = sig[..32].try_into().unwrap();
    // S + L: add L to S as 256-bit little-endian integers (S < L < 2^253, so it never overflows).
    let mut s_plus_l = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let t = u16::from(sig[32 + i]) + u16::from(l[i]) + carry;
        s_plus_l[i] = t.to_le_bytes()[0];
        carry = t >> 8;
    }
    for s in [l, s_plus_l, [0xff; 32]] {
        assert!(!verify(&key.address(), &d, &sig_of(r, s)));
    }
}
