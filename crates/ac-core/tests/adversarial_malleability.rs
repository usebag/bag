//! Signature malleability and degenerate keys in the Rust core: line F7 (a), (b) and (c) for
//! Ed25519. The core verifies with `verify_strict`, which must refuse `S + L`, a small-order key and a
//! non-canonical key encoding wherever a signature is checked: the envelope's `sig`, a hop's `sig`, a record's
//! `sig`. Every envelope verifies before it is changed.

mod support;

use ac_core::chain::Hop;
use ac_core::envelope::Envelope;
use ac_core::records::{KeyRecord, Record};
use ac_core::{Address, Code, hash, hex};
use support::{NOW, Rng, STUDY_SEED, chain_code, control, fixed_key, fixtures_with_hops, verdict};

/// L, the order of the Ed25519 base point, little-endian.
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// The signature with `S + L` in place of `S`: the same value modulo L, a different encoding.
fn plus_l(sig: &[u8; 64]) -> [u8; 64] {
    let mut out = *sig;
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = u16::from(out[32 + i]) + u16::from(L[i]) + carry;
        out[32 + i] = sum.to_le_bytes()[0];
        carry = sum >> 8;
    }
    assert_eq!(carry, 0, "S + L fits in 256 bits");
    assert_ne!(&out, sig);
    out
}

#[test]
fn f7a_s_plus_l_is_refused_on_the_envelope_and_the_hop() {
    for f in fixtures_with_hops(STUDY_SEED + 0xF7, 20, 1) {
        control(&f);
        let malleated = Envelope { sig: plus_l(&f.env.sig), ..f.env.clone() };
        assert_eq!(verdict(&malleated.to_bytes()), Some(Code::BadSig), "F7(a) envelope");
        let mut hops = f.env.auth.clone();
        hops[0].sig = plus_l(&hops[0].sig);
        assert_eq!(chain_code(&f, &hops), Some(Code::BadHopSig), "F7(a) hop");
    }
}

/// The eight small-order points of Ed25519 in their canonical encodings, the identity first.
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

/// Non-canonical encodings of small-order points: y + p for y = 1 and y = 0, and x = 0 with the sign bit set.
/// No key whose secret is known has a y below 19, so y + p exists only for such points.
const NON_CANONICAL: [&str; 4] = [
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0100000000000000000000000000000000000000000000000000000000000080",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
];

/// `R` = the identity, `S` = 0: under a cofactorless check it verifies for the identity key over any digest.
fn degenerate_sig() -> [u8; 64] {
    let mut sig = [0u8; 64];
    sig[0] = 1;
    sig
}

/// F7 (b) and (c): a degenerate key as `from`, as a hop's `iss` and as a record's `key`, with the degenerate
/// signature. Each is refused with its signature code.
fn refuse_degenerate_key(encoding: &str) {
    let degenerate = Address::from_key(hex::decode_array::<32>(encoding).unwrap());
    let to = vec![fixed_key(71).address()];
    let sealed = support::sealed(&mut Rng::new(STUDY_SEED + 0x7b), &to);
    let base = Envelope::sign(&fixed_key(70), to.clone(), vec![], NOW, sealed.clone()).unwrap();
    assert_eq!(verdict(&base.to_bytes()), None, "positive control");
    let mut env = Envelope { from: degenerate.clone(), sig: degenerate_sig(), ..base };
    env.id = env.compute_id().unwrap();
    assert_eq!(verdict(&env.to_bytes()), Some(Code::BadSig), "{encoding} as from");
    let hop = Hop {
        iss: degenerate.clone(),
        sub: fixed_key(70).address(),
        caveats: vec![],
        exp: NOW + 3_600,
        sig: degenerate_sig(),
    };
    let env = Envelope::sign(&fixed_key(70), to, vec![hop], NOW, sealed).unwrap();
    assert_eq!(verdict(&env.to_bytes()), Some(Code::BadHopSig), "{encoding} as iss");
    let record = Record::Key(KeyRecord {
        key: degenerate,
        sealing_key: "aa".repeat(32),
        iat: NOW,
        exp: NOW + 3_600,
        sig: degenerate_sig(),
    });
    let parsed = Record::parse(&record.to_bytes()).unwrap();
    assert_eq!(parsed.verify(NOW, 300).err(), Some(Code::BadRecordSig), "{encoding} as key");
}

#[test]
fn f7b_small_order_keys_are_refused_as_from_iss_and_record_key() {
    // The witness that the input is a real forgery for a lax verifier: ed25519-dalek's cofactorless `verify`
    // accepts the degenerate signature under the identity key; the core's strict check must not.
    use ed25519_dalek::Verifier as _;
    let identity =
        ed25519_dalek::VerifyingKey::from_bytes(&degenerate_sig()[..32].try_into().unwrap()).unwrap();
    let digest = hash::sha256(b"any digest");
    let lax = identity.verify(&digest, &ed25519_dalek::Signature::from_bytes(&degenerate_sig())).is_ok();
    eprintln!("F7(b): a cofactorless verifier accepts the identity-key forgery: {lax}");
    assert!(lax, "the forgery must be one a lax verifier accepts, or the test proves nothing");
    for encoding in SMALL_ORDER {
        refuse_degenerate_key(encoding);
    }
}

#[test]
fn f7c_non_canonical_key_encodings_are_refused() {
    for encoding in NON_CANONICAL {
        refuse_degenerate_key(encoding);
    }
}
