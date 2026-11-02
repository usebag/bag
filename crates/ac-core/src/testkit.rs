//! Fixtures for the unit tests: keys from fixed seeds and opaque sealed parts. Test data by construction.

use crate::address::Address;
use crate::envelope::{Envelope, Sealed, Wrap};
use crate::keys::SigningKey;

/// A fixed time, 2027-01-15 08:00 UTC, so no test depends on the clock.
pub const NOW: u64 = 1_800_000_000;

/// The key of a one-byte seed (`[n; 32]`).
pub fn key(n: u8) -> SigningKey {
    SigningKey::from_seed(&[n; 32])
}

/// The address of `key(n)`.
pub fn addr(n: u8) -> Address {
    key(n).address()
}

/// An opaque sealed part with one wrap per recipient, in order (the relay never opens it).
pub fn sealed(to: &[Address]) -> Sealed {
    Sealed {
        wraps: to.iter().map(|a| Wrap { to: a.clone(), enc: "ab".repeat(32), ct: "cd".repeat(48) }).collect(),
        nonce: "ef".repeat(12),
        ct: "01".repeat(64),
    }
}

/// A self-rooted envelope from `key(1)` to the given recipients at `NOW`.
pub fn envelope_to(to: &[Address]) -> Envelope {
    Envelope::sign(&key(1), to.to_vec(), vec![], NOW, sealed(to)).unwrap()
}

/// The wire JSON of an envelope as a value, to change before writing it back.
pub fn json(env: &Envelope) -> serde_json::Value {
    serde_json::from_str(&env.to_json_text()).unwrap()
}

/// The wire bytes of an envelope with one member replaced.
pub fn with_field(env: &Envelope, field: &str, value: serde_json::Value) -> Vec<u8> {
    let mut j = json(env);
    j[field] = value;
    j.to_string().into_bytes()
}
