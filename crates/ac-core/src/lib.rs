//! # ac-core
//!
//! The verification core of bag, in Rust, for the reference relay (`crates/ac-relay`) and future tools:
//! the canonical form, SHA-256, Ed25519, envelopes, authority chains and records, as spec/SPEC.md defines them.
//! It reproduces the spec's test vectors (`spec/vectors/`, checked by `tests/conformance.rs`) and writes the same
//! bytes as the TypeScript core (`packages/core`); its error codes are the same strings, in the same order.
//!
//! It verifies and signs; it never seals or opens (no HPKE: a relay never sees content), and it never evaluates a
//! caveat (that is the edge's job).
//!
//! ```
//! use ac_core::{chain, envelope::{Envelope, Sealed, Wrap}, keys::SigningKey};
//!
//! let alice = SigningKey::from_seed(&[1; 32]);
//! let bob = SigningKey::from_seed(&[2; 32]).address();
//! let sealed = Sealed {
//!     wraps: vec![Wrap { to: bob.clone(), enc: "00".repeat(32), ct: "11".repeat(48) }],
//!     nonce: "22".repeat(12),
//!     ct: "33".repeat(40),
//! };
//! let env = Envelope::sign(&alice, vec![bob], vec![], 1_800_000_000, sealed).unwrap();
//! let parsed = Envelope::parse(&env.to_bytes()).unwrap();
//! parsed.verify_outer(1_800_000_000, 604_800, 300).unwrap();
//! let verified = chain::verify(&parsed.from, parsed.ts, &parsed.auth).unwrap();
//! assert_eq!(verified.root, alice.address()); // an empty chain is self-rooted
//! assert_eq!(parsed.to_bytes(), env.to_bytes()); // written as packages/core writes it
//! ```
#![forbid(unsafe_code)]

pub mod address;
pub mod canonical;
pub mod chain;
pub mod discovery;
pub mod envelope;
pub mod error;
pub mod handles;
pub mod hash;
pub mod hex;
pub mod json;
pub mod keys;
pub mod net;
pub mod records;
pub mod requests;

pub use address::Address;
pub use error::{Code, Result};

#[cfg(test)]
pub(crate) mod testkit;

pub mod policy;
