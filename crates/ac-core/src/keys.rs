//! Ed25519: verification for the relay, signing for fixtures, tests and tools.
//!
//! Every signature covers the 32-byte digest of a canonical preimage ([`crate::hash::digest`]). Verification is
//! strict (`verify_strict`): it refuses a non-canonical `S` and a small-order `R` or public key, so a signature
//! is never malleable. It also refuses a non-canonical encoding (y >= p) of the public key or `R` before dalek
//! decodes it, as the TypeScript and Python verifiers do (spec/SPEC.md §10). No honestly generated key
//! or signature is refused by it.

use crate::address::Address;
use crate::canonical::Value;
use crate::error::Result;
use ed25519_dalek::Signer as _;
use std::fmt;

/// An Ed25519 signing key. Its `Debug` shows the address only, never the secret.
pub struct SigningKey(ed25519_dalek::SigningKey);

impl SigningKey {
    /// The signing key of a 32-byte seed (RFC 8032's private key).
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> SigningKey {
        SigningKey(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    /// The address of this key's public half.
    #[must_use]
    pub fn address(&self) -> Address {
        Address::from_key(self.0.verifying_key().to_bytes())
    }

    /// Signs 32 digest bytes.
    #[must_use]
    pub fn sign(&self, digest: &[u8; 32]) -> [u8; 64] {
        self.0.sign(digest).to_bytes()
    }

    /// Signs the digest of a canonical preimage.
    ///
    /// # Errors
    ///
    /// As for [`crate::hash::digest`].
    pub fn sign_preimage(&self, preimage: &Value) -> Result<[u8; 64]> {
        Ok(self.sign(&crate::hash::digest(preimage)?))
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKey({}, secret redacted)", self.address())
    }
}

/// Whether the 32 bytes encode y < p = 2^255 - 19 once the sign bit is cleared. A y >= p (y + p for y < 19) is a
/// second encoding of a point; dalek's decoder accepts it without reducing, and its `verify_strict` refuses it
/// only when the point has small order.
fn is_canonical_point(b: &[u8; 32]) -> bool {
    !(b[31] & 0x7f == 0x7f && b[1..31].iter().all(|&x| x == 0xff) && b[0] >= 0xed)
}

/// Whether `sig` is a valid strict Ed25519 signature by `signer` over the 32 `digest` bytes.
#[must_use]
pub fn verify(signer: &Address, digest: &[u8; 32], sig: &[u8; 64]) -> bool {
    let mut r = [0u8; 32];
    r.copy_from_slice(&sig[..32]);
    if !is_canonical_point(signer.key()) || !is_canonical_point(&r) {
        return false;
    }
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(signer.key()) else {
        return false;
    };
    key.verify_strict(digest, &ed25519_dalek::Signature::from_bytes(sig)).is_ok()
}

#[cfg(test)]
mod tests;
