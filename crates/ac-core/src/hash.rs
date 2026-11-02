//! SHA-256, and the digest every signature covers: `sha256(utf8(canonical(preimage)))`.

use crate::canonical::{self, Value};
use crate::error::Result;
use sha2::{Digest as _, Sha256};

/// SHA-256 of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// SHA-256 of `data`, as lower-case hex.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    crate::hex::encode(&sha256(data))
}

/// The 32 bytes a signature covers: SHA-256 of the UTF-8 of the canonical text of `preimage`.
///
/// # Errors
///
/// As for [`canonical::to_string`]: an integer over 2^53 - 1.
pub fn digest(preimage: &Value) -> Result<[u8; 32]> {
    Ok(sha256(canonical::to_string(preimage)?.as_bytes()))
}

#[cfg(test)]
mod tests;
