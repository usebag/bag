//! Addresses: `ed25519:` followed by the 64 lower-case hex characters of an Ed25519 public key.
//!
//! Parsing checks the text only. Whether the 32 bytes are a valid curve point is decided when a signature is
//! verified: a key that is not a point verifies nothing.

use crate::error::{Code, Result};
use std::fmt;

/// The identity-suite prefix of every v0 address.
pub const PREFIX: &str = "ed25519:";

/// An address: an Ed25519 public key with its suite prefix.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address {
    text: String,
    key: [u8; 32],
}

impl Address {
    /// Parses `ed25519:` + 64 lower-case hex.
    ///
    /// # Errors
    ///
    /// [`Code::BadAddress`] for anything else: another prefix, upper-case hex, another length.
    pub fn parse(text: &str) -> Result<Address> {
        let hex = text.strip_prefix(PREFIX).ok_or(Code::BadAddress)?;
        let key = crate::hex::decode_array::<32>(hex).map_err(|_| Code::BadAddress)?;
        Ok(Address { text: text.to_owned(), key })
    }

    /// The address of a raw Ed25519 public key.
    #[must_use]
    pub fn from_key(key: [u8; 32]) -> Address {
        Address { text: format!("{PREFIX}{}", crate::hex::encode(&key)), key }
    }

    /// The address as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The 32 bytes of the public key.
    #[must_use]
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", self.text)
    }
}

impl serde::Serialize for Address {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.text)
    }
}

#[cfg(test)]
mod tests;
