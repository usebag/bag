//! Lower-case hex, the encoding of every byte field.
//!
//! Decoding is strict: only `0-9a-f`, an even number of characters, and for fixed-size fields exactly twice the
//! byte length. Upper-case hex is refused, so that one value has one encoding.

use crate::error::{Code, Result};

const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Lower-case hex of `bytes`.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

fn nibble(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(Code::BadHex),
    }
}

/// The bytes of lower-case hex text of any even length.
///
/// # Errors
///
/// [`Code::BadHex`] for an odd length or any character outside `0-9a-f`.
pub fn decode(text: &str) -> Result<Vec<u8>> {
    let raw = text.as_bytes();
    if !raw.len().is_multiple_of(2) {
        return Err(Code::BadHex);
    }
    raw.chunks_exact(2).map(|pair| Ok((nibble(pair[0])? << 4) | nibble(pair[1])?)).collect()
}

/// The `N` bytes of lower-case hex text that is exactly `2 * N` characters long.
///
/// # Errors
///
/// [`Code::BadHex`] for any other length or any character outside `0-9a-f`.
pub fn decode_array<const N: usize>(text: &str) -> Result<[u8; N]> {
    if text.len() != 2 * N {
        return Err(Code::BadHex);
    }
    let bytes = decode(text)?;
    bytes.try_into().map_err(|_| Code::BadHex)
}

/// Checks that `text` is lower-case hex of an even length, without allocating.
///
/// # Errors
///
/// [`Code::BadHex`] as for [`decode`].
pub fn check(text: &str) -> Result<()> {
    if !text.len().is_multiple_of(2) {
        return Err(Code::BadHex);
    }
    text.bytes().try_for_each(|c| nibble(c).map(|_| ()))
}

#[cfg(test)]
mod tests;
