//! The signed requests of the relay API: a fetch's headers and a subscriber's auth frame.
//!
//! * fetch: `["ac/fetch/1", signer, id, ts, audience]`, signed by the `AC-Signer` key, with `ts` within the clock
//!   skew and `audience` the relay's base URL (spec/SPEC.md §8.3; added 2026-11-02, so that a proof made for one
//!   relay is refused at another);
//! * subscribe: `["ac/sub/1", nonce, signer, mailbox, cursor or null]`, signed by the signer over the relay's
//!   challenge nonce.

use crate::address::Address;
use crate::canonical::Value;

/// The domain tag of a fetch request's preimage.
pub const FETCH_TAG: &str = "ac/fetch/1";
/// The domain tag of a subscribe response's preimage.
pub const SUBSCRIBE_TAG: &str = "ac/sub/1";

/// `["ac/fetch/1", signer, id, ts, audience]`: `audience` is the relay's base URL as the caller addressed it, the
/// `relays` entry with its trailing slashes dropped, byte for byte.
#[must_use]
pub fn fetch_preimage(signer: &Address, id: &str, ts: u64, audience: &str) -> Value {
    Value::Array(vec![
        Value::from(FETCH_TAG),
        Value::from(signer.as_str()),
        Value::from(id),
        Value::Int(ts),
        Value::from(audience),
    ])
}

/// `["ac/sub/1", nonce, signer, mailbox, cursor or null]`.
#[must_use]
pub fn subscribe_preimage(nonce: &str, signer: &Address, mailbox: &Address, cursor: Option<u64>) -> Value {
    Value::Array(vec![
        Value::from(SUBSCRIBE_TAG),
        Value::from(nonce),
        Value::from(signer.as_str()),
        Value::from(mailbox.as_str()),
        cursor.map_or(Value::Null, Value::Int),
    ])
}

#[cfg(test)]
mod tests;
