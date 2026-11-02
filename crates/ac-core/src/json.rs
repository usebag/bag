//! Reading and writing JSON (spec/SPEC.md §2.5, §5.1).
//!
//! Reading: UTF-8 JSON text, one value, no byte-order mark, no escaped lone surrogate, no object that names a member
//! twice (all `bad-json`). Integers are JSON integers from 0 to 2^53 - 1; a number written with a fraction or an
//! exponent is not one (a conforming writer never writes `1.0` or `1e0`, §2.5). Until 2026-10-25 a member given
//! twice kept its last value, as `JSON.parse` does; since 2026-10-25 §2.5 says every reader MUST refuse it, and
//! the TypeScript reader and the Python verifier refuse it too, so a relay and an edge still read one envelope alike.
//!
//! Writing: objects with their members in wire order and no white space, strings escaped exactly as
//! `JSON.stringify` escapes them (the canonical form's rule, [`crate::canonical::write_str`]), so that this crate
//! writes the same bytes as `packages/core`.

use crate::address::Address;
use crate::canonical::{MAX_SAFE_INTEGER, write_str};
use crate::error::{Code, Result};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt::{self, Write as _};

/// Parses UTF-8 JSON text into a value.
///
/// # Errors
///
/// [`Code::BadJson`] for bytes that are not UTF-8, text that is not exactly one JSON value, a leading byte-order
/// mark, a string or member name that escapes a lone surrogate, or an object that names a member twice (two names
/// are one when their decoded strings are equal: `"a"` and `"\u0061"`).
pub fn parse(bytes: &[u8]) -> Result<Value> {
    serde_json::from_slice::<Distinct>(bytes).map(|d| d.0).map_err(|_| Code::BadJson)
}

/// A JSON value whose objects name each member once: `serde_json`'s own `Value` keeps the last of two, so the reader
/// builds the value itself, with a map visitor that refuses a name it has seen in the same object (§2.5).
struct Distinct(Value);

impl<'de> Deserialize<'de> for Distinct {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Distinct, D::Error> {
        deserializer.deserialize_any(DistinctVisitor).map(Distinct)
    }
}

/// Builds a [`Value`] as `serde_json`'s own visitor does, but refuses a member name given twice.
struct DistinctVisitor;

impl<'de> Visitor<'de> for DistinctVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value whose objects name each member once")
    }

    fn visit_bool<E>(self, v: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> std::result::Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_u64<E>(self, v: u64) -> std::result::Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_f64<E>(self, v: f64) -> std::result::Result<Value, E> {
        // serde_json hands over finite numbers only (`1e400` fails before), as its own visitor gets them.
        Ok(Value::from(v))
    }

    fn visit_str<E>(self, v: &str) -> std::result::Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_unit<E>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(Distinct(item)) = seq.next_element()? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Value, A::Error> {
        let mut object = Map::new();
        while let Some(name) = map.next_key::<String>()? {
            if object.contains_key(&name) {
                return Err(de::Error::custom("an object names a member twice"));
            }
            let Distinct(value) = map.next_value()?;
            object.insert(name, value);
        }
        Ok(Value::Object(object))
    }
}

/// The value as a JSON integer from 0 to 2^53 - 1.
#[must_use]
pub fn canonical_integer(value: &Value) -> Option<u64> {
    value.as_u64().filter(|n| *n <= MAX_SAFE_INTEGER)
}

/// Whether the object's member names are exactly `keys`, in any order.
#[must_use]
pub fn has_exact_keys(object: &Map<String, Value>, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|k| object.contains_key(*k))
}

/// Whether the text is lowercase hex of an even length, of exactly `bytes` bytes when that is given.
#[must_use]
pub fn is_hex(text: &str, bytes: Option<usize>) -> bool {
    crate::hex::check(text).is_ok() && bytes.is_none_or(|n| text.len() == 2 * n)
}

/// A byte field: [`Code::BadShape`] when it is not a string, [`Code::BadHex`] when it is not hex of that length.
///
/// # Errors
///
/// [`Code::BadShape`], [`Code::BadHex`].
pub fn hex_field(value: Option<&Value>, bytes: Option<usize>) -> Result<String> {
    let text = value.and_then(Value::as_str).ok_or(Code::BadShape)?;
    if is_hex(text, bytes) { Ok(text.to_owned()) } else { Err(Code::BadHex) }
}

/// An address field: [`Code::BadShape`] when it is not a string, [`Code::BadAddress`] when it is not an address.
///
/// # Errors
///
/// [`Code::BadShape`], [`Code::BadAddress`].
pub fn address_field(value: Option<&Value>) -> Result<Address> {
    Address::parse(value.and_then(Value::as_str).ok_or(Code::BadShape)?)
}

/// The value as an address, if it is one.
pub(crate) fn address(value: Option<&Value>) -> Option<Address> {
    value.and_then(Value::as_str).and_then(|t| Address::parse(t).ok())
}

/// A JSON object written member by member, in the order the members are added.
pub(crate) struct Writer {
    out: String,
    first: bool,
}

impl Writer {
    pub(crate) fn object() -> Writer {
        Writer { out: String::from("{"), first: true }
    }

    fn key(&mut self, name: &str) {
        if !self.first {
            self.out.push(',');
        }
        self.first = false;
        write_str(&mut self.out, name);
        self.out.push(':');
    }

    pub(crate) fn str(mut self, name: &str, value: &str) -> Writer {
        self.key(name);
        write_str(&mut self.out, value);
        self
    }

    pub(crate) fn opt_str(mut self, name: &str, value: Option<&str>) -> Writer {
        self.key(name);
        match value {
            Some(v) => write_str(&mut self.out, v),
            None => self.out.push_str("null"),
        }
        self
    }

    pub(crate) fn int(mut self, name: &str, value: u64) -> Writer {
        self.key(name);
        let _ = write!(self.out, "{value}");
        self
    }

    pub(crate) fn strs<S: AsRef<str>>(mut self, name: &str, items: &[S]) -> Writer {
        self.key(name);
        self.out.push_str(&array(items.iter().map(|s| {
            let mut t = String::new();
            write_str(&mut t, s.as_ref());
            t
        })));
        self
    }

    /// A member whose value is JSON text written by the caller.
    pub(crate) fn raw(mut self, name: &str, json: &str) -> Writer {
        self.key(name);
        self.out.push_str(json);
        self
    }

    pub(crate) fn finish(mut self) -> String {
        self.out.push('}');
        self.out
    }
}

/// A JSON array of items that are JSON text already.
pub(crate) fn array(items: impl Iterator<Item = String>) -> String {
    let mut out = String::from("[");
    for (i, item) in items.enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&item);
    }
    out.push(']');
    out
}

#[cfg(test)]
mod tests;
