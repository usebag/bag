//! The canonical form: a fixed-position JSON array, serialized byte for byte as JavaScript's `JSON.stringify`
//! writes it (spec/SPEC.md §2).
//!
//! Values are strings, integers from 0 to 2^53 - 1, `null` and arrays, nothing else. Arrays are written `[a,b]`
//! with no white space. Strings escape exactly what `JSON.stringify` escapes: `"` as `\"`, `\` as `\\`, U+0008 as
//! `\b`, U+0009 as `\t`, U+000A as `\n`, U+000C as `\f`, U+000D as `\r`, every other code point below U+0020 as
//! `\u00xx` in lower-case hex, and everything else as raw UTF-8 (no Unicode normalization). A Rust string cannot
//! hold a lone surrogate, so the rule that rejects one holds by construction; JSON text that escapes one fails to
//! parse before it gets here. The serializer is written by hand: no JSON library decides these bytes.

use crate::error::{Code, Result};
use std::fmt::Write as _;

/// The largest integer the canonical form allows: 2^53 - 1, JavaScript's `Number.MAX_SAFE_INTEGER`.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// A value of the canonical form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// A string.
    Str(String),
    /// An integer; it must be at most [`MAX_SAFE_INTEGER`] to serialize.
    Int(u64),
    /// `null`, only where the spec allows it.
    Null,
    /// An array of values.
    Array(Vec<Value>),
}

impl Value {
    /// A string value, or `null` for `None`.
    #[must_use]
    pub fn opt_str(text: Option<&str>) -> Value {
        text.map_or(Value::Null, Value::from)
    }

    /// An array of string values.
    #[must_use]
    pub fn strings<S: AsRef<str>>(items: &[S]) -> Value {
        Value::Array(items.iter().map(|s| Value::from(s.as_ref())).collect())
    }
}

impl From<&str> for Value {
    fn from(text: &str) -> Value {
        Value::Str(text.to_owned())
    }
}

impl From<String> for Value {
    fn from(text: String) -> Value {
        Value::Str(text)
    }
}

impl From<u64> for Value {
    fn from(n: u64) -> Value {
        Value::Int(n)
    }
}

impl From<Vec<Value>> for Value {
    fn from(items: Vec<Value>) -> Value {
        Value::Array(items)
    }
}

/// The canonical text of `value`.
///
/// # Errors
///
/// [`Code::BadCanonical`] when an integer anywhere in `value` is over [`MAX_SAFE_INTEGER`].
pub fn to_string(value: &Value) -> Result<String> {
    let mut out = String::new();
    write_value(&mut out, value)?;
    Ok(out)
}

/// The canonical bytes of `value` (its text as UTF-8).
///
/// # Errors
///
/// As for [`to_string`].
pub fn to_bytes(value: &Value) -> Result<Vec<u8>> {
    to_string(value).map(String::into_bytes)
}

fn write_value(out: &mut String, value: &Value) -> Result<()> {
    match value {
        Value::Str(text) => write_str(out, text),
        Value::Int(n) => {
            if *n > MAX_SAFE_INTEGER {
                return Err(Code::BadCanonical);
            }
            // Writing to a String cannot fail.
            let _ = write!(out, "{n}");
        }
        Value::Null => out.push_str("null"),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item)?;
            }
            out.push(']');
        }
    }
    Ok(())
}

/// Appends `text` as a JSON string exactly as `JSON.stringify` writes it.
pub fn write_str(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The canonical value of parsed JSON: strings, integers in range, `null` and arrays of them.
///
/// # Errors
///
/// [`Code::BadCanonical`] for a boolean, an object, a negative number, a number with a fraction or exponent, and an
/// integer over [`MAX_SAFE_INTEGER`] (spec/SPEC.md §2.1).
pub fn from_json(json: &serde_json::Value) -> Result<Value> {
    match json {
        serde_json::Value::String(text) => Ok(Value::Str(text.clone())),
        serde_json::Value::Number(n) => match n.as_u64() {
            Some(v) if v <= MAX_SAFE_INTEGER => Ok(Value::Int(v)),
            _ => Err(Code::BadCanonical),
        },
        serde_json::Value::Null => Ok(Value::Null),
        serde_json::Value::Array(items) => {
            items.iter().map(from_json).collect::<Result<Vec<_>>>().map(Value::Array)
        }
        serde_json::Value::Bool(_) | serde_json::Value::Object(_) => Err(Code::BadCanonical),
    }
}

#[cfg(test)]
mod tests;
