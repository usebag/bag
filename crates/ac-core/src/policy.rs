//! The served org policy record: what an org's root signs for senders to comply
//! with, its scopes and what an external chain must carry. Read and verified alike with `packages/core/src/policy.ts`
//! over the shared table `spec/drafts/policy-vectors.json`. The org's members record (its roots, rates, outbound rules
//! and moderation) is never served, so no relay reads it and this crate has no reader for it. Not a record kind of
//! [`crate::records`] until the draft enters the spec; the relay enforces no part of it yet.

use crate::address::Address;
use crate::canonical::{MAX_SAFE_INTEGER, Value};
use crate::chain::{MAX_CAVEAT_BYTES, MAX_HOPS};
use crate::envelope::MAX_ENVELOPE_BYTES;
use crate::error::{Code, Result};
use crate::json;
use serde_json::{Map, Value as Json};
use std::collections::BTreeSet;

/// The domain tag of the served policy record's preimage.
pub const POLICY_TAG: &str = "ac/policy/1";
/// The code of a refusal by a policy rule that no other code names: the draft's addition to Appendix A, the edge's
/// own (never a relay's answer), written here until it joins [`Code`].
pub const POLICY_REFUSED: &str = "policy-refused";
/// The most scopes.
pub const MAX_SCOPES: usize = 32;
/// The most patterns of `accept_types` and of `required_caveats`.
pub const MAX_PATTERNS: usize = 32;

const KEYS: [&str; 7] = ["kind", "key", "scopes", "external", "inspection", "iat", "sig"];

/// One scope: the incoming chains whose effective caveats match `pattern`, the types they may carry, their size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    /// `*`, an exact caveat, or `<name>=*` (the record's `match`).
    pub pattern: String,
    /// The type patterns accepted.
    pub accept_types: Vec<String>,
    /// The largest envelope, in bytes.
    pub max_bytes: u64,
}

/// What a chain rooted outside the org must carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct External {
    /// Caveat patterns that must each match an effective caveat.
    pub required_caveats: Vec<String>,
    /// The longest `exp - ts` of any hop, in seconds.
    pub max_hop_lifetime: Option<u64>,
    /// The most hops.
    pub max_hops: Option<u64>,
}

/// A served org policy record. `inspection` is reserved and always null, so it has no field here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRecord {
    /// The org root, which signs it.
    pub key: Address,
    /// The scopes, in order.
    pub scopes: Vec<Scope>,
    /// The external-chain section.
    pub external: Option<External>,
    /// When it was issued; a newer one replaces it, and it does not expire.
    pub iat: u64,
    /// The signature of `key`.
    pub sig: [u8; 64],
}

fn object<'a>(value: &'a Json, keys: &[&str]) -> Result<&'a Map<String, Json>> {
    value.as_object().filter(|o| json::has_exact_keys(o, keys)).ok_or(Code::BadRecord)
}

fn nullable<T>(value: Option<&Json>, read: impl Fn(&Json) -> Result<T>) -> Result<Option<T>> {
    match value {
        Some(Json::Null) => Ok(None),
        Some(v) => read(v).map(Some),
        None => Err(Code::BadRecord),
    }
}

fn int(value: Option<&Json>, min: u64, max: u64) -> Result<u64> {
    value.and_then(json::canonical_integer).filter(|n| (min..=max).contains(n)).ok_or(Code::BadRecord)
}

fn strings(value: Option<&Json>, min: usize, test: impl Fn(&str) -> bool) -> Result<Vec<String>> {
    let list = value.and_then(Json::as_array).filter(|l| (min..=MAX_PATTERNS).contains(&l.len()));
    let texts: Vec<String> = list
        .ok_or(Code::BadRecord)?
        .iter()
        .map(|v| v.as_str().filter(|s| test(s)).map(str::to_owned))
        .collect::<Option<_>>()
        .ok_or(Code::BadRecord)?;
    if texts.iter().collect::<BTreeSet<_>>().len() == texts.len() { Ok(texts) } else { Err(Code::BadRecord) }
}

fn is_caveat_text(text: &str) -> bool {
    !text.is_empty() && text.len() <= MAX_CAVEAT_BYTES
}

/// Whether the text is a caveat pattern: `*` (when `star`), an exact caveat, or `<name>=*`.
#[must_use]
pub fn is_caveat_pattern(text: &str, star: bool) -> bool {
    (star && text == "*") || (text != "*" && text != "=*" && is_caveat_text(text))
}

/// Whether the text is a type pattern: `*`, `<prefix>.*` or an exact type, with no other `*`.
#[must_use]
pub fn is_type_pattern(text: &str) -> bool {
    let name = text.strip_suffix(".*").unwrap_or(text);
    text == "*" || (is_caveat_text(text) && !name.is_empty() && !name.contains('*'))
}

/// Whether one of `caveats` matches the pattern: `*` always, `<name>=*` by its prefix, any other exactly.
#[must_use]
pub fn matches_caveat(pattern: &str, caveats: &[String]) -> bool {
    match pattern.strip_suffix('*').filter(|p| p.ends_with('=')) {
        _ if pattern == "*" => true,
        Some(prefix) => caveats.iter().any(|c| c.starts_with(prefix)),
        None => caveats.iter().any(|c| c == pattern),
    }
}

/// Whether `ty` matches a type pattern: `*` any, `<prefix>.*` by its prefix and dot, any other exactly.
#[must_use]
pub fn type_matches(pattern: &str, ty: &str) -> bool {
    pattern == "*"
        || pattern.strip_suffix('*').filter(|p| p.ends_with('.')).map_or(ty == pattern, |p| ty.starts_with(p))
}

fn scope(value: &Json) -> Result<Scope> {
    let v = object(value, &["match", "accept_types", "max_bytes"])?;
    let pattern = v.get("match").and_then(Json::as_str).filter(|p| is_caveat_pattern(p, true));
    Ok(Scope {
        pattern: pattern.ok_or(Code::BadRecord)?.to_owned(),
        accept_types: strings(v.get("accept_types"), 1, is_type_pattern)?,
        max_bytes: int(v.get("max_bytes"), 1, MAX_ENVELOPE_BYTES as u64)?,
    })
}

fn external(value: &Json) -> Result<External> {
    let v = object(value, &["required_caveats", "max_hop_lifetime", "max_hops"])?;
    Ok(External {
        required_caveats: strings(v.get("required_caveats"), 0, |p| is_caveat_pattern(p, false))?,
        max_hop_lifetime: nullable(v.get("max_hop_lifetime"), |x| int(Some(x), 1, MAX_SAFE_INTEGER))?,
        max_hops: nullable(v.get("max_hops"), |x| int(Some(x), 0, MAX_HOPS as u64))?,
    })
}

impl PolicyRecord {
    /// Parses record bytes: UTF-8 JSON (`bad-json`), then [`PolicyRecord::from_json`].
    ///
    /// # Errors
    ///
    /// [`Code::BadJson`], then [`Code::BadRecord`].
    pub fn parse(bytes: &[u8]) -> Result<PolicyRecord> {
        PolicyRecord::from_json(&json::parse(bytes)?)
    }

    /// Checks a parsed record's form and caps, not its signature or time. A deny list, a rate, an outbound rule or
    /// a moderation section is no member of a served record, so one is `bad-record`.
    ///
    /// # Errors
    ///
    /// [`Code::BadRecord`] for any member that breaks its form or cap.
    pub fn from_json(value: &Json) -> Result<PolicyRecord> {
        let v = object(value, &KEYS)?;
        let kind = v.get("kind").and_then(Json::as_str) == Some("policy");
        let key = json::address(v.get("key")).filter(|_| kind).ok_or(Code::BadRecord)?;
        let iat = int(v.get("iat"), 0, MAX_SAFE_INTEGER)?;
        let sig = v.get("sig").and_then(Json::as_str).filter(|s| json::is_hex(s, Some(64)));
        let sig = crate::hex::decode_array::<64>(sig.ok_or(Code::BadRecord)?)?;
        let scopes = v.get("scopes").and_then(Json::as_array).filter(|s| s.len() <= MAX_SCOPES);
        let scopes = scopes.ok_or(Code::BadRecord)?.iter().map(scope).collect::<Result<_>>()?;
        if v.get("inspection") != Some(&Json::Null) {
            return Err(Code::BadRecord);
        }
        Ok(PolicyRecord { key, scopes, external: nullable(v.get("external"), external)?, iat, sig })
    }

    /// `["ac/policy/1", key, scopes, external, inspection, iat]`, each section a fixed-position list or null.
    #[must_use]
    pub fn preimage(&self) -> Value {
        let scopes = self.scopes.iter().map(|s| {
            Value::Array(vec![s.pattern.as_str().into(), Value::strings(&s.accept_types), s.max_bytes.into()])
        });
        let external = self.external.as_ref().map_or(Value::Null, |e| {
            let n = |v: Option<u64>| v.map_or(Value::Null, Value::Int);
            Value::Array(vec![Value::strings(&e.required_caveats), n(e.max_hop_lifetime), n(e.max_hops)])
        });
        Value::Array(vec![
            Value::from(POLICY_TAG),
            Value::from(self.key.as_str()),
            Value::Array(scopes.collect()),
            external,
            Value::Null,
            Value::Int(self.iat),
        ])
    }

    /// The digest the record's signature covers, as hex.
    ///
    /// # Errors
    ///
    /// [`Code::BadCanonical`] for an integer over 2^53 - 1 (only a record built in code can hold one).
    pub fn digest_hex(&self) -> Result<String> {
        Ok(crate::hex::encode(&crate::hash::digest(&self.preimage())?))
    }

    /// Verifies the record at `now`, in order: its signature by `key` (`bad-record-sig`) and `iat <= now + skew`
    /// (`future-iat`). Its form was checked when it was read; it does not expire, a newer `iat` replacing it.
    ///
    /// # Errors
    ///
    /// [`Code::BadRecordSig`], [`Code::FutureIat`].
    pub fn verify(&self, now: u64, skew: u64) -> Result<()> {
        let digest = crate::hash::digest(&self.preimage()).map_err(|_| Code::BadRecord)?;
        if !crate::keys::verify(&self.key, &digest, &self.sig) {
            return Err(Code::BadRecordSig);
        }
        if self.iat > now.saturating_add(skew) { Err(Code::FutureIat) } else { Ok(()) }
    }
}

#[cfg(test)]
mod tests;
