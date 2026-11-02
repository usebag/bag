//! Authority chains: hops from a root to a signer, and the nine rules of spec/SPEC.md §6.2.
//!
//! A hop is `{"iss", "sub", "caveats", "exp", "sig"}`; `sig` is by `iss` over the digest of
//! `["ac/hop/1", iss, sub, caveats, exp]`. Each hop carries only the caveats it adds; the effective list is their
//! concatenation in chain order. Caveats are collected here and never evaluated: that is the edge's work, never the
//! relay's.
//!
//! The rules run in order, each over every hop before the next, and the first that fails gives the code:
//! 1 at most 8 hops (`too-many-hops`); 2 each hop well formed (`bad-hop`); 3 at most 32 caveats a hop
//! (`too-many-caveats`); 4 each caveat at most 256 UTF-8 bytes (`caveat-too-long`); 5 `hop[i].sub == hop[i+1].iss`
//! (`chain-broken`); 6 the last `sub` is the sender (`chain-not-to-sender`); 7 `hop[i+1].exp <= hop[i].exp`
//! (`exp-not-monotone`); 8 the time judged at is at most every `exp` (`hop-expired`); 9 every signature verifies
//! under its `iss` (`bad-hop-sig`). Rules 1 to 4 are the chain's shape, checked by parsing.

use crate::address::Address;
use crate::canonical::{MAX_SAFE_INTEGER, Value};
use crate::error::{Code, Result};
use crate::json;
use crate::keys::SigningKey;

/// The most hops a chain may have.
pub const MAX_HOPS: usize = 8;
/// The most caveats one hop may add.
pub const MAX_CAVEATS: usize = 32;
/// The longest caveat, in UTF-8 bytes.
pub const MAX_CAVEAT_BYTES: usize = 256;
/// The domain tag of a hop's preimage.
pub const HOP_TAG: &str = "ac/hop/1";

const HOP_KEYS: [&str; 5] = ["iss", "sub", "caveats", "exp", "sig"];

/// One hop: `iss` grants to `sub`, under the caveats this hop adds, until `exp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hop {
    /// The granting key.
    pub iss: Address,
    /// The key granted to.
    pub sub: Address,
    /// The caveats this hop adds: non-empty strings.
    pub caveats: Vec<String>,
    /// The end of the grant, in Unix seconds.
    pub exp: u64,
    /// The signature by `iss` over the hop's preimage digest.
    pub sig: [u8; 64],
}

impl Hop {
    /// `["ac/hop/1", iss, sub, caveats, exp]`.
    #[must_use]
    pub fn preimage(&self) -> Value {
        hop_preimage(&self.iss, &self.sub, &self.caveats, self.exp)
    }

    /// A hop from `key` to `sub`, signed.
    ///
    /// # Errors
    ///
    /// The codes of rules 2 to 4 for a hop that could not pass them: [`Code::BadHop`] (an empty caveat, an `exp`
    /// over 2^53 - 1), [`Code::TooManyCaveats`], [`Code::CaveatTooLong`].
    pub fn sign(key: &SigningKey, sub: &Address, caveats: Vec<String>, exp: u64) -> Result<Hop> {
        let iss = key.address();
        let unsigned = Hop { iss, sub: sub.clone(), caveats, exp, sig: [0; 64] };
        check_hops(std::slice::from_ref(&unsigned))?;
        let sig = key.sign_preimage(&unsigned.preimage())?;
        Ok(Hop { sig, ..unsigned })
    }

    /// The hop as it sits in an envelope's id preimage: `[iss, sub, caveats, exp, sig]`.
    #[must_use]
    pub fn id_entry(&self) -> Value {
        Value::Array(vec![
            Value::from(self.iss.as_str()),
            Value::from(self.sub.as_str()),
            Value::strings(&self.caveats),
            Value::Int(self.exp),
            Value::Str(crate::hex::encode(&self.sig)),
        ])
    }

    /// The hop as wire JSON text: `{"iss","sub","caveats","exp","sig"}`, in that order, with no white space.
    #[must_use]
    pub fn to_json_text(&self) -> String {
        json::Writer::object()
            .str("iss", self.iss.as_str())
            .str("sub", self.sub.as_str())
            .strs("caveats", &self.caveats)
            .int("exp", self.exp)
            .str("sig", &crate::hex::encode(&self.sig))
            .finish()
    }
}

/// `["ac/hop/1", iss, sub, caveats, exp]`.
#[must_use]
pub fn hop_preimage(iss: &Address, sub: &Address, caveats: &[String], exp: u64) -> Value {
    Value::Array(vec![
        Value::from(HOP_TAG),
        Value::from(iss.as_str()),
        Value::from(sub.as_str()),
        Value::strings(caveats),
        Value::Int(exp),
    ])
}

/// Rule 2 on wire JSON: an object with exactly the five members, `iss` and `sub` addresses, `caveats` a list of
/// non-empty strings, `exp` a canonical integer, `sig` 64 bytes of hex.
fn well_formed(value: &serde_json::Value) -> Option<Hop> {
    let object = value.as_object().filter(|o| json::has_exact_keys(o, &HOP_KEYS))?;
    let iss = json::address(object.get("iss"))?;
    let sub = json::address(object.get("sub"))?;
    let caveats = object
        .get("caveats")?
        .as_array()?
        .iter()
        .map(|c| c.as_str().filter(|s| !s.is_empty()).map(str::to_owned))
        .collect::<Option<Vec<_>>>()?;
    let exp = json::canonical_integer(object.get("exp")?)?;
    let sig = object.get("sig")?.as_str().filter(|s| json::is_hex(s, Some(64)))?;
    Some(Hop { iss, sub, caveats, exp, sig: crate::hex::decode_array::<64>(sig).ok()? })
}

/// Rules 3 and 4, each over every hop before the next.
fn check_caps(hops: &[Hop]) -> Result<()> {
    if hops.iter().any(|h| h.caveats.len() > MAX_CAVEATS) {
        return Err(Code::TooManyCaveats);
    }
    if hops.iter().any(|h| h.caveats.iter().any(|c| c.len() > MAX_CAVEAT_BYTES)) {
        return Err(Code::CaveatTooLong);
    }
    Ok(())
}

/// Rules 1 to 4 on hops built in code: what parsing would refuse.
///
/// # Errors
///
/// [`Code::TooManyHops`], [`Code::BadHop`] (an empty caveat, an `exp` over 2^53 - 1), [`Code::TooManyCaveats`],
/// [`Code::CaveatTooLong`].
pub fn check_hops(hops: &[Hop]) -> Result<()> {
    if hops.len() > MAX_HOPS {
        return Err(Code::TooManyHops);
    }
    if hops.iter().any(|h| h.exp > MAX_SAFE_INTEGER || h.caveats.iter().any(String::is_empty)) {
        return Err(Code::BadHop);
    }
    check_caps(hops)
}

/// Rules 1 to 4 on wire JSON (an envelope's `auth`, an `AC-Auth` header, a subscriber's `auth`).
///
/// # Errors
///
/// [`Code::BadShape`] when `auth` is not a list, then [`Code::TooManyHops`], [`Code::BadHop`],
/// [`Code::TooManyCaveats`], [`Code::CaveatTooLong`].
pub fn check_shape(auth: Option<&serde_json::Value>) -> Result<Vec<Hop>> {
    let list = auth.and_then(serde_json::Value::as_array).ok_or(Code::BadShape)?;
    if list.len() > MAX_HOPS {
        return Err(Code::TooManyHops);
    }
    let hops = list.iter().map(well_formed).collect::<Option<Vec<_>>>().ok_or(Code::BadHop)?;
    check_caps(&hops)?;
    Ok(hops)
}

/// Parses JSON text holding a list of hops, with rules 1 to 4.
///
/// # Errors
///
/// [`Code::BadJson`] when the text is not JSON, then as for [`check_shape`].
pub fn parse_hops_json(text: &str) -> Result<Vec<Hop>> {
    check_shape(Some(&json::parse(text.as_bytes())?))
}

/// What a valid chain establishes (spec/SPEC.md §6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The first hop's `iss`, or the subject for an empty chain (self-rooted).
    pub root: Address,
    /// The key the chain names as acting through the subject: the last hop's `iss`, or the subject.
    pub principal: Address,
    /// Every hop's caveats, concatenated in chain order. Never evaluated here.
    pub caveats: Vec<String>,
}

/// Verifies a chain that ends at `subject` (an envelope's `from`, a fetch or subscribe signer), judged at `at`
/// (the envelope's `ts`, the request's `AC-Ts`, the challenge's `ts`), by the nine rules in order.
///
/// # Errors
///
/// The rule codes, in rule order: [`Code::TooManyHops`], [`Code::BadHop`], [`Code::TooManyCaveats`],
/// [`Code::CaveatTooLong`], [`Code::ChainBroken`], [`Code::ChainNotToSender`], [`Code::ExpNotMonotone`],
/// [`Code::HopExpired`], [`Code::BadHopSig`].
pub fn verify(subject: &Address, at: u64, hops: &[Hop]) -> Result<Verified> {
    check_hops(hops)?;
    let (Some(first), Some(last)) = (hops.first(), hops.last()) else {
        return Ok(Verified { root: subject.clone(), principal: subject.clone(), caveats: Vec::new() });
    };
    if hops.windows(2).any(|w| w[0].sub != w[1].iss) {
        return Err(Code::ChainBroken);
    }
    if &last.sub != subject {
        return Err(Code::ChainNotToSender);
    }
    if hops.windows(2).any(|w| w[1].exp > w[0].exp) {
        return Err(Code::ExpNotMonotone);
    }
    if hops.iter().any(|h| at > h.exp) {
        return Err(Code::HopExpired);
    }
    for hop in hops {
        let digest = crate::hash::digest(&hop.preimage())?;
        if !crate::keys::verify(&hop.iss, &digest, &hop.sig) {
            return Err(Code::BadHopSig);
        }
    }
    Ok(Verified {
        root: first.iss.clone(),
        principal: last.iss.clone(),
        caveats: hops.iter().flat_map(|h| h.caveats.iter().cloned()).collect(),
    })
}

#[cfg(test)]
mod tests;
