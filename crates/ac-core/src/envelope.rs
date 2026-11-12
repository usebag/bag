//! Envelopes (spec/SPEC.md §5): parsing with every check in its order, the id, the outer signature and the
//! timestamp window.
//!
//! A relay sees the outer members only. `sealed` is opaque here: its hash enters the id and its form is checked,
//! but it is never opened (no HPKE in this crate).
//!
//! * id = SHA-256 hex of `canonical([v, to, from, auth as [[iss, sub, caveats, exp, sig]...], suite, ts,
//!   sealedHash])`;
//! * sealedHash = SHA-256 hex of `canonical([wraps as [[to, enc, ct]...], nonce, ct])`;
//! * `sig` is by `from` over the 32 bytes of the id.

use crate::address::Address;
use crate::canonical::{MAX_SAFE_INTEGER, Value};
use crate::chain::Hop;
use crate::error::{Code, Result};
use crate::json;
use crate::keys::SigningKey;
use std::collections::BTreeSet;

/// The envelope format version, `v`.
pub const VERSION: u64 = 1;
/// The crypto suite: Ed25519, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.
pub const SUITE: u64 = 1;
/// The most recipients one envelope may name.
pub const MAX_RECIPIENTS: usize = 16;
/// The largest envelope, in bytes as received.
pub const MAX_ENVELOPE_BYTES: usize = 196_608;
/// The relay TTL, 7 days, and the clock skew.
pub const DEFAULT_TTL: u64 = 604_800;
/// The allowed clock skew, in seconds.
pub const DEFAULT_SKEW: u64 = 300;

const ENVELOPE_KEYS: [&str; 9] = ["v", "id", "to", "from", "auth", "suite", "ts", "sealed", "sig"];
const SEALED_KEYS: [&str; 3] = ["wraps", "nonce", "ct"];
const WRAP_KEYS: [&str; 3] = ["to", "enc", "ct"];

/// One recipient's wrap of the content key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wrap {
    /// The recipient.
    pub to: Address,
    /// The HPKE encapsulated key: 32 bytes of hex.
    pub enc: String,
    /// The wrapped content key: 48 bytes of hex.
    pub ct: String,
}

/// The sealed part, opaque to a relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    /// One wrap per recipient, in the order of `to`.
    pub wraps: Vec<Wrap>,
    /// The content nonce: 12 bytes of hex.
    pub nonce: String,
    /// The content ciphertext with its tag: at least 16 bytes of hex.
    pub ct: String,
}

impl Sealed {
    /// `[wraps as [[to, enc, ct]...], nonce, ct]`.
    #[must_use]
    pub fn preimage(&self) -> Value {
        Value::Array(vec![
            Value::Array(
                self.wraps
                    .iter()
                    .map(|w| {
                        Value::Array(vec![
                            Value::from(w.to.as_str()),
                            Value::from(w.enc.as_str()),
                            Value::from(w.ct.as_str()),
                        ])
                    })
                    .collect(),
            ),
            Value::from(self.nonce.as_str()),
            Value::from(self.ct.as_str()),
        ])
    }

    /// The sealed hash: SHA-256 hex of the canonical preimage.
    #[must_use]
    pub fn hash_hex(&self) -> String {
        // The preimage holds strings only, so its canonical text always exists.
        let text = crate::canonical::to_string(&self.preimage()).unwrap_or_default();
        crate::hash::sha256_hex(text.as_bytes())
    }

    fn to_json_text(&self) -> String {
        let wraps = json::array(self.wraps.iter().map(|w| {
            json::Writer::object().str("to", w.to.as_str()).str("enc", &w.enc).str("ct", &w.ct).finish()
        }));
        json::Writer::object().raw("wraps", &wraps).str("nonce", &self.nonce).str("ct", &self.ct).finish()
    }
}

/// An envelope's outer members and its sealed part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// The format version; 1.
    pub v: u64,
    /// The id as carried on the wire (checked by [`Envelope::check_id`]).
    pub id: [u8; 32],
    /// The recipients, 1 to 16, distinct.
    pub to: Vec<Address>,
    /// The signing key, the session key.
    pub from: Address,
    /// The authority chain, root first.
    pub auth: Vec<Hop>,
    /// The crypto suite; 1.
    pub suite: u64,
    /// When the sender built it, Unix seconds.
    pub ts: u64,
    /// The sealed part.
    pub sealed: Sealed,
    /// The signature by `from` over the id.
    pub sig: [u8; 64],
}

/// `v` or `suite`: [`Code::BadShape`] when not a number, `wrong` when not the integer `want`.
fn version_like(value: Option<&serde_json::Value>, want: u64, wrong: Code) -> Result<u64> {
    let number = value.filter(|v| v.is_number()).ok_or(Code::BadShape)?;
    if number.as_u64() == Some(want) { Ok(want) } else { Err(wrong) }
}

/// §5.4 step 8: a non-empty list of at most 16 distinct addresses.
fn recipients(value: Option<&serde_json::Value>) -> Result<Vec<Address>> {
    let list = value.and_then(serde_json::Value::as_array).filter(|l| !l.is_empty()).ok_or(Code::BadShape)?;
    if list.len() > MAX_RECIPIENTS {
        return Err(Code::TooManyRecipients);
    }
    let to = list.iter().map(|a| json::address_field(Some(a))).collect::<Result<Vec<_>>>()?;
    check_distinct(&to)?;
    Ok(to)
}

fn check_distinct(to: &[Address]) -> Result<()> {
    if to.iter().collect::<BTreeSet<_>>().len() == to.len() { Ok(()) } else { Err(Code::BadShape) }
}

/// §5.4 step 12: exactly `wraps`, `nonce` and `ct`; one wrap per recipient in the order of `to`.
fn sealed(value: Option<&serde_json::Value>, to: &[Address]) -> Result<Sealed> {
    let object = value.and_then(serde_json::Value::as_object).ok_or(Code::BadShape)?;
    if !json::has_exact_keys(object, &SEALED_KEYS) {
        return Err(Code::BadShape);
    }
    let list = object
        .get("wraps")
        .and_then(serde_json::Value::as_array)
        .filter(|l| l.len() == to.len())
        .ok_or(Code::BadShape)?;
    let mut wraps = Vec::with_capacity(list.len());
    for (w, recipient) in list.iter().zip(to) {
        let wrap = w.as_object().filter(|o| json::has_exact_keys(o, &WRAP_KEYS)).ok_or(Code::BadShape)?;
        if wrap.get("to").and_then(serde_json::Value::as_str) != Some(recipient.as_str()) {
            return Err(Code::BadShape);
        }
        let enc = json::hex_field(wrap.get("enc"), Some(32))?;
        let ct = json::hex_field(wrap.get("ct"), Some(48))?;
        wraps.push(Wrap { to: recipient.clone(), enc, ct });
    }
    let nonce = json::hex_field(object.get("nonce"), Some(12))?;
    let ct = json::hex_field(object.get("ct"), None)?;
    if ct.len() < 32 {
        return Err(Code::BadHex);
    }
    Ok(Sealed { wraps, nonce, ct })
}

impl Envelope {
    /// Parses envelope bytes with the envelope cap of the spec, 196,608 bytes (§5.4).
    ///
    /// # Errors
    ///
    /// As for [`Envelope::parse_with_cap`].
    pub fn parse(bytes: &[u8]) -> Result<Envelope> {
        Envelope::parse_with_cap(bytes, MAX_ENVELOPE_BYTES)
    }

    /// Parses envelope bytes: at most `cap` bytes (`envelope-too-large`), UTF-8 JSON (`bad-json`), then
    /// [`Envelope::from_json`]. A relay passes its configured cap.
    ///
    /// # Errors
    ///
    /// [`Code::EnvelopeTooLarge`], [`Code::BadJson`], then as for [`Envelope::from_json`].
    pub fn parse_with_cap(bytes: &[u8], cap: usize) -> Result<Envelope> {
        if bytes.len() > cap {
            return Err(Code::EnvelopeTooLarge);
        }
        Envelope::from_json(&json::parse(bytes)?)
    }

    /// Checks a parsed envelope in the order of §5.4, steps 3 to 13: an object; `v`; `suite`; exactly the nine
    /// members; `id`; `to`; `from`; `auth` (chain rules 1 to 4); `ts`; `sealed`; `sig`. Verifies no signature.
    ///
    /// # Errors
    ///
    /// The code of the first check that fails: [`Code::BadShape`], [`Code::BadVersion`], [`Code::BadSuite`],
    /// [`Code::BadHex`], [`Code::TooManyRecipients`], [`Code::BadAddress`], [`Code::TooManyHops`],
    /// [`Code::BadHop`], [`Code::TooManyCaveats`], [`Code::CaveatTooLong`].
    pub fn from_json(value: &serde_json::Value) -> Result<Envelope> {
        let object = value.as_object().ok_or(Code::BadShape)?;
        let v = version_like(object.get("v"), VERSION, Code::BadVersion)?;
        let suite = version_like(object.get("suite"), SUITE, Code::BadSuite)?;
        if !json::has_exact_keys(object, &ENVELOPE_KEYS) {
            return Err(Code::BadShape);
        }
        let id = json::hex_field(object.get("id"), Some(32))?;
        let to = recipients(object.get("to"))?;
        let from = json::address_field(object.get("from"))?;
        let auth = crate::chain::check_shape(object.get("auth"))?;
        let ts = object.get("ts").and_then(json::canonical_integer).ok_or(Code::BadShape)?;
        let sealed = sealed(object.get("sealed"), &to)?;
        let sig = json::hex_field(object.get("sig"), Some(64))?;
        Ok(Envelope {
            v,
            id: crate::hex::decode_array::<32>(&id)?,
            to,
            from,
            auth,
            suite,
            ts,
            sealed,
            sig: crate::hex::decode_array::<64>(&sig)?,
        })
    }

    /// `[v, to, from, auth as [[iss, sub, caveats, exp, sig]...], suite, ts, sealedHash]`.
    #[must_use]
    pub fn id_preimage(&self) -> Value {
        id_preimage(self.v, &self.to, &self.from, &self.auth, self.suite, self.ts, &self.sealed)
    }

    /// The id recomputed from the preimage.
    ///
    /// # Errors
    ///
    /// [`Code::BadCanonical`] for an integer over 2^53 - 1 (only an envelope built in code can hold one).
    pub fn compute_id(&self) -> Result<[u8; 32]> {
        crate::hash::digest(&self.id_preimage())
    }

    /// The carried id as lower-case hex.
    #[must_use]
    pub fn id_hex(&self) -> String {
        crate::hex::encode(&self.id)
    }

    /// §5.5 step 1: 1 to 16 distinct recipients (an envelope built in code may break it).
    ///
    /// # Errors
    ///
    /// [`Code::BadShape`] for none or a repeated one, [`Code::TooManyRecipients`] for over 16.
    pub fn check_recipients(&self) -> Result<()> {
        if self.to.is_empty() {
            return Err(Code::BadShape);
        }
        if self.to.len() > MAX_RECIPIENTS {
            return Err(Code::TooManyRecipients);
        }
        check_distinct(&self.to)
    }

    /// §5.5 step 2: the carried id recomputes.
    ///
    /// # Errors
    ///
    /// [`Code::BadId`].
    pub fn check_id(&self) -> Result<()> {
        if self.compute_id()? == self.id { Ok(()) } else { Err(Code::BadId) }
    }

    /// §5.5 step 3: `sig` is `from`'s signature over the 32 id bytes.
    ///
    /// # Errors
    ///
    /// [`Code::BadSig`].
    pub fn check_sig(&self) -> Result<()> {
        if crate::keys::verify(&self.from, &self.id, &self.sig) { Ok(()) } else { Err(Code::BadSig) }
    }

    /// §5.5 step 4: `now - (ttl + skew) <= ts <= now + skew`.
    ///
    /// # Errors
    ///
    /// [`Code::StaleTs`], then [`Code::FutureTs`].
    pub fn check_ts(&self, now: u64, ttl: u64, skew: u64) -> Result<()> {
        check_window(self.ts, now, ttl, skew)
    }

    /// The outer checks of §5.5 in order: the recipients, the id, the signature, the timestamp window. A relay
    /// runs the chain between the signature and the window, so it calls the steps itself.
    ///
    /// # Errors
    ///
    /// As for the four steps, in that order.
    pub fn verify_outer(&self, now: u64, ttl: u64, skew: u64) -> Result<()> {
        self.check_recipients()?;
        self.check_id()?;
        self.check_sig()?;
        self.check_ts(now, ttl, skew)
    }

    /// Builds and signs an envelope (for fixtures, tests and tools): `key`'s address becomes `from`, and the id
    /// and signature are computed. Like the TypeScript builder it checks what parsing would refuse in the
    /// recipients, the chain's shape and `ts`, not the chain's meaning (§5.6).
    ///
    /// # Errors
    ///
    /// [`Code::BadShape`] or [`Code::TooManyRecipients`] for the recipients, [`Code::BadShape`] for a `ts` over
    /// 2^53 - 1, the codes of chain rules 1 to 4.
    pub fn sign(
        key: &SigningKey,
        to: Vec<Address>,
        auth: Vec<Hop>,
        ts: u64,
        sealed: Sealed,
    ) -> Result<Envelope> {
        if ts > MAX_SAFE_INTEGER {
            return Err(Code::BadShape);
        }
        let mut env = Envelope {
            v: VERSION,
            id: [0; 32],
            to,
            from: key.address(),
            auth,
            suite: SUITE,
            ts,
            sealed,
            sig: [0; 64],
        };
        env.check_recipients()?;
        crate::chain::check_hops(&env.auth)?;
        env.id = env.compute_id()?;
        env.sig = key.sign(&env.id);
        Ok(env)
    }

    /// The envelope as wire JSON text, members in the order of §5.1 with no white space: the bytes
    /// `packages/core` writes for the same envelope.
    #[must_use]
    pub fn to_json_text(&self) -> String {
        let to: Vec<&str> = self.to.iter().map(Address::as_str).collect();
        let auth = json::array(self.auth.iter().map(Hop::to_json_text));
        json::Writer::object()
            .int("v", self.v)
            .str("id", &self.id_hex())
            .strs("to", &to)
            .str("from", self.from.as_str())
            .raw("auth", &auth)
            .int("suite", self.suite)
            .int("ts", self.ts)
            .raw("sealed", &self.sealed.to_json_text())
            .str("sig", &crate::hex::encode(&self.sig))
            .finish()
    }

    /// The wire bytes: [`Envelope::to_json_text`] as UTF-8.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_json_text().into_bytes()
    }
}

/// `now - (ttl + skew) <= ts` (`stale-ts`) and `ts <= now + skew` (`future-ts`), for an envelope's `ts` or a
/// fetch's `AC-Ts`.
///
/// # Errors
///
/// [`Code::StaleTs`], then [`Code::FutureTs`].
pub fn check_window(ts: u64, now: u64, ttl: u64, skew: u64) -> Result<()> {
    if ts.saturating_add(ttl).saturating_add(skew) < now {
        return Err(Code::StaleTs);
    }
    if ts > now.saturating_add(skew) {
        return Err(Code::FutureTs);
    }
    Ok(())
}

fn id_preimage(
    v: u64,
    to: &[Address],
    from: &Address,
    auth: &[Hop],
    suite: u64,
    ts: u64,
    sealed: &Sealed,
) -> Value {
    Value::Array(vec![
        Value::Int(v),
        Value::Array(to.iter().map(|a| Value::from(a.as_str())).collect()),
        Value::from(from.as_str()),
        Value::Array(auth.iter().map(Hop::id_entry).collect()),
        Value::Int(suite),
        Value::Int(ts),
        Value::Str(sealed.hash_hex()),
    ])
}

#[cfg(test)]
mod tests;
