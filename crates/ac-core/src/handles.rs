//! Handles (spec/SPEC.md §12.3 and §12.4, L2):
//! `jane@acme.example` names an address under an org's domain, bound by a handle record that the org's key signs. A
//! handle finds an address and admits no one.
//!
//! * the record: `{kind: "handle", org, handle, address, iat, ttl, sig}`, `ttl` 1 to 86,400 s, signed by `org` over
//!   `["ac/handle/1", org, handle, address, iat, ttl]`;
//! * served by the org at its one origin (§12.1), `<origin>/.well-known/bag/handles/<local>.json`, never by a
//!   relay;
//! * checked in order: form (`bad-record`), signature (`bad-record-sig`), `future-iat`, `record-expired`, the org key
//!   and the handle against the ones the reader resolves (`resolve-failed`), the address against the org's revoked
//!   list (`revoked`).
//!
//! The relay stores no handle record: [`crate::records::Record::parse`] refuses its kind, `bad-record`.

use crate::address::Address;
use crate::canonical::{MAX_SAFE_INTEGER, Value};
use crate::error::{Code, Result};
use crate::json;
use crate::keys::SigningKey;
use crate::records::{Domain, MAX_ADDRESS_TTL};
use serde_json::Value as Json;
use std::fmt;

/// The domain tag of a handle record's preimage.
pub const HANDLE_TAG: &str = "ac/handle/1";
/// Where an org serves its handle records, under its one origin (§12.1); then `<local>.json`.
pub const HANDLES_PATH: &str = "/.well-known/bag/handles/";
/// The longest local part of a handle, in characters.
pub const MAX_HANDLE_LOCAL: usize = 64;
/// The kind of a handle record.
pub const HANDLE_KIND: &str = "handle";
/// The special-use top-level names a handle's domain may not end in: they name no org on the public DNS (`.local`
/// mDNS, RFC 6762; `.localhost` and `.invalid`, RFC 6761; `.onion`, RFC 7686; `.alt`, RFC 9476; `.arpa`, RFC 3172;
/// `.internal`, ICANN's private-use name). Added 2026-10-26.
pub const SPECIAL_USE_TLDS: [&str; 7] = ["alt", "arpa", "internal", "invalid", "local", "localhost", "onion"];

/// Whether a domain's last label is one of [`SPECIAL_USE_TLDS`]: no handle names it, and no TXT record is asked for it
/// (§12.2 item 4).
#[must_use]
pub fn is_special_use(domain: &Domain) -> bool {
    SPECIAL_USE_TLDS.contains(&domain.as_str().rsplit('.').next().unwrap_or_default())
}

const HANDLE_KEYS: [&str; 7] = ["kind", "org", "handle", "address", "iat", "ttl", "sig"];

/// A handle, `<local>@<domain>`: the local part 1 to 64 of `a`-`z`, `0`-`9`, `.`, `-` and `_`, from and to a letter or
/// a digit (so that no handle maps to a dot file), and a domain root's host whose last label is not one of
/// [`SPECIAL_USE_TLDS`].
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Handle {
    local: String,
    domain: Domain,
}

fn is_local(local: &str) -> bool {
    let b = local.as_bytes();
    let inner = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'-' | b'_');
    let edge = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    (1..=MAX_HANDLE_LOCAL).contains(&b.len()) && b.iter().all(inner) && edge(b[0]) && edge(b[b.len() - 1])
}

impl Handle {
    /// Reads a handle.
    ///
    /// # Errors
    ///
    /// [`Code::BadAddress`] for anything else, an address included (where a handle or an address may stand).
    pub fn parse(text: &str) -> Result<Handle> {
        let (local, domain) = text.split_once('@').ok_or(Code::BadAddress)?;
        if !is_local(local) {
            return Err(Code::BadAddress);
        }
        let domain = Domain::parse(domain).map_err(|_| Code::BadAddress)?;
        if is_special_use(&domain) {
            return Err(Code::BadAddress);
        }
        Ok(Handle { local: local.to_owned(), domain })
    }

    /// The local part.
    #[must_use]
    pub fn local(&self) -> &str {
        &self.local
    }

    /// The domain.
    #[must_use]
    pub fn domain(&self) -> &Domain {
        &self.domain
    }

    /// The path of its record under its domain's origin: `/.well-known/bag/handles/<local>.json`.
    #[must_use]
    pub fn path(&self) -> String {
        format!("{HANDLES_PATH}{}.json", self.local)
    }
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.local, self.domain)
    }
}

impl fmt::Debug for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Handle({self})")
    }
}

/// A handle record: `org`'s word that `handle` names `address`, valid from `iat` to `iat + ttl`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleRecord {
    /// The org key that signs it.
    pub org: Address,
    /// The handle it binds.
    pub handle: Handle,
    /// The address the handle names.
    pub address: Address,
    /// When it was issued.
    pub iat: u64,
    /// How long it may be used: 1 to 86,400 s from `iat`.
    pub ttl: u64,
    /// The signature by `org`.
    pub sig: [u8; 64],
}

fn bad(ok: bool) -> Result<()> {
    if ok { Ok(()) } else { Err(Code::BadRecord) }
}

impl HandleRecord {
    /// Parses handle record bytes: UTF-8 JSON (`bad-json`), then [`HandleRecord::from_json`].
    ///
    /// # Errors
    ///
    /// [`Code::BadJson`], then [`Code::BadRecord`].
    pub fn parse(bytes: &[u8]) -> Result<HandleRecord> {
        HandleRecord::from_json(&json::parse(bytes)?)
    }

    /// Checks a parsed handle record's form (§12.4 item 1), not its signature or time.
    ///
    /// # Errors
    ///
    /// [`Code::BadRecord`].
    pub fn from_json(value: &Json) -> Result<HandleRecord> {
        let v = value.as_object().ok_or(Code::BadRecord)?;
        bad(v.get("kind").and_then(Json::as_str) == Some(HANDLE_KIND))?;
        bad(json::has_exact_keys(v, &HANDLE_KEYS))?;
        let org = json::address(v.get("org")).ok_or(Code::BadRecord)?;
        let handle = v.get("handle").and_then(Json::as_str).ok_or(Code::BadRecord)?;
        let handle = Handle::parse(handle).map_err(|_| Code::BadRecord)?;
        let address = json::address(v.get("address")).ok_or(Code::BadRecord)?;
        let iat = v.get("iat").and_then(json::canonical_integer).ok_or(Code::BadRecord)?;
        let ttl = v.get("ttl").and_then(json::canonical_integer).ok_or(Code::BadRecord)?;
        bad((1..=MAX_ADDRESS_TTL).contains(&ttl))?;
        let sig = v
            .get("sig")
            .and_then(Json::as_str)
            .filter(|s| json::is_hex(s, Some(64)))
            .ok_or(Code::BadRecord)?;
        let sig = crate::hex::decode_array::<64>(sig)?;
        Ok(HandleRecord { org, handle, address, iat, ttl, sig })
    }

    fn check_form(&self) -> Result<()> {
        bad((1..=MAX_ADDRESS_TTL).contains(&self.ttl) && self.iat <= MAX_SAFE_INTEGER)
    }

    /// `["ac/handle/1", org, handle, address, iat, ttl]`.
    #[must_use]
    pub fn preimage(&self) -> Value {
        Value::Array(vec![
            Value::from(HANDLE_TAG),
            Value::from(self.org.as_str()),
            Value::from(self.handle.to_string()),
            Value::from(self.address.as_str()),
            Value::Int(self.iat),
            Value::Int(self.ttl),
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

    /// Signs the record with the org's key.
    ///
    /// # Errors
    ///
    /// [`Code::BadKey`] when `key` is not `org`, [`Code::BadRecord`] for a record that breaks its form.
    pub fn sign(&mut self, key: &SigningKey) -> Result<()> {
        if key.address() != self.org {
            return Err(Code::BadKey);
        }
        self.check_form()?;
        self.sig = key.sign_preimage(&self.preimage())?;
        Ok(())
    }

    /// Verifies the record for a reader that resolves `handle` of a domain whose current key is `org`, at `now`
    /// (§12.4 item 3), in order: its form; its signature under its own `org` (`bad-record-sig`); `iat <= now + skew`
    /// (`future-iat`); `now <= iat + ttl` (`record-expired`); its org and handle against the expected ones
    /// (`resolve-failed`); its address against the org's `revoked` list (`revoked`).
    ///
    /// # Errors
    ///
    /// [`Code::BadRecord`], [`Code::BadRecordSig`], [`Code::FutureIat`], [`Code::RecordExpired`],
    /// [`Code::ResolveFailed`], [`Code::Revoked`].
    pub fn verify(
        &self,
        org: &Address,
        handle: &Handle,
        revoked: &[Address],
        now: u64,
        skew: u64,
    ) -> Result<()> {
        self.check_form()?;
        let digest = crate::hash::digest(&self.preimage()).map_err(|_| Code::BadRecord)?;
        if !crate::keys::verify(&self.org, &digest, &self.sig) {
            return Err(Code::BadRecordSig);
        }
        if self.iat > now.saturating_add(skew) {
            return Err(Code::FutureIat);
        }
        if now > self.iat.saturating_add(self.ttl) {
            return Err(Code::RecordExpired);
        }
        if self.org != *org || self.handle != *handle {
            return Err(Code::ResolveFailed);
        }
        if revoked.contains(&self.address) { Err(Code::Revoked) } else { Ok(()) }
    }

    /// The record as wire JSON text, members in wire order with no white space: the bytes `packages/core` writes.
    #[must_use]
    pub fn to_json_text(&self) -> String {
        json::Writer::object()
            .str("kind", HANDLE_KIND)
            .str("org", self.org.as_str())
            .str("handle", &self.handle.to_string())
            .str("address", self.address.as_str())
            .int("iat", self.iat)
            .int("ttl", self.ttl)
            .str("sig", &crate::hex::encode(&self.sig))
            .finish()
    }
}

#[cfg(test)]
mod tests;
