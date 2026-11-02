//! Who may read (spec/SPEC.md §8.3 to §8.5).
//!
//! * fetch: `AC-Signer`, `AC-Ts` and `AC-Sig` over `["ac/fetch/1", signer, id, ts, audience]`, and an optional
//!   `AC-Auth`: the hops as UTF-8 JSON in base64url. The relay rebuilds the preimage from the canonical signer of
//!   `AC-Signer`, the id of the path (64 lower-case hex, else 400 `bad-hex`), `AC-Ts`, and each of its own public base
//!   URLs as `audience` ([`crate::config::Config::audiences`]), byte for byte; no header names the audience. A
//!   missing or malformed header, or a signature that verifies for none of them, is 401 `bad-auth`: a proof made for
//!   another relay, or over the four fields before 2026-11-02, with no window in which both pass (added 2026-11-02).
//!   `AC-Ts` outside the skew is 401 `stale-ts` or `future-ts`. The chain is verified for the
//!   signer at `AC-Ts`, and its root (the signer itself without a chain) must be a party of the envelope: its
//!   `from`, one of its `to`, or its principal, the last hop's `iss`, so that a principal
//!   reads what its sessions sent; otherwise 403 `not-authorized`, the org root of a longer chain included. An id
//!   the relay does not hold is 404 `not-found`. Since 2026-10-26 a chain from a party is
//!   403 `revoked` when the revoked list the relay keeps for its root names a hop's `iss` or `sub`. The answer is the
//!   exact stored bytes with `AC-Received-At`, the second the relay stored them.
//! * subscribe: `{"t":"auth","mailbox","signer","auth":[hops],"cursor":int|null,"sig"}` with `sig` over
//!   `["ac/sub/1", nonce, signer, mailbox, cursor]`. A malformed frame or a signature that does not verify is
//!   `bad-auth`; the chain is verified for the signer at the challenge's `ts` (a chain code when it fails), its root
//!   must be the mailbox (`not-authorized`), and since 2026-10-26 no hop's `iss` or `sub` may be in the revoked
//!   list the relay keeps for the mailbox (`revoked`). The subscription lasts until the chain's earliest `exp`, or until a newer
//!   address record of the mailbox revokes a key of its chain (src/ws.rs).
//!
//! The kept list ([`crate::store::Store::revoked`]) is the `revoked` list of the newest address record of the key that
//! the relay has stored, kept past that record's expiry until a newer one replaces it.

use crate::metrics::{METRICS, STORE_CORRUPT, STORE_ERRORS};
use crate::relay::{Rejection, Relay};
use crate::store::{StoreError, StoredEnvelope};
use ac_core::chain::{self, Hop};
use ac_core::envelope::{Envelope, check_window};
use ac_core::records::Kind;
use ac_core::requests::{fetch_preimage, subscribe_preimage};
use ac_core::{Address, Code, hash, hex, json, keys};
use base64::Engine as _;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

/// base64url; the spec writes it without padding, and a padded header is read too.
const BASE64URL: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

const AUTH_KEYS: [&str; 6] = ["t", "mailbox", "signer", "auth", "cursor", "sig"];

/// The headers of a fetch, as received.
#[derive(Debug, Default, Clone, Copy)]
pub struct FetchHeaders<'a> {
    /// `AC-Signer`.
    pub signer: Option<&'a str>,
    /// `AC-Ts`.
    pub ts: Option<&'a str>,
    /// `AC-Sig`.
    pub sig: Option<&'a str>,
    /// `AC-Auth`.
    pub auth: Option<&'a str>,
}

/// A subscriber that answered the challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscriber {
    /// The mailbox it reads.
    pub mailbox: Address,
    /// The key that signed.
    pub signer: Address,
    /// The cursor it asked to resume after, or `None` for its stored ack.
    pub cursor: Option<u64>,
    /// The earliest `exp` of its chain, `None` for the mailbox key itself: the subscription ends once the relay's
    /// clock is past it.
    pub expires: Option<u64>,
    /// Its chain, empty for the mailbox key itself: the subscription ends once a newer address record of the mailbox
    /// revokes a key of it.
    pub hops: Vec<Hop>,
}

/// Unix seconds as ASCII digits, a canonical integer.
fn seconds(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok().filter(|n| *n <= ac_core::canonical::MAX_SAFE_INTEGER)
}

/// The hops of an `AC-Auth` header: base64url of UTF-8 JSON, a list of at most 8 well-formed hops.
///
/// # Errors
///
/// [`Code::BadAuth`] for anything that is not, the chain's shape codes included (a malformed header).
pub fn decode_auth_header(text: &str) -> Result<Vec<Hop>, Code> {
    let raw = BASE64URL.decode(text.trim()).map_err(|_| Code::BadAuth)?;
    let json = String::from_utf8(raw).map_err(|_| Code::BadAuth)?;
    chain::parse_hops_json(&json).map_err(|_| Code::BadAuth)
}

/// Encodes hops for an `AC-Auth` header: base64url, without padding, of their JSON.
#[must_use]
pub fn encode_auth_header(hops: &[Hop]) -> String {
    let json = format!("[{}]", hops.iter().map(Hop::to_json_text).collect::<Vec<_>>().join(","));
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
}

impl Relay {
    /// Whether the revoked list the relay keeps for `root` names a key of `hops`, a hop's `iss` or `sub`; an
    /// empty chain names none, and reads no list.
    ///
    /// # Errors
    ///
    /// A storage failure.
    pub fn revokes(&self, root: &Address, hops: &[Hop]) -> Result<bool, StoreError> {
        if hops.is_empty() {
            return Ok(false);
        }
        let list = self.store.revoked(root.as_str())?;
        Ok(hops.iter().any(|h| list.iter().any(|k| k == h.iss.as_str() || k == h.sub.as_str())))
    }

    /// The exact stored bytes of envelope `id` and when the relay stored them, for a signer that is a party to it
    /// (its `from`, a `to` or its principal) or holds a chain from one.
    ///
    /// # Errors
    ///
    /// 400 `bad-hex` for an id that is not 32 bytes of hex; 401 `bad-auth`, `stale-ts` or `future-ts`; 403
    /// `not-authorized`, or `revoked` for a chain whose root's kept list names a key of it; 404 `not-found`.
    pub fn fetch(&self, id: &str, headers: &FetchHeaders<'_>) -> Result<StoredEnvelope, Rejection> {
        if !json::is_hex(id, Some(32)) {
            return Err(Code::BadHex.into());
        }
        let bad_auth = || Rejection::new(Code::BadAuth);
        let signer = headers.signer.and_then(|s| Address::parse(s).ok()).ok_or_else(bad_auth)?;
        let ts = headers.ts.and_then(seconds).ok_or_else(bad_auth)?;
        let sig = headers.sig.and_then(|s| hex::decode_array::<64>(s).ok()).ok_or_else(bad_auth)?;
        let hops = headers.auth.map_or(Ok(Vec::new()), decode_auth_header)?;
        let signed_for = |audience: &str| {
            hash::digest(&fetch_preimage(&signer, id, ts, audience))
                .is_ok_and(|d| keys::verify(&signer, &d, &sig))
        };
        if !self.config.audiences().any(signed_for) {
            return Err(bad_auth());
        }
        check_window(ts, self.now(), 0, self.config.skew).map_err(Rejection::at_fetch)?;
        let verified = chain::verify(&signer, ts, &hops).map_err(|code| {
            tracing::info!(event = "fetch-chain-refused", code = %code, signer = %signer);
            Rejection::new(Code::NotAuthorized)
        })?;
        let stored = self.store.envelope(id, self.now())?.ok_or(Rejection::new(Code::NotFound))?;
        let env = Envelope::parse_with_cap(&stored.bytes, usize::MAX).map_err(|code| {
            tracing::error!(event = "store-corrupt", id, code = %code);
            METRICS.tick(STORE_CORRUPT);
            Rejection::internal()
        })?;
        // The principal: the last hop's `iss`, or `from` for an empty chain (spec/SPEC.md §1).
        let principal = env.auth.last().map_or(&env.from, |hop| &hop.iss);
        let root = &verified.root;
        if &env.from != root && !env.to.contains(root) && principal != root {
            return Err(Code::NotAuthorized.into());
        }
        if self.revokes(root, &hops)? {
            return Err(Code::Revoked.into());
        }
        Ok(stored)
    }

    /// The latest stored record of `kind` for `address`; records are public (§8.4).
    ///
    /// # Errors
    ///
    /// 400 `bad-address` for a malformed address; 404 `not-found` for an unknown kind or no record.
    pub fn fetch_record(&self, address: &str, kind: &str) -> Result<Vec<u8>, Rejection> {
        let address = Address::parse(address)?;
        let Some(kind) = Kind::from_wire(kind) else {
            return Err(Code::NotFound.into());
        };
        self.store.record(address.as_str(), kind)?.map(|r| r.bytes).ok_or(Rejection::new(Code::NotFound))
    }

    /// Checks a subscriber's auth frame against the challenge it answers (its `nonce` and `ts`).
    ///
    /// # Errors
    ///
    /// [`Code::BadAuth`] for a frame that is not the auth frame or a signature that does not verify; the chain
    /// codes; [`Code::NotAuthorized`] when the chain's root is not the mailbox; [`Code::Revoked`] when the mailbox's
    /// kept revoked list names a key of the chain; [`Code::Internal`] when the store fails to read that list.
    pub fn authorize_subscriber(
        &self,
        frame: &str,
        nonce: &str,
        challenge_ts: u64,
    ) -> Result<Subscriber, Code> {
        let value = json::parse(frame.as_bytes()).map_err(|_| Code::BadAuth)?;
        let object =
            value.as_object().filter(|o| json::has_exact_keys(o, &AUTH_KEYS)).ok_or(Code::BadAuth)?;
        if object.get("t").and_then(serde_json::Value::as_str) != Some("auth") {
            return Err(Code::BadAuth);
        }
        let mailbox = json::address_field(object.get("mailbox")).map_err(|_| Code::BadAuth)?;
        let signer = json::address_field(object.get("signer")).map_err(|_| Code::BadAuth)?;
        let cursor = match object.get("cursor") {
            Some(serde_json::Value::Null) => None,
            Some(c) => Some(json::canonical_integer(c).ok_or(Code::BadAuth)?),
            None => return Err(Code::BadAuth),
        };
        let sig = json::hex_field(object.get("sig"), Some(64)).map_err(|_| Code::BadAuth)?;
        let auth = object.get("auth").filter(|a| a.is_array()).ok_or(Code::BadAuth)?;
        let digest =
            hash::digest(&subscribe_preimage(nonce, &signer, &mailbox, cursor)).map_err(|_| Code::BadAuth)?;
        if !keys::verify(&signer, &digest, &hex::decode_array::<64>(&sig)?) {
            return Err(Code::BadAuth);
        }
        let hops = chain::check_shape(Some(auth))?;
        let verified = chain::verify(&signer, challenge_ts, &hops)?;
        if verified.root != mailbox {
            return Err(Code::NotAuthorized);
        }
        let revoked = self.revokes(&mailbox, &hops).map_err(|e| {
            tracing::error!(event = "store-error", error = %e);
            METRICS.tick(STORE_ERRORS);
            Code::Internal
        })?;
        if revoked {
            return Err(Code::Revoked);
        }
        let expires = hops.iter().map(|h| h.exp).min();
        Ok(Subscriber { mailbox, signer, cursor, expires, hops })
    }
}

#[cfg(test)]
mod tests;
