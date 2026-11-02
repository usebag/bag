//! Records (spec/SPEC.md §7): the address record, the accept-from record and the key record.
//!
//! Each is a JSON object with a `kind` member, `"address"`, `"accept-from"` or `"key"`, and exactly the other
//! members of its kind, signed by its own key (`key`, or `owner` for accept-from) over the digest of its preimage:
//!
//! * address: `["ac/addr/1", key, sealing_key or null, relays, rotation_key or null, revoked, ttl, iat,
//!   rotated_from or null]`;
//! * accept-from: `["ac/accept/1", owner, roots, max_bytes, ttl, iat]`;
//! * key: `["ac/key/1", key, sealing_key, iat, exp]`.
//!
//! A record that breaks its form is `bad-record`; the caps give `too-many-relays` and `too-many-revoked`. An
//! address record is valid from `iat - skew` to `iat + ttl` (`ttl` at most 86,400 s); a key record until `exp`;
//! an accept-from record does not expire, and its `ttl` is how long the relay keeps mail for the mailbox. A key
//! change is accepted only as a rotation countersigned by the previous key or its rotation key (§7.3); a reader that
//! holds no previous record checks the claim under `rotated_from` ([`verify_rotation_claim`]). An accept-from
//! record's roots are 1 to 1,024 addresses and `domain:<host>` entries ([`Root`]), or `["*"]` alone; a key
//! record lives a day at most.

use crate::address::Address;
use crate::canonical::{MAX_SAFE_INTEGER, Value};
use crate::error::{Code, Result};
use crate::json;
use crate::keys::SigningKey;
use serde_json::{Map, Value as Json};
use std::collections::BTreeSet;
use std::fmt;

/// The longest an address record may be used, in seconds.
pub const MAX_ADDRESS_TTL: u64 = 86_400;
/// The most relays an address record may name (raised from 8 on 2026-10-30, 'relays N', spec/SPEC.md §7.2).
pub const MAX_RELAYS: usize = 64;
/// The most revoked keys an address record may list.
pub const MAX_REVOKED: usize = 1_024;
/// The most entries an accept-from record's `roots` may hold (changed 2026-10-25).
pub const MAX_ROOTS: usize = 1_024;
/// The longest a key record may live, `exp - iat`, in seconds: the 24-hour ceiling, which binds key records as
/// it binds address records (changed 2026-10-25).
pub const MAX_KEY_LIFETIME: u64 = 86_400;
/// The domain tag of an address record's preimage.
pub const ADDRESS_TAG: &str = "ac/addr/1";
/// The domain tag of an accept-from record's preimage.
pub const ACCEPT_TAG: &str = "ac/accept/1";
/// The domain tag of a key record's preimage.
pub const KEY_TAG: &str = "ac/key/1";
/// The wildcard root of an accept-from record; it stands alone in `roots`.
pub const ANY_ROOT: &str = "*";
/// The prefix of a domain root of an accept-from record: `domain:` and a host name.
pub const DOMAIN_ROOT_PREFIX: &str = "domain:";
/// The longest host name of a domain root, in characters (a DNS name in text form, RFC 1035 §2.3.4).
pub const MAX_DOMAIN_LEN: usize = 253;

const ADDRESS_KEYS: [&str; 11] = [
    "kind",
    "key",
    "sealing_key",
    "relays",
    "rotation_key",
    "revoked",
    "ttl",
    "iat",
    "rotated_from",
    "rotation_sig",
    "sig",
];
const ACCEPT_KEYS: [&str; 7] = ["kind", "owner", "roots", "max_bytes", "ttl", "iat", "sig"];
const KEY_KEYS: [&str; 6] = ["kind", "key", "sealing_key", "iat", "exp", "sig"];

/// A record kind, as a published object's `kind` and the record fetch path name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    /// An address record.
    Address,
    /// An accept-from record.
    AcceptFrom,
    /// A key record.
    Key,
}

impl Kind {
    /// Every kind.
    pub const ALL: [Kind; 3] = [Kind::Address, Kind::AcceptFrom, Kind::Key];

    /// The wire name: `address`, `accept-from` or `key`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Kind::Address => "address",
            Kind::AcceptFrom => "accept-from",
            Kind::Key => "key",
        }
    }

    /// The kind of a wire name.
    #[must_use]
    pub fn from_wire(text: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.as_str() == text)
    }
}

/// An address record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressRecord {
    /// The address this record describes, which signs it.
    pub key: Address,
    /// Its X25519 public key, 32 bytes of hex, or none.
    pub sealing_key: Option<String>,
    /// 0 to 64 distinct `http://` or `https://` relay URLs.
    pub relays: Vec<String>,
    /// An address that may countersign this key's rotation.
    pub rotation_key: Option<Address>,
    /// 0 to 1,024 distinct revoked principal keys.
    pub revoked: Vec<Address>,
    /// How long the record may be used: 1 to 86,400 s from `iat`.
    pub ttl: u64,
    /// When it was issued.
    pub iat: u64,
    /// The previous key, when this record rotates it.
    pub rotated_from: Option<Address>,
    /// The countersignature of a rotation; only with `rotated_from`.
    pub rotation_sig: Option<[u8; 64]>,
    /// The signature by `key`.
    pub sig: [u8; 64],
}

/// An accept-from record: which roots a mailbox accepts, how large, and how long its relay keeps mail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptFromRecord {
    /// The mailbox, which signs it.
    pub owner: Address,
    /// The accepted roots: distinct root addresses, or exactly `["*"]`.
    pub roots: Roots,
    /// The largest envelope accepted, in bytes; positive.
    pub max_bytes: u64,
    /// How long the relay keeps mail for this mailbox, in seconds; positive, capped by the relay's TTL.
    pub ttl: u64,
    /// When it was issued.
    pub iat: u64,
    /// The signature by `owner`.
    pub sig: [u8; 64],
}

/// The roots of an accept-from record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Roots {
    /// `["*"]`: every root.
    Any,
    /// A non-empty list of distinct root addresses.
    Listed(Vec<Address>),
    /// A non-empty list of distinct entries in their signed order, addresses and domains, at least one of them a
    /// domain. A list of addresses only is [`Roots::Listed`].
    WithDomains(Vec<Root>),
}

/// The host of a `domain:` root: a lowercase DNS name of at most 253 characters and two or more labels,
/// each of 1 to 63 letters, digits and hyphens with no hyphen at either end, no trailing dot, and not an IP literal
/// ([`crate::net::is_ip_literal_host`]). No port, scheme, path or user part can ride along.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Domain(String);

fn is_dns_label(label: &str) -> bool {
    let b = label.as_bytes();
    let inner = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-';
    (1..=63).contains(&b.len()) && b.iter().all(inner) && b[0] != b'-' && b[b.len() - 1] != b'-'
}

impl Domain {
    /// Parses a host name.
    ///
    /// # Errors
    ///
    /// [`Code::BadRecord`] for anything but a host as above.
    pub fn parse(host: &str) -> Result<Domain> {
        let labels: Vec<&str> = host.split('.').collect();
        bad(host.len() <= MAX_DOMAIN_LEN
            && labels.len() >= 2
            && labels.iter().all(|l| is_dns_label(l))
            && !crate::net::is_ip_literal_host(host))?;
        Ok(Domain(host.to_owned()))
    }

    /// The host name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Domain({})", self.0)
    }
}

/// One entry of an accept-from record's roots besides `"*"`: a root key, or a domain whose current key is one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Root {
    /// A root by its address.
    Address(Address),
    /// `domain:<host>`: the key of the address record at the host's well-known URL.
    Domain(Domain),
}

impl Root {
    /// Parses an address or `domain:<host>`.
    ///
    /// # Errors
    ///
    /// [`Code::BadRecord`] for anything else, `"*"` included.
    pub fn parse(text: &str) -> Result<Root> {
        match text.strip_prefix(DOMAIN_ROOT_PREFIX) {
            Some(host) => Domain::parse(host).map(Root::Domain),
            None => Address::parse(text).map(Root::Address).map_err(|_| Code::BadRecord),
        }
    }

    /// The entry as the record writes it.
    #[must_use]
    pub fn to_text(&self) -> String {
        match self {
            Root::Address(a) => a.to_string(),
            Root::Domain(d) => format!("{DOMAIN_ROOT_PREFIX}{d}"),
        }
    }
}

impl Roots {
    /// The roots of a record's list of root texts, which is non-empty and has distinct entries: `["*"]`, a list
    /// of addresses, or a list with domains.
    fn from_texts(texts: &[&str]) -> Result<Roots> {
        let entries: Vec<Root> = texts.iter().map(|t| Root::parse(t)).collect::<Result<_>>()?;
        if entries.iter().all(|r| matches!(r, Root::Address(_))) {
            let addresses = entries.into_iter().filter_map(|r| match r {
                Root::Address(a) => Some(a),
                Root::Domain(_) => None,
            });
            Ok(Roots::Listed(addresses.collect()))
        } else {
            Ok(Roots::WithDomains(entries))
        }
    }
}

/// A key record: the sealing key of an address, from `iat` until `exp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRecord {
    /// The address, which signs it.
    pub key: Address,
    /// Its X25519 public key, 32 bytes of hex.
    pub sealing_key: String,
    /// When it was issued.
    pub iat: u64,
    /// When it stops being valid: from `iat` to `iat + 86,400` ([`MAX_KEY_LIFETIME`]).
    pub exp: u64,
    /// The signature by `key`.
    pub sig: [u8; 64],
}

/// Any record.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "a record is parsed, checked and dropped one at a time; boxing would only add an allocation"
)]
pub enum Record {
    /// An address record.
    Address(AddressRecord),
    /// An accept-from record.
    AcceptFrom(AcceptFromRecord),
    /// A key record.
    Key(KeyRecord),
}

fn bad(ok: bool) -> Result<()> {
    if ok { Ok(()) } else { Err(Code::BadRecord) }
}

fn int(value: Option<&Json>) -> Result<u64> {
    value.and_then(json::canonical_integer).ok_or(Code::BadRecord)
}

fn address(value: Option<&Json>) -> Result<Address> {
    json::address(value).ok_or(Code::BadRecord)
}

fn null_or<T>(value: Option<&Json>, read: impl Fn(&Json) -> Option<T>) -> Result<Option<T>> {
    match value {
        Some(Json::Null) => Ok(None),
        Some(v) => read(v).map(Some).ok_or(Code::BadRecord),
        None => Err(Code::BadRecord),
    }
}

fn hex(value: &Json, bytes: usize) -> Option<String> {
    value.as_str().filter(|s| json::is_hex(s, Some(bytes))).map(str::to_owned)
}

fn sig(value: Option<&Json>) -> Result<[u8; 64]> {
    let text = value.and_then(|v| hex(v, 64)).ok_or(Code::BadRecord)?;
    crate::hex::decode_array::<64>(&text)
}

fn distinct<T: Ord>(items: &[T]) -> bool {
    items.iter().collect::<BTreeSet<_>>().len() == items.len()
}

/// `http://` or `https://`, a non-empty authority, and no space or control character (Unicode `Cc`, U+0000 to
/// U+001F and U+007F to U+009F): the TypeScript core's `^https?://[^\p{Cc} /?#]+[^\p{Cc} ]*$`.
#[must_use]
pub fn is_relay_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://")) else {
        return false;
    };
    let first_ok =
        rest.chars().next().is_some_and(|c| !c.is_control() && !matches!(c, ' ' | '/' | '?' | '#'));
    first_ok && rest.chars().all(|c| !c.is_control() && c != ' ')
}

impl AddressRecord {
    fn from_json(v: &Map<String, Json>) -> Result<AddressRecord> {
        bad(json::has_exact_keys(v, &ADDRESS_KEYS))?;
        let key = address(v.get("key"))?;
        let sealing_key = null_or(v.get("sealing_key"), |x| hex(x, 32))?;
        let relays = v.get("relays").and_then(Json::as_array).ok_or(Code::BadRecord)?;
        if relays.len() > MAX_RELAYS {
            return Err(Code::TooManyRelays);
        }
        let relays: Vec<String> = relays
            .iter()
            .map(|u| u.as_str().filter(|s| is_relay_url(s)).map(str::to_owned))
            .collect::<Option<_>>()
            .ok_or(Code::BadRecord)?;
        bad(distinct(&relays))?;
        let rotation_key = null_or(v.get("rotation_key"), |x| json::address(Some(x)))?;
        let revoked = v.get("revoked").and_then(Json::as_array).ok_or(Code::BadRecord)?;
        if revoked.len() > MAX_REVOKED {
            return Err(Code::TooManyRevoked);
        }
        let revoked: Vec<Address> =
            revoked.iter().map(|a| json::address(Some(a))).collect::<Option<_>>().ok_or(Code::BadRecord)?;
        bad(distinct(&revoked))?;
        let ttl = int(v.get("ttl"))?;
        bad((1..=MAX_ADDRESS_TTL).contains(&ttl))?;
        let iat = int(v.get("iat"))?;
        let rotated_from = null_or(v.get("rotated_from"), |x| json::address(Some(x)))?;
        let rotation_sig = null_or(v.get("rotation_sig"), |x| hex(x, 64))?
            .map(|s| crate::hex::decode_array::<64>(&s))
            .transpose()?;
        bad(rotation_sig.is_none() || rotated_from.is_some())?;
        let sig = sig(v.get("sig"))?;
        Ok(AddressRecord {
            key,
            sealing_key,
            relays,
            rotation_key,
            revoked,
            ttl,
            iat,
            rotated_from,
            rotation_sig,
            sig,
        })
    }

    /// The form checks of §7.2, in the order the parser runs them, for a record built in code.
    fn check_form(&self) -> Result<()> {
        bad(self.sealing_key.as_deref().is_none_or(|k| json::is_hex(k, Some(32))))?;
        if self.relays.len() > MAX_RELAYS {
            return Err(Code::TooManyRelays);
        }
        bad(self.relays.iter().all(|u| is_relay_url(u)) && distinct(&self.relays))?;
        if self.revoked.len() > MAX_REVOKED {
            return Err(Code::TooManyRevoked);
        }
        bad(distinct(&self.revoked))?;
        bad((1..=MAX_ADDRESS_TTL).contains(&self.ttl) && self.iat <= MAX_SAFE_INTEGER)?;
        bad(self.rotation_sig.is_none() || self.rotated_from.is_some())
    }

    /// `["ac/addr/1", key, sealing_key or null, relays, rotation_key or null, revoked, ttl, iat,
    /// rotated_from or null]`.
    #[must_use]
    pub fn preimage(&self) -> Value {
        Value::Array(vec![
            Value::from(ADDRESS_TAG),
            Value::from(self.key.as_str()),
            Value::opt_str(self.sealing_key.as_deref()),
            Value::strings(&self.relays),
            Value::opt_str(self.rotation_key.as_ref().map(Address::as_str)),
            Value::Array(self.revoked.iter().map(|a| Value::from(a.as_str())).collect()),
            Value::Int(self.ttl),
            Value::Int(self.iat),
            Value::opt_str(self.rotated_from.as_ref().map(Address::as_str)),
        ])
    }

    /// Countersigns a rotation with the previous key or the previous record's rotation key.
    ///
    /// # Errors
    ///
    /// [`Code::BadRecord`] unless the record names `rotated_from`; [`Code::BadCanonical`] for an integer over
    /// 2^53 - 1.
    pub fn countersign(&mut self, previous: &SigningKey) -> Result<()> {
        if self.rotated_from.is_none() {
            return Err(Code::BadRecord);
        }
        self.rotation_sig = Some(previous.sign_preimage(&self.preimage())?);
        Ok(())
    }
}

impl AcceptFromRecord {
    fn from_json(v: &Map<String, Json>) -> Result<AcceptFromRecord> {
        bad(json::has_exact_keys(v, &ACCEPT_KEYS))?;
        let owner = address(v.get("owner"))?;
        let list =
            v.get("roots").and_then(Json::as_array).filter(|l| !l.is_empty()).ok_or(Code::BadRecord)?;
        bad(list.len() <= MAX_ROOTS)?;
        let texts: Vec<&str> = list.iter().map(Json::as_str).collect::<Option<_>>().ok_or(Code::BadRecord)?;
        bad(texts.iter().all(|r| *r == ANY_ROOT || Root::parse(r).is_ok()) && distinct(&texts))?;
        let roots = if texts.contains(&ANY_ROOT) {
            bad(texts.len() == 1)?;
            Roots::Any
        } else {
            Roots::from_texts(&texts)?
        };
        let max_bytes = int(v.get("max_bytes"))?;
        bad(max_bytes >= 1)?;
        let ttl = int(v.get("ttl"))?;
        bad(ttl >= 1)?;
        let iat = int(v.get("iat"))?;
        let sig = sig(v.get("sig"))?;
        Ok(AcceptFromRecord { owner, roots, max_bytes, ttl, iat, sig })
    }

    fn check_form(&self) -> Result<()> {
        bad(match &self.roots {
            Roots::Any => true,
            Roots::Listed(list) => !list.is_empty() && list.len() <= MAX_ROOTS && distinct(list),
            Roots::WithDomains(list) => {
                list.iter().any(|r| matches!(r, Root::Domain(_))) && list.len() <= MAX_ROOTS && distinct(list)
            }
        })?;
        bad(self.max_bytes >= 1 && self.max_bytes <= MAX_SAFE_INTEGER)?;
        bad(self.ttl >= 1 && self.ttl <= MAX_SAFE_INTEGER && self.iat <= MAX_SAFE_INTEGER)
    }

    /// `["ac/accept/1", owner, roots, max_bytes, ttl, iat]`.
    #[must_use]
    pub fn preimage(&self) -> Value {
        Value::Array(vec![
            Value::from(ACCEPT_TAG),
            Value::from(self.owner.as_str()),
            Value::Array(self.root_texts().into_iter().map(Value::from).collect()),
            Value::Int(self.max_bytes),
            Value::Int(self.ttl),
            Value::Int(self.iat),
        ])
    }

    fn root_texts(&self) -> Vec<String> {
        match &self.roots {
            Roots::Any => vec![ANY_ROOT.to_owned()],
            Roots::Listed(list) => list.iter().map(Address::to_string).collect(),
            Roots::WithDomains(list) => list.iter().map(Root::to_text).collect(),
        }
    }

    /// Whether the record admits an envelope rooted at `root` without resolving anything: `roots` is `["*"]` or
    /// lists the address. A `domain:` entry admits it only when the domain's current key is `root`, which the
    /// relay resolves ([`AcceptFromRecord::domains`]).
    #[must_use]
    pub fn admits(&self, root: &Address) -> bool {
        match &self.roots {
            Roots::Any => true,
            Roots::Listed(list) => list.contains(root),
            Roots::WithDomains(list) => list.contains(&Root::Address(root.clone())),
        }
    }

    /// The `domain:` entries of `roots`, in their order; empty unless the roots name a domain.
    #[must_use]
    pub fn domains(&self) -> Vec<&Domain> {
        match &self.roots {
            Roots::WithDomains(list) => list
                .iter()
                .filter_map(|r| match r {
                    Root::Domain(d) => Some(d),
                    Root::Address(_) => None,
                })
                .collect(),
            Roots::Any | Roots::Listed(_) => Vec::new(),
        }
    }
}

impl KeyRecord {
    fn from_json(v: &Map<String, Json>) -> Result<KeyRecord> {
        bad(json::has_exact_keys(v, &KEY_KEYS))?;
        let key = address(v.get("key"))?;
        let sealing_key = v.get("sealing_key").and_then(|x| hex(x, 32)).ok_or(Code::BadRecord)?;
        let iat = int(v.get("iat"))?;
        let exp = int(v.get("exp"))?;
        bad(exp >= iat && exp - iat <= MAX_KEY_LIFETIME)?;
        let sig = sig(v.get("sig"))?;
        Ok(KeyRecord { key, sealing_key, iat, exp, sig })
    }

    fn check_form(&self) -> Result<()> {
        bad(json::is_hex(&self.sealing_key, Some(32))
            && self.exp >= self.iat
            && self.exp - self.iat <= MAX_KEY_LIFETIME
            && self.exp <= MAX_SAFE_INTEGER)
    }

    /// `["ac/key/1", key, sealing_key, iat, exp]`.
    #[must_use]
    pub fn preimage(&self) -> Value {
        Value::Array(vec![
            Value::from(KEY_TAG),
            Value::from(self.key.as_str()),
            Value::from(self.sealing_key.as_str()),
            Value::Int(self.iat),
            Value::Int(self.exp),
        ])
    }
}

impl Record {
    /// Parses record bytes: UTF-8 JSON (`bad-json`), then [`Record::from_json`].
    ///
    /// # Errors
    ///
    /// [`Code::BadJson`], then as for [`Record::from_json`].
    pub fn parse(bytes: &[u8]) -> Result<Record> {
        Record::from_json(&json::parse(bytes)?)
    }

    /// Checks a parsed record's form and caps (§7.1 to §7.4), not its signature or time.
    ///
    /// # Errors
    ///
    /// [`Code::BadRecord`], [`Code::TooManyRelays`], [`Code::TooManyRevoked`].
    pub fn from_json(value: &Json) -> Result<Record> {
        let object = value.as_object().ok_or(Code::BadRecord)?;
        match object.get("kind").and_then(Json::as_str).and_then(Kind::from_wire) {
            Some(Kind::Address) => AddressRecord::from_json(object).map(Record::Address),
            Some(Kind::AcceptFrom) => AcceptFromRecord::from_json(object).map(Record::AcceptFrom),
            Some(Kind::Key) => KeyRecord::from_json(object).map(Record::Key),
            None => Err(Code::BadRecord),
        }
    }

    /// The record's kind.
    #[must_use]
    pub fn kind(&self) -> Kind {
        match self {
            Record::Address(_) => Kind::Address,
            Record::AcceptFrom(_) => Kind::AcceptFrom,
            Record::Key(_) => Kind::Key,
        }
    }

    /// The address that signs the record and that it is stored under: `key`, or `owner` for accept-from.
    #[must_use]
    pub fn signer(&self) -> &Address {
        match self {
            Record::Address(r) => &r.key,
            Record::AcceptFrom(r) => &r.owner,
            Record::Key(r) => &r.key,
        }
    }

    /// When the record was issued.
    #[must_use]
    pub fn iat(&self) -> u64 {
        match self {
            Record::Address(r) => r.iat,
            Record::AcceptFrom(r) => r.iat,
            Record::Key(r) => r.iat,
        }
    }

    /// The record's signed preimage.
    #[must_use]
    pub fn preimage(&self) -> Value {
        match self {
            Record::Address(r) => r.preimage(),
            Record::AcceptFrom(r) => r.preimage(),
            Record::Key(r) => r.preimage(),
        }
    }

    fn sig(&self) -> &[u8; 64] {
        match self {
            Record::Address(r) => &r.sig,
            Record::AcceptFrom(r) => &r.sig,
            Record::Key(r) => &r.sig,
        }
    }

    fn sig_mut(&mut self) -> &mut [u8; 64] {
        match self {
            Record::Address(r) => &mut r.sig,
            Record::AcceptFrom(r) => &mut r.sig,
            Record::Key(r) => &mut r.sig,
        }
    }

    fn check_form(&self) -> Result<()> {
        match self {
            Record::Address(r) => r.check_form(),
            Record::AcceptFrom(r) => r.check_form(),
            Record::Key(r) => r.check_form(),
        }
    }

    /// The digest the record's signature covers, as hex.
    ///
    /// # Errors
    ///
    /// [`Code::BadCanonical`] for an integer over 2^53 - 1 (only a record built in code can hold one).
    pub fn digest_hex(&self) -> Result<String> {
        Ok(crate::hex::encode(&crate::hash::digest(&self.preimage())?))
    }

    /// Signs the record with its own key.
    ///
    /// # Errors
    ///
    /// [`Code::BadKey`] when `key` is not the record's signer, the form codes for a record that breaks its form,
    /// [`Code::BadCanonical`] for an integer over 2^53 - 1.
    pub fn sign(&mut self, key: &SigningKey) -> Result<()> {
        if &key.address() != self.signer() {
            return Err(Code::BadKey);
        }
        self.check_form()?;
        *self.sig_mut() = key.sign_preimage(&self.preimage())?;
        Ok(())
    }

    /// Verifies the record at `now` (§7.5), in order: its form and caps; its signature (`bad-record-sig`);
    /// `iat <= now + skew` (`future-iat`); its expiry (`record-expired`): an address record after `iat + ttl`, a
    /// key record after `exp`. An accept-from record does not expire.
    ///
    /// # Errors
    ///
    /// The form codes, [`Code::BadRecordSig`], [`Code::FutureIat`], [`Code::RecordExpired`].
    pub fn verify(&self, now: u64, skew: u64) -> Result<()> {
        self.check_form()?;
        let digest = crate::hash::digest(&self.preimage()).map_err(|_| Code::BadRecord)?;
        if !crate::keys::verify(self.signer(), &digest, self.sig()) {
            return Err(Code::BadRecordSig);
        }
        if self.iat() > now.saturating_add(skew) {
            return Err(Code::FutureIat);
        }
        let expired = match self {
            Record::Address(r) => now > r.iat.saturating_add(r.ttl),
            Record::Key(r) => now > r.exp,
            Record::AcceptFrom(_) => false,
        };
        if expired { Err(Code::RecordExpired) } else { Ok(()) }
    }

    /// The record as wire JSON text, members in wire order with no white space: the bytes `packages/core`
    /// writes for the same record.
    #[must_use]
    pub fn to_json_text(&self) -> String {
        let hex = |s: &[u8; 64]| crate::hex::encode(s);
        match self {
            Record::Address(r) => {
                let revoked: Vec<&str> = r.revoked.iter().map(Address::as_str).collect();
                json::Writer::object()
                    .str("kind", Kind::Address.as_str())
                    .str("key", r.key.as_str())
                    .opt_str("sealing_key", r.sealing_key.as_deref())
                    .strs("relays", &r.relays)
                    .opt_str("rotation_key", r.rotation_key.as_ref().map(Address::as_str))
                    .strs("revoked", &revoked)
                    .int("ttl", r.ttl)
                    .int("iat", r.iat)
                    .opt_str("rotated_from", r.rotated_from.as_ref().map(Address::as_str))
                    .opt_str("rotation_sig", r.rotation_sig.as_ref().map(hex).as_deref())
                    .str("sig", &hex(&r.sig))
                    .finish()
            }
            Record::AcceptFrom(r) => json::Writer::object()
                .str("kind", Kind::AcceptFrom.as_str())
                .str("owner", r.owner.as_str())
                .strs("roots", &r.root_texts())
                .int("max_bytes", r.max_bytes)
                .int("ttl", r.ttl)
                .int("iat", r.iat)
                .str("sig", &hex(&r.sig))
                .finish(),
            Record::Key(r) => json::Writer::object()
                .str("kind", Kind::Key.as_str())
                .str("key", r.key.as_str())
                .str("sealing_key", &r.sealing_key)
                .int("iat", r.iat)
                .int("exp", r.exp)
                .str("sig", &hex(&r.sig))
                .finish(),
        }
    }

    /// The wire bytes: [`Record::to_json_text`] as UTF-8.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_json_text().into_bytes()
    }
}

/// Whether `next` rotates `prev` (§7.3): `next.rotated_from` is `prev.key`, and `next.rotation_sig` verifies over
/// `next`'s preimage under `prev.key` or `prev.rotation_key`. Anything else, a bare rotation without a
/// `rotation_sig` included, is `bad-rotation`. Run [`Record::verify`] on both records first: this checks the link. A
/// reader that holds no record of `next.rotated_from` checks [`verify_rotation_claim`] instead.
///
/// # Errors
///
/// [`Code::BadRotation`].
pub fn verify_rotation(prev: &AddressRecord, next: &AddressRecord) -> Result<()> {
    if next.rotated_from.as_ref() != Some(&prev.key) {
        return Err(Code::BadRotation);
    }
    let sig = next.rotation_sig.as_ref().ok_or(Code::BadRotation)?;
    let digest = crate::hash::digest(&next.preimage()).map_err(|_| Code::BadRotation)?;
    let signed_by = |a: &Address| crate::keys::verify(a, &digest, sig);
    if signed_by(&prev.key) || prev.rotation_key.as_ref().is_some_and(signed_by) {
        Ok(())
    } else {
        Err(Code::BadRotation)
    }
}

/// The rotation a record claims, for a reader that holds no record of its `rotated_from` (§7.3;
/// changed 2026-10-25): when `rotated_from` is set, `rotation_sig` must verify over the record's preimage under
/// `rotated_from`, so a bare rotation and a countersignature by any other key are `bad-rotation`. A record that names
/// no `rotated_from` claims nothing and passes. A rotation countersigned by the previous record's rotation key
/// verifies only through [`verify_rotation`], by a reader that holds that previous record, the one place the rotation
/// key is written. Run [`Record::verify`] first: this checks the claim.
///
/// # Errors
///
/// [`Code::BadRotation`].
pub fn verify_rotation_claim(next: &AddressRecord) -> Result<()> {
    let Some(previous) = &next.rotated_from else {
        return Ok(());
    };
    let sig = next.rotation_sig.as_ref().ok_or(Code::BadRotation)?;
    let digest = crate::hash::digest(&next.preimage()).map_err(|_| Code::BadRotation)?;
    if crate::keys::verify(previous, &digest, sig) { Ok(()) } else { Err(Code::BadRotation) }
}

#[cfg(test)]
mod tests;
