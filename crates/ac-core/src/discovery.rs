//! Discovery by DNS (spec/SPEC.md §12.1 and §12.2, L2): an org's TXT
//! record at `_bag.<domain>` names the key that signs its address record and, at most, that
//! the org's one origin is `https://bag.<domain>` rather than `https://<domain>`; it names no URL.
//!
//! DNS is a hint and the signature is the authority: the record at the origin must still verify and agree with the
//! TXT's key, by that key or by one rotation it countersigned, so a forged TXT can fail a resolution but never
//! choose the key a reader pins, and never moves a pin. Pure: the relay looks the records up
//! (`crates/ac-relay/src/dns.rs`) and hands them here, as the TypeScript core's `discover` takes an edge's.

use crate::address::Address;
use crate::error::{Code, Result};
use crate::handles::is_special_use;
use crate::records::{self, AddressRecord, Domain, MAX_DOMAIN_LEN};
use std::fmt;

/// The name under which an org publishes its TXT record, before its domain.
pub const DISCOVERY_PREFIX: &str = "_bag.";
/// The path of an org's address record at its origin (§12.1).
pub const WELL_KNOWN_RECORD_PATH: &str = "/.well-known/bag/address.json";
/// The one value of a TXT's `host` field: the org's origin is then `https://bag.<domain>` (§12.1).
pub const BAG_HOST: &str = "bag";
/// The first field of a bag TXT record.
pub const TXT_VERSION_FIELD: &str = "v=ac1";
/// The longest bag TXT record, in bytes once its strings are joined (implementation default).
pub const MAX_TXT_BYTES: usize = 1_024;
/// The longest character-string of a TXT record, in bytes (RFC 1035 §3.3).
pub const MAX_TXT_STRING: usize = 255;

/// Why a domain's TXT records resolve nothing; each is `resolve-failed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// A bag record that breaks §12.2 items 1 to 3, with what is wrong.
    Malformed(&'static str),
    /// Two or more bag records: how many.
    Ambiguous(usize),
}

impl Refusal {
    /// The code: `resolve-failed`.
    #[must_use]
    pub const fn code(&self) -> Code {
        Code::ResolveFailed
    }
}

/// The URL of an org's address record at its origin (§12.1): `https://<host>/.well-known/bag/address.json`,
/// the host the domain itself or `bag.<domain>`. No URL is ever read from DNS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordUrl {
    host: Domain,
    path: String,
}

impl RecordUrl {
    /// The address record's URL at the origin `https://<host>`: `https://<host>/.well-known/bag/address.json`.
    #[must_use]
    pub fn well_known(host: &Domain) -> RecordUrl {
        RecordUrl { host: host.clone(), path: WELL_KNOWN_RECORD_PATH.to_owned() }
    }

    /// The host to fetch from.
    #[must_use]
    pub fn host(&self) -> &Domain {
        &self.host
    }

    /// The path to fetch.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The org's origin, `https://<host>`, where its records are all served (§12.1), its handle records included.
    #[must_use]
    pub fn origin(&self) -> String {
        format!("https://{}", self.host)
    }
}

impl fmt::Display for RecordUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "https://{}{}", self.host, self.path)
    }
}

/// A bag TXT record: the key that signs the org's record, and the host of the org's origin when the TXT says
/// `host=bag`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Txt {
    /// The key the org's address record must agree with (§12.2 item 5).
    pub key: Address,
    /// `bag.<domain>` when the TXT says `host=bag`; none for the origin at the domain.
    pub host: Option<Domain>,
}

/// Where a domain's address record is, and the key it must agree with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    /// The TXT's key; none when the domain has no bag TXT record.
    pub key: Option<Address>,
    /// The address record's URL at the org's origin (§12.1).
    pub url: RecordUrl,
}

impl Discovery {
    /// The well-known URL and no key: a domain with no bag TXT record.
    #[must_use]
    pub fn well_known(domain: &Domain) -> Discovery {
        Discovery { key: None, url: RecordUrl::well_known(domain) }
    }

    /// Checks the org record the discovery led to (§12.2 item 5): when the TXT named a key, the
    /// record agrees with it when its key is that key, or when it names that key in `rotated_from` and its
    /// `rotation_sig` verifies under it ([`records::verify_rotation_claim`]: one countersigned step). It never moves a
    /// pin: the reader's pin then moves only by §7.3.
    ///
    /// # Errors
    ///
    /// [`Code::ResolveFailed`] for a record that agrees in neither way.
    pub fn check(&self, record: &AddressRecord) -> Result<()> {
        match &self.key {
            Some(key) if *key != record.key && !countersigned_by(record, key) => Err(Code::ResolveFailed),
            _ => Ok(()),
        }
    }
}

/// Whether `record` names `key` in `rotated_from` and its `rotation_sig` verifies under it (§7.3's claim, one step).
fn countersigned_by(record: &AddressRecord, key: &Address) -> bool {
    record.rotated_from.as_ref() == Some(key) && records::verify_rotation_claim(record).is_ok()
}

/// The name to look a domain's TXT records up at, or none when none is asked (§12.2 item 4): a name over 253
/// characters (no such name), or a domain under a special-use name, which RFC 6761, 6762, 7686 and 9476 keep off DNS.
#[must_use]
pub fn txt_name(domain: &Domain) -> Option<String> {
    let name = format!("{DISCOVERY_PREFIX}{domain}");
    (name.len() <= MAX_DOMAIN_LEN && !is_special_use(domain)).then_some(name)
}

fn printable(c: u8) -> bool {
    c == b'\t' || (b' '..=b'~').contains(&c)
}

fn white(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

/// Reads the text form of one TXT record (RFC 1035 §5.1; §12.2 item 7): character-strings separated by spaces or tabs,
/// each quoted or bare, with `\DDD` and `\X` escapes, at most 255 bytes each, the text tab and space to `~` only.
///
/// # Errors
///
/// What is wrong, for anything else (`resolve-failed` where a reader meets it).
pub fn parse_presentation(text: &str) -> std::result::Result<Vec<Vec<u8>>, &'static str> {
    let b = text.as_bytes();
    if !b.iter().all(|c| printable(*c)) {
        return Err("a TXT text holds a character other than tab and space to ~");
    }
    // The byte of the escape at b[at], just after its backslash, and the index after it.
    let escaped = |at: usize| -> std::result::Result<(u8, usize), &'static str> {
        let c = *b.get(at).ok_or("a TXT text ends in a backslash")?;
        if !c.is_ascii_digit() {
            return Ok((c, at + 1));
        }
        let digits = b.get(at..at + 3).filter(|d| d.iter().all(u8::is_ascii_digit));
        let value = digits.map(|d| d.iter().fold(0u16, |n, x| n * 10 + u16::from(x - b'0')));
        let byte = value.and_then(|v| u8::try_from(v).ok()).ok_or("\\DDD needs three digits up to 255")?;
        Ok((byte, at + 3))
    };
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        while b.get(i).copied().is_some_and(white) {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        let quoted = b[i] == b'"';
        if quoted {
            i += 1;
        }
        let mut s = Vec::new();
        loop {
            let Some(&c) = b.get(i) else {
                if quoted {
                    return Err("a quoted TXT string is not closed");
                }
                break;
            };
            if quoted && c == b'"' {
                i += 1;
                if b.get(i).is_some_and(|n| !white(*n)) {
                    return Err("a quoted TXT string is followed by more text");
                }
                break;
            }
            if !quoted && white(c) {
                break;
            }
            if !quoted && c == b'"' {
                return Err("a quote inside a bare TXT string");
            }
            if !quoted && (c == b'(' || c == b')') {
                return Err("a parenthesis inside a bare TXT string");
            }
            if c == b'\\' {
                let (byte, next) = escaped(i + 1)?;
                s.push(byte);
                i = next;
            } else {
                s.push(c);
                i += 1;
            }
        }
        if s.len() > MAX_TXT_STRING {
            return Err("a TXT string over 255 bytes");
        }
        out.push(s);
    }
    if out.is_empty() { Err("a TXT text with no string") } else { Ok(out) }
}

fn trim(mut b: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = b
        && white(*first)
    {
        b = rest;
    }
    while let [rest @ .., last] = b
        && white(*last)
    {
        b = rest;
    }
    b
}

/// A field `name=value` with spaces and tabs around (§12.2 item 1), or none when it breaks the grammar.
fn field(part: &[u8]) -> Option<(&[u8], &[u8])> {
    let at = part.iter().position(|c| *c == b'=')?;
    let (name, value) = (trim(&part[..at]), trim(&part[at + 1..]));
    let name_ok = (1..=32).contains(&name.len())
        && name[0].is_ascii_alphabetic()
        && name.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_');
    let value_ok = !value.is_empty() && value.iter().all(|c| (b'!'..=b'~').contains(c) && *c != b';');
    (name_ok && value_ok).then_some((name, value))
}

/// Reads one TXT record's joined text for `domain` (§12.2 items 1 to 3): none when it is not a bag record
/// (its first field is not `v=ac1`); an error when it is one but malformed: a field given twice, no `key`, a `rec`
/// (DNS names no URL), a field that breaks the grammar, a `key` that is not an address, a `host` other than
/// `bag`, a byte other than tab and space to `~`, or over 1,024 bytes. A field of another name is ignored.
///
/// # Errors
///
/// What is wrong with a bag record.
pub fn parse_txt(text: &[u8], domain: &Domain) -> std::result::Result<Option<Txt>, &'static str> {
    let parts: Vec<&[u8]> = text.split(|c| *c == b';').map(trim).filter(|p| !p.is_empty()).collect();
    match parts.first().and_then(|p| field(p)) {
        Some((name, value)) if name == b"v" && value == b"ac1" => {}
        _ => return Ok(None),
    }
    if !text.iter().all(|c| printable(*c)) {
        return Err("a bag TXT record holds a byte other than tab and space to ~");
    }
    if text.len() > MAX_TXT_BYTES {
        return Err("a bag TXT record over 1,024 bytes");
    }
    let mut fields: Vec<(&[u8], &[u8])> = Vec::with_capacity(parts.len());
    for part in &parts {
        let (name, value) = field(part).ok_or("a TXT field that is not name=value")?;
        if fields.iter().any(|(n, _)| *n == name) {
            return Err("a TXT field given twice");
        }
        fields.push((name, value));
    }
    let get = |want: &[u8]| fields.iter().find(|(n, _)| *n == want).map(|(_, v)| *v);
    if get(b"rec").is_some() {
        return Err("the TXT names a rec: DNS names no URL");
    }
    let key = get(b"key").ok_or("a bag TXT record names no key")?;
    // Every value is printable ASCII by now, so it is UTF-8.
    let key = Address::parse(&String::from_utf8_lossy(key)).map_err(|_| "the TXT key is not an address")?;
    let host = match get(b"host") {
        None => None,
        Some(v) if v == BAG_HOST.as_bytes() => Some(
            Domain::parse(&format!("{BAG_HOST}.{domain}"))
                .ok()
                .ok_or("bag.<domain> is over 253 characters")?,
        ),
        Some(_) => return Err("the TXT host is bag or absent"),
    };
    Ok(Some(Txt { key, host }))
}

/// Where a domain's address record is, from the TXT records its lookup of `_bag.<domain>` gave, each a list
/// of character-strings (§12.2 item 4): with no bag record, the origin at the domain and no key; with one,
/// its key and the origin its `host` names; with two or more, or a malformed one, a refusal. A domain [`txt_name`]
/// does not ask has no bag record, whatever records are handed in.
///
/// # Errors
///
/// [`Refusal::Malformed`] or [`Refusal::Ambiguous`], each `resolve-failed`.
pub fn discover(records: &[Vec<Vec<u8>>], domain: &Domain) -> std::result::Result<Discovery, Refusal> {
    if txt_name(domain).is_none() {
        return Ok(Discovery::well_known(domain));
    }
    let mut ours = Vec::new();
    for record in records {
        if let Some(txt) = parse_txt(&record.concat(), domain).map_err(Refusal::Malformed)? {
            ours.push(txt);
        }
    }
    if ours.len() > 1 {
        return Err(Refusal::Ambiguous(ours.len()));
    }
    Ok(match ours.pop() {
        None => Discovery::well_known(domain),
        Some(Txt { key, host }) => {
            Discovery { key: Some(key), url: RecordUrl::well_known(host.as_ref().unwrap_or(domain)) }
        }
    })
}

#[cfg(test)]
mod tests;
