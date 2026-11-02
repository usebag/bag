//! The TXT lookup of `_bag.<domain>` (spec/SPEC.md §12.2, §8.8 item 1, Appendix B 73): a stub resolver
//! of the relay's own, TXT only, over UDP. A DNS crate would be ac-relay's thirteenth direct dependency, past
//! CONTRIBUTING.md's twelve, and `hickory-resolver` 0.26.3 measured 78 more locked crates.
//!
//! DNS is a hint and the signature is the authority: an answer only says which of two origins an org's records are at
//! and which key its record must agree with, and that record must still verify (src/resolver.rs,
//! [`ac_core::discovery`]), so a fault here can fail or misdirect a resolution and never forge an identity. Every
//! answer is still read as untrusted input: each query goes out on a fresh socket on a port the system chooses,
//! connected to its server, so a datagram from any other address is never read; the id is random
//! and must be echoed, the question must be the query's, a datagram that matches neither is discarded while the try
//! lasts (RFC 5452 §9.1), a compression pointer must point before the name it is read from, and a truncated answer,
//! one longer than the 1,232 bytes asked for, or one that does not parse fails. No TCP, no DNSSEC, no cache: the
//! relay caches the records it resolves (§8.8 item 4).
//!
//! [`UdpTxt`] asks the nameservers of `/etc/resolv.conf`, read at each lookup; [`FixedTxt`] is the test-only table of
//! `--dns-resolve`, which a relay with any test-only flag uses in place of DNS, so that no test asks a real server.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;
use tokio::net::UdpSocket;

/// The UDP payload the stub advertises with EDNS(0), and the longest answer it reads.
pub const PAYLOAD: usize = 1_232;
/// The longest CNAME chain followed.
pub const MAX_CNAMES: usize = 8;
/// The most nameservers asked, as glibc's MAXNS.
pub const MAX_SERVERS: usize = 3;
/// How long one server is waited for.
pub const TRY_TIMEOUT: Duration = Duration::from_secs(2);
/// Where the system names its nameservers.
pub const RESOLV_CONF: &str = "/etc/resolv.conf";

const TYPE_CNAME: u16 = 5;
const TYPE_TXT: u16 = 16;
const TYPE_OPT: u16 = 41;
const CLASS_IN: u16 = 1;
const HEADER: usize = 12;
const MAX_NAME: usize = 255;

/// A TXT record: its character-strings, in order.
pub type TxtRecord = Vec<Vec<u8>>;
/// A lookup's outcome: every TXT record at the name (none when it has none or does not exist), or why it failed.
pub type Lookup = Result<Vec<TxtRecord>, String>;
/// A lookup in progress.
pub type Looking<'a> = Pin<Box<dyn Future<Output = Lookup> + Send + 'a>>;

/// The TXT records of a name.
pub trait TxtLookup: Send + Sync {
    /// Looks up the TXT records of `name`.
    fn lookup<'a>(&'a self, name: &'a str) -> Looking<'a>;
    /// `dns` for a lookup that asks a server, `fixed` for a table: the `source` of the relay's `txt` log line.
    fn source(&self) -> &'static str;
}

/// The test-only table of `--dns-resolve <name>=<txt>`: the TXT records each name has, and none for any other name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FixedTxt(pub Vec<(String, TxtRecord)>);

impl TxtLookup for FixedTxt {
    fn lookup<'a>(&'a self, name: &'a str) -> Looking<'a> {
        let found =
            self.0.iter().filter(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, r)| r.clone()).collect();
        Box::pin(std::future::ready(Ok(found)))
    }

    fn source(&self) -> &'static str {
        "fixed"
    }
}

#[derive(Debug, Clone)]
enum Servers {
    Fixed(Vec<SocketAddr>),
    File(PathBuf),
}

/// The stub resolver: TXT over UDP to the nameservers of `/etc/resolv.conf`, or to fixed ones.
#[derive(Debug, Clone)]
pub struct UdpTxt {
    servers: Servers,
    try_timeout: Duration,
}

impl UdpTxt {
    /// A stub that asks these servers, waiting `try_timeout` for each.
    #[must_use]
    pub fn new(servers: Vec<SocketAddr>, try_timeout: Duration) -> UdpTxt {
        UdpTxt { servers: Servers::Fixed(servers), try_timeout }
    }

    /// The system's stub: the nameservers `/etc/resolv.conf` names when it looks up, [`TRY_TIMEOUT`] each.
    #[must_use]
    pub fn system() -> UdpTxt {
        UdpTxt { servers: Servers::File(PathBuf::from(RESOLV_CONF)), try_timeout: TRY_TIMEOUT }
    }

    fn servers(&self) -> Vec<SocketAddr> {
        match &self.servers {
            Servers::Fixed(list) => list.clone(),
            Servers::File(path) => parse_resolv_conf(&std::fs::read_to_string(path).unwrap_or_default()),
        }
    }
}

impl TxtLookup for UdpTxt {
    fn lookup<'a>(&'a self, name: &'a str) -> Looking<'a> {
        Box::pin(async move { ask_servers(&self.servers(), name, self.try_timeout).await })
    }

    fn source(&self) -> &'static str {
        "dns"
    }
}

/// The nameservers of resolv.conf text: at most [`MAX_SERVERS`] `nameserver <ip>` lines, port 53; 127.0.0.1 and
/// `::1` when it names none (resolv.conf(5)). A scoped IPv6 address (`fe80::1%en0`) is skipped.
#[must_use]
pub fn parse_resolv_conf(text: &str) -> Vec<SocketAddr> {
    let named: Vec<SocketAddr> = text
        .lines()
        .filter_map(|line| {
            let mut words = line.split(['#', ';']).next().unwrap_or_default().split_whitespace();
            (words.next() == Some("nameserver")).then(|| words.next()).flatten()?.parse::<IpAddr>().ok()
        })
        .take(MAX_SERVERS)
        .map(|ip| SocketAddr::new(ip, 53))
        .collect();
    if named.is_empty() {
        vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 53), SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 53)]
    } else {
        named
    }
}

/// A query for the TXT records of `name`, recursion desired, with an EDNS(0) OPT record of [`PAYLOAD`] when `edns`.
///
/// # Errors
///
/// What is wrong with the name: an empty label, one over 63 bytes, or over 255 bytes in all.
pub fn query(name: &str, id: u16, edns: bool) -> Result<Vec<u8>, &'static str> {
    let mut q = Vec::with_capacity(HEADER + name.len() + 2 + 4 + 11);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, u8::from(edns)]);
    for label in name.split('.') {
        let len = u8::try_from(label.len())
            .ok()
            .filter(|n| (1..=63).contains(n))
            .ok_or("a label of 1 to 63 bytes")?;
        q.push(len);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    if q.len() - HEADER > MAX_NAME {
        return Err("a name over 255 bytes");
    }
    q.extend_from_slice(&TYPE_TXT.to_be_bytes());
    q.extend_from_slice(&CLASS_IN.to_be_bytes());
    if edns {
        // The OPT record (RFC 6891): the root name, its type, the payload as its class, a TTL of zeros (extended
        // code, version 0, no flags) and no data.
        let (kind, payload) =
            (TYPE_OPT.to_be_bytes(), u16::try_from(PAYLOAD).unwrap_or(u16::MAX).to_be_bytes());
        q.extend_from_slice(&[0, kind[0], kind[1], payload[0], payload[1], 0, 0, 0, 0, 0, 0]);
    }
    Ok(q)
}

/// What a server's datagram is to a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Read {
    /// Not an answer to this query (another id, not a response, or another question): discarded.
    Mismatch,
    /// The name's TXT records: none for NXDOMAIN or an empty answer.
    Records(Vec<TxtRecord>),
    /// FORMERR: the server may not know EDNS, so the query is asked again without it.
    FormErr,
    /// Another failure: a response code (SERVFAIL, REFUSED and the like), a truncated, oversized or unreadable answer.
    Failed(String),
}

fn u16_at(msg: &[u8], at: usize) -> Option<u16> {
    msg.get(at..at + 2).map(|b| u16::from_be_bytes([b[0], b[1]]))
}

/// The name at `at` as lower-case labels, and the offset just past its bytes at `at`. A compression pointer must
/// point before the start of the labels it is read among, so every pointer goes further back and a loop cannot
/// form; the name may not pass 255 bytes.
fn name_at(msg: &[u8], at: usize) -> Result<(Vec<Vec<u8>>, usize), &'static str> {
    let (mut labels, mut pos, mut start, mut end, mut size) = (Vec::new(), at, at, None, 1);
    loop {
        let len = *msg.get(pos).ok_or("a name runs past the message")?;
        match len & 0xC0 {
            0x00 if len == 0 => return Ok((labels, end.unwrap_or(pos + 1))),
            0x00 => {
                let label =
                    msg.get(pos + 1..pos + 1 + usize::from(len)).ok_or("a label runs past the message")?;
                size += 1 + label.len();
                if size > MAX_NAME {
                    return Err("a name over 255 bytes");
                }
                labels.push(label.to_ascii_lowercase());
                pos += 1 + label.len();
            }
            0xC0 => {
                let low = *msg.get(pos + 1).ok_or("a pointer runs past the message")?;
                let target = (usize::from(len & 0x3F) << 8) | usize::from(low);
                if target >= start {
                    return Err("a compression pointer that does not point back");
                }
                end.get_or_insert(pos + 2);
                (pos, start) = (target, target);
            }
            _ => return Err("an extended label type"),
        }
    }
}

fn labels_of(name: &str) -> Vec<Vec<u8>> {
    name.split('.').map(|l| l.as_bytes().to_ascii_lowercase()).collect()
}

/// A TXT record's character-strings, which must fill its data exactly.
fn strings(rdata: &[u8]) -> Result<TxtRecord, &'static str> {
    if rdata.is_empty() {
        return Err("a TXT record with no string");
    }
    let (mut out, mut i) = (Vec::new(), 0);
    while i < rdata.len() {
        let n = usize::from(rdata[i]);
        out.push(rdata.get(i + 1..i + 1 + n).ok_or("TXT strings that overrun their record")?.to_vec());
        i += 1 + n;
    }
    Ok(out)
}

/// Reads a datagram as the answer to the TXT query `id` for `name`.
#[must_use]
pub fn read_answer(msg: &[u8], id: u16, name: &str) -> Read {
    let Some(flags) = u16_at(msg, 2).filter(|_| u16_at(msg, 0) == Some(id)) else { return Read::Mismatch };
    if flags & 0x8000 == 0 {
        return Read::Mismatch;
    }
    let question =
        (u16_at(msg, 4) == Some(1)).then(|| name_at(msg, HEADER).ok()).flatten().filter(|(q, end)| {
            *q == labels_of(name)
                && u16_at(msg, *end) == Some(TYPE_TXT)
                && u16_at(msg, end + 2) == Some(CLASS_IN)
        });
    let Some((_, end)) = question else { return Read::Mismatch };
    match answers(msg, flags, end + 4, name) {
        Ok(read) => read,
        Err(why) => Read::Failed(why.to_owned()),
    }
}

fn answers(msg: &[u8], flags: u16, mut pos: usize, name: &str) -> Result<Read, &'static str> {
    if msg.len() > PAYLOAD {
        return Err("an answer over 1,232 bytes");
    }
    if flags & 0x0200 != 0 {
        return Err("a truncated answer");
    }
    if (flags >> 11) & 0x0F != 0 {
        return Err("an answer to another opcode");
    }
    match flags & 0x000F {
        0 => {}
        1 => return Ok(Read::FormErr),
        3 => return Ok(Read::Records(Vec::new())),
        _ => return Err("a server failure (SERVFAIL, REFUSED or another code)"),
    }
    let count = u16_at(msg, 6).ok_or("no answer count")?;
    let mut rrs = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let (owner, at) = name_at(msg, pos)?;
        let (kind, class) =
            (u16_at(msg, at).ok_or("a short record")?, u16_at(msg, at + 2).ok_or("a short record")?);
        let len = usize::from(u16_at(msg, at + 8).ok_or("a short record")?);
        let data = (at + 10, at + 10 + len);
        if msg.len() < data.1 {
            return Err("a record runs past the message");
        }
        rrs.push((owner, kind, class, data));
        pos = data.1;
    }
    let mut target = labels_of(name);
    for hop in 0..=MAX_CNAMES {
        let Some((_, _, _, (start, stop))) = rrs
            .iter()
            .find(|(owner, kind, class, _)| *owner == target && *kind == TYPE_CNAME && *class == CLASS_IN)
        else {
            break;
        };
        if hop == MAX_CNAMES {
            return Err("a CNAME chain over 8");
        }
        let (next, end) = name_at(msg, *start)?;
        if end != *stop {
            return Err("a CNAME whose name does not fill its record");
        }
        target = next;
    }
    let found = rrs
        .iter()
        .filter(|(owner, kind, class, _)| *owner == target && *kind == TYPE_TXT && *class == CLASS_IN);
    Ok(Read::Records(
        found.map(|(_, _, _, (start, stop))| strings(&msg[*start..*stop])).collect::<Result<_, _>>()?,
    ))
}

fn random_id() -> Result<u16, String> {
    let mut b = [0u8; 2];
    getrandom::fill(&mut b).map_err(|e| format!("no random id: {e}"))?;
    Ok(u16::from_be_bytes(b))
}

/// One try at one server: the query, then datagrams until one answers it or the try's time is up.
async fn ask(server: SocketAddr, name: &str, edns: bool, wait: Duration) -> Result<Read, String> {
    let id = random_id()?;
    let q = query(name, id, edns).map_err(str::to_owned)?;
    let local: SocketAddr =
        if server.is_ipv4() { (Ipv4Addr::UNSPECIFIED, 0).into() } else { (Ipv6Addr::UNSPECIFIED, 0).into() };
    let socket = UdpSocket::bind(local).await.map_err(|e| format!("bind: {e}"))?;
    socket.connect(server).await.map_err(|e| format!("connect: {e}"))?;
    socket.send(&q).await.map_err(|e| format!("send: {e}"))?;
    let deadline = tokio::time::Instant::now() + wait;
    let mut buf = vec![0u8; PAYLOAD + 1];
    loop {
        match tokio::time::timeout_at(deadline, socket.recv(&mut buf)).await {
            Err(_) => return Err("no answer".to_owned()),
            Ok(Err(e)) => return Err(format!("recv: {e}")),
            Ok(Ok(n)) => match read_answer(&buf[..n], id, name) {
                Read::Mismatch => {}
                read => return Ok(read),
            },
        }
    }
}

/// Asks each server in turn, again without EDNS after a FORMERR, until one answers; else the last failure.
async fn ask_servers(servers: &[SocketAddr], name: &str, wait: Duration) -> Lookup {
    let mut last = String::from("no nameserver");
    for server in servers {
        for edns in [true, false] {
            match ask(*server, name, edns, wait).await {
                Ok(Read::Records(records)) => return Ok(records),
                Ok(Read::FormErr) if edns => continue,
                Ok(Read::FormErr) => last = format!("{server}: FORMERR"),
                Ok(Read::Failed(why)) | Err(why) => last = format!("{server}: {why}"),
                Ok(Read::Mismatch) => last = format!("{server}: no answer"),
            }
            break;
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests;
