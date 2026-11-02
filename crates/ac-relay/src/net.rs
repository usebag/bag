//! Addresses: where the relay listens (`--bind`), the URL it announces (`--advertise`), the further public base URLs a
//! fetch proof may name (`--accept-base`), and the client a request counts and logs as.
//!
//! The relay binds one address, IPv4 or IPv6, by default 127.0.0.1; 0.0.0.0 or `::` listens on every interface.
//! It announces one URL, in its `AC_RELAY_URL=` line and in health: `--advertise` when given, with the port written
//! in it, else none for `https` and the listening one for `http`; otherwise `http://` and the bound
//! address, or the loopback address of its family when that is unspecified. The client is
//! the TCP peer, or the one a trusted proxy names ([`Front::client`]), counted by [`bucket`], logged by [`LogIp`].

use crate::metrics::{METRICS, PROXY_HEADER_IGNORED};
use axum::http::{HeaderMap, HeaderName};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The default bind address: loopback only, so a relay is reachable from other hosts only when asked.
pub const DEFAULT_BIND: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// The header a trusted proxy names the client in by default: cloudflared's `CF-Connecting-IP`.
pub const DEFAULT_CLIENT_IP_HEADER: &str = "cf-connecting-ip";

/// The scheme, host and port to announce instead of the bound address, from `--advertise`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advertise {
    scheme: &'static str,
    host: String,
    port: Option<u16>,
}

impl Advertise {
    /// Parses `http://<host>[:<port>][/]` or `https://<host>[:<port>][/]`, where the host is a name or an IPv4
    /// address of letters, digits, dots and hyphens, or an IPv6 address in brackets, and a port is from 1 to 65535.
    ///
    /// # Errors
    ///
    /// A sentence naming what is wrong: the scheme, the host, the port, or a path, query, fragment or user part.
    pub fn parse(text: &str) -> Result<Advertise, String> {
        let bad = |why: &str| format!("{text:?} is not an http:// or https:// URL of a host: {why}");
        let (scheme, rest) = if let Some(rest) = text.strip_prefix("http://") {
            ("http", rest)
        } else if let Some(rest) = text.strip_prefix("https://") {
            ("https", rest)
        } else {
            return Err(bad("the scheme is http or https"));
        };
        let authority = rest.strip_suffix('/').unwrap_or(rest);
        if authority.contains(['/', '?', '#', '@']) {
            return Err(bad("no path, query, fragment or user part"));
        }
        let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
            let (v6, after) = inner.split_once(']').ok_or_else(|| bad("an IPv6 host ends with ]"))?;
            v6.parse::<Ipv6Addr>().map_err(|_| bad("the host in brackets is an IPv6 address"))?;
            let port = match after {
                "" => None,
                p => Some(p.strip_prefix(':').ok_or_else(|| bad("a port follows the host after :"))?),
            };
            (&authority[..v6.len() + 2], port)
        } else {
            match authority.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            }
        };
        let name = host.starts_with('[')
            || host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
        if host.is_empty() || !name {
            return Err(bad("the host is a name, an IPv4 address or [an IPv6 address]"));
        }
        if let Some(port) = port {
            let digits = !port.is_empty() && port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit());
            if !digits || !matches!(port.parse::<u32>(), Ok(1..=65_535)) {
                return Err(bad("the port is from 1 to 65535"));
            }
        }
        Ok(Advertise { scheme, host: host.to_owned(), port: port.and_then(|p| p.parse().ok()) })
    }
}

/// The URL the relay announces once it listens on `bind` at `port`.
#[must_use]
pub fn announced_url(bind: IpAddr, port: u16, advertise: Option<&Advertise>) -> String {
    if let Some(a) = advertise {
        let port = a.port.or((a.scheme == "http").then_some(port)).map_or(String::new(), |p| format!(":{p}"));
        return format!("{}://{}{port}", a.scheme, a.host);
    }
    let host = match bind {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    format!("http://{}", SocketAddr::new(host, port))
}

/// A public base URL of `--accept-base`, which a fetch proof's audience may name besides the announced URL: a
/// `relays` entry of spec/SPEC.md §7.1, `http://` or `https://`, a lower-case host and a port only when it is not the
/// scheme's default, and nothing further (no path, query, fragment or userinfo, as [`Advertise::parse`] refuses). It is
/// kept as written but for one trailing slash, which is dropped; no port is added.
///
/// # Errors
///
/// [`Advertise::parse`]'s sentence, or one naming the upper-case host or the written default port.
pub fn accept_base(text: &str) -> Result<String, String> {
    let a = Advertise::parse(text)?;
    let bad = |why: &str| format!("{text:?} is not a relays entry (spec/SPEC.md §7.1): {why}");
    if a.host.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(bad("the host is in lower case"));
    }
    if a.port == Some(if a.scheme == "https" { 443 } else { 80 }) {
        return Err(bad("no port is written when it is the scheme's default"));
    }
    Ok(text.strip_suffix('/').unwrap_or(text).to_owned())
}

/// The TCP peer's address, with an IPv4-mapped IPv6 address (an IPv4 client of a relay bound to `::`) read as the
/// IPv4 address it maps, so that a host is one client whichever family the relay binds (implementation default).
#[must_use]
pub fn client_ip(peer: SocketAddr) -> IpAddr {
    peer.ip().to_canonical()
}

/// `ip` with every bit past its first `len` cleared.
fn masked(ip: IpAddr, len: u8) -> IpAddr {
    let n = u32::from(len);
    match ip {
        IpAddr::V4(a) => IpAddr::V4((a.to_bits() & u32::MAX.checked_shl(32 - n).unwrap_or(0)).into()),
        IpAddr::V6(a) => IpAddr::V6((a.to_bits() & u128::MAX.checked_shl(128 - n).unwrap_or(0)).into()),
    }
}

/// The bucket a client counts in for the connection and subscription caps and the pairing rendezvous: its IPv4 address,
/// or its IPv6 address's /64, one host's network.
pub(crate) fn bucket(ip: IpAddr) -> IpAddr {
    let ip = ip.to_canonical();
    if ip.is_ipv4() { ip } else { masked(ip, 64) }
}

/// The bucket a client counts in for the per-address rate limits, the fetch window, the record signers' quota and the
/// byte quota: its IPv4 address, or its IPv6 address's /56, roughly one end site. One routed /48 holds 65,536 /64s, so at
/// /64 these limits would not bound one actor (SPEC §8.9 item 2).
pub(crate) fn rate_bucket(ip: IpAddr) -> IpAddr {
    let ip = ip.to_canonical();
    if ip.is_ipv4() { ip } else { masked(ip, 56) }
}

/// A trusted proxy's network (`--trust-proxy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    len: u8,
}

impl Cidr {
    /// Parses `<address>/<length>`, or one address as its /32 or /128, with no bit set past the length.
    ///
    /// # Errors
    ///
    /// A sentence naming what is wrong.
    pub fn parse(text: &str) -> Result<Cidr, String> {
        let (addr, len) = text.split_once('/').map_or((text, None), |(a, l)| (a, Some(l)));
        let net = addr.parse::<IpAddr>().map_err(|_| format!("{text:?} is not an address or a network"))?;
        let width = if net.is_ipv4() { 32 } else { 128 };
        let len = len.map_or(Some(width), |l| l.parse::<u8>().ok().filter(|l| *l <= width));
        let len = len.ok_or_else(|| format!("{text:?}: the length is from 0 to {width}"))?;
        if masked(net, len) != net {
            return Err(format!("{text:?} has bits set past its /{len}"));
        }
        Ok(Cidr { net, len })
    }

    /// Whether `ip` (IPv4-mapped read as IPv4) is inside the network.
    fn contains(self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        ip.is_ipv4() == self.net.is_ipv4() && masked(ip, self.len) == self.net
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.net, self.len)
    }
}

/// How a log line names a client's address (`--log-ip`, 2026-10-25).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum LogIp {
    /// Its /24 (IPv4) or /48 (IPv6), the default.
    #[default]
    Prefix,
    /// The whole address, for studies.
    Full,
    /// Nothing: `-`.
    None,
}

impl LogIp {
    /// `ip` as the log lines name it: `203.0.113.0/24`, `2001:db8:1::/48`, the address, or `-`.
    pub(crate) fn show(self, ip: IpAddr) -> String {
        match (self, ip.to_canonical()) {
            (LogIp::Full, ip) => ip.to_string(),
            (LogIp::None, _) => "-".to_owned(),
            (LogIp::Prefix, ip @ IpAddr::V4(_)) => format!("{}/24", masked(ip, 24)),
            (LogIp::Prefix, ip) => format!("{}/48", masked(ip, 48)),
        }
    }
}

/// Who may name a request's client, and how the log lines name clients.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Front {
    /// The networks of the trusted proxies; none by default, so that no header is read.
    pub trusted: Vec<Cidr>,
    /// The header in which a trusted proxy names the client; [`DEFAULT_CLIENT_IP_HEADER`] when `None`.
    pub header: Option<HeaderName>,
    /// How the log lines name a client's address.
    pub log_ip: LogIp,
}

impl Front {
    /// Whether `ip` is inside a trusted proxy's network.
    pub(crate) fn trusts(&self, ip: IpAddr) -> bool {
        self.trusted.iter().any(|c| c.contains(ip))
    }

    /// The client of a request from `peer`: the peer ([`client_ip`]), unless it is a trusted proxy whose header names
    /// one: the right-most address of the header's values (its lines joined by commas) not a trusted proxy's. A value
    /// that is not an address voids the header, as does a list of trusted addresses only: the request is the proxy's.
    /// A header not read is counted ([`PROXY_HEADER_IGNORED`]): `untrusted-source` from a peer not trusted, `malformed`
    /// for a value that is not an address.
    pub(crate) fn client(&self, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
        let (peer, name) = (client_ip(peer), self.header.clone());
        let name = name.unwrap_or(HeaderName::from_static(DEFAULT_CLIENT_IP_HEADER));
        let values: Option<Vec<&str>> = headers.get_all(name).iter().map(|v| v.to_str().ok()).collect();
        let ignored = |reason| {
            METRICS.count(PROXY_HEADER_IGNORED, "reason", reason);
            peer
        };
        let values = match values {
            Some(values) if values.is_empty() => return peer,
            _ if !self.trusts(peer) => return ignored("untrusted-source"),
            None => return ignored("malformed"),
            Some(values) => values,
        };
        for entry in values.iter().flat_map(|v| v.split(',')).rev() {
            match entry.trim().parse::<IpAddr>() {
                Ok(ip) if self.trusts(ip) => {}
                Ok(ip) => return ip.to_canonical(),
                Err(_) => return ignored("malformed"),
            }
        }
        peer
    }
}

#[cfg(test)]
mod tests;
