//! The private-address guard (spec/SPEC.md §10): whether an IP address may be the target of
//! a fetch that another party chose, such as the relay reading the well-known record of a domain an accept-from record
//! names. It parses and classifies only; the caller resolves a host and passes every address it got.
//! `packages/core/src/net.ts` classifies the same way, and both are tested on one table of cases.
//!
//! Not public: the IANA special-purpose ranges ([`Category`] names each), in IPv4 `0/8`, `10/8`, `100.64/10`,
//! `127/8`, `169.254/16`, `172.16/12`, `192.0.0/24`, `192.0.2/24`, `192.88.99/24`, `192.168/16`, `198.18/15`,
//! `198.51.100/24`, `203.0.113/24`, `224/4` and `240/4`, and in IPv6 `::`, `::1`, `fc00::/7`, `fe80::/10`,
//! `ff00::/8`, `2001:db8::/32`, `3fff::/20`, `2001::/23`, `2002::/16` and everything outside `2000::/3`. An
//! IPv4-mapped address (`::ffff:0:0/96`) or a NAT64 one (`64:ff9b::/96`) takes the category of the IPv4 address it
//! carries.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Where an address belongs: [`Category::Public`], or the special-purpose range that makes it not public.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Category {
    /// Globally reachable.
    Public,
    /// `0.0.0.0/8` ("this network") and `::`.
    Unspecified,
    /// `127.0.0.0/8` and `::1`.
    Loopback,
    /// `169.254.0.0/16` and `fe80::/10`.
    LinkLocal,
    /// RFC 1918: `10.0.0.0/8`, `172.16.0.0/12` and `192.168.0.0/16`.
    Private,
    /// RFC 6598, `100.64.0.0/10` (carrier-grade NAT).
    Shared,
    /// RFC 4193 unique local, `fc00::/7`.
    Ula,
    /// `224.0.0.0/4` and `ff00::/8`.
    Multicast,
    /// `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32` and `3fff::/20`.
    Documentation,
    /// RFC 2544, `198.18.0.0/15`.
    Benchmarking,
    /// IETF protocol assignments: `192.0.0.0/24`, `2001::/23` (Teredo among them) and `2002::/16` (6to4).
    Special,
    /// The rest that is not unicast on the Internet: `240.0.0.0/4` (with the broadcast address), `192.88.99.0/24`,
    /// and IPv6 outside `2000::/3`.
    Reserved,
}

impl Category {
    /// Every category, [`Category::Public`] first, in the order of `NET_CATEGORIES` in `packages/core/src/net.ts`.
    pub const ALL: [Category; 12] = [
        Category::Public,
        Category::Unspecified,
        Category::Loopback,
        Category::LinkLocal,
        Category::Private,
        Category::Shared,
        Category::Ula,
        Category::Multicast,
        Category::Documentation,
        Category::Benchmarking,
        Category::Special,
        Category::Reserved,
    ];

    /// The category's name, as `packages/core/src/net.ts` writes it, for example `"link-local"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Category::Public => "public",
            Category::Unspecified => "unspecified",
            Category::Loopback => "loopback",
            Category::LinkLocal => "link-local",
            Category::Private => "private",
            Category::Shared => "shared",
            Category::Ula => "ula",
            Category::Multicast => "multicast",
            Category::Documentation => "documentation",
            Category::Benchmarking => "benchmarking",
            Category::Special => "special",
            Category::Reserved => "reserved",
        }
    }

    /// Whether a fetch may go to an address of this category.
    #[must_use]
    pub const fn is_public(self) -> bool {
        matches!(self, Category::Public)
    }
}

/// The IPv4 ranges that are not public, as (first octets, prefix length, category), checked in order.
const V4: [(u32, u32, Category); 15] = [
    (0x0000_0000, 8, Category::Unspecified),
    (0x0a00_0000, 8, Category::Private),
    (0x6440_0000, 10, Category::Shared),
    (0x7f00_0000, 8, Category::Loopback),
    (0xa9fe_0000, 16, Category::LinkLocal),
    (0xac10_0000, 12, Category::Private),
    (0xc000_0000, 24, Category::Special),
    (0xc000_0200, 24, Category::Documentation),
    (0xc058_6300, 24, Category::Reserved),
    (0xc0a8_0000, 16, Category::Private),
    (0xc612_0000, 15, Category::Benchmarking),
    (0xc633_6400, 24, Category::Documentation),
    (0xcb00_7100, 24, Category::Documentation),
    (0xe000_0000, 4, Category::Multicast),
    (0xf000_0000, 4, Category::Reserved),
];

/// The IPv6 ranges inside `2000::/3` that are not public, as (first bits, prefix length, category).
const V6: [(u128, u32, Category); 4] = [
    (0x2001_0db8 << 96, 32, Category::Documentation),
    (0x3fff << 112, 20, Category::Documentation),
    (0x2001 << 112, 23, Category::Special),
    (0x2002 << 112, 16, Category::Special),
];

fn in_prefix_v4(addr: u32, first: u32, prefix: u32) -> bool {
    (addr ^ first) >> (32 - prefix) == 0
}

fn in_prefix_v6(addr: u128, first: u128, prefix: u32) -> bool {
    (addr ^ first) >> (128 - prefix) == 0
}

fn classify_v4(ip: Ipv4Addr) -> Category {
    let n = u32::from(ip);
    V4.iter().find(|(first, prefix, _)| in_prefix_v4(n, *first, *prefix)).map_or(Category::Public, |r| r.2)
}

fn classify_v6(ip: Ipv6Addr) -> Category {
    let n = u128::from(ip);
    let o = ip.octets();
    if n == 0 {
        Category::Unspecified
    } else if n == 1 {
        Category::Loopback
    } else if n >> 8 == 0 {
        Category::Reserved
    } else if in_prefix_v6(n, 0xffff << 32, 96) || in_prefix_v6(n, 0x0064_ff9b << 96, 96) {
        // IPv4-mapped, or NAT64 (RFC 6052): the IPv4 address it carries decides.
        classify_v4(Ipv4Addr::new(o[12], o[13], o[14], o[15]))
    } else if in_prefix_v6(n, 0xfc << 120, 7) {
        Category::Ula
    } else if in_prefix_v6(n, 0xfe80 << 112, 10) {
        Category::LinkLocal
    } else if in_prefix_v6(n, 0xff << 120, 8) {
        Category::Multicast
    } else if !in_prefix_v6(n, 0x2 << 124, 3) {
        Category::Reserved
    } else {
        V6.iter()
            .find(|(first, prefix, _)| in_prefix_v6(n, *first, *prefix))
            .map_or(Category::Public, |r| r.2)
    }
}

/// The category of an address.
#[must_use]
pub fn classify(ip: IpAddr) -> Category {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

/// An IP address literal (std's reader: dotted-quad IPv4 with no leading zeros, or IPv6 text with at most one `::`
/// and an optional IPv4 tail; no brackets, zone or port), or none.
#[must_use]
pub fn parse_ip(text: &str) -> Option<IpAddr> {
    text.parse().ok()
}

/// The first of `addresses` that is not public, with its category; none when every one is public. An empty list
/// gives none too: the caller refuses a host that resolved to no address on its own.
#[must_use]
pub fn first_non_public(addresses: &[IpAddr]) -> Option<(IpAddr, Category)> {
    addresses.iter().map(|ip| (*ip, classify(*ip))).find(|(_, c)| !c.is_public())
}

/// Whether a host is an IP literal, or would be read as one: it is an address (also inside brackets), or its last
/// dot-separated label is decimal digits or `0x` and hex digits (the WHATWG URL rule "ends in a number", which
/// inet_aton-style resolvers follow too, so `127.1`, `0177.0.0.1` and `0x7f.1` count). `isIpLiteralHost` in
/// `packages/core/src/net.ts`.
#[must_use]
pub fn is_ip_literal_host(host: &str) -> bool {
    let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    if parse_ip(bare).is_some() {
        return true;
    }
    // A trailing dot names the root zone: the label before it is the last one.
    let trimmed = bare.strip_suffix('.').filter(|t| !t.is_empty()).unwrap_or(bare);
    let last = trimmed.rsplit('.').next().unwrap_or_default();
    let hex = last.strip_prefix("0x").or_else(|| last.strip_prefix("0X"));
    match hex {
        Some(digits) => digits.bytes().all(|b| b.is_ascii_hexdigit()),
        None => !last.is_empty() && last.bytes().all(|b| b.is_ascii_digit()),
    }
}

#[cfg(test)]
mod tests;
