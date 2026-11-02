use super::{
    Advertise, Cidr, DEFAULT_BIND, Front, LogIp, accept_base, announced_url, bucket, client_ip, rate_bucket,
};
use crate::testkit::counted;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

#[test]
fn rate_limits_key_ipv6_at_its_56_and_the_connection_caps_at_its_64() {
    let (a, b) = (ip("2001:db8:1:100::1"), ip("2001:db8:1:1ff::1"));
    assert_ne!(bucket(a), bucket(b), "two /64s");
    assert_eq!(rate_bucket(a), rate_bucket(b), "one /56");
    assert_eq!(rate_bucket(a), ip("2001:db8:1:100::"));
    assert_ne!(rate_bucket(a), rate_bucket(ip("2001:db8:1:200::1")), "another /56");
    assert_eq!(rate_bucket(ip("::ffff:203.0.113.7")), ip("203.0.113.7"));
}

#[test]
fn the_default_bind_is_loopback() {
    assert_eq!(DEFAULT_BIND, IpAddr::V4(Ipv4Addr::LOCALHOST));
}

#[test]
fn without_advertise_the_url_is_the_bound_address_or_the_loopback_of_an_unspecified_one() {
    assert_eq!(announced_url(DEFAULT_BIND, 7777, None), "http://127.0.0.1:7777");
    assert_eq!(announced_url(ip("192.168.1.20"), 7777, None), "http://192.168.1.20:7777");
    assert_eq!(announced_url(ip("0.0.0.0"), 80, None), "http://127.0.0.1:80");
    assert_eq!(announced_url(ip("::"), 7777, None), "http://[::1]:7777");
    assert_eq!(announced_url(ip("::1"), 7777, None), "http://[::1]:7777");
    assert_eq!(announced_url(ip("fd7a:115c:a1e0::1"), 9, None), "http://[fd7a:115c:a1e0::1]:9");
}

#[test]
fn advertise_keeps_a_written_port_and_otherwise_names_none_for_https_and_the_listening_one_for_http() {
    // Once the port was always the listening one, so a relay behind a TLS proxy announced
    // https://relay-acme.usuals.now:7701, a URL no client can use.
    let lan = Advertise::parse("http://192.168.1.20:7777").unwrap();
    assert_eq!(announced_url(ip("0.0.0.0"), 7777, Some(&lan)), "http://192.168.1.20:7777");
    assert_eq!(announced_url(ip("0.0.0.0"), 54_321, Some(&lan)), "http://192.168.1.20:7777", "written: kept");
    let cases = [
        ("http://100.74.1.2", "http://100.74.1.2:7777"),
        ("http://relay.tailnet-1.ts.net/", "http://relay.tailnet-1.ts.net:7777"),
        ("https://Relay.Example:443/", "https://Relay.Example:443"),
        ("https://relay-acme.usuals.now", "https://relay-acme.usuals.now"),
        ("https://relay.example:8443/", "https://relay.example:8443"),
        ("https://[fd7a:115c:a1e0::1]", "https://[fd7a:115c:a1e0::1]"),
        ("http://[fd7a:115c:a1e0::1]", "http://[fd7a:115c:a1e0::1]:7777"),
        ("http://[::1]:8080/", "http://[::1]:8080"),
        ("http://localhost:1", "http://localhost:1"),
        ("http://a:65535", "http://a:65535"),
    ];
    for (text, url) in cases {
        let a = Advertise::parse(text).unwrap_or_else(|e| panic!("{text}: {e}"));
        assert_eq!(announced_url(ip("::"), 7777, Some(&a)), url, "{text}");
    }
}

#[test]
fn an_accept_base_is_a_relays_entry_kept_as_written_but_for_one_trailing_slash() {
    for (text, base) in [
        ("https://relay2.bag.dev", "https://relay2.bag.dev"),
        ("https://relay2.bag.dev/", "https://relay2.bag.dev"),
        ("https://relay2.bag.dev:8443", "https://relay2.bag.dev:8443"),
        ("http://relay.example", "http://relay.example"),
        ("http://relay.example:443", "http://relay.example:443"),
        ("http://[::1]:8080", "http://[::1]:8080"),
    ] {
        assert_eq!(accept_base(text).as_deref(), Ok(base), "{text}");
    }
    for (text, why) in [
        ("ftp://relay.example", "the scheme"),
        ("HTTPS://relay.example", "the scheme"),
        ("https://", "the host"),
        ("https://Relay2.bag.dev", "lower case"),
        ("https://[FD7A::1]", "lower case"),
        ("https://relay2.bag.dev:443", "default"),
        ("http://relay.example:80/", "default"),
        ("https://user@relay.example", "no path"),
        ("https://relay.example/bag", "no path"),
        ("https://relay.example//", "no path"),
        ("https://relay.example?x", "no path"),
        ("https://relay.example#x", "no path"),
        ("https://a b", "the host"),
    ] {
        let refused = accept_base(text).expect_err(text);
        assert!(refused.contains(why), "{text}: {refused}");
    }
}

#[test]
fn advertise_refuses_anything_but_a_scheme_a_host_and_a_port() {
    let cases = [
        ("192.168.1.20:7777", "the scheme"),
        ("ftp://relay.example", "the scheme"),
        ("HTTP://relay.example", "the scheme"),
        ("http://", "the host"),
        ("http:///", "the host"),
        ("http://:7777", "the host"),
        ("http://relay example", "the host"),
        ("http://relay_example", "the host"),
        ("http://relay.example/v0", "no path"),
        ("http://relay.example//", "no path"),
        ("http://relay.example?x=1", "no path"),
        ("http://relay.example#x", "no path"),
        ("http://user@relay.example", "no path"),
        ("http://relay.example:", "the port"),
        ("http://relay.example:0", "the port"),
        ("http://relay.example:65536", "the port"),
        ("http://relay.example:123456", "the port"),
        ("http://relay.example:+80", "the port"),
        ("http://relay.example:80:80", "the port"),
        ("http://[::1", "ends with ]"),
        ("http://[not-v6]", "in brackets"),
        ("http://[192.168.1.20]", "in brackets"),
        ("http://[::1]x", "a port follows"),
        ("http://[::1]:", "the port"),
    ];
    for (text, why) in cases {
        let e = Advertise::parse(text).expect_err(text);
        assert!(e.contains(why) && e.contains(&format!("{text:?}")), "{text}: {e}");
    }
}

#[test]
fn a_client_is_its_peer_address_with_an_ipv4_mapped_address_read_as_ipv4() {
    let v4 = SocketAddr::new(ip("192.168.1.5"), 50_000);
    assert_eq!(client_ip(v4), ip("192.168.1.5"));
    let mapped = SocketAddr::new(IpAddr::V6(Ipv4Addr::new(192, 168, 1, 5).to_ipv6_mapped()), 50_000);
    assert_eq!(client_ip(mapped), ip("192.168.1.5"));
    let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 50_000);
    assert_eq!(client_ip(v6), ip("::1"));
}

// --- trusted proxies, buckets and log modes ------------------------------------------------------

fn cidr(text: &str) -> Cidr {
    Cidr::parse(text).unwrap_or_else(|e| panic!("{text}: {e}"))
}

#[test]
fn a_cidr_is_a_network_or_one_address_and_nothing_else() {
    for (text, shown) in [
        ("172.16.207.0/28", "172.16.207.0/28"),
        ("10.0.0.0/8", "10.0.0.0/8"),
        ("0.0.0.0/0", "0.0.0.0/0"),
        ("127.0.0.1", "127.0.0.1/32"),
        ("2001:db8::/32", "2001:db8::/32"),
        ("::/0", "::/0"),
        ("::1", "::1/128"),
    ] {
        assert_eq!(cidr(text).to_string(), shown, "{text}");
    }
    for (text, why) in [
        ("0.0.0.0/33", "the length is from 0 to 32"),
        ("::1/129", "the length is from 0 to 128"),
        ("10.0.0.0/x", "the length"),
        ("10.0.0.0/", "the length"),
        ("10.0.0.0/-1", "the length"),
        ("10.0.0.1/8", "bits set past its /8"),
        ("2001:db8::1/64", "bits set past its /64"),
        ("relay.example", "not an address or a network"),
        ("", "not an address or a network"),
        ("[::1]", "not an address or a network"),
        ("10.0.0.0/8/8", "the length"),
    ] {
        let e = Cidr::parse(text).expect_err(text);
        assert!(e.contains(why) && e.contains(&format!("{text:?}")), "{text}: {e}");
    }
}

#[test]
fn a_cidr_holds_the_addresses_of_its_family_and_an_ipv4_mapped_one_is_read_as_ipv4() {
    let net = cidr("172.16.207.0/28");
    assert!(net.contains(ip("172.16.207.0")) && net.contains(ip("172.16.207.15")));
    assert!(!net.contains(ip("172.16.207.16")) && !net.contains(ip("172.16.206.255")));
    assert!(net.contains(IpAddr::V6(Ipv4Addr::new(172, 16, 207, 2).to_ipv6_mapped())));
    assert!(!net.contains(ip("::ffff:172.17.207.2")));
    assert!(!net.contains(ip("2001:db8::1")), "another family");
    assert!(cidr("0.0.0.0/0").contains(ip("203.0.113.7")) && !cidr("0.0.0.0/0").contains(ip("::1")));
    let v6 = cidr("2001:db8::/32");
    assert!(
        v6.contains(ip("2001:db8:ffff::1"))
            && !v6.contains(ip("2001:db9::1"))
            && !v6.contains(ip("10.0.0.1"))
    );
    assert!(cidr("::/0").contains(ip("fe80::1")) && cidr("::1").contains(ip("::1")));
}

#[test]
fn a_client_is_counted_by_its_ipv4_address_or_its_ipv6_64() {
    assert_eq!(bucket(ip("203.0.113.7")), ip("203.0.113.7"));
    assert_eq!(bucket(ip("::ffff:203.0.113.7")), ip("203.0.113.7"));
    assert_eq!(bucket(ip("2001:db8:1:2:aaaa:bbbb:cccc:dddd")), ip("2001:db8:1:2::"));
    assert_eq!(bucket(ip("2001:db8:1:2::1")), bucket(ip("2001:db8:1:2:ffff:ffff:ffff:ffff")), "one /64");
    assert_ne!(bucket(ip("2001:db8:1:2::1")), bucket(ip("2001:db8:1:3::1")), "another /64");
}

#[test]
fn the_log_names_a_client_by_its_24_or_48_by_default_the_whole_address_on_full_and_nothing_on_none() {
    assert_eq!(LogIp::default(), LogIp::Prefix);
    let cases = [
        ("203.0.113.7", "203.0.113.0/24", "203.0.113.7"),
        ("::ffff:203.0.113.7", "203.0.113.0/24", "203.0.113.7"),
        ("127.0.0.1", "127.0.0.0/24", "127.0.0.1"),
        ("2001:db8:1:2:3:4:5:6", "2001:db8:1::/48", "2001:db8:1:2:3:4:5:6"),
        ("::1", "::/48", "::1"),
    ];
    for (address, prefix, full) in cases {
        assert_eq!(LogIp::Prefix.show(ip(address)), prefix, "{address}");
        assert_eq!(LogIp::Full.show(ip(address)), full, "{address}");
        assert_eq!(LogIp::None.show(ip(address)), "-", "{address}");
    }
}

fn front(trusted: &[&str], header: Option<&str>) -> Front {
    let header = header.map(|h| HeaderName::from_bytes(h.as_bytes()).unwrap());
    Front { trusted: trusted.iter().map(|t| cidr(t)).collect(), header, log_ip: LogIp::Full }
}

fn headers(name: &str, values: &[&[u8]]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for v in values {
        map.append(HeaderName::from_bytes(name.as_bytes()).unwrap(), HeaderValue::from_bytes(v).unwrap());
    }
    map
}

const PROXY: &str = "127.0.0.1:50000";

#[test]
fn a_trusted_peer_names_its_client_in_the_header_and_any_other_peer_is_its_own_client() {
    let peer: SocketAddr = PROXY.parse().unwrap();
    let named = headers("cf-connecting-ip", &[b"203.0.113.7"]);
    assert_eq!(front(&["127.0.0.0/8"], None).client(peer, &named), ip("203.0.113.7"));
    assert_eq!(front(&["10.0.0.0/8"], None).client(peer, &named), ip("127.0.0.1"), "the peer is not trusted");
    assert_eq!(front(&[], None).client(peer, &named), ip("127.0.0.1"), "no proxy: no header is read");
    assert_eq!(front(&["127.0.0.0/8"], None).client(peer, &HeaderMap::new()), ip("127.0.0.1"), "no header");
    let mapped = SocketAddr::new(IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()), 50_000);
    assert_eq!(front(&["127.0.0.0/8"], None).client(mapped, &named), ip("203.0.113.7"), "a mapped peer");
    let v6 = headers("cf-connecting-ip", &[b" 2001:db8::7 "]);
    assert_eq!(front(&["127.0.0.1"], None).client(peer, &v6), ip("2001:db8::7"), "trimmed, IPv6");
    let mapped_client = headers("cf-connecting-ip", &[b"::ffff:198.51.100.9"]);
    assert_eq!(front(&["127.0.0.1"], None).client(peer, &mapped_client), ip("198.51.100.9"));
    // Another header name: the default one counts for nothing then.
    let custom = front(&["127.0.0.0/8"], Some("x-real-ip"));
    assert_eq!(custom.client(peer, &named), ip("127.0.0.1"));
    assert_eq!(custom.client(peer, &headers("x-real-ip", &[b"192.0.2.44"])), ip("192.0.2.44"));
}

#[test]
fn a_malformed_value_from_a_trusted_peer_leaves_the_peer_never_a_third_address() {
    let peer: SocketAddr = PROXY.parse().unwrap();
    let f = front(&["127.0.0.0/8"], None);
    for value in [
        &b"not-an-ip"[..],
        b"203.0.113.7:80",
        b"[2001:db8::1]",
        b"",
        b"   ",
        b"203.0.113.7, junk",
        b"203.0.113.256",
        b"\xff\xfe",
    ] {
        assert_eq!(f.client(peer, &headers("cf-connecting-ip", &[value])), ip("127.0.0.1"), "{value:?}");
    }
    // Two lines of the header are one list, right-most first; a bad line voids the header.
    let two = headers("cf-connecting-ip", &[b"198.51.100.1", b"203.0.113.7"]);
    assert_eq!(f.client(peer, &two), ip("203.0.113.7"));
    let bad_line = headers("cf-connecting-ip", &[b"203.0.113.7", b"\xff"]);
    assert_eq!(f.client(peer, &bad_line), ip("127.0.0.1"));
}

#[test]
fn a_header_not_read_is_counted_untrusted_source_from_a_peer_not_trusted_and_else_malformed() {
    let series = |reason: &str| format!("ac_relay_proxy_header_ignored_total{{reason=\"{reason}\"}}");
    let (untrusted, malformed) = (counted(&series("untrusted-source")), counted(&series("malformed")));
    let peer: SocketAddr = PROXY.parse().unwrap();
    let spoofed = headers("cf-connecting-ip", &[b"203.0.113.7"]);
    assert_eq!(front(&[], None).client(peer, &spoofed), ip("127.0.0.1"));
    let unreadable = headers("cf-connecting-ip", &[b"\xff"]);
    assert_eq!(front(&["10.0.0.0/8"], None).client(peer, &unreadable), ip("127.0.0.1"));
    assert!(counted(&series("untrusted-source")) >= untrusted + 2, "an untrusted peer's, readable or not");
    let f = front(&["127.0.0.0/8"], None);
    for value in [&b"junk"[..], b"\xff", b"203.0.113.7, junk"] {
        assert_eq!(f.client(peer, &headers("cf-connecting-ip", &[value])), ip("127.0.0.1"), "{value:?}");
    }
    assert!(counted(&series("malformed")) >= malformed + 3);
}

#[test]
fn x_forwarded_for_takes_the_right_most_address_that_is_not_a_trusted_proxy() {
    let peer: SocketAddr = PROXY.parse().unwrap();
    let f = front(&["127.0.0.0/8", "172.16.207.0/28"], Some("x-forwarded-for"));
    let xff = |v: &'static [u8]| headers("x-forwarded-for", &[v]);
    assert_eq!(f.client(peer, &xff(b"192.0.2.1, 203.0.113.7, 127.0.0.1")), ip("203.0.113.7"));
    assert_eq!(f.client(peer, &xff(b"192.0.2.1,203.0.113.7,172.16.207.2,127.0.0.9")), ip("203.0.113.7"));
    assert_eq!(f.client(peer, &xff(b"junk, 203.0.113.7")), ip("203.0.113.7"), "left of the client: not read");
    assert_eq!(f.client(peer, &xff(b"127.0.0.2, 172.16.207.3")), ip("127.0.0.1"), "proxies only: the peer");
}
