use super::{Category, classify, first_non_public, is_ip_literal_host, parse_ip};
use std::collections::BTreeMap;
use std::net::IpAddr;

/// The classification table, row for row the same as packages/core/test/net.test.ts.
const CLASSIFIED: [(&str, &str); 76] = [
    ("0.0.0.0", "unspecified"),
    ("0.255.255.255", "unspecified"),
    ("1.1.1.1", "public"),
    ("8.8.8.8", "public"),
    ("9.255.255.255", "public"),
    ("10.0.0.0", "private"),
    ("10.255.255.255", "private"),
    ("11.0.0.0", "public"),
    ("100.63.255.255", "public"),
    ("100.64.0.0", "shared"),
    ("100.127.255.255", "shared"),
    ("100.128.0.0", "public"),
    ("126.255.255.255", "public"),
    ("127.0.0.1", "loopback"),
    ("127.255.255.254", "loopback"),
    ("128.0.0.0", "public"),
    ("169.253.255.255", "public"),
    ("169.254.0.1", "link-local"),
    ("169.254.169.254", "link-local"),
    ("169.255.0.0", "public"),
    ("172.15.255.255", "public"),
    ("172.16.0.0", "private"),
    ("172.31.255.255", "private"),
    ("172.32.0.0", "public"),
    ("192.0.0.8", "special"),
    ("192.0.1.0", "public"),
    ("192.0.2.1", "documentation"),
    ("192.88.99.1", "reserved"),
    ("192.167.255.255", "public"),
    ("192.168.0.1", "private"),
    ("192.168.255.255", "private"),
    ("192.169.0.0", "public"),
    ("198.17.255.255", "public"),
    ("198.18.0.0", "benchmarking"),
    ("198.19.255.255", "benchmarking"),
    ("198.20.0.0", "public"),
    ("198.51.100.7", "documentation"),
    ("203.0.113.9", "documentation"),
    ("223.255.255.255", "public"),
    ("224.0.0.1", "multicast"),
    ("239.255.255.250", "multicast"),
    ("240.0.0.1", "reserved"),
    ("255.255.255.255", "reserved"),
    ("::", "unspecified"),
    ("::1", "loopback"),
    ("::2", "reserved"),
    ("::1.2.3.4", "reserved"),
    ("::ffff:127.0.0.1", "loopback"),
    ("::ffff:7f00:1", "loopback"),
    ("::ffff:10.1.2.3", "private"),
    ("::ffff:169.254.169.254", "link-local"),
    ("::ffff:8.8.8.8", "public"),
    ("64:ff9b::8.8.8.8", "public"),
    ("64:ff9b::192.168.1.1", "private"),
    ("64:ff9b:1::1", "reserved"),
    ("100::1", "reserved"),
    ("1fff:ffff::1", "reserved"),
    ("2001::1", "special"),
    ("2001:1ff:ffff::1", "special"),
    ("2001:200::1", "public"),
    ("2001:db8::1", "documentation"),
    ("2002:c000:204::1", "special"),
    ("2606:4700:4700::1111", "public"),
    ("2a00:1450:4001::1", "public"),
    ("3fff::1", "documentation"),
    ("3fff:1000::1", "public"),
    ("4000::1", "reserved"),
    ("fc00::1", "ula"),
    ("fd12:3456:789a::1", "ula"),
    ("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ula"),
    ("fe80::1", "link-local"),
    ("FE80::ABCD", "link-local"),
    ("febf:ffff::1", "link-local"),
    ("fec0::1", "reserved"),
    ("ff02::1", "multicast"),
    ("ff0e::1", "multicast"),
];
/// Text that is not an IP address literal, the same list as packages/core/test/net.test.ts.
const UNPARSED: [&str; 21] = [
    "",
    "1.2.3",
    "1.2.3.4.5",
    "256.0.0.1",
    "01.2.3.4",
    "1.2.3.04",
    "0x7f.0.0.1",
    "1.2.3.4 ",
    " 1.2.3.4",
    "::1%en0",
    "[::1]",
    "1:2:3:4:5:6:7:8:9",
    "1::2::3",
    ":::",
    ":1",
    "1:",
    "12345::",
    "::ffff:1.2.3",
    "1.2.3.4::",
    "1:2:3:4:5:6:7:1.2.3.4",
    "::g",
];

fn category(name: &str) -> Category {
    Category::ALL.into_iter().find(|c| c.as_str() == name).unwrap_or_else(|| panic!("no category {name}"))
}

#[test]
fn every_row_of_the_table_classifies_as_its_category() {
    for (text, name) in CLASSIFIED {
        let ip = parse_ip(text).unwrap_or_else(|| panic!("{text} is an address"));
        assert_eq!(classify(ip), category(name), "{text}");
        assert_eq!(classify(ip).is_public(), name == "public", "{text}");
    }
}

#[test]
fn the_table_has_every_category_with_these_counts() {
    let mut counts: BTreeMap<&str, usize> = Category::ALL.iter().map(|c| (c.as_str(), 0)).collect();
    for (_, name) in CLASSIFIED {
        *counts.get_mut(name).unwrap() += 1;
    }
    let expected = [
        ("public", 24),
        ("unspecified", 3),
        ("loopback", 5),
        ("link-local", 6),
        ("private", 8),
        ("shared", 2),
        ("ula", 3),
        ("multicast", 4),
        ("documentation", 5),
        ("benchmarking", 2),
        ("special", 4),
        ("reserved", 10),
    ];
    assert_eq!(counts, expected.into_iter().collect());
    let distinct: std::collections::BTreeSet<&str> = CLASSIFIED.iter().map(|(t, _)| *t).collect();
    assert_eq!(distinct.len(), 76);
}

#[test]
fn text_that_is_no_address_parses_to_none() {
    for text in UNPARSED {
        assert_eq!(parse_ip(text), None, "{text:?}");
    }
}

#[test]
fn the_names_are_the_typescript_core_s() {
    let names: Vec<&str> = Category::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(
        names,
        [
            "public",
            "unspecified",
            "loopback",
            "link-local",
            "private",
            "shared",
            "ula",
            "multicast",
            "documentation",
            "benchmarking",
            "special",
            "reserved"
        ]
    );
}

#[test]
fn a_host_is_judged_by_its_first_address_that_is_not_public() {
    let ip = |t: &str| t.parse::<IpAddr>().unwrap();
    assert_eq!(first_non_public(&[]), None);
    assert_eq!(first_non_public(&[ip("8.8.8.8"), ip("2606:4700:4700::1111")]), None);
    assert_eq!(
        first_non_public(&[ip("8.8.8.8"), ip("10.0.0.1"), ip("127.0.0.1")]),
        Some((ip("10.0.0.1"), Category::Private))
    );
}

#[test]
fn ip_literal_hosts_are_the_typescript_core_s() {
    let cases = [
        ("1.2.3.4", true),
        ("127.1", true),
        ("0177.0.0.1", true),
        ("0x7f.1", true),
        ("1.0x7f", true),
        ("1.0X7F", true),
        ("example.0x", true),
        ("2130706433", true),
        ("1.2.3.4.", true),
        ("::1", true),
        ("[::1]", true),
        ("[fe80::1]", true),
        ("acme.example", false),
        ("acme.example.", false),
        ("0x7f.example", false),
        ("a1.b2", false),
        ("1a.2b", false),
        (".", false),
        ("", false),
        ("[acme.example]", false),
    ];
    for (host, literal) in cases {
        assert_eq!(is_ip_literal_host(host), literal, "{host:?}");
    }
    assert!(!is_ip_literal_host("0x7g") && !is_ip_literal_host("a..") && !is_ip_literal_host("["));
}
