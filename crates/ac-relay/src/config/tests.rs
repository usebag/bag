use super::{BODY_LIMIT, Config, RateLimits, WellKnown};
use ac_core::records::Domain;
use std::time::Duration;

#[test]
fn the_defaults_are_the_plan_s() {
    let c = Config::default();
    assert_eq!((c.ttl, c.skew, c.max_envelope_bytes, c.body_limit), (604_800, 300, 196_608, 262_144));
    assert_eq!(c.record_limit, 131_072);
    assert_eq!(
        c.rate,
        RateLimits {
            window: 60,
            per_from: 120,
            per_root: 1_200,
            per_ip: 600,
            fetch_per_ip: 6_000,
            fetch_global_per_minute: 30_000,
            signers_per_day: 100,
            bytes_per_day: 100_000_000,
            domain_day: 10_000
        }
    );
    assert_eq!(c.max_unacked, 32);
    assert_eq!((c.ping_interval, c.idle_timeout), (Duration::from_secs(30), Duration::from_mins(1)));
    assert_eq!(c.sweep_interval, Duration::from_mins(1));
    assert_eq!(
        (c.header_timeout, c.body_timeout, c.connections_per_ip),
        (Duration::from_secs(10), Duration::from_secs(30), 79)
    );
    assert_eq!(
        c.well_known,
        WellKnown {
            timeout: Duration::from_secs(10),
            cache_max: 86_400,
            insecure_http: false,
            resolve: vec![],
            dns_resolve: vec![]
        }
    );
    assert!(!c.well_known.is_test_only());
    assert!(c.validate().is_ok());
}

#[test]
fn a_direct_clients_subscriptions_stop_short_of_its_cap_by_a_share_with_a_floor() {
    let limit = |cap: usize, share: u32| {
        Config { connections_per_ip: cap, connection_reserve_permille: share, ..Config::default() }
            .subscriptions_per_ip()
    };
    // The share rounds half up, 76 × 0.125 = 9.5, and the floor of 8 holds under a cap of 64.
    let table = [
        (1, 1),
        (2, 1),
        (4, 2),
        (8, 4),
        (16, 8),
        (40, 32),
        (64, 56),
        (72, 63),
        (79, 69),
        (76, 66),
        (80, 70),
        (160, 140),
    ];
    for (cap, expected) in table {
        assert_eq!(limit(cap, 125), expected, "cap {cap}");
    }
    assert_eq!((limit(72, 0), limit(2, 0)), (72, 2), "no share holds nothing back");
    assert_eq!(limit(72, 999), 1, "always one");
    assert!(Config { connection_reserve_permille: 999, ..Config::default() }.validate().is_ok());
    let over = Config { connection_reserve_permille: 1000, ..Config::default() };
    assert!(over.validate().unwrap_err().contains("--connection-reserve-permille"));
}

#[test]
fn the_well_known_settings_are_bounded_and_the_test_only_ones_named() {
    let with = |timeout: u64, cache_max: u64| Config {
        well_known: WellKnown { timeout: Duration::from_secs(timeout), cache_max, ..WellKnown::default() },
        ..Config::default()
    };
    for (timeout, cache_max) in [(0, 60), (61, 60), (10, 0), (10, 86_401)] {
        assert!(with(timeout, cache_max).validate().is_err(), "{timeout} {cache_max}");
    }
    for (timeout, cache_max) in [(1, 1), (60, 86_400)] {
        assert!(with(timeout, cache_max).validate().is_ok(), "{timeout} {cache_max}");
    }
    assert!(WellKnown { insecure_http: true, ..WellKnown::default() }.is_test_only());
    let resolve = WellKnown::parse_resolve("acme.e2e.test=127.0.0.1:7777").unwrap();
    assert_eq!(resolve, (Domain::parse("acme.e2e.test").unwrap(), "127.0.0.1:7777".parse().unwrap()));
    assert!(WellKnown { resolve: vec![resolve], ..WellKnown::default() }.is_test_only());
    assert_eq!(WellKnown::parse_resolve("acme.e2e.test=[::1]:1").unwrap().1, "[::1]:1".parse().unwrap());
    for bad in ["acme.e2e.test", "ACME.test=127.0.0.1:1", "acme.e2e.test=127.0.0.1", "acme.e2e.test=nope:1"] {
        assert!(WellKnown::parse_resolve(bad).is_err(), "{bad}");
    }
}

#[test]
fn a_dns_resolve_value_is_a_name_and_a_txt_record_in_text_form() {
    let (name, strings) =
        WellKnown::parse_dns_resolve(r#"_bag.ACME.e2e.test="v=ac1; key=" "ed25519:ab""#).unwrap();
    assert_eq!(name, "_bag.acme.e2e.test");
    assert_eq!(strings, vec![b"v=ac1; key=".to_vec(), b"ed25519:ab".to_vec()]);
    let bare = WellKnown::parse_dns_resolve("_bag.acme.e2e.test=v=ac1;key=x").unwrap();
    assert_eq!(bare.1, vec![b"v=ac1;key=x".to_vec()]);
    assert!(WellKnown { dns_resolve: vec![bare], ..WellKnown::default() }.is_test_only());
    let long = format!("{}.test=x", vec!["a".repeat(63); 4].join("."));
    for bad in ["no-equals", "=x", "a..b=x", "a b=x", "a=", r#"a="open"#, &long] {
        assert!(WellKnown::parse_dns_resolve(bad).is_err(), "{bad}");
    }
}

#[test]
fn validate_refuses_settings_that_cannot_work() {
    let bad = [
        Config { ttl: 0, ..Config::default() },
        Config { max_envelope_bytes: 0, ..Config::default() },
        Config { max_envelope_bytes: BODY_LIMIT + 1, ..Config::default() },
        Config { max_unacked: 0, ..Config::default() },
        Config { rate: RateLimits { window: 0, ..RateLimits::default() }, ..Config::default() },
        Config { record_limit: 0, ..Config::default() },
        Config { record_limit: BODY_LIMIT + 1, ..Config::default() },
        Config { header_timeout: Duration::ZERO, ..Config::default() },
        Config { body_timeout: Duration::ZERO, ..Config::default() },
        Config { connections_per_ip: 0, ..Config::default() },
        Config { ping_interval: Duration::ZERO, ..Config::default() },
        Config { idle_timeout: Duration::from_secs(59), ..Config::default() },
    ];
    for c in bad {
        assert!(c.validate().is_err(), "{c:?}");
    }
    assert!(Config { max_envelope_bytes: BODY_LIMIT, ..Config::default() }.validate().is_ok());
}

#[test]
fn the_idle_timeout_is_at_least_two_ping_intervals() {
    let with = |ping: u64, idle: u64| Config {
        ping_interval: Duration::from_millis(ping),
        idle_timeout: Duration::from_millis(idle),
        ..Config::default()
    };
    assert!(with(50, 100).validate().is_ok());
    assert!(with(50, 120).validate().is_ok());
    let refused = with(50, 99).validate().unwrap_err();
    assert!(refused.contains("--idle-timeout") && refused.contains("--ping-interval"), "{refused}");
    assert!(with(0, 100).validate().is_err());
}
