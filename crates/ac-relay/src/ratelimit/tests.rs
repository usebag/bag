use super::{DAY, Limit, RateLimiter, Refused};
use crate::config::RateLimits;
use std::net::{IpAddr, Ipv4Addr};

const IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const OTHER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

fn limiter(per_from: u32, per_root: u32, per_ip: u32) -> RateLimiter {
    RateLimiter::new(RateLimits { window: 60, per_from, per_root, per_ip, ..RateLimits::default() })
}

#[test]
fn per_from_limit_with_retry_after_to_the_window_end() {
    let mut l = limiter(2, 100, 100);
    assert!(l.check_sender(6_000, "a", Some(("r", Some("d")))).is_ok());
    assert!(l.check_sender(6_010, "a", Some(("r", Some("d")))).is_ok());
    assert_eq!(
        l.check_sender(6_015, "a", Some(("r", Some("d")))),
        Err(Refused { limit: Limit::From, retry_after: 45 })
    );
    // Another sender is not affected.
    assert!(l.check_sender(6_015, "b", Some(("r", Some("d")))).is_ok());
}

#[test]
fn a_client_addresss_fetches_have_a_window_of_their_own() {
    let mut l =
        RateLimiter::new(RateLimits { window: 60, per_ip: 1, fetch_per_ip: 2, ..RateLimits::default() });
    assert!(l.check_fetch(0, IP).is_ok());
    assert!(l.check_fetch(1, IP).is_ok());
    assert_eq!(l.check_fetch(59, IP), Err(Refused { limit: Limit::Fetch, retry_after: 1 }));
    assert_eq!(Limit::Fetch.as_str(), "fetch");
    // Another address has its own, and fetches and publishes do not share a counter.
    assert!(l.check_fetch(59, OTHER).is_ok());
    assert!(l.check_address(59, IP).is_ok());
    assert!(l.check_address(59, IP).is_err());
    assert_eq!(l.check_fetch(59, IP), Err(Refused { limit: Limit::Fetch, retry_after: 1 }));
    // The next window starts empty.
    assert!(l.check_fetch(60, IP).is_ok());
}

#[test]
fn every_counter_takes_one_56_for_one_client_and_a_neighbouring_56_for_another() {
    let (one, same, other): (IpAddr, IpAddr, IpAddr) = (
        "2001:db8:1:100::1".parse().unwrap(),
        "2001:db8:1:1ff::1".parse().unwrap(),
        "2001:db8:1:200::1".parse().unwrap(),
    );
    let rate = RateLimits {
        per_ip: 1,
        fetch_per_ip: 1,
        signers_per_day: 1,
        bytes_per_day: 1,
        ..RateLimits::default()
    };
    let mut l = RateLimiter::new(rate);
    assert!(l.check_address(0, one).is_ok());
    assert!(l.check_address(0, same).is_err());
    assert!(l.check_address(0, other).is_ok());
    assert!(l.check_fetch(0, one).is_ok());
    assert!(l.check_fetch(0, same).is_err());
    assert!(l.check_fetch(0, other).is_ok());
    assert!(l.check_new_signer(0, one).is_ok());
    assert!(l.check_new_signer(0, same).is_err());
    assert!(l.check_new_signer(0, other).is_ok());
    assert!(l.check_envelope(0, one, 1, "a", "r", None).is_ok());
    assert!(l.check_envelope(0, same, 1, "b", "r", None).is_err());
    assert!(l.check_envelope(0, other, 1, "c", "r", None).is_ok());
    l.refund_bytes(same, 1);
    assert!(l.check_envelope(0, one, 1, "d", "r", None).is_ok(), "the refund reached the /56");
}

#[test]
fn the_fetch_ceiling_counts_every_address_by_the_minute() {
    let third = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let rate = RateLimits { window: 5, fetch_per_ip: 2, fetch_global_per_minute: 3, ..RateLimits::default() };
    let mut l = RateLimiter::new(rate);
    assert!(l.check_fetch(60, IP).is_ok());
    assert!(l.check_fetch(60, IP).is_ok());
    // An address over its own window spends none of the ceiling.
    assert_eq!(l.check_fetch(61, IP).unwrap_err().limit, Limit::Fetch);
    assert!(l.check_fetch(61, OTHER).is_ok());
    assert_eq!(l.check_fetch(61, third), Err(Refused { limit: Limit::FetchGlobal, retry_after: 59 }));
    assert_eq!(Limit::FetchGlobal.as_str(), "fetch-global");
    // The address windows rolled at 65; the ceiling's minute did not.
    assert_eq!(l.check_fetch(65, third).unwrap_err().limit, Limit::FetchGlobal);
    assert!(l.check_fetch(120, third).is_ok());
}

#[test]
fn a_fetch_ceiling_of_zero_is_none() {
    let rate = RateLimits { fetch_per_ip: 1_000, fetch_global_per_minute: 0, ..RateLimits::default() };
    let mut l = RateLimiter::new(rate);
    for _ in 0..1_000 {
        assert!(l.check_fetch(0, IP).is_ok());
    }
}

#[test]
fn a_client_addresss_bytes_have_a_daily_quota_and_a_refusal_counts_nothing() {
    let mut l = RateLimiter::new(RateLimits { bytes_per_day: 100, ..RateLimits::default() });
    let mut send = |now, ip, size| l.check_envelope(now, ip, size, "a", "r", None);
    assert!(send(DAY, IP, 60).is_ok());
    assert_eq!(
        send(DAY + 10, IP, 41),
        Err(Refused { limit: Limit::Bytes, retry_after: DAY - 10 }),
        "over by one"
    );
    assert_eq!(Limit::Bytes.as_str(), "bytes");
    assert!(send(DAY + 10, IP, 40).is_ok(), "the refused 41 were not counted");
    assert!(send(DAY + 10, IP, 1).is_err());
    assert!(send(DAY + 10, OTHER, 100).is_ok());
    assert!(send(2 * DAY, IP, 100).is_ok(), "the next UTC day starts empty");
    // No sum of sizes wraps.
    assert!(send(2 * DAY, OTHER, u64::MAX).is_err());
}

#[test]
fn a_bytes_quota_of_zero_is_none() {
    let mut l = RateLimiter::new(RateLimits { bytes_per_day: 0, ..RateLimits::default() });
    assert!(l.check_envelope(0, IP, u64::MAX, "a", "r", None).is_ok());
    assert!(l.check_envelope(0, IP, u64::MAX, "b", "s", None).is_ok());
}

#[test]
fn an_envelope_moves_no_counter_unless_every_limit_passes() {
    let rate = RateLimits { per_from: 1, bytes_per_day: 100, ..RateLimits::default() };
    let mut l = RateLimiter::new(rate);
    // Refused by its bytes: the `from` counter did not move.
    assert_eq!(l.check_envelope(0, IP, 101, "a", "r", None).unwrap_err().limit, Limit::Bytes);
    assert!(l.check_envelope(0, IP, 1, "a", "r", None).is_ok());
    // Refused by its `from`: the bytes did not move.
    assert_eq!(l.check_envelope(0, IP, 99, "a", "r", None).unwrap_err().limit, Limit::From);
    assert!(l.check_envelope(0, IP, 99, "b", "r", None).is_ok());
}

#[test]
fn bytes_given_back_are_free_again_and_never_below_nothing() {
    let mut l = RateLimiter::new(RateLimits { bytes_per_day: 100, ..RateLimits::default() });
    assert!(l.check_envelope(0, IP, 100, "a", "r", None).is_ok());
    assert!(l.check_envelope(0, IP, 1, "b", "r", None).is_err());
    l.refund_bytes(IP, 100);
    assert!(l.check_envelope(0, IP, 100, "b", "r", None).is_ok());
    l.refund_bytes(IP, 1_000);
    l.refund_bytes(OTHER, 1);
    assert!(l.check_envelope(0, IP, 100, "c", "r", None).is_ok());
    assert!(l.check_envelope(0, IP, 1, "d", "r", None).is_err());
}

#[test]
fn per_root_and_per_address_limits() {
    let mut l = limiter(100, 2, 3);
    assert!(l.check_sender(0, "a", Some(("r", Some("d")))).is_ok());
    assert!(l.check_sender(0, "b", Some(("r", Some("d")))).is_ok());
    assert_eq!(
        l.check_sender(59, "c", Some(("r", Some("d")))),
        Err(Refused { limit: Limit::Root, retry_after: 1 })
    );
    assert!(l.check_sender(59, "c", Some(("s", Some("d")))).is_ok());
    // A record publish has no root.
    assert!(l.check_sender(59, "e", None).is_ok());
    // The address is its own counter, charged by every publish that reaches it.
    for _ in 0..3 {
        assert!(l.check_address(59, IP).is_ok());
    }
    assert_eq!(l.check_address(59, IP), Err(Refused { limit: Limit::Ip, retry_after: 1 }));
    assert!(l.check_address(59, OTHER).is_ok());
}

#[test]
fn a_refused_sender_costs_its_counters_nothing() {
    let mut l = limiter(1, 100, 100);
    assert!(l.check_sender(0, "a", Some(("r", Some("d")))).is_ok());
    for _ in 0..5 {
        assert!(l.check_sender(1, "a", Some(("r", Some("d")))).is_err());
    }
    // The root counter moved once, not six times: a different sender still gets through.
    let mut tight = limiter(1, 2, 2);
    assert!(tight.check_sender(0, "a", Some(("r", Some("d")))).is_ok());
    assert!(tight.check_sender(0, "a", Some(("r", Some("d")))).is_err());
    assert!(tight.check_sender(0, "b", Some(("r", Some("d")))).is_ok());
    // A refused address counts nothing more either.
    let mut one = limiter(100, 100, 1);
    assert!(one.check_address(0, IP).is_ok());
    for _ in 0..5 {
        assert!(one.check_address(0, IP).is_err());
    }
    assert!(one.check_address(60, IP).is_ok());
}

#[test]
fn counters_reset_when_the_window_turns() {
    let mut l = limiter(1, 1, 1);
    assert!(l.check_sender(119, "a", Some(("r", Some("d")))).is_ok());
    assert!(l.check_sender(119, "a", Some(("r", Some("d")))).is_err());
    assert!(l.check_address(119, IP).is_ok());
    assert!(l.check_address(119, IP).is_err());
    assert!(l.check_sender(120, "a", Some(("r", Some("d")))).is_ok());
    assert!(l.check_address(120, IP).is_ok());
    // A window of another length.
    let mut five = RateLimiter::new(RateLimits { window: 5, per_ip: 1, ..RateLimits::default() });
    assert!(five.check_address(7, IP).is_ok());
    assert_eq!(five.check_address(9, IP), Err(Refused { limit: Limit::Ip, retry_after: 1 }));
    assert!(five.check_address(10, IP).is_ok());
    assert_eq!(Limit::From.as_str(), "from");
    assert_eq!(Limit::Root.as_str(), "root");
    assert_eq!(Limit::Ip.as_str(), "ip");
    assert_eq!(Limit::RecordSigners.as_str(), "record-signers");
}

#[test]
fn new_record_signers_per_address_per_utc_day() {
    let mut l = RateLimiter::new(RateLimits { signers_per_day: 2, ..RateLimits::default() });
    // 1_800_000_000 is 2027-01-15 08:00:00 UTC: 57,600 s to the next midnight.
    let now = 1_800_000_000;
    assert_eq!(DAY - now % DAY, 57_600);
    assert!(l.check_new_signer(now, IP).is_ok());
    assert!(l.check_new_signer(now + 10, IP).is_ok());
    assert_eq!(
        l.check_new_signer(now + 10, IP),
        Err(Refused { limit: Limit::RecordSigners, retry_after: 57_590 })
    );
    // Another address has its own quota, and the minute windows do not reset it.
    assert!(l.check_new_signer(now + 10, OTHER).is_ok());
    assert!(l.check_new_signer(now + 3_600, IP).is_err());
    // The next UTC day does.
    let midnight = now - now % DAY + DAY;
    assert!(l.check_new_signer(midnight, IP).is_ok());
    assert!(l.check_new_signer(midnight + 1, IP).is_ok());
    assert_eq!(l.check_new_signer(midnight + 2, IP).unwrap_err().retry_after, DAY - 2);
}

#[test]
fn the_sender_domain_quota_a_utc_day_checked_with_the_sender_limits() {
    let mut l = RateLimiter::new(RateLimits { domain_day: 2, ..RateLimits::default() });
    let now = 1_800_000_000;
    assert!(l.check_sender(now, "a", Some(("r", Some("domain:acme.example")))).is_ok());
    assert!(l.check_sender(now + 1, "b", Some(("s", Some("domain:acme.example")))).is_ok());
    // A third from any key and any root of the domain is refused until the next 00:00 UTC, past every minute window.
    let refused = Refused { limit: Limit::Domain, retry_after: 57_600 - 120 };
    assert_eq!(l.check_sender(now + 120, "c", Some(("t", Some("domain:acme.example")))), Err(refused));
    // Another domain has its own quota, and a record (no envelope) none.
    assert!(l.check_sender(now + 120, "c", Some(("t", Some("domain:globex.example")))).is_ok());
    assert!(l.check_sender(now + 120, "c", None).is_ok());
    // A root no domain admitted has no sender domain, and keeps no counter here.
    for _ in 0..5 {
        assert!(l.check_sender(now + 120, "c", Some(("t", None))).is_ok());
    }
    assert_eq!(l.domains.len(), 2);
    // The refusal charged nothing: "c" and root "t" have used one publish each in this window.
    let mut tight =
        RateLimiter::new(RateLimits { per_from: 1, per_root: 1, domain_day: 1, ..RateLimits::default() });
    assert!(tight.check_sender(now, "a", Some(("r", Some("d")))).is_ok());
    assert_eq!(tight.check_sender(now, "b", Some(("s", Some("d")))).unwrap_err().limit, Limit::Domain);
    assert!(
        tight.check_sender(now, "b", Some(("s", Some("e")))).is_ok(),
        "b and s were not charged by the refusal"
    );
    let midnight = now - now % DAY + DAY;
    assert!(l.check_sender(midnight, "c", Some(("t", Some("domain:acme.example")))).is_ok());
    assert_eq!(Limit::Domain.as_str(), "domain");
}

#[test]
fn a_quota_of_0_is_no_quota_and_keeps_no_counter() {
    // domain_day: 0 is set explicitly here: the default is 10,000, so a "quota of 0" test must name 0.
    let mut l = RateLimiter::new(RateLimits {
        per_from: u32::MAX,
        per_root: u32::MAX,
        domain_day: 0,
        ..RateLimits::default()
    });
    for _ in 0..1_000 {
        assert!(l.check_sender(0, "a", Some(("r", Some("domain:acme.example")))).is_ok());
    }
    assert!(l.domains.is_empty());
}
