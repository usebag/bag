use super::{
    CONNECTIONS_OPEN, Metrics, RATE_LIMITED, RESOLUTIONS, SEEDED, SEEDED_BY_LABEL, SEEDED_BY_RESULT,
    SUBSCRIPTIONS_OPEN, codes, litestream, rev, route_of,
};
use crate::config::{Config, RateLimits};
use ac_core::Code;
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

const DAY: u64 = 86_400;

#[test]
fn counters_render_in_name_order_each_family_once_with_its_type_line() {
    let m = Metrics::new();
    m.count("ac_relay_b_total", "result", "ok");
    m.count("ac_relay_b_total", "result", "ok");
    m.add("ac_relay_b_total", "result", "bad-json", 3);
    m.tick("ac_relay_a_total");
    m.add("ac_relay_c_total", "limit", "ip", u64::MAX);
    m.count("ac_relay_c_total", "limit", "ip");
    let text = m.render(0);
    let counters: Vec<&str> = text.lines().take_while(|l| !l.contains(" gauge")).collect();
    assert_eq!(
        counters,
        [
            "# TYPE ac_relay_a_total counter",
            "ac_relay_a_total 1",
            "# TYPE ac_relay_b_total counter",
            "ac_relay_b_total{result=\"bad-json\"} 3",
            "ac_relay_b_total{result=\"ok\"} 2",
            "# TYPE ac_relay_c_total counter",
            &format!("ac_relay_c_total{{limit=\"ip\"}} {}", u64::MAX),
        ],
        "a counter at its top stays there: {text}"
    );
}

#[test]
fn gauges_are_set_and_moved_and_the_day_s_mailboxes_are_counted_once_each() {
    let m = Metrics::default();
    m.set("ac_relay_store_live_bytes", 4_000_000_000);
    m.set("ac_relay_too_big", u64::MAX);
    m.shift("ac_relay_subscriptions_open", 2);
    m.shift("ac_relay_subscriptions_open", -1);
    let now = 20_000 * DAY + 5;
    m.subscribed(now, "ed25519:aaaa");
    m.subscribed(now + 60, "ed25519:aaaa");
    m.subscribed(now + 120, "ed25519:bbbb");
    let text = m.render(now + 180);
    for line in [
        "# TYPE ac_relay_mailboxes_subscribed_today gauge\nac_relay_mailboxes_subscribed_today 2\n",
        "# TYPE ac_relay_store_live_bytes gauge\nac_relay_store_live_bytes 4000000000\n",
        "# TYPE ac_relay_subscriptions_open gauge\nac_relay_subscriptions_open 1\n",
        &format!("ac_relay_too_big {}\n", i64::MAX),
    ] {
        assert!(text.contains(line), "{line:?} in {text}");
    }
    assert!(!text.contains("ed25519:"), "only the count of mailboxes leaves: {text}");
    // At 00:00 UTC the count starts again: read on the next day it is 0, and a subscription that day starts it at 1.
    assert!(m.render(now + DAY).contains("ac_relay_mailboxes_subscribed_today 0\n"));
    m.subscribed(now + DAY, "ed25519:aaaa");
    assert!(m.render(now + DAY).contains("ac_relay_mailboxes_subscribed_today 1\n"));
}

#[test]
fn a_started_relay_shows_its_open_subscriptions_and_the_day_s_mailboxes_at_0_before_the_first() {
    let m = Metrics::new();
    let now = 20_000 * DAY + 5;
    m.started(now);
    let text = m.render(now);
    // A test build has no AC_REV, so `unknown`; the image's build passes it.
    let built = rev(option_env!("AC_REV"));
    let info = format!("# TYPE ac_relay_build_info gauge\nac_relay_build_info{{rev=\"{built}\"}} 1\n");
    for line in [
        "# TYPE ac_relay_subscriptions_open gauge\nac_relay_subscriptions_open 0\n",
        "# TYPE ac_relay_connections_open gauge\nac_relay_connections_open 0\n",
        "# TYPE ac_relay_mailboxes_subscribed_today gauge\nac_relay_mailboxes_subscribed_today 0\n",
        "# TYPE ac_relay_client_networks_today gauge\nac_relay_client_networks_today 0\n",
        &info,
        "ac_relay_store_full_total 0\n",
        &format!("process_start_time_seconds {now}\n"),
    ] {
        assert!(text.contains(line), "{line:?} in {text}");
    }
    // A second start in the same process (two relays in one test) moves the gauges by nothing.
    m.shift(SUBSCRIPTIONS_OPEN, 1);
    m.shift(CONNECTIONS_OPEN, 2);
    m.started(now + 1);
    let again = m.render(now + 1);
    assert!(again.contains("ac_relay_subscriptions_open 1\n"), "{again}");
    assert!(again.contains("ac_relay_connections_open 2\n"), "{again}");
}

#[test]
fn the_build_s_rev_is_a_commit_of_7_to_40_lower_case_hex_digits_or_unknown() {
    for commit in ["a10619f", "a10619f3", "0123456789abcdef0123456789abcdef01234567"] {
        assert_eq!(rev(Some(commit)), commit);
    }
    let long = "0123456789abcdef0123456789abcdef012345678";
    let injected = "a10619f3\"} 1\nx";
    for other in [None, Some(""), Some("a10619"), Some("A10619F3"), Some(injected), Some("dev"), Some(long)] {
        assert_eq!(rev(other), "unknown", "{other:?}");
    }
}

#[test]
fn the_limits_the_relay_runs_with_are_gauges_by_the_names_their_refusals_are_counted_under() {
    let m = Metrics::new();
    let rate = RateLimits { per_ip: 7, bytes_per_day: 0, ..RateLimits::default() };
    let config = Config { rate, connections_per_ip: 64, max_store_bytes: 1 << 30, ..Config::default() };
    m.limits(&config);
    let text = m.render(0);
    assert!(text.contains("# TYPE ac_relay_limit gauge\nac_relay_limit{limit=\"bytes\"} 0\n"), "{text}");
    for (limit, value) in [
        ("window", 60),
        ("from", 120),
        ("root", 1_200),
        ("ip", 7),
        ("fetch", 6_000),
        ("fetch-global", 30_000),
        ("record-signers", 100),
        ("bytes", 0),
        ("domain", 10_000),
        ("connections-per-ip", 64),
        ("subscriptions-per-ip", u64::try_from(config.subscriptions_per_ip()).unwrap()),
        ("store-bytes", 1 << 30),
        ("ttl", config.ttl),
    ] {
        let line = format!("ac_relay_limit{{limit=\"{limit}\"}} {value}\n");
        assert!(text.contains(&line), "{line:?} in {text}");
    }
    assert_eq!(text.matches("ac_relay_limit{").count(), 13, "{text}");
    // A rate limit's name is the one its refusals are counted under, as a cap's is the refusal's reason.
    let rate_limits = SEEDED_BY_LABEL[1];
    assert_eq!((rate_limits.0, rate_limits.1), (RATE_LIMITED, "limit"));
    for limit in ["from", "root", "ip", "fetch", "fetch-global", "record-signers", "bytes", "domain"] {
        assert!(rate_limits.2.contains(&limit), "{limit}");
    }
}

#[test]
fn the_day_s_client_networks_are_counted_once_each_by_the_rate_limits_bucket_and_no_address_leaves() {
    let m = Metrics::new();
    let now = 20_000 * DAY + 5;
    let ip = |text: &str| text.parse::<IpAddr>().unwrap();
    for (at, client) in [
        (now, "203.0.113.7"),
        (now + 1, "203.0.113.7"),
        (now + 2, "::ffff:203.0.113.7"),
        (now + 3, "203.0.113.8"),
        (now + 4, "2001:db8:1:200::1"),
        (now + 5, "2001:db8:1:2ff:ffff::9"),
        (now + 6, "2001:db8:1:300::1"),
    ] {
        m.client(at, ip(client));
    }
    let text = m.render(now + 10);
    let four = "# TYPE ac_relay_client_networks_today gauge\nac_relay_client_networks_today 4\n";
    assert!(text.contains(four), "{text}");
    for never in ["203.0.113", "2001:db8"] {
        assert!(!text.contains(never), "{never} in {text}");
    }
    // At 00:00 UTC the set and its key go: read the next day it is 0, and a call that day starts it at 1.
    assert!(m.render(now + DAY).contains("ac_relay_client_networks_today 0\n"));
    m.client(now + DAY, ip("203.0.113.7"));
    assert!(m.render(now + DAY).contains("ac_relay_client_networks_today 1\n"));
    // The mailboxes' set is the other one.
    assert!(m.render(now + DAY).contains("ac_relay_mailboxes_subscribed_today 0\n"));
}

#[test]
fn a_refusal_with_a_signature_s_code_counts_what_was_signed_and_any_other_counts_nothing() {
    let m = Metrics::new();
    for (call, code) in [
        ("envelope", Some(Code::BadSig)),
        ("fetch", Some(Code::BadSig)),
        ("subscribe", Some(Code::BadSig)),
        ("pair-open", Some(Code::BadSig)),
        ("fetch", Some(Code::BadHopSig)),
        ("envelope", Some(Code::BadHopSig)),
        ("envelope", Some(Code::BadRecordSig)),
        ("envelope", Some(Code::BadId)),
        ("fetch", Some(Code::RateLimited)),
        ("envelope", None),
    ] {
        m.refused(call, code);
    }
    let text = m.render(0);
    let family = "ac_relay_signature_failures_total";
    let counted: Vec<&str> = text.lines().filter(|l| l.starts_with(family)).collect();
    assert_eq!(
        counted,
        [
            "ac_relay_signature_failures_total{kind=\"envelope\"} 1",
            "ac_relay_signature_failures_total{kind=\"fetch\"} 1",
            "ac_relay_signature_failures_total{kind=\"hop\"} 2",
            "ac_relay_signature_failures_total{kind=\"pair-open\"} 1",
            "ac_relay_signature_failures_total{kind=\"record\"} 1",
            "ac_relay_signature_failures_total{kind=\"subscribe\"} 1",
        ]
    );
    let kinds = SEEDED_BY_LABEL[5];
    assert_eq!((kinds.0, kinds.1, kinds.2.len()), ("ac_relay_signature_failures_total", "kind", 6));
}

#[test]
fn a_started_relay_shows_every_seeded_counter_at_0_for_each_value_of_its_closed_set() {
    let m = Metrics::new();
    m.started(0);
    let text = m.render(0);
    let at = |line: &str| assert!(text.lines().any(|l| l == line), "{line:?} in {text}");
    for family in SEEDED {
        at(&format!("{family} 0"));
    }
    let mut seeded = 0;
    for (family, label, values) in SEEDED_BY_LABEL {
        assert!(text.contains(&format!("# TYPE {family} counter\n")), "{family}");
        for value in values {
            at(&format!("{family}{{{label}=\"{value}\"}} 0"));
            seeded += 1;
        }
    }
    assert_eq!(seeded, 22 + 10 + 5 + 6 + 2 + 6 + 7 + 3, "the seeded series of the eight labelled families");
    let all: Vec<&str> = codes().collect();
    assert_eq!(all.len(), Code::ALL.len());
    for (family, words) in SEEDED_BY_RESULT {
        for value in words.iter().chain(&all) {
            at(&format!("{family}{{result=\"{value}\"}} 0"));
        }
    }
    // A code of the edge's group that a relay answers (403 on a fetch or a subscribe by a revoked chain).
    at(&format!("ac_relay_fetches_total{{result=\"{}\"}} 0", Code::Revoked.as_str()));
    // The ones the alerts read (deploy/relay/observability/relays-alerts.yml) are among them.
    for line in [
        "ac_relay_blocklist_invalid_total 0",
        "ac_relay_new_signers_total 0",
        "ac_relay_blocked_total 0",
        "ac_relay_domain_resolutions_total{outcome=\"pin-mismatch\"} 0",
        "ac_relay_publishes_total{result=\"bad-sig\"} 0",
        "ac_relay_publishes_total{result=\"bad-hop-sig\"} 0",
        "ac_relay_publishes_total{result=\"bad-record-sig\"} 0",
        "ac_relay_publishes_total{result=\"bad-rotation\"} 0",
        "ac_relay_rate_limited_total{limit=\"domain\"} 0",
        "ac_relay_rate_limited_total{limit=\"fetch-global\"} 0",
        "ac_relay_record_fetches_total{result=\"not-found\"} 0",
        // W1.2: the security note's M1 to M4, the claims and the connections.
        "ac_relay_proxy_header_ignored_total{reason=\"untrusted-source\"} 0",
        "ac_relay_resolutions_capped_total 0",
        "ac_relay_signature_failures_total{kind=\"pair-open\"} 0",
        "ac_relay_pending_dropped_total{reason=\"root-not-accepted\"} 0",
        "ac_relay_pair_claims_total{result=\"rate-limited\"} 0",
        "ac_relay_pair_opens_total{result=\"body-timeout\"} 0",
        "ac_relay_connections_accepted_total 0",
    ] {
        at(line);
    }
    // A count taken before a second start is kept: seeding adds 0.
    m.count(RESOLUTIONS, "outcome", "pin-mismatch");
    m.count(RATE_LIMITED, "limit", "domain");
    m.started(1);
    let again = m.render(1);
    assert!(again.contains("ac_relay_domain_resolutions_total{outcome=\"pin-mismatch\"} 1\n"), "{again}");
    assert!(again.contains("ac_relay_rate_limited_total{limit=\"domain\"} 1\n"), "{again}");
}

#[test]
fn the_seeded_resolution_outcomes_are_the_reasons_the_resolver_names() {
    use crate::resolver::Failure;
    let outcomes = SEEDED_BY_LABEL[0];
    assert_eq!((outcomes.0, outcomes.1), (RESOLUTIONS, "outcome"));
    let failures = [
        Failure::Dns(String::new()),
        Failure::NoAddress,
        Failure::NonPublic { address: [127, 0, 0, 1].into(), category: ac_core::net::Category::Loopback },
        Failure::Timeout,
        Failure::Fetch(String::new()),
        Failure::Status(500),
        Failure::TooLarge,
        Failure::NotAddress,
        Failure::PinMismatch { pinned: String::new(), offered: String::new(), check: Code::BadRotation },
        Failure::NotCached,
        Failure::TxtLookup(String::new()),
        Failure::TxtMalformed("x"),
        Failure::TxtAmbiguous(2),
        Failure::TxtKeyMismatch { txt: String::new(), offered: String::new() },
    ];
    let record_codes =
        [Code::BadJson, Code::BadRecord, Code::BadRecordSig, Code::FutureIat, Code::RecordExpired];
    let reasons =
        failures.iter().map(Failure::reason).chain(record_codes.map(|c| Failure::Record(c).reason()));
    for reason in reasons.chain(["pinned", "refreshed", "rotated"]) {
        assert!(outcomes.2.contains(&reason), "{reason}");
    }
    assert_eq!(
        outcomes.2.len(),
        failures.len() + record_codes.len() + 3,
        "no outcome seeded twice or unnamed"
    );
}

#[test]
fn the_seeded_sweep_kinds_are_the_kinds_a_sweep_counts() {
    use crate::clock::ManualClock;
    use crate::config::Config;
    use crate::relay::Relay;
    use crate::store::memory::MemoryStore;
    let relay = Relay::new(Arc::new(MemoryStore::new()), Arc::new(ManualClock::new(0)), Config::default());
    assert!(crate::sweeper::sweep_once(&relay).is_some());
    let swept = SEEDED_BY_LABEL[3];
    assert_eq!((swept.0, swept.1), ("ac_relay_swept_total", "kind"));
    let text = super::METRICS.render(0);
    let counted: Vec<&str> = text
        .lines()
        .filter_map(|l| l.strip_prefix("ac_relay_swept_total{kind=\"")?.split('"').next())
        .collect();
    assert_eq!(counted.len(), swept.2.len(), "{text}");
    for kind in counted {
        assert!(swept.2.contains(&kind), "{kind}");
    }
}

#[test]
fn durations_fill_every_bucket_at_or_over_them_with_the_sum_and_the_count() {
    let m = Metrics::new();
    assert!(!m.render(0).contains("histogram"), "no TYPE line before the first request");
    m.observe("/v0/publish", 200, Duration::from_millis(5));
    m.observe("/v0/publish", 200, Duration::from_millis(300));
    m.observe("/v0/publish", 200, Duration::from_secs(11));
    m.observe("not-found", 404, Duration::from_micros(1));
    let text = m.render(0);
    let at = |le: &str| {
        let key = format!(
            "http_server_request_duration_seconds_bucket{{http_route=\"/v0/publish\",http_response_status_code=\"200\",le=\"{le}\"}} "
        );
        let line = text.lines().find(|l| l.starts_with(&key)).unwrap_or_else(|| panic!("{key} in {text}"));
        line[key.len()..].parse::<u64>().unwrap()
    };
    assert_eq!((at("0.005"), at("0.25"), at("0.5"), at("10"), at("+Inf")), (1, 1, 2, 2, 3));
    assert_eq!(text.matches("# TYPE http_server_request_duration_seconds histogram").count(), 1);
    let labels = "{http_route=\"/v0/publish\",http_response_status_code=\"200\"}";
    assert!(
        text.contains(&format!("http_server_request_duration_seconds_sum{labels} 11.305000\n")),
        "{text}"
    );
    assert!(text.contains(&format!("http_server_request_duration_seconds_count{labels} 3\n")), "{text}");
    assert!(text.contains("http_route=\"not-found\",http_response_status_code=\"404\",le=\"0.005\"} 1\n"));
}

#[test]
fn a_path_names_its_route_and_any_other_path_is_not_found() {
    for (path, route) in [
        ("/v0/publish", "/v0/publish"),
        ("/v0/fetch/0011", "/v0/fetch/{id}"),
        ("/v0/fetch/record/ed25519:aa/address", "/v0/fetch/record/{address}/{kind}"),
        ("/v0/fetch/record", "/v0/fetch/{id}"),
        ("/v0/health", "/v0/health"),
        ("/v0/abuse", "/v0/abuse"),
        ("/v0/subscribe", "/v0/subscribe"),
        ("/v0/pair/open", "/v0/pair/open"),
        ("/v0/pair/claim/42", "/v0/pair/claim/{n}"),
    ] {
        assert_eq!(route_of(path), route, "{path}");
    }
    for path in [
        "/",
        "/metrics",
        "/v0/fetch/",
        "/v0/fetch/a/b",
        "/v0/fetch/record/a",
        "/v0/pair/claim/1/2",
        "/v0/publish/x",
    ] {
        assert_eq!(route_of(path), "not-found", "{path}");
    }
}

/// A one-shot HTTP server on loopback that answers `status` and `body` to the first request, and its URL.
fn answer_once(status: &str, body: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/metrics", listener.local_addr().unwrap());
    let status = status.to_owned();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut head = [0_u8; 1024];
        let _ = stream.read(&mut head);
        let reply =
            format!("HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
        let _ = stream.write_all(reply.as_bytes());
    });
    url
}

#[tokio::test]
async fn litestream_s_lines_pass_and_nothing_else_does() {
    let body = "# HELP go_goroutines Number of goroutines.\n# TYPE go_goroutines gauge\ngo_goroutines 12\n\
                # HELP litestream_txid The current transaction ID\n# TYPE litestream_txid gauge\n\
                litestream_txid{db=\"/data/relay.sqlite\"} 1416\n\
                litestream_replica_operation_total{operation=\"PUT\",replica_type=\"s3\"} 7\n\
                process_open_fds 9\n";
    let text = litestream(answer_once("200 OK", body)).await;
    assert_eq!(
        text,
        "# TYPE ac_relay_litestream_up gauge\nac_relay_litestream_up 1\n\
         # HELP litestream_txid The current transaction ID\n# TYPE litestream_txid gauge\n\
         litestream_txid{db=\"/data/relay.sqlite\"} 1416\n\
         litestream_replica_operation_total{operation=\"PUT\",replica_type=\"s3\"} 7\n"
    );
}

#[tokio::test]
async fn litestream_down_or_failing_is_up_0_and_no_line_of_it() {
    let refused = TcpListener::bind("127.0.0.1:0").unwrap();
    let closed = format!("http://{}/metrics", refused.local_addr().unwrap());
    drop(refused);
    let failing = answer_once("500 Internal Server Error", "litestream_txid 1\n");
    for url in [closed, failing] {
        assert_eq!(litestream(url).await, "# TYPE ac_relay_litestream_up gauge\nac_relay_litestream_up 0\n");
    }
}
