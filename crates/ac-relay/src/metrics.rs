//! The relay's own metrics: counts, gauges and request durations in Prometheus's text format, written by
//! hand with no crate, and answered at `GET /metrics` on a listener of its own (`--metrics-port`), never on the public
//! port, where `/metrics` is 404 `not-found`. Names follow OpenTelemetry's where it has one
//! (`http_server_request_duration_seconds`, `process_start_time_seconds`), so an OpenTelemetry collector reads them too.
//!
//! Every label value is a `&'static str`: a route, a code, a limit, a reason or an outcome, each from a closed set in
//! the source, and a status; the build's `rev` is the commit compiled in. No address, id, root, domain, nameplate or IP
//! is `'static`, so none can be a label. One process serves one relay, so the counts are the process's ([`METRICS`]),
//! and they start again at 0 with it. The day's counts of subscribed mailboxes and of client networks, and the day's
//! first subscribes, keep a hash of each mailbox or network, under a key made in memory for that day, until 00:00 UTC,
//! when all three go; only the counts leave.
//!
//! With `--metrics-litestream`, each scrape also reads Litestream's own metrics on this host and passes on its
//! `litestream_*` lines only, after `ac_relay_litestream_up` (1, or 0 when that read failed): Fly scrapes one endpoint
//! per Machine (flyctl 0.5.1), so Litestream's metrics come through the relay's. A replica that stops uploading moves
//! no error counter of Litestream 0.5.17; its `litestream_txid` then rises while its PUT operations stay flat.

use crate::config::Config;
use crate::ratelimit::Limit;
use crate::relay::Relay;
use ac_core::Code;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::header::CONTENT_TYPE;
use axum::middleware::Next;
use axum::response::{IntoResponse as _, Response};
use axum::routing::get;
use std::collections::{BTreeMap, HashSet};
use std::fmt::{Display, Write as _};
use std::hash::{BuildHasher as _, Hash, RandomState};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// The process's metrics.
pub static METRICS: Metrics = Metrics::new();

/// The request duration buckets: upper bounds in microseconds, and as `le` writes them (OpenTelemetry's default
/// boundaries for `http.server.request.duration`, in seconds).
const BUCKETS: [(u64, &str); 14] = [
    (5_000, "0.005"),
    (10_000, "0.01"),
    (25_000, "0.025"),
    (50_000, "0.05"),
    (75_000, "0.075"),
    (100_000, "0.1"),
    (250_000, "0.25"),
    (500_000, "0.5"),
    (750_000, "0.75"),
    (1_000_000, "1"),
    (2_500_000, "2.5"),
    (5_000_000, "5"),
    (7_500_000, "7.5"),
    (10_000_000, "10"),
];

/// The routes of [`crate::http::router`], the record fetch before the fetch by id: the `http_route` label, and
/// `not-found` for any other path.
const ROUTES: [&str; 8] = [
    "/v0/publish",
    "/v0/fetch/record/{address}/{kind}",
    "/v0/fetch/{id}",
    "/v0/health",
    "/v0/abuse",
    "/v0/subscribe",
    "/v0/pair/open",
    "/v0/pair/claim/{n}",
];

/// How long a read of Litestream's metrics may take.
const LITESTREAM_TIMEOUT: Duration = Duration::from_secs(2);

/// The most bytes of Litestream's metrics read.
const LITESTREAM_MAX_BYTES: u64 = 1 << 20;

/// The histogram family.
const DURATION: &str = "http_server_request_duration_seconds";

/// The counter of `store-error` lines: a write or read of the database failed.
pub const STORE_ERRORS: &str = "ac_relay_store_errors_total";
/// The counter of `store-full` refusals: the store's live bytes reached `--max-store-bytes`.
pub const STORE_FULL: &str = "ac_relay_store_full_total";
/// The counter of `store-corrupt` lines: a stored row did not parse.
pub const STORE_CORRUPT: &str = "ac_relay_store_corrupt_total";
/// The counter of `rate-limited` refusals, by `limit`.
pub const RATE_LIMITED: &str = "ac_relay_rate_limited_total";
/// The counter of refused connections and subscriptions, by `reason`.
pub const CONNECTIONS_REFUSED: &str = "ac_relay_connections_refused_total";
/// The counter of `domain:` resolutions, by `outcome` (`pinned`, `refreshed`, `rotated`, or the refusal's reason).
pub const RESOLUTIONS: &str = "ac_relay_domain_resolutions_total";
/// The gauge of subscriptions open.
pub const SUBSCRIPTIONS_OPEN: &str = "ac_relay_subscriptions_open";
/// The gauge of connections open on the relay's port, each from its accept until it closes, a WebSocket's included.
pub const CONNECTIONS_OPEN: &str = "ac_relay_connections_open";
/// The counter of connections served on the relay's port (one refused at accept is in [`CONNECTIONS_REFUSED`]).
pub const CONNECTIONS_ACCEPTED: &str = "ac_relay_connections_accepted_total";
/// The counter of client-address headers not read, by `reason` ([`crate::net::Front::client`]).
pub const PROXY_HEADER_IGNORED: &str = "ac_relay_proxy_header_ignored_total";
/// The counter of publishes and pending retries past the cap of resolutions (the `resolutions-capped` line).
pub const RESOLUTIONS_CAPPED: &str = "ac_relay_resolutions_capped_total";
/// The counter of pending rows dropped, by `reason` (the `pending-dropped` line).
pub const PENDING_DROPPED: &str = "ac_relay_pending_dropped_total";
/// The counter of pairing claims, by `result`.
pub const PAIR_CLAIMS: &str = "ac_relay_pair_claims_total";
/// The gauge of nameplates open, read at each scrape.
pub const NAMEPLATES_OPEN: &str = "ac_relay_nameplates_open";
/// The counter of subscriptions answered `ok` to a mailbox that no envelope has reached at this relay (its last cursor
/// is 0, and cursors are never deleted), each mailbox once in a UTC day ([`Metrics::first_subscribed`]): installs
/// whose host is wired and started, with no per-mailbox mark stored. Over: a fresh install that receives nothing counts
/// once on each day it subscribes; a relay that is a pairing rendezvous counts each invitation's mailbox too (relay 1;
/// relay 2 is the clean read); a restart starts the day's set again. Under: a mailbox that a peer wrote to before its
/// first subscribe never counts.
pub const FIRST_SUBSCRIBES: &str = "ac_relay_first_subscribes_total";
/// The counter of signatures that did not verify, by `kind`, what was signed ([`Metrics::refused`]).
const SIGNATURE_FAILURES: &str = "ac_relay_signature_failures_total";
/// The gauges of the limits the relay runs with, by `limit` ([`Metrics::limits`]).
const LIMITS: &str = "ac_relay_limit";

/// The counters with no label that an alert or a daily total reads with `increase` (deploy/relay/observability/):
/// [`Metrics::started`] seeds them at 0.
pub const SEEDED: [&str; 10] = [
    STORE_FULL,
    STORE_ERRORS,
    STORE_CORRUPT,
    "ac_relay_blocked_total",
    "ac_relay_blocklist_invalid_total",
    "ac_relay_new_signers_total",
    "ac_relay_deliveries_total",
    RESOLUTIONS_CAPPED,
    CONNECTIONS_ACCEPTED,
    FIRST_SUBSCRIBES,
];

/// The labelled counters an alert or a daily total reads with `increase`, each with its label and the values of its
/// closed set that [`Metrics::started`] seeds at 0. The resolutions: every outcome and refusal reason of
/// `resolver::Failure`, with the record codes it names (`bad-json` to `record-expired`; a cap's code is not
/// seeded). The rate limits: every `ratelimit::Limit` and the pairing claim's. The record fetches: every result of
/// the call. The sweeps: every kind `sweeper::swept_metrics` counts. Then every reason a header is ignored, every
/// kind of signature, every reason `Relay::retry_pending` drops a row for, and every result of a claim.
pub const SEEDED_BY_LABEL: [(&str, &str, &[&str]); 8] = [
    (
        RESOLUTIONS,
        "outcome",
        &[
            "pinned",
            "refreshed",
            "rotated",
            "dns-failed",
            "no-address",
            "non-public-address",
            "timeout",
            "fetch-failed",
            "http-status",
            "too-large",
            "bad-json",
            "bad-record",
            "bad-record-sig",
            "future-iat",
            "record-expired",
            "not-an-address-record",
            "pin-mismatch",
            "not-cached",
            "txt-lookup-failed",
            "txt-malformed",
            "txt-ambiguous",
            "txt-key-mismatch",
        ],
    ),
    (
        RATE_LIMITED,
        "limit",
        &[
            Limit::From.as_str(),
            Limit::Root.as_str(),
            Limit::Ip.as_str(),
            Limit::Fetch.as_str(),
            Limit::FetchGlobal.as_str(),
            Limit::RecordSigners.as_str(),
            Limit::Bytes.as_str(),
            Limit::Domain.as_str(),
            Limit::Pairing.as_str(),
            "pair-claim",
        ],
    ),
    (
        "ac_relay_record_fetches_total",
        "result",
        &["ok", Code::BadAddress.as_str(), Code::NotFound.as_str(), Code::RateLimited.as_str(), "internal"],
    ),
    (
        "ac_relay_swept_total",
        "kind",
        &["mailbox", "envelopes", "tombstoned", "tombstones-expired", "records", "pending"],
    ),
    (PROXY_HEADER_IGNORED, "reason", &["untrusted-source", "malformed"]),
    (SIGNATURE_FAILURES, "kind", &["envelope", "record", "hop", "fetch", "subscribe", "pair-open"]),
    (
        PENDING_DROPPED,
        "reason",
        &[
            "expired",
            "revoked",
            "too-large-for-mailbox",
            "root-not-accepted",
            "gone",
            "corrupt",
            "not-hosted",
        ],
    ),
    (PAIR_CLAIMS, "result", &["ok", "no-nameplate", Code::RateLimited.as_str()]),
];

/// The counters by `result` that the daily totals read, with each call's own words: [`Metrics::started`] seeds these
/// and, under each family, every code of [`Code::ALL`], the closed set a refusal's code is from (the group is no
/// bound: a relay answers the edge's `revoked`). The alerts' signature and rotation refusals of a publish are among
/// them.
pub const SEEDED_BY_RESULT: [(&str, &[&str]); 4] = [
    ("ac_relay_publishes_total", &["stored", "duplicate", "record", "body-timeout", "internal"]),
    ("ac_relay_fetches_total", &["ok", "internal"]),
    ("ac_relay_subscribes_total", &["ok"]),
    ("ac_relay_pair_opens_total", &["ok", "body-timeout", "internal"]),
];

/// Every code's wire form, the result of a refusal ([`SEEDED_BY_RESULT`]).
fn codes() -> impl Iterator<Item = &'static str> + Clone {
    Code::ALL.iter().copied().map(Code::as_str)
}

/// The `rev` of the build info: `AC_REV` as the image's build passed it (deploy/relay/Dockerfile) when it is 7 to 40
/// lower-case hex digits, a commit; else `unknown`.
fn rev(built: Option<&'static str>) -> &'static str {
    let hex = |r: &str| r.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'));
    built.filter(|r| (7..=40).contains(&r.len()) && hex(r)).unwrap_or("unknown")
}

/// A series: its family, its label (empty for none) and the label's value.
type Series = (&'static str, &'static str, &'static str);

/// Counts, gauges and durations.
#[derive(Debug)]
pub struct Metrics {
    counters: Mutex<BTreeMap<Series, u64>>,
    gauges: Mutex<BTreeMap<Series, i64>>,
    durations: Mutex<BTreeMap<(&'static str, u16), Durations>>,
    mailboxes: Mutex<Option<Today>>,
    networks: Mutex<Option<Today>>,
    fresh: Mutex<Option<Today>>,
}

/// One route and status's requests: a count under each bucket's bound, their sum in microseconds and their count.
#[derive(Debug, Clone, Copy, Default)]
struct Durations {
    buckets: [u64; BUCKETS.len()],
    micros: u64,
    count: u64,
}

/// What was seen in one UTC day, as hashes under `key`, made for that day.
#[derive(Debug)]
struct Today {
    day: u64,
    key: RandomState,
    seen: HashSet<u64>,
}

impl Today {
    /// `thing` seen at `now`, true the first time in its UTC day; the first of a new day drops the last day's hashes
    /// and key.
    fn see(set: &Mutex<Option<Today>>, now: u64, thing: impl Hash) -> bool {
        let day = now / 86_400;
        let mut today = lock(set);
        if today.as_ref().is_some_and(|t| t.day != day) {
            *today = None;
        }
        let today = today.get_or_insert_with(|| Today { day, key: RandomState::new(), seen: HashSet::new() });
        let hash = today.key.hash_one(thing);
        today.seen.insert(hash)
    }

    /// How many were seen on the day of `now`.
    fn count(set: &Mutex<Option<Today>>, now: u64) -> i64 {
        let n = lock(set).as_ref().filter(|t| t.day == now / 86_400).map_or(0, |t| t.seen.len());
        i64::try_from(n).unwrap_or(i64::MAX)
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // Every update completes under the lock, so a panic elsewhere leaves usable counts.
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Each sample of `series` after its family's TYPE line of `kind`, with its label when it has one.
fn write_series<N: Display>(out: &mut String, kind: &str, series: &BTreeMap<Series, N>) {
    let mut family = "";
    for (&(name, label, value), n) in series {
        if name != family {
            let _ = writeln!(out, "# TYPE {name} {kind}");
            family = name;
        }
        if label.is_empty() {
            let _ = writeln!(out, "{name} {n}");
        } else {
            let _ = writeln!(out, "{name}{{{label}=\"{value}\"}} {n}");
        }
    }
}

impl Default for Metrics {
    fn default() -> Metrics {
        Metrics::new()
    }
}

impl Metrics {
    /// No counts yet.
    #[must_use]
    pub const fn new() -> Metrics {
        Metrics {
            counters: Mutex::new(BTreeMap::new()),
            gauges: Mutex::new(BTreeMap::new()),
            durations: Mutex::new(BTreeMap::new()),
            mailboxes: Mutex::new(None),
            networks: Mutex::new(None),
            fresh: Mutex::new(None),
        }
    }

    /// `n` more of the counter `family`, under `label="value"`, or with no label when `label` is empty.
    pub fn add(&self, family: &'static str, label: &'static str, value: &'static str, n: u64) {
        let mut counters = lock(&self.counters);
        let count = counters.entry((family, label, value)).or_default();
        *count = count.saturating_add(n);
    }

    /// One more of the counter `family` under `label="value"`.
    pub fn count(&self, family: &'static str, label: &'static str, value: &'static str) {
        self.add(family, label, value, 1);
    }

    /// One more of the counter `family`, which has no label.
    pub fn tick(&self, family: &'static str) {
        self.add(family, "", "", 1);
    }

    /// A call of `kind` (`envelope` for a publish, `fetch`, `subscribe` or `pair-open`) refused with `code`: one more
    /// of [`SIGNATURE_FAILURES`] when it is a signature's code, under `kind`, or `hop` for a hop of the chain and
    /// `record` for a record, whatever the call.
    pub fn refused(&self, kind: &'static str, code: Option<Code>) {
        let kind = match code {
            Some(Code::BadSig) => kind,
            Some(Code::BadHopSig) => "hop",
            Some(Code::BadRecordSig) => "record",
            _ => return,
        };
        self.count(SIGNATURE_FAILURES, "kind", kind);
    }

    /// The relay starts at `now`: its start time, `ac_relay_build_info{rev} 1` ([`rev`]; the region is the scrape's
    /// label), and at 0 the counters an alert or a daily total reads with `increase`, which counts nothing for a
    /// series' first sample, so that the first event after a deploy is seen: [`SEEDED`], each value of
    /// [`SEEDED_BY_LABEL`], and each result of [`SEEDED_BY_RESULT`]. Each moves by 0, keeping any count it has. So do
    /// the gauges of open subscriptions and connections, there from the first scrape at 0, since none outlives a
    /// restart, so that their alert and panels read 0, not no data, and a second relay in one test process keeps the
    /// first's count. The day's mailboxes and networks are in every render, 0 until the first.
    pub fn started(&self, now: u64) {
        self.gauge("ac_relay_build_info", "rev", rev(option_env!("AC_REV")), 1);
        self.set("process_start_time_seconds", now);
        for family in SEEDED {
            self.add(family, "", "", 0);
        }
        for (family, label, values) in SEEDED_BY_LABEL {
            for &value in values {
                self.add(family, label, value, 0);
            }
        }
        for (family, words) in SEEDED_BY_RESULT {
            for value in words.iter().copied().chain(codes()) {
                self.add(family, "result", value, 0);
            }
        }
        self.shift(SUBSCRIPTIONS_OPEN, 0);
        self.shift(CONNECTIONS_OPEN, 0);
    }

    /// The limits `config` sets, as gauges of [`LIMITS`] by `limit`, for a board to show beside their refusals: each
    /// rate limit under its name in [`RATE_LIMITED`] (`from`, `root`, `ip`, `fetch` a `window` of seconds,
    /// `fetch-global` a minute, the rest a UTC day), each cap under its reason in [`CONNECTIONS_REFUSED`],
    /// `store-bytes`, and `ttl` in seconds; 0 is no limit where its flag says so.
    pub fn limits(&self, config: &Config) {
        let (r, cap) = (&config.rate, |n: usize| u64::try_from(n).unwrap_or(u64::MAX));
        for (limit, value) in [
            ("window", r.window),
            (Limit::From.as_str(), r.per_from.into()),
            (Limit::Root.as_str(), r.per_root.into()),
            (Limit::Ip.as_str(), r.per_ip.into()),
            (Limit::Fetch.as_str(), r.fetch_per_ip.into()),
            (Limit::FetchGlobal.as_str(), r.fetch_global_per_minute.into()),
            (Limit::RecordSigners.as_str(), r.signers_per_day.into()),
            (Limit::Bytes.as_str(), r.bytes_per_day),
            (Limit::Domain.as_str(), r.domain_day.into()),
            ("connections-per-ip", cap(config.connections_per_ip)),
            ("subscriptions-per-ip", cap(config.subscriptions_per_ip())),
            ("store-bytes", config.max_store_bytes),
            ("ttl", config.ttl),
        ] {
            self.gauge(LIMITS, "limit", limit, value);
        }
    }

    /// The gauge `family` under `label="value"` is `n`, or with no label when `label` is empty.
    pub fn gauge(&self, family: &'static str, label: &'static str, value: &'static str, n: u64) {
        lock(&self.gauges).insert((family, label, value), i64::try_from(n).unwrap_or(i64::MAX));
    }

    /// The gauge `name` is `value`.
    pub fn set(&self, name: &'static str, value: u64) {
        self.gauge(name, "", "", value);
    }

    /// The gauge `name` moves by `by`.
    pub fn shift(&self, name: &'static str, by: i64) {
        let mut gauges = lock(&self.gauges);
        let gauge = gauges.entry((name, "", "")).or_default();
        *gauge = gauge.saturating_add(by);
    }

    /// One request of `route` answered `status` after `took`.
    pub fn observe(&self, route: &'static str, status: u16, took: Duration) {
        let micros = u64::try_from(took.as_micros()).unwrap_or(u64::MAX);
        let mut durations = lock(&self.durations);
        let d = durations.entry((route, status)).or_default();
        for (count, (bound, _)) in d.buckets.iter_mut().zip(BUCKETS) {
            *count += u64::from(micros <= bound);
        }
        d.micros = d.micros.saturating_add(micros);
        d.count += 1;
    }

    /// `mailbox` subscribed at `now`: counted once in its UTC day.
    pub fn subscribed(&self, now: u64, mailbox: &str) {
        Today::see(&self.mailboxes, now, mailbox);
    }

    /// `mailbox`, which no envelope has reached at this relay, subscribed at `now`: one more of [`FIRST_SUBSCRIBES`]
    /// the first time in its UTC day, counted as [`Metrics::subscribed`] counts, by a hash under the day's key.
    pub fn first_subscribed(&self, now: u64, mailbox: &str) {
        if Today::see(&self.fresh, now, mailbox) {
            self.tick(FIRST_SUBSCRIBES);
        }
    }

    /// A call from client `ip` at `now`: its network (the rate limits' bucket, an IPv4 address or an IPv6 /56) counted
    /// once in its UTC day; no network is kept, only a hash under the day's key (spec/SPEC.md §10, "Metadata").
    pub fn client(&self, now: u64, ip: IpAddr) {
        Today::see(&self.networks, now, crate::net::rate_bucket(ip));
    }

    /// The text of `/metrics` at `now`: the counters, then the gauges with the day's subscribed mailboxes and client
    /// networks, then the durations, each family once with its TYPE line.
    #[must_use]
    pub fn render(&self, now: u64) -> String {
        let mut out = String::new();
        write_series(&mut out, "counter", &lock(&self.counters));
        let mut gauges = lock(&self.gauges).clone();
        gauges.insert(("ac_relay_mailboxes_subscribed_today", "", ""), Today::count(&self.mailboxes, now));
        gauges.insert(("ac_relay_client_networks_today", "", ""), Today::count(&self.networks, now));
        write_series(&mut out, "gauge", &gauges);
        let durations = lock(&self.durations);
        if !durations.is_empty() {
            let _ = writeln!(out, "# TYPE {DURATION} histogram");
        }
        for (&(route, status), d) in durations.iter() {
            let labels = format!("http_route=\"{route}\",http_response_status_code=\"{status}\"");
            for ((_, le), n) in BUCKETS.iter().zip(d.buckets) {
                let _ = writeln!(out, "{DURATION}_bucket{{{labels},le=\"{le}\"}} {n}");
            }
            let (count, micros) = (d.count, d.micros);
            let _ = writeln!(out, "{DURATION}_bucket{{{labels},le=\"+Inf\"}} {count}");
            let _ =
                writeln!(out, "{DURATION}_sum{{{labels}}} {}.{:06}", micros / 1_000_000, micros % 1_000_000);
            let _ = writeln!(out, "{DURATION}_count{{{labels}}} {count}");
        }
        out
    }
}

/// The `http_route` of a request's path: the route of [`ROUTES`] it matches, a `{...}` part standing for one
/// non-empty segment, else `not-found`.
#[must_use]
pub fn route_of(path: &str) -> &'static str {
    let fits = |route: &str| match route.split_once('{') {
        None => path == route,
        Some((prefix, _)) => path.strip_prefix(prefix).is_some_and(|rest| {
            rest.split('/').all(|part| !part.is_empty())
                && rest.split('/').count() == route.matches('{').count()
        }),
    };
    ROUTES.into_iter().find(|route| fits(route)).unwrap_or("not-found")
}

/// Times each request of the public router by route and status.
pub(crate) async fn time(request: Request, next: Next) -> Response {
    let route = route_of(request.uri().path());
    let started = Instant::now();
    let response = next.run(request).await;
    METRICS.observe(route, response.status().as_u16(), started.elapsed());
    response
}

/// The metrics listener's routes: `GET /metrics`, and 404 `not-found` for anything else.
pub fn router(relay: Arc<Relay>) -> Router {
    Router::new().route("/metrics", get(scrape)).fallback(crate::http::not_found).with_state(relay)
}

async fn scrape(State(relay): State<Arc<Relay>>) -> Response {
    let now = relay.now();
    METRICS.set(NAMEPLATES_OPEN, u64::try_from(relay.pairs.open_at(now)).unwrap_or(u64::MAX));
    let mut text = METRICS.render(now);
    if let Some(url) = relay.config.metrics_litestream.clone() {
        text.push_str(&litestream(url).await);
    }
    ([(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")], text).into_response()
}

/// `ac_relay_litestream_up` and, when the read of `url` succeeded, Litestream's `litestream_*` lines.
pub async fn litestream(url: String) -> String {
    let read = tokio::task::spawn_blocking(move || read_litestream(&url)).await.ok().and_then(Result::ok);
    let up = u8::from(read.is_some());
    let mut out = format!("# TYPE ac_relay_litestream_up gauge\nac_relay_litestream_up {up}\n");
    for line in read.iter().flat_map(|text| text.lines()) {
        let named = line.strip_prefix("# TYPE ").or_else(|| line.strip_prefix("# HELP ")).unwrap_or(line);
        if named.starts_with("litestream_") {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

fn read_litestream(url: &str) -> Result<String, ureq::Error> {
    let config = ureq::Agent::config_builder()
        .http_status_as_error(true)
        .max_redirects(0)
        .proxy(None)
        .timeout_global(Some(LITESTREAM_TIMEOUT))
        .build();
    let mut answer = ureq::Agent::new_with_config(config).get(url).call()?;
    answer.body_mut().with_config().limit(LITESTREAM_MAX_BYTES).read_to_string()
}

#[cfg(test)]
mod tests;
