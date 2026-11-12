//! `ac-relay`: the reference relay as a process.
//!
//! ```text
//! ac-relay --port 0 --db /tmp/relay.sqlite [--bind 127.0.0.1] [--advertise http://<host>] [--accept-base <url>]...
//!          [--ttl 604800]
//!          [--skew 300] [--max-envelope-bytes 196608] [--well-known-timeout 10] [--well-known-cache-max 86400]
//!          [--well-known-insecure-http] [--well-known-resolve <host>=<ip>:<port>]... [--dns-resolve <name>=<txt>]...
//!          [--header-timeout 10] [--body-timeout 30] [--connections-per-ip 79]
//!          [--connection-reserve-permille 125] [--rate-window 60]
//!          [--rate-per-from 120] [--rate-per-root 1200] [--rate-per-ip 600] [--fetch-per-ip 6000]
//!          [--fetch-global-per-minute 30000]
//!          [--record-signers-per-day 100] [--bytes-per-ip-per-day 100000000]
//!          [--sweep-interval 60] [--ping-interval 30] [--idle-timeout 60]
//!          [--trust-proxy <cidr>]... [--client-ip-header cf-connecting-ip] [--log-ip prefix|full|none]
//!          [--exit-on-stdin-eof] [--domain-publishes-per-day 10000] [--blocklist <file>] [--abuse-contact <uri>]
//!          [--max-store-bytes 0] [--metrics-port <port> [--metrics-bind ::] [--metrics-litestream <url>]]
//! ac-relay --db r.sqlite --pin-reset <domain> [--queue] --new-key <key> --operator <o> --channel <c> --reason <r>
//! ac-relay probe <url> --key <file>
//! ac-relay block <file> [+<entry> | -<entry>]...
//! ```
//!
//! It listens on `--bind` (default 127.0.0.1; 0.0.0.0 or `::` for every interface) and, once listening, prints
//! exactly one line to stdout, `AC_RELAY_URL=<url>`, which the e2e harness reads: `http://127.0.0.1:<port>` by
//! default, else `--advertise`'s, which health answers too ([`ac_relay::net`]). Logs are
//! JSON lines on stderr, the first naming the bind address and that URL; a test-only well-known or DNS flag adds a
//! warning line after it, and is refused (exit 2) unless `--bind` is a loopback address. A count or duration
//! flag that must be positive is at least 1 (0 is exit 2), and `--idle-timeout` at least twice `--ping-interval` (else exit 2). SIGTERM or
//! SIGINT stops it gracefully, with exit status 0; their handlers are registered before the URL line is printed, so a
//! signal sent the moment the line is read is caught too. With `--exit-on-stdin-eof` the end of stdin
//! stops it the same way, after a `stdin-eof` log line: a parent holding the write end of a pipe to the relay's stdin
//! ends the relay by exiting, however it exits (SIGKILL included); without the flag stdin is never read. Its stdin must
//! then be a pipe (a file or /dev/null stops it at once); a terminal stdin in a background job of an interactive shell
//! stops the relay with SIGTTIN on the read. With `--pin-reset` it listens on nothing: it deletes one domain's pin from
//! the database, prints `pin-reset <domain> <key or none>`, logs it, and exits 0 (the operator's override, run while
//! the relay is stopped). `ac-relay probe` checks a relay from outside and exits 0, 1 or 2 ([`ac_relay::probe`]).
//! `ac-relay block` adds (`+`) and removes (`-`) the entries of a blocklist file, which a running relay reads again by
//! itself ([`ac_relay::abuse`]), and prints the entries; a bad edit changes nothing and exits 1.
#![forbid(unsafe_code)]

use ac_core::Address;
use ac_core::records::Domain;
use ac_relay::Relay;
use ac_relay::clock::{Clock as _, SystemClock};
use ac_relay::config::{
    Config, DEFAULT_BODY_TIMEOUT, DEFAULT_CONNECTION_RESERVE_PERMILLE, DEFAULT_CONNECTIONS_PER_IP,
    DEFAULT_HEADER_TIMEOUT, DEFAULT_MAX_ENVELOPE_BYTES, DEFAULT_SKEW, DEFAULT_TTL,
    DEFAULT_WELL_KNOWN_CACHE_MAX, DEFAULT_WELL_KNOWN_TIMEOUT, RateLimits, WellKnown,
};
use ac_relay::net::{
    Advertise, Cidr, DEFAULT_BIND, DEFAULT_CLIENT_IP_HEADER, Front, LogIp, accept_base, announced_url,
};
use ac_relay::store::Store as _;
use ac_relay::store::sqlite::{RESTORE_CURSOR_GAP, SqliteStore};
use axum::http::HeaderName;
use clap::{CommandFactory as _, Parser};
use std::future::Future;
use std::io::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

/// The bag reference relay: publish, fetch and subscribe over HTTP and WebSocket, stored in SQLite.
#[derive(Debug, Parser)]
#[command(name = "ac-relay", version)]
struct Args {
    /// The port to listen on; 0 picks a free one.
    #[arg(long, default_value_t = 0)]
    port: u16,
    /// The address to listen on, IPv4 or IPv6; 0.0.0.0 or :: listens on every interface.
    #[arg(long, default_value_t = DEFAULT_BIND)]
    bind: IpAddr,
    /// The URL to print instead of the bound address, and to answer from health, as `http://<host>[:<port>]` (or
    /// https): a port written is kept; without one, https prints none and http the listening port.
    #[arg(long, value_parser = Advertise::parse)]
    advertise: Option<Advertise>,
    /// Another public base URL a fetch proof's audience may name besides the announced URL: a relays entry (http or
    /// https, a lower-case host, a port only when not the scheme's default, nothing further); repeatable. For a
    /// relay's second name while it moves; never a base another relay also takes.
    #[arg(long = "accept-base", value_name = "URL", value_parser = accept_base)]
    accept_base: Vec<String>,
    /// The SQLite database file; created when missing, and its directory must exist.
    #[arg(long)]
    db: PathBuf,
    /// The relay TTL in seconds: the longest an envelope is kept, and with the skew the stale-ts window.
    #[arg(long, default_value_t = DEFAULT_TTL)]
    ttl: u64,
    /// The allowed clock skew in seconds.
    #[arg(long, default_value_t = DEFAULT_SKEW)]
    skew: u64,
    /// The envelope cap in bytes, at most the 262144-byte body cap.
    #[arg(long, default_value_t = DEFAULT_MAX_ENVELOPE_BYTES)]
    max_envelope_bytes: usize,
    /// How long one resolution of a `domain:` root may take, in seconds (1 to 60).
    #[arg(long, default_value_t = DEFAULT_WELL_KNOWN_TIMEOUT)]
    well_known_timeout: u64,
    /// The longest a domain's record is cached, in seconds (1 to 86400); records are cached until iat + ttl, for
    /// 60 s at least unless this is shorter.
    #[arg(long, default_value_t = DEFAULT_WELL_KNOWN_CACHE_MAX)]
    well_known_cache_max: u64,
    /// Test only: read well-known records over http://, and from hosts whose addresses are not public. Refused
    /// unless --bind is a loopback address.
    #[arg(long)]
    well_known_insecure_http: bool,
    /// Test only: resolve a host to a fixed address in place of DNS, as curl's --resolve; repeatable. Refused
    /// unless --bind is a loopback address.
    #[arg(long, value_name = "HOST=IP:PORT", value_parser = WellKnown::parse_resolve)]
    well_known_resolve: Vec<(Domain, SocketAddr)>,
    /// Test only: a TXT record at a name in place of DNS, its text quoted as in a zone file (spec/SPEC.md §12.2 item
    /// 7), such as `_bag.acme.test="v=ac1; key=ed25519:..."`; repeatable. With it, or another test-only
    /// flag, the relay asks no DNS server. Refused unless --bind is a loopback address.
    #[arg(long, value_name = "NAME=TXT", value_parser = WellKnown::parse_dns_resolve)]
    dns_resolve: Vec<(String, Vec<Vec<u8>>)>,
    /// Operator override: delete the pin of a domain from --db, print the key it held, and exit without listening.
    /// For an organization that lost both its key and its rotation key; stop the relay first. Needs the flags below.
    #[arg(long, value_name = "DOMAIN", value_parser = parse_domain,
        requires_all = ["new_key", "operator", "channel", "reason"])]
    pin_reset: Option<Domain>,
    /// With --pin-reset: open no database; append the request to `<db>.pin-resets` for a relay's next start.
    #[arg(long, requires = "pin_reset")]
    queue: bool,
    /// The key the organization confirmed by a channel independent of the relay and of DNS (an address).
    #[arg(long, value_name = "ADDRESS", value_parser = parse_address, requires = "pin_reset")]
    new_key: Option<Address>,
    /// Who confirmed it: the operator and the organization's named counterparty.
    #[arg(long, requires = "pin_reset")]
    operator: Option<String>,
    /// The specific channel that confirmed it, named concretely (never "another channel").
    #[arg(long, requires = "pin_reset")]
    channel: Option<String>,
    /// Why a countersigned rotation (spec/SPEC.md §7.3) could not be used.
    #[arg(long, requires = "pin_reset")]
    reason: Option<String>,
    /// How long a client may take to send a request head, in seconds; on a new connection also its first bytes.
    /// A connection that has not sent one by then is closed.
    #[arg(long, value_name = "SECONDS", default_value_t = DEFAULT_HEADER_TIMEOUT, value_parser = at_least_one)]
    header_timeout: u64,
    /// How long a client may take to send a publish body, in seconds; then it is answered 408 and closed.
    #[arg(long, value_name = "SECONDS", default_value_t = DEFAULT_BODY_TIMEOUT, value_parser = at_least_one)]
    body_timeout: u64,
    /// The most connections one client may hold open at once; one more is closed at once. A client is an IPv4
    /// address or an IPv6 /64; behind a --trust-proxy, the one its header names, whose WebSocket connections count
    /// (the proxy's own do not), and one more of those is refused `rate-limited` after the upgrade.
    #[arg(long, value_name = "N", default_value_t = DEFAULT_CONNECTIONS_PER_IP as u64, value_parser = at_least_one)]
    connections_per_ip: u64,
    /// The share of --connections-per-ip a direct client's subscriptions may not take, kept for its calls, in
    /// thousandths: at least 8 places, or half a smaller cap; 0 holds none back. Under 1000. Behind a --trust-proxy
    /// calls are not counted, and it is not used. A subscription over the limit is refused `rate-limited`.
    #[arg(long, value_name = "PERMILLE", default_value_t = DEFAULT_CONNECTION_RESERVE_PERMILLE)]
    connection_reserve_permille: u32,
    /// The length of the rate windows, in seconds: publishes are counted in fixed windows aligned to multiples of it.
    #[arg(long, value_name = "SECONDS", default_value_t = 60, value_parser = at_least_one)]
    rate_window: u64,
    /// The envelopes one `from` key may publish in a window (and the records one signer may).
    #[arg(long, value_name = "N", default_value_t = 120, value_parser = count)]
    rate_per_from: u32,
    /// The envelopes that may be published under one root in a window.
    #[arg(long, value_name = "N", default_value_t = 1_200, value_parser = count)]
    rate_per_root: u32,
    /// The publishes one client may make in a window, counted before any signature is verified. A client is an IPv4
    /// address or an IPv6 /56; behind a --trust-proxy, the one its header names (without one, every client of the
    /// proxy shares this limit).
    #[arg(long, value_name = "N", default_value_t = 600, value_parser = count)]
    rate_per_ip: u32,
    /// The fetches, of an envelope or a record, one client may make in a window, counted before any signature is
    /// verified. A client is an IPv4 address or an IPv6 /56; behind a --trust-proxy, the one its header names (without
    /// one, every client of the proxy shares this limit).
    #[arg(long, value_name = "N", default_value_t = 6_000, value_parser = count)]
    fetch_per_ip: u32,
    /// The fetches the relay takes in a minute from all clients together, counted before any signature is verified: the
    /// line behind --fetch-per-ip, against a flood from many addresses. 0 turns it off.
    #[arg(long, value_name = "N", default_value_t = 30_000)]
    fetch_global_per_minute: u32,
    /// The new record signers (keys the relay holds no record of) one client may bring in a UTC day. A client is an
    /// IPv4 address or an IPv6 /56; behind a --trust-proxy, the one its header names (without one, every client of
    /// the proxy shares this quota).
    #[arg(long, value_name = "N", default_value_t = 100, value_parser = count)]
    record_signers_per_day: u32,
    /// The bytes of envelopes one client may store in a UTC day; past them, 429 rate-limited until 00:00 UTC. A duplicate
    /// stores nothing and counts nothing. A client is an IPv4 address or an IPv6 /56; behind a --trust-proxy, the one its
    /// header names (without one, every client of the proxy shares this quota). 0 turns it off.
    #[arg(long, value_name = "BYTES", default_value_t = 100_000_000)]
    bytes_per_ip_per_day: u64,
    /// How often expired mailbox rows, envelopes, tombstones and records are swept, in seconds.
    #[arg(long, value_name = "SECONDS", default_value_t = 60, value_parser = at_least_one)]
    sweep_interval: u64,
    /// How often a subscriber is pinged, in seconds.
    #[arg(long, value_name = "SECONDS", default_value_t = 30, value_parser = at_least_one)]
    ping_interval: u64,
    /// How long a subscriber may stay silent, a pong included, before it is closed (4003), and how long the relay
    /// waits for its auth frame, in seconds; at least twice --ping-interval.
    #[arg(long, value_name = "SECONDS", default_value_t = 60, value_parser = at_least_one)]
    idle_timeout: u64,
    /// A trusted proxy's network, as <address>/<length>, or its address; repeatable. A request from one names its
    /// client in --client-ip-header, which is counted and logged as that client. Without it no header is read.
    #[arg(long, value_name = "CIDR", value_parser = Cidr::parse)]
    trust_proxy: Vec<Cidr>,
    /// The header in which a trusted proxy names the client (default cf-connecting-ip, cloudflared's; for
    /// x-forwarded-for the right-most address that is not a trusted proxy's). Only with --trust-proxy.
    #[arg(long, value_name = "NAME", requires = "trust_proxy")]
    client_ip_header: Option<HeaderName>,
    /// How the log lines name a client's address: prefix (its /24 or /48), full, or none.
    #[arg(long, value_enum, default_value_t = LogIp::Prefix, overrides_with = "log_ip")]
    log_ip: LogIp,
    /// Stop gracefully, as on SIGTERM, when stdin reaches its end (or fails): a parent that holds a pipe to the
    /// relay's stdin ends it by exiting, however it exits. Without it stdin is not read. Stdin must be a pipe (a file
    /// or /dev/null stops it at once); a terminal stdin in a background job of an interactive shell stops the relay
    /// with SIGTTIN on the read.
    #[arg(long)]
    exit_on_stdin_eof: bool,
    /// The envelopes one sender domain may publish in a UTC day: the `domain:` root whose current key is the chain's
    /// root, as the recipients' accept-from records resolved it (a root no domain admitted counts against none, only
    /// --rate-per-root). 0 turns the quota off; the default is 10,000.
    #[arg(long, value_name = "N", default_value_t = 10_000)]
    domain_publishes_per_day: u32,
    /// The operator's blocklist: one `ed25519:` address or `domain:<host>` root a line, edited with `ac-relay block`
    /// and read again on change; a missing file blocks nothing. A listed key's publishes are 403 not-authorized.
    #[arg(long, value_name = "FILE")]
    blocklist: Option<PathBuf>,
    /// Where abuse is reported, such as mailto:abuse@example.org: answered at /v0/abuse (404 without it).
    #[arg(long, value_name = "URI")]
    abuse_contact: Option<String>,
    /// The bytes of live data the database may hold (its pages in use, not its file, which keeps its largest size)
    /// from which a publish of an envelope, or of a record of a signer the relay holds none of, is refused 503
    /// `store-full`; a known signer's records, fetch, subscribe and the sweep go on. 0, the default, is no bound. Leave room on the volume for the write-ahead log: 900000000 on a volume of 1 GB.
    #[arg(long, value_name = "BYTES", default_value_t = 0)]
    max_store_bytes: u64,
    /// A second port, answering `GET /metrics` with the relay's counts in Prometheus's text format and nothing else;
    /// without it there is no such listener. The relay's own port answers /metrics 404.
    #[arg(long, value_name = "PORT")]
    metrics_port: Option<u16>,
    /// The address of the metrics listener, IPv4 or IPv6; `::` listens on every interface. Only with --metrics-port.
    #[arg(long, value_name = "IP", default_value_t = DEFAULT_BIND, requires = "metrics_port")]
    metrics_bind: IpAddr,
    /// Litestream's metrics on this host, as `http://127.0.0.1:<port>/metrics` (or `[::1]`, or localhost): each scrape
    /// passes on its `litestream_*` lines, with `ac_relay_litestream_up` 0 when the read fails. Only with
    /// --metrics-port.
    #[arg(long, value_name = "URL", value_parser = parse_local_url, requires = "metrics_port")]
    metrics_litestream: Option<String>,
}

/// `ac-relay probe <url> --key <file>`: the relay checked from outside, for a healthcheck (exit 0, 1 or 2).
#[derive(Debug, Parser)]
#[command(name = "ac-relay probe", version)]
struct ProbeArgs {
    /// The relay's URL, as its clients reach it.
    url: String,
    /// The probe's key file, 64 hex characters, made (mode 0600) when missing; its seed is never printed.
    #[arg(long, value_name = "FILE")]
    key: PathBuf,
}

/// A count or a number of seconds of at least 1: 0 is a flag error (exit 2).
fn at_least_one(text: &str) -> Result<u64, String> {
    match text.parse::<u64>() {
        Ok(0) => Err("must be at least 1".into()),
        Ok(n) => Ok(n),
        Err(e) => Err(e.to_string()),
    }
}

/// A limit of at least 1 that fits the counters (u32): 0 is a flag error (exit 2).
fn count(text: &str) -> Result<u32, String> {
    let n = at_least_one(text)?;
    u32::try_from(n).map_err(|_| format!("must be at most {}", u32::MAX))
}

fn parse_address(text: &str) -> Result<Address, String> {
    Address::parse(text).map_err(|_| format!("{text:?} is not an ed25519: address"))
}

fn parse_local_url(text: &str) -> Result<String, String> {
    let local = ["http://127.0.0.1:", "http://[::1]:", "http://localhost:"];
    if local.iter().any(|prefix| {
        text.strip_prefix(prefix).is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
    }) {
        Ok(text.to_owned())
    } else {
        Err(format!("{text:?} is not an http:// URL on this host with a port"))
    }
}

fn parse_domain(text: &str) -> Result<Domain, String> {
    Domain::parse(text).map_err(|_| format!("{text:?} is not a domain root's host (a lowercase DNS name)"))
}

fn main() -> ExitCode {
    if std::env::args_os().nth(1).is_some_and(|a| a == "probe") {
        let args = ProbeArgs::parse_from(std::env::args_os().skip(1));
        let done = ac_relay::probe::run(&args.url, &args.key);
        let written = match &done {
            Ok(id) => writeln!(std::io::stdout(), "probe ok {id}"),
            Err(why) => writeln!(std::io::stderr(), "probe: {why}"),
        };
        return if done.is_ok() && written.is_ok() { ExitCode::SUCCESS } else { ExitCode::FAILURE };
    }
    if std::env::args_os().nth(1).is_some_and(|a| a == "block") {
        let args: Vec<String> = std::env::args().skip(2).collect();
        let Some((file, edits)) = args.split_first() else {
            let _ = writeln!(std::io::stderr(), "usage: ac-relay block <file> [+<entry> | -<entry>]...");
            return ExitCode::from(2);
        };
        let edited = ac_relay::abuse::edit(std::path::Path::new(file), edits);
        let mut out = std::io::stdout().lock();
        let written = match &edited {
            Ok(list) => list.iter().try_for_each(|e| writeln!(out, "{e}")),
            Err(why) => writeln!(std::io::stderr(), "block: {why}"),
        };
        return if edited.is_ok() && written.is_ok() { ExitCode::SUCCESS } else { ExitCode::FAILURE };
    }
    relay()
}

#[tokio::main]
async fn relay() -> ExitCode {
    let args = Args::parse();
    let test_only =
        args.well_known_insecure_http || !args.well_known_resolve.is_empty() || !args.dns_resolve.is_empty();
    if test_only && !args.bind.is_loopback() {
        let why = format!(
            "--well-known-insecure-http, --well-known-resolve and --dns-resolve are test-only: they need a loopback \
             --bind, not {}",
            args.bind
        );
        Args::command().error(clap::error::ErrorKind::ArgumentConflict, why).exit();
    }
    if args.idle_timeout < args.ping_interval.saturating_mul(2) {
        let why = format!(
            "--idle-timeout ({}) must be at least twice --ping-interval ({}): a subscriber that answers every ping \
             must have a whole interval to do it",
            args.idle_timeout, args.ping_interval
        );
        Args::command().error(clap::error::ErrorKind::ArgumentConflict, why).exit();
    }
    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::INFO)
        .with_current_span(false)
        .init();
    let run = match args.pin_reset.clone() {
        Some(domain) => pin_reset(&args, &domain),
        None => start(args).await,
    };
    match run {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(event = "fatal", error = %error);
            ExitCode::FAILURE
        }
    }
}

/// The operator's override: deletes one domain's pin, so that the relay pins the key it reads next at first contact
/// again, and logs the reset with its record. With --queue it opens no database and appends the request to a file.
fn pin_reset(args: &Args, domain: &Domain) -> Result<(), String> {
    let req = serde_json::json!({ "domain": domain.as_str(), "operator": args.operator, "channel": args.channel,
        "new_key": args.new_key.as_ref().map(ToString::to_string), "reason": args.reason,
        "requested_at": SystemClock.now() });
    let line = if args.queue {
        let path = format!("{}.pin-resets", args.db.display());
        let append = std::fs::OpenOptions::new().create(true).append(true).open(&path);
        append.and_then(|mut file| writeln!(file, "{req}")).map_err(|e| format!("{path}: {e}"))?;
        format!("pin-reset-queued {domain}")
    } else {
        let store = SqliteStore::open(&args.db).map_err(|e| format!("{e} ({})", args.db.display()))?;
        reset_pin(&store, &args.db, &req)?
    };
    let mut out = std::io::stdout().lock();
    writeln!(out, "{line}").and_then(|()| out.flush()).map_err(io_error)
}

/// One reset applied: the pin deleted, and one `pin-reset` line with the record a pin reset
/// calls for (subject, old and new key, operator, channel, reason, time). Returns the line the command prints.
fn reset_pin(store: &SqliteStore, db: &Path, req: &serde_json::Value) -> Result<String, String> {
    let get = |k: &str| req[k].as_str().filter(|s| !s.is_empty()).ok_or(format!("the request has no {k}"));
    let (new_key, operator, channel, reason) =
        (get("new_key")?, get("operator")?, get("channel")?, get("reason")?);
    let domain = parse_domain(get("domain")?)?;
    let removed = store.delete_domain_pin(domain.as_str()).map_err(|e| e.to_string())?;
    let old_key = removed.as_ref().map_or("none", |pin| pin.key.as_str());
    let (pinned_at, requested_at) = (removed.as_ref().map(|pin| pin.pinned_at), req["requested_at"].as_u64());
    tracing::warn!(event = "pin-reset", domain = %domain, old_key, new_key, operator, channel, reason, requested_at,
        pinned_at, db = %db.display());
    Ok(format!("pin-reset {domain} {old_key}"))
}

/// The resets queued in `<db>.pin-resets`, applied before the relay listens; the file is then renamed with the time, so
/// that a request is applied once. A bad request is logged as `pin-reset-refused` and skipped, never fatal.
fn apply_pin_resets(store: &SqliteStore, db: &Path) {
    let file = format!("{}.pin-resets", db.display());
    let Ok(text) = std::fs::read_to_string(&file) else { return };
    for (n, line) in text.lines().enumerate().filter(|(_, l)| !l.trim().is_empty()) {
        let applied =
            serde_json::from_str(line).map_err(|e| e.to_string()).and_then(|req| reset_pin(store, db, &req));
        if let Err(error) = applied {
            tracing::error!(event = "pin-reset-refused", line = n + 1, error = %error);
        }
    }
    std::fs::rename(&file, format!("{file}.{}", SystemClock.now()))
        .unwrap_or_else(|e| tracing::error!(event = "pin-reset-refused", file = %file, error = %e));
}

async fn start(args: Args) -> Result<(), String> {
    let well_known = WellKnown {
        timeout: Duration::from_secs(args.well_known_timeout),
        cache_max: args.well_known_cache_max,
        insecure_http: args.well_known_insecure_http,
        resolve: args.well_known_resolve.clone(),
        dns_resolve: args.dns_resolve.clone(),
    };
    let (trusted, header) = (args.trust_proxy.clone(), args.client_ip_header.clone());
    let mut config = Config {
        ttl: args.ttl,
        skew: args.skew,
        max_envelope_bytes: args.max_envelope_bytes,
        header_timeout: Duration::from_secs(args.header_timeout),
        body_timeout: Duration::from_secs(args.body_timeout),
        connections_per_ip: usize::try_from(args.connections_per_ip).unwrap_or(usize::MAX),
        connection_reserve_permille: args.connection_reserve_permille,
        rate: RateLimits {
            window: args.rate_window,
            per_from: args.rate_per_from,
            per_root: args.rate_per_root,
            per_ip: args.rate_per_ip,
            fetch_per_ip: args.fetch_per_ip,
            fetch_global_per_minute: args.fetch_global_per_minute,
            signers_per_day: args.record_signers_per_day,
            bytes_per_day: args.bytes_per_ip_per_day,
            domain_day: args.domain_publishes_per_day,
        },
        sweep_interval: Duration::from_secs(args.sweep_interval),
        ping_interval: Duration::from_secs(args.ping_interval),
        idle_timeout: Duration::from_secs(args.idle_timeout),
        well_known,
        front: Front { trusted, header, log_ip: args.log_ip },
        blocklist: args.blocklist.clone(),
        abuse_contact: args.abuse_contact.clone(),
        max_store_bytes: args.max_store_bytes,
        metrics_litestream: args.metrics_litestream.clone(),
        accept_bases: args.accept_base.clone(),
        ..Config::default()
    };
    config.validate()?;
    let blocked = args.blocklist.as_deref().map(ac_relay::abuse::read).transpose()?.map(|list| list.len());
    let store = SqliteStore::open(&args.db).map_err(|e| format!("{e} ({})", args.db.display()))?;
    apply_pin_resets(&store, &args.db);
    let volume = PathBuf::from(format!("{}.volume", args.db.display()));
    if let Some(mailboxes) = store.raise_after_restore(&volume).map_err(|e| e.to_string())? {
        tracing::warn!(event = "cursors-raised", mailboxes, by = RESTORE_CURSOR_GAP);
    }
    let listener = TcpListener::bind((args.bind, args.port))
        .await
        .map_err(|e| format!("cannot listen on {}: {e}", SocketAddr::new(args.bind, args.port)))?;
    let port = listener.local_addr().map_err(io_error)?.port();
    let metrics = metrics_listener(&args).await?;
    let metrics_at = metrics.as_ref().map(TcpListener::local_addr).transpose().map_err(io_error)?;
    let url = announced_url(args.bind, port, args.advertise.as_ref());
    let shutdown = shutdown_signal(args.exit_on_stdin_eof).map_err(io_error)?;
    announce(&url).map_err(io_error)?;
    let trusted: Vec<String> = config.front.trusted.iter().map(ToString::to_string).collect();
    tracing::info!(event = "listening", bind = %args.bind, port, url = %url, accept_bases = %args.accept_base.join(" "),
        db = %args.db.display(),
        ttl = config.ttl, skew = config.skew, max_envelope_bytes = config.max_envelope_bytes,
        well_known_timeout = args.well_known_timeout, well_known_cache_max = config.well_known.cache_max,
        header_timeout = args.header_timeout, body_timeout = args.body_timeout,
        connections_per_ip = args.connections_per_ip, subscriptions_per_ip = config.subscriptions_per_ip(),
        rate_window = args.rate_window, rate_per_from = args.rate_per_from, rate_per_root = args.rate_per_root, rate_per_ip = args.rate_per_ip, fetch_per_ip = args.fetch_per_ip,
        fetch_global_per_minute = args.fetch_global_per_minute,
        record_signers_per_day = args.record_signers_per_day, bytes_per_ip_per_day = args.bytes_per_ip_per_day,
        sweep_interval = args.sweep_interval,
        ping_interval = args.ping_interval, idle_timeout = args.idle_timeout, trust_proxy = %trusted.join(" "),
        client_ip_header = args.client_ip_header.as_ref().map_or(DEFAULT_CLIENT_IP_HEADER, HeaderName::as_str),
        log_ip = %format!("{:?}", config.front.log_ip).to_lowercase(), blocked,
        domain_publishes_per_day = args.domain_publishes_per_day, abuse_contact = args.abuse_contact.as_deref(),
        max_store_bytes = args.max_store_bytes, metrics = metrics_at.map(|at| at.to_string()).as_deref(),
        metrics_litestream = args.metrics_litestream.as_deref(),
        txt = if config.well_known.is_test_only() { "fixed" } else { "dns" });
    if config.well_known.insecure_http {
        tracing::warn!(
            event = "well-known-insecure-http",
            note = "test only: domain roots are read over http://, and from hosts whose addresses are not public"
        );
    }
    if !config.well_known.resolve.is_empty() {
        let hosts: Vec<String> = config.well_known.resolve.iter().map(|(d, a)| format!("{d}={a}")).collect();
        tracing::warn!(event = "well-known-resolve", note = "test only: these hosts are not looked up",
            hosts = %hosts.join(" "));
    }
    if !config.well_known.dns_resolve.is_empty() {
        let names: Vec<&str> = config.well_known.dns_resolve.iter().map(|(n, _)| n.as_str()).collect();
        tracing::warn!(event = "dns-resolve", note = "test only: these TXT records are given, and no DNS server is asked",
            names = %names.join(" "));
    }
    config.url = Some(url);
    let relay = Arc::new(Relay::new(Arc::new(store), Arc::new(SystemClock), config));
    ac_relay::run_with_metrics(listener, metrics, relay, shutdown).await.map_err(io_error)?;
    tracing::info!(event = "stopped");
    Ok(())
}

/// The metrics listener of `--metrics-port`, on `--metrics-bind`; none without the flag.
async fn metrics_listener(args: &Args) -> Result<Option<TcpListener>, String> {
    let Some(port) = args.metrics_port else { return Ok(None) };
    let at = SocketAddr::new(args.metrics_bind, port);
    TcpListener::bind(at).await.map(Some).map_err(|e| format!("cannot listen on {at}: {e}"))
}

/// The one line on stdout: the URL the relay is reached at.
fn announce(url: &str) -> std::io::Result<()> {
    let mut out = std::io::stdout().lock();
    writeln!(out, "AC_RELAY_URL={url}")?;
    out.flush()
}

#[allow(clippy::needless_pass_by_value, reason = "taken by value to serve as a map_err function")]
fn io_error(e: std::io::Error) -> String {
    format!("i/o: {e}")
}

/// Registers the handlers of SIGTERM and SIGINT now, and resolves on either once awaited. `start` calls it before the
/// URL line: until 2026-10-26 the handlers were registered only when the server's task first polled this future,
/// after the line, and a SIGTERM in between ended the relay by its default action, with no drain and no `stopped`
/// line. With `stdin_eof` (`--exit-on-stdin-eof`)
/// it also starts the thread of [`stdin_closed`] now, and resolves at the end of stdin as well.
fn shutdown_signal(stdin_eof: bool) -> std::io::Result<impl Future<Output = ()> + Send + 'static> {
    use tokio::signal::unix::{SignalKind, signal};
    let (mut term, mut interrupt) = (signal(SignalKind::terminate())?, signal(SignalKind::interrupt())?);
    let closed = if stdin_eof { Some(stdin_closed()?) } else { None };
    Ok(async move {
        let eof = async move {
            if let Some(closed) = closed {
                closed.await.unwrap_or_else(|_| "the stdin thread ended".to_owned())
            } else {
                std::future::pending::<String>().await
            }
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = interrupt.recv() => {}
            read = eof => tracing::info!(event = "stdin-eof", read = %read),
        }
    })
}

/// A thread that copies stdin to nothing until its end or a read error (`io::copy` retries an interrupted read), and
/// then sends how the read ended, `eof` or the error, which the `stdin-eof` line logs as `read`; a thread that died
/// would end the receiver too. It is never joined: the process exits past it.
fn stdin_closed() -> std::io::Result<tokio::sync::oneshot::Receiver<String>> {
    let (done, closed) = tokio::sync::oneshot::channel();
    std::thread::Builder::new().name("stdin-eof".into()).spawn(move || {
        let read = std::io::copy(&mut std::io::stdin().lock(), &mut std::io::sink());
        let _ = done.send(read.map_or_else(|e| e.to_string(), |_| "eof".to_owned()));
    })?;
    Ok(closed)
}

#[cfg(test)]
mod tests {
    use super::Args;
    use clap::Parser as _;

    /// The per-sender-domain daily publish quota defaults ON at 10,000 when `--domain-publishes-per-day` is not
    /// given (`config.rs` builds `rate.domain_day` from this arg), and an explicit `--domain-publishes-per-day 0`
    /// still turns the quota off. (`ratelimit.rs` treats `domain_day == 0` as no quota.)
    #[test]
    fn domain_publishes_per_day_defaults_to_10_000_and_an_explicit_zero_is_off() {
        let unset = Args::try_parse_from(["ac-relay", "--db", "relay.sqlite"]).unwrap();
        assert_eq!(unset.domain_publishes_per_day, 10_000, "default on at 10,000 when the flag is not given");

        let off =
            Args::try_parse_from(["ac-relay", "--db", "relay.sqlite", "--domain-publishes-per-day", "0"])
                .unwrap();
        assert_eq!(off.domain_publishes_per_day, 0, "an explicit 0 still turns the quota off");

        let custom =
            Args::try_parse_from(["ac-relay", "--db", "relay.sqlite", "--domain-publishes-per-day", "5000"])
                .unwrap();
        assert_eq!(custom.domain_publishes_per_day, 5_000, "an explicit value is kept");
    }
}
