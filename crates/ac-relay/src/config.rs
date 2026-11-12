//! The relay's settings and their defaults.

use crate::net::Front;
use ac_core::records::Domain;
use std::net::SocketAddr;
use std::time::Duration;

/// The relay TTL: how long an envelope is kept at most, and with the skew the stale-`ts` window (7 days).
pub const DEFAULT_TTL: u64 = 604_800;
/// The allowed clock skew, in seconds.
pub const DEFAULT_SKEW: u64 = 300;
/// The envelope cap, in bytes (192 KiB).
pub const DEFAULT_MAX_ENVELOPE_BYTES: usize = 196_608;
/// The hard cap on any request body, in bytes (256 KiB); not configurable.
pub const BODY_LIMIT: usize = 262_144;
/// The cap on a record's body, in bytes (128 KiB); not configurable. A larger record is 413
/// `body-too-large`, so that what any key can store at the relay is bounded.
pub const RECORD_LIMIT: usize = 131_072;
/// The most envelope bytes one subscriber batch sends (1 MiB), on top of `max_unacked`; a batch always sends one row.
pub const BATCH_BYTES: usize = 1_048_576;
/// How long one resolution of a `domain:` root may take, in seconds, from the DNS lookup to the last byte.
pub const DEFAULT_WELL_KNOWN_TIMEOUT: u64 = 10;
/// The longest a domain's record is cached, in seconds: a day, the longest an address record lives.
pub const DEFAULT_WELL_KNOWN_CACHE_MAX: u64 = 86_400;
/// The longest `--well-known-timeout` may be, in seconds: a publish waits for the resolution.
pub const MAX_WELL_KNOWN_TIMEOUT: u64 = 60;
/// How long a client may take to send a request head, in seconds.
pub const DEFAULT_HEADER_TIMEOUT: u64 = 10;
/// How long a client may take to send a publish body, in seconds.
pub const DEFAULT_BODY_TIMEOUT: u64 = 30;
/// The most connections one client may hold open at once; behind a trusted proxy, its WebSocket
/// connections. 79: one server's 64 identities (`MAX_IDENTITIES`) hold 64 subscriptions and the edge at most 4
/// connections beside them for its calls (`RELAY_TURNS`), 68 whatever the load; a second process at the address, a
/// server of one and CLI sends, measured 5 more, 73. 74 was the smallest cap clean under load, and 5 is one more such
/// process (e2e scenario 54). A direct client's subscriptions stop at 69, the reserve below.
pub const DEFAULT_CONNECTIONS_PER_IP: usize = 79;

/// The share of a direct client's cap held back from its subscriptions, in thousandths (2026-10-31): each of
/// its calls takes a place too, so a cap full of subscriptions starves the address's own publishes and renewals.
pub const DEFAULT_CONNECTION_RESERVE_PERMILLE: u32 = 125;

/// The fewest places held back whatever the share: the calls of two processes, `RELAY_TURNS` each. Half a smaller cap.
pub const CONNECTION_RESERVE_FLOOR: usize = 8;

/// How the relay resolves the `domain:` roots of accept-from records (src/resolver.rs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WellKnown {
    /// How long one resolution may take.
    pub timeout: Duration,
    /// The longest a domain's record is cached, in seconds; it bounds the 60-second floor too.
    pub cache_max: u64,
    /// Test only (`--well-known-insecure-http`): `http://` in place of `https://`, and hosts whose addresses are not
    /// public. The binary refuses it unless `--bind` is a loopback address.
    pub insecure_http: bool,
    /// Test only (`--well-known-resolve`): hosts resolved to a fixed address, in place of DNS, as curl's
    /// `--resolve`. The binary refuses it unless `--bind` is a loopback address.
    pub resolve: Vec<(Domain, SocketAddr)>,
    /// Test only (`--dns-resolve`): TXT records in place of DNS, each a name and its character-strings. With
    /// it, or any other test-only setting, the relay asks no DNS server: a name it was not given has no TXT record.
    /// The binary refuses it unless `--bind` is a loopback address.
    pub dns_resolve: Vec<(String, Vec<Vec<u8>>)>,
}

impl Default for WellKnown {
    fn default() -> WellKnown {
        WellKnown {
            timeout: Duration::from_secs(DEFAULT_WELL_KNOWN_TIMEOUT),
            cache_max: DEFAULT_WELL_KNOWN_CACHE_MAX,
            insecure_http: false,
            resolve: Vec::new(),
            dns_resolve: Vec::new(),
        }
    }
}

impl WellKnown {
    /// Parses one `--well-known-resolve` value, `<host>=<ip>:<port>` (an IPv6 address in brackets), where the host
    /// is a domain root's host.
    ///
    /// # Errors
    ///
    /// A sentence naming what is wrong.
    pub fn parse_resolve(text: &str) -> Result<(Domain, SocketAddr), String> {
        let bad = |why: &str| format!("{text:?} is not <host>=<ip>:<port>: {why}");
        let (host, at) = text.split_once('=').ok_or_else(|| bad("no ="))?;
        let domain = Domain::parse(host).map_err(|_| bad("the host is not a domain root's host"))?;
        let addr = at.parse::<SocketAddr>().map_err(|_| bad("the address is not <ip>:<port>"))?;
        Ok((domain, addr))
    }

    /// Parses one `--dns-resolve` value, `<name>=<txt>`: a DNS name (labels of 1 to 63 letters, digits, `-` and `_`,
    /// at most 253 characters) and one TXT record in the text form of spec/SPEC.md §12.2 item 7, such as
    /// `_bag.acme.test="v=ac1; key=ed25519:..."`. The name is kept in lower case.
    ///
    /// # Errors
    ///
    /// A sentence naming what is wrong.
    pub fn parse_dns_resolve(text: &str) -> Result<(String, Vec<Vec<u8>>), String> {
        let bad = |why: &str| format!("{text:?} is not <name>=<txt>: {why}");
        let (name, written) = text.split_once('=').ok_or_else(|| bad("no ="))?;
        let label = |l: &str| {
            (1..=63).contains(&l.len())
                && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        };
        if name.len() > 253 || !name.split('.').all(label) {
            return Err(bad("the name is not a DNS name"));
        }
        let strings = ac_core::discovery::parse_presentation(written).map_err(bad)?;
        Ok((name.to_ascii_lowercase(), strings))
    }

    /// Whether a test-only setting is on, which the binary allows on a loopback bind only. With one on, the relay
    /// asks no DNS server for TXT records.
    #[must_use]
    pub fn is_test_only(&self) -> bool {
        self.insecure_http || !self.resolve.is_empty() || !self.dns_resolve.is_empty()
    }
}

/// Fixed-window rate limits, counted in memory (persistent counters are deferred).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimits {
    /// The window length in seconds; windows are aligned to multiples of it.
    pub window: u64,
    /// Publishes per window from one `from` key.
    pub per_from: u32,
    /// Publishes per window under one root.
    pub per_root: u32,
    /// Publishes per window from one client address, counted before any signature is verified.
    pub per_ip: u32,
    /// Fetches, of an envelope or a record, per window from one client address, counted before any signature is
    /// verified.
    pub fetch_per_ip: u32,
    /// Fetches per minute from all client addresses together, counted before any signature is verified; 0 is no
    /// ceiling.
    pub fetch_global_per_minute: u32,
    /// New record signers (keys the relay holds no record of) per UTC day from one client address.
    pub signers_per_day: u32,
    /// Bytes of envelopes stored per UTC day from one client address (src/policy.rs, step 8); 0 is no quota.
    pub bytes_per_day: u64,
    /// Envelopes per UTC day from one sender domain (src/policy.rs, step 8); 0 is no quota. The default is 10,000.
    pub domain_day: u32,
}

impl Default for RateLimits {
    fn default() -> RateLimits {
        RateLimits {
            window: 60,
            per_from: 120,
            per_root: 1_200,
            per_ip: 600,
            fetch_per_ip: 6_000,
            fetch_global_per_minute: 30_000,
            signers_per_day: 100,
            bytes_per_day: 100_000_000,
            domain_day: 10_000,
        }
    }
}

/// Everything the relay needs to know besides its store and its clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The relay TTL in seconds.
    pub ttl: u64,
    /// The clock skew in seconds.
    pub skew: u64,
    /// The envelope cap in bytes.
    pub max_envelope_bytes: usize,
    /// The hard body cap in bytes.
    pub body_limit: usize,
    /// The cap on a record's body in bytes.
    pub record_limit: usize,
    /// The rate limits.
    pub rate: RateLimits,
    /// The most envelopes sent to a subscriber and not yet acknowledged.
    pub max_unacked: usize,
    /// The most envelope bytes one batch to a subscriber sends, past its first row ([`BATCH_BYTES`]).
    pub batch_bytes: usize,
    /// How often a subscriber is pinged.
    pub ping_interval: Duration,
    /// How long a subscriber may stay silent before it is closed (and how long the relay waits for its auth).
    pub idle_timeout: Duration,
    /// How often expired mailbox rows and orphaned envelopes are swept.
    pub sweep_interval: Duration,
    /// How long a client may take to send a request head (and, on a new connection, its first bytes).
    pub header_timeout: Duration,
    /// How long a client may take to send a publish body.
    pub body_timeout: Duration,
    /// The most connections one client address may hold open at once.
    pub connections_per_ip: usize,
    /// The share of that cap a direct client's subscriptions may not take, in thousandths; 0 holds none back.
    pub connection_reserve_permille: u32,
    /// How `domain:` roots are resolved.
    pub well_known: WellKnown,
    /// The trusted proxies and the log mode of client addresses.
    pub front: Front,
    /// The URL the relay announces and health answers; `None` until the binary has its port. It is the first public
    /// base URL a fetch proof's `audience` may name (spec/SPEC.md §8.3).
    pub url: Option<String>,
    /// The other public base URLs a fetch proof's `audience` may name (`--accept-base`): a relay's second name while it
    /// moves, where a client signs the name it used. None by default.
    pub accept_bases: Vec<String>,
    /// The operator's blocklist file (src/abuse.rs); none blocks nothing.
    pub blocklist: Option<std::path::PathBuf>,
    /// Where abuse is reported (`/v0/abuse`); none answers 404.
    pub abuse_contact: Option<String>,
    /// The store's live bytes ([`crate::store::Size::live`]) from which an envelope, or a record of a signer the store
    /// holds none of, is refused 503 `store-full` (src/policy.rs); 0 is no bound.
    pub max_store_bytes: u64,
    /// Litestream's metrics URL on this host, whose `litestream_*` lines each scrape of `/metrics` passes on
    /// (src/metrics.rs); none reads nothing.
    pub metrics_litestream: Option<String>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            ttl: DEFAULT_TTL,
            skew: DEFAULT_SKEW,
            max_envelope_bytes: DEFAULT_MAX_ENVELOPE_BYTES,
            body_limit: BODY_LIMIT,
            record_limit: RECORD_LIMIT,
            rate: RateLimits::default(),
            max_unacked: 32,
            batch_bytes: BATCH_BYTES,
            ping_interval: Duration::from_secs(30),
            idle_timeout: Duration::from_mins(1),
            sweep_interval: Duration::from_mins(1),
            header_timeout: Duration::from_secs(DEFAULT_HEADER_TIMEOUT),
            body_timeout: Duration::from_secs(DEFAULT_BODY_TIMEOUT),
            connections_per_ip: DEFAULT_CONNECTIONS_PER_IP,
            connection_reserve_permille: DEFAULT_CONNECTION_RESERVE_PERMILLE,
            well_known: WellKnown::default(),
            front: Front::default(),
            url: None,
            accept_bases: Vec::new(),
            blocklist: None,
            abuse_contact: None,
            max_store_bytes: 0,
            metrics_litestream: None,
        }
    }
}

impl Config {
    /// The most subscriptions one direct client may hold: the cap less `max(floor, round(share × cap))`, the floor never
    /// more than half the cap, and always one. Behind a trusted proxy calls are not counted, and the cap is the limit.
    #[must_use]
    pub fn subscriptions_per_ip(&self) -> usize {
        let (cap, share) = (self.connections_per_ip, self.connection_reserve_permille as usize);
        if share == 0 {
            return cap;
        }
        let reserve =
            (cap.saturating_mul(share).saturating_add(500) / 1000).max(CONNECTION_RESERVE_FLOOR.min(cap / 2));
        cap.saturating_sub(reserve).max(1)
    }

    /// The public base URLs a fetch proof's `audience` may name: `url`, then each of `accept_bases`. Each is compared
    /// byte for byte, and never with a `Host` or forwarded header, which a caller writes; a relay with none accepts no
    /// fetch proof.
    pub fn audiences(&self) -> impl Iterator<Item = &str> {
        self.url.iter().chain(&self.accept_bases).map(String::as_str)
    }

    /// Checks that the settings make sense together.
    ///
    /// # Errors
    ///
    /// A sentence naming the setting that does not.
    pub fn validate(&self) -> Result<(), String> {
        if self.ttl == 0 {
            return Err("--ttl must be at least 1 second".into());
        }
        if self.max_envelope_bytes == 0 || self.max_envelope_bytes > self.body_limit {
            return Err(format!("--max-envelope-bytes must be from 1 to the body cap, {}", self.body_limit));
        }
        if self.record_limit == 0 || self.record_limit > self.body_limit {
            return Err(format!("the record cap must be from 1 to the body cap, {}", self.body_limit));
        }
        if self.rate.window == 0 || self.max_unacked == 0 {
            return Err("the rate window and the unacknowledged window must be at least 1".into());
        }
        if self.header_timeout.is_zero() || self.body_timeout.is_zero() || self.connections_per_ip == 0 {
            return Err("--header-timeout, --body-timeout and --connections-per-ip must be at least 1".into());
        }
        if self.connection_reserve_permille >= 1000 {
            return Err("--connection-reserve-permille must be under 1000".into());
        }
        // A pong renews the idle deadline, and the next ping goes out one interval later: an idle timeout of at
        // least two intervals leaves a responsive subscriber a full interval to answer.
        if self.ping_interval.is_zero() || self.idle_timeout < self.ping_interval.saturating_mul(2) {
            return Err(
                "--idle-timeout must be at least twice --ping-interval, which must be at least 1".into()
            );
        }
        let timeout = self.well_known.timeout;
        if timeout < Duration::from_secs(1) || timeout > Duration::from_secs(MAX_WELL_KNOWN_TIMEOUT) {
            return Err(format!("--well-known-timeout must be from 1 to {MAX_WELL_KNOWN_TIMEOUT} seconds"));
        }
        if !(1..=DEFAULT_WELL_KNOWN_CACHE_MAX).contains(&self.well_known.cache_max) {
            return Err(format!(
                "--well-known-cache-max must be from 1 to {DEFAULT_WELL_KNOWN_CACHE_MAX} seconds"
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
