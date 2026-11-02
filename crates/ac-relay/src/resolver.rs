//! The resolution of `domain:` roots (spec/SPEC.md §8.2 step 7), as the edge resolves an
//! org's root (§9 item 4): the address record at `https://<host>/.well-known/bag/address.json`, over HTTPS
//! only, following no redirect, within a time cap and the edge's 262,144-byte cap, after a guard that
//! refuses a host any of whose addresses is not public ([`ac_core::net`]); verified with [`ac_core`] (form,
//! signature, kind, validity at the relay's clock and skew); cached until `iat + ttl`, for 60 s at least and the
//! relay's ceiling at most; pinned per
//! domain in the store (`domain_pins`), a changed key accepted only through a rotation countersigned by the pinned key
//! or its rotation key (§7.3), `pin-mismatch` in the log otherwise. A failure is remembered for 60 s, so a burst
//! cannot make the relay hammer a host; meanwhile the pinned key stays the domain's current key while its stored
//! record is valid, so a bad record at the well-known path cannot take it out of service, and a
//! domain with no valid pinned record grants nothing: step 7 then fails closed with 503 `resolve-failed` (Amendment 1).
//! The relay evaluates no caveat; it asks only whether the chain's root is the current key of a domain the mailbox
//! owner named, and reads that record's `revoked` list. A root that is not a domain's cached key
//! refreshes its record, once a minute at most, so that a countersigned rotation is followed at once.
//!
//! The network half is [`WellKnownFetch`], so that tests put a fake in its place. [`HttpsFetcher`] is the real one:
//! blocking ureq on tokio's blocking pool, so no request handler blocks a runtime thread. It connects only to the
//! addresses the guard passed (its resolver hands ureq exactly those), so a DNS answer cannot change in between.
//!
//! Since 2026-10-26 (spec/SPEC.md §12.2, L2, §8.8 item 1) a resolution first looks up
//! the TXT records of `_bag.<host>` ([`crate::dns`]): with a bag record, the org's record is read at
//! the origin it names, `https://bag.<host>` for `host=bag`, else `https://<host>`, at the well-known
//! path (no URL is read from DNS), and must agree with the key it names, by that key or by one rotation the key
//! countersigned (`txt-key-mismatch` otherwise, before any pin is read); with none, or for a host no TXT is
//! asked for, the well-known URL as before; two, a malformed one or a failed lookup fail the resolution. DNS is a hint
//! and the signature is the authority: the TXT never moves a pin, which moves only by §7.3. The lookup and the fetch
//! share the timeout.

use crate::config::WellKnown;
use crate::dns::{FixedTxt, TxtLookup, UdpTxt};
use crate::metrics::{METRICS, RESOLUTIONS, STORE_CORRUPT};
use crate::relay::{Rejection, Relay};
use crate::store::DomainPin;
use ac_core::discovery::{self, Discovery, RecordUrl, Refusal};
use ac_core::net::{self, Category};
use ac_core::records::{self, AddressRecord, Domain, Record};
use ac_core::{Address, Code};
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs as _};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

/// The path of an org's address record at its domain.
pub const WELL_KNOWN_PATH: &str = "/.well-known/bag/address.json";
/// The largest well-known answer read, in bytes: the edge's cap (SPEC.md Appendix B 41 and 49).
pub const MAX_WELL_KNOWN_BYTES: u64 = 262_144;
/// The shortest a resolved record is cached, in seconds, unless the relay's ceiling is shorter.
pub const CACHE_FLOOR: u64 = 60;
/// How long a failed resolution is remembered, in seconds.
pub const FAILURE_TTL: u64 = 60;
/// The `Retry-After` of a 503 `resolve-failed`, in seconds: the failure's memory.
pub const RETRY_AFTER: u64 = FAILURE_TTL;
/// The fewest seconds between two refreshes of a domain whose cached key is not a chain's root.
pub const REFRESH_EVERY: u64 = 60;
/// The most domains one publish may send to the network (since 2026-10-26): first contacts, expired caches and
/// refreshes alike. An accept-from record names up to 1,024 domains, and one publish once fetched them all;
/// past this, a domain counts from the cache alone, as in a publish with no network, and a later try reads the next.
pub const MAX_FETCHES_PER_PUBLISH: usize = 8;

/// The most domains one pass over the pending rows reads from the network, each row at most
/// [`MAX_FETCHES_PER_PUBLISH`] of them (LD-1): past it the rows count from the cache alone until the next pass.
pub const MAX_FETCHES_PER_RETRY: usize = 64;

/// Why a domain did not resolve. [`Failure::reason`] is the word the log names it by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The DNS lookup failed.
    Dns(String),
    /// The lookup gave no address.
    NoAddress,
    /// An address of the host is not public: the guard refused the host, and nothing was connected to.
    NonPublic {
        /// The first address that is not public.
        address: IpAddr,
        /// Its category.
        category: Category,
    },
    /// The resolution took longer than the timeout.
    Timeout,
    /// The connection, TLS or HTTP failed.
    Fetch(String),
    /// The answer's status was not 200; a redirect is one of these, since none is followed.
    Status(u16),
    /// The body was over [`MAX_WELL_KNOWN_BYTES`].
    TooLarge,
    /// The bytes are not a valid record at the relay's clock: `bad-json`, `bad-record`, `bad-record-sig`,
    /// `future-iat`, `record-expired` or a cap's code.
    Record(Code),
    /// A valid record of another kind than address.
    NotAddress,
    /// A record of another key than the pinned one that is not a valid rotation of the pinned record.
    PinMismatch {
        /// The pinned key, kept.
        pinned: String,
        /// The key of the record that was refused.
        offered: String,
        /// Why the rotation does not hold: `bad-rotation`.
        check: Code,
    },
    /// Not resolved: the cache, the only thing [`Relay::publish`] asks, holds nothing for the domain.
    NotCached,
    /// The TXT lookup of `_bag.<host>` failed: no answer, a server failure, an unreadable answer.
    TxtLookup(String),
    /// The domain's bag TXT record is malformed (§12.2 items 1 to 3): what is wrong.
    TxtMalformed(&'static str),
    /// The domain has this many bag TXT records, more than one.
    TxtAmbiguous(usize),
    /// The record agrees with the key the TXT names neither by that key nor by one rotation it countersigned (§12.2
    /// item 5).
    TxtKeyMismatch {
        /// The key the TXT names.
        txt: String,
        /// The key of the record that was refused.
        offered: String,
    },
}

impl Failure {
    /// The reason the log names: `dns-failed`, `no-address`, `non-public-address`, `timeout`, `fetch-failed`,
    /// `http-status`, `too-large`, the record's code, `not-an-address-record`, `pin-mismatch` or `not-cached`; since
    /// 2026-10-26 `txt-lookup-failed`, `txt-malformed`, `txt-ambiguous` or `txt-key-mismatch`.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Failure::Dns(_) => "dns-failed",
            Failure::NoAddress => "no-address",
            Failure::NonPublic { .. } => "non-public-address",
            Failure::Timeout => "timeout",
            Failure::Fetch(_) => "fetch-failed",
            Failure::Status(_) => "http-status",
            Failure::TooLarge => "too-large",
            Failure::Record(code) => code.as_str(),
            Failure::NotAddress => "not-an-address-record",
            Failure::PinMismatch { .. } => "pin-mismatch",
            Failure::NotCached => "not-cached",
            Failure::TxtLookup(_) => "txt-lookup-failed",
            Failure::TxtMalformed(_) => "txt-malformed",
            Failure::TxtAmbiguous(_) => "txt-ambiguous",
            Failure::TxtKeyMismatch { .. } => "txt-key-mismatch",
        }
    }
}

/// What a domain grants at the moment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Grant {
    /// The domain's current key and its record's revoked list.
    Key {
        /// The pinned key, whose record is fresh.
        key: Address,
        /// The record's `revoked` list.
        revoked: Vec<Address>,
    },
    /// Nothing: the domain did not resolve.
    Unresolved(Failure),
}

/// What a fetch gives: the answer's bytes, or why there are none.
pub type FetchResult = Result<Vec<u8>, Failure>;

/// A fetch in progress.
pub type Fetching<'a> = Pin<Box<dyn Future<Output = FetchResult> + Send + 'a>>;

/// The network half of resolution: the bytes at an org record's URL (the well-known URL at the org's origin, the domain
/// or, since 2026-10-26, `bag.<domain>`), under the guard and the caps.
pub trait WellKnownFetch: Send + Sync {
    /// Fetches the record at `url`.
    fn fetch<'a>(&'a self, url: &'a RecordUrl) -> Fetching<'a>;
}

/// A host lookup: the socket addresses of a host at a port.
pub type Lookup = fn(&str, u16) -> std::io::Result<Vec<SocketAddr>>;

/// The system's lookup (getaddrinfo, through std), which [`HttpsFetcher`] runs on a blocking thread.
///
/// # Errors
///
/// The lookup's.
pub fn system_lookup(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    Ok((host, port).to_socket_addrs()?.collect())
}

/// The real fetch: `https://<host><path>` (the well-known path at the org's origin) with ureq (rustls, the webpki
/// roots), no redirect, no proxy, `accept: application/json`, the timeout over the whole fetch, at most
/// [`MAX_WELL_KNOWN_BYTES`] read, and connections only to addresses the guard passed.
#[derive(Debug, Clone)]
pub struct HttpsFetcher {
    timeout: Duration,
    /// `http://` in place of `https://` (the test-only `--well-known-insecure-http`).
    http: bool,
    /// No guard (the same test-only flag): hosts whose addresses are not public are fetched too.
    any_address: bool,
    /// Fixed addresses of hosts (the test-only `--well-known-resolve`).
    resolve: Vec<(Domain, SocketAddr)>,
    lookup: Lookup,
}

impl HttpsFetcher {
    /// The fetcher of these settings, on the system's lookup.
    #[must_use]
    pub fn new(settings: &WellKnown) -> HttpsFetcher {
        HttpsFetcher {
            timeout: settings.timeout,
            http: settings.insecure_http,
            any_address: settings.insecure_http,
            resolve: settings.resolve.clone(),
            lookup: system_lookup,
        }
    }

    /// The whole fetch, blocking: the addresses, the guard, then one GET.
    fn fetch_blocking(&self, url: &RecordUrl) -> FetchResult {
        let host = url.host().as_str();
        let (scheme, port) = if self.http { ("http", 80) } else { ("https", 443) };
        let addrs = match self.resolve.iter().find(|(d, _)| d == url.host()) {
            Some((_, addr)) => vec![*addr],
            None => (self.lookup)(host, port).map_err(|e| Failure::Dns(e.to_string()))?,
        };
        if addrs.is_empty() {
            return Err(Failure::NoAddress);
        }
        if !self.any_address {
            let ips: Vec<IpAddr> = addrs.iter().map(SocketAddr::ip).collect();
            if let Some((address, category)) = net::first_non_public(&ips) {
                return Err(Failure::NonPublic { address, category });
            }
        }
        let config = ureq::Agent::config_builder()
            .https_only(!self.http)
            .http_status_as_error(false)
            .max_redirects(0)
            .proxy(None)
            .timeout_global(Some(self.timeout))
            .user_agent(concat!("ac-relay/", env!("CARGO_PKG_VERSION")))
            .accept("application/json")
            .build();
        let connector = ureq::unversioned::transport::DefaultConnector::new();
        let agent = ureq::Agent::with_parts(config, connector, Fixed(addrs));
        let mut answer = agent.get(format!("{scheme}://{host}{}", url.path())).call().map_err(failed)?;
        let status = answer.status().as_u16();
        if status != 200 {
            return Err(Failure::Status(status));
        }
        // ureq refuses a body that reaches its limit, so the limit is one byte over the cap.
        answer.body_mut().with_config().limit(MAX_WELL_KNOWN_BYTES + 1).read_to_vec().map_err(failed)
    }
}

impl WellKnownFetch for HttpsFetcher {
    fn fetch<'a>(&'a self, url: &'a RecordUrl) -> Fetching<'a> {
        let job = self.clone();
        let url = url.clone();
        Box::pin(async move {
            let timeout = job.timeout;
            let blocking = tokio::task::spawn_blocking(move || job.fetch_blocking(&url));
            match tokio::time::timeout(timeout, blocking).await {
                Ok(Ok(result)) => result,
                Ok(Err(join)) => Err(Failure::Fetch(join.to_string())),
                Err(_) => Err(Failure::Timeout),
            }
        })
    }
}

fn failed(e: ureq::Error) -> Failure {
    match e {
        ureq::Error::Timeout(_) => Failure::Timeout,
        ureq::Error::BodyExceedsLimit(_) => Failure::TooLarge,
        other => Failure::Fetch(other.to_string()),
    }
}

/// The resolver ureq gets: the addresses the guard passed, nothing looked up again.
#[derive(Debug)]
struct Fixed(Vec<SocketAddr>);

impl ureq::unversioned::resolver::Resolver for Fixed {
    fn resolve(
        &self,
        _uri: &ureq::http::Uri,
        _config: &ureq::config::Config,
        _timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        let mut out = self.empty();
        for addr in self.0.iter().take(16) {
            out.push(*addr);
        }
        Ok(out)
    }
}

/// The TXT lookup of these settings: the `--dns-resolve` table when any test-only setting is on, so that no
/// test asks a DNS server, else the stub resolver on the system's nameservers.
#[must_use]
pub fn txt_lookup(settings: &WellKnown) -> Arc<dyn TxtLookup> {
    if settings.is_test_only() {
        Arc::new(FixedTxt(settings.dns_resolve.clone()))
    } else {
        Arc::new(UdpTxt::system())
    }
}

/// The relay's state for domains besides their pins: the fetcher, the TXT lookup, the failures it remembers, and one
/// lock per domain being resolved, so concurrent publishes resolve a domain once.
pub struct Domains {
    fetcher: Arc<dyn WellKnownFetch>,
    txt: Arc<dyn TxtLookup>,
    failures: Mutex<HashMap<String, (u64, Failure)>>,
    flights: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    recent: Mutex<HashMap<String, u64>>,
}

impl Domains {
    /// No failure remembered and nothing in flight.
    #[must_use]
    pub fn new(fetcher: Arc<dyn WellKnownFetch>, txt: Arc<dyn TxtLookup>) -> Domains {
        Domains {
            fetcher,
            txt,
            failures: Mutex::default(),
            flights: Mutex::default(),
            recent: Mutex::default(),
        }
    }

    pub(crate) fn set_txt(&mut self, txt: Arc<dyn TxtLookup>) {
        self.txt = txt;
    }

    pub(crate) fn txt_source(&self) -> &'static str {
        self.txt.source()
    }

    /// Whether `domain`, whose cached key is not a chain's root, may be fetched now: not while a failure of it
    /// is remembered (§8.8 item 6), and once in [`REFRESH_EVERY`] seconds of the relay's clock, a yes counting as one.
    fn refresh_due(&self, domain: &Domain, now: u64) -> bool {
        let failed = self.failures().get(domain.as_str()).is_some_and(|(until, _)| *until > now);
        let mut recent = self.recent.lock().unwrap_or_else(PoisonError::into_inner);
        recent.retain(|_, at| now < at.saturating_add(REFRESH_EVERY));
        if failed || recent.contains_key(domain.as_str()) {
            return false;
        }
        recent.insert(domain.as_str().to_owned(), now);
        true
    }

    fn failures(&self) -> MutexGuard<'_, HashMap<String, (u64, Failure)>> {
        // Every update completes under the lock or not at all.
        self.failures.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn flight(&self, domain: &Domain) -> Arc<tokio::sync::Mutex<()>> {
        let mut flights = self.flights.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(flights.entry(domain.as_str().to_owned()).or_default())
    }

    fn land(&self, domain: &Domain) {
        let mut flights = self.flights.lock().unwrap_or_else(PoisonError::into_inner);
        if flights.get(domain.as_str()).is_some_and(|f| Arc::strong_count(f) == 1) {
            flights.remove(domain.as_str());
        }
    }

    fn remember(&self, domain: &Domain, until: u64, failure: &Failure) {
        let mut failures = self.failures();
        failures.retain(|_, (u, _)| *u > until.saturating_sub(FAILURE_TTL));
        failures.insert(domain.as_str().to_owned(), (until, failure.clone()));
    }
}

/// What a fetched record does to a domain's pin.
enum Pinned {
    /// First contact: the key is pinned.
    New,
    /// The pinned key's record, read again.
    Same,
    /// A countersigned rotation from the pinned key.
    Rotated(String),
}

impl Relay {
    /// What `domain` grants from the cache alone, with no network call: the pinned key while its record is fresh;
    /// after a remembered failure, the pinned key while its record is still valid (`iat + ttl`), else the failure;
    /// otherwise `None`, which a resolution answers.
    ///
    /// # Errors
    ///
    /// A [`Rejection`] (500) for a store failure or a pin whose record does not parse.
    pub fn cached_grant(&self, domain: &Domain) -> Result<Option<Grant>, Rejection> {
        let now = self.now();
        let pin = self.store.domain_pin(domain.as_str())?;
        if let Some(pin) = &pin
            && pin.expires_at > now
        {
            return Ok(Some(granted(pinned_record(pin)?)));
        }
        let failed = self.domains.failures().get(domain.as_str()).filter(|(until, _)| *until > now).cloned();
        match failed {
            Some((_, failure)) => Ok(Some(match kept(pin.as_ref(), now)? {
                Some(record) => granted(record),
                None => Grant::Unresolved(failure),
            })),
            None => Ok(None),
        }
    }

    /// What `domain` grants: [`Relay::cached_grant`], else one resolution, at most one at a time per domain.
    ///
    /// # Errors
    ///
    /// A [`Rejection`] (500) for a store failure or a pin whose record does not parse.
    pub async fn resolve_grant(&self, domain: &Domain) -> Result<Grant, Rejection> {
        match self.cached_grant(domain)? {
            Some(grant) => Ok(grant),
            None => self.fetch_grant(domain, true).await,
        }
    }

    /// What `domain` grants a chain rooted at `root`: [`Relay::resolve_grant`], but a cached key other than `root` is
    /// fetched again when [`Domains::refresh_due`] allows, so a countersigned rotation to `root` admits it now.
    pub(crate) async fn grant_for(&self, domain: &Domain, root: &Address) -> Result<Grant, Rejection> {
        let cached = self.cached_grant(domain)?;
        let other = matches!(&cached, Some(Grant::Key { key, .. }) if key != root);
        match cached {
            Some(grant) if !other => Ok(grant),
            _ => self.fetch_grant(domain, !(other && self.domains.refresh_due(domain, self.now()))).await,
        }
    }

    /// One resolution of `domain` at a time: after any in flight, the cache's answer when `cached`, else a fetch.
    async fn fetch_grant(&self, domain: &Domain, cached: bool) -> Result<Grant, Rejection> {
        let flight = self.domains.flight(domain);
        let grant = {
            let _resolving = flight.lock().await;
            match if cached { self.cached_grant(domain)? } else { None } {
                Some(grant) => grant,
                None => self.resolve_now(domain).await?,
            }
        };
        drop(flight);
        self.domains.land(domain);
        Ok(grant)
    }

    async fn resolve_now(&self, domain: &Domain) -> Result<Grant, Rejection> {
        let timeout = self.config.well_known.timeout;
        let found = tokio::time::timeout(timeout, self.discover_and_fetch(domain))
            .await
            .unwrap_or(Err(Failure::Timeout));
        let outcome = match found {
            Ok((discovery, bytes)) => self.take_record(domain, &discovery, &bytes)?,
            Err(failure) => Err(failure),
        };
        match outcome {
            Ok(grant) => {
                self.domains.failures().remove(domain.as_str());
                Ok(grant)
            }
            Err(failure) => {
                let now = self.now();
                self.domains.remember(domain, now.saturating_add(FAILURE_TTL), &failure);
                let pin = self.store.domain_pin(domain.as_str())?;
                let kept = kept(pin.as_ref(), now)?;
                log_failure(domain, &failure, kept.as_ref());
                Ok(match kept {
                    Some(record) => granted(record),
                    None => Grant::Unresolved(failure),
                })
            }
        }
    }

    /// Where `domain`'s record is (§12.2): one TXT lookup of `_bag.<domain>`, logged with its source, then the
    /// record's bytes from the URL it leads to. A domain no TXT is asked for (§12.2 item 4) reads the well-known URL.
    async fn discover_and_fetch(&self, domain: &Domain) -> Result<(Discovery, Vec<u8>), Failure> {
        let found = match discovery::txt_name(domain) {
            None => Discovery::well_known(domain),
            Some(name) => {
                let txt = &self.domains.txt;
                let looked = txt.lookup(&name).await;
                tracing::info!(event = "txt", domain = %domain, name = %name, source = txt.source(),
                    ok = looked.is_ok(), records = looked.as_ref().map_or(0, Vec::len));
                discovery::discover(&looked.map_err(Failure::TxtLookup)?, domain).map_err(|refusal| {
                    match refusal {
                        Refusal::Malformed(why) => Failure::TxtMalformed(why),
                        Refusal::Ambiguous(n) => Failure::TxtAmbiguous(n),
                    }
                })?
            }
        };
        let bytes = self.domains.fetcher.fetch(&found.url).await?;
        Ok((found, bytes))
    }

    /// Verifies a fetched record and moves the domain's pin by it: first contact pins its key, the pinned
    /// key's record refreshes the pin, another key is taken only through `verify_rotation`. A record that does not
    /// agree with its TXT's key (§12.2 item 5: that key, or one rotation it countersigned) is refused before the pin is
    /// read. The grant and the cache's expiry come from the newest valid record of the key the relay now holds, whichever
    /// this fetch returned, so that a stale copy from the host rolls back no revoked list.
    fn take_record(
        &self,
        domain: &Domain,
        found: &Discovery,
        bytes: &[u8],
    ) -> Result<Result<Grant, Failure>, Rejection> {
        let now = self.now();
        let record = match Record::parse(bytes) {
            Ok(r) => r,
            Err(code) => return Ok(Err(Failure::Record(code))),
        };
        if let Err(code) = record.verify(now, self.config.skew) {
            return Ok(Err(Failure::Record(code)));
        }
        let Record::Address(next) = record else { return Ok(Err(Failure::NotAddress)) };
        if found.check(&next).is_err() {
            let txt = found.key.as_ref().map(ToString::to_string).unwrap_or_default();
            return Ok(Err(Failure::TxtKeyMismatch { txt, offered: next.key.to_string() }));
        }
        let pin = self.store.domain_pin(domain.as_str())?;
        let (how, kept, pinned_at, current) = match &pin {
            None => (Pinned::New, bytes.to_vec(), now, next),
            Some(p) if p.key == next.key.as_str() => {
                let pinned = pinned_record(p)?;
                if next.iat >= pinned.iat || now > pinned.iat.saturating_add(pinned.ttl) {
                    (Pinned::Same, bytes.to_vec(), p.pinned_at, next)
                } else {
                    (Pinned::Same, p.record.clone(), p.pinned_at, pinned)
                }
            }
            Some(p) => match records::verify_rotation(&pinned_record(p)?, &next) {
                Ok(()) => (Pinned::Rotated(p.key.clone()), bytes.to_vec(), now, next),
                Err(check) => {
                    let (pinned, offered) = (p.key.clone(), next.key.to_string());
                    return Ok(Err(Failure::PinMismatch { pinned, offered, check }));
                }
            },
        };
        let floor = now.saturating_add(CACHE_FLOOR);
        let ceiling = now.saturating_add(self.config.well_known.cache_max);
        let expires_at = current.iat.saturating_add(current.ttl).max(floor).min(ceiling);
        let key = current.key.to_string();
        let (source, url) = (if found.key.is_some() { "txt" } else { "well-known" }, found.url.to_string());
        self.store.put_domain_pin(&DomainPin {
            domain: domain.as_str().to_owned(),
            key: key.clone(),
            record: kept,
            pinned_at,
            expires_at,
        })?;
        match how {
            Pinned::New => {
                METRICS.count(RESOLUTIONS, "outcome", "pinned");
                tracing::info!(event = "well-known", domain = %domain, outcome = "pinned", key = %key, expires_at,
                    source, url = %url);
            }
            Pinned::Same => {
                METRICS.count(RESOLUTIONS, "outcome", "refreshed");
                tracing::info!(event = "well-known", domain = %domain, outcome = "refreshed", key = %key, expires_at,
                    source, url = %url);
            }
            Pinned::Rotated(from) => {
                METRICS.count(RESOLUTIONS, "outcome", "rotated");
                tracing::info!(event = "well-known", domain = %domain, outcome = "rotated", from = %from, key = %key,
                    expires_at, source, url = %url);
            }
        }
        Ok(Ok(granted(current)))
    }
}

/// What a domain grants through a record: its key, and its revoked list.
fn granted(record: AddressRecord) -> Grant {
    Grant::Key { key: record.key, revoked: record.revoked }
}

/// The pinned record while it is valid (`now <= iat + ttl`): the domain's current key when a resolution fails, a pin
/// mismatch included, so that a bad record at the well-known path cannot take the pinned key out of service (SPEC.md
/// Appendix B 55).
fn kept(pin: Option<&DomainPin>, now: u64) -> Result<Option<AddressRecord>, Rejection> {
    let Some(pin) = pin else { return Ok(None) };
    let record = pinned_record(pin)?;
    Ok((now <= record.iat.saturating_add(record.ttl)).then_some(record))
}

/// The address record a pin holds. The relay wrote it after verifying it, so anything else is a corrupt store.
fn pinned_record(pin: &DomainPin) -> Result<AddressRecord, Rejection> {
    match Record::parse(&pin.record) {
        Ok(Record::Address(a)) if a.key.as_str() == pin.key => Ok(a),
        _ => {
            tracing::error!(event = "store-corrupt", domain = %pin.domain, kind = "domain-pin");
            METRICS.tick(STORE_CORRUPT);
            Err(Rejection::internal())
        }
    }
}

/// One line per failed resolution ("one log line per resolve"): the reason, the
/// fields of its kind, and, when the pinned key stays current, that key and until when.
fn log_failure(domain: &Domain, failure: &Failure, kept: Option<&AddressRecord>) {
    let (mut address, mut category, mut pinned, mut offered, mut check, mut detail, mut status) =
        (None, None, None, None, None, None, None);
    let (mut txt, mut records) = (None, None);
    match failure {
        Failure::NonPublic { address: a, category: c } => {
            (address, category) = (Some(a.to_string()), Some(c.as_str()));
        }
        Failure::PinMismatch { pinned: p, offered: o, check: c } => {
            (pinned, offered, check) = (Some(p.as_str()), Some(o.as_str()), Some(c.as_str()));
        }
        Failure::Dns(d) | Failure::Fetch(d) | Failure::TxtLookup(d) => detail = Some(d.as_str()),
        Failure::TxtMalformed(why) => detail = Some(*why),
        Failure::TxtAmbiguous(n) => records = Some(*n),
        Failure::TxtKeyMismatch { txt: t, offered: o } => {
            (txt, offered) = (Some(t.as_str()), Some(o.as_str()));
        }
        Failure::Status(s) => status = Some(*s),
        _ => {}
    }
    let kept_key = kept.map(|r| r.key.to_string());
    let valid_until = kept.map(|r| r.iat.saturating_add(r.ttl));
    METRICS.count(RESOLUTIONS, "outcome", failure.reason());
    tracing::warn!(event = "well-known-refused", domain = %domain, reason = failure.reason(),
        address = address.as_deref(), category, pinned, offered, check, detail, status, txt, records,
        kept = kept_key.as_deref(), valid_until);
}

#[cfg(test)]
pub(crate) mod testkit;
#[cfg(test)]
mod tests;
