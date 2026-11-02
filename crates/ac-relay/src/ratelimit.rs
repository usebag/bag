//! Fixed windows, in memory: publishes per client address, per `from` key and per root in
//! windows of `RateLimits::window` seconds (60 by default), and the new record signers of each client address per UTC
//! day.
//!
//! Windows are aligned to multiples of their length, so every counter resets at the same instant and a refused
//! publish learns exactly how long to wait (`Retry-After`). The order is spec/SPEC.md §8.2's:
//! the client address is checked and charged first, by [`RateLimiter::check_address`], before any signature is
//! verified and whatever the publish's outcome, so that the signature work of one address is bounded; the `from` and
//! root counters are checked together after dedup, and charged only by a publish that passes both, by
//! [`RateLimiter::check_sender`], so that a duplicate counts against its client address only. Counters live in
//! memory only and start empty when the relay starts; a client counts by [`crate::net::rate_bucket`]. The
//! sender domain's daily quota is checked and charged with the `from` and root counters. A client's fetches
//! have a window of their own, [`RateLimiter::check_fetch`], checked and charged before a fetch's signature is verified,
//! and the relay has a ceiling on all fetches in a minute behind it, against a flood from many addresses.
//! The bytes a client may store in a UTC day are charged with an envelope's `from` and root, by
//! [`RateLimiter::check_envelope`], so that one address cannot fill the store that every mailbox shares.

use crate::config::RateLimits;
use crate::net::rate_bucket;
use std::collections::HashMap;
use std::net::IpAddr;

/// One UTC day, the window of the record signers' quota.
pub const DAY: u64 = 86_400;

/// One minute, the window of the relay-wide fetch ceiling, whatever `--rate-window` says.
pub const MINUTE: u64 = 60;

/// Which limit refused a publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// The `from` key's.
    From,
    /// The root's.
    Root,
    /// The client address's.
    Ip,
    /// The client address's fetches.
    Fetch,
    /// The relay's ceiling on all fetches in a minute.
    FetchGlobal,
    /// The client address's daily quota of new record signers.
    RecordSigners,
    /// The client address's daily quota of stored bytes.
    Bytes,
    /// The sender domain's daily quota.
    Domain,
    /// An open nameplate's pairing requests (src/pair.rs).
    Pairing,
}

impl Limit {
    /// A short name for logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Limit::From => "from",
            Limit::Root => "root",
            Limit::Ip => "ip",
            Limit::Fetch => "fetch",
            Limit::FetchGlobal => "fetch-global",
            Limit::RecordSigners => "record-signers",
            Limit::Bytes => "bytes",
            Limit::Domain => "domain",
            Limit::Pairing => "pairing",
        }
    }
}

/// A refusal: which limit, and the seconds until its window ends (at least 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused {
    /// The limit that was used up.
    pub limit: Limit,
    /// Seconds until the window ends.
    pub retry_after: u64,
}

/// The counters of the current windows.
#[derive(Debug)]
pub struct RateLimiter {
    limits: RateLimits,
    window: u64,
    from: HashMap<String, u32>,
    root: HashMap<String, u32>,
    ip: HashMap<IpAddr, u32>,
    fetches: HashMap<IpAddr, u32>,
    minute: u64,
    all_fetches: u32,
    day: u64,
    signers: HashMap<IpAddr, u32>,
    bytes: HashMap<IpAddr, u64>,
    domains: HashMap<String, u32>,
}

impl RateLimiter {
    /// Empty counters for `limits`.
    #[must_use]
    pub fn new(limits: RateLimits) -> RateLimiter {
        RateLimiter {
            limits,
            window: 0,
            from: HashMap::new(),
            root: HashMap::new(),
            ip: HashMap::new(),
            fetches: HashMap::new(),
            minute: 0,
            all_fetches: 0,
            day: 0,
            signers: HashMap::new(),
            bytes: HashMap::new(),
            domains: HashMap::new(),
        }
    }

    /// Starts a new window when `now` is past the current one; the seconds left in it.
    fn roll(&mut self, now: u64) -> u64 {
        let window = now / self.limits.window;
        if window != self.window {
            self.window = window;
            self.from.clear();
            self.root.clear();
            self.ip.clear();
            self.fetches.clear();
        }
        self.limits.window - now % self.limits.window
    }

    /// Starts a new UTC day when `now` is past the current one; the seconds to the next 00:00 UTC.
    fn roll_day(&mut self, now: u64) -> u64 {
        if now / DAY != self.day {
            self.day = now / DAY;
            self.signers.clear();
            self.bytes.clear();
            self.domains.clear();
        }
        DAY - now % DAY
    }

    /// Counts one publish against the client address `ip`, or refuses it when the address has used its allowance in
    /// this window (and then counts nothing).
    ///
    /// # Errors
    ///
    /// [`Refused`] with [`Limit::Ip`].
    pub fn check_address(&mut self, now: u64, ip: IpAddr) -> Result<(), Refused> {
        let retry_after = self.roll(now);
        let used = self.ip.entry(rate_bucket(ip)).or_default();
        if *used >= self.limits.per_ip {
            return Err(Refused { limit: Limit::Ip, retry_after });
        }
        *used += 1;
        Ok(())
    }

    /// Counts one fetch, of an envelope or a record, against the client address `ip` and the relay's ceiling, or refuses
    /// it and counts nothing. The address's window comes first, so that an address over it spends none of the ceiling.
    /// A ceiling of 0 is none.
    ///
    /// # Errors
    ///
    /// [`Refused`] with [`Limit::Fetch`], or with [`Limit::FetchGlobal`] and the seconds to the next minute.
    pub fn check_fetch(&mut self, now: u64, ip: IpAddr) -> Result<(), Refused> {
        let retry_after = self.roll(now);
        let client = rate_bucket(ip);
        if self.fetches.get(&client).copied().unwrap_or(0) >= self.limits.fetch_per_ip {
            return Err(Refused { limit: Limit::Fetch, retry_after });
        }
        if now / MINUTE != self.minute {
            (self.minute, self.all_fetches) = (now / MINUTE, 0);
        }
        let ceiling = self.limits.fetch_global_per_minute;
        if ceiling > 0 && self.all_fetches >= ceiling {
            return Err(Refused { limit: Limit::FetchGlobal, retry_after: MINUTE - now % MINUTE });
        }
        self.all_fetches += 1;
        *self.fetches.entry(client).or_default() += 1;
        Ok(())
    }

    /// Counts one publish against its `from` key and, for an envelope, its root and its sender domain when it has one
    /// (the domain's counter only while its quota is on), or refuses it without counting anything: every limit is
    /// checked before any counter moves.
    ///
    /// # Errors
    ///
    /// [`Refused`] with the first limit used up, in the order from, root, domain.
    pub fn check_sender(
        &mut self,
        now: u64,
        from: &str,
        env: Option<(&str, Option<&str>)>,
    ) -> Result<(), Refused> {
        let (retry_after, day_left) = (self.roll(now), self.roll_day(now));
        let (root, domain) = (env.map(|e| e.0), env.and_then(|e| e.1).filter(|_| self.limits.domain_day > 0));
        let used = |map: &HashMap<String, u32>, key: &str| map.get(key).copied().unwrap_or(0);
        if used(&self.from, from) >= self.limits.per_from {
            return Err(Refused { limit: Limit::From, retry_after });
        }
        if root.is_some_and(|r| used(&self.root, r) >= self.limits.per_root) {
            return Err(Refused { limit: Limit::Root, retry_after });
        }
        if domain.is_some_and(|d| used(&self.domains, d) >= self.limits.domain_day) {
            return Err(Refused { limit: Limit::Domain, retry_after: day_left });
        }
        for (map, key) in [(&mut self.from, Some(from)), (&mut self.root, root), (&mut self.domains, domain)]
        {
            if let Some(k) = key {
                *map.entry(k.to_owned()).or_default() += 1;
            }
        }
        Ok(())
    }

    /// [`RateLimiter::check_sender`] for an envelope of `size` bytes, with the daily quota of stored bytes of the client
    /// address `ip`: every limit is checked before any counter moves, the bytes first. A quota of 0 is none.
    ///
    /// # Errors
    ///
    /// [`Refused`] with [`Limit::Bytes`] and the seconds to the next 00:00 UTC, or as [`RateLimiter::check_sender`].
    pub fn check_envelope(
        &mut self,
        now: u64,
        ip: IpAddr,
        size: u64,
        from: &str,
        root: &str,
        domain: Option<&str>,
    ) -> Result<(), Refused> {
        let retry_after = self.roll_day(now);
        let (quota, client) = (self.limits.bytes_per_day, rate_bucket(ip));
        let stored = self.bytes.get(&client).copied().unwrap_or(0).saturating_add(size);
        if quota > 0 && stored > quota {
            return Err(Refused { limit: Limit::Bytes, retry_after });
        }
        self.check_sender(now, from, Some((root, domain)))?;
        if quota > 0 {
            self.bytes.insert(client, stored);
        }
        Ok(())
    }

    /// Gives `size` bytes back to the client address `ip`: its envelope was not stored after all.
    pub fn refund_bytes(&mut self, ip: IpAddr, size: u64) {
        if let Some(used) = self.bytes.get_mut(&rate_bucket(ip)) {
            *used = used.saturating_sub(size);
        }
    }

    /// Counts one new record signer (a key the relay holds no record of) against the client address `ip` for the UTC
    /// day of `now`, or refuses it when the address has brought its quota of new signers today.
    ///
    /// # Errors
    ///
    /// [`Refused`] with [`Limit::RecordSigners`], `retry_after` the seconds to the next 00:00 UTC.
    pub fn check_new_signer(&mut self, now: u64, ip: IpAddr) -> Result<(), Refused> {
        let retry_after = self.roll_day(now);
        let used = self.signers.entry(rate_bucket(ip)).or_default();
        if *used >= self.limits.signers_per_day {
            return Err(Refused { limit: Limit::RecordSigners, retry_after });
        }
        *used += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
