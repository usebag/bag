//! The publish call (spec/SPEC.md §8.2): the policy steps in order, the first that fails being the answer.
//!
//! The body is a record when its top-level object has a `kind` member, an envelope otherwise. For an envelope (steps 3a
//! and 6a were added and the numbers of the others kept): 1 size (`body-too-large`,
//! `envelope-too-large`); 2 parse and caps (§5.4); 3 the id (`bad-id`); 3a the client address's limit, checked and
//! charged before any signature is verified, whatever the publish's outcome; 4 the outer signature (`bad-sig`); 5 the
//! chain, rules 1 to 9 at the envelope's `ts`, with no caveat evaluation; 6 the `ts` window, then the receipt bound:
//! a chained envelope is `hop-expired` once the relay's clock is past the earliest `exp` of its hops
//! plus the skew, whatever its `ts` says ([`check_receipt`]); 6a dedup by id, a tombstone included: an id already
//! stored is 200 `duplicate`, counted against its client address only; 7 hosted
//! recipients: none is `not-hosted`, and a hosted recipient is delivered to only if its `roots` admit the chain's root
//! and the envelope fits its `max_bytes`. Roots admit it when they are `["*"]` or list the root's address (no
//! network), and since 2026-10-26 an address admits it only if no hop's `iss` or `sub` is
//! in the revoked list the relay keeps for the root (src/auth.rs, [`Relay::revokes`]); or else when a `domain:`
//! entry's current key is the root (src/resolver.rs), and then only if no hop's `iss` or `sub` is in that
//! domain record's `revoked` list (after a failed resolution the current key is the pinned one while its record is
//! valid). When none remains, the answer is 503 `resolve-failed` (with `Retry-After`) if one waited on a domain with
//! no current key, else `revoked` if one refused a revoked key, else `root-not-accepted` if one refused the root, else
//! `too-large-for-mailbox`; 8 the sender's limits, per `from`, per root and the sender domain's daily quota (the
//! domain whose current key step 7 found to be the root; a root no domain admitted has none) and the client
//! address's daily quota of stored bytes, counted only by a publish that passes all, then for a pairing request each open nameplate's request limits (src/pair.rs); 9 one
//! stored copy, one mailbox row per delivered recipient, and a push to live subscribers.
//! After step 5 (and a record's signature) the operator's blocklist refuses a listed key, or the pinned key of a listed
//! domain, with 403 `not-authorized` (src/abuse.rs); before step 8 it refuses a root that a listed domain granted. Also
//! before step 8, a store whose live bytes have reached `--max-store-bytes` refuses an envelope that would be
//! stored with 503 `store-full` (`refuse_full`), and a record of a signer it holds none of (LN2-L3): a duplicate, a
//! record of a signer it holds, so that rotation and revocation go on, fetch and subscribe are not refused.
//!
//! Step 7 is the only one that can need the network. [`Relay::publish_resolving`], the HTTP handler's call, resolves
//! each domain it needs once, and a cached one whose key is not the root again, once a minute at most;
//! [`Relay::publish`] makes no network call and counts a domain only when its key is cached. Both run the same steps.
//! A recipient left waiting on a domain beside one that took the envelope is held pending. Since
//! 2026-10-26 one publish sends at most [`MAX_FETCHES_PER_PUBLISH`] domains to the network, those whose
//! pin names the chain's root first; the rest count from the cache, as in [`Relay::publish`].
//!
//! For a record: its size (at most 131,072 bytes, `body-too-large`) and form (§7.1); the client address's limit
//! (step 3a); its signature and time (§7.5); a rotation checked against the stored address record of `rotated_from`
//! when the relay holds one (`bad-rotation`); for a signer the relay holds no record of, 503 `store-full` at the store's
//! bound, then the client address's daily quota of new record signers (429 `rate-limited` until the next 00:00 UTC),
//! which a refused record does not spend; the signer's limit (an implementation
//! default: a record counts against its signer as an envelope against its `from`); then the newer `iat` wins, and a
//! record not newer than the stored one is 409 `stale-record`. An address record is stored until `iat + ttl`, a key
//! record until `exp`, and the sweep deletes it after that; an accept-from record does not expire. An address record
//! stored keeps its `revoked` list past its expiry until a newer one replaces it, and moves the subscriptions of its
//! key's mailbox to read that list again.

use crate::metrics::{METRICS, PENDING_DROPPED, RATE_LIMITED, RESOLUTIONS_CAPPED, STORE_CORRUPT, STORE_FULL};
use crate::relay::{Published, Rejection, Relay};
use crate::resolver::{Failure, Grant, MAX_FETCHES_PER_PUBLISH, MAX_FETCHES_PER_RETRY, RETRY_AFTER};
use crate::store::{Delivery, NewEnvelope};
use ac_core::chain::Hop;
use ac_core::envelope::Envelope;
use ac_core::records::{self, AcceptFromRecord, Domain, Kind, Record, Roots};
use ac_core::{Address, Code, chain, json};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::atomic::Ordering;

/// Step 7's verdict on one recipient.
enum Slot {
    /// The relay holds no accept-from record for it.
    NotHosted,
    /// Delivered, its row expiring then.
    Deliver(u64),
    /// Admitted, but the envelope is over its `max_bytes`.
    TooLarge,
    /// Its roots do not admit the chain's root.
    RefusedRoot,
    /// A domain admitted the root and its record revokes a key of the chain, or an address admitted it and the list
    /// kept for the root does.
    Revoked,
    /// No address or `"*"` admitted the root, and a `domain:` entry did not resolve.
    Unresolved,
    /// No address or `"*"` admitted the root: its `domain:` entries decide.
    Waiting(AcceptFromRecord),
}

/// An envelope through step 6a, and step 7 as far as it goes without the network.
struct Pending<'a> {
    env: Envelope,
    root: Address,
    body: &'a [u8],
    now: u64,
    ip: IpAddr,
    size: u64,
    slots: Vec<(Address, Slot)>,
}

impl Pending<'_> {
    /// The domains step 7 still needs, each once, in the order the recipients name them.
    fn domains(&self) -> Vec<Domain> {
        let mut out: Vec<Domain> = Vec::new();
        for (_, slot) in &self.slots {
            if let Slot::Waiting(accept) = slot {
                for d in accept.domains() {
                    if !out.contains(d) {
                        out.push(d.clone());
                    }
                }
            }
        }
        out
    }
}

/// How far a publish got without the network.
enum Prepared<'a> {
    /// Answered: a record, or an envelope no `domain:` entry can change.
    Done(Result<Published, Rejection>),
    /// An envelope whose step 7 needs the grants of some domains.
    Envelope(Box<Pending<'a>>),
}

impl Relay {
    /// Publishes an envelope or a record without any network call: a `domain:` root counts only when its key is
    /// cached, and is unresolved (503 `resolve-failed`) otherwise. The HTTP handler calls
    /// [`Relay::publish_resolving`].
    ///
    /// # Errors
    ///
    /// A [`Rejection`] with the first policy step that refused it.
    pub fn publish(&self, body: &[u8], ip: IpAddr) -> Result<Published, Rejection> {
        match self.prepare(body, ip)? {
            Prepared::Done(answer) => answer,
            Prepared::Envelope(pending) => {
                let mut grants = BTreeMap::new();
                for d in pending.domains() {
                    let grant = self.cached_grant(&d)?.unwrap_or(Grant::Unresolved(Failure::NotCached));
                    grants.insert(d, grant);
                }
                self.finish(*pending, &grants)
            }
        }
    }

    /// Publishes an envelope or a record, resolving each `domain:` root step 7 needs and the cache does not hold,
    /// once (src/resolver.rs): the call the HTTP handler makes. At most [`MAX_FETCHES_PER_PUBLISH`] domains go to the
    /// network, those whose pin names the chain's root first; the others count from the cache alone.
    ///
    /// # Errors
    ///
    /// A [`Rejection`] with the first policy step that refused it.
    pub async fn publish_resolving(&self, body: &[u8], ip: IpAddr) -> Result<Published, Rejection> {
        match self.prepare(body, ip)? {
            Prepared::Done(answer) => answer,
            Prepared::Envelope(pending) => {
                let cap = MAX_FETCHES_PER_PUBLISH;
                let (grants, _, deferred) = self.grants_within(pending.domains(), &pending.root, cap).await?;
                if deferred > 0 {
                    tracing::warn!(event = "resolutions-capped", id = %pending.env.id_hex(), cap, deferred);
                    METRICS.tick(RESOLUTIONS_CAPPED);
                }
                self.finish(*pending, &grants)
            }
        }
    }

    /// The grants of `domains` for `root`: the cache's answer where it settles one, and the rest from the network, at
    /// most `cap` of them, those whose pin names the root first; past `cap` the cache's alone. With them, how
    /// many went to the network and how many had to wait.
    async fn grants_within(
        &self,
        domains: Vec<Domain>,
        root: &Address,
        cap: usize,
    ) -> Result<(BTreeMap<Domain, Grant>, usize, usize), Rejection> {
        let (mut grants, mut network) = (BTreeMap::new(), Vec::new());
        for d in domains {
            match self.cached_grant(&d)? {
                Some(Grant::Key { key, revoked }) if key == *root => {
                    grants.insert(d, Grant::Key { key, revoked });
                }
                Some(failed @ Grant::Unresolved(_)) => {
                    grants.insert(d, failed);
                }
                cached => {
                    let pinned = self.store.domain_pin(d.as_str())?.is_some_and(|p| p.key == root.as_str());
                    network.push((!pinned, d, cached));
                }
            }
        }
        // A stable sort: the domains whose pin names the root first, then the order the recipients name them.
        network.sort_by_key(|(unpinned, _, _)| *unpinned);
        let (fetched, deferred) = (network.len().min(cap), network.len().saturating_sub(cap));
        for (i, (_, d, cached)) in network.into_iter().enumerate() {
            let grant = if i < cap {
                self.grant_for(&d, root).await?
            } else {
                cached.unwrap_or(Grant::Unresolved(Failure::NotCached))
            };
            grants.insert(d, grant);
        }
        Ok((grants, fetched, deferred))
    }

    /// Steps 1 to 6a, and step 7 for every recipient whose roots admit or refuse without a domain.
    fn prepare<'a>(&self, body: &'a [u8], ip: IpAddr) -> Result<Prepared<'a>, Rejection> {
        if body.len() > self.config.body_limit {
            return Err(Code::BodyTooLarge.into());
        }
        let parsed = json::parse(body);
        if let Ok(value @ serde_json::Value::Object(_)) = &parsed
            && value.get("kind").is_some()
        {
            if body.len() > self.config.record_limit {
                return Err(Code::BodyTooLarge.into());
            }
            return Ok(Prepared::Done(self.publish_record(value, body, ip)));
        }
        // An envelope's size is checked before it is read (§5.4 step 1).
        if body.len() > self.config.max_envelope_bytes {
            return Err(Code::EnvelopeTooLarge.into());
        }
        let env = Envelope::from_json(&parsed?)?;
        env.check_id()?;
        let now = self.now();
        self.limit_address(now, ip)?;
        self.signature_work(1);
        env.check_sig()?;
        self.signature_work(env.auth.len());
        let verified = chain::verify(&env.from, env.ts, &env.auth)?;
        self.refuse_blocked(
            env.auth.iter().flat_map(|h| [&h.iss, &h.sub]).chain([&env.from, &verified.root]),
        )?;
        env.check_ts(now, self.config.ttl, self.config.skew)?;
        check_receipt(&env.auth, now, self.config.skew)?;
        let id = env.id_hex();
        if self.store.has_envelope(&id, now)? {
            let (from, root) = (env.from.to_string(), verified.root.to_string());
            return Ok(Prepared::Done(Ok(Published::Envelope {
                id,
                duplicate: true,
                delivered: 0,
                from,
                root,
            })));
        }

        let size = u64::try_from(body.len()).unwrap_or(u64::MAX);
        let mut slots = Vec::with_capacity(env.to.len());
        for to in &env.to {
            let slot = match self.accept_from(to)? {
                None => Slot::NotHosted,
                Some(accept) if accept.admits(&verified.root) => {
                    self.admitted(to, &accept, &verified.root, &env.auth, size, now)?
                }
                Some(accept) if accept.domains().is_empty() => Slot::RefusedRoot,
                Some(accept) => Slot::Waiting(accept),
            };
            slots.push((to.clone(), slot));
        }
        if slots.iter().all(|(_, s)| matches!(s, Slot::NotHosted)) {
            return Err(Code::NotHosted.into());
        }
        let pending = Pending { env, root: verified.root, body, now, ip, size, slots };
        if pending.slots.iter().any(|(_, s)| matches!(s, Slot::Waiting(_))) {
            Ok(Prepared::Envelope(Box::new(pending)))
        } else {
            Ok(Prepared::Done(self.finish(pending, &BTreeMap::new())))
        }
    }

    /// Step 7 for a recipient whose roots admit the chain's root with no domain: delivered if it fits, unless they admit
    /// it by its address and the revoked list the relay keeps for the root names a key of the chain: then
    /// `revoked`. `["*"]` reads no list (spec/SPEC.md Appendix B 54); the edge still reads the root's (§9).
    fn admitted(
        &self,
        to: &Address,
        accept: &AcceptFromRecord,
        root: &Address,
        hops: &[Hop],
        size: u64,
        at: u64,
    ) -> Result<Slot, Rejection> {
        if !matches!(accept.roots, Roots::Any) && self.revokes(root, hops)? {
            tracing::info!(event = "revoked-hop", mailbox = %to, root = %root);
            return Ok(Slot::Revoked);
        }
        Ok(self.fits(accept, size, at))
    }

    fn fits(&self, accept: &AcceptFromRecord, size: u64, now: u64) -> Slot {
        if size <= accept.max_bytes {
            Slot::Deliver(now.saturating_add(self.config.ttl.min(accept.ttl)))
        } else {
            Slot::TooLarge
        }
    }

    /// The rest of step 7 with the domains' grants, then steps 8 and 9.
    fn finish(&self, pending: Pending<'_>, grants: &BTreeMap<Domain, Grant>) -> Result<Published, Rejection> {
        let Pending { env, root, body, now, ip, size, slots } = pending;
        let chain_keys: Vec<&Address> = env.auth.iter().flat_map(|h| [&h.iss, &h.sub]).collect();
        let mut decided = Vec::with_capacity(slots.len());
        for (to, slot) in slots {
            let slot = match slot {
                Slot::Waiting(accept) => {
                    let slot = self.by_domains(&accept, &root, &chain_keys, grants, size, now);
                    log_domain_verdict(&to, &root, &accept, &slot, grants);
                    slot
                }
                other => other,
            };
            decided.push((to, slot));
        }
        let (mut deliveries, mut held, until) = (Vec::new(), Vec::new(), now.saturating_add(self.config.ttl));
        for (to, slot) in &decided {
            let addr = to.to_string();
            match slot {
                Slot::Deliver(expires_at) => deliveries.push(Delivery { addr, expires_at: *expires_at }),
                Slot::Unresolved => held.push(Delivery { addr, expires_at: until }),
                _ => {}
            }
        }
        if deliveries.is_empty() {
            let any = |test: fn(&Slot) -> bool| decided.iter().any(|(_, s)| test(s));
            return Err(if any(|s| matches!(s, Slot::Unresolved)) {
                Rejection { retry_after: Some(RETRY_AFTER), ..Rejection::new(Code::ResolveFailed) }
            } else if any(|s| matches!(s, Slot::Revoked)) {
                Code::Revoked.into()
            } else if any(|s| matches!(s, Slot::RefusedRoot)) {
                Code::RootNotAccepted.into()
            } else {
                Code::TooLargeForMailbox.into()
            });
        }

        // The domains whose current key is the root: a listed one refuses the publish, whether or not the relay had
        // pinned it before (a first contact or a rotation pins it only now), and the first is the sender domain.
        let list = self.blocklist.entries();
        let senders: Vec<String> = grants
            .iter()
            .filter(|(_, g)| matches!(g, Grant::Key { key, .. } if *key == root))
            .map(|(d, _)| format!("domain:{d}"))
            .collect();
        if let Some(listed) = senders.iter().find(|d| list.contains(*d)) {
            tracing::info!(event = "blocked", key = %root, domain = %listed);
            METRICS.tick("ac_relay_blocked_total");
            return Err(Code::NotAuthorized.into());
        }
        self.refuse_full()?;
        let size = u64::try_from(body.len()).unwrap_or(u64::MAX);
        let sender_domain = senders.first().map(String::as_str);
        self.limit_envelope(now, ip, size, env.from.as_str(), root.as_str(), sender_domain)?;
        // A pairing request (src/pair.rs): counted against each open nameplate it is delivered to, after the sender's.
        self.pairs.request(now, ip, deliveries.iter().map(|d| d.addr.as_str())).map_err(|refused| {
            METRICS.count(RATE_LIMITED, "limit", refused.limit.as_str());
            tracing::info!(event = "rate-limited", limit = refused.limit.as_str(), from = %env.from,
                ip = %self.config.front.log_ip.show(ip), retry_after = refused.retry_after);
            limited(refused)
        })?;

        let id = env.id_hex();
        let published = |duplicate, delivered| Published::Envelope {
            id: id.clone(),
            duplicate,
            delivered,
            from: env.from.to_string(),
            root: root.to_string(),
        };
        let new = NewEnvelope {
            id: &id,
            bytes: body,
            from: env.from.as_str(),
            root: root.as_str(),
            ts: env.ts,
            received_at: now,
            pending: &held,
        };
        match self.store.insert_envelope(&new, &deliveries)? {
            // Another publish of the same id won the race between the dedup check and the insert: it stored nothing.
            None => {
                self.limiter().refund_bytes(ip, size);
                Ok(published(true, 0))
            }
            Some(cursors) => {
                for d in &deliveries {
                    self.notify(&d.addr);
                }
                for p in &held {
                    tracing::info!(event = "pending", id = %id, mailbox = %p.addr, until = p.expires_at);
                }
                Ok(published(false, cursors.len()))
            }
        }
    }

    /// Step 7 for a recipient whose roots name domains and admit the root by no address: a domain whose current
    /// key is the root admits it, unless one such domain's record revokes a key of the chain; else a domain that did
    /// not resolve leaves it unresolved; else the roots refuse it.
    fn by_domains(
        &self,
        accept: &AcceptFromRecord,
        root: &Address,
        chain_keys: &[&Address],
        grants: &BTreeMap<Domain, Grant>,
        size: u64,
        now: u64,
    ) -> Slot {
        let (mut granted, mut revoked, mut unresolved) = (false, false, false);
        for d in accept.domains() {
            match grants.get(d) {
                Some(Grant::Key { key, revoked: list }) if key == root => {
                    granted = true;
                    revoked |= chain_keys.iter().any(|k| list.contains(*k));
                }
                Some(Grant::Key { .. }) => {}
                Some(Grant::Unresolved(_)) | None => unresolved = true,
            }
        }
        match (granted, revoked, unresolved) {
            (true, true, _) => Slot::Revoked,
            (true, false, _) => self.fits(accept, size, now),
            (false, _, true) => Slot::Unresolved,
            (false, _, false) => Slot::RefusedRoot,
        }
    }

    fn publish_record(
        &self,
        value: &serde_json::Value,
        body: &[u8],
        ip: IpAddr,
    ) -> Result<Published, Rejection> {
        let record = Record::from_json(value)?;
        let now = self.now();
        self.limit_address(now, ip)?;
        self.signature_work(1);
        record.verify(now, self.config.skew)?;
        self.refuse_blocked([record.signer()])?;
        if let Record::Address(next) = &record
            && let Some(previous) = &next.rotated_from
            && let Some(stored) = self.stored_record(previous, Kind::Address)?
        {
            let Record::Address(prev) = stored else {
                return Err(corrupt(previous, Kind::Address));
            };
            records::verify_rotation(&prev, next)?;
        } else if let Record::Address(next) = &record {
            // No record of `rotated_from` here: its claim alone, under `rotated_from` (§7.3; since 2026-10-25).
            records::verify_rotation_claim(next)?;
        }
        let signer = record.signer();
        let new_signer = !self.store.has_records(signer.as_str())?;
        if new_signer {
            self.refuse_full()?;
            self.limit_new_signer(now, ip, signer)?;
        }
        self.limit_signer(now, signer.as_str())?;
        if let Some(stored) = self.store.record(signer.as_str(), record.kind())?
            && stored.iat >= record.iat()
        {
            return Err(Code::StaleRecord.into());
        }
        // A newer record stored between the check and the write wins.
        let valid_until = crate::store::expiry_of(&record);
        if !self.store.put_record(signer.as_str(), record.kind(), record.iat(), valid_until, body)? {
            return Err(Code::StaleRecord.into());
        }
        if record.kind() == Kind::Address {
            self.address_stored(signer.as_str());
        }
        if new_signer {
            METRICS.tick("ac_relay_new_signers_total");
        }
        let (kind, iat) = (record.kind(), record.iat());
        Ok(Published::Record { kind, signer: signer.to_string(), iat, valid_until })
    }

    /// The stored record of `kind` for `addr`, parsed. Stored records were verified when published.
    pub(crate) fn stored_record(&self, addr: &Address, kind: Kind) -> Result<Option<Record>, Rejection> {
        let Some(stored) = self.store.record(addr.as_str(), kind)? else {
            return Ok(None);
        };
        match Record::parse(&stored.bytes) {
            Ok(r) if r.kind() == kind => Ok(Some(r)),
            _ => Err(corrupt(addr, kind)),
        }
    }

    fn accept_from(&self, addr: &Address) -> Result<Option<AcceptFromRecord>, Rejection> {
        match self.stored_record(addr, Kind::AcceptFrom)? {
            Some(Record::AcceptFrom(a)) => Ok(Some(a)),
            Some(_) => Err(corrupt(addr, Kind::AcceptFrom)),
            None => Ok(None),
        }
    }

    /// 503 `store-full` with a `Retry-After` of one sweep when the store's live bytes have reached the bound.
    fn refuse_full(&self) -> Result<(), Rejection> {
        let max = self.config.max_store_bytes;
        let live = if max == 0 { 0 } else { self.store.live_bytes()? };
        if max == 0 || live < max {
            return Ok(());
        }
        let retry_after = self.config.sweep_interval.as_secs().max(1);
        tracing::warn!(event = "store-full", live, max, retry_after);
        METRICS.tick(STORE_FULL);
        Err(Rejection { retry_after: Some(retry_after), ..Rejection::new(Code::StoreFull) })
    }

    /// The rate counters. A panic elsewhere cannot leave them harmfully half-updated: keep counting.
    fn limiter(&self) -> std::sync::MutexGuard<'_, crate::ratelimit::RateLimiter> {
        self.limiter.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The client address's fetch window, before any signature is verified or any store read: every fetch, of an
    /// envelope or a record, that reaches it counts.
    pub(crate) fn limit_fetch(&self, now: u64, ip: IpAddr) -> Result<(), Rejection> {
        self.limiter().check_fetch(now, ip).map_err(|refused| {
            METRICS.count(RATE_LIMITED, "limit", refused.limit.as_str());
            tracing::info!(event = "rate-limited", limit = refused.limit.as_str(),
                ip = %self.config.front.log_ip.show(ip), retry_after = refused.retry_after);
            limited(refused)
        })
    }

    /// Step 3a: the client address's limit, before any signature is verified; every publish that reaches it counts.
    pub(crate) fn limit_address(&self, now: u64, ip: IpAddr) -> Result<(), Rejection> {
        self.limiter().check_address(now, ip).map_err(|refused| {
            METRICS.count(RATE_LIMITED, "limit", refused.limit.as_str());
            tracing::info!(event = "rate-limited", limit = refused.limit.as_str(),
                ip = %self.config.front.log_ip.show(ip), retry_after = refused.retry_after);
            limited(refused)
        })
    }

    /// Step 8 for an envelope: its limits per `from`, per root and per sender domain, and the client address's daily
    /// quota of stored bytes, counted only when all pass.
    fn limit_envelope(
        &self,
        now: u64,
        ip: IpAddr,
        size: u64,
        from: &str,
        root: &str,
        domain: Option<&str>,
    ) -> Result<(), Rejection> {
        self.limiter().check_envelope(now, ip, size, from, root, domain).map_err(|refused| {
            METRICS.count(RATE_LIMITED, "limit", refused.limit.as_str());
            tracing::info!(event = "rate-limited", limit = refused.limit.as_str(), from, root, domain, size,
                ip = %self.config.front.log_ip.show(ip), retry_after = refused.retry_after);
            limited(refused)
        })
    }

    /// A record counts against its signer as an envelope against its `from`.
    fn limit_signer(&self, now: u64, signer: &str) -> Result<(), Rejection> {
        self.limiter().check_sender(now, signer, None).map_err(|refused| {
            METRICS.count(RATE_LIMITED, "limit", refused.limit.as_str());
            tracing::info!(
                event = "rate-limited",
                limit = refused.limit.as_str(),
                from = signer,
                retry_after = refused.retry_after
            );
            limited(refused)
        })
    }

    /// The client address's daily quota of new record signers (keys the relay holds no record of); behind a trusted
    /// proxy, the client its header names.
    fn limit_new_signer(&self, now: u64, ip: IpAddr, signer: &Address) -> Result<(), Rejection> {
        self.limiter().check_new_signer(now, ip).map_err(|refused| {
            METRICS.count(RATE_LIMITED, "limit", refused.limit.as_str());
            tracing::info!(event = "rate-limited", limit = refused.limit.as_str(), signer = %signer,
                ip = %self.config.front.log_ip.show(ip), retry_after = refused.retry_after);
            limited(refused)
        })
    }

    /// The blocklist: 403 `not-authorized` when one of `keys` is listed, or is the pinned key of a listed domain.
    fn refuse_blocked<'k>(&self, keys: impl IntoIterator<Item = &'k Address>) -> Result<(), Rejection> {
        let list = self.blocklist.entries();
        let mut pinned = Vec::new();
        for d in list.iter().filter_map(|e| e.strip_prefix("domain:")) {
            pinned.extend(self.store.domain_pin(d)?.map(|p| p.key));
        }
        match keys.into_iter().find(|k| list.contains(k.as_str()) || pinned.iter().any(|p| p == k.as_str())) {
            Some(key) => {
                tracing::info!(event = "blocked", key = %key);
                METRICS.tick("ac_relay_blocked_total");
                Err(Code::NotAuthorized.into())
            }
            None => Ok(()),
        }
    }

    /// Counts the signature verifications a publish is about to ask of `ac_core` (at most `n`).
    fn signature_work(&self, n: usize) {
        self.signature_checks.fetch_add(u64::try_from(n).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// Judges the live pending rows again, the earliest to expire first, at most 256 a call, by step 7
    /// at the relay's clock: an admitted row becomes a mailbox row, expiring at `received_at` + min(TTL, its `ttl`), a
    /// refused one is dropped, an unresolved one waits. One call reads at most [`MAX_FETCHES_PER_RETRY`] domains from the
    /// network. The rows delivered; a store failure is a 500.
    pub(crate) async fn retry_pending(&self) -> Result<usize, Rejection> {
        let (now, mut delivered, mut budget) = (self.now(), 0, MAX_FETCHES_PER_RETRY);
        for (id, addr) in self.store.pending(now, 256)? {
            let outcome = match self.pending_verdict(&id, &addr, now, &mut budget).await? {
                Ok(Slot::Unresolved) => continue,
                Ok(Slot::Deliver(expires_at)) if expires_at > now => Ok(expires_at),
                Ok(Slot::Deliver(_)) => Err("expired"),
                Ok(Slot::Revoked) => Err("revoked"),
                Ok(Slot::TooLarge) => Err("too-large-for-mailbox"),
                Ok(_) => Err("root-not-accepted"),
                Err(reason) => Err(reason),
            };
            let cursor = self.store.settle_pending(&id, &addr, outcome.ok())?;
            match outcome {
                Ok(expires_at) => {
                    self.notify(&addr);
                    delivered += 1;
                    tracing::info!(event = "pending-delivered", id = %id, mailbox = %addr, cursor, expires_at);
                }
                Err(reason) => {
                    tracing::info!(event = "pending-dropped", id = %id, mailbox = %addr, reason);
                    METRICS.count(PENDING_DROPPED, "reason", reason);
                }
            }
        }
        Ok(delivered)
    }

    /// Step 7 for a pending row now, or why it is dropped without one: `gone`, `corrupt` or `not-hosted`. The domains it
    /// reads from the network come out of `budget`.
    async fn pending_verdict(
        &self,
        id: &str,
        addr: &str,
        now: u64,
        budget: &mut usize,
    ) -> Result<Result<Slot, &'static str>, Rejection> {
        let Some(stored) = self.store.envelope(id, now)? else { return Ok(Err("gone")) };
        let Some(env) = json::parse(&stored.bytes).and_then(|v| Envelope::from_json(&v)).ok() else {
            return Ok(Err("corrupt"));
        };
        let Ok(verified) = chain::verify(&env.from, env.ts, &env.auth) else { return Ok(Err("corrupt")) };
        let Ok(to) = Address::parse(addr) else { return Ok(Err("corrupt")) };
        let Some(accept) = self.accept_from(&to)? else { return Ok(Err("not-hosted")) };
        let (root, size) = (verified.root, u64::try_from(stored.bytes.len()).unwrap_or(u64::MAX));
        if accept.admits(&root) {
            return Ok(Ok(self.admitted(&to, &accept, &root, &env.auth, size, stored.received_at)?));
        }
        let cap = MAX_FETCHES_PER_PUBLISH.min(*budget);
        let domains = accept.domains().into_iter().cloned().collect();
        let (grants, fetched, deferred) = self.grants_within(domains, &root, cap).await?;
        *budget -= fetched;
        if deferred > 0 {
            tracing::info!(event = "resolutions-capped", id, cap, deferred);
            METRICS.tick(RESOLUTIONS_CAPPED);
        }
        let chain_keys: Vec<&Address> = env.auth.iter().flat_map(|h| [&h.iss, &h.sub]).collect();
        Ok(Ok(self.by_domains(&accept, &root, &chain_keys, &grants, size, stored.received_at)))
    }
}

/// Step 6's receipt bound (spec/SPEC.md §8.2; added 2026-10-25): live delivery is judged
/// at the relay's clock as well as at `ts`. A chain is refused `hop-expired` once `received_at`, the relay's clock at
/// receipt, is past the earliest `exp` of all its hops plus the skew, the relay's own `--skew`, so that a `ts`
/// back-dated into a hop's life no longer revives an expired key for live delivery. An empty
/// chain has no `exp` and no bound. The edge applies the same bound to the `received_at` the relay hands it.
///
/// # Errors
///
/// [`Code::HopExpired`].
pub fn check_receipt(hops: &[Hop], received_at: u64, skew: u64) -> Result<(), Code> {
    match hops.iter().map(|h| h.exp).min() {
        Some(exp) if received_at > exp.saturating_add(skew) => Err(Code::HopExpired),
        _ => Ok(()),
    }
}

/// A rate limit's 429, with its `Retry-After`.
fn limited(refused: crate::ratelimit::Refused) -> Rejection {
    Rejection { retry_after: Some(refused.retry_after), ..Rejection::new(Code::RateLimited) }
}

/// One log line for a recipient whose domains decided against it: the root, and what each domain gave.
fn log_domain_verdict(
    to: &Address,
    root: &Address,
    accept: &AcceptFromRecord,
    slot: &Slot,
    grants: &BTreeMap<Domain, Grant>,
) {
    let outcome = match slot {
        Slot::Revoked => "revoked",
        Slot::Unresolved => "unresolved",
        Slot::RefusedRoot => "other-key",
        _ => return,
    };
    let domains: Vec<String> = accept
        .domains()
        .into_iter()
        .map(|d| match grants.get(d) {
            Some(Grant::Key { key, .. }) => format!("{d}={key}"),
            Some(Grant::Unresolved(failure)) => format!("{d}:{}", failure.reason()),
            None => format!("{d}:{}", Failure::NotCached.reason()),
        })
        .collect();
    tracing::info!(event = "domain-roots", mailbox = %to, root = %root, outcome, domains = %domains.join(" "));
}

fn corrupt(addr: &Address, kind: Kind) -> Rejection {
    tracing::error!(event = "store-corrupt", addr = %addr, kind = kind.as_str());
    METRICS.tick(STORE_CORRUPT);
    Rejection::internal()
}

#[cfg(test)]
mod tests;
