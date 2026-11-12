//! The relay's state, and the outcomes of its calls.

use crate::clock::Clock;
use crate::config::Config;
use crate::dns::{FixedTxt, TxtLookup};
use crate::ratelimit::RateLimiter;
use crate::resolver::{Domains, HttpsFetcher, WellKnownFetch, txt_lookup};
use crate::store::{Store, StoreError};
use ac_core::Code;
use ac_core::records::Kind;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

/// How many mailbox notifications may queue for a slow subscriber before it is told it lagged (it then reads
/// its mailbox from the store, so nothing is lost).
const EVENTS: usize = 1_024;

/// The relay: its store, its clock, its settings, its rate counters, its live-subscriber notifications, and its
/// state for `domain:` roots (src/resolver.rs).
pub struct Relay {
    pub(crate) store: Arc<dyn Store>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) config: Config,
    pub(crate) limiter: Mutex<RateLimiter>,
    pub(crate) domains: Domains,
    /// The operator's blocklist (src/abuse.rs).
    pub(crate) blocklist: crate::abuse::Blocklist,
    /// The pairing rendezvous's open nameplates (src/pair.rs).
    pub(crate) pairs: crate::pair::Pairs,
    /// The signature verifications the publish path has asked of `ac_core` (at most: the outer signature and one
    /// per hop of an envelope, one per record), so that a test can show a publish over the per-address limit costs
    /// none.
    pub(crate) signature_checks: AtomicU64,
    events: broadcast::Sender<String>,
    /// How many address records the relay has stored since it started.
    address_records: AtomicU64,
}

impl Relay {
    /// A relay over `store`, reading time from `clock`, resolving `domain:` roots over HTTPS as `config` says.
    #[must_use]
    pub fn new(store: Arc<dyn Store>, clock: Arc<dyn Clock>, config: Config) -> Relay {
        let (events, _) = broadcast::channel(EVENTS);
        let limiter = Mutex::new(RateLimiter::new(config.rate));
        let domains =
            Domains::new(Arc::new(HttpsFetcher::new(&config.well_known)), txt_lookup(&config.well_known));
        let (signature_checks, address_records) = (AtomicU64::new(0), AtomicU64::new(0));
        let blocklist = crate::abuse::Blocklist::new(config.blocklist.clone());
        let pairs = crate::pair::Pairs::default();
        Relay {
            store,
            clock,
            config,
            limiter,
            domains,
            blocklist,
            pairs,
            signature_checks,
            events,
            address_records,
        }
    }

    /// The same relay with another fetch of well-known records, a fake in tests; it looks up no TXT record in DNS
    /// either (every name has none), until [`Relay::with_txt`] gives it a lookup.
    #[must_use]
    pub fn with_fetcher(mut self, fetcher: Arc<dyn WellKnownFetch>) -> Relay {
        self.domains = Domains::new(fetcher, Arc::new(FixedTxt::default()));
        self
    }

    /// The same relay with another TXT lookup of `_bag.<domain>` (spec/SPEC.md §12.2), a fake in tests.
    #[must_use]
    pub fn with_txt(mut self, txt: Arc<dyn TxtLookup>) -> Relay {
        self.domains.set_txt(txt);
        self
    }

    /// Where the relay's TXT lookups go: `dns` (the stub resolver) or `fixed` (a table, in tests).
    #[must_use]
    pub fn txt_source(&self) -> &'static str {
        self.domains.txt_source()
    }

    /// The store.
    #[must_use]
    pub fn store(&self) -> &dyn Store {
        self.store.as_ref()
    }

    /// The current time, Unix seconds.
    #[must_use]
    pub fn now(&self) -> u64 {
        self.clock.now()
    }

    /// Notifications of new mailbox rows: each message is the mailbox's address.
    #[must_use]
    pub fn events(&self) -> broadcast::Receiver<String> {
        self.events.subscribe()
    }

    pub(crate) fn notify(&self, mailbox: &str) {
        // No live subscriber is not an error: the rows wait in the store.
        let _ = self.events.send(mailbox.to_owned());
    }

    /// How many address records the relay has stored since it started: a subscription under a chain reads its
    /// mailbox's kept revoked list again once this has moved since its last read.
    pub(crate) fn address_records(&self) -> u64 {
        self.address_records.load(Ordering::SeqCst)
    }

    /// An address record of `key` is stored, and its revoked list kept: counted, then `key`'s mailbox notified, so that
    /// its subscriptions read the list again before their next frame.
    pub(crate) fn address_stored(&self, key: &str) {
        self.address_records.fetch_add(1, Ordering::SeqCst);
        self.notify(key);
    }
}

/// An accepted publish (spec/SPEC.md §8.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Published {
    /// An envelope: answered `{"ok": true, "id", "duplicate", "delivered"}`.
    Envelope {
        /// The envelope's id.
        id: String,
        /// True when the relay already held it; nothing was stored again.
        duplicate: bool,
        /// The mailbox rows this publish wrote, one per recipient delivered to; 0 for a duplicate.
        delivered: usize,
        /// The `from` address.
        from: String,
        /// The chain's root.
        root: String,
    },
    /// A record, stored as the newest of its signer and kind: answered with these and `ok`.
    Record {
        /// Its kind.
        kind: Kind,
        /// Its signer.
        signer: String,
        /// Its `iat`.
        iat: u64,
        /// Its last valid second: `iat + ttl`, `exp`, or none for an accept-from record, which does not expire.
        valid_until: Option<u64>,
    },
}

/// A refused call: the HTTP status, the code (none for the relay's own failure), and for 429 the seconds to wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rejection {
    /// The HTTP status.
    pub status: u16,
    /// The code sent as `{"error": code}`; `None` for a 500, sent as `{"error": "internal"}` (no code of
    /// Appendix A names the relay's own failure).
    pub code: Option<Code>,
    /// For 429, the `Retry-After` seconds.
    pub retry_after: Option<u64>,
    /// For `envelope-too-large`, the relay's envelope cap, sent as `max_envelope_bytes` beside the code.
    pub max_envelope_bytes: Option<usize>,
}

/// The relay status of a code (spec/SPEC.md, Appendix A): 400 for JSON, shape and form, 413 for size, 401 for a
/// failed proof, 403 for the hosting policy (a revoked key of a domain root's record included) and reading rights,
/// 404 for nothing stored, 409 for a stale record, 429 for a rate limit, 500 for `internal`, the relay's own failure
/// (Appendix A since 2026-10-25; no relay path raises it as a code, a 500 carries none), 503 for a `domain:` root that did
/// not resolve and for a store over its bound (`store-full`), each a try to repeat, 422 for every other verification
/// failure.
#[must_use]
pub const fn status(code: Code) -> u16 {
    match code {
        Code::BadHex
        | Code::BadAddress
        | Code::BadJson
        | Code::BadShape
        | Code::BadVersion
        | Code::BadSuite
        | Code::BadRecord => 400,
        Code::EnvelopeTooLarge | Code::BodyTooLarge => 413,
        Code::BadAuth => 401,
        Code::NotHosted
        | Code::RootNotAccepted
        | Code::TooLargeForMailbox
        | Code::NotAuthorized
        | Code::Revoked => 403,
        Code::NotFound => 404,
        Code::StaleRecord => 409,
        Code::RateLimited => 429,
        Code::Internal => 500,
        Code::ResolveFailed | Code::StoreFull => 503,
        _ => 422,
    }
}

impl Rejection {
    /// A rejection with the status of Appendix A.
    #[must_use]
    pub const fn new(code: Code) -> Rejection {
        Rejection { status: status(code), code: Some(code), retry_after: None, max_envelope_bytes: None }
    }

    /// A rejection of a fetch proof's time: `stale-ts` or `future-ts` are 401 there (§8.3).
    #[must_use]
    pub const fn at_fetch(code: Code) -> Rejection {
        let status = match code {
            Code::StaleTs | Code::FutureTs => 401,
            _ => status(code),
        };
        Rejection { status, code: Some(code), retry_after: None, max_envelope_bytes: None }
    }

    /// The relay's own failure: 500.
    #[must_use]
    pub const fn internal() -> Rejection {
        Rejection { status: 500, code: None, retry_after: None, max_envelope_bytes: None }
    }

    /// The wire string of the code: the code, or `internal` for a 500.
    #[must_use]
    pub fn error(&self) -> &'static str {
        self.code.map_or("internal", Code::as_str)
    }
}

impl From<Code> for Rejection {
    fn from(code: Code) -> Rejection {
        Rejection::new(code)
    }
}

/// A store failure is a 500 for every call, logged with its message.
impl From<StoreError> for Rejection {
    fn from(e: StoreError) -> Rejection {
        tracing::error!(event = "store-error", error = %e);
        crate::metrics::METRICS.tick(crate::metrics::STORE_ERRORS);
        Rejection::internal()
    }
}

#[cfg(test)]
mod tests;
