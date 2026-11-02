//! The relay's storage: one trait, a SQLite implementation for the binary and an in-memory one for unit tests.
//!
//! The tables: `envelopes(id, bytes, from_addr, root, ts, size, received_at, expires_at)`,
//! `mailbox(addr, cursor, id, expires_at)` with one row per hosted recipient, `cursors(addr, next)`,
//! `acks(addr, signer, cursor)` and `records(addr, kind, iat, bytes, expires_at)`; later `domain_pins(domain,
//! key, record_bytes, pinned_at, expires_at)`, one pin per domain an accept-from record names; and later
//! `tombstones(id, until)`, the ids the sweep dropped while a replay could still pass the `ts` window. An
//! envelope is stored once however many mailboxes hold it; a cursor is per mailbox, starts at 1 and only grows, even
//! across sweeps. An envelope's `received_at` is the relay's clock when it was stored, which no later publish of the
//! same id moves; every read of an envelope returns it, for the `env` frame's `received_at` and fetch's
//! `AC-Received-At` (spec/SPEC.md §8.3, §8.5). Later `pending(id, addr, until)` holds a recipient
//! left waiting on a domain while others took the envelope, which is kept as long. Since 2026-10-26
//! `revoked(addr, iat, keys)` keeps the `revoked` list of each key's newest address record after the sweep
//! has deleted the record, until a newer one replaces it ([`Store::revoked`]).

pub mod memory;
pub mod sqlite;

use ac_core::records::{Kind, Record};
use std::fmt;

/// A storage failure. The relay answers 500 `internal` and logs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(pub String);

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "store: {}", self.0)
    }
}

impl std::error::Error for StoreError {}

/// The result of a store call.
pub type StoreResult<T> = Result<T, StoreError>;

/// A stored record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRecord {
    /// Its `iat`.
    pub iat: u64,
    /// Its exact bytes as published.
    pub bytes: Vec<u8>,
}

/// An envelope to store.
#[derive(Debug, Clone, Copy)]
pub struct NewEnvelope<'a> {
    /// The id, hex.
    pub id: &'a str,
    /// The exact bytes as published.
    pub bytes: &'a [u8],
    /// The `from` address.
    pub from: &'a str,
    /// The chain's root.
    pub root: &'a str,
    /// The envelope's `ts`.
    pub ts: u64,
    /// When the relay received it.
    pub received_at: u64,
    /// The recipients held pending, each until its `expires_at`: no mailbox row yet.
    pub pending: &'a [Delivery],
}

/// One mailbox row to write: the recipient and when the row expires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    /// The hosted recipient.
    pub addr: String,
    /// `received_at + min(relay TTL, the recipient's accept-from ttl)`.
    pub expires_at: u64,
}

/// A mailbox row as a subscriber receives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxEntry {
    /// The row's cursor in its mailbox.
    pub cursor: u64,
    /// The envelope's exact bytes.
    pub bytes: Vec<u8>,
    /// When the relay stored the envelope (Unix seconds).
    pub received_at: u64,
}

/// A stored envelope as fetch hands it out: its exact bytes and when the relay stored it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEnvelope {
    /// The exact bytes as published.
    pub bytes: Vec<u8>,
    /// When the relay stored it (Unix seconds).
    pub received_at: u64,
}

/// The pin of a domain: the key the relay accepted for it, at first contact or through a countersigned
/// rotation, the exact bytes of the record that carries it, and until when that record answers without a new fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainPin {
    /// The domain, a domain root's host.
    pub domain: String,
    /// The pinned key, an address.
    pub key: String,
    /// The bytes of the newest record of that key the relay read.
    pub record: Vec<u8>,
    /// When the key was pinned: first contact, or the rotation to it.
    pub pinned_at: u64,
    /// Until when the record is used without a new fetch.
    pub expires_at: u64,
}

/// The failure of a store that keeps no domain pins: [`Store`]'s default for them, so that such a store makes every
/// `domain:` root fail closed rather than resolve without a pin.
#[must_use]
pub fn no_domain_pins() -> StoreError {
    StoreError("this store keeps no domain pins".into())
}

/// The `revoked` list of an address record's bytes, each key as text; empty for bytes that are not an address record.
#[must_use]
pub fn revoked_of(bytes: &[u8]) -> Vec<String> {
    match Record::parse(bytes) {
        Ok(Record::Address(r)) => r.revoked.iter().map(ToString::to_string).collect(),
        _ => Vec::new(),
    }
}

/// When a record stops being valid (§7.5): an address record at `iat + ttl`, a key record at `exp`; an accept-from
/// record never. The sweep deletes a record once its clock is past this second.
#[must_use]
pub fn expiry_of(record: &Record) -> Option<u64> {
    match record {
        Record::Address(r) => Some(r.iat.saturating_add(r.ttl)),
        Record::Key(r) => Some(r.exp),
        Record::AcceptFrom(_) => None,
    }
}

/// What a sweep did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Swept {
    /// Expired mailbox rows deleted.
    pub mailbox: usize,
    /// Envelopes deleted: every row that referred to them expired.
    pub envelopes: usize,
    /// Tombstones written for those envelopes whose `ts` plus the replay window was not yet past.
    pub tombstoned: usize,
    /// Tombstones deleted: their `until` was past.
    pub tombstones_expired: usize,
    /// Address and key records deleted: their validity was past.
    pub records: usize,
    /// Pending rows deleted: their `until` was past.
    pub pending: usize,
}

impl Swept {
    /// Adds one transaction's rows to a sweep's.
    pub(crate) fn add(&mut self, other: Swept) {
        self.mailbox += other.mailbox;
        self.envelopes += other.envelopes;
        self.tombstoned += other.tombstoned;
        self.tombstones_expired += other.tombstones_expired;
        self.records += other.records;
        self.pending += other.pending;
    }
}

/// What the store holds, for the hourly `store-size` line (`sweeper`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Size {
    /// The database's bytes: SQLite's page count times its page size (the file, once its log is checkpointed).
    pub bytes: u64,
    /// The bytes of those in use: the free pages (the next insert reuses them) taken out.
    pub live: u64,
    /// Envelopes stored.
    pub envelopes: u64,
    /// Mailbox rows.
    pub mailbox: u64,
    /// Records of every kind.
    pub records: u64,
    /// Domain pins.
    pub pins: u64,
}

/// The relay's storage.
pub trait Store: Send + Sync {
    /// The stored record of `kind` for `addr`.
    ///
    /// # Errors
    ///
    /// A storage failure.
    fn record(&self, addr: &str, kind: Kind) -> StoreResult<Option<StoredRecord>>;

    /// Stores a record unless one with the same or a newer `iat` is there; true when it was stored. `expires_at`
    /// is when it stops being valid ([`expiry_of`]), `None` for one that does not expire. An address record stored
    /// also replaces, in the same transaction, the list [`Store::revoked`] keeps for `addr`, unless that list came
    /// from a record with a newer `iat`.
    ///
    /// # Errors
    ///
    /// A storage failure.
    fn put_record(
        &self,
        addr: &str,
        kind: Kind,
        iat: u64,
        expires_at: Option<u64>,
        bytes: &[u8],
    ) -> StoreResult<bool>;

    /// The revoked list kept for `addr`: the `revoked` list of the newest address record of `addr` the store
    /// has stored, kept past that record's expiry and the sweep until an address record of `addr` with a newer `iat`
    /// replaces it; empty when it has stored none.
    ///
    /// # Errors
    ///
    /// A storage failure.
    fn revoked(&self, addr: &str) -> StoreResult<Vec<String>>;

    /// Whether the relay holds any record signed by `addr`, of any kind: a signer it holds none of is new (the
    /// daily quota of new record signers per client address).
    ///
    /// # Errors
    ///
    /// A storage failure.
    fn has_records(&self, addr: &str) -> StoreResult<bool> {
        for kind in Kind::ALL {
            if self.record(addr, kind)?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether an envelope with this id is stored, or was swept while a replay of it could still pass the `ts`
    /// window at `now` (a tombstone whose `until` is not past).
    ///
    /// # Errors
    ///
    /// A storage failure.
    fn has_envelope(&self, id: &str, now: u64) -> StoreResult<bool>;

    /// Stores the envelope once, appends one mailbox row per delivery and writes its pending rows, atomically; the
    /// envelope expires with the last of them. Returns each recipient's new cursor, in the order of `deliveries`, or
    /// `None` when the id is already stored or tombstoned at the envelope's `received_at` (nothing is written).
    ///
    /// # Errors
    ///
    /// A storage failure; nothing is written then either.
    fn insert_envelope(
        &self,
        env: &NewEnvelope<'_>,
        deliveries: &[Delivery],
    ) -> StoreResult<Option<Vec<u64>>>;

    /// A stored envelope that has not expired at `now`: its bytes and when the relay stored it.
    ///
    /// # Errors
    ///
    /// A storage failure.
    fn envelope(&self, id: &str, now: u64) -> StoreResult<Option<StoredEnvelope>>;

    /// Up to `limit` unexpired rows of mailbox `addr` with a cursor above `after`, in cursor order.
    ///
    /// # Errors
    ///
    /// A storage failure.
    fn mailbox_after(&self, addr: &str, after: u64, limit: usize, now: u64)
    -> StoreResult<Vec<MailboxEntry>>;

    /// The last cursor given out in mailbox `addr`, 0 when none.
    ///
    /// # Errors
    ///
    /// A storage failure.
    fn last_cursor(&self, addr: &str) -> StoreResult<u64>;

    /// Records that `signer` has received mailbox `addr` up to `cursor`; an ack never moves backwards.
    ///
    /// # Errors
    ///
    /// A storage failure.
    fn ack(&self, addr: &str, signer: &str, cursor: u64) -> StoreResult<()>;

    /// The cursor `signer` last acknowledged in mailbox `addr`.
    ///
    /// # Errors
    ///
    /// A storage failure.
    fn acked(&self, addr: &str, signer: &str) -> StoreResult<Option<u64>>;

    /// One sweep at `now`: deletes the mailbox rows expired at `now` and the pending rows past their `until`, then the
    /// envelopes whose rows have all expired, keeping a tombstone `(id, ts + replay_window)` for each whose
    /// `ts + replay_window` is not yet past; deletes the tombstones whose `until` is past, and the address and key
    /// records whose validity is past. `replay_window` is the relay TTL plus its skew: the oldest `ts` the `ts` window
    /// still takes. A store may go through a large sweep in several transactions, each whole, so that one wave of
    /// expired rows does not hold the store; a caller on the async runtime runs it off the workers.
    ///
    /// # Errors
    ///
    /// A storage failure; nothing of the transaction it fell in is deleted, and the next sweep takes up the rest.
    fn sweep(&self, now: u64, replay_window: u64) -> StoreResult<Swept>;

    /// The store's size now. A store that reports none fails, so that the `store-size` line says so.
    ///
    /// # Errors
    ///
    /// A storage failure, or a store that reports no size.
    fn size(&self) -> StoreResult<Size> {
        Err(StoreError("this store reports no size".into()))
    }

    /// [`Size::live`] alone, cheap enough for every publish: what `--max-store-bytes` bounds.
    ///
    /// # Errors
    ///
    /// A storage failure, or a store that reports no size.
    fn live_bytes(&self) -> StoreResult<u64> {
        self.size().map(|s| s.live)
    }

    /// The envelope id and recipient of up to `limit` pending rows live at `now` (`until > now`), the earliest
    /// `until` first.
    ///
    /// # Errors
    ///
    /// A storage failure.
    fn pending(&self, now: u64, limit: usize) -> StoreResult<Vec<(String, String)>>;

    /// Deletes the pending row of `id` for `addr` and, with `deliver`, appends that mailbox's row expiring then, in
    /// one transaction: the new cursor, or `None` when nothing was appended (there was no such row).
    ///
    /// # Errors
    ///
    /// A storage failure; nothing is changed then.
    fn settle_pending(&self, id: &str, addr: &str, deliver: Option<u64>) -> StoreResult<Option<u64>>;

    /// The pin of `domain`. A store that keeps none fails, so that a `domain:` root never resolves without
    /// its pin.
    ///
    /// # Errors
    ///
    /// A storage failure, or [`no_domain_pins`] for a store without them.
    fn domain_pin(&self, _domain: &str) -> StoreResult<Option<DomainPin>> {
        Err(no_domain_pins())
    }

    /// Stores the pin of `pin.domain`, replacing the one there.
    ///
    /// # Errors
    ///
    /// A storage failure, or [`no_domain_pins`] for a store without them.
    fn put_domain_pin(&self, _pin: &DomainPin) -> StoreResult<()> {
        Err(no_domain_pins())
    }

    /// Deletes the pin of `domain` and returns it, `None` when there was none: the operator's override
    /// (`ac-relay --pin-reset`), for an organization that lost its key and its rotation key.
    ///
    /// # Errors
    ///
    /// A storage failure, or [`no_domain_pins`] for a store without them.
    fn delete_domain_pin(&self, _domain: &str) -> StoreResult<Option<DomainPin>> {
        Err(no_domain_pins())
    }
}

#[cfg(test)]
mod tests;
