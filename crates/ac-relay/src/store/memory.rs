//! The in-memory store, for unit tests. Same behaviour as the SQLite store, nothing persisted.

use super::{
    Delivery, DomainPin, MailboxEntry, NewEnvelope, Store, StoreResult, StoredEnvelope, StoredRecord, Swept,
    revoked_of,
};
use ac_core::records::Kind;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Mutex, MutexGuard};

/// A stored envelope: its bytes, when its last row expires, its `ts`, and when the relay stored it.
#[derive(Debug)]
struct Stored {
    bytes: Vec<u8>,
    expires_at: u64,
    ts: u64,
    received_at: u64,
}

#[derive(Debug, Default)]
struct State {
    envelopes: HashMap<String, Stored>,
    mailbox: BTreeMap<(String, u64), (String, u64)>,
    cursors: HashMap<String, u64>,
    acks: HashMap<(String, String), u64>,
    records: HashMap<(String, Kind), (StoredRecord, Option<u64>)>,
    tombstones: HashMap<String, u64>,
    pins: HashMap<String, DomainPin>,
    pending: BTreeSet<(u64, String, String)>,
    /// The revoked list kept for each key, with the `iat` of the address record it came from.
    revoked: HashMap<String, (u64, Vec<String>)>,
}

impl State {
    fn tombstoned(&self, id: &str, now: u64) -> bool {
        self.tombstones.get(id).is_some_and(|until| *until >= now)
    }

    fn append(&mut self, addr: &str, id: &str, expires_at: u64) -> u64 {
        let next = self.cursors.entry(addr.to_owned()).or_insert(1);
        let cursor = *next;
        *next += 1;
        self.mailbox.insert((addr.to_owned(), cursor), (id.to_owned(), expires_at));
        cursor
    }
}

/// The in-memory store.
#[derive(Debug, Default)]
pub struct MemoryStore(Mutex<State>);

impl MemoryStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> MemoryStore {
        MemoryStore::default()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        // Every update completes under the lock or not at all, so a panic elsewhere leaves a usable state.
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Store for MemoryStore {
    fn record(&self, addr: &str, kind: Kind) -> StoreResult<Option<StoredRecord>> {
        Ok(self.state().records.get(&(addr.to_owned(), kind)).map(|(r, _)| r.clone()))
    }

    fn put_record(
        &self,
        addr: &str,
        kind: Kind,
        iat: u64,
        expires_at: Option<u64>,
        bytes: &[u8],
    ) -> StoreResult<bool> {
        let mut s = self.state();
        let key = (addr.to_owned(), kind);
        if s.records.get(&key).is_some_and(|(r, _)| r.iat >= iat) {
            return Ok(false);
        }
        s.records.insert(key, (StoredRecord { iat, bytes: bytes.to_vec() }, expires_at));
        if kind == Kind::Address && s.revoked.get(addr).is_none_or(|(kept, _)| *kept < iat) {
            s.revoked.insert(addr.to_owned(), (iat, revoked_of(bytes)));
        }
        Ok(true)
    }

    fn revoked(&self, addr: &str) -> StoreResult<Vec<String>> {
        Ok(self.state().revoked.get(addr).map(|(_, keys)| keys.clone()).unwrap_or_default())
    }

    fn has_records(&self, addr: &str) -> StoreResult<bool> {
        Ok(self.state().records.keys().any(|(a, _)| a == addr))
    }

    fn has_envelope(&self, id: &str, now: u64) -> StoreResult<bool> {
        let s = self.state();
        Ok(s.envelopes.contains_key(id) || s.tombstoned(id, now))
    }

    fn insert_envelope(
        &self,
        env: &NewEnvelope<'_>,
        deliveries: &[Delivery],
    ) -> StoreResult<Option<Vec<u64>>> {
        let mut s = self.state();
        if s.envelopes.contains_key(env.id) || s.tombstoned(env.id, env.received_at) {
            return Ok(None);
        }
        let expires_at =
            deliveries.iter().chain(env.pending).map(|d| d.expires_at).max().unwrap_or(env.received_at);
        let stored =
            Stored { bytes: env.bytes.to_vec(), expires_at, ts: env.ts, received_at: env.received_at };
        s.envelopes.insert(env.id.to_owned(), stored);
        let cursors = deliveries.iter().map(|d| s.append(&d.addr, env.id, d.expires_at)).collect();
        for p in env.pending {
            s.pending.insert((p.expires_at, env.id.to_owned(), p.addr.clone()));
        }
        Ok(Some(cursors))
    }

    fn envelope(&self, id: &str, now: u64) -> StoreResult<Option<StoredEnvelope>> {
        Ok(self
            .state()
            .envelopes
            .get(id)
            .filter(|e| e.expires_at > now)
            .map(|e| StoredEnvelope { bytes: e.bytes.clone(), received_at: e.received_at }))
    }

    fn mailbox_after(
        &self,
        addr: &str,
        after: u64,
        limit: usize,
        now: u64,
    ) -> StoreResult<Vec<MailboxEntry>> {
        let s = self.state();
        let start = (addr.to_owned(), after.saturating_add(1));
        let end = (addr.to_owned(), u64::MAX);
        Ok(s.mailbox
            .range(start..=end)
            .filter(|(_, (_, exp))| *exp > now)
            .filter_map(|((_, cursor), (id, _))| {
                s.envelopes.get(id).map(|e| MailboxEntry {
                    cursor: *cursor,
                    bytes: e.bytes.clone(),
                    received_at: e.received_at,
                })
            })
            .take(limit)
            .collect())
    }

    fn last_cursor(&self, addr: &str) -> StoreResult<u64> {
        Ok(self.state().cursors.get(addr).map_or(0, |next| next - 1))
    }

    fn ack(&self, addr: &str, signer: &str, cursor: u64) -> StoreResult<()> {
        let mut s = self.state();
        let entry = s.acks.entry((addr.to_owned(), signer.to_owned())).or_insert(cursor);
        *entry = (*entry).max(cursor);
        Ok(())
    }

    fn acked(&self, addr: &str, signer: &str) -> StoreResult<Option<u64>> {
        Ok(self.state().acks.get(&(addr.to_owned(), signer.to_owned())).copied())
    }

    fn sweep(&self, now: u64, replay_window: u64) -> StoreResult<Swept> {
        let mut s = self.state();
        let before = s.mailbox.len();
        s.mailbox.retain(|_, (_, exp)| *exp > now);
        let mailbox = before - s.mailbox.len();
        let before = s.pending.len();
        s.pending.retain(|(until, ..)| *until > now);
        let pending = before - s.pending.len();
        let before = s.tombstones.len();
        s.tombstones.retain(|_, until| *until >= now);
        let tombstones_expired = before - s.tombstones.len();
        let live: HashSet<String> = s.mailbox.values().map(|(id, _)| id.clone()).collect();
        let gone: Vec<(String, u64)> = s
            .envelopes
            .iter()
            .filter(|(id, e)| e.expires_at <= now && !live.contains(*id))
            .map(|(id, e)| (id.clone(), e.ts))
            .collect();
        let mut tombstoned = 0;
        for (id, ts) in &gone {
            s.envelopes.remove(id);
            let until = ts.saturating_add(replay_window);
            if until >= now {
                s.tombstones.insert(id.clone(), until);
                tombstoned += 1;
            }
        }
        let before = s.records.len();
        s.records.retain(|_, (_, expires_at)| expires_at.is_none_or(|e| e >= now));
        let records = before - s.records.len();
        Ok(Swept { mailbox, envelopes: gone.len(), tombstoned, tombstones_expired, records, pending })
    }

    fn pending(&self, now: u64, limit: usize) -> StoreResult<Vec<(String, String)>> {
        let s = self.state();
        let live = s.pending.iter().filter(|(until, ..)| *until > now).take(limit);
        Ok(live.map(|(_, i, a)| (i.clone(), a.clone())).collect())
    }

    fn settle_pending(&self, id: &str, addr: &str, deliver: Option<u64>) -> StoreResult<Option<u64>> {
        let mut s = self.state();
        let before = s.pending.len();
        s.pending.retain(|(_, i, a)| (i.as_str(), a.as_str()) != (id, addr));
        Ok(match deliver {
            Some(expires_at) if s.pending.len() < before => Some(s.append(addr, id, expires_at)),
            _ => None,
        })
    }

    fn domain_pin(&self, domain: &str) -> StoreResult<Option<DomainPin>> {
        Ok(self.state().pins.get(domain).cloned())
    }

    fn put_domain_pin(&self, pin: &DomainPin) -> StoreResult<()> {
        self.state().pins.insert(pin.domain.clone(), pin.clone());
        Ok(())
    }

    fn delete_domain_pin(&self, domain: &str) -> StoreResult<Option<DomainPin>> {
        Ok(self.state().pins.remove(domain))
    }
}
