//! The SQLite store (rusqlite with the bundled SQLite): WAL, foreign keys, STRICT tables, one connection behind a
//! mutex. Each call is one short statement or one transaction.
//!
//! The schema has a version, `PRAGMA user_version`: 1 is the first, 2 adds
//! `domain_pins`, 3 adds `tombstones`, the expiry indexes of `envelopes`, `records` and `tombstones`, and
//! `records.expires_at`, 4 adds `pending` (which a version 3 gains as it opens), 5 adds `revoked` (which an older
//! version gains as it opens, filled from its stored address records). Opening reads the version first: a newer one
//! is refused, so an older relay never writes a database it does not understand; an older one is migrated forward
//! in one transaction; 0 is a new file. The sweep finds what expired
//! through the expiry indexes, so with nothing expired it reads no row (the full scan it replaces held
//! the lock 558 ms at 300,000 envelopes).

use super::{
    Delivery, DomainPin, MailboxEntry, NewEnvelope, Size, Store, StoreError, StoreResult, StoredEnvelope,
    StoredRecord, Swept, expiry_of, revoked_of,
};
use ac_core::canonical::MAX_SAFE_INTEGER;
use ac_core::records::{Kind, Record};
use rusqlite::{Connection, OptionalExtension as _, Transaction, TransactionBehavior, params};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

/// The schema version this store reads and writes.
pub const SCHEMA_VERSION: i64 = 5;

/// The whole schema, every statement idempotent, so that opening a current database also restores a missing table.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS envelopes (
  id TEXT PRIMARY KEY,
  bytes BLOB NOT NULL,
  from_addr TEXT NOT NULL,
  root TEXT NOT NULL,
  ts INTEGER NOT NULL,
  size INTEGER NOT NULL,
  received_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS envelopes_by_expiry ON envelopes(expires_at);
CREATE TABLE IF NOT EXISTS mailbox (
  addr TEXT NOT NULL,
  cursor INTEGER NOT NULL,
  id TEXT NOT NULL REFERENCES envelopes(id),
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (addr, cursor)
) STRICT;
CREATE INDEX IF NOT EXISTS mailbox_by_id ON mailbox(id);
CREATE INDEX IF NOT EXISTS mailbox_by_expiry ON mailbox(expires_at);
CREATE TABLE IF NOT EXISTS cursors (
  addr TEXT PRIMARY KEY,
  next INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS acks (
  addr TEXT NOT NULL,
  signer TEXT NOT NULL,
  cursor INTEGER NOT NULL,
  PRIMARY KEY (addr, signer)
) STRICT;
CREATE TABLE IF NOT EXISTS records (
  addr TEXT NOT NULL,
  kind TEXT NOT NULL,
  iat INTEGER NOT NULL,
  bytes BLOB NOT NULL,
  expires_at INTEGER,
  PRIMARY KEY (addr, kind)
) STRICT;
CREATE INDEX IF NOT EXISTS records_by_expiry ON records(expires_at);
CREATE TABLE IF NOT EXISTS tombstones (
  id TEXT PRIMARY KEY,
  until INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS tombstones_by_until ON tombstones(until);
CREATE TABLE IF NOT EXISTS domain_pins (
  domain TEXT PRIMARY KEY,
  key TEXT NOT NULL,
  record_bytes BLOB NOT NULL,
  pinned_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS pending (id TEXT NOT NULL, addr TEXT NOT NULL, until INTEGER NOT NULL,
  PRIMARY KEY (id, addr)) STRICT, WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS pending_by_until ON pending(until);
CREATE TABLE IF NOT EXISTS revoked (addr TEXT PRIMARY KEY, iat INTEGER NOT NULL, keys TEXT NOT NULL)
  STRICT, WITHOUT ROWID;
PRAGMA user_version = 5;
";

/// How far [`SqliteStore::raise_after_restore`] raises a mailbox's next cursor: past any mail it took between a copy's
/// time and the loss, which is seconds of mail at the relay's rates.
pub const RESTORE_CURSOR_GAP: u64 = 1 << 20;

/// The database's `application_id` once its volume has been marked: "ac01". It is not the schema, so a build that does
/// not know it opens the file as before.
const MARKED: i64 = 0x6163_3031;

/// The most rows of each kind one transaction of a sweep deletes (LN2-L8), as the retry of pending rows bounds its own:
/// rows that expire together, which a client can arrange, leave the store's lock free between transactions.
const SWEEP_CHUNK: usize = 256;

/// The pause between two transactions of one sweep. The store's mutex is not fair, so without it this thread could take
/// the lock straight back from a call already waiting for it.
const SWEEP_PAUSE: Duration = Duration::from_millis(1);

/// The SQLite store.
#[derive(Debug)]
pub struct SqliteStore(Mutex<Connection>);

fn err(e: impl std::fmt::Display) -> StoreError {
    StoreError(e.to_string())
}

/// A u64 as SQLite's i64. Every stored integer is at most 2^53 - 1 or a cursor, so this never fails in practice.
fn int(n: u64) -> StoreResult<i64> {
    i64::try_from(n).map_err(err)
}

fn uint(n: i64) -> StoreResult<u64> {
    u64::try_from(n).map_err(err)
}

/// One number from a query of one row and one column.
fn number(conn: &Connection, sql: &str) -> StoreResult<u64> {
    uint(conn.query_row(sql, [], |r| r.get(0)).map_err(err)?)
}

/// The database's bytes, and the bytes of them in use: the pages in use are those not on the free list.
fn pages(conn: &Connection) -> StoreResult<(u64, u64)> {
    let page = number(conn, "PRAGMA page_size")?;
    let (all, free) = (number(conn, "PRAGMA page_count")?, number(conn, "PRAGMA freelist_count")?);
    Ok((all.saturating_mul(page), all.saturating_sub(free).saturating_mul(page)))
}

/// Versions 1 and 2 to 3: the record expiry column, filled from each stored record (a record that does not parse
/// keeps none and is never swept); the indexes and the tombstone table come with [`SCHEMA`].
fn migrate_to_3(tx: &Transaction<'_>) -> StoreResult<()> {
    tx.execute_batch("ALTER TABLE records ADD COLUMN expires_at INTEGER;").map_err(err)?;
    let rows: Vec<(String, String, Vec<u8>)> = {
        let mut stmt = tx.prepare("SELECT addr, kind, bytes FROM records").map_err(err)?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).map_err(err)?;
        rows.collect::<Result<_, _>>().map_err(err)?
    };
    for (addr, kind, bytes) in rows {
        let expires_at = Record::parse(&bytes).ok().as_ref().and_then(expiry_of).map(int).transpose()?;
        tx.execute(
            "UPDATE records SET expires_at = ?3 WHERE addr = ?1 AND kind = ?2",
            params![addr, kind, expires_at],
        )
        .map_err(err)?;
    }
    Ok(())
}

/// Keeps the `revoked` list of an address record stored as the newest of its key, its keys joined by spaces:
/// it replaces the list kept for that key only from a newer `iat`, so an older record published once the sweep has
/// deleted the newer one cannot shorten it.
fn keep_list(tx: &Transaction<'_>, addr: &str, iat: u64, bytes: &[u8]) -> StoreResult<()> {
    tx.execute(
        "INSERT INTO revoked (addr, iat, keys) VALUES (?1, ?2, ?3) ON CONFLICT (addr) DO UPDATE
         SET iat = excluded.iat, keys = excluded.keys WHERE excluded.iat > revoked.iat",
        params![addr, int(iat)?, revoked_of(bytes).join(" ")],
    )
    .map_err(err)?;
    Ok(())
}

/// Versions 1 to 4 to 5: the list of every stored address record, kept as [`keep_list`] keeps it.
fn migrate_to_5(tx: &Transaction<'_>) -> StoreResult<()> {
    let rows: Vec<(String, i64, Vec<u8>)> = {
        let mut stmt = tx.prepare("SELECT addr, iat, bytes FROM records WHERE kind = ?1").map_err(err)?;
        let rows = stmt
            .query_map(params![Kind::Address.as_str()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .map_err(err)?;
        rows.collect::<Result<_, _>>().map_err(err)?
    };
    for (addr, iat, bytes) in rows {
        keep_list(tx, &addr, uint(iat)?, &bytes)?;
    }
    Ok(())
}

/// Appends a row for envelope `id` to mailbox `addr`, at its next cursor, which it returns.
fn append(tx: &Transaction<'_>, addr: &str, id: &str, expires_at: u64) -> StoreResult<u64> {
    let cursor: i64 = tx
        .query_row(
            "INSERT INTO cursors (addr, next) VALUES (?1, 2)
             ON CONFLICT (addr) DO UPDATE SET next = next + 1 RETURNING next - 1",
            params![addr],
            |r| r.get(0),
        )
        .map_err(err)?;
    tx.execute(
        "INSERT INTO mailbox (addr, cursor, id, expires_at) VALUES (?1, ?2, ?3, ?4)",
        params![addr, cursor, id, int(expires_at)?],
    )
    .map_err(err)?;
    uint(cursor)
}

impl SqliteStore {
    /// Opens or creates the database at `path`, in WAL mode with foreign keys on, at schema version 5: a new file
    /// gets the schema, an older version is migrated forward, a newer one is refused.
    ///
    /// # Errors
    ///
    /// When the file cannot be opened, WAL cannot be set, its schema version is newer than
    /// [`SCHEMA_VERSION`] (or 0 with tables in it, so not a relay's), or the schema cannot be created or migrated.
    pub fn open(path: &Path) -> StoreResult<SqliteStore> {
        let mut conn = Connection::open(path).map_err(err)?;
        let mode: String =
            conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0)).map_err(err)?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(StoreError(format!("journal_mode is {mode}, not wal")));
        }
        conn.pragma_update(None, "foreign_keys", "ON").map_err(err)?;
        conn.pragma_update(None, "synchronous", "NORMAL").map_err(err)?;
        conn.busy_timeout(Duration::from_secs(5)).map_err(err)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(err)?;
        let version: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0)).map_err(err)?;
        if version > SCHEMA_VERSION {
            return Err(StoreError(format!(
                "the database's schema is version {version}, newer than this relay's {SCHEMA_VERSION}: run the \
                 ac-relay that wrote it, or a newer one"
            )));
        }
        if version == 0 {
            let tables: i64 = tx
                .query_row("SELECT count(*) FROM sqlite_master WHERE type = 'table'", [], |r| r.get(0))
                .map_err(err)?;
            if tables > 0 {
                return Err(StoreError(format!(
                    "the database holds {tables} tables and no schema version: not a relay's database"
                )));
            }
        } else if version < 3 {
            migrate_to_3(&tx)?;
        }
        tx.execute_batch(SCHEMA).map_err(err)?;
        if (1..5).contains(&version) {
            migrate_to_5(&tx)?;
        }
        tx.commit().map_err(err)?;
        Ok(SqliteStore(Mutex::new(conn)))
    }

    /// Raises every mailbox's next cursor if this database came from another volume, and returns how many mailboxes
    /// that was (spec/SPEC.md Appendix B item 102). A relay marks the two together on a first start: the database in its
    /// `application_id`, which a copy keeps, and the volume with the file `volume` beside it, which a copy leaves
    /// behind. A database marked with no file beside it, or the reverse, is a restore, and the mail to come must not
    /// take cursors the edges already hold for mail the copy never saw. Marking neither is a first start, and raises
    /// nothing. This is defence: an edge decides delivery by id, so a raise that is skipped or repeated loses nothing.
    ///
    /// # Errors
    ///
    /// When the database cannot be read or changed, or the file `volume` cannot be written.
    pub fn raise_after_restore(&self, volume: &Path) -> StoreResult<Option<usize>> {
        let conn = self.conn();
        let marked = conn.query_row("PRAGMA application_id", [], |r| r.get::<_, i64>(0)).map_err(err)? != 0;
        let on_volume = volume.exists();
        if marked && on_volume {
            return Ok(None);
        }
        let gap = int(RESTORE_CURSOR_GAP)?;
        let raised = (marked || on_volume)
            .then(|| conn.execute("UPDATE cursors SET next = next + ?1", params![gap]).map_err(err))
            .transpose()?;
        conn.execute_batch(&format!("PRAGMA application_id = {MARKED}")).map_err(err)?;
        std::fs::write(volume, b"").map_err(err)?;
        Ok(raised)
    }

    /// One transaction of a sweep, at most [`SWEEP_CHUNK`] rows of each kind; whether a kind may have more. An envelope
    /// is unreferenced only once its rows have gone, so the envelopes wait for the last chunk of rows: until then each
    /// pass would step over every envelope still referenced.
    pub(crate) fn sweep_chunk(&self, now: i64, window: i64) -> StoreResult<(Swept, bool)> {
        let chunk = i64::try_from(SWEEP_CHUNK).map_err(err)?;
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(err)?;
        let mailbox = tx
            .execute(
                "DELETE FROM mailbox WHERE rowid IN
                   (SELECT rowid FROM mailbox WHERE expires_at <= ?1 LIMIT ?2)",
                params![now, chunk],
            )
            .map_err(err)?;
        let pending = tx
            .execute(
                "DELETE FROM pending WHERE (id, addr) IN
                   (SELECT id, addr FROM pending WHERE until <= ?1 LIMIT ?2)",
                params![now, chunk],
            )
            .map_err(err)?;
        let tombstones_expired = tx
            .execute(
                "DELETE FROM tombstones WHERE id IN (SELECT id FROM tombstones WHERE until < ?1 LIMIT ?2)",
                params![now, chunk],
            )
            .map_err(err)?;
        let (mut tombstoned, mut envelopes) = (0, 0);
        if mailbox < SWEEP_CHUNK {
            // Ordered, so that the insert and the delete take the same rows.
            let unreferenced = "SELECT rowid FROM envelopes
                 WHERE expires_at <= ?1 AND NOT EXISTS (SELECT 1 FROM mailbox WHERE mailbox.id = envelopes.id)
                 ORDER BY expires_at, rowid LIMIT";
            tombstoned = tx
                .execute(
                    &format!(
                        "INSERT OR IGNORE INTO tombstones (id, until)
                         SELECT id, ts + ?2 FROM envelopes WHERE rowid IN ({unreferenced} ?3) AND ts + ?2 >= ?1"
                    ),
                    params![now, window, chunk],
                )
                .map_err(err)?;
            envelopes = tx
                .execute(
                    &format!("DELETE FROM envelopes WHERE rowid IN ({unreferenced} ?2)"),
                    params![now, chunk],
                )
                .map_err(err)?;
        }
        let records = tx
            .execute(
                "DELETE FROM records WHERE rowid IN (SELECT rowid FROM records WHERE expires_at < ?1 LIMIT ?2)",
                params![now, chunk],
            )
            .map_err(err)?;
        tx.commit().map_err(err)?;
        let more = [mailbox, pending, tombstones_expired, envelopes, records].contains(&SWEEP_CHUNK);
        Ok((Swept { mailbox, envelopes, tombstoned, tombstones_expired, records, pending }, more))
    }

    fn conn(&self) -> MutexGuard<'_, Connection> {
        // A transaction rolls back when a panic drops it, so the connection stays usable after one.
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Store for SqliteStore {
    fn record(&self, addr: &str, kind: Kind) -> StoreResult<Option<StoredRecord>> {
        let conn = self.conn();
        let row = conn
            .query_row(
                "SELECT iat, bytes FROM records WHERE addr = ?1 AND kind = ?2",
                params![addr, kind.as_str()],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(err)?;
        row.map(|(iat, bytes)| Ok(StoredRecord { iat: uint(iat)?, bytes })).transpose()
    }

    fn put_record(
        &self,
        addr: &str,
        kind: Kind,
        iat: u64,
        expires_at: Option<u64>,
        bytes: &[u8],
    ) -> StoreResult<bool> {
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(err)?;
        let changed = tx
            .execute(
                "INSERT INTO records (addr, kind, iat, bytes, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (addr, kind) DO UPDATE SET iat = excluded.iat, bytes = excluded.bytes,
                 expires_at = excluded.expires_at WHERE excluded.iat > records.iat",
                params![addr, kind.as_str(), int(iat)?, bytes, expires_at.map(int).transpose()?],
            )
            .map_err(err)?;
        if changed == 1 && kind == Kind::Address {
            keep_list(&tx, addr, iat, bytes)?;
        }
        tx.commit().map_err(err)?;
        Ok(changed == 1)
    }

    fn revoked(&self, addr: &str) -> StoreResult<Vec<String>> {
        let conn = self.conn();
        let keys: Option<String> = conn
            .query_row("SELECT keys FROM revoked WHERE addr = ?1", params![addr], |r| r.get(0))
            .optional()
            .map_err(err)?;
        Ok(keys.map(|k| k.split_whitespace().map(str::to_owned).collect()).unwrap_or_default())
    }

    fn has_records(&self, addr: &str) -> StoreResult<bool> {
        let conn = self.conn();
        conn.query_row("SELECT 1 FROM records WHERE addr = ?1 LIMIT 1", params![addr], |_| Ok(()))
            .optional()
            .map(|o| o.is_some())
            .map_err(err)
    }

    fn has_envelope(&self, id: &str, now: u64) -> StoreResult<bool> {
        let conn = self.conn();
        conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM envelopes WHERE id = ?1)
                 OR EXISTS (SELECT 1 FROM tombstones WHERE id = ?1 AND until >= ?2)",
            params![id, int(now)?],
            |r| r.get(0),
        )
        .map_err(err)
    }

    fn insert_envelope(
        &self,
        env: &NewEnvelope<'_>,
        deliveries: &[Delivery],
    ) -> StoreResult<Option<Vec<u64>>> {
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(err)?;
        let tombstoned: bool = tx
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM tombstones WHERE id = ?1 AND until >= ?2)",
                params![env.id, int(env.received_at)?],
                |r| r.get(0),
            )
            .map_err(err)?;
        if tombstoned {
            return Ok(None);
        }
        let held = deliveries.iter().chain(env.pending);
        let expires_at = held.map(|d| d.expires_at).max().unwrap_or(env.received_at);
        let size = int(u64::try_from(env.bytes.len()).map_err(err)?)?;
        let inserted = tx
            .execute(
                "INSERT INTO envelopes (id, bytes, from_addr, root, ts, size, received_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) ON CONFLICT (id) DO NOTHING",
                params![
                    env.id,
                    env.bytes,
                    env.from,
                    env.root,
                    int(env.ts)?,
                    size,
                    int(env.received_at)?,
                    int(expires_at)?
                ],
            )
            .map_err(err)?;
        if inserted == 0 {
            return Ok(None);
        }
        let mut cursors = Vec::with_capacity(deliveries.len());
        for d in deliveries {
            cursors.push(append(&tx, &d.addr, env.id, d.expires_at)?);
        }
        for p in env.pending {
            tx.execute(
                "INSERT OR IGNORE INTO pending (id, addr, until) VALUES (?1, ?2, ?3)",
                params![env.id, p.addr, int(p.expires_at)?],
            )
            .map_err(err)?;
        }
        tx.commit().map_err(err)?;
        Ok(Some(cursors))
    }

    fn envelope(&self, id: &str, now: u64) -> StoreResult<Option<StoredEnvelope>> {
        let conn = self.conn();
        let row = conn
            .query_row(
                "SELECT bytes, received_at FROM envelopes WHERE id = ?1 AND expires_at > ?2",
                params![id, int(now)?],
                |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(err)?;
        row.map(|(bytes, received_at)| Ok(StoredEnvelope { bytes, received_at: uint(received_at)? }))
            .transpose()
    }

    fn mailbox_after(
        &self,
        addr: &str,
        after: u64,
        limit: usize,
        now: u64,
    ) -> StoreResult<Vec<MailboxEntry>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare_cached(
                "SELECT m.cursor, e.bytes, e.received_at FROM mailbox m JOIN envelopes e ON e.id = m.id
                 WHERE m.addr = ?1 AND m.cursor > ?2 AND m.expires_at > ?3 ORDER BY m.cursor LIMIT ?4",
            )
            .map_err(err)?;
        let limit = int(u64::try_from(limit).map_err(err)?)?;
        let rows = stmt
            .query_map(params![addr, int(after)?, int(now)?, limit], |r| {
                Ok((r.get::<_, i64>(0)?, r.get(1)?, r.get::<_, i64>(2)?))
            })
            .map_err(err)?;
        rows.map(|row| {
            let (cursor, bytes, received_at) = row.map_err(err)?;
            Ok(MailboxEntry { cursor: uint(cursor)?, bytes, received_at: uint(received_at)? })
        })
        .collect()
    }

    fn last_cursor(&self, addr: &str) -> StoreResult<u64> {
        let conn = self.conn();
        let next: Option<i64> = conn
            .query_row("SELECT next FROM cursors WHERE addr = ?1", params![addr], |r| r.get(0))
            .optional()
            .map_err(err)?;
        next.map_or(Ok(0), |n| uint(n - 1))
    }

    fn ack(&self, addr: &str, signer: &str, cursor: u64) -> StoreResult<()> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO acks (addr, signer, cursor) VALUES (?1, ?2, ?3)
             ON CONFLICT (addr, signer) DO UPDATE SET cursor = excluded.cursor
             WHERE excluded.cursor > acks.cursor",
            params![addr, signer, int(cursor)?],
        )
        .map_err(err)?;
        Ok(())
    }

    fn acked(&self, addr: &str, signer: &str) -> StoreResult<Option<u64>> {
        let conn = self.conn();
        let cursor: Option<i64> = conn
            .query_row(
                "SELECT cursor FROM acks WHERE addr = ?1 AND signer = ?2",
                params![addr, signer],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        cursor.map(uint).transpose()
    }

    fn sweep(&self, now: u64, replay_window: u64) -> StoreResult<Swept> {
        let now = int(now)?;
        // ts is at most 2^53 - 1, so ts + window stays an integer; a longer window is no longer in effect.
        let window = i64::try_from(replay_window.min(MAX_SAFE_INTEGER)).unwrap_or(i64::MAX);
        let mut swept = Swept::default();
        loop {
            let (chunk, more) = self.sweep_chunk(now, window)?;
            swept.add(chunk);
            if !more {
                return Ok(swept);
            }
            std::thread::sleep(SWEEP_PAUSE);
        }
    }

    fn size(&self) -> StoreResult<Size> {
        let conn = self.conn();
        let (bytes, live) = pages(&conn)?;
        let n = |sql: &str| number(&conn, sql);
        Ok(Size {
            bytes,
            live,
            envelopes: n("SELECT count(*) FROM envelopes")?,
            mailbox: n("SELECT count(*) FROM mailbox")?,
            records: n("SELECT count(*) FROM records")?,
            pins: n("SELECT count(*) FROM domain_pins")?,
        })
    }

    fn live_bytes(&self) -> StoreResult<u64> {
        pages(&self.conn()).map(|(_, live)| live)
    }

    fn pending(&self, now: u64, limit: usize) -> StoreResult<Vec<(String, String)>> {
        let conn = self.conn();
        let sql = "SELECT id, addr FROM pending WHERE until > ?1 ORDER BY until, id, addr LIMIT ?2";
        let mut stmt = conn.prepare_cached(sql).map_err(err)?;
        let limit = int(u64::try_from(limit).map_err(err)?)?;
        let rows = stmt.query_map(params![int(now)?, limit], |r| Ok((r.get(0)?, r.get(1)?))).map_err(err)?;
        rows.collect::<Result<_, _>>().map_err(err)
    }

    fn settle_pending(&self, id: &str, addr: &str, deliver: Option<u64>) -> StoreResult<Option<u64>> {
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(err)?;
        let n =
            tx.execute("DELETE FROM pending WHERE id = ?1 AND addr = ?2", params![id, addr]).map_err(err)?;
        let cursor = match deliver {
            Some(expires_at) if n == 1 => Some(append(&tx, addr, id, expires_at)?),
            _ => None,
        };
        tx.commit().map_err(err)?;
        Ok(cursor)
    }

    fn domain_pin(&self, domain: &str) -> StoreResult<Option<DomainPin>> {
        let conn = self.conn();
        let row = conn
            .query_row(
                "SELECT key, record_bytes, pinned_at, expires_at FROM domain_pins WHERE domain = ?1",
                params![domain],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(err)?;
        row.map(|(key, record, pinned_at, expires_at)| {
            Ok(DomainPin {
                domain: domain.to_owned(),
                key,
                record,
                pinned_at: uint(pinned_at)?,
                expires_at: uint(expires_at)?,
            })
        })
        .transpose()
    }

    fn put_domain_pin(&self, pin: &DomainPin) -> StoreResult<()> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO domain_pins (domain, key, record_bytes, pinned_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (domain) DO UPDATE SET key = excluded.key, record_bytes = excluded.record_bytes,
             pinned_at = excluded.pinned_at, expires_at = excluded.expires_at",
            params![pin.domain, pin.key, pin.record, int(pin.pinned_at)?, int(pin.expires_at)?],
        )
        .map_err(err)?;
        Ok(())
    }

    fn delete_domain_pin(&self, domain: &str) -> StoreResult<Option<DomainPin>> {
        let pin = self.domain_pin(domain)?;
        if pin.is_some() {
            self.conn().execute("DELETE FROM domain_pins WHERE domain = ?1", params![domain]).map_err(err)?;
        }
        Ok(pin)
    }
}
