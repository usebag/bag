//! The sweep finds what expired through indexes, so with nothing expired it holds the
//! store's write lock for almost nothing however many envelopes are stored (the full scan it replaces held
//! it 558 to 588 ms at 300,000), and a tombstone row is small (170 bytes with a hex id and an expiry index).
//!
//! The test stores 300,000 envelopes, the line's number: it takes about 6 s in a debug build (4 s in release), under
//! the 30 s past which it would be run by hand. `AC_SWEEP_LOCK_ROWS` sets another number, for a reading at
//! another size:
//!
//! ```text
//! AC_SWEEP_LOCK_ROWS=30000 cargo test --release --locked -p ac-relay --test hardening_sweep -- --nocapture
//! ```
//!
//! Rows are written with one transaction through a second connection on the store's own schema (the store writes one
//! transaction per envelope, which only makes the setup slower); the timed call is the store's `sweep`, which holds
//! the store's mutex and one `BEGIN IMMEDIATE` to `COMMIT`.

mod common;

use ac_relay::store::sqlite::SqliteStore;
use ac_relay::store::{Store as _, Swept};
use common::{NOW, TempDir};
use rusqlite::{Connection, params};
use std::path::Path;
use std::time::{Duration, Instant};

/// The bound: a tenth of the 558 ms the full scan held the lock.
const LOCK_BOUND: Duration = Duration::from_millis(56);

fn rows() -> u64 {
    std::env::var("AC_SWEEP_LOCK_ROWS").ok().and_then(|v| v.parse().ok()).unwrap_or(300_000)
}

/// Stores `n` envelopes of 2,048 bytes, one mailbox row each, none expiring before `NOW + 86,400`.
fn fill(path: &Path, n: u64) {
    let mut c = Connection::open(path).unwrap();
    let tx = c.transaction().unwrap();
    {
        let bytes = vec![b'x'; 2_048];
        let mut envelope = tx
            .prepare(
                "INSERT INTO envelopes (id, bytes, from_addr, root, ts, size, received_at, expires_at)
                 VALUES (?1, ?2, 'ed25519:f', 'ed25519:r', ?3, 2048, ?3, ?4)",
            )
            .unwrap();
        let mut row = tx
            .prepare("INSERT INTO mailbox (addr, cursor, id, expires_at) VALUES ('m', ?1, ?2, ?3)")
            .unwrap();
        for i in 0..n {
            let id = format!("{i:064x}");
            let ts = i64::try_from(NOW - 60).unwrap();
            let expires_at = i64::try_from(NOW + 86_400 + i).unwrap();
            envelope.execute(params![id, bytes, ts, expires_at]).unwrap();
            row.execute(params![i64::try_from(i + 1).unwrap(), id, expires_at]).unwrap();
        }
        tx.execute(
            "INSERT INTO cursors (addr, next) VALUES ('m', ?1)",
            params![i64::try_from(n + 1).unwrap()],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
}

#[test]
fn l4_the_sweep_holds_its_lock_at_most_56_ms_with_nothing_expired() {
    let n = rows();
    let dir = TempDir::new("sweep-lock");
    let path = dir.path().join("relay.sqlite");
    let store = SqliteStore::open(&path).unwrap();
    let started = Instant::now();
    fill(&path, n);
    let filled = started.elapsed();
    let c = Connection::open(&path).unwrap();
    let count: i64 = c.query_row("SELECT count(*) FROM envelopes", [], |r| r.get(0)).unwrap();
    assert_eq!(u64::try_from(count).unwrap(), n);
    let bytes = std::fs::metadata(&path).unwrap().len();
    // The plan: each delete and the tombstone insert search an expiry index; none scans a table.
    let plan = |sql: &str| -> String {
        let mut stmt = c.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        let rows = stmt.query_map(params![1, 1], |r| r.get::<_, String>(3)).unwrap();
        rows.map(Result::unwrap).collect::<Vec<_>>().join("; ")
    };
    let unreferenced =
        "expires_at <= ?1 AND NOT EXISTS (SELECT 1 FROM mailbox WHERE mailbox.id = envelopes.id)";
    let chunk =
        format!("SELECT rowid FROM envelopes WHERE {unreferenced} ORDER BY expires_at, rowid LIMIT ?2");
    let plans = [
        plan(
            "DELETE FROM mailbox WHERE rowid IN (SELECT rowid FROM mailbox WHERE expires_at <= ?1 LIMIT ?2)",
        ),
        plan(&format!("DELETE FROM envelopes WHERE rowid IN ({chunk})")),
        plan(&format!("SELECT id, ts + 1 FROM envelopes WHERE rowid IN ({chunk}) AND ts + ?2 >= ?1")),
        plan("DELETE FROM tombstones WHERE id IN (SELECT id FROM tombstones WHERE until < ?1 LIMIT ?2)"),
        plan("DELETE FROM records WHERE rowid IN (SELECT rowid FROM records WHERE expires_at < ?1 LIMIT ?2)"),
    ];
    for (p, index) in plans.iter().zip([
        "mailbox_by_expiry",
        "envelopes_by_expiry",
        "envelopes_by_expiry",
        "tombstones_by_until",
        "records_by_expiry",
    ]) {
        assert!(
            p.contains(&format!("USING INDEX {index}"))
                || p.contains(&format!("USING COVERING INDEX {index}")),
            "{p}"
        );
        assert!(!p.contains("SCAN envelopes") && !p.contains("SCAN mailbox"), "{p}");
        assert!(!p.contains("TEMP B-TREE"), "the chunk's order is the index's: {p}");
    }
    let mut held = Vec::new();
    for _ in 0..5 {
        let t = Instant::now();
        let swept = store.sweep(NOW, 604_800 + 300).unwrap();
        held.push(t.elapsed());
        assert_eq!(swept, Swept::default(), "nothing expired");
    }
    // The hourly `store-size` line reads its numbers under the same lock; they match the fill and the file.
    let t = Instant::now();
    let size = store.size().unwrap();
    let sized = t.elapsed();
    assert_eq!((size.envelopes, size.mailbox, size.bytes), (n, n, bytes));
    eprintln!("MEASURE: store.size() at {n} envelopes: {sized:?}, {} bytes", size.bytes);
    held.sort();
    // M6 again on the same rows, for comparison only: the statement the index replaced, rolled back.
    let tx = c.unchecked_transaction().unwrap();
    let t = Instant::now();
    tx.execute(
        "DELETE FROM envelopes WHERE NOT EXISTS (SELECT 1 FROM mailbox WHERE mailbox.id = envelopes.id)",
        [],
    )
    .unwrap();
    let full_scan = t.elapsed();
    tx.rollback().unwrap();
    eprintln!(
        "MEASURE L4: {n} envelopes of 2,048 bytes ({bytes} bytes on disk, written in {filled:?}), nothing expired: \
         the sweep held its lock {:?} (median of 5), {:?} at most; the full scan it replaced: {full_scan:?}",
        held[2], held[4]
    );
    assert!(held[4] <= LOCK_BOUND, "the sweep held its lock {:?}", held[4]);
}

#[test]
fn l3_a_tombstone_row_costs_under_200_bytes() {
    let dir = TempDir::new("tombstone-size");
    let path = dir.path().join("relay.sqlite");
    let _store = SqliteStore::open(&path).unwrap();
    let c = Connection::open(&path).unwrap();
    let size = |c: &Connection| -> i64 {
        c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
        let pages: i64 = c.query_row("PRAGMA page_count", [], |r| r.get(0)).unwrap();
        let page: i64 = c.query_row("PRAGMA page_size", [], |r| r.get(0)).unwrap();
        pages * page
    };
    let before = size(&c);
    let n: i64 = 10_000;
    c.execute_batch("BEGIN").unwrap();
    for i in 0..n {
        // Ids are 32-byte hashes in hex, spread over the key space like real ones.
        let id = format!(
            "{:064x}",
            u128::try_from(i).unwrap().wrapping_mul(0x9e37_79b9_7f4a_7c15_f39c_c060_5ced_c835)
        );
        c.execute("INSERT INTO tombstones (id, until) VALUES (?1, ?2)", params![id, i + 1_800_000_000])
            .unwrap();
    }
    c.execute_batch("COMMIT").unwrap();
    let per_row = (size(&c) - before) / n;
    eprintln!(
        "MEASURE L3: {n} tombstones grew the database by {} bytes: {per_row} bytes a row",
        size(&c) - before
    );
    assert!(per_row < 200, "{per_row} bytes a tombstone row");
}
