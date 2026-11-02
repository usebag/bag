//! One behavioural suite, run against both stores.

use super::memory::MemoryStore;
use super::sqlite::SCHEMA_VERSION;
use super::sqlite::{RESTORE_CURSOR_GAP, SqliteStore};
use super::{Delivery, DomainPin, MailboxEntry, NewEnvelope, Store, StoredEnvelope, Swept, expiry_of};
use crate::resolver::testkit::org_bytes;
use crate::testkit::{NOW, TempDir, accept, addr, address_record, record_bytes};
use ac_core::records::{Kind, Record, Roots};

fn env<'a>(id: &'a str, bytes: &'a [u8]) -> NewEnvelope<'a> {
    NewEnvelope {
        id,
        bytes,
        from: "ed25519:from",
        root: "ed25519:root",
        ts: 100,
        received_at: 100,
        pending: &[],
    }
}

fn to(addr: &str, expires_at: u64) -> Delivery {
    Delivery { addr: addr.into(), expires_at }
}

fn stored(bytes: &[u8], received_at: u64) -> StoredEnvelope {
    StoredEnvelope { bytes: bytes.to_vec(), received_at }
}

fn each_store(test: impl Fn(&dyn Store)) {
    test(&MemoryStore::new());
    let dir = TempDir::new("store");
    test(&SqliteStore::open(&dir.path().join("relay.sqlite")).unwrap());
}

#[test]
fn an_envelope_is_stored_once_with_one_row_per_recipient() {
    each_store(|s| {
        assert!(!s.has_envelope("e1", 100).unwrap());
        let cursors = s.insert_envelope(&env("e1", b"{1}"), &[to("a", 200), to("b", 150)]).unwrap();
        assert_eq!(cursors, Some(vec![1, 1]));
        assert!(s.has_envelope("e1", 100).unwrap());
        assert_eq!(s.insert_envelope(&env("e1", b"{other}"), &[to("a", 200)]).unwrap(), None);
        assert_eq!(s.envelope("e1", 100).unwrap(), Some(stored(b"{1}", 100)));
        assert_eq!(s.mailbox_after("a", 0, 10, 100).unwrap().len(), 1);
        assert_eq!(s.last_cursor("a").unwrap(), 1);
        assert_eq!(s.last_cursor("nobody").unwrap(), 0);
    });
}

/// Every read of an envelope returns the second the relay stored it, and a later insert of the same
/// id moves nothing, so a duplicate publish never restamps it.
#[test]
fn an_envelope_keeps_the_second_it_was_stored() {
    each_store(|s| {
        let first = NewEnvelope { received_at: 120, ..env("e1", b"{1}") };
        s.insert_envelope(&first, &[to("a", 1_000)]).unwrap();
        let again = NewEnvelope { received_at: 130, ..env("e1", b"{1}") };
        assert_eq!(s.insert_envelope(&again, &[to("a", 1_000), to("b", 1_000)]).unwrap(), None);
        assert_eq!(s.envelope("e1", 140).unwrap(), Some(stored(b"{1}", 120)));
        let row = MailboxEntry { cursor: 1, bytes: b"{1}".to_vec(), received_at: 120 };
        assert_eq!(s.mailbox_after("a", 0, 10, 140).unwrap(), vec![row]);
        assert!(s.mailbox_after("b", 0, 10, 140).unwrap().is_empty());
    });
}

#[test]
fn cursors_are_per_mailbox_and_only_grow() {
    each_store(|s| {
        for (i, id) in ["e1", "e2", "e3"].iter().enumerate() {
            let c = s.insert_envelope(&env(id, id.as_bytes()), &[to("a", 1_000)]).unwrap().unwrap();
            assert_eq!(c, vec![u64::try_from(i).unwrap() + 1]);
        }
        assert_eq!(
            s.insert_envelope(&env("e4", b"e4"), &[to("b", 1_000), to("a", 1_000)]).unwrap(),
            Some(vec![1, 4])
        );
        let rows = s.mailbox_after("a", 1, 10, 100).unwrap();
        assert_eq!(rows.iter().map(|r| r.cursor).collect::<Vec<_>>(), vec![2, 3, 4]);
        assert_eq!(rows[0].bytes, b"e2".to_vec());
        assert_eq!(s.mailbox_after("a", 0, 2, 100).unwrap().len(), 2);
        assert!(s.mailbox_after("a", 4, 10, 100).unwrap().is_empty());
        // Cursors keep growing after a sweep empties the mailbox.
        assert_eq!(s.sweep(1_000, 0).unwrap(), Swept { mailbox: 5, envelopes: 4, ..Swept::default() });
        assert_eq!(s.insert_envelope(&env("e5", b"e5"), &[to("a", 5_000)]).unwrap(), Some(vec![5]));
        assert_eq!(s.last_cursor("a").unwrap(), 5);
    });
}

#[test]
fn expired_rows_are_hidden_then_swept_with_their_orphans() {
    each_store(|s| {
        s.insert_envelope(&env("short", b"s"), &[to("a", 150)]).unwrap();
        s.insert_envelope(&env("shared", b"x"), &[to("a", 150), to("b", 300)]).unwrap();
        assert_eq!(s.mailbox_after("a", 0, 10, 149).unwrap().len(), 2);
        assert!(s.mailbox_after("a", 0, 10, 150).unwrap().is_empty());
        assert_eq!(s.envelope("short", 150).unwrap(), None);
        assert_eq!(s.envelope("shared", 150).unwrap(), Some(stored(b"x", 100)));
        assert_eq!(s.sweep(150, 0).unwrap(), Swept { mailbox: 2, envelopes: 1, ..Swept::default() });
        assert!(!s.has_envelope("short", 150).unwrap());
        assert!(s.has_envelope("shared", 150).unwrap());
        assert_eq!(s.mailbox_after("b", 0, 10, 150).unwrap().len(), 1);
        assert_eq!(s.sweep(300, 0).unwrap(), Swept { mailbox: 1, envelopes: 1, ..Swept::default() });
        assert_eq!(s.sweep(300, 0).unwrap(), Swept::default());
    });
}

#[test]
fn an_envelope_with_no_recipient_row_expires_at_once() {
    each_store(|s| {
        assert_eq!(s.insert_envelope(&env("none", b"n"), &[]).unwrap(), Some(vec![]));
        assert_eq!(s.envelope("none", 100).unwrap(), None);
        assert_eq!(s.sweep(100, 0).unwrap(), Swept { envelopes: 1, tombstoned: 1, ..Swept::default() });
    });
}

#[test]
fn acks_are_per_mailbox_and_signer_and_never_move_back() {
    each_store(|s| {
        assert_eq!(s.acked("a", "x").unwrap(), None);
        s.ack("a", "x", 5).unwrap();
        s.ack("a", "x", 3).unwrap();
        assert_eq!(s.acked("a", "x").unwrap(), Some(5));
        s.ack("a", "y", 1).unwrap();
        assert_eq!(s.acked("a", "y").unwrap(), Some(1));
        assert_eq!(s.acked("b", "x").unwrap(), None);
        s.ack("a", "x", 9).unwrap();
        assert_eq!(s.acked("a", "x").unwrap(), Some(9));
    });
}

#[test]
fn records_newer_iat_wins() {
    each_store(|s| {
        assert_eq!(s.record("a", Kind::AcceptFrom).unwrap(), None);
        assert!(s.put_record("a", Kind::AcceptFrom, 10, None, b"v10").unwrap());
        assert!(!s.put_record("a", Kind::AcceptFrom, 10, None, b"other").unwrap());
        assert!(!s.put_record("a", Kind::AcceptFrom, 9, None, b"v9").unwrap());
        assert_eq!(s.record("a", Kind::AcceptFrom).unwrap().unwrap().bytes, b"v10".to_vec());
        assert!(s.put_record("a", Kind::AcceptFrom, 11, None, b"v11").unwrap());
        let r = s.record("a", Kind::AcceptFrom).unwrap().unwrap();
        assert_eq!((r.iat, r.bytes), (11, b"v11".to_vec()));
        // Kinds are separate slots.
        assert_eq!(s.record("a", Kind::Key).unwrap(), None);
        assert!(s.put_record("a", Kind::Key, 1, Some(500), b"k").unwrap());
        assert_eq!(s.record("a", Kind::AcceptFrom).unwrap().unwrap().iat, 11);
    });
}

#[test]
fn sqlite_persists_across_reopen_in_wal_mode() {
    let dir = TempDir::new("reopen");
    let path = dir.path().join("relay.sqlite");
    {
        let s = SqliteStore::open(&path).unwrap();
        s.insert_envelope(&env("e1", b"{}"), &[to("a", 1_000)]).unwrap();
        s.put_record("a", Kind::AcceptFrom, 1, None, b"r").unwrap();
        s.ack("a", "x", 1).unwrap();
    }
    let s = SqliteStore::open(&path).unwrap();
    assert!(s.has_envelope("e1", 100).unwrap());
    assert_eq!(s.last_cursor("a").unwrap(), 1);
    assert_eq!(s.acked("a", "x").unwrap(), Some(1));
    assert!(s.record("a", Kind::AcceptFrom).unwrap().is_some());
    assert!(path.with_extension("sqlite-wal").exists());
}

/// A store at `path` holding `mails` envelopes for mailbox "a".
fn with_mail(path: &std::path::Path, mails: u8) -> SqliteStore {
    let s = SqliteStore::open(path).unwrap();
    for n in 0..mails {
        s.insert_envelope(&env(&format!("e{n}"), b"{}"), &[to("a", 1_000)]).unwrap();
    }
    s
}

#[test]
fn a_first_start_marks_the_store_and_its_volume_and_raises_nothing() {
    let dir = TempDir::new("mark-first");
    let (path, volume) = (dir.path().join("relay.sqlite"), dir.path().join("relay.sqlite.volume"));
    let s = with_mail(&path, 2);
    assert_eq!(s.raise_after_restore(&volume).unwrap(), None);
    assert!(volume.exists());
    assert_eq!(s.raise_after_restore(&volume).unwrap(), None, "a restart");
    assert_eq!(s.last_cursor("a").unwrap(), 2);
}

#[test]
fn a_copy_on_a_new_volume_raises_every_mailbox_once() {
    let (old, new) = (TempDir::new("mark-old"), TempDir::new("mark-new"));
    let path = old.path().join("relay.sqlite");
    {
        let s = with_mail(&path, 2);
        s.insert_envelope(&env("other", b"{}"), &[to("b", 1_000)]).unwrap();
        assert_eq!(s.raise_after_restore(&old.path().join("relay.sqlite.volume")).unwrap(), None);
    }
    let (copy, volume) = (new.path().join("relay.sqlite"), new.path().join("relay.sqlite.volume"));
    std::fs::copy(&path, &copy).unwrap();
    let s = SqliteStore::open(&copy).unwrap();
    assert_eq!(s.raise_after_restore(&volume).unwrap(), Some(2), "both mailboxes");
    assert!(volume.exists());
    s.insert_envelope(&env("after", b"{}"), &[to("a", 1_000)]).unwrap();
    assert_eq!(s.last_cursor("a").unwrap(), 3 + RESTORE_CURSOR_GAP);
    assert_eq!(s.raise_after_restore(&volume).unwrap(), None, "that boot alone");
}

#[test]
fn an_unmarked_store_on_a_marked_volume_is_a_restore_too() {
    let dir = TempDir::new("mark-older");
    let (path, volume) = (dir.path().join("relay.sqlite"), dir.path().join("relay.sqlite.volume"));
    std::fs::write(&volume, b"").unwrap();
    let s = with_mail(&path, 1);
    assert_eq!(s.raise_after_restore(&volume).unwrap(), Some(1));
    assert_eq!(s.raise_after_restore(&volume).unwrap(), None);
}

#[test]
fn a_volume_that_cannot_be_marked_is_reported() {
    let dir = TempDir::new("mark-refused");
    let s = with_mail(&dir.path().join("relay.sqlite"), 1);
    assert!(s.raise_after_restore(&dir.path().join("missing").join("relay.sqlite.volume")).is_err());
}

#[test]
fn sqlite_reports_an_unopenable_path() {
    let dir = TempDir::new("bad");
    let err = SqliteStore::open(&dir.path().join("missing").join("relay.sqlite")).unwrap_err();
    assert!(err.to_string().starts_with("store: "), "{err}");
}

/// A stored integer that is not unsigned, written by something other than this store, is a store failure on every read
/// that returns it, never a value: an envelope's `received_at` (every read returns it), the next cursor of
/// a mailbox, a record's `iat` and a pin's two times.
#[test]
fn sqlite_refuses_stored_integers_that_are_not_unsigned() {
    let dir = TempDir::new("unsigned");
    let path = dir.path().join("relay.sqlite");
    let s = SqliteStore::open(&path).unwrap();
    s.insert_envelope(&env("e1", b"{1}"), &[to("a", 1_000)]).unwrap();
    s.put_record("r", Kind::Key, 1, None, b"key").unwrap();
    let pin = DomainPin {
        domain: "acme.example".into(),
        key: "k".into(),
        record: b"{}".to_vec(),
        pinned_at: 1,
        expires_at: 2,
    };
    s.put_domain_pin(&pin).unwrap();
    let c = rusqlite::Connection::open(&path).unwrap();
    let set = |sql: &str| c.execute_batch(sql).unwrap();
    set("UPDATE envelopes SET received_at = -1;");
    assert!(s.envelope("e1", 100).is_err(), "an envelope's received_at");
    assert!(s.mailbox_after("a", 0, 10, 100).is_err(), "a mailbox row's received_at");
    set("UPDATE envelopes SET received_at = 100; UPDATE cursors SET next = -5;");
    assert_eq!(s.envelope("e1", 100).unwrap(), Some(stored(b"{1}", 100)));
    assert!(s.last_cursor("a").is_err(), "the next cursor");
    assert!(s.insert_envelope(&env("e2", b"{2}"), &[to("a", 1_000)]).is_err(), "a new row's cursor");
    assert!(!s.has_envelope("e2", 100).unwrap(), "nothing written");
    set("UPDATE records SET iat = -1;");
    assert!(s.record("r", Kind::Key).is_err(), "a record's iat");
    set("UPDATE domain_pins SET pinned_at = -1;");
    assert!(s.domain_pin("acme.example").is_err(), "a pin's pinned_at");
    set("UPDATE domain_pins SET pinned_at = 1, expires_at = -1;");
    assert!(s.domain_pin("acme.example").is_err(), "a pin's expires_at");
}

#[test]
fn sqlite_refuses_integers_beyond_i64() {
    let dir = TempDir::new("range");
    let s = SqliteStore::open(&dir.path().join("relay.sqlite")).unwrap();
    assert!(s.put_record("a", Kind::Key, u64::MAX, None, b"x").is_err());
    assert!(s.ack("a", "x", u64::MAX).is_err());
    assert!(s.envelope("e", u64::MAX).is_err());
}

#[test]
fn sqlite_reports_a_broken_database_on_every_call() {
    let dir = TempDir::new("broken");
    let path = dir.path().join("relay.sqlite");
    let s = SqliteStore::open(&path).unwrap();
    s.insert_envelope(&env("e1", b"{}"), &[to("a", 1_000)]).unwrap();
    // Another connection takes the tables away under the store.
    let other = rusqlite::Connection::open(&path).unwrap();
    other.execute_batch("DROP TABLE mailbox; DROP TABLE envelopes; DROP TABLE cursors; DROP TABLE acks; DROP TABLE records;").unwrap();
    assert!(s.record("a", Kind::Key).is_err());
    assert!(s.put_record("a", Kind::Key, 1, None, b"x").is_err());
    assert!(s.has_envelope("e1", 100).is_err());
    assert!(s.has_records("a").is_err());
    assert!(s.insert_envelope(&env("e2", b"{}"), &[to("a", 1_000)]).is_err());
    assert!(s.envelope("e1", 100).is_err());
    assert!(s.mailbox_after("a", 0, 10, 100).is_err());
    assert!(s.last_cursor("a").is_err());
    assert!(s.ack("a", "x", 1).is_err());
    assert!(s.acked("a", "x").is_err());
    assert!(s.sweep(100, 0).is_err());
    // Only the mailbox and cursor tables gone: the envelope row goes in, the transaction rolls back.
    let dir = TempDir::new("half");
    let path = dir.path().join("relay.sqlite");
    let s = SqliteStore::open(&path).unwrap();
    rusqlite::Connection::open(&path).unwrap().execute_batch("DROP TABLE mailbox;").unwrap();
    assert!(s.insert_envelope(&env("e3", b"{}"), &[to("a", 1_000)]).is_err());
    assert!(!s.has_envelope("e3", 100).unwrap());
    rusqlite::Connection::open(&path).unwrap().execute_batch("DROP TABLE cursors;").unwrap();
    assert!(s.insert_envelope(&env("e4", b"{}"), &[to("a", 1_000)]).is_err());
}

#[test]
fn sqlite_refuses_a_file_that_is_not_a_database() {
    let dir = TempDir::new("notdb");
    let path = dir.path().join("relay.sqlite");
    std::fs::write(&path, vec![0x55; 4_096]).unwrap();
    assert!(SqliteStore::open(&path).is_err());
}

fn pin(domain: &str, key: &str, expires_at: u64) -> DomainPin {
    DomainPin { domain: domain.into(), key: key.into(), record: b"{r}".to_vec(), pinned_at: 100, expires_at }
}

#[test]
fn domain_pins_are_one_per_domain_replaced_and_deleted() {
    each_store(|s| {
        assert_eq!(s.domain_pin("acme.example").unwrap(), None);
        s.put_domain_pin(&pin("acme.example", "k1", 200)).unwrap();
        s.put_domain_pin(&pin("globex.example", "g1", 300)).unwrap();
        assert_eq!(s.domain_pin("acme.example").unwrap(), Some(pin("acme.example", "k1", 200)));
        s.put_domain_pin(&DomainPin {
            record: b"{r2}".to_vec(),
            pinned_at: 150,
            ..pin("acme.example", "k2", 250)
        })
        .unwrap();
        let replaced = s.domain_pin("acme.example").unwrap().unwrap();
        assert_eq!(
            (replaced.key.as_str(), replaced.record, replaced.pinned_at),
            ("k2", b"{r2}".to_vec(), 150)
        );
        assert_eq!(s.delete_domain_pin("acme.example").unwrap().map(|p| p.key), Some("k2".into()));
        assert_eq!(s.delete_domain_pin("acme.example").unwrap(), None);
        assert_eq!(s.domain_pin("acme.example").unwrap(), None);
        assert_eq!(s.domain_pin("globex.example").unwrap().map(|p| p.expires_at), Some(300));
    });
}

#[test]
fn sqlite_keeps_domain_pins_across_reopen_and_reports_a_broken_table() {
    let dir = TempDir::new("pins");
    let path = dir.path().join("relay.sqlite");
    SqliteStore::open(&path).unwrap().put_domain_pin(&pin("acme.example", "k1", 200)).unwrap();
    let s = SqliteStore::open(&path).unwrap();
    assert_eq!(s.domain_pin("acme.example").unwrap(), Some(pin("acme.example", "k1", 200)));
    assert!(s.put_domain_pin(&pin("acme.example", "k1", u64::MAX)).is_err(), "beyond i64");
    rusqlite::Connection::open(&path).unwrap().execute_batch("DROP TABLE domain_pins;").unwrap();
    assert!(s.domain_pin("acme.example").is_err());
    assert!(s.put_domain_pin(&pin("acme.example", "k1", 200)).is_err());
    assert!(s.delete_domain_pin("acme.example").is_err());
    // A row whose integers SQLite holds but a u64 cannot: refused on read.
    let s = SqliteStore::open(&path).unwrap();
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch("INSERT INTO domain_pins VALUES ('bad.example', 'k', x'00', -1, 1);")
        .unwrap();
    assert!(s.domain_pin("bad.example").is_err());
}

#[test]
fn a_swept_envelope_leaves_a_tombstone_until_its_replay_window_ends() {
    each_store(|s| {
        // ts 100, its row expires at 150; the replay window (relay TTL plus skew) is 310 s: until 410.
        s.insert_envelope(&env("e1", b"{1}"), &[to("a", 150)]).unwrap();
        s.insert_envelope(&env("old", b"{o}"), &[to("a", 150)]).unwrap();
        assert_eq!(
            s.sweep(150, 310).unwrap(),
            Swept { mailbox: 2, envelopes: 2, tombstoned: 2, ..Swept::default() }
        );
        assert!(s.has_envelope("e1", 150).unwrap(), "the tombstone answers dedup");
        assert_eq!(s.envelope("e1", 150).unwrap(), None, "the bytes are gone");
        let replay = NewEnvelope { received_at: 200, ..env("e1", b"{1}") };
        assert_eq!(s.insert_envelope(&replay, &[to("a", 900)]).unwrap(), None, "not stored again");
        assert_eq!(s.last_cursor("a").unwrap(), 2);
        assert!(s.has_envelope("e1", 410).unwrap(), "through its until");
        assert_eq!(s.sweep(410, 310).unwrap(), Swept::default());
        assert_eq!(s.sweep(411, 310).unwrap(), Swept { tombstones_expired: 2, ..Swept::default() });
        assert!(!s.has_envelope("e1", 411).unwrap());
        // An envelope whose window is already past when it is swept leaves none.
        s.insert_envelope(&env("late", b"{l}"), &[to("a", 500)]).unwrap();
        assert_eq!(s.sweep(500, 310).unwrap(), Swept { mailbox: 1, envelopes: 1, ..Swept::default() });
        assert!(!s.has_envelope("late", 500).unwrap());
        // An expired tombstone not yet swept does not answer dedup, nor refuse an insert.
        s.insert_envelope(&env("e2", b"{2}"), &[to("a", 150)]).unwrap();
        assert_eq!(s.sweep(150, 310).unwrap().tombstoned, 1);
        assert!(!s.has_envelope("e2", 411).unwrap());
        let again = NewEnvelope { received_at: 411, ..env("e2", b"{2}") };
        assert_eq!(s.insert_envelope(&again, &[to("a", 900)]).unwrap(), Some(vec![5]));
    });
}

#[test]
fn a_replay_window_past_two_to_the_53_is_no_longer_in_effect() {
    each_store(|s| {
        s.insert_envelope(&env("e1", b"{1}"), &[to("a", 150)]).unwrap();
        assert_eq!(s.sweep(150, u64::MAX).unwrap().tombstoned, 1);
        assert!(s.has_envelope("e1", 1 << 52).unwrap());
    });
}

#[test]
fn address_and_key_records_are_swept_after_their_validity_and_accept_from_never() {
    each_store(|s| {
        assert!(!s.has_records("a").unwrap());
        assert!(s.put_record("a", Kind::Address, 100, Some(200), b"addr").unwrap());
        assert!(s.has_records("a").unwrap());
        assert!(s.put_record("a", Kind::Key, 100, Some(300), b"key").unwrap());
        assert!(s.put_record("a", Kind::AcceptFrom, 100, None, b"accept").unwrap());
        assert!(!s.has_records("b").unwrap());
        // Valid through its last second.
        assert_eq!(s.sweep(200, 0).unwrap(), Swept::default());
        assert_eq!(s.sweep(201, 0).unwrap(), Swept { records: 1, ..Swept::default() });
        assert_eq!(s.record("a", Kind::Address).unwrap(), None);
        assert!(s.record("a", Kind::Key).unwrap().is_some());
        // A newer record replaces the expiry with its own.
        assert!(s.put_record("a", Kind::Key, 150, Some(1_000), b"key2").unwrap());
        assert_eq!(s.sweep(301, 0).unwrap(), Swept::default());
        assert_eq!(s.sweep(1_001, 0).unwrap(), Swept { records: 1, ..Swept::default() });
        assert_eq!(s.sweep(u64::from(u32::MAX), 0).unwrap(), Swept::default());
        assert_eq!(s.record("a", Kind::AcceptFrom).unwrap().unwrap().bytes, b"accept".to_vec());
        assert!(s.has_records("a").unwrap());
    });
}

#[test]
fn the_expiry_of_a_record_is_iat_plus_ttl_exp_or_none() {
    assert_eq!(expiry_of(&address_record(5, NOW, None)), Some(NOW + 3_600));
    assert_eq!(expiry_of(&accept(5, Roots::Any, 1, 60, NOW)), None);
    let mut key = Record::Key(ac_core::records::KeyRecord {
        key: crate::testkit::addr(6),
        sealing_key: "bb".repeat(32),
        iat: NOW,
        exp: NOW + 60,
        sig: [0; 64],
    });
    key.sign(&crate::testkit::key(6)).unwrap();
    assert_eq!(expiry_of(&key), Some(NOW + 60));
}

/// The schema at `user_version` 2, as an earlier relay wrote it; version 1 lacks `domain_pins`.
const SCHEMA_V2: &str = "
CREATE TABLE envelopes (id TEXT PRIMARY KEY, bytes BLOB NOT NULL, from_addr TEXT NOT NULL, root TEXT NOT NULL,
  ts INTEGER NOT NULL, size INTEGER NOT NULL, received_at INTEGER NOT NULL, expires_at INTEGER NOT NULL) STRICT;
CREATE TABLE mailbox (addr TEXT NOT NULL, cursor INTEGER NOT NULL, id TEXT NOT NULL REFERENCES envelopes(id),
  expires_at INTEGER NOT NULL, PRIMARY KEY (addr, cursor)) STRICT;
CREATE INDEX mailbox_by_id ON mailbox(id);
CREATE INDEX mailbox_by_expiry ON mailbox(expires_at);
CREATE TABLE cursors (addr TEXT PRIMARY KEY, next INTEGER NOT NULL) STRICT;
CREATE TABLE acks (addr TEXT NOT NULL, signer TEXT NOT NULL, cursor INTEGER NOT NULL, PRIMARY KEY (addr, signer)) STRICT;
CREATE TABLE records (addr TEXT NOT NULL, kind TEXT NOT NULL, iat INTEGER NOT NULL, bytes BLOB NOT NULL,
  PRIMARY KEY (addr, kind)) STRICT;
";
const PINS_V2: &str =
    "CREATE TABLE domain_pins (domain TEXT PRIMARY KEY, key TEXT NOT NULL, record_bytes BLOB NOT NULL,
  pinned_at INTEGER NOT NULL, expires_at INTEGER NOT NULL) STRICT;";

fn user_version(path: &std::path::Path) -> i64 {
    rusqlite::Connection::open(path).unwrap().query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap()
}

/// A database of `version` with an envelope, its row, three records (an address record, an accept-from record and
/// bytes that are not a record) and, from version 2, a pin.
fn old_database(path: &std::path::Path, version: i64) {
    let c = rusqlite::Connection::open(path).unwrap();
    c.execute_batch(SCHEMA_V2).unwrap();
    if version >= 2 {
        c.execute_batch(PINS_V2).unwrap();
        c.execute_batch("INSERT INTO domain_pins VALUES ('acme.example', 'k1', x'7b7d', 1, 2);").unwrap();
    }
    c.execute_batch(
        "INSERT INTO envelopes VALUES ('e1', x'7b7d', 'f', 'r', 100, 2, 100, 150);
         INSERT INTO mailbox VALUES ('a', 1, 'e1', 150);
         INSERT INTO cursors VALUES ('a', 2);",
    )
    .unwrap();
    let address = record_bytes(&address_record(5, NOW, None));
    let accepting = record_bytes(&accept(6, Roots::Any, 1, 60, NOW));
    for (addr, kind, bytes) in
        [("five", "address", address), ("six", "accept-from", accepting), ("bad", "key", b"{".to_vec())]
    {
        c.execute("INSERT INTO records VALUES (?1, ?2, 1, ?3)", rusqlite::params![addr, kind, bytes])
            .unwrap();
    }
    c.pragma_update(None, "user_version", version).unwrap();
}

#[test]
fn sqlite_migrates_versions_1_and_2_forward_keeping_their_rows() {
    for version in [1, 2] {
        let dir = TempDir::new("migrate");
        let path = dir.path().join("relay.sqlite");
        old_database(&path, version);
        let s = SqliteStore::open(&path).unwrap();
        assert_eq!(user_version(&path), SCHEMA_VERSION);
        assert_eq!(SCHEMA_VERSION, 5);
        assert!(s.has_envelope("e1", 100).unwrap());
        assert_eq!(s.mailbox_after("a", 0, 10, 100).unwrap().len(), 1);
        assert_eq!(s.domain_pin("acme.example").unwrap().is_some(), version == 2, "version {version}");
        let c = rusqlite::Connection::open(&path).unwrap();
        let expiry = |addr: &str| -> Option<i64> {
            c.query_row("SELECT expires_at FROM records WHERE addr = ?1", [addr], |r| r.get(0)).unwrap()
        };
        assert_eq!(expiry("five"), Some(i64::try_from(NOW + 3_600).unwrap()), "an address record: iat + ttl");
        assert_eq!(expiry("six"), None, "an accept-from record does not expire");
        assert_eq!(expiry("bad"), None, "bytes that are not a record are kept and never swept");
        // The migrated database sweeps: the row expired at 150, the envelope becomes a tombstone.
        assert_eq!(
            s.sweep(150, 310).unwrap(),
            Swept { mailbox: 1, envelopes: 1, tombstoned: 1, ..Swept::default() }
        );
        assert_eq!(
            s.sweep(NOW + 3_601, 310).unwrap(),
            Swept { tombstones_expired: 1, records: 1, ..Swept::default() }
        );
        drop(s);
        // Opening it again changes nothing.
        let again = SqliteStore::open(&path).unwrap();
        assert_eq!(user_version(&path), 5);
        assert!(again.record("six", Kind::AcceptFrom).unwrap().is_some());
    }
}

#[test]
fn sqlite_refuses_a_newer_schema_and_tables_without_a_version() {
    let dir = TempDir::new("newer");
    let path = dir.path().join("relay.sqlite");
    SqliteStore::open(&path).unwrap();
    rusqlite::Connection::open(&path).unwrap().pragma_update(None, "user_version", 6).unwrap();
    let refused = SqliteStore::open(&path).unwrap_err().to_string();
    assert!(refused.contains("version 6, newer than this relay's 5"), "{refused}");
    assert_eq!(user_version(&path), 6, "left as it was");
    let foreign = dir.path().join("other.sqlite");
    rusqlite::Connection::open(&foreign).unwrap().execute_batch("CREATE TABLE t (x INTEGER);").unwrap();
    let refused = SqliteStore::open(&foreign).unwrap_err().to_string();
    assert!(refused.contains("no schema version"), "{refused}");
    // A migration that cannot run is refused too, and leaves the version as it was.
    let broken = dir.path().join("broken.sqlite");
    let c = rusqlite::Connection::open(&broken).unwrap();
    c.execute_batch("CREATE TABLE envelopes (id TEXT PRIMARY KEY) STRICT;").unwrap();
    c.pragma_update(None, "user_version", 2).unwrap();
    drop(c);
    assert!(SqliteStore::open(&broken).is_err(), "no records table to migrate");
    assert_eq!(user_version(&broken), 2);
}

#[test]
fn sqlite_refuses_integers_beyond_i64_in_the_new_calls() {
    let dir = TempDir::new("range3");
    let s = SqliteStore::open(&dir.path().join("relay.sqlite")).unwrap();
    assert!(s.sweep(u64::MAX, 0).is_err());
    assert!(s.has_envelope("e", u64::MAX).is_err());
    let late = NewEnvelope { received_at: u64::MAX, ..env("e", b"{}") };
    assert!(s.insert_envelope(&late, &[to("a", 1)]).is_err());
    assert!(s.put_record("a", Kind::Key, 1, Some(u64::MAX), b"x").is_err());
}

/// A store with an envelope whose only row expired at 150 (ts 100), for the sweep's failures below.
fn expiring(label: &str) -> (TempDir, std::path::PathBuf, SqliteStore) {
    let dir = TempDir::new(label);
    let path = dir.path().join("relay.sqlite");
    let s = SqliteStore::open(&path).unwrap();
    s.insert_envelope(&env("e1", b"{1}"), &[to("a", 150)]).unwrap();
    (dir, path, s)
}

#[test]
fn a_wave_of_expired_rows_goes_in_chunks_and_the_store_takes_writes_between_them() {
    let dir = TempDir::new("sweep-chunks");
    let s = SqliteStore::open(&dir.path().join("relay.sqlite")).unwrap();
    for i in 0..600 {
        s.insert_envelope(&env(&format!("e{i}"), b"{}"), &[to("a", 200)]).unwrap();
    }
    let (first, more) = s.sweep_chunk(1_000, 5_000).unwrap();
    assert_eq!((first.mailbox, first.envelopes, first.tombstoned, more), (256, 0, 0, true));
    assert!(s.envelope("e599", 100).unwrap().is_some(), "the envelopes wait for their rows");
    // Between two transactions a write goes through, and the rest of the sweep leaves it alone.
    s.insert_envelope(&env("later", b"{}"), &[to("a", 5_000)]).unwrap();
    let rest = s.sweep(1_000, 5_000).unwrap();
    assert_eq!((rest.mailbox, rest.envelopes, rest.tombstoned), (344, 600, 600));
    assert_eq!(s.envelope("e0", 1_000).unwrap(), None);
    assert!(s.has_envelope("e599", 1_000).unwrap(), "its tombstone");
    assert!(s.envelope("later", 1_000).unwrap().is_some());
    assert_eq!(s.sweep_chunk(1_000, 5_000).unwrap(), (Swept::default(), false));
}

#[test]
fn a_sweep_of_exactly_one_chunk_ends_with_an_empty_pass() {
    let dir = TempDir::new("sweep-one-chunk");
    let s = SqliteStore::open(&dir.path().join("relay.sqlite")).unwrap();
    for i in 0..256 {
        s.insert_envelope(&env(&format!("e{i}"), b"{}"), &[to("a", 200)]).unwrap();
    }
    assert_eq!(s.sweep(1_000, 0).unwrap(), Swept { mailbox: 256, envelopes: 256, ..Swept::default() });
}

#[test]
fn a_sweep_that_fails_part_way_changes_nothing() {
    // The tombstone insert fails (a trigger stands in for any failure): the mailbox delete before it is rolled back.
    let (_d, path, s) = expiring("sweep-tombstone");
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER no_tomb BEFORE INSERT ON tombstones BEGIN SELECT RAISE(ABORT, 'no'); END;",
        )
        .unwrap();
    assert!(s.sweep(150, 310).is_err());
    assert_eq!(s.envelope("e1", 100).unwrap(), Some(stored(b"{1}", 100)), "nothing deleted");
    // The envelope delete fails.
    let (_d, path, s) = expiring("sweep-envelope");
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER no_del BEFORE DELETE ON envelopes BEGIN SELECT RAISE(ABORT, 'no'); END;",
        )
        .unwrap();
    assert!(s.sweep(150, 310).is_err());
    assert!(s.has_envelope("e1", 150).unwrap());
    // The tombstone table is gone: the tombstone delete fails, and so does an insert, which reads it.
    let (_d, path, s) = expiring("sweep-no-tombstones");
    rusqlite::Connection::open(&path).unwrap().execute_batch("DROP TABLE tombstones;").unwrap();
    assert!(s.sweep(150, 310).is_err());
    assert!(s.insert_envelope(&env("e2", b"{2}"), &[to("a", 900)]).is_err());
    // The records table is gone: the last delete fails, and the rest is rolled back.
    let (_d, path, s) = expiring("sweep-no-records");
    rusqlite::Connection::open(&path).unwrap().execute_batch("DROP TABLE records;").unwrap();
    assert!(s.sweep(150, 310).is_err());
    assert_eq!(s.mailbox_after("a", 0, 10, 100).unwrap().len(), 1);
}

#[test]
fn sqlite_refuses_a_database_its_schema_cannot_apply_to_and_a_migration_that_fails() {
    let dir = TempDir::new("schema-clash");
    let path = dir.path().join("relay.sqlite");
    SqliteStore::open(&path).unwrap();
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch("DROP INDEX envelopes_by_expiry; CREATE TABLE envelopes_by_expiry (x INTEGER);")
        .unwrap();
    assert!(SqliteStore::open(&path).is_err(), "an index name taken by a table");
    // Version 2 with a records table that refuses updates: the migration fails and leaves version 2.
    let old = dir.path().join("old.sqlite");
    old_database(&old, 2);
    rusqlite::Connection::open(&old)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER no_update BEFORE UPDATE ON records BEGIN SELECT RAISE(ABORT, 'no'); END;",
        )
        .unwrap();
    assert!(SqliteStore::open(&old).is_err());
    assert_eq!(user_version(&old), 2);
}

// --- pending rows -----------------------------------------------------------------

#[test]
fn pending_rows_are_written_with_the_envelope_listed_by_expiry_and_keep_it_while_they_live() {
    each_store(|s| {
        let held = [to("b", 700), to("c", 400)];
        let new = NewEnvelope { pending: &held, ..env("e1", b"{1}") };
        assert_eq!(s.insert_envelope(&new, &[to("a", 150)]).unwrap(), Some(vec![1]));
        let other = NewEnvelope { pending: &[to("b", 300)][..], ..env("e2", b"{2}") };
        assert_eq!(s.insert_envelope(&other, &[]).unwrap(), Some(vec![]));
        let pair = |id: &str, addr: &str| (id.to_owned(), addr.to_owned());
        assert_eq!(s.pending(100, 10).unwrap(), vec![pair("e2", "b"), pair("e1", "c"), pair("e1", "b")]);
        assert_eq!(s.pending(100, 2).unwrap(), vec![pair("e2", "b"), pair("e1", "c")], "the earliest first");
        assert_eq!(s.pending(400, 10).unwrap(), vec![pair("e1", "b")], "live while until > now");
        assert!(s.mailbox_after("b", 0, 10, 100).unwrap().is_empty(), "no mailbox row yet");
        // The envelope outlives its delivered row while a pending row lives, and goes with the last of them.
        assert_eq!(s.sweep(150, 0).unwrap(), Swept { mailbox: 1, ..Swept::default() });
        assert_eq!(s.envelope("e1", 150).unwrap(), Some(stored(b"{1}", 100)));
        assert_eq!(s.sweep(400, 0).unwrap(), Swept { envelopes: 1, pending: 2, ..Swept::default() });
        assert_eq!(s.pending(400, 10).unwrap(), vec![pair("e1", "b")]);
        assert_eq!(s.sweep(700, 0).unwrap(), Swept { envelopes: 1, pending: 1, ..Swept::default() });
        assert!(s.pending(0, 10).unwrap().is_empty());
    });
}

#[test]
fn a_settled_pending_row_becomes_a_mailbox_row_or_goes_and_a_second_settle_does_nothing() {
    each_store(|s| {
        s.insert_envelope(&env("x", b"{x}"), &[to("b", 500)]).unwrap();
        let held = [to("b", 900), to("c", 900)];
        s.insert_envelope(&NewEnvelope { pending: &held, ..env("e1", b"{1}") }, &[to("a", 900)]).unwrap();
        assert_eq!(s.settle_pending("e1", "b", Some(600)).unwrap(), Some(2), "b's next cursor");
        let row = MailboxEntry { cursor: 2, bytes: b"{1}".to_vec(), received_at: 100 };
        assert_eq!(s.mailbox_after("b", 1, 10, 100).unwrap(), vec![row]);
        assert!(s.mailbox_after("b", 1, 10, 600).unwrap().is_empty(), "it expires then");
        assert_eq!(s.settle_pending("e1", "b", Some(600)).unwrap(), None, "settled once");
        assert_eq!(s.settle_pending("e1", "c", None).unwrap(), None, "dropped");
        assert!(s.mailbox_after("c", 0, 10, 100).unwrap().is_empty());
        assert!(s.pending(100, 10).unwrap().is_empty());
        assert_eq!(s.settle_pending("nothing", "b", Some(600)).unwrap(), None);
        assert_eq!(s.last_cursor("b").unwrap(), 2);
    });
}

#[test]
fn sqlite_migrates_version_3_to_4_keeping_every_row_and_gaining_the_pending_table() {
    let dir = TempDir::new("migrate-3");
    let path = dir.path().join("relay.sqlite");
    {
        let s = SqliteStore::open(&path).unwrap();
        s.insert_envelope(&env("e1", b"{1}"), &[to("a", 900)]).unwrap();
        s.put_record("six", Kind::AcceptFrom, 1, None, &record_bytes(&accept(6, Roots::Any, 1, 60, NOW)))
            .unwrap();
    }
    // The schema 3: everything but `pending`.
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute_batch("DROP INDEX pending_by_until; DROP TABLE pending;").unwrap();
    c.pragma_update(None, "user_version", 3).unwrap();
    drop(c);
    let s = SqliteStore::open(&path).unwrap();
    assert_eq!(user_version(&path), 5);
    assert_eq!(s.mailbox_after("a", 0, 10, 100).unwrap().len(), 1);
    assert!(s.record("six", Kind::AcceptFrom).unwrap().is_some());
    let held = [to("b", 900)];
    s.insert_envelope(&NewEnvelope { pending: &held, ..env("e2", b"{2}") }, &[]).unwrap();
    assert_eq!(s.pending(100, 10).unwrap(), vec![("e2".to_owned(), "b".to_owned())]);
}

#[test]
fn sqlite_refuses_a_pending_listing_past_its_integers() {
    let dir = TempDir::new("pending-range");
    let s = SqliteStore::open(&dir.path().join("relay.sqlite")).unwrap();
    assert!(s.pending(u64::MAX, 10).is_err());
    assert!(s.pending(100, usize::MAX).is_err());
    let held = [to("b", u64::MAX)];
    assert!(s.insert_envelope(&NewEnvelope { pending: &held, ..env("e1", b"{1}") }, &[]).is_err());
}

#[test]
fn sqlite_pending_calls_fail_as_store_errors_when_their_table_is_gone() {
    let dir = TempDir::new("pending-gone");
    let path = dir.path().join("relay.sqlite");
    let s = SqliteStore::open(&path).unwrap();
    let held = [to("b", 900)];
    s.insert_envelope(&NewEnvelope { pending: &held, ..env("e1", b"{1}") }, &[]).unwrap();
    // A settle whose row expires past what SQLite holds is refused, and changes nothing.
    assert!(s.settle_pending("e1", "b", Some(u64::MAX)).is_err());
    assert_eq!(s.pending(100, 10).unwrap().len(), 1, "rolled back");
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch("DROP INDEX pending_by_until; DROP TABLE pending;")
        .unwrap();
    assert!(s.pending(100, 10).is_err());
    assert!(s.settle_pending("e1", "b", None).is_err());
    assert!(s.sweep(100, 0).is_err());
    let again = [to("c", 900)];
    assert!(s.insert_envelope(&NewEnvelope { pending: &again, ..env("e2", b"{2}") }, &[]).is_err());
}

// --- the revoked list kept for each key ------------------------------------------------------

/// The keys of `ns` as the store hands them back.
fn keys(ns: &[u8]) -> Vec<String> {
    ns.iter().map(|n| addr(*n).to_string()).collect()
}

#[test]
fn the_revoked_list_of_the_newest_address_record_outlives_its_sweep_until_a_newer_record_replaces_it() {
    each_store(|s| {
        let five = addr(5);
        let five = five.as_str();
        assert!(s.revoked(five).unwrap().is_empty(), "nothing stored yet");
        let newer = org_bytes(5, NOW + 10, 60, &[addr(6), addr(7)], None);
        assert!(s.put_record(five, Kind::Address, NOW + 10, Some(NOW + 70), &newer).unwrap());
        assert_eq!(s.revoked(five).unwrap(), keys(&[6, 7]));
        assert_eq!(s.sweep(NOW + 71, 0).unwrap().records, 1);
        assert_eq!(s.record(five, Kind::Address).unwrap(), None, "the record is swept");
        assert_eq!(s.revoked(five).unwrap(), keys(&[6, 7]), "its list is kept");
        // An older record, still valid, published once the newer is gone: stored, and the list stays.
        let older = org_bytes(5, NOW, 86_400, &[], None);
        assert!(s.put_record(five, Kind::Address, NOW, Some(NOW + 86_400), &older).unwrap());
        assert_eq!(s.revoked(five).unwrap(), keys(&[6, 7]));
        // A record of another kind keeps nothing, whatever its bytes; a newer address record replaces the list.
        assert!(s.put_record(five, Kind::Key, NOW + 20, Some(NOW + 80), &newer).unwrap());
        assert_eq!(s.revoked(five).unwrap(), keys(&[6, 7]));
        let cleared = org_bytes(5, NOW + 20, 60, &[], None);
        assert!(s.put_record(five, Kind::Address, NOW + 20, Some(NOW + 80), &cleared).unwrap());
        assert!(s.revoked(five).unwrap().is_empty());
        let again = org_bytes(5, NOW + 30, 60, &[addr(8)], None);
        assert!(s.put_record(five, Kind::Address, NOW + 30, Some(NOW + 90), &again).unwrap());
        assert_eq!(s.revoked(five).unwrap(), keys(&[8]));
        assert!(s.revoked(addr(6).as_str()).unwrap().is_empty(), "one list per key");
        // Bytes that are not an address record keep an empty list.
        assert!(s.put_record("other", Kind::Address, 1, Some(2), b"{").unwrap());
        assert!(s.revoked("other").unwrap().is_empty());
    });
}

#[test]
fn sqlite_keeps_the_revoked_lists_across_a_reopen_and_fills_them_in_as_it_migrates_version_4() {
    let dir = TempDir::new("revoked-kept");
    let path = dir.path().join("relay.sqlite");
    let revoking = org_bytes(5, NOW, 60, &[addr(6)], None);
    {
        let s = SqliteStore::open(&path).unwrap();
        assert!(s.put_record(addr(5).as_str(), Kind::Address, NOW, Some(NOW + 60), &revoking).unwrap());
        s.sweep(NOW + 61, 0).unwrap();
    }
    let s = SqliteStore::open(&path).unwrap();
    assert_eq!(s.revoked(addr(5).as_str()).unwrap(), keys(&[6]), "kept past the sweep and the reopen");
    drop(s);
    // The schema 4: everything but `revoked`, with an address record that revokes key 6 stored.
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute_batch("DROP TABLE revoked;").unwrap();
    let (iat, until) = (i64::try_from(NOW).unwrap(), i64::try_from(NOW + 3_600).unwrap());
    let seven = org_bytes(7, NOW, 3_600, &[addr(6)], None);
    c.execute(
        "INSERT INTO records VALUES (?1, 'address', ?2, ?3, ?4)",
        rusqlite::params![addr(7).as_str(), iat, seven, until],
    )
    .unwrap();
    c.pragma_update(None, "user_version", 4).unwrap();
    drop(c);
    let s = SqliteStore::open(&path).unwrap();
    assert_eq!(user_version(&path), 5);
    assert_eq!(s.revoked(addr(7).as_str()).unwrap(), keys(&[6]), "filled in from the stored record");
    assert!(
        s.revoked(addr(5).as_str()).unwrap().is_empty(),
        "swept before the migration: nothing to fill in"
    );
    // A version-4 database whose address record has an iat SQLite cannot hand back as a u64: refused, left at 4.
    let broken = dir.path().join("broken.sqlite");
    drop(SqliteStore::open(&broken).unwrap());
    let c = rusqlite::Connection::open(&broken).unwrap();
    c.execute_batch(
        "DROP TABLE revoked; INSERT INTO records VALUES ('k', 'address', -1, x'7b7d', NULL);
         PRAGMA user_version = 4;",
    )
    .unwrap();
    drop(c);
    assert!(SqliteStore::open(&broken).is_err());
    assert_eq!(user_version(&broken), 4);
}

#[test]
fn sqlite_revoked_list_calls_fail_as_store_errors_when_their_table_is_gone() {
    let dir = TempDir::new("revoked-gone");
    let path = dir.path().join("relay.sqlite");
    let s = SqliteStore::open(&path).unwrap();
    rusqlite::Connection::open(&path).unwrap().execute_batch("DROP TABLE revoked;").unwrap();
    assert!(s.revoked(addr(5).as_str()).is_err());
    // The address record and its list are written in one transaction: neither is.
    let record = org_bytes(5, NOW, 60, &[addr(6)], None);
    assert!(s.put_record(addr(5).as_str(), Kind::Address, NOW, Some(NOW + 60), &record).is_err());
    assert_eq!(s.record(addr(5).as_str(), Kind::Address).unwrap(), None, "rolled back");
    assert!(s.put_record(addr(5).as_str(), Kind::Key, NOW, Some(NOW + 60), &record).unwrap(), "other kinds");
}

/// The SQLite store reports its database's bytes and its rows by table; the memory store reports none.
#[test]
fn sqlite_reports_its_size_and_the_memory_store_none() {
    assert!(MemoryStore::new().size().is_err());
    let dir = TempDir::new("size");
    let s = SqliteStore::open(&dir.path().join("relay.sqlite")).unwrap();
    let empty = s.size().unwrap();
    assert_eq!((empty.envelopes, empty.mailbox, empty.records, empty.pins), (0, 0, 0, 0));
    assert!(empty.bytes > 0 && empty.bytes.is_multiple_of(4_096), "{empty:?}");
    let body = vec![b'x'; 2_000];
    for i in 0..20 {
        s.insert_envelope(&env(&format!("e{i}"), &body), &[to("a", 1_000), to("b", 1_000)]).unwrap();
    }
    s.put_record("a", Kind::AcceptFrom, 10, None, b"{}").unwrap();
    let pin = DomainPin {
        domain: "example.test".into(),
        key: "ed25519:k".into(),
        record: vec![1],
        pinned_at: 10,
        expires_at: 60,
    };
    s.put_domain_pin(&pin).unwrap();
    let full = s.size().unwrap();
    assert_eq!((full.envelopes, full.mailbox, full.records, full.pins), (20, 40, 1, 1));
    assert!(full.bytes > empty.bytes && full.bytes.is_multiple_of(4_096), "{empty:?} then {full:?}");
    // The live bytes are the pages in use. The sweep frees the pages of the expired rows to the free list: the
    // file keeps its size and the live bytes fall, which is what a bound on the store can count.
    assert!(empty.live <= empty.bytes && full.live > empty.live, "{empty:?} then {full:?}");
    assert_eq!(s.live_bytes().unwrap(), full.live);
    s.sweep(2_000, 0).unwrap();
    let swept = s.size().unwrap();
    assert_eq!(swept.bytes, full.bytes, "the file does not shrink");
    assert!(swept.live < full.live, "{full:?} then {swept:?}");
    assert_eq!(s.live_bytes().unwrap(), swept.live);
}
