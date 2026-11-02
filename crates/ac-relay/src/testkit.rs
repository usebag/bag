//! Fixtures for the unit tests: keys from fixed seeds, signed envelopes and records, a temporary directory.
//! Test data by construction; nothing here is a real key.

use ac_core::Address;
use ac_core::chain::Hop;
use ac_core::envelope::{Envelope, Sealed, Wrap};
use ac_core::keys::SigningKey;
use ac_core::records::{AcceptFromRecord, AddressRecord, Record, Roots};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

/// A fixed time, so no test depends on the clock.
pub const NOW: u64 = 1_800_000_000;

pub fn key(n: u8) -> SigningKey {
    SigningKey::from_seed(&[n; 32])
}

pub fn addr(n: u8) -> Address {
    key(n).address()
}

pub fn sealed(to: &[Address], fill: usize) -> Sealed {
    Sealed {
        wraps: to.iter().map(|a| Wrap { to: a.clone(), enc: "ab".repeat(32), ct: "cd".repeat(48) }).collect(),
        nonce: "ef".repeat(12),
        ct: "01".repeat(fill),
    }
}

/// An envelope from `key(from)` with the given chain, at `ts`.
pub fn envelope(from: u8, to: &[Address], auth: Vec<Hop>, ts: u64) -> Envelope {
    Envelope::sign(&key(from), to.to_vec(), auth, ts, sealed(to, 32)).unwrap()
}

pub fn bytes(env: &Envelope) -> Vec<u8> {
    env.to_bytes()
}

/// An accept-from record for mailbox `key(owner)`, signed.
pub fn accept(owner: u8, roots: Roots, max_bytes: u64, ttl: u64, iat: u64) -> Record {
    let mut r =
        Record::AcceptFrom(AcceptFromRecord { owner: addr(owner), roots, max_bytes, ttl, iat, sig: [0; 64] });
    r.sign(&key(owner)).unwrap();
    r
}

/// An address record for `key(n)`, signed, optionally rotated from `key(from)` and countersigned by `key(by)`.
pub fn address_record(n: u8, iat: u64, rotation: Option<(u8, Option<u8>)>) -> Record {
    let mut a = AddressRecord {
        key: addr(n),
        sealing_key: Some("aa".repeat(32)),
        relays: vec!["http://127.0.0.1:1".into()],
        rotation_key: None,
        revoked: vec![],
        ttl: 3_600,
        iat,
        rotated_from: rotation.map(|(from, _)| addr(from)),
        rotation_sig: None,
        sig: [0; 64],
    };
    if let Some((_, Some(by))) = rotation {
        a.countersign(&key(by)).unwrap();
    }
    let mut r = Record::Address(a);
    r.sign(&key(n)).unwrap();
    r
}

pub fn record_bytes(r: &Record) -> Vec<u8> {
    r.to_bytes()
}

/// The value of the series `name` (its labels as written) in the process's metrics, 0 when it has none. The unit
/// tests share them, so a test reads a count before and after and expects it to have moved by at least its own.
pub fn counted(name: &str) -> u64 {
    let text = crate::metrics::METRICS.render(NOW);
    text.lines().find_map(|l| l.strip_prefix(name)?.strip_prefix(' ')?.parse().ok()).unwrap_or(0)
}

/// A fresh directory under `AC_TEST_TMP` (else the system temporary directory), removed on drop unless
/// `AC_KEEP_TMP=1`.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(label: &str) -> TempDir {
        static N: AtomicU32 = AtomicU32::new(0);
        let base = std::env::var_os("AC_TEST_TMP").map_or_else(std::env::temp_dir, PathBuf::from);
        let dir = base.join(format!(
            "bag-ac-relay-{label}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if std::env::var("AC_KEEP_TMP").as_deref() != Ok("1") {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
