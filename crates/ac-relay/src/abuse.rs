//! The operator's blocklist (`--blocklist`): a text file of `ed25519:<hex>` addresses and `domain:<host>`
//! roots, one a line, `#` starting a comment, edited by `ac-relay block` ([`edit`]) and read again by the relay once
//! its modification time or size has changed (checked on each publish), so no restart is needed. A missing file is an
//! empty list; a file that no longer parses keeps the list in force and logs `blocklist-invalid`. src/policy.rs
//! refuses (403 `not-authorized`) an envelope whose `from`, root or a hop's key is listed or is the pinned key of a
//! listed domain, and a record whose signer is.

use ac_core::Address;
use ac_core::records::Domain;
use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

/// The entries, each as written, `ed25519:...` or `domain:...`.
pub type Entries = Arc<BTreeSet<String>>;
type Stamp = Option<(SystemTime, u64, u64)>;

/// One entry checked: an address, or `domain:` and a domain root's host.
///
/// # Errors
///
/// A sentence naming the entry.
pub fn entry(text: &str) -> Result<String, String> {
    let ok = text.strip_prefix("domain:").map_or(Address::parse(text).is_ok(), |h| Domain::parse(h).is_ok());
    ok.then(|| text.to_owned())
        .ok_or_else(|| format!("{text:?} is not an ed25519: address or a domain:<host> root"))
}

/// The entries of a blocklist file; none for a missing file.
///
/// # Errors
///
/// A sentence naming the file and the line, or the I/O error.
pub fn read(path: &Path) -> Result<BTreeSet<String>, String> {
    let text = match std::fs::read_to_string(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        text => text.map_err(|e| format!("blocklist {}: {e}", path.display()))?,
    };
    let lines = text.lines().enumerate().map(|(n, l)| (n + 1, l.split('#').next().unwrap_or("").trim()));
    let list =
        lines.filter(|(_, l)| !l.is_empty()).map(|(n, l)| entry(l).map_err(|e| format!("line {n}: {e}")));
    list.collect()
}

/// Applies `+<entry>` (add) and `-<entry>` (remove) edits and writes the file again, a temporary file renamed over
/// it so that the relay never reads half a file; comments are not kept. The entries after the edits.
///
/// # Errors
///
/// An edit without its sign or with a bad entry, or the file's read or write failing.
pub fn edit(path: &Path, edits: &[String]) -> Result<BTreeSet<String>, String> {
    let mut list = read(path)?;
    if edits.is_empty() {
        return Ok(list);
    }
    for e in edits {
        let sign =
            e.chars().next().filter(|c| matches!(c, '+' | '-')).ok_or(format!("{e:?}: + or - first"))?;
        let entry = entry(&e[1..])?;
        list.remove(&entry);
        if sign == '+' {
            list.insert(entry);
        }
    }
    let text = list.iter().fold(String::new(), |mut text, e| {
        text.push_str(e);
        text.push('\n');
        text
    });
    let tmp = path.with_extension("tmp");
    let written = std::fs::write(&tmp, text).and_then(|()| std::fs::rename(&tmp, path));
    written.map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("{}: {e}", path.display())
    })?;
    Ok(list)
}

/// A blocklist file as the relay holds it: the entries of its last good read, and the stamp (modification time and
/// size) of the file it last read.
#[derive(Debug)]
pub struct Blocklist {
    path: Option<PathBuf>,
    held: Mutex<(Stamp, Entries)>,
}

impl Blocklist {
    /// The blocklist of `path`, read on first use; none, an empty one.
    #[must_use]
    pub fn new(path: Option<PathBuf>) -> Blocklist {
        Blocklist {
            path,
            held: Mutex::new((Some((SystemTime::UNIX_EPOCH, u64::MAX, 0)), Entries::default())),
        }
    }

    /// The current entries, the file read again first when its stamp has changed.
    pub fn entries(&self) -> Entries {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(path) = &self.path else { return Arc::clone(&held.1) };
        let stamp = std::fs::metadata(path).ok().and_then(|m| Some((m.modified().ok()?, m.len(), m.ino())));
        if stamp != held.0 {
            held.0 = stamp;
            match read(path) {
                Ok(list) => held.1 = Arc::new(list),
                Err(error) => {
                    tracing::error!(event = "blocklist-invalid", error = %error, kept = held.1.len());
                    crate::metrics::METRICS.tick("ac_relay_blocklist_invalid_total");
                }
            }
            tracing::warn!(event = "blocklist", entries = held.1.len(), path = %path.display());
        }
        Arc::clone(&held.1)
    }
}

#[cfg(test)]
mod tests;
