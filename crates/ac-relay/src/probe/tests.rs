use super::{load_key, run};
use crate::testkit::TempDir;
use std::os::unix::fs::PermissionsExt as _;

#[test]
fn a_missing_key_file_is_made_0600_and_read_back_as_the_same_key() {
    let dir = TempDir::new("probe-key");
    let path = dir.path().join("probe.key");
    let made = load_key(&path).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!((text.len(), text.ends_with('\n')), (65, true), "64 hex characters and a newline");
    assert_eq!(load_key(&path).unwrap().address(), made.address());
}

#[test]
fn a_key_file_of_other_content_or_one_that_cannot_be_made_is_refused() {
    let dir = TempDir::new("probe-key-bad");
    let path = dir.path().join("probe.key");
    std::fs::write(&path, "not hex\n").unwrap();
    assert_eq!(load_key(&path).err().unwrap().to_string(), "it does not hold 64 hex characters");
    let nowhere = dir.path().join("missing-dir").join("probe.key");
    assert!(load_key(&nowhere).is_err(), "a key file in a directory that does not exist");
    assert!(load_key(dir.path()).is_err(), "a directory is not a key file");
}

#[test]
fn with_no_relay_listening_the_probe_fails_at_health() {
    let dir = TempDir::new("probe-dead");
    let why = run("http://127.0.0.1:9/", &dir.path().join("probe.key")).unwrap_err();
    assert!(why.starts_with("health: "), "{why}");
    assert!(!dir.path().join("probe.key").exists(), "no key is made before health answers");
}
