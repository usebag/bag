use super::{Blocklist, edit, entry, read};
use crate::testkit::{TempDir, addr};
use std::collections::BTreeSet;

fn set(entries: &[&str]) -> BTreeSet<String> {
    entries.iter().map(|e| (*e).to_owned()).collect()
}

#[test]
fn an_entry_is_an_address_or_a_domain_root() {
    let a = addr(1).to_string();
    assert_eq!(entry(&a), Ok(a.clone()));
    assert_eq!(entry("domain:acme.example"), Ok("domain:acme.example".to_owned()));
    let upper = a.to_uppercase();
    for bad in ["", "acme.example", "domain:", "domain:localhost", "domain:127.0.0.1", "ed25519:00", &upper] {
        assert!(entry(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn a_file_reads_with_comments_and_blank_lines_and_a_missing_one_is_empty() {
    let dir = TempDir::new("blocklist-read");
    let path = dir.path().join("blocklist");
    assert_eq!(read(&path), Ok(BTreeSet::new()));
    let a = addr(1).to_string();
    std::fs::write(&path, format!("# spam, 2026-10-28\n\n  {a}  # reported\ndomain:acme.example\n")).unwrap();
    assert_eq!(read(&path), Ok(set(&[&a, "domain:acme.example"])));
    std::fs::write(&path, format!("{a}\nnot-an-entry\n")).unwrap();
    let why = read(&path).unwrap_err();
    assert!(why.starts_with("line 2: "), "{why}");
}

#[test]
fn edit_adds_and_removes_writes_once_and_a_bad_edit_changes_nothing() {
    let dir = TempDir::new("blocklist-edit");
    let path = dir.path().join("blocklist");
    let (a, b) = (addr(1).to_string(), addr(2).to_string());
    // No edit lists, and writes no file.
    assert_eq!(edit(&path, &[]), Ok(BTreeSet::new()));
    assert!(!path.exists());
    let added = edit(&path, &[format!("+{a}"), format!("+{b}"), "+domain:acme.example".to_owned()]);
    assert_eq!(added, Ok(set(&[&a, &b, "domain:acme.example"])));
    assert_eq!(read(&path), added);
    assert_eq!(edit(&path, &[format!("-{b}"), format!("+{a}")]), Ok(set(&[&a, "domain:acme.example"])));
    let before = std::fs::read_to_string(&path).unwrap();
    for bad in [b.clone(), format!("+{b}x"), "-".to_owned(), String::new()] {
        assert!(edit(&path, &[format!("-{a}"), bad.clone()]).is_err(), "{bad:?}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before, "{bad:?} changed the file");
    }
    assert!(!path.with_extension("tmp").exists());
}

#[test]
fn the_relay_reads_a_changed_file_again_and_keeps_its_list_while_the_file_is_bad() {
    let dir = TempDir::new("blocklist-reload");
    let path = dir.path().join("blocklist");
    let (a, b) = (addr(1).to_string(), addr(2).to_string());
    let list = Blocklist::new(Some(path.clone()));
    assert!(list.entries().is_empty(), "a missing file blocks nothing");
    edit(&path, &[format!("+{a}")]).unwrap();
    assert_eq!(*list.entries(), set(&[&a]));
    edit(&path, &[format!("+{b}")]).unwrap();
    assert_eq!(*list.entries(), set(&[&a, &b]));
    std::fs::write(&path, format!("{a}\nbroken\n")).unwrap();
    assert_eq!(*list.entries(), set(&[&a, &b]), "a bad file keeps the last good list");
    std::fs::write(&path, "").unwrap();
    assert!(list.entries().is_empty());
    edit(&path, &[format!("+{b}")]).unwrap();
    assert_eq!(*list.entries(), set(&[&b]));
    std::fs::remove_file(&path).unwrap();
    assert!(list.entries().is_empty(), "a removed file blocks nothing");
    assert!(Blocklist::new(None).entries().is_empty());
}
