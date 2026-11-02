//! Stream 5's abuse controls through HTTP and the binary: `/v0/abuse`, a blocklist edited by `ac-relay block` while
//! the relay runs, and the subcommand's own answers.

mod common;

use ac_core::records::Roots;
use ac_relay::Config;
use common::{NOW, Server, TempDir, addr, bytes, envelope};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_ac-relay");

fn block(file: &std::path::Path, edits: &[String]) -> (i32, String, String) {
    let out = Command::new(BIN).arg("block").arg(file).args(edits).output().unwrap();
    let text = |b: Vec<u8>| String::from_utf8(b).unwrap();
    (out.status.code().unwrap(), text(out.stdout), text(out.stderr))
}

#[tokio::test]
async fn the_abuse_contact_is_answered_and_without_one_is_404() {
    let contact = "mailto:abuse@relay.example";
    let s = Server::start(Config { abuse_contact: Some(contact.into()), ..Config::default() }).await;
    let r = s.get("/v0/abuse", &[]).await;
    assert_eq!((r.status, r.header("content-type")), (200, Some("application/json")));
    assert_eq!(r.json(), serde_json::json!({"contact": contact}));
    s.stop().await;
    let none = Server::start(Config::default()).await;
    let r = none.get("/v0/abuse", &[]).await;
    assert_eq!((r.status, r.error()), (404, "not-found".to_owned()));
    none.stop().await;
}

#[tokio::test]
async fn a_key_blocked_by_the_subcommand_is_refused_403_until_it_is_removed_with_no_restart() {
    let dir = TempDir::new("abuse-controls");
    let file = dir.path().join("blocklist");
    let s = Server::start(Config { blocklist: Some(file.clone()), ..Config::default() }).await;
    s.host(2, Roots::Any, 65_536, 3_600, NOW).await;
    let first = bytes(&envelope(1, &[addr(2)], vec![], NOW));
    assert_eq!(s.publish(&first).await.status, 200, "a missing file blocks nothing");
    let (code, out, _) = block(&file, &[format!("+{}", addr(1)), "+domain:acme.example".into()]);
    // Printed in sorted order: `domain:` before `ed25519:`.
    assert_eq!((code, out), (0, format!("domain:acme.example\n{}\n", addr(1))));
    let next = bytes(&envelope(1, &[addr(2)], vec![], NOW - 1));
    let r = s.publish(&next).await;
    assert_eq!((r.status, r.error()), (403, "not-authorized".to_owned()));
    assert_eq!(block(&file, &[format!("-{}", addr(1))]).0, 0);
    assert_eq!(s.publish(&next).await.status, 200);
    s.stop().await;
}

#[test]
fn the_block_subcommand_lists_refuses_a_bad_edit_and_names_its_usage() {
    let dir = TempDir::new("block-subcommand");
    let file = dir.path().join("blocklist");
    assert_eq!(block(&file, &[]), (0, String::new(), String::new()), "a missing file lists empty");
    assert_eq!(block(&file, &[format!("+{}", addr(1))]).0, 0);
    assert_eq!(block(&file, &[]).1, format!("{}\n", addr(1)));
    let (code, out, err) = block(&file, &[format!("-{}", addr(1)), "+not-an-entry".into()]);
    assert_eq!((code, out.as_str()), (1, ""));
    assert!(err.starts_with("block: \"not-an-entry\""), "{err}");
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        format!("{}\n", addr(1)),
        "the bad edit changed nothing"
    );
    let out = Command::new(BIN).arg("block").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr).unwrap().starts_with("usage: ac-relay block <file>"));
}
