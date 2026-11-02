//! A stdout the relay cannot write: it exits 1 instead of running unannounced.
//!
//! This test is alone in its binary on purpose. On macOS a pipe's close-on-exec is a second call after `pipe`
//! (`std::sys::pal::unix::pipe`), so a child another thread spawns between the two inherits the read end. The read
//! end then outlives `drop(reader)`, the URL line is written, and the relay runs on (a gate run of 2026-10-30; the
//! reader gone: exit 1 in 8,814 of 8,814 runs; the reader inherited by a sibling: it ran on, with this log). A test
//! binary runs its tests in threads of one process, so any other test here would be such a thread; cargo runs the
//! binaries one at a time.

mod common;

use common::{PATIENCE, Tail, TempDir, exit_within};
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_ac-relay");

#[test]
fn a_stdout_it_cannot_write_exits_non_zero() {
    let dir = TempDir::new("stdout");
    // A pipe whose reader is gone: writing the URL line fails with EPIPE (Rust ignores SIGPIPE), so the relay
    // must exit instead of running unannounced. (A read-only descriptor would not do: Rust's stdout treats
    // EBADF as a successful write.)
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let mut child = Command::new(BIN)
        .arg("--db")
        .arg(dir.path().join("r.sqlite"))
        // Its stdin is a pipe the Child holds: it stops when this test process ends, however that ends.
        .arg("--exit-on-stdin-eof")
        .stdin(Stdio::piped())
        .stdout(writer)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut tail = Tail::new(&mut child);
    // No SIGTERM: the relay exits on its own when it cannot write the URL line.
    let Some(status) = exit_within(&mut child, PATIENCE) else {
        let _ = child.kill();
        let _ = child.wait();
        let said = tail.rest();
        panic!("the relay did not exit within {PATIENCE:?}; stderr:\n{said}");
    };
    let log = tail.rest();
    assert_eq!(status.code(), Some(1), "{log}");
    assert!(log.contains("i/o"), "{log}");
}
