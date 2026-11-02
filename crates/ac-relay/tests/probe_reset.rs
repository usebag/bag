//! `ac-relay probe` against
//! servers that answer and then reset the connection (linger 0). (a) A proxy in front of a real relay reads each request
//! whole, answers it whole with `connection: close` in one write, and resets: every probe run reads every answer and
//! passes. (b) A server that answers as soon as it has the request head, the body unread or still arriving, and resets:
//! a run reads the answer when its request was written, or fails with the transport's own error when the reset came
//! first, and never with `Invalid argument (os error 22)`, which ureq's per-read `setsockopt` under `timeout_global`
//! returned on macOS for a reset socket though the answer had arrived (a red run). And a probe of a relay by another
//! name than its own signs its fetch for the URL health answers, so it passes (added 2026-11-02 with the audience).

mod common;

use ac_relay::{Config, probe};
use common::{Server, TempDir};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

/// The head of an HTTP message read from `stream`, and the number of body bytes its `content-length` names; `None` when
/// the stream ends first. Reads nothing past the head's end but what arrived with it.
async fn read_head(stream: &mut TcpStream, got: &mut Vec<u8>) -> Option<(usize, usize)> {
    let mut chunk = [0u8; 4_096];
    loop {
        if let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&got[..end]).to_ascii_lowercase();
            let length = head
                .split("\r\n")
                .filter_map(|l| l.split_once(':'))
                .find(|(k, _)| k.trim() == "content-length")
                .map_or(0, |(_, v)| v.trim().parse().unwrap_or(0));
            return Some((end + 4, length));
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => got.extend_from_slice(&chunk[..n]),
        }
    }
}

/// A whole HTTP message from `stream`: its head and the body its `content-length` names.
async fn read_message(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut got = Vec::new();
    let (head, length) = read_head(stream, &mut got).await?;
    while got.len() < head + length {
        let mut chunk = [0u8; 4_096];
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => got.extend_from_slice(&chunk[..n]),
        }
    }
    Some(got)
}

/// `answer`'s head with `connection: close`, so that the client never sends a second request on the connection.
fn closing(answer: &[u8]) -> Vec<u8> {
    let end = answer.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    [&answer[..end], b"\r\nconnection: close", &answer[end..]].concat()
}

/// (a): a proxy in front of `upstream` that reads each request whole, forwards it on a connection of its own, reads
/// the answer whole, writes it to the client in one write and resets the client's connection.
async fn resetting_proxy(upstream: SocketAddr) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Some(request) = read_message(&mut client).await else { return };
                let mut up = common::connect(upstream).await;
                up.write_all(&request).await.unwrap();
                let answer = read_message(&mut up).await.unwrap();
                client.write_all(&closing(&answer)).await.unwrap();
                client.set_zero_linger().unwrap();
            });
        }
    });
    addr
}

/// (b): a server that answers each path as soon as it has read a request head, the body unread or still arriving,
/// and resets the connection: health is ok, a record is not found, and every publish is answered for another id.
async fn early_resetter() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut got = Vec::new();
                if read_head(&mut client, &mut got).await.is_none() {
                    return;
                }
                let path = String::from_utf8_lossy(&got).split(' ').nth(1).unwrap_or("").to_owned();
                let (status, body) = match path.as_str() {
                    "/v0/health" => ("200 OK", r#"{"ok":true}"#),
                    p if p.starts_with("/v0/fetch/record/") => ("404 Not Found", r#"{"error":"not-found"}"#),
                    _ => ("200 OK", r#"{"ok":true,"id":"other","duplicate":false,"delivered":1}"#),
                };
                let answer = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = client.write_all(answer.as_bytes()).await;
                let _ = client.set_zero_linger();
            });
        }
    });
    addr
}

async fn run_probe(url: String, key_file: std::path::PathBuf) -> Result<String, String> {
    tokio::task::spawn_blocking(move || probe::run(&url, &key_file)).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l7_a_the_probe_reads_every_answer_a_server_sends_before_it_resets_the_connection() {
    let relay = Server::start_system(Config::default()).await;
    let proxy = resetting_proxy(relay.addr).await;
    let dir = TempDir::new("probe-reset");
    let mut outcomes = Vec::new();
    for run in 0..10 {
        let file = dir.path().join(format!("probe-{run}.key"));
        outcomes.push(run_probe(format!("http://{proxy}"), file).await);
    }
    let failed: Vec<&String> = outcomes.iter().filter_map(|o| o.as_ref().err()).collect();
    eprintln!(
        "MEASURE L7 (a): {} of 10 runs passed through the resetting proxy; failures {failed:?}",
        10 - failed.len()
    );
    assert!(failed.is_empty(), "{failed:?}");
    relay.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_probe_by_another_name_signs_its_fetch_for_the_url_health_answers() {
    let config = Config { url: Some("https://relay.example".into()), ..Config::default() };
    let relay = Server::start_system(config).await;
    let dir = TempDir::new("probe-audience");
    let probed = run_probe(format!("http://{}", relay.addr), dir.path().join("probe.key")).await;
    assert!(probed.is_ok(), "{probed:?}");
    relay.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l7_b_an_answer_before_the_body_and_a_reset_never_reads_as_invalid_argument() {
    let server = early_resetter().await;
    let dir = TempDir::new("probe-early");
    let file = dir.path().join("probe.key");
    let (mut read, mut transport, mut einval) = (0, Vec::new(), Vec::new());
    for _ in 0..50 {
        let why = run_probe(format!("http://{server}"), file.clone()).await.unwrap_err();
        if why.contains("os error 22") {
            einval.push(why);
        } else if why.starts_with(r#"publish: 200 {"ok":true,"id":"other""#) {
            read += 1;
        } else {
            transport.push(why);
        }
    }
    eprintln!(
        "MEASURE L7 (b): 50 runs: {read} read every answer (failing at the publish's id, as they should), {} ended on a \
         transport error {transport:?}, {} on os error 22 {einval:?}",
        transport.len(),
        einval.len()
    );
    assert!(einval.is_empty(), "{einval:?}");
    assert!(transport.iter().all(|w| w.contains(": io: ")), "{transport:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l7_c_a_call_with_no_answer_fails_after_its_5_s() {
    // A listener that never accepts: the kernel completes the connection and takes the request, and nothing answers.
    let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dir = TempDir::new("probe-silent");
    let started = std::time::Instant::now();
    let why =
        run_probe(format!("http://{}", silent.local_addr().unwrap()), dir.path().join("probe.key")).await;
    let took = started.elapsed();
    eprintln!("MEASURE L7 (c): a server that never answers: {why:?} after {took:?}");
    assert_eq!(why, Err("health: no answer within 5 s".to_owned()));
    assert!(
        took >= std::time::Duration::from_secs(5) && took < std::time::Duration::from_secs(8),
        "{took:?}"
    );
    drop(silent);
}
