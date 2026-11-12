//! The relay binary on port 0 and a raw WebSocket client, for the socket lines of
//! `abuse_socket.rs`. Every key comes from a fixed seed: test data by construction.
#![allow(dead_code, reason = "each test binary uses its own subset of this module")]

use crate::common::{
    PATIENCE, Reply, TempDir, accept, addr, auth_frame, bytes, envelope, exit_within, key, read_url_line,
    record_bytes, request,
};
use ac_core::chain::Hop;
use ac_core::envelope::Envelope;
use ac_core::keys::SigningKey;
use ac_core::records::Roots;
use std::io::Read as _;
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::time::Instant;

pub const BIN: &str = env!("CARGO_BIN_EXE_ac-relay");

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// The relay binary on port 0, its stderr collected by a thread so that its log pipe never fills.
pub struct Bin {
    child: Child,
    pub addr: SocketAddr,
    pub log: Arc<Mutex<String>>,
    _dir: TempDir,
}

impl Bin {
    pub fn spawn() -> Bin {
        Bin::spawn_with(&[])
    }

    /// The binary with `extra` flags (A8 raises `--connections-per-ip`, since it opens 129 connections
    /// from one address).
    pub fn spawn_with(extra: &[&str]) -> Bin {
        let dir = TempDir::new("abuse-socket");
        let mut child = Command::new(BIN)
            .args(["--port", "0", "--db"])
            .arg(dir.path().join("relay.sqlite"))
            .args(extra)
            // Its stdin is a pipe the Child holds: it stops when this test process ends, however that ends.
            .arg("--exit-on-stdin-eof")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // The stderr thread starts before the wait for the URL line, so that a failure can print what the
        // relay said; the failure joins it once the relay is dead and its pipe has ended.
        let log = Arc::new(Mutex::new(String::new()));
        let mut stderr = child.stderr.take().unwrap();
        let sink = Arc::clone(&log);
        let reader = std::thread::spawn(move || {
            let mut chunk = [0u8; 8_192];
            while let Ok(n @ 1..) = stderr.read(&mut chunk) {
                sink.lock().unwrap().push_str(&String::from_utf8_lossy(&chunk[..n]));
            }
        });
        let started = std::time::Instant::now();
        let (line, stdout) = match read_url_line(child.stdout.take().unwrap(), PATIENCE) {
            Ok(read) => read,
            Err(failure) => {
                let what = failure.reap(&mut child, started.elapsed());
                reader.join().unwrap();
                let said = log.lock().unwrap().clone();
                panic!("{what}; stderr:\n{said}");
            }
        };
        child.stdout = Some(stdout);
        let port: u16 = line.trim_end().rsplit_once(':').and_then(|(_, p)| p.parse().ok()).unwrap();
        Bin { child, addr: SocketAddr::from(([127, 0, 0, 1], port)), log, _dir: dir }
    }

    pub async fn publish(&self, body: &[u8]) -> Reply {
        request(self.addr, "POST", "/v0/publish", &[], body).await
    }

    pub async fn health(&self) -> u16 {
        request(self.addr, "GET", "/v0/health", &[], b"").await.status
    }

    /// Hosts mailbox `key(2)` for every root, up to the envelope cap of 196,608 bytes.
    pub async fn host(&self) {
        let r = self.publish(&record_bytes(&accept(2, Roots::Any, 196_608, 3_600, now()))).await;
        assert_eq!(r.status, 200, "{}", r.text());
    }

    /// The mailbox's last cursor, read through subscribe: a resume cursor past the end is clamped to it.
    pub async fn last_cursor(&self) -> u64 {
        let mut ws = Raw::connect(self.addr).await;
        let ok = ws.handshake(&key(2), &[], Some(u64::MAX >> 11)).await;
        assert_eq!(ok["t"], "ok", "{ok}");
        ok["cursor"].as_u64().unwrap()
    }

    /// Line A9: health 200, a genuine publish stored, and no panic on stderr.
    pub async fn a9(&self, after: &str, n: u64) {
        assert_eq!(self.health().await, 200, "A9 after {after}: health");
        let r = self.publish(&bytes(&envelope(1, &[addr(2)], vec![], now() - n))).await;
        assert_eq!(
            (r.status, r.json()["delivered"].clone()),
            (200, 1.into()),
            "A9 after {after}: {}",
            r.text()
        );
        let log = self.log.lock().unwrap().clone();
        assert!(!log.contains("panicked"), "A9 after {after}: the relay panicked");
    }
}

impl Drop for Bin {
    fn drop(&mut self) {
        // A relay that exits on stdin EOF does so now; one still running after 2 s is killed.
        drop(self.child.stdin.take());
        if exit_within(&mut self.child, Duration::from_secs(2)).is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// A WebSocket client on a raw socket: it sends any frame of any size, masked as a client must, and answers
/// nothing on its own.
pub struct Raw {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl Raw {
    pub async fn connect(addr: SocketAddr) -> Raw {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let request = format!(
            "GET /v0/subscribe HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut raw = Raw { stream, buf: Vec::new() };
        loop {
            if let Some(end) = raw.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                assert!(raw.buf.starts_with(b"HTTP/1.1 101"), "{}", String::from_utf8_lossy(&raw.buf));
                raw.buf.drain(..end + 4);
                return raw;
            }
            assert!(raw.fill(Instant::now() + Duration::from_secs(5)).await, "no upgrade answer");
        }
    }

    /// Reads more bytes; false on EOF, an error or the deadline.
    pub async fn fill(&mut self, deadline: Instant) -> bool {
        let mut chunk = vec![0u8; 16_384];
        match tokio::time::timeout_at(deadline, self.stream.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => {
                self.buf.extend_from_slice(&chunk[..n]);
                true
            }
            _ => false,
        }
    }

    pub async fn need(&mut self, n: usize, deadline: Instant) -> bool {
        while self.buf.len() < n {
            if !self.fill(deadline).await {
                return false;
            }
        }
        true
    }

    /// The next frame from the relay (unmasked, unfragmented), or `None` on EOF, an error or the deadline.
    pub async fn frame(&mut self, deadline: Instant) -> Option<(u8, Vec<u8>)> {
        if !self.need(2, deadline).await {
            return None;
        }
        let (len, header) = match self.buf[1] & 0x7f {
            126 => {
                self.need(4, deadline).await.then_some(())?;
                (usize::from(u16::from_be_bytes([self.buf[2], self.buf[3]])), 4)
            }
            127 => {
                self.need(10, deadline).await.then_some(())?;
                (usize::try_from(u64::from_be_bytes(self.buf[2..10].try_into().unwrap())).unwrap(), 10)
            }
            n => (usize::from(n), 2),
        };
        self.need(header + len, deadline).await.then_some(())?;
        let opcode = self.buf[0] & 0x0f;
        let payload = self.buf[header..header + len].to_vec();
        self.buf.drain(..header + len);
        Some((opcode, payload))
    }

    /// The next text frame as JSON, skipping pings and pongs; panics on anything else or after 5 s.
    pub async fn json(&mut self) -> serde_json::Value {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match self.frame(deadline).await {
                Some((0x1, payload)) => return serde_json::from_slice(&payload).unwrap(),
                Some((0x9 | 0xa, _)) => {}
                other => panic!("expected a text frame, got {other:?}"),
            }
        }
    }

    /// Every frame until the connection ends: the text frames, and the close code (`None` for no close
    /// frame).
    pub async fn until_closed(&mut self, wait: Duration) -> (Vec<serde_json::Value>, Option<u16>) {
        let deadline = Instant::now() + wait;
        let mut texts = Vec::new();
        loop {
            match self.frame(deadline).await {
                Some((0x1, payload)) => texts.push(serde_json::from_slice(&payload).unwrap_or_default()),
                Some((0x8, payload)) => {
                    return (texts, payload.get(..2).map(|c| u16::from_be_bytes([c[0], c[1]])));
                }
                Some(_) => {}
                None => {
                    assert!(Instant::now() < deadline, "the connection stayed open for {wait:?}");
                    return (texts, None);
                }
            }
        }
    }

    /// Sends one masked frame; a relay that has already closed may refuse the bytes, which is not an error
    /// here.
    pub async fn send(&mut self, opcode: u8, payload: &[u8]) {
        let mask = [0x37_u8, 0xfa, 0x21, 0x3d];
        let mut frame = vec![0x80 | opcode];
        match payload.len() {
            n if n < 126 => frame.push(0x80 | u8::try_from(n).unwrap()),
            n if n <= 0xffff => {
                frame.push(0x80 | 0x7e);
                frame.extend_from_slice(&u16::try_from(n).unwrap().to_be_bytes());
            }
            n => {
                frame.push(0x80 | 0x7f);
                frame.extend_from_slice(&u64::try_from(n).unwrap().to_be_bytes());
            }
        }
        frame.extend_from_slice(&mask);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        let _ = self.stream.write_all(&frame).await;
    }

    pub async fn send_json(&mut self, value: &serde_json::Value) {
        self.send(0x1, value.to_string().as_bytes()).await;
    }

    /// Reads the challenge and answers it as `signer` for mailbox `key(2)`; returns the relay's answer.
    pub async fn handshake(
        &mut self,
        signer: &SigningKey,
        hops: &[Hop],
        cursor: Option<u64>,
    ) -> serde_json::Value {
        let challenge = self.json().await;
        assert_eq!(challenge["t"], "challenge");
        let nonce = challenge["nonce"].as_str().unwrap().to_owned();
        self.send_json(&auth_frame(signer, &addr(2), hops, cursor, &nonce)).await;
        self.json().await
    }
}

/// An envelope of exactly `size` bytes: the ciphertext sized to fit, then spaces, which JSON allows after the
/// value.
pub fn envelope_of(size: usize, ts: u64) -> Vec<u8> {
    let base =
        Envelope::sign(&key(1), vec![addr(2)], vec![], ts, crate::common::sealed(&[addr(2)], 16)).unwrap();
    let fill = 16 + (size - base.to_bytes().len()) / 2;
    let env =
        Envelope::sign(&key(1), vec![addr(2)], vec![], ts, crate::common::sealed(&[addr(2)], fill)).unwrap();
    let mut out = env.to_bytes();
    out.resize(size, b' ');
    out
}
