//! Support for the integration tests: a relay served in-process on port 0 over a real SQLite file and real
//! sockets, a minimal HTTP/1.1 client (so a test controls every byte it sends), a WebSocket client, and
//! fixtures signed with keys from fixed seeds (test data by construction, never a real key).
//!
//! A test that waits on a relay, to connect, to answer or to be healthy, waits up to `PATIENCE` and looks
//! again every `POLL`: the last step's coverage run executes these tests while other builds load the machine.
#![allow(dead_code, reason = "each test binary uses its own subset of this module")]

use ac_core::chain::Hop;
use ac_core::envelope::{Envelope, Sealed, Wrap};
use ac_core::keys::SigningKey;
use ac_core::records::{AcceptFromRecord, AddressRecord, Record, Roots};
use ac_core::requests::{fetch_preimage, subscribe_preimage};
use ac_core::{Address, hex};
use ac_relay::clock::{Clock, ManualClock, SystemClock};
use ac_relay::store::Store;
use ac_relay::store::sqlite::SqliteStore;
use ac_relay::{Config, Relay};
use futures_util::{SinkExt as _, StreamExt as _};
use std::fmt::Write as _;
use std::io::{BufRead as _, BufReader, ErrorKind};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, ExitStatus};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

/// A fixed time for tests on the manual clock.
pub const NOW: u64 = 1_800_000_000;

pub fn key(n: u8) -> SigningKey {
    SigningKey::from_seed(&[n; 32])
}

pub fn addr(n: u8) -> Address {
    key(n).address()
}

/// A fresh directory under `AC_TEST_TMP` (else the system temporary directory), removed on drop unless
/// `AC_KEEP_TMP=1`.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(label: &str) -> TempDir {
        static N: AtomicU32 = AtomicU32::new(0);
        let base = std::env::var_os("AC_TEST_TMP").map_or_else(std::env::temp_dir, PathBuf::from);
        let dir = base.join(format!(
            "bag-ac-relay-it-{label}-{}-{}",
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

/// A relay served in-process.
pub struct Server {
    pub addr: SocketAddr,
    /// The relay's public base URL, the audience of [`Server::fetch`]'s proofs: the config's `url`, else
    /// `http://<addr>`, set as the binary sets it.
    pub base: String,
    pub clock: Arc<ManualClock>,
    pub relay: Arc<Relay>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<std::io::Result<()>>>,
    _dir: TempDir,
}

impl Server {
    /// A relay on the manual clock at `NOW`, with `config`.
    pub async fn start(config: Config) -> Server {
        let clock = Arc::new(ManualClock::new(NOW));
        Server::start_with(config, clock.clone(), clock).await
    }

    /// A relay on the system clock.
    pub async fn start_system(config: Config) -> Server {
        Server::start_with(config, Arc::new(ManualClock::new(0)), Arc::new(SystemClock)).await
    }

    /// A relay on the manual clock at `NOW` over `store` instead of SQLite.
    pub async fn start_with_store(config: Config, store: Arc<dyn Store>) -> Server {
        let clock = Arc::new(ManualClock::new(NOW));
        Server::start_inner(config, clock.clone(), clock, Some(store)).await
    }

    async fn start_with(config: Config, manual: Arc<ManualClock>, clock: Arc<dyn Clock>) -> Server {
        Server::start_inner(config, manual, clock, None).await
    }

    async fn start_inner(
        mut config: Config,
        manual: Arc<ManualClock>,
        clock: Arc<dyn Clock>,
        store: Option<Arc<dyn Store>>,
    ) -> Server {
        let dir = TempDir::new("server");
        let store =
            store.unwrap_or_else(|| Arc::new(SqliteStore::open(&dir.path().join("relay.sqlite")).unwrap()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base = config.url.get_or_insert_with(|| format!("http://{addr}")).clone();
        let relay = Arc::new(Relay::new(store, clock, config));
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(ac_relay::run(listener, Arc::clone(&relay), async move {
            let _ = stopped.await;
        }));
        Server { addr, base, clock: manual, relay, stop: Some(stop), task: Some(task), _dir: dir }
    }

    /// Shuts the relay down and waits for it.
    pub async fn stop(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            tokio::time::timeout(Duration::from_secs(10), task).await.unwrap().unwrap().unwrap();
        }
    }

    pub async fn get(&self, path: &str, headers: &[(&str, &str)]) -> Reply {
        request(self.addr, "GET", path, headers, b"").await
    }

    pub async fn post(&self, path: &str, body: &[u8]) -> Reply {
        request(self.addr, "POST", path, &[("Content-Type", "application/json")], body).await
    }

    pub async fn publish(&self, body: &[u8]) -> Reply {
        self.post("/v0/publish", body).await
    }

    /// Publishes an accept-from record for mailbox `key(owner)`; panics unless it is accepted.
    pub async fn host(&self, owner: u8, roots: Roots, max_bytes: u64, ttl: u64, iat: u64) {
        let r = self.publish(&record_bytes(&accept(owner, roots, max_bytes, ttl, iat))).await;
        assert_eq!(r.status, 200, "{}", r.text());
    }

    /// GETs `/v0/fetch/{id}` signed by `signer` at `ts` for the relay's base, with a delegation chain when `hops` is
    /// not empty.
    pub async fn fetch(&self, id: &str, signer: &SigningKey, ts: u64, hops: &[Hop]) -> Reply {
        self.fetch_for(id, signer, ts, hops, &self.base, &[]).await
    }

    /// [`Server::fetch`] with the proof's audience `audience`, and the `extra` headers after the proof's.
    pub async fn fetch_for(
        &self,
        id: &str,
        signer: &SigningKey,
        ts: u64,
        hops: &[Hop],
        audience: &str,
        extra: &[(&str, &str)],
    ) -> Reply {
        let sig = signer.sign_preimage(&fetch_preimage(&signer.address(), id, ts, audience)).unwrap();
        let (signer, ts, sig) = (signer.address().to_string(), ts.to_string(), hex::encode(&sig));
        let auth = ac_relay::auth::encode_auth_header(hops);
        let mut headers =
            vec![("AC-Signer", signer.as_str()), ("AC-Ts", ts.as_str()), ("AC-Sig", sig.as_str())];
        if !hops.is_empty() {
            headers.push(("AC-Auth", auth.as_str()));
        }
        headers.extend_from_slice(extra);
        self.get(&format!("/v0/fetch/{id}"), &headers).await
    }

    pub fn ws_url(&self) -> String {
        format!("ws://{}/v0/subscribe", self.addr)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

/// An HTTP answer.
#[derive(Debug)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|e| panic!("not JSON ({e}): {}", self.text()))
    }

    /// The `error` code of an error answer.
    pub fn error(&self) -> String {
        self.json()["error"].as_str().unwrap_or_default().to_owned()
    }
}

/// How long a test waits for a relay, or for an answer from one, before it fails.
pub const PATIENCE: Duration = Duration::from_secs(30);

/// How often a waiting test looks again.
pub const POLL: Duration = Duration::from_millis(50);

/// The exit status of `child` once it has exited, looked for every 10 ms until `within` has passed by the
/// clock; None when it is still running then. The caller kills it. (A count of sleeps never returns early, so
/// 200 of 25 ms took at least 5 s; the defect was that its clock started at the spawn and left no slack for a
/// loaded machine.)
pub fn exit_within(child: &mut Child, within: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + within;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Why [`read_url_line`] returned no line. [`UrlFailure::reap`] ends the relay and says which it was.
#[derive(Debug)]
pub enum UrlFailure {
    /// The pipe ended before a line: the relay exited, or closed its stdout.
    Eof,
    /// The read failed, with the error's text (or the reading thread ended without a result).
    Read(String),
    /// No line and no end of the pipe within the time given.
    Timeout(Duration),
}

impl UrlFailure {
    /// Ends `child` and describes the failure for a panic message, which the caller completes with the
    /// relay's stderr. After a timeout or a read error the relay is killed and waited for, which returns at
    /// once. After the end of the pipe it gets [`PATIENCE`] to exit on its own, and is then killed; the
    /// message names its exit status. `waited` is how long the caller has waited for the line.
    pub fn reap(self, child: &mut Child, waited: Duration) -> String {
        match self {
            UrlFailure::Timeout(within) => {
                let _ = child.kill();
                let _ = child.wait();
                format!("no URL line on stdout within {within:?} (waited {waited:?})")
            }
            UrlFailure::Read(error) => {
                let _ = child.kill();
                let _ = child.wait();
                format!("reading the URL line from stdout failed after {waited:?}: {error}")
            }
            UrlFailure::Eof => {
                if let Some(status) = exit_within(child, PATIENCE) {
                    format!("the relay exited before its URL line ({status:?}, waited {waited:?})")
                } else {
                    let _ = child.kill();
                    let _ = child.wait();
                    format!(
                        "stdout ended before the URL line (waited {waited:?}) and the relay did not exit \
                         within {PATIENCE:?}"
                    )
                }
            }
        }
    }
}

/// The first line a relay prints on its stdout (`AC_RELAY_URL=...`) and the stdout handle back, for the rest
/// of the test to use. Otherwise the [`UrlFailure`]: the end of the pipe before a line (an empty read), a
/// read error, or no line within `within`. A thread does the blocking read, since a `read_line` cannot be
/// timed out. After a failure the caller passes the relay to [`UrlFailure::reap`], which ends it; the
/// pipe's end then ends the thread.
pub fn read_url_line(stdout: ChildStdout, within: Duration) -> Result<(String, ChildStdout), UrlFailure> {
    let (sender, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut out = BufReader::new(stdout);
        let mut line = String::new();
        let read = out.read_line(&mut line);
        let _ = sender.send(read.map(|_| (line, out.into_inner())));
    });
    match rx.recv_timeout(within) {
        Ok(Ok((line, _))) if line.is_empty() => Err(UrlFailure::Eof),
        Ok(Ok(read)) => Ok(read),
        Ok(Err(error)) => Err(UrlFailure::Read(error.to_string())),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(UrlFailure::Timeout(within)),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(UrlFailure::Read("the reading thread ended without a result".to_owned()))
        }
    }
}

/// A relay process's stderr, read as the relay writes it by a thread that ends at the end of the pipe: a test
/// waits for a log event instead of sleeping or blocking on a read, and a failure can print everything the
/// relay said.
pub struct Tail {
    rx: mpsc::Receiver<String>,
    seen: Vec<String>,
}

impl Tail {
    /// Takes the piped stderr of `child`.
    pub fn new(child: &mut Child) -> Tail {
        let stderr = child.stderr.take().expect("a piped stderr");
        let (sender, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        Tail { rx, seen: Vec::new() }
    }

    /// The fields of the first line read whose event is `event`; lines that are not JSON log lines are
    /// skipped.
    pub fn fields(&self, event: &str) -> Option<serde_json::Value> {
        self.seen.iter().find_map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).ok()?;
            if v["fields"]["event"] == event { Some(v["fields"].clone()) } else { None }
        })
    }

    fn has(&self, event: &str) -> bool {
        self.fields(event).is_some()
    }

    /// Reads until a line whose event is `event` has been read, for up to `within`: false when the pipe ends
    /// first (the relay has exited) or the time is up.
    pub fn until(&mut self, event: &str, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        while !self.has(event) {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.rx.recv_timeout(left) {
                Ok(line) => self.seen.push(line),
                Err(_) => return false,
            }
        }
        true
    }

    /// Every line read so far, one to a line.
    pub fn log(&self) -> String {
        self.seen.join("\n")
    }

    /// Everything the relay wrote: reads to the end of the pipe, which comes when it has exited or been
    /// killed, for up to [`PATIENCE`] for each line.
    pub fn rest(&mut self) -> String {
        while let Ok(line) = self.rx.recv_timeout(PATIENCE) {
            self.seen.push(line);
        }
        self.log()
    }
}

/// Whether a connect that failed with `e` is worth another try: refused (nothing listening yet), invalid
/// argument (macOS, for a socket reset under the call), would block or address not available (local ports run
/// short), reset, aborted, interrupted or timed out. Nothing has been sent yet, so another try cannot repeat
/// a request.
fn transient(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::ConnectionRefused
            | ErrorKind::InvalidInput
            | ErrorKind::WouldBlock
            | ErrorKind::AddrNotAvailable
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::Interrupted
            | ErrorKind::TimedOut
    )
}

/// A TCP connection to `addr`, tried again every [`POLL`] while connecting fails with a [`transient`] error,
/// until `deadline`.
async fn try_connect(addr: SocketAddr, deadline: Instant) -> std::io::Result<TcpStream> {
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let Ok(attempt) = tokio::time::timeout(left, TcpStream::connect(addr)).await else {
            return Err(std::io::Error::new(ErrorKind::TimedOut, "no connection before the deadline"));
        };
        match attempt {
            Ok(stream) => return Ok(stream),
            Err(e) if transient(&e) && Instant::now() + POLL < deadline => tokio::time::sleep(POLL).await,
            Err(e) => return Err(e),
        }
    }
}

/// A TCP connection to `addr`, tried for up to [`PATIENCE`] while connecting fails with a [`transient`]
/// error.
pub async fn connect(addr: SocketAddr) -> TcpStream {
    try_connect(addr, Instant::now() + PATIENCE).await.unwrap_or_else(|e| panic!("connect to {addr}: {e}"))
}

/// One HTTP/1.1 request on its own connection (`Connection: close`), read to the end. The connect is tried
/// again while it fails with a [`transient`] error (nothing is sent before it succeeds), and the answer is
/// read until the server closes the connection, for up to [`PATIENCE`] in all; a read that returns part of
/// the answer, or nothing yet, is followed by another.
pub async fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Reply {
    let deadline = Instant::now() + PATIENCE;
    exchange(addr, method, path, headers, body, deadline)
        .await
        .unwrap_or_else(|why| panic!("{method} {path} to {addr}: {why}"))
}

/// Asks `GET /v0/health` at `addr` every [`POLL`] until the answer is 200 with `"ok": true`, for up to
/// [`PATIENCE`], and returns that answer. A relay process that has printed its URL line is bound; a test that
/// uses it before its health answers assumes it is serving as well.
pub async fn wait_healthy(addr: SocketAddr) -> Reply {
    let deadline = Instant::now() + PATIENCE;
    loop {
        let last = match exchange(addr, "GET", "/v0/health", &[], b"", deadline).await {
            Ok(r)
                if r.status == 200
                    && serde_json::from_slice::<serde_json::Value>(&r.body)
                        .is_ok_and(|v| v["ok"] == true) =>
            {
                return r;
            }
            Ok(r) => format!("{} {}", r.status, r.text()),
            Err(why) => why,
        };
        assert!(
            Instant::now() + POLL < deadline,
            "no healthy answer from {addr} within {PATIENCE:?}, the last: {last}"
        );
        tokio::time::sleep(POLL).await;
    }
}

/// [`request`]'s exchange by `deadline`, or what went wrong: no connection, a request head that could not be
/// written, or no header block in what arrived.
async fn exchange(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    deadline: Instant,
) -> Result<Reply, String> {
    let mut stream = try_connect(addr, deadline).await.map_err(|e| format!("connect: {e}"))?;
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in headers {
        let _ = write!(head, "{k}: {v}\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await.map_err(|e| format!("the request head: {e}"))?;
    // A server that refuses early may close before reading all of the body; the answer is still read.
    let _ = stream.write_all(body).await;
    let (raw, end) = read_until_closed(&mut stream, deadline).await;
    parse_reply(&raw).map_err(|why| format!("{why} in the {} bytes read before {end}", raw.len()))
}

/// What `stream` sends until it closes, a read fails or `deadline` passes, and which of the three ended it.
pub async fn read_until_closed(stream: &mut TcpStream, deadline: Instant) -> (Vec<u8>, String) {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4_096];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => return (raw, "the close".to_owned()),
            Ok(Ok(n)) => raw.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => return (raw, format!("a read error ({e})")),
            Err(_) => return (raw, "the deadline".to_owned()),
        }
    }
}

fn parse_reply(raw: &[u8]) -> Result<Reply, String> {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or("no HTTP header block")?;
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = head.split("\r\n");
    let first = lines.next().unwrap_or_default();
    let status: u16 = first
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("no status in {first:?}"))?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned())))
        .collect();
    let mut body = raw[split + 4..].to_vec();
    let chunked =
        headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.contains("chunked"));
    if chunked {
        body = dechunk(&body);
    }
    Ok(Reply { status, headers, body })
}

fn dechunk(mut raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let Some(end) = raw.windows(2).position(|w| w == b"\r\n") else { return out };
        let size = usize::from_str_radix(String::from_utf8_lossy(&raw[..end]).trim(), 16).unwrap_or(0);
        if size == 0 {
            return out;
        }
        out.extend_from_slice(&raw[end + 2..end + 2 + size]);
        raw = &raw[end + 2 + size + 2..];
    }
}

pub fn sealed(to: &[Address], fill: usize) -> Sealed {
    Sealed {
        wraps: to.iter().map(|a| Wrap { to: a.clone(), enc: "ab".repeat(32), ct: "cd".repeat(48) }).collect(),
        nonce: "ef".repeat(12),
        ct: "01".repeat(fill),
    }
}

/// An envelope from `key(from)` with the given chain at `ts`; `fill` bytes of opaque ciphertext.
pub fn envelope(from: u8, to: &[Address], auth: Vec<Hop>, ts: u64) -> Envelope {
    Envelope::sign(&key(from), to.to_vec(), auth, ts, sealed(to, 32)).unwrap()
}

pub fn bytes(env: &Envelope) -> Vec<u8> {
    env.to_bytes()
}

pub fn accept(owner: u8, roots: Roots, max_bytes: u64, ttl: u64, iat: u64) -> Record {
    let mut r =
        Record::AcceptFrom(AcceptFromRecord { owner: addr(owner), roots, max_bytes, ttl, iat, sig: [0; 64] });
    r.sign(&key(owner)).unwrap();
    r
}

pub fn record_bytes(r: &Record) -> Vec<u8> {
    r.to_bytes()
}

/// The address record of `key(n)` at `iat`, valid `ttl` seconds, revoking `revoked`, signed: the list a relay
/// keeps for `key(n)`.
pub fn address_record(n: u8, iat: u64, ttl: u64, revoked: &[Address]) -> Vec<u8> {
    let mut r = Record::Address(AddressRecord {
        key: addr(n),
        sealing_key: None,
        relays: vec![],
        rotation_key: None,
        revoked: revoked.to_vec(),
        ttl,
        iat,
        rotated_from: None,
        rotation_sig: None,
        sig: [0; 64],
    });
    r.sign(&key(n)).unwrap();
    r.to_bytes()
}

/// The JSON value of an envelope or a record's wire text, to change before writing it back.
pub fn wire(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap()
}

pub type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;

pub async fn ws_connect(server: &Server) -> Ws {
    let (ws, _) = tokio_tungstenite::connect_async(server.ws_url()).await.unwrap();
    ws
}

/// The next text frame as JSON, skipping pings; panics on a close or after 5 s.
pub async fn ws_json(ws: &mut Ws) -> serde_json::Value {
    loop {
        let frame =
            tokio::time::timeout(Duration::from_secs(5), ws.next()).await.expect("a frame within 5 s");
        match frame.expect("an open socket").expect("a frame") {
            Message::Text(t) => return serde_json::from_str(t.as_str()).unwrap(),
            Message::Ping(_) | Message::Pong(_) => {}
            other => panic!("expected a text frame, got {other:?}"),
        }
    }
}

/// Reads until the close frame and returns its code; panics after 5 s.
pub async fn ws_close_code(ws: &mut Ws) -> u16 {
    loop {
        let frame =
            tokio::time::timeout(Duration::from_secs(5), ws.next()).await.expect("a close within 5 s");
        match frame {
            Some(Ok(Message::Close(Some(c)))) => return u16::from(c.code),
            Some(Ok(Message::Close(None))) | None => return u16::from(CloseCode::Status),
            Some(Ok(_)) => {}
            Some(Err(e)) => panic!("socket error before close: {e}"),
        }
    }
}

pub async fn ws_send(ws: &mut Ws, value: &serde_json::Value) {
    ws.send(Message::Text(value.to_string().into())).await.unwrap();
}

/// The auth frame of `signer` for `mailbox` over the challenge's nonce.
pub fn auth_frame(
    signer: &SigningKey,
    mailbox: &Address,
    hops: &[Hop],
    cursor: Option<u64>,
    nonce: &str,
) -> serde_json::Value {
    let sig = signer.sign_preimage(&subscribe_preimage(nonce, &signer.address(), mailbox, cursor)).unwrap();
    serde_json::json!({
        "t": "auth",
        "mailbox": mailbox.as_str(),
        "signer": signer.address().as_str(),
        "auth": hops.iter().map(|h| wire(&h.to_json_text())).collect::<Vec<_>>(),
        "cursor": cursor,
        "sig": hex::encode(&sig),
    })
}

/// Connects, answers the challenge as `signer` for `mailbox`, and returns the socket and the `ok` cursor.
pub async fn subscribe(
    server: &Server,
    signer: &SigningKey,
    mailbox: &Address,
    hops: &[Hop],
    cursor: Option<u64>,
) -> (Ws, u64) {
    let mut ws = ws_connect(server).await;
    let challenge = ws_json(&mut ws).await;
    assert_eq!(challenge["t"], "challenge");
    let nonce = challenge["nonce"].as_str().unwrap().to_owned();
    ws_send(&mut ws, &auth_frame(signer, mailbox, hops, cursor, &nonce)).await;
    let ok = ws_json(&mut ws).await;
    assert_eq!(ok["t"], "ok", "{ok}");
    (ws, ok["cursor"].as_u64().unwrap())
}

/// The next `env` frame's cursor and envelope id; the envelope is a JSON string of the stored bytes.
pub async fn ws_env(ws: &mut Ws) -> (u64, String) {
    let frame = ws_json(ws).await;
    assert_eq!(frame["t"], "env", "{frame}");
    let envelope = wire(frame["envelope"].as_str().expect("the envelope as a JSON string"));
    (frame["cursor"].as_u64().unwrap(), envelope["id"].as_str().unwrap().to_owned())
}

/// A WebSocket client on a raw socket: it answers nothing on its own (no automatic pong), so a test can be a
/// subscriber that goes truly silent, and it never writes after its last frame, so a close by the relay is
/// always read, never cut short by a failed write.
pub struct RawWs {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl RawWs {
    pub async fn connect(addr: SocketAddr) -> RawWs {
        let mut stream = connect(addr).await;
        let request = format!(
            "GET /v0/subscribe HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut ws = RawWs { stream, buf: Vec::new() };
        let head = loop {
            if let Some(end) = ws.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&ws.buf[..end]).into_owned();
                ws.buf.drain(..end + 4);
                break head;
            }
            ws.fill().await;
        };
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        ws
    }

    async fn fill(&mut self) {
        let mut chunk = [0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), self.stream.read(&mut chunk))
            .await
            .expect("data within 5 s")
            .unwrap();
        assert!(n > 0, "the relay closed the socket without a close frame");
        self.buf.extend_from_slice(&chunk[..n]);
    }

    async fn need(&mut self, n: usize) {
        while self.buf.len() < n {
            self.fill().await;
        }
    }

    /// The next frame from the relay: its opcode and payload (relay frames are unmasked and unfragmented).
    pub async fn frame(&mut self) -> (u8, Vec<u8>) {
        self.need(2).await;
        let opcode = self.buf[0] & 0x0f;
        let (len, header) = match self.buf[1] & 0x7f {
            126 => {
                self.need(4).await;
                (usize::from(u16::from_be_bytes([self.buf[2], self.buf[3]])), 4)
            }
            127 => {
                self.need(10).await;
                let mut b = [0u8; 8];
                b.copy_from_slice(&self.buf[2..10]);
                (usize::try_from(u64::from_be_bytes(b)).unwrap(), 10)
            }
            n => (usize::from(n), 2),
        };
        self.need(header + len).await;
        let payload = self.buf[header..header + len].to_vec();
        self.buf.drain(..header + len);
        (opcode, payload)
    }

    /// The next text frame as JSON, skipping pings.
    pub async fn json(&mut self) -> serde_json::Value {
        loop {
            let (opcode, payload) = self.frame().await;
            match opcode {
                0x1 => return serde_json::from_slice(&payload).unwrap(),
                0x9 => {}
                other => panic!("expected a text frame, got opcode {other}"),
            }
        }
    }

    /// Reads until the close frame, skipping pings and text, and returns its code.
    pub async fn close_code(&mut self) -> u16 {
        loop {
            let (opcode, payload) = self.frame().await;
            if opcode == 0x8 {
                return u16::from_be_bytes([payload[0], payload[1]]);
            }
        }
    }

    /// Sends a masked text frame, as a client must.
    pub async fn send_text(&mut self, text: &str) {
        let mask = [0x1d_u8, 0x2e, 0x3f, 0x40];
        let len = text.len();
        let mut frame = vec![0x81];
        if len < 126 {
            frame.push(0x80 | u8::try_from(len).unwrap());
        } else {
            frame.push(0x80 | 0x7e);
            frame.extend_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        frame.extend(text.bytes().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        self.stream.write_all(&frame).await.unwrap();
    }
}
