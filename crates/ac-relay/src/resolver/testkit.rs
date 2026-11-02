//! Fixtures for the domain tests (resolver and policy): org records signed with keys from fixed seeds (test data by
//! construction, never a real key), a fake fetch, and a raw HTTP server on loopback.

use super::{FetchResult, Fetching, WellKnownFetch};
use crate::dns::{Looking, TxtLookup, TxtRecord};
use crate::testkit::{addr, key};
use ac_core::Address;
use ac_core::discovery::RecordUrl;
use ac_core::records::{AddressRecord, Domain, Record};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

pub fn domain(host: &str) -> Domain {
    Domain::parse(host).unwrap()
}

/// The well-known URL of a host's record.
pub fn well_known(host: &str) -> RecordUrl {
    RecordUrl::well_known(&domain(host))
}

/// The address record of an org key `key(n)` at `iat` for `ttl`, revoking `revoked`, rotated from `key(from)` and
/// countersigned by `key(by)` when given.
pub fn org(
    n: u8,
    iat: u64,
    ttl: u64,
    revoked: &[Address],
    rotation: Option<(u8, Option<u8>)>,
) -> AddressRecord {
    let mut a = AddressRecord {
        key: addr(n),
        sealing_key: None,
        relays: vec![],
        rotation_key: None,
        revoked: revoked.to_vec(),
        ttl,
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
    let Record::Address(a) = r else { unreachable!() };
    a
}

pub fn org_bytes(
    n: u8,
    iat: u64,
    ttl: u64,
    revoked: &[Address],
    rotation: Option<(u8, Option<u8>)>,
) -> Vec<u8> {
    Record::Address(org(n, iat, ttl, revoked, rotation)).to_bytes()
}

/// A fetch that answers what a test set for each host, and counts the calls and keeps the URLs; an unset host is a
/// 404.
#[derive(Default)]
pub struct FakeFetch {
    answers: Mutex<HashMap<String, FetchResult>>,
    calls: Mutex<HashMap<String, usize>>,
    urls: Mutex<Vec<String>>,
    /// How long each fetch waits before it answers.
    pub delay: Mutex<Duration>,
}

impl FakeFetch {
    pub fn new() -> Arc<FakeFetch> {
        Arc::new(FakeFetch::default())
    }

    pub fn set(&self, host: &str, answer: FetchResult) {
        self.answers.lock().unwrap().insert(host.to_owned(), answer);
    }

    pub fn calls(&self, host: &str) -> usize {
        self.calls.lock().unwrap().get(host).copied().unwrap_or(0)
    }

    /// Every URL fetched, in order.
    pub fn urls(&self) -> Vec<String> {
        self.urls.lock().unwrap().clone()
    }
}

impl WellKnownFetch for FakeFetch {
    fn fetch<'a>(&'a self, url: &'a RecordUrl) -> Fetching<'a> {
        Box::pin(async move {
            let host = url.host().as_str();
            *self.calls.lock().unwrap().entry(host.to_owned()).or_default() += 1;
            self.urls.lock().unwrap().push(url.to_string());
            let delay = *self.delay.lock().unwrap();
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let answers = self.answers.lock().unwrap();
            answers.get(host).cloned().unwrap_or(Err(super::Failure::Status(404)))
        })
    }
}

/// A TXT lookup that answers what a test set for each name (none for any other), counts the lookups, and fails a
/// name set to an error.
#[derive(Default)]
pub struct FakeTxt {
    answers: Mutex<HashMap<String, Result<Vec<TxtRecord>, String>>>,
    lookups: Mutex<usize>,
}

impl FakeTxt {
    pub fn new() -> Arc<FakeTxt> {
        Arc::new(FakeTxt::default())
    }

    /// The domain's TXT records, each given as one string.
    pub fn set(&self, domain: &str, records: &[&str]) {
        let records = records.iter().map(|r| vec![r.as_bytes().to_vec()]).collect();
        self.answers.lock().unwrap().insert(format!("_bag.{domain}"), Ok(records));
    }

    pub fn fail(&self, domain: &str, why: &str) {
        self.answers.lock().unwrap().insert(format!("_bag.{domain}"), Err(why.to_owned()));
    }

    pub fn lookups(&self) -> usize {
        *self.lookups.lock().unwrap()
    }
}

impl TxtLookup for FakeTxt {
    fn lookup<'a>(&'a self, name: &'a str) -> Looking<'a> {
        *self.lookups.lock().unwrap() += 1;
        let answer = self.answers.lock().unwrap().get(name).cloned().unwrap_or(Ok(Vec::new()));
        Box::pin(std::future::ready(answer))
    }

    fn source(&self) -> &'static str {
        "fixed"
    }
}

/// A raw HTTP server on loopback that writes `answer` to every connection after reading its request head, and
/// keeps the first bytes it read; `answer` None accepts and never answers.
pub struct RawServer {
    pub addr: SocketAddr,
    connections: Arc<AtomicUsize>,
    first_bytes: Arc<Mutex<Vec<u8>>>,
}

impl RawServer {
    pub async fn start(answer: Option<Vec<u8>>) -> RawServer {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let first_bytes = Arc::new(Mutex::new(Vec::new()));
        let (count, first) = (Arc::clone(&connections), Arc::clone(&first_bytes));
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::SeqCst);
                let (answer, first) = (answer.clone(), Arc::clone(&first));
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4_096];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    {
                        let mut seen = first.lock().unwrap();
                        if seen.is_empty() {
                            seen.extend_from_slice(&buf[..n]);
                        }
                    }
                    match answer {
                        Some(bytes) => {
                            let _ = socket.write_all(&bytes).await;
                            let _ = socket.shutdown().await;
                        }
                        None => tokio::time::sleep(Duration::from_secs(30)).await,
                    }
                });
            }
        });
        RawServer { addr, connections, first_bytes }
    }

    /// A server that answers `status` with `body` as JSON, and an optional extra header line.
    pub async fn http(status: &str, body: &[u8], extra: &str) -> RawServer {
        let mut answer = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n{extra}connection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        answer.extend_from_slice(body);
        RawServer::start(Some(answer)).await
    }

    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    pub fn first_bytes(&self) -> Vec<u8> {
        self.first_bytes.lock().unwrap().clone()
    }
}
