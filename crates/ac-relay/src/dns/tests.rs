//! The stub resolver against fake DNS servers on loopback, never a real one: the query it writes, the
//! answers it reads (strings, CNAME chains, NXDOMAIN), and every malformed answer:
//! truncation, bad compression pointers, a wrong id or question, an oversized datagram, strings that overrun; and
//! a fresh socket per query, connected to its server, so no other address can answer.

use super::{
    FixedTxt, MAX_CNAMES, PAYLOAD, Read, TxtLookup as _, UdpTxt, parse_resolv_conf, query, read_answer,
};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;

const NAME: &str = "_bag.acme.example";
const QUICK: Duration = Duration::from_millis(300);

/// A name in wire form.
fn wire(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        out.push(u8::try_from(label.len()).unwrap());
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// The question's bytes of a query: its name, type and class.
fn question_of(q: &[u8]) -> Vec<u8> {
    let mut end = 12;
    while q[end] != 0 {
        end += 1 + usize::from(q[end]);
    }
    q[12..end + 5].to_vec()
}

/// A response to `q` with these flags (QR set by the caller), its question, and raw answer records.
fn response(q: &[u8], flags: u16, answers: &[Vec<u8>]) -> Vec<u8> {
    let mut out = q[..2].to_vec();
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&[0, 1]);
    out.extend_from_slice(&u16::try_from(answers.len()).unwrap().to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&question_of(q));
    for a in answers {
        out.extend_from_slice(a);
    }
    out
}

/// A record: owner (wire bytes), type, class IN, TTL 60, data.
fn rr(owner: &[u8], kind: u16, data: &[u8]) -> Vec<u8> {
    let mut out = owner.to_vec();
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
    out.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
    out.extend_from_slice(data);
    out
}

fn txt_data(strings: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for s in strings {
        out.push(u8::try_from(s.len()).unwrap());
        out.extend_from_slice(s);
    }
    out
}

/// The pointer to the question's name, at offset 12.
const AT_QUESTION: [u8; 2] = [0xC0, 12];
const OK: u16 = 0x8180;

fn q(id: u16) -> Vec<u8> {
    query(NAME, id, true).unwrap()
}

fn records(read: Read) -> Vec<Vec<Vec<u8>>> {
    match read {
        Read::Records(r) => r,
        other => panic!("not records: {other:?}"),
    }
}

#[test]
fn the_query_asks_for_txt_with_recursion_and_edns() {
    let with = query(NAME, 0xABCD, true).unwrap();
    assert_eq!(&with[..12], &[0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1]);
    let name = wire(NAME);
    assert_eq!(&with[12..12 + name.len()], name.as_slice());
    assert_eq!(&with[12 + name.len()..12 + name.len() + 4], &[0, 16, 0, 1]);
    assert_eq!(&with[12 + name.len() + 4..], &[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]);
    let without = query(NAME, 7, false).unwrap();
    assert_eq!(without[11], 0);
    assert_eq!(without.len(), 12 + name.len() + 4);
    let long_label = format!("{}.example", "a".repeat(64));
    let long_name = vec!["a".repeat(63); 5].join(".");
    for bad in ["a..b", "", long_label.as_str(), long_name.as_str()] {
        assert!(query(bad, 1, true).is_err(), "{bad:?}");
    }
}

#[test]
fn resolv_conf_names_at_most_three_servers_and_the_loopback_by_default() {
    let text = "# comment\nsearch example\nnameserver 192.0.2.1 # main\nnameserver 2001:db8::53\n; nameserver 192.0.2.9\n\
                nameserver fe80::1%en0\nnameserver 192.0.2.2\nnameserver 192.0.2.3\n";
    let named: Vec<String> = parse_resolv_conf(text).iter().map(ToString::to_string).collect();
    assert_eq!(named, ["192.0.2.1:53", "[2001:db8::53]:53", "192.0.2.2:53"]);
    let default: Vec<String> =
        parse_resolv_conf("options ndots:1\n").iter().map(ToString::to_string).collect();
    assert_eq!(default, ["127.0.0.1:53", "[::1]:53"]);
}

#[tokio::test]
async fn the_fixed_table_answers_its_names_only() {
    let fixed = FixedTxt(vec![
        (NAME.to_owned(), vec![b"v=ac1; ".to_vec(), b"key=x".to_vec()]),
        (NAME.to_uppercase(), vec![b"other".to_vec()]),
        ("_bag.globex.example".to_owned(), vec![b"x".to_vec()]),
    ]);
    assert_eq!(fixed.lookup(NAME).await.unwrap().len(), 2);
    assert_eq!(fixed.lookup("_bag.nowhere.example").await, Ok(vec![]));
    assert_eq!((fixed.source(), UdpTxt::new(vec![], QUICK).source()), ("fixed", "dns"));
}

#[test]
fn an_answer_gives_every_txt_record_of_the_name_in_order() {
    let query = q(1);
    let a = rr(&AT_QUESTION, 16, &txt_data(&[b"v=ac1; key=", b"ed25519:x"]));
    let b = rr(&wire(NAME), 16, &txt_data(&[b"v=spf1 -all"]));
    let other = rr(&wire("other.example"), 16, &txt_data(&[b"not ours"]));
    let got = records(read_answer(&response(&query, OK, &[a, other, b]), 1, NAME));
    assert_eq!(
        got,
        vec![vec![b"v=ac1; key=".to_vec(), b"ed25519:x".to_vec()], vec![b"v=spf1 -all".to_vec()]]
    );
    let upper = response(&q(1), OK, &[rr(&wire(&NAME.to_uppercase()), 16, &txt_data(&[b"y"]))]);
    assert_eq!(records(read_answer(&upper, 1, NAME)).len(), 1, "names compare without case");
}

#[test]
fn nxdomain_and_an_empty_answer_are_no_records() {
    assert_eq!(read_answer(&response(&q(2), 0x8183, &[]), 2, NAME), Read::Records(vec![]));
    assert_eq!(read_answer(&response(&q(2), OK, &[]), 2, NAME), Read::Records(vec![]));
}

#[test]
fn a_cname_chain_is_followed_to_eight_and_no_further() {
    let query = q(3);
    let chain = |hops: usize| {
        let mut rrs = Vec::new();
        for i in 0..hops {
            let owner = if i == 0 { wire(NAME) } else { wire(&format!("c{i}.example")) };
            rrs.push(rr(&owner, 5, &wire(&format!("c{}.example", i + 1))));
        }
        rrs.push(rr(&wire(&format!("c{hops}.example")), 16, &txt_data(&[b"end"])));
        response(&query, OK, &rrs)
    };
    assert_eq!(records(read_answer(&chain(MAX_CNAMES), 3, NAME)), vec![vec![b"end".to_vec()]]);
    assert!(matches!(read_answer(&chain(MAX_CNAMES + 1), 3, NAME), Read::Failed(_)));
    let looped = response(
        &query,
        OK,
        &[rr(&wire(NAME), 5, &wire("a.example")), rr(&wire("a.example"), 5, &wire(NAME))],
    );
    assert!(matches!(read_answer(&looped, 3, NAME), Read::Failed(_)), "a loop stops at the bound");
    let short = response(&query, OK, &[rr(&wire(NAME), 5, &[&wire("a.example")[..], &[0]].concat())]);
    assert!(matches!(read_answer(&short, 3, NAME), Read::Failed(_)), "a CNAME must fill its data");
}

#[test]
fn every_malformed_answer_fails() {
    let query = q(4);
    let fails =
        |msg: &[u8], why: &str| assert!(matches!(read_answer(msg, 4, NAME), Read::Failed(_)), "{why}");
    fails(&response(&query, 0x8380, &[]), "truncated (TC)");
    fails(&response(&query, 0x8182, &[]), "SERVFAIL");
    fails(&response(&query, 0x8185, &[]), "REFUSED");
    fails(&response(&query, 0x8980, &[]), "another opcode");
    let mut oversized = response(&query, OK, &[rr(&AT_QUESTION, 16, &txt_data(&[&[b'x'; 255][..]; 5]))]);
    oversized.resize(PAYLOAD + 1, 0);
    fails(&oversized, "over 1,232 bytes");
    let forward = response(&query, OK, &[rr(&[0xC0, 200], 16, &txt_data(&[b"x"]))]);
    fails(&forward, "a pointer forward");
    let mut itself = response(&query, OK, &[]);
    let at = u8::try_from(itself.len()).unwrap();
    itself.extend_from_slice(&rr(&[0xC0, at], 16, &txt_data(&[b"x"])));
    itself[7] = 1;
    fails(&itself, "a pointer to itself");
    let mut looped = response(&query, OK, &[]);
    let at = looped.len();
    // A label, then a pointer back to that label: the pointer does not point before the labels it is read among.
    looped.extend_from_slice(&[1, b'a', 0xC0, u8::try_from(at).unwrap()]);
    looped.extend_from_slice(&rr(&[], 16, &txt_data(&[b"x"])));
    looped[7] = 1;
    fails(&looped, "a pointer loop");
    fails(&response(&query, OK, &[rr(&[0x40, 0], 16, &txt_data(&[b"x"]))]), "an extended label type");
    let long: Vec<u8> = (0..5).flat_map(|_| [&[63u8][..], &[b'a'; 63][..]].concat()).chain([0]).collect();
    fails(&response(&query, OK, &[rr(&long, 16, &txt_data(&[b"x"]))]), "a name over 255 bytes");
    fails(&response(&query, OK, &[rr(&AT_QUESTION, 16, &[5, b'a', b'b'])]), "strings that overrun");
    fails(&response(&query, OK, &[rr(&AT_QUESTION, 16, &[])]), "a TXT record with no string");
    let mut past = response(&query, OK, &[rr(&AT_QUESTION, 16, &txt_data(&[b"x"]))]);
    past.truncate(past.len() - 1);
    fails(&past, "a record past the message");
    let mut counted = response(&query, OK, &[]);
    counted[7] = 3;
    fails(&counted, "a count past the records");
}

#[test]
fn a_datagram_that_is_not_the_answer_is_a_mismatch() {
    let query = q(5);
    let answer = response(&query, OK, &[rr(&AT_QUESTION, 16, &txt_data(&[b"x"]))]);
    assert_eq!(read_answer(&answer, 6, NAME), Read::Mismatch, "another id");
    assert_eq!(read_answer(&answer, 5, "_bag.globex.example"), Read::Mismatch, "another name");
    assert_eq!(read_answer(&answer[..3], 5, NAME), Read::Mismatch, "too short");
    let mut not_response = answer.clone();
    not_response[2] &= 0x7F;
    assert_eq!(read_answer(&not_response, 5, NAME), Read::Mismatch, "a query, not a response");
    let name_len = wire(NAME).len();
    for (offset, what) in [(12 + name_len + 1, "another type"), (12 + name_len + 3, "another class")] {
        let mut other = answer.clone();
        other[offset] ^= 0x01;
        assert_eq!(read_answer(&other, 5, NAME), Read::Mismatch, "{what}");
    }
    let mut two = answer.clone();
    two[5] = 2;
    assert_eq!(read_answer(&two, 5, NAME), Read::Mismatch, "two questions");
    assert_eq!(read_answer(&response(&q(5), 0x8181, &[]), 5, NAME), Read::FormErr);
}

#[test]
fn random_damage_never_panics() {
    let query = q(9);
    let base = response(
        &query,
        OK,
        &[rr(&wire(NAME), 5, &wire("b.example")), rr(&wire("b.example"), 16, &txt_data(&[b"v=ac1", b"key"]))],
    );
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..2_000 {
        let mut msg = base.clone();
        for _ in 0..=(next() % 4) {
            let i = usize::try_from(next() % u64::try_from(msg.len()).unwrap()).unwrap();
            msg[i] = u8::try_from(next() & 0xFF).unwrap();
        }
        if next() % 5 == 0 {
            msg.truncate(usize::try_from(next() % u64::try_from(msg.len()).unwrap()).unwrap());
        }
        let _ = read_answer(&msg, 9, NAME);
    }
}

/// A fake DNS server on loopback: it keeps every query and sends back what `answer` makes of it.
struct FakeDns {
    addr: SocketAddr,
    queries: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl FakeDns {
    async fn start(answer: impl Fn(&[u8], usize) -> Vec<Vec<u8>> + Send + 'static) -> FakeDns {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let queries = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&queries);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4_096];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                let q = buf[..n].to_vec();
                let count = {
                    let mut all = seen.lock().unwrap();
                    all.push(q.clone());
                    all.len()
                };
                for datagram in answer(&q, count) {
                    let _ = socket.send_to(&datagram, from).await;
                }
            }
        });
        FakeDns { addr, queries }
    }

    fn queries(&self) -> Vec<Vec<u8>> {
        self.queries.lock().unwrap().clone()
    }
}

fn stub(servers: &[&FakeDns]) -> UdpTxt {
    UdpTxt::new(servers.iter().map(|s| s.addr).collect(), QUICK)
}

#[tokio::test]
async fn a_lookup_reads_the_answer_to_the_query_it_sent() {
    let server =
        FakeDns::start(|q, _| vec![response(q, OK, &[rr(&AT_QUESTION, 16, &txt_data(&[b"v=ac1"]))])]).await;
    assert_eq!(stub(&[&server]).lookup(NAME).await, Ok(vec![vec![b"v=ac1".to_vec()]]));
    let sent = server.queries();
    assert_eq!(sent.len(), 1);
    assert_eq!(&sent[0][2..], &query(NAME, 0, true).unwrap()[2..], "the query as written, its id aside");
}

#[tokio::test]
async fn a_wrong_id_or_question_is_discarded_and_the_right_answer_after_it_taken() {
    let server = FakeDns::start(|q, _| {
        let right = response(q, OK, &[rr(&AT_QUESTION, 16, &txt_data(&[b"right"]))]);
        let mut wrong_id = right.clone();
        wrong_id[1] ^= 0xFF;
        let mut wrong_name = response(q, OK, &[rr(&AT_QUESTION, 16, &txt_data(&[b"forged"]))]);
        wrong_name[13] ^= 0x20 ^ 0x01;
        vec![wrong_id, wrong_name, right]
    })
    .await;
    assert_eq!(stub(&[&server]).lookup(NAME).await, Ok(vec![vec![b"right".to_vec()]]));
    let forged_only = FakeDns::start(|q, _| {
        let mut wrong_id = response(q, OK, &[rr(&AT_QUESTION, 16, &txt_data(&[b"forged"]))]);
        wrong_id[0] ^= 0x01;
        vec![wrong_id]
    })
    .await;
    let failed = stub(&[&forged_only]).lookup(NAME).await.unwrap_err();
    assert!(failed.ends_with("no answer"), "{failed}");
}

#[tokio::test]
async fn a_failing_server_hands_over_to_the_next_and_every_failure_fails() {
    let servfail = FakeDns::start(|q, _| vec![response(q, 0x8182, &[])]).await;
    let good =
        FakeDns::start(|q, _| vec![response(q, OK, &[rr(&AT_QUESTION, 16, &txt_data(&[b"second"]))])]).await;
    assert_eq!(stub(&[&servfail, &good]).lookup(NAME).await, Ok(vec![vec![b"second".to_vec()]]));
    let truncated = FakeDns::start(|q, _| vec![response(q, 0x8380, &[])]).await;
    let failed = stub(&[&servfail, &truncated]).lookup(NAME).await.unwrap_err();
    assert!(failed.contains("truncated"), "{failed}");
    let silent = FakeDns::start(|_, _| vec![]).await;
    assert!(stub(&[&silent]).lookup(NAME).await.unwrap_err().ends_with("no answer"));
    assert_eq!(UdpTxt::new(vec![], QUICK).lookup(NAME).await, Err("no nameserver".to_owned()));
    let oversized = FakeDns::start(|q, _| {
        let mut big = response(q, OK, &[rr(&AT_QUESTION, 16, &txt_data(&[&[b'x'; 255][..]; 5]))]);
        big.resize(PAYLOAD + 40, 0);
        vec![big]
    })
    .await;
    assert!(stub(&[&oversized]).lookup(NAME).await.unwrap_err().contains("1,232"));
}

#[tokio::test]
async fn formerr_to_edns_is_asked_again_without_it() {
    let old = FakeDns::start(|q, _| {
        let edns = q[11] == 1;
        vec![if edns {
            response(q, 0x8181, &[])
        } else {
            response(q, OK, &[rr(&AT_QUESTION, 16, &txt_data(&[b"plain"]))])
        }]
    })
    .await;
    assert_eq!(stub(&[&old]).lookup(NAME).await, Ok(vec![vec![b"plain".to_vec()]]));
    let sent = old.queries();
    assert_eq!((sent.len(), sent[0][11], sent[1][11]), (2, 1, 0));
    let never = FakeDns::start(|q, _| vec![response(q, 0x8181, &[])]).await;
    assert!(stub(&[&never]).lookup(NAME).await.unwrap_err().ends_with("FORMERR"));
}

// ---- A fresh socket per query, connected to its server ------------------------------

#[tokio::test]
async fn each_query_leaves_from_a_fresh_socket_of_its_own_on_a_port_the_system_chose() {
    // A server that holds its answers until it has seen both queries: the two lookups were in flight at once, so a
    // socket shared between queries would show one source port, and two fresh sockets show two.
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let at = server.local_addr().unwrap();
    let serving = tokio::spawn(async move {
        let mut buf = vec![0u8; 4_096];
        let mut seen = Vec::new();
        while seen.len() < 2 {
            let (n, from) = server.recv_from(&mut buf).await.unwrap();
            seen.push((buf[..n].to_vec(), from));
        }
        for (q, from) in &seen {
            let answer = response(q, OK, &[rr(&AT_QUESTION, 16, &txt_data(&[b"x"]))]);
            server.send_to(&answer, from).await.unwrap();
        }
        seen.into_iter().map(|(_, from)| from).collect::<Vec<SocketAddr>>()
    });
    let stub = UdpTxt::new(vec![at], Duration::from_secs(2));
    let (a, b) = tokio::join!(stub.lookup(NAME), stub.lookup(NAME));
    assert_eq!((a.unwrap().len(), b.unwrap().len()), (1, 1));
    let from = serving.await.unwrap();
    assert_ne!(from[0].port(), from[1].port(), "two sockets, two ports");
    assert!(from.iter().all(|f| f.ip().is_loopback() && f.port() != 0 && f.port() != at.port()), "{from:?}");
}

#[tokio::test]
async fn a_datagram_from_another_address_is_never_read_though_it_carries_the_query_s_id_and_question() {
    // Each query's socket is connected to its server, so the system drops a datagram from any other address before
    // the stub reads it: a forger who learns the id and the question cannot answer from elsewhere.
    async fn server(answer: bool) -> SocketAddr {
        let (server, forger) =
            (UdpSocket::bind("127.0.0.1:0").await.unwrap(), UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let at = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4_096];
            while let Ok((n, from)) = server.recv_from(&mut buf).await {
                let q = buf[..n].to_vec();
                let lie = response(&q, OK, &[rr(&AT_QUESTION, 16, &txt_data(&[b"forged"]))]);
                let _ = forger.send_to(&lie, from).await;
                if answer {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    let right = response(&q, OK, &[rr(&AT_QUESTION, 16, &txt_data(&[b"right"]))]);
                    let _ = server.send_to(&right, from).await;
                }
            }
        });
        at
    }
    let both = server(true).await;
    assert_eq!(UdpTxt::new(vec![both], QUICK).lookup(NAME).await, Ok(vec![vec![b"right".to_vec()]]));
    let forger_only = server(false).await;
    let failed = UdpTxt::new(vec![forger_only], QUICK).lookup(NAME).await.unwrap_err();
    assert!(failed.ends_with("no answer"), "{failed}");
}
