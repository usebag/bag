//! The receipt bound of spec/SPEC.md §8.2 step 6 (adopted 2026-10-25), the
//! `received_at` of `env` frames and of fetch, the envelope as a JSON string of its exact stored bytes, the
//! principal's fetch and delivery at least once (§8.5). An in-process relay over a real
//! SQLite file under `AC_TEST_TMP`, on a real loopback socket, with a `ManualClock` (`common::Server`). A line that
//! measures prints `MEASURE <line>: ...` (visible with `--nocapture`) and asserts what was predicted.

mod common;

use ac_core::chain::Hop;
use ac_core::envelope::Envelope;
use ac_core::records::Roots;
use ac_relay::Config;
use common::{NOW, Reply, Server, Ws, addr, bytes, envelope, key, subscribe, ws_send};
use futures_util::StreamExt as _;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

/// The earliest `exp` of the chains of L1: the relay's default skew before `NOW`, so that `NOW` is the bound's last
/// second.
const E: u64 = NOW - 300;

async fn hosted(config: Config) -> Server {
    let s = Server::start(config).await;
    s.host(2, Roots::Any, 65_536, 3_600, NOW).await;
    s
}

fn status(r: &Reply) -> (u16, String) {
    let code = if r.status == 200 { String::new() } else { r.error() };
    (r.status, code)
}

fn delivered(r: &Reply) -> String {
    if r.status == 200 { r.json()["delivered"].to_string() } else { "-".to_owned() }
}

/// `key(20)` grants `key(21)` until `first`, which grants `key(22)` until `last` (chain rule 7: `last <= first`).
fn two_hops(first: u64, last: u64) -> Vec<Hop> {
    vec![
        Hop::sign(&key(20), &addr(21), vec![], first).unwrap(),
        Hop::sign(&key(21), &addr(22), vec![], last).unwrap(),
    ]
}

/// The next text frame's exact text, skipping pings; panics on a close or after 5 s.
async fn next_text(ws: &mut Ws) -> String {
    loop {
        let frame =
            tokio::time::timeout(Duration::from_secs(5), ws.next()).await.expect("a frame within 5 s");
        match frame.expect("an open socket").expect("a frame") {
            Message::Text(t) => return t.as_str().to_owned(),
            Message::Ping(_) | Message::Pong(_) => {}
            other => panic!("expected a text frame, got {other:?}"),
        }
    }
}

async fn until_acked(s: &Server, cursor: u64) {
    for _ in 0..100 {
        if s.relay.store().acked(addr(2).as_str(), addr(2).as_str()).unwrap() == Some(cursor) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the relay never stored the ack of cursor {cursor}");
}

/// L1 (a): stored when received at min(exp) + skew, `hop-expired` one second later with nothing stored; past the
/// bound the same stored bytes are `hop-expired`, not a duplicate (the bound runs before dedup, step 6a).
#[tokio::test]
async fn l1_the_bound_holds_to_the_second_of_min_exp_plus_skew() {
    let s = hosted(Config::default()).await;
    let chain = two_hops(E + 600, E);
    let in_time = bytes(&envelope(22, &[addr(2)], chain.clone(), E - 1));
    let at_bound = s.publish(&in_time).await;
    s.clock.set(E + 301);
    let late_env = envelope(22, &[addr(2)], chain, E - 2);
    let late = s.publish(&bytes(&late_env)).await;
    let rows = s.relay.store().last_cursor(addr(2).as_str()).unwrap();
    let fetched = s.fetch(&late_env.id_hex(), &key(2), E + 301, &[]).await;
    let again = s.publish(&in_time).await;
    s.clock.set(E + 300);
    let duplicate = s.publish(&in_time).await;
    eprintln!(
        "MEASURE L1(a): chain exps E + 600 and E, ts E - 1, relay skew 300: received at E + 300 {:?} delivered {}; \
         at E + 301 {:?}, mailbox rows {rows}, its fetch {:?}; the stored bytes again at E + 301 {:?}, at E + 300 \
         {:?} duplicate {}",
        status(&at_bound),
        delivered(&at_bound),
        status(&late),
        status(&fetched),
        status(&again),
        status(&duplicate),
        duplicate.json()["duplicate"]
    );
    assert_eq!((at_bound.status, delivered(&at_bound).as_str()), (200, "1"));
    assert_eq!(status(&late), (422, "hop-expired".to_owned()));
    assert_eq!(rows, 1, "the late envelope is not stored");
    assert_eq!(status(&fetched), (404, "not-found".to_owned()));
    assert_eq!(status(&again), (422, "hop-expired".to_owned()), "past the bound before dedup");
    assert_eq!((duplicate.status, duplicate.json()["duplicate"].clone()), (200, true.into()));
    s.stop().await;
}

/// L1 (a): the skew is the relay's own `--skew`, not a second constant.
#[tokio::test]
async fn l1_the_bound_uses_the_relays_own_skew() {
    let s = hosted(Config { skew: 10, ..Config::default() }).await;
    let chain = two_hops(E + 600, E);
    s.clock.set(E + 10);
    let at_bound = s.publish(&bytes(&envelope(22, &[addr(2)], chain.clone(), E - 1))).await;
    s.clock.set(E + 11);
    let late = s.publish(&bytes(&envelope(22, &[addr(2)], chain, E - 2))).await;
    eprintln!(
        "MEASURE L1(a): relay skew 10: received at E + 10 {:?} delivered {}; at E + 11 {:?}",
        status(&at_bound),
        delivered(&at_bound),
        status(&late)
    );
    assert_eq!((at_bound.status, delivered(&at_bound).as_str()), (200, "1"));
    assert_eq!(status(&late), (422, "hop-expired".to_owned()));
    s.stop().await;
}

/// L1 (a): an empty chain has no `exp`, so only the ts window judges it.
#[tokio::test]
async fn l1_an_empty_chain_meets_no_receipt_bound() {
    let s = hosted(Config::default()).await;
    let old = s.publish(&bytes(&envelope(1, &[addr(2)], vec![], NOW - 604_800))).await;
    assert_eq!((old.status, delivered(&old).as_str()), (200, "1"), "{}", old.text());
    s.stop().await;
}

/// L1 (b): every `env` frame and every fetch name the second the relay stored the envelope; a later duplicate
/// publish moves neither.
#[tokio::test]
async fn l1_frames_and_fetch_carry_the_second_the_relay_stored_it() {
    let s = hosted(Config::default()).await;
    let env = envelope(1, &[addr(2)], vec![], NOW);
    s.clock.set(NOW + 5);
    assert_eq!(s.publish(&bytes(&env)).await.status, 200);
    s.clock.set(NOW + 20);
    let again = s.publish(&bytes(&env)).await;
    assert_eq!(again.json()["duplicate"], true);
    let (mut ws, _) = subscribe(&s, &key(2), &addr(2), &[], None).await;
    let frame: serde_json::Value = serde_json::from_str(&next_text(&mut ws).await).unwrap();
    let r = s.fetch(&env.id_hex(), &key(2), NOW + 20, &[]).await;
    eprintln!(
        "MEASURE L1(b): stored at NOW + 5, published again at NOW + 20: frame received_at {}, fetch AC-Received-At \
         {:?}",
        frame["received_at"],
        r.header("ac-received-at")
    );
    assert_eq!(frame["received_at"], NOW + 5);
    assert_eq!((r.status, r.header("ac-received-at")), (200, Some((NOW + 5).to_string().as_str())));
    assert_eq!(r.body, bytes(&env));
    s.stop().await;
}

/// The text with `after_colon` after every `:` and `after_comma` after every `,` that is not inside a string.
fn respace(text: &str, after_colon: &str, after_comma: &str) -> String {
    let (mut out, mut in_string, mut escaped) = (String::new(), false, false);
    for c in text.chars() {
        out.push(c);
        if in_string {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
        } else if c == ':' {
            out.push_str(after_colon);
        } else if c == ',' {
            out.push_str(after_comma);
        }
    }
    out
}

/// L2 (a): one envelope's values in six layouts, each on a relay of its own (they share one id); the frame's
/// `envelope` is a JSON string whose UTF-8 bytes are the published bytes, and so is fetch's body.
#[tokio::test]
async fn l2_every_layout_comes_back_byte_for_byte() {
    let hop = Hop::sign(&key(20), &addr(22), vec!["repo=café".into()], NOW + 3_600).unwrap();
    let env = envelope(22, &[addr(2)], vec![hop], NOW);
    let default = env.to_json_text();
    let value: serde_json::Value = serde_json::from_str(&default).unwrap();
    let names = ["v", "id", "to", "from", "auth", "suite", "ts", "sealed", "sig"];
    let reversed: Vec<String> =
        names.iter().rev().map(|n| format!("{}:{}", serde_json::Value::from(*n), value[n])).collect();
    let layouts = [
        ("the default writer", default.clone()),
        ("members in reverse order", format!("{{{}}}", reversed.join(","))),
        ("a space after every : and ,", respace(&default, " ", " ")),
        ("two-space indentation", serde_json::to_string_pretty(&value).unwrap()),
        ("the caveat's non-ASCII raw", default.clone()),
        ("the caveat's non-ASCII escaped", default.replace('é', "\\u00e9")),
    ];
    let (mut identical, mut fetched_identical, mut by_writer, mut by_library) = (0, 0, 0, 0);
    for (label, layout) in &layouts {
        let s = hosted(Config::default()).await;
        let r = s.publish(layout.as_bytes()).await;
        assert_eq!((r.status, delivered(&r).as_str()), (200, "1"), "{label}: {}", r.text());
        let (mut ws, _) = subscribe(&s, &key(2), &addr(2), &[], None).await;
        let frame: serde_json::Value = serde_json::from_str(&next_text(&mut ws).await).unwrap();
        let members: Vec<&str> = frame.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(members, ["cursor", "envelope", "received_at", "t"], "{label}");
        let text = frame["envelope"].as_str().unwrap_or_else(|| panic!("{label}: not a string: {frame}"));
        identical += usize::from(text.as_bytes() == layout.as_bytes());
        let got = s.fetch(&env.id_hex(), &key(2), NOW, &[]).await;
        fetched_identical += usize::from(got.body == layout.as_bytes());
        by_writer += usize::from(Envelope::parse(layout.as_bytes()).unwrap().to_json_text() != *layout);
        let parsed: serde_json::Value = serde_json::from_str(layout).unwrap();
        by_library += usize::from(serde_json::to_string(&parsed).unwrap() != *layout);
        s.stop().await;
    }
    eprintln!(
        "MEASURE L2(a): {identical} of 6 frames carry the published bytes exactly, fetch {fetched_identical} of 6; \
         the layouts a re-serialization would change: by the reference writer {by_writer} of 6, by a JSON library \
         (serde_json, members sorted) {by_library} of 6; layouts 1 and 5 are the same bytes: {}",
        layouts[0].1 == layouts[4].1
    );
    assert_eq!((identical, fetched_identical), (6, 6));
    assert!(by_library >= 5, "a re-serializing relay would fail the check for at least 5 of the 6");
}

/// L3: fetch by id admits `from`, a `to`, the principal (the last hop's `iss`) and a chain from any of them; the org
/// root of a two-hop chain, a third party and their delegates are 403.
#[tokio::test]
async fn l3_the_principal_and_its_sessions_fetch_and_the_org_root_does_not() {
    let s = hosted(Config::default()).await;
    let org_to_principal = Hop::sign(&key(40), &addr(41), vec![], NOW + 3_600).unwrap();
    let principal_to_session = Hop::sign(&key(41), &addr(42), vec![], NOW + 3_600).unwrap();
    let env = envelope(42, &[addr(2)], vec![org_to_principal, principal_to_session], NOW);
    assert_eq!(s.publish(&bytes(&env)).await.status, 200);
    let id = env.id_hex();
    let hop = |from: u8, to: u8| vec![Hop::sign(&key(from), &addr(to), vec![], NOW + 600).unwrap()];
    let cases: [(&str, u8, Vec<Hop>); 8] = [
        ("from, the session", 42, vec![]),
        ("to", 2, vec![]),
        ("the principal", 41, vec![]),
        ("the principal's own session", 43, hop(41, 43)),
        ("the org root", 40, vec![]),
        ("a third party", 9, vec![]),
        ("a third party's delegate", 44, hop(9, 44)),
        ("the org root's delegate", 45, hop(40, 45)),
    ];
    let mut seen = Vec::new();
    for (label, n, hops) in &cases {
        let r = s.fetch(&id, &key(*n), NOW, hops).await;
        let exact = r.status == 200
            && r.body == bytes(&env)
            && r.header("ac-received-at") == Some(NOW.to_string().as_str());
        seen.push((*label, status(&r), exact));
    }
    eprintln!("MEASURE L3: {seen:?}");
    let ok = (200, String::new());
    let refused = (403, "not-authorized".to_owned());
    let want = [&ok, &ok, &ok, &ok, &refused, &refused, &refused, &refused];
    for ((label, got, exact), want) in seen.iter().zip(want) {
        assert_eq!(got, want, "{label}");
        assert_eq!(*exact, got.0 == 200, "{label}: the exact bytes and AC-Received-At with every 200");
    }
    s.stop().await;
}

/// L4 (a): delivery is at least once. Frames not acked come again, byte for byte, to the next subscription that
/// resumes from the stored ack; acked ones do not; an ack deletes nothing, so fetch and a delegate from cursor 0
/// still read every envelope.
#[tokio::test]
async fn l4_unacked_frames_come_again_after_a_resubscribe() {
    let s = hosted(Config::default()).await;
    let envs: Vec<Envelope> = (0..3).map(|i| envelope(1, &[addr(2)], vec![], NOW - i)).collect();
    for env in &envs {
        assert_eq!(s.publish(&bytes(env)).await.status, 200);
    }
    let (mut ws, start) = subscribe(&s, &key(2), &addr(2), &[], None).await;
    let mut first = Vec::new();
    for _ in 0..3 {
        first.push(next_text(&mut ws).await);
    }
    ws_send(&mut ws, &serde_json::json!({"t": "ack", "cursor": 1})).await;
    until_acked(&s, 1).await;
    ws.close(None).await.unwrap();
    let (mut ws, resumed) = subscribe(&s, &key(2), &addr(2), &[], None).await;
    let again = [next_text(&mut ws).await, next_text(&mut ws).await];
    ws_send(&mut ws, &serde_json::json!({"t": "ack", "cursor": 3})).await;
    until_acked(&s, 3).await;
    ws.close(None).await.unwrap();
    let (mut ws, after_all) = subscribe(&s, &key(2), &addr(2), &[], None).await;
    let quiet = tokio::time::timeout(Duration::from_millis(300), ws.next()).await.is_err();
    ws.close(None).await.unwrap();
    let fetched = s.fetch(&envs[0].id_hex(), &key(2), NOW, &[]).await;
    let delegate = Hop::sign(&key(2), &addr(30), vec![], NOW + 600).unwrap();
    let (mut ws, from_zero) = subscribe(&s, &key(30), &addr(2), &[delegate], Some(0)).await;
    let mut delegated = Vec::new();
    for _ in 0..3 {
        delegated.push(next_text(&mut ws).await);
    }
    eprintln!(
        "MEASURE L4(a): first subscription cursor {start}, 3 frames, acked 1; again from the stored ack: cursor \
         {resumed}, frames 2 and 3 identical {}; after acking 3: cursor {after_all}, no frame {quiet}; fetch of \
         the first after its ack {}; a delegate from cursor 0 {from_zero}: 3 frames identical {}",
        again[..] == first[1..],
        fetched.status,
        delegated == first
    );
    assert_eq!((start, resumed, after_all, from_zero), (0, 1, 3, 0));
    assert_eq!(again[..], first[1..]);
    assert!(quiet, "no frame after everything was acked");
    assert_eq!((fetched.status, fetched.body.clone()), (200, bytes(&envs[0])));
    assert_eq!(delegated, first);
    s.stop().await;
}
