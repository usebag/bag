//! The pairing rendezvous over HTTP (src/pair.rs): open, claim,
//! expiry, the codes of each refusal, and the request limits a publish to an open invitation meets.

mod common;

use ac_core::canonical::Value;
use ac_core::hex;
use ac_core::records::Roots;
use ac_relay::Config;
use common::{NOW, Server, addr, envelope, key};
use serde_json::json;

/// An open of `key(invitation)`'s invitation for `ttl`, signed by that key over
/// `["ac/pair-open/1", inviter, invitation, relays, ttl]`.
fn body(invitation: u8, ttl: u64) -> Vec<u8> {
    let (inviter, i, relay) = (addr(1).to_string(), addr(invitation).to_string(), "https://relay.test");
    let pre = Value::Array(vec![
        Value::from("ac/pair-open/1"),
        Value::from(inviter.as_str()),
        Value::from(i.as_str()),
        Value::Array(vec![Value::from(relay)]),
        Value::Int(ttl),
    ]);
    let sig = hex::encode(&key(invitation).sign_preimage(&pre).unwrap());
    json!({"inviter": inviter, "invitation": i, "relays": [relay], "ttl": ttl, "sig": sig})
        .to_string()
        .into_bytes()
}

async fn open(s: &Server, invitation: u8, ttl: u64) -> String {
    let r = s.post("/v0/pair/open", &body(invitation, ttl)).await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.header("content-type"), Some("application/json"));
    let n = r.json()["nameplate"].as_str().unwrap().to_owned();
    assert!(n.len() == 3 && !n.starts_with('0') && n.bytes().all(|c| c.is_ascii_digit()), "{n}");
    n
}

#[tokio::test]
async fn an_open_nameplate_is_claimed_until_it_expires() {
    let s = Server::start(Config::default()).await;
    let n = open(&s, 2, 120).await;
    let want = json!({"inviter": addr(1).to_string(), "invitation": addr(2).to_string(),
        "relays": ["https://relay.test"], "exp": NOW + 120});
    for _ in 0..2 {
        let r = s.get(&format!("/v0/pair/claim/{n}"), &[]).await;
        assert_eq!((r.status, r.json()), (200, want.clone()));
    }
    s.clock.advance(120);
    let r = s.get(&format!("/v0/pair/claim/{n}"), &[]).await;
    assert_eq!((r.status, r.error()), (404, "no-nameplate".to_owned()));
    s.stop().await;
}

#[tokio::test]
async fn a_claim_of_no_open_nameplate_is_404_no_nameplate() {
    let s = Server::start(Config::default()).await;
    for path in ["/v0/pair/claim/100", "/v0/pair/claim/0472", "/v0/pair/claim/abc", "/v0/pair/claim/%FF"] {
        let r = s.get(path, &[]).await;
        assert_eq!((r.status, r.error()), (404, "no-nameplate".to_owned()), "{path}");
    }
    s.stop().await;
}

#[tokio::test]
async fn each_refused_open_has_its_status_and_code() {
    let s = Server::start(Config::default()).await;
    let r = s.post("/v0/pair/open", &body(2, 601)).await;
    assert_eq!((r.status, r.error()), (400, "bad-shape".to_owned()));
    // Signed by another key than the invitation's: 422 bad-sig, and no nameplate.
    let forged = String::from_utf8(body(3, 600)).unwrap().replace(&addr(3).to_string(), &addr(2).to_string());
    let r = s.post("/v0/pair/open", forged.as_bytes()).await;
    assert_eq!((r.status, r.error()), (422, "bad-sig".to_owned()));
    let r = s.post("/v0/pair/open", b"{").await;
    assert_eq!((r.status, r.error()), (400, "bad-json".to_owned()));
    let r = s.post("/v0/pair/open", &[b' '; 769]).await;
    assert_eq!((r.status, r.error()), (413, "body-too-large".to_owned()));
    open(&s, 2, 600).await;
    let r = s.post("/v0/pair/open", &body(2, 600)).await;
    assert_eq!((r.status, r.error()), (409, "stale-record".to_owned()));
    let r = s.get("/v0/pair/open", &[]).await;
    assert_eq!(r.status, 405);
    s.stop().await;
}

#[tokio::test]
async fn the_eleventh_claim_in_a_second_is_429_with_retry_after() {
    let s = Server::start(Config::default()).await;
    for _ in 0..10 {
        assert_eq!(s.get("/v0/pair/claim/100", &[]).await.status, 404);
    }
    let r = s.get("/v0/pair/claim/100", &[]).await;
    assert_eq!((r.status, r.error(), r.header("retry-after")), (429, "rate-limited".to_owned(), Some("1")));
    s.clock.advance(1);
    assert_eq!(s.get("/v0/pair/claim/100", &[]).await.status, 404);
    s.stop().await;
}

#[tokio::test]
async fn requests_to_an_open_invitation_are_five_at_once_then_one_a_second_and_ten_from_one_address() {
    let s = Server::start(Config::default()).await;
    s.host(2, Roots::Any, 65_536, 3_600, NOW).await;
    open(&s, 2, 600).await;
    let first = envelope(5, &[addr(2)], vec![], NOW);
    assert_eq!(s.publish(&first.to_bytes()).await.status, 200);
    // A duplicate is not a request.
    assert_eq!(s.publish(&first.to_bytes()).await.json()["duplicate"], true);
    for from in 6..10 {
        assert_eq!(s.publish(&envelope(from, &[addr(2)], vec![], NOW).to_bytes()).await.status, 200);
    }
    // The sixth in the first second: the nameplate's bucket is empty.
    let r = s.publish(&envelope(10, &[addr(2)], vec![], NOW).to_bytes()).await;
    assert_eq!((r.status, r.error(), r.header("retry-after")), (429, "rate-limited".to_owned(), Some("1")));
    // Then one a second; every test client is 127.0.0.1, so its tenth is the last.
    for t in 1..=5 {
        s.clock.advance(1);
        assert_eq!(s.publish(&envelope(5, &[addr(2)], vec![], NOW + t).to_bytes()).await.status, 200, "{t}");
        let r = s.publish(&envelope(6, &[addr(2)], vec![], NOW + t).to_bytes()).await;
        assert_eq!(r.status, 429, "{t}");
    }
    s.clock.advance(1);
    let r = s.publish(&envelope(5, &[addr(2)], vec![], NOW + 6).to_bytes()).await;
    assert_eq!((r.status, r.error(), r.header("retry-after")), (429, "rate-limited".to_owned(), Some("594")));
    // Mail to a mailbox with no open nameplate is not counted.
    s.host(3, Roots::Any, 65_536, 3_600, NOW).await;
    assert_eq!(s.publish(&envelope(5, &[addr(3)], vec![], NOW + 6).to_bytes()).await.status, 200);
    // Past exp the invitation's mailbox is ordinary mail again.
    s.clock.advance(594);
    assert_eq!(s.publish(&envelope(5, &[addr(2)], vec![], NOW + 600).to_bytes()).await.status, 200);
    s.stop().await;
}

#[tokio::test]
async fn a_publish_not_delivered_to_an_open_invitation_is_not_a_request() {
    let s = Server::start(Config::default()).await;
    s.host(3, Roots::Any, 65_536, 3_600, NOW).await;
    // The invitation 4 has a nameplate but no mailbox here: mail naming it beside 3 is delivered to 3 only.
    open(&s, 4, 600).await;
    for from in 5..12 {
        let r = s.publish(&envelope(from, &[addr(3), addr(4)], vec![], NOW).to_bytes()).await;
        assert_eq!((r.status, r.json()["delivered"].clone()), (200, json!(1)), "{from}");
    }
    s.stop().await;
}
