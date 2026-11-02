//! Fetch over HTTP (spec/SPEC.md §8.3): the sender, each recipient and a delegate get the exact stored bytes; a
//! third party gets 403; a failed proof 401, a proof for another base than the relay's own among them, whatever the
//! request's Host or forwarded headers name.

mod common;

use ac_core::chain::Hop;
use ac_core::records::Roots;
use ac_relay::Config;
use ac_relay::config::RateLimits;
use common::{NOW, Server, addr, envelope, key};

async fn server_with_one_envelope() -> (Server, String, Vec<u8>) {
    let s = Server::start(Config::default()).await;
    s.host(2, Roots::Any, 65_536, 3_600, NOW).await;
    let env = envelope(1, &[addr(2), addr(3)], vec![], NOW);
    // Published with extra white space: fetch returns these exact bytes, not a re-serialization.
    let body = env.to_json_text().replace(',', ", ").into_bytes();
    assert_eq!(s.publish(&body).await.status, 200);
    (s, env.id_hex(), body)
}

/// `fetches` a window for one client address, and one envelope stored for the fetches to reach.
async fn server_with_a_fetch_window(fetches: u32) -> (Server, String) {
    let rate = RateLimits { fetch_per_ip: fetches, ..RateLimits::default() };
    let s = Server::start(Config { rate, ..Config::default() }).await;
    s.host(2, Roots::Any, 65_536, 3_600, NOW).await;
    let env = envelope(1, &[addr(2)], vec![], NOW);
    assert_eq!(s.publish(env.to_json_text().as_bytes()).await.status, 200);
    (s, env.id_hex())
}

fn forged<'a>(signer: &'a str, ts: &'a str, sig: &'a str) -> [(&'a str, &'a str); 3] {
    [("AC-Signer", signer), ("AC-Ts", ts), ("AC-Sig", sig)]
}

#[tokio::test]
async fn both_fetch_shapes_share_one_window_that_refuses_before_the_signature() {
    let (s, id) = server_with_a_fetch_window(3).await;
    let path = format!("/v0/fetch/{id}");
    let record = format!("/v0/fetch/record/{}/accept-from", addr(2));
    let (signer, ts, sig) = (addr(2).to_string(), NOW.to_string(), "00".repeat(64));
    assert_eq!(s.fetch(&id, &key(2), NOW, &[]).await.status, 200);
    assert_eq!(s.get(&record, &[]).await.status, 200);
    // A forged proof reaches the verify inside the window, and it counts.
    let r = s.get(&path, &forged(&signer, &ts, &sig)).await;
    assert_eq!((r.status, r.error()), (401, "bad-auth".to_owned()));
    // Past it, a forged proof is not told it is forged: nothing verified it. A good one and a record wait too.
    let wait = (60 - NOW % 60).to_string();
    for r in [
        s.get(&path, &forged(&signer, &ts, &sig)).await,
        s.fetch(&id, &key(2), NOW, &[]).await,
        s.get(&record, &[]).await,
    ] {
        assert_eq!((r.status, r.error()), (429, "rate-limited".to_owned()));
        assert_eq!(r.header("retry-after"), Some(wait.as_str()));
    }
    s.stop().await;
}

#[tokio::test]
async fn a_used_up_fetch_window_leaves_publishes_alone_and_ends_with_its_window() {
    let (s, id) = server_with_a_fetch_window(1).await;
    assert_eq!(s.fetch(&id, &key(2), NOW, &[]).await.status, 200);
    assert_eq!(s.fetch(&id, &key(2), NOW, &[]).await.status, 429);
    let next = envelope(1, &[addr(2)], vec![], NOW + 1);
    assert_eq!(s.publish(next.to_json_text().as_bytes()).await.status, 200);
    s.clock.advance(60);
    assert_eq!(s.fetch(&id, &key(2), NOW + 60, &[]).await.status, 200);
    s.stop().await;
}

#[tokio::test]
async fn the_sender_and_each_recipient_get_the_exact_bytes() {
    let (s, id, body) = server_with_one_envelope().await;
    for n in [1, 2, 3] {
        let r = s.fetch(&id, &key(n), NOW, &[]).await;
        assert_eq!(r.status, 200, "key {n}: {}", r.text());
        assert_eq!(r.body, body);
        assert_eq!(r.header("content-type"), Some("application/json"));
    }
    s.stop().await;
}

#[tokio::test]
async fn a_third_party_is_403_and_a_delegate_of_a_party_is_200() {
    let (s, id, body) = server_with_one_envelope().await;
    let r = s.fetch(&id, &key(9), NOW, &[]).await;
    assert_eq!((r.status, r.error()), (403, "not-authorized".to_owned()));
    let hop = Hop::sign(&key(2), &addr(20), vec![], NOW + 60).unwrap();
    let r = s.fetch(&id, &key(20), NOW, &[hop]).await;
    assert_eq!((r.status, r.body), (200, body));
    let expired = Hop::sign(&key(2), &addr(20), vec![], NOW - 1).unwrap();
    let r = s.fetch(&id, &key(20), NOW, &[expired]).await;
    assert_eq!((r.status, r.error()), (403, "not-authorized".to_owned()));
    s.stop().await;
}

#[tokio::test]
async fn the_proof_must_verify_and_be_fresh() {
    let (s, id, _) = server_with_one_envelope().await;
    let r = s.fetch(&id, &key(2), NOW - 301, &[]).await;
    assert_eq!((r.status, r.error()), (401, "stale-ts".to_owned()));
    let r = s.fetch(&id, &key(2), NOW + 301, &[]).await;
    assert_eq!((r.status, r.error()), (401, "future-ts".to_owned()));
    let path = format!("/v0/fetch/{id}");
    let signer = addr(2).to_string();
    let ts = NOW.to_string();
    let sig = "00".repeat(64);
    let r = s.get(&path, &[("AC-Signer", &signer), ("AC-Ts", &ts), ("AC-Sig", &sig)]).await;
    assert_eq!((r.status, r.error()), (401, "bad-auth".to_owned()));
    let r = s.get(&path, &[("AC-Signer", &signer), ("AC-Ts", &ts)]).await;
    assert_eq!((r.status, r.error()), (401, "bad-auth".to_owned()));
    let r = s.get(&path, &[("AC-Signer", &signer), ("AC-Ts", &ts), ("AC-Sig", &sig), ("AC-Auth", "!")]).await;
    assert_eq!((r.status, r.error()), (401, "bad-auth".to_owned()));
    assert_eq!(s.get(&path, &[]).await.status, 401);
    s.stop().await;
}

#[tokio::test]
async fn unknown_and_malformed_ids() {
    let (s, _, _) = server_with_one_envelope().await;
    let unknown = "ab".repeat(32);
    let r = s.fetch(&unknown, &key(2), NOW, &[]).await;
    assert_eq!((r.status, r.error()), (404, "not-found".to_owned()));
    let r = s.fetch("xyz", &key(2), NOW, &[]).await;
    assert_eq!((r.status, r.error()), (400, "bad-hex".to_owned()));
    let r = s.get("/v0/fetch/%ff%fe", &[]).await;
    assert_eq!((r.status, r.error()), (400, "bad-hex".to_owned()));
    // A record path that does not decode is no address.
    let r = s.get("/v0/fetch/record/%ff%fe/key", &[]).await;
    assert_eq!((r.status, r.error()), (400, "bad-address".to_owned()));
    s.stop().await;
}

#[tokio::test]
async fn the_audience_is_a_configured_base_and_never_the_host_or_a_forwarded_header() {
    let config = Config {
        url: Some("https://relay.example".into()),
        accept_bases: vec!["https://old.example".into()],
        ..Config::default()
    };
    let s = Server::start(config).await;
    s.host(2, Roots::Any, 65_536, 3_600, NOW).await;
    let env = envelope(1, &[addr(2)], vec![], NOW);
    assert_eq!(s.publish(env.to_json_text().as_bytes()).await.status, 200);
    let id = env.id_hex();
    for base in ["https://relay.example", "https://old.example"] {
        assert_eq!(s.fetch_for(&id, &key(2), NOW, &[], base, &[]).await.status, 200, "{base}");
    }
    // The client's Host header names http://<addr>, which is no base of this relay; a forwarded header names another.
    let host = format!("http://{}", s.addr);
    let forwarded = [
        ("X-Forwarded-Host", "evil.example"),
        ("X-Forwarded-Proto", "https"),
        ("Forwarded", "host=evil.example;proto=https"),
    ];
    for audience in [host.as_str(), "https://evil.example"] {
        let r = s.fetch_for(&id, &key(2), NOW, &[], audience, &forwarded).await;
        assert_eq!((r.status, r.error()), (401, "bad-auth".to_owned()), "{audience}");
    }
    s.stop().await;
}
