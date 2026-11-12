//! Publish over HTTP against a relay on port 0 (spec/SPEC.md §8.2): accepted, duplicate, partial delivery, every
//! refusal with its status, and records.

mod common;

use ac_core::chain::Hop;
use ac_core::envelope::Envelope;
use ac_core::records::{AddressRecord, Record, Roots};
use ac_relay::Config;
use ac_relay::config::RateLimits;
use common::{NOW, Server, accept, addr, bytes, envelope, key, record_bytes, sealed, wire};

#[tokio::test]
async fn health_answers_ok_with_the_version_the_time_and_the_announced_url() {
    let s = Server::start(Config::default()).await;
    let r = s.get("/v0/health", &[]).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type"), Some("application/json"));
    // In process with no url, the test server sets http://<addr>, as the binary sets its announced URL (since
    // 2026-11-02, the first audience of a fetch proof), and health answers it.
    // Since 2026-11-11 it also states the envelope cap, an additive member.
    let want = serde_json::json!({"ok": true, "version": "0.0.0", "now": NOW, "url": s.base, "max_envelope_bytes": 196_608});
    assert_eq!(r.json(), want);
    assert_eq!(s.base, format!("http://{}", s.addr));
    s.stop().await;
    let url = Some("https://relay.example".to_owned());
    let s = Server::start(Config { url: url.clone(), ..Config::default() }).await;
    assert_eq!(s.get("/v0/health", &[]).await.json()["url"], "https://relay.example");
    s.stop().await;
}

#[tokio::test]
async fn an_envelope_is_accepted_once_and_then_a_duplicate() {
    let s = Server::start(Config::default()).await;
    s.host(2, Roots::Any, 65_536, 3_600, NOW).await;
    s.host(3, Roots::Any, 65_536, 3_600, NOW).await;
    let env = envelope(1, &[addr(2), addr(3)], vec![], NOW);
    let r = s.publish(&bytes(&env)).await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(
        r.json(),
        serde_json::json!({"ok": true, "id": env.id_hex(), "duplicate": false, "delivered": 2})
    );
    let again = s.publish(&bytes(&env)).await;
    assert_eq!(
        again.json(),
        serde_json::json!({"ok": true, "id": env.id_hex(), "duplicate": true, "delivered": 0})
    );
    assert_eq!(s.relay.store().last_cursor(addr(2).as_str()).unwrap(), 1);
    s.stop().await;
}

#[tokio::test]
async fn json_shape_and_form_are_400() {
    let s = Server::start(Config::default()).await;
    for (body, code) in [
        (&b"{not json"[..], "bad-json"),
        (b"", "bad-json"),
        (b"[]", "bad-shape"),
        (br#"{"kind":"memo"}"#, "bad-record"),
    ] {
        let r = s.publish(body).await;
        assert_eq!((r.status, r.error()), (400, code.to_owned()), "{}", String::from_utf8_lossy(body));
    }
    let mut v2 = wire(&envelope(1, &[addr(2)], vec![], NOW).to_json_text());
    v2["v"] = 2.into();
    let r = s.publish(v2.to_string().as_bytes()).await;
    assert_eq!((r.status, r.error()), (400, "bad-version".to_owned()));
    s.stop().await;
}

#[tokio::test]
async fn sizes_over_the_caps_are_413() {
    let s = Server::start(Config { body_limit: 4_096, max_envelope_bytes: 2_048, ..Config::default() }).await;
    let r = s.publish(&vec![b' '; 5_000]).await;
    assert_eq!((r.status, r.json()), (413, serde_json::json!({"error": "body-too-large"})));
    let big = Envelope::sign(&key(1), vec![addr(2)], vec![], NOW, sealed(&[addr(2)], 1_200)).unwrap();
    let r = s.publish(&bytes(&big)).await;
    // The refusal names the relay's cap beside the code, an additive member.
    assert_eq!(
        (r.status, r.json()),
        (413, serde_json::json!({"error": "envelope-too-large", "max_envelope_bytes": 2_048}))
    );
    s.stop().await;
}

#[tokio::test]
async fn health_states_the_configured_envelope_cap() {
    let s = Server::start(Config { max_envelope_bytes: 2_048, ..Config::default() }).await;
    let health = s.get("/v0/health", &[]).await.json();
    assert_eq!((health["max_envelope_bytes"].clone(), health["ok"].clone()), (2_048.into(), true.into()));
    s.stop().await;
}

#[tokio::test]
async fn verification_failures_are_422() {
    let s = Server::start(Config::default()).await;
    s.host(2, Roots::Any, 65_536, 3_600, NOW).await;
    let env = envelope(1, &[addr(2)], vec![], NOW);
    let mut wrong_id = wire(&env.to_json_text());
    wrong_id["ts"] = (NOW + 1).into();
    let mut wrong_sig = wire(&env.to_json_text());
    wrong_sig["sig"] = ac_core::hex::encode(&key(9).sign(&env.id)).into();
    let expired = Hop::sign(&key(10), &addr(1), vec![], NOW - 1).unwrap();
    let cases = [
        (wrong_id.to_string().into_bytes(), "bad-id"),
        (wrong_sig.to_string().into_bytes(), "bad-sig"),
        (bytes(&envelope(1, &[addr(2)], vec![expired], NOW)), "hop-expired"),
        (bytes(&envelope(1, &[addr(2)], vec![], NOW - 605_101)), "stale-ts"),
        (bytes(&envelope(1, &[addr(2)], vec![], NOW + 301)), "future-ts"),
    ];
    for (body, code) in cases {
        let r = s.publish(&body).await;
        assert_eq!((r.status, r.error()), (422, code.to_owned()));
    }
    s.stop().await;
}

#[tokio::test]
async fn hosting_policy_failures_are_403_and_partial_delivery_is_200() {
    let s = Server::start(Config::default()).await;
    let r = s.publish(&bytes(&envelope(1, &[addr(2)], vec![], NOW))).await;
    assert_eq!((r.status, r.error()), (403, "not-hosted".to_owned()));
    s.host(2, Roots::Listed(vec![addr(9)]), 65_536, 3_600, NOW).await;
    let r = s.publish(&bytes(&envelope(1, &[addr(2)], vec![], NOW))).await;
    assert_eq!((r.status, r.error()), (403, "root-not-accepted".to_owned()));
    let hop = Hop::sign(&key(9), &addr(1), vec!["type=coding.task".into()], NOW + 60).unwrap();
    let r = s.publish(&bytes(&envelope(1, &[addr(2)], vec![hop], NOW))).await;
    assert_eq!(r.status, 200, "{}", r.text());
    s.host(3, Roots::Any, 100, 3_600, NOW).await;
    let r = s.publish(&bytes(&envelope(1, &[addr(3)], vec![], NOW))).await;
    assert_eq!((r.status, r.error()), (403, "too-large-for-mailbox".to_owned()));
    s.host(4, Roots::Any, 65_536, 3_600, NOW).await;
    let r = s.publish(&bytes(&envelope(1, &[addr(2), addr(3), addr(4)], vec![], NOW - 1))).await;
    assert_eq!((r.status, r.json()["delivered"].clone()), (200, 1.into()), "{}", r.text());
    s.stop().await;
}

#[tokio::test]
async fn a_used_up_rate_limit_is_429_with_retry_after() {
    let rate = RateLimits { window: 60, per_from: 2, per_root: 100, per_ip: 100, ..RateLimits::default() };
    let s = Server::start(Config { rate, ..Config::default() }).await;
    s.host(2, Roots::Any, 65_536, 3_600, NOW).await;
    for ts in [NOW, NOW - 1] {
        assert_eq!(s.publish(&bytes(&envelope(1, &[addr(2)], vec![], ts))).await.status, 200);
    }
    s.clock.advance(20);
    let r = s.publish(&bytes(&envelope(1, &[addr(2)], vec![], NOW - 2))).await;
    assert_eq!((r.status, r.error()), (429, "rate-limited".to_owned()));
    assert_eq!(r.header("retry-after"), Some("40"));
    s.clock.advance(40);
    assert_eq!(s.publish(&bytes(&envelope(1, &[addr(2)], vec![], NOW - 2))).await.status, 200);
    s.stop().await;
}

#[tokio::test]
async fn records_are_published_and_fetched_publicly_and_a_stale_one_is_409() {
    let s = Server::start(Config::default()).await;
    let first = accept(2, Roots::Any, 1_000, 3_600, NOW - 5);
    let r = s.publish(&record_bytes(&first)).await;
    // The answer names what was stored; an accept-from record does not expire.
    let answer = serde_json::json!({"ok": true, "kind": "accept-from", "signer": addr(2).as_str(), "iat": NOW - 5,
        "valid_until": null});
    assert_eq!((r.status, r.json()), (200, answer));
    let path = format!("/v0/fetch/record/{}/accept-from", addr(2));
    assert_eq!(s.get(&path, &[]).await.body, record_bytes(&first));
    let newer = accept(2, Roots::Listed(vec![addr(4)]), 1_000, 3_600, NOW);
    assert_eq!(s.publish(&record_bytes(&newer)).await.status, 200);
    let fetched = s.get(&path, &[]).await;
    assert_eq!((fetched.status, fetched.body), (200, record_bytes(&newer)));
    for stale in [&first, &newer] {
        let r = s.publish(&record_bytes(stale)).await;
        assert_eq!((r.status, r.error()), (409, "stale-record".to_owned()));
    }
    let missing = s.get(&format!("/v0/fetch/record/{}/key", addr(2)), &[]).await;
    assert_eq!((missing.status, missing.error()), (404, "not-found".to_owned()));
    let bad = s.get("/v0/fetch/record/nobody/key", &[]).await;
    assert_eq!((bad.status, bad.error()), (400, "bad-address".to_owned()));
    s.stop().await;
}

#[tokio::test]
async fn a_countersigned_rotation_is_accepted_and_a_bare_one_refused() {
    let s = Server::start(Config::default()).await;
    let record = |n: u8, iat: u64, from: Option<u8>, by: Option<u8>| {
        let mut a = AddressRecord {
            key: addr(n),
            sealing_key: Some("aa".repeat(32)),
            relays: vec![],
            rotation_key: None,
            revoked: vec![],
            ttl: 3_600,
            iat,
            rotated_from: from.map(addr),
            rotation_sig: None,
            sig: [0; 64],
        };
        if let Some(by) = by {
            a.countersign(&key(by)).unwrap();
        }
        let mut r = Record::Address(a);
        r.sign(&key(n)).unwrap();
        record_bytes(&r)
    };
    assert_eq!(s.publish(&record(5, NOW - 10, None, None)).await.status, 200);
    let bare = s.publish(&record(6, NOW, Some(5), None)).await;
    assert_eq!((bare.status, bare.error()), (422, "bad-rotation".to_owned()));
    let forged = s.publish(&record(6, NOW, Some(5), Some(6))).await;
    assert_eq!((forged.status, forged.error()), (422, "bad-rotation".to_owned()));
    let good = s.publish(&record(6, NOW, Some(5), Some(5))).await;
    assert_eq!(good.status, 200, "{}", good.text());
    let fetched = s.get(&format!("/v0/fetch/record/{}/address", addr(6)), &[]).await;
    assert_eq!(fetched.body, record(6, NOW, Some(5), Some(5)));
    s.stop().await;
}

#[tokio::test]
async fn unknown_routes_are_404_json() {
    let s = Server::start(Config::default()).await;
    let r = s.get("/v1/anything", &[]).await;
    assert_eq!((r.status, r.error()), (404, "not-found".to_owned()));
    assert_eq!(s.get("/v0/publish", &[]).await.status, 405);
    let r = s.get("/v0/subscribe", &[]).await;
    assert_eq!((r.status, r.error()), (400, "bad-shape".to_owned()));
    s.stop().await;
}
