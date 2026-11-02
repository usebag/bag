//! The relay's policy under abuse: an in-process relay over a real SQLite file under
//! `AC_TEST_TMP`, on a real loopback socket, with a `ManualClock` at `NOW` (`common::Server`). Lines A2, R1's
//! relay half, R3 (measure), R4 (measure), the rotation from an unknown previous key (measure), an older record
//! after a newer one, A5, A7, the relay half of the repeated-member-name line, and the later-added R6.
//! A line that measures prints `MEASURE <line>: ...` (visible with `--nocapture`) and asserts
//! what was observed; a line that names a refusal asserts that refusal. R3 and R4 assert the fixed behaviour
//! now, and R6 too, with what the relay before the fixes did in their doc comments.

mod common;

use ac_core::chain::Hop;
use ac_core::records::{AddressRecord, Record, Roots};
use ac_relay::Config;
use common::{NOW, Reply, Server, addr, bytes, envelope, key, record_bytes};

/// A relay on the manual clock that hosts mailbox `key(2)` for every root.
async fn hosted(config: Config) -> Server {
    let s = Server::start(config).await;
    s.host(2, Roots::Any, 65_536, 3_600, NOW).await;
    s
}

fn status(r: &Reply) -> (u16, String) {
    let code = if r.status == 200 { String::new() } else { r.error() };
    (r.status, code)
}

#[tokio::test]
async fn a2_a_burst_from_one_from_is_refused_at_the_121st() {
    let s = hosted(Config::default()).await;
    for i in 0..120 {
        let r = s.publish(&bytes(&envelope(1, &[addr(2)], vec![], NOW - i))).await;
        assert_eq!(r.status, 200, "publish {}: {}", i + 1, r.text());
    }
    let refused = s.publish(&bytes(&envelope(1, &[addr(2)], vec![], NOW - 120))).await;
    assert_eq!(status(&refused), (429, "rate-limited".to_owned()));
    let retry: u64 = refused.header("retry-after").unwrap().parse().unwrap();
    assert!((1..=60).contains(&retry), "Retry-After {retry}");
    assert_eq!(s.relay.store().last_cursor(addr(2).as_str()).unwrap(), 120, "the 120 before it are stored");
    s.clock.advance(retry);
    let next = s.publish(&bytes(&envelope(1, &[addr(2)], vec![], NOW - 121))).await;
    assert_eq!(next.status, 200, "the next window accepts: {}", next.text());
    assert_eq!(s.relay.store().last_cursor(addr(2).as_str()).unwrap(), 121);
    s.stop().await;
}

#[tokio::test]
async fn r1_the_same_bytes_twice_are_a_duplicate_stored_once() {
    let s = hosted(Config::default()).await;
    let env = bytes(&envelope(1, &[addr(2)], vec![], NOW));
    assert_eq!(s.publish(&env).await.json()["delivered"], 1);
    let again = s.publish(&env).await.json();
    assert_eq!((again["duplicate"].clone(), again["delivered"].clone()), (true.into(), 0.into()));
    assert_eq!(s.relay.store().last_cursor(addr(2).as_str()).unwrap(), 1, "one stored row");
    s.stop().await;
}

/// R3, since fixed: the sweep keeps a tombstone of the id until `ts + ttl + skew`,
/// which dedup reads. Before the fix the same bytes were stored again after the sweep (200 `duplicate: false`,
/// `delivered` 1, cursor 2).
#[tokio::test]
async fn r3_a_replay_after_the_sweep_is_a_duplicate_until_the_window_ends() {
    let s = hosted(Config { ttl: 10, ..Config::default() }).await;
    let env = envelope(1, &[addr(2)], vec![], NOW);
    let id = env.id_hex();
    assert_eq!(s.publish(&bytes(&env)).await.json()["delivered"], 1);
    s.clock.advance(11);
    let swept = ac_relay::sweeper::sweep_once(&s.relay).unwrap();
    assert_eq!((swept.envelopes, swept.tombstoned), (1, 1), "swept: {swept:?}");
    assert_eq!(s.relay.store().envelope(&id, 0).unwrap(), None, "the bytes are gone");
    // Same bytes, same ts: 11 s old, inside the window of ttl + skew = 310 s.
    let r = s.publish(&bytes(&env)).await;
    let body = r.json();
    let cursor = s.relay.store().last_cursor(addr(2).as_str()).unwrap();
    eprintln!(
        "MEASURE R3: replay after the sweep: status {}, duplicate {}, delivered {}, mailbox cursor {cursor}",
        r.status, body["duplicate"], body["delivered"]
    );
    assert_eq!(
        (r.status, body["duplicate"].clone(), body["delivered"].clone()),
        (200, true.into(), 0.into())
    );
    assert_eq!(cursor, 1, "no new mailbox row");
    // At ts + ttl + skew the tombstone still holds; one second later it is swept, and the bytes are stale.
    s.clock.set(NOW + 310);
    assert_eq!(ac_relay::sweeper::sweep_once(&s.relay).unwrap().tombstones_expired, 0);
    assert_eq!(s.publish(&bytes(&env)).await.json()["duplicate"], true);
    s.clock.set(NOW + 311);
    let swept = ac_relay::sweeper::sweep_once(&s.relay).unwrap();
    assert_eq!(swept.tombstones_expired, 1, "{swept:?}");
    assert!(!s.relay.store().has_envelope(&id, NOW + 311).unwrap(), "the tombstone is gone");
    let late = s.publish(&bytes(&env)).await;
    eprintln!("MEASURE R3: the same bytes after the tombstone: {:?}", status(&late));
    assert_eq!(status(&late), (422, "stale-ts".to_owned()));
    s.stop().await;
}

/// R4, since fixed: dedup now runs before the `from` and root
/// limits, so a replay counts against the client address that sent it only. Before the fix the replays locked the victim
/// out (119 duplicates, the 120th 429, the victim's genuine publish 429).
#[tokio::test]
async fn r4_replays_of_a_captured_envelope_no_longer_lock_out_its_sender() {
    let s = hosted(Config::default()).await;
    let captured = bytes(&envelope(1, &[addr(2)], vec![], NOW));
    assert_eq!(s.publish(&captured).await.status, 200, "the victim's genuine publish");
    let (mut duplicates, mut limited) = (0, 0);
    for _ in 0..120 {
        let r = s.publish(&captured).await;
        match status(&r) {
            (200, _) if r.json()["duplicate"] == true => duplicates += 1,
            (429, code) if code == "rate-limited" => limited += 1,
            other => panic!("replay answered {other:?}"),
        }
    }
    let victim = s.publish(&bytes(&envelope(1, &[addr(2)], vec![], NOW - 1))).await;
    let delivered =
        if victim.status == 200 { victim.json()["delivered"].to_string() } else { "-".to_owned() };
    eprintln!(
        "MEASURE R4: 120 replays: {duplicates} answered duplicate, {limited} answered 429; the victim's new \
         envelope: {:?}, delivered {delivered}",
        status(&victim)
    );
    assert_eq!((duplicates, limited), (120, 0));
    assert_eq!((status(&victim), delivered.as_str()), ((200, String::new()), "1"));
    assert_eq!(
        s.relay.store().last_cursor(addr(2).as_str()).unwrap(),
        2,
        "replays store nothing; the victim's does"
    );
    s.stop().await;
}

/// Line R6, added later and not part of the first set of lines: a back-dated `ts` revived an expired hop,
/// since chain rule 8 judges validity at the envelope's `ts` and the stale window is ttl + skew. Before the fix
/// (and on main up to 2026-10-25) `ts = exp - 1` at `exp + 86,400` was stored, 200 with `delivered` 1. Fixed
/// on 2026-10-25: live delivery is judged at the relay's clock as
/// well, against the earliest `exp` of the chain and the relay's own skew, after the ts window. So the same
/// bytes are 422 `hop-expired` at `exp + 86,400` and stored when received at `exp + skew` (the positive
/// control); an envelope outside the ts window is `stale-ts` first.
#[tokio::test]
async fn r6_a_backdated_ts_no_longer_revives_an_expired_hop() {
    let s = hosted(Config::default()).await;
    let exp = NOW - 86_400;
    let first = Hop::sign(&key(20), &addr(21), vec![], exp).unwrap();
    let last = Hop::sign(&key(21), &addr(22), vec![], exp).unwrap();
    let chain = vec![first, last];
    let backdated = bytes(&envelope(22, &[addr(2)], chain.clone(), exp - 1));
    let r = s.publish(&backdated).await;
    let now_r = s.publish(&bytes(&envelope(22, &[addr(2)], chain.clone(), NOW))).await;
    let stale_ts = NOW - (604_800 + 300) - 1;
    let stale = s.publish(&bytes(&envelope(22, &[addr(2)], chain, stale_ts))).await;
    let stored_before = s.relay.store().last_cursor(addr(2).as_str()).unwrap();
    // The positive control: the same bytes received inside min(exp) + skew, at its last second, are stored.
    s.clock.set(exp + 300);
    let control = s.publish(&backdated).await;
    let delivered =
        if control.status == 200 { control.json()["delivered"].to_string() } else { "-".to_owned() };
    eprintln!(
        "MEASURE R6: last hop expired 86400 s before the relay's clock; ts = exp - 1: {:?}; ts = now: {:?}; \
         ts = now - (ttl + skew) - 1: {:?}; rows stored by these {stored_before}; the same bytes received at \
         exp + skew: {:?} delivered {delivered}",
        status(&r),
        status(&now_r),
        status(&stale),
        status(&control)
    );
    assert_eq!(status(&r), (422, "hop-expired".to_owned()), "refused at receipt: past min(exp) + skew");
    assert_eq!(status(&now_r), (422, "hop-expired".to_owned()));
    assert_eq!(status(&stale), (422, "stale-ts".to_owned()), "the ts window first");
    assert_eq!(stored_before, 0, "nothing stored");
    assert_eq!((control.status, delivered.as_str()), (200, "1"), "inside min(exp) + skew at receipt: stored");
    s.stop().await;
}

fn address_record(n: u8, iat: u64, rotated_from: Option<u8>, countersigned_by: Option<u8>) -> Record {
    let mut a = AddressRecord {
        key: addr(n),
        sealing_key: Some("aa".repeat(32)),
        relays: vec![],
        rotation_key: None,
        revoked: vec![],
        ttl: 3_600,
        iat,
        rotated_from: rotated_from.map(addr),
        rotation_sig: None,
        sig: [0; 64],
    };
    if let Some(by) = countersigned_by {
        a.countersign(&key(by)).unwrap();
    }
    let mut r = Record::Address(a);
    r.sign(&key(n)).unwrap();
    r
}

/// Rotation from an unknown previous key, fixed on 2026-10-25: a relay that holds no record of `rotated_from`
/// checks the rotation's claim alone, under `rotated_from`, so both records are 422 `bad-rotation` and nothing
/// is stored. Before the fix both were stored (200; fetch 200).
#[tokio::test]
async fn d2_a_rotation_from_an_unknown_previous_key_is_bad_rotation() {
    let s = Server::start(Config::default()).await;
    // key(5) never published a record here; the countersignature is key(7)'s, which does not verify under key(5).
    let forged = s.publish(&record_bytes(&address_record(6, NOW, Some(5), Some(7)))).await;
    let bare = s.publish(&record_bytes(&address_record(8, NOW, Some(5), None))).await;
    let stored = s.get(&format!("/v0/fetch/record/{}/address", addr(6)), &[]).await.status;
    eprintln!(
        "MEASURE: rotation_sig not under rotated_from, no stored previous record: {:?} (fetch {stored}); \
         a bare rotation (rotation_sig null): {:?}",
        status(&forged),
        status(&bare)
    );
    assert_eq!(status(&forged), (422, "bad-rotation".to_owned()));
    assert_eq!(stored, 404);
    assert_eq!(status(&bare), (422, "bad-rotation".to_owned()));
    // The positive control: countersigned by rotated_from itself, it is stored with no previous record.
    let by_previous = s.publish(&record_bytes(&address_record(9, NOW, Some(5), Some(5)))).await;
    assert_eq!(status(&by_previous), (200, String::new()));
    s.stop().await;
}

#[tokio::test]
async fn d3_an_older_record_after_a_newer_one_is_stale_record() {
    let s = Server::start(Config::default()).await;
    assert_eq!(s.publish(&record_bytes(&address_record(7, NOW, None, None))).await.status, 200);
    let older = s.publish(&record_bytes(&address_record(7, NOW - 10, None, None))).await;
    assert_eq!(status(&older), (409, "stale-record".to_owned()));
    s.stop().await;
}

#[tokio::test]
async fn a5_a_non_party_cannot_fetch_and_an_unknown_id_is_not_found() {
    let s = hosted(Config::default()).await;
    let env = envelope(1, &[addr(2)], vec![], NOW);
    assert_eq!(s.publish(&bytes(&env)).await.status, 200);
    let id = env.id_hex();
    for party in [1, 2] {
        let r = s.fetch(&id, &key(party), NOW, &[]).await;
        assert_eq!((r.status, r.body.clone()), (200, bytes(&env)), "positive control: key({party})");
    }
    let r = s.fetch(&id, &key(9), NOW, &[]).await;
    assert_eq!(status(&r), (403, "not-authorized".to_owned()), "a non-party");
    let hop = Hop::sign(&key(8), &addr(9), vec![], NOW + 60).unwrap();
    let r = s.fetch(&id, &key(9), NOW, &[hop]).await;
    assert_eq!(status(&r), (403, "not-authorized".to_owned()), "a chain from a non-party");
    let r = s.fetch(&"ab".repeat(32), &key(2), NOW, &[]).await;
    assert_eq!(status(&r), (404, "not-found".to_owned()), "an unknown id");
    s.stop().await;
}

fn nested(depth: usize) -> String {
    format!("{}{}", "[".repeat(depth), "]".repeat(depth))
}

/// The three bodies of A7 at `depth`: bare brackets, nested inside a hop's `caveats`, inside a record's `relays`.
fn deep_bodies(depth: usize) -> [(&'static str, Vec<u8>); 3] {
    let hop = Hop::sign(&key(10), &addr(1), vec![], NOW + 60).unwrap();
    let env = envelope(1, &[addr(2)], vec![hop], NOW).to_json_text();
    assert!(env.contains("\"caveats\":[]"));
    let record = record_bytes(&address_record(11, NOW, None, None));
    let record = String::from_utf8(record).unwrap();
    assert!(record.contains("\"relays\":[]"));
    [
        ("bare", "[".repeat(depth).into_bytes()),
        ("caveats", env.replace("\"caveats\":[]", &format!("\"caveats\":{}", nested(depth))).into_bytes()),
        ("relays", record.replace("\"relays\":[]", &format!("\"relays\":{}", nested(depth))).into_bytes()),
    ]
}

async fn alive(s: &Server) {
    assert_eq!(s.get("/v0/health", &[]).await.status, 200, "the relay is alive");
}

/// A7 as pre-registered: 100,000 levels, each body under the 262,144-byte request cap but over the 65,536-byte
/// envelope cap. The line named 400 `bad-json`, but a body over the envelope cap is refused 413
/// `envelope-too-large` before it is read (SPEC.md Appendix B item 22), so the pre-registered bytes could never
/// reach the parser: a deviation from the pre-registered line, not a defect. This test
/// asserts the documented 413; the test below carries the line with bodies under the cap.
#[tokio::test]
async fn a7_nesting_100000_deep_is_refused_by_the_envelope_cap() {
    let s = hosted(Config::default()).await;
    let mut seen = Vec::new();
    for (label, body) in deep_bodies(100_000) {
        assert!(body.len() <= 262_144, "{label}: {} bytes", body.len());
        let r = s.publish(&body).await;
        seen.push((label, body.len(), status(&r)));
        alive(&s).await;
    }
    eprintln!("A7 100000 levels: {seen:?}");
    for (label, _, got) in seen {
        assert_eq!(got, (413, "envelope-too-large".to_owned()), "{label}");
    }
    s.stop().await;
}

#[tokio::test]
async fn a7_nesting_under_the_envelope_cap_is_bad_json_and_depth_100_in_caveats_is_bad_hop() {
    let s = hosted(Config::default()).await;
    for (label, body) in deep_bodies(30_000) {
        assert!(body.len() <= 65_536, "{label}");
        assert_eq!(status(&s.publish(&body).await), (400, "bad-json".to_owned()), "{label} at 30000");
        alive(&s).await;
    }
    let bare = "[".repeat(65_536);
    assert_eq!(status(&s.publish(bare.as_bytes()).await), (400, "bad-json".to_owned()), "65536 brackets");
    let [_, (_, caveats), _] = deep_bodies(100);
    assert_eq!(status(&s.publish(&caveats).await), (422, "bad-hop".to_owned()), "depth 100 in caveats");
    alive(&s).await;
    s.stop().await;
}

/// `text` with `member` written twice: the extra value before the real one (`last_is_real`) or after it.
fn twice(text: &str, member: &str, extra: &str, last_is_real: bool) -> Vec<u8> {
    let key = format!("\"{member}\":");
    let start = text.find(&key).unwrap();
    let doubled = if last_is_real {
        format!("{}{key}{extra},{}", &text[..start], &text[start..])
    } else {
        let end = start + text[start..].find(',').unwrap();
        format!("{},{key}{extra}{}", &text[..end], &text[end..])
    };
    assert_ne!(doubled, text);
    doubled.into_bytes()
}

/// Repeated member names, fixed on 2026-10-25: every reader refuses a member name given twice, so the relay,
/// which reads through `ac_core::json::parse`, answers 400 `bad-json` to each case. Before the fix the last value
/// won: 422 `bad-id` for "id: valid then wrong", "ts: real then other" and "hop exp: real then other", 200 for the other three envelopes,
/// 200 and 422 `bad-record-sig` for the two records.
#[tokio::test]
async fn d6_duplicate_members_are_bad_json() {
    let s = hosted(Config::default()).await;
    let other_id = format!("\"{}\"", "ab".repeat(32));
    let mut n = 0;
    let mut fresh = |auth: Vec<Hop>| {
        n += 1;
        envelope(1, &[addr(2)], auth, NOW - n).to_json_text()
    };
    let hop = || vec![Hop::sign(&key(12), &addr(1), vec![], NOW + 60).unwrap()];
    let record = |n: u8| String::from_utf8(record_bytes(&address_record(n, NOW, None, None))).unwrap();
    let cases = [
        ("id: valid then wrong", twice(&fresh(vec![]), "id", &other_id, false)),
        ("id: wrong then valid", twice(&fresh(vec![]), "id", &other_id, true)),
        ("ts: other then real", twice(&fresh(vec![]), "ts", "1", true)),
        ("ts: real then other", twice(&fresh(vec![]), "ts", "1", false)),
        ("hop exp: other then real", twice(&fresh(hop()), "exp", "1", true)),
        ("hop exp: real then other", twice(&fresh(hop()), "exp", &NOW.to_string(), false)),
        ("record ttl: other then real", twice(&record(13), "ttl", "5", true)),
        ("record ttl: real then other", twice(&record(14), "ttl", "5", false)),
    ];
    for (label, body) in cases {
        let r = s.publish(&body).await;
        eprintln!("MEASURE: {label}: {:?}", status(&r));
        assert_eq!(status(&r), (400, "bad-json".to_owned()), "{label}");
    }
    assert_eq!(s.relay.store().last_cursor(addr(2).as_str()).unwrap(), 0, "nothing stored");
    s.stop().await;
}
