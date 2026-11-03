//! The day's first subscribes over a real WebSocket: a subscription answered `ok` to a mailbox that no envelope has
//! reached counts once in its UTC day, one to a mailbox an envelope reached never counts, nor does a refused one, and
//! the next UTC day counts the fresh mailbox again. The counts are the process's (`METRICS`), so this binary holds this
//! one test.

mod common;

use ac_core::records::Roots;
use ac_relay::Config;
use ac_relay::metrics::METRICS;
use common::{
    NOW, PATIENCE, POLL, Server, addr, auth_frame, bytes, envelope, key, subscribe, ws_close_code,
    ws_connect, ws_json, ws_send,
};
use std::time::Instant;

const DAY: u64 = 86_400;
const FIRST: &str = "ac_relay_first_subscribes_total";

/// The value of the sample `name` in the process's counts, 0 when it is not there.
fn sample(name: &str) -> u64 {
    let text = METRICS.render(0);
    text.lines().find_map(|l| l.strip_prefix(name)?.strip_prefix(' ')?.parse().ok()).unwrap_or(0)
}

/// Waits until the subscriptions counted under `result` reach `n`: the relay counts one after its answer, which the
/// client may read first, and counts a first subscribe before it.
async fn subscribes(result: &str, n: u64) {
    let name = format!("ac_relay_subscribes_total{{result=\"{result}\"}}");
    let deadline = Instant::now() + PATIENCE;
    while sample(&name) != n {
        assert!(Instant::now() < deadline, "{name} never reached {n}");
        tokio::time::sleep(POLL).await;
    }
}

#[tokio::test]
async fn a_fresh_mailbox_counts_once_a_day_and_one_an_envelope_reached_or_a_refusal_never() {
    let s = Server::start(Config::default()).await;
    s.host(2, Roots::Any, 65_536, 3_600, NOW).await;
    s.host(3, Roots::Any, 65_536, 3_600, NOW).await;
    assert_eq!(s.publish(&bytes(&envelope(1, &[addr(3)], vec![], NOW))).await.status, 200);

    // Mailbox 3's last cursor is 1: no first subscribe, though this subscription resumes after 0.
    let (held_3, cursor) = subscribe(&s, &key(3), &addr(3), &[], None).await;
    assert_eq!(cursor, 0);
    subscribes("ok", 1).await;
    assert_eq!(sample(FIRST), 0, "a mailbox an envelope reached");

    // Mailbox 2 has none: its first subscribe counts, and a second that day does not.
    let (held_2, _) = subscribe(&s, &key(2), &addr(2), &[], None).await;
    subscribes("ok", 2).await;
    assert_eq!(sample(FIRST), 1, "a fresh mailbox");
    let (again_2, _) = subscribe(&s, &key(2), &addr(2), &[], None).await;
    subscribes("ok", 3).await;
    assert_eq!(sample(FIRST), 1, "once in its UTC day");

    // Key 4 asks for fresh mailbox 5 with no chain: refused, and not counted.
    let mut refused = ws_connect(&s).await;
    let challenge = ws_json(&mut refused).await;
    let nonce = challenge["nonce"].as_str().unwrap().to_owned();
    ws_send(&mut refused, &auth_frame(&key(4), &addr(5), &[], None, &nonce)).await;
    assert_eq!(ws_json(&mut refused).await["error"], "not-authorized");
    assert_eq!(ws_close_code(&mut refused).await, 4001);
    subscribes("not-authorized", 1).await;
    assert_eq!(sample(FIRST), 1, "a refused subscribe");

    // At 00:00 UTC the day's set goes: mailbox 2, still fresh, counts once more.
    s.clock.advance(DAY);
    let (next_day_2, _) = subscribe(&s, &key(2), &addr(2), &[], None).await;
    subscribes("ok", 4).await;
    assert_eq!(sample(FIRST), 2, "the next UTC day");

    drop((held_3, held_2, again_2, next_day_2));
    s.stop().await;
}
