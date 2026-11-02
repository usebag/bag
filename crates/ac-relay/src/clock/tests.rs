use super::{Clock, ManualClock, SystemClock};

#[test]
fn the_system_clock_reads_unix_seconds() {
    let now = SystemClock.now();
    assert!(now > 1_700_000_000, "{now}");
}

#[test]
fn a_manual_clock_moves_only_when_told() {
    let c = ManualClock::new(10);
    assert_eq!(c.now(), 10);
    c.advance(5);
    assert_eq!(c.now(), 15);
    c.set(3);
    assert_eq!(c.now(), 3);
    assert_eq!(ManualClock::default().now(), 0);
}
