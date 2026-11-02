//! The sweeper: every `sweep_interval` (60 s by default), the expired mailbox rows, then the envelopes whose rows all
//! expired, each kept as a tombstone while a replay of it could still pass the `ts` window, the tombstones past
//! their `until`, and the address and key records past their validity (spec/SPEC.md §8.7); then the
//! pending rows are retried, on a task of their own, since a retry can wait on slow hosts.
//! Before them, the pairing rendezvous's expired nameplates (src/pair.rs).

use crate::metrics::{METRICS, STORE_ERRORS};
use crate::relay::Relay;
use crate::store::{Size, Swept};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval};

/// One sweep at the relay's current time; a failure is logged and returns `None`. It blocks, so [`run`] runs it off the
/// async workers.
pub fn sweep_once(relay: &Relay) -> Option<Swept> {
    let started = Instant::now();
    relay.pairs.sweep(relay.now());
    let replay_window = relay.config.ttl.saturating_add(relay.config.skew);
    match relay.store.sweep(relay.now(), replay_window) {
        Ok(swept) => {
            if swept != Swept::default() {
                tracing::info!(
                    event = "sweep",
                    mailbox = swept.mailbox,
                    envelopes = swept.envelopes,
                    tombstoned = swept.tombstoned,
                    tombstones_expired = swept.tombstones_expired,
                    records = swept.records,
                    pending = swept.pending
                );
            }
            swept_metrics(relay, &swept, started.elapsed());
            Some(swept)
        }
        Err(e) => {
            tracing::error!(event = "store-error", error = %e);
            METRICS.tick(STORE_ERRORS);
            None
        }
    }
}

/// A sweep's metrics: the rows it removed, by kind; how long it took; and the store's live bytes after it, read every
/// sweep (SQLite's page counts), where the counts of rows wait for the hourly [`log_size`].
fn swept_metrics(relay: &Relay, swept: &Swept, took: Duration) {
    let kinds = [
        ("mailbox", swept.mailbox),
        ("envelopes", swept.envelopes),
        ("tombstoned", swept.tombstoned),
        ("tombstones-expired", swept.tombstones_expired),
        ("records", swept.records),
        ("pending", swept.pending),
    ];
    for (kind, n) in kinds {
        METRICS.add("ac_relay_swept_total", "kind", kind, u64::try_from(n).unwrap_or(u64::MAX));
    }
    METRICS.tick("ac_relay_sweeps_total");
    METRICS.set(
        "ac_relay_sweep_last_duration_microseconds",
        u64::try_from(took.as_micros()).unwrap_or(u64::MAX),
    );
    match relay.store.live_bytes() {
        Ok(live) => METRICS.set("ac_relay_store_live_bytes", live),
        Err(e) => {
            tracing::error!(event = "store-error", error = %e);
            METRICS.tick(STORE_ERRORS);
        }
    }
}

/// The `store-size` line, and its gauges: the database's bytes and what it holds; a failure is a `store-error`. The
/// gauges are set before the line is written, so whoever reads the line finds them.
fn log_size(relay: &Relay) {
    match relay.store.size() {
        Ok(Size { bytes, live, envelopes, mailbox, records, pins }) => {
            METRICS.set("ac_relay_store_bytes", bytes);
            METRICS.set("ac_relay_store_live_bytes", live);
            METRICS.set("ac_relay_store_envelopes", envelopes);
            METRICS.set("ac_relay_store_mailbox_rows", mailbox);
            METRICS.set("ac_relay_store_records", records);
            METRICS.set("ac_relay_store_domain_pins", pins);
            tracing::info!(event = "store-size", bytes, live, envelopes, mailbox, records, pins);
        }
        Err(e) => {
            tracing::error!(event = "store-error", error = %e);
            METRICS.tick(STORE_ERRORS);
        }
    }
}

/// Sweeps and retries every `sweep_interval` until `stop` changes or its sender is dropped, a retry not delaying it.
/// It logs `store-size` after the first sweep, then every hour of sweeps (60 at the default interval). The first tick
/// is at once, so the store's gauges are there from the start, with the store's true size: not seeded at 0, since a
/// restarted or restored relay holds a store.
pub async fn run(relay: Arc<Relay>, mut stop: watch::Receiver<bool>) {
    let mut tick = interval(relay.config.sweep_interval);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let every = (3_600_000 / relay.config.sweep_interval.as_millis().max(1)).max(1);
    let mut sweeps = 0_u128;
    let mut retrying: Option<JoinHandle<()>> = None;
    loop {
        tokio::select! {
            _ = tick.tick() => {
                // Off the workers: a Machine with one CPU has one, and a wave of expired rows would stop every call.
                let sweeping = Arc::clone(&relay);
                if let Err(e) = tokio::task::spawn_blocking(move || sweep_once(&sweeping)).await {
                    tracing::error!(event = "store-error", error = %e);
                    METRICS.tick(STORE_ERRORS);
                }
                if sweeps.is_multiple_of(every) {
                    log_size(&relay);
                }
                sweeps += 1;
                // Beside the tick (LD-1): a retry can wait on slow hosts, and the sweep must not. One pass at a time.
                if retrying.as_ref().is_none_or(JoinHandle::is_finished) {
                    let retry = Arc::clone(&relay);
                    retrying = Some(tokio::spawn(async move {
                        let _ = retry.retry_pending().await;
                    }));
                }
            }
            _ = stop.changed() => break,
        }
    }
    if let Some(retry) = retrying {
        retry.abort();
    }
}
