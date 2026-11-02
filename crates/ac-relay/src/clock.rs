//! Time, in Unix seconds, behind a trait so that tests can set it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of the current time in Unix seconds.
pub trait Clock: Send + Sync {
    /// The current time in Unix seconds.
    fn now(&self) -> u64;
}

/// The system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
    }
}

/// A clock that stands still until it is set or advanced: for tests.
#[derive(Debug, Default)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    /// A clock that reads `now`.
    #[must_use]
    pub fn new(now: u64) -> ManualClock {
        ManualClock(AtomicU64::new(now))
    }

    /// Sets the time.
    pub fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }

    /// Moves the time forward by `seconds`.
    pub fn advance(&self, seconds: u64) {
        self.0.fetch_add(seconds, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests;
