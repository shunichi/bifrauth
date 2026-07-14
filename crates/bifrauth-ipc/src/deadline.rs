//! An absolute CLOCK_BOOTTIME deadline plus per-stage caps (design §16, ipc-design §3).
//!
//! There is one **overall** deadline per connection (default 30s). Every blocking step (frame read/write,
//! transport dispatch) must finish within the *remaining* overall time; a per-stage cap (e.g. the Face ID
//! wait) only ever shortens that, never extends it. Because the authority is CLOCK_BOOTTIME, a suspend that
//! crosses the deadline makes the very next check time out immediately.

use crate::clock::Clock;
use core::time::Duration;

/// The overall per-connection deadline (design §16 total timeout).
pub const OVERALL_DEADLINE_SECS: u64 = 30;

/// An absolute boot-time instant (nanoseconds) by which an operation must complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadline {
    boottime_ns: u64,
}

impl Deadline {
    /// A deadline `secs` seconds from now on the given clock. Overflow is treated as **already expired**
    /// (fail closed): a computation that cannot be represented must not yield a far-future
    /// never-expiring deadline. In practice `secs` is always a small policy constant, so overflow never
    /// occurs; the clamp only guarantees the safe direction.
    pub fn after_secs(clock: &impl Clock, secs: u64) -> Self {
        let now = clock.now_boottime_ns();
        let boottime_ns = secs
            .checked_mul(1_000_000_000)
            .and_then(|d| now.checked_add(d))
            .unwrap_or(now); // overflow → deadline == now → remaining 0 → fail closed
        Deadline { boottime_ns }
    }

    /// The overall per-connection deadline (30s from now).
    pub fn overall(clock: &impl Clock) -> Self {
        Self::after_secs(clock, OVERALL_DEADLINE_SECS)
    }

    /// The raw absolute boot-time nanoseconds.
    pub fn boottime_ns(&self) -> u64 {
        self.boottime_ns
    }

    /// Whether the deadline has been reached (`now >= deadline`). At-or-past the instant counts as expired.
    pub fn is_expired(&self, clock: &impl Clock) -> bool {
        clock.now_boottime_ns() >= self.boottime_ns
    }

    /// Remaining time until the deadline, or `Duration::ZERO` if already reached.
    pub fn remaining(&self, clock: &impl Clock) -> Duration {
        let now = clock.now_boottime_ns();
        Duration::from_nanos(self.boottime_ns.saturating_sub(now))
    }

    /// A stage deadline = the sooner of `self` (overall) and `now + cap_secs`. Never extends the overall.
    pub fn stage(&self, clock: &impl Clock, cap_secs: u64) -> Deadline {
        let cap = Self::after_secs(clock, cap_secs);
        Deadline {
            boottime_ns: self.boottime_ns.min(cap.boottime_ns),
        }
    }
}
