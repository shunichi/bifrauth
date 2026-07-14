//! Boot-time clock abstraction (design §16). The TTL / IPC-deadline authority is `CLOCK_BOOTTIME`
//! (advances during suspend), never the wall clock.

/// A monotonic boot-time clock in nanoseconds (advances during suspend). Injectable for tests.
pub trait Clock {
    fn now_boottime_ns(&self) -> u64;
}

/// Production clock backed by `clock_gettime(CLOCK_BOOTTIME)`.
#[derive(Debug, Default, Clone, Copy)]
pub struct BoottimeClock;

impl Clock for BoottimeClock {
    fn now_boottime_ns(&self) -> u64 {
        let ts = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        (ts.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(ts.tv_nsec as u64)
    }
}
