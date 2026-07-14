//! The accept loop (ipc-design §1/§2/§5). A **bounded** pool of worker threads each accept and handle one
//! connection at a time, so a slow flow (Face ID wait, transport, NSS) blocks only its own worker — other
//! workers keep issuing and completing, which is what makes the "lock released during I/O" and the
//! per-uid / total pending caps meaningful. The pool size is the hard cap on concurrent flows; excess
//! connections wait in the kernel accept backlog (fail closed once it fills). No unbounded thread spawn.
//!
//! Accept errors are classified (never blindly retried): `Interrupted` retries immediately, resource
//! exhaustion (EMFILE/ENFILE/ENOMEM/ENOBUFS) backs off briefly to avoid a hot spin, and a permanent
//! listener error (EBADF/EINVAL/ENOTSOCK) ends that worker. [`serve`] returns when all workers have ended.
//!
//! Authorization: `SO_PEERCRED` — production accepts only uid == 0 (pass `|uid| uid == 0` as `authorize`);
//! pid/gid are recorded for audit only, never used as an authenticator. A panicking connection is caught
//! at the worker boundary so it cannot take down a worker or the daemon; the RAII cleanup guard in
//! [`crate::session`] still cancels that connection's pending request during the unwind.

use crate::Verifier;
use crate::session::{self, Policy, Terminal, UserResolver};
use bifrauth_ipc::{Clock, Transport};
use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Default number of worker threads (hard cap on concurrent flows).
pub const DEFAULT_WORKERS: usize = 8;

/// Backoff after a resource-exhaustion accept error, to avoid a hot spin while fds/memory free up.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// What to do after an `accept()` error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AcceptAction {
    /// Transient interruption — retry immediately.
    Retry,
    /// Resource exhaustion or an unclassified error — back off, then retry (never hot-spin).
    Backoff,
    /// Permanent listener error — this worker should stop.
    Stop,
}

/// Classify an `accept()` error. Uses the raw errno for cases without a stable `ErrorKind`.
fn classify_accept_error(e: &io::Error) -> AcceptAction {
    if e.kind() == io::ErrorKind::Interrupted {
        return AcceptAction::Retry;
    }
    match e.raw_os_error() {
        // EBADF, EINVAL, ENOTSOCK: the listener is gone/invalid — stop this worker.
        Some(9) | Some(22) | Some(88) => AcceptAction::Stop,
        // ENFILE, EMFILE, ENOMEM, ENOBUFS: resource exhaustion — back off and retry.
        Some(23) | Some(24) | Some(12) | Some(105) => AcceptAction::Backoff,
        // Anything else: back off rather than hot-spin or kill the pool.
        _ => AcceptAction::Backoff,
    }
}

/// The peer's uid from `SO_PEERCRED`, or `None` if it could not be read.
pub fn peer_uid(stream: &UnixStream) -> Option<u32> {
    rustix::net::sockopt::socket_peercred(stream)
        .ok()
        .map(|c| c.uid.as_raw())
}

/// Current wall-clock second (for the iPhone display only; never the TTL authority). Falls back to 0 if
/// the clock is before the epoch (which only skews the displayed timestamp, not security).
fn wall_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Shared, thread-safe daemon state handed to every worker.
pub struct Shared<C: Clock, T: Transport, R: UserResolver, A: Fn(u32) -> bool> {
    pub verifier: Mutex<Verifier<C>>,
    pub clock: C,
    pub transport: T,
    pub policy: Policy,
    pub resolver: R,
    /// Peer authorization by uid (production: `|uid| uid == 0`).
    pub authorize: A,
}

/// Run `workers` worker threads accepting on `listener` until it errors fatally. Blocks until all workers
/// exit. Each worker handles one connection at a time; a connection panic is contained.
pub fn serve<C, T, R, A>(
    listener: Arc<UnixListener>,
    shared: Arc<Shared<C, T, R, A>>,
    workers: usize,
) where
    C: Clock + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    R: UserResolver + Send + Sync + 'static,
    A: Fn(u32) -> bool + Send + Sync + 'static,
{
    let mut handles = Vec::new();
    for _ in 0..workers.max(1) {
        let listener = Arc::clone(&listener);
        let shared = Arc::clone(&shared);
        handles.push(std::thread::spawn(move || worker_loop(&listener, &shared)));
    }
    for h in handles {
        let _ = h.join();
    }
}

/// One worker: accept → authorize by peer uid → handle (panic-contained) → repeat.
fn worker_loop<C, T, R, A>(listener: &UnixListener, shared: &Shared<C, T, R, A>)
where
    C: Clock,
    T: Transport,
    R: UserResolver,
    A: Fn(u32) -> bool,
{
    loop {
        let mut stream = match listener.accept() {
            Ok((s, _addr)) => s,
            Err(e) => match classify_accept_error(&e) {
                AcceptAction::Retry => continue,
                AcceptAction::Backoff => {
                    std::thread::sleep(ACCEPT_BACKOFF);
                    continue;
                }
                AcceptAction::Stop => return,
            },
        };
        // Authorization (§2). Drop the connection on a non-authorized or unreadable peer.
        match peer_uid(&stream) {
            Some(uid) if (shared.authorize)(uid) => {}
            _ => continue,
        }
        // Contain a connection panic: the RAII guard in `session` cancels the pending during unwind, and
        // catching here keeps this worker (and the daemon) alive.
        let _terminal: Result<Terminal, _> = panic::catch_unwind(AssertUnwindSafe(|| {
            session::run_connection(
                &mut stream,
                &shared.verifier,
                &shared.clock,
                &shared.transport,
                &shared.policy,
                &shared.resolver,
                wall_epoch(),
            )
        }));
        // A production build would emit an audit record from `_terminal` here.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_errors_are_classified_not_hot_spun() {
        // Interrupted retries immediately.
        assert_eq!(
            classify_accept_error(&io::Error::from(io::ErrorKind::Interrupted)),
            AcceptAction::Retry
        );
        // Permanent listener errors stop the worker (EBADF / EINVAL / ENOTSOCK).
        for errno in [9, 22, 88] {
            assert_eq!(
                classify_accept_error(&io::Error::from_raw_os_error(errno)),
                AcceptAction::Stop
            );
        }
        // Resource exhaustion backs off (ENFILE / EMFILE / ENOMEM / ENOBUFS).
        for errno in [23, 24, 12, 105] {
            assert_eq!(
                classify_accept_error(&io::Error::from_raw_os_error(errno)),
                AcceptAction::Backoff
            );
        }
        // An unclassified errno backs off rather than hot-spinning or killing the pool.
        assert_eq!(
            classify_accept_error(&io::Error::from_raw_os_error(9999)),
            AcceptAction::Backoff
        );
    }
}
