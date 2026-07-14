//! The accept loop (ipc-design §2). Each accepted connection is authorized by `SO_PEERCRED` (uid == 0 is
//! the only accepted peer; pid/gid are for audit only, not an authenticator) and then handed to the
//! per-connection state machine in [`crate::session`]. I/O happens outside the verifier lock.

use crate::Verifier;
use crate::session::{self, Policy, Terminal, UserResolver};
use bifrauth_ipc::{Clock, Transport};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

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

/// Serve connections until `listener` errors fatally. Non-root peers are rejected and closed immediately.
/// A single connection's failure never aborts the loop.
pub fn serve<C, T, R>(
    listener: &UnixListener,
    verifier: &Mutex<Verifier<C>>,
    clock: &C,
    transport: &T,
    policy: &Policy,
    resolver: &R,
) where
    C: Clock,
    T: Transport,
    R: UserResolver,
{
    for conn in listener.incoming() {
        let mut stream = match conn {
            Ok(s) => s,
            Err(_) => continue,
        };
        // Authorization: root-only (§2). pid/gid are not used as an authenticator.
        match peer_uid(&stream) {
            Some(0) => {}
            _ => continue, // drop the connection
        }
        let _terminal: Terminal = session::run_connection(
            &mut stream,
            verifier,
            clock,
            transport,
            policy,
            resolver,
            wall_epoch(),
        );
        // A production build would emit an audit record from `_terminal` here.
    }
}
