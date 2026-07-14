//! systemd socket-activation intake (ipc-design §2.1, 追補C).
//!
//! The socket is owned solely by `bifrauthd.socket` (`SocketMode=0600`, `SocketUser=root`,
//! `SocketGroup=root`); the daemon never binds it itself, which removes a whole class of unlink/chmod
//! races. On startup the daemon receives exactly one listening FD and **validates it fully before use**:
//! it must be the sole passed FD, an `AF_UNIX` / `SOCK_STREAM` listening socket, and bound to the expected
//! path. Any mismatch fails closed.

use rustix::net::sockopt;
use rustix::net::{AddressFamily, SocketType};
use std::os::fd::{BorrowedFd, FromRawFd, RawFd};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, Ordering};

/// The first systemd-passed FD number (`SD_LISTEN_FDS_START`).
const LISTEN_FDS_START: RawFd = 3;

/// Process-global one-shot latch: the activation FD may be claimed exactly once. Guarantees that even
/// two concurrent calls produce at most one owner of raw FD 3 (a second `from_raw_fd(3)` would create a
/// second owner of the same descriptor, violating `FromRawFd`'s safety contract → double-close).
static ACTIVATION_CLAIMED: AtomicBool = AtomicBool::new(false);

/// Why the passed listener FD was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemdError {
    /// `LISTEN_FDS` was unset or unparsable.
    NoListenFds,
    /// `LISTEN_PID` did not name this process (the FDs were meant for another process).
    WrongPid,
    /// The number of passed FDs was not exactly 1.
    WrongFdCount(usize),
    /// The FD is not a listening socket (`SO_ACCEPTCONN != 1`).
    NotListening,
    /// The FD is not in the `AF_UNIX` domain.
    NotUnixDomain,
    /// The FD is not a `SOCK_STREAM` socket.
    NotStream,
    /// The FD is not bound to the expected path.
    WrongPath,
    /// The activation FD was already claimed by an earlier call (one-shot).
    AlreadyClaimed,
    /// A socket-inspection syscall failed.
    Os(rustix::io::Errno),
}

impl From<rustix::io::Errno> for SystemdError {
    fn from(e: rustix::io::Errno) -> Self {
        SystemdError::Os(e)
    }
}

/// Validate that `fd` is a listening `AF_UNIX`/`SOCK_STREAM` socket bound to `expected_path`.
///
/// `expected_path` is the filesystem path bytes without a trailing NUL (e.g. `/run/bifrauthd/pam.sock`).
pub fn validate_listener(fd: BorrowedFd<'_>, expected_path: &[u8]) -> Result<(), SystemdError> {
    if !sockopt::socket_acceptconn(fd)? {
        return Err(SystemdError::NotListening);
    }
    if sockopt::socket_domain(fd)? != AddressFamily::UNIX {
        return Err(SystemdError::NotUnixDomain);
    }
    if sockopt::socket_type(fd)? != SocketType::STREAM {
        return Err(SystemdError::NotStream);
    }
    let addr = rustix::net::getsockname(fd)?;
    let unix =
        rustix::net::SocketAddrUnix::try_from(addr).map_err(|_| SystemdError::NotUnixDomain)?;
    match unix.path_bytes() {
        Some(p) if p == expected_path => Ok(()),
        _ => Err(SystemdError::WrongPath),
    }
}

/// Parse the systemd socket-activation environment and return the single validated listener.
///
/// **One-shot.** The first call claims raw FD 3; any later call (or a concurrent second call) returns
/// [`SystemdError::AlreadyClaimed`] without touching the FD, so there is only ever one owner. On a
/// successful claim the activation variables are removed from the environment (equivalent to
/// `sd_listen_fds(true)`), so the FD cannot be re-interpreted by anything downstream. Requires
/// `LISTEN_PID` == this process and `LISTEN_FDS` == 1; takes ownership of FD 3.
pub fn listener_from_env(expected_path: &[u8]) -> Result<UnixListener, SystemdError> {
    // Latch first: whoever flips false→true is the sole claimant. A failed claim still consumes the
    // one-shot (activation is attempted once; a misconfig means the daemon exits).
    if ACTIVATION_CLAIMED.swap(true, Ordering::SeqCst) {
        return Err(SystemdError::AlreadyClaimed);
    }
    let listen_pid: i32 = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(SystemdError::NoListenFds)?;
    let self_pid = rustix::process::getpid().as_raw_nonzero().get();
    if listen_pid != self_pid {
        return Err(SystemdError::WrongPid);
    }
    let listen_fds: usize = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(SystemdError::NoListenFds)?;
    if listen_fds != 1 {
        return Err(SystemdError::WrongFdCount(listen_fds));
    }

    // SAFETY: systemd guarantees FD 3 is open when LISTEN_FDS==1; validate before returning ownership.
    let borrowed = unsafe { BorrowedFd::borrow_raw(LISTEN_FDS_START) };
    validate_listener(borrowed, expected_path)?;
    // Set FD_CLOEXEC so the listener is not leaked into child processes.
    rustix::io::fcntl_setfd(borrowed, rustix::io::FdFlags::CLOEXEC)?;
    // Consume the activation environment (sd_listen_fds(true) equivalent) so it cannot be re-interpreted.
    // SAFETY: this runs once at startup, before any worker threads are spawned, so the non-thread-safe
    // env mutation has no concurrent reader/writer.
    unsafe {
        std::env::remove_var("LISTEN_PID");
        std::env::remove_var("LISTEN_FDS");
        std::env::remove_var("LISTEN_FDNAMES");
    }
    // SAFETY: FD 3 is a valid, validated listening socket, claimed exactly once (the one-shot latch), that
    // we now take sole ownership of.
    Ok(unsafe { UnixListener::from_raw_fd(LISTEN_FDS_START) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let dir = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
        std::path::Path::new(&dir).join(name)
    }

    /// These tests need to `bind` a real Unix socket. A restricted sandbox may deny that with
    /// PermissionDenied; the capability, not the validation logic, is environment-gated, so we skip only
    /// when binding is impossible. Normal CI runs them.
    fn can_bind() -> bool {
        let p = temp_path("bifrauthd-systemd-probe.sock");
        let _ = std::fs::remove_file(&p);
        let ok = UnixListener::bind(&p).is_ok();
        let _ = std::fs::remove_file(&p);
        ok
    }

    #[test]
    fn accepts_a_listening_unix_stream_at_expected_path() {
        if !can_bind() {
            eprintln!("skipping: binding a unix socket is not permitted in this environment");
            return;
        }
        let path = temp_path("bifrauthd-systemd-ok.sock");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let bytes = path.as_os_str().as_encoded_bytes();
        assert_eq!(validate_listener(listener.as_fd(), bytes), Ok(()));
        // Wrong expected path is rejected.
        assert_eq!(
            validate_listener(listener.as_fd(), b"/run/bifrauthd/pam.sock"),
            Err(SystemdError::WrongPath)
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_a_connected_non_listening_socket() {
        if !can_bind() {
            eprintln!("skipping: binding a unix socket is not permitted in this environment");
            return;
        }
        let path = temp_path("bifrauthd-systemd-conn.sock");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let client = std::os::unix::net::UnixStream::connect(&path).unwrap();
        let bytes = path.as_os_str().as_encoded_bytes();
        // The client end is a connected stream, not a listener.
        assert_eq!(
            validate_listener(client.as_fd(), bytes),
            Err(SystemdError::NotListening)
        );
        drop(listener);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_a_datagram_socket() {
        if !can_bind() {
            eprintln!("skipping: binding a unix socket is not permitted in this environment");
            return;
        }
        let path = temp_path("bifrauthd-systemd-dgram.sock");
        let _ = std::fs::remove_file(&path);
        let dgram = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
        let bytes = path.as_os_str().as_encoded_bytes();
        // A datagram socket is neither listening nor SOCK_STREAM; NotListening is checked first.
        assert_eq!(
            validate_listener(dgram.as_fd(), bytes),
            Err(SystemdError::NotListening)
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn listener_from_env_is_one_shot() {
        // This is the only test that touches the process-global claim latch. The first call fails for
        // lack of a real activation environment (no LISTEN_PID etc.), but it still consumes the one-shot;
        // every later call is refused regardless of environment, so raw FD 3 can never gain a second owner.
        let _first = listener_from_env(b"/run/bifrauthd/pam.sock");
        assert!(matches!(
            listener_from_env(b"/run/bifrauthd/pam.sock"),
            Err(SystemdError::AlreadyClaimed)
        ));
    }
}
