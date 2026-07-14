//! Length-prefixed message framing (ipc-design §3): a 4-byte big-endian length prefix followed by the
//! body. The body length must be `1..=MAX_BODY_LEN`; zero-length and oversized frames are rejected
//! **before allocating**. Every read/write is bounded by the connection's remaining overall deadline.

use crate::clock::Clock;
use crate::deadline::Deadline;
use core::time::Duration;
use std::io::{self, Read, Write};

/// Maximum IPC body size (ipc-design §3). The 4-byte prefix can express far more, so an over-cap
/// declaration is rejected before any allocation.
pub const MAX_BODY_LEN: usize = 8 * 1024;

/// Errors from reading/writing a frame. `Io` keeps only the kind so the type stays comparable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// The peer closed the connection cleanly with no partial frame in flight.
    Eof,
    /// The connection ended mid-frame (partial prefix or body).
    Truncated,
    /// The declared body length was zero.
    ZeroLength,
    /// The declared body length exceeded [`MAX_BODY_LEN`].
    TooLarge,
    /// A read/write did not complete within the remaining overall deadline.
    TimedOut,
    /// Any other I/O error (kind only).
    Io(io::ErrorKind),
}

/// A stream that can bound its blocking reads/writes with a timeout (so a stalled peer cannot hold a
/// connection past the overall deadline). Implemented for `UnixStream`; trivially mockable in tests.
pub trait SetTimeout {
    fn set_io_timeout(&self, dur: Option<Duration>) -> io::Result<()>;
}

impl SetTimeout for std::os::unix::net::UnixStream {
    fn set_io_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout(dur)?;
        self.set_write_timeout(dur)
    }
}

/// Map an I/O error to a frame error, folding timeouts (`WouldBlock`/`TimedOut`) into `TimedOut`.
fn map_io(e: io::Error) -> FrameError {
    match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => FrameError::TimedOut,
        k => FrameError::Io(k),
    }
}

/// Arm the stream's timeout to the remaining overall deadline. `Duration::ZERO` is not a legal socket
/// timeout (it would mean "block forever"), so a reached deadline maps straight to `TimedOut`.
fn arm<S: SetTimeout>(
    stream: &S,
    deadline: Deadline,
    clock: &impl Clock,
) -> Result<(), FrameError> {
    let remaining = deadline.remaining(clock);
    if remaining.is_zero() {
        return Err(FrameError::TimedOut);
    }
    stream.set_io_timeout(Some(remaining)).map_err(map_io)
}

/// Read exactly `buf.len()` bytes. Distinguishes a clean EOF (no bytes yet) from a truncated frame
/// (some bytes then EOF), and rechecks the deadline between blocking reads.
fn read_full<S: Read + SetTimeout>(
    stream: &mut S,
    buf: &mut [u8],
    deadline: Deadline,
    clock: &impl Clock,
) -> Result<(), FrameError> {
    let mut filled = 0;
    while filled < buf.len() {
        arm(stream, deadline, clock)?;
        match stream.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(if filled == 0 {
                    FrameError::Eof
                } else {
                    FrameError::Truncated
                });
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(map_io(e)),
        }
    }
    Ok(())
}

/// Read one framed message body, enforcing the length bounds before allocating.
pub fn read_message<S: Read + SetTimeout>(
    stream: &mut S,
    deadline: Deadline,
    clock: &impl Clock,
) -> Result<Vec<u8>, FrameError> {
    let mut len_buf = [0u8; 4];
    read_full(stream, &mut len_buf, deadline, clock)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Err(FrameError::ZeroLength);
    }
    if len > MAX_BODY_LEN {
        return Err(FrameError::TooLarge);
    }
    let mut body = vec![0u8; len];
    read_full(stream, &mut body, deadline, clock)?;
    Ok(body)
}

/// Write one framed message body. The body must be `1..=MAX_BODY_LEN` (a caller bug otherwise).
pub fn write_message<S: Write + SetTimeout>(
    stream: &mut S,
    body: &[u8],
    deadline: Deadline,
    clock: &impl Clock,
) -> Result<(), FrameError> {
    debug_assert!(!body.is_empty() && body.len() <= MAX_BODY_LEN);
    if body.is_empty() {
        return Err(FrameError::ZeroLength);
    }
    if body.len() > MAX_BODY_LEN {
        return Err(FrameError::TooLarge);
    }
    let len = (body.len() as u32).to_be_bytes();
    write_all(stream, &len, deadline, clock)?;
    write_all(stream, body, deadline, clock)?;
    stream.flush().map_err(map_io)
}

fn write_all<S: Write + SetTimeout>(
    stream: &mut S,
    mut buf: &[u8],
    deadline: Deadline,
    clock: &impl Clock,
) -> Result<(), FrameError> {
    while !buf.is_empty() {
        arm(stream, deadline, clock)?;
        match stream.write(buf) {
            Ok(0) => return Err(FrameError::Io(io::ErrorKind::WriteZero)),
            Ok(n) => buf = &buf[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(map_io(e)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::BoottimeClock;
    use std::os::unix::net::UnixStream;

    /// These tests exercise the deadline path, which sets socket timeouts. A sandbox may forbid
    /// `setsockopt(SO_RCVTIMEO/SO_SNDTIMEO)` (PermissionDenied); the *capability*, not the security
    /// behavior, is environment-gated, so we skip only when timeouts cannot be set. Normal CI runs them.
    fn timeouts_supported() -> bool {
        match UnixStream::pair() {
            Ok((a, _)) => a.set_read_timeout(Some(Duration::from_millis(50))).is_ok(),
            Err(_) => false,
        }
    }

    #[test]
    fn round_trips_over_a_real_unix_socket() {
        if !timeouts_supported() {
            eprintln!("skipping: socket timeouts not permitted in this environment");
            return;
        }
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let clock = BoottimeClock;
        let deadline = Deadline::overall(&clock);
        write_message(&mut a, b"hello frame", deadline, &clock).unwrap();
        assert_eq!(
            read_message(&mut b, deadline, &clock).unwrap(),
            b"hello frame"
        );
    }

    #[test]
    fn an_already_expired_deadline_times_out_without_blocking() {
        let (_a, mut b) = UnixStream::pair().unwrap();
        let clock = BoottimeClock;
        // Zero-second deadline: the remaining time is already zero, so the read must not block.
        let deadline = Deadline::after_secs(&clock, 0);
        assert_eq!(
            read_message(&mut b, deadline, &clock),
            Err(FrameError::TimedOut)
        );
    }

    #[test]
    fn a_clean_peer_close_reads_as_eof() {
        if !timeouts_supported() {
            eprintln!("skipping: socket timeouts not permitted in this environment");
            return;
        }
        let (a, mut b) = UnixStream::pair().unwrap();
        let clock = BoottimeClock;
        drop(a); // peer closes with nothing sent
        assert_eq!(
            read_message(&mut b, Deadline::overall(&clock), &clock),
            Err(FrameError::Eof)
        );
    }
}
