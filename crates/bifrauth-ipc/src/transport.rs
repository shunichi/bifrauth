//! The transport port (ipc-design §1). This is the seam between the verifier's auth flow and the
//! channel that actually reaches the iPhone (the verifier↔transport-helper socket, task B). Task 0008
//! defines the trait and drives it with a mock adapter; it does not implement a real socket.
//!
//! Contract:
//! - `dispatch` is called **only after** the PAM side reports `conversation_succeeded == true`.
//! - It receives an absolute [`Deadline`] and must not block past it, so a later real implementation
//!   cannot stall a connection indefinitely (measure remaining against `CLOCK_BOOTTIME`).
//! - A returned `Ok(bytes)` is an **unverified** response. It is *not* a success signal: only
//!   `Verifier::verify_response` decides success. The bytes are treated as untrusted input.

use crate::deadline::Deadline;

/// Why a transport dispatch did not yield a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// No response arrived before the deadline.
    Timeout,
    /// The transport channel is unavailable (helper not connected, etc.).
    Unavailable,
    /// The transport failed for another reason (I/O, protocol on the B link, ...).
    Failed,
}

/// The port used to send a signed challenge envelope to the device and obtain its (untrusted) response.
pub trait Transport {
    /// Send `envelope` and return the raw response bytes. Must respect `deadline`.
    fn dispatch(&self, envelope: &[u8], deadline: Deadline) -> Result<Vec<u8>, TransportError>;
}
