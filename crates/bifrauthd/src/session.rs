//! The per-connection IPC state machine (ipc-design §4/§5), PAM module ↔ verifier.
//!
//! Flow: `AuthRequest → ConfirmationCode → DisplayAck → [dispatch] → Outcome`, over one connection, for
//! one `request_id`. It ties [`crate::Verifier`] (state) to a [`Transport`] port (device I/O) and the
//! [`bifrauth_ipc`] wire/framing.
//!
//! Locking (ipc-design §5): the verifier mutex is held **only** for the short state transitions
//! (`issue_challenge` / `verify_response` / `cancel_pending`) via [`with_verifier`]. It is released during
//! frame reads/writes and during transport dispatch, so one slow flow cannot stall all authentication.
//!
//! Cleanup (ipc-design §4.1, 追補A): once a challenge is issued, a [`CleanupGuard`] cancels the pending
//! request on every abnormal exit (bad/late/misordered message, EOF, decode error, timeout, transport
//! error, send failure). `verify_response` consumes the request itself, so on the verify path the guard is
//! disarmed to avoid a (harmless, idempotent) second cancel.
//!
//! Trust (ipc-design §6, 追補B): the transport is called **only after** `conversation_succeeded == true`,
//! its returned bytes are untrusted, and only `verify_response` decides success. If verification succeeds
//! but the `Outcome` cannot be delivered to PAM, that is **not** an external success — PAM sees no
//! `Outcome`, so the login fails closed.

use crate::{ChallengeContext, Verifier, VerifyError};
use bifrauth_ipc::frame::{self, FrameError, SetTimeout};
use bifrauth_ipc::wire::{AuthRequest, ConfirmationCode, DisplayAck, Outcome, OutcomeCode};
use bifrauth_ipc::{Clock, Deadline, Transport, TransportError};
use std::io::{Read, Write};
use std::sync::Mutex;

/// Per-stage caps (seconds), each additionally clamped to the remaining overall deadline (§3).
const AUTH_REQUEST_STAGE_SECS: u64 = 5;
const CONFIRMATION_WRITE_STAGE_SECS: u64 = 5;
const DISPLAY_ACK_STAGE_SECS: u64 = 5;
/// The device-side Face ID wait (design §16 per-stage limit).
const DISPATCH_STAGE_SECS: u64 = 20;
const OUTCOME_WRITE_STAGE_SECS: u64 = 5;

/// Daemon-supplied identity/policy (ipc-design §3, answer 3). These are **not** taken from `AuthRequest`.
#[derive(Debug, Clone)]
pub struct Policy {
    pub linux_device_id: [u8; 16],
    pub linux_device_name: String,
    /// Requested challenge TTL in seconds (profile 1..=30).
    pub ttl_seconds: u64,
    /// Allowlist of dedicated PAM services this daemon will serve.
    pub allowed_pam_services: Vec<String>,
}

impl Policy {
    fn service_allowed(&self, service: &str) -> bool {
        self.allowed_pam_services.iter().any(|s| s == service)
    }
}

/// Resolves a username to its uid and verifies the correspondence (confused-deputy guard, ipc-design §3).
pub trait UserResolver {
    /// Return the uid for `username`, or `None` if it does not resolve.
    fn resolve(&self, username: &str) -> Option<u32>;
}

/// Why a connection ended (for tests/audit; not sent on the wire).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Terminal {
    /// An `Outcome` frame was delivered to PAM with this code.
    OutcomeSent(OutcomeCode),
    /// Verification decided `code`, but the `Outcome` frame could not be delivered (fail closed:
    /// PAM never sees success).
    OutcomeSendFailed(OutcomeCode),
    /// The connection closed before any challenge was issued (parse/policy/resolve failure); no state.
    ClosedBeforeIssue(PreIssueReason),
    /// A failure after the challenge was issued; the pending request was cancelled. Present when we could
    /// not even deliver an `Outcome` (e.g. the confirmation-code send failed).
    ClosedAfterCleanup,
}

/// Reasons a connection is refused before issuing a challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreIssueReason {
    /// The `AuthRequest` frame could not be read/decoded.
    BadAuthRequest,
    /// `pam_service` is not in the daemon allowlist.
    ServiceNotAllowed,
    /// The username did not resolve to a uid.
    UnknownUser,
    /// Building/issuing the challenge failed.
    IssueFailed,
}

/// Run one connection to completion. Returns how it ended (Outcome delivered, failed-closed, or refused).
///
/// `verifier` is shared (mutex) so I/O happens outside the lock; `clock` drives deadlines and must be the
/// same clock the verifier uses. `wall_epoch` is the wall-clock second for the iPhone's display only (not
/// the TTL authority).
#[allow(clippy::too_many_arguments)]
pub fn run_connection<S, C, T, R>(
    stream: &mut S,
    verifier: &Mutex<Verifier<C>>,
    clock: &C,
    transport: &T,
    policy: &Policy,
    resolver: &R,
    wall_epoch: u64,
) -> Terminal
where
    S: Read + Write + SetTimeout,
    C: Clock,
    T: Transport,
    R: UserResolver,
{
    let overall = Deadline::overall(clock);

    // --- Stage 1: read AuthRequest (no state yet; any failure just closes the connection). ---
    let req = match read_msg::<S, C, AuthRequest>(
        stream,
        overall.stage(clock, AUTH_REQUEST_STAGE_SECS),
        clock,
        AuthRequest::decode,
    ) {
        Ok(r) => r,
        Err(_) => return Terminal::ClosedBeforeIssue(PreIssueReason::BadAuthRequest),
    };

    // --- Policy + identity checks (daemon-side, before issuing). ---
    if !policy.service_allowed(&req.pam_service) {
        return Terminal::ClosedBeforeIssue(PreIssueReason::ServiceNotAllowed);
    }
    let uid = match resolver.resolve(&req.username) {
        Some(u) => u,
        None => return Terminal::ClosedBeforeIssue(PreIssueReason::UnknownUser),
    };

    // --- Stage 2: issue the challenge (short lock). ---
    let ctx = ChallengeContext {
        uid,
        username: req.username.clone(),
        pam_service: req.pam_service.clone(),
        pam_tty: req.pam_tty.clone(),
        pam_rhost: req.pam_rhost.clone(),
        linux_device_id: policy.linux_device_id,
        linux_device_name: policy.linux_device_name.clone(),
        ttl_seconds: policy.ttl_seconds,
        issued_at: wall_epoch,
    };
    let issued = match with_verifier(verifier, |v| v.issue_challenge(&ctx)) {
        Ok(i) => i,
        Err(_e) => return Terminal::ClosedBeforeIssue(PreIssueReason::IssueFailed),
    };

    // From here a pending request exists: arm the cleanup guard for every abnormal exit.
    let mut guard = CleanupGuard::new(issued.request_id);

    // --- Stage 3: send ConfirmationCode. A send failure also needs cleanup (追補). ---
    let cc = ConfirmationCode {
        request_id: issued.request_id,
        confirmation_code: issued.confirmation_code.clone(),
    };
    let cc_bytes = match cc.encode() {
        Ok(b) => b,
        Err(_) => return guard.cancel_and(verifier, Terminal::ClosedAfterCleanup),
    };
    if frame::write_message(
        stream,
        &cc_bytes,
        overall.stage(clock, CONFIRMATION_WRITE_STAGE_SECS),
        clock,
    )
    .is_err()
    {
        return guard.cancel_and(verifier, Terminal::ClosedAfterCleanup);
    }

    // --- Stage 4: read DisplayAck (same request_id only). ---
    let ack = match read_msg::<S, C, DisplayAck>(
        stream,
        overall.stage(clock, DISPLAY_ACK_STAGE_SECS),
        clock,
        DisplayAck::decode,
    ) {
        Ok(a) if a.request_id == issued.request_id => a,
        // Wrong request_id, misordered/duplicate, decode error, EOF, timeout → cleanup + close.
        _ => return guard.cancel_and(verifier, Terminal::ClosedAfterCleanup),
    };
    if !ack.conversation_succeeded {
        // The PAM conversation did not complete: deny (transport is never called).
        return finish_with_outcome(
            stream,
            verifier,
            clock,
            overall,
            &mut guard,
            issued.request_id,
            OutcomeCode::Denied,
        );
    }

    // --- Stage 5: dispatch to the device (lock released; deadline-bounded). ---
    let response = match transport
        .dispatch(&issued.envelope, overall.stage(clock, DISPATCH_STAGE_SECS))
    {
        Ok(bytes) => bytes,
        Err(e) => {
            let code = match e {
                TransportError::Timeout => OutcomeCode::Timeout,
                TransportError::Unavailable | TransportError::Failed => OutcomeCode::Unavailable,
            };
            return finish_with_outcome(
                stream,
                verifier,
                clock,
                overall,
                &mut guard,
                issued.request_id,
                code,
            );
        }
    };

    // --- Stage 6: verify (short lock). This consumes the pending request itself, so disarm the guard. ---
    let verify = with_verifier(verifier, |v| v.verify_response(&response));
    guard.disarm();
    let code = match verify {
        Ok(rid) if rid == issued.request_id => OutcomeCode::Success,
        Ok(_) => OutcomeCode::InternalError, // consumed a different id — impossible for a single-flow conn
        Err(VerifyError::Expired) => OutcomeCode::Timeout,
        Err(_) => OutcomeCode::Denied,
    };

    // --- Stage 7: deliver the Outcome. If delivery fails after a Success verify, PAM sees nothing → the
    //     login fails closed; it is NOT an external success (追補B). ---
    finish_with_outcome(
        stream,
        verifier,
        clock,
        overall,
        &mut guard,
        issued.request_id,
        code,
    )
}

/// Send the terminal `Outcome`. Any still-armed pending is cancelled first (idempotent). Distinguishes a
/// delivered outcome from a delivery failure so the caller/tests can assert fail-closed behavior.
fn finish_with_outcome<S, C>(
    stream: &mut S,
    verifier: &Mutex<Verifier<C>>,
    clock: &C,
    overall: Deadline,
    guard: &mut CleanupGuard,
    request_id: [u8; 16],
    code: OutcomeCode,
) -> Terminal
where
    S: Read + Write + SetTimeout,
    C: Clock,
{
    guard.cancel(verifier);
    let outcome = Outcome {
        request_id,
        result: code,
    };
    let bytes = match outcome.encode() {
        Ok(b) => b,
        Err(_) => return Terminal::OutcomeSendFailed(code),
    };
    match frame::write_message(
        stream,
        &bytes,
        overall.stage(clock, OUTCOME_WRITE_STAGE_SECS),
        clock,
    ) {
        Ok(()) => Terminal::OutcomeSent(code),
        Err(_) => Terminal::OutcomeSendFailed(code),
    }
}

/// Read one framed message and decode it, mapping any framing/decoding failure to `()` (the caller
/// decides the terminal state). Rejecting the frame never allocates past [`frame::MAX_BODY_LEN`].
fn read_msg<S, C, M>(
    stream: &mut S,
    deadline: Deadline,
    clock: &C,
    decode: fn(&[u8]) -> Result<M, bifrauth_ipc::IpcSchemaError>,
) -> Result<M, ()>
where
    S: Read + SetTimeout,
    C: Clock,
{
    let bytes = frame::read_message(stream, deadline, clock).map_err(|_: FrameError| ())?;
    decode(&bytes).map_err(|_| ())
}

/// Run a closure while holding the verifier lock for the shortest possible time.
fn with_verifier<C: Clock, X>(
    verifier: &Mutex<Verifier<C>>,
    f: impl FnOnce(&mut Verifier<C>) -> X,
) -> X {
    let mut guard = verifier.lock().expect("verifier mutex poisoned");
    f(&mut guard)
}

/// Cancels a pending request on drop unless disarmed. Idempotent: [`Verifier::cancel_pending`] is a no-op
/// once the request is gone, so calling `cancel` more than once (or after `verify_response` consumed it)
/// is safe.
struct CleanupGuard {
    request_id: [u8; 16],
    armed: bool,
}

impl CleanupGuard {
    fn new(request_id: [u8; 16]) -> Self {
        CleanupGuard {
            request_id,
            armed: true,
        }
    }

    /// Disarm (the request has been consumed elsewhere, e.g. by `verify_response`).
    fn disarm(&mut self) {
        self.armed = false;
    }

    /// Cancel the pending request if still armed (idempotent), then disarm.
    fn cancel<C: Clock>(&mut self, verifier: &Mutex<Verifier<C>>) {
        if self.armed {
            self.armed = false;
            with_verifier(verifier, |v| v.cancel_pending(&self.request_id));
        }
    }

    /// Cancel and return the given terminal (convenience for early returns).
    fn cancel_and<C: Clock>(
        &mut self,
        verifier: &Mutex<Verifier<C>>,
        terminal: Terminal,
    ) -> Terminal {
        self.cancel(verifier);
        terminal
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bifrauth_crypto as crypto;
    use bifrauth_ipc::wire::AuthRequest;
    use core::time::Duration;
    use mock_iphone::MockIphone;
    use std::cell::Cell;
    use std::collections::HashMap;
    use std::io;

    const VERIFIER_SEED: [u8; 32] = [0x03; 32];
    const DEVICE_SEED: [u8; 32] = [0x55; 32];
    const IPHONE_DEV: [u8; 16] = [0x66; 16];
    const LINUX_DEV: [u8; 16] = [0x44; 16];
    const UID: u32 = 1000;
    const WALL_EPOCH: u64 = 1_700_000_000;

    // ---- a deterministic in-memory stream with framing-aware write-failure injection ----

    /// A reactive responder: given the outbound frames captured so far, optionally produce the next
    /// inbound message body. Fired once when the preloaded inbound is drained, which lets a test build a
    /// `DisplayAck` carrying the *actual* issued `request_id` (learned from the `ConfirmationCode` the
    /// session just sent) — impossible to precompute since the id is drawn from the CSPRNG.
    type Responder = Box<dyn FnMut(&[Vec<u8>]) -> Option<Vec<u8>>>;

    struct MockStream {
        inbound: Vec<u8>,
        in_pos: usize,
        outbound: Vec<u8>,
        responder: Option<Responder>,
        // Frame-completion tracking so we can fail exactly at the Nth outbound frame boundary.
        fail_after_frames: Option<usize>,
        completed_frames: usize,
        parse_need_len: usize, // bytes still needed to finish the 4-byte length prefix
        parse_len_buf: [u8; 4],
        parse_body_remaining: Option<usize>,
    }

    impl MockStream {
        fn new(inbound: Vec<u8>) -> Self {
            MockStream {
                inbound,
                in_pos: 0,
                outbound: Vec::new(),
                responder: None,
                fail_after_frames: None,
                completed_frames: 0,
                parse_need_len: 4,
                parse_len_buf: [0; 4],
                parse_body_remaining: None,
            }
        }

        fn with_responder(mut self, r: Responder) -> Self {
            self.responder = Some(r);
            self
        }

        fn fail_after_frames(mut self, n: usize) -> Self {
            self.fail_after_frames = Some(n);
            self
        }

        /// Advance the outbound frame parser by one byte (to count completed frames).
        fn feed(&mut self, b: u8) {
            match self.parse_body_remaining {
                None => {
                    let idx = 4 - self.parse_need_len;
                    self.parse_len_buf[idx] = b;
                    self.parse_need_len -= 1;
                    if self.parse_need_len == 0 {
                        let len = u32::from_be_bytes(self.parse_len_buf) as usize;
                        self.parse_body_remaining = Some(len);
                        self.parse_need_len = 4;
                        if len == 0 {
                            self.completed_frames += 1;
                            self.parse_body_remaining = None;
                        }
                    }
                }
                Some(rem) => {
                    let rem = rem - 1;
                    if rem == 0 {
                        self.completed_frames += 1;
                        self.parse_body_remaining = None;
                    } else {
                        self.parse_body_remaining = Some(rem);
                    }
                }
            }
        }

        /// Parse captured outbound bytes into successive message bodies.
        fn outbound_frames(&self) -> Vec<Vec<u8>> {
            let mut frames = Vec::new();
            let mut i = 0;
            while i + 4 <= self.outbound.len() {
                let len = u32::from_be_bytes(self.outbound[i..i + 4].try_into().unwrap()) as usize;
                i += 4;
                if i + len > self.outbound.len() {
                    break;
                }
                frames.push(self.outbound[i..i + len].to_vec());
                i += len;
            }
            frames
        }
    }

    impl io::Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            // If the preloaded inbound is drained, fire the (one-shot) responder to synthesize the next
            // message from what we've sent so far (e.g. a DisplayAck echoing the issued request_id).
            if self.in_pos >= self.inbound.len()
                && let Some(mut r) = self.responder.take()
            {
                let frames = self.outbound_frames();
                if let Some(body) = r(&frames) {
                    let mut framed = (body.len() as u32).to_be_bytes().to_vec();
                    framed.extend_from_slice(&body);
                    self.inbound.extend(framed);
                }
            }
            let n = (self.inbound.len() - self.in_pos).min(buf.len());
            buf[..n].copy_from_slice(&self.inbound[self.in_pos..self.in_pos + n]);
            self.in_pos += n;
            Ok(n) // n == 0 signals EOF, exercising the truncation/EOF paths
        }
    }

    impl io::Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if let Some(t) = self.fail_after_frames
                && self.completed_frames >= t
            {
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            for &b in buf {
                self.feed(b);
            }
            self.outbound.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl SetTimeout for MockStream {
        fn set_io_timeout(&self, _dur: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
    }

    // ---- a mock transport that records whether/when it was called ----

    enum Behavior {
        Iphone(MockIphone),
        Err(TransportError),
    }

    struct MockTransport {
        behavior: Behavior,
        calls: Cell<usize>,
    }

    impl MockTransport {
        fn new(behavior: Behavior) -> Self {
            MockTransport {
                behavior,
                calls: Cell::new(0),
            }
        }
        fn calls(&self) -> usize {
            self.calls.get()
        }
    }

    impl Transport for MockTransport {
        fn dispatch(
            &self,
            envelope: &[u8],
            _deadline: Deadline,
        ) -> Result<Vec<u8>, TransportError> {
            self.calls.set(self.calls.get() + 1);
            match &self.behavior {
                Behavior::Iphone(ph) => Ok(ph
                    .process(envelope)
                    .expect("mock iphone processes envelope")),
                Behavior::Err(e) => Err(e.clone()),
            }
        }
    }

    struct MapResolver(HashMap<String, u32>);
    impl UserResolver for MapResolver {
        fn resolve(&self, username: &str) -> Option<u32> {
            self.0.get(username).copied()
        }
    }

    // ---- a real (non-suspending) clock stand-in: monotonic-ish, fixed for determinism ----

    #[derive(Clone, Copy)]
    struct FixedClock(u64);
    impl Clock for FixedClock {
        fn now_boottime_ns(&self) -> u64 {
            self.0
        }
    }

    // ---- fixtures ----

    fn verifier_pk() -> [u8; 32] {
        crypto::ed25519::public_key(&crypto::ed25519::signing_key(&VERIFIER_SEED))
    }

    fn iphone(seed: &[u8; 32]) -> MockIphone {
        MockIphone::new(IPHONE_DEV, seed, verifier_pk(), LINUX_DEV).unwrap()
    }

    fn policy() -> Policy {
        Policy {
            linux_device_id: LINUX_DEV,
            linux_device_name: "workstation".into(),
            ttl_seconds: 30,
            allowed_pam_services: vec!["bifrauth-login".into()],
        }
    }

    fn resolver() -> MapResolver {
        let mut m = HashMap::new();
        m.insert("alice".to_string(), UID);
        MapResolver(m)
    }

    fn verifier_with_device() -> Mutex<Verifier<FixedClock>> {
        let mut v = Verifier::new(VERIFIER_SEED, FixedClock(1_000_000_000));
        let ph = iphone(&DEVICE_SEED);
        v.register_device(UID, IPHONE_DEV, &ph.device_public_key_sec1())
            .unwrap();
        Mutex::new(v)
    }

    fn frame_bytes(body: &[u8]) -> Vec<u8> {
        let mut v = (body.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(body);
        v
    }

    fn auth_request(service: &str, user: &str) -> Vec<u8> {
        AuthRequest {
            username: user.into(),
            pam_service: service.into(),
            pam_tty: None,
            pam_rhost: None,
        }
        .encode()
        .unwrap()
    }

    /// A one-shot responder that, on inbound drain, reads the issued request_id from the just-sent
    /// ConfirmationCode (outbound frame 0) and replies with a `DisplayAck` carrying it.
    fn display_ack_responder(display_ok: bool) -> Responder {
        Box::new(move |frames: &[Vec<u8>]| {
            let cc = ConfirmationCode::decode(frames.first()?).ok()?;
            Some(
                DisplayAck {
                    request_id: cc.request_id,
                    conversation_succeeded: display_ok,
                }
                .encode()
                .unwrap(),
            )
        })
    }

    /// Drive a full flow: AuthRequest preloaded, DisplayAck synthesized reactively with the real id.
    fn run_flow(
        display_ok: bool,
        transport: &MockTransport,
        fail_after_frames: Option<usize>,
    ) -> (Terminal, usize) {
        let v = verifier_with_device();
        let clock = FixedClock(1_000_000_000);
        let mut s = MockStream::new(frame_bytes(&auth_request("bifrauth-login", "alice")))
            .with_responder(display_ack_responder(display_ok));
        if let Some(n) = fail_after_frames {
            s = s.fail_after_frames(n);
        }
        let terminal = run_connection(
            &mut s,
            &v,
            &clock,
            transport,
            &policy(),
            &resolver(),
            WALL_EPOCH,
        );
        (terminal, v.lock().unwrap().pending_count())
    }

    // ---- tests ----

    #[test]
    fn happy_path_success_only_from_verify_and_transport_called_once() {
        let transport = MockTransport::new(Behavior::Iphone(iphone(&DEVICE_SEED)));
        let (terminal, pending) = run_flow(true, &transport, None);
        assert_eq!(terminal, Terminal::OutcomeSent(OutcomeCode::Success));
        assert_eq!(transport.calls(), 1);
        assert_eq!(pending, 0);
    }

    #[test]
    fn display_ack_false_denies_and_never_calls_transport() {
        let transport = MockTransport::new(Behavior::Iphone(iphone(&DEVICE_SEED)));
        let (terminal, pending) = run_flow(false, &transport, None);
        assert_eq!(terminal, Terminal::OutcomeSent(OutcomeCode::Denied));
        assert_eq!(transport.calls(), 0); // transport is gated behind conversation_succeeded
        assert_eq!(pending, 0);
    }

    #[test]
    fn success_is_decided_by_verify_not_by_returned_bytes() {
        // A different device key produces a well-formed but non-verifying response.
        let transport = MockTransport::new(Behavior::Iphone(iphone(&[0x77; 32])));
        let (terminal, pending) = run_flow(true, &transport, None);
        assert_eq!(terminal, Terminal::OutcomeSent(OutcomeCode::Denied));
        assert_eq!(transport.calls(), 1);
        assert_eq!(pending, 0);
    }

    #[test]
    fn transport_error_maps_to_outcome_and_cleans_up() {
        let transport = MockTransport::new(Behavior::Err(TransportError::Timeout));
        let (terminal, pending) = run_flow(true, &transport, None);
        assert_eq!(terminal, Terminal::OutcomeSent(OutcomeCode::Timeout));
        assert_eq!(transport.calls(), 1);
        assert_eq!(pending, 0);
    }

    #[test]
    fn eof_before_display_ack_cleans_up_and_never_calls_transport() {
        let v = verifier_with_device();
        let clock = FixedClock(1_000_000_000);
        let transport = MockTransport::new(Behavior::Iphone(iphone(&DEVICE_SEED)));
        // Only AuthRequest; DisplayAck read hits EOF.
        let mut s = MockStream::new(frame_bytes(&auth_request("bifrauth-login", "alice")));
        let terminal = run_connection(
            &mut s,
            &v,
            &clock,
            &transport,
            &policy(),
            &resolver(),
            WALL_EPOCH,
        );
        assert_eq!(terminal, Terminal::ClosedAfterCleanup);
        assert_eq!(transport.calls(), 0);
        assert_eq!(v.lock().unwrap().pending_count(), 0);
    }

    #[test]
    fn wrong_request_id_in_display_ack_cleans_up() {
        let v = verifier_with_device();
        let clock = FixedClock(1_000_000_000);
        let transport = MockTransport::new(Behavior::Iphone(iphone(&DEVICE_SEED)));
        let ack = DisplayAck {
            request_id: [0xAB; 16], // not the issued id
            conversation_succeeded: true,
        }
        .encode()
        .unwrap();
        let mut inbound = frame_bytes(&auth_request("bifrauth-login", "alice"));
        inbound.extend(frame_bytes(&ack));
        let mut s = MockStream::new(inbound);
        let terminal = run_connection(
            &mut s,
            &v,
            &clock,
            &transport,
            &policy(),
            &resolver(),
            WALL_EPOCH,
        );
        assert_eq!(terminal, Terminal::ClosedAfterCleanup);
        assert_eq!(transport.calls(), 0);
        assert_eq!(v.lock().unwrap().pending_count(), 0);
    }

    #[test]
    fn confirmation_code_send_failure_cleans_up() {
        let v = verifier_with_device();
        let clock = FixedClock(1_000_000_000);
        let transport = MockTransport::new(Behavior::Iphone(iphone(&DEVICE_SEED)));
        // Fail on the very first outbound frame (the ConfirmationCode).
        let mut s = MockStream::new(frame_bytes(&auth_request("bifrauth-login", "alice")))
            .fail_after_frames(0);
        let terminal = run_connection(
            &mut s,
            &v,
            &clock,
            &transport,
            &policy(),
            &resolver(),
            WALL_EPOCH,
        );
        assert_eq!(terminal, Terminal::ClosedAfterCleanup);
        assert_eq!(transport.calls(), 0);
        assert_eq!(v.lock().unwrap().pending_count(), 0);
    }

    #[test]
    fn outcome_send_failure_after_success_is_not_an_external_success() {
        // 追補B: verify succeeds, but the Outcome frame cannot be delivered. PAM must see no Success.
        let v = verifier_with_device();
        let clock = FixedClock(1_000_000_000);
        // Let the ConfirmationCode (frame 0) write, then fail the Outcome (frame 1).
        let mut s = MockStream::new(frame_bytes(&auth_request("bifrauth-login", "alice")))
            .with_responder(display_ack_responder(true))
            .fail_after_frames(1);
        let transport = MockTransport::new(Behavior::Iphone(iphone(&DEVICE_SEED)));
        let terminal = run_connection(
            &mut s,
            &v,
            &clock,
            &transport,
            &policy(),
            &resolver(),
            WALL_EPOCH,
        );

        assert_eq!(terminal, Terminal::OutcomeSendFailed(OutcomeCode::Success));
        // The verify consumed the pending request, and only the ConfirmationCode reached PAM — no Outcome.
        assert_eq!(v.lock().unwrap().pending_count(), 0);
        let frames = s.outbound_frames();
        assert_eq!(frames.len(), 1);
        assert!(ConfirmationCode::decode(&frames[0]).is_ok());
    }

    #[test]
    fn service_not_in_allowlist_is_refused_before_issue() {
        let v = verifier_with_device();
        let clock = FixedClock(1_000_000_000);
        let transport = MockTransport::new(Behavior::Iphone(iphone(&DEVICE_SEED)));
        let mut s = MockStream::new(frame_bytes(&auth_request("sshd", "alice")));
        let terminal = run_connection(
            &mut s,
            &v,
            &clock,
            &transport,
            &policy(),
            &resolver(),
            WALL_EPOCH,
        );
        assert_eq!(
            terminal,
            Terminal::ClosedBeforeIssue(PreIssueReason::ServiceNotAllowed)
        );
        assert_eq!(transport.calls(), 0);
        assert_eq!(v.lock().unwrap().pending_count(), 0);
    }

    #[test]
    fn unknown_user_is_refused_before_issue() {
        let v = verifier_with_device();
        let clock = FixedClock(1_000_000_000);
        let transport = MockTransport::new(Behavior::Iphone(iphone(&DEVICE_SEED)));
        let mut s = MockStream::new(frame_bytes(&auth_request("bifrauth-login", "mallory")));
        let terminal = run_connection(
            &mut s,
            &v,
            &clock,
            &transport,
            &policy(),
            &resolver(),
            WALL_EPOCH,
        );
        assert_eq!(
            terminal,
            Terminal::ClosedBeforeIssue(PreIssueReason::UnknownUser)
        );
        assert_eq!(v.lock().unwrap().pending_count(), 0);
    }

    #[test]
    fn malformed_zero_length_and_oversize_auth_request_do_not_crash() {
        let clock = FixedClock(1_000_000_000);
        let transport = MockTransport::new(Behavior::Iphone(iphone(&DEVICE_SEED)));

        // Zero-length frame prefix.
        let v = verifier_with_device();
        let mut s = MockStream::new(vec![0, 0, 0, 0]);
        assert_eq!(
            run_connection(
                &mut s,
                &v,
                &clock,
                &transport,
                &policy(),
                &resolver(),
                WALL_EPOCH
            ),
            Terminal::ClosedBeforeIssue(PreIssueReason::BadAuthRequest)
        );

        // Oversize declared length (> 8 KiB) is rejected before allocating.
        let v = verifier_with_device();
        let mut oversize = ((frame::MAX_BODY_LEN as u32) + 1).to_be_bytes().to_vec();
        oversize.extend_from_slice(&[0u8; 16]);
        let mut s = MockStream::new(oversize);
        assert_eq!(
            run_connection(
                &mut s,
                &v,
                &clock,
                &transport,
                &policy(),
                &resolver(),
                WALL_EPOCH
            ),
            Terminal::ClosedBeforeIssue(PreIssueReason::BadAuthRequest)
        );

        // Garbage CBOR body.
        let v = verifier_with_device();
        let mut s = MockStream::new(frame_bytes(&[0xff, 0xff, 0xff, 0xff]));
        assert_eq!(
            run_connection(
                &mut s,
                &v,
                &clock,
                &transport,
                &policy(),
                &resolver(),
                WALL_EPOCH
            ),
            Terminal::ClosedBeforeIssue(PreIssueReason::BadAuthRequest)
        );
    }
}
