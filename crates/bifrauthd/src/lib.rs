//! bifrauthd verifier core (P4 core).
//!
//! The root-owned verifier's state machine: issue challenges from a trusted PAM context, keep pending
//! requests with a CLOCK_BOOTTIME deadline, and verify iPhone responses (design §9.7, §16, §11).
//!
//! This module is a library with no socket/IPC. The root Unix socket IPC (SO_PEERCRED, framing) and the
//! bifrauthctl CLI are separate follow-up tasks. It builds on [`bifrauth_proto`] and [`bifrauth_crypto`].
//!
//! Trust model: the verifier is the sole source of truth. The TTL authority is `CLOCK_BOOTTIME`
//! (suspend-inclusive), not the wall clock. The response's `signed_payload_hash` is recomputed and never
//! used as a signature input; the P-256 signature is verified against the stored canonical bytes.

use bifrauth_crypto as crypto;
use bifrauth_proto::{Challenge, Envelope, Response, SchemaError};
use std::collections::HashMap;

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

/// Errors from [`Verifier::issue_challenge`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssueError {
    /// The OS CSPRNG failed (treat as an auth failure; do not panic).
    Rng,
    /// Building/encoding the challenge failed (e.g. an out-of-range field such as TTL).
    Build(SchemaError),
}

/// Errors from [`Verifier::verify_response`]. On every variant except [`VerifyError::MalformedResponse`]
/// and [`VerifyError::UnknownOrConsumedRequest`], the request_id has already been consumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The response bytes did not decode (no request_id to consume).
    MalformedResponse(SchemaError),
    /// The request_id is not pending: unknown, already consumed, or a replay.
    UnknownOrConsumedRequest,
    /// The request expired (CLOCK_BOOTTIME deadline passed).
    Expired,
    /// The response's iphone_device_id is not registered for the request's uid.
    UnregisteredDevice,
    /// The response's protocol_version does not match.
    ProtocolVersionMismatch,
    /// The recomputed SHA-256 of the canonical challenge does not match the response's
    /// signed_payload_hash (malformed). Note: the hash is never used as a signature input.
    HashMismatch,
    /// The P-256 signature over the stored canonical bytes is invalid.
    SignatureInvalid,
}

/// The trusted PAM context a challenge is built from (design §9.1). The verifier fills nonce/request_id/
/// confirmation_code and derives `requested_action` from `pam_service`.
#[derive(Debug, Clone)]
pub struct ChallengeContext {
    pub uid: u32,
    pub username: String,
    pub pam_service: String,
    pub pam_tty: Option<String>,
    pub pam_rhost: Option<String>,
    pub linux_device_id: [u8; 16],
    pub linux_device_name: String,
    /// Requested TTL in seconds; must be within the profile's 1..=30.
    pub ttl_seconds: u64,
    /// Wall-clock epoch seconds for iPhone display (not the TTL authority).
    pub issued_at: u64,
}

/// The result of issuing a challenge.
#[derive(Debug, Clone)]
pub struct IssuedChallenge {
    pub request_id: [u8; 16],
    /// The `bifrauth.envelope.v1` bytes to hand to the transport helper.
    pub envelope: Vec<u8>,
    /// The 6-digit confirmation code to display via the PAM conversation.
    pub confirmation_code: String,
}

/// A pending request awaiting a response. The nonce/uid/action/etc. are inside `canonical` and are bound
/// by the signature, so only the canonical bytes, uid (for device lookup), and deadline are stored.
#[derive(Debug, Clone)]
struct Pending {
    canonical: Vec<u8>,
    uid: u32,
    deadline_ns: u64,
}

/// The root verifier state machine.
pub struct Verifier<C: Clock = BoottimeClock> {
    /// Ed25519 seed; the signing key is derived per issue (avoids leaking the dalek type).
    verifier_seed: [u8; 32],
    verifier_key_id: [u8; 32],
    /// Registered device P-256 SEC1 public keys: uid -> (iphone_device_id -> SEC1 bytes).
    devices: HashMap<u32, HashMap<[u8; 16], Vec<u8>>>,
    pending: HashMap<[u8; 16], Pending>,
    clock: C,
}

impl<C: Clock> Verifier<C> {
    /// Create a verifier from a 32B Ed25519 seed and a clock. Pending requests start empty (a process
    /// restart therefore drops all pending requests, as required by design §16).
    pub fn new(verifier_seed: [u8; 32], clock: C) -> Self {
        let pubkey = crypto::ed25519::public_key(&crypto::ed25519::signing_key(&verifier_seed));
        let verifier_key_id = crypto::sha256(&pubkey);
        Verifier {
            verifier_seed,
            verifier_key_id,
            devices: HashMap::new(),
            pending: HashMap::new(),
            clock,
        }
    }

    /// Register an iPhone device's P-256 SEC1 public key for a uid.
    pub fn register_device(&mut self, uid: u32, iphone_device_id: [u8; 16], p256_sec1: Vec<u8>) {
        self.devices
            .entry(uid)
            .or_default()
            .insert(iphone_device_id, p256_sec1);
    }

    /// Number of pending requests (for tests/metrics).
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Build, sign, and record a challenge for `ctx`. Returns the envelope bytes and confirmation code.
    pub fn issue_challenge(
        &mut self,
        ctx: &ChallengeContext,
    ) -> Result<IssuedChallenge, IssueError> {
        let request_id = crypto::csprng::random_bytes::<16>().map_err(|_| IssueError::Rng)?;
        let nonce = crypto::csprng::random_bytes::<16>().map_err(|_| IssueError::Rng)?;
        let confirmation_code = crypto::csprng::confirmation_code().map_err(|_| IssueError::Rng)?;

        let challenge = Challenge {
            protocol_version: 1,
            request_id,
            nonce,
            verifier_key_id: self.verifier_key_id,
            linux_device_id: ctx.linux_device_id,
            linux_device_name: ctx.linux_device_name.clone(),
            target_uid: ctx.uid,
            target_username: ctx.username.clone(),
            pam_service: ctx.pam_service.clone(),
            pam_tty: ctx.pam_tty.clone(),
            pam_rhost: ctx.pam_rhost.clone(),
            // Derive the purpose from the trusted PAM service (design §9.2).
            requested_action: format!("{}.authenticate", ctx.pam_service),
            issued_at: ctx.issued_at,
            expires_at: ctx.issued_at.saturating_add(ctx.ttl_seconds),
            confirmation_code: confirmation_code.clone(),
        };
        // encode() validates all layer-B constraints (incl. TTL 1..=30 and text policy).
        let canonical = challenge.encode().map_err(IssueError::Build)?;

        let sig = crypto::ed25519::sign(
            &crypto::ed25519::signing_key(&self.verifier_seed),
            &canonical,
        );
        let envelope = Envelope {
            canonical_challenge: canonical.clone(),
            verifier_signature: sig,
        }
        .encode()
        .map_err(IssueError::Build)?;

        // The authoritative deadline is measured on CLOCK_BOOTTIME (suspend-inclusive).
        let deadline_ns = self
            .clock
            .now_boottime_ns()
            .saturating_add(ctx.ttl_seconds.saturating_mul(1_000_000_000));
        self.pending.insert(
            request_id,
            Pending {
                canonical,
                uid: ctx.uid,
                deadline_ns,
            },
        );

        Ok(IssuedChallenge {
            request_id,
            envelope,
            confirmation_code,
        })
    }

    /// Verify a response (design §9.7). On success returns the request_id.
    ///
    /// The request_id is **atomically consumed** at the start (removed from the pending store) even when
    /// the signature is later found invalid, so a replay or concurrent double-verify is rejected.
    pub fn verify_response(&mut self, response_bytes: &[u8]) -> Result<[u8; 16], VerifyError> {
        let resp = Response::decode(response_bytes).map_err(VerifyError::MalformedResponse)?;

        // Atomic consume: removing the pending entry consumes the request_id for good.
        let pending = self
            .pending
            .remove(&resp.request_id)
            .ok_or(VerifyError::UnknownOrConsumedRequest)?;

        // TTL on CLOCK_BOOTTIME (the request is already consumed at this point).
        if self.clock.now_boottime_ns() > pending.deadline_ns {
            return Err(VerifyError::Expired);
        }
        if resp.protocol_version != 1 {
            return Err(VerifyError::ProtocolVersionMismatch);
        }
        // The device must be registered for this uid.
        let dev_pk = self
            .devices
            .get(&pending.uid)
            .and_then(|m| m.get(&resp.iphone_device_id))
            .ok_or(VerifyError::UnregisteredDevice)?;
        // Recompute the hash; the response value must match (malformed otherwise) but is never a sig input.
        if resp.signed_payload_hash != crypto::sha256(&pending.canonical) {
            return Err(VerifyError::HashMismatch);
        }
        // Verify the P-256 signature over the stored canonical bytes.
        crypto::p256_ecdsa::verify(dev_pk, &pending.canonical, &resp.signature)
            .map_err(|_| VerifyError::SignatureInvalid)?;

        Ok(resp.request_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mock_iphone::MockIphone;
    use std::cell::Cell;
    use std::rc::Rc;

    /// A controllable clock for tests.
    #[derive(Clone)]
    struct MockClock(Rc<Cell<u64>>);
    impl MockClock {
        fn new(ns: u64) -> Self {
            MockClock(Rc::new(Cell::new(ns)))
        }
        fn advance(&self, ns: u64) {
            self.0.set(self.0.get() + ns);
        }
    }
    impl Clock for MockClock {
        fn now_boottime_ns(&self) -> u64 {
            self.0.get()
        }
    }

    const VERIFIER_SEED: [u8; 32] = [0x03; 32];
    const DEVICE_SEED: [u8; 32] = [0x55; 32];
    const IPHONE_DEV: [u8; 16] = [0x66; 16];
    const LINUX_DEV: [u8; 16] = [0x44; 16];
    const UID: u32 = 1000;

    fn ctx() -> ChallengeContext {
        ChallengeContext {
            uid: UID,
            username: "alice".into(),
            pam_service: "polkit-1".into(),
            pam_tty: None,
            pam_rhost: Some("host.example".into()),
            linux_device_id: LINUX_DEV,
            linux_device_name: "workstation".into(),
            ttl_seconds: 30,
            issued_at: 1_700_000_000,
        }
    }

    /// A verifier with a registered mock iPhone, plus that mock for producing responses.
    fn setup(clock: MockClock) -> (Verifier<MockClock>, MockIphone) {
        let mut v = Verifier::new(VERIFIER_SEED, clock);
        let verifier_pk =
            crypto::ed25519::public_key(&crypto::ed25519::signing_key(&VERIFIER_SEED));
        let iphone = MockIphone::new(IPHONE_DEV, &DEVICE_SEED, verifier_pk, LINUX_DEV).unwrap();
        v.register_device(UID, IPHONE_DEV, iphone.device_public_key_sec1().to_vec());
        (v, iphone)
    }

    #[test]
    fn issue_verify_end_to_end() {
        let clock = MockClock::new(1_000_000_000);
        let (mut v, iphone) = setup(clock);
        let issued = v.issue_challenge(&ctx()).unwrap();
        assert_eq!(v.pending_count(), 1);
        assert_eq!(issued.confirmation_code.len(), 6);

        let response = iphone.process(&issued.envelope).unwrap();
        let rid = v.verify_response(&response).unwrap();
        assert_eq!(rid, issued.request_id);
        // Consumed on success.
        assert_eq!(v.pending_count(), 0);
    }

    #[test]
    fn replay_is_rejected_after_consume() {
        let clock = MockClock::new(1_000_000_000);
        let (mut v, iphone) = setup(clock);
        let issued = v.issue_challenge(&ctx()).unwrap();
        let response = iphone.process(&issued.envelope).unwrap();
        assert!(v.verify_response(&response).is_ok());
        // Second verify of the same response is rejected (already consumed).
        assert_eq!(
            v.verify_response(&response),
            Err(VerifyError::UnknownOrConsumedRequest)
        );
    }

    #[test]
    fn bad_signature_still_consumes_request_id() {
        let clock = MockClock::new(1_000_000_000);
        let (mut v, iphone) = setup(clock);
        let issued = v.issue_challenge(&ctx()).unwrap();
        let mut response = iphone.process(&issued.envelope).unwrap();
        // Corrupt the DER signature body (the last byte of the response bytes).
        let n = response.len();
        response[n - 1] ^= 0x01;
        // Rejected, but the request_id is consumed.
        assert!(matches!(
            v.verify_response(&response),
            Err(VerifyError::SignatureInvalid) | Err(VerifyError::MalformedResponse(_))
        ));
        assert_eq!(v.pending_count(), 0);
    }

    #[test]
    fn expired_on_boottime_is_rejected() {
        let clock = MockClock::new(1_000_000_000);
        let (mut v, iphone) = setup(clock.clone());
        let issued = v.issue_challenge(&ctx()).unwrap(); // ttl 30s
        let response = iphone.process(&issued.envelope).unwrap();
        // Advance BOOTTIME past the 30s deadline (suspend-inclusive authority).
        clock.advance(31 * 1_000_000_000);
        assert_eq!(v.verify_response(&response), Err(VerifyError::Expired));
        // Consumed even when expired.
        assert_eq!(v.pending_count(), 0);
    }

    #[test]
    fn unregistered_device_is_rejected() {
        let clock = MockClock::new(1_000_000_000);
        let mut v = Verifier::new(VERIFIER_SEED, clock);
        // Do NOT register the device.
        let verifier_pk =
            crypto::ed25519::public_key(&crypto::ed25519::signing_key(&VERIFIER_SEED));
        let iphone = MockIphone::new(IPHONE_DEV, &DEVICE_SEED, verifier_pk, LINUX_DEV).unwrap();
        let issued = v.issue_challenge(&ctx()).unwrap();
        let response = iphone.process(&issued.envelope).unwrap();
        assert_eq!(
            v.verify_response(&response),
            Err(VerifyError::UnregisteredDevice)
        );
    }

    #[test]
    fn unknown_request_id_is_rejected() {
        let clock = MockClock::new(1_000_000_000);
        let (mut v, iphone) = setup(clock);
        let issued = v.issue_challenge(&ctx()).unwrap();
        let response = iphone.process(&issued.envelope).unwrap();
        // Drop the pending state (simulate restart), then verify.
        let mut v2 = Verifier::new(VERIFIER_SEED, MockClock::new(1_000_000_000));
        v2.register_device(UID, IPHONE_DEV, iphone.device_public_key_sec1().to_vec());
        let _ = issued;
        assert_eq!(
            v2.verify_response(&response),
            Err(VerifyError::UnknownOrConsumedRequest)
        );
    }

    #[test]
    fn ttl_out_of_range_fails_to_issue() {
        let clock = MockClock::new(1_000_000_000);
        let (mut v, _iphone) = setup(clock);
        let mut c = ctx();
        c.ttl_seconds = 31; // profile allows 1..=30
        assert!(matches!(v.issue_challenge(&c), Err(IssueError::Build(_))));
    }
}
