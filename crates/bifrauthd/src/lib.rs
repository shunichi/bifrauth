//! bifrauthd verifier core (P4 core).
//!
//! The root-owned verifier's state machine: issue challenges from a trusted PAM context, keep pending
//! requests with a CLOCK_BOOTTIME deadline, and verify iPhone responses (design §9.7, §15.3, §16, §11).
//!
//! This module is a library with no socket/IPC. The root Unix socket IPC (SO_PEERCRED, framing, the
//! confirmation-code notification) and the bifrauthctl CLI are separate follow-up tasks. It builds on
//! [`bifrauth_proto`] and [`bifrauth_crypto`].
//!
//! Trust model: the verifier is the sole source of truth. The TTL authority is `CLOCK_BOOTTIME`
//! (suspend-inclusive), not the wall clock. The response's `signed_payload_hash` is recomputed and never
//! used as a signature input; the P-256 signature is verified against the stored canonical bytes.
//!
//! Concurrency: all mutation goes through `&mut self`, so within this core the consume-then-verify step is
//! atomic. The IPC layer must serialize the whole `Verifier` under a single mutex/actor.
//!
//! This core assumes registered device keys are already validated and non-revoked; revocation lives in the
//! registry/CLI (task 0009).

use bifrauth_crypto as crypto;
use bifrauth_proto::{Challenge, Envelope, Response, SchemaError};
use std::collections::HashMap;

/// Maximum total pending requests across all uids (design §15.3 queue cap).
pub const MAX_PENDING_TOTAL: usize = 256;
/// Maximum concurrent pending requests for a single uid (design §15.3).
pub const MAX_PENDING_PER_UID: usize = 8;
/// How many times to regenerate a colliding request_id before giving up (astronomically unlikely).
const MAX_REQUEST_ID_TRIES: u32 = 8;

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
    /// The total pending-request queue is full (design §15.3).
    QueueFull,
    /// This uid already has the maximum concurrent pending requests (design §15.3).
    TooManyPendingForUid,
    /// Could not obtain a fresh (non-colliding) request_id.
    RequestIdCollision,
    /// The TTL nanosecond deadline overflowed (fail closed).
    ClockOverflow,
}

/// Errors from [`Verifier::verify_response`].
///
/// Consume boundary: [`VerifyError::MalformedResponse`] and [`VerifyError::UnknownOrConsumedRequest`] do
/// **not** consume a request_id (there is nothing to consume). Once the request_id is extracted and its
/// pending entry removed, **any** later validation failure still consumes it (single-use).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The response bytes did not decode (no request_id to consume). Note: the response schema already
    /// requires protocol_version == 1, so a wrong-version response is a MalformedResponse.
    MalformedResponse(SchemaError),
    /// The request_id is not pending: unknown, already consumed, or a replay.
    UnknownOrConsumedRequest,
    /// The request expired (CLOCK_BOOTTIME deadline reached).
    Expired,
    /// The response's iphone_device_id is not registered for the request's uid.
    UnregisteredDevice,
    /// The recomputed SHA-256 of the canonical challenge does not match the response's
    /// signed_payload_hash (malformed). Note: the hash is never used as a signature input.
    HashMismatch,
    /// The P-256 signature over the stored canonical bytes is invalid.
    SignatureInvalid,
}

/// Errors from [`Verifier::register_device`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterError {
    /// The bytes do not parse as a P-256 SEC1 public key.
    InvalidPublicKey,
    /// A key is already registered for this (uid, device_id); use a separate update/revoke path.
    AlreadyRegistered,
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
    signer: crypto::ed25519::Signer,
    verifier_key_id: [u8; 32],
    /// Registered device P-256 SEC1 public keys: uid -> (iphone_device_id -> SEC1 bytes).
    devices: HashMap<u32, HashMap<[u8; 16], Vec<u8>>>,
    pending: HashMap<[u8; 16], Pending>,
    /// Concurrent pending count per uid (kept in sync with `pending` for the §15.3 cap).
    per_uid: HashMap<u32, usize>,
    clock: C,
}

impl<C: Clock> Verifier<C> {
    /// Create a verifier from a 32B Ed25519 seed and a clock. Pending requests start empty (a process
    /// restart therefore drops all pending requests, as required by design §16). The seed is consumed
    /// into a zeroizing signer and not retained.
    pub fn new(verifier_seed: [u8; 32], clock: C) -> Self {
        let signer = crypto::ed25519::Signer::from_seed(&verifier_seed);
        let verifier_key_id = crypto::sha256(&signer.public_key());
        Verifier {
            signer,
            verifier_key_id,
            devices: HashMap::new(),
            pending: HashMap::new(),
            per_uid: HashMap::new(),
            clock,
        }
    }

    /// Register an iPhone device's P-256 SEC1 public key for a uid. The key is parsed/validated, and an
    /// existing (uid, device_id) registration is not silently overwritten.
    pub fn register_device(
        &mut self,
        uid: u32,
        iphone_device_id: [u8; 16],
        p256_sec1: &[u8],
    ) -> Result<(), RegisterError> {
        crypto::p256_ecdsa::validate_public_key(p256_sec1)
            .map_err(|_| RegisterError::InvalidPublicKey)?;
        let entry = self.devices.entry(uid).or_default();
        if entry.contains_key(&iphone_device_id) {
            return Err(RegisterError::AlreadyRegistered);
        }
        entry.insert(iphone_device_id, p256_sec1.to_vec());
        Ok(())
    }

    /// Number of pending requests (for tests/metrics).
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Remove pending requests whose deadline has been reached (called before issuing).
    fn prune_expired(&mut self) {
        let now = self.clock.now_boottime_ns();
        let expired: Vec<[u8; 16]> = self
            .pending
            .iter()
            .filter(|(_, p)| now >= p.deadline_ns)
            .map(|(k, _)| *k)
            .collect();
        for k in expired {
            self.consume(&k);
        }
    }

    /// Atomically remove a pending request by id, keeping `per_uid` in sync.
    fn consume(&mut self, request_id: &[u8; 16]) -> Option<Pending> {
        let pending = self.pending.remove(request_id)?;
        if let Some(c) = self.per_uid.get_mut(&pending.uid) {
            *c -= 1;
            if *c == 0 {
                self.per_uid.remove(&pending.uid);
            }
        }
        Some(pending)
    }

    /// Build, sign, and record a challenge for `ctx`. Returns the envelope bytes and confirmation code.
    pub fn issue_challenge(
        &mut self,
        ctx: &ChallengeContext,
    ) -> Result<IssuedChallenge, IssueError> {
        // Prune expired requests first so the caps below reflect live requests only.
        self.prune_expired();
        if self.pending.len() >= MAX_PENDING_TOTAL {
            return Err(IssueError::QueueFull);
        }
        if self.per_uid.get(&ctx.uid).copied().unwrap_or(0) >= MAX_PENDING_PER_UID {
            return Err(IssueError::TooManyPendingForUid);
        }

        // A fresh request_id that does not collide with a live pending entry (never overwrite).
        let mut request_id = [0u8; 16];
        let mut got_id = false;
        for _ in 0..MAX_REQUEST_ID_TRIES {
            let candidate = crypto::csprng::random_bytes::<16>().map_err(|_| IssueError::Rng)?;
            if !self.pending.contains_key(&candidate) {
                request_id = candidate;
                got_id = true;
                break;
            }
        }
        if !got_id {
            return Err(IssueError::RequestIdCollision);
        }

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

        let sig = self.signer.sign(&canonical);
        let envelope = Envelope {
            canonical_challenge: canonical.clone(),
            verifier_signature: sig,
        }
        .encode()
        .map_err(IssueError::Build)?;

        // The authoritative deadline is measured on CLOCK_BOOTTIME (suspend-inclusive), fail closed on overflow.
        let deadline_ns = ctx
            .ttl_seconds
            .checked_mul(1_000_000_000)
            .and_then(|d| self.clock.now_boottime_ns().checked_add(d))
            .ok_or(IssueError::ClockOverflow)?;

        self.pending.insert(
            request_id,
            Pending {
                canonical,
                uid: ctx.uid,
                deadline_ns,
            },
        );
        *self.per_uid.entry(ctx.uid).or_insert(0) += 1;

        Ok(IssuedChallenge {
            request_id,
            envelope,
            confirmation_code,
        })
    }

    /// Verify a response (design §9.7). On success returns the request_id.
    ///
    /// The request_id is **atomically consumed** at the start (removed from the pending store) even when a
    /// later check (signature, hash, device, expiry) fails, so a replay or concurrent double-verify is
    /// rejected. See [`VerifyError`] for the exact consume boundary.
    pub fn verify_response(&mut self, response_bytes: &[u8]) -> Result<[u8; 16], VerifyError> {
        let resp = Response::decode(response_bytes).map_err(VerifyError::MalformedResponse)?;

        // Atomic consume: removing the pending entry consumes the request_id for good.
        let pending = self
            .consume(&resp.request_id)
            .ok_or(VerifyError::UnknownOrConsumedRequest)?;

        // TTL on CLOCK_BOOTTIME: valid while now < deadline (the request is already consumed here).
        if self.clock.now_boottime_ns() >= pending.deadline_ns {
            return Err(VerifyError::Expired);
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
    use bifrauth_proto::Response;
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

    fn verifier_pk() -> [u8; 32] {
        crypto::ed25519::public_key(&crypto::ed25519::signing_key(&VERIFIER_SEED))
    }

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

    fn iphone(seed: &[u8; 32]) -> MockIphone {
        MockIphone::new(IPHONE_DEV, seed, verifier_pk(), LINUX_DEV).unwrap()
    }

    /// A verifier with a registered mock iPhone (device A), plus that mock.
    fn setup(clock: MockClock) -> (Verifier<MockClock>, MockIphone) {
        let mut v = Verifier::new(VERIFIER_SEED, clock);
        let ph = iphone(&DEVICE_SEED);
        v.register_device(UID, IPHONE_DEV, &ph.device_public_key_sec1())
            .unwrap();
        (v, ph)
    }

    #[test]
    fn issue_verify_end_to_end() {
        let (mut v, ph) = setup(MockClock::new(1_000_000_000));
        let issued = v.issue_challenge(&ctx()).unwrap();
        assert_eq!(v.pending_count(), 1);
        assert_eq!(issued.confirmation_code.len(), 6);

        let response = ph.process(&issued.envelope).unwrap();
        let rid = v.verify_response(&response).unwrap();
        assert_eq!(rid, issued.request_id);
        assert_eq!(v.pending_count(), 0);
    }

    #[test]
    fn replay_is_rejected_after_consume() {
        let (mut v, ph) = setup(MockClock::new(1_000_000_000));
        let issued = v.issue_challenge(&ctx()).unwrap();
        let response = ph.process(&issued.envelope).unwrap();
        assert!(v.verify_response(&response).is_ok());
        assert_eq!(
            v.verify_response(&response),
            Err(VerifyError::UnknownOrConsumedRequest)
        );
    }

    #[test]
    fn valid_der_wrong_key_signature_is_strictly_invalid_then_consumed() {
        // Register device A, but let device B (same device_id, different key) produce the response: the
        // signature is valid DER but does not verify against A's registered key.
        let (mut v, _a) = setup(MockClock::new(1_000_000_000));
        let issued = v.issue_challenge(&ctx()).unwrap();
        let device_b = iphone(&[0x77; 32]);
        let response = device_b.process(&issued.envelope).unwrap();
        assert_eq!(
            v.verify_response(&response),
            Err(VerifyError::SignatureInvalid)
        );
        // Consumed: a retry is UnknownOrConsumedRequest.
        assert_eq!(
            v.verify_response(&response),
            Err(VerifyError::UnknownOrConsumedRequest)
        );
    }

    #[test]
    fn hash_mismatch_is_rejected_and_consumed() {
        let (mut v, ph) = setup(MockClock::new(1_000_000_000));
        let issued = v.issue_challenge(&ctx()).unwrap();
        let response = ph.process(&issued.envelope).unwrap();
        // Tamper the signed_payload_hash (still schema-valid) and re-encode.
        let mut r = Response::decode(&response).unwrap();
        r.signed_payload_hash[0] ^= 0x01;
        let tampered = r.encode().unwrap();
        assert_eq!(v.verify_response(&tampered), Err(VerifyError::HashMismatch));
        assert_eq!(
            v.verify_response(&tampered),
            Err(VerifyError::UnknownOrConsumedRequest)
        );
    }

    #[test]
    fn expired_exactly_at_deadline_is_rejected_and_consumed() {
        let clock = MockClock::new(1_000_000_000);
        let (mut v, ph) = setup(clock.clone());
        let issued = v.issue_challenge(&ctx()).unwrap(); // ttl 30s
        let response = ph.process(&issued.envelope).unwrap();
        // Advance to exactly the deadline: now == deadline must be treated as expired.
        clock.advance(30 * 1_000_000_000);
        assert_eq!(v.verify_response(&response), Err(VerifyError::Expired));
        assert_eq!(v.pending_count(), 0);
    }

    #[test]
    fn accepts_just_before_deadline() {
        let clock = MockClock::new(1_000_000_000);
        let (mut v, ph) = setup(clock.clone());
        let issued = v.issue_challenge(&ctx()).unwrap();
        let response = ph.process(&issued.envelope).unwrap();
        clock.advance(30 * 1_000_000_000 - 1); // one ns before the deadline
        assert!(v.verify_response(&response).is_ok());
    }

    #[test]
    fn unregistered_device_is_rejected_and_consumed() {
        let clock = MockClock::new(1_000_000_000);
        let mut v = Verifier::new(VERIFIER_SEED, clock);
        let ph = iphone(&DEVICE_SEED); // NOT registered
        let issued = v.issue_challenge(&ctx()).unwrap();
        let response = ph.process(&issued.envelope).unwrap();
        assert_eq!(
            v.verify_response(&response),
            Err(VerifyError::UnregisteredDevice)
        );
        assert_eq!(v.pending_count(), 0);
    }

    #[test]
    fn unknown_request_id_after_restart_is_rejected() {
        let (mut v, ph) = setup(MockClock::new(1_000_000_000));
        let issued = v.issue_challenge(&ctx()).unwrap();
        let response = ph.process(&issued.envelope).unwrap();
        // A fresh verifier (simulating a restart) has no pending state.
        let mut v2 = Verifier::new(VERIFIER_SEED, MockClock::new(1_000_000_000));
        v2.register_device(UID, IPHONE_DEV, &ph.device_public_key_sec1())
            .unwrap();
        let _ = (&mut v, issued);
        assert_eq!(
            v2.verify_response(&response),
            Err(VerifyError::UnknownOrConsumedRequest)
        );
    }

    #[test]
    fn ttl_out_of_range_fails_to_issue() {
        let (mut v, _ph) = setup(MockClock::new(1_000_000_000));
        let mut c = ctx();
        c.ttl_seconds = 31; // profile allows 1..=30
        assert!(matches!(v.issue_challenge(&c), Err(IssueError::Build(_))));
    }

    #[test]
    fn per_uid_limit_is_enforced() {
        let (mut v, _ph) = setup(MockClock::new(1_000_000_000));
        for _ in 0..MAX_PENDING_PER_UID {
            v.issue_challenge(&ctx()).unwrap();
        }
        assert!(matches!(
            v.issue_challenge(&ctx()),
            Err(IssueError::TooManyPendingForUid)
        ));
    }

    #[test]
    fn expired_requests_are_pruned_on_issue() {
        let clock = MockClock::new(1_000_000_000);
        let (mut v, _ph) = setup(clock.clone());
        for _ in 0..MAX_PENDING_PER_UID {
            v.issue_challenge(&ctx()).unwrap();
        }
        // Let them all expire, then a new issue prunes and succeeds.
        clock.advance(31 * 1_000_000_000);
        assert!(v.issue_challenge(&ctx()).is_ok());
        assert_eq!(v.pending_count(), 1);
    }

    #[test]
    fn register_rejects_invalid_key_and_duplicate() {
        let (mut v, ph) = setup(MockClock::new(1_000_000_000));
        // Invalid SEC1 bytes.
        assert_eq!(
            v.register_device(UID, [0x77; 16], &[0u8; 5]),
            Err(RegisterError::InvalidPublicKey)
        );
        // Duplicate (uid, device_id) is not silently overwritten.
        assert_eq!(
            v.register_device(UID, IPHONE_DEV, &ph.device_public_key_sec1()),
            Err(RegisterError::AlreadyRegistered)
        );
    }
}
